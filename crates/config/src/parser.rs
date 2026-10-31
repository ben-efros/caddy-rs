//! Caddyfile parser.
//!
//! Produces a small, explicit AST from the token stream. The parser supports the structurally
//! common Caddyfile forms — braced site blocks, the single unbraced site permitted by Caddy,
//! global options, named matchers, nested directive blocks, snippet definitions and imports
//! (`(name) { ... }`, `import name [args...]`), and named routes (`&(name) { ... }`,
//! `invoke name`) — and rejects the rest with a located error.
//!
//! Before lexing, the raw source is preprocessed exactly like Caddy's
//! `caddyconfig/caddyfile/parse.go`: `{$ENV}` and `{$ENV:default}` placeholders are replaced
//! (one level deep, with the process environment consulted for the name) on the raw bytes, so
//! expansion works in site addresses, arguments, quoted strings and heredoc bodies alike.
//! Caddy emits no diagnostic when a referenced variable is unset; this implementation substitutes
//! the same empty string but also records a non-fatal warning in
//! [`GlobalOptions::warnings`], which the adapter surfaces to callers (and the CLI prints).
//!
//! Snippets and imports are expanded at parse time by splicing tokens, mirroring Caddy's
//! `doImport`: `{args[N]}`/`{args.N}` are replaced inside tokens, a token that is exactly
//! `{args[start:end]}` splices in a range of arguments, `{block}` and `{blocks.NAME}` splice the
//! import's following block (or one of its named sub-blocks), and import cycles are rejected with
//! Caddy's diagnostic. Only imports of snippets defined in the same Caddyfile are implemented:
//! file/glob imports require a filename at the adapter boundary that this build does not carry,
//! so they are rejected loudly rather than approximated (tracked as a compatibility gap).
//!
//! Named routes are parsed and validated (duplicate definitions and undefined `invoke` targets
//! are located errors with Caddy's messages). Emitting Caddy's `named_routes`/`invoke` JSON is the
//! adapter's responsibility and is not implemented yet, so a Caddyfile that actually invokes a
//! named route fails loudly in the adapter.

use std::collections::{BTreeMap, BTreeSet};

use crate::lexer::{lex, LexError, Position, Token, TokenKind};

/// A parsed Caddyfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caddyfile {
    /// Global options block, if present.
    pub options: GlobalOptions,
    /// Site blocks in source order.
    pub sites: Vec<SiteBlock>,
    /// Named route definitions (`&(name) { ... }`), in source order. The adapter emits these only
    /// when a site invokes them (which is not implemented yet).
    pub named_routes: Vec<NamedRoute>,
}

/// Global options supported by the adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalOptions {
    /// Automatic HTTPS mode from `auto_https`.
    pub auto_https: Option<AutoHttpsMode>,
    /// `http_port`.
    pub http_port: Option<u16>,
    /// `https_port`.
    pub https_port: Option<u16>,
    /// Non-fatal notes produced while preprocessing the Caddyfile (environment-placeholder
    /// expansion) and while reading options. Adapters surface these to callers.
    pub warnings: Vec<String>,
}

/// `auto_https` modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoHttpsMode {
    /// `auto_https off`.
    Off,
    /// `auto_https disable_redirects`.
    DisableRedirects,
    /// `auto_https ignore_loaded_certs`.
    IgnoreLoadedCerts,
}

/// One site block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBlock {
    /// One or more site addresses.
    pub addresses: Vec<SiteAddress>,
    /// Directives, including named-matcher definitions (names starting with `@`).
    pub directives: Vec<Directive>,
    /// Source position of the block's first address.
    pub position: Position,
}

/// A parsed site address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteAddress {
    /// Original spelling.
    pub raw: String,
    /// Explicit scheme (`http` or `https`), when written.
    pub scheme: Option<String>,
    /// Hostname, without port. Empty for a bare `:port` address.
    pub host: String,
    /// Explicit port, when written.
    pub port: Option<u16>,
}

impl SiteAddress {
    /// Effective port for this address.
    pub fn effective_port(&self, http_port: u16, https_port: u16) -> u16 {
        if let Some(port) = self.port {
            return port;
        }
        match self.scheme.as_deref() {
            Some("http") => http_port,
            Some("https") => https_port,
            _ => https_port,
        }
    }

    /// Whether this address implies TLS.
    pub fn is_https(&self, http_port: u16, https_port: u16) -> bool {
        match self.scheme.as_deref() {
            Some("http") => false,
            Some("https") => true,
            _ => self.effective_port(http_port, https_port) != http_port,
        }
    }
}

/// One directive (or matcher definition, `@name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// Directive name.
    pub name: String,
    /// Arguments on the directive line.
    pub args: Vec<String>,
    /// Nested block, if any.
    pub block: Vec<Directive>,
    /// Source position of the name.
    pub position: Position,
}

/// A named route definition (`&(name) { ... }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedRoute {
    /// Route name, without the `&(` / `)` delimiters.
    pub name: String,
    /// Directives inside the route block.
    pub directives: Vec<Directive>,
    /// Source position of the definition.
    pub position: Position,
}

/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Lexing failed.
    #[error(transparent)]
    Lex(#[from] LexError),
    /// Grammar error.
    #[error("Caddyfile {}: {}", position, message)]
    Syntax {
        /// Location.
        position: Position,
        /// Diagnosis.
        message: String,
    },
}

impl ParseError {
    fn syntax(position: Position, message: impl Into<String>) -> Self {
        Self::Syntax {
            position,
            message: message.into(),
        }
    }
}

/// Result of Caddyfile preprocessing: the source with environment placeholders substituted,
/// plus any non-fatal diagnostics found while expanding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvExpansion {
    /// Source text with `{$ENV}` / `{$ENV:default}` placeholders replaced.
    pub source: String,
    /// Non-fatal diagnostics, one per missing variable without a default.
    pub warnings: Vec<String>,
}

/// Replace `{$ENV}` and `{$ENV:default}` placeholders in raw Caddyfile source using the process
/// environment.
///
/// This is Caddy's preprocessing step (`replaceEnvVars` in
/// `caddyconfig/caddyfile/parse.go`): it runs on the raw source *before* lexing, so values may
/// contain any characters (including whitespace, braces, or newlines) and are lexed as if written
/// literally. Expansion is one level deep: a value that itself looks like `{$OTHER}` is not
/// expanded again.
///
/// Caddy has no escape sequence for this syntax: a backslash before `{$` does not prevent
/// expansion (the backslash survives into the token text), and `\{$...}` therefore expands like
/// `{$...}`. Malformed spans are left untouched: `{$}`, an unterminated `{$FOO`, and `{ $FOO}`
/// (with a space before the `$`) are not placeholders. A value that literally contains `{$NAME}`
/// can only be produced by an environment variable's own value (which is not re-expanded).
pub fn expand_env_vars(input: &str) -> EnvExpansion {
    expand_env_vars_with(input, |name| {
        std::env::var_os(name).map(|value| value.to_string_lossy().into_owned())
    })
}

/// Like [`expand_env_vars`], but resolves variable names with `lookup` instead of the process
/// environment. Useful for embedding and for tests.
pub fn expand_env_vars_with<F>(input: &str, lookup: F) -> EnvExpansion
where
    F: Fn(&str) -> Option<String>,
{
    let mut source = input.to_string();
    let mut warnings = Vec::new();
    let mut offset = 0;
    // Replacements may add or remove line breaks (an environment value can contain them). Keep
    // the accumulated delta so warnings still point at the line in the caller's original source.
    let mut newline_shift: i64 = 0;
    loop {
        let Some(relative_begin) = source[offset..].find("{$") else {
            break;
        };
        let begin = offset + relative_begin;
        let Some(relative_end) = source[begin + 2..].find('}') else {
            // Unterminated placeholder: Caddy stops scanning the whole input here.
            break;
        };
        let end = begin + 2 + relative_end;

        let placeholder = source[begin + 2..end].to_string();
        if placeholder.is_empty() {
            // `{$}` is not a placeholder; skip past it without rewriting anything.
            offset = end + 1;
            continue;
        }

        let (name, default) = match placeholder.split_once(':') {
            Some((name, default)) => (name, Some(default.to_string())),
            None => (placeholder.as_str(), None),
        };
        let value = match lookup(name) {
            Some(value) => value,
            None => match default {
                Some(default) => default,
                None => {
                    let current_line = source[..begin].matches('\n').count() as i64 + 1;
                    let line = (current_line - newline_shift).max(1);
                    warnings.push(format!(
                        "Caddyfile line {line}: environment variable `{name}` is not set and \
                         has no default; substituted an empty string"
                    ));
                    String::new()
                }
            },
        };

        let removed_newlines = source[begin..=end].matches('\n').count() as i64;
        let inserted_newlines = value.matches('\n').count() as i64;
        newline_shift += inserted_newlines - removed_newlines;
        let value_len = value.len();
        source.replace_range(begin..=end, &value);
        // Continue after the replacement so that placeholder-looking environment values are not
        // expanded recursively (Caddy's one-level-deep behaviour).
        offset = begin + value_len;
    }
    EnvExpansion { source, warnings }
}

/// Parse a Caddyfile.
pub fn parse(input: &str) -> Result<Caddyfile, ParseError> {
    let expansion = expand_env_vars(input);
    let tokens = lex(&expansion.source)?;
    let parser = Parser::new(tokens);
    let mut file = parser.parse_file()?;
    let mut warnings = expansion.warnings;
    warnings.append(&mut file.options.warnings);
    file.options.warnings = warnings;
    Ok(file)
}

/// Directives that must never be parsed as a site address. Caddy produces a specific diagnostic
/// for this confusion; the adapter rejects it explicitly.
const KNOWN_DIRECTIVES: &[&str] = &[
    "respond",
    "redir",
    "file_server",
    "root",
    "method",
    "reverse_proxy",
    "header",
    "encode",
    "route",
    "handle",
    "handle_path",
    "tls",
    "log",
    "uri",
    "rewrite",
    "try_files",
    "handle_response",
    "map",
    "invoke",
    "acme_server",
    "php_fastcgi",
    "templates",
    "request_body",
    "basic_auth",
    "forward_auth",
    "rate_limit",
];

/// Tracks import edges between snippets so recursive imports can be rejected with Caddy's
/// diagnostic. Node names follow Caddy: the top-level file is `Caddyfile`, and a token that came
/// from snippet `name` belongs to node `Caddyfile:name`.
#[derive(Debug, Default)]
struct ImportGraph {
    nodes: BTreeSet<String>,
    edges: BTreeMap<String, Vec<String>>,
}

impl ImportGraph {
    fn add_node(&mut self, name: &str) {
        self.nodes.insert(name.to_string());
    }

    fn add_edge(&mut self, from: &str, to: &str) -> Result<(), String> {
        if !self.nodes.contains(from) || !self.nodes.contains(to) {
            return Err("one of the nodes does not exist".to_string());
        }
        if self.will_cycle(to, from) {
            return Err(format!("a cycle of imports exists between {from} and {to}"));
        }
        if self
            .edges
            .get(from)
            .is_some_and(|targets| targets.iter().any(|target| target == to))
        {
            return Ok(());
        }
        self.edges
            .entry(from.to_string())
            .or_default()
            .push(to.to_string());
        Ok(())
    }

    /// Whether following edges from `start` reaches `goal` (Caddy's `willCycle`).
    fn will_cycle(&self, start: &str, goal: &str) -> bool {
        if start == goal {
            return true;
        }
        let mut seen = BTreeSet::new();
        let mut stack = vec![start.to_string()];
        while let Some(node) = stack.pop() {
            if !seen.insert(node.clone()) {
                continue;
            }
            if let Some(targets) = self.edges.get(&node) {
                for target in targets {
                    if target == goal {
                        return true;
                    }
                    stack.push(target.clone());
                }
            }
        }
        false
    }
}

/// Node name for the token currently being parsed, given the snippet it came from.
fn import_node_name(snippet: Option<&str>) -> String {
    match snippet {
        Some(name) => format!("Caddyfile:{name}"),
        None => "Caddyfile".to_string(),
    }
}

struct Parser {
    tokens: Vec<Token>,
    /// Snippet context of each token (the snippet definition the token came from, if any). Kept
    /// aligned with `tokens` across splices; used only for import-cycle diagnostics.
    contexts: Vec<Option<String>>,
    cursor: usize,
    snippets: BTreeMap<String, Vec<Token>>,
    named_routes: Vec<NamedRoute>,
    import_graph: ImportGraph,
    warnings: Vec<String>,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        let contexts = vec![None; tokens.len()];
        Self {
            tokens,
            contexts,
            cursor: 0,
            snippets: BTreeMap::new(),
            named_routes: Vec::new(),
            import_graph: ImportGraph::default(),
            warnings: Vec::new(),
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }

    fn advance(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.cursor).cloned();
        if token.is_some() {
            self.cursor += 1;
        }
        token
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek().map(|t| t.kind), Some(TokenKind::Newline)) {
            self.cursor += 1;
        }
    }

    fn peek_is_word(&self, word: &str) -> bool {
        matches!(
            self.peek(),
            Some(Token {
                kind: TokenKind::Word,
                text,
                ..
            }) if text == word
        )
    }

    fn current_context(&self) -> Option<String> {
        self.contexts.get(self.cursor).cloned().flatten()
    }

    /// Splice `new_tokens` over `start..end`, keeping token/context arrays aligned.
    fn splice(
        &mut self,
        start: usize,
        end: usize,
        new_tokens: Vec<Token>,
        new_contexts: Vec<Option<String>>,
    ) {
        debug_assert_eq!(new_tokens.len(), new_contexts.len());
        self.tokens.splice(start..end, new_tokens);
        self.contexts.splice(start..end, new_contexts);
    }

    fn parse_file(mut self) -> Result<Caddyfile, ParseError> {
        self.skip_newlines();
        let mut options = GlobalOptions::default();
        if matches!(self.peek().map(|t| t.kind), Some(TokenKind::LeftBrace)) {
            let position = self.advance().expect("peeked").position;
            let directives = self.parse_directives(position, true)?;
            options = read_global_options(directives)?;
            self.skip_newlines();
        }

        let mut sites = Vec::new();
        loop {
            self.skip_newlines();
            if self.peek().is_none() {
                break;
            }
            // A top-level import is spliced in place; it may expand to snippets, named routes,
            // or whole site blocks, so restart the loop on the new tokens.
            if self.peek_is_word("import") {
                self.expand_import()?;
                continue;
            }
            let Some(first) = self.peek() else { break };
            let position = first.position;
            let mut raw_addresses = Vec::new();
            while let Some(token) = self.peek() {
                match token.kind {
                    TokenKind::Word | TokenKind::Quoted => {
                        raw_addresses.push(token.text.clone());
                        self.cursor += 1;
                    }
                    _ => break,
                }
            }
            if raw_addresses.is_empty() {
                let token = self.peek().expect("not eof");
                return Err(ParseError::syntax(
                    token.position,
                    format!("expected a site address, found `{}`", token.text),
                ));
            }
            // Snippet definitions and named routes share the site-address syntax of a single
            // parenthesised key; Caddy detects them after reading the addresses.
            if raw_addresses.len() == 1 {
                let raw = raw_addresses[0].as_str();
                if raw.len() >= 3 && raw.starts_with('(') && raw.ends_with(')') {
                    self.define_snippet(&raw[1..raw.len() - 1], position)?;
                    continue;
                }
                if raw.starts_with("&(") && raw.ends_with(')') {
                    self.define_named_route(&raw[2..raw.len() - 1], position)?;
                    continue;
                }
            }
            let addresses = parse_addresses(&raw_addresses, position)?;
            if raw_addresses.len() == 1 {
                let candidate = raw_addresses[0].trim_end_matches(',');
                if KNOWN_DIRECTIVES.contains(&candidate) {
                    return Err(ParseError::syntax(
                        position,
                        format!(
                            "parsed `{candidate}` as a site address, but it is a known directive; \
                             directives must appear in a site block"
                        ),
                    ));
                }
            }
            let directives = match self.peek().map(|t| t.kind) {
                Some(TokenKind::LeftBrace) => {
                    self.cursor += 1;
                    self.parse_directives(position, true)?
                }
                _ => {
                    // Caddy allows a single site block without braces. Everything remaining in the
                    // file belongs to it.
                    self.skip_newlines();
                    let mut directives = Vec::new();
                    loop {
                        self.skip_newlines();
                        if self.peek().is_none() {
                            break;
                        }
                        if self.peek_is_word("import") {
                            self.expand_import()?;
                            continue;
                        }
                        if matches!(self.peek().map(|t| t.kind), Some(TokenKind::RightBrace)) {
                            let token = self.peek().expect("peeked");
                            return Err(ParseError::syntax(
                                token.position,
                                "unexpected `}` with no matching `{`",
                            ));
                        }
                        self.parse_directives_until_newline(&mut directives)?;
                    }
                    directives
                }
            };
            sites.push(SiteBlock {
                addresses,
                directives,
                position,
            });
        }

        if sites.is_empty() {
            return Err(ParseError::syntax(
                Position { line: 1, column: 1 },
                "Caddyfile contains no site blocks",
            ));
        }
        self.validate_invokes(&sites)?;
        options.warnings.append(&mut self.warnings);
        Ok(Caddyfile {
            options,
            sites,
            named_routes: self.named_routes,
        })
    }

    /// Read a `{ ... }` block starting at the cursor (which must be `{`) and return the tokens
    /// between the braces, leaving the cursor after the matching `}`.
    fn collect_braced_block(&mut self, opener: Position) -> Result<Vec<Token>, ParseError> {
        debug_assert!(matches!(
            self.peek().map(|t| t.kind),
            Some(TokenKind::LeftBrace)
        ));
        self.cursor += 1;
        let mut depth = 1usize;
        let mut tokens = Vec::new();
        loop {
            let Some(token) = self.advance() else {
                return Err(ParseError::syntax(
                    opener,
                    "unclosed `{`: expected a matching `}`",
                ));
            };
            match token.kind {
                TokenKind::LeftBrace => {
                    depth += 1;
                    tokens.push(token);
                }
                TokenKind::RightBrace => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(tokens);
                    }
                    tokens.push(token);
                }
                _ => tokens.push(token),
            }
        }
    }

    /// Register `(name) { ... }`.
    fn define_snippet(&mut self, name: &str, position: Position) -> Result<(), ParseError> {
        if !matches!(self.peek().map(|t| t.kind), Some(TokenKind::LeftBrace)) {
            return Err(ParseError::syntax(
                position,
                format!("snippet `({name})` must be followed by a `{{` block"),
            ));
        }
        let tokens = self.collect_braced_block(position)?;
        if self.snippets.contains_key(name) {
            return Err(ParseError::syntax(
                position,
                format!("redeclaration of previously declared snippet {name}"),
            ));
        }
        self.snippets.insert(name.to_string(), tokens);
        Ok(())
    }

    /// Register `&(name) { ... }`.
    fn define_named_route(&mut self, name: &str, position: Position) -> Result<(), ParseError> {
        if !matches!(self.peek().map(|t| t.kind), Some(TokenKind::LeftBrace)) {
            return Err(ParseError::syntax(
                position,
                format!("named route `&({name})` must be followed by a `{{` block"),
            ));
        }
        self.cursor += 1;
        let directives = self.parse_directives(position, true)?;
        if self.named_routes.iter().any(|route| route.name == name) {
            return Err(ParseError::syntax(
                position,
                format!("cannot have duplicate named_routes: {name}"),
            ));
        }
        self.named_routes.push(NamedRoute {
            name: name.to_string(),
            directives,
            position,
        });
        Ok(())
    }

    /// Reject `invoke` directives that reference undefined named routes, transitively from site
    /// blocks. Named routes that no site invokes are not validated, matching Caddy (their targets
    /// are only resolved when attached to a server).
    fn validate_invokes(&self, sites: &[SiteBlock]) -> Result<(), ParseError> {
        let mut pending: Vec<(String, Position)> = Vec::new();
        for site in sites {
            collect_invokes(&site.directives, &mut pending);
        }
        let mut visited: BTreeSet<String> = BTreeSet::new();
        while let Some((name, position)) = pending.pop() {
            if !visited.insert(name.clone()) {
                continue;
            }
            let Some(route) = self.named_routes.iter().find(|route| route.name == name) else {
                return Err(ParseError::syntax(
                    position,
                    format!("cannot invoke named route '{name}', which was not defined"),
                ));
            };
            collect_invokes(&route.directives, &mut pending);
        }
        Ok(())
    }

    fn parse_directives(
        &mut self,
        opener: Position,
        require_closing_brace: bool,
    ) -> Result<Vec<Directive>, ParseError> {
        let mut directives = Vec::new();
        loop {
            self.skip_newlines();
            let Some(token) = self.peek() else {
                if require_closing_brace {
                    return Err(ParseError::syntax(
                        opener,
                        "unclosed `{`: expected a matching `}`",
                    ));
                }
                break;
            };
            match token.kind {
                TokenKind::RightBrace if require_closing_brace => {
                    self.cursor += 1;
                    break;
                }
                TokenKind::RightBrace => {
                    return Err(ParseError::syntax(
                        token.position,
                        "unexpected `}` with no matching `{`",
                    ));
                }
                TokenKind::LeftBrace => {
                    return Err(ParseError::syntax(
                        token.position,
                        "unexpected `{`; expected a directive name",
                    ));
                }
                _ => {
                    if self.peek_is_word("import") {
                        self.expand_import()?;
                        continue;
                    }
                    self.parse_directives_until_newline(&mut directives)?;
                }
            }
        }
        Ok(directives)
    }

    fn parse_directives_until_newline(
        &mut self,
        out: &mut Vec<Directive>,
    ) -> Result<(), ParseError> {
        let Some(name_token) = self.advance() else {
            return Ok(());
        };
        if matches!(name_token.kind, TokenKind::Newline) {
            return Ok(());
        }
        if matches!(
            name_token.kind,
            TokenKind::LeftBrace | TokenKind::RightBrace
        ) {
            return Err(ParseError::syntax(
                name_token.position,
                format!("unexpected `{}`", name_token.text),
            ));
        }
        let mut args = Vec::new();
        loop {
            match self.peek().map(|t| (&t.kind, &t.text)) {
                Some((TokenKind::Word | TokenKind::Quoted, text)) => {
                    args.push(text.clone());
                    self.cursor += 1;
                }
                _ => break,
            }
        }
        let block = if matches!(self.peek().map(|t| t.kind), Some(TokenKind::LeftBrace)) {
            self.cursor += 1;
            self.parse_directives(name_token.position, true)?
        } else {
            if matches!(self.peek().map(|t| t.kind), Some(TokenKind::Newline)) {
                self.cursor += 1;
            }
            Vec::new()
        };
        out.push(Directive {
            name: name_token.text,
            args,
            block,
            position: name_token.position,
        });
        Ok(())
    }

    /// Expand the `import` directive at the cursor by splicing the imported tokens in its place,
    /// mirroring Caddy's `doImport`. The cursor ends up on the first spliced token.
    fn expand_import(&mut self) -> Result<(), ParseError> {
        let import_index = self.cursor;
        let import_position = self.tokens[import_index].position;
        let import_context = self.current_context();
        self.cursor += 1;

        // The import target and any replacement arguments must be on the directive's line.
        let mut raw_args = Vec::new();
        while let Some(token) = self.peek() {
            match token.kind {
                TokenKind::Word | TokenKind::Quoted => {
                    raw_args.push(token.text.clone());
                    self.cursor += 1;
                }
                _ => break,
            }
        }
        let Some(pattern) = raw_args.first().cloned() else {
            return Err(ParseError::syntax(
                import_position,
                "wrong argument count; expecting at least 1 argument",
            ));
        };
        if pattern.is_empty() {
            return Err(ParseError::syntax(
                import_position,
                "Import requires a non-empty filepath",
            ));
        }
        let args = raw_args[1..].to_vec();

        // An optional block that opens on the same line provides `{block}`/`{blocks.NAME}` values.
        let mut block_tokens = Vec::new();
        if matches!(self.peek().map(|t| t.kind), Some(TokenKind::LeftBrace)) {
            block_tokens = self.collect_braced_block(import_position)?;
        }
        let end = self.cursor;
        let mapping = build_block_mapping(&block_tokens, import_position)?;
        let block_tokens = trim_newlines(block_tokens);

        let Some(imported) = self.snippets.get(&pattern).cloned() else {
            return Err(ParseError::syntax(
                import_position,
                format!(
                    "File to import not found: {pattern}; file and glob imports are not supported \
                     by this build yet, only snippets defined in this Caddyfile can be imported"
                ),
            ));
        };

        // Cycle detection, matching Caddy's import graph and diagnostic.
        let from = import_node_name(import_context.as_deref());
        let to = format!("Caddyfile:{pattern}");
        self.import_graph.add_node(&from);
        self.import_graph.add_node(&to);
        if let Err(message) = self.import_graph.add_edge(&from, &to) {
            return Err(ParseError::syntax(import_position, message));
        }

        let (tokens, contexts) = self.substitute_import(
            &imported,
            &args,
            &block_tokens,
            &mapping,
            import_context.as_deref(),
            &pattern,
        );
        self.splice(import_index, end, tokens, contexts);
        self.cursor = import_index;
        Ok(())
    }

    /// Apply argument/block substitution to imported snippet tokens and tag them with their
    /// snippet context for import-cycle diagnostics.
    fn substitute_import(
        &mut self,
        imported: &[Token],
        args: &[String],
        block_tokens: &[Token],
        mapping: &BTreeMap<String, Vec<Token>>,
        import_context: Option<&str>,
        snippet_name: &str,
    ) -> (Vec<Token>, Vec<Option<String>>) {
        let snippet_context = Some(snippet_name.to_string());
        let imported_context = import_context.map(str::to_string);
        let mut out_tokens: Vec<Token> = Vec::new();
        let mut out_contexts: Vec<Option<String>> = Vec::new();
        let mut index = 0;
        while index < imported.len() {
            let token = &imported[index];
            // Snippet definitions inside imported content are copied verbatim so their bodies are
            // not argument-replaced (Caddy's `maybeSnippet` logic).
            if at_line_start(&out_tokens)
                && is_snippet_name(&token.text)
                && matches!(
                    imported.get(index + 1).map(|next| next.kind),
                    Some(TokenKind::LeftBrace)
                )
            {
                out_tokens.push(token.clone());
                out_contexts.push(snippet_context.clone());
                index += 1;
                let mut depth = 0usize;
                while index < imported.len() {
                    let nested = &imported[index];
                    match nested.kind {
                        TokenKind::LeftBrace => depth += 1,
                        TokenKind::RightBrace => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                    out_tokens.push(nested.clone());
                    out_contexts.push(snippet_context.clone());
                    index += 1;
                    if depth == 0 && nested.kind == TokenKind::RightBrace {
                        break;
                    }
                }
                continue;
            }
            match token.kind {
                TokenKind::Newline | TokenKind::LeftBrace | TokenKind::RightBrace => {
                    out_tokens.push(token.clone());
                    out_contexts.push(snippet_context.clone());
                }
                _ => {
                    if token.text == "{block}" {
                        for block in block_tokens {
                            out_tokens.push(block.clone());
                            out_contexts.push(imported_context.clone());
                        }
                    } else if token.text.starts_with("{blocks.") && token.text.ends_with('}') {
                        let key = &token.text["{blocks.".len()..token.text.len() - 1];
                        if let Some(value) = mapping.get(key) {
                            for block in value {
                                out_tokens.push(block.clone());
                                out_contexts.push(imported_context.clone());
                            }
                        }
                    } else if let Some((start, range_end)) =
                        parse_variadic(&token.text, args.len(), &mut self.warnings, token.position)
                    {
                        for arg in &args[start..range_end] {
                            let mut replaced = token.clone();
                            replaced.text = arg.clone();
                            out_tokens.push(replaced);
                            out_contexts.push(snippet_context.clone());
                        }
                    } else {
                        let mut replaced = token.clone();
                        replaced.text = replace_args_placeholders(
                            &token.text,
                            args,
                            &mut self.warnings,
                            token.position,
                        );
                        out_tokens.push(replaced);
                        out_contexts.push(snippet_context.clone());
                    }
                }
            }
            index += 1;
        }
        (out_tokens, out_contexts)
    }
}

fn at_line_start(tokens: &[Token]) -> bool {
    tokens
        .last()
        .is_none_or(|token| token.kind == TokenKind::Newline)
}

fn is_snippet_name(text: &str) -> bool {
    text.len() >= 3 && text.starts_with('(') && text.ends_with(')')
}

/// Remove newline tokens at the boundaries of a token run, so spliced blocks do not introduce
/// blank directives.
fn trim_newlines(mut tokens: Vec<Token>) -> Vec<Token> {
    while tokens
        .first()
        .is_some_and(|token| token.kind == TokenKind::Newline)
    {
        tokens.remove(0);
    }
    while tokens
        .last()
        .is_some_and(|token| token.kind == TokenKind::Newline)
    {
        tokens.pop();
    }
    tokens
}

/// Turn the block after an `import` into named sub-blocks (`{blocks.NAME}` values).
fn build_block_mapping(
    tokens: &[Token],
    position: Position,
) -> Result<BTreeMap<String, Vec<Token>>, ParseError> {
    let mut mapping = BTreeMap::new();
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index].kind {
            TokenKind::Newline => {
                index += 1;
                continue;
            }
            TokenKind::LeftBrace => {
                return Err(ParseError::syntax(
                    position,
                    "anonymous blocks are not supported",
                ));
            }
            TokenKind::RightBrace => break,
            _ => {}
        }
        let key = tokens[index].text.clone();
        index += 1;
        let mut value = Vec::new();
        while index < tokens.len() {
            match tokens[index].kind {
                TokenKind::Newline | TokenKind::LeftBrace | TokenKind::RightBrace => break,
                _ => {
                    value.push(tokens[index].clone());
                    index += 1;
                }
            }
        }
        // A nested block must open on the same line as the sub-block key (Caddy's NextBlock).
        if matches!(
            tokens.get(index).map(|token| token.kind),
            Some(TokenKind::LeftBrace)
        ) {
            index += 1;
            let mut depth = 1usize;
            while index < tokens.len() {
                let token = &tokens[index];
                match token.kind {
                    TokenKind::LeftBrace => {
                        depth += 1;
                        value.push(token.clone());
                    }
                    TokenKind::RightBrace => {
                        depth -= 1;
                        if depth == 0 {
                            index += 1;
                            break;
                        }
                        value.push(token.clone());
                    }
                    _ => value.push(token.clone()),
                }
                index += 1;
            }
        }
        mapping.insert(key, trim_newlines(value));
    }
    Ok(mapping)
}

fn push_import_warning(warnings: &mut Vec<String>, position: Position, message: String) {
    warnings.push(format!("Caddyfile line {}: {message}", position.line));
}

/// Parse a whole-token variadic argument placeholder (`{args[:]}`, `{args[1:]}`, `{args[1:3]}`)
/// into an argument range. Returns `None` for anything that is not a valid variadic placeholder;
/// Caddy logs a warning for malformed forms and leaves the token untouched.
fn parse_variadic(
    text: &str,
    arg_count: usize,
    warnings: &mut Vec<String>,
    position: Position,
) -> Option<(usize, usize)> {
    let inner = text.strip_prefix("{args[")?.strip_suffix("]}")?;
    if inner.is_empty() {
        push_import_warning(
            warnings,
            position,
            format!("Placeholder {text} cannot have an empty index"),
        );
        return None;
    }
    let (start_text, end_text) = inner.split_once(':')?;
    // A token may contain several placeholders separated by `:`; that is not variadic.
    if start_text.contains('}') || end_text.contains('{') {
        return None;
    }
    let start = if start_text.is_empty() {
        0
    } else {
        match start_text.parse::<usize>() {
            Ok(value) => value,
            Err(_) => {
                push_import_warning(
                    warnings,
                    position,
                    format!("Variadic placeholder {text} has an invalid start index"),
                );
                return None;
            }
        }
    };
    let end = if end_text.is_empty() {
        arg_count
    } else {
        match end_text.parse::<usize>() {
            Ok(value) => value,
            Err(_) => {
                push_import_warning(
                    warnings,
                    position,
                    format!("Variadic placeholder {text} has an invalid end index"),
                );
                return None;
            }
        }
    };
    if start > end || end > arg_count {
        push_import_warning(
            warnings,
            position,
            format!(
                "Variadic placeholder {text} indices are out of bounds, only {arg_count} \
                 argument(s) exist"
            ),
        );
        return None;
    }
    Some((start, end))
}

/// Replace `{args[N]}` and the deprecated `{args.N}` placeholders inside a token's text.
fn replace_args_placeholders(
    text: &str,
    args: &[String],
    warnings: &mut Vec<String>,
    position: Position,
) -> String {
    if !text.contains('{') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let key = &after[..close];
        if let Some(value) = resolve_args_key(key, args, warnings, position) {
            out.push_str(&value);
        } else {
            out.push('{');
            out.push_str(key);
            out.push('}');
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

fn resolve_args_key(
    key: &str,
    args: &[String],
    warnings: &mut Vec<String>,
    position: Position,
) -> Option<String> {
    // Deprecated `{args.N}` form.
    if let Some(index_text) = key.strip_prefix("args.") {
        if index_text.is_empty() || index_text.contains(['{', '}']) {
            return None;
        }
        let index: usize = match index_text.parse() {
            Ok(value) => value,
            Err(_) => {
                push_import_warning(
                    warnings,
                    position,
                    format!("Placeholder {{{key}}} has an invalid index"),
                );
                return None;
            }
        };
        if index >= args.len() {
            push_import_warning(
                warnings,
                position,
                format!(
                    "Placeholder {{{key}}} index is out of bounds, only {} argument(s) exist",
                    args.len()
                ),
            );
            return None;
        }
        push_import_warning(
            warnings,
            position,
            format!("Placeholder {{{key}}} deprecated, use {{args[{index}]}} instead"),
        );
        return Some(args[index].clone());
    }

    let inner = key.strip_prefix("args[")?.strip_suffix(']')?;
    if inner.contains(':') {
        push_import_warning(
            warnings,
            position,
            format!("Variadic placeholder {{{key}}} must be a token on its own"),
        );
        return None;
    }
    let index: usize = match inner.parse() {
        Ok(value) => value,
        Err(_) => {
            push_import_warning(
                warnings,
                position,
                format!("Placeholder {{{key}}} has an invalid index"),
            );
            return None;
        }
    };
    if index >= args.len() {
        push_import_warning(
            warnings,
            position,
            format!(
                "Placeholder {{{key}}} index is out of bounds, only {} argument(s) exist",
                args.len()
            ),
        );
        return None;
    }
    Some(args[index].clone())
}

fn collect_invokes(directives: &[Directive], out: &mut Vec<(String, Position)>) {
    for directive in directives {
        if directive.name == "invoke" {
            if let Some(name) = directive.args.first() {
                out.push((name.clone(), directive.position));
            }
        }
        collect_invokes(&directive.block, out);
    }
}

fn parse_addresses(
    raw_addresses: &[String],
    position: Position,
) -> Result<Vec<SiteAddress>, ParseError> {
    let mut addresses = Vec::new();
    for raw in raw_addresses {
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            addresses.push(parse_address(part, position)?);
        }
    }
    if addresses.is_empty() {
        return Err(ParseError::syntax(position, "site has no usable address"));
    }
    Ok(addresses)
}

fn parse_address(raw: &str, position: Position) -> Result<SiteAddress, ParseError> {
    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_string()), rest),
        None => (None, raw),
    };
    if let Some(scheme) = &scheme {
        if scheme != "http" && scheme != "https" {
            return Err(ParseError::syntax(
                position,
                format!("unsupported URL scheme `{scheme}://`; only http and https are supported"),
            ));
        }
    }
    let (host, port) =
        split_host_port(rest).map_err(|message| ParseError::syntax(position, message))?;
    Ok(SiteAddress {
        raw: raw.to_string(),
        scheme,
        host,
        port,
    })
}

fn split_host_port(input: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = input.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err("unclosed IPv6 literal".to_string());
        };
        let host = input[..end + 2].to_string();
        let tail = &input[end + 2..];
        let port = if tail.is_empty() {
            None
        } else if let Some(port) = tail.strip_prefix(':') {
            Some(parse_port(port)?)
        } else {
            return Err(format!("unexpected `{tail}` after IPv6 literal"));
        };
        return Ok((host, port));
    }
    match input.rsplit_once(':') {
        Some((host, port)) if !port.contains('/') => {
            Ok((host.to_string(), Some(parse_port(port)?)))
        }
        _ => Ok((input.to_string(), None)),
    }
}

fn parse_port(port: &str) -> Result<u16, String> {
    port.parse::<u16>()
        .map_err(|_| format!("port `{port}` is not a valid TCP/UDP port (0-65535)"))
}

fn read_global_options(directives: Vec<Directive>) -> Result<GlobalOptions, ParseError> {
    let mut options = GlobalOptions::default();
    for directive in directives {
        match directive.name.as_str() {
            "auto_https" => {
                let mode = directive.args.first().map(String::as_str).unwrap_or("");
                options.auto_https = Some(match mode {
                    "off" => AutoHttpsMode::Off,
                    "disable_redirects" => AutoHttpsMode::DisableRedirects,
                    "ignore_loaded_certs" => AutoHttpsMode::IgnoreLoadedCerts,
                    other => {
                        return Err(ParseError::syntax(
                            directive.position,
                            format!(
                                "unknown auto_https mode `{other}`; expected off, disable_redirects, or ignore_loaded_certs"
                            ),
                        ))
                    }
                });
            }
            "http_port" => {
                options.http_port = Some(global_port(&directive)?);
            }
            "https_port" => {
                options.https_port = Some(global_port(&directive)?);
            }
            "email" | "acme_ca" | "acme_ca_root" | "acme_dns" | "local_certs" | "debug" => {
                return Err(ParseError::syntax(
                    directive.position,
                    format!(
                        "global option `{}` is not implemented by this build (tracked as T-CONF-011); \
                         it is rejected rather than silently ignored",
                        directive.name
                    ),
                ))
            }
            other => {
                return Err(ParseError::syntax(
                    directive.position,
                    format!("unrecognized global option `{other}`"),
                ))
            }
        }
    }
    Ok(options)
}

fn global_port(directive: &Directive) -> Result<u16, ParseError> {
    let Some(value) = directive.args.first() else {
        return Err(ParseError::syntax(
            directive.position,
            format!("`{}` requires a port argument", directive.name),
        ));
    };
    parse_port(value).map_err(|message| ParseError::syntax(directive.position, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_braced_site_with_nested_blocks() {
        let file = parse(
            r#"
            example.com {
                reverse_proxy localhost:8096 {
                    header_up Host {host}
                }
            }
            "#,
        )
        .expect("parses");
        assert_eq!(file.sites.len(), 1);
        let site = &file.sites[0];
        assert_eq!(site.addresses[0].host, "example.com");
        assert_eq!(site.addresses[0].effective_port(80, 443), 443);
        assert_eq!(site.directives[0].name, "reverse_proxy");
        assert_eq!(site.directives[0].args, vec!["localhost:8096"]);
        assert_eq!(site.directives[0].block[0].name, "header_up");
    }

    #[test]
    fn parses_only_fixture_with_unbraced_single_site() {
        let file = parse(":80\n\nfile_server {\n\tpass_thru\n}\n").expect("parses");
        assert_eq!(file.sites.len(), 1);
        assert_eq!(file.sites[0].addresses[0].effective_port(80, 443), 80);
        assert_eq!(file.sites[0].directives[0].name, "file_server");
        assert_eq!(file.sites[0].directives[0].block[0].name, "pass_thru");
    }

    #[test]
    fn parses_global_options() {
        let file =
            parse("{ auto_https off\n http_port 8080\n}\n:80 {\n respond ok\n}\n").expect("parses");
        assert_eq!(file.options.auto_https, Some(AutoHttpsMode::Off));
        assert_eq!(file.options.http_port, Some(8080));
    }

    #[test]
    fn parses_named_matchers() {
        let file = parse(
            r#"
            :80 {
                @api {
                    path /api/*
                    method GET
                }
                reverse_proxy @api localhost:9000
            }
            "#,
        )
        .expect("parses");
        let directives = &file.sites[0].directives;
        assert_eq!(directives[0].name, "@api");
        assert_eq!(directives[0].block.len(), 2);
        assert_eq!(directives[1].args[0], "@api");
    }

    #[test]
    fn reports_unclosed_brace_at_opener() {
        let error = parse(":80 {\n respond ok\n").expect_err("unclosed");
        let message = error.to_string();
        assert!(message.contains("unclosed"), "{message}");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let error = parse("foo://example.com {\n respond ok\n}\n").expect_err("scheme");
        assert!(error.to_string().contains("unsupported URL scheme"));
    }

    #[test]
    fn rejects_invalid_port() {
        let error = parse(":70000 {\n respond ok\n}\n").expect_err("port");
        assert!(error.to_string().contains("70000"));
    }

    #[test]
    fn heredoc_is_a_directive_argument() {
        let file =
            parse(":80 {\n respond <<EOF\n <html>\n   <body>hi</body>\n </html>\n EOF 200\n}\n")
                .expect("parses");
        let directive = &file.sites[0].directives[0];
        assert_eq!(directive.name, "respond");
        assert_eq!(
            directive.args,
            vec![
                "<html>\n  <body>hi</body>\n</html>".to_string(),
                "200".to_string()
            ]
        );
    }

    #[test]
    fn heredoc_is_a_directive_block_argument() {
        let file = parse(
            ":80 {\n reverse_proxy localhost:9000 {\n header_up X-Test <<EOF\n yes\n EOF\n }\n}\n",
        )
        .expect("parses");
        let proxy = &file.sites[0].directives[0];
        assert_eq!(proxy.block[0].name, "header_up");
        assert_eq!(
            proxy.block[0].args,
            vec!["X-Test".to_string(), "yes".to_string()]
        );
    }

    #[test]
    fn heredoc_preserves_structure_after_closing_marker() {
        let file =
            parse(":80 {\n respond <<EOF\n {\"looks\": \"structural\"}\n EOF\n respond after\n}\n")
                .expect("parses");
        let directives = &file.sites[0].directives;
        assert_eq!(directives.len(), 2);
        assert_eq!(
            directives[0].args[0],
            "{\"looks\": \"structural\"}".to_string()
        );
        assert_eq!(directives[1].name, "respond");
    }

    #[test]
    fn backslash_continuation_chains_arguments() {
        let file = parse(":80 {\n respond hello \\\n world\n}\n").expect("parses");
        assert_eq!(
            file.sites[0].directives[0].args,
            vec!["hello".to_string(), "world".to_string()]
        );
        assert_eq!(file.sites[0].directives.len(), 1);
    }

    #[test]
    fn env_placeholders_expand_before_parsing() {
        let expansion =
            expand_env_vars_with("example.com {\n respond {$GREETING:hello}\n}\n", |name| {
                (name == "GREETING").then(|| "hi there".to_string())
            });
        assert_eq!(expansion.source, "example.com {\n respond hi there\n}\n");
        assert!(expansion.warnings.is_empty());

        let expansion = expand_env_vars_with(":{$PORT}\nrespond {$MISSING}\n", |name| {
            (name == "PORT").then(|| "8080".to_string())
        });
        assert_eq!(expansion.source, ":8080\nrespond \n");
        assert_eq!(expansion.warnings.len(), 1);
        assert!(
            expansion.warnings[0].contains("`MISSING`"),
            "{:?}",
            expansion.warnings
        );
        assert!(
            expansion.warnings[0].contains("Caddyfile line 2"),
            "{:?}",
            expansion.warnings
        );
    }

    #[test]
    fn env_defaults_nested_in_site_address() {
        let file = parse(":{$PORT:8080} {\n respond ok\n}\n").expect("parses");
        assert_eq!(file.sites[0].addresses[0].port, Some(8080));
    }

    #[test]
    fn env_expansion_is_not_recursive() {
        let expansion = expand_env_vars_with("{$A}", |name| match name {
            "A" => Some("{$B}".to_string()),
            "B" => Some("nope".to_string()),
            _ => None,
        });
        assert_eq!(expansion.source, "{$B}");
        assert!(expansion.warnings.is_empty());
    }

    #[test]
    fn malformed_env_placeholders_are_left_untouched() {
        for input in ["{$}", "{$FOO", "}{$", "{ $FOO}", "{$FOO:default"] {
            let expansion = expand_env_vars_with(input, |_| None);
            assert_eq!(expansion.source, input, "input {input:?}");
            assert!(expansion.warnings.is_empty(), "input {input:?}");
        }
    }

    #[test]
    fn env_escaping_matches_caddy_no_escape_sequence() {
        // Caddy expands before lexing and has no escape for `{$`: the backslash survives.
        let expansion = expand_env_vars_with(r"\{$FOO}", |name| {
            (name == "FOO").then(|| "bar".to_string())
        });
        assert_eq!(expansion.source, r"\bar");
    }

    #[test]
    fn env_placeholder_inside_heredoc_is_expanded() {
        let expansion = expand_env_vars_with(
            "respond <<EOF\nHello {$CADDY_RS_HEREDOC_TEST_NAME:world}\nEOF\n",
            |_| None,
        );
        assert_eq!(expansion.source, "respond <<EOF\nHello world\nEOF\n");
        let file =
            parse(":80 {\n respond <<EOF\n Hello {$CADDY_RS_HEREDOC_TEST_NAME:world}\n EOF\n}\n")
                .expect("parses");
        assert_eq!(
            file.sites[0].directives[0].args,
            vec!["Hello world".to_string()]
        );
    }

    #[test]
    fn missing_env_var_warns_through_the_public_parse_result() {
        let file = parse(":80 {\n respond {$CADDY_RS_UNSET_TEST_VAR}\n}\n").expect("parses");
        assert_eq!(file.sites[0].directives[0].args, Vec::<String>::new());
        assert_eq!(
            file.options.warnings.len(),
            1,
            "{:?}",
            file.options.warnings
        );
        assert!(
            file.options.warnings[0].contains("CADDY_RS_UNSET_TEST_VAR"),
            "{:?}",
            file.options.warnings
        );
    }
    // --- snippets, imports and named routes -------------------------------------------------

    #[test]
    fn snippet_import_expands_directives() {
        let file =
            parse("(site) {\n header X-Snippet yes\n}\n:80 {\n import site\n}\n").expect("parses");
        assert_eq!(file.sites.len(), 1);
        let directives = &file.sites[0].directives;
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].name, "header");
        assert_eq!(
            directives[0].args,
            vec!["X-Snippet".to_string(), "yes".to_string()]
        );
    }

    #[test]
    fn import_arguments_replace_placeholders_in_tokens() {
        let file = parse(
            "(logging) {\n log {\n  output file /var/log/caddy/{args[0]}.log\n }\n}\n\
             a.example.com {\n import logging a.example.com\n}\n",
        )
        .expect("parses");
        let log = &file.sites[0].directives[0];
        assert_eq!(log.name, "log");
        assert_eq!(log.block[0].name, "output");
        assert_eq!(
            log.block[0].args,
            vec![
                "file".to_string(),
                "/var/log/caddy/a.example.com.log".to_string()
            ]
        );
    }

    #[test]
    fn import_variadic_arguments_splice_tokens() {
        let file = parse("(snippet) {\n respond {args[:]}\n}\n:80 {\n import snippet a b c\n}\n")
            .expect("parses");
        assert_eq!(
            file.sites[0].directives[0].args,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );

        let file = parse("(snippet) {\n respond {args[1:]}\n}\n:80 {\n import snippet a b c\n}\n")
            .expect("parses");
        assert_eq!(
            file.sites[0].directives[0].args,
            vec!["b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn import_block_placeholder_splices_the_import_block() {
        let file =
            parse("(snippet) {\n header {\n  {block}\n }\n}\nexample.com {\n import snippet {\n  foo bar\n }\n}\n")
                .expect("parses");
        let header = &file.sites[0].directives[0];
        assert_eq!(header.name, "header");
        assert_eq!(header.block[0].name, "foo");
        assert_eq!(header.block[0].args, vec!["bar".to_string()]);
    }

    #[test]
    fn import_blocks_placeholders_use_named_subblocks() {
        let file = parse(
            "(snippet) {\n header {\n  {blocks.foo}\n }\n header {\n  {blocks.bar}\n }\n}\n\
             example.com {\n import snippet {\n  foo {\n   foo a\n  }\n  bar {\n   bar b\n  }\n }\n}\n",
        )
        .expect("parses");
        let directives = &file.sites[0].directives;
        assert_eq!(directives.len(), 2);
        assert_eq!(directives[0].block[0].name, "foo");
        assert_eq!(directives[0].block[0].args, vec!["a".to_string()]);
        assert_eq!(directives[1].block[0].name, "bar");
        assert_eq!(directives[1].block[0].args, vec!["b".to_string()]);
    }

    #[test]
    fn import_without_block_drops_block_placeholders() {
        // Caddy substitutes an empty token list for `{block}` when no block was given.
        let file = parse(
            "(snippet) {\n header {\n  reverse_proxy localhost:3000\n  {block}\n }\n}\nexample.com {\n import snippet\n}\n",
        )
        .expect("parses");
        let header = &file.sites[0].directives[0];
        assert_eq!(header.block.len(), 1);
        assert_eq!(header.block[0].name, "reverse_proxy");
    }

    #[test]
    fn duplicate_snippet_is_rejected() {
        let error = parse("(a) {\n respond a\n}\n(a) {\n respond b\n}\n:80 {\n respond ok\n}\n")
            .expect_err("duplicate snippet");
        assert!(
            error
                .to_string()
                .contains("redeclaration of previously declared snippet a"),
            "{error}"
        );
    }

    #[test]
    fn import_cycle_is_rejected_with_caddy_diagnostic() {
        let error = parse(
            "(import1) {\n import import2\n}\n(import2) {\n import import1\n}\nimport import1\n",
        )
        .expect_err("cycle");
        assert_eq!(
            error.to_string(),
            "Caddyfile line 5: a cycle of imports exists between Caddyfile:import2 and \
             Caddyfile:import1",
            "{error}"
        );
    }

    #[test]
    fn undefined_import_is_rejected_by_name() {
        let error = parse(":80 {\n import nope\n}\n").expect_err("undefined import");
        assert!(
            error.to_string().contains("File to import not found: nope"),
            "{error}"
        );
    }

    #[test]
    fn file_imports_are_rejected_loudly() {
        let error = parse(":80 {\n import ./snippets/common.caddy\n}\n").expect_err("file import");
        assert!(
            error.to_string().contains("not supported by this build"),
            "{error}"
        );
        assert!(
            error.to_string().contains("./snippets/common.caddy"),
            "{error}"
        );
    }

    #[test]
    fn top_level_import_can_produce_a_site_block() {
        let file = parse(
            "(site) {\n https://{args[0]} {\n  {block}\n }\n}\nimport site test.domain {\n reverse_proxy http://192.168.1.1:8080 {\n  header_up Host {host}\n }\n}\n",
        )
        .expect("parses");
        assert_eq!(file.sites.len(), 1);
        assert_eq!(file.sites[0].addresses[0].host, "test.domain");
        let proxy = &file.sites[0].directives[0];
        assert_eq!(proxy.name, "reverse_proxy");
        assert_eq!(proxy.args, vec!["http://192.168.1.1:8080".to_string()]);
        assert_eq!(proxy.block[0].name, "header_up");
        assert_eq!(
            proxy.block[0].args,
            vec!["Host".to_string(), "{host}".to_string()]
        );
    }

    #[test]
    fn named_routes_are_parsed_and_duplicates_rejected() {
        let file =
            parse("&(api) {\n header X-Version v1\n respond api\n}\n:80 {\n respond ok\n}\n")
                .expect("parses");
        assert_eq!(file.named_routes.len(), 1);
        assert_eq!(file.named_routes[0].name, "api");
        assert_eq!(file.named_routes[0].directives.len(), 2);
        assert_eq!(file.named_routes[0].directives[0].name, "header");

        let error =
            parse("&(api) {\n respond a\n}\n&(api) {\n respond b\n}\n:80 {\n respond ok\n}\n")
                .expect_err("duplicate named route");
        assert!(
            error
                .to_string()
                .contains("cannot have duplicate named_routes: api"),
            "{error}"
        );
    }

    #[test]
    fn undefined_invoke_is_rejected_transitively() {
        let error = parse(":80 {\n invoke foo\n}\n").expect_err("undefined invoke");
        assert_eq!(
            error.to_string(),
            "Caddyfile line 2: cannot invoke named route 'foo', which was not defined"
        );

        let error = parse("&(outer) {\n invoke missing\n}\n:80 {\n invoke outer\n}\n")
            .expect_err("transitive undefined invoke");
        assert!(
            error
                .to_string()
                .contains("cannot invoke named route 'missing', which was not defined"),
            "{error}"
        );
    }

    #[test]
    fn uninvoked_named_route_targets_are_not_validated() {
        // Caddy only resolves invoke targets when a server actually attaches the named route.
        let file = parse("&(outer) {\n invoke missing\n}\n:80 {\n respond ok\n}\n")
            .expect("parses: unreferenced named route is inert");
        assert_eq!(file.named_routes.len(), 1);
    }

    #[test]
    fn import_inside_named_route_expands() {
        let file = parse(
            "(common) {\n respond \"from snippet\"\n}\n&(foo) {\n import common\n}\n:80 {\n invoke foo\n}\n",
        )
        .expect("parses");
        assert_eq!(file.named_routes.len(), 1);
        assert_eq!(file.named_routes[0].directives[0].name, "respond");
        assert_eq!(
            file.named_routes[0].directives[0].args,
            vec!["from snippet".to_string()]
        );
    }

    #[test]
    fn import_argument_problems_warn_without_failing() {
        let file = parse("(snippet) {\n respond {args.0}\n}\n:80 {\n import snippet hi\n}\n")
            .expect("parses");
        assert_eq!(file.sites[0].directives[0].args, vec!["hi".to_string()]);
        assert!(
            file.options
                .warnings
                .iter()
                .any(|warning| warning.contains("deprecated")),
            "{:?}",
            file.options.warnings
        );

        let file = parse("(snippet) {\n respond {args[5]}\n}\n:80 {\n import snippet hi\n}\n")
            .expect("parses");
        assert_eq!(
            file.sites[0].directives[0].args,
            vec!["{args[5]}".to_string()]
        );
        assert!(
            file.options
                .warnings
                .iter()
                .any(|warning| warning.contains("index is out of bounds, only 1 argument(s) exist")),
            "{:?}",
            file.options.warnings
        );
    }
}
