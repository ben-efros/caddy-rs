//! Caddyfile parser.
//!
//! Produces a small, explicit AST from the token stream. The parser intentionally supports the
//! structurally common Caddyfile forms — braced site blocks, the single unbraced site permitted by
//! Caddy, global options, named matchers, and nested directive blocks — and rejects the rest with
//! a located error.
//!
//! Before lexing, the raw source is preprocessed exactly like Caddy's
//! `caddyconfig/caddyfile/parse.go`: `{$ENV}` and `{$ENV:default}` placeholders are replaced
//! (one level deep, with the process environment consulted for the name) on the raw bytes, so
//! expansion works in site addresses, arguments, quoted strings and heredoc bodies alike.
//! Caddy emits no diagnostic when a referenced variable is unset; this implementation substitutes
//! the same empty string but also records a non-fatal warning in
//! [`GlobalOptions::warnings`], which the adapter surfaces to callers (and the CLI prints).

use crate::lexer::{lex, LexError, Position, Token, TokenKind};

/// A parsed Caddyfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caddyfile {
    /// Global options block, if present.
    pub options: GlobalOptions,
    /// Site blocks in source order.
    pub sites: Vec<SiteBlock>,
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
    let mut file = Parser { tokens, cursor: 0 }.parse_file()?;
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

struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
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
        while self.peek().is_some() {
            self.skip_newlines();
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
                    while self.peek().is_some() {
                        self.parse_directives_until_newline(&mut directives)?;
                        self.skip_newlines();
                    }
                    directives
                }
            };
            sites.push(SiteBlock {
                addresses,
                directives,
                position,
            });
            self.skip_newlines();
        }

        if sites.is_empty() {
            return Err(ParseError::syntax(
                Position { line: 1, column: 1 },
                "Caddyfile contains no site blocks",
            ));
        }
        Ok(Caddyfile { options, sites })
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
}
