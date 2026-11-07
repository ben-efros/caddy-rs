//! `http.matchers.expression`: a documented subset of Caddy's CEL expression matcher.
//!
//! Caddy v2.11.9 compiles expressions with cel-go (`modules/caddyhttp/celmatcher.go`), expands
//! `{placeholders}` into a request replacer call, and exposes CEL matcher functions such as
//! `host()`, `path()`, `method()`, `header()` and `client_ip()`. Running a full CEL engine offline
//! is not practical, so this module implements a hand-written Pratt parser and evaluator for a
//! deliberately small, honest subset:
//!
//! * boolean literals, `!`, `&&`, `||`, parentheses;
//! * string literals (`'...'`, `"..."`, CEL-style raw strings with an `r` prefix, escapes);
//! * integer literals (including unary minus);
//! * comparisons `==`, `!=`, `<`, `<=`, `>`, `>=` over strings, integers and booleans
//!   (booleans only support equality);
//! * `in` over list literals of strings, integers or booleans;
//! * Caddy placeholders `{http.request.method}`, `{http.vars.foo}`, `{http.error.status_code}`,
//!   `{http.request.header.X}`, `{http.request.cookie.session}`, ... (dynamic values resolved with
//!   the request replacer at evaluation time);
//! * caddy-rs convenience aliases for the common request fields:
//!   `request.method`, `request.host`, `request.hostport`, `request.port`, `request.path`,
//!   `request.uri`, `request.uri.path`, `request.uri.query`, `request.scheme`,
//!   `request.remote_ip`, `request.remote.host`, `request.remote.port`,
//!   `request.header("X")` / `request.header["X"]`, `request.cookie("session")` /
//!   `request.cookie["session"]`, `vars.<name>` / `vars["name"]`, and
//!   `tls.enabled`/`tls.handshake_complete` (other known `tls.*` attributes parse but evaluate to
//!   a missing value because the HTTP engine only carries a TLS boolean).
//!
//! Unknown identifiers, malformed syntax, non-boolean top-level expressions and static type
//! mismatches are located configuration errors, not request-time surprises. Missing optional
//! values follow the observed Caddy behaviour: comparisons against a missing value are false for
//! `==` and ordering, true for `!=`; missing headers, cookies and query parameters are empty
//! strings, while unset vars and unknown placeholders are missing (all verified against Caddy).
//!
//! Unsupported CEL syntax (rejected loudly): CEL matcher functions (`host()`, `path()`, `method()`,
//! `header({...})`, `client_ip()`, `path_regexp()`, `tls()`, `query()`, `vars()`, ...), macros and
//! comprehensions (`all`, `exists`, `map`, `filter`), `matches()`/regex, timestamps/durations,
//! bytes/doubles/uints, list indexing, nested lists, ternaries, and CEL's optional types. The
//! Caddyfile adapter owns adaptation of the `expression` matcher (see the task report), not this
//! module.

use std::borrow::Cow;
use std::collections::BTreeSet;

use http::HeaderName;

use crate::types::{Error, Matcher, Request, Result};

/// `http.matchers.expression` with a pre-parsed, type-checked AST.
#[derive(Debug, Clone)]
pub(crate) struct ExpressionMatcher {
    ast: Expr,
    source: String,
}

impl ExpressionMatcher {
    pub(crate) fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        // Caddy marshals the matcher as a bare JSON string when it has no name; the
        // `{ "expr": ..., "name": ... }` object form is accepted too (Caddy's MarshalJSON).
        let expression = match value {
            serde_json::Value::String(expression) => expression.as_str(),
            serde_json::Value::Object(object) => object
                .get("expr")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::InvalidConfig {
                    path: format!("{path}.expr"),
                    message: "expression matcher requires a string `expr`".to_string(),
                })?,
            _ => {
                return Err(Error::InvalidConfig {
                    path: path.to_string(),
                    message: "expression matcher must be a string expression or an object with a string `expr`"
                        .to_string(),
                })
            }
        };
        let ast = parse(expression).map_err(|message| Error::InvalidConfig {
            path: path.to_string(),
            message,
        })?;
        Ok(Self {
            ast,
            source: expression.to_string(),
        })
    }
}

impl Matcher for ExpressionMatcher {
    fn matches(&self, request: &Request) -> bool {
        matches!(evaluate(&self.ast, request), Value::Bool(true))
    }

    fn describe(&self) -> String {
        format!("expression {}", self.source)
    }
}

// ---------------------------------------------------------------------------------------------
// AST and static types

#[derive(Debug, Clone)]
enum Expr {
    Bool(bool),
    Int(i64),
    Str(String),
    Reference {
        kind: ReferenceKind,
        ty: StaticType,
    },
    Compare {
        left: Box<Expr>,
        op: CompareOp,
        right: Box<Expr>,
    },
    In {
        left: Box<Expr>,
        values: Vec<Expr>,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CompareOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }

    fn is_ordering(self) -> bool {
        matches!(self, Self::Lt | Self::Le | Self::Gt | Self::Ge)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StaticType {
    Bool,
    Int,
    String,
    /// A Caddy placeholder whose type is only known after expansion (Caddy's `ph` returns `any`).
    Dynamic,
}

impl StaticType {
    fn name(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Int => "int",
            Self::String => "string",
            Self::Dynamic => "dynamic placeholder",
        }
    }
}

#[derive(Debug, Clone)]
enum ReferenceKind {
    /// Raw Caddy placeholder, including the braces' content.
    Placeholder(String),
    Method,
    Host,
    HostPort,
    Port,
    Path,
    Uri,
    UriQuery,
    Scheme,
    RemoteIp,
    RemotePort,
    Remote,
    Header(String),
    Cookie(String),
    Var(String),
    TlsEnabled,
    TlsHandshakeComplete,
    /// A known `tls.*` attribute that the HTTP engine does not carry (evaluates to missing).
    TlsMissing,
}

impl Expr {
    fn static_type(&self) -> StaticType {
        match self {
            Self::Bool(_) => StaticType::Bool,
            Self::Int(_) => StaticType::Int,
            Self::Str(_) => StaticType::String,
            Self::Reference { ty, .. } => *ty,
            Self::Compare { .. }
            | Self::In { .. }
            | Self::And(..)
            | Self::Or(..)
            | Self::Not(_) => StaticType::Bool,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Evaluation

#[derive(Debug, Clone, PartialEq)]
enum Value<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Str(Cow<'a, str>),
}

fn evaluate<'a>(expr: &'a Expr, request: &'a Request) -> Value<'a> {
    match expr {
        Expr::Bool(value) => Value::Bool(*value),
        Expr::Int(value) => Value::Int(*value),
        Expr::Str(value) => Value::Str(Cow::Borrowed(value.as_str())),
        Expr::Reference { kind, .. } => evaluate_reference(kind, request),
        Expr::Compare { left, op, right } => {
            let left_value = evaluate(left, request);
            let right_value = evaluate(right, request);
            Value::Bool(compare(
                *op,
                left.static_type(),
                right.static_type(),
                &left_value,
                &right_value,
            ))
        }
        Expr::In { left, values } => {
            let left_value = evaluate(left, request);
            let left_type = left.static_type();
            Value::Bool(values.iter().any(|candidate| {
                let right_value = evaluate(candidate, request);
                compare(
                    CompareOp::Eq,
                    left_type,
                    candidate.static_type(),
                    &left_value,
                    &right_value,
                )
            }))
        }
        Expr::And(left, right) => {
            if !matches!(evaluate(left, request), Value::Bool(true)) {
                return Value::Bool(false);
            }
            Value::Bool(matches!(evaluate(right, request), Value::Bool(true)))
        }
        Expr::Or(left, right) => {
            if matches!(evaluate(left, request), Value::Bool(true)) {
                return Value::Bool(true);
            }
            Value::Bool(matches!(evaluate(right, request), Value::Bool(true)))
        }
        Expr::Not(value) => Value::Bool(!matches!(evaluate(value, request), Value::Bool(true))),
    }
}

fn evaluate_reference<'a>(kind: &ReferenceKind, request: &'a Request) -> Value<'a> {
    match kind {
        ReferenceKind::Placeholder(name) => {
            if let Some(header_name) = name.strip_prefix("http.request.header.") {
                return header_value(request, header_name);
            }
            if let Some(variable) = name
                .strip_prefix("http.vars.")
                .or_else(|| name.strip_prefix("vars."))
            {
                return request
                    .vars
                    .get(variable)
                    .map(|value| Value::Str(Cow::Borrowed(value.as_str())))
                    .unwrap_or(Value::Null);
            }
            if name.starts_with("http.request.tls.") {
                // The engine only carries a TLS-enabled flag; certificate/cipher metadata is not
                // available, so Caddy's TLS placeholders evaluate as missing.
                return Value::Null;
            }
            match request.get_placeholder(name) {
                Some(value) => Value::Str(Cow::Owned(value)),
                None => Value::Null,
            }
        }
        ReferenceKind::Method => Value::Str(Cow::Borrowed(request.method.as_str())),
        ReferenceKind::Host => Value::Str(Cow::Owned(
            request
                .get_placeholder("http.request.host")
                .unwrap_or_default(),
        )),
        ReferenceKind::HostPort => Value::Str(Cow::Owned(
            request
                .get_placeholder("http.request.hostport")
                .unwrap_or_default(),
        )),
        ReferenceKind::Port => Value::Str(Cow::Owned(
            request
                .get_placeholder("http.request.port")
                .unwrap_or_default(),
        )),
        ReferenceKind::Path => Value::Str(Cow::Borrowed(request.uri.path())),
        ReferenceKind::Uri => Value::Str(Cow::Owned(
            request
                .get_placeholder("http.request.uri")
                .unwrap_or_default(),
        )),
        ReferenceKind::UriQuery => Value::Str(Cow::Borrowed(request.uri.query().unwrap_or(""))),
        ReferenceKind::Scheme => {
            Value::Str(Cow::Borrowed(if request.tls { "https" } else { "http" }))
        }
        ReferenceKind::RemoteIp | ReferenceKind::RemotePort | ReferenceKind::Remote => {
            let name = match kind {
                ReferenceKind::RemoteIp => "http.request.remote.host",
                ReferenceKind::RemotePort => "http.request.remote.port",
                ReferenceKind::Remote => "http.request.remote",
                _ => unreachable!("matched remote reference"),
            };
            Value::Str(Cow::Owned(
                request.get_placeholder(name).unwrap_or_default(),
            ))
        }
        ReferenceKind::Header(name) => header_value(request, name),
        ReferenceKind::Cookie(name) => Value::Str(Cow::Owned(cookie_value(request, name))),
        ReferenceKind::Var(name) => request
            .vars
            .get(name)
            .map(|value| Value::Str(Cow::Borrowed(value.as_str())))
            .unwrap_or(Value::Null),
        ReferenceKind::TlsEnabled | ReferenceKind::TlsHandshakeComplete => Value::Bool(request.tls),
        ReferenceKind::TlsMissing => Value::Null,
    }
}

fn header_value<'a>(request: &'a Request, name: &str) -> Value<'a> {
    let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
        return Value::Null;
    };
    let mut values = request.headers.get_all(&name).iter();
    let Some(first) = values.next() else {
        // Caddy's header placeholder expands to the empty string when the header does not exist.
        return Value::Str(Cow::Borrowed(""));
    };
    let Ok(first) = first.to_str() else {
        return Value::Null;
    };
    let remaining: Vec<&str> = values.filter_map(|value| value.to_str().ok()).collect();
    if remaining.is_empty() {
        Value::Str(Cow::Borrowed(first))
    } else {
        let mut joined = first.to_string();
        for value in remaining {
            joined.push(',');
            joined.push_str(value);
        }
        Value::Str(Cow::Owned(joined))
    }
}

fn cookie_value(request: &Request, name: &str) -> String {
    request
        .get_placeholder(&format!("http.request.cookie.{name}"))
        .unwrap_or_default()
}

/// Compare two scalar values using the static types of their expressions for coercion. This is
/// CEL-ish dynamic behaviour for placeholders (`ph` yields `any`) while static aliases are
/// type-checked at load time.
fn compare(
    op: CompareOp,
    left_type: StaticType,
    right_type: StaticType,
    left: &Value<'_>,
    right: &Value<'_>,
) -> bool {
    // Caddy (CEL) semantics for missing values: `==` is false unless both are null, `!=` is true
    // unless both are null, and ordering is false.
    if matches!(left, Value::Null) || matches!(right, Value::Null) {
        return match op {
            CompareOp::Eq => matches!(left, Value::Null) && matches!(right, Value::Null),
            CompareOp::Ne => !(matches!(left, Value::Null) && matches!(right, Value::Null)),
            _ => false,
        };
    }
    let wants_int = left_type == StaticType::Int || right_type == StaticType::Int;
    let wants_bool = left_type == StaticType::Bool || right_type == StaticType::Bool;
    if wants_int {
        let (Some(left), Some(right)) = (as_int(left), as_int(right)) else {
            return false;
        };
        return match op {
            CompareOp::Eq => left == right,
            CompareOp::Ne => left != right,
            CompareOp::Lt => left < right,
            CompareOp::Le => left <= right,
            CompareOp::Gt => left > right,
            CompareOp::Ge => left >= right,
        };
    }
    if wants_bool {
        let (Some(left), Some(right)) = (as_bool(left), as_bool(right)) else {
            return false;
        };
        return match op {
            CompareOp::Eq => left == right,
            CompareOp::Ne => left != right,
            // Ordering booleans is a load-time type error; be false if it ever gets here.
            _ => false,
        };
    }
    let (Some(left), Some(right)) = (as_str(left), as_str(right)) else {
        return false;
    };
    match op {
        CompareOp::Eq => left == right,
        CompareOp::Ne => left != right,
        CompareOp::Lt => left < right,
        CompareOp::Le => left <= right,
        CompareOp::Gt => left > right,
        CompareOp::Ge => left >= right,
    }
}

fn as_int(value: &Value<'_>) -> Option<i64> {
    match value {
        Value::Int(value) => Some(*value),
        Value::Str(value) => value.trim().parse::<i64>().ok(),
        Value::Bool(_) | Value::Null => None,
    }
}

fn as_bool(value: &Value<'_>) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Str(value) => match value.trim() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        Value::Int(_) | Value::Null => None,
    }
}

fn as_str<'v>(value: &'v Value<'v>) -> Option<&'v str> {
    match value {
        Value::Str(value) => Some(value.as_ref()),
        Value::Int(_) | Value::Bool(_) | Value::Null => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Lexer

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    Placeholder(String),
    Str(String),
    Int(i64),
    True,
    False,
    In,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Dot,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
    Minus,
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    start: usize,
}

fn lex(input: &str) -> std::result::Result<Vec<Token>, String> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        // Single/double quoted strings and CEL raw strings (`r'...'`, `r"..."`).
        if byte == b'\'' || byte == b'"' {
            let (value, next) = lex_string(input, index, false)?;
            tokens.push(Token {
                kind: TokenKind::Str(value),
                start,
            });
            index = next;
            continue;
        }
        if byte == b'r'
            && index + 1 < bytes.len()
            && (bytes[index + 1] == b'\'' || bytes[index + 1] == b'"')
        {
            let (value, next) = lex_string(input, index + 1, true)?;
            tokens.push(Token {
                kind: TokenKind::Str(value),
                start,
            });
            index = next;
            continue;
        }
        if byte == b'`' {
            // CEL raw string literal: everything up to the next backtick is literal, with no
            // escape processing (a backslash and newlines are ordinary characters). A raw string
            // cannot contain a backtick; the next one always terminates it.
            let Some(relative_end) = bytes[index + 1..].iter().position(|byte| *byte == b'`')
            else {
                return Err(format!(
                    "invalid raw string literal: unterminated backtick starting at byte {index}; expected a closing backtick"
                ));
            };
            let end = index + 1 + relative_end;
            tokens.push(Token {
                kind: TokenKind::Str(input[index + 1..end].to_string()),
                start,
            });
            index = end + 1;
            continue;
        }
        if byte == b'{' {
            let Some(relative_end) = bytes[index + 1..].iter().position(|byte| *byte == b'}')
            else {
                return Err(format!(
                    "unterminated placeholder starting at byte {index}; expected `}}`"
                ));
            };
            let end = index + 1 + relative_end;
            let content = &input[index + 1..end];
            if content.trim().is_empty() {
                return Err(format!("empty placeholder at byte {index}"));
            }
            tokens.push(Token {
                kind: TokenKind::Placeholder(content.trim().to_string()),
                start,
            });
            index = end + 1;
            continue;
        }
        if byte.is_ascii_digit() {
            let mut end = index + 1;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            let value = input[index..end].parse::<i64>().map_err(|error| {
                format!(
                    "invalid integer literal `{}` at byte {index}: {error}",
                    &input[index..end]
                )
            })?;
            tokens.push(Token {
                kind: TokenKind::Int(value),
                start,
            });
            index = end;
            continue;
        }
        if is_ident_start(byte) {
            let mut end = index + 1;
            while end < bytes.len() && is_ident_continue(bytes[end]) {
                end += 1;
            }
            let ident = &input[index..end];
            let kind = match ident {
                "true" => TokenKind::True,
                "false" => TokenKind::False,
                "in" => TokenKind::In,
                _ => TokenKind::Ident(ident.to_string()),
            };
            tokens.push(Token { kind, start });
            index = end;
            continue;
        }
        let (kind, consumed) = match (byte, bytes.get(index + 1).copied()) {
            (b'=', Some(b'=')) => (TokenKind::Eq, 2),
            (b'!', Some(b'=')) => (TokenKind::Ne, 2),
            (b'<', Some(b'=')) => (TokenKind::Le, 2),
            (b'>', Some(b'=')) => (TokenKind::Ge, 2),
            (b'&', Some(b'&')) => (TokenKind::And, 2),
            (b'|', Some(b'|')) => (TokenKind::Or, 2),
            (b'<', _) => (TokenKind::Lt, 1),
            (b'>', _) => (TokenKind::Gt, 1),
            (b'!', _) => (TokenKind::Not, 1),
            (b'(', _) => (TokenKind::LParen, 1),
            (b')', _) => (TokenKind::RParen, 1),
            (b'[', _) => (TokenKind::LBracket, 1),
            (b']', _) => (TokenKind::RBracket, 1),
            (b',', _) => (TokenKind::Comma, 1),
            (b'.', _) => (TokenKind::Dot, 1),
            (b'-', _) => (TokenKind::Minus, 1),
            (other, _) => {
                return Err(format!(
                    "unsupported character `{}` at byte {index}; only the documented expression subset is implemented",
                    other as char
                ))
            }
        };
        tokens.push(Token { kind, start });
        index += consumed;
    }
    tokens.push(Token {
        kind: TokenKind::Eof,
        start: input.len(),
    });
    Ok(tokens)
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Parse a quoted string starting at `quote`, decoding CEL-style escapes unless `raw`.
fn lex_string(
    input: &str,
    quote: usize,
    raw: bool,
) -> std::result::Result<(String, usize), String> {
    let bytes = input.as_bytes();
    let delimiter = bytes[quote];
    let mut output = String::new();
    let mut index = quote + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == delimiter {
            return Ok((output, index + 1));
        }
        if !raw && byte == b'\\' {
            index += 1;
            if index >= bytes.len() {
                return Err(format!(
                    "unterminated escape sequence in string starting at byte {quote}"
                ));
            }
            let escaped = bytes[index];
            match escaped {
                b'n' => output.push('\n'),
                b'r' => output.push('\r'),
                b't' => output.push('\t'),
                b'b' => output.push('\u{0008}'),
                b'f' => output.push('\u{000C}'),
                b'\\' => output.push('\\'),
                b'\'' => output.push('\''),
                b'"' => output.push('"'),
                b'{' => output.push('{'),
                b'}' => output.push('}'),
                b'u' => {
                    if index + 4 >= bytes.len() {
                        return Err(format!(
                            "truncated \\u escape in string starting at byte {quote}"
                        ));
                    }
                    let hex = &input[index + 1..index + 5];
                    let character = u32::from_str_radix(hex, 16).map_err(|error| {
                        format!("invalid \\u escape `{hex}` at byte {index}: {error}")
                    })?;
                    let Some(character) = char::from_u32(character) else {
                        return Err(format!("invalid unicode scalar in \\u escape `{hex}`"));
                    };
                    output.push(character);
                    index += 4;
                }
                other => {
                    return Err(format!(
                        "unsupported escape `\\{}` in string starting at byte {quote}",
                        other as char
                    ))
                }
            }
            index += 1;
            continue;
        }
        let Some(character) = input[index..].chars().next() else {
            break;
        };
        output.push(character);
        index += character.len_utf8();
    }
    Err(format!(
        "unterminated string starting at byte {quote}; expected closing `{}`",
        delimiter as char
    ))
}

// ---------------------------------------------------------------------------------------------
// Parser

struct Parser<'a> {
    input: &'a str,
    tokens: Vec<Token>,
    index: usize,
}

fn parse(input: &str) -> std::result::Result<Expr, String> {
    let tokens = lex(input)?;
    let mut parser = Parser {
        input,
        tokens,
        index: 0,
    };
    let expr = parser.parse_or()?;
    if !matches!(parser.peek(), TokenKind::Eof) {
        return Err(parser.error("unexpected token after the complete expression"));
    }
    ensure_type(
        &expr,
        StaticType::Bool,
        "the expression matcher must evaluate to bool",
    )?;
    Ok(expr)
}

impl<'a> Parser<'a> {
    fn peek(&self) -> &TokenKind {
        &self.tokens[self.index].kind
    }

    fn peek_token(&self) -> &Token {
        &self.tokens[self.index]
    }

    fn next(&mut self) -> TokenKind {
        let kind = self.tokens[self.index].kind.clone();
        if self.index + 1 < self.tokens.len() {
            self.index += 1;
        }
        kind
    }

    fn error(&self, message: impl Into<String>) -> String {
        let token = self.peek_token();
        format!(
            "{} at byte {} in expression `{}`",
            message.into(),
            token.start,
            self.input
        )
    }

    fn expect(
        &mut self,
        expected: TokenKind,
        description: &str,
    ) -> std::result::Result<(), String> {
        if self.peek() == &expected {
            self.next();
            Ok(())
        } else {
            Err(self.error(format!("expected {description}")))
        }
    }

    fn parse_or(&mut self) -> std::result::Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), TokenKind::Or) {
            self.next();
            let right = self.parse_and()?;
            ensure_type(&left, StaticType::Bool, "left operand of `||` must be bool")?;
            ensure_type(
                &right,
                StaticType::Bool,
                "right operand of `||` must be bool",
            )?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> std::result::Result<Expr, String> {
        let mut left = self.parse_unary()?;
        while matches!(self.peek(), TokenKind::And) {
            self.next();
            let right = self.parse_unary()?;
            ensure_type(&left, StaticType::Bool, "left operand of `&&` must be bool")?;
            ensure_type(
                &right,
                StaticType::Bool,
                "right operand of `&&` must be bool",
            )?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> std::result::Result<Expr, String> {
        if matches!(self.peek(), TokenKind::Not) {
            self.next();
            let value = self.parse_unary()?;
            ensure_type(&value, StaticType::Bool, "operand of `!` must be bool")?;
            return Ok(Expr::Not(Box::new(value)));
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> std::result::Result<Expr, String> {
        let left = self.parse_primary()?;
        let op = match self.peek() {
            TokenKind::Eq => Some(CompareOp::Eq),
            TokenKind::Ne => Some(CompareOp::Ne),
            TokenKind::Lt => Some(CompareOp::Lt),
            TokenKind::Le => Some(CompareOp::Le),
            TokenKind::Gt => Some(CompareOp::Gt),
            TokenKind::Ge => Some(CompareOp::Ge),
            _ => None,
        };
        if let Some(op) = op {
            self.next();
            let right = self.parse_primary()?;
            check_comparison(op, &left, &right, self.input, self.peek_token().start)?;
            return Ok(Expr::Compare {
                left: Box::new(left),
                op,
                right: Box::new(right),
            });
        }
        if matches!(self.peek(), TokenKind::In) {
            self.next();
            self.expect(TokenKind::LBracket, "`[` after `in`")?;
            let mut values = Vec::new();
            if !matches!(self.peek(), TokenKind::RBracket) {
                loop {
                    let value = self.parse_primary()?;
                    if matches!(
                        value,
                        Expr::Compare { .. }
                            | Expr::In { .. }
                            | Expr::And(..)
                            | Expr::Or(..)
                            | Expr::Not(_)
                    ) {
                        return Err(
                            self.error("list elements must be scalar literals or references")
                        );
                    }
                    values.push(value);
                    if matches!(self.peek(), TokenKind::Comma) {
                        self.next();
                        if matches!(self.peek(), TokenKind::RBracket) {
                            break;
                        }
                        continue;
                    }
                    break;
                }
            }
            self.expect(TokenKind::RBracket, "`]` after the `in` list")?;
            check_membership(&left, &values, self.input, self.peek_token().start)?;
            return Ok(Expr::In {
                left: Box::new(left),
                values,
            });
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> std::result::Result<Expr, String> {
        let token = self.next();
        match token {
            TokenKind::True => Ok(Expr::Bool(true)),
            TokenKind::False => Ok(Expr::Bool(false)),
            TokenKind::Int(value) => Ok(Expr::Int(value)),
            TokenKind::Minus => {
                let TokenKind::Int(value) = self.peek().clone() else {
                    return Err(self.error("unary `-` is only supported for integer literals"));
                };
                self.next();
                Ok(Expr::Int(-value))
            }
            TokenKind::Str(value) => Ok(Expr::Str(value)),
            TokenKind::Placeholder(name) => Ok(Expr::Reference {
                kind: ReferenceKind::Placeholder(name),
                ty: StaticType::Dynamic,
            }),
            TokenKind::LParen => {
                let value = self.parse_or()?;
                self.expect(TokenKind::RParen, "`)`")?;
                Ok(value)
            }
            TokenKind::Ident(_) => self.parse_reference(token),
            other => Err(format!(
                "expected a literal, placeholder, parenthesized expression or identifier, found {:?} at byte {} in expression `{}`",
                other,
                self.peek_token().start,
                self.input
            )),
        }
    }

    fn parse_reference(&mut self, token: TokenKind) -> std::result::Result<Expr, String> {
        let TokenKind::Ident(first) = token else {
            unreachable!("parse_reference called with non-identifier")
        };
        let mut segments = vec![first];
        let mut indices = Vec::new();
        loop {
            match self.peek() {
                TokenKind::Dot => {
                    self.next();
                    let TokenKind::Ident(segment) = self.peek().clone() else {
                        return Err(self.error("expected an identifier after `.`"));
                    };
                    self.next();
                    segments.push(segment);
                }
                TokenKind::LBracket => {
                    self.next();
                    let TokenKind::Str(index) = self.peek().clone() else {
                        return Err(self.error(
                            "index access only supports string literals, e.g. `vars[\"name\"]`",
                        ));
                    };
                    self.next();
                    self.expect(TokenKind::RBracket, "`]` after the index")?;
                    indices.push(index);
                }
                _ => break,
            }
        }
        let mut call_args: Option<Vec<String>> = None;
        if matches!(self.peek(), TokenKind::LParen) {
            self.next();
            let mut args = Vec::new();
            if !matches!(self.peek(), TokenKind::RParen) {
                loop {
                    let TokenKind::Str(arg) = self.peek().clone() else {
                        return Err(self.error(
                            "function-style header/cookie access requires string literal arguments, e.g. `request.header(\"X\")`",
                        ));
                    };
                    self.next();
                    args.push(arg);
                    if matches!(self.peek(), TokenKind::Comma) {
                        self.next();
                        continue;
                    }
                    break;
                }
            }
            self.expect(TokenKind::RParen, "`)` after the arguments")?;
            call_args = Some(args);
        }
        resolve_reference(
            &segments,
            indices,
            call_args,
            self.input,
            self.peek_token().start,
        )
    }
}

fn ensure_type(
    expr: &Expr,
    expected: StaticType,
    message: &str,
) -> std::result::Result<(), String> {
    let actual = expr.static_type();
    match (expected, actual) {
        (_, StaticType::Dynamic) if expected != StaticType::Bool => Ok(()),
        (expected, actual) if expected == actual => Ok(()),
        _ => Err(format!("{message}; found {}", actual.name())),
    }
}

fn check_comparison(
    op: CompareOp,
    left: &Expr,
    right: &Expr,
    input: &str,
    byte: usize,
) -> std::result::Result<(), String> {
    let left_type = left.static_type();
    let right_type = right.static_type();
    let concrete = |ty: StaticType| ty != StaticType::Dynamic;
    if concrete(left_type) && concrete(right_type) && left_type != right_type {
        return Err(format!(
            "type mismatch in `{}` comparison at byte {byte} in expression `{input}`: {} vs {}",
            op.as_str(),
            left_type.name(),
            right_type.name()
        ));
    }
    if op.is_ordering() {
        for ty in [left_type, right_type] {
            if ty == StaticType::Bool {
                return Err(format!(
                    "ordering operator `{}` does not support bool at byte {byte} in expression `{input}`",
                    op.as_str()
                ));
            }
        }
    }
    Ok(())
}

fn check_membership(
    left: &Expr,
    values: &[Expr],
    input: &str,
    byte: usize,
) -> std::result::Result<(), String> {
    let mut element_types: BTreeSet<StaticType> = BTreeSet::new();
    for value in values {
        let ty = value.static_type();
        if ty != StaticType::Dynamic {
            element_types.insert(ty);
        }
    }
    if element_types.len() > 1 {
        return Err(format!(
            "`in` list must contain values of one type at byte {byte} in expression `{input}`"
        ));
    }
    if let Some(element_type) = element_types.iter().next().copied() {
        let left_type = left.static_type();
        if left_type != StaticType::Dynamic && left_type != element_type {
            return Err(format!(
                "type mismatch in `in` at byte {byte} in expression `{input}`: {} vs list of {}",
                left_type.name(),
                element_type.name()
            ));
        }
    }
    Ok(())
}

fn resolve_reference(
    segments: &[String],
    indices: Vec<String>,
    call_args: Option<Vec<String>>,
    input: &str,
    byte: usize,
) -> std::result::Result<Expr, String> {
    let invalid = |message: String| format!("{message} at byte {byte} in expression `{input}`");
    let make = |kind, ty| Ok(Expr::Reference { kind, ty });
    if !indices.is_empty() {
        if indices.len() != 1 {
            return Err(invalid("only one string index is supported".to_string()));
        }
        let name = indices[0].clone();
        return match segments {
            [first, second] if first == "request" && second == "header" => {
                validate_header_name(&name).map_err(invalid)?;
                make(ReferenceKind::Header(name), StaticType::String)
            }
            [first, second] if first == "request" && second == "cookie" => {
                if name.is_empty() {
                    return Err(invalid("cookie name must not be empty".to_string()));
                }
                make(ReferenceKind::Cookie(name), StaticType::String)
            }
            [first] if first == "vars" => make(ReferenceKind::Var(name), StaticType::String),
            _ => Err(invalid(format!(
                "index access is only supported for request.header, request.cookie and vars, not `{}`",
                segments.join(".")
            ))),
        };
    }
    if let Some(args) = call_args {
        return match segments {
            [first, second] if first == "request" && second == "header" => {
                let [name] = args.as_slice() else {
                    return Err(invalid(
                        "request.header(...) requires exactly one string argument".to_string(),
                    ));
                };
                validate_header_name(name).map_err(invalid)?;
                make(ReferenceKind::Header(name.clone()), StaticType::String)
            }
            [first, second] if first == "request" && second == "cookie" => {
                let [name] = args.as_slice() else {
                    return Err(invalid(
                        "request.cookie(...) requires exactly one string argument".to_string(),
                    ));
                };
                if name.is_empty() {
                    return Err(invalid("cookie name must not be empty".to_string()));
                }
                make(ReferenceKind::Cookie(name.clone()), StaticType::String)
            }
            _ => Err(invalid(format!(
                "`{}` is not a supported callable expression; only request.header(...) and request.cookie(...) are callable",
                segments.join(".")
            ))),
        };
    }
    match segments {
        [first] if first == "true" || first == "false" => {
            Err(invalid("unexpected boolean literal".to_string()))
        }
        [first] if first == "client_ip" => Err(invalid(
            "`client_ip` is a Caddy CEL matcher function, not a variable; use `request.remote_ip` or `{http.vars.client_ip}`"
                .to_string(),
        )),
        [first] if first == "req" => Err(invalid(
            "Caddy's CEL `req` object is not exposed by this subset; use the request.* aliases or placeholders"
                .to_string(),
        )),
        [first, second] if first == "request" && second == "method" => {
            make(ReferenceKind::Method, StaticType::String)
        }
        [first, second] if first == "request" && second == "host" => {
            make(ReferenceKind::Host, StaticType::String)
        }
        [first, second] if first == "request" && second == "hostport" => {
            make(ReferenceKind::HostPort, StaticType::String)
        }
        [first, second] if first == "request" && second == "port" => {
            make(ReferenceKind::Port, StaticType::String)
        }
        [first, second] if first == "request" && second == "path" => {
            make(ReferenceKind::Path, StaticType::String)
        }
        [first, second] if first == "request" && second == "uri" => {
            make(ReferenceKind::Uri, StaticType::String)
        }
        [first, second] if first == "request" && second == "scheme" => {
            make(ReferenceKind::Scheme, StaticType::String)
        }
        [first, second] if first == "request" && second == "remote_ip" => {
            make(ReferenceKind::RemoteIp, StaticType::String)
        }
        [first, second] if first == "request" && second == "remote" => {
            make(ReferenceKind::Remote, StaticType::String)
        }
        [first, second, third]
            if first == "request" && second == "uri" && third == "path" =>
        {
            make(ReferenceKind::Path, StaticType::String)
        }
        [first, second, third]
            if first == "request" && second == "uri" && third == "query" =>
        {
            make(ReferenceKind::UriQuery, StaticType::String)
        }
        [first, second, third]
            if first == "request" && second == "remote" && third == "host" =>
        {
            make(ReferenceKind::RemoteIp, StaticType::String)
        }
        [first, second, third]
            if first == "request" && second == "remote" && third == "port" =>
        {
            make(ReferenceKind::RemotePort, StaticType::String)
        }
        [first, second] if first == "request" && second == "header" => {
            Err(invalid(
                "request.header requires a header name: use request.header(\"Name\") or request.header[\"Name\"]"
                    .to_string(),
            ))
        }
        [first, second] if first == "request" && second == "cookie" => {
            Err(invalid(
                "request.cookie requires a cookie name: use request.cookie(\"name\") or request.cookie[\"name\"]"
                    .to_string(),
            ))
        }
        [first, second, third] if first == "request" && second == "header" => {
            validate_header_name(third).map_err(invalid)?;
            make(ReferenceKind::Header(third.clone()), StaticType::String)
        }
        [first, second, third] if first == "request" && second == "cookie" => {
            if third.is_empty() {
                return Err(invalid("cookie name must not be empty".to_string()));
            }
            make(ReferenceKind::Cookie(third.clone()), StaticType::String)
        }
        [first, second, ..] if first == "vars" => {
            let name = segments[1..].join(".");
            make(ReferenceKind::Var(name), StaticType::String)
        }
        [first] if first == "vars" => Err(invalid(
            "`vars` must name a variable, e.g. `vars.my_var` or `vars[\"my_var\"]`".to_string(),
        )),
        [first, second, ..] if first == "tls" => {
            let attribute = segments[1..].join(".");
            match attribute.as_str() {
                "enabled" => make(ReferenceKind::TlsEnabled, StaticType::Bool),
                "handshake_complete" => make(ReferenceKind::TlsHandshakeComplete, StaticType::Bool),
                "version" | "cipher_suite" | "proto" | "server_name" | "client.subject"
                | "client.issuer" | "client.serial" | "client.not_before"
                | "client.not_after" => make(ReferenceKind::TlsMissing, StaticType::String),
                "resumed" => make(ReferenceKind::TlsMissing, StaticType::Bool),
                other => Err(invalid(format!(
                    "unknown TLS attribute `tls.{other}`; supported attributes: tls.enabled, tls.handshake_complete, tls.version, tls.cipher_suite, tls.proto, tls.server_name, tls.resumed, tls.client.subject, tls.client.issuer, tls.client.serial, tls.client.not_before, tls.client.not_after"
                ))),
            }
        }
        [first] if first == "tls" => Err(invalid(
            "`tls` must name an attribute, e.g. `tls.enabled`".to_string(),
        )),
        _ => Err(invalid(format!(
            "unknown identifier `{}`; supported request aliases are request.method, request.host, request.hostport, request.port, request.path, request.uri, request.uri.path, request.uri.query, request.scheme, request.remote_ip, request.remote.host, request.remote.port, request.header(...), request.cookie(...), vars.<name>, tls.enabled, tls.handshake_complete and known tls.* attributes",
            segments.join(".")
        ))),
    }
}

fn validate_header_name(name: &str) -> std::result::Result<(), String> {
    HeaderName::from_bytes(name.as_bytes())
        .map(|_| ())
        .map_err(|error| format!("invalid header name `{name}`: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{header, HeaderValue, Method};

    fn matcher(expression: &str) -> std::result::Result<ExpressionMatcher, String> {
        let value = serde_json::Value::String(expression.to_string());
        ExpressionMatcher::from_json(&value, "match.expression").map_err(|error| error.to_string())
    }

    fn request() -> Request {
        let mut request = Request::new(Method::POST, "/books/42?sort=asc".parse().unwrap());
        request
            .headers
            .insert(header::HOST, HeaderValue::from_static("example.com"));
        request.headers.insert(
            header::COOKIE,
            HeaderValue::from_static("session=abc123; theme=dark"),
        );
        request.headers.insert(
            HeaderName::from_static("x-test"),
            HeaderValue::from_static("yes"),
        );
        request
            .vars
            .insert("tenant".to_string(), "acme".to_string());
        request
    }

    #[test]
    fn parses_supported_grammar() {
        for expression in [
            "true",
            "!false",
            "request.method == 'GET'",
            "request.method != \"POST\"",
            "request.method == `POST`",
            "request.path == `\\books\\42`",
            "{http.error.status_code} == `402`",
            "request.path == '/books/42'",
            "request.host == 'example.com'",
            "request.uri.path == request.path",
            "request.uri.query == 'sort=asc'",
            "request.scheme == 'http'",
            "request.remote_ip == ''",
            "(request.method == 'GET' || request.method == 'HEAD') && request.path == '/a'",
            "request.method in ['GET', 'HEAD']",
            "{http.error.status_code} in [404, 410]",
            "{http.error.status_code} >= 400 && {http.error.status_code} <= 499",
            "request.header('X-Test') == 'yes'",
            "request.header['X-Test'] == 'yes'",
            "request.header.X_Test == 'missing'",
            "request.cookie('session') == 'abc123'",
            "vars.tenant == 'acme'",
            "vars['tenant'] == 'acme'",
            "tls.enabled == false",
            "tls.handshake_complete == false",
            "'a' < 'b'",
            "-1 < 0",
            "1 in [1, 2, 3]",
            "request.method in ['GET',]",
            "r'raw\\string' == 'raw\\\\string'",
        ] {
            matcher(expression).unwrap_or_else(|error| panic!("{expression}: {error}"));
        }
    }

    #[test]
    fn rejects_invalid_grammar_and_type_errors_at_load() {
        let cases = [
            "",
            "(",
            "request.method ==",
            "request.method",
            "{http.request.method}",
            "request.method == 404",
            "request.path < 42",
            "tls.enabled < true",
            "request.method && true",
            "request.path in [1, 2]",
            "request.path in [1, 'a']",
            "unknown.identifier == 'x'",
            "request.unknown == 'x'",
            "request.header() == 'x'",
            "request.header == 'x'",
            "vars == 'x'",
            "tls.bogus == 'x'",
            "client_ip == '127.0.0.1'",
            "method('GET')",
            "request.method.startsWith('G')",
            "request.path matches '...'",
            "'unterminated",
            "request.method == `GET",
            "1 && true",
            "!1",
            "request.path in ['a'] ||",
            "request.header('bad name') == 'x'",
        ];
        for expression in cases {
            let error = matcher(expression).expect_err("expression must fail at load");
            assert!(
                error.contains("match.expression") || error.contains("expression"),
                "{expression}: {error}"
            );
            assert!(
                !error.contains("internal"),
                "located error for {expression}: {error}"
            );
        }
    }

    #[test]
    fn evaluates_request_aliases_and_placeholders() {
        let request = request();
        for (expression, expected) in [
            ("request.method == 'POST'", true),
            ("request.method == `POST`", true),
            (r"`\foo` == '\\foo'", true),
            ("request.method != 'GET'", true),
            ("request.host == 'example.com'", true),
            ("request.path == '/books/42'", true),
            ("request.uri.path == '/books/42'", true),
            ("request.uri.query == 'sort=asc'", true),
            ("request.scheme == 'http'", true),
            ("request.header('X-Test') == 'yes'", true),
            ("request.header['X-Test'] == 'yes'", true),
            ("request.cookie('session') == 'abc123'", true),
            ("request.cookie['theme'] == 'dark'", true),
            ("vars.tenant == 'acme'", true),
            ("vars['tenant'] == 'acme'", true),
            ("{http.request.method} == 'POST'", true),
            ("{http.request.uri.path} in ['/books/42', '/other']", true),
            ("{http.request.header.X-Test} == 'yes'", true),
            ("{http.request.cookie.session} == 'abc123'", true),
            ("{http.vars.tenant} == 'acme'", true),
            ("tls.enabled == false", true),
            ("request.method in ['GET', 'POST']", true),
            ("!(request.method == 'GET')", true),
            ("request.method == 'PUT' || request.method == 'POST'", true),
            (
                "request.method == 'POST' && request.path == '/books/42'",
                true,
            ),
            ("'alpha' < 'beta'", true),
            ("10 >= 10", true),
        ] {
            assert!(
                matcher(expression).unwrap().matches(&request),
                "{expression}"
            );
        }
        for expression in [
            "request.method == 'GET'",
            "request.path == '/other'",
            "request.cookie('session') == 'missing'",
            "vars.tenant == 'other'",
            "tls.enabled == true",
            "request.method in ['GET', 'HEAD']",
        ] {
            assert!(
                !matcher(expression).unwrap().matches(&request),
                "{expression}"
            );
        }
    }

    #[test]
    fn missing_values_follow_caddy_semantics() {
        let request = request();
        // Missing header expands to the empty string (Caddy replacer semantics), so `== ''`
        // matches and `!= ''` does not.
        assert!(matcher("request.header('X-Missing') == ''")
            .unwrap()
            .matches(&request));
        assert!(!matcher("request.header('X-Missing') != ''")
            .unwrap()
            .matches(&request));
        assert!(matcher("{http.request.header.X-Missing} == ''")
            .unwrap()
            .matches(&request));
        assert!(!matcher("{http.request.header.X-Missing} != ''")
            .unwrap()
            .matches(&request));
        // Missing cookie and query parameter are empty strings (Caddy replacer semantics).
        assert!(matcher("request.cookie('missing') == ''")
            .unwrap()
            .matches(&request));
        assert!(matcher("{http.request.uri.query.missing} == ''")
            .unwrap()
            .matches(&request));
        // Missing vars and unknown placeholders are null.
        assert!(!matcher("vars.missing == ''").unwrap().matches(&request));
        assert!(matcher("vars.missing != ''").unwrap().matches(&request));
        assert!(!matcher("{unknown.placeholder} == ''")
            .unwrap()
            .matches(&request));
        assert!(matcher("{unknown.placeholder} != ''")
            .unwrap()
            .matches(&request));
        // Missing TLS metadata is null; no error and no match for equality.
        assert!(!matcher("tls.version == 'TLSv1.3'")
            .unwrap()
            .matches(&request));
        assert!(matcher("tls.version != 'TLSv1.3'")
            .unwrap()
            .matches(&request));
        // Empty query is a present empty string, so `== ''` matches.
        let mut no_query = Request::new(Method::GET, "/".parse().unwrap());
        no_query.tls = false;
        assert!(matcher("request.uri.query == ''")
            .unwrap()
            .matches(&no_query));
        assert!(!matcher("request.uri.query != ''")
            .unwrap()
            .matches(&no_query));
    }

    #[test]
    fn integer_status_expressions_used_by_handle_errors_still_work() {
        let mut request = Request::new(Method::GET, "/".parse().unwrap());
        request
            .vars
            .insert("http.error.status_code".to_string(), "404".to_string());
        assert!(matcher("{http.error.status_code} in [404, 410]")
            .unwrap()
            .matches(&request));
        assert!(
            matcher("{http.error.status_code} >= 400 && {http.error.status_code} <= 499")
                .unwrap()
                .matches(&request)
        );
        assert!(!matcher("{http.error.status_code} >= 500")
            .unwrap()
            .matches(&request));
        assert!(!matcher("{http.error.status_code} in [500, 502]")
            .unwrap()
            .matches(&request));
    }

    #[test]
    fn raw_and_escaped_strings_work() {
        let request = request();
        assert!(matcher(r"'line\nbreak' == 'line\nbreak'")
            .unwrap()
            .matches(&request));
        assert!(matcher(r#"r'back\slash' == r'back\slash'"#)
            .unwrap()
            .matches(&request));
        assert!(matcher(r#"'quote\'inside' == "quote'inside""#)
            .unwrap()
            .matches(&request));
        // Backtick raw strings are literal (no escapes), can contain backslashes and newlines, and
        // cannot contain a backtick.
        assert!(matcher("`line\nbreak` == `line\nbreak`")
            .unwrap()
            .matches(&request));
        assert!(matcher("`a\nb` == `a\nb`").unwrap().matches(&request));
        assert!(matcher(r"`\raw` == '\\raw'").unwrap().matches(&request));
    }

    #[test]
    fn unterminated_backtick_is_a_located_parse_error() {
        let error = matcher("request.method == `GET").expect_err("unterminated backtick");
        assert!(error.contains("match.expression"), "{error}");
        assert!(error.contains("unterminated backtick"), "{error}");
        assert!(error.contains("byte"), "{error}");
    }

    #[test]
    fn object_json_form_with_name_is_accepted() {
        let value = serde_json::json!({"expr": "true", "name": "named"});
        let matcher =
            ExpressionMatcher::from_json(&value, "match.expression").expect("object form");
        assert!(matcher.matches(&request()));
    }
}
