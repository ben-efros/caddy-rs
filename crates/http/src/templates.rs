//! `http.handlers.templates`: execute response bodies as templates (documented subset).
//!
//! Caddy v2.11.9's `modules/caddyhttp/templates` buffers a response when its `Content-Type`
//! matches `mime_types` (default `text/html`, `text/plain`, `text/markdown`) and executes the
//! buffered body with Go `text/template` + Sprig + Caddy's own functions. This module uses the
//! caddy-rs response-transform hook to do the same, with a hand-written template interpreter for a
//! coherent subset instead of adding a dependency:
//!
//! * actions `{{...}}` (or configured delimiters), whitespace-trim markers `{{-`/`-}}`, comments
//!   `{{/* ... */}}`;
//! * `{{if}}`/`{{else if}}`/`{{else}}`/`{{end}}`, `{{range}}`/`{{else}}`/`{{end}}`,
//!   `{{with}}`/`{{else}}`/`{{end}}`, `{{define}}`/`{{template}}`, variables `$x := ...`/`$x = ...`;
//! * pipelines (`{{"text" | upper}}`), field access (`{{.Req.Method}}`, `{{.Host}}`), `.Args`,
//!   `.Req.Header.Get "X"`, `.Req.URL.Path`, `.Req.URL.RawQuery`, `.Cookie "name"`,
//!   `{{range index .Req.Header "X-Test"}}...{{end}}`, and `.RespHeader.Set/Add/Del`;
//! * functions: `placeholder`/`ph`, `env`, `include`, `import`, `readFile`, `fileExists`,
//!   `stripHTML`, `truncate`, `replace`, `splitFrontMatter`, `httpError`, `pathEscape`, `html`,
//!   plus template built-ins (`index`, `len`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `and`, `or`,
//!   `not`, `print`, `printf`, `upper`, `lower`, `split`, `join`, `list`).
//!
//! Unsupported (rejected at execution time with a located error naming the action/line):
//! `markdown`, `httpInclude`, `listFiles`, `fileStat`, `humanize`, `maybe`, custom extension
//! functions, `{{block}}`, `{{break}}`/`{{continue}}`, Sprig's wider library, and Go template's
//! full reflection/method set. Caddy's `splitFrontMatter` supports YAML/TOML/JSON front matter;
//! this build implements a conservative YAML/TOML `key: value` / `key = value` subset (no nested
//! structures), and JSON front matter is unsupported.
//!
//! Safety: `include`, `import`, `readFile` and `fileExists` are confined to the configured
//! `file_root` (default `{http.vars.root}`, falling back to `.`). Leading `/` is treated as
//! root-relative (Caddy `http.Dir` behaviour); `..` components are clamped at the root rather than
//! escaping it.
//!
//! Unlike Caddy, templates are parsed per response (Caddy's handler has no template source in its
//! configuration; it executes the upstream response body), so malformed templates cannot be a
//! configuration-load error. They surface as a 500 (or the `httpError` status) and the task report
//! documents this unavoidable difference.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use http::{header, HeaderMap, HeaderValue, StatusCode};

use crate::body::{Body, StreamingResponse};
use crate::types::{Error, Handler, Outcome, Request, ResponseTransform, Result};

/// Caddy's default MIME types for template rendering.
const DEFAULT_MIME_TYPES: &[&str] = &["text/html", "text/plain", "text/markdown"];

/// The `templates` handler configuration.
#[derive(Debug)]
struct TemplatesConfig {
    file_root: String,
    mime_types: Vec<String>,
    delimiters: (String, String),
}

/// `http.handlers.templates`.
#[derive(Debug)]
pub struct TemplatesHandler {
    config: std::sync::Arc<TemplatesConfig>,
}

impl TemplatesHandler {
    /// Build from Caddy JSON (`file_root`, `mime_types`, `delimiters`; `between` accepted as a
    /// caddy-rs alias for the Caddyfile spelling).
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "templates handler must be an object"))?;
        for field in object.keys() {
            if !matches!(
                field.as_str(),
                "handler"
                    | "file_root"
                    | "mime_types"
                    | "delimiters"
                    | "between"
                    | "extensions"
                    | "match"
            ) {
                return Err(invalid(path, format!("unknown templates field `{field}`")));
            }
        }
        if object.get("extensions").is_some() {
            return Err(invalid(
                format!("{path}.extensions"),
                "custom template extension modules are not implemented by this build",
            ));
        }
        if object.get("match").is_some() {
            // Caddy's `match` here is the (unused-by-this-build) extension module map keyed by
            // `namespace=http.handlers.templates.functions`; reject rather than silently ignoring.
            return Err(invalid(
                format!("{path}.match"),
                "template extension functions are not implemented by this build",
            ));
        }
        let file_root = match object.get("file_root") {
            None | Some(serde_json::Value::Null) => "{http.vars.root}".to_string(),
            Some(serde_json::Value::String(root)) => root.clone(),
            Some(_) => {
                return Err(invalid(
                    format!("{path}.file_root"),
                    "`file_root` must be a string",
                ))
            }
        };
        let mime_types = match object.get("mime_types") {
            None | Some(serde_json::Value::Null) => DEFAULT_MIME_TYPES
                .iter()
                .map(|mime| (*mime).to_string())
                .collect(),
            Some(serde_json::Value::Array(items)) => {
                let mut mimes = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    mimes.push(
                        item.as_str()
                            .ok_or_else(|| {
                                invalid(
                                    format!("{path}.mime_types[{index}]"),
                                    "mime type must be a string",
                                )
                            })?
                            .to_string(),
                    );
                }
                mimes
            }
            Some(_) => {
                return Err(invalid(
                    format!("{path}.mime_types"),
                    "`mime_types` must be an array of strings",
                ))
            }
        };
        let delimiters = match object.get("delimiters").or_else(|| object.get("between")) {
            None | Some(serde_json::Value::Null) => ("{{".to_string(), "}}".to_string()),
            Some(serde_json::Value::Array(items)) => {
                if items.len() != 2 {
                    return Err(invalid(
                        format!("{path}.delimiters"),
                        "delimiters must consist of exactly two elements: opening and closing",
                    ));
                }
                let open = items[0].as_str().ok_or_else(|| {
                    invalid(
                        format!("{path}.delimiters[0]"),
                        "delimiter must be a string",
                    )
                })?;
                let close = items[1].as_str().ok_or_else(|| {
                    invalid(
                        format!("{path}.delimiters[1]"),
                        "delimiter must be a string",
                    )
                })?;
                if open.is_empty() || close.is_empty() {
                    return Err(invalid(
                        format!("{path}.delimiters"),
                        "delimiters must not be empty",
                    ));
                }
                (open.to_string(), close.to_string())
            }
            Some(_) => {
                return Err(invalid(
                    format!("{path}.delimiters"),
                    "`delimiters` must be an array of two strings",
                ))
            }
        };
        Ok(Self {
            config: std::sync::Arc::new(TemplatesConfig {
                file_root,
                mime_types,
                delimiters,
            }),
        })
    }
}

#[async_trait]
impl Handler for TemplatesHandler {
    fn name(&self) -> &'static str {
        "templates"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        let transform = TemplatesTransform {
            config: std::sync::Arc::clone(&self.config),
            request: request.clone(),
        };
        request.push_response_transform(std::sync::Arc::new(transform));
        Ok(Outcome::Continue(request))
    }
}

/// A response transform that buffers matching bodies and executes them as templates.
struct TemplatesTransform {
    config: std::sync::Arc<TemplatesConfig>,
    request: Request,
}

#[async_trait]
impl ResponseTransform for TemplatesTransform {
    async fn transform(&self, response: StreamingResponse) -> StreamingResponse {
        let content_type = response
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let should_buffer = self
            .config
            .mime_types
            .iter()
            .any(|mime| content_type.contains(mime));
        if !should_buffer
            || self.request.method == http::Method::HEAD
            || !status_allows_body(response.status)
        {
            return response;
        }
        let StreamingResponse {
            status,
            mut headers,
            body,
        } = response;
        let source = match body.into_bytes().await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => return internal_error_response(),
        };
        let root = self.resolve_root();
        let mut renderer = Renderer::new(&self.request, root);
        match renderer.render_source(&source, &self.config.delimiters) {
            Ok(body) => {
                let body_allowed = status_allows_body(status)
                    && !(self.request.method == http::Method::HEAD)
                    && !(self.request.method == http::Method::CONNECT
                        && (200..=299).contains(&status.as_u16()));
                // Caddy removes validators/ranges for dynamic content and re-computes the length.
                headers.remove(header::ACCEPT_RANGES);
                headers.remove(header::LAST_MODIFIED);
                headers.remove(header::ETAG);
                if body_allowed {
                    if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
                        headers.insert(header::CONTENT_LENGTH, value);
                    }
                } else {
                    headers.remove(header::CONTENT_LENGTH);
                }
                // Merge response headers mutated by `.RespHeader.Set/Add/Del`.
                renderer.apply_response_headers(&mut headers);
                StreamingResponse {
                    status,
                    headers,
                    body: Body::Bytes(Bytes::from(body)),
                }
            }
            Err(TemplateError::Http(status)) => {
                let mut response = internal_error_response();
                response.status = status;
                response
            }
            Err(_) => internal_error_response(),
        }
    }
}

fn internal_error_response() -> StreamingResponse {
    // Caddy propagates template failures as handler errors; in caddy-rs the transform can only
    // return a response, so send an empty 500 (or the `httpError` status). Headers that may have
    // been set by the underlying handler (Content-Type, validators, encoding, ranges) are dropped.
    StreamingResponse {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        headers: HeaderMap::new(),
        body: Body::Bytes(Bytes::new()),
    }
}

fn status_allows_body(status: StatusCode) -> bool {
    !(status.as_u16() < 200
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED)
}

impl TemplatesTransform {
    fn resolve_root(&self) -> Option<PathBuf> {
        let expanded = self.request.replace_all(&self.config.file_root);
        let expanded = if expanded.is_empty() { "." } else { &expanded };
        Some(PathBuf::from(expanded))
    }
}

// ---------------------------------------------------------------------------------------------
// Errors

#[derive(Debug)]
enum TemplateError {
    Parse(String),
    Exec(String),
    Http(StatusCode),
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(message) | Self::Exec(message) => formatter.write_str(message),
            Self::Http(status) => write!(formatter, "template raised HTTP {}", status.as_u16()),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Values

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

impl Value {
    fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(value) => *value,
            Self::Int(value) => *value != 0,
            Self::Float(value) => *value != 0.0,
            Self::Str(value) => !value.is_empty(),
            Self::List(values) => !values.is_empty(),
            Self::Map(values) => !values.is_empty(),
        }
    }

    fn render(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Bool(value) => value.to_string(),
            Self::Int(value) => value.to_string(),
            Self::Float(value) => value.to_string(),
            Self::Str(value) => value.clone(),
            Self::List(values) => {
                let rendered: Vec<String> = values.iter().map(Value::render).collect();
                format!("[{}]", rendered.join(" "))
            }
            Self::Map(values) => {
                let rendered: Vec<String> = values
                    .iter()
                    .map(|(key, value)| format!("{key}:{}", value.render()))
                    .collect();
                format!("map[{}]", rendered.join(" "))
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Template syntax tree

#[derive(Debug, Clone)]
enum Node {
    Text(String),
    Action(Pipeline),
    If {
        branches: Vec<(Pipeline, Vec<Node>)>,
        otherwise: Vec<Node>,
    },
    Range {
        pipeline: Pipeline,
        variables: Vec<String>,
        body: Vec<Node>,
        otherwise: Vec<Node>,
    },
    With {
        pipeline: Pipeline,
        body: Vec<Node>,
        otherwise: Vec<Node>,
    },
    Template {
        name: String,
        pipeline: Option<Pipeline>,
    },
    Assign {
        name: String,
        pipeline: Pipeline,
    },
}

#[derive(Debug, Clone)]
struct Pipeline {
    commands: Vec<Command>,
}

#[derive(Debug, Clone)]
struct Command {
    operands: Vec<Operand>,
}

#[derive(Debug, Clone)]
enum Operand {
    Literal(Value),
    Field(String),
    Variable(String),
    Function(String),
    Pipeline(Box<Pipeline>),
}

#[derive(Debug, Clone)]
struct Template {
    nodes: Vec<Node>,
    definitions: BTreeMap<String, Vec<Node>>,
}

#[derive(Debug, Clone)]
enum RawEvent {
    Text(String),
    Action(String),
}

// ---------------------------------------------------------------------------------------------
// Delimiter scanner

fn scan(
    source: &str,
    open: &str,
    close: &str,
) -> std::result::Result<Vec<RawEvent>, TemplateError> {
    let mut events = Vec::new();
    let mut rest = source;
    let mut text = String::new();
    while let Some(start) = rest.find(open) {
        text.push_str(&rest[..start]);
        let after_open = &rest[start + open.len()..];
        let Some(end) = after_open.find(close) else {
            return Err(TemplateError::Parse(format!(
                "unterminated template action: missing closing delimiter `{close}`"
            )));
        };
        let mut action = after_open[..end].to_string();
        let trim_left = action.starts_with('-');
        if trim_left {
            action.remove(0);
            while text.ends_with(|ch: char| ch.is_whitespace()) {
                text.pop();
            }
        }
        let trim_right = action.ends_with('-');
        if trim_right {
            action.pop();
        }
        if !text.is_empty() {
            events.push(RawEvent::Text(std::mem::take(&mut text)));
        }
        events.push(RawEvent::Action(action.trim().to_string()));
        rest = &after_open[end + close.len()..];
        if trim_right {
            rest = rest.trim_start();
        }
    }
    text.push_str(rest);
    if !text.is_empty() {
        events.push(RawEvent::Text(text));
    }
    Ok(events)
}

// ---------------------------------------------------------------------------------------------
// Action lexer / pipeline parser

#[derive(Debug, Clone, PartialEq)]
enum ActToken {
    Ident(String),
    Field(String),
    Variable(String),
    Literal(Value),
    Pipe,
    LParen,
    RParen,
    Comma,
    Declare,
    Assign,
}

fn lex_action(action: &str) -> std::result::Result<Vec<ActToken>, TemplateError> {
    let bytes = action.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        match byte {
            b'|' => {
                tokens.push(ActToken::Pipe);
                index += 1;
            }
            b'(' => {
                tokens.push(ActToken::LParen);
                index += 1;
            }
            b')' => {
                tokens.push(ActToken::RParen);
                index += 1;
            }
            b',' => {
                tokens.push(ActToken::Comma);
                index += 1;
            }
            b':' if bytes.get(index + 1) == Some(&b'=') => {
                tokens.push(ActToken::Declare);
                index += 2;
            }
            b'=' => {
                tokens.push(ActToken::Assign);
                index += 1;
            }
            b'"' | b'\'' | b'`' => {
                let quote = byte;
                let mut value = String::new();
                index += 1;
                let mut closed = false;
                while index < bytes.len() {
                    let current = bytes[index];
                    if current == quote {
                        closed = true;
                        index += 1;
                        break;
                    }
                    if current == b'\\' && quote != b'`' {
                        index += 1;
                        if index >= bytes.len() {
                            break;
                        }
                        match bytes[index] {
                            b'n' => value.push('\n'),
                            b'r' => value.push('\r'),
                            b't' => value.push('\t'),
                            b'\\' => value.push('\\'),
                            b'"' => value.push('"'),
                            b'\'' => value.push('\''),
                            other => value.push(other as char),
                        }
                        index += 1;
                        continue;
                    }
                    let Some(ch) = action[index..].chars().next() else {
                        break;
                    };
                    value.push(ch);
                    index += ch.len_utf8();
                }
                if !closed {
                    return Err(TemplateError::Parse(format!(
                        "unterminated string literal in template action `{action}`"
                    )));
                }
                tokens.push(ActToken::Literal(Value::Str(value)));
            }
            b'.' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric()
                        || bytes[index] == b'_'
                        || bytes[index] == b'.')
                {
                    index += 1;
                }
                tokens.push(ActToken::Field(action[start..index].to_string()));
            }
            b'$' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric()
                        || bytes[index] == b'_'
                        || bytes[index] == b'.')
                {
                    index += 1;
                }
                if index == start + 1 {
                    tokens.push(ActToken::Variable("$".to_string()));
                } else {
                    tokens.push(ActToken::Variable(action[start..index].to_string()));
                }
            }
            b'-' if bytes.get(index + 1).is_some_and(u8::is_ascii_digit) => {
                let start = index;
                index += 1;
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index += 1;
                }
                tokens.push(ActToken::Literal(Value::Int(
                    action[start..index].parse().map_err(|error| {
                        TemplateError::Parse(format!(
                            "invalid integer `{}`: {error}",
                            &action[start..index]
                        ))
                    })?,
                )));
            }
            _ if byte.is_ascii_digit() => {
                let start = index;
                while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.')
                {
                    index += 1;
                }
                let text = &action[start..index];
                if let Ok(value) = text.parse::<i64>() {
                    tokens.push(ActToken::Literal(Value::Int(value)));
                } else if let Ok(value) = text.parse::<f64>() {
                    tokens.push(ActToken::Literal(Value::Float(value)));
                } else {
                    return Err(TemplateError::Parse(format!("invalid number `{text}`")));
                }
            }
            _ if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                let ident = &action[start..index];
                match ident {
                    "true" => tokens.push(ActToken::Literal(Value::Bool(true))),
                    "false" => tokens.push(ActToken::Literal(Value::Bool(false))),
                    "nil" => tokens.push(ActToken::Literal(Value::Null)),
                    other => tokens.push(ActToken::Ident(other.to_string())),
                }
            }
            other => {
                return Err(TemplateError::Parse(format!(
                    "unsupported character `{}` in template action `{action}`",
                    other as char
                )))
            }
        }
    }
    Ok(tokens)
}

fn parse_pipeline_tokens(
    tokens: &[ActToken],
    action: &str,
) -> std::result::Result<Pipeline, TemplateError> {
    if tokens.is_empty() {
        return Err(TemplateError::Parse(format!(
            "empty template action `{action}`"
        )));
    }
    // Split top-level commands on pipes, respecting parentheses.
    let mut commands = Vec::new();
    let mut current = Vec::new();
    let mut depth = 0usize;
    for token in tokens {
        match token {
            ActToken::LParen => {
                depth += 1;
                current.push(token.clone());
            }
            ActToken::RParen => {
                depth = depth.saturating_sub(1);
                current.push(token.clone());
            }
            ActToken::Pipe if depth == 0 => {
                commands.push(parse_command(&current, action)?);
                current.clear();
            }
            other => current.push(other.clone()),
        }
    }
    commands.push(parse_command(&current, action)?);
    Ok(Pipeline { commands })
}

fn parse_command(tokens: &[ActToken], action: &str) -> std::result::Result<Command, TemplateError> {
    if tokens.is_empty() {
        return Err(TemplateError::Parse(format!(
            "empty command in template action `{action}`"
        )));
    }
    let mut operands = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        match &tokens[index] {
            ActToken::LParen => {
                let start = index + 1;
                let mut depth = 1usize;
                index += 1;
                while index < tokens.len() && depth > 0 {
                    match tokens[index] {
                        ActToken::LParen => depth += 1,
                        ActToken::RParen => depth -= 1,
                        _ => {}
                    }
                    index += 1;
                }
                if depth != 0 {
                    return Err(TemplateError::Parse(format!(
                        "unbalanced parentheses in template action `{action}`"
                    )));
                }
                let inner = &tokens[start..index - 1];
                operands.push(Operand::Pipeline(Box::new(parse_pipeline_tokens(
                    inner, action,
                )?)));
            }
            ActToken::Ident(name) => {
                operands.push(Operand::Function(name.clone()));
                index += 1;
            }
            ActToken::Field(path) => {
                operands.push(Operand::Field(path.clone()));
                index += 1;
            }
            ActToken::Variable(path) => {
                operands.push(Operand::Variable(path.clone()));
                index += 1;
            }
            ActToken::Literal(value) => {
                operands.push(Operand::Literal(value.clone()));
                index += 1;
            }
            other => {
                return Err(TemplateError::Parse(format!(
                    "unexpected token in template action `{action}`: {other:?}"
                )))
            }
        }
    }
    Ok(Command { operands })
}

// ---------------------------------------------------------------------------------------------
// Template parser

fn parse_template(
    source: &str,
    delimiters: &(String, String),
) -> std::result::Result<Template, TemplateError> {
    let events = scan(source, &delimiters.0, &delimiters.1)?;
    let mut parser = TemplateParser {
        events,
        index: 0,
        definitions: BTreeMap::new(),
    };
    let (nodes, stop) = parser.parse_block(&[])?;
    if let Some(stop) = stop {
        return Err(TemplateError::Parse(format!(
            "unexpected template action `{stop}`"
        )));
    }
    Ok(Template {
        nodes,
        definitions: parser.definitions,
    })
}

struct TemplateParser {
    events: Vec<RawEvent>,
    index: usize,
    definitions: BTreeMap<String, Vec<Node>>,
}

impl TemplateParser {
    fn next_event(&mut self) -> Option<RawEvent> {
        if self.index >= self.events.len() {
            return None;
        }
        let event = self.events[self.index].clone();
        self.index += 1;
        Some(event)
    }

    fn parse_block(
        &mut self,
        expected_end: &[&str],
    ) -> std::result::Result<(Vec<Node>, Option<String>), TemplateError> {
        let mut nodes = Vec::new();
        while let Some(event) = self.next_event() {
            match event {
                RawEvent::Text(text) => nodes.push(Node::Text(text)),
                RawEvent::Action(action) => {
                    if action.starts_with("/*") {
                        // Template comment; no output and no evaluation.
                        continue;
                    }
                    let keyword = action.split_whitespace().next().unwrap_or("");
                    if expected_end.contains(&keyword) || keyword == "end" || keyword == "else" {
                        if expected_end.is_empty() && (keyword == "end" || keyword == "else") {
                            return Err(TemplateError::Parse(format!(
                                "unexpected `{action}` without an open block"
                            )));
                        }
                        if !expected_end.is_empty() && (keyword == "end" || keyword == "else") {
                            return Ok((nodes, Some(action)));
                        }
                    }
                    match keyword {
                        "if" => {
                            let (condition, _) = self.parse_if_condition(&action)?;
                            let (body, stop) = self.parse_block(&["else", "end"])?;
                            let stop = stop.ok_or_else(|| {
                                TemplateError::Parse(format!("unterminated `if` before `{action}`"))
                            })?;
                            let mut branches = vec![(condition, body)];
                            let otherwise;
                            if stop.starts_with("else if ") {
                                // Rewrite the else-if chain into a nested if node.
                                let nested_action = stop.trim_start_matches("else ").to_string();
                                let nested = self.parse_if_from_action(&nested_action)?;
                                otherwise = vec![nested];
                            } else if stop.trim() == "else" {
                                let (body, stop) = self.parse_block(&["end"])?;
                                if stop.as_deref().map(str::trim) != Some("end") {
                                    return Err(TemplateError::Parse(
                                        "unterminated `else` block: expected `end`".to_string(),
                                    ));
                                }
                                otherwise = body;
                            } else if stop.trim() == "end" {
                                otherwise = Vec::new();
                            } else {
                                return Err(TemplateError::Parse(format!(
                                    "unexpected `{stop}` after if block"
                                )));
                            }
                            nodes.push(Node::If {
                                branches: std::mem::take(&mut branches),
                                otherwise,
                            });
                        }
                        "range" => {
                            let (variables, pipeline) = self.parse_range_head(&action)?;
                            let (body, stop) = self.parse_block(&["else", "end"])?;
                            let stop = stop.ok_or_else(|| {
                                TemplateError::Parse(format!(
                                    "unterminated `range` before `{action}`"
                                ))
                            })?;
                            let otherwise = if stop.trim() == "else" {
                                let (body, end) = self.parse_block(&["end"])?;
                                if end.as_deref().map(str::trim) != Some("end") {
                                    return Err(TemplateError::Parse(
                                        "unterminated `range` else block: expected `end`"
                                            .to_string(),
                                    ));
                                }
                                body
                            } else {
                                Vec::new()
                            };
                            nodes.push(Node::Range {
                                pipeline,
                                variables,
                                body,
                                otherwise,
                            });
                        }
                        "with" => {
                            let tokens = lex_action(&action)?;
                            if tokens.len() < 2 {
                                return Err(TemplateError::Parse(format!(
                                    "`{action}` requires a pipeline"
                                )));
                            }
                            let pipeline = parse_pipeline_tokens(&tokens[1..], &action)?;
                            let (body, stop) = self.parse_block(&["else", "end"])?;
                            let stop = stop.ok_or_else(|| {
                                TemplateError::Parse(format!(
                                    "unterminated `with` before `{action}`"
                                ))
                            })?;
                            let otherwise = if stop.trim() == "else" {
                                let (body, end) = self.parse_block(&["end"])?;
                                if end.as_deref().map(str::trim) != Some("end") {
                                    return Err(TemplateError::Parse(
                                        "unterminated `with` else block: expected `end`"
                                            .to_string(),
                                    ));
                                }
                                body
                            } else {
                                Vec::new()
                            };
                            nodes.push(Node::With {
                                pipeline,
                                body,
                                otherwise,
                            });
                        }
                        "define" => {
                            let tokens = lex_action(&action)?;
                            let Some(ActToken::Literal(Value::Str(name))) = tokens.get(1) else {
                                return Err(TemplateError::Parse(format!(
                                    "`{action}` requires a quoted template name"
                                )));
                            };
                            if tokens.len() != 2 {
                                return Err(TemplateError::Parse(format!(
                                    "unexpected tokens after template name in `{action}`"
                                )));
                            }
                            let (body, stop) = self.parse_block(&["end"])?;
                            if stop.as_deref().map(str::trim) != Some("end") {
                                return Err(TemplateError::Parse(format!(
                                    "unterminated `define` for `{name}`: expected `end`"
                                )));
                            }
                            self.definitions.insert(name.clone(), body);
                        }
                        "template" => {
                            let tokens = lex_action(&action)?;
                            let Some(ActToken::Literal(Value::Str(name))) = tokens.get(1) else {
                                return Err(TemplateError::Parse(format!(
                                    "`{action}` requires a quoted template name"
                                )));
                            };
                            let pipeline = if tokens.len() > 2 {
                                Some(parse_pipeline_tokens(&tokens[2..], &action)?)
                            } else {
                                None
                            };
                            nodes.push(Node::Template {
                                name: name.clone(),
                                pipeline,
                            });
                        }
                        "block" => {
                            return Err(TemplateError::Parse(
                                "`block` actions are not implemented by this build".to_string(),
                            ))
                        }
                        "break" | "continue" => {
                            return Err(TemplateError::Parse(format!(
                                "`{keyword}` actions are not implemented by this build"
                            )))
                        }
                        "" => {}
                        _ => {
                            let tokens = lex_action(&action)?;
                            // Variable declaration/assignment: `$x := pipeline` / `$x = pipeline`.
                            if let (Some(ActToken::Variable(name)), Some(operator)) =
                                (tokens.first(), tokens.get(1))
                            {
                                if matches!(operator, ActToken::Declare | ActToken::Assign) {
                                    let pipeline = parse_pipeline_tokens(&tokens[2..], &action)?;
                                    nodes.push(Node::Assign {
                                        name: name.clone(),
                                        pipeline,
                                    });
                                    continue;
                                }
                            }
                            nodes.push(Node::Action(parse_pipeline_tokens(&tokens, &action)?));
                        }
                    }
                }
            }
        }
        if expected_end.is_empty() {
            Ok((nodes, None))
        } else {
            Err(TemplateError::Parse(format!(
                "unterminated block: expected one of {expected_end:?}"
            )))
        }
    }

    fn parse_if_condition(
        &mut self,
        action: &str,
    ) -> std::result::Result<(Pipeline, String), TemplateError> {
        let tokens = lex_action(action)?;
        if tokens.len() < 2 {
            return Err(TemplateError::Parse(format!(
                "`{action}` requires a pipeline"
            )));
        }
        let condition = parse_pipeline_tokens(&tokens[1..], action)?;
        Ok((condition, action.to_string()))
    }

    fn parse_if_from_action(&mut self, action: &str) -> std::result::Result<Node, TemplateError> {
        let (condition, _) = self.parse_if_condition(action)?;
        let (body, stop) = self.parse_block(&["else", "end"])?;
        let stop = stop
            .ok_or_else(|| TemplateError::Parse(format!("unterminated `if` before `{action}`")))?;
        let mut branches = vec![(condition, body)];
        let otherwise = if stop.starts_with("else if ") {
            vec![self.parse_if_from_action(stop.trim_start_matches("else "))?]
        } else if stop.trim() == "else" {
            let (body, end) = self.parse_block(&["end"])?;
            if end.as_deref().map(str::trim) != Some("end") {
                return Err(TemplateError::Parse(
                    "unterminated `else` block: expected `end`".to_string(),
                ));
            }
            body
        } else {
            Vec::new()
        };
        Ok(Node::If {
            branches: std::mem::take(&mut branches),
            otherwise,
        })
    }

    fn parse_range_head(
        &mut self,
        action: &str,
    ) -> std::result::Result<(Vec<String>, Pipeline), TemplateError> {
        let tokens = lex_action(action)?;
        let mut index = 1usize;
        let mut variables = Vec::new();
        // Optional `$k, $v :=` or `$v :=` variable declarations before the pipeline.
        if let Some(ActToken::Variable(name)) = tokens.get(index) {
            let mut next = index + 1;
            if tokens.get(next) == Some(&ActToken::Comma) {
                if let Some(ActToken::Variable(second)) = tokens.get(next + 1) {
                    variables.push(name.clone());
                    variables.push(second.clone());
                    next += 2;
                } else {
                    return Err(TemplateError::Parse(format!(
                        "invalid range variable list in `{action}`"
                    )));
                }
            } else {
                variables.push(name.clone());
            }
            if tokens.get(next) == Some(&ActToken::Declare) {
                index = next + 1;
                if variables.len() == 1 {
                    // Single range variable receives the element; we keep the declaration list.
                }
            } else {
                return Err(TemplateError::Parse(format!(
                    "range variable declaration in `{action}` must use `:=`"
                )));
            }
        }
        if index >= tokens.len() {
            return Err(TemplateError::Parse(format!(
                "`{action}` requires a pipeline"
            )));
        }
        Ok((variables, parse_pipeline_tokens(&tokens[index..], action)?))
    }
}

// ---------------------------------------------------------------------------------------------
// Renderer

struct Renderer<'a> {
    request: &'a Request,
    root: Option<PathBuf>,
    root_value: Value,
    args: Vec<Value>,
    scopes: Vec<HashMap<String, Value>>,
    definitions: BTreeMap<String, Vec<Node>>,
    response_headers: HeaderMap,
    depth: usize,
    delimiters: (String, String),
}

impl<'a> Renderer<'a> {
    fn new(request: &'a Request, root: Option<PathBuf>) -> Self {
        let root_value = request_value(request);
        Self {
            request,
            root,
            root_value,
            args: Vec::new(),
            scopes: Vec::new(),
            definitions: BTreeMap::new(),
            response_headers: HeaderMap::new(),
            depth: 0,
            delimiters: ("{{".to_string(), "}}".to_string()),
        }
    }

    fn render_source(
        &mut self,
        source: &str,
        delimiters: &(String, String),
    ) -> std::result::Result<String, TemplateError> {
        self.delimiters = delimiters.clone();
        let template = parse_template(source, delimiters)?;
        for (name, nodes) in template.definitions {
            self.definitions.entry(name).or_insert(nodes);
        }
        let dot = self.root_value.clone();
        let mut output = String::new();
        // Top-level variable assignments need a scope to live in.
        self.scopes.push(HashMap::new());
        let result = self.render_nodes(&template.nodes, &dot, &mut output);
        self.scopes.pop();
        result?;
        Ok(output)
    }

    fn render_nodes(
        &mut self,
        nodes: &[Node],
        dot: &Value,
        output: &mut String,
    ) -> std::result::Result<(), TemplateError> {
        for node in nodes {
            match node {
                Node::Text(text) => output.push_str(text),
                Node::Action(pipeline) => {
                    let value = self.evaluate(pipeline, dot)?;
                    output.push_str(&value.render());
                }
                Node::If {
                    branches,
                    otherwise,
                } => {
                    let mut chosen = None;
                    for (condition, body) in branches {
                        if self.evaluate(condition, dot)?.truthy() {
                            chosen = Some(body);
                            break;
                        }
                    }
                    match chosen {
                        Some(body) => self.render_nodes(body, dot, output)?,
                        None => self.render_nodes(otherwise, dot, output)?,
                    }
                }
                Node::With {
                    pipeline,
                    body,
                    otherwise,
                } => {
                    let value = self.evaluate(pipeline, dot)?;
                    if value.truthy() {
                        self.render_nodes(body, &value, output)?;
                    } else {
                        self.render_nodes(otherwise, dot, output)?;
                    }
                }
                Node::Range {
                    pipeline,
                    variables,
                    body,
                    otherwise,
                } => {
                    let value = self.evaluate(pipeline, dot)?;
                    let items: Vec<(Value, Value)> = match value {
                        Value::List(values) => values
                            .into_iter()
                            .enumerate()
                            .map(|(index, value)| (Value::Int(index as i64), value))
                            .collect(),
                        Value::Map(values) => values
                            .into_iter()
                            .map(|(key, value)| (Value::Str(key), value))
                            .collect(),
                        Value::Str(text) => text
                            .chars()
                            .enumerate()
                            .map(|(index, ch)| {
                                (Value::Int(index as i64), Value::Str(ch.to_string()))
                            })
                            .collect(),
                        Value::Null => Vec::new(),
                        other => vec![(Value::Int(0), other)],
                    };
                    if items.is_empty() {
                        self.render_nodes(otherwise, dot, output)?;
                    } else {
                        for (key, item) in items {
                            self.scopes.push(HashMap::new());
                            if variables.len() >= 2 {
                                self.scopes
                                    .last_mut()
                                    .expect("pushed scope")
                                    .insert(variables[0].trim_start_matches('$').to_string(), key);
                                self.scopes.last_mut().expect("pushed scope").insert(
                                    variables[1].trim_start_matches('$').to_string(),
                                    item.clone(),
                                );
                            } else if let Some(first) = variables.first() {
                                self.scopes.last_mut().expect("pushed scope").insert(
                                    first.trim_start_matches('$').to_string(),
                                    item.clone(),
                                );
                            }
                            self.render_nodes(body, &item, output)?;
                            self.scopes.pop();
                        }
                    }
                }
                Node::Template { name, pipeline } => {
                    let Some(nodes) = self.definitions.get(name).cloned() else {
                        return Err(TemplateError::Exec(format!(
                            "template `{name}` is not defined (define it or import it first)"
                        )));
                    };
                    let value = match pipeline {
                        Some(pipeline) => self.evaluate(pipeline, dot)?,
                        None => dot.clone(),
                    };
                    self.render_nodes(&nodes.clone(), &value, output)?;
                }
                Node::Assign { name, pipeline } => {
                    let value = self.evaluate(pipeline, dot)?;
                    let scope = self.scopes.last_mut().ok_or_else(|| {
                        TemplateError::Exec("variable assignment outside a block".to_string())
                    })?;
                    scope.insert(name.trim_start_matches('$').to_string(), value);
                }
            }
        }
        Ok(())
    }

    fn evaluate(
        &mut self,
        pipeline: &Pipeline,
        dot: &Value,
    ) -> std::result::Result<Value, TemplateError> {
        let mut value: Option<Value> = None;
        for (index, command) in pipeline.commands.iter().enumerate() {
            if index == 0 {
                value = Some(self.evaluate_command(command, dot, None)?);
            } else {
                let piped = value.clone().unwrap_or(Value::Null);
                value = Some(self.evaluate_command(command, dot, Some(piped))?);
            }
        }
        Ok(value.unwrap_or(Value::Null))
    }

    fn evaluate_command(
        &mut self,
        command: &Command,
        dot: &Value,
        piped: Option<Value>,
    ) -> std::result::Result<Value, TemplateError> {
        let Some(first) = command.operands.first() else {
            return Ok(Value::Null);
        };
        match first {
            Operand::Function(name) => {
                let mut args = Vec::new();
                for operand in &command.operands[1..] {
                    args.push(self.evaluate_operand(operand, dot)?);
                }
                if let Some(piped) = piped {
                    args.push(piped);
                }
                self.call_function(name, args)
            }
            Operand::Field(path) => {
                if !command.operands[1..].is_empty() {
                    let mut args = Vec::new();
                    for operand in &command.operands[1..] {
                        args.push(self.evaluate_operand(operand, dot)?);
                    }
                    if let Some(piped) = piped {
                        args.push(piped);
                    }
                    self.call_method(path, args, dot)
                } else if let Some(piped) = piped {
                    // A piped non-function value followed by no args is just the piped value.
                    Ok(piped)
                } else {
                    self.resolve_field(path, dot)
                }
            }
            Operand::Variable(path) => {
                let value = self.resolve_variable(path, dot)?;
                if !command.operands[1..].is_empty() {
                    return Err(TemplateError::Exec(format!(
                        "cannot call variable `{path}` with arguments"
                    )));
                }
                Ok(value)
            }
            Operand::Literal(value) => {
                if !command.operands[1..].is_empty() {
                    return Err(TemplateError::Exec(
                        "cannot call a literal value with arguments".to_string(),
                    ));
                }
                Ok(value.clone())
            }
            Operand::Pipeline(inner) => {
                if !command.operands[1..].is_empty() {
                    return Err(TemplateError::Exec(
                        "a parenthesized pipeline cannot be called with extra arguments"
                            .to_string(),
                    ));
                }
                self.evaluate(inner, dot)
            }
        }
    }

    fn evaluate_operand(
        &mut self,
        operand: &Operand,
        dot: &Value,
    ) -> std::result::Result<Value, TemplateError> {
        match operand {
            Operand::Literal(value) => Ok(value.clone()),
            Operand::Field(path) => self.resolve_field(path, dot),
            Operand::Variable(path) => self.resolve_variable(path, dot),
            Operand::Function(name) => Err(TemplateError::Exec(format!(
                "template function `{name}` used as a value (call it with arguments)"
            ))),
            Operand::Pipeline(inner) => self.evaluate(inner, dot),
        }
    }

    fn resolve_variable(
        &self,
        path: &str,
        _dot: &Value,
    ) -> std::result::Result<Value, TemplateError> {
        let path = path.trim_start_matches('$');
        if path.is_empty() {
            return Ok(self.root_value.clone());
        }
        let mut segments = path.split('.');
        let name = segments.next().unwrap_or("");
        let mut value = self
            .scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).cloned())
            .ok_or_else(|| TemplateError::Exec(format!("undefined template variable `${name}`")))?;
        for segment in segments {
            value = index_value(&value, segment).ok_or_else(|| {
                TemplateError::Exec(format!("variable `${path}` has no field `{segment}`"))
            })?;
        }
        Ok(value)
    }

    fn resolve_field(&self, path: &str, dot: &Value) -> std::result::Result<Value, TemplateError> {
        let path = path.trim_start_matches('.');
        if path.is_empty() {
            return Ok(dot.clone());
        }
        if path == "Args" {
            return Ok(Value::List(self.args.clone()));
        }
        if let Some(index) = path.strip_prefix("Args.") {
            let index: usize = index
                .parse()
                .map_err(|_| TemplateError::Exec("`.Args` index must be an integer".to_string()))?;
            return Ok(self.args.get(index).cloned().unwrap_or(Value::Null));
        }
        let mut value = if path == "Req"
            || path.starts_with("Req.")
            || path == "Host"
            || path == "RemoteIP"
            || path == "ClientIP"
            || path == "Args"
            || path == "OriginalReq"
            || path == "RespHeader"
        {
            self.root_value.clone()
        } else {
            dot.clone()
        };
        for segment in path.split('.') {
            value = index_value(&value, segment).ok_or_else(|| {
                TemplateError::Exec(format!(
                    "template field `.{}` is not present in the template context",
                    path
                ))
            })?;
        }
        Ok(value)
    }

    fn call_method(
        &mut self,
        path: &str,
        args: Vec<Value>,
        _dot: &Value,
    ) -> std::result::Result<Value, TemplateError> {
        match path {
            ".Cookie" => {
                let [name] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        ".Cookie requires one argument".to_string(),
                    ));
                };
                Ok(Value::Str(
                    self.request
                        .get_placeholder(&format!("http.request.cookie.{}", name.render()))
                        .unwrap_or_default(),
                ))
            }
            ".Req.Header.Get" => {
                let [name] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        ".Req.Header.Get requires one argument".to_string(),
                    ));
                };
                let name = name.render();
                Ok(self
                    .request
                    .headers
                    .get(name.as_str())
                    .and_then(|value| value.to_str().ok())
                    .map(|value| Value::Str(value.to_string()))
                    .unwrap_or_else(|| Value::Str(String::new())))
            }
            ".RespHeader.Set" | ".RespHeader.Add" | ".RespHeader.Del" => {
                let method = path.rsplit('.').next().unwrap_or("");
                if method == "Del" {
                    let [name] = args.as_slice() else {
                        return Err(TemplateError::Exec(
                            ".RespHeader.Del requires one argument".to_string(),
                        ));
                    };
                    if let Ok(name) = http::HeaderName::from_bytes(name.render().as_bytes()) {
                        self.response_headers.remove(name);
                    }
                    return Ok(Value::Str(String::new()));
                }
                let [name, value] = args.as_slice() else {
                    return Err(TemplateError::Exec(format!(
                        ".RespHeader.{method} requires two arguments"
                    )));
                };
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(name.render().as_bytes()),
                    HeaderValue::from_str(&value.render()),
                ) {
                    if method == "Add" {
                        self.response_headers.append(name, value);
                    } else {
                        self.response_headers.insert(name, value);
                    }
                }
                Ok(Value::Str(String::new()))
            }
            other => Err(TemplateError::Exec(format!(
                "template method `{other}` is not implemented by this build"
            ))),
        }
    }

    fn call_function(
        &mut self,
        name: &str,
        args: Vec<Value>,
    ) -> std::result::Result<Value, TemplateError> {
        match name {
            "placeholder" | "ph" => {
                let [name] = args.as_slice() else {
                    return Err(TemplateError::Exec(format!("{name} requires one argument")));
                };
                let name = name.render();
                if name.starts_with("file.") {
                    // Caddy strips the file placeholder from the template replacer to prevent
                    // untrusted templates from reading arbitrary files.
                    return Err(TemplateError::Exec(
                        "the `file.*` placeholder is not available in templates".to_string(),
                    ));
                }
                Ok(Value::Str(
                    self.request.get_placeholder(&name).unwrap_or_default(),
                ))
            }
            "env" => {
                let [name] = args.as_slice() else {
                    return Err(TemplateError::Exec("env requires one argument".to_string()));
                };
                Ok(Value::Str(std::env::var(name.render()).unwrap_or_default()))
            }
            "include" => {
                let Some(path) = args.first() else {
                    return Err(TemplateError::Exec(
                        "include requires a filename".to_string(),
                    ));
                };
                let path = path.render();
                let source = self.read_file(&path)?;
                let saved_args = std::mem::replace(&mut self.args, args[1..].to_vec());
                let saved_scopes = std::mem::take(&mut self.scopes);
                self.depth += 1;
                if self.depth > 8 {
                    self.depth -= 1;
                    self.args = saved_args;
                    self.scopes = saved_scopes;
                    return Err(TemplateError::Exec(
                        "template include recursion limit exceeded".to_string(),
                    ));
                }
                let result = self
                    .render_source(&source, &self.delimiters.clone())
                    .map(Value::Str);
                self.depth -= 1;
                self.args = saved_args;
                self.scopes = saved_scopes;
                result
            }
            "import" => {
                let Some(path) = args.first() else {
                    return Err(TemplateError::Exec(
                        "import requires a filename".to_string(),
                    ));
                };
                let source = self.read_file(&path.render())?;
                let template = parse_template(&source, &self.delimiters.clone())?;
                for (name, nodes) in template.definitions {
                    self.definitions.insert(name, nodes);
                }
                Ok(Value::Str(String::new()))
            }
            "readFile" => {
                let Some(path) = args.first() else {
                    return Err(TemplateError::Exec(
                        "readFile requires a filename".to_string(),
                    ));
                };
                Ok(Value::Str(self.read_file(&path.render())?))
            }
            "fileExists" => {
                let Some(path) = args.first() else {
                    return Err(TemplateError::Exec(
                        "fileExists requires a filename".to_string(),
                    ));
                };
                Ok(Value::Bool(
                    self.resolve_file_path(&path.render())
                        .is_some_and(|path| path.exists()),
                ))
            }
            "stripHTML" => {
                let [input] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "stripHTML requires one argument".to_string(),
                    ));
                };
                Ok(Value::Str(strip_html(&input.render())))
            }
            "truncate" => {
                let [length, input] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "truncate requires a length and a string".to_string(),
                    ));
                };
                let length = as_int(length).ok_or_else(|| {
                    TemplateError::Exec("truncate length must be an integer".to_string())
                })?;
                let text = input.render();
                Ok(Value::Str(
                    text.chars().take(length.max(0) as usize).collect(),
                ))
            }
            "replace" => {
                let [old, new, input] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "replace requires old, new and string arguments".to_string(),
                    ));
                };
                Ok(Value::Str(
                    input.render().replace(&old.render(), &new.render()),
                ))
            }
            "splitFrontMatter" => {
                let [input] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "splitFrontMatter requires one argument".to_string(),
                    ));
                };
                Ok(split_front_matter(&input.render()))
            }
            "httpError" => {
                let [status] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "httpError requires a status code".to_string(),
                    ));
                };
                let status = as_int(status)
                    .and_then(|status| u16::try_from(status).ok())
                    .and_then(|status| StatusCode::from_u16(status).ok())
                    .ok_or_else(|| {
                        TemplateError::Exec("httpError requires a valid status code".to_string())
                    })?;
                Err(TemplateError::Http(status))
            }
            "pathEscape" => {
                let [input] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "pathEscape requires one argument".to_string(),
                    ));
                };
                Ok(Value::Str(percent_encode_path(&input.render())))
            }
            "html" => {
                let [input] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "html requires one argument".to_string(),
                    ));
                };
                Ok(Value::Str(html_escape(&input.render())))
            }
            "upper" => {
                let [input] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "upper requires one argument".to_string(),
                    ));
                };
                Ok(Value::Str(input.render().to_uppercase()))
            }
            "lower" => {
                let [input] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "lower requires one argument".to_string(),
                    ));
                };
                Ok(Value::Str(input.render().to_lowercase()))
            }
            "split" => {
                let [separator, input] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "split requires separator and string".to_string(),
                    ));
                };
                Ok(Value::List(
                    input
                        .render()
                        .split(&separator.render())
                        .map(|part| Value::Str(part.to_string()))
                        .collect(),
                ))
            }
            "join" => {
                let [separator, list] = args.as_slice() else {
                    return Err(TemplateError::Exec(
                        "join requires separator and list".to_string(),
                    ));
                };
                let Value::List(values) = list else {
                    return Err(TemplateError::Exec("join requires a list".to_string()));
                };
                Ok(Value::Str(
                    values
                        .iter()
                        .map(Value::render)
                        .collect::<Vec<_>>()
                        .join(&separator.render()),
                ))
            }
            "list" => Ok(Value::List(args)),
            "index" => {
                let Some(collection) = args.first() else {
                    return Err(TemplateError::Exec(
                        "index requires a collection".to_string(),
                    ));
                };
                let mut value = collection.clone();
                for key in &args[1..] {
                    let key = key.render();
                    match &value {
                        Value::Map(map) => {
                            value = map
                                .get(&key)
                                .cloned()
                                .or_else(|| {
                                    map.iter()
                                        .find(|(name, _)| name.eq_ignore_ascii_case(&key))
                                        .map(|(_, value)| value.clone())
                                })
                                .unwrap_or(Value::Null);
                        }
                        _ => {
                            value = index_value(&value, &key).ok_or_else(|| {
                                TemplateError::Exec(
                                    "index: key not found in template value".to_string(),
                                )
                            })?;
                        }
                    }
                }
                Ok(value)
            }
            "len" => {
                let [value] = args.as_slice() else {
                    return Err(TemplateError::Exec("len requires one argument".to_string()));
                };
                let length = match value {
                    Value::Str(text) => text.chars().count(),
                    Value::List(values) => values.len(),
                    Value::Map(values) => values.len(),
                    _ => 0,
                };
                Ok(Value::Int(length as i64))
            }
            "eq" | "ne" | "lt" | "le" | "gt" | "ge" => {
                if args.len() < 2 {
                    return Err(TemplateError::Exec(format!(
                        "{name} requires two arguments"
                    )));
                }
                let left = &args[0];
                let right = &args[1];
                let result = compare_values(name, left, right)?;
                Ok(Value::Bool(result))
            }
            "and" => Ok(Value::Bool(args.iter().all(Value::truthy))),
            "or" => Ok(Value::Bool(args.iter().any(Value::truthy))),
            "not" => {
                let [value] = args.as_slice() else {
                    return Err(TemplateError::Exec("not requires one argument".to_string()));
                };
                Ok(Value::Bool(!value.truthy()))
            }
            "print" => Ok(Value::Str(
                args.iter().map(Value::render).collect::<String>(),
            )),
            "printf" => {
                let Some(format) = args.first() else {
                    return Err(TemplateError::Exec(
                        "printf requires a format string".to_string(),
                    ));
                };
                let format = format.render();
                let mut rendered = String::new();
                let mut rest = args[1..].iter();
                let mut chars = format.chars();
                while let Some(ch) = chars.next() {
                    if ch != '%' {
                        rendered.push(ch);
                        continue;
                    }
                    match chars.next() {
                        Some('%') => rendered.push('%'),
                        Some('s') | Some('v') => {
                            if let Some(value) = rest.next() {
                                rendered.push_str(&value.render());
                            }
                        }
                        Some('d') => {
                            if let Some(value) = rest.next() {
                                if let Some(value) = as_int(value) {
                                    rendered.push_str(&value.to_string());
                                }
                            }
                        }
                        Some(other) => {
                            rendered.push('%');
                            rendered.push(other);
                        }
                        None => rendered.push('%'),
                    }
                }
                Ok(Value::Str(rendered))
            }
            other => Err(TemplateError::Exec(format!(
                "template function `{other}` is not implemented by this build"
            ))),
        }
    }

    fn resolve_file_path(&self, name: &str) -> Option<PathBuf> {
        let root = self.root.as_ref()?;
        let mut parts: Vec<std::ffi::OsString> = Vec::new();
        for component in Path::new(name).components() {
            match component {
                Component::Normal(part) => parts.push(part.to_os_string()),
                Component::CurDir => {}
                Component::ParentDir => {
                    // `http.Dir` cleans `/`+name against the root; never climb above it.
                    parts.pop();
                }
                Component::RootDir | Component::Prefix(_) => {}
            }
        }
        Some(
            parts
                .iter()
                .fold(root.clone(), |path, part| path.join(part)),
        )
    }

    fn read_file(&self, name: &str) -> std::result::Result<String, TemplateError> {
        let path = self.resolve_file_path(name).ok_or_else(|| {
            TemplateError::Exec("template file root is not configured".to_string())
        })?;
        std::fs::read_to_string(&path).map_err(|error| {
            TemplateError::Exec(format!(
                "template file `{}` could not be read: {error}",
                path.display()
            ))
        })
    }

    fn apply_response_headers(&self, headers: &mut HeaderMap) {
        for (name, value) in &self.response_headers {
            headers.insert(name.clone(), value.clone());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers

fn invalid(path: impl Into<String>, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.into(),
        message: message.into(),
    }
}

fn request_value(request: &Request) -> Value {
    let mut req = BTreeMap::new();
    req.insert(
        "Method".to_string(),
        Value::Str(request.method.as_str().to_string()),
    );
    req.insert(
        "Host".to_string(),
        Value::Str(
            request
                .get_placeholder("http.request.host")
                .unwrap_or_default(),
        ),
    );
    let mut url = BTreeMap::new();
    url.insert(
        "Path".to_string(),
        Value::Str(request.uri.path().to_string()),
    );
    url.insert(
        "RawQuery".to_string(),
        Value::Str(request.uri.query().unwrap_or("").to_string()),
    );
    url.insert(
        "Scheme".to_string(),
        Value::Str(if request.tls { "https" } else { "http" }.to_string()),
    );
    url.insert(
        "Host".to_string(),
        Value::Str(
            request
                .get_placeholder("http.request.host")
                .unwrap_or_default(),
        ),
    );
    req.insert("URL".to_string(), Value::Map(url));
    let mut headers = BTreeMap::new();
    for (name, value) in &request.headers {
        let entry = headers
            .entry(name.as_str().to_string())
            .or_insert_with(|| Value::List(Vec::new()));
        if let Value::List(values) = entry {
            if let Ok(value) = value.to_str() {
                values.push(Value::Str(value.to_string()));
            }
        }
    }
    req.insert("Header".to_string(), Value::Map(headers));
    req.insert(
        "Proto".to_string(),
        Value::Str(format!("{:?}", request.version)),
    );
    req.insert(
        "RemoteAddr".to_string(),
        Value::Str(
            request
                .remote_addr
                .map(|address| address.to_string())
                .unwrap_or_default(),
        ),
    );
    req.insert("TLS".to_string(), Value::Bool(request.tls));
    let req = Value::Map(req);
    let mut root = BTreeMap::new();
    root.insert("Req".to_string(), req.clone());
    root.insert("OriginalReq".to_string(), req);
    root.insert(
        "Host".to_string(),
        Value::Str(
            request
                .get_placeholder("http.request.host")
                .unwrap_or_default(),
        ),
    );
    root.insert(
        "RemoteIP".to_string(),
        Value::Str(
            request
                .get_placeholder("http.request.remote.host")
                .unwrap_or_default(),
        ),
    );
    root.insert(
        "ClientIP".to_string(),
        Value::Str(
            request
                .get_placeholder("http.vars.client_ip")
                .unwrap_or_default(),
        ),
    );
    root.insert("Args".to_string(), Value::List(Vec::new()));
    root.insert("RespHeader".to_string(), Value::Map(BTreeMap::new()));
    Value::Map(root)
}

fn index_value(value: &Value, key: &str) -> Option<Value> {
    match value {
        Value::Map(map) => map.get(key).cloned().or_else(|| {
            map.iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(key))
                .map(|(_, value)| value.clone())
        }),
        Value::List(values) => key
            .parse::<usize>()
            .ok()
            .and_then(|index| values.get(index).cloned()),
        Value::Str(text) => key
            .parse::<usize>()
            .ok()
            .and_then(|index| text.chars().nth(index))
            .map(|ch| Value::Str(ch.to_string())),
        _ => None,
    }
}

fn as_int(value: &Value) -> Option<i64> {
    match value {
        Value::Int(value) => Some(*value),
        Value::Float(value) => Some(*value as i64),
        Value::Str(value) => value.parse().ok(),
        _ => None,
    }
}

fn as_float(value: &Value) -> Option<f64> {
    match value {
        Value::Int(value) => Some(*value as f64),
        Value::Float(value) => Some(*value),
        Value::Str(value) => value.parse().ok(),
        _ => None,
    }
}

fn compare_values(
    op: &str,
    left: &Value,
    right: &Value,
) -> std::result::Result<bool, TemplateError> {
    let both_strings = matches!(left, Value::Str(_)) && matches!(right, Value::Str(_));
    if both_strings {
        let left = left.render();
        let right = right.render();
        return Ok(match op {
            "eq" => left == right,
            "ne" => left != right,
            "lt" => left < right,
            "le" => left <= right,
            "gt" => left > right,
            "ge" => left >= right,
            _ => unreachable!("matched comparison op"),
        });
    }
    let left_number = as_float(left);
    let right_number = as_float(right);
    if let (Some(left), Some(right)) = (left_number, right_number) {
        return Ok(match op {
            "eq" => (left - right).abs() < f64::EPSILON,
            "ne" => (left - right).abs() >= f64::EPSILON,
            "lt" => left < right,
            "le" => left <= right,
            "gt" => left > right,
            "ge" => left >= right,
            _ => unreachable!("matched comparison op"),
        });
    }
    if op == "eq" {
        return Ok(left == right);
    }
    if op == "ne" {
        return Ok(left != right);
    }
    Err(TemplateError::Exec(format!(
        "template comparison `{op}` requires comparable values"
    )))
}

fn strip_html(input: &str) -> String {
    let mut output = String::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    for ch in input.chars() {
        match ch {
            '<' if quote.is_none() => depth += 1,
            '>' if quote.is_none() => {
                if depth > 0 {
                    depth -= 1;
                } else {
                    output.push(ch);
                }
            }
            '"' | '\'' if depth > 0 && quote == Some(ch) => quote = None,
            '"' | '\'' if depth > 0 && quote.is_none() => quote = Some(ch),
            _ if depth == 0 => output.push(ch),
            _ => {}
        }
    }
    output
}

fn html_escape(input: &str) -> String {
    let mut escaped = String::new();
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&#34;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn percent_encode_path(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                output.push(byte as char)
            }
            other => output.push_str(&format!("%{other:02X}")),
        }
    }
    output
}

fn split_front_matter(input: &str) -> Value {
    let mut meta = BTreeMap::new();
    let mut body = input.to_string();
    let (opening, closing) = if input.starts_with("---\n") {
        ("---\n", "\n---")
    } else if input.starts_with("+++\n") {
        ("+++\n", "\n+++")
    } else {
        return Value::Map(BTreeMap::from([
            ("Meta".to_string(), Value::Map(meta)),
            ("Body".to_string(), Value::Str(body)),
        ]));
    };
    let rest = &input[opening.len()..];
    if let Some(end) = rest.find(closing) {
        let raw_meta = &rest[..end];
        body = rest[end + closing.len()..]
            .trim_start_matches('\n')
            .to_string();
        for line in raw_meta.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once(':').or_else(|| line.split_once('=')) {
                let key = key.trim().trim_matches('"').to_string();
                let value = value.trim().trim_matches('"').to_string();
                meta.insert(key, Value::Str(value));
            }
        }
    }
    Value::Map(BTreeMap::from([
        ("Meta".to_string(), Value::Map(meta)),
        ("Body".to_string(), Value::Str(body)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn request(path: &str) -> Request {
        let mut request = Request::new(Method::GET, path.parse().unwrap());
        request
            .headers
            .insert(header::HOST, HeaderValue::from_static("example.com"));
        request
    }

    fn render(source: &str, request: &Request) -> std::result::Result<String, TemplateError> {
        let mut renderer = Renderer::new(request, Some(PathBuf::from(".")));
        renderer.render_source(source, &("{{".to_string(), "}}".to_string()))
    }

    #[test]
    fn placeholder_and_control_structures() {
        let mut request = request("/foo");
        request
            .headers
            .insert("x-test", HeaderValue::from_static("one"));
        request
            .headers
            .append("x-test", HeaderValue::from_static("two"));
        assert_eq!(
            render(
                "{{placeholder \"http.request.method\"}} {{ph \"http.request.uri.path\"}}",
                &request
            )
            .unwrap(),
            "GET /foo"
        );
        assert_eq!(
            render(
                "{{if eq (ph \"http.request.method\") \"GET\"}}yes{{else}}no{{end}}",
                &request
            )
            .unwrap(),
            "yes"
        );
        assert_eq!(
            render("{{with .Req.URL.Path}}{{.}}{{else}}none{{end}}", &request).unwrap(),
            "/foo"
        );
        assert_eq!(
            render(
                "{{range index .Req.Header \"x-test\"}}{{.}},{{end}}",
                &request
            )
            .unwrap(),
            "one,two,"
        );
        assert_eq!(
            render("{{/* comment */}}a{{- \"b\" -}}   c", &request).unwrap(),
            "abc"
        );
    }

    #[test]
    fn delimiters_and_functions() {
        let request = request("/");
        let mut renderer = Renderer::new(&request, Some(PathBuf::from(".")));
        assert_eq!(
            renderer
                .render_source(
                    "<<if true>>yes<<else>>no<<end>>",
                    &("<<".to_string(), ">>".to_string())
                )
                .unwrap(),
            "yes"
        );
        assert_eq!(
            render("{{stripHTML \"<b>hello</b> <i>world</i>\"}}", &request).unwrap(),
            "hello world"
        );
        assert_eq!(
            render("{{truncate 3 \"abcdef\"}}", &request).unwrap(),
            "abc"
        );
        assert_eq!(
            render("{{replace \"a\" \"b\" \"banana\"}}", &request).unwrap(),
            "bbnbnb"
        );
        assert_eq!(render("{{html \"<a>\"}}", &request).unwrap(), "&lt;a&gt;");
    }

    #[test]
    fn variables_and_definitions() {
        let request = request("/");
        assert_eq!(render("{{$x := \"hi\"}}{{$x}}", &request).unwrap(), "hi");
        assert_eq!(
            render(
                "{{define \"greeting\"}}hello {{.}}{{end}}{{template \"greeting\" \"world\"}}",
                &request
            )
            .unwrap(),
            "hello world"
        );
    }

    #[test]
    fn split_front_matter_returns_meta_and_body() {
        let request = request("/");
        assert_eq!(
            render("{{$doc := splitFrontMatter \"---\\ntitle: Hi\\n---\\nBody\"}}{{$doc.Meta.title}}|{{$doc.Body}}", &request).unwrap(),
            "Hi|Body"
        );
    }

    #[test]
    fn else_if_range_variables_and_include_args() {
        let request = request("/");
        assert_eq!(
            render(
                "{{if eq 1 2}}a{{else if eq 1 1}}b{{else}}c{{end}}",
                &request
            )
            .unwrap(),
            "b"
        );
        assert_eq!(
            render(
                "{{range $i, $v := list \"x\" \"y\"}}{{$i}}={{$v}};{{end}}",
                &request
            )
            .unwrap(),
            "0=x;1=y;"
        );
        assert_eq!(
            render("{{include \"args.html\" \"one\" 2}}", &request)
                .unwrap_err()
                .to_string()
                .contains("could not be read"),
            true
        );
    }

    #[test]
    fn malformed_templates_fail_loudly() {
        let request = request("/");
        assert!(render("{{if true}}missing end", &request).is_err());
        assert!(render("{{unknown_function}}", &request).is_err());
        assert!(render("{{", &request).is_err());
        assert!(render("{{.Req.Header.Get}}", &request).is_err());
    }

    #[test]
    fn template_handler_config_and_transform() {
        let handler = TemplatesHandler::from_json(
            &serde_json::json!({
                "handler": "templates",
                "file_root": ".",
                "mime_types": ["text/html"],
                "delimiters": ["<<", ">>"]
            }),
            "handler",
        )
        .expect("config");
        assert_eq!(handler.config.delimiters.0, "<<");
        let between = TemplatesHandler::from_json(
            &serde_json::json!({"handler": "templates", "between": ["<<", ">>"]}),
            "handler",
        )
        .expect("between alias");
        assert_eq!(between.config.delimiters.0, "<<");
        let error = TemplatesHandler::from_json(
            &serde_json::json!({"handler": "templates", "delimiters": ["<<"]}),
            "handler",
        )
        .expect_err("bad delimiters");
        assert!(error.to_string().contains("delimiters"), "{error}");
    }
}
