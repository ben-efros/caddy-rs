//! Built-in HTTP handlers for the supported Caddy module set.
//!
//! Handler values that Caddy expands through the request replacer are expanded here with the
//! request-scoped [`crate::placeholders::Replacer`] (T-ROUTE-030/T-ROUTE-031):
//!
//! * `static_response` body and header names/values use `ReplaceKnown` semantics (unknown
//!   placeholders stay visible), matching Caddy's `modules/caddyhttp/staticresp.go`.
//! * `headers` request/response names and values use `ReplaceKnown` semantics, matching
//!   `modules/caddyhttp/headers/headers.go`.
//! * `rewrite` method, `uri` and `strip_path_prefix`, and `vars` keys/values use `ReplaceAll`
//!   semantics (unknown placeholders expand to nothing), matching
//!   `modules/caddyhttp/rewrite/rewrite.go` and `modules/caddyhttp/vars.go`.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode, Uri};

use crate::router::Router;
use crate::types::{Error, Handler, Outcome, Request, Response, Result, StreamingOutcome};

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// Convert a JSON value (string or array of strings) into header values.
pub fn header_values(value: &serde_json::Value, path: &str) -> Result<Vec<HeaderValue>> {
    header_value_strings(value, path)?
        .into_iter()
        .map(|item| {
            HeaderValue::from_str(&item)
                .map_err(|error| invalid(path, format!("invalid header value `{item}`: {error}")))
        })
        .collect()
}

/// Convert a JSON value (string or array of strings) into raw header value strings.
///
/// Expansion happens per request, so values are kept as strings until the handler runs.
fn header_value_strings(value: &serde_json::Value, path: &str) -> Result<Vec<String>> {
    let items: Vec<&str> = match value {
        serde_json::Value::String(value) => vec![value],
        serde_json::Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| invalid(path, "header values must be strings"))
            })
            .collect::<Result<_>>()?,
        _ => {
            return Err(invalid(
                path,
                "header value must be a string or array of strings",
            ))
        }
    };
    Ok(items.into_iter().map(str::to_string).collect())
}

fn expand_header_name(request: &Request, name: &str, path: &str) -> Result<HeaderName> {
    let expanded = request.replace_known(name);
    expanded
        .parse::<HeaderName>()
        .map_err(|error| invalid(path, format!("invalid header name `{expanded}`: {error}")))
}

fn expand_header_values(
    request: &Request,
    values: &[String],
    path: &str,
) -> Result<Vec<HeaderValue>> {
    values
        .iter()
        .map(|value| {
            let expanded = request.replace_known(value);
            HeaderValue::from_str(&expanded).map_err(|error| {
                invalid(path, format!("invalid header value `{expanded}`: {error}"))
            })
        })
        .collect()
}

/// `static_response`: write a fixed response, expanding placeholders in body and headers.
pub struct StaticResponseHandler {
    status: StatusCode,
    headers: Vec<(String, Vec<String>)>,
    body: String,
}

impl StaticResponseHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "static_response must be an object"))?;
        let status = match object.get("status_code") {
            Some(serde_json::Value::Number(number)) => number
                .as_u64()
                .and_then(|code| u16::try_from(code).ok())
                .and_then(|code| StatusCode::from_u16(code).ok())
                .ok_or_else(|| invalid(path, "`status_code` is not a valid HTTP status"))?,
            Some(serde_json::Value::String(text)) => text
                .parse::<u16>()
                .ok()
                .and_then(|code| StatusCode::from_u16(code).ok())
                .ok_or_else(|| invalid(path, "`status_code` is not a valid HTTP status"))?,
            Some(_) => return Err(invalid(path, "`status_code` must be a number")),
            None => StatusCode::OK,
        };
        let body = object
            .get("body")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut headers = Vec::new();
        if let Some(values) = object.get("headers") {
            let values = values
                .as_object()
                .ok_or_else(|| invalid(path, "`headers` must be an object"))?;
            for (field, value) in values {
                headers.push((
                    field.clone(),
                    header_value_strings(value, &format!("{path}.headers.{field}"))?,
                ));
            }
        }
        Ok(Self {
            status,
            headers,
            body,
        })
    }
}

/// Caddy's implicit `Content-Type` for a `static_response` body.
///
/// Mirrors `modules/caddyhttp/staticresp.go`: a body that (after trimming whitespace) is at least
/// three bytes long, starts/ends with `{`/`}` or `[`/`]`, and is valid JSON is served as
/// `application/json`; every other non-empty body is `text/plain; charset=utf-8`.
fn implicit_content_type(body: &str) -> &'static str {
    let trimmed = body.trim();
    if trimmed.len() > 2 {
        let bytes = trimmed.as_bytes();
        let braced = bytes[0] == b'{' && bytes[bytes.len() - 1] == b'}';
        let bracketed = bytes[0] == b'[' && bytes[bytes.len() - 1] == b']';
        if (braced || bracketed) && serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            return "application/json";
        }
    }
    "text/plain; charset=utf-8"
}

/// Caddy only fills in an implicit `Content-Type` when the configured headers left it absent or
/// empty (`w.Header().Get("Content-Type") == ""`); an explicit non-empty value always wins.
fn implicit_content_type_is_unset(headers: &http::HeaderMap) -> bool {
    match headers.get(http::header::CONTENT_TYPE) {
        None => true,
        Some(value) => value.is_empty(),
    }
}

#[async_trait]
impl Handler for StaticResponseHandler {
    fn name(&self) -> &'static str {
        "static_response"
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        let body = request.replace_known(&self.body);
        // Caddy sets the implicit Content-Type from the *expanded* body, on GET and HEAD alike;
        // the body itself is discarded by the transport for HEAD, never the headers.
        let implicit_type = if body.is_empty() {
            None
        } else {
            Some(implicit_content_type(&body))
        };
        let mut response = Response {
            status: self.status,
            headers: http::HeaderMap::new(),
            body: Bytes::from(body),
        };
        for (raw_name, values) in &self.headers {
            let path = format!("static_response.headers.{raw_name}");
            let name = expand_header_name(&request, raw_name, &path)?;
            let values = expand_header_values(&request, values, &path)?;
            for value in values {
                response.headers.append(name.clone(), value);
            }
        }
        if let Some(content_type) = implicit_type {
            if implicit_content_type_is_unset(&response.headers) {
                response.headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static(content_type),
                );
            }
        }
        Ok(Outcome::Respond(response))
    }
}

/// `headers`: stage response header mutations (and apply request header mutations).
pub struct HeadersHandler {
    request_set: Vec<(String, Vec<String>)>,
    response_set: Vec<(String, Vec<String>)>,
    response_add: Vec<(String, Vec<String>)>,
    response_delete: Vec<String>,
}

impl HeadersHandler {
    /// Build from Caddy JSON (`{"handler":"headers","response":{...}}`).
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "headers handler must be an object"))?;
        let mut handler = Self {
            request_set: Vec::new(),
            response_set: Vec::new(),
            response_add: Vec::new(),
            response_delete: Vec::new(),
        };
        if let Some(request) = object.get("request") {
            handler.request_set = parse_header_operations(request, &format!("{path}.request"))?;
        }
        if let Some(response) = object.get("response") {
            let response_path = format!("{path}.response");
            let response_object = response
                .as_object()
                .ok_or_else(|| invalid(&response_path, "response must be an object"))?;
            if let Some(set) = response_object.get("set") {
                handler.response_set = parse_header_map(set, &format!("{response_path}.set"))?;
            }
            if let Some(add) = response_object.get("add") {
                handler.response_add = parse_header_map(add, &format!("{response_path}.add"))?;
            }
            if let Some(delete) = response_object.get("delete") {
                let delete = delete.as_array().ok_or_else(|| {
                    invalid(
                        &format!("{response_path}.delete"),
                        "delete must be an array",
                    )
                })?;
                for (index, field) in delete.iter().enumerate() {
                    let field = field.as_str().ok_or_else(|| {
                        invalid(
                            &format!("{response_path}.delete[{index}]"),
                            "expected a string",
                        )
                    })?;
                    handler.response_delete.push(field.to_string());
                }
            }
        }
        Ok(handler)
    }
}

fn parse_header_map(value: &serde_json::Value, path: &str) -> Result<Vec<(String, Vec<String>)>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "expected an object"))?;
    let mut output = Vec::new();
    for (field, value) in object {
        output.push((
            field.clone(),
            header_value_strings(value, &format!("{path}.{field}"))?,
        ));
    }
    Ok(output)
}

fn parse_header_operations(
    value: &serde_json::Value,
    path: &str,
) -> Result<Vec<(String, Vec<String>)>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "expected an object"))?;
    if let Some(set) = object.get("set") {
        parse_header_map(set, &format!("{path}.set"))
    } else {
        Ok(Vec::new())
    }
}

#[async_trait]
impl Handler for HeadersHandler {
    fn name(&self) -> &'static str {
        "headers"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        for (raw_name, values) in &self.request_set {
            let path = format!("headers.request.set.{raw_name}");
            let name = expand_header_name(&request, raw_name, &path)?;
            let values = expand_header_values(&request, values, &path)?;
            request.headers.remove(&name);
            for value in values {
                request.headers.append(name.clone(), value);
            }
        }
        for (raw_name, values) in &self.response_set {
            let path = format!("headers.response.set.{raw_name}");
            let name = expand_header_name(&request, raw_name, &path)?;
            let values = expand_header_values(&request, values, &path)?;
            request.pending_response_headers.remove(&name);
            for value in values {
                request.pending_response_headers.append(name.clone(), value);
            }
        }
        for (raw_name, values) in &self.response_add {
            let path = format!("headers.response.add.{raw_name}");
            let name = expand_header_name(&request, raw_name, &path)?;
            let values = expand_header_values(&request, values, &path)?;
            for value in values {
                request.pending_response_headers.append(name.clone(), value);
            }
        }
        for raw_name in &self.response_delete {
            let name = expand_header_name(&request, raw_name, "headers.response.delete")?;
            request.pending_response_headers.remove(&name);
        }
        Ok(Outcome::Continue(request))
    }
}

/// `vars`: set request variables, expanding placeholders in names and values.
pub struct VarsHandler {
    vars: Vec<(String, String)>,
}

impl VarsHandler {
    /// Build from Caddy JSON; every string field except `handler` is a variable.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "vars handler must be an object"))?;
        let mut vars = Vec::new();
        for (key, value) in object {
            if key == "handler" {
                continue;
            }
            let value = match value {
                serde_json::Value::String(value) => value.clone(),
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::Bool(flag) => flag.to_string(),
                _ => continue,
            };
            vars.push((key.clone(), value));
        }
        Ok(Self { vars })
    }
}

#[async_trait]
impl Handler for VarsHandler {
    fn name(&self) -> &'static str {
        "vars"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        let vars: Vec<(String, String)> = self
            .vars
            .iter()
            .map(|(key, value)| (request.replace_all(key), request.replace_all(value)))
            .collect();
        for (key, value) in vars {
            request.vars.insert(key, value);
        }
        Ok(Outcome::Continue(request))
    }
}

/// `rewrite`: change the request URI, method, or path prefix.
///
/// Order of operations matches Caddy's `Rewrite.Rewrite`: method, then URI, then path prefix.
/// Placeholders use `ReplaceAll` semantics, as Caddy does for these fields.
pub struct RewriteHandler {
    uri: Option<String>,
    method: Option<String>,
    strip_path_prefix: Option<String>,
}

impl RewriteHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "rewrite handler must be an object"))?;
        Ok(Self {
            uri: object
                .get("uri")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            method: object
                .get("method")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            strip_path_prefix: object
                .get("strip_path_prefix")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        })
    }
}

/// Apply a rewritten `uri` template with Caddy's component-wise semantics: a configured URI that
/// has no `?` preserves the current query string, and a URI with only `?query` preserves the
/// current path. Fragments are dropped because they are never sent to a server.
fn rewritten_uri(request: &Request, template: &str) -> Result<Uri> {
    let expanded = request.replace_all(template);
    let without_fragment = expanded.split('#').next().unwrap_or("");
    let (path, query) = match without_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (without_fragment, None),
    };

    let mut new_path = request.uri.path().to_string();
    let mut new_query = request.uri.query().map(str::to_string);
    if !path.is_empty() {
        new_path = path.to_string();
    }
    if let Some(query) = query {
        new_query = if query.is_empty() {
            None
        } else {
            Some(query.to_string())
        };
    }

    let mut rebuilt = new_path;
    if let Some(query) = &new_query {
        rebuilt.push('?');
        rebuilt.push_str(query);
    }
    rebuilt
        .parse::<Uri>()
        .map_err(|error| invalid("rewrite.uri", error.to_string()))
}

fn strip_path_prefix(request: &mut Request, prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        return Ok(());
    }
    let mut prefix = prefix.to_string();
    if !prefix.starts_with('/') {
        prefix.insert(0, '/');
    }
    let Some(rest) = request.uri.path().strip_prefix(prefix.as_str()) else {
        return Ok(());
    };
    let rest = if rest.is_empty() {
        "/".to_string()
    } else if rest.starts_with('/') {
        rest.to_string()
    } else {
        // Caddy's `canonicalizePath` restores the leading slash after trimming.
        format!("/{rest}")
    };
    let new_uri = match request.uri.query() {
        Some(query) => format!("{rest}?{query}"),
        None => rest,
    };
    request.uri = new_uri
        .parse::<Uri>()
        .map_err(|error| invalid("rewrite.strip_path_prefix", error.to_string()))?;
    Ok(())
}

#[async_trait]
impl Handler for RewriteHandler {
    fn name(&self) -> &'static str {
        "rewrite"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        if let Some(method) = &self.method {
            let expanded = request.replace_all(method).to_ascii_uppercase();
            request.method = Method::from_bytes(expanded.as_bytes())
                .map_err(|_| invalid("rewrite.method", format!("invalid method `{expanded}`")))?;
        }
        if let Some(uri) = &self.uri {
            if !uri.is_empty() {
                request.uri = rewritten_uri(&request, uri)?;
            }
        }
        if let Some(prefix) = &self.strip_path_prefix {
            let expanded = request.replace_all(prefix);
            strip_path_prefix(&mut request, &expanded)?;
        }
        Ok(Outcome::Continue(request))
    }
}

/// `subroute`: evaluate a nested route list.
pub struct SubrouteHandler {
    router: Arc<Router>,
}

impl SubrouteHandler {
    /// Build from a nested router.
    pub fn new(router: Router) -> Self {
        Self {
            router: Arc::new(router),
        }
    }
}

#[async_trait]
impl Handler for SubrouteHandler {
    fn name(&self) -> &'static str {
        "subroute"
    }

    fn requires_buffered_request_body(&self) -> bool {
        self.router.requires_buffered_request_body()
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        // Caddy compiles a subroute's routes with the *outer* handler chain as their continuation
        // (`RouteList.Compile(next)`), so an empty or non-matching subroute is a no-op that passes
        // control on instead of responding. `handle_outcome` exposes exactly that distinction.
        self.router.handle_outcome(request).await
    }

    async fn handle_streaming(&self, request: Request) -> Result<StreamingOutcome> {
        // Preserve streamed inner responses (for example a reverse_proxy inside a subroute)
        // instead of collecting them at the subroute boundary.
        self.router.handle_streaming_outcome(request).await
    }
}

/// `encode`: accepted for configuration compatibility; compression is tracked for a later task.
pub struct EncodeHandler;

#[async_trait]
impl Handler for EncodeHandler {
    fn name(&self) -> &'static str {
        "encode"
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        // The handler is a no-op rather than an error so configurations remain runnable; the
        // divergence is recorded in docs/compatibility/BEHAVIOR-DIVERGENCES.md (DIV-0009).
        Ok(Outcome::Continue(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request(method: Method, uri: &str) -> Request {
        let mut request = Request::new(method, uri.parse::<Uri>().unwrap());
        request.headers.insert(
            http::header::HOST,
            HeaderValue::from_static("example.com:8080"),
        );
        request
    }

    fn request() -> Request {
        let mut request = Request::new(Method::GET, "/old/path?q=1".parse::<Uri>().unwrap());
        request
            .headers
            .insert(http::header::HOST, HeaderValue::from_static("example.com"));
        request
    }

    #[tokio::test]
    async fn static_response_writes_status_body_and_headers() {
        let handler = StaticResponseHandler::from_json(
            &serde_json::json!({
                "handler": "static_response",
                "status_code": 418,
                "body": "teapot",
                "headers": {"X-Test": ["yes"]}
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Respond(response) = handler.handle(request()).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(response.status, StatusCode::IM_A_TEAPOT);
        assert_eq!(response.body, Bytes::from_static(b"teapot"));
        assert_eq!(response.headers["x-test"], "yes");
    }

    #[tokio::test]
    async fn static_response_expands_body_header_values_and_header_names() {
        let handler = StaticResponseHandler::from_json(
            &serde_json::json!({
                "handler": "static_response",
                "body": "{http.request.method} {http.request.uri.path} {http.request.host}",
                "headers": {
                    "X-Method-{http.request.method}": ["{http.request.method}"],
                    "X-Query": ["q={http.request.uri.query}"],
                    "X-Unknown": ["{not.a.placeholder}"]
                }
            }),
            "handler",
        )
        .unwrap();
        let request = test_request(Method::POST, "/some/path?q=1");
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(
            response.body,
            Bytes::from_static(b"POST /some/path example.com")
        );
        assert_eq!(response.headers["x-method-post"], "POST");
        assert_eq!(response.headers["x-query"], "q=q=1");
        // ReplaceKnown keeps unknown placeholders visible instead of silently dropping them.
        assert_eq!(response.headers["x-unknown"], "{not.a.placeholder}");
    }

    #[tokio::test]
    async fn headers_handler_expands_request_and_response_values() {
        let handler = HeadersHandler::from_json(
            &serde_json::json!({
                "handler": "headers",
                "request": {"set": {"X-From": ["{http.request.method}"]}},
                "response": {
                    "set": {"X-Path": ["{http.request.uri.path}"]},
                    "add": {"Vary": ["Accept"]}
                }
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.headers["x-from"], "GET");
        assert_eq!(request.pending_response_headers["x-path"], "/old/path");
        assert_eq!(request.pending_response_headers["vary"], "Accept");
    }

    #[tokio::test]
    async fn headers_handler_stages_response_headers() {
        let handler = HeadersHandler::from_json(
            &serde_json::json!({
                "handler": "headers",
                "response": {"set": {"X-Frame-Options": ["DENY"]}, "add": {"Vary": ["Accept"]}}
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.pending_response_headers["x-frame-options"], "DENY");
        assert_eq!(request.pending_response_headers["vary"], "Accept");
    }

    #[tokio::test]
    async fn rewrite_handler_strips_prefix_and_keeps_query() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "strip_path_prefix": "/old"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/path");
        assert_eq!(request.uri.query(), Some("q=1"));
    }

    #[tokio::test]
    async fn rewrite_expands_uri_placeholders_and_preserves_query() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "uri": "/new/{http.request.method}"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/new/GET");
        // No `?` in the configured URI, so the original query string survives.
        assert_eq!(request.uri.query(), Some("q=1"));
    }

    #[tokio::test]
    async fn rewrite_uri_with_only_query_keeps_path() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "uri": "?a=b"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/old/path");
        assert_eq!(request.uri.query(), Some("a=b"));
    }

    #[tokio::test]
    async fn rewrite_expands_strip_path_prefix_and_method() {
        let mut request = request();
        request
            .vars
            .insert("prefix".to_string(), "/old".to_string());
        let handler = RewriteHandler::from_json(
            &serde_json::json!({
                "handler": "rewrite",
                "method": "{http.request.method}",
                "strip_path_prefix": "{http.vars.prefix}"
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.uri.path(), "/path");
        assert_eq!(request.uri.query(), Some("q=1"));
    }

    #[tokio::test]
    async fn rewrite_unknown_placeholder_expands_to_empty() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "uri": "/x/{not.a.placeholder}"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/x/");
    }

    #[tokio::test]
    async fn rewrite_with_empty_uri_template_is_a_noop() {
        let handler = RewriteHandler::from_json(
            &serde_json::json!({"handler": "rewrite", "uri": "{http.vars.missing}"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.uri.path(), "/old/path");
        assert_eq!(request.uri.query(), Some("q=1"));
    }

    #[tokio::test]
    async fn vars_handler_sets_request_variables() {
        let handler = VarsHandler::from_json(
            &serde_json::json!({"handler": "vars", "root": "/srv"}),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(request.vars.get("root").map(String::as_str), Some("/srv"));
    }

    async fn static_response(body: serde_json::Value) -> Response {
        let handler = StaticResponseHandler::from_json(&body, "handler").unwrap();
        let Outcome::Respond(response) = handler.handle(request()).await.unwrap() else {
            panic!("expected response");
        };
        response
    }

    fn content_type(response: &Response) -> Option<&str> {
        response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
    }

    #[tokio::test]
    async fn static_response_string_body_gets_caddy_text_content_type() {
        // Real Caddy's staticresp.go: every non-empty non-JSON string body is
        // `text/plain; charset=utf-8`.
        let response = static_response(serde_json::json!({
            "handler": "static_response",
            "body": "hello oracle"
        }))
        .await;
        assert_eq!(content_type(&response), Some("text/plain; charset=utf-8"));
        assert_eq!(response.body, Bytes::from_static(b"hello oracle"));
    }

    #[tokio::test]
    async fn static_response_json_body_gets_json_content_type() {
        for body in ["{\"a\":1}", "[1,2,3]", "  {\"nested\":true}\n"] {
            let response = static_response(serde_json::json!({
                "handler": "static_response",
                "body": body
            }))
            .await;
            assert_eq!(
                content_type(&response),
                Some("application/json"),
                "body {body:?}"
            );
        }
        // Caddy requires more than two trimmed bytes regardless of validity: `{}` is text.
        for body in ["{}", "[]", "{not json}", "[trailing", "  ", "   \n\t"] {
            let response = static_response(serde_json::json!({
                "handler": "static_response",
                "body": body
            }))
            .await;
            assert_eq!(
                content_type(&response),
                Some("text/plain; charset=utf-8"),
                "body {body:?}"
            );
        }
    }

    #[tokio::test]
    async fn static_response_explicit_content_type_wins() {
        let response = static_response(serde_json::json!({
            "handler": "static_response",
            "body": "hello",
            "headers": {"Content-Type": ["application/x-custom"]}
        }))
        .await;
        assert_eq!(content_type(&response), Some("application/x-custom"));

        // Caddy treats an empty configured value as "not set" (Header.Get == "") and replaces it
        // with the implicit type.
        let response = static_response(serde_json::json!({
            "handler": "static_response",
            "body": "hello",
            "headers": {"Content-Type": [""]}
        }))
        .await;
        assert_eq!(content_type(&response), Some("text/plain; charset=utf-8"));
    }

    #[tokio::test]
    async fn static_response_empty_body_has_no_content_type() {
        // Caddy only sets the implicit Content-Type when the expanded body is non-empty, and it
        // explicitly clears Content-Type afterwards so Go cannot sniff one.
        let response = static_response(serde_json::json!({
            "handler": "static_response",
            "body": ""
        }))
        .await;
        assert_eq!(content_type(&response), None);
        assert!(response.body.is_empty());

        // A placeholder that expands to an empty string behaves like an empty body.
        let handler = StaticResponseHandler::from_json(
            &serde_json::json!({
                "handler": "static_response",
                "body": "{http.request.uri.query}"
            }),
            "handler",
        )
        .unwrap();
        let no_query = Request::new(Method::GET, "/no-query".parse::<Uri>().unwrap());
        let Outcome::Respond(response) = handler.handle(no_query).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(content_type(&response), None);
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn static_response_content_type_uses_expanded_body_and_ignores_method() {
        // The implicit type is computed from the expanded body (Caddy computes it before writing
        // the body and independently of HEAD/GET).
        let handler = StaticResponseHandler::from_json(
            &serde_json::json!({
                "handler": "static_response",
                "body": "{http.request.method}"
            }),
            "handler",
        )
        .unwrap();
        let request = Request::new(Method::GET, "/".parse::<Uri>().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(content_type(&response), Some("text/plain; charset=utf-8"));

        let head = Request::new(Method::HEAD, "/".parse::<Uri>().unwrap());
        let Outcome::Respond(response) = handler.handle(head).await.unwrap() else {
            panic!("expected response");
        };
        assert_eq!(content_type(&response), Some("text/plain; charset=utf-8"));
    }

    #[tokio::test]
    async fn vars_handler_expands_keys_and_values() {
        let handler = VarsHandler::from_json(
            &serde_json::json!({
                "handler": "vars",
                "prefix-{http.request.method}": "/srv/{http.request.uri.path}"
            }),
            "handler",
        )
        .unwrap();
        let Outcome::Continue(request) = handler.handle(request()).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(
            request.vars.get("prefix-GET").map(String::as_str),
            Some("/srv//old/path")
        );
    }
}
