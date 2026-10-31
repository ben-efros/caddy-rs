//! Built-in HTTP handlers for the supported Caddy module set.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode, Uri};

use crate::router::Router;
use crate::types::{Error, Handler, Outcome, Request, Response, Result};

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// Convert a JSON value (string or array of strings) into header values.
pub fn header_values(value: &serde_json::Value, path: &str) -> Result<Vec<HeaderValue>> {
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
    items
        .into_iter()
        .map(|item| {
            HeaderValue::from_str(item)
                .map_err(|error| invalid(path, format!("invalid header value `{item}`: {error}")))
        })
        .collect()
}

fn header_name(field: &str, path: &str) -> Result<HeaderName> {
    field
        .parse::<HeaderName>()
        .map_err(|error| invalid(path, format!("invalid header name `{field}`: {error}")))
}

/// `static_response`: write a fixed response.
pub struct StaticResponseHandler {
    status: StatusCode,
    headers: Vec<(HeaderName, Vec<HeaderValue>)>,
    body: Bytes,
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
                    header_name(field, path)?,
                    header_values(value, &format!("{path}.headers.{field}"))?,
                ));
            }
        }
        Ok(Self {
            status,
            headers,
            body: Bytes::from(body),
        })
    }
}

#[async_trait]
impl Handler for StaticResponseHandler {
    fn name(&self) -> &'static str {
        "static_response"
    }

    async fn handle(&self, _request: Request) -> Result<Outcome> {
        let mut response = Response {
            status: self.status,
            headers: http::HeaderMap::new(),
            body: self.body.clone(),
        };
        for (name, values) in &self.headers {
            for value in values {
                response.headers.append(name.clone(), value.clone());
            }
        }
        Ok(Outcome::Respond(response))
    }
}

/// `headers`: stage response header mutations (and apply request header mutations).
pub struct HeadersHandler {
    request_set: Vec<(HeaderName, Vec<HeaderValue>)>,
    response_set: Vec<(HeaderName, Vec<HeaderValue>)>,
    response_add: Vec<(HeaderName, Vec<HeaderValue>)>,
    response_delete: Vec<HeaderName>,
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
                    handler
                        .response_delete
                        .push(header_name(field, &response_path)?);
                }
            }
        }
        Ok(handler)
    }
}

fn parse_header_map(
    value: &serde_json::Value,
    path: &str,
) -> Result<Vec<(HeaderName, Vec<HeaderValue>)>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "expected an object"))?;
    let mut output = Vec::new();
    for (field, value) in object {
        output.push((
            header_name(field, path)?,
            header_values(value, &format!("{path}.{field}"))?,
        ));
    }
    Ok(output)
}

fn parse_header_operations(
    value: &serde_json::Value,
    path: &str,
) -> Result<Vec<(HeaderName, Vec<HeaderValue>)>> {
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
        for (name, values) in &self.request_set {
            request.headers.remove(name);
            for value in values {
                request.headers.append(name.clone(), value.clone());
            }
        }
        for (name, values) in &self.response_set {
            request.pending_response_headers.remove(name);
            for value in values {
                request
                    .pending_response_headers
                    .append(name.clone(), value.clone());
            }
        }
        for (name, values) in &self.response_add {
            for value in values {
                request
                    .pending_response_headers
                    .append(name.clone(), value.clone());
            }
        }
        for name in &self.response_delete {
            request.pending_response_headers.remove(name);
        }
        Ok(Outcome::Continue(request))
    }
}

/// `vars`: set request variables.
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
        for (key, value) in &self.vars {
            request.vars.insert(key.clone(), value.clone());
        }
        Ok(Outcome::Continue(request))
    }
}

/// `rewrite`: change the request URI, method, or path prefix.
pub struct RewriteHandler {
    uri: Option<String>,
    method: Option<Method>,
    strip_path_prefix: Option<String>,
}

impl RewriteHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "rewrite handler must be an object"))?;
        let method = match object.get("method").and_then(serde_json::Value::as_str) {
            Some(method) => Some(Method::from_bytes(method.as_bytes()).map_err(|_| {
                invalid(
                    &format!("{path}.method"),
                    format!("invalid method `{method}`"),
                )
            })?),
            None => None,
        };
        Ok(Self {
            uri: object
                .get("uri")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            method,
            strip_path_prefix: object
                .get("strip_path_prefix")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        })
    }
}

#[async_trait]
impl Handler for RewriteHandler {
    fn name(&self) -> &'static str {
        "rewrite"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        if let Some(method) = &self.method {
            request.method = method.clone();
        }
        if let Some(prefix) = &self.strip_path_prefix {
            if let Some(rest) = request.uri.path().strip_prefix(prefix.as_str()) {
                let rest = if rest.is_empty() { "/" } else { rest };
                let new_uri = match request.uri.query() {
                    Some(query) => format!("{rest}?{query}"),
                    None => rest.to_string(),
                };
                request.uri = new_uri
                    .parse::<Uri>()
                    .map_err(|error| invalid("rewrite.strip_path_prefix", error.to_string()))?;
            }
        }
        if let Some(uri) = &self.uri {
            if uri.contains('{') {
                return Err(Error::NotImplemented {
                    feature: "placeholder expansion in rewrite URIs",
                    tracking_id: "HTTP-PLACEHOLDERS",
                });
            }
            request.uri = uri
                .parse::<Uri>()
                .map_err(|error| invalid("rewrite.uri", error.to_string()))?;
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

    async fn handle(&self, request: Request) -> Result<Outcome> {
        let response = self.router.handle(request).await?;
        Ok(Outcome::Respond(response))
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
    use http::Uri;

    fn request() -> Request {
        Request::new(Method::GET, "/old/path?q=1".parse::<Uri>().unwrap())
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
}
