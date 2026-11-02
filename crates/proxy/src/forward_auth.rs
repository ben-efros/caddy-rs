//! Canonical Caddy `forward_auth` expansion support: `rewrite` and `handle_response`.
//!
//! Caddy has no runtime `forward_auth` module. The Caddyfile adapter expands the directive into a
//! `reverse_proxy` handler configured with:
//!
//! ```json
//! {
//!   "handler": "reverse_proxy",
//!   "upstreams": [{"dial": "auth:9091"}],
//!   "rewrite": {"method": "GET", "uri": "/auth"},
//!   "headers": {"request": {"set": {
//!       "X-Forwarded-Method": ["{http.request.method}"],
//!       "X-Forwarded-Uri": ["{http.request.uri}"]
//!   }}},
//!   "handle_response": [{
//!     "match": {"status_code": [2]},
//!     "routes": [
//!       {"handle": [{"handler": "vars"}]},
//!       {"handle": [{"handler": "headers", "request": {"delete": ["Remote-User"]}}]},
//!       {"handle": [{"handler": "headers",
//!                    "request": {"set": {"Remote-User": ["{http.reverse_proxy.header.Remote-User}"]}}}],
//!        "match": [{"not": [{"vars": {"{http.reverse_proxy.header.Remote-User}": [""]}}]}]}
//!     ]
//!   }]
//! }
//! ```
//!
//! Semantics implemented here:
//!
//! * **rewrite**: changes the outbound method and URI (path/query) of the auth sub-request only.
//!   Rewriting the method to GET/HEAD drops the forwarded request body, matching Caddy's
//!   `prepareRequest` (the original request body stays available to later handlers).
//! * **handle_response**: entries are matched against the upstream response status (a one-digit
//!   value matches the whole class, e.g. `2` means 2xx). The first matching entry runs its routes
//!   against a copy of the original request:
//!   - `headers` request `add`/`set`/`delete` operations are applied (canonical header copy);
//!   - `vars` without configuration is a no-op (it exists in the expansion only to keep the route
//!     non-terminal);
//!   - `static_response` may terminate with a synthetic response;
//!   - if no route terminates, the modified request is returned so the handler chain **continues**
//!     (this is what turns `forward_auth` into a gate rather than a full proxy).
//!     When no `handle_response` entry matches (for example 401/403), the upstream response is
//!     proxied to the client unchanged — that is how auth challenges reach the browser.
//!
//! Security stance: only the canonical/back-compatible subset is executed. Any other
//! `handle_response`/`rewrite` form that Caddy implements but this module does not (extra rewrite
//! fields, response header matchers, `status_code` overrides, unknown route handlers or matchers)
//! is rejected with a located [`caddy_rs_http::Error::NotImplemented`] at configuration load time.
//! A config is never accepted with a gate silently skipped.

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde_json::Value;

use caddy_rs_http::{Error as HttpError, Request, Response, Result as HttpResult};

use crate::health::status_matches;
use crate::template::{
    expand_body, parse_body_template, parse_method, HeaderOps, Template, TemplateContext,
};

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

fn not_implemented(feature: &'static str) -> HttpError {
    HttpError::NotImplemented {
        feature,
        tracking_id: "T-PROXY-037",
    }
}

/// Caddy's `reverse_proxy.rewrite` configuration, limited to the fields the canonical
/// `forward_auth` expansion emits (`method`, `uri`).
#[derive(Debug, Clone, Default)]
pub struct RequestRewrite {
    method: Option<Method>,
    uri: Option<Template>,
}

impl RequestRewrite {
    /// Parse a `rewrite` object.
    ///
    /// Returns `Ok(None)` for an absent or empty rewrite. Other Caddy rewrite fields are rejected
    /// loudly: they change how the request is forwarded, so ignoring them would silently alter
    /// the proxied request.
    pub fn from_json(value: Option<&Value>, path: &str) -> HttpResult<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`rewrite` must be an object"))?;
        for field in [
            "strip_path_prefix",
            "strip_path_suffix",
            "uri_substring",
            "path_regexp",
            "query",
        ] {
            if object.get(field).is_some() {
                return Err(not_implemented(
                    "reverse_proxy `rewrite` options other than `method`/`uri`",
                ));
            }
        }
        let method = match object.get("method") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let text = value.as_str().ok_or_else(|| {
                    invalid(&format!("{path}.method"), "`method` must be a string")
                })?;
                Some(parse_method(text, &format!("{path}.method"))?)
            }
        };
        let uri = match object.get("uri") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let text = value
                    .as_str()
                    .ok_or_else(|| invalid(&format!("{path}.uri"), "`uri` must be a string"))?;
                Some(Template::parse(text))
            }
        };
        if method.is_none() && uri.is_none() {
            return Ok(None);
        }
        Ok(Some(Self { method, uri }))
    }

    /// Whether the rewrite forces a bodyless sub-request (Caddy drops the body when the rewritten
    /// method is GET or HEAD).
    pub fn drops_body(&self) -> bool {
        self.method
            .as_ref()
            .is_some_and(|method| *method == Method::GET || *method == Method::HEAD)
    }

    /// Compute the outbound method and path-and-query for the auth sub-request.
    ///
    /// The original request is never mutated: placeholders expand against it and the rewrite is
    /// applied only to the returned pieces.
    pub fn prepare(&self, request: &Request) -> (Method, String) {
        let method = self
            .method
            .clone()
            .unwrap_or_else(|| request.method.clone());
        let original = request
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let path_and_query = match &self.uri {
            None => original.to_string(),
            Some(template) => {
                let context = TemplateContext {
                    request,
                    response_status: None,
                    response_headers: None,
                    vars: Some(&request.vars),
                };
                rewrite_uri(original, &template.expand(&context))
            }
        };
        (method, path_and_query)
    }
}

/// Apply Caddy's `rewrite.uri` component semantics:
///
/// * a path replaces the original path and preserves the original query string;
/// * an explicit `?query` replaces the query (a bare `?` clears it);
/// * a URI starting with `?` changes only the query.
fn rewrite_uri(original: &str, configured: &str) -> String {
    // Fragments are never sent to a server (Caddy drops them too).
    let configured = configured.split('#').next().unwrap_or(configured);
    let (original_path, original_query) = original.split_once('?').unwrap_or((original, ""));
    let (configured_path, configured_query) = match configured.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (configured, None),
    };

    let path = if configured_path.is_empty() {
        original_path.to_string()
    } else {
        configured_path.to_string()
    };
    let query = match configured_query {
        Some(query) => query.to_string(),
        None => original_query.to_string(),
    };
    if query.is_empty() {
        path
    } else {
        format!("{path}?{query}")
    }
}

/// Result of running a matching `handle_response` entry.
///
/// `Continue` carries a full request; boxing it would add an allocation on every successful
/// forward-auth check, so the same trade-off as `caddy_rs_http::Outcome` is kept.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum HandleResponseResult {
    /// No route terminated the response: continue the handler chain with the (possibly modified)
    /// original request.
    Continue(Request),
    /// A route produced a terminal response (for example `static_response`).
    Respond(Response),
}

/// Parsed `reverse_proxy.handle_response` configuration.
#[derive(Debug, Default)]
pub struct HandleResponse {
    handlers: Vec<ResponseHandler>,
}

#[derive(Debug)]
struct ResponseHandler {
    /// `None` means the entry always matches; an empty list (JSON `[]`) matches nothing, matching
    /// Caddy's nil-vs-empty distinction.
    status_codes: Option<Vec<u16>>,
    routes: Vec<ResponseRoute>,
}

#[derive(Debug)]
struct ResponseRoute {
    condition: Option<ResponseCondition>,
    actions: Vec<ResponseAction>,
}

#[derive(Debug)]
enum ResponseCondition {
    /// Canonical `not vars {"{http.reverse_proxy.header.X}": [""]}`: the upstream response carries
    /// a non-empty header `X`.
    ProxyHeaderNotEmpty(HeaderName),
}

#[derive(Debug)]
enum ResponseAction {
    /// `vars` handler from the canonical expansion: a no-op that keeps the route non-terminal.
    Noop,
    RequestHeaders(HeaderOps),
    StaticResponse {
        status: StatusCode,
        headers: Vec<(HeaderName, Template)>,
        body: Option<Template>,
    },
}

impl HandleResponse {
    /// Parse a `handle_response` array.
    pub fn from_json(value: Option<&Value>, path: &str) -> HttpResult<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let entries = value
            .as_array()
            .ok_or_else(|| invalid(path, "`handle_response` must be an array"))?;
        let mut handlers = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            handlers.push(parse_response_handler(entry, &format!("{path}[{index}]"))?);
        }
        Ok(Self { handlers })
    }

    /// Whether any response handler is configured.
    pub fn is_configured(&self) -> bool {
        !self.handlers.is_empty()
    }

    /// Evaluate the response handlers against an upstream response.
    ///
    /// Returns the first matching handler's outcome, or `None` when no handler matches (the
    /// caller then proxies the upstream response to the client unchanged).
    pub fn evaluate(
        &self,
        request: &Request,
        status: StatusCode,
        upstream_headers: &HeaderMap,
    ) -> Option<HandleResponseResult> {
        for handler in &self.handlers {
            if !handler.matches(status) {
                continue;
            }
            let mut request = request.clone();
            for route in &handler.routes {
                if let Some(condition) = &route.condition {
                    if !condition.matches(upstream_headers) {
                        continue;
                    }
                }
                for action in &route.actions {
                    match action {
                        ResponseAction::Noop => {}
                        ResponseAction::RequestHeaders(ops) => {
                            // Snapshot first: templates read request headers while ops mutate them.
                            let snapshot = request.clone();
                            let context = TemplateContext {
                                request: &snapshot,
                                response_status: Some(status),
                                response_headers: Some(upstream_headers),
                                vars: Some(&snapshot.vars),
                            };
                            ops.apply(&mut request.headers, &context);
                        }
                        ResponseAction::StaticResponse {
                            status: response_status,
                            headers,
                            body,
                        } => {
                            let context = TemplateContext {
                                request: &request,
                                response_status: Some(status),
                                response_headers: Some(upstream_headers),
                                vars: Some(&request.vars),
                            };
                            let mut response = Response {
                                status: *response_status,
                                headers: HeaderMap::new(),
                                body: expand_body(body.as_ref(), &context),
                            };
                            for (name, template) in headers {
                                if let Ok(value) = HeaderValue::from_str(&template.expand(&context))
                                {
                                    response.headers.insert(name.clone(), value);
                                }
                            }
                            if !response.body.is_empty()
                                && !response.headers.contains_key(http::header::CONTENT_TYPE)
                            {
                                let content_type = if is_json_body(&response.body) {
                                    "application/json"
                                } else {
                                    "text/plain; charset=utf-8"
                                };
                                response.headers.insert(
                                    http::header::CONTENT_TYPE,
                                    HeaderValue::from_static(content_type),
                                );
                            }
                            return Some(HandleResponseResult::Respond(response));
                        }
                    }
                }
            }
            return Some(HandleResponseResult::Continue(request));
        }
        None
    }
}

fn is_json_body(body: &[u8]) -> bool {
    matches!(body.first(), Some(b'{') | Some(b'[')) && serde_json::from_slice::<Value>(body).is_ok()
}

impl ResponseHandler {
    fn matches(&self, status: StatusCode) -> bool {
        match &self.status_codes {
            None => true,
            Some(codes) => codes
                .iter()
                .copied()
                .any(|configured| status_matches(status, configured)),
        }
    }
}

impl ResponseCondition {
    fn matches(&self, upstream_headers: &HeaderMap) -> bool {
        match self {
            Self::ProxyHeaderNotEmpty(name) => upstream_headers
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|value| !value.is_empty()),
        }
    }
}

fn parse_response_handler(value: &Value, path: &str) -> HttpResult<ResponseHandler> {
    let object = value.as_object().ok_or_else(|| {
        invalid(
            path,
            "each `handle_response` entry must be a response-handler object",
        )
    })?;
    if object.get("status_code").is_some() {
        return Err(not_implemented(
            "`handle_response.status_code` overrides (only status matching and routes are implemented)",
        ));
    }

    let status_codes = match object.get("match") {
        None | Some(Value::Null) => None,
        Some(match_value) => {
            let matcher = match_value
                .as_object()
                .ok_or_else(|| invalid(&format!("{path}.match"), "`match` must be an object"))?;
            for field in matcher.keys() {
                if field != "status_code" {
                    return Err(not_implemented(
                        "`handle_response.match` options other than `status_code`",
                    ));
                }
            }
            match matcher.get("status_code") {
                None | Some(Value::Null) => None,
                Some(codes) => {
                    let codes = codes.as_array().ok_or_else(|| {
                        invalid(
                            &format!("{path}.match.status_code"),
                            "`status_code` must be an array of integers",
                        )
                    })?;
                    let mut parsed = Vec::with_capacity(codes.len());
                    for (index, code) in codes.iter().enumerate() {
                        let code = code.as_u64().ok_or_else(|| {
                            invalid(
                                &format!("{path}.match.status_code[{index}]"),
                                "status codes must be non-negative integers",
                            )
                        })?;
                        parsed.push(u16::try_from(code).map_err(|_| {
                            invalid(
                                &format!("{path}.match.status_code[{index}]"),
                                "status code must fit in a u16",
                            )
                        })?);
                    }
                    Some(parsed)
                }
            }
        }
    };

    let mut routes = Vec::new();
    if let Some(value) = object.get("routes") {
        let entries = value
            .as_array()
            .ok_or_else(|| invalid(&format!("{path}.routes"), "`routes` must be an array"))?;
        for (index, entry) in entries.iter().enumerate() {
            routes.push(parse_response_route(
                entry,
                &format!("{path}.routes[{index}]"),
            )?);
        }
    }
    Ok(ResponseHandler {
        status_codes,
        routes,
    })
}

fn parse_response_route(value: &Value, path: &str) -> HttpResult<ResponseRoute> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "response route must be an object"))?;
    let condition = parse_route_condition(object.get("match"), &format!("{path}.match"))?;
    let mut actions = Vec::new();
    if let Some(handle) = object.get("handle") {
        let handlers = handle
            .as_array()
            .ok_or_else(|| invalid(&format!("{path}.handle"), "`handle` must be an array"))?;
        for (index, handler) in handlers.iter().enumerate() {
            actions.push(parse_route_action(
                handler,
                &format!("{path}.handle[{index}]"),
            )?);
        }
    }
    Ok(ResponseRoute { condition, actions })
}

fn parse_route_condition(
    value: Option<&Value>,
    path: &str,
) -> HttpResult<Option<ResponseCondition>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let sets = value
        .as_array()
        .ok_or_else(|| invalid(path, "`match` must be an array of matcher sets"))?;
    if sets.is_empty() {
        return Ok(None);
    }
    if sets.len() != 1 {
        return Err(not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        ));
    }
    let set = sets[0]
        .as_object()
        .ok_or_else(|| invalid(path, "each matcher set must be an object"))?;
    if set.len() != 1 {
        return Err(not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        ));
    }
    let Some(inner) = set.get("not") else {
        return Err(not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        ));
    };
    let inner_sets = inner
        .as_array()
        .ok_or_else(|| invalid(path, "`not` must be an array of matcher sets"))?;
    if inner_sets.len() != 1 {
        return Err(not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        ));
    }
    let inner_set = inner_sets[0]
        .as_object()
        .ok_or_else(|| invalid(path, "`not` entries must be objects"))?;
    if inner_set.len() != 1 {
        return Err(not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        ));
    }
    let Some(vars) = inner_set.get("vars") else {
        return Err(not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        ));
    };
    let vars = vars
        .as_object()
        .ok_or_else(|| invalid(path, "`vars` matcher must be an object"))?;
    if vars.len() != 1 {
        return Err(not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        ));
    }
    let Some((placeholder, expected)) = vars.iter().next() else {
        return Err(not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        ));
    };
    let header = parse_proxy_header_placeholder(placeholder).ok_or_else(|| {
        not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        )
    })?;
    let expected_ok = expected
        .as_array()
        .is_some_and(|values| values.len() == 1 && values[0].as_str() == Some(""));
    if !expected_ok {
        return Err(not_implemented(
            "`handle_response` route matchers other than the canonical `not vars` check",
        ));
    }
    Ok(Some(ResponseCondition::ProxyHeaderNotEmpty(header)))
}

/// Extract the header name from `{http.reverse_proxy.header.<Name>}`.
fn parse_proxy_header_placeholder(text: &str) -> Option<HeaderName> {
    let inner = text.strip_prefix('{')?.strip_suffix('}')?;
    let name = inner.strip_prefix("http.reverse_proxy.header.")?;
    name.parse().ok()
}

fn parse_route_action(value: &Value, path: &str) -> HttpResult<ResponseAction> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "route handlers must be objects"))?;
    let handler = object
        .get("handler")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(path, "route handler object is missing `handler`"))?;
    match handler {
        "vars" => {
            // The canonical expansion emits a no-op `vars` handler. Actual variable assignment is
            // not needed for forward_auth, and silently accepting it would be wrong.
            if object.keys().any(|key| key != "handler") {
                return Err(not_implemented(
                    "`vars` handlers inside `handle_response` need configuration",
                ));
            }
            Ok(ResponseAction::Noop)
        }
        "headers" => {
            if object.get("response").is_some() {
                return Err(not_implemented(
                    "`headers` response operations inside `handle_response`",
                ));
            }
            match object.get("request") {
                Some(request) => Ok(ResponseAction::RequestHeaders(HeaderOps::from_json(
                    request,
                    &format!("{path}.request"),
                )?)),
                None => Ok(ResponseAction::Noop),
            }
        }
        "static_response" => {
            let status = match object.get("status_code") {
                None | Some(Value::Null) => StatusCode::OK,
                Some(value) => {
                    let code = match value {
                        Value::Number(number) => number
                            .as_u64()
                            .ok_or_else(|| invalid(path, "`status_code` must be an integer"))?,
                        Value::String(text) => text.parse::<u64>().map_err(|_| {
                            not_implemented(
                                "`static_response` status codes containing placeholders",
                            )
                        })?,
                        _ => {
                            return Err(invalid(
                                &format!("{path}.status_code"),
                                "`status_code` must be an integer or numeric string",
                            ))
                        }
                    };
                    StatusCode::from_u16(u16::try_from(code).map_err(|_| {
                        invalid(&format!("{path}.status_code"), "status must fit in a u16")
                    })?)
                    .map_err(|error| {
                        invalid(
                            &format!("{path}.status_code"),
                            format!("invalid status: {error}"),
                        )
                    })?
                }
            };
            for field in ["close", "abort"] {
                if object.get(field).is_some() {
                    return Err(not_implemented(
                        "`static_response` close/abort options inside `handle_response`",
                    ));
                }
            }
            let body = parse_body_template(object.get("body"), &format!("{path}.body"))?;
            let mut headers = Vec::new();
            if let Some(configured) = object.get("headers") {
                let configured = configured.as_object().ok_or_else(|| {
                    invalid(&format!("{path}.headers"), "`headers` must be an object")
                })?;
                for (field, values) in configured {
                    let name: HeaderName = field.parse().map_err(|error| {
                        invalid(
                            &format!("{path}.headers"),
                            format!("invalid header name `{field}`: {error}"),
                        )
                    })?;
                    let values: Vec<&str> = match values {
                        Value::String(value) => vec![value.as_str()],
                        Value::Array(values) => values
                            .iter()
                            .map(|value| {
                                value.as_str().ok_or_else(|| {
                                    invalid(
                                        &format!("{path}.headers"),
                                        "header values must be strings",
                                    )
                                })
                            })
                            .collect::<HttpResult<Vec<_>>>()?,
                        _ => {
                            return Err(invalid(
                                &format!("{path}.headers"),
                                "header values must be a string or array of strings",
                            ))
                        }
                    };
                    for value in values {
                        headers.push((name.clone(), Template::parse(value)));
                    }
                }
            }
            Ok(ResponseAction::StaticResponse {
                status,
                headers,
                body,
            })
        }
        _other => Err(not_implemented(
            "route handlers inside `handle_response` other than headers/vars/static_response",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn request(method: Method, uri: &str) -> Request {
        let mut request = Request::new(method, uri.parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, HeaderValue::from_static("example.com"));
        request
    }

    fn canonical_handle_response() -> Value {
        serde_json::json!([{
            "match": {"status_code": [2]},
            "routes": [
                {"handle": [{"handler": "vars"}]},
                {"handle": [{"handler": "headers", "request": {"delete": ["Remote-User"]}}]},
                {
                    "handle": [{"handler": "headers", "request": {"set": {
                        "Remote-User": ["{http.reverse_proxy.header.Remote-User}"]
                    }}}],
                    "match": [{"not": [{"vars": {"{http.reverse_proxy.header.Remote-User}": [""]}}]}]
                }
            ]
        }])
    }

    #[test]
    fn rewrite_changes_method_and_preserves_original_query() {
        let rewrite = RequestRewrite::from_json(
            Some(&serde_json::json!({"method": "get", "uri": "/auth"})),
            "rewrite",
        )
        .unwrap()
        .unwrap();
        let (method, uri) = rewrite.prepare(&request(Method::POST, "/protected?x=1"));
        assert_eq!(method, Method::GET);
        assert_eq!(uri, "/auth?x=1");
        assert!(rewrite.drops_body());
    }

    #[test]
    fn rewrite_uri_component_semantics() {
        assert_eq!(rewrite_uri("/a?x=1", "/b"), "/b?x=1");
        assert_eq!(rewrite_uri("/a?x=1", "/b?y=2"), "/b?y=2");
        assert_eq!(rewrite_uri("/a?x=1", "?y=2"), "/a?y=2");
        assert_eq!(rewrite_uri("/a?x=1", "?"), "/a");
        assert_eq!(rewrite_uri("/a?x=1", "/b#frag"), "/b?x=1");
    }

    #[test]
    fn unsupported_rewrite_fields_fail_loudly() {
        let error = RequestRewrite::from_json(
            Some(&serde_json::json!({"strip_path_prefix": "/api"})),
            "rewrite",
        )
        .expect_err("unsupported rewrite field must fail");
        assert!(error.to_string().contains("T-PROXY-037"), "{error}");
    }

    #[test]
    fn matching_2xx_continues_with_copied_header() {
        let handle =
            HandleResponse::from_json(Some(&canonical_handle_response()), "handle_response")
                .unwrap();
        let mut request = request(Method::GET, "/");
        request
            .headers
            .insert("remote-user", HeaderValue::from_static("attacker"));
        let mut headers = HeaderMap::new();
        headers.insert("remote-user", HeaderValue::from_static("alice"));
        let result = handle
            .evaluate(&request, StatusCode::OK, &headers)
            .expect("2xx matches");
        let HandleResponseResult::Continue(request) = result else {
            panic!("canonical 2xx response must continue the chain");
        };
        assert_eq!(request.headers["remote-user"], "alice");
    }

    #[test]
    fn missing_auth_header_deletes_client_supplied_value() {
        let handle =
            HandleResponse::from_json(Some(&canonical_handle_response()), "handle_response")
                .unwrap();
        let mut request = request(Method::GET, "/");
        request
            .headers
            .insert("remote-user", HeaderValue::from_static("attacker"));
        let result = handle
            .evaluate(&request, StatusCode::OK, &HeaderMap::new())
            .expect("2xx matches");
        let HandleResponseResult::Continue(request) = result else {
            panic!("2xx must continue");
        };
        assert!(
            !request.headers.contains_key("remote-user"),
            "a client-supplied authorization header must not survive when the auth service omits it"
        );
    }

    #[test]
    fn non_matching_status_passes_through() {
        let handle =
            HandleResponse::from_json(Some(&canonical_handle_response()), "handle_response")
                .unwrap();
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
        ] {
            assert!(handle
                .evaluate(&request(Method::GET, "/"), status, &HeaderMap::new())
                .is_none());
        }
    }

    #[test]
    fn empty_status_list_matches_nothing_like_caddy() {
        let handle = HandleResponse::from_json(
            Some(&serde_json::json!([{"match": {"status_code": []}, "routes": []}])),
            "handle_response",
        )
        .unwrap();
        assert!(
            handle
                .evaluate(
                    &request(Method::GET, "/"),
                    StatusCode::OK,
                    &HeaderMap::new()
                )
                .is_none(),
            "JSON [] produces a non-nil empty slice in Caddy, which matches nothing"
        );
    }

    #[test]
    fn static_response_terminates_with_expanded_placeholders() {
        let handle = HandleResponse::from_json(
            Some(&serde_json::json!([{
                "routes": [{"handle": [{
                    "handler": "static_response",
                    "status_code": 403,
                    "body": "denied by {http.reverse_proxy.header.X-Reason}",
                    "headers": {"X-Reason": ["{http.reverse_proxy.header.X-Reason}"]}
                }]}]
            }])),
            "handle_response",
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-reason", HeaderValue::from_static("policy"));
        let Some(HandleResponseResult::Respond(response)) = handle.evaluate(
            &request(Method::GET, "/"),
            StatusCode::UNAUTHORIZED,
            &headers,
        ) else {
            panic!("static_response must terminate");
        };
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(
            response.body,
            bytes::Bytes::from_static(b"denied by policy")
        );
        assert_eq!(response.headers["x-reason"], "policy");
    }

    #[test]
    fn unsupported_response_handler_forms_fail_loudly() {
        for config in [
            serde_json::json!([{"status_code": 200, "routes": []}]),
            serde_json::json!([{"match": {"headers": {"X": ["1"]}}, "routes": []}]),
            serde_json::json!([{"routes": [{"match": [{"method": ["GET"]}], "handle": []}]}]),
            serde_json::json!([{"routes": [{"handle": [{"handler": "file_server"}]}]}]),
            serde_json::json!([{"routes": [{"handle": [{"handler": "headers", "response": {"set": {"X": ["1"]}}}]}]}]),
        ] {
            let error = HandleResponse::from_json(Some(&config), "handle_response")
                .expect_err("unsupported handle_response form must be rejected");
            assert!(error.to_string().contains("T-PROXY-037"), "{error}");
        }
    }

    #[test]
    fn absent_handle_response_is_not_configured() {
        let handle = HandleResponse::from_json(None, "handle_response").unwrap();
        assert!(!handle.is_configured());
        assert!(handle
            .evaluate(
                &request(Method::GET, "/"),
                StatusCode::OK,
                &HeaderMap::new()
            )
            .is_none());
    }
}
