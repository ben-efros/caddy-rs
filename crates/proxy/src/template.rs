//! Placeholder templates and header-operation parsing shared by the proxy handler.
//!
//! Caddy expands `{...}` placeholders in header values and rewrites. caddy-rs has no general
//! replacer yet (`DIV-0007`), so this module implements the subset needed by the canonical
//! `forward_auth` expansion plus the common request placeholders. Unknown placeholders are kept
//! **verbatim** (the pre-existing behaviour for `header_up` values) rather than silently blanked,
//! so a configuration is never silently rewritten into something different from what the operator
//! wrote.
//!
//! # `forward_auth`
//!
//! The canonical Caddy adaptation of `forward_auth` emits:
//!
//! * `rewrite: {method: "GET", uri: "/auth"}` (handled in [`crate::forward_auth`]);
//! * `headers.request.set` with `{http.request.method}` / `{http.request.uri}` so the auth service
//!   receives the original method and URI;
//! * `handle_response` routes that copy `{http.reverse_proxy.header.*}` values onto the original
//!   request.
//!
//! All three rely on the template expansion implemented here.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde_json::Value;

use caddy_rs_http::{Error as HttpError, Request, Result as HttpResult};

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// The request/response data placeholders are expanded from.
pub struct TemplateContext<'a> {
    /// Original request (never the rewritten-outbound clone: Caddy expands placeholders against
    /// the original values before a forward-auth rewrite).
    pub request: &'a Request,
    /// Upstream response status, when evaluating `handle_response`.
    pub response_status: Option<StatusCode>,
    /// Upstream response headers, when evaluating `handle_response`.
    pub response_headers: Option<&'a HeaderMap>,
    /// Extra variables available as `{vars.<name>}` (currently only request vars).
    pub vars: Option<&'a std::collections::BTreeMap<String, String>>,
}

/// One parsed placeholder template.
#[derive(Debug, Clone, Default)]
pub struct Template {
    parts: Vec<TemplatePart>,
}

#[derive(Debug, Clone)]
enum TemplatePart {
    Literal(String),
    Method,
    Uri,
    UriPath,
    UriQuery,
    Host,
    HostPort,
    RequestPort,
    Remote,
    RemoteHost,
    RemotePort,
    Scheme,
    RequestHeader(HeaderName),
    ProxyStatusCode,
    ProxyHeader(HeaderName),
    Var(String),
}

impl Template {
    /// Parse a template. Unknown placeholders are preserved verbatim (see module docs).
    pub fn parse(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'{' {
                if let Some(close) = text[index + 1..].find('}') {
                    let close = index + 1 + close;
                    let token = &text[index + 1..close];
                    if let Some(part) = parse_placeholder(token) {
                        if !literal.is_empty() {
                            parts.push(TemplatePart::Literal(std::mem::take(&mut literal)));
                        }
                        parts.push(part);
                        index = close + 1;
                        continue;
                    }
                }
            }
            // Not a recognised placeholder: keep the byte (including any `{`) verbatim.
            let ch = text[index..]
                .chars()
                .next()
                .expect("index at char boundary");
            literal.push(ch);
            index += ch.len_utf8();
        }
        if !literal.is_empty() {
            parts.push(TemplatePart::Literal(literal));
        }
        Self { parts }
    }

    /// Whether this template is a plain literal with no recognised placeholders.
    pub fn is_literal(&self) -> bool {
        self.parts
            .iter()
            .all(|part| matches!(part, TemplatePart::Literal(_)))
    }

    /// Expand the template against a request/response context.
    pub fn expand(&self, context: &TemplateContext<'_>) -> String {
        let mut output = String::new();
        for part in &self.parts {
            match part {
                TemplatePart::Literal(text) => output.push_str(text),
                TemplatePart::Method => output.push_str(context.request.method.as_str()),
                TemplatePart::Uri => output.push_str(
                    context
                        .request
                        .uri
                        .path_and_query()
                        .map(|value| value.as_str())
                        .unwrap_or(""),
                ),
                TemplatePart::UriPath => output.push_str(context.request.uri.path()),
                TemplatePart::UriQuery => {
                    output.push_str(context.request.uri.query().unwrap_or(""))
                }
                TemplatePart::Host => {
                    // Caddy `http.request.host`: Host header without the port.
                    output.push_str(
                        context
                            .request
                            .host()
                            .and_then(split_host_port)
                            .map(|(host, _)| host)
                            .unwrap_or_default(),
                    );
                }
                TemplatePart::HostPort => {
                    // Caddy `http.request.hostport`: the full Host header value.
                    output.push_str(context.request.host().unwrap_or_default());
                }
                TemplatePart::RequestPort => {
                    // Caddy `http.request.port`: the Host header's port, empty when absent.
                    if let Some((_, port)) = context.request.host().and_then(split_host_port) {
                        output.push_str(port);
                    }
                }
                TemplatePart::Remote => {
                    if let Some(remote) = context.request.remote_addr {
                        output.push_str(&remote.to_string());
                    }
                }
                TemplatePart::RemoteHost => {
                    // Caddy `http.request.remote.host`: the transport peer, never the
                    // trusted-proxy-resolved `client_ip` (that is `{http.vars.client_ip}`).
                    if let Some(remote) = context.request.remote_addr {
                        output.push_str(&remote.ip().to_string());
                    }
                }
                TemplatePart::RemotePort => {
                    if let Some(remote) = context.request.remote_addr {
                        output.push_str(&remote.port().to_string());
                    }
                }
                TemplatePart::Scheme => {
                    output.push_str(if context.request.tls { "https" } else { "http" });
                }
                TemplatePart::RequestHeader(name) => {
                    output.push_str(&joined_header(context.request.headers.get_all(name), name));
                }
                TemplatePart::ProxyStatusCode => {
                    if let Some(status) = context.response_status {
                        output.push_str(&status.as_u16().to_string());
                    }
                }
                TemplatePart::ProxyHeader(name) => {
                    if let Some(headers) = context.response_headers {
                        output.push_str(&joined_header(headers.get_all(name), name));
                    }
                }
                TemplatePart::Var(name) => {
                    if let Some(value) = context.vars.and_then(|vars| vars.get(name)) {
                        output.push_str(value);
                    }
                }
            }
        }
        output
    }
}

/// Split a `host[:port]` value (including bracketed IPv6) into `(host, port)`.
fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        return Some((host, after.strip_prefix(':').unwrap_or("")));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host, port)),
        Some(_) => None,
        None => Some((value, "")),
    }
}

fn parse_placeholder(token: &str) -> Option<TemplatePart> {
    let token = token.trim();
    if let Some(rest) = token
        .strip_prefix("http.reverse_proxy.header.")
        .or_else(|| token.strip_prefix("rp.header."))
    {
        return rest
            .parse::<HeaderName>()
            .ok()
            .map(TemplatePart::ProxyHeader);
    }
    if let Some(rest) = token
        .strip_prefix("http.request.header.")
        .or_else(|| token.strip_prefix("header."))
    {
        return rest
            .parse::<HeaderName>()
            .ok()
            .map(TemplatePart::RequestHeader);
    }
    if let Some(rest) = token
        .strip_prefix("http.vars.")
        .or_else(|| token.strip_prefix("vars."))
    {
        return Some(TemplatePart::Var(rest.to_string()));
    }
    match token {
        "http.request.method" | "method" => Some(TemplatePart::Method),
        "http.request.uri" | "uri" => Some(TemplatePart::Uri),
        "http.request.uri.path" | "path" => Some(TemplatePart::UriPath),
        "http.request.uri.query" | "query" => Some(TemplatePart::UriQuery),
        "http.request.host" | "host" => Some(TemplatePart::Host),
        "http.request.hostport" | "hostport" => Some(TemplatePart::HostPort),
        "http.request.port" | "port" => Some(TemplatePart::RequestPort),
        "http.request.remote" | "remote" => Some(TemplatePart::Remote),
        "http.request.remote.host" | "remote_host" => Some(TemplatePart::RemoteHost),
        "http.request.remote.port" | "remote_port" => Some(TemplatePart::RemotePort),
        "http.request.scheme" | "scheme" => Some(TemplatePart::Scheme),
        "http.reverse_proxy.status_code" | "rp.status_code" => Some(TemplatePart::ProxyStatusCode),
        _ => None,
    }
}

/// Join all values of a header the way Caddy's reverse-proxy header placeholders do (comma, no
/// space).
fn joined_header<'a>(values: http::header::GetAll<'a, HeaderValue>, _name: &HeaderName) -> String {
    let mut joined = String::new();
    for value in values {
        let Ok(value) = value.to_str() else {
            continue;
        };
        if !joined.is_empty() {
            joined.push(',');
        }
        joined.push_str(value);
    }
    joined
}

/// One delete pattern from Caddy's `headers` `delete` list (basic wildcards supported).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletePattern {
    /// `*`: clear every header (Caddy applies this before add/set).
    All,
    /// `prefix*`.
    Prefix(String),
    /// `*suffix`.
    Suffix(String),
    /// `*infix*`.
    Contains(String),
    /// A plain field name.
    Exact(HeaderName),
}

impl DeletePattern {
    fn parse(text: &str) -> Result<Self, String> {
        if text == "*" {
            return Ok(Self::All);
        }
        if let Some(suffix) = text.strip_prefix('*').and_then(|t| t.strip_suffix('*')) {
            if suffix.is_empty() {
                return Ok(Self::All);
            }
            return Ok(Self::Contains(suffix.to_ascii_lowercase()));
        }
        if let Some(suffix) = text.strip_prefix('*') {
            return Ok(Self::Suffix(suffix.to_ascii_lowercase()));
        }
        if let Some(prefix) = text.strip_suffix('*') {
            return Ok(Self::Prefix(prefix.to_ascii_lowercase()));
        }
        text.parse::<HeaderName>()
            .map(Self::Exact)
            .map_err(|error| format!("invalid header name `{text}`: {error}"))
    }

    fn matches(&self, name: &HeaderName) -> bool {
        let name = name.as_str();
        match self {
            Self::All => true,
            Self::Exact(exact) => exact.as_str() == name,
            Self::Prefix(prefix) => name.starts_with(prefix.as_str()),
            Self::Suffix(suffix) => name.ends_with(suffix.as_str()),
            Self::Contains(infix) => name.contains(infix.as_str()),
        }
    }
}

/// Caddy `headers` request operations (`add`, `set`, `delete`), with template values.
#[derive(Debug, Clone, Default)]
pub struct HeaderOps {
    /// Headers appended (`add`).
    pub add: Vec<(HeaderName, Template)>,
    /// Headers replaced (`set`).
    pub set: Vec<(HeaderName, Template)>,
    /// Header delete patterns (`delete`).
    pub delete: Vec<DeletePattern>,
}

impl HeaderOps {
    /// Parse a Caddy `HeaderOps` object.
    ///
    /// Only `add`/`set`/`delete` are implemented; `replace` needs a regex engine that is not
    /// available offline, so it is rejected loudly. Unknown fields are ignored, matching Caddy's
    /// JSON loader (a field Caddy does not know cannot change its behaviour either).
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "header operations must be an object"))?;
        for field in ["replace", "deferred", "require"] {
            if object.get(field).is_some() {
                return Err(HttpError::NotImplemented {
                    feature: "`headers` operations other than add/set/delete (replace, deferred, require)",
                    tracking_id: "T-PROXY-037",
                });
            }
        }

        let mut ops = Self::default();
        if let Some(add) = object.get("add") {
            ops.add = parse_template_map(add, &format!("{path}.add"))?;
        }
        if let Some(set) = object.get("set") {
            ops.set = parse_template_map(set, &format!("{path}.set"))?;
        }
        if let Some(delete) = object.get("delete") {
            let entries = delete
                .as_array()
                .ok_or_else(|| invalid(&format!("{path}.delete"), "`delete` must be an array"))?;
            for (index, entry) in entries.iter().enumerate() {
                let text = entry.as_str().ok_or_else(|| {
                    invalid(
                        &format!("{path}.delete[{index}]"),
                        "delete entries must be header names",
                    )
                })?;
                ops.delete.push(
                    DeletePattern::parse(text)
                        .map_err(|message| invalid(&format!("{path}.delete[{index}]"), message))?,
                );
            }
        }
        Ok(ops)
    }

    /// Whether any operation is configured.
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.set.is_empty() && self.delete.is_empty()
    }

    /// Apply the operations in Caddy's order: clear-all delete, add, set, then patterned deletes.
    pub fn apply(&self, headers: &mut HeaderMap, context: &TemplateContext<'_>) {
        // Caddy clears everything first if `*` is in the delete list so that added headers are not
        // immediately removed again.
        if self.delete.contains(&DeletePattern::All) {
            headers.clear();
        }
        for (name, template) in &self.add {
            if let Ok(value) = HeaderValue::from_str(&template.expand(context)) {
                headers.append(name.clone(), value);
            }
        }
        // Caddy `Set` joins multiple configured values into one comma-separated value, except for
        // `Set-Cookie`, where multiple values are appended as separate fields.
        let mut grouped: Vec<(HeaderName, Vec<String>)> = Vec::new();
        for (name, template) in &self.set {
            let value = template.expand(context);
            match grouped.iter_mut().find(|(existing, _)| existing == name) {
                Some((_, values)) => values.push(value),
                None => grouped.push((name.clone(), vec![value])),
            }
        }
        for (name, values) in grouped {
            if name == http::header::SET_COOKIE && values.len() > 1 {
                headers.remove(&name);
                for value in values {
                    if let Ok(value) = HeaderValue::from_str(&value) {
                        headers.append(name.clone(), value);
                    }
                }
            } else if let Ok(value) = HeaderValue::from_str(&values.join(",")) {
                headers.insert(name, value);
            }
        }
        let patterns: Vec<&DeletePattern> = self
            .delete
            .iter()
            .filter(|pattern| **pattern != DeletePattern::All)
            .collect();
        if patterns.is_empty() {
            return;
        }
        let names: Vec<HeaderName> = headers
            .keys()
            .filter(|name| patterns.iter().any(|pattern| pattern.matches(name)))
            .cloned()
            .collect();
        for name in names {
            headers.remove(name);
        }
    }
}

fn parse_template_map(value: &Value, path: &str) -> HttpResult<Vec<(HeaderName, Template)>> {
    let object = value.as_object().ok_or_else(|| {
        invalid(
            path,
            "header operations must be an object of field -> values",
        )
    })?;
    let mut entries = Vec::new();
    for (field, values) in object {
        let name: HeaderName = field
            .parse()
            .map_err(|error| invalid(path, format!("invalid header name `{field}`: {error}")))?;
        let values: Vec<&str> = match values {
            Value::String(value) => vec![value.as_str()],
            Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| invalid(path, "header values must be strings"))
                })
                .collect::<HttpResult<Vec<_>>>()?,
            _ => {
                return Err(invalid(
                    path,
                    "header values must be a string or array of strings",
                ))
            }
        };
        for value in values {
            entries.push((name.clone(), Template::parse(value)));
        }
    }
    Ok(entries)
}

/// Parse an optional response body template (used by `handle_response` `static_response`).
pub fn parse_body_template(value: Option<&Value>, path: &str) -> HttpResult<Option<Template>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| invalid(path, "`body` must be a string"))?;
    Ok(Some(Template::parse(text)))
}

/// Expand a body template (or return empty bytes when unset).
pub fn expand_body(template: Option<&Template>, context: &TemplateContext<'_>) -> Bytes {
    match template {
        Some(template) => Bytes::from(template.expand(context).into_bytes()),
        None => Bytes::new(),
    }
}

/// Convenience: parse `method` values for rewrite (validated at config time).
pub fn parse_method(text: &str, path: &str) -> HttpResult<Method> {
    // Caddy upper-cases the configured method (`strings.ToUpper`).
    text.to_ascii_uppercase()
        .parse::<Method>()
        .map_err(|error| invalid(path, format!("invalid method: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn request(method: Method, uri: &str) -> Request {
        let mut request = Request::new(method, uri.parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, HeaderValue::from_static("example.com"));
        request
    }

    #[test]
    fn expands_host_and_remote_placeholders_like_caddy() {
        // Caddy: `http.request.host` excludes the port, `http.request.hostport` is the full Host
        // header, `http.request.port` is the Host header's port, and `http.request.remote*` is the
        // transport peer (never the trusted-proxy-resolved client_ip).
        let mut request = request(Method::GET, "/");
        request.headers.insert(
            http::header::HOST,
            HeaderValue::from_static("example.com:8080"),
        );
        request.remote_addr = Some("192.0.2.10:5555".parse().unwrap());
        let context = TemplateContext {
            request: &request,
            response_status: None,
            response_headers: None,
            vars: None,
        };
        let template = Template::parse(concat!(
            "{http.request.host}|{http.request.hostport}|{http.request.port}|",
            "{http.request.remote}|{http.request.remote.host}|{http.request.remote.port}",
        ));
        assert_eq!(
            template.expand(&context),
            "example.com|example.com:8080|8080|192.0.2.10:5555|192.0.2.10|5555"
        );

        // No peer address (Unix-socket peer): the remote placeholders render empty, like Caddy's
        // unknown-address behaviour in caddy-rs's placeholder subset.
        let mut no_peer = request.clone();
        no_peer.remote_addr = None;
        let no_peer_context = TemplateContext {
            request: &no_peer,
            response_status: None,
            response_headers: None,
            vars: None,
        };
        let template = Template::parse(
            "{http.request.remote}|{http.request.remote.host}|{http.request.remote.port}",
        );
        assert_eq!(template.expand(&no_peer_context), "||");
    }

    #[test]
    fn expands_request_placeholders() {
        let mut request = request(Method::POST, "/protected?x=1");
        request
            .headers
            .insert("x-request-id", HeaderValue::from_static("abc"));
        let context = TemplateContext {
            request: &request,
            response_status: None,
            response_headers: None,
            vars: None,
        };
        let template = Template::parse("{http.request.method} {method} {http.request.uri} {http.request.uri.path} {http.request.uri.query} {http.request.host} {http.request.scheme} {http.request.header.X-Request-Id}");
        assert_eq!(
            template.expand(&context),
            "POST POST /protected?x=1 /protected x=1 example.com http abc"
        );
    }

    #[test]
    fn expands_response_placeholders() {
        let request = request(Method::GET, "/");
        let mut headers = HeaderMap::new();
        headers.append("remote-user", HeaderValue::from_static("alice"));
        headers.append("remote-groups", HeaderValue::from_static("a"));
        headers.append("remote-groups", HeaderValue::from_static("b"));
        let context = TemplateContext {
            request: &request,
            response_status: Some(StatusCode::OK),
            response_headers: Some(&headers),
            vars: None,
        };
        assert_eq!(
            Template::parse("{http.reverse_proxy.header.Remote-User}").expand(&context),
            "alice"
        );
        assert_eq!(
            Template::parse("{http.reverse_proxy.header.Remote-Groups}").expand(&context),
            "a,b"
        );
        assert_eq!(
            Template::parse("{http.reverse_proxy.status_code}").expand(&context),
            "200"
        );
        assert_eq!(
            Template::parse("{http.reverse_proxy.header.Missing}").expand(&context),
            ""
        );
    }

    #[test]
    fn unknown_placeholders_are_preserved_verbatim() {
        let request = request(Method::GET, "/");
        let context = TemplateContext {
            request: &request,
            response_status: None,
            response_headers: None,
            vars: None,
        };
        assert_eq!(
            Template::parse("{env.SECRET}").expand(&context),
            "{env.SECRET}"
        );
        assert_eq!(Template::parse("plain").expand(&context), "plain");
    }

    #[test]
    fn header_ops_follow_caddy_order() {
        let request = request(Method::GET, "/");
        let context = TemplateContext {
            request: &request,
            response_status: None,
            response_headers: None,
            vars: None,
        };
        let ops = HeaderOps::from_json(
            &serde_json::json!({
                "add": {"X-Multi": ["a", "b"]},
                "set": {"X-Single": ["{http.request.method}"]},
                "delete": ["X-Drop*", "X-Multi"]
            }),
            "headers.request",
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-multi", HeaderValue::from_static("old"));
        headers.insert("x-drop-me", HeaderValue::from_static("bye"));
        headers.insert("x-keep", HeaderValue::from_static("ok"));
        ops.apply(&mut headers, &context);
        assert!(!headers.contains_key("x-multi"), "deleted after add/set");
        assert!(!headers.contains_key("x-drop-me"));
        assert_eq!(headers["x-keep"], "ok");
        assert_eq!(headers["x-single"], "GET");
    }

    #[test]
    fn set_joins_multiple_values_except_set_cookie() {
        let request = request(Method::GET, "/");
        let context = TemplateContext {
            request: &request,
            response_status: None,
            response_headers: None,
            vars: None,
        };
        let ops = HeaderOps::from_json(
            &serde_json::json!({
                "set": {
                    "X-Single": ["a", "b"],
                    "Set-Cookie": ["a=1", "b=2"]
                }
            }),
            "headers.request",
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        ops.apply(&mut headers, &context);
        assert_eq!(
            headers["x-single"], "a,b",
            "Caddy joins Set values with a comma"
        );
        assert_eq!(
            headers.get_all("set-cookie").iter().count(),
            2,
            "multiple Set-Cookie values stay separate fields"
        );
    }

    #[test]
    fn star_delete_clears_before_add() {
        let request = request(Method::GET, "/");
        let context = TemplateContext {
            request: &request,
            response_status: None,
            response_headers: None,
            vars: None,
        };
        let ops = HeaderOps::from_json(
            &serde_json::json!({"delete": ["*"], "set": {"X-Only": ["yes"]}}),
            "headers.request",
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-old", HeaderValue::from_static("bye"));
        ops.apply(&mut headers, &context);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers["x-only"], "yes");
    }

    #[test]
    fn replace_and_deferred_are_rejected_loudly() {
        for field in ["replace", "deferred", "require"] {
            let mut object = serde_json::Map::new();
            object.insert(field.to_string(), serde_json::json!({}));
            let error = HeaderOps::from_json(&Value::Object(object), "headers.request")
                .expect_err("unsupported header operation must fail");
            assert!(error.to_string().contains("T-PROXY-037"), "{error}");
        }
    }

    #[test]
    fn delete_wildcards_match_like_caddy() {
        assert!(DeletePattern::parse("*User")
            .unwrap()
            .matches(&"remote-user".parse().unwrap()));
        assert!(DeletePattern::parse("Remote*")
            .unwrap()
            .matches(&"remote-user".parse().unwrap()));
        assert!(DeletePattern::parse("*ser*")
            .unwrap()
            .matches(&"remote-user".parse().unwrap()));
        assert!(!DeletePattern::parse("X-*")
            .unwrap()
            .matches(&"remote-user".parse().unwrap()));
        assert!(DeletePattern::parse("*")
            .unwrap()
            .matches(&"anything".parse().unwrap()));
    }
}
