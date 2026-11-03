//! Caddy-compatible placeholder expansion for the HTTP engine (T-ROUTE-030).
//!
//! Caddy evaluates placeholders through `caddy.Replacer` (`replacer.go`) plus the HTTP-specific
//! providers in `modules/caddyhttp/replacer.go`. This module implements the documented subset that
//! the handlers in this crate need, with Caddy's two expansion modes:
//!
//! * [`Replacer::replace_known`] mirrors `Replacer.ReplaceKnown`: **unknown placeholders are left
//!   in the output verbatim**, and placeholders whose value is empty expand to the caller-supplied
//!   empty string. Caddy uses this mode for `static_response` bodies, `headers` values, and
//!   response header values, so a typo in a placeholder stays visible instead of silently
//!   vanishing.
//! * [`Replacer::replace_all`] mirrors `Replacer.ReplaceAll`: **unknown placeholders expand to the
//!   empty string**. Caddy uses this mode for `rewrite` URIs, methods, path prefixes, and `vars`
//!   keys/values.
//!
//! # Supported placeholders
//!
//! | Placeholder | Value |
//! | --- | --- |
//! | `{http.request.method}` | Request method |
//! | `{http.request.scheme}` | `https` when the connection is TLS, else `http` |
//! | `{http.request.host}` | Host header / URI authority without the port |
//! | `{http.request.hostport}` | Host header / URI authority including the port |
//! | `{http.request.port}` | Port from the host, empty when absent |
//! | `{http.request.remote}` | Peer socket address (`ip:port`), empty when unknown |
//! | `{http.request.remote.host}` | Peer IP address, empty when unknown |
//! | `{http.request.remote.port}` | Peer port, empty when unknown |
//! | `{http.request.uri}` | Current path plus query string |
//! | `{http.request.uri_escaped}` | `{http.request.uri}` URL-query-escaped |
//! | `{http.request.uri.path}` | Current path |
//! | `{http.request.uri.path_escaped}` | Path URL-query-escaped |
//! | `{http.request.uri.path.file}` | Final path segment |
//! | `{http.request.uri.path.dir}` | Path up to and including the final `/` |
//! | `{http.request.uri.path.file.base}` | Final segment without its extension |
//! | `{http.request.uri.path.file.ext}` | Final segment extension (including the dot) |
//! | `{http.request.uri.path.N}` | `N`th path segment (0-based, from the left) |
//! | `{http.request.uri.query}` | Raw query string (no `?`), empty when absent |
//! | `{http.request.uri.query_escaped}` | Query URL-query-escaped |
//! | `{http.request.uri.query.NAME}` | First/multiple query parameter values joined with `,` |
//! | `{http.request.uri.prefixed_query}` | `?query` when non-empty, else empty |
//! | `{http.request.header.NAME}` | Request header values joined with `,` (case-insensitive) |
//! | `{http.request.cookie.NAME}` | First cookie value with that name (case-insensitive) |
//! | `{http.request.host.labels.N}` | `N`th host label (0-based, from the right, lowercased) |
//! | `{http.vars.NAME}` | Request variable set by the `vars` handler |
//! | `{http.matchers.file.relative}` | Root-relative path of the file matched by the `file` matcher |
//! | `{http.matchers.file.absolute}` | Absolute path of the file matched by the `file` matcher |
//! | `{http.matchers.file.type}` | `file` or `directory` for the `file` matcher |
//! | `{http.matchers.file.remainder}` | Path remainder after `split_path` in the `file` matcher |
//! | `{http.auth.user.NAME}` | Authenticated user metadata (`id` = username), set by `basic_auth` |
//! | `{vars.NAME}` | Alias for `{http.vars.NAME}`; Caddy's Caddyfile adapter rewrites this form |
//! | `{env.NAME}` | Environment variable, empty when unset |
//! | `{http.response.header.NAME}` | Response header values, only when a replacer is built with [`Replacer::with_response_headers`] |
//!
//! Recognised but unsupported Caddy placeholders (`http.request.tls.*`, `http.request.proto*`,
//! `http.request.orig_*`, `http.request.body*`, `time.*`, `system.*`, `re.*`,
//! `http.reverse_proxy.*`, ...) are treated exactly like unknown ones, which is the behaviour
//! documented by DIV-0007: `replace_known` leaves them visible, `replace_all` empties them.
//!
//! # Expansion semantics and bounds
//!
//! Expansion is deliberately **single-pass**, exactly like Caddy's `Replacer`: a replacement value
//! that itself contains `{...}` is written literally and never re-expanded. That keeps expansion
//! bounded (there is no recursion and therefore no cycle to guard against) and prevents request
//! data from injecting placeholders that are evaluated against the replacer.
//!
//! Two other Caddy behaviours are mirrored for safety:
//!
//! * `\{` and `\}` escape braces; the backslash is consumed and the brace is written literally.
//! * An unclosed `{` is written verbatim, but more than [`MAX_UNCLOSED_PLACEHOLDERS`] unclosed
//!   placeholders abort the expansion and return the empty string (Caddy returns `""` from
//!   `ReplaceAll`/`ReplaceKnown` when its internal replace errors on the same condition).
//!
//! This module never panics on malformed input: no indexing/slicing can fail because brace
//! scanning only slices at ASCII brace boundaries.

use std::net::SocketAddr;

use http::HeaderMap;

use crate::types::Request;

/// Caddy's threshold for unclosed placeholders before expansion gives up (`replacer.go`).
pub const MAX_UNCLOSED_PLACEHOLDERS: usize = 100;

/// How [`Replacer::replace`] treats placeholders it does not recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownPlaceholders {
    /// Leave the literal `{name}` in the output (Caddy `ReplaceKnown`).
    Keep,
    /// Replace the placeholder with nothing (Caddy `ReplaceAll`).
    Empty,
}

/// A request-scoped placeholder replacer.
///
/// Build one with [`Request::placeholders`], or with [`Replacer::new`] when only the request is
/// available. Handlers that also know the response headers (for `{http.response.header.*}`) can
/// chain [`Replacer::with_response_headers`].
#[derive(Debug, Clone, Copy)]
pub struct Replacer<'a> {
    request: &'a Request,
    response_headers: Option<&'a HeaderMap>,
}

impl<'a> Replacer<'a> {
    /// A replacer for `request`, without response-header support.
    pub fn new(request: &'a Request) -> Self {
        Self {
            request,
            response_headers: None,
        }
    }

    /// A replacer that can also expand `{http.response.header.NAME}`.
    pub fn with_response_headers(mut self, headers: &'a HeaderMap) -> Self {
        self.response_headers = Some(headers);
        self
    }

    /// Look up one placeholder name (the text between the braces).
    ///
    /// Returns `None` when the name is not part of the supported subset, and `Some("")` when it is
    /// known but currently empty (for example `{http.request.uri.query}` without a query string).
    pub fn get(&self, name: &str) -> Option<String> {
        // Exact names first: the `http.request.uri.path.N` prefix must not swallow
        // `http.request.uri.path.file` and friends.
        let uri = &self.request.uri;
        let path = uri.path();
        let query = uri.query().unwrap_or("");
        let host = raw_host(self.request);
        match name {
            "http.request.method" => Some(self.request.method.as_str().to_string()),
            "http.request.scheme" => {
                Some(if self.request.tls { "https" } else { "http" }.to_string())
            }
            "http.request.host" => Some(split_host_port(host).0.to_string()),
            "http.request.hostport" => Some(host.to_string()),
            "http.request.port" => Some(split_host_port(host).1.unwrap_or("").to_string()),
            "http.request.remote" => Some(format_socket_addr(self.request.remote_addr)),
            "http.request.remote.host" => Some(
                self.request
                    .remote_addr
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default(),
            ),
            "http.request.remote.port" => Some(
                self.request
                    .remote_addr
                    .map(|addr| addr.port().to_string())
                    .unwrap_or_default(),
            ),
            "http.request.uri" => Some(request_uri(self.request)),
            "http.request.uri_escaped" => Some(query_escape(&request_uri(self.request))),
            "http.request.uri.path" => Some(path.to_string()),
            "http.request.uri.path_escaped" => Some(query_escape(path)),
            "http.request.uri.path.file" => Some(path_file(path).to_string()),
            "http.request.uri.path.dir" => Some(path_dir(path).to_string()),
            "http.request.uri.path.file.base" => Some(path_file_base(path).to_string()),
            "http.request.uri.path.file.ext" => Some(path_file_ext(path).to_string()),
            "http.request.uri.query" => Some(query.to_string()),
            "http.request.uri.query_escaped" => Some(query_escape(query)),
            "http.request.uri.prefixed_query" => Some(if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            }),
            _ => {
                if let Some(name) = name.strip_prefix("env.") {
                    return Some(std::env::var(name).unwrap_or_default());
                }
                if let Some(name) = name.strip_prefix("http.matchers.file.") {
                    // Recorded by the `file` matcher in request vars (Caddy sets these on its
                    // request-scoped replacer when the matcher matches).
                    return Some(
                        self.request
                            .vars
                            .get(&format!("matchers.file.{name}"))
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
                if let Some(name) = name.strip_prefix("http.vars.") {
                    // Caddy always reports variables as known; unset ones are empty.
                    return Some(self.request.vars.get(name).cloned().unwrap_or_default());
                }
                if let Some(name) = name.strip_prefix("vars.") {
                    // Caddyfile shorthand: the adapter rewrites `{vars.x}` to `{http.vars.x}`
                    // before the JSON reaches Caddy, so accepting both is compatible.
                    return Some(self.request.vars.get(name).cloned().unwrap_or_default());
                }
                if let Some(rest) = name.strip_prefix("http.auth.user.") {
                    // Set by the `basic_auth`/`authentication` handler after a successful login;
                    // matches Caddy's `repl.Set("http.auth.user.*", ...)`.
                    let key = format!("http.auth.user.{rest}");
                    return Some(self.request.vars.get(&key).cloned().unwrap_or_default());
                }
                if let Some(name) = name.strip_prefix("http.response.header.") {
                    let headers = self.response_headers?;
                    return Some(join_header_values(headers, name));
                }
                if let Some(name) = name.strip_prefix("http.request.header.") {
                    return Some(join_header_values(&self.request.headers, name));
                }
                if let Some(name) = name.strip_prefix("http.request.cookie.") {
                    return Some(cookie_value(&self.request.headers, name));
                }
                if let Some(name) = name.strip_prefix("http.request.uri.query.") {
                    return Some(query_parameter(query, name));
                }
                if let Some(name) = name.strip_prefix("http.request.host.labels.") {
                    return host_label(host, name);
                }
                if let Some(name) = name.strip_prefix("http.request.uri.path.") {
                    return path_segment(path, name);
                }
                None
            }
        }
    }

    /// Expand like Caddy's `Replacer.ReplaceKnown`: unknown placeholders are left verbatim and
    /// known-but-empty placeholders expand to `empty`.
    pub fn replace_known_with(&self, input: &str, empty: &str) -> String {
        self.expand(input, UnknownPlaceholders::Keep, empty)
    }

    /// Expand like Caddy's `Replacer.ReplaceKnown(input, "")`: unknown placeholders are left
    /// verbatim and known-but-empty placeholders expand to nothing.
    pub fn replace_known(&self, input: &str) -> String {
        self.replace_known_with(input, "")
    }

    /// Expand like Caddy's `Replacer.ReplaceAll`: unknown placeholders expand to nothing.
    pub fn replace_all(&self, input: &str) -> String {
        self.expand(input, UnknownPlaceholders::Empty, "")
    }

    /// The underlying single-pass scanner.
    fn expand(&self, input: &str, unknown: UnknownPlaceholders, empty: &str) -> String {
        if !input.contains('{') && !input.contains('}') {
            return input.to_string();
        }

        let bytes = input.as_bytes();
        let mut output = String::with_capacity(input.len());
        let mut last_written = 0usize;
        let mut index = 0usize;
        let mut unclosed = 0usize;

        while index < bytes.len() {
            let byte = bytes[index];

            // Escaped braces are emitted literally; the backslash is consumed.
            if byte == b'\\'
                && index + 1 < bytes.len()
                && (bytes[index + 1] == b'{' || bytes[index + 1] == b'}')
            {
                output.push_str(&input[last_written..index]);
                output.push(bytes[index + 1] as char);
                index += 2;
                last_written = index;
                continue;
            }

            if byte != b'{' {
                index += 1;
                continue;
            }

            let Some(relative_end) = find_unescaped_close(&input[index + 1..]) else {
                unclosed += 1;
                if unclosed > MAX_UNCLOSED_PLACEHOLDERS {
                    // Caddy's replacer returns an empty string after this error.
                    return String::new();
                }
                index += 1;
                continue;
            };
            let end = index + 1 + relative_end;
            let name = &input[index + 1..end];

            output.push_str(&input[last_written..index]);
            match self.get(name) {
                Some(value) => {
                    if value.is_empty() {
                        output.push_str(empty);
                    } else {
                        output.push_str(&value);
                    }
                }
                None => {
                    if unknown == UnknownPlaceholders::Keep {
                        output.push_str(&input[index..=end]);
                    }
                }
            }

            index = end + 1;
            last_written = index;
        }

        output.push_str(&input[last_written..]);
        output
    }
}

/// Find the first `}` that is not escaped by a backslash.
fn find_unescaped_close(input: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'}' && (index == 0 || bytes[index - 1] != b'\\') {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// Host header (or URI authority) verbatim, or `""` when neither is present.
fn raw_host(request: &Request) -> &str {
    request.host().unwrap_or("")
}

/// Split `host[:port]`, handling bracketed IPv6 literals. Returns `(host, port)`.
fn split_host_port(host: &str) -> (&str, Option<&str>) {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some((inner, tail)) = rest.split_once(']') {
            return (inner, tail.strip_prefix(':'));
        }
        return (host, None);
    }
    match host.rsplit_once(':') {
        // A bare IPv6 address such as `::1` is not a host:port pair.
        Some((name, port)) if !name.contains(':') => (name, Some(port)),
        _ => (host, None),
    }
}

fn format_socket_addr(addr: Option<SocketAddr>) -> String {
    match addr {
        Some(addr) => addr.to_string(),
        None => String::new(),
    }
}

fn request_uri(request: &Request) -> String {
    match request.uri.query() {
        Some(query) => format!("{}?{query}", request.uri.path()),
        None => request.uri.path().to_string(),
    }
}

fn path_file(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

fn path_dir(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) => &path[..=index],
        None => "",
    }
}

fn path_file_base(path: &str) -> &str {
    let file = path_file(path);
    match file.rfind('.') {
        Some(index) => &file[..index],
        None => file,
    }
}

fn path_file_ext(path: &str) -> &str {
    let file = path_file(path);
    match file.rfind('.') {
        Some(index) => &file[index..],
        None => "",
    }
}

/// Split a path into segments the way Caddy does (`strings.Split` with a leading empty element
/// removed).
fn path_segments(path: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = path.split('/').collect();
    if parts.first() == Some(&"") {
        parts.remove(0);
    }
    parts
}

fn path_segment(path: &str, index: &str) -> Option<String> {
    let index: usize = index.parse().ok()?;
    let parts = path_segments(path);
    Some(parts.get(index).copied().unwrap_or("").to_string())
}

fn host_label(host: &str, index: &str) -> Option<String> {
    let index: usize = index.parse().ok()?;
    let host = split_host_port(host).0;
    let labels: Vec<&str> = host.split('.').collect();
    let position = match labels.len().checked_sub(index + 1) {
        Some(position) => position,
        None => return Some(String::new()),
    };
    Some(labels[position].to_ascii_lowercase())
}

fn join_header_values(headers: &HeaderMap, name: &str) -> String {
    let Some(name) = http::header::HeaderName::from_bytes(name.as_bytes()).ok() else {
        return String::new();
    };
    let mut values = Vec::new();
    for value in headers.get_all(name) {
        if let Ok(value) = value.to_str() {
            values.push(value);
        }
    }
    values.join(",")
}

fn cookie_value(headers: &HeaderMap, name: &str) -> String {
    for value in headers.get_all(http::header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let Some((cookie_name, cookie_value)) = pair.trim().split_once('=') else {
                continue;
            };
            if cookie_name.eq_ignore_ascii_case(name) {
                return cookie_value.to_string();
            }
        }
    }
    String::new()
}

fn query_pairs(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        pairs.push((percent_decode(name), percent_decode(value)));
    }
    pairs
}

fn query_parameter(query: &str, name: &str) -> String {
    query_pairs(query)
        .into_iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value)
        .collect::<Vec<_>>()
        .join(",")
}

/// `url.QueryEscape` equivalent: ASCII alphanumerics and `-_.~` are kept, space becomes `+`, and
/// every other byte becomes an uppercase `%XX` escape.
fn query_escape(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char);
            }
            b' ' => output.push('+'),
            other => {
                output.push('%');
                output.push(HEX[(other >> 4) as usize] as char);
                output.push(HEX[(other & 0x0f) as usize] as char);
            }
        }
    }
    output
}

/// `url.QueryUnescape` equivalent (used for query parameter names and values).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1]);
                let low = hex_value(bytes[index + 2]);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        output.push((high << 4) | low);
                        index += 3;
                    }
                    _ => {
                        output.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            other => {
                output.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Convenience free function: `replace_known` for a request.
pub fn replace_known(request: &Request, input: &str) -> String {
    Replacer::new(request).replace_known(input)
}

/// Convenience free function: `replace_all` for a request.
pub fn replace_all(request: &Request, input: &str) -> String {
    Replacer::new(request).replace_all(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderValue, Method, Uri};

    fn request() -> Request {
        let mut request = Request::new(
            Method::POST,
            "/a/b%20c/d.txt?x=1&y=two+words".parse().unwrap(),
        );
        request.headers.insert(
            http::header::HOST,
            HeaderValue::from_static("Example.COM:8443"),
        );
        request.headers.insert(
            http::header::USER_AGENT,
            HeaderValue::from_static("caddy-rs-test"),
        );
        request
            .headers
            .append(http::header::ACCEPT, HeaderValue::from_static("text/plain"));
        request
            .headers
            .append(http::header::ACCEPT, HeaderValue::from_static("text/html"));
        request.headers.insert(
            http::header::COOKIE,
            HeaderValue::from_static("session=abc123; Theme=dark"),
        );
        request.remote_addr = Some("203.0.113.7:5555".parse().unwrap());
        request.vars.insert("root".to_string(), "/srv".to_string());
        request
    }

    fn expand(name: &str) -> String {
        Replacer::new(&request()).get(name).unwrap_or_default()
    }

    #[test]
    fn expands_request_line_placeholders() {
        let request = request();
        let replacer = Replacer::new(&request);
        assert_eq!(replacer.get("http.request.method").as_deref(), Some("POST"));
        assert_eq!(replacer.get("http.request.scheme").as_deref(), Some("http"));
        assert_eq!(
            replacer.get("http.request.host").as_deref(),
            Some("Example.COM")
        );
        assert_eq!(
            replacer.get("http.request.hostport").as_deref(),
            Some("Example.COM:8443")
        );
        assert_eq!(replacer.get("http.request.port").as_deref(), Some("8443"));
        assert_eq!(
            replacer.get("http.request.uri").as_deref(),
            Some("/a/b%20c/d.txt?x=1&y=two+words")
        );
        assert_eq!(
            replacer.get("http.request.uri.path").as_deref(),
            Some("/a/b%20c/d.txt")
        );
        assert_eq!(
            replacer.get("http.request.uri.query").as_deref(),
            Some("x=1&y=two+words")
        );
        assert_eq!(
            replacer.get("http.request.uri.prefixed_query").as_deref(),
            Some("?x=1&y=two+words")
        );
    }

    #[test]
    fn expands_remote_placeholders() {
        let request = request();
        let replacer = Replacer::new(&request);
        assert_eq!(
            replacer.get("http.request.remote").as_deref(),
            Some("203.0.113.7:5555")
        );
        assert_eq!(
            replacer.get("http.request.remote.host").as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(
            replacer.get("http.request.remote.port").as_deref(),
            Some("5555")
        );
        let mut unknown = Request::new(Method::GET, "/".parse().unwrap());
        unknown.remote_addr = None;
        let replacer = Replacer::new(&unknown);
        assert_eq!(replacer.get("http.request.remote").as_deref(), Some(""));
        assert_eq!(
            replacer.get("http.request.remote.host").as_deref(),
            Some("")
        );
        assert_eq!(
            replacer.get("http.request.remote.port").as_deref(),
            Some("")
        );
    }

    #[test]
    fn expands_path_parts_and_labels() {
        assert_eq!(expand("http.request.uri.path.file"), "d.txt");
        assert_eq!(expand("http.request.uri.path.dir"), "/a/b%20c/");
        assert_eq!(expand("http.request.uri.path.file.base"), "d");
        assert_eq!(expand("http.request.uri.path.file.ext"), ".txt");
        assert_eq!(expand("http.request.uri.path.0"), "a");
        assert_eq!(expand("http.request.uri.path.2"), "d.txt");
        assert_eq!(expand("http.request.uri.path.9"), "");
        // Non-numeric indices are unknown in Caddy, not empty.
        assert!(Replacer::new(&request())
            .get("http.request.uri.path.nope")
            .is_none());
        assert_eq!(expand("http.request.host.labels.0"), "com");
        assert_eq!(expand("http.request.host.labels.1"), "example");
        assert_eq!(expand("http.request.host.labels.9"), "");
        assert!(Replacer::new(&request())
            .get("http.request.host.labels.-1")
            .is_none());
    }

    #[test]
    fn expands_headers_cookies_and_query_parameters() {
        let request = request();
        let replacer = Replacer::new(&request);
        assert_eq!(
            replacer.get("http.request.header.user-agent").as_deref(),
            Some("caddy-rs-test")
        );
        assert_eq!(
            replacer.get("http.request.header.accept").as_deref(),
            Some("text/plain,text/html")
        );
        assert_eq!(
            replacer.get("http.request.header.missing").as_deref(),
            Some("")
        );
        assert_eq!(
            replacer.get("http.request.cookie.session").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            replacer.get("http.request.cookie.theme").as_deref(),
            Some("dark")
        );
        assert_eq!(
            replacer.get("http.request.cookie.missing").as_deref(),
            Some("")
        );
        assert_eq!(
            replacer.get("http.request.uri.query.y").as_deref(),
            Some("two words")
        );
        assert_eq!(
            replacer.get("http.request.uri.query.x").as_deref(),
            Some("1")
        );
    }

    #[test]
    fn expands_vars_and_env_and_response_headers() {
        let request = request();
        let replacer = Replacer::new(&request);
        assert_eq!(replacer.get("http.vars.root").as_deref(), Some("/srv"));
        assert_eq!(replacer.get("vars.root").as_deref(), Some("/srv"));
        assert_eq!(replacer.get("http.vars.missing").as_deref(), Some(""));
        assert_eq!(replacer.get("http.auth.user.id").as_deref(), Some(""));
        // `env.NAME` is always known, even when unset.
        assert_eq!(
            replacer
                .get("env.CADDY_RS_SURELY_UNSET_PLACEHOLDER")
                .as_deref(),
            Some("")
        );
        let path = std::env::var("PATH").unwrap_or_default();
        assert_eq!(replacer.get("env.PATH").as_deref(), Some(path.as_str()));

        let mut headers = HeaderMap::new();
        headers.insert("X-Request-Id", HeaderValue::from_static("abc"));
        let replacer = Replacer::new(&request).with_response_headers(&headers);
        assert_eq!(
            replacer.get("http.response.header.x-request-id").as_deref(),
            Some("abc")
        );
        // Without a response-header map the placeholder is unknown.
        assert!(Replacer::new(&request)
            .get("http.response.header.x-request-id")
            .is_none());
    }

    #[test]
    fn replace_known_leaves_unknown_placeholders_verbatim() {
        let request = request();
        let replacer = Replacer::new(&request);
        assert_eq!(
            replacer.replace_known("method={http.request.method} unknown={nope}"),
            "method=POST unknown={nope}"
        );
        // Known-but-empty expands to the supplied empty string.
        assert_eq!(
            replacer.replace_known_with("q={http.request.uri.query.nope}", "-"),
            "q=-"
        );
        assert_eq!(
            replacer.replace_known_with("q={http.request.uri.query.nope}", ""),
            "q="
        );
    }

    #[test]
    fn replace_all_empties_unknown_placeholders() {
        let request = request();
        let replacer = Replacer::new(&request);
        assert_eq!(
            replacer.replace_all("method={http.request.method} unknown={nope}"),
            "method=POST unknown="
        );
        assert_eq!(replacer.replace_all("/{http.vars.root}"), "//srv");
    }

    #[test]
    fn expansion_is_single_pass_and_bounded() {
        let mut request = request();
        request
            .vars
            .insert("nested".to_string(), "{http.request.method}".to_string());
        let replacer = Replacer::new(&request);
        // The replacement value is written literally, never re-expanded (Caddy behaviour), so
        // there is no recursion/unbounded growth.
        assert_eq!(
            replacer.replace_all("{http.vars.nested}"),
            "{http.request.method}"
        );

        let unclosed = "{".repeat(MAX_UNCLOSED_PLACEHOLDERS + 1);
        assert_eq!(replacer.replace_all(&unclosed), "");
        assert_eq!(replacer.replace_known(&unclosed), "");
        // A single unclosed brace is preserved literally.
        assert_eq!(replacer.replace_all("a{b"), "a{b");
    }

    #[test]
    fn escaped_braces_are_literal_and_unconsumed() {
        let request = request();
        let replacer = Replacer::new(&request);
        assert_eq!(
            replacer.replace_all(r"\{http.request.method\}"),
            "{http.request.method}"
        );
        assert_eq!(
            replacer.replace_known(r"literal \{x\} brace"),
            "literal {x} brace"
        );
        // Backslashes not followed by a brace are untouched.
        assert_eq!(replacer.replace_known(r"a\nb"), r"a\nb");
    }

    #[test]
    fn malformed_input_never_panics() {
        let request = request();
        let replacer = Replacer::new(&request);
        for input in [
            "",
            "{",
            "}",
            "{}",
            "{ }",
            "{{",
            "}}",
            "{http.request.method",
            "{http.request.method}}",
            "héllo {http.request.method} wörld",
            "{http.request.uri.path.999999999999999999999999}",
        ] {
            let _ = replacer.replace_all(input);
            let _ = replacer.replace_known(input);
        }
    }

    #[test]
    fn free_functions_match_replacer_methods() {
        let request = request();
        assert_eq!(replace_known(&request, "{http.request.method}"), "POST");
        assert_eq!(replace_all(&request, "{nope}"), "");
    }

    #[test]
    fn bytes_body_is_untouched_by_expansion() {
        // Sanity check that the request body type is not involved in placeholder expansion.
        let request = Request::new(Method::GET, "/".parse::<Uri>().unwrap());
        assert_eq!(request.body, Bytes::new());
    }
}
