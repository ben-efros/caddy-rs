//! Authentication handlers: `forward_auth` and HTTP Basic (`basic_auth`/`authentication`).
//!
//! # `forward_auth`
//!
//! Caddy has no runtime `forward_auth` module: the Caddyfile directive is expanded by the adapter
//! into a specially-configured `reverse_proxy` handler (see
//! `upstream/modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go`). caddy-rs models the same
//! flow as a first-class handler so the HTTP engine can run adapted configurations without a live
//! proxy upstream. The JSON shape deliberately mirrors the reverse-proxy subset:
//!
//! ```json
//! {
//!   "handler": "forward_auth",
//!   "upstreams": [{"dial": "authelia:9091"}],
//!   "uri": "/api/authz/forward-auth",
//!   "method": "GET",
//!   "copy_headers": ["Remote-User", "Remote-Email", "Remote-Groups>X-Groups"],
//!   "header_up": {"X-Auth-Source": ["caddy-rs"]},
//!   "trusted_proxies": ["10.0.0.0/8"]
//! }
//! ```
//!
//! Semantics (matching the Caddy adapter expansion):
//! * send a subrequest to the auth upstream with the configured method (`GET` by default) and URI
//!   (placeholders expanded with [`Request::replace_all`] semantics); the original method and URI
//!   are sent as `X-Forwarded-Method`/`X-Forwarded-Uri`, and `X-Forwarded-For`/`-Proto`/`-Host` are
//!   maintained like Caddy's reverse proxy (`trusted_proxies` controls whether inbound values are
//!   trusted);
//! * on a `2xx` auth response, copy the configured headers onto the original request (target
//!   header is deleted first, so a client cannot inject values the auth service did not return) and
//!   continue down the handler chain; the auth response body is discarded;
//! * on any non-`2xx` status, pass the auth response through to the client (status, headers and
//!   body), so `401`/`403` challenges reach the browser unchanged.
//!
//! # `basic_auth` / `authentication`
//!
//! Upstream Caddy's runtime module is `http.handlers.authentication` with the HTTP Basic provider
//! `http_basic`:
//!
//! ```json
//! {
//!   "handler": "authentication",
//!   "providers": {
//!     "http_basic": {
//!       "accounts": [{"username": "alice", "password": "<bcrypt hash or base64>"}],
//!       "hash": {"algorithm": "bcrypt"},
//!       "realm": "restricted"
//!     }
//!   }
//! }
//! ```
//!
//! For adapter convenience caddy-rs also accepts the same object with `"handler": "basic_auth"`
//! and the account fields at the top level (a caddy-rs extension; see below).
//!
//! ## Password hashing support
//!
//! Caddy's `bcrypt` (`http.authentication.hashes.bcrypt`) and `argon2id`
//! (`http.authentication.hashes.argon2id`) password-hash modules are implemented natively:
//! bcrypt hashes in `$2a$`, `$2b$`, `$2y$` and (for Caddy parity) `$2x$` modular-crypt form are
//! verified with the `bcrypt` crate (which uses a constant-time digest comparison), and argon2id
//! PHC strings (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<key>`) are parsed exactly like Caddy's
//! `DecodeHash` (raw standard base64, strict, parameters in `m,t,p` order, version 19) and verified
//! with the `argon2` crate using the salt/parameters encoded in the hash and a constant-time key
//! comparison. Unsupported or malformed hashes are rejected as located configuration errors at
//! load (Caddy defers some of these to a request-time `401`; this stricter validation is recorded
//! as a divergence). Unknown usernames still perform a real verification against Caddy's fixed
//! fake bcrypt/argon2id hashes so account existence is not a timing oracle.
//!
//! The explicit caddy-rs extension `{"hash": {"algorithm": "plaintext"}}` remains available for
//! local development and tests, where each account's `password` is the literal plaintext. It is
//! deliberately opt-in and never inferred: a missing `hash` still defaults to Caddy's `bcrypt`.
//! Clear-text (or base64-of-clear-text) account passwords under bcrypt/argon2id are rejected
//! loudly at load, because they decode to bytes that are not a valid modular-crypt/PHC hash.
//!
//! On success the handler sets the request variable `http.auth.user.id` (exposed as the
//! `{http.auth.user.id}` placeholder, matching Caddy) and continues; on failure it responds `401`
//! with `WWW-Authenticate: Basic realm="..."`. When the server enabled access logging, the same
//! username is published into the per-request `AccessLogContext` so the access entry carries
//! Caddy's `user_id` (Caddy reads `http.auth.user.id` at log time, `server.go:1289-1290`).

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, Version};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::types::{Error, Handler, Outcome, Request, Response, Result};

/// Overall connect timeout for the auth subrequest (Caddy's reverse proxy has a 3s dial timeout;
/// this build uses a slightly more forgiving value).
const AUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn invalid(path: impl Into<String>, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.into(),
        message: message.into(),
    }
}

fn runtime_io(error: impl std::fmt::Display) -> Error {
    Error::Io(std::io::Error::new(ErrorKind::Other, error.to_string()))
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Parse a header value out of JSON (string or array of strings).
fn header_string_values(value: &serde_json::Value, path: &str) -> Result<Vec<String>> {
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

/// All values of one response header, joined with `,` the way Caddy's reverse-proxy header
/// placeholder does.
fn joined_header(headers: &HeaderMap, name: &HeaderName) -> Option<String> {
    let mut values = Vec::new();
    for value in headers.get_all(name) {
        if let Ok(value) = value.to_str() {
            values.push(value);
        }
    }
    if values.is_empty() {
        None
    } else {
        Some(values.join(","))
    }
}

/// A parsed `trusted_proxies` entry: a single IP or a CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
            None => (value, None),
        };
        let base: IpAddr = address.parse().ok()?;
        let max_prefix = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = prefix.unwrap_or(max_prefix);
        if prefix > max_prefix {
            return None;
        }
        Some(Self { base, prefix })
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.base, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(base) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(base) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

/// `forward_auth`: gate the request behind a subrequest to an authentication service.
pub struct ForwardAuthHandler {
    upstream: String,
    uri: String,
    method: Method,
    copy_headers: Vec<(HeaderName, HeaderName)>,
    header_up: Vec<(String, Vec<String>)>,
    trusted_proxies: Vec<Cidr>,
    client: Client<HttpConnector, Full<Bytes>>,
}

impl std::fmt::Debug for ForwardAuthHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForwardAuthHandler")
            .field("upstream", &self.upstream)
            .field("uri", &self.uri)
            .field("method", &self.method)
            .field("copy_headers", &self.copy_headers)
            .field("header_up", &self.header_up)
            .field("trusted_proxies", &self.trusted_proxies)
            .finish_non_exhaustive()
    }
}

impl ForwardAuthHandler {
    /// Build from Caddy-style JSON (`{"handler":"forward_auth",...}`).
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "forward_auth handler must be an object"))?;

        let uri = object
            .get("uri")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                invalid(
                    format!("{path}.uri"),
                    "forward_auth requires a non-empty `uri` subrequest path",
                )
            })?;
        if uri.is_empty() {
            return Err(invalid(
                format!("{path}.uri"),
                "forward_auth requires a non-empty `uri` subrequest path",
            ));
        }

        let method = match object.get("method").and_then(serde_json::Value::as_str) {
            Some(method) => {
                Method::from_bytes(method.to_ascii_uppercase().as_bytes()).map_err(|_| {
                    invalid(
                        format!("{path}.method"),
                        format!("invalid method `{method}`"),
                    )
                })?
            }
            None => Method::GET,
        };

        let upstreams = object
            .get("upstreams")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                invalid(
                    format!("{path}.upstreams"),
                    "forward_auth requires an `upstreams` array",
                )
            })?;
        if upstreams.is_empty() {
            return Err(invalid(
                format!("{path}.upstreams"),
                "forward_auth requires at least one upstream",
            ));
        }
        if upstreams.len() > 1 {
            return Err(Error::NotImplemented {
                feature: "forward_auth load balancing across multiple upstreams",
                tracking_id: "HTTP-FORWARD-AUTH-UPSTREAM",
            });
        }
        let dial = upstreams[0]
            .as_object()
            .and_then(|upstream| upstream.get("dial"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                invalid(
                    format!("{path}.upstreams[0].dial"),
                    "forward_auth upstream must declare a non-empty `dial`",
                )
            })?;
        validate_dial(dial, &format!("{path}.upstreams[0].dial"))?;

        let mut copy_headers = Vec::new();
        if let Some(values) = object.get("copy_headers") {
            let values = values.as_array().ok_or_else(|| {
                invalid(
                    format!("{path}.copy_headers"),
                    "`copy_headers` must be an array of header names",
                )
            })?;
            for (index, value) in values.iter().enumerate() {
                let value = value.as_str().ok_or_else(|| {
                    invalid(
                        format!("{path}.copy_headers[{index}]"),
                        "expected a header name string",
                    )
                })?;
                let (from, to) = match value.split_once('>') {
                    Some((from, to)) => (from.trim(), to.trim()),
                    None => (value.trim(), value.trim()),
                };
                if from.is_empty() || to.is_empty() {
                    return Err(invalid(
                        format!("{path}.copy_headers[{index}]"),
                        format!("invalid header copy `{value}`"),
                    ));
                }
                let from = from.parse::<HeaderName>().map_err(|error| {
                    invalid(
                        format!("{path}.copy_headers[{index}]"),
                        format!("invalid source header `{from}`: {error}"),
                    )
                })?;
                let to = to.parse::<HeaderName>().map_err(|error| {
                    invalid(
                        format!("{path}.copy_headers[{index}]"),
                        format!("invalid destination header `{to}`: {error}"),
                    )
                })?;
                copy_headers.push((from, to));
            }
        }

        let mut header_up = Vec::new();
        if let Some(values) = object.get("header_up") {
            let values = values.as_object().ok_or_else(|| {
                invalid(
                    format!("{path}.header_up"),
                    "`header_up` must be an object of header name to value(s)",
                )
            })?;
            for (name, value) in values {
                let field = name.strip_prefix('-').unwrap_or(name);
                if field.is_empty() {
                    return Err(invalid(
                        format!("{path}.header_up"),
                        "header_up field name must not be empty",
                    ));
                }
                field.parse::<HeaderName>().map_err(|error| {
                    invalid(
                        format!("{path}.header_up.{name}"),
                        format!("invalid header name `{field}`: {error}"),
                    )
                })?;
                header_up.push((
                    name.clone(),
                    header_string_values(value, &format!("{path}.header_up.{name}"))?,
                ));
            }
        }

        let mut trusted_proxies = Vec::new();
        if let Some(values) = object.get("trusted_proxies") {
            let values = values.as_array().ok_or_else(|| {
                invalid(
                    format!("{path}.trusted_proxies"),
                    "`trusted_proxies` must be an array of IP addresses or CIDR ranges",
                )
            })?;
            for (index, value) in values.iter().enumerate() {
                let value = value.as_str().ok_or_else(|| {
                    invalid(
                        format!("{path}.trusted_proxies[{index}]"),
                        "expected an IP address or CIDR string",
                    )
                })?;
                let cidr = Cidr::parse(value).ok_or_else(|| {
                    invalid(
                        format!("{path}.trusted_proxies[{index}]"),
                        format!("invalid trusted proxy `{value}`"),
                    )
                })?;
                trusted_proxies.push(cidr);
            }
        }

        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(AUTH_CONNECT_TIMEOUT));
        let client = Client::builder(TokioExecutor::new()).build(connector);

        Ok(Self {
            upstream: dial.to_string(),
            uri,
            method,
            copy_headers,
            header_up,
            trusted_proxies,
            client,
        })
    }

    fn is_trusted(&self, address: IpAddr) -> bool {
        self.trusted_proxies
            .iter()
            .any(|cidr| cidr.contains(address))
    }

    /// Build the auth subrequest from the original request.
    fn build_subrequest(&self, request: &Request) -> Result<http::Request<Full<Bytes>>> {
        let path = request.replace_all(&self.uri);
        let path = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        let uri = format!("http://{}{}", self.upstream, path)
            .parse::<Uri>()
            .map_err(|error| invalid("forward_auth.uri", error.to_string()))?;

        let mut headers = HeaderMap::new();
        for (name, value) in &request.headers {
            if is_hop_by_hop(name)
                || name == http::header::HOST
                || name == http::header::CONTENT_LENGTH
            {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }

        // Host: the auth service receives the original Host, like Caddy's forward-auth expansion
        // of reverse_proxy (which preserves the request Host).
        let host = request
            .host()
            .map(str::to_string)
            .or_else(|| {
                uri.authority()
                    .map(|authority| authority.host().to_string())
            })
            .unwrap_or_default();
        if !host.is_empty() {
            if let Ok(value) = HeaderValue::from_str(&host) {
                headers.insert(http::header::HOST, value);
            }
        }

        // X-Forwarded-For / -Proto / -Host, following Caddy's reverse proxy: untrusted peers have
        // their inbound forwarded headers stripped; trusted peers keep a prior X-Forwarded-For and
        // the chain is extended with the peer address.
        let trusted = request
            .remote_addr
            .map(|address| self.is_trusted(address.ip()))
            .unwrap_or(false);

        let forwarded_for = HeaderName::from_static("x-forwarded-for");
        let prior_forwarded_for = headers
            .get(&forwarded_for)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        headers.remove(&forwarded_for);
        let client_ip = request
            .remote_addr
            .map(|address| address.ip().to_string())
            .filter(|ip| !ip.is_empty());
        if let Some(client_ip) = client_ip.as_deref() {
            let value = match (trusted, prior_forwarded_for) {
                (true, Some(prior)) if !prior.is_empty() => format!("{prior}, {client_ip}"),
                _ => client_ip.to_string(),
            };
            if let Ok(value) = HeaderValue::from_str(&value) {
                headers.insert(forwarded_for, value);
            }
        }

        let forwarded_proto = HeaderName::from_static("x-forwarded-proto");
        let prior_proto = headers
            .get(&forwarded_proto)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let proto = if trusted {
            prior_proto.unwrap_or_else(|| scheme(request).to_string())
        } else {
            scheme(request).to_string()
        };
        if let Ok(value) = HeaderValue::from_str(&proto) {
            headers.insert(forwarded_proto, value);
        }

        let forwarded_host = HeaderName::from_static("x-forwarded-host");
        let prior_host = headers
            .get(&forwarded_host)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let host_header = if trusted {
            prior_host.unwrap_or_else(|| request.host().unwrap_or("").to_string())
        } else {
            request.host().unwrap_or("").to_string()
        };
        if !host_header.is_empty() {
            if let Ok(value) = HeaderValue::from_str(&host_header) {
                headers.insert(forwarded_host, value);
            }
        }

        // The forward_auth adapter always adds the original method and URI for the auth service.
        if let Ok(value) = HeaderValue::from_str(request.method.as_str()) {
            headers.insert(HeaderName::from_static("x-forwarded-method"), value);
        }
        let original_uri = match request.uri.query() {
            Some(query) => format!("{}?{query}", request.uri.path()),
            None => request.uri.path().to_string(),
        };
        if let Ok(value) = HeaderValue::from_str(&original_uri) {
            headers.insert(HeaderName::from_static("x-forwarded-uri"), value);
        }

        // Configured header_up entries, applied last so they can override the defaults above.
        for (name, values) in &self.header_up {
            if let Some(delete) = name.strip_prefix('-') {
                if let Ok(delete) = delete.parse::<HeaderName>() {
                    headers.remove(delete);
                }
                continue;
            }
            let Ok(field) = name.parse::<HeaderName>() else {
                continue;
            };
            headers.remove(&field);
            for value in values {
                let expanded = request.replace_known(value);
                if let Ok(value) = HeaderValue::from_str(&expanded) {
                    headers.append(field.clone(), value);
                }
            }
        }

        let mut builder = http::Request::builder()
            .method(self.method.clone())
            .uri(uri);
        if let Some(target) = builder.headers_mut() {
            *target = headers;
        }
        builder
            .body(Full::new(Bytes::new()))
            .map_err(|error| invalid("forward_auth.request", error.to_string()))
    }
}

fn scheme(request: &Request) -> &'static str {
    if request.tls {
        "https"
    } else {
        "http"
    }
}

fn validate_dial(dial: &str, path: &str) -> Result<()> {
    if dial.is_empty() {
        return Err(invalid(path, "upstream dial address is empty"));
    }
    if dial.contains('{') {
        return Err(Error::NotImplemented {
            feature: "placeholders in forward_auth upstream dials",
            tracking_id: "HTTP-FORWARD-AUTH-PLACEHOLDERS",
        });
    }
    if dial.starts_with("unix/") {
        return Err(Error::NotImplemented {
            feature: "unix socket forward_auth upstreams",
            tracking_id: "HTTP-FORWARD-AUTH-UNIX",
        });
    }
    if dial.starts_with("http://") || dial.starts_with("https://") {
        return Err(invalid(
            path,
            format!("upstream dial `{dial}` must not include a scheme"),
        ));
    }
    if !dial.contains(':') {
        return Err(invalid(
            path,
            format!("upstream dial `{dial}` is missing a port"),
        ));
    }
    Ok(())
}

#[async_trait::async_trait]
impl Handler for ForwardAuthHandler {
    fn name(&self) -> &'static str {
        "forward_auth"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        let subrequest = self.build_subrequest(&request)?;
        let response = self.client.request(subrequest).await.map_err(|error| {
            runtime_io(format!(
                "forward_auth upstream `{}`: {error}",
                self.upstream
            ))
        })?;
        let status = response.status();
        let upstream_headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| {
                runtime_io(format!(
                    "forward_auth upstream `{}`: reading response body: {error}",
                    self.upstream
                ))
            })?
            .to_bytes();

        if status.is_success() {
            for (from, to) in &self.copy_headers {
                // Delete first: a client-supplied header must not survive when the auth service
                // does not return it (Caddy's adapter relies on the same delete-then-set order).
                request.headers.remove(to);
                if let Some(value) = joined_header(&upstream_headers, from) {
                    if !value.is_empty() {
                        let value = HeaderValue::from_str(&value).map_err(|error| {
                            invalid(
                                "forward_auth.copy_headers",
                                format!("auth response header `{from}` is not a valid header value: {error}"),
                            )
                        })?;
                        request.headers.insert(to.clone(), value);
                    }
                }
            }
            Ok(Outcome::Continue(request))
        } else {
            // Pass the auth response through unchanged (except hop-by-hop headers).
            let mut headers = HeaderMap::new();
            for (name, value) in &upstream_headers {
                if is_hop_by_hop(name) {
                    continue;
                }
                headers.append(name.clone(), value.clone());
            }
            Ok(Outcome::Respond(Response {
                status,
                headers,
                body,
            }))
        }
    }
}

/// How account passwords are verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordAlgorithm {
    Bcrypt,
    Argon2id,
    /// caddy-rs extension: account `password` is literal plaintext (opt-in only).
    Plaintext,
}

/// The `authentication` handler restricted to its HTTP Basic provider (plus the `basic_auth`
/// shorthand handler name).
#[derive(Debug)]
pub struct BasicAuthHandler {
    accounts: BTreeMap<String, Account>,
    realm: String,
    /// Caddy's fixed fake hashes, verified for unknown usernames to avoid a user-existence timing
    /// side channel (see `BcryptHash.FakeHash`/`Argon2idHash.FakeHash` upstream).
    fake_hash: std::sync::Arc<PasswordHash>,
    /// Memoised comparison results (Caddy's `hash_cache`), keyed by a secret-keyed MAC.
    cache: std::sync::Arc<HashCache>,
    /// Hash-permit pool; the process-wide one unless a test injects its own.
    limiter: std::sync::Arc<tokio::sync::Semaphore>,
    /// Longest a request may wait for a hash permit before a 503. `None` (`stock_compat: true`)
    /// waits indefinitely, like stock Caddy.
    max_wait: Option<std::time::Duration>,
}

/// Longest wait for a hash permit under the secure default before answering 503 + `Retry-After`.
const HASH_QUEUE_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Entries kept by the hash cache (Caddy's `HashCache` also stops growing at 1000 entries).
const HASH_CACHE_CAPACITY: usize = 1000;

/// Caddy's `hash_cache`: remembers whether a (stored hash, presented password) pair matched, so a
/// repeated credential pair is answered without recomputing bcrypt/argon2id.
///
/// Unlike a map keyed by the plaintext, entries are keyed by `HMAC-SHA256(secret, hash || 0 ||
/// password)` with a random per-handler secret that never leaves the process, so the cache
/// contents cannot be used to test password guesses offline.
struct HashCache {
    key: ring::hmac::Key,
    entries: std::sync::Mutex<std::collections::HashMap<[u8; 32], bool>>,
}

impl std::fmt::Debug for HashCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HashCache").finish_non_exhaustive()
    }
}

impl HashCache {
    fn new() -> Self {
        let rng = ring::rand::SystemRandom::new();
        Self {
            key: ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng)
                .expect("the system random source is available"),
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn key(&self, identity: &[u8], password: &[u8]) -> [u8; 32] {
        let mut message = Vec::with_capacity(8 + identity.len() + password.len());
        message.extend_from_slice(&(identity.len() as u64).to_be_bytes());
        message.extend_from_slice(identity);
        message.extend_from_slice(password);
        let tag = ring::hmac::sign(&self.key, &message);
        let mut key = [0u8; 32];
        key.copy_from_slice(tag.as_ref());
        key
    }

    fn get(&self, key: &[u8; 32]) -> Option<bool> {
        self.entries.lock().ok()?.get(key).copied()
    }

    fn insert(&self, key: [u8; 32], matched: bool) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= HASH_CACHE_CAPACITY && !entries.contains_key(&key) {
            if let Some(victim) = entries.keys().next().copied() {
                entries.remove(&victim);
            }
        }
        entries.insert(key, matched);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }
}

#[derive(Debug, Clone)]
struct Account {
    /// `Arc` so the hash can move into the blocking pool without a deep copy per request.
    hash: std::sync::Arc<PasswordHash>,
}

/// A validated account password: the modular-crypt/PHC hash is parsed at configuration load, so
/// malformed hashes fail loudly instead of turning into request-time 401s.
#[derive(Clone)]
enum PasswordHash {
    /// `$2a$`/`$2b$`/`$2x$`/`$2y$` modular-crypt bcrypt hash (validated by `bcrypt::HashParts`).
    Bcrypt(String),
    /// Argon2id PHC hash with the salt/parameters/key decoded from the encoded hash.
    Argon2id(Argon2idHash),
    /// caddy-rs extension: literal plaintext (opt-in only).
    Plaintext(Vec<u8>),
}

/// Manual `Debug`: never prints a plaintext password, a bcrypt hash or an argon2 key.
impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Bcrypt(_) => "Bcrypt",
            Self::Argon2id(_) => "Argon2id",
            Self::Plaintext(_) => "Plaintext",
        };
        formatter
            .debug_tuple(kind)
            .field(&format_args!("<redacted>"))
            .finish()
    }
}

#[derive(Clone)]
struct Argon2idHash {
    salt: Vec<u8>,
    key: Vec<u8>,
    params: Params,
}

/// Manual `Debug`: salt and derived key are redacted; the cost parameters stay visible.
impl std::fmt::Debug for Argon2idHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Argon2idHash")
            .field("salt", &format_args!("<redacted>"))
            .field("key", &format_args!("<redacted>"))
            .field("params", &self.params)
            .finish()
    }
}

impl BasicAuthHandler {
    /// Build from Caddy JSON. Accepts the canonical `authentication` handler shape as well as the
    /// caddy-rs `basic_auth` shorthand that carries the `http_basic` provider fields directly.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        Self::from_json_with_stock_compat(value, path, false)
    }

    /// Like [`Self::from_json`] with the generation's `stock_compat`: `true` keeps Caddy's
    /// unbounded wait for a hash permit, `false` (the secure default) answers 503 + `Retry-After`
    /// once the wait exceeds [`HASH_QUEUE_MAX_WAIT`].
    pub fn from_json_with_stock_compat(
        value: &serde_json::Value,
        path: &str,
        stock_compat: bool,
    ) -> Result<Self> {
        let mut handler = Self::from_json_inner(value, path)?;
        handler.max_wait = (!stock_compat).then_some(HASH_QUEUE_MAX_WAIT);
        Ok(handler)
    }

    #[cfg(test)]
    fn with_hash_limits(
        mut self,
        limiter: std::sync::Arc<tokio::sync::Semaphore>,
        max_wait: std::time::Duration,
    ) -> Self {
        self.limiter = limiter;
        if self.max_wait.is_some() {
            self.max_wait = Some(max_wait);
        }
        self
    }

    fn from_json_inner(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "basic_auth handler must be an object"))?;
        let handler_name = object.get("handler").and_then(serde_json::Value::as_str);

        let provider = if handler_name == Some("authentication") {
            match object.get("providers") {
                None => None,
                Some(providers) => {
                    let providers = providers.as_object().ok_or_else(|| {
                        invalid(
                            format!("{path}.providers"),
                            "`providers` must be an object of provider name to configuration",
                        )
                    })?;
                    for name in providers.keys() {
                        if name != "http_basic" {
                            return Err(invalid(
                                format!("{path}.providers.{name}"),
                                format!(
                                    "authentication provider `{name}` is not implemented by this build"
                                ),
                            ));
                        }
                    }
                    providers.get("http_basic")
                }
            }
        } else {
            // caddy-rs `basic_auth` shorthand: provider fields at the top level.
            Some(value)
        };

        let provider = match provider {
            None => {
                return Ok(Self {
                    accounts: BTreeMap::new(),
                    realm: "restricted".to_string(),
                    fake_hash: std::sync::Arc::new(fake_hash(PasswordAlgorithm::Bcrypt)),
                    cache: std::sync::Arc::new(HashCache::new()),
                    limiter: std::sync::Arc::clone(hash_verification_limiter()),
                    max_wait: Some(HASH_QUEUE_MAX_WAIT),
                });
            }
            Some(provider) => provider.as_object().ok_or_else(|| {
                invalid(path, "http_basic provider configuration must be an object")
            })?,
        };

        let algorithm = parse_algorithm(provider.get("hash"), path)?;
        let realm = match provider.get("realm").and_then(serde_json::Value::as_str) {
            Some(realm) => realm.to_string(),
            None => "restricted".to_string(),
        };
        // Validate that the challenge header can be built now, so a bad realm fails at config
        // time rather than during a request.
        let challenge = format!("Basic realm=\"{realm}\"");
        HeaderValue::from_str(&challenge).map_err(|error| {
            invalid(
                format!("{path}.realm"),
                format!("realm `{realm}` produces an invalid challenge header: {error}"),
            )
        })?;

        let mut accounts: BTreeMap<String, Account> = BTreeMap::new();
        let account_list = match provider.get("accounts") {
            None => &Vec::new(),
            Some(accounts) => accounts.as_array().ok_or_else(|| {
                invalid(format!("{path}.accounts"), "`accounts` must be an array")
            })?,
        };
        for (index, account) in account_list.iter().enumerate() {
            let account_path = format!("{path}.accounts[{index}]");
            let account = account.as_object().ok_or_else(|| {
                invalid(
                    &account_path,
                    "account must be an object with username/password",
                )
            })?;
            let username = account
                .get("username")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    invalid(
                        format!("{account_path}.username"),
                        "account must have a string `username`",
                    )
                })?;
            let password = account
                .get("password")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    invalid(
                        format!("{account_path}.password"),
                        "account must have a string `password` (hash)",
                    )
                })?;

            // Caddy expands placeholders in account usernames/passwords at provision time using
            // the global replacer, so `{env.NAME}` works here; unknown placeholders stay literal.
            let username = expand_env_placeholders(username);
            let password = expand_env_placeholders(password);
            if username.is_empty() || password.is_empty() {
                return Err(invalid(&account_path, "username and password are required"));
            }
            if accounts.contains_key(&username) {
                return Err(invalid(
                    &account_path,
                    format!("username is not unique: {username}"),
                ));
            }

            let password_bytes = match algorithm {
                PasswordAlgorithm::Plaintext => password.into_bytes(),
                PasswordAlgorithm::Bcrypt | PasswordAlgorithm::Argon2id => {
                    if password.contains('{') {
                        // Mirrors Caddy: a password that still contains braces after placeholder
                        // expansion is not a valid base64 hash and must fail provisioning.
                        return Err(invalid(
                            format!("{account_path}.password"),
                            "password hash contains a literal `{`; expected a bcrypt/argon2id \
                             modular-crypt hash or base64-encoded hash",
                        ));
                    }
                    if password.starts_with('$') {
                        password.into_bytes()
                    } else {
                        decode_base64(password.trim()).ok_or_else(|| {
                            invalid(
                                format!("{account_path}.password"),
                                "base64-decoding password failed; clear-text passwords are not \
                                 accepted for bcrypt/argon2id (use a modular-crypt/PHC hash)",
                            )
                        })?
                    }
                }
            };
            let hash = parse_password_hash(
                algorithm,
                &password_bytes,
                &format!("{account_path}.password"),
            )?;
            accounts.insert(
                username,
                Account {
                    hash: std::sync::Arc::new(hash),
                },
            );
        }

        Ok(Self {
            accounts,
            realm,
            fake_hash: std::sync::Arc::new(fake_hash(algorithm)),
            cache: std::sync::Arc::new(HashCache::new()),
            limiter: std::sync::Arc::clone(hash_verification_limiter()),
            max_wait: Some(HASH_QUEUE_MAX_WAIT),
        })
    }
}

fn parse_algorithm(hash: Option<&serde_json::Value>, path: &str) -> Result<PasswordAlgorithm> {
    let Some(hash) = hash else {
        // Caddy's default hash algorithm is bcrypt.
        return Ok(PasswordAlgorithm::Bcrypt);
    };
    let hash = hash.as_object().ok_or_else(|| {
        invalid(
            format!("{path}.hash"),
            "`hash` must be a module object with an `algorithm`",
        )
    })?;
    let algorithm = hash
        .get("algorithm")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            invalid(
                format!("{path}.hash.algorithm"),
                "hash object must name an `algorithm`",
            )
        })?;
    match algorithm {
        "bcrypt" => Ok(PasswordAlgorithm::Bcrypt),
        "argon2id" => Ok(PasswordAlgorithm::Argon2id),
        "plaintext" => Ok(PasswordAlgorithm::Plaintext),
        other => Err(invalid(
            format!("{path}.hash.algorithm"),
            format!(
                "hash algorithm `{other}` is not implemented by this build (supported: bcrypt, \
                 argon2id, and the caddy-rs extension `plaintext`)"
            ),
        )),
    }
}

/// Caddy's fixed fake bcrypt hash (cost 14), used for unknown usernames so verification time does
/// not disclose account existence.
const BCRYPT_FAKE_HASH: &str = "$2a$14$X3ulqf/iGxnf1k6oMZ.RZeJUoqI9PX2PM4rS5lkIKJXduLGXGPrt6";

/// Caddy's fixed fake Argon2id hash (m=47104,t=1,p=1), used for unknown usernames.
const ARGON2ID_FAKE_HASH: &str =
    "$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg";

fn fake_hash(algorithm: PasswordAlgorithm) -> PasswordHash {
    match algorithm {
        PasswordAlgorithm::Bcrypt => PasswordHash::Bcrypt(BCRYPT_FAKE_HASH.to_string()),
        PasswordAlgorithm::Argon2id => PasswordHash::Argon2id(
            parse_argon2id_hash(ARGON2ID_FAKE_HASH.as_bytes(), "built-in argon2id fake hash")
                .expect("built-in argon2id fake hash is valid"),
        ),
        PasswordAlgorithm::Plaintext => PasswordHash::Plaintext(b"caddy-rs-fake-password".to_vec()),
    }
}

/// Validate and parse an account password at configuration load.
fn parse_password_hash(
    algorithm: PasswordAlgorithm,
    bytes: &[u8],
    path: &str,
) -> Result<PasswordHash> {
    match algorithm {
        PasswordAlgorithm::Plaintext => Ok(PasswordHash::Plaintext(bytes.to_vec())),
        PasswordAlgorithm::Bcrypt => {
            let encoded = std::str::from_utf8(bytes).map_err(|error| {
                invalid(path, format!("bcrypt hash is not valid UTF-8: {error}"))
            })?;
            if !["$2a$", "$2b$", "$2x$", "$2y$"]
                .iter()
                .any(|prefix| encoded.starts_with(prefix))
            {
                return Err(invalid(
                    path,
                    "unsupported bcrypt hash; expected `$2a$`, `$2b$`, `$2x$` or `$2y$` \
                     modular-crypt format (not a clear-text password)",
                ));
            }
            let parts = encoded
                .parse::<bcrypt::HashParts>()
                .map_err(|error| invalid(path, format!("invalid bcrypt hash: {error}")))?;
            let cost = parts.get_cost();
            if !(4..=31).contains(&cost) {
                return Err(invalid(
                    path,
                    format!("bcrypt cost {cost} is outside the supported range 4..=31"),
                ));
            }
            Ok(PasswordHash::Bcrypt(encoded.to_string()))
        }
        PasswordAlgorithm::Argon2id => {
            Ok(PasswordHash::Argon2id(parse_argon2id_hash(bytes, path)?))
        }
    }
}

/// Parse an Argon2id PHC string exactly like Caddy v2.11.7's `DecodeHash`:
/// six `$`-separated fields, variant `argon2id`, `v=19`, three parameters in `m,t,p` order, and
/// raw standard base64 (strict, unpadded) salt/key. Parameter validity is also checked here so a
/// malformed hash fails at load rather than on the request path.
fn parse_argon2id_hash(bytes: &[u8], path: &str) -> Result<Argon2idHash> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| invalid(path, format!("argon2id hash is not valid UTF-8: {error}")))?;
    let parts: Vec<&str> = text.split('$').collect();
    if parts.len() != 6 || !parts[0].is_empty() {
        return Err(invalid(
            path,
            "invalid argon2id hash format; expected \
             `$argon2id$v=19$m=<mem>,t=<time>,p=<threads>$<salt>$<key>`",
        ));
    }
    if parts[1] != "argon2id" {
        return Err(invalid(
            path,
            format!(
                "unsupported argon2 variant `{}`; only `argon2id` is supported",
                parts[1]
            ),
        ));
    }
    let version = parts[2]
        .strip_prefix("v=")
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "invalid argon2id version field `{}`; expected `v=19`",
                    parts[2]
                ),
            )
        })?;
    if version != 19 {
        return Err(invalid(
            path,
            format!("incompatible argon2id version {version}; expected version 19"),
        ));
    }
    let params: Vec<&str> = parts[3].split(',').collect();
    if params.len() != 3 {
        return Err(invalid(
            path,
            "invalid argon2id parameters; expected exactly `m=...,t=...,p=...`",
        ));
    }
    let memory = params[0]
        .strip_prefix("m=")
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "invalid argon2id memory parameter `{}`; expected `m=<u32>`",
                    params[0]
                ),
            )
        })?;
    let time = params[1]
        .strip_prefix("t=")
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "invalid argon2id iterations parameter `{}`; expected `t=<u32>`",
                    params[1]
                ),
            )
        })?;
    let threads = params[2]
        .strip_prefix("p=")
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "invalid argon2id parallelism parameter `{}`; expected `p=<u32>`",
                    params[2]
                ),
            )
        })?;
    let salt = decode_base64_raw_std_strict(parts[4])
        .ok_or_else(|| invalid(path, "argon2id salt is not valid unpadded standard base64"))?;
    let key = decode_base64_raw_std_strict(parts[5])
        .ok_or_else(|| invalid(path, "argon2id key is not valid unpadded standard base64"))?;
    if salt.len() < 8 {
        return Err(invalid(
            path,
            format!(
                "argon2id salt is {} bytes; at least 8 are required",
                salt.len()
            ),
        ));
    }
    let params = Params::new(memory, time, threads, Some(key.len())).map_err(|error| {
        invalid(
            path,
            format!(
                "invalid argon2id parameters m={memory},t={time},p={threads},\
                     keylen={}: {error}",
                key.len()
            ),
        )
    })?;
    Ok(Argon2idHash { salt, key, params })
}

/// Decode unpadded standard base64 with Caddy's strict trailing-bit rules
/// (`base64.RawStdEncoding.Strict()`): no padding, no invalid characters, no non-zero trailing
/// bits and no dangling one-character group.
fn decode_base64_raw_std_strict(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if input.contains('=') || input.len() % 4 == 1 {
        return None;
    }
    let mut lookup = [255u8; 256];
    for (index, byte) in ALPHABET.iter().enumerate() {
        lookup[*byte as usize] = index as u8;
    }
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let value = lookup[byte as usize];
        if value == 255 {
            return None;
        }
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if buffer != 0 {
        return None;
    }
    Some(output)
}

/// Constant-time verification against a parsed hash. bcrypt's crate compares the computed digest
/// in constant time; argon2id and the plaintext extension use [`constant_time_eq`].
fn verify_password(hash: &PasswordHash, password: &[u8]) -> bool {
    match hash {
        PasswordHash::Bcrypt(encoded) => bcrypt::verify(password, encoded).unwrap_or(false),
        PasswordHash::Argon2id(hash) => {
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, hash.params.clone());
            let mut computed = vec![0u8; hash.key.len()];
            if argon2
                .hash_password_into(password, &hash.salt, &mut computed)
                .is_err()
            {
                return false;
            }
            constant_time_eq(&computed, &hash.key)
        }
        PasswordHash::Plaintext(expected) => constant_time_eq(expected, password),
    }
}

/// Upper bound on simultaneous password-hash computations: the machine's parallelism (at least
/// 2). Hashing is pure CPU (and, for argon2id, memory) work, so more concurrency than cores only
/// adds memory pressure without adding throughput.
fn hash_verification_limit() -> usize {
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .max(2)
}

/// Process-wide limiter shared by every `basic_auth` handler instance, so the bound holds for
/// the whole server rather than per route.
fn hash_verification_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static LIMITER: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIMITER
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(hash_verification_limit())))
}

/// Run blocking `work` on the blocking pool once a permit is free. Callers beyond the limit wait
/// asynchronously (they never occupy a worker thread and are never rejected, so response codes
/// stay exactly Caddy's). A cancelled/panicked job counts as a failed verification.
///
/// The permit moves INTO the blocking closure: if the request future is dropped (HTTP/2
/// `RST_STREAM`, timeout) the detached hash keeps its permit until it really finishes, so
/// cancelled requests cannot multiply concurrent hashes beyond the limit.
async fn run_limited<F>(limiter: &std::sync::Arc<tokio::sync::Semaphore>, work: F) -> bool
where
    F: FnOnce() -> bool + Send + 'static,
{
    run_limited_within(limiter, None, work)
        .await
        .unwrap_or(false)
}

/// [`run_limited`] with an optional cap on the wait for a permit: `None` waits indefinitely;
/// `Some(limit)` gives up with `None` (the caller answers 503) once the wait exceeds `limit`.
async fn run_limited_within<F>(
    limiter: &std::sync::Arc<tokio::sync::Semaphore>,
    max_wait: Option<std::time::Duration>,
    work: F,
) -> Option<bool>
where
    F: FnOnce() -> bool + Send + 'static,
{
    let acquire = std::sync::Arc::clone(limiter).acquire_owned();
    let permit = match max_wait {
        None => acquire.await,
        Some(limit) => tokio::time::timeout(limit, acquire).await.ok()?,
    };
    let Ok(permit) = permit else {
        return Some(false);
    };
    Some(
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .unwrap_or(false),
    )
}

impl PasswordHash {
    /// Stable bytes identifying the stored hash, mixed into the hash-cache key.
    fn cache_identity(&self) -> Vec<u8> {
        match self {
            Self::Bcrypt(encoded) => [b"bcrypt:".as_slice(), encoded.as_bytes()].concat(),
            Self::Argon2id(hash) => {
                let mut identity = b"argon2id:".to_vec();
                for value in [
                    hash.params.m_cost(),
                    hash.params.t_cost(),
                    hash.params.p_cost(),
                ] {
                    identity.extend_from_slice(&value.to_be_bytes());
                }
                identity.extend_from_slice(&(hash.salt.len() as u64).to_be_bytes());
                identity.extend_from_slice(&hash.salt);
                identity.extend_from_slice(&hash.key);
                identity
            }
            Self::Plaintext(expected) => [b"plaintext:".as_slice(), expected].concat(),
        }
    }
}

impl BasicAuthHandler {
    /// Verify `password` against `hash` without blocking an async worker. bcrypt (cost 14 for the
    /// unknown-user fake hash) and argon2id take 100 ms to seconds of CPU; the constant-time
    /// plaintext extension is trivially cheap and stays inline. Repeated pairs are answered from
    /// the hash cache. `None` means the hash pool stayed saturated past the secure-default wait.
    ///
    /// `username` is `Some` only for a real account: the verdict for the fake hash of an unknown
    /// user is never cached (a cached unknown-user verdict would make a repeat probe cheaper than
    /// the same probe of a real account, a user-existence oracle), and the username is part of
    /// every cache key.
    async fn verify_offloaded(
        &self,
        username: Option<&str>,
        hash: std::sync::Arc<PasswordHash>,
        password: Vec<u8>,
    ) -> Option<bool> {
        if matches!(*hash, PasswordHash::Plaintext(_)) {
            return Some(verify_password(&hash, &password));
        }
        let key = username.map(|username| {
            let mut identity = (username.len() as u64).to_be_bytes().to_vec();
            identity.extend_from_slice(username.as_bytes());
            identity.extend_from_slice(&hash.cache_identity());
            self.cache.key(&identity, &password)
        });
        if let Some(matched) = key.as_ref().and_then(|key| self.cache.get(key)) {
            return Some(matched);
        }
        let cache = std::sync::Arc::clone(&self.cache);
        run_limited_within(&self.limiter, self.max_wait, move || {
            let matched = verify_password(&hash, &password);
            // Cached from inside the job so a hash whose request was cancelled still pays off.
            if let Some(key) = key {
                cache.insert(key, matched);
            }
            matched
        })
        .await
    }
}

fn overloaded() -> Outcome {
    let mut response = Response {
        status: StatusCode::SERVICE_UNAVAILABLE,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    response
        .headers
        .insert(http::header::RETRY_AFTER, HeaderValue::from_static("5"));
    Outcome::Respond(response)
}

/// Expand `{env.NAME}` placeholders the way Caddy's global replacer does at provision time.
/// Unknown placeholders are left literal (ReplaceKnown semantics); unset environment variables
/// expand to the empty string (env lookups are always known to Caddy).
fn expand_env_placeholders(input: &str) -> String {
    if !input.contains('{') {
        return input.to_string();
    }
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('{') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            output.push_str(&rest[start..]);
            return output;
        };
        let name = &after[..end];
        if let Some(variable) = name.strip_prefix("env.") {
            output.push_str(&std::env::var(variable).unwrap_or_default());
        } else {
            output.push('{');
            output.push_str(name);
            output.push('}');
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    output
}

/// Decode standard base64 (with optional padding). Returns `None` on invalid input.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (index, byte) in ALPHABET.iter().enumerate() {
        lookup[*byte as usize] = index as u8;
    }
    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let value = lookup[byte as usize];
        if value == 255 {
            return None;
        }
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(output)
}

/// Parse an HTTP Basic `Authorization` header into `(username, password)`.
fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(http::header::AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = decode_base64(encoded.trim())?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    if username.is_empty() {
        return None;
    }
    Some((username.to_string(), password.to_string()))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn challenge(realm: &str) -> Outcome {
    let mut response = Response {
        status: StatusCode::UNAUTHORIZED,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    if let Ok(value) = HeaderValue::from_str(&format!("Basic realm=\"{realm}\"")) {
        response
            .headers
            .insert(http::header::WWW_AUTHENTICATE, value);
    }
    Outcome::Respond(response)
}

#[async_trait::async_trait]
impl Handler for BasicAuthHandler {
    fn name(&self) -> &'static str {
        "basic_auth"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        let Some((username, password)) = parse_basic_auth(&request.headers) else {
            return Ok(challenge(&self.realm));
        };

        // Verify even for unknown usernames, against Caddy's fixed fake hash for the configured
        // algorithm, so response timing does not reveal whether the account exists. The hash runs
        // on the blocking pool behind a concurrency limiter (SEC-MEDIUM-HTTP B1) so bad
        // credentials cannot starve the async workers; unknown users take the same path.
        let account = self.accounts.get(&username);
        let hash = account.map_or_else(
            || std::sync::Arc::clone(&self.fake_hash),
            |account| std::sync::Arc::clone(&account.hash),
        );
        let cache_user = account.is_some().then_some(username.as_str());
        let Some(matches) = self
            .verify_offloaded(cache_user, hash, password.into_bytes())
            .await
        else {
            return Ok(overloaded());
        };
        if !matches || account.is_none() {
            return Ok(challenge(&self.realm));
        }

        // Same placeholder Caddy sets after successful authentication, so later handlers
        // (`headers`, `reverse_proxy` header_up, logs) can forward the identity.
        request.record_access_log_user_id(username.clone());
        request
            .vars
            .insert("http.auth.user.id".to_string(), username);
        Ok(Outcome::Continue(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use http::header;
    use http_body_util::Full as TestFull;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use tokio::net::TcpListener;

    fn base_request() -> Request {
        let mut request = Request::new(Method::POST, "/protected?q=1".parse::<Uri>().unwrap());
        request
            .headers
            .insert(header::HOST, HeaderValue::from_static("example.com"));
        request
            .headers
            .insert(header::COOKIE, HeaderValue::from_static("session=abc"));
        request.remote_addr = Some("203.0.113.7:5555".parse().unwrap());
        request
    }

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        method: Method,
        uri: String,
        headers: HeaderMap,
    }

    struct MockResponse {
        status: StatusCode,
        headers: Vec<(&'static str, &'static str)>,
        body: &'static str,
    }

    type Responder = Arc<dyn Fn(&RecordedRequest) -> MockResponse + Send + Sync>;

    /// Spawn a mock auth upstream; returns its dial address and the recorded subrequests.
    async fn spawn_auth_server(responder: Responder) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local addr");
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let recorded_for_server = Arc::clone(&recorded);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let responder = Arc::clone(&responder);
                let recorded = Arc::clone(&recorded_for_server);
                tokio::spawn(async move {
                    let service =
                        service_fn(move |request: http::Request<hyper::body::Incoming>| {
                            let responder = Arc::clone(&responder);
                            let recorded = Arc::clone(&recorded);
                            async move {
                                let recorded_request = RecordedRequest {
                                    method: request.method().clone(),
                                    uri: request
                                        .uri()
                                        .path_and_query()
                                        .map(|path| path.as_str().to_string())
                                        .unwrap_or_default(),
                                    headers: request.headers().clone(),
                                };
                                recorded.lock().unwrap().push(recorded_request.clone());
                                let response = responder(&recorded_request);
                                let mut builder = http::Response::builder().status(response.status);
                                for (name, value) in response.headers {
                                    builder = builder.header(name, value);
                                }
                                Ok::<_, std::convert::Infallible>(
                                    builder
                                        .body(TestFull::new(Bytes::from_static(
                                            response.body.as_bytes(),
                                        )))
                                        .expect("mock response"),
                                )
                            }
                        });
                    let _ = http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (address.to_string(), recorded)
    }

    fn forward_auth_handler(dial: &str, extra: serde_json::Value) -> ForwardAuthHandler {
        let mut value = serde_json::json!({
            "handler": "forward_auth",
            "upstreams": [{"dial": dial}],
            "uri": "/authz"
        });
        if let serde_json::Value::Object(extra) = extra {
            let object = value.as_object_mut().unwrap();
            for (key, value) in extra {
                object.insert(key, value);
            }
        }
        ForwardAuthHandler::from_json(&value, "handler").expect("handler config")
    }

    #[test]
    fn forward_auth_requires_uri_and_upstreams() {
        let error = ForwardAuthHandler::from_json(
            &serde_json::json!({"handler": "forward_auth", "upstreams": [{"dial": "auth:9091"}]}),
            "handler",
        )
        .expect_err("missing uri");
        assert!(error.to_string().contains("uri"), "{error}");

        let error = ForwardAuthHandler::from_json(
            &serde_json::json!({"handler": "forward_auth", "uri": "/authz"}),
            "handler",
        )
        .expect_err("missing upstreams");
        assert!(error.to_string().contains("upstreams"), "{error}");

        let error = ForwardAuthHandler::from_json(
            &serde_json::json!({
                "handler": "forward_auth",
                "uri": "/authz",
                "upstreams": [{"dial": "auth:9091"}, {"dial": "auth2:9091"}]
            }),
            "handler",
        )
        .expect_err("multiple upstreams");
        assert!(matches!(error, Error::NotImplemented { .. }), "{error}");
    }

    #[test]
    fn forward_auth_rejects_invalid_upstream_and_header_config() {
        let error = ForwardAuthHandler::from_json(
            &serde_json::json!({
                "handler": "forward_auth",
                "uri": "/authz",
                "upstreams": [{"dial": "https://auth:9091"}]
            }),
            "handler",
        )
        .expect_err("scheme");
        assert!(error.to_string().contains("scheme"), "{error}");

        let error = ForwardAuthHandler::from_json(
            &serde_json::json!({
                "handler": "forward_auth",
                "uri": "/authz",
                "upstreams": [{"dial": "auth:9091"}],
                "copy_headers": ["bad header"]
            }),
            "handler",
        )
        .expect_err("bad copy header");
        assert!(error.to_string().contains("copy_headers"), "{error}");

        let error = ForwardAuthHandler::from_json(
            &serde_json::json!({
                "handler": "forward_auth",
                "uri": "/authz",
                "upstreams": [{"dial": "auth:9091"}],
                "trusted_proxies": ["not-an-ip"]
            }),
            "handler",
        )
        .expect_err("bad trusted proxy");
        assert!(error.to_string().contains("trusted_proxies"), "{error}");
    }

    #[tokio::test]
    async fn forward_auth_copies_identity_headers_and_continues_on_2xx() {
        let responder: Responder = Arc::new(|_request| MockResponse {
            status: StatusCode::OK,
            headers: vec![("Remote-User", "alice"), ("Remote-Groups", "dev")],
            body: "ignored",
        });
        let (dial, recorded) = spawn_auth_server(responder).await;
        let handler = forward_auth_handler(
            &dial,
            serde_json::json!({
                "copy_headers": ["Remote-User", "Remote-Email", "Remote-Groups>X-Groups"],
                "header_up": {"X-Auth-Source": ["caddy-rs"]}
            }),
        );

        let mut request = base_request();
        // A client-supplied value for a copied header must be replaced or removed.
        request
            .headers
            .insert("Remote-User", HeaderValue::from_static("attacker"));
        request.headers.insert(
            "Remote-Email",
            HeaderValue::from_static("attacker@example.com"),
        );

        let Outcome::Continue(request) = handler.handle(request).await.expect("auth ok") else {
            panic!("expected continue");
        };
        assert_eq!(request.headers["remote-user"], "alice");
        assert!(!request.headers.contains_key("remote-email"));
        assert_eq!(request.headers["x-groups"], "dev");
        assert!(!request.headers.contains_key("remote-groups"));

        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let auth_request = &recorded[0];
        assert_eq!(auth_request.method, Method::GET);
        assert_eq!(auth_request.uri, "/authz");
        assert_eq!(auth_request.headers["host"], "example.com");
        assert_eq!(auth_request.headers["x-forwarded-method"], "POST");
        assert_eq!(auth_request.headers["x-forwarded-uri"], "/protected?q=1");
        assert_eq!(auth_request.headers["x-forwarded-for"], "203.0.113.7");
        assert_eq!(auth_request.headers["x-forwarded-proto"], "http");
        assert_eq!(auth_request.headers["x-forwarded-host"], "example.com");
        assert_eq!(auth_request.headers["x-auth-source"], "caddy-rs");
        // Original headers (cookies) are forwarded to the auth service.
        assert_eq!(
            auth_request.headers.get(header::COOKIE),
            Some(&HeaderValue::from_static("session=abc"))
        );
        // And no request body/content-length is sent.
        assert!(!auth_request.headers.contains_key(header::CONTENT_LENGTH));
    }

    #[tokio::test]
    async fn forward_auth_expands_uri_placeholders() {
        let responder: Responder = Arc::new(|_request| MockResponse {
            status: StatusCode::OK,
            headers: vec![],
            body: "",
        });
        let (dial, recorded) = spawn_auth_server(responder).await;
        let handler = forward_auth_handler(
            &dial,
            serde_json::json!({"uri": "/authz/{http.request.uri.path}"}),
        );
        let request = base_request();
        let Outcome::Continue(_request) = handler.handle(request).await.expect("auth ok") else {
            panic!("expected continue");
        };
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded[0].uri, "/authz//protected");
    }

    #[tokio::test]
    async fn forward_auth_passes_through_non_2xx_responses() {
        for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
            let responder: Responder = Arc::new(move |_request| MockResponse {
                status,
                headers: vec![("WWW-Authenticate", "Basic realm=\"auth\"")],
                body: "denied",
            });
            let (dial, _recorded) = spawn_auth_server(responder).await;
            let handler = forward_auth_handler(&dial, serde_json::json!({}));
            let Outcome::Respond(response) =
                handler.handle(base_request()).await.expect("response")
            else {
                panic!("expected passthrough response for {status}");
            };
            assert_eq!(response.status, status);
            assert_eq!(response.body, Bytes::from_static(b"denied"));
            if status == StatusCode::UNAUTHORIZED {
                assert_eq!(
                    response.headers[header::WWW_AUTHENTICATE],
                    "Basic realm=\"auth\""
                );
            }
        }
    }

    #[tokio::test]
    async fn forward_auth_reports_connection_failure_loudly() {
        // Nothing listens on this port: the handler must surface an I/O error, not continue.
        let handler = forward_auth_handler("127.0.0.1:1", serde_json::json!({}));
        let error = handler
            .handle(base_request())
            .await
            .expect_err("connect fails");
        assert!(matches!(error, Error::Io(_)), "{error}");
        assert!(
            error.to_string().contains("forward_auth upstream"),
            "{error}"
        );
    }

    fn basic_auth_handler(value: serde_json::Value) -> BasicAuthHandler {
        // `stock_compat` (unbounded hash-permit wait) keeps these functional tests independent of
        // load on the shared process-wide hash pool; the capped default has its own tests.
        BasicAuthHandler::from_json_with_stock_compat(&value, "handler", true)
            .expect("basic_auth config")
    }

    fn plaintext_handler(accounts: serde_json::Value) -> BasicAuthHandler {
        basic_auth_handler(serde_json::json!({
            "handler": "basic_auth",
            "hash": {"algorithm": "plaintext"},
            "realm": "test",
            "accounts": accounts
        }))
    }

    fn authorization(username: &str, password: &str) -> HeaderValue {
        let encoded = base64_encode(format!("{username}:{password}").as_bytes());
        HeaderValue::from_str(&format!("Basic {encoded}")).expect("header")
    }

    fn base64_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let combined = (b0 << 16) | (b1 << 8) | b2;
            output.push(ALPHABET[(combined >> 18) as usize & 63] as char);
            output.push(ALPHABET[(combined >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                output.push(ALPHABET[(combined >> 6) as usize & 63] as char);
            } else {
                output.push('=');
            }
            if chunk.len() > 2 {
                output.push(ALPHABET[combined as usize & 63] as char);
            } else {
                output.push('=');
            }
        }
        output
    }

    #[test]
    fn parses_canonical_authentication_json_and_shorthand() {
        let canonical = basic_auth_handler(serde_json::json!({
            "handler": "authentication",
            "providers": {"http_basic": {
                "accounts": [{"username": "alice", "password": "c2VjcmV0"}],
                "hash": {"algorithm": "plaintext"},
                "realm": "canonical"
            }}
        }));
        assert_eq!(canonical.realm, "canonical");

        let shorthand = plaintext_handler(serde_json::json!([
            {"username": "alice", "password": "secret"}
        ]));
        assert_eq!(shorthand.accounts.len(), 1);

        let error = BasicAuthHandler::from_json(
            &serde_json::json!({
                "handler": "authentication",
                "providers": {
                    "http_basic": {"accounts": []},
                    "jwt": {}
                }
            }),
            "handler",
        )
        .expect_err("unknown provider");
        assert!(error.to_string().contains("jwt"), "{error}");
    }

    #[test]
    fn basic_auth_config_rejects_invalid_accounts_and_algorithms() {
        let error = BasicAuthHandler::from_json(
            &serde_json::json!({
                "handler": "basic_auth",
                "accounts": [{"username": "alice", "password": "x"}],
                "hash": {"algorithm": "scrypt"}
            }),
            "handler",
        )
        .expect_err("unknown algorithm");
        assert!(error.to_string().contains("scrypt"), "{error}");

        let error = BasicAuthHandler::from_json(
            &serde_json::json!({
                "handler": "basic_auth",
                "hash": {"algorithm": "plaintext"},
                "accounts": [
                    {"username": "alice", "password": "a"},
                    {"username": "alice", "password": "b"}
                ]
            }),
            "handler",
        )
        .expect_err("duplicate username");
        assert!(error.to_string().contains("not unique"), "{error}");

        let error = BasicAuthHandler::from_json(
            &serde_json::json!({
                "handler": "basic_auth",
                "hash": {"algorithm": "plaintext"},
                "accounts": [{"username": "alice", "password": ""}]
            }),
            "handler",
        )
        .expect_err("empty password");
        assert!(error.to_string().contains("required"), "{error}");

        // A bcrypt hash field containing literal braces must be rejected, like Caddy.
        let error = BasicAuthHandler::from_json(
            &serde_json::json!({
                "handler": "basic_auth",
                "accounts": [{"username": "alice", "password": "ab{cd}ef"}]
            }),
            "handler",
        )
        .expect_err("braced password");
        assert!(error.to_string().contains("password"), "{error}");
    }

    #[tokio::test]
    async fn basic_auth_plaintext_verifies_credentials_and_sets_identity() {
        let handler = plaintext_handler(serde_json::json!([
            {"username": "alice", "password": "s3cret"}
        ]));

        // Missing credentials -> 401 challenge.
        let Outcome::Respond(response) = handler.handle(base_request()).await.unwrap() else {
            panic!("expected challenge");
        };
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers[header::WWW_AUTHENTICATE],
            "Basic realm=\"test\""
        );

        // Wrong password -> 401.
        let mut request = base_request();
        let failed_context = Arc::new(caddy_rs_admin::access_log::AccessLogContext::new());
        request = request.with_access_log(Arc::clone(&failed_context));
        request
            .headers
            .insert(header::AUTHORIZATION, authorization("alice", "wrong"));
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected challenge");
        };
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            failed_context.user_id(),
            None,
            "a rejected credential must not publish a user id"
        );

        // Unknown user -> 401.
        let mut request = base_request();
        request
            .headers
            .insert(header::AUTHORIZATION, authorization("bob", "s3cret"));
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected challenge");
        };
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        // Correct credentials -> continue with the Caddy identity placeholder variable set.
        let mut request = base_request();
        let access_log_context = Arc::new(caddy_rs_admin::access_log::AccessLogContext::new());
        request = request.with_access_log(Arc::clone(&access_log_context));
        request
            .headers
            .insert(header::AUTHORIZATION, authorization("alice", "s3cret"));
        let Outcome::Continue(request) = handler.handle(request).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(
            request.vars.get("http.auth.user.id").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            request.get_placeholder("http.auth.user.id").as_deref(),
            Some("alice")
        );
        assert_eq!(
            access_log_context.user_id().as_deref(),
            Some("alice"),
            "the access entry must carry the authenticated user"
        );
    }

    #[tokio::test]
    async fn basic_auth_bcrypt_verifies_credentials_and_sets_identity() {
        let handler = basic_auth_handler(serde_json::json!({
            "handler": "basic_auth",
            "hash": {"algorithm": "bcrypt"},
            "accounts": [{
                // Upstream Caddy's cost-4 bcrypt hash of "correct horse".
                "username": "alice",
                "password": "$2a$04$XziKIb5ayw0suaNwlK.1vOqOj9gEveGnkq.anOrdVrnkN5z1bA2A."
            }]
        }));

        // Unauthenticated requests still get the Caddy-compatible 401 challenge.
        let Outcome::Respond(response) = handler.handle(base_request()).await.unwrap() else {
            panic!("expected challenge");
        };
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        // Wrong password -> plain 401 challenge.
        let mut request = base_request();
        request
            .headers
            .insert(header::AUTHORIZATION, authorization("alice", "wrong"));
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected challenge");
        };
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers[header::WWW_AUTHENTICATE],
            "Basic realm=\"restricted\""
        );

        // Correct password -> continue and set Caddy's identity placeholder.
        let mut request = base_request();
        request.headers.insert(
            header::AUTHORIZATION,
            authorization("alice", "correct horse"),
        );
        let Outcome::Continue(request) = handler.handle(request).await.unwrap() else {
            panic!("expected continue");
        };
        assert_eq!(
            request.vars.get("http.auth.user.id").map(String::as_str),
            Some("alice")
        );
    }

    /// Oracle-captured bcrypt vectors (Python `bcrypt` for `$2a$`/`$2b$`, prefix-swapped to
    /// `$2y$`/`$2x$` since those variants share the algorithm) that real Caddy v2.11.7 accepted
    /// with HTTP 200 (see `.scratch/logs/w16-auth-oracle/`).
    const ORACLE_BCRYPT_VECTORS: &[(&str, &str)] = &[
        (
            "$2a$04$9QlsJIJQgPZUami30idia.XdCzenqBjwJUFXbz7pFAnHxsjGibTKK",
            "correct horse",
        ),
        (
            "$2b$04$CEH17OA6jMx9./SPzCa5LOPuscyz/cPVUYFoBSp3Y.ZDlRNy8Rc.O",
            "correct horse",
        ),
        (
            "$2y$04$9QlsJIJQgPZUami30idia.XdCzenqBjwJUFXbz7pFAnHxsjGibTKK",
            "correct horse",
        ),
        (
            "$2x$04$9QlsJIJQgPZUami30idia.XdCzenqBjwJUFXbz7pFAnHxsjGibTKK",
            "correct horse",
        ),
    ];

    /// Oracle-captured Argon2id PHC vectors generated with the `argon2` CLI and accepted by real
    /// Caddy v2.11.7 (HTTP 200).
    const ORACLE_ARGON2_VECTORS: &[(&str, &str)] = &[
        (
            "$argon2id$v=19$m=47104,t=2,p=1$c2FsdHNhbHQ$Z8rbAmmUGEG/qPhwSd9oICo6lEK8zJCDzyvsJss2ftE",
            "correct horse",
        ),
        (
            "$argon2id$v=19$m=19456,t=2,p=2$b3RoZXJzYWx0$hswpKvmAIY0wzaurlWuWHJeNDta45Nkv0CaXhAWMVd8",
            "correct horse",
        ),
        (
            "$argon2id$v=19$m=8192,t=3,p=1$dGhpcmRzYWx0$Pya7EQ8OExE2d4FJ7G7HZ56Vw2ISN402M/kPKRmFyM0",
            "another password",
        ),
        (
            "$argon2id$v=19$m=46,t=1,p=1$dW5pY29kZXNhbHQ$qkbmvPvO39xqVfw4T4l952gONQ9818f5Z/smW92Ckso",
            "correct horse",
        ),
    ];

    async fn assert_authorized(handler: &BasicAuthHandler, user: &str, password: &str) -> bool {
        let mut request = base_request();
        request
            .headers
            .insert(header::AUTHORIZATION, authorization(user, password));
        match handler.handle(request).await.unwrap() {
            Outcome::Continue(request) => {
                assert_eq!(
                    request.vars.get("http.auth.user.id").map(String::as_str),
                    Some(user)
                );
                true
            }
            Outcome::Respond(response) => {
                assert_eq!(response.status, StatusCode::UNAUTHORIZED);
                false
            }
        }
    }

    #[tokio::test]
    async fn bcrypt_verifies_real_vectors_cost_10_in_all_supported_versions() {
        use std::str::FromStr;
        // Cost-10 hash generated by the same bcrypt crate, rendered in each supported version.
        let parts = bcrypt::hash_with_result("correct horse", 10).expect("hash");
        for version in [
            bcrypt::Version::TwoA,
            bcrypt::Version::TwoB,
            bcrypt::Version::TwoY,
            bcrypt::Version::TwoX,
        ] {
            let prefix = format!("${}$", version);
            let encoded = parts.format_for_version(version);
            assert!(encoded.starts_with(&prefix), "{encoded}");
            let handler = basic_auth_handler(serde_json::json!({
                "handler": "basic_auth",
                "hash": {"algorithm": "bcrypt"},
                "accounts": [{"username": "alice", "password": encoded}]
            }));
            assert!(assert_authorized(&handler, "alice", "correct horse").await);
            assert!(!assert_authorized(&handler, "alice", "wrong horse").await);
            // Parsing accepts the exact rendered form (HashParts::from_str is the load validator).
            assert!(bcrypt::HashParts::from_str(&encoded).is_ok());
        }
    }

    #[tokio::test]
    async fn bcrypt_accepts_oracle_vectors_and_truncates_like_caddy() {
        for (hash, password) in ORACLE_BCRYPT_VECTORS {
            let handler = basic_auth_handler(serde_json::json!({
                "handler": "basic_auth",
                "hash": {"algorithm": "bcrypt"},
                "accounts": [{"username": "alice", "password": hash}]
            }));
            assert!(
                assert_authorized(&handler, "alice", password).await,
                "oracle bcrypt vector {hash}"
            );
            assert!(!assert_authorized(&handler, "alice", "wrong").await);
        }

        // Real Caddy v2.11.7 accepts a 100-byte password against a hash of its 72-byte prefix
        // (Go bcrypt truncates); the Rust backend must keep that parity.
        let hash = "$2b$04$YjOCOcFuLc/FT5P2sHfL3up87G4A5qrzkKlnkc5rQxap1BL0KzAw.";
        let handler = basic_auth_handler(serde_json::json!({
            "handler": "basic_auth",
            "hash": {"algorithm": "bcrypt"},
            "accounts": [{"username": "alice", "password": hash}]
        }));
        assert!(assert_authorized(&handler, "alice", &"a".repeat(72)).await);
        assert!(assert_authorized(&handler, "alice", &"a".repeat(100)).await);
    }

    #[tokio::test]
    async fn argon2id_verifies_oracle_vectors_with_encoded_parameters() {
        for (hash, password) in ORACLE_ARGON2_VECTORS {
            let handler = basic_auth_handler(serde_json::json!({
                "handler": "basic_auth",
                "hash": {"algorithm": "argon2id"},
                "accounts": [{"username": "alice", "password": hash}]
            }));
            assert!(
                assert_authorized(&handler, "alice", password).await,
                "oracle argon2id vector {hash}"
            );
            assert!(!assert_authorized(&handler, "alice", "wrong").await);
        }
    }

    #[tokio::test]
    async fn bcrypt_and_argon2id_reject_empty_unicode_and_unknown_credentials() {
        // Argon2id hash of a unicode password with non-default parameters, generated in-test.
        let salt = b"unicode-salt-123";
        let params = Params::new(8192, 2, 1, Some(32)).unwrap();
        let mut key = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into("pässwörd☃".as_bytes(), salt, &mut key)
            .unwrap();
        let hash = format!(
            "$argon2id$v=19$m=8192,t=2,p=1${}${}",
            base64_encode(salt).trim_end_matches('='),
            base64_encode(&key).trim_end_matches('=')
        );
        let handler = basic_auth_handler(serde_json::json!({
            "handler": "basic_auth",
            "hash": {"algorithm": "argon2id"},
            "accounts": [{"username": "alice", "password": hash}]
        }));
        assert!(assert_authorized(&handler, "alice", "pässwörd☃").await);
        assert!(!assert_authorized(&handler, "alice", "passwörd☃").await);
        assert!(!assert_authorized(&handler, "alice", "").await);
        assert!(!assert_authorized(&handler, "nobody", "pässwörd☃").await);
        // Empty password against a bcrypt account is a plain 401 too.
        let bcrypt = basic_auth_handler(serde_json::json!({
            "handler": "basic_auth",
            "hash": {"algorithm": "bcrypt"},
            "accounts": [{"username": "alice", "password": ORACLE_BCRYPT_VECTORS[0].0}]
        }));
        assert!(!assert_authorized(&bcrypt, "alice", "").await);
    }

    #[test]
    fn malformed_and_unsupported_hashes_fail_at_config_load() {
        let cases = [
            // Truncated / structurally invalid bcrypt.
            ("$2b$04$not-a-valid-hash", "bcrypt"),
            ("$2b$04$", "bcrypt"),
            (
                "$2a$03$9QlsJIJQgPZUami30idia.XdCzenqBjwJUFXbz7pFAnHxsjGibTKK",
                "bcrypt",
            ),
            (
                "$2c$04$9QlsJIJQgPZUami30idia.XdCzenqBjwJUFXbz7pFAnHxsjGibTKK",
                "bcrypt",
            ),
            ("hunter2", "bcrypt"),
            ("password", "bcrypt"),
            // Invalid argon2id encodings (variant/version/parameters/base64/salt/key lengths).
            ("$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$AAAA", "argon2id"),
            ("$argon2id$v=16$m=8192,t=1,p=1$c2FsdHNhbHQ$AAAA", "argon2id"),
            ("$argon2id$v=19$t=1,m=8192,p=1$c2FsdHNhbHQ$AAAA", "argon2id"),
            ("$argon2id$v=19$m=8192,t=1$c2FsdHNhbHQ$AAAA", "argon2id"),
            (
                "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ=$AAAA",
                "argon2id",
            ),
            ("$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$AA", "argon2id"),
            (
                "$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHQ$AAAAAAAA",
                "argon2id",
            ),
            (
                "$argon2id$v=19$m=8192,t=1,p=0$c2FsdHNhbHQ$AAAAAAAA",
                "argon2id",
            ),
        ];
        for (hash, algorithm) in cases {
            let error = BasicAuthHandler::from_json(
                &serde_json::json!({
                    "handler": "basic_auth",
                    "hash": {"algorithm": algorithm},
                    "accounts": [{"username": "alice", "password": hash}]
                }),
                "handler",
            )
            .expect_err("malformed hash must fail at load");
            assert!(
                error.to_string().contains(".accounts[0].password"),
                "located error for {hash}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn canonical_authentication_json_verifies_bcrypt_and_argon2id() {
        // The canonical `authentication` handler shape (what Caddy adapts `basic_auth` to) uses
        // the same verification path as the caddy-rs `basic_auth` shorthand.
        let bcrypt = basic_auth_handler(serde_json::json!({
            "handler": "authentication",
            "providers": {"http_basic": {
                "hash": {"algorithm": "bcrypt"},
                "accounts": [{"username": "alice", "password": ORACLE_BCRYPT_VECTORS[0].0}],
                "realm": "canonical"
            }}
        }));
        assert!(assert_authorized(&bcrypt, "alice", "correct horse").await);
        assert!(!assert_authorized(&bcrypt, "alice", "wrong").await);
        let argon = basic_auth_handler(serde_json::json!({
            "handler": "authentication",
            "providers": {"http_basic": {
                "hash": {"algorithm": "argon2id"},
                "accounts": [{"username": "alice", "password": ORACLE_ARGON2_VECTORS[0].0}]
            }}
        }));
        assert!(assert_authorized(&argon, "alice", "correct horse").await);
        assert!(!assert_authorized(&argon, "alice", "wrong").await);
    }

    #[tokio::test]
    async fn legacy_base64_encoded_bcrypt_hash_is_accepted() {
        let hash = ORACLE_BCRYPT_VECTORS[0].0;
        let encoded = base64_encode(hash.as_bytes());
        let handler = basic_auth_handler(serde_json::json!({
            "handler": "basic_auth",
            "hash": {"algorithm": "bcrypt"},
            "accounts": [{"username": "alice", "password": encoded}]
        }));
        assert!(assert_authorized(&handler, "alice", "correct horse").await);
        assert!(!assert_authorized(&handler, "alice", "wrong").await);
    }

    #[tokio::test]
    async fn verification_time_does_not_depend_on_password_length() {
        // Coarse timing check (documented design note): bcrypt's work factor is independent of the
        // supplied password length (only the first 72 bytes are used), and argon2id's cost is
        // dominated by the memory/iteration parameters. Use a cost-4 hash to keep the test fast;
        // compare medians with a generous ratio to avoid scheduler noise.
        use std::time::Instant;
        let short_password = b"a".to_vec();
        let long_password = b"a".repeat(64);
        let short_hash = bcrypt::hash(&short_password, 4).expect("short hash");
        let long_hash = bcrypt::hash(&long_password, 4).expect("long hash");
        let mut short_times = Vec::new();
        let mut long_times = Vec::new();
        for _ in 0..15 {
            let started = Instant::now();
            assert!(verify_password(
                &parse_password_hash(PasswordAlgorithm::Bcrypt, short_hash.as_bytes(), "test")
                    .unwrap(),
                &short_password
            ));
            short_times.push(started.elapsed());
            let started = Instant::now();
            assert!(verify_password(
                &parse_password_hash(PasswordAlgorithm::Bcrypt, long_hash.as_bytes(), "test")
                    .unwrap(),
                &long_password
            ));
            long_times.push(started.elapsed());
        }
        short_times.sort();
        long_times.sort();
        let short_median = short_times[short_times.len() / 2];
        let long_median = long_times[long_times.len() / 2];
        assert!(
            long_median < short_median * 5,
            "verification time depends on password length: short={short_median:?} long={long_median:?}"
        );
    }

    #[test]
    fn base64_and_basic_header_decoding() {
        let decoded = decode_base64("YWxpY2U6czNjcmV0").expect("decode");
        assert_eq!(decoded, b"alice:s3cret");

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic YWxpY2U6czNjcmV0"),
        );
        assert_eq!(
            parse_basic_auth(&headers),
            Some(("alice".to_string(), "s3cret".to_string()))
        );

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        assert_eq!(parse_basic_auth(&headers), None);
    }

    #[test]
    fn cidr_matching() {
        assert!(Cidr::parse("10.0.0.0/8")
            .unwrap()
            .contains("10.1.2.3".parse().unwrap()));
        assert!(!Cidr::parse("10.0.0.0/8")
            .unwrap()
            .contains("11.1.2.3".parse().unwrap()));
        assert!(Cidr::parse("192.168.1.5")
            .unwrap()
            .contains("192.168.1.5".parse().unwrap()));
        assert!(Cidr::parse("2001:db8::/32")
            .unwrap()
            .contains("2001:db8::1".parse().unwrap()));
        assert!(Cidr::parse("not-an-ip").is_none());
        assert!(Cidr::parse("10.0.0.0/33").is_none());
    }

    /// B1 (SEC-MEDIUM-HTTP): password hashing is CPU-heavy (the unknown-user fake bcrypt hash is
    /// cost 14, about a second). It must run off the async workers, otherwise a few concurrent
    /// bad-credential requests starve every tokio worker and the whole server stops answering.
    /// With a single worker thread and eight in-flight bad-credential requests, an unrelated timer
    /// task must still be serviced promptly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn bad_credentials_do_not_starve_the_async_workers() {
        let handler = std::sync::Arc::new(basic_auth_handler(serde_json::json!({
            "handler": "basic_auth",
            "hash": {"algorithm": "bcrypt"},
            "accounts": [{
                "username": "alice",
                "password": "$2a$04$XziKIb5ayw0suaNwlK.1vOqOj9gEveGnkq.anOrdVrnkN5z1bA2A."
            }]
        })));

        let started = std::time::Instant::now();
        let mut attackers = Vec::new();
        for index in 0..8 {
            let handler = std::sync::Arc::clone(&handler);
            attackers.push(tokio::spawn(async move {
                let mut request = base_request();
                // Unknown user => the cost-14 fake hash is verified.
                request.headers.insert(
                    header::AUTHORIZATION,
                    authorization(&format!("nobody{index}"), "x"),
                );
                handler.handle(request).await
            }));
        }
        // An unrelated task on the same runtime must still make progress while the attackers
        // are in flight (each hash takes seconds in a debug build, so a starved runtime would
        // not answer for many seconds).
        let probe = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        let probed = tokio::time::timeout(Duration::from_millis(1500), probe).await;
        let elapsed = started.elapsed();
        assert!(
            probed.is_ok() && elapsed < Duration::from_millis(1500),
            "an unrelated task was starved by password hashing on the async workers \
             (took {elapsed:?})"
        );
        probed.unwrap().expect("probe task");

        for attacker in attackers {
            let Outcome::Respond(response) = attacker.await.unwrap().unwrap() else {
                panic!("expected challenge");
            };
            assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        }
    }

    /// The concurrency limiter caps simultaneous hash computations but never rejects: callers
    /// beyond the limit wait and still get a correct answer (no divergence from Caddy's status
    /// codes, so there is no `stock_compat` switch for it).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hash_verification_limiter_caps_concurrency_without_rejecting() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let running = std::sync::Arc::new(AtomicUsize::new(0));
        let peak = std::sync::Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (limiter, running, peak) = (limiter.clone(), running.clone(), peak.clone());
            tasks.push(tokio::spawn(async move {
                run_limited(&limiter, move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(30));
                    running.fetch_sub(1, Ordering::SeqCst);
                    true
                })
                .await
            }));
        }
        for task in tasks {
            assert!(task.await.unwrap(), "waiting callers must still succeed");
        }
        assert!(peak.load(Ordering::SeqCst) <= 2, "limit exceeded");
        assert!(peak.load(Ordering::SeqCst) >= 1);
    }

    /// SEC-MEDIUM-HTTP B1 review: a dropped request future (h2 RST_STREAM, timeout) detaches the
    /// blocking job but must NOT free its permit, otherwise cancelled requests let unbounded
    /// concurrent hashes run. Permits are released only when the hash really finishes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_requests_keep_their_permit_until_the_hash_finishes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let running = std::sync::Arc::new(AtomicUsize::new(0));
        let peak = std::sync::Arc::new(AtomicUsize::new(0));
        let job = |running: std::sync::Arc<AtomicUsize>, peak: std::sync::Arc<AtomicUsize>| {
            move || {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(300));
                running.fetch_sub(1, Ordering::SeqCst);
                true
            }
        };
        let mut cancelled = Vec::new();
        for _ in 0..2 {
            let (limiter, running, peak) = (limiter.clone(), running.clone(), peak.clone());
            cancelled.push(tokio::spawn(async move {
                run_limited(&limiter, job(running, peak)).await
            }));
        }
        // Let both jobs start on the blocking pool, then cancel the request futures.
        tokio::time::sleep(Duration::from_millis(60)).await;
        for task in &cancelled {
            task.abort();
        }
        for task in cancelled {
            let _ = task.await;
        }
        // Eight more requests arrive while the two orphaned hashes are still running.
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (limiter, running, peak) = (limiter.clone(), running.clone(), peak.clone());
            tasks.push(tokio::spawn(async move {
                run_limited(&limiter, job(running, peak)).await
            }));
        }
        for task in tasks {
            assert!(task.await.unwrap());
        }
        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "in-flight hashes exceeded the limit after cancellation: {}",
            peak.load(Ordering::SeqCst)
        );
    }

    fn cached_handler(
        stock_compat: bool,
        limiter: &Arc<tokio::sync::Semaphore>,
    ) -> BasicAuthHandler {
        let value = serde_json::json!({
            "handler": "basic_auth",
            "hash": {"algorithm": "bcrypt"},
            "accounts": [{"username": "alice", "password": bcrypt::hash("pw", 4).unwrap()}]
        });
        BasicAuthHandler::from_json_with_stock_compat(&value, "handler", stock_compat)
            .expect("config")
            .with_hash_limits(Arc::clone(limiter), Duration::from_millis(150))
    }

    async fn attempt(handler: &BasicAuthHandler, user: &str, password: &str) -> Outcome {
        let mut request = base_request();
        request
            .headers
            .insert(header::AUTHORIZATION, authorization(user, password));
        handler.handle(request).await.unwrap()
    }

    fn status_of(outcome: &Outcome) -> Option<StatusCode> {
        match outcome {
            Outcome::Respond(response) => Some(response.status),
            _ => None,
        }
    }

    /// B1 review: like Caddy's `hash_cache`, a repeated credential pair (success or failure) is
    /// answered from the cache without computing a hash, so legitimate clients are unaffected by a
    /// saturated hash pool. Proven by exhausting the pool: cached pairs still answer, uncached
    /// pairs time out with 503.
    #[tokio::test]
    async fn hash_cache_answers_repeat_credentials_while_the_pool_is_exhausted() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let handler = cached_handler(false, &limiter);
        assert!(matches!(
            attempt(&handler, "alice", "pw").await,
            Outcome::Continue(_)
        ));
        assert_eq!(
            status_of(&attempt(&handler, "alice", "wrong").await),
            Some(StatusCode::UNAUTHORIZED)
        );

        let _held = Arc::clone(&limiter).acquire_owned().await.unwrap();
        assert!(
            matches!(attempt(&handler, "alice", "pw").await, Outcome::Continue(_)),
            "a cached success must not need a hash permit"
        );
        assert_eq!(
            status_of(&attempt(&handler, "alice", "wrong").await),
            Some(StatusCode::UNAUTHORIZED),
            "a cached failure must not need a hash permit"
        );
        assert_eq!(
            status_of(&attempt(&handler, "alice", "never-seen").await),
            Some(StatusCode::SERVICE_UNAVAILABLE),
            "an uncached pair needs a permit and must not queue forever"
        );
    }

    /// B1 round 2: the cache must not turn into a user-existence oracle. A verdict for an unknown
    /// username (fake hash) is never cached, so probing `(candidate, P)` after `(nonexistent, P)`
    /// costs the same hash path for unknown and real accounts. Proven with the pool exhausted:
    /// both must need a permit (503), neither may be answered instantly from the cache.
    #[tokio::test]
    async fn unknown_user_probes_cost_the_same_hash_path_as_real_accounts() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let handler = cached_handler(false, &limiter);
        // Warm: the unknown-user pair is computed once.
        assert_eq!(
            status_of(&attempt(&handler, "zz-nonexistent", "P").await),
            Some(StatusCode::UNAUTHORIZED)
        );
        let _held = Arc::clone(&limiter).acquire_owned().await.unwrap();
        for user in ["zz-nonexistent", "alice"] {
            assert_eq!(
                status_of(&attempt(&handler, user, "P").await),
                Some(StatusCode::SERVICE_UNAVAILABLE),
                "{user} must need a hash permit on every attempt (no cached verdict)"
            );
        }
    }

    /// Secure default: waiting for a hash permit is capped; the overload answer is 503 with
    /// `Retry-After`, not an unbounded queue.
    #[tokio::test]
    async fn queue_wait_is_capped_with_503_and_retry_after_by_default() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let handler = cached_handler(false, &limiter);
        let _held = Arc::clone(&limiter).acquire_owned().await.unwrap();
        let Outcome::Respond(response) = attempt(&handler, "alice", "pw").await else {
            panic!("expected a response");
        };
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers.contains_key(http::header::RETRY_AFTER));
    }

    /// `stock_compat: true` keeps Caddy's behaviour: wait as long as it takes, never 503.
    #[tokio::test]
    async fn stock_compat_waits_for_a_permit_without_a_cap() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let handler = cached_handler(true, &limiter);
        let held = Arc::clone(&limiter).acquire_owned().await.unwrap();
        let pending = attempt(&handler, "alice", "pw");
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(400), &mut pending)
                .await
                .is_err(),
            "stock_compat must keep waiting past the secure-default cap"
        );
        drop(held);
        assert!(matches!(pending.await, Outcome::Continue(_)));
    }

    #[test]
    fn hash_cache_keys_are_secret_keyed_and_the_cache_is_bounded() {
        let first = HashCache::new();
        let second = HashCache::new();
        assert_ne!(
            first.key(b"hash", b"pw"),
            second.key(b"hash", b"pw"),
            "keys must depend on a per-cache secret so the cache is not a password oracle"
        );
        assert_ne!(first.key(b"hash", b"pw"), first.key(b"hash", b"pw2"));
        assert_ne!(first.key(b"hash", b"pw"), first.key(b"hash2", b"pw"));
        // Unambiguous framing: moving a byte between hash and password changes the key.
        assert_ne!(first.key(b"ab", b"c"), first.key(b"a", b"bc"));
        for index in 0..(HASH_CACHE_CAPACITY * 2) {
            first.insert(first.key(b"hash", index.to_string().as_bytes()), true);
        }
        assert!(first.len() <= HASH_CACHE_CAPACITY);
    }

    #[test]
    fn hash_verification_limit_is_a_small_multiple_of_parallelism() {
        let limit = hash_verification_limit();
        assert!(limit >= 2);
        let parallelism = std::thread::available_parallelism().map_or(1, usize::from);
        assert!(limit <= parallelism.max(2) * 2);
    }

    #[tokio::test]
    async fn offloaded_verification_still_accepts_and_rejects_each_algorithm() {
        let bcrypt = std::sync::Arc::new(
            parse_password_hash(
                PasswordAlgorithm::Bcrypt,
                bcrypt::hash("pw", 4).unwrap().as_bytes(),
                "t",
            )
            .unwrap(),
        );
        let handler = basic_auth_handler(serde_json::json!({"handler": "basic_auth"}));
        let accept = handler
            .verify_offloaded(Some("u"), bcrypt.clone(), b"pw".to_vec())
            .await;
        assert_eq!(accept, Some(true));
        let reject = handler
            .verify_offloaded(Some("u"), bcrypt, b"nope".to_vec())
            .await;
        assert_eq!(reject, Some(false));

        let plain = std::sync::Arc::new(PasswordHash::Plaintext(b"pw".to_vec()));
        let accept = handler
            .verify_offloaded(Some("u"), plain.clone(), b"pw".to_vec())
            .await;
        assert_eq!(accept, Some(true));
        let reject = handler
            .verify_offloaded(Some("u"), plain, b"px".to_vec())
            .await;
        assert_eq!(reject, Some(false));
    }
}

/// SEC-MEDIUM D4 residual: password material must not appear in `{:?}`.
#[cfg(test)]
mod debug_redaction {
    use super::*;

    #[test]
    fn password_hash_debug_hides_plaintext_hashes_and_keys() {
        let argon = PasswordHash::Argon2id(Argon2idHash {
            salt: vec![251, 252],
            key: vec![253, 254],
            params: Params::new(8192, 2, 1, Some(32)).unwrap(),
        });
        let cases = [
            (
                PasswordHash::Plaintext(b"hunter2-secret".to_vec()),
                "hunter2",
            ),
            (
                PasswordHash::Bcrypt("$2y$10$BCRYPTSECRETHASH".to_string()),
                "BCRYPTSECRET",
            ),
            (argon, "253"),
        ];
        for (hash, secret) in cases {
            for text in [format!("{hash:?}"), format!("{hash:#?}")] {
                assert!(!text.contains(secret), "{text}");
            }
        }
    }
}
