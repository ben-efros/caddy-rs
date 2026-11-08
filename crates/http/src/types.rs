//! Request/response types and the handler/matcher traits.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use thiserror::Error;

use crate::body::{BodyError, RequestBody, StreamingResponse};
use crate::upgrade::UpgradedResponse;

/// Per-request access-log carrier shared with the server and the handler pipeline.
///
/// Re-exported from `caddy-rs-admin`, which owns the Caddy-compatible access-entry model; handlers
/// only need the request-scoped context.
pub use caddy_rs_admin::access_log::{AccessLogContext, AccessLogUpstream, BodyBytes};

/// Errors raised while building or executing handlers.
#[derive(Debug, Error)]
pub enum Error {
    /// A handler or matcher that this build recognises but cannot execute yet.
    #[error("not implemented: {feature} ({tracking_id})")]
    NotImplemented {
        /// Capability.
        feature: &'static str,
        /// Plan task tracking the gap.
        tracking_id: &'static str,
    },

    /// A handler's JSON configuration is malformed.
    #[error("invalid handler configuration at `{path}`: {message}")]
    InvalidConfig {
        /// JSON path.
        path: String,
        /// Diagnosis.
        message: String,
    },

    /// A handler failed the request with a recommended HTTP status (Caddy's `HandlerError`).
    ///
    /// The error routes configured on the server (`apps.http.servers.*.errors.routes`) see the
    /// status, status text and message through the `{http.error.*}` placeholders; without error
    /// routes the server answers with this status.
    #[error("handler error (status {status}): {message}")]
    Handler {
        /// Recommended HTTP status.
        status: StatusCode,
        /// Error message (empty when the handler produced none).
        message: String,
    },

    /// I/O failure while serving a request.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failure while consuming a streaming response body (buffered compatibility path).
    #[error(transparent)]
    Body(#[from] BodyError),

    /// An upgraded (101 + tunnel) response reached a router path that cannot carry a tunnel.
    ///
    /// The buffered and streaming-only APIs cannot represent a raw connection; callers that need
    /// HTTP Upgrade support must use `Router::handle_upgradable`.
    #[error("upgraded response cannot be represented on `{context}`")]
    UpgradeNotRepresentable {
        /// Router API that received the upgraded response.
        context: &'static str,
    },
}

impl Error {
    /// Build a handler error carrying Caddy's recommended HTTP status.
    pub fn handler(status: StatusCode, message: impl Into<String>) -> Self {
        Self::Handler {
            status,
            message: message.into(),
        }
    }

    /// The recommended HTTP status for a handler error (Caddy's `HandlerError.StatusCode`).
    ///
    /// Non-handler errors have no status; the server maps them to 500 like Caddy does for plain
    /// Go errors.
    pub fn handler_status(&self) -> Option<StatusCode> {
        match self {
            Self::Handler { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The error message used for `{http.error.message}`.
    pub fn handler_message(&self) -> String {
        match self {
            Self::Handler { message, .. } => message.clone(),
            other => other.to_string(),
        }
    }
}

/// Result alias for the HTTP crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A matcher-recorded error that short-circuits route evaluation (Caddy's `MatcherErrorVarKey`).
///
/// Caddy matchers can set an error variable while returning "no match"; the route list then
/// aborts evaluation and responds with the error status. The `file` matcher uses this for its
/// `=NNN` `first_exist` fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherError {
    /// HTTP status to respond with.
    pub status: StatusCode,
    /// Diagnostic message (not sent to the client).
    pub message: String,
}

/// Client-certificate metadata exposed through Caddy's `{http.request.tls.client.*}`
/// placeholders (Caddy v2.11.9 `modules/caddyhttp/replacer.go` client-cert branch).
///
/// Populated by the server from the TLS handshake; `verified` records whether the listener's
/// client-auth mode verified the chain (`require_and_verify`/`verify_if_given`) or merely
/// required a certificate (`require`/`request`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificate {
    /// Subject distinguished name (Go `x509.Name.String()` style).
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number in decimal.
    pub serial: String,
    /// SHA-256 fingerprint of the DER certificate, lowercase hex.
    pub fingerprint: String,
    /// DER-encoded SubjectPublicKeyInfo.
    pub public_key_der: Vec<u8>,
    /// SHA-256 of `public_key_der`, lowercase hex.
    pub public_key_sha256: String,
    /// PEM-encoded leaf certificate.
    pub certificate_pem: String,
    /// Base64 DER leaf certificate.
    pub certificate_der_base64: String,
    /// SAN DNS names.
    pub dns_names: Vec<String>,
    /// SAN email addresses.
    pub emails: Vec<String>,
    /// SAN IP addresses.
    pub ips: Vec<String>,
    /// SAN URIs.
    pub uris: Vec<String>,
    /// Whether the client certificate chain was verified by the listener.
    pub verified: bool,
}

/// TLS protocol version for a terminated connection.
///
/// This mirrors Go's `tls.VersionTLS*` constants (and Caddy's `r.TLS.Version`) in a TLS-neutral
/// way so the HTTP crate does not depend on a TLS implementation. The server maps rustls's
/// negotiated protocol version to this value; requests built without a transport leave it absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.0 (`tls.VersionTLS10`).
    Tls10,
    /// TLS 1.1 (`tls.VersionTLS11`).
    Tls11,
    /// TLS 1.2 (`tls.VersionTLS12`).
    Tls12,
    /// TLS 1.3 (`tls.VersionTLS13`).
    Tls13,
}

impl TlsVersion {
    /// Map an IANA/Go `tls.Version*` numeric value to a version.
    pub fn from_iana(value: u16) -> Option<Self> {
        match value {
            0x0301 => Some(Self::Tls10),
            0x0302 => Some(Self::Tls11),
            0x0303 => Some(Self::Tls12),
            0x0304 => Some(Self::Tls13),
            _ => None,
        }
    }

    /// Caddy's `tlsProtocolStrings` value (used by FastCGI `SSL_PROTOCOL`).
    pub fn caddy_name(self) -> &'static str {
        match self {
            Self::Tls10 => "TLSv1",
            Self::Tls11 => "TLSv1.1",
            Self::Tls12 => "TLSv1.2",
            Self::Tls13 => "TLSv1.3",
        }
    }

    /// Numeric IANA/Go value (`tls.VersionTLS*`).
    pub fn iana_id(self) -> u16 {
        match self {
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
        }
    }
}

/// Map an IANA cipher-suite id to Go's `tls.CipherSuite.Name`.
///
/// Caddy's FastCGI environment uses `caddytls.SupportedCipherSuites()` (`tls.CipherSuites()`)
/// names, which are Go's IANA names. Only suites usable by this build's rustls `ring` provider are
/// mapped; `None` means the id is unknown (the FastCGI `SSL_CIPHER` variable is then omitted, like
/// Caddy's lookup loop does).
pub fn cipher_suite_name(id: u16) -> Option<&'static str> {
    match id {
        0xC02B => Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        0xC02C => Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        0xC02F => Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        0xC030 => Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        0xCCA8 => Some("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        0xCCA9 => Some("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        0x1301 => Some("TLS_AES_128_GCM_SHA256"),
        0x1302 => Some("TLS_AES_256_GCM_SHA384"),
        0x1303 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        _ => None,
    }
}

/// Negotiated TLS session metadata for a request (Caddy's `r.TLS` protocol/cipher fields).
///
/// The server populates this from the TLS listener's handshake; non-TLS requests leave
/// [`Request::tls_connection`] absent. The cipher-suite name matches Go/IANA naming when known
/// (see [`cipher_suite_name`]); HTTP/3 currently carries the version without a cipher because
/// quinn does not expose the negotiated suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConnection {
    /// Negotiated protocol version.
    pub version: TlsVersion,
    /// Negotiated cipher suite name in Go/IANA form, when known.
    pub cipher_suite: Option<String>,
}

impl TlsConnection {
    /// Build from IANA/Go numeric values (`0` means "not exposed", e.g. the HTTP/3 cipher id).
    pub fn from_iana(version: u16, cipher_suite: u16) -> Option<Self> {
        let version = TlsVersion::from_iana(version)?;
        let cipher_suite = (cipher_suite != 0)
            .then(|| cipher_suite_name(cipher_suite))
            .flatten()
            .map(str::to_string);
        Some(Self {
            version,
            cipher_suite,
        })
    }
}

/// An internal HTTP request, decoupled from hyper so handlers are testable without sockets.
#[derive(Debug)]
pub struct Request {
    /// Request method.
    pub method: Method,
    /// Request URI.
    pub uri: Uri,
    /// Request headers.
    pub headers: HeaderMap,
    /// Buffered request body.
    ///
    /// This is the compatibility accessor used by handlers and tests that need the complete body.
    /// It is empty when the body is streamed (see [`Request::has_streaming_body`]) or after
    /// [`Request::take_body`]/[`Request::collect_body`] consumed the stream.
    pub body: Bytes,
    /// Streaming request body source, when the server did not buffer it.
    ///
    /// Stored behind a `Mutex` so `Request` stays `Sync` (async handler futures hold `&Request`
    /// across awaits). The body is single-owner and taken out through [`Request::take_body`].
    /// Cloned requests do not carry the streaming body; clones are only used for response-side
    /// bookkeeping.
    body_stream: Option<std::sync::Mutex<RequestBody>>,
    /// Byte limit set by `request_body` for buffered bodies, enforced by the router before a
    /// body-consuming handler runs (streaming bodies carry the limit inside [`RequestBody`]).
    body_limit: Option<u64>,
    /// Error recorded by a matcher during route evaluation (`file` matcher `=NNN` fallback).
    matcher_error: Option<MatcherError>,
    /// Peer address, when known.
    pub remote_addr: Option<SocketAddr>,
    /// Textual peer address override for transports without a `SocketAddr` (for example a PROXY
    /// protocol v2 `AF_UNIX` source), used by the `{http.request.remote.*}` placeholders.
    pub remote_addr_text: Option<String>,
    /// Whether the connection is TLS.
    pub tls: bool,
    /// Negotiated TLS protocol version and cipher suite, when the connection terminated TLS.
    pub tls_connection: Option<TlsConnection>,
    /// Presented client certificate, when the TLS listener requested one (Caddy's
    /// `r.TLS.PeerCertificates[0]`). `None` when no certificate was presented or TLS is off.
    pub client_certificate: Option<ClientCertificate>,
    /// The request's effective HTTP version, propagated by the server from the hyper connection.
    ///
    /// This is what the `protocol` matcher keys off (Caddy's `r.Proto`): HTTP/1.1 for plain
    /// cleartext, HTTP/2 for TLS/ALPN h2, prior-knowledge h2c, and h2c-upgraded requests alike.
    /// Requests built without a transport default to HTTP/1.1 (the cleartext assumption).
    pub version: Version,
    /// Per-request variables (Caddy `vars` handler).
    pub vars: BTreeMap<String, String>,
    /// Response headers staged by response middleware (`headers` handler).
    pub pending_response_headers: HeaderMap,
    /// Response transforms registered by middleware handlers (`encode`).
    ///
    /// Shared across request clones so a transform registered before a nested subroute is applied
    /// exactly once: the router drains the stack at the point a handler produces the response.
    response_transforms: Arc<std::sync::Mutex<ResponseTransformList>>,
    /// Per-request access-log context (Caddy's request-scoped `ExtraLogFields` + observed values).
    ///
    /// The server creates it when access logging is enabled; authentication handlers publish the
    /// authenticated user id and `reverse_proxy` publishes the upstream attempt into it. The server
    /// applies it to the emitted entry after the response body completes. `None` when access
    /// logging is disabled, so the common path pays nothing.
    access_log: Option<Arc<AccessLogContext>>,
}

/// Registered response transforms; `Debug` prints only the count (the trait objects are not
/// `Debug`).
#[derive(Default)]
struct ResponseTransformList(Vec<Arc<dyn ResponseTransform>>);

impl std::fmt::Debug for ResponseTransformList {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ResponseTransformList")
            .field(&self.0.len())
            .finish()
    }
}

impl Request {
    /// Build a request with defaults, for tests and the server adapter.
    pub fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            body_stream: None,
            body_limit: None,
            matcher_error: None,
            remote_addr: None,
            remote_addr_text: None,
            tls: false,
            tls_connection: None,
            client_certificate: None,
            version: Version::HTTP_11,
            vars: BTreeMap::new(),
            pending_response_headers: HeaderMap::new(),
            response_transforms: Arc::new(std::sync::Mutex::new(ResponseTransformList::default())),
            access_log: None,
        }
    }

    /// Attach a streaming request body (server adapter; buffered bodies should use
    /// [`Request::body`] directly).
    pub fn with_streaming_body(mut self, body: RequestBody) -> Self {
        self.body_stream = Some(std::sync::Mutex::new(body));
        self.body = Bytes::new();
        self
    }

    /// Attach the per-request access-log context (server adapter).
    ///
    /// The server creates one context per request when access logging is enabled; handlers publish
    /// observations into it and the server applies it to the emitted entry once the response body
    /// has completed.
    pub fn with_access_log(mut self, context: Arc<AccessLogContext>) -> Self {
        self.access_log = Some(context);
        self
    }

    /// The per-request access-log context, when access logging is enabled.
    pub fn access_log(&self) -> Option<&Arc<AccessLogContext>> {
        self.access_log.as_ref()
    }

    /// Publish the authenticated user id into the access-log context (Caddy's `user_id`).
    ///
    /// Authentication handlers call this after a successful credential check; it is a no-op when
    /// access logging is disabled. Caddy's entry always carries `user_id` (empty for anonymous
    /// requests), so only the observed value is published here.
    pub fn record_access_log_user_id(&self, user_id: impl Into<String>) {
        if let Some(context) = &self.access_log {
            context.set_user_id(user_id);
        }
    }

    /// Publish the proxy upstream attempt into the access-log context (caddy-rs `upstream`).
    ///
    /// `reverse_proxy` calls this for every attempt that received an upstream response; it is a
    /// no-op when access logging is disabled.
    pub fn record_access_log_upstream(&self, upstream: AccessLogUpstream) {
        if let Some(context) = &self.access_log {
            context.set_upstream(upstream);
        }
    }

    /// Request-body byte counter when the server is counting it (access logging enabled).
    ///
    /// The server attaches this handle to streamed request bodies so [`RequestBody`] reads feed
    /// Caddy's actual `bytes_read`; buffered bodies are counted by the server directly.
    pub fn access_log_request_bytes(&self) -> Option<BodyBytes> {
        self.access_log
            .as_ref()
            .map(|context| context.request_bytes())
    }

    /// Whether the request body is streamed rather than buffered.
    pub fn has_streaming_body(&self) -> bool {
        self.body_stream.is_some()
    }

    /// Replace the request body with already-buffered bytes, dropping any streaming source.
    ///
    /// Used by middleware that synthesises a body (the `request_body` handler's `set` field). The
    /// caller is responsible for keeping framing headers (`Content-Length`) in sync.
    pub fn set_body_bytes(&mut self, body: impl Into<Bytes>) {
        self.body = body.into();
        self.body_stream = None;
    }

    /// Apply a byte limit to the request body for later consumers.
    ///
    /// Streaming bodies carry the limit inside [`RequestBody`], so reading past it fails lazily
    /// with [`BodyError::TooLarge`]. Buffered bodies are already fully read into [`Request::body`];
    /// the limit is recorded in [`Request::body_limit`] and the router turns it into a `413`
    /// before the next body-consuming handler runs (matching Caddy, where a handler that never
    /// reads the body does not trigger the limit error).
    pub fn limit_body(&mut self, limit: u64) {
        self.body_limit = Some(limit);
        if let Some(body) = self.body_stream.take() {
            let body = body
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .with_limit(Some(limit));
            self.body_stream = Some(std::sync::Mutex::new(body));
        }
    }

    /// The byte limit set by `request_body` for the request body, if any.
    ///
    /// The router enforces it for buffered bodies before dispatching to a body-consuming handler;
    /// streaming bodies enforce it lazily while being read.
    pub fn body_limit(&self) -> Option<u64> {
        self.body_limit
    }

    /// Record a matcher error that the router must turn into an HTTP response (Caddy's
    /// `MatcherErrorVarKey`).
    pub fn set_matcher_error(&mut self, status: StatusCode, message: impl Into<String>) {
        self.matcher_error = Some(MatcherError {
            status,
            message: message.into(),
        });
    }

    /// Take the matcher error, if one was recorded during this evaluation.
    pub fn take_matcher_error(&mut self) -> Option<MatcherError> {
        self.matcher_error.take()
    }

    /// Take the request body for explicit consumption (buffered bodies are moved out too).
    ///
    /// This is the streaming handler API: a handler that consumes the body calls this once and
    /// then reads frames with [`RequestBody::next_frame`] or collects with
    /// [`RequestBody::collect`]. Handlers that only need the buffered bytes can keep reading
    /// [`Request::body`].
    pub fn take_body(&mut self) -> RequestBody {
        match self.body_stream.take() {
            Some(body) => body
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            None => RequestBody::buffered(std::mem::take(&mut self.body)),
        }
    }

    /// Collect the request body into bytes (streaming produces no request-size changes beyond the
    /// limit check) and also store it in [`Request::body`] for later compatibility access.
    ///
    /// This is the replacement for handlers that previously assumed `request.body` was always
    /// populated when the server started streaming bodies.
    pub async fn collect_body(
        &mut self,
        limit: Option<u64>,
    ) -> std::result::Result<Bytes, BodyError> {
        if let Some(stream) = self.body_stream.take() {
            let stream = stream
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let bytes = stream.collect(limit).await?;
            self.body = bytes.clone();
            Ok(bytes)
        } else if let Some(limit) = limit {
            if self.body.len() as u64 > limit {
                return Err(BodyError::TooLarge { limit });
            }
            Ok(self.body.clone())
        } else {
            Ok(self.body.clone())
        }
    }

    /// Request body size when known: buffered length, or a stream's exact size hint.
    pub fn body_size_hint(&self) -> Option<u64> {
        match &self.body_stream {
            Some(body) => body
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .exact_size(),
            None => Some(self.body.len() as u64),
        }
    }

    /// Request path (no query string).
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    /// Request host: the `Host` header, else the URI authority.
    pub fn host(&self) -> Option<&str> {
        if let Some(host) = self.headers.get(http::header::HOST) {
            return host.to_str().ok();
        }
        self.uri.authority().map(|authority| authority.as_str())
    }

    /// Host without port, lowercased.
    pub fn host_without_port(&self) -> Option<String> {
        let host = self.host()?;
        let host = if let Some(rest) = host.strip_prefix('[') {
            rest.split(']').next().unwrap_or(rest)
        } else {
            host.rsplit_once(':').map(|(host, _)| host).unwrap_or(host)
        };
        Some(host.to_ascii_lowercase())
    }

    /// Query string without `?`.
    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    /// A request-scoped placeholder replacer (T-ROUTE-030).
    ///
    /// This is the public expansion API for handlers and, later, the proxy / access-log layers.
    /// Use [`crate::placeholders::Replacer::with_response_headers`] when the response headers are
    /// also in scope (for `{http.response.header.*}`).
    pub fn placeholders(&self) -> crate::placeholders::Replacer<'_> {
        crate::placeholders::Replacer::new(self)
    }

    /// Register a response transform applied when a handler produces the response (Caddy's
    /// middleware wrapping model).
    pub fn push_response_transform(&mut self, transform: Arc<dyn ResponseTransform>) {
        self.response_transforms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0
            .push(transform);
    }

    /// Drain the registered response transforms (the router applies them in reverse order).
    pub(crate) fn take_response_transforms(&self) -> Vec<Arc<dyn ResponseTransform>> {
        std::mem::take(
            &mut self
                .response_transforms
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0,
        )
    }

    /// Discard registered transforms (used when the handler chain errors, matching Caddy's
    /// "disable encoding completely" behaviour for error responses).
    pub(crate) fn clear_response_transforms(&self) {
        self.response_transforms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0
            .clear();
    }

    /// Expand placeholders with Caddy's `ReplaceKnown` semantics: unknown placeholders are left
    /// verbatim, known-but-empty ones expand to nothing.
    pub fn replace_known(&self, input: &str) -> String {
        self.placeholders().replace_known(input)
    }

    /// Expand placeholders with Caddy's `ReplaceAll` semantics: unknown placeholders expand to
    /// nothing.
    pub fn replace_all(&self, input: &str) -> String {
        self.placeholders().replace_all(input)
    }

    /// Look up one placeholder by name; `None` means the name is not in the supported subset.
    pub fn get_placeholder(&self, name: &str) -> Option<String> {
        self.placeholders().get(name)
    }
}

/// An internal HTTP response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// Status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body.
    pub body: Bytes,
}

impl Response {
    /// Empty 200 response.
    pub fn ok() -> Self {
        Self {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    /// Response with a status and text body.
    pub fn text(status: StatusCode, body: impl Into<Bytes>) -> Self {
        let body = body.into();
        let mut response = Self {
            status,
            headers: HeaderMap::new(),
            body,
        };
        response.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response
    }

    /// Response with a body and a caller-supplied content type.
    pub fn bytes(status: StatusCode, content_type: &'static str, body: impl Into<Bytes>) -> Self {
        let mut response = Self {
            status,
            headers: HeaderMap::new(),
            body: body.into(),
        };
        response.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(content_type),
        );
        response
    }

    /// A 404 response in Caddy's plain style.
    pub fn not_found() -> Self {
        Self::text(StatusCode::NOT_FOUND, "404 Not Found")
    }

    /// Attach a header if it can be represented.
    pub fn with_header(mut self, name: http::header::HeaderName, value: http::HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }
}

impl Clone for Request {
    fn clone(&self) -> Self {
        // Streaming bodies are single-owner and cannot be cloned; clones are used for response
        // bookkeeping (for example staged response headers), which never needs the request body.
        Self {
            method: self.method.clone(),
            uri: self.uri.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
            body_stream: None,
            body_limit: self.body_limit,
            matcher_error: self.matcher_error.clone(),
            remote_addr: self.remote_addr,
            remote_addr_text: self.remote_addr_text.clone(),
            tls: self.tls,
            tls_connection: self.tls_connection.clone(),
            client_certificate: self.client_certificate.clone(),
            version: self.version,
            vars: self.vars.clone(),
            pending_response_headers: self.pending_response_headers.clone(),
            response_transforms: Arc::clone(&self.response_transforms),
            access_log: self.access_log.clone(),
        }
    }
}

/// What a handler does with a request.
#[derive(Debug)]
pub enum Outcome {
    /// Continue to the next handler with the (possibly modified) request.
    Continue(Request),
    /// Write this response and stop the chain.
    Respond(Response),
}

/// What a streaming-capable handler does with a request.
///
/// The `Continue` variant is large because it carries the whole request; boxing it would add an
/// allocation on every request, so the same trade-off as [`Outcome`] is kept.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum StreamingOutcome {
    /// Continue to the next handler with the (possibly modified) request.
    Continue(Request),
    /// Write this (possibly streaming) response and stop the chain.
    Respond(StreamingResponse),
    /// Switch protocols (HTTP/1.1 `101 Switching Protocols`) and hand the tunnel to the server.
    ///
    /// Only the upgrade-aware router path (`Router::handle_upgradable`) can carry this outcome;
    /// the buffered/streaming-only paths return [`Error::UpgradeNotRepresentable`].
    Upgrade(UpgradedResponse),
}

/// The result of an upgrade-aware router evaluation: a normal response or a protocol switch.
#[derive(Debug)]
pub enum ResponseOutcome {
    /// A normal (possibly streaming) response.
    Response(StreamingResponse),
    /// A protocol switch carrying the upgraded upstream tunnel.
    Upgrade(UpgradedResponse),
}

/// An HTTP handler.
#[async_trait]
pub trait Handler: Send + Sync {
    /// Stable module key for logs and tests.
    fn name(&self) -> &'static str;

    /// Process a request with the buffered compatibility API.
    async fn handle(&self, request: Request) -> Result<Outcome>;

    /// Whether this handler requires the complete request body before dispatch.
    ///
    /// The server buffers `hyper::body::Incoming` for routers that contain such a handler. Handlers
    /// that can consume a streamed request body (streaming `reverse_proxy`) return `false`; the
    /// router composes this capability over every built handler, including nested subroutes, so
    /// custom handlers supplied through [`crate::CustomHandlerFactory`] are honoured too.
    fn requires_buffered_request_body(&self) -> bool {
        false
    }

    /// Whether this handler reads the request body at all, even if it can consume a streamed body
    /// without needing it pre-buffered (for example streaming `reverse_proxy`).
    ///
    /// The router uses this to enforce a `request_body` limit before dispatching to a
    /// body-consuming handler, because that handler is the one that would observe Caddy's lazy
    /// `413`. The default mirrors [`Handler::requires_buffered_request_body`]: a handler that
    /// needs the complete body up front clearly consumes it.
    fn consumes_request_body(&self) -> bool {
        self.requires_buffered_request_body()
    }

    /// Process a request on the streaming path.
    ///
    /// The default implementation delegates to [`Handler::handle`] and wraps a buffered response,
    /// so existing handlers keep working unchanged. Handlers that can stream (for example
    /// `reverse_proxy`) override this method; see [`crate::body`] for the server integration
    /// contract.
    async fn handle_streaming(&self, request: Request) -> Result<StreamingOutcome> {
        Ok(match self.handle(request).await? {
            Outcome::Continue(request) => StreamingOutcome::Continue(request),
            Outcome::Respond(response) => {
                StreamingOutcome::Respond(StreamingResponse::from_buffered(response))
            }
        })
    }
}

/// A response transform registered by a middleware handler (for example `encode`).
///
/// Caddy middleware wraps the response writer and mutates the response while it flows back up the
/// handler chain. caddy-rs handlers return owned [`Outcome`]s, so middleware registers a transform
/// on the [`Request`] instead; the router applies registered transforms (in reverse registration
/// order, i.e. closest-to-the-response first) when a handler produces the response.
#[async_trait]
pub trait ResponseTransform: Send + Sync {
    /// Transform a response before it leaves the router.
    async fn transform(
        &self,
        response: crate::body::StreamingResponse,
    ) -> crate::body::StreamingResponse;
}

/// A request matcher.
pub trait Matcher: Send + Sync {
    /// Whether the request matches.
    fn matches(&self, request: &Request) -> bool;

    /// Whether the request matches, applying matcher side effects (placeholders) on success.
    ///
    /// The default delegates to [`Matcher::matches`]. Matchers that publish Caddy placeholders —
    /// today `http.matchers.file`, which sets `{http.matchers.file.relative}` and friends — override
    /// this to record them in [`Request::vars`] when they match.
    fn matches_mut(&self, request: &mut Request) -> bool {
        self.matches(request)
    }

    /// Human-readable description for logs.
    fn describe(&self) -> String;
}

/// Convenience alias for a shared handler.
pub type SharedHandler = Arc<dyn Handler>;

/// Convenience alias for a shared matcher.
pub type SharedMatcher = Arc<dyn Matcher>;

#[cfg(test)]
mod request_body_tests {
    use super::*;
    use crate::body::StreamingBody;
    use tokio::sync::mpsc;

    fn request_with_streaming_body(
        receiver: mpsc::Receiver<std::result::Result<Bytes, BodyError>>,
    ) -> Request {
        let mut request = Request::new(Method::POST, "/upload".parse().unwrap());
        request = request
            .with_streaming_body(RequestBody::streaming(StreamingBody::from_chunks(receiver)));
        assert!(request.has_streaming_body());
        assert!(request.body.is_empty());
        request
    }

    #[tokio::test]
    async fn collect_body_buffers_a_stream_for_compatibility_handlers() {
        let (sender, receiver) = mpsc::channel(4);
        let mut request = request_with_streaming_body(receiver);
        sender.send(Ok(Bytes::from_static(b"abc"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"defg"))).await.unwrap();
        drop(sender);

        let body = request.collect_body(None).await.expect("collect body");
        assert_eq!(body, Bytes::from_static(b"abcdefg"));
        assert_eq!(request.body, Bytes::from_static(b"abcdefg"));
        assert!(!request.has_streaming_body());
        // A second collect returns the buffered bytes without replaying the stream.
        assert_eq!(
            request.collect_body(None).await.expect("collect again"),
            Bytes::from_static(b"abcdefg")
        );
    }

    #[tokio::test]
    async fn collect_body_enforces_the_limit_while_streaming() {
        let (sender, receiver) = mpsc::channel(4);
        let mut request = request_with_streaming_body(receiver);
        sender.send(Ok(Bytes::from_static(b"1234"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"56"))).await.unwrap();
        drop(sender);
        let error = request.collect_body(Some(5)).await.expect_err("too large");
        assert!(matches!(error, BodyError::TooLarge { limit: 5 }), "{error}");
    }

    #[tokio::test]
    async fn take_body_returns_buffered_bytes_or_the_stream() {
        // Buffered request: take_body moves the bytes out and leaves the compatibility field empty.
        let mut buffered = Request::new(Method::POST, "/".parse().unwrap());
        buffered.body = Bytes::from_static(b"buffered");
        let body = buffered.take_body();
        assert_eq!(
            body.collect(None).await.expect("collect"),
            Bytes::from_static(b"buffered")
        );
        assert!(buffered.body.is_empty());

        // Streaming request: take_body hands over the stream.
        let (sender, receiver) = mpsc::channel(4);
        let mut streamed = request_with_streaming_body(receiver);
        sender.send(Ok(Bytes::from_static(b"wire"))).await.unwrap();
        drop(sender);
        let body = streamed.take_body();
        assert_eq!(
            body.collect(None).await.expect("collect"),
            Bytes::from_static(b"wire")
        );
        assert!(!streamed.has_streaming_body());
    }
}
