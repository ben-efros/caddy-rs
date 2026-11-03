//! Request/response types and the handler/matcher traits.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use thiserror::Error;

use crate::body::{BodyError, RequestBody, StreamingResponse};
use crate::upgrade::UpgradedResponse;

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

/// Result alias for the HTTP crate.
pub type Result<T> = std::result::Result<T, Error>;

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
    /// Peer address, when known.
    pub remote_addr: Option<SocketAddr>,
    /// Whether the connection is TLS.
    pub tls: bool,
    /// Per-request variables (Caddy `vars` handler).
    pub vars: BTreeMap<String, String>,
    /// Response headers staged by response middleware (`headers` handler).
    pub pending_response_headers: HeaderMap,
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
            remote_addr: None,
            tls: false,
            vars: BTreeMap::new(),
            pending_response_headers: HeaderMap::new(),
        }
    }

    /// Attach a streaming request body (server adapter; buffered bodies should use
    /// [`Request::body`] directly).
    pub fn with_streaming_body(mut self, body: RequestBody) -> Self {
        self.body_stream = Some(std::sync::Mutex::new(body));
        self.body = Bytes::new();
        self
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
            remote_addr: self.remote_addr,
            tls: self.tls,
            vars: self.vars.clone(),
            pending_response_headers: self.pending_response_headers.clone(),
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
