//! Request/response types and the handler/matcher traits.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use thiserror::Error;

use crate::body::{BodyError, StreamingResponse};
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
#[derive(Debug, Clone)]
pub struct Request {
    /// Request method.
    pub method: Method,
    /// Request URI.
    pub uri: Uri,
    /// Request headers.
    pub headers: HeaderMap,
    /// Request body.
    pub body: Bytes,
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
            remote_addr: None,
            tls: false,
            vars: BTreeMap::new(),
            pending_response_headers: HeaderMap::new(),
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

    /// Human-readable description for logs.
    fn describe(&self) -> String;
}

/// Convenience alias for a shared handler.
pub type SharedHandler = Arc<dyn Handler>;

/// Convenience alias for a shared matcher.
pub type SharedMatcher = Arc<dyn Matcher>;
