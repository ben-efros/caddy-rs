//! Conversion between hyper messages and the transport-agnostic HTTP engine types.
//!
//! This module also enforces the per-server request-body limit (caddy-rs hardening extension,
//! see [`crate::limits`]) and converts body-read failures into HTTP status codes.
//!
//! Response bodies are handed to hyper as [`caddy_rs_http::Body`], which can be either a buffered
//! `Bytes` value or a streamed body. The router's streaming entry point
//! ([`Router::handle_streaming`]) is used so handlers that can stream (the reverse proxy today)
//! are never buffered at the connection boundary. The legacy buffered [`Response`] is converted on
//! the spot, so every handler keeps working unchanged.
//!
//! ## Framing policy
//!
//! Hyper frames a body without `Content-Length` as chunked (HTTP/1.1) or with DATA frames
//! (HTTP/2). A stale `Content-Length` is worse than a missing one: it can truncate or hang a
//! response. The server therefore keeps an upstream `Content-Length` header only when it matches
//! [`Body::exact_size`]; otherwise it removes the header and lets hyper frame the body. A
//! mid-stream body error is propagated to hyper after the headers have been sent, which aborts the
//! downstream connection instead of attempting a 5xx that can no longer be written.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;

use caddy_rs_http::{Body, Request, Response, Router, StreamingResponse};

use crate::auto_https::AutomaticHttpsServing;
use crate::limits::ServerLimits;

/// Serve one hyper request through a router with the server's default limits.
pub async fn serve_request(
    router: Arc<Router>,
    request: hyper::Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    tls: bool,
) -> hyper::Response<Body> {
    serve_request_with_limits(&ServerLimits::default(), router, request, remote_addr, tls).await
}

/// Serve one hyper request through a router, enforcing the server's request limits.
///
/// An oversized request body produces `413 Request Entity Too Large`; nothing is forwarded to
/// the handler. The limit is configured by the caddy-rs server-level extension
/// `max_request_body_size` (see [`ServerLimits`]) and is enforced for both `Content-Length` and
/// chunked request bodies.
///
/// The response body is returned unbuffered (see the module docs); the body type is
/// [`caddy_rs_http::Body`], which hyper streams.
pub async fn serve_request_with_limits(
    limits: &ServerLimits,
    router: Arc<Router>,
    request: hyper::Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    tls: bool,
) -> hyper::Response<Body> {
    serve_request_with_limits_and_alpn(limits, router, request, remote_addr, tls, None).await
}

/// Like [`serve_request_with_limits`], also recording the negotiated TLS ALPN protocol in the
/// request context.
///
/// The internal HTTP [`Request`] carries `tls` and per-request variables; the negotiated ALPN
/// protocol is exposed to handlers as the `tls.alpn` variable (for example
/// `{http.vars.tls.alpn}`), which is how this build forwards HTTP/2-vs-HTTP/1.1 information into
/// the router. The Caddy `{http.request.tls.*}` placeholder family remains a documented gap
/// (T-ROUTE-030).
pub async fn serve_request_with_limits_and_alpn(
    limits: &ServerLimits,
    router: Arc<Router>,
    request: hyper::Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    tls: bool,
    tls_alpn: Option<&str>,
) -> hyper::Response<Body> {
    serve_request_with_automatic(limits, router, request, remote_addr, tls, tls_alpn, None).await
}

/// Like [`serve_request_with_limits_and_alpn`], with automatic-HTTPS pre-routing: ACME HTTP-01
/// challenge responses and HTTP→HTTPS redirects are handled before the router runs.
///
/// Pre-routing responses stay fully buffered (they are small static bodies) and are returned
/// before any request-body handling, preserving the automatic-HTTPS ordering.
pub(crate) async fn serve_request_with_automatic(
    limits: &ServerLimits,
    router: Arc<Router>,
    request: hyper::Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    tls: bool,
    tls_alpn: Option<&str>,
    automatic: Option<Arc<AutomaticHttpsServing>>,
) -> hyper::Response<Body> {
    if !tls {
        if let Some(automatic) = &automatic {
            if let Some(response) = automatic.pre_router_response(&request) {
                return response;
            }
        }
    }
    let (parts, body) = request.into_parts();
    let body = match read_body(body, limits.max_request_body_size).await {
        Ok(body) => body,
        Err(BodyReadError::TooLarge { limit }) => {
            tracing::debug!(
                limit,
                path = parts.uri.path(),
                "request body exceeds max_request_body_size"
            );
            return status_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "413 Request Entity Too Large",
            );
        }
        Err(BodyReadError::Read(error)) => {
            eprintln!("caddy-rs: cannot read request body: {error}");
            return status_response(StatusCode::BAD_REQUEST, "400 Bad Request");
        }
    };
    let mut internal = Request::new(parts.method, parts.uri);
    internal.headers = parts.headers;
    internal.body = body;
    internal.remote_addr = remote_addr;
    internal.tls = tls;
    if let Some(alpn) = tls_alpn {
        internal
            .vars
            .insert("tls.alpn".to_string(), alpn.to_string());
    }

    match router.handle_streaming(internal).await {
        Ok(response) => to_hyper_streaming(response),
        Err(error) => {
            eprintln!("caddy-rs: handler error: {error}");
            status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "500 Internal Server Error",
            )
        }
    }
}

/// Failure while consuming a request body.
enum BodyReadError {
    /// The configured body limit was exceeded.
    TooLarge { limit: u64 },
    /// The transport failed while reading the body.
    Read(Box<dyn std::error::Error + Send + Sync>),
}

/// Collect a request body, enforcing an optional byte limit.
async fn read_body(body: Incoming, limit: Option<u64>) -> Result<Bytes, BodyReadError> {
    match limit {
        Some(limit) => {
            // `usize::try_from(...).unwrap_or(usize::MAX)` keeps the limit meaningful on
            // platforms where `usize` is narrower than `u64`.
            let capacity = usize::try_from(limit).unwrap_or(usize::MAX);
            match Limited::new(body, capacity).collect().await {
                Ok(collected) => Ok(collected.to_bytes()),
                Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
                    Err(BodyReadError::TooLarge { limit })
                }
                Err(error) => Err(BodyReadError::Read(error)),
            }
        }
        None => match body.collect().await {
            Ok(collected) => Ok(collected.to_bytes()),
            Err(error) => Err(BodyReadError::Read(Box::new(error))),
        },
    }
}

/// Convert a fully buffered internal response to a hyper response.
pub fn to_hyper(response: Response) -> hyper::Response<Body> {
    to_hyper_streaming(StreamingResponse::from_buffered(response))
}

/// Convert an internal (possibly streaming) response to a hyper response, applying the framing
/// policy documented at the top of this module.
pub fn to_hyper_streaming(response: StreamingResponse) -> hyper::Response<Body> {
    let StreamingResponse {
        status,
        mut headers,
        body,
    } = response;

    let exact_size = body.exact_size();
    let declared = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    let keep_content_length = match (declared, exact_size) {
        (Some(declared), Some(exact)) => declared == exact,
        _ => false,
    };
    if !keep_content_length {
        // Hyper will set a correct Content-Length for exact-size bodies and use chunked
        // (HTTP/1.1) or DATA frames (HTTP/2) for the rest.
        headers.remove(http::header::CONTENT_LENGTH);
    }

    let mut builder = hyper::Response::builder().status(status);
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    builder.body(body).unwrap_or_else(|error| {
        eprintln!("caddy-rs: cannot build response: {error}");
        status_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "500 Internal Server Error",
        )
    })
}

fn status_response(status: StatusCode, body: &'static str) -> hyper::Response<Body> {
    hyper::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from_bytes(Bytes::from_static(body.as_bytes())))
        .expect("static error response is valid")
}

/// Type used for `service_fn` closures.
pub type ServiceResult = Result<hyper::Response<Body>, Infallible>;
