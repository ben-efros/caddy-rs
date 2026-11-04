//! Conversion between hyper messages and the transport-agnostic HTTP engine types.
//!
//! This module also enforces the per-server request-body limit (caddy-rs hardening extension,
//! see [`crate::limits`]) and converts body-read failures into HTTP status codes.
//!
//! ## Request-body streaming
//!
//! Request bodies are passed to the engine as `caddy_rs_http::RequestBody`, which can be buffered
//! bytes or a stream. The server streams `hyper::body::Incoming` without collecting it when:
//!
//! * the router contains no handler that needs a buffered body (`reverse_proxy` today; request
//!   streaming through the proxy is the T-PROXY-004 follow-up), and
//! * a valid `Content-Length` was declared (the load-time limit check is enough) or no
//!   `max_request_body_size` is configured.
//!
//! A chunked body with a configured limit keeps the bounded buffered path so the limit can be
//! enforced before dispatch (`413`), preserving T-HTTP-013 semantics. On the streaming path the
//! limit is enforced lazily by `RequestBody::with_limit` as the body is read, and handlers that
//! never read the body leave it unread (Caddy's lazy limit semantics).
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
use http::{Method, StatusCode, Version};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::upgrade::OnUpgrade;

use caddy_rs_http::{
    Body, Request, RequestBody, Response, ResponseOutcome, Router, StreamingBody,
    StreamingResponse, Tunnel,
};

use crate::auto_https::AutomaticHttpsServing;
use crate::limits::ServerLimits;

/// One served request at the hyper connection boundary.
///
/// Most requests produce a normal (possibly streaming) response. A protocol switch additionally
/// hands the server the upgraded upstream tunnel plus the pending client-side upgrade future; the
/// connection layer spawns the bidirectional copy and writes the 101 response.
pub(crate) enum ServedResponse {
    /// A normal (possibly streaming) response.
    Response(hyper::Response<Body>),
    /// A protocol switch: write `response`, then tunnel the client and `tunnel` together.
    Upgraded {
        /// The `101 Switching Protocols` response to write to the client.
        response: hyper::Response<Body>,
        /// The upgraded upstream connection.
        tunnel: Tunnel,
        /// The pending client-side upgrade.
        on_upgrade: OnUpgrade,
    },
}

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
/// Pre-routing responses stay fully buffered (they are small static bodies). This entry point does
/// not carry a client upgrade future; an upstream protocol switch is reported as `502` because a
/// tunnel cannot be established without the connection layer. The server listener uses
/// [`serve_request_with_automatic_upgradable`] instead.
pub(crate) async fn serve_request_with_automatic(
    limits: &ServerLimits,
    router: Arc<Router>,
    request: hyper::Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    tls: bool,
    tls_alpn: Option<&str>,
    automatic: Option<Arc<AutomaticHttpsServing>>,
) -> hyper::Response<Body> {
    match serve_request_with_automatic_upgradable(
        limits,
        router,
        request,
        remote_addr,
        None,
        tls,
        tls_alpn,
        automatic,
        None,
    )
    .await
    {
        ServedResponse::Response(response) => response,
        ServedResponse::Upgraded { .. } => {
            // `on_upgrade` is None here, so the upgradable function never returns this variant.
            status_response(
                StatusCode::BAD_GATEWAY,
                "502 Bad Gateway: protocol upgrade requires the connection layer",
            )
        }
    }
}

/// Serve one request, preserving protocol upgrades when `on_upgrade` is supplied.
///
/// `on_upgrade` must have been obtained from the request (via `hyper::upgrade::on(&mut request)`)
/// before the request is consumed. When the router returns an
/// [`ResponseOutcome::Upgrade`](caddy_rs_http::ResponseOutcome::Upgrade) and `on_upgrade` is
/// available, the caller receives [`ServedResponse::Upgraded`] and must write the response and run
/// the tunnel copy. HTTP/2 extended CONNECT (WebSocket over HTTP/2) is rejected with `501`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_request_with_automatic_upgradable(
    limits: &ServerLimits,
    router: Arc<Router>,
    request: hyper::Request<Incoming>,
    remote_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    tls: bool,
    tls_alpn: Option<&str>,
    automatic: Option<Arc<AutomaticHttpsServing>>,
    on_upgrade: Option<OnUpgrade>,
) -> ServedResponse {
    if !tls {
        if let Some(automatic) = &automatic {
            if let Some(response) = automatic.pre_router_response(&request) {
                return ServedResponse::Response(response);
            }
        }
    }
    // HTTP/2 extended CONNECT (RFC 8441) is not implemented: hyper's auto connection does not
    // expose it, so reject loudly rather than mis-serving a WebSocket-ish request as CONNECT.
    if request.version() == Version::HTTP_2 && request.method() == Method::CONNECT {
        tracing::debug!("rejecting HTTP/2 extended CONNECT: WebSocket over HTTP/2 is unsupported");
        return ServedResponse::Response(status_response(
            StatusCode::NOT_IMPLEMENTED,
            "501 Not Implemented: HTTP/2 extended CONNECT (WebSocket over HTTP/2) is unsupported",
        ));
    }
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_string();
    let limit = limits.max_request_body_size;
    // A declared body over the limit is rejected before any body bytes are read, for both the
    // buffered and streaming paths. Chunked/unknown-length streams are limited lazily as they are
    // consumed (see `RequestBody::with_limit`); handlers that never read the body leave it
    // unread, which matches Caddy's lazy request-body limit semantics.
    let declared_length = declared_content_length(&parts.headers);
    if let (Some(limit), Some(declared)) = (limit, declared_length) {
        if declared > limit {
            tracing::debug!(
                limit,
                declared,
                path = %path,
                "request body exceeds max_request_body_size"
            );
            return ServedResponse::Response(status_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "413 Request Entity Too Large",
            ));
        }
    }

    let mut internal = Request::new(parts.method, parts.uri);
    internal.headers = parts.headers;
    internal.remote_addr = remote_addr;
    internal.tls = tls;
    if let Some(local) = local_addr {
        // Caddy exposes `{http.request.local.*}`; the placeholder subset in `caddy-rs-http` does
        // not cover local addresses yet, so the server exposes them as request variables until
        // the HTTP crate adds the placeholders.
        internal
            .vars
            .insert("http.request.local".to_string(), local.to_string());
        internal.vars.insert(
            "http.request.local.host".to_string(),
            local.ip().to_string(),
        );
        internal.vars.insert(
            "http.request.local.port".to_string(),
            local.port().to_string(),
        );
    }
    // Streamed dispatch is used when:
    // * no handler in the route tree needs the buffered body (today only `reverse_proxy` does, and
    //   proxy request-body streaming is the T-PROXY-004 follow-up), and
    // * either a valid Content-Length was declared (hyper reads exactly that many bytes, so the
    //   declared-vs-limit check above is sufficient) or no body limit is configured.
    // A chunked body with a configured limit keeps the buffered path so the limit can still be
    // enforced *before* the handler runs (413 pre-dispatch, preserving T-HTTP-013 semantics);
    // buffering is bounded by the configured limit.
    let can_stream =
        !router.requires_buffered_request_body() && (declared_length.is_some() || limit.is_none());
    if !can_stream {
        // Compatibility/bounded path: handlers that consume the full body today (the reverse
        // proxy; T-PROXY-004 follow-up streams through it) and chunked bodies with a configured
        // limit are buffered, enforcing the limit while reading exactly as before.
        let body = match read_body(body, limit).await {
            Ok(body) => body,
            Err(BodyReadError::TooLarge { limit }) => {
                tracing::debug!(
                    limit,
                    path = %path,
                    "request body exceeds max_request_body_size"
                );
                return ServedResponse::Response(status_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "413 Request Entity Too Large",
                ));
            }
            Err(BodyReadError::Read(error)) => {
                eprintln!("caddy-rs: cannot read request body: {error}");
                return ServedResponse::Response(status_response(
                    StatusCode::BAD_REQUEST,
                    "400 Bad Request",
                ));
            }
        };
        internal.body = body;
    } else {
        // Streaming path: the engine receives hyper's `Incoming` as a chunk stream and the server
        // never collects it. The limit is applied lazily by `RequestBody::with_limit`, and the
        // request size is the declared Content-Length when present (0 when chunked/unknown).
        let body = RequestBody::streaming(StreamingBody::from_hyper(body)).with_limit(limit);
        internal = internal.with_streaming_body(body);
    }
    if let Some(alpn) = tls_alpn {
        internal
            .vars
            .insert("tls.alpn".to_string(), alpn.to_string());
    }

    match router.handle_upgradable(internal).await {
        Ok(ResponseOutcome::Response(response)) => {
            ServedResponse::Response(to_hyper_streaming(response))
        }
        Ok(ResponseOutcome::Upgrade(upgraded)) => {
            let Some(on_upgrade) = on_upgrade else {
                eprintln!(
                    "caddy-rs: upstream switched protocols but the client connection cannot \
                     upgrade; serving 502"
                );
                return ServedResponse::Response(status_response(
                    StatusCode::BAD_GATEWAY,
                    "502 Bad Gateway: client connection cannot be upgraded",
                ));
            };
            // A 101 response has no body; hyper completes the client handshake when the response
            // carries the upgrade headers and status.
            let mut builder = hyper::Response::builder().status(upgraded.status);
            for (name, value) in &upgraded.headers {
                builder = builder.header(name, value);
            }
            let response = builder.body(Body::empty()).unwrap_or_else(|error| {
                eprintln!("caddy-rs: cannot build upgrade response: {error}");
                status_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "500 Internal Server Error",
                )
            });
            ServedResponse::Upgraded {
                response,
                tunnel: upgraded.tunnel,
                on_upgrade,
            }
        }
        Err(error) => {
            eprintln!("caddy-rs: handler error: {error}");
            ServedResponse::Response(status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "500 Internal Server Error",
            ))
        }
    }
}

/// Declared request body size (`Content-Length`), when present and valid.
pub(crate) fn declared_content_length(headers: &http::HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn declared_content_length_parses_valid_headers_only() {
        let mut headers = http::HeaderMap::new();
        assert_eq!(declared_content_length(&headers), None);

        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("1024"),
        );
        assert_eq!(declared_content_length(&headers), Some(1024));

        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("  42 "),
        );
        assert_eq!(declared_content_length(&headers), Some(42));

        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("not-a-number"),
        );
        assert_eq!(declared_content_length(&headers), None);
    }
}
