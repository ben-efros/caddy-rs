//! HTTP Upgrade / WebSocket tunnel primitives.
//!
//! An HTTP/1.1 `101 Switching Protocols` response is not a normal response: after the handshake the
//! connection stops speaking HTTP and the two peers exchange raw bytes. This module provides the
//! transport-agnostic pieces the engine needs to carry such a connection through handlers and the
//! router:
//!
//! * [`Tunnel`] — a boxed, bidirectional byte stream (any `AsyncRead + AsyncWrite + Unpin + Send`),
//!   which the proxy wraps around the upgraded upstream connection and the server wraps around the
//!   upgraded client connection before running `copy_bidirectional`;
//! * [`UpgradedResponse`] — status (normally `101`), handshake headers and the upstream [`Tunnel`];
//! * [`requested_upgrade_type`] — the RFC 7230 upgrade negotiation check shared by the proxy and
//!   the server.
//!
//! Handler and router integration:
//!
//! * [`StreamingOutcome::Upgrade`](crate::types::StreamingOutcome::Upgrade) lets a handler (the
//!   reverse proxy) return an upgrade instead of a body;
//! * [`Router::handle_upgradable`](crate::router::Router::handle_upgradable) is the server entry
//!   point that returns either a normal [`StreamingResponse`] or an [`UpgradedResponse`];
//! * the buffered and streaming-only router APIs ([`Router::handle`](crate::router::Router::handle),
//!   [`Router::handle_streaming`](crate::router::Router::handle_streaming)) cannot represent a
//!   tunnel and return [`Error::UpgradeNotRepresentable`] instead of silently dropping it.
//!
//! ## Server integration contract
//!
//! The server must serve the connection with hyper's upgrade-aware HTTP/1 connection
//! (`hyper_util::server::conn::auto::Builder::serve_connection_with_upgrades`), obtain the client
//! side upgrade with `hyper::upgrade::on(&mut request)` before the request is consumed, write the
//! returned [`UpgradedResponse`] status/headers as the 101 response, then, once the client upgrade
//! resolves, run the bidirectional copy between the client stream and
//! [`UpgradedResponse::tunnel`]. The copy task is also the owner of the connection's shutdown and
//! generation-draining state: dropping it closes both sides, and a shutdown signal must drop it so
//! neither side leaks.
//!
//! ## Not supported
//!
//! HTTP/2 extended CONNECT (`:protocol = websocket`, RFC 8441) is not implemented: hyper's
//! auto connection does not expose it and the server rejects it loudly. Upgrade remains an
//! HTTP/1.1 feature here; TLS termination works because the tunnel wraps the decrypted stream.

use std::fmt;
use std::pin::Pin;

use http::{HeaderMap, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional byte stream carried by an upgraded connection.
pub trait TunnelStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TunnelStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A boxed bidirectional byte stream from an upgraded connection.
pub struct Tunnel {
    stream: Box<dyn TunnelStream>,
}

impl Tunnel {
    /// Wrap an upgraded stream.
    pub fn new(stream: impl TunnelStream + 'static) -> Self {
        Self {
            stream: Box::new(stream),
        }
    }

    /// Take the raw stream (for example to hand it to `tokio::io::copy_bidirectional`).
    pub fn into_inner(self) -> Box<dyn TunnelStream> {
        self.stream
    }

    /// Pin the underlying stream for `AsyncRead`/`AsyncWrite` polling.
    pub fn as_pinned_mut(&mut self) -> Pin<&mut dyn TunnelStream> {
        Pin::new(&mut *self.stream)
    }
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Tunnel").finish_non_exhaustive()
    }
}

/// An upgraded response: the `101 Switching Protocols` handshake plus the upstream tunnel.
#[derive(Debug)]
pub struct UpgradedResponse {
    /// Response status (normally `101 Switching Protocols`).
    pub status: StatusCode,
    /// Handshake response headers (`Upgrade`, `Connection: Upgrade`, `Sec-WebSocket-*`, ...).
    pub headers: HeaderMap,
    /// The upgraded upstream connection.
    pub tunnel: Tunnel,
}

impl UpgradedResponse {
    /// Build an upgraded response from its parts.
    pub fn new(status: StatusCode, headers: HeaderMap, tunnel: Tunnel) -> Self {
        Self {
            status,
            headers,
            tunnel,
        }
    }
}

/// The protocol a request asks to upgrade to, following RFC 7230 upgrade negotiation.
///
/// Returns `Some(protocol)` only when the `Connection` header contains the `upgrade` token and the
/// `Upgrade` header carries a non-empty printable-ASCII protocol name. The value is returned as
/// sent (callers compare case-insensitively).
pub fn requested_upgrade_type(headers: &HeaderMap) -> Option<String> {
    let connection_upgrade = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        });
    if !connection_upgrade {
        return None;
    }
    let upgrade = headers.get(http::header::UPGRADE)?.to_str().ok()?.trim();
    if upgrade.is_empty() || !upgrade.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    Some(upgrade.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderValue, Request, StatusCode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tunnel_is_a_bidirectional_stream() {
        let (left, mut right) = tokio::io::duplex(64);
        let mut tunnel = Tunnel::new(left);
        let mut stream = tunnel.as_pinned_mut();
        stream.write_all(b"ping").await.unwrap();
        let mut buffer = [0_u8; 4];
        right.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"ping");
        right.write_all(b"pong").await.unwrap();
        let mut buffer = [0_u8; 4];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"pong");
    }

    #[test]
    fn upgrade_type_requires_connection_token_and_printable_protocol() {
        let mut request = Request::builder()
            .header(http::header::UPGRADE, "websocket")
            .body(())
            .unwrap();
        assert_eq!(requested_upgrade_type(request.headers()), None);
        request.headers_mut().insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        assert_eq!(
            requested_upgrade_type(request.headers()).as_deref(),
            Some("websocket")
        );
        request.headers_mut().insert(
            http::header::UPGRADE,
            HeaderValue::from_static("bad protocol"),
        );
        assert_eq!(requested_upgrade_type(request.headers()), None);
    }

    #[test]
    fn upgraded_response_carries_status_headers_and_tunnel() {
        let (stream, _other) = tokio::io::duplex(8);
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        let response = UpgradedResponse::new(
            StatusCode::SWITCHING_PROTOCOLS,
            headers,
            Tunnel::new(stream),
        );
        assert_eq!(response.status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(response.headers[http::header::UPGRADE], "websocket");
        assert!(format!("{:?}", response).contains("UpgradedResponse"));
    }
}
