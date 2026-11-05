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

/// HTTP/1.1 `Upgrade: h2c` protocol token (RFC 7540 §3.2 cleartext HTTP/2 upgrade).
pub const H2C_UPGRADE_TOKEN: &str = "h2c";

/// The connection-specific `HTTP2-Settings` header (RFC 7540 §3.2.1).
pub const HTTP2_SETTINGS_HEADER: &str = "HTTP2-Settings";

/// Whether the request headers offer an h2c (cleartext HTTP/2) protocol upgrade.
///
/// This is the RFC 7230 negotiation check plus a case-insensitive `h2c` token comparison, matching
/// Caddy's cleartext listener behaviour. The server is responsible for only honouring it on an
/// HTTP/1.1, non-TLS connection, for requiring a valid [`HTTP2-Settings`](HTTP2_SETTINGS_HEADER)
/// header (see [`h2c_upgrade_settings`]), and for serving HTTP/2 on the upgraded stream.
pub fn is_h2c_upgrade(headers: &HeaderMap) -> bool {
    requested_upgrade_type(headers)
        .is_some_and(|protocol| protocol.eq_ignore_ascii_case(H2C_UPGRADE_TOKEN))
}

/// Why an h2c Upgrade offer's `HTTP2-Settings` header is not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2cSettingsError {
    /// The `HTTP2-Settings` header is absent. RFC 7540 §3.2.1 forbids upgrading to HTTP/2
    /// without it.
    Missing,
    /// The header value is not a valid base64url string (RFC 4648 §5).
    InvalidBase64,
    /// The decoded value is not a SETTINGS frame payload: RFC 7540 §6.5 requires a length that
    /// is a multiple of 6 octets (one SETTINGS entry per 6 octets).
    InvalidSettings,
}

impl fmt::Display for H2cSettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            H2cSettingsError::Missing => write!(
                formatter,
                "h2c upgrade request is missing the {HTTP2_SETTINGS_HEADER} header"
            ),
            H2cSettingsError::InvalidBase64 => write!(
                formatter,
                "{HTTP2_SETTINGS_HEADER} is not a valid base64url string"
            ),
            H2cSettingsError::InvalidSettings => write!(
                formatter,
                "{HTTP2_SETTINGS_HEADER} is not a SETTINGS frame payload (length must be a \
                 multiple of 6 octets)"
            ),
        }
    }
}

impl std::error::Error for H2cSettingsError {}

/// Validate the `HTTP2-Settings` header of an h2c Upgrade offer (RFC 7540 §3.2.1).
///
/// The header carries the payload of the SETTINGS frame that governs the upgraded HTTP/2
/// connection, encoded as base64url (RFC 4648 §5) with padding omitted. A server MUST NOT switch
/// an `Upgrade: h2c` request to HTTP/2 unless this header is present and decodes to a valid
/// SETTINGS frame payload; callers reject the offer with `400 Bad Request` otherwise. Only the
/// framing is validated here — unknown SETTINGS identifiers are allowed (RFC 7540 §6.5.2 requires
/// implementations to ignore parameters they do not understand).
pub fn h2c_upgrade_settings(headers: &HeaderMap) -> Result<(), H2cSettingsError> {
    let value = headers
        .get(HTTP2_SETTINGS_HEADER)
        .ok_or(H2cSettingsError::Missing)?;
    let value = value
        .to_str()
        .map_err(|_| H2cSettingsError::InvalidBase64)?;
    let payload = decode_base64url(value).ok_or(H2cSettingsError::InvalidBase64)?;
    if payload.len() % 6 != 0 {
        return Err(H2cSettingsError::InvalidSettings);
    }
    Ok(())
}

/// Decode a base64url string (RFC 4648 §5): the URL-safe alphabet (`-` and `_` in place of `+`
/// and `/`), padding omitted and tolerated at the tail.
fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    // RFC 4648 §5 base64url omits padding; tolerate trailing `=` so values encoded by
    // third-party clients with padding still validate.
    let input = input.trim_end_matches('=');
    let mut decoded = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((accumulator >> bits) as u8);
        }
    }
    Some(decoded)
}

/// The handshake headers for a `101 Switching Protocols` h2c response.
///
/// Caddy sends `Connection: Upgrade` and `Upgrade: h2c`; the server writes this status/header pair
/// and then serves HTTP/2 on the upgraded stream.
pub fn h2c_upgrade_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("Upgrade"),
    );
    headers.insert(
        http::header::UPGRADE,
        http::HeaderValue::from_static(H2C_UPGRADE_TOKEN),
    );
    headers
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

    #[test]
    fn detects_h2c_upgrade_offers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            "Upgrade, HTTP2-Settings".parse().unwrap(),
        );
        headers.insert(http::header::UPGRADE, "h2c".parse().unwrap());
        assert!(is_h2c_upgrade(&headers));
        // Case-insensitive protocol token.
        headers.insert(http::header::UPGRADE, "H2C".parse().unwrap());
        assert!(is_h2c_upgrade(&headers));
        // Missing Connection: upgrade token is not an upgrade negotiation.
        headers.insert(http::header::CONNECTION, "keep-alive".parse().unwrap());
        assert!(!is_h2c_upgrade(&headers));
        // Other protocols are not h2c.
        headers.insert(http::header::CONNECTION, "Upgrade".parse().unwrap());
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        assert!(!is_h2c_upgrade(&headers));
    }

    #[test]
    fn h2c_upgrade_headers_are_canonical() {
        let headers = h2c_upgrade_headers();
        assert_eq!(headers[http::header::UPGRADE], "h2c");
        assert_eq!(headers[http::header::CONNECTION], "Upgrade");
    }

    #[test]
    fn h2c_upgrade_settings_accepts_the_oracle_payload() {
        // The payload used by the live-oracle and integration tests: two SETTINGS entries
        // (MAX_CONCURRENT_STREAMS=100 and INITIAL_WINDOW_SIZE=65535), which is a valid
        // multiple of 6 octets.
        let mut headers = HeaderMap::new();
        headers.insert(HTTP2_SETTINGS_HEADER, "AAMAAABkAAQAAP__".parse().unwrap());
        assert_eq!(h2c_upgrade_settings(&headers), Ok(()));
        // A single SETTINGS frame of 6 octets is valid too (HEADER_TABLE_SIZE=4096).
        headers.insert(HTTP2_SETTINGS_HEADER, "AAEAABAA".parse().unwrap());
        assert_eq!(h2c_upgrade_settings(&headers), Ok(()));
        // An empty payload is an empty SETTINGS frame, which RFC 7540 §6.5 permits.
        headers.insert(HTTP2_SETTINGS_HEADER, "".parse().unwrap());
        assert_eq!(h2c_upgrade_settings(&headers), Ok(()));
    }

    #[test]
    fn h2c_upgrade_settings_rejects_missing_or_malformed_values() {
        let mut headers = HeaderMap::new();
        // Missing header: RFC 7540 §3.2.1 forbids upgrading without it.
        assert_eq!(
            h2c_upgrade_settings(&headers),
            Err(H2cSettingsError::Missing)
        );

        // Not base64url at all.
        headers.insert(HTTP2_SETTINGS_HEADER, "!!!not-base64!!!".parse().unwrap());
        assert_eq!(
            h2c_upgrade_settings(&headers),
            Err(H2cSettingsError::InvalidBase64)
        );

        // Not base64url: standard (+/) alphabet is rejected by the URL-safe alphabet.
        headers.insert(HTTP2_SETTINGS_HEADER, "AAMAAABkAAQAAP+/".parse().unwrap());
        assert_eq!(
            h2c_upgrade_settings(&headers),
            Err(H2cSettingsError::InvalidBase64)
        );

        // Decodes, but is not a SETTINGS frame payload (3 octets, not a multiple of 6).
        headers.insert(HTTP2_SETTINGS_HEADER, "AAAA".parse().unwrap());
        assert_eq!(
            h2c_upgrade_settings(&headers),
            Err(H2cSettingsError::InvalidSettings)
        );
    }

    #[test]
    fn base64url_decode_handles_the_url_safe_alphabet_and_padding() {
        // Two SETTINGS entries, base64url with `_` in the final characters:
        // MAX_CONCURRENT_STREAMS=100 and INITIAL_WINDOW_SIZE=0xFFFF (65535).
        assert_eq!(
            decode_base64url("AAMAAABkAAQAAP__").as_deref(),
            Some(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x00, 0x00, 0xff, 0xff][..])
        );
        // Padding is not part of base64url (RFC 4648 §5) but is tolerated at the tail.
        assert_eq!(
            decode_base64url("AAMAAABkAAQAAP__=").as_deref(),
            Some(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x00, 0x00, 0xff, 0xff][..])
        );
        // The URL-safe `-` alphabet.
        assert_eq!(decode_base64url("-w").as_deref(), Some(&[0xfb][..]));
        // Invalid characters and stray `=` inside the value are rejected.
        assert_eq!(decode_base64url("AA=A"), None);
        assert_eq!(decode_base64url("A$A"), None);
    }

    #[test]
    fn h2c_settings_error_is_formatted_for_logs() {
        assert!(H2cSettingsError::Missing
            .to_string()
            .contains("HTTP2-Settings"));
        assert!(H2cSettingsError::InvalidBase64
            .to_string()
            .contains("base64url"));
        assert!(H2cSettingsError::InvalidSettings
            .to_string()
            .contains("multiple of 6"));
    }
}
