//! WebSocket tunnel shutdown: close-frame synthesis and graceful tunnel pumping.
//!
//! HTTP/1.1 protocol switches are byte-transparent tunnels: `reverse_proxy` hands the upgraded
//! upstream stream to the server, which pairs it with the upgraded client connection. Without
//! WebSocket framing awareness, an upstream EOF or a server shutdown just closes the TCP
//! connection, so a WebSocket client observes an abnormal closure (`1006`) instead of a close
//! handshake.
//!
//! This module adds the framing awareness Caddy has in
//! `modules/caddyhttp/reverseproxy/streaming.go` (`writeCloseControl`):
//!
//! * [`request_is_websocket`] / [`response_negotiated_websocket`] / [`is_websocket_handshake`]
//!   decide whether the upgraded connection is a real WebSocket handshake (RFC 6455 `Upgrade:
//!   websocket` + `Connection: upgrade` tokens, `Sec-WebSocket-Key` on the request and
//!   `Sec-WebSocket-Accept` on the 101 response). Only then are frames ever synthesised.
//! * [`tunnel`] pumps bytes bidirectionally and stays byte-transparent, except that it writes a
//!   single WebSocket Close control frame at the end of a tunnel:
//!   * upstream EOF (backend closed first): `1000` (normal closure) to the client, then the
//!     client write half is shut down so the client sees data + close frame + FIN instead of
//!     `1006`;
//!   * server shutdown/drain: `1001` (going away) to the client and, masked, to the upstream,
//!     matching Caddy's `writeCloseControl` on `closeConnections`;
//!   * `ping`/`pong` and every other frame are forwarded untouched.
//!
//! Masking follows RFC 6455 §5.3: the proxy acts as the server towards the client (unmasked
//! frames) and as the client towards the upstream (masked frames).
//!
//! ## Residuals
//!
//! * After the close frame is written the tunnel gives the peer at most
//!   [`CLOSE_HANDSHAKE_TIMEOUT`] to finish its side before the remaining copy direction is
//!   aborted; the client's Close acknowledgement is not required (Caddy likewise closes
//!   immediately after writing the frame).
//! * Close frames are only synthesised at normal EOF/shutdown; a tunnel copy error still closes
//!   the TCP connection (Caddy behaves the same way for streaming errors).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::{HeaderMap, HeaderName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

/// WebSocket close status code: normal closure (upstream EOF).
pub const CLOSE_NORMAL: u16 = 1000;
/// WebSocket close status code: going away (server shutdown/drain).
pub const CLOSE_GOING_AWAY: u16 = 1001;
/// Bounded wait for the remaining copy direction after a close frame was written.
pub const CLOSE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether the request is a WebSocket upgrade offer.
///
/// Mirrors Caddy's `isWebsocket` token checks and additionally requires the RFC 6455
/// `Sec-WebSocket-Key` request header, so arbitrary `Upgrade: websocket` requests that are not a
/// real WebSocket handshake never get synthesised frames.
pub fn request_is_websocket(headers: &HeaderMap) -> bool {
    header_has_token(headers, http::header::CONNECTION, "upgrade")
        && header_has_token(headers, http::header::UPGRADE, "websocket")
        && headers.contains_key("sec-websocket-key")
}

/// Whether a `101 Switching Protocols` response completed a WebSocket handshake.
///
/// The upstream must have accepted the handshake by returning `Sec-WebSocket-Accept` (Caddy
/// forwards this header from the backend to the client).
pub fn response_negotiated_websocket(headers: &HeaderMap) -> bool {
    headers.contains_key("sec-websocket-accept")
}

/// Whether this request/response pair is an upgraded WebSocket connection.
pub fn is_websocket_handshake(request: &HeaderMap, response: &HeaderMap) -> bool {
    request_is_websocket(request) && response_negotiated_websocket(response)
}

/// A WebSocket Close control frame carrying only a status code (no reason text), like Caddy's
/// `writeCloseControl`. The frame is unmasked for the server role (towards the client) and masked
/// for the client role (towards the upstream).
pub fn close_frame(code: u16, masked: bool) -> Vec<u8> {
    // Final bit + opcode 0x8 (close). Control frames are never fragmented and their payload is at
    // most 125 bytes: 2 status-code bytes here.
    let mut frame = Vec::with_capacity(8);
    frame.push(0x88);
    let payload = code.to_be_bytes();
    if masked {
        frame.push(0x80 | 0x02);
        let key = next_mask_key();
        frame.extend_from_slice(&key);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ key[index % 4]);
        }
    } else {
        frame.push(0x02);
        frame.extend_from_slice(&payload);
    }
    frame
}

/// Write one close control frame and flush it.
pub async fn write_close_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    code: u16,
    masked: bool,
) -> std::io::Result<()> {
    writer.write_all(&close_frame(code, masked)).await?;
    writer.flush().await
}

/// Pump an upgraded tunnel while keeping WebSocket clients on a clean close handshake.
///
/// `client` is the upgraded client connection (the proxy acts as the server: unmasked frames) and
/// `upstream` is the upgraded backend connection (the proxy acts as the client: masked frames).
/// When `websocket` is false the pump is a plain byte-transparent bidirectional copy that still
/// reacts to `shutdown`; no WebSocket frames are ever synthesised.
pub async fn tunnel<C, U>(
    client: C,
    upstream: U,
    websocket: bool,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    // Backend -> client. A clean EOF is normal for a WebSocket peer: tell the client with a close
    // frame before shutting the client write half down, so its library reports a close handshake
    // rather than an abnormal 1006.
    let mut shutdown_upstream = shutdown.clone();
    let mut upstream_to_client = Direction(tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            tokio::select! {
                _ = shutdown_upstream.changed() => {
                    if websocket {
                        write_close_frame(&mut client_write, CLOSE_GOING_AWAY, false).await?;
                    }
                    client_write.flush().await?;
                    let _ = client_write.shutdown().await;
                    return Ok(());
                }
                read = upstream_read.read(&mut buffer) => {
                    match read? {
                        0 => {
                            if websocket {
                                write_close_frame(&mut client_write, CLOSE_NORMAL, false).await?;
                            }
                            client_write.flush().await?;
                            let _ = client_write.shutdown().await;
                            return Ok(());
                        }
                        count => {
                            client_write.write_all(&buffer[..count]).await?;
                            client_write.flush().await?;
                        }
                    }
                }
            }
        }
    }));

    // Client -> backend.
    let mut shutdown_client = shutdown;
    let mut client_to_upstream = Direction(tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            tokio::select! {
                _ = shutdown_client.changed() => {
                    if websocket {
                        write_close_frame(&mut upstream_write, CLOSE_GOING_AWAY, true).await?;
                    }
                    upstream_write.flush().await?;
                    let _ = upstream_write.shutdown().await;
                    return Ok(());
                }
                read = client_read.read(&mut buffer) => {
                    match read? {
                        0 => {
                            let _ = upstream_write.shutdown().await;
                            return Ok(());
                        }
                        count => {
                            upstream_write.write_all(&buffer[..count]).await?;
                            upstream_write.flush().await?;
                        }
                    }
                }
            }
        }
    }));

    // Wait for the first direction. A copy error tears the tunnel down immediately; a clean EOF in
    // one direction leaves the other one to drain (Caddy's half-close behaviour) with a bounded
    // close-handshake timeout once the WebSocket close frame has been written.
    let first_result;
    let remaining: &mut Direction;
    tokio::select! {
        result = &mut upstream_to_client.0 => {
            first_result = result;
            remaining = &mut client_to_upstream;
        }
        result = &mut client_to_upstream.0 => {
            first_result = result;
            remaining = &mut upstream_to_client;
        }
    }
    if let Ok(Err(error)) = &first_result {
        remaining.abort();
        return Err(std::io::Error::new(
            error.kind(),
            format!("upgraded tunnel copy failed: {error}"),
        ));
    }
    match tokio::time::timeout(CLOSE_HANDSHAKE_TIMEOUT, &mut remaining.0).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => return Err(error),
        Ok(Err(join_error)) => return Err(std::io::Error::other(join_error)),
        Err(_) => remaining.abort(),
    }
    // Surface the first direction's panic/join error (copy errors were handled above).
    if let Err(join_error) = first_result {
        return Err(std::io::Error::other(join_error));
    }
    Ok(())
}

/// A direction copy task that is aborted when the pump future is dropped (for example on a forced
/// server shutdown), so cancelling the tunnel never leaks the background copies.
struct Direction(tokio::task::JoinHandle<std::io::Result<()>>);

impl Direction {
    fn abort(&self) {
        self.0.abort();
    }
}

impl Drop for Direction {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    })
}

/// A fresh RFC 6455 masking key. Masks must be unpredictable on the wire; a counter mixed with the
/// clock is sufficient for the single best-effort close frame this module writes.
fn next_mask_key() -> [u8; 4] {
    static COUNTER: AtomicU64 = AtomicU64::new(0x9E37_79B1_85EB_CA87);
    let mut value = COUNTER.fetch_add(0x9E37_79B1_85EB_CA87, Ordering::Relaxed);
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    value ^= clock.rotate_left(17);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let mask = (value ^ (value >> 31)) as u32;
    mask.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connecting = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
        let (server_side, _) = listener.accept().await.unwrap();
        let client_side = connecting.await.unwrap().unwrap();
        (server_side, client_side)
    }

    async fn read_to_end(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        tokio::time::timeout(StdDuration::from_secs(5), async {
            let mut buffer = Vec::new();
            stream.read_to_end(&mut buffer).await.unwrap();
            buffer
        })
        .await
        .expect("timed out reading from tunnel peer")
    }

    fn unmask_close(frame: &[u8]) -> (u16, bool) {
        assert_eq!(frame[0], 0x88, "expected a WebSocket close frame");
        let masked = frame[1] & 0x80 != 0;
        let length = (frame[1] & 0x7f) as usize;
        assert_eq!(length, 2, "close frame carries only a status code");
        let (key, payload) = if masked {
            (&frame[2..6], &frame[6..8])
        } else {
            (&[0_u8; 4][..], &frame[2..4])
        };
        let mut code_bytes = [0_u8; 2];
        for (index, byte) in payload.iter().enumerate() {
            code_bytes[index] = byte ^ key[index % 4];
        }
        (u16::from_be_bytes(code_bytes), masked)
    }

    #[test]
    fn detects_only_real_websocket_handshakes() {
        let mut request = HeaderMap::new();
        request.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("keep-alive, Upgrade"),
        );
        request.insert(
            http::header::UPGRADE,
            http::HeaderValue::from_static("WebSocket"),
        );
        assert!(
            !request_is_websocket(&request),
            "Sec-WebSocket-Key is required"
        );
        request.insert(
            "sec-websocket-key",
            http::HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        assert!(request_is_websocket(&request));

        let mut response = HeaderMap::new();
        assert!(!response_negotiated_websocket(&response));
        response.insert(
            "sec-websocket-accept",
            http::HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        );
        assert!(is_websocket_handshake(&request, &response));

        // A non-WebSocket upgrade (for example a custom protocol) is never treated as WebSocket.
        let mut custom = HeaderMap::new();
        custom.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("Upgrade"),
        );
        custom.insert(
            http::header::UPGRADE,
            http::HeaderValue::from_static("spdy/3"),
        );
        assert!(!request_is_websocket(&custom));
    }

    #[test]
    fn close_frame_encoding_matches_rfc6455() {
        assert_eq!(
            close_frame(CLOSE_NORMAL, false),
            vec![0x88, 0x02, 0x03, 0xE8]
        );
        let masked = close_frame(CLOSE_GOING_AWAY, true);
        assert_eq!(masked.len(), 8);
        let (code, is_masked) = unmask_close(&masked);
        assert_eq!(code, CLOSE_GOING_AWAY);
        assert!(is_masked);
    }

    #[tokio::test]
    async fn upstream_eof_sends_normal_close_frame_instead_of_1006() {
        let (proxy_client, mut test_client) = tcp_pair().await;
        let (proxy_upstream, mut test_upstream) = tcp_pair().await;
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let pump = tokio::spawn(tunnel(proxy_client, proxy_upstream, true, shutdown_rx));

        // Backend sends payload and then closes its side (a clean upstream EOF).
        test_upstream.write_all(b"hello").await.unwrap();
        test_upstream.shutdown().await.unwrap();

        let received = read_to_end(&mut test_client).await;
        assert_eq!(&received[..5], b"hello");
        let (code, masked) = unmask_close(&received[5..]);
        assert_eq!(
            code, CLOSE_NORMAL,
            "upstream EOF must map to a normal close"
        );
        assert!(
            !masked,
            "the proxy is the server towards the client: unmasked frame"
        );
        drop(test_client);
        pump.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_sends_going_away_close_to_both_sides() {
        let (proxy_client, mut test_client) = tcp_pair().await;
        let (proxy_upstream, mut test_upstream) = tcp_pair().await;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let pump = tokio::spawn(tunnel(proxy_client, proxy_upstream, true, shutdown_rx));

        test_client.write_all(b"before").await.unwrap();
        test_upstream.read_exact(&mut [0_u8; 6]).await.unwrap();
        shutdown_tx.send(true).unwrap();

        let client_received = read_to_end(&mut test_client).await;
        let (client_code, masked) = unmask_close(&client_received);
        assert_eq!(client_code, CLOSE_GOING_AWAY);
        assert!(!masked);

        let upstream_received = read_to_end(&mut test_upstream).await;
        let (upstream_code, masked) = unmask_close(&upstream_received);
        assert_eq!(upstream_code, CLOSE_GOING_AWAY);
        assert!(
            masked,
            "the proxy is the client towards the upstream: masked frame"
        );
        pump.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ping_and_pong_frames_pass_through_untouched() {
        let (proxy_client, mut test_client) = tcp_pair().await;
        let (proxy_upstream, mut test_upstream) = tcp_pair().await;
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let pump = tokio::spawn(tunnel(proxy_client, proxy_upstream, true, shutdown_rx));

        // A masked ping frame from the client (opcode 0x9, mask bit, 4-byte key, no payload).
        let ping = [0x89_u8, 0x80, 0x01, 0x02, 0x03, 0x04];
        test_client.write_all(&ping).await.unwrap();
        let mut forwarded = [0_u8; 6];
        test_upstream.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, ping, "ping frames must not be rewritten");

        // A pong from the backend in the reverse direction.
        let pong = [0x8A_u8, 0x00];
        test_upstream.write_all(&pong).await.unwrap();
        let mut received = [0_u8; 2];
        test_client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, pong, "pong frames must not be rewritten");

        test_upstream.shutdown().await.unwrap();
        let rest = read_to_end(&mut test_client).await;
        assert_eq!(rest, close_frame(CLOSE_NORMAL, false));
        drop(test_client);
        pump.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancelling_the_pump_closes_both_directions() {
        // The server aborts the tunnel task on a forced shutdown; dropping the pump future must
        // abort both copy tasks (and therefore close the proxy-side sockets), not leak them.
        let (proxy_client, mut test_client) = tcp_pair().await;
        let (proxy_upstream, mut test_upstream) = tcp_pair().await;
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let pump = tokio::spawn(tunnel(proxy_client, proxy_upstream, false, shutdown_rx));

        test_client.write_all(b"data").await.unwrap();
        let mut forwarded = [0_u8; 4];
        test_upstream.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(&forwarded, b"data");

        pump.abort();
        let _ = pump.await;
        let mut buffer = [0_u8; 8];
        let client_read =
            tokio::time::timeout(StdDuration::from_secs(5), test_client.read(&mut buffer))
                .await
                .expect("timed out waiting for the client side to close")
                .unwrap();
        assert_eq!(
            client_read, 0,
            "cancelled pump must close the client connection"
        );
        let upstream_read =
            tokio::time::timeout(StdDuration::from_secs(5), test_upstream.read(&mut buffer))
                .await
                .expect("timed out waiting for the upstream side to close")
                .unwrap();
        assert_eq!(
            upstream_read, 0,
            "cancelled pump must close the upstream connection"
        );
    }

    #[tokio::test]
    async fn non_websocket_upgrade_is_byte_transparent() {
        let (proxy_client, mut test_client) = tcp_pair().await;
        let (proxy_upstream, mut test_upstream) = tcp_pair().await;
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let pump = tokio::spawn(tunnel(proxy_client, proxy_upstream, false, shutdown_rx));

        test_upstream.write_all(b"raw-bytes").await.unwrap();
        // Half-close: the non-WebSocket tunnel must not inject a close frame.
        test_upstream.shutdown().await.unwrap();
        let received = read_to_end(&mut test_client).await;
        assert_eq!(received, b"raw-bytes");
        drop(test_client);
        pump.await.unwrap().unwrap();

        // Shutdown on a non-WebSocket upgrade also injects nothing.
        let (proxy_client, mut test_client) = tcp_pair().await;
        let (proxy_upstream, mut test_upstream) = tcp_pair().await;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let pump = tokio::spawn(tunnel(proxy_client, proxy_upstream, false, shutdown_rx));
        test_client.write_all(b"client-data").await.unwrap();
        let mut forwarded = [0_u8; 11];
        test_upstream.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(&forwarded, b"client-data");
        shutdown_tx.send(true).unwrap();
        assert!(read_to_end(&mut test_client).await.is_empty());
        assert!(read_to_end(&mut test_upstream).await.is_empty());
        pump.await.unwrap().unwrap();
    }
}
