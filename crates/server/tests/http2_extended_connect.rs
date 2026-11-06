//! HTTP/2 extended CONNECT (RFC 8441) and WebSocket over HTTP/2 (T-PROXY-043).
//!
//! Caddy v2.11.7 serves HTTP/2 through Go's net/http (and `x/net/http2` for h2c), whose HTTP/2
//! server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` by default. `reverse_proxy` rewrites an
//! `h2` extended CONNECT (`:method CONNECT` + `:protocol websocket`) into an HTTP/1.1 WebSocket
//! upgrade to the upstream and turns the h2 stream into the client side of the tunnel.
//!
//! These tests drive a raw HTTP/1.1 WebSocket-style upstream and a real h2 client (`h2` crate) over
//! real TCP sockets: prior-knowledge h2, the h2c-upgraded variant, byte transparency, the WebSocket
//! close handshake, and loud rejection of unsupported CONNECT forms.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http::Method;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CLOSE_NORMAL: [u8; 4] = [0x88, 0x02, 0x03, 0xE8];

/// Caddy v2.11.7 / Go parity: HTTP/2 extended CONNECT is disabled unless the process runs with
/// `GODEBUG=http2xconnect=1` (Go issue #71128). This test process opts in before any connection.
fn enable_http2_extended_connect() {
    use std::sync::Once;
    static ENABLE: Once = Once::new();
    ENABLE.call_once(|| {
        let mut godebug = std::env::var("GODEBUG").unwrap_or_default();
        if !godebug.contains("http2xconnect=1") {
            if !godebug.is_empty() {
                godebug.push(',');
            }
            godebug.push_str("http2xconnect=1");
            std::env::set_var("GODEBUG", godebug);
        }
    });
}

fn config(upstream: &str, protocols: Option<Vec<&str>>) -> Config {
    let mut server = serde_json::json!({
        "listen": ["127.0.0.1:0"],
        "routes": [
            {
                "match": [{"path": ["/plain"]}],
                "handle": [{"handler": "static_response", "body": "plain-ok"}]
            },
            {
                "handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": upstream}]
                }]
            }
        ]
    });
    if let Some(protocols) = protocols {
        server["protocols"] = serde_json::json!(protocols);
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": server}}}
    }))
    .expect("test config decodes")
}

async fn start(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(store);
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (runtime, address)
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await.expect("read head byte");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UpstreamMode {
    /// Echo all bytes after the handshake until the client closes.
    Echo,
    /// Send a greeting and close the tunnel immediately (upstream EOF).
    CloseAfterGreeting,
}

/// Raw HTTP/1.1 WebSocket-style upstream: answers a WebSocket upgrade with 101 and then either
/// echoes bytes or closes after a greeting.
async fn spawn_upstream(mode: UpstreamMode) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let head = read_head(&mut stream).await;
                assert_eq!(
                    header_value(&head, "upgrade").map(str::to_ascii_lowercase),
                    Some("websocket".to_string()),
                    "upstream must receive an HTTP/1.1 WebSocket upgrade: {head}"
                );
                assert_eq!(
                    header_value(&head, "connection")
                        .map(|value| value.to_ascii_lowercase().contains("upgrade")),
                    Some(true),
                    "upstream must receive Connection: Upgrade: {head}"
                );
                assert!(
                    header_value(&head, "sec-websocket-key").is_some(),
                    "the proxy must synthesize Sec-WebSocket-Key for the HTTP/1.1 upstream: {head}"
                );
                let response = "HTTP/1.1 101 Switching Protocols\r\n\
                                Connection: Upgrade\r\n\
                                Upgrade: websocket\r\n\
                                Sec-WebSocket-Accept: caddy-rs-test-accept\r\n\
                                \r\n";
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                if mode == UpstreamMode::CloseAfterGreeting {
                    let _ = stream.write_all(b"greeting").await;
                    let _ = stream.shutdown().await;
                    return;
                }
                let mut buffer = [0_u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address.to_string()
}

async fn h2_client(address: SocketAddr) -> h2::client::SendRequest<Bytes> {
    let stream = TcpStream::connect(address).await.expect("h2 connect");
    let (send_request, connection) = h2::client::handshake(stream).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send_request
}

fn extended_connect_request(path: &str) -> http::Request<()> {
    let mut request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://example.com{path}"))
        .body(())
        .expect("request builds");
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("websocket"));
    request
}

#[tokio::test]
async fn godebug_gate_advertises_enable_connect_protocol() {
    enable_http2_extended_connect();
    let upstream = spawn_upstream(UpstreamMode::Echo).await;
    let (runtime, address) = start(config(&upstream, None)).await;
    let mut send_request = h2_client(address).await;
    // The h2 client's view of the peer SETTINGS: SETTINGS_ENABLE_CONNECT_PROTOCOL must be enabled
    // once the server's SETTINGS frame has been processed.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !send_request.is_extended_connect_protocol_enabled() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "server never advertised SETTINGS_ENABLE_CONNECT_PROTOCOL with GODEBUG=http2xconnect=1"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    runtime.shutdown().await;
}

#[tokio::test]
async fn extended_connect_tunnels_bytes_to_an_http1_websocket_upstream() {
    enable_http2_extended_connect();
    let upstream = spawn_upstream(UpstreamMode::Echo).await;
    let (runtime, address) = start(config(&upstream, None)).await;
    let mut send_request = h2_client(address).await;

    let request = extended_connect_request("/ws");
    let (response, mut send_stream) = send_request
        .send_request(request, false)
        .expect("send extended CONNECT");
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("response timeout")
        .expect("extended CONNECT response");
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "an h2 extended CONNECT gets 200 (not 101), like Caddy"
    );

    // Byte-transparent duplex tunnel: arbitrary WebSocket-framed bytes echo back unchanged.
    let payload = Bytes::from_static(&[0x82, 0x05, b'h', b'e', b'l', b'l', b'o']);
    send_stream
        .send_data(payload.clone(), false)
        .expect("send tunnel bytes");
    let mut recv_stream = response.into_body();
    let echoed = tokio::time::timeout(Duration::from_secs(5), recv_stream.data())
        .await
        .expect("echo timeout")
        .expect("echo data")
        .expect("echo frame");
    assert_eq!(echoed, payload, "bytes must pass through unchanged");

    // Client close: ending the request stream closes the upstream tunnel.
    send_stream.send_data(Bytes::new(), true).ok();
    runtime.shutdown().await;
}

#[tokio::test]
async fn extended_connect_uses_the_websocket_close_handshake_on_upstream_eof() {
    enable_http2_extended_connect();
    let upstream = spawn_upstream(UpstreamMode::CloseAfterGreeting).await;
    let (runtime, address) = start(config(&upstream, None)).await;
    let mut send_request = h2_client(address).await;

    let request = extended_connect_request("/ws-close");
    let (response, _send_stream) = send_request
        .send_request(request, false)
        .expect("send extended CONNECT");
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("response timeout")
        .expect("extended CONNECT response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut recv_stream = response.into_body();

    let greeting = tokio::time::timeout(Duration::from_secs(5), recv_stream.data())
        .await
        .expect("greeting timeout")
        .expect("greeting data")
        .expect("greeting frame");
    assert_eq!(greeting, Bytes::from_static(b"greeting"));
    let close = tokio::time::timeout(Duration::from_secs(5), recv_stream.data())
        .await
        .expect("close timeout")
        .expect("close data")
        .expect("close frame");
    assert_eq!(
        close,
        Bytes::from_static(&CLOSE_NORMAL),
        "upstream EOF over an h2 extended CONNECT must send a normal-close WebSocket frame"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn h2c_upgraded_connection_accepts_extended_connect() {
    enable_http2_extended_connect();
    let upstream = spawn_upstream(UpstreamMode::Echo).await;
    let (runtime, address) = start(config(&upstream, Some(vec!["h1", "h2c"]))).await;

    // HTTP/1.1 h2c upgrade first.
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let request = "GET /plain HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Connection: Upgrade, HTTP2-Settings\r\n\
                   Upgrade: h2c\r\n\
                   HTTP2-Settings: AAMAAABkAAQAAP__\r\n\
                   \r\n";
    stream.write_all(request.as_bytes()).await.unwrap();
    let head = read_head(&mut stream).await;
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols"),
        "expected h2c 101, got: {head}"
    );

    // The rest of the connection is HTTP/2; start an h2 client on it and use extended CONNECT.
    let (mut send_request, connection) = h2::client::handshake(stream)
        .await
        .expect("h2 handshake over h2c upgrade");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = extended_connect_request("/ws-h2c");
    let (response, mut send_stream) = send_request
        .send_request(request, false)
        .expect("send extended CONNECT");
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("response timeout")
        .expect("extended CONNECT response");
    assert_eq!(response.status(), http::StatusCode::OK);

    let payload = Bytes::from_static(b"h2c-tunnel");
    send_stream
        .send_data(payload.clone(), false)
        .expect("send tunnel bytes");
    let mut recv_stream = response.into_body();
    let echoed = tokio::time::timeout(Duration::from_secs(5), recv_stream.data())
        .await
        .expect("echo timeout")
        .expect("echo data")
        .expect("echo frame");
    assert_eq!(echoed, payload);
    runtime.shutdown().await;
}

#[tokio::test]
async fn ordinary_h2_requests_are_unaffected() {
    enable_http2_extended_connect();
    let upstream = spawn_upstream(UpstreamMode::Echo).await;
    let (runtime, address) = start(config(&upstream, None)).await;
    let mut send_request = h2_client(address).await;
    let request = http::Request::builder()
        .method(Method::GET)
        .uri("http://example.com/plain")
        .body(())
        .expect("request builds");
    let (response, _send_stream) = send_request.send_request(request, true).expect("send GET");
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("response timeout")
        .expect("GET response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = response
        .into_body()
        .data()
        .await
        .expect("body data")
        .expect("body frame");
    assert_eq!(body, Bytes::from_static(b"plain-ok"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn unsupported_connect_forms_are_rejected_loudly() {
    enable_http2_extended_connect();
    let upstream = spawn_upstream(UpstreamMode::Echo).await;
    let (runtime, address) = start(config(&upstream, None)).await;
    let mut send_request = h2_client(address).await;

    // Plain HTTP/2 CONNECT (no RFC 8441 `:protocol`).
    let request = http::Request::builder()
        .method(Method::CONNECT)
        .uri("http://example.com/ws")
        .body(())
        .expect("request builds");
    let (response, _send_stream) = send_request
        .send_request(request, true)
        .expect("send CONNECT");
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("response timeout")
        .expect("CONNECT response");
    assert_eq!(
        response.status(),
        http::StatusCode::NOT_IMPLEMENTED,
        "plain HTTP/2 CONNECT must be rejected"
    );

    // Extended CONNECT with an unsupported protocol.
    let mut request = http::Request::builder()
        .method(Method::CONNECT)
        .uri("http://example.com/ws")
        .body(())
        .expect("request builds");
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("something-else"));
    let (response, _send_stream) = send_request
        .send_request(request, true)
        .expect("send extended CONNECT");
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("response timeout")
        .expect("CONNECT response");
    assert_eq!(
        response.status(),
        http::StatusCode::NOT_IMPLEMENTED,
        "an unsupported :protocol must be rejected loudly"
    );
    runtime.shutdown().await;
}
