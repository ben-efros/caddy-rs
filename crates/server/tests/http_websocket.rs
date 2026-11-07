//! End-to-end HTTP Upgrade / WebSocket-style passthrough tests through real listeners.
//!
//! The upstream is a raw TCP "WebSocket-style" server: it answers the HTTP/1.1 upgrade handshake
//! with `101 Switching Protocols`, sends a greeting, then echoes raw bytes. The client is also raw
//! so the test can verify the exact wire headers and byte stream after the switch, including close
//! propagation in both directions.
//!
//! Coverage:
//! * handle/proxy/server upgrade path over cleartext HTTP/1.1 (the standard WebSocket transport),
//! * upgrade through a TLS listener (the tunnel wraps the decrypted stream),
//! * non-upgrade requests through the same reverse proxy are unaffected,
//! * client disconnect closes the upstream tunnel and upstream EOF reaches the client,
//! * HTTP/2 extended CONNECT is rejected loudly (unsupported).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::Full;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const EXAMPLE_CERT: &str = include_str!("../../tls/testdata/https/example.com.pem");
const EXAMPLE_KEY: &str = include_str!("../../tls/testdata/https/example.com.key");

/// Configuration: one server proxying to `dial`, optionally terminating TLS.
fn config(dial: &str, tls: bool) -> Config {
    let mut server = serde_json::json!({
        "listen": ["127.0.0.1:0"],
        "routes": [{
            "handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": dial}],
                "headers": {"request": {"set": {"X-Added": ["yes"]}}}
            }]
        }]
    });
    if tls {
        server["tls_connection_policies"] = serde_json::json!([{}]);
    }
    // An ephemeral HTTP port keeps the derived redirect listener off :80, which CI (unprivileged)
    // cannot bind.
    let mut apps = serde_json::json!({"http": {"http_port": 0, "servers": {"srv0": server}}});
    if tls {
        apps["tls"] = serde_json::json!({
            "certificates": {"load_pem": [{"certificate": EXAMPLE_CERT, "key": EXAMPLE_KEY}]}
        });
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": apps
    }))
    .expect("test config decodes")
}

async fn start(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener is bound");
    (runtime, address)
}

// ---- raw WebSocket-style upstream -----------------------------------------------------------

async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => head.push(byte[0]),
            Ok(Err(_)) | Err(_) => break,
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

/// A raw upstream: normal requests get `200 plain`; upgrade requests get `101`, a greeting, then
/// raw echo until EOF. When `close_after_greeting` is set the upstream closes right after greeting.
async fn spawn_upstream(close_after_greeting: bool) -> (String, Arc<tokio::sync::Notify>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream_saw_eof = Arc::new(tokio::sync::Notify::new());
    let notify = Arc::clone(&upstream_saw_eof);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let notify = Arc::clone(&notify);
            let close_after_greeting = close_after_greeting;
            tokio::spawn(async move {
                let head = read_http_head(&mut stream).await;
                if header_value(&head, "upgrade").is_none() {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nplain",
                        )
                        .await;
                    return;
                }
                let upgrade = header_value(&head, "upgrade").unwrap_or("missing");
                let connection = header_value(&head, "connection").unwrap_or("missing");
                let added = header_value(&head, "x-added").unwrap_or("missing");
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: {upgrade}\r\n\
                     Sec-WebSocket-Accept: test-accept\r\n\
                     X-Seen-Connection: {connection}\r\n\
                     X-Seen-Upgrade: {upgrade}\r\n\
                     X-Seen-X-Added: {added}\r\n\
                     Keep-Alive: timeout=5\r\n\
                     Transfer-Encoding: chunked\r\n\
                     \r\n"
                );
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                if stream.write_all(b"greeting").await.is_err() {
                    return;
                }
                if close_after_greeting {
                    stream.shutdown().await.ok();
                    return;
                }
                let mut buffer = [0_u8; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => {
                            notify.notify_waiters();
                            return;
                        }
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                notify.notify_waiters();
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (address.to_string(), upstream_saw_eof)
}

// ---- raw clients -----------------------------------------------------------------------------

fn upgrade_request(path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: example.com\r\n\
         Connection: keep-alive, Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    )
}

async fn read_exact_timeout<S: AsyncRead + Unpin>(stream: &mut S, expected: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0_u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buffer))
        .await
        .expect("read timeout")
        .expect("read bytes");
    buffer
}

async fn read_to_eof_timeout<S: AsyncRead + Unpin>(stream: &mut S) -> usize {
    let mut buffer = [0_u8; 64];
    tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
        .await
        .expect("EOF timeout")
        .expect("read result")
}

/// Unmasked WebSocket Close control frame with a status code and no reason.
fn close_frame(status: u16) -> [u8; 4] {
    let [high, low] = status.to_be_bytes();
    [0x88, 0x02, high, low]
}

/// Read exactly one close frame and return its status code.
async fn read_close_frame<S: AsyncRead + Unpin>(stream: &mut S) -> u16 {
    let frame = read_exact_timeout(stream, &close_frame(1000)).await;
    assert_eq!(frame[0], 0x88, "expected a WebSocket close frame");
    assert_eq!(frame[1], 0x02, "close frame carries only a status code");
    assert_eq!(frame[2] & 0x80, 0, "server-to-client frames are unmasked");
    u16::from_be_bytes([frame[2], frame[3]])
}

// ---- tests -----------------------------------------------------------------------------------

#[tokio::test]
async fn websocket_upgrade_passthrough_over_http1() {
    let (dial, upstream_saw_eof) = spawn_upstream(false).await;
    let (runtime, address) = start(config(&dial, false)).await;

    let mut client = TcpStream::connect(address).await.expect("client connect");
    client
        .write_all(upgrade_request("/ws").as_bytes())
        .await
        .expect("write handshake");
    let head = read_http_head(&mut client).await;
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols"),
        "expected 101, got: {head}"
    );
    assert_eq!(header_value(&head, "upgrade"), Some("websocket"));
    assert_eq!(header_value(&head, "connection"), Some("Upgrade"));
    assert_eq!(
        header_value(&head, "sec-websocket-accept"),
        Some("test-accept")
    );
    // The proxy reconstructed the upgrade negotiation for the upstream and applied header_up.
    assert_eq!(header_value(&head, "x-seen-connection"), Some("Upgrade"));
    assert_eq!(header_value(&head, "x-seen-upgrade"), Some("websocket"));
    assert_eq!(header_value(&head, "x-seen-x-added"), Some("yes"));
    // Hop-by-hop response headers are stripped.
    assert_eq!(header_value(&head, "keep-alive"), None);
    assert_eq!(header_value(&head, "transfer-encoding"), None);

    // Bytes flow both ways after the handshake.
    assert_eq!(
        read_exact_timeout(&mut client, b"greeting").await,
        b"greeting"
    );
    client
        .write_all(b"ping")
        .await
        .expect("write after upgrade");
    assert_eq!(read_exact_timeout(&mut client, b"ping").await, b"ping");

    // Client disconnect propagates to the upstream tunnel.
    client.shutdown().await.expect("client shutdown");
    tokio::time::timeout(Duration::from_secs(5), upstream_saw_eof.notified())
        .await
        .expect("upstream must observe the client disconnect");
    runtime.shutdown().await;
}

#[tokio::test]
async fn upstream_close_propagates_to_upgraded_client() {
    let (dial, _upstream_saw_eof) = spawn_upstream(true).await;
    let (runtime, address) = start(config(&dial, false)).await;

    let mut client = TcpStream::connect(address).await.expect("client connect");
    client
        .write_all(upgrade_request("/ws").as_bytes())
        .await
        .expect("write handshake");
    let head = read_http_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert_eq!(
        read_exact_timeout(&mut client, b"greeting").await,
        b"greeting"
    );
    // Upstream closed its side; the proxy synthesises a normal-close control frame so a real
    // WebSocket client sees a close handshake (code 1000) instead of abnormal closure 1006, then
    // the client side is closed.
    assert_eq!(
        read_close_frame(&mut client).await,
        1000,
        "upstream EOF must map to a normal WebSocket close"
    );
    assert_eq!(read_to_eof_timeout(&mut client).await, 0);
    runtime.shutdown().await;
}

#[tokio::test]
async fn non_upgrade_requests_are_unaffected() {
    let (dial, _upstream_saw_eof) = spawn_upstream(false).await;
    let (runtime, address) = start(config(&dial, false)).await;

    let mut client = TcpStream::connect(address).await.expect("client connect");
    client
        .write_all(b"GET /plain HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let head = read_http_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(read_exact_timeout(&mut client, b"plain").await, b"plain");
    runtime.shutdown().await;
}

#[tokio::test]
async fn websocket_upgrade_passthrough_over_tls() {
    let (dial, _upstream_saw_eof) = spawn_upstream(false).await;
    let (runtime, address) = start(config(&dial, true)).await;

    // Trust the test certificate and offer only HTTP/1.1: WebSocket upgrade is an HTTP/1.1 feature.
    let mut roots = RootCertStore::empty();
    for certificate in caddy_rs_tls::certificates_from_pem(EXAMPLE_CERT).expect("cert PEM parses") {
        roots.add(certificate).expect("valid root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tcp = TcpStream::connect(address).await.expect("client connect");
    let server_name = ServerName::try_from("example.com").expect("server name");
    let mut client: TlsStream<TcpStream> = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake");

    client
        .write_all(upgrade_request("/ws").as_bytes())
        .await
        .expect("write handshake");
    let head = read_http_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert_eq!(
        header_value(&head, "sec-websocket-accept"),
        Some("test-accept")
    );
    assert_eq!(
        read_exact_timeout(&mut client, b"greeting").await,
        b"greeting"
    );
    client
        .write_all(b"secure")
        .await
        .expect("write after upgrade");
    assert_eq!(read_exact_timeout(&mut client, b"secure").await, b"secure");
    runtime.shutdown().await;
}

#[tokio::test]
async fn plain_h2_connect_without_protocol_is_rejected() {
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let (dial, _upstream_saw_eof) = spawn_upstream(false).await;
    let (runtime, address) = start(config(&dial, false)).await;

    let stream = TcpStream::connect(address).await.expect("client connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("h2c handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    // A plain CONNECT over HTTP/2 (no RFC 8441 `:protocol`) is not WebSocket-over-HTTP/2 and stays
    // loudly rejected; the websocket `:protocol` form is covered by `http2_extended_connect.rs`.
    let request = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("http://{address}/ws"))
        .body(Full::<Bytes>::new(Bytes::new()))
        .expect("request builds");
    let response = sender
        .send_request(request)
        .await
        .expect("CONNECT response");
    assert_eq!(
        response.status(),
        http::StatusCode::NOT_IMPLEMENTED,
        "plain HTTP/2 CONNECT must be rejected with 501"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_upgraded_connections() {
    let (dial, _upstream_saw_eof) = spawn_upstream(false).await;
    let (runtime, address) = start(config(&dial, false)).await;

    let mut client = TcpStream::connect(address).await.expect("client connect");
    client
        .write_all(upgrade_request("/ws").as_bytes())
        .await
        .expect("write handshake");
    let head = read_http_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert_eq!(
        read_exact_timeout(&mut client, b"greeting").await,
        b"greeting"
    );

    // Shutting the runtime down must send a going-away close frame to the WebSocket client (so it
    // sees a clean close handshake rather than 1006) and then close the tunnelled connection.
    runtime.shutdown().await;
    assert_eq!(
        read_close_frame(&mut client).await,
        1001,
        "graceful shutdown must send a going-away WebSocket close"
    );
    assert_eq!(
        read_to_eof_timeout(&mut client).await,
        0,
        "shutdown must close the upgraded client connection"
    );
}

/// An HTTP upgrade that is not a real WebSocket handshake (no `Sec-WebSocket-Key`) must stay
/// byte-transparent: no close frame is synthesised, so the client sees the upstream bytes followed
/// directly by EOF.
#[tokio::test]
async fn non_websocket_upgrade_gets_no_close_frame() {
    let (dial, _upstream_saw_eof) = spawn_upstream(true).await;
    let (runtime, address) = start(config(&dial, false)).await;

    let mut client = TcpStream::connect(address).await.expect("client connect");
    client
        .write_all(
            b"GET /custom HTTP/1.1\r\n\
              Host: example.com\r\n\
              Connection: keep-alive, Upgrade\r\n\
              Upgrade: custom-protocol\r\n\
              \r\n",
        )
        .await
        .expect("write handshake");
    let head = read_http_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert_eq!(
        read_exact_timeout(&mut client, b"greeting").await,
        b"greeting"
    );
    // Upstream EOF immediately: the tunnel must not inject a WebSocket close frame.
    assert_eq!(
        read_to_eof_timeout(&mut client).await,
        0,
        "a non-WebSocket upgrade must remain byte-transparent"
    );
    runtime.shutdown().await;
}
