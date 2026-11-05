//! Integration tests for per-server limits/timeouts (T-HTTP-013) and h2c (T-HTTP-012).
//!
//! These tests use real TCP listeners and real HTTP clients so the hyper connection boundary is
//! exercised end to end: oversized bodies, idle connections, stalled reads, connection caps, and
//! HTTP/1.1 + HTTP/2 prior-knowledge coexistence on one listener.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A one-server HTTP config with the given extra server fields merged in.
fn test_config(server_fields: serde_json::Value) -> Config {
    let mut server = serde_json::json!({
        "listen": ["127.0.0.1:0"],
        "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
    });
    let base = server.as_object_mut().expect("server object is an object");
    for (name, value) in server_fields
        .as_object()
        .expect("server fields are an object")
    {
        base.insert(name.clone(), value.clone());
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": server}}}
    }))
    .expect("test config decodes")
}

/// Start a runtime serving one server with `server_fields`.
async fn start(
    server_fields: serde_json::Value,
) -> (Arc<GenerationStore>, ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(test_config(server_fields))
        .expect("test config validates and loads");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener is bound");
    (store, runtime, address)
}

/// A fresh legacy hyper client request. A new client per call keeps connection reuse out of the
/// assertions.
async fn http_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> (u16, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{address}{path}"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::copy_from_slice(body.unwrap_or(b""))))
        .expect("valid request");
    let response = client.request(request).await.expect("request completes");
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    (status, body)
}

/// Read until EOF or `deadline` elapses, returning everything received.
async fn read_until_close(stream: &mut TcpStream, duration: Duration) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + duration;
    let mut collected = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(count)) => collected.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) | Err(_) => break,
        }
    }
    collected
}

#[tokio::test]
async fn oversized_content_length_body_returns_413() {
    let (_store, runtime, address) = start(serde_json::json!({
        "max_request_body_size": 8
    }))
    .await;

    // Body within the limit is served normally.
    let (status, _) = http_request(address, "POST", "/", Some(b"12345678")).await;
    assert_eq!(status, 200, "a body exactly at the limit must be served");

    // Oversized body: the limit is applied before the handler runs.
    let (status, body) = http_request(address, "POST", "/", Some(&[b'x'; 64])).await;
    assert_eq!(status, 413, "oversized body must return 413");
    assert_eq!(body, Bytes::from_static(b"413 Request Entity Too Large"));

    runtime.shutdown().await;
}

#[tokio::test]
async fn oversized_chunked_body_returns_413() {
    let (_store, runtime, address) = start(serde_json::json!({
        "max_request_body_size": 8
    }))
    .await;

    // No Content-Length: the limit must still apply while decoding the chunked body.
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let request = "POST / HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Transfer-Encoding: chunked\r\n\
                   \r\n\
                   a\r\n0123456789\r\n\
                   0\r\n\r\n";
    let _ = stream.write_all(request.as_bytes()).await;
    let response = read_until_close(&mut stream, Duration::from_secs(2)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 413"),
        "expected 413 for an oversized chunked body, got: {response:?}"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn idle_connection_is_closed() {
    let (_store, runtime, address) = start(serde_json::json!({
        "idle_timeout": "150ms"
    }))
    .await;

    // 1. A connection that never sends a request is closed after the idle timeout.
    let mut idle = TcpStream::connect(address).await.expect("connect");
    let started = std::time::Instant::now();
    let mut buffer = [0_u8; 16];
    let outcome = tokio::time::timeout(Duration::from_secs(3), idle.read(&mut buffer)).await;
    match outcome {
        Ok(Ok(0)) => {}
        other => panic!("idle connection was not closed cleanly: {other:?}"),
    }
    assert!(
        started.elapsed() >= Duration::from_millis(80),
        "connection closed before the configured idle timeout: {:?}",
        started.elapsed()
    );

    // 2. A keep-alive connection is closed after the last response.
    let mut keep_alive = TcpStream::connect(address).await.expect("connect");
    keep_alive
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n")
        .await
        .expect("write request");
    let response = read_until_close(&mut keep_alive, Duration::from_secs(3)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected a 200 response, got: {response:?}"
    );
    assert!(
        response.contains("ok"),
        "expected the response body, got: {response:?}"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn read_timeout_closes_stalled_request() {
    let (_store, runtime, address) = start(serde_json::json!({
        "read_timeout": "150ms"
    }))
    .await;

    let mut stream = TcpStream::connect(address).await.expect("connect");
    // Send an incomplete request head and then stall: the server must abort the connection.
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
        .await
        .expect("write partial request");
    let mut buffer = [0_u8; 16];
    let outcome = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await;
    match outcome {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("stalled read was not aborted: {other:?}"),
    }

    runtime.shutdown().await;
}

#[tokio::test]
async fn malformed_timeout_and_limits_fail_validation_with_located_error() {
    // T-HTTP-042: malformed caddy.Duration/numeric server limits fail at load/validation instead
    // of being deferred to apply (DIV-0039 residual).
    for (fields, field) in [
        (serde_json::json!({"read_timeout": "soon"}), "read_timeout"),
        (serde_json::json!({"idle_timeout": 1.5}), "idle_timeout"),
        (
            serde_json::json!({"max_request_body_size": "1MiB"}),
            "max_request_body_size",
        ),
    ] {
        let store = Arc::new(GenerationStore::with_builtin_registry());
        let error = store
            .load(test_config(fields.clone()))
            .expect_err("a malformed server limit must fail validation");
        let message = error.to_string();
        assert!(
            message.contains(&format!("apps.http.servers.srv0.{field}")),
            "error for {fields} must name the offending field, got: {message}"
        );
    }
}

#[tokio::test]
async fn string_and_nanosecond_timeouts_are_accepted() {
    // Caddy JSON accepts both spellings; both must reach the connection boundary.
    let (_store, runtime, address) = start(serde_json::json!({
        "read_timeout": 5_000_000_000_i64,
        "write_timeout": "2s",
        "idle_timeout": "1m"
    }))
    .await;
    let (status, body) = http_request(address, "GET", "/", None).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"ok"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn max_connections_is_enforced_per_listener() {
    let (_store, runtime, address) = start(serde_json::json!({
        "max_connections": 1
    }))
    .await;

    // Hold the only slot with an idle connection.
    let held = TcpStream::connect(address).await.expect("first connect");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The second connection is accepted by the kernel but closed without a response.
    let mut rejected = TcpStream::connect(address).await.expect("second connect");
    let _ = rejected
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await;
    let mut buffer = [0_u8; 32];
    match tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut buffer)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("connection above max_connections was not closed: {other:?}"),
    }

    // Releasing the slot lets the listener serve again.
    drop(held);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut served = false;
    while std::time::Instant::now() < deadline {
        let mut stream = TcpStream::connect(address).await.expect("retry connect");
        let _ = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await;
        let response = read_until_close(&mut stream, Duration::from_millis(500)).await;
        if String::from_utf8_lossy(&response).contains("200 OK") {
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        served,
        "listener did not serve again after the held connection was released"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn http1_and_h2c_share_one_listener() {
    let (_store, runtime, address) = start(serde_json::json!({})).await;

    // 1. HTTP/1.1 on the listener.
    let (status, body) = http_request(address, "GET", "/", None).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"ok"));

    // 2. HTTP/2 with prior knowledge (h2c) on the same listener: no TLS, no upgrade.
    let stream = TcpStream::connect(address).await.expect("h2 connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("h2c prior-knowledge handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://{address}/"))
        .header(http::header::HOST, "example.com")
        .body(Full::<Bytes>::new(Bytes::new()))
        .expect("valid h2 request");
    let response = sender.send_request(request).await.expect("h2 request");
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(response.status(), 200);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("h2 body")
        .to_bytes();
    assert_eq!(body, Bytes::from_static(b"ok"));

    // 3. HTTP/1.1 still works on the same listener after the h2 connection.
    let (status, body) = http_request(address, "GET", "/", None).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"ok"));

    runtime.shutdown().await;
}

#[tokio::test]
async fn h2c_upgrade_offer_is_served_as_http1_without_h2c_protocol() {
    // Caddy's default protocols do not include h2c, so a cleartext listener serves an
    // `Upgrade: h2c` offer as ordinary HTTP/1.1 (200), not 101.
    let (_store, runtime, address) = start(serde_json::json!({})).await;
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let request = "GET / HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Connection: Upgrade, HTTP2-Settings\r\n\
                   Upgrade: h2c\r\n\
                   HTTP2-Settings: AAMAAABkAAQAAP__\r\n\
                   \r\n";
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write h2c offer");
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .expect("response head timeout")
            .expect("read response byte");
        assert!(read > 0, "connection closed before the response head");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "expected ordinary HTTP/1.1 200 without h2c protocols, got: {head:?}"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn body_limit_is_per_server() {
    // Two servers on distinct listeners with different body caps. The request is identical; only
    // the owning server's configuration decides the outcome.
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a free port");
    let open_port = reserved.local_addr().expect("reserved address").port();
    drop(reserved);
    let open_listen = format!("127.0.0.1:{open_port}");

    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(
            Config::from_value(serde_json::json!({
                "admin": {"disabled": true},
                "apps": {"http": {"servers": {
                    "strict": {
                        "listen": ["127.0.0.1:0"],
                        "max_request_body_size": 8,
                        "routes": [{"handle": [{"handler": "static_response", "body": "strict"}]}]
                    },
                    "open": {
                        "listen": [open_listen],
                        "routes": [{"handle": [{"handler": "static_response", "body": "open"}]}]
                    }
                }}}
            }))
            .expect("two-server config decodes"),
        )
        .expect("two-server config loads");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let strict_address = runtime
        .listener_address("127.0.0.1:0")
        .expect("strict listener bound");
    let open_address = runtime
        .listener_address(&open_listen)
        .expect("open listener bound");

    let body = [b'x'; 64];
    let (status, _) = http_request(strict_address, "POST", "/", Some(&body)).await;
    assert_eq!(status, 413, "the strict server must reject the body");
    let (status, body) = http_request(open_address, "POST", "/", Some(&body)).await;
    assert_eq!(status, 200, "the open server must accept the same body");
    assert_eq!(body, Bytes::from_static(b"open"));

    runtime.shutdown().await;
}

#[tokio::test]
async fn reload_applies_new_limits_to_existing_listener() {
    let (_store, runtime, address) = start(serde_json::json!({
        "max_request_body_size": 8
    }))
    .await;
    let body = [b'x'; 64];
    let (status, _) = http_request(address, "POST", "/", Some(&body)).await;
    assert_eq!(status, 413);

    // Reload the same listener with a looser body cap; the listener is reused (no rebind) and the
    // new generation's limits apply to subsequent connections.
    _store
        .load(test_config(serde_json::json!({
            "max_request_body_size": 128
        })))
        .expect("reload config loads");
    let mut runtime = runtime;
    runtime.apply().await.expect("reload applies");
    assert_eq!(
        runtime.listener_address("127.0.0.1:0"),
        Some(address),
        "the listener must be reused across the reload"
    );
    let (status, _) = http_request(address, "POST", "/", Some(&body)).await;
    assert_eq!(status, 200, "the reloaded body cap must apply");
    runtime.shutdown().await;
}

#[tokio::test]
async fn oversized_header_is_rejected() {
    let (_store, runtime, address) = start(serde_json::json!({
        "max_header_bytes": 1024
    }))
    .await;

    let mut stream = TcpStream::connect(address).await.expect("connect");
    let request = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: {}\r\n\r\n",
        "a".repeat(4096)
    );
    let _ = stream.write_all(request.as_bytes()).await;
    let response = read_until_close(&mut stream, Duration::from_secs(2)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "an oversized request head must not be served, got: {response:?}"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn h2c_upgrade_switches_to_http2() {
    // Caddy serves h2c via the HTTP/1.1 Upgrade mechanism (T-HTTP-022) only when the server's
    // `protocols` explicitly include `h2c`: answer 101 with Connection/Upgrade headers, then speak
    // HTTP/2 on the upgraded stream. A real h2 client completes the upgrade and exchanges requests
    // over the switched protocol.
    let (_store, runtime, address) = start(serde_json::json!({"protocols": ["h2c"]})).await;

    let mut stream = TcpStream::connect(address).await.expect("connect");
    let request = "GET / HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Connection: Upgrade, HTTP2-Settings\r\n\
                   Upgrade: h2c\r\n\
                   HTTP2-Settings: AAMAAABkAAQAAP__\r\n\
                   \r\n";
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write h2c upgrade request");

    // Read exactly the response head (byte-by-byte) so bytes of the subsequent HTTP/2 server
    // preface are not consumed.
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .expect("upgrade response head timeout")
            .expect("read upgrade response byte");
        assert!(read > 0, "connection closed before the 101 response");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols"),
        "expected a 101 upgrade response, got: {head:?}"
    );
    assert!(
        head.to_ascii_lowercase().contains("upgrade: h2c"),
        "missing Upgrade: h2c header: {head:?}"
    );
    assert!(
        head.to_ascii_lowercase().contains("connection: upgrade"),
        "missing Connection: Upgrade header: {head:?}"
    );

    // The client performs its HTTP/2 handshake on the upgraded stream and issues a request.
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("HTTP/2 handshake after h2c upgrade");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://{address}/"))
        .header(http::header::HOST, "example.com")
        .body(Full::<Bytes>::new(Bytes::new()))
        .expect("valid h2 request");
    let response = sender.send_request(request).await.expect("h2c request");
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(response.status(), 200);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("h2c body")
        .to_bytes();
    assert_eq!(body, Bytes::from_static(b"ok"));

    runtime.shutdown().await;
}
