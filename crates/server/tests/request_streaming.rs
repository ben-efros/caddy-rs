//! Request-body streaming model integration tests (T-PROXY-039 sub-wave: http + server).
//!
//! These tests use real TCP listeners so they exercise the hyper connection boundary:
//!
//! * a request with a declared (large) body is dispatched to the handler before the client sends
//!   the body, proving the server no longer collects `hyper::body::Incoming` on the streaming
//!   path;
//! * a chunked request without a configured body limit is likewise not buffered before dispatch;
//! * a declared oversized body is rejected with `413` before any body bytes are read;
//! * the compatibility path is preserved: routes containing `reverse_proxy` still receive the
//!   complete buffered request body (proxy request streaming is the T-PROXY-004 follow-up).
//!
//! Chunked bodies with a configured `max_request_body_size` keep the bounded buffered path so the
//! limit can be enforced before dispatch (existing `http_limits.rs` coverage).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A one-server HTTP config with the given extra server fields merged in.
fn test_config(server_fields: Value) -> Config {
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
async fn start(server_fields: Value) -> (Arc<GenerationStore>, ServerRuntime, SocketAddr) {
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

/// Read up to `limit` bytes with a timeout; returns everything received (possibly empty).
async fn read_with_timeout(stream: &mut TcpStream, limit: usize, timeout: Duration) -> Vec<u8> {
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buffer = [0_u8; 4096];
    while collected.len() < limit {
        match tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(count)) => collected.extend_from_slice(&buffer[..count]),
            Ok(Err(_)) | Err(_) => break,
        }
    }
    collected
}

/// Send a raw request and read the response head/body until the connection is idle.
async fn raw_request(address: SocketAddr, request: &[u8], timeout: Duration) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.write_all(request).await.expect("write request");
    read_with_timeout(&mut stream, 64 * 1024, timeout).await
}

#[tokio::test]
async fn declared_body_is_dispatched_before_the_client_sends_it() {
    let (_store, runtime, address) = start(serde_json::json!({})).await;

    // A declared body that is never sent: the handler must still run. The server previously
    // collected the whole body before dispatch, so this request would have stalled.
    let request = "POST /upload HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Content-Length: 4194304\r\n\
                   \r\n";
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write head");
    let response = read_with_timeout(&mut stream, 1024, Duration::from_secs(2)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "handler must respond without the request body being sent; got: {response:?}"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn chunked_body_without_a_limit_is_not_buffered_before_dispatch() {
    let (_store, runtime, address) = start(serde_json::json!({})).await;

    let request = "POST /upload HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Transfer-Encoding: chunked\r\n\
                   \r\n";
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write head");
    let response = read_with_timeout(&mut stream, 1024, Duration::from_secs(2)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "handler must respond without chunked body chunks; got: {response:?}"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn declared_oversized_body_is_rejected_before_any_body_bytes_are_read() {
    let (_store, runtime, address) = start(serde_json::json!({
        "max_request_body_size": 8
    }))
    .await;

    // Declared length over the limit: 413 without waiting for (or reading) the body.
    let request = "POST / HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Content-Length: 1048576\r\n\
                   \r\n";
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write head");
    let response = read_with_timeout(&mut stream, 1024, Duration::from_secs(2)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 413"),
        "expected 413 before body bytes are read; got: {response:?}"
    );

    runtime.shutdown().await;
}

/// Minimal HTTP/1.1 upstream that records the request body and answers with its length.
async fn spawn_body_recording_upstream() -> (String, Arc<tokio::sync::Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let address = listener.local_addr().expect("upstream address");
    let recorded: Arc<tokio::sync::Mutex<Vec<u8>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let recorded_for_task = Arc::clone(&recorded);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                return;
            };
            let recorded = Arc::clone(&recorded_for_task);
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0_u8; 4096];
                // Read until the end of the headers.
                let header_end = loop {
                    if let Some(position) = find_subslice(&buffer, b"\r\n\r\n") {
                        break position + 4;
                    }
                    match stream.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(count) => buffer.extend_from_slice(&chunk[..count]),
                        Err(_) => return,
                    }
                };
                let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while buffer.len() < header_end + content_length {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(count) => buffer.extend_from_slice(&chunk[..count]),
                        Err(_) => break,
                    }
                }
                let body = buffer[header_end..].to_vec();
                let body_len = body.len();
                *recorded.lock().await = body;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nreceived={body_len}",
                    11 + body_len.to_string().len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (format!("{address}"), recorded)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[tokio::test]
async fn proxy_route_receives_the_complete_buffered_request_body() {
    let (upstream, recorded) = spawn_body_recording_upstream().await;
    let (_store, runtime, address) = start(serde_json::json!({
        "routes": [{
            "handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": upstream}]
            }]
        }]
    }))
    .await;

    // The reverse proxy consumes `request.body` on the buffered compatibility path; the server must
    // therefore buffer before dispatch for routers containing it (T-PROXY-004 streams this later).
    let body = "0123456789".repeat(256);
    let request = format!(
        "POST /echo HTTP/1.1\r\n\
         Host: example.com\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    let response = raw_request(address, request.as_bytes(), Duration::from_secs(5)).await;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "proxy request must succeed; got: {response:?}"
    );
    assert!(
        response.contains(&format!("received={}", body.len())),
        "upstream must report the full body length; got: {response:?}"
    );
    assert_eq!(*recorded.lock().await, body.as_bytes());

    runtime.shutdown().await;
}
