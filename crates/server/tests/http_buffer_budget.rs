//! Process-wide budget for buffered request bodies.
//!
//! The budget is a process-global, so these tests live in their own test binary: run alongside
//! other body-buffering tests in one process they would compete for it and flake.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
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

/// A server whose only route is a `reverse_proxy` with `retries`, which makes the server buffer
/// the whole request body in memory before dispatch. The upstream is a closed port: the tests only
/// care whether the body is accepted (the proxy then answers 502) or refused (413).
fn buffering_proxy_fields() -> serde_json::Value {
    serde_json::json!({
        "routes": [{"handle": [{
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "127.0.0.1:1"}],
            "load_balancing": {"retries": 1}
        }]}]
    })
}

/// Send a chunked POST of `total` bytes in 1 MiB chunks and return the response head. The write
/// side runs concurrently and tolerates the server closing early, because a server that enforces
/// its limit answers before it has read everything.
async fn post_chunked(address: SocketAddr, total: usize) -> String {
    const CHUNK: usize = 1024 * 1024;
    let stream = TcpStream::connect(address).await.expect("connect");
    let (mut reader, mut writer) = stream.into_split();
    let writer_task = tokio::spawn(async move {
        let head = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        if writer.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let chunk = vec![b'a'; CHUNK];
        let mut sent = 0;
        while sent < total {
            let size = CHUNK.min(total - sent);
            let framed = format!("{size:x}\r\n");
            if writer.write_all(framed.as_bytes()).await.is_err()
                || writer.write_all(&chunk[..size]).await.is_err()
                || writer.write_all(b"\r\n").await.is_err()
            {
                return;
            }
            sent += size;
        }
        let _ = writer.write_all(b"0\r\n\r\n").await;
        // Keep the connection open (no FIN) until the response has been read.
        std::future::pending::<()>().await;
    });
    let mut received = Vec::new();
    let mut buffer = [0_u8; 4096];
    let read = async {
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    received.extend_from_slice(&buffer[..count]);
                    if received.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(60), read).await;
    writer_task.abort();
    String::from_utf8_lossy(&received).into_owned()
}

/// Open a chunked POST of `mib` MiB and leave it unfinished: the server has buffered (and
/// reserved memory for) every byte so far and keeps the connection waiting for the last chunk.
async fn hold_chunked(address: SocketAddr, mib: usize) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let head = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
    let _ = stream.write_all(head.as_bytes()).await;
    let chunk = vec![b'a'; 1024 * 1024];
    for _ in 0..mib {
        if stream.write_all(b"100000\r\n").await.is_err()
            || stream.write_all(&chunk).await.is_err()
            || stream.write_all(b"\r\n").await.is_err()
        {
            break;
        }
    }
    stream
}

/// The per-request cap alone does not bound memory (hundreds of concurrent streams each just under
/// it pin N x cap), so buffered bodies also draw on a process-wide budget: once concurrent
/// in-flight bodies have used it, another buffered request is answered 503 instead of growing the
/// heap. This test genuinely holds about 1 GiB in the server for a moment.
#[tokio::test]
async fn concurrent_buffered_bodies_exhaust_a_process_wide_budget_with_503() {
    let (_store, runtime, address) = start(buffering_proxy_fields()).await;

    // Ten unfinished 100 MiB bodies: each reserves ~200 MiB of the 1 GiB budget, so about five
    // fit and the rest are refused (and release what they had taken).
    let mut holders = Vec::new();
    for _ in 0..10 {
        holders.push(hold_chunked(address, 100).await);
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // The budget now has at most ~24 MiB of body room left; a 30 MiB body cannot fit.
    let refused = post_chunked(address, 30 * 1024 * 1024).await;
    assert!(
        refused.starts_with("HTTP/1.1 503") || (cfg!(windows) && refused.is_empty()),
        "with the budget used up a buffered body must be refused with 503, got: {refused:?}"
    );

    // Releasing the in-flight bodies returns the budget.
    drop(holders);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let accepted = post_chunked(address, 30 * 1024 * 1024).await;
    assert!(
        accepted.starts_with("HTTP/1.1 502"),
        "after the holders disconnect the same body must be accepted, got: {accepted:?}"
    );

    runtime.shutdown().await;
}
