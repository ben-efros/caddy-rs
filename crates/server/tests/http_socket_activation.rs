//! End-to-end systemd-style socket activation tests (T-HTTP-041).
//!
//! `SocketActivation::from_raw_descriptors` takes already-open listening descriptors and runs the
//! same inspection/matching/adoption path as `SocketActivation::from_env`, without touching the
//! process-global `LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES` environment (which cannot be mutated
//! safely from a multithreaded test binary). The environment parsing itself is unit-tested in
//! `crates/server/src/activation.rs`; this file proves the fd-adoption path end to end: a socket
//! created here and handed to the runtime is served without rebinding.

use std::net::SocketAddr;
use std::os::fd::IntoRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::{ServerRuntime, SocketActivation};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One-server config with the given listen addresses and static-response body.
fn config(listens: &[String], body: &str) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": listens,
            "routes": [{"handle": [{"handler": "static_response", "body": body}]}]
        }}}}
    }))
    .expect("test config decodes")
}

fn store_with(config: Config) -> Arc<GenerationStore> {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates and loads");
    store
}

async fn http_get(address: SocketAddr) -> (u16, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .uri(format!("http://{address}/"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
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

async fn unix_get(path: &std::path::Path) -> String {
    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .expect("connect to Unix listener");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write Unix request");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(count)) => {
                response.extend_from_slice(&chunk[..count]);
                if String::from_utf8_lossy(&response).contains("unix-activated") {
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
    String::from_utf8_lossy(&response).into_owned()
}

fn unique_socket_path(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "caddy-rs-{label}-{}-{nanos}.sock",
        std::process::id()
    ))
}

#[tokio::test]
async fn inherited_tcp_socket_is_served_without_rebinding() {
    // Create a listening socket the way systemd would and pass its descriptor to the runtime.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind inherited socket");
    let address = listener.local_addr().expect("inherited local address");
    let activation =
        SocketActivation::from_raw_descriptors(vec![(listener.into_raw_fd(), Some("http".into()))])
            .expect("valid inherited descriptor");

    let store = store_with(config(&[address.to_string()], "activated"));
    let mut runtime = ServerRuntime::new(Arc::clone(&store)).with_socket_activation(activation);
    runtime.apply().await.expect("runtime applies");

    let configured = address.to_string();
    assert_eq!(
        runtime.listener_address(&configured),
        Some(address),
        "inherited socket address must be served as configured"
    );
    let (status, body) = http_get(address).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"activated"));

    runtime.shutdown().await;
}

#[tokio::test]
async fn inherited_unix_socket_is_served_without_rebinding() {
    let path = unique_socket_path("unix");
    let _ = std::fs::remove_file(&path);
    let listener =
        std::os::unix::net::UnixListener::bind(&path).expect("bind inherited Unix socket");
    let activation = SocketActivation::from_raw_descriptors(vec![(
        listener.into_raw_fd(),
        Some("caddy-unix".into()),
    )])
    .expect("valid inherited Unix descriptor");

    // Caddy listen spelling: `unix/` + absolute path.
    let listen = format!("unix/{}", path.display());
    let store = store_with(config(std::slice::from_ref(&listen), "unix-activated"));
    let mut runtime = ServerRuntime::new(Arc::clone(&store)).with_socket_activation(activation);
    runtime.apply().await.expect("runtime applies");

    assert_eq!(
        runtime.status().listener_address(&listen),
        Some(path.to_string_lossy().as_ref()),
        "Unix listener bound address must be reported"
    );
    let response = unix_get(&path).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected a 200 response over the inherited Unix socket, got: {response:?}"
    );
    assert!(
        response.contains("unix-activated"),
        "expected the activated route body, got: {response:?}"
    );

    runtime.shutdown().await;
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn unmatched_configured_listener_falls_back_to_binding() {
    // One inherited descriptor claims the first listener; the second has no inherited socket and
    // must be bound normally, keeping non-activated behaviour unchanged.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind inherited socket");
    let inherited_address = listener.local_addr().expect("inherited local address");
    let activation =
        SocketActivation::from_raw_descriptors(vec![(listener.into_raw_fd(), Some("http".into()))])
            .expect("valid inherited descriptor");

    let store = store_with(config(
        &[inherited_address.to_string(), "127.0.0.1:0".to_string()],
        "ok",
    ));
    let mut runtime = ServerRuntime::new(Arc::clone(&store)).with_socket_activation(activation);
    runtime.apply().await.expect("runtime applies");

    let bound_address = runtime
        .listener_address("127.0.0.1:0")
        .expect("fallback listener bound a port");
    assert_eq!(
        runtime.listener_address(&inherited_address.to_string()),
        Some(inherited_address)
    );
    assert_ne!(
        bound_address, inherited_address,
        "fallback listener must be a separate socket"
    );

    let (status, body) = http_get(inherited_address).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"ok"));
    let (status, body) = http_get(bound_address).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"ok"));

    runtime.shutdown().await;
}

#[tokio::test]
async fn unclaimed_inherited_socket_fails_apply_loudly() {
    // The inherited socket's address is not configured: applying must fail with a located error
    // instead of silently ignoring a socket the service manager expects us to serve.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind inherited socket");
    let inherited_address = listener.local_addr().expect("inherited local address");
    let activation = SocketActivation::from_raw_descriptors(vec![(
        listener.into_raw_fd(),
        Some("stray".into()),
    )])
    .expect("valid inherited descriptor");

    let store = store_with(config(&["127.0.0.1:1".to_string()], "ok"));
    let mut runtime = ServerRuntime::new(Arc::clone(&store)).with_socket_activation(activation);
    let error = runtime
        .apply()
        .await
        .expect_err("unclaimed inherited socket must fail the apply");
    let message = error.to_string();
    assert!(
        message.contains("socket activation"),
        "error must name socket activation: {message}"
    );
    assert!(
        message.contains("LISTEN_FDS[0]"),
        "error must locate the descriptor: {message}"
    );
    assert!(
        message.contains(&inherited_address.to_string()),
        "error must name the inherited address: {message}"
    );
    assert_eq!(runtime.status().generation_id, None);
}

#[tokio::test]
async fn malformed_inherited_descriptor_fails_loudly() {
    // A connected (non-listening) Unix socket is not a valid activation descriptor.
    let (left, _right) = std::os::unix::net::UnixStream::pair().expect("Unix stream pair");
    let error = SocketActivation::from_raw_descriptors(vec![(left.into_raw_fd(), None)])
        .expect_err("a non-listening descriptor must be rejected");
    assert_eq!(error.path(), "activation_fd[0]");
    assert!(
        error.message().contains("not listening"),
        "error must explain the descriptor state: {error}"
    );

    // A valid descriptor that is not a socket (here: a regular file) is rejected.
    let file = std::fs::File::open(std::env::current_exe().expect("current exe path"))
        .expect("open a regular file");
    let error = SocketActivation::from_raw_descriptors(vec![(file.into_raw_fd(), None)])
        .expect_err("a non-socket descriptor must be rejected");
    assert_eq!(error.path(), "activation_fd[0]");
    assert!(
        error.message().contains("not a socket"),
        "error must explain the descriptor state: {error}"
    );

    // A negative descriptor is rejected before any syscall on it.
    let error = SocketActivation::from_raw_descriptors(vec![(-1, None)])
        .expect_err("an invalid descriptor must be rejected");
    assert_eq!(error.path(), "activation_fd[0]");
    assert!(
        error.message().contains("not a valid file descriptor"),
        "error must explain the descriptor state: {error}"
    );
}

#[tokio::test]
async fn non_activated_runtime_is_unchanged() {
    // Without injected descriptors (and with no LISTEN_* environment in the test process), the
    // runtime binds normally.
    assert!(
        std::env::var_os("LISTEN_FDS").is_none(),
        "test must not run under socket activation"
    );
    let store = store_with(config(&["127.0.0.1:0".to_string()], "plain"));
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    let (status, body) = http_get(address).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"plain"));
    runtime.shutdown().await;
}
