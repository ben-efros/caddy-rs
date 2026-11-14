//! End-to-end tests for the Unix-domain-socket admin listener (`admin.listen: "unix/<path>"`).
//!
//! These drive the real runtime: bind, serve the admin API over the socket, and verify the socket
//! file is removed when the listener moves to another transport, changes path, or the runtime
//! shuts down.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::Full;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

fn config_with_admin(admin: serde_json::Value) -> Config {
    Config::from_value(serde_json::json!({
        "admin": admin,
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
        }}}}
    }))
    .expect("test config decodes")
}

fn unix_admin(directory: &Path) -> (String, PathBuf) {
    let path = directory.join("admin.sock");
    (format!("unix/{}", path.display()), path)
}

async fn wait_for_socket(path: &Path) {
    for _ in 0..500 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("admin socket never appeared at {}", path.display());
}

/// Send one HTTP/1.1 request over the admin Unix socket and return the raw response.
async fn request_over_unix(path: &Path, method: &str, target: &str) -> String {
    let mut stream = UnixStream::connect(path)
        .await
        .expect("connect to admin socket");
    stream
        .write_all(
            format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8_lossy(&response).to_string()
}

async fn request_tcp(address: SocketAddr, method: &str, target: &str) -> u16 {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{address}{target}"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("request builds");
    client
        .request(request)
        .await
        .expect("admin request")
        .status()
        .as_u16()
}

async fn runtime_with_admin(admin: serde_json::Value) -> (Arc<GenerationStore>, ServerRuntime) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config_with_admin(admin))
        .expect("generation loads");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    (store, runtime)
}

#[tokio::test]
async fn unix_admin_serves_the_api_and_the_socket_is_removed_on_shutdown() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (configured, path) = unix_admin(directory.path());
    let (store, runtime) = runtime_with_admin(serde_json::json!({"listen": configured})).await;
    let generation = store.current().expect("active generation").id();
    assert_eq!(generation, 1);

    wait_for_socket(&path).await;
    let response = request_over_unix(&path, "GET", "/config/").await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the admin API answers over the socket: {response}"
    );
    runtime.shutdown().await;
    assert!(
        !path.exists(),
        "the socket file is removed on graceful shutdown"
    );
}

#[tokio::test]
async fn reload_from_unix_to_tcp_removes_the_socket() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (configured, path) = unix_admin(directory.path());
    let (store, mut runtime) = runtime_with_admin(serde_json::json!({"listen": configured})).await;
    wait_for_socket(&path).await;

    store
        .load(config_with_admin(
            serde_json::json!({"listen": "127.0.0.1:0"}),
        ))
        .expect("second generation loads");
    runtime.apply().await.expect("reload applies");
    assert!(
        !path.exists(),
        "the Unix socket is removed when the admin listener moves to TCP"
    );
    let address = runtime.admin_address().expect("TCP admin listener bound");
    assert_eq!(request_tcp(address, "GET", "/config/").await, 200);
    runtime.shutdown().await;
}

#[tokio::test]
async fn reload_from_tcp_to_unix_creates_a_working_socket() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (configured, path) = unix_admin(directory.path());
    let (store, mut runtime) =
        runtime_with_admin(serde_json::json!({"listen": "127.0.0.1:0"})).await;
    assert!(runtime.admin_address().is_some());

    store
        .load(config_with_admin(serde_json::json!({"listen": configured})))
        .expect("second generation loads");
    runtime.apply().await.expect("reload applies");
    wait_for_socket(&path).await;
    assert!(
        runtime.admin_address().is_none(),
        "the TCP admin listener stopped"
    );
    let response = request_over_unix(&path, "GET", "/config/").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    runtime.shutdown().await;
    assert!(!path.exists());
}

#[tokio::test]
async fn reload_between_unix_paths_cleans_the_old_socket() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (first_configured, first_path) = unix_admin(directory.path());
    let second_path = directory.path().join("admin-2.sock");
    let second_configured = format!("unix/{}", second_path.display());
    let (store, mut runtime) =
        runtime_with_admin(serde_json::json!({"listen": first_configured})).await;
    wait_for_socket(&first_path).await;

    store
        .load(config_with_admin(
            serde_json::json!({"listen": second_configured}),
        ))
        .expect("second generation loads");
    runtime.apply().await.expect("reload applies");
    wait_for_socket(&second_path).await;
    assert!(
        !first_path.exists(),
        "the previous Unix socket path is removed on a path change"
    );
    assert!(request_over_unix(&second_path, "GET", "/config/")
        .await
        .starts_with("HTTP/1.1 200"));
    runtime.shutdown().await;
    assert!(!second_path.exists());
}
