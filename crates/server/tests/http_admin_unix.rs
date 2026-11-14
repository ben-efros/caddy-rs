//! Integration tests for the Unix-domain-socket admin listener.
//!
//! Covers the acceptance matrix for `admin.listen: "unix/<absolute path>"`: the admin API answers
//! over the socket, the socket is owner-only, requests without an `Origin` header are allowed,
//! reload and stop work through the socket, TCP<->Unix transitions clean up socket files, and
//! concurrent requests are served.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

fn config_with_admin(admin: serde_json::Value, body: &str) -> Config {
    Config::from_value(serde_json::json!({
        "admin": admin,
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": body}]}]
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

/// Send one HTTP/1.1 request over the admin Unix socket and return `(status, body)`.
///
/// No `Origin` header is sent: Caddy (and caddy-rs) disable origin/host enforcement for Unix
/// sockets, so these requests must be allowed.
async fn unix_request(
    path: &Path,
    method: &str,
    target: &str,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = UnixStream::connect(path)
        .await
        .expect("connect to admin socket");
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8_lossy(&response).to_string();
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .expect("status code");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

async fn apply_with_admin(
    admin: serde_json::Value,
    body: &str,
) -> (Arc<GenerationStore>, ServerRuntime) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config_with_admin(admin, body))
        .expect("generation loads");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    (store, runtime)
}

#[tokio::test]
async fn serves_the_admin_api_over_a_unix_socket() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (configured, path) = unix_admin(directory.path());
    let (store, runtime) = apply_with_admin(serde_json::json!({"listen": configured}), "ok").await;
    assert_eq!(store.current().expect("active generation").id(), 1);

    wait_for_socket(&path).await;
    let (status, body) = unix_request(&path, "GET", "/config/", None).await;
    assert_eq!(status, 200, "GET /config/ over the Unix socket: {body}");
    let served: serde_json::Value = serde_json::from_str(&body).expect("config JSON");
    assert_eq!(
        served["apps"]["http"]["servers"]["srv0"]["listen"][0],
        "127.0.0.1:0"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn socket_file_is_owner_only() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (configured, path) = unix_admin(directory.path());
    let (_store, runtime) = apply_with_admin(serde_json::json!({"listen": configured}), "ok").await;
    wait_for_socket(&path).await;
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "admin socket is owner-only, got {mode:o}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn requests_without_an_origin_header_are_allowed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (configured, path) = unix_admin(directory.path());
    let (store, mut runtime) =
        apply_with_admin(serde_json::json!({"listen": configured}), "before").await;
    wait_for_socket(&path).await;

    // A state-changing request with no Origin header: the Unix transport disables origin checks.
    let updated = config_with_admin(
        serde_json::json!({"listen": format!("unix/{}", path.display())}),
        "after",
    );
    let updated = String::from_utf8(updated.to_vec().expect("config JSON")).expect("utf8 config");
    let (status, body) = unix_request(&path, "POST", "/load", Some(&updated)).await;
    assert_eq!(status, 200, "POST /load without Origin: {body}");
    assert_eq!(store.current().expect("new generation").id(), 2);
    runtime.apply().await.expect("reload applies");
    runtime.shutdown().await;
}

#[tokio::test]
async fn reload_and_stop_work_over_the_unix_socket() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (configured, path) = unix_admin(directory.path());
    let (store, runtime) =
        apply_with_admin(serde_json::json!({"listen": configured}), "before").await;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let supervisor = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    wait_for_socket(&path).await;

    let updated = config_with_admin(
        serde_json::json!({"listen": format!("unix/{}", path.display())}),
        "after",
    );
    let updated = String::from_utf8(updated.to_vec().expect("config JSON")).expect("utf8 config");
    let (status, body) = unix_request(&path, "POST", "/load", Some(&updated)).await;
    assert_eq!(status, 200, "POST /load over the Unix socket: {body}");

    // The supervisor applies the new generation asynchronously; poll the admin API until the
    // served configuration reflects it.
    let mut reloaded = false;
    for _ in 0..500 {
        let (status, body) = unix_request(&path, "GET", "/config/", None).await;
        assert_eq!(status, 200, "GET /config/ after reload: {body}");
        if body.contains("after") {
            reloaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        reloaded,
        "the reloaded configuration is served over the socket"
    );
    assert_eq!(store.current().expect("generation after reload").id(), 2);

    let (status, body) = unix_request(&path, "POST", "/stop", None).await;
    assert_eq!(status, 200, "POST /stop over the Unix socket: {body}");
    let result = tokio::time::timeout(Duration::from_secs(15), supervisor)
        .await
        .expect("the runtime loop exits after /stop")
        .expect("supervisor task joins");
    result.expect("runtime run succeeds");
    assert!(
        !path.exists(),
        "the Unix socket file is removed when the runtime exits after /stop"
    );
}

#[tokio::test]
async fn reload_unix_to_tcp_to_unix_cleans_up_socket_files() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (first_configured, first_path) = unix_admin(directory.path());
    let second_path = directory.path().join("admin-2.sock");
    let second_configured = format!("unix/{}", second_path.display());
    let (store, mut runtime) =
        apply_with_admin(serde_json::json!({"listen": first_configured}), "ok").await;
    wait_for_socket(&first_path).await;

    // Unix -> TCP: the socket file must be removed and the admin API must answer on TCP.
    store
        .load(config_with_admin(
            serde_json::json!({"listen": "127.0.0.1:0"}),
            "ok",
        ))
        .expect("TCP generation loads");
    runtime.apply().await.expect("reload to TCP applies");
    assert!(
        !first_path.exists(),
        "Unix socket removed when admin moves to TCP"
    );
    assert!(
        runtime.admin_address().is_some(),
        "TCP admin listener bound"
    );
    assert!(runtime.admin_address().is_some());

    // TCP -> Unix (a different path): the new socket must exist and serve.
    store
        .load(config_with_admin(
            serde_json::json!({"listen": second_configured}),
            "ok",
        ))
        .expect("Unix generation loads");
    runtime.apply().await.expect("reload back to Unix applies");
    wait_for_socket(&second_path).await;
    assert!(
        runtime.admin_address().is_none(),
        "TCP admin listener stopped"
    );
    let (status, body) = unix_request(&second_path, "GET", "/config/", None).await;
    assert_eq!(status, 200, "the new Unix socket serves: {body}");
    runtime.shutdown().await;
    assert!(!second_path.exists(), "socket removed on shutdown");
}

#[tokio::test]
async fn ten_concurrent_requests_over_the_unix_socket_all_succeed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (configured, path) = unix_admin(directory.path());
    let (_store, runtime) = apply_with_admin(serde_json::json!({"listen": configured}), "ok").await;
    wait_for_socket(&path).await;

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let socket = path.clone();
        tasks.push(tokio::spawn(async move {
            unix_request(&socket, "GET", "/config/", None).await
        }));
    }
    for task in tasks {
        let (status, body) = task.await.expect("concurrent request joins");
        assert_eq!(status, 200, "concurrent GET /config/: {body}");
        assert!(
            body.contains("\"apps\""),
            "concurrent response is the config: {body}"
        );
    }
    runtime.shutdown().await;
}
