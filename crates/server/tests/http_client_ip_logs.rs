//! Access-log `request.client_ip` must be the trusted-proxy-resolved client IP (Caddy's
//! `client_ip` request variable), while `remote_ip`/`remote_port` stay the transport peer.
//!
//! Caddy resolves it once in `PrepareRequest` (`modules/caddyhttp/server.go`:
//! `determineTrustedProxy`) and `LoggableHTTPRequest` logs `GetVar(ClientIPVarKey)`; an untrusted
//! peer resolves to itself, a trusted peer resolves through `client_ip_headers` (bare address, no
//! port), and a Unix-socket peer is `"@"` in Go's `Request.RemoteAddr`.
//!
//! These tests drive real listeners and read the JSON access-log sink.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn log_sink(path: &Path) -> Value {
    serde_json::json!({
        "logs": {"default": {
            "writer": {"output": "file", "filename": path.display().to_string()},
            "encoder": {"format": "json"}
        }}
    })
}

fn server_config(listen: &str, trusted: Option<Value>, unix: bool, log_path: &Path) -> Config {
    let mut server = serde_json::json!({
        "listen": [listen],
        "logs": {},
        "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
    });
    if let Some(trusted) = trusted {
        server["trusted_proxies"] = trusted;
    }
    if unix {
        server["trusted_proxies_unix"] = serde_json::json!(true);
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": server}}},
        "logging": log_sink(log_path)
    }))
    .expect("client-ip logging config decodes")
}

fn read_log_lines(path: &Path) -> Vec<Value> {
    let contents = std::fs::read(path).expect("access log exists");
    String::from_utf8_lossy(&contents)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("access log line is JSON"))
        .collect()
}

async fn start(config: Config) -> (ServerRuntime, Option<SocketAddr>) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(store);
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .status()
        .listeners
        .values()
        .next()
        .and_then(|bound| bound.parse().ok());
    (runtime, address)
}

async fn raw_get(address: SocketAddr, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("client connect");
    let mut request = String::from("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    response
}

#[tokio::test]
async fn trusted_proxy_forwarded_client_ip_is_logged_while_peer_stays_remote_ip() {
    let directory = tempfile::tempdir().unwrap();
    let log_path = directory.path().join("access.log");
    let (runtime, address) = start(server_config(
        "127.0.0.1:0",
        Some(serde_json::json!(["127.0.0.1/32"])),
        false,
        &log_path,
    ))
    .await;
    let address = address.expect("listener bound");

    let response = raw_get(address, &[("X-Forwarded-For", "203.0.113.7")]).await;
    assert!(
        String::from_utf8_lossy(&response).contains("200"),
        "{:?}",
        String::from_utf8_lossy(&response)
    );
    runtime.shutdown().await;

    let entries = read_log_lines(&log_path);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let request = &entries[0]["request"];
    assert_eq!(
        request["client_ip"], "203.0.113.7",
        "trusted proxy must resolve client_ip from X-Forwarded-For: {request}"
    );
    assert_eq!(
        request["remote_ip"], "127.0.0.1",
        "remote_ip must stay the transport peer: {request}"
    );
    assert!(
        request["remote_port"]
            .as_str()
            .is_some_and(|port| !port.is_empty()),
        "remote_port must stay the peer port: {request}"
    );
}

#[tokio::test]
async fn untrusted_peer_logs_its_own_ip_in_client_ip_and_ignores_forwarded_header() {
    let directory = tempfile::tempdir().unwrap();
    let log_path = directory.path().join("access.log");
    let (runtime, address) = start(server_config(
        "127.0.0.1:0",
        Some(serde_json::json!(["192.0.2.0/24"])),
        false,
        &log_path,
    ))
    .await;
    let address = address.expect("listener bound");

    raw_get(address, &[("X-Forwarded-For", "203.0.113.7")]).await;
    runtime.shutdown().await;

    let entries = read_log_lines(&log_path);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let request = &entries[0]["request"];
    assert_eq!(request["client_ip"], "127.0.0.1", "{request}");
    assert_eq!(request["remote_ip"], "127.0.0.1", "{request}");
}

#[tokio::test]
async fn custom_client_ip_header_is_used_for_trusted_proxies() {
    let directory = tempfile::tempdir().unwrap();
    let log_path = directory.path().join("access.log");
    let mut config = server_config(
        "127.0.0.1:0",
        Some(serde_json::json!(["127.0.0.1/32"])),
        false,
        &log_path,
    );
    // Add the Caddy `client_ip_headers` option to the server object.
    let mut value = config.to_value().unwrap();
    value["apps"]["http"]["servers"]["srv0"]["client_ip_headers"] =
        serde_json::json!(["X-Real-IP"]);
    config = Config::from_value(value).expect("config with client_ip_headers");

    let (runtime, address) = start(config).await;
    let address = address.expect("listener bound");
    raw_get(
        address,
        &[
            ("X-Real-IP", "198.51.100.42"),
            ("X-Forwarded-For", "203.0.113.7"),
        ],
    )
    .await;
    runtime.shutdown().await;

    let entries = read_log_lines(&log_path);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["request"]["client_ip"], "198.51.100.42");
    assert_eq!(entries[0]["request"]["remote_ip"], "127.0.0.1");
}

#[cfg(unix)]
#[tokio::test]
async fn trusted_unix_peer_logs_forwarded_ip_and_caddy_unix_remote_ip() {
    let directory = tempfile::tempdir().unwrap();
    let log_path = directory.path().join("access.log");
    let socket_path = directory.path().join("caddy.sock");
    let listen = format!("unix/{}", socket_path.display());
    let (runtime, _) = start(server_config(&listen, None, true, &log_path)).await;

    let mut stream = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("unix connect");
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 198.51.100.9\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write request");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    assert!(String::from_utf8_lossy(&response).contains("200"));
    runtime.shutdown().await;

    let entries = read_log_lines(&log_path);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let request = &entries[0]["request"];
    assert_eq!(
        request["client_ip"], "198.51.100.9",
        "trusted Unix peer must resolve client_ip: {request}"
    );
    // Go's net/http sets RemoteAddr = "@" for Unix-socket peers; Caddy logs "@" with no port.
    assert_eq!(request["remote_ip"], "@", "{request}");
    assert_eq!(request["remote_port"], "", "{request}");
}

#[cfg(unix)]
#[tokio::test]
async fn untrusted_unix_peer_logs_empty_client_ip_and_caddy_unix_remote_ip() {
    let directory = tempfile::tempdir().unwrap();
    let log_path = directory.path().join("access.log");
    let socket_path = directory.path().join("caddy.sock");
    let listen = format!("unix/{}", socket_path.display());
    let (runtime, _) = start(server_config(&listen, None, false, &log_path)).await;

    let mut stream = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("unix connect");
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 198.51.100.9\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write request");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    runtime.shutdown().await;

    let entries = read_log_lines(&log_path);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let request = &entries[0]["request"];
    assert_eq!(
        request["client_ip"], "",
        "untrusted Unix peer resolves to the empty client_ip string, like Caddy: {request}"
    );
    assert_eq!(request["remote_ip"], "@", "{request}");
    assert_eq!(request["remote_port"], "", "{request}");
}
