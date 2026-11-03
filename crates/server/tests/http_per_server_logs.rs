//! End-to-end per-server access-log association tests (T-CONF-030).
//!
//! Caddy's `apps.http.servers.<name>.logs` (`ServerLogConfig`) decides which access logger a
//! request host maps to and whether entries are skipped; the global `logging.logs[]` sinks still
//! decide where entries are written. Every test configures a file sink, drives real requests
//! through a real listener, and inspects the emitted JSON lines.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// One HTTP server returning `"ok"`, a file access-log sink, and optional per-server `logs`.
fn config(log_path: &Path, server_logs: Option<serde_json::Value>) -> Config {
    let mut server = serde_json::json!({
        "listen": ["127.0.0.1:0"],
        "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
    });
    if let Some(logs) = server_logs {
        server["logs"] = logs;
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "logging": {"logs": {"default": {
            "writer": {"output": "file", "filename": log_path.to_string_lossy()},
            "encoder": {"format": "json"}
        }}},
        "apps": {"http": {"servers": {"srv0": server}}}
    }))
    .expect("test config decodes")
}

async fn start(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (runtime, address)
}

async fn get(address: SocketAddr, host: &str) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .uri(format!("http://{address}/path"))
        .header(http::header::HOST, host)
        .body(Full::new(Bytes::new()))
        .expect("valid request");
    let response = client.request(request).await.expect("request completes");
    let status = response.status();
    let _ = response.into_body().collect().await.expect("body");
    assert_eq!(status, 200, "request to {host} succeeds");
}

fn read_loggers(path: &Path) -> Vec<String> {
    let contents = std::fs::read(path).expect("access log exists");
    String::from_utf8_lossy(&contents)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: serde_json::Value =
                serde_json::from_str(line).expect("access log line is JSON");
            value["logger"]
                .as_str()
                .expect("access entry has a logger name")
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn logger_names_route_hosts_to_named_loggers() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("access.log");
    let (runtime, address) = start(config(
        &path,
        Some(serde_json::json!({
            "logger_names": {"mapped.example.com": ["site"]}
        })),
    ))
    .await;

    get(address, "mapped.example.com").await;
    get(address, "other.example.com").await;
    runtime.shutdown().await;

    let loggers = read_loggers(&path);
    assert_eq!(
        loggers,
        vec![
            "http.log.access.site".to_string(),
            // Unmapped hosts use the empty default logger name, i.e. the base access logger.
            "http.log.access".to_string(),
        ]
    );
}

#[tokio::test]
async fn logger_names_accept_a_single_string_and_wildcards_with_exact_precedence() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("access.log");
    let (runtime, address) = start(config(
        &path,
        Some(serde_json::json!({
            "logger_names": {
                "*.example.com": "wildcard",
                "exact.example.com": ["exact"]
            }
        })),
    ))
    .await;

    get(address, "app.example.com").await;
    // Exact host wins over the wildcard pattern (Caddy's getLoggerHosts tries exact first).
    get(address, "exact.example.com").await;
    runtime.shutdown().await;

    let loggers = read_loggers(&path);
    assert_eq!(
        loggers,
        vec![
            "http.log.access.wildcard".to_string(),
            "http.log.access.exact".to_string(),
        ]
    );
}

#[tokio::test]
async fn skip_hosts_suppresses_only_matching_hosts() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("access.log");
    let (runtime, address) = start(config(
        &path,
        Some(serde_json::json!({
            "skip_hosts": ["*.skip.example.com"]
        })),
    ))
    .await;

    get(address, "a.skip.example.com").await;
    get(address, "keep.example.com").await;
    runtime.shutdown().await;

    assert_eq!(read_loggers(&path), vec!["http.log.access".to_string()]);
}

#[tokio::test]
async fn skip_unmapped_hosts_drops_hosts_without_a_logger_mapping() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("access.log");
    let (runtime, address) = start(config(
        &path,
        Some(serde_json::json!({
            "skip_unmapped_hosts": true,
            "logger_names": {"mapped.example.com": ["mapped"]}
        })),
    ))
    .await;

    get(address, "unmapped.example.com").await;
    get(address, "mapped.example.com").await;
    runtime.shutdown().await;

    assert_eq!(
        read_loggers(&path),
        vec!["http.log.access.mapped".to_string()]
    );
}

#[tokio::test]
async fn default_logger_name_applies_to_unmapped_hosts() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("access.log");
    let (runtime, address) = start(config(
        &path,
        Some(serde_json::json!({
            "default_logger_name": "fallback"
        })),
    ))
    .await;

    get(address, "anything.example.com").await;
    runtime.shutdown().await;

    assert_eq!(
        read_loggers(&path),
        vec!["http.log.access.fallback".to_string()]
    );
}

#[tokio::test]
async fn multiple_logger_names_emit_one_entry_each() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("access.log");
    let (runtime, address) = start(config(
        &path,
        Some(serde_json::json!({
            "logger_names": {"multi.example.com": ["one", "two"]}
        })),
    ))
    .await;

    get(address, "multi.example.com").await;
    runtime.shutdown().await;

    assert_eq!(
        read_loggers(&path),
        vec![
            "http.log.access.one".to_string(),
            "http.log.access.two".to_string(),
        ]
    );
}

#[tokio::test]
async fn mapped_host_wins_over_skip_hosts() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("access.log");
    let (runtime, address) = start(config(
        &path,
        Some(serde_json::json!({
            "logger_names": {"both.example.com": ["mapped"]},
            "skip_hosts": ["both.example.com"]
        })),
    ))
    .await;

    get(address, "both.example.com").await;
    runtime.shutdown().await;

    // Caddy's shouldLogRequest checks logger_names before skip_hosts: mapped hosts are logged.
    assert_eq!(
        read_loggers(&path),
        vec!["http.log.access.mapped".to_string()]
    );
}

#[tokio::test]
async fn empty_logger_name_selects_the_base_access_logger() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("access.log");
    let (runtime, address) = start(config(
        &path,
        Some(serde_json::json!({
            "logger_names": {"empty.example.com": ["", "named"]}
        })),
    ))
    .await;

    get(address, "empty.example.com").await;
    runtime.shutdown().await;

    assert_eq!(
        read_loggers(&path),
        vec![
            "http.log.access".to_string(),
            "http.log.access.named".to_string(),
        ]
    );
}

#[tokio::test]
async fn absent_per_server_logs_keeps_the_default_association() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("access.log");
    let (runtime, address) = start(config(&path, None)).await;

    get(address, "plain.example.com").await;
    runtime.shutdown().await;

    assert_eq!(read_loggers(&path), vec!["http.log.access".to_string()]);
}
