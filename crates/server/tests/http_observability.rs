//! End-to-end observability tests (T-ADMIN-024): the runtime wires the admin crate's metrics
//! recorder and access-log sinks into live listeners.
//!
//! Every test uses real TCP listeners and a real hyper client. Assertions are made through the
//! public surfaces the runtime exposes: the admin `GET /metrics` endpoint, the access-log files
//! written by the configured sinks, and `ServerRuntime::apply` returning located errors.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http::{HeaderMap, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// One server returning a fixed body, with the given admin and logging configuration.
fn observability_config(
    admin: serde_json::Value,
    logging: Option<serde_json::Value>,
    body: &str,
) -> Config {
    let mut config = serde_json::json!({
        "admin": admin,
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": body}]}]
        }}}}
    });
    if let Some(logging) = logging {
        config["logging"] = logging;
    }
    Config::from_value(config).expect("test config decodes")
}

async fn start(config: Config) -> (Arc<GenerationStore>, ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (store, runtime, address)
}

async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{address}{path}"))
        .header(http::header::HOST, "example.com");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::new()))
        .expect("valid request");
    let response = client.request(request).await.expect("request completes");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    (status, headers, body)
}

fn read_log_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    let contents = std::fs::read(path).expect("access log exists");
    String::from_utf8_lossy(&contents)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("access log line is JSON"))
        .collect()
}

#[tokio::test]
async fn metrics_endpoint_reflects_live_requests() {
    let (_store, runtime, address) = start(observability_config(
        serde_json::json!({"listen": "127.0.0.1:0"}),
        None,
        "hello",
    ))
    .await;
    let admin = runtime.admin_address().expect("admin bound");

    // Two requests through the real listener.
    for _ in 0..2 {
        let (status, _headers, body) = request(address, "GET", "/", &[]).await;
        assert_eq!(status, 200);
        assert_eq!(body, Bytes::from_static(b"hello"));
    }

    let (status, _headers, metrics) = request(admin, "GET", "/metrics", &[]).await;
    assert_eq!(status, 200);
    let metrics = String::from_utf8_lossy(&metrics).into_owned();

    // Counter, in-flight gauge, latency and size histograms for the live server.
    assert!(
        metrics.contains("caddy_http_requests_total"),
        "missing requests counter:\n{metrics}"
    );
    assert!(
        metrics.contains("server=\"srv0\""),
        "missing server label:\n{metrics}"
    );
    assert!(
        metrics.contains("method=\"GET\""),
        "missing method label:\n{metrics}"
    );
    assert!(
        metrics.contains("code=\"200\""),
        "missing code label:\n{metrics}"
    );
    assert!(
        metrics.contains("caddy_http_requests_in_flight"),
        "missing in-flight gauge:\n{metrics}"
    );
    assert!(
        metrics.contains("caddy_http_request_duration_seconds_bucket"),
        "missing latency histogram:\n{metrics}"
    );
    assert!(
        metrics.contains("caddy_http_response_size_bytes_bucket"),
        "missing response-size histogram:\n{metrics}"
    );
    // The two completed requests are counted. Caddy's requests counter carries only the
    // server/handler labels; method/code live on the latency and size histograms.
    let counter_line = metrics
        .lines()
        .find(|line| line.starts_with("caddy_http_requests_total{"))
        .expect("counter sample line");
    assert!(
        counter_line.trim_end().ends_with(" 2"),
        "expected two recorded requests, got: {counter_line}"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn access_log_file_receives_entry_with_redaction() {
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let logging = serde_json::json!({
        "logs": {
            "default": {
                "writer": {"output": "file", "filename": log_path.to_string_lossy()},
                "encoder": {"format": "json"},
                "level": "INFO"
            }
        }
    });
    let (_store, runtime, address) = start(observability_config(
        serde_json::json!({"disabled": true}),
        Some(logging),
        "hello",
    ))
    .await;
    assert_eq!(runtime.access_log_sink_count(), 1);

    let (status, _headers, _body) = request(
        address,
        "GET",
        "/path?x=1",
        &[
            ("Authorization", "Bearer super-secret"),
            ("Cookie", "session=secret"),
            ("X-Debug", "1"),
        ],
    )
    .await;
    assert_eq!(status, 200);

    // Shutdown flushes the buffered sink.
    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert_eq!(entries.len(), 1, "one access entry per request");
    let entry = &entries[0];
    assert_eq!(entry["level"], "info");
    assert_eq!(entry["logger"], "http.log.access");
    assert_eq!(entry["msg"], "handled request");
    assert_eq!(entry["status"], 200);
    assert_eq!(entry["size"], 5);
    assert!(entry["duration"].is_number());
    assert_eq!(entry["request"]["method"], "GET");
    assert_eq!(entry["request"]["host"], "example.com");
    assert_eq!(entry["request"]["uri"], "/path?x=1");
    assert_eq!(entry["request"]["proto"], "HTTP/1.1");
    assert_eq!(entry["request"]["remote_ip"], "127.0.0.1");
    assert_eq!(entry["request"]["headers"]["X-Debug"][0], "1");
    // Credentials are redacted by default (Caddy's should_log_credentials off).
    assert_eq!(entry["request"]["headers"]["Authorization"][0], "REDACTED");
    assert_eq!(entry["request"]["headers"]["Cookie"][0], "REDACTED");
    // The static_response Content-Type is visible in the response headers.
    assert_eq!(
        entry["resp_headers"]["Content-Type"][0],
        "text/plain; charset=utf-8"
    );
    // Cleartext connection: no TLS object.
    assert!(entry["request"].get("tls").is_none());
}

#[tokio::test]
async fn reload_flushes_and_rebuilds_access_log_sinks() {
    let directory = tempfile::tempdir().expect("tempdir");
    let first_log = directory.path().join("first.log");
    let second_log = directory.path().join("second.log");
    let logging_for = |path: &std::path::Path| {
        serde_json::json!({
            "logs": {
                "default": {
                    "writer": {"output": "file", "filename": path.to_string_lossy()},
                    "encoder": {"format": "json"}
                }
            }
        })
    };

    let (store, mut runtime, address) = start(observability_config(
        serde_json::json!({"disabled": true}),
        Some(logging_for(&first_log)),
        "one",
    ))
    .await;
    assert_eq!(runtime.access_log_sink_count(), 1);
    request(address, "GET", "/", &[]).await;

    // Reload with a different logging file: the apply must flush the old sink and rebuild.
    store
        .load(observability_config(
            serde_json::json!({"disabled": true}),
            Some(logging_for(&second_log)),
            "two",
        ))
        .expect("second config loads");
    runtime.apply().await.expect("reload applies");
    assert_eq!(runtime.access_log_sink_count(), 1);

    // The old sink was flushed during the reload, so the first request is already on disk.
    let old_entries = read_log_lines(&first_log);
    assert_eq!(old_entries.len(), 1, "reload must flush the old sink");
    assert_eq!(old_entries[0]["status"], 200);

    // New requests go to the rebuilt sink; shutdown flushes it.
    request(address, "GET", "/", &[]).await;
    runtime.shutdown().await;
    let new_entries = read_log_lines(&second_log);
    assert_eq!(new_entries.len(), 1, "rebuilt sink receives new entries");
    assert_eq!(
        read_log_lines(&first_log).len(),
        1,
        "old sink is not reused"
    );
}

#[tokio::test]
async fn invalid_logging_config_fails_apply_loudly() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(observability_config(
            serde_json::json!({"disabled": true}),
            Some(serde_json::json!({
                "logs": {
                    "default": {
                        // File writer without a filename: valid Caddy JSON shape for the typed model
                        // and module registry, but the sink cannot be built.
                        "writer": {"output": "file"},
                        "encoder": {"format": "json"}
                    }
                }
            })),
            "hello",
        ))
        .expect("config loads and validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    let error = runtime
        .apply()
        .await
        .expect_err("unbuildable access-log sink must fail the apply");
    let message = error.to_string();
    assert!(
        message.contains("observability configuration"),
        "error must be located to observability: {message}"
    );
    assert!(
        message.contains("logging.logs.default"),
        "error must name the logging path: {message}"
    );
    assert!(
        message.contains("filename"),
        "error must name the offending field: {message}"
    );
    // No listener was published for the failed generation.
    assert!(runtime.listener_address("127.0.0.1:0").is_none());
    runtime.shutdown().await;
}

#[tokio::test]
async fn absent_logging_config_does_not_open_the_default_sink() {
    // A configuration without a `logging` section must not emit access logs (Caddy only logs
    // access entries for explicitly configured servers); the runtime should report zero sinks and
    // serve normally.
    let (_store, runtime, address) = start(observability_config(
        serde_json::json!({"disabled": true}),
        None,
        "plain",
    ))
    .await;
    assert_eq!(runtime.access_log_sink_count(), 0);
    let (status, _headers, body) = request(address, "GET", "/", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"plain"));
    runtime.shutdown().await;
}
