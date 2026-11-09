//! `log_skip` runtime behaviour (T-HTTP-050).
//!
//! Caddy's access logger reads the `log_skip` request variable after the handler chain and skips
//! only the access-log entry (`modules/caddyhttp/server.go:1246-1253`). These tests drive real
//! listeners and assert on the sink output and the metrics endpoint, never on an internal helper.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http::{HeaderMap, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};

fn free_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

async fn request(address: SocketAddr, method: &str, path: &str) -> (StatusCode, HeaderMap, Bytes) {
    request_with_host(address, method, path, "example.com").await
}

async fn request_with_host(
    address: SocketAddr,
    method: &str,
    path: &str,
    host: &str,
) -> (StatusCode, HeaderMap, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{address}{path}"))
        .header(http::header::HOST, host)
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

fn read_log_lines(path: &std::path::Path) -> Vec<Value> {
    let contents = std::fs::read(path).expect("access log exists");
    String::from_utf8_lossy(&contents)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("access log line is JSON"))
        .collect()
}

fn logged_uris(entries: &[Value]) -> Vec<&str> {
    entries
        .iter()
        .filter_map(|entry| entry["request"]["uri"].as_str())
        .collect()
}

fn request_counter(metrics: &str) -> &str {
    metrics
        .lines()
        .find(|line| line.starts_with("caddy_http_requests_total{"))
        .expect("requests counter sample")
}

/// Start a JSON config with one listener and the given routes, access logging to `log_path`, and
/// an ephemeral admin listener for metrics.
fn runtime_config(routes: Value, log_path: &std::path::Path) -> Config {
    Config::from_value(json!({
        "admin": {"listen": "127.0.0.1:0"},
        "logging": {"logs": {"default": {
            "writer": {"output": "file", "filename": log_path.to_string_lossy()},
            "encoder": {"format": "json"},
            "level": "INFO"
        }}},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": routes
        }}}}
    }))
    .expect("test config decodes")
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

#[tokio::test]
async fn caddyfile_log_skip_suppresses_the_matching_entry_but_keeps_metrics() {
    // End to end through the Caddyfile adapter: `log_skip @skip` must emit the vars handler and the
    // runtime must honour it. The unmatched request in the same server must still be logged.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let port = free_loopback_port();
    let caddyfile = format!(
        r#"{{
	admin 127.0.0.1:0
	auto_https off
}}

http://127.0.0.1:{port} {{
	@skip path /skip
	log_skip @skip
	respond "ok"
}}
"#
    );
    let adapted = caddy_rs_config::adapt_with_source(&caddyfile, None)
        .expect("Caddyfile with log_skip adapts");
    // The handler must be the generic vars handler, not a `log_skip` module.
    let routes =
        &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"];
    assert_eq!(
        routes[0]["handle"][0],
        json!({"handler": "vars", "log_skip": true})
    );
    // Attach the file sink directly: the Caddyfile `log` directive's named logger is not needed to
    // prove `log_skip`, and the runtime emits to the default sink in these tests.
    let mut config_value = adapted.config;
    config_value["logging"] = json!({"logs": {"default": {
        "writer": {"output": "file", "filename": log_path.to_string_lossy()},
        "encoder": {"format": "json"},
        "level": "INFO"
    }}});
    let config = Config::from_value(config_value).expect("adapted JSON decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("adapted config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let listen = format!(":{port}");
    runtime
        .listener_address(&listen)
        .expect("Caddyfile listener bound");
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let admin = runtime.admin_address().expect("admin bound");

    let (status, _headers, body) = request_with_host(address, "GET", "/skip", "127.0.0.1").await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"ok"));
    let (status, _headers, body) = request_with_host(address, "GET", "/logged", "127.0.0.1").await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"ok"));

    // Metrics are recorded for both requests, including the skipped one. Caddy skips only the
    // access entry, so the skip must not affect observability counters.
    let (status, _headers, metrics) = request(admin, "GET", "/metrics").await;
    assert_eq!(status, 200);
    let metrics = String::from_utf8_lossy(&metrics).into_owned();
    let counter = request_counter(&metrics);
    assert!(
        counter.trim_end().ends_with(" 2"),
        "both requests must be counted: {counter}"
    );

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert_eq!(
        logged_uris(&entries),
        vec!["/logged"],
        "the skipped request must not produce an access entry, the unmatched one must: {entries:?}"
    );
}

#[tokio::test]
async fn json_vars_log_skip_true_suppresses_the_access_entry() {
    // JSON-only path: a hand-written `vars` handler with the boolean `log_skip: true` must skip,
    // proving the check is on the variable value rather than on the Caddyfile directive.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let config = runtime_config(
        json!([
            {"match": [{"path": ["/skip"]}], "handle": [{"handler": "vars", "log_skip": true}]},
            {"handle": [{"handler": "static_response", "body": "ok"}]}
        ]),
        &log_path,
    );
    let (_store, runtime, address) = start(config).await;

    for path in ["/skip", "/logged"] {
        let (status, _headers, body) = request(address, "GET", path).await;
        assert_eq!(status, 200);
        assert_eq!(body, Bytes::from_static(b"ok"));
    }

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert_eq!(logged_uris(&entries), vec!["/logged"], "{entries:?}");
}

#[tokio::test]
async fn log_skip_inside_an_unmatched_matcher_still_logs() {
    // The vars handler only runs when its matcher matches. A request for another path must be
    // logged even though the server contains a `log_skip` route.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let config = runtime_config(
        json!([
            {"match": [{"path": ["/skip"]}], "handle": [{"handler": "vars", "log_skip": true}]},
            {"handle": [{"handler": "static_response", "body": "ok"}]}
        ]),
        &log_path,
    );
    let (_store, runtime, address) = start(config).await;

    let (status, _headers, _body) = request(address, "GET", "/other").await;
    assert_eq!(status, 200);

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert_eq!(logged_uris(&entries), vec!["/other"], "{entries:?}");
}

#[tokio::test]
async fn the_final_log_skip_value_decides_at_emit_time() {
    // Caddy reads the variable after the whole handler chain. A later vars handler must be able to
    // clear an earlier `true` (logged) or set a later `true` (skipped); a string "true" and a
    // non-scalar value are not the boolean `true` and must not skip.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let config = runtime_config(
        json!([
            {"match": [{"path": ["/true-then-false"]}], "handle": [{"handler": "vars", "log_skip": true}]},
            {"match": [{"path": ["/true-then-false"]}], "handle": [{"handler": "vars", "log_skip": false}]},
            {"match": [{"path": ["/false-then-true"]}], "handle": [{"handler": "vars", "log_skip": false}]},
            {"match": [{"path": ["/false-then-true"]}], "handle": [{"handler": "vars", "log_skip": true}]},
            {"match": [{"path": ["/string-true"]}], "handle": [{"handler": "vars", "log_skip": "true"}]},
            {"match": [{"path": ["/true-then-array"]}], "handle": [{"handler": "vars", "log_skip": true}]},
            {"match": [{"path": ["/true-then-array"]}], "handle": [{"handler": "vars", "log_skip": ["x"]}]},
            {"handle": [{"handler": "static_response", "body": "ok"}]}
        ]),
        &log_path,
    );
    let (_store, runtime, address) = start(config).await;

    for path in [
        "/true-then-false",
        "/false-then-true",
        "/string-true",
        "/true-then-array",
    ] {
        let (status, _headers, _body) = request(address, "GET", path).await;
        assert_eq!(status, 200, "{path}");
    }

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    let mut uris = logged_uris(&entries);
    uris.sort_unstable();
    assert_eq!(
        uris,
        vec!["/string-true", "/true-then-array", "/true-then-false"],
        "the final boolean value decides; a string \"true\" or non-scalar value does not skip: \
         {entries:?}"
    );
}

#[tokio::test]
async fn log_skip_also_suppresses_error_status_entries() {
    // The skip is scoped to access logging, not to successful responses: a 500 response whose
    // route set `log_skip` must not be logged either, while the response itself is unchanged.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let config = runtime_config(
        json!([
            {"match": [{"path": ["/skip-500"]}], "handle": [
                {"handler": "vars", "log_skip": true},
                {"handler": "static_response", "status_code": 500, "body": "boom"}
            ]},
            {"handle": [{"handler": "static_response", "body": "ok"}]}
        ]),
        &log_path,
    );
    let (_store, runtime, address) = start(config).await;

    let (status, _headers, body) = request(address, "GET", "/skip-500").await;
    assert_eq!(status, 500);
    assert_eq!(body, Bytes::from_static(b"boom"));

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert!(entries.is_empty(), "{entries:?}");
}

#[tokio::test]
async fn caddyfile_vars_boolean_spellings_match_the_runtime() {
    // Caddy's `ScalarVal` makes unquoted `TRUE` a boolean (skip) while a quoted "true" stays a
    // string (log). This is the adapter+runtime agreement for the `vars` forms.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let port = free_loopback_port();
    let caddyfile = format!(
        r#"{{
	admin 127.0.0.1:0
	auto_https off
}}

http://127.0.0.1:{port} {{
	@truthy path /truthy
	vars @truthy log_skip TRUE
	@quoted path /quoted
	vars @quoted log_skip "true"
	respond "ok"
}}
"#
    );
    let adapted = caddy_rs_config::adapt_with_source(&caddyfile, None).expect("Caddyfile adapts");
    let mut config_value = adapted.config;
    config_value["logging"] = json!({"logs": {"default": {
        "writer": {"output": "file", "filename": log_path.to_string_lossy()},
        "encoder": {"format": "json"},
        "level": "INFO"
    }}});
    let config = Config::from_value(config_value).expect("adapted JSON decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("adapted config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    runtime
        .listener_address(&format!(":{port}"))
        .expect("listener bound");
    let address = SocketAddr::from(([127, 0, 0, 1], port));

    for path in ["/truthy", "/quoted", "/plain"] {
        let (status, _headers, body) = request_with_host(address, "GET", path, "127.0.0.1").await;
        assert_eq!(status, 200, "{path}");
        assert_eq!(body, Bytes::from_static(b"ok"), "{path}");
    }

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    let mut uris = logged_uris(&entries);
    uris.sort_unstable();
    assert_eq!(uris, vec!["/plain", "/quoted"], "{entries:?}");
}
