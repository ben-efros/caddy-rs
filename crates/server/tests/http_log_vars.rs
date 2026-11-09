//! Request-scoped access-log controls (`log_skip`, `log_name`, `log_level`) end to end.
//!
//! Caddy stores these as request variables and reads them *after* the handler chain
//! (`modules/caddyhttp/server.go:1246-1282`, `modules/caddyhttp/logging.go:98-112`). caddy-rs
//! captures the request at the connection boundary, so the decision has to travel from the
//! post-routing request into the body-end emission point. Every test here drives a real listener
//! and inspects the JSON lines and levels written by real sinks, so removing the wiring makes the
//! assertions fail rather than taking an internal shortcut.

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
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

fn read_log_lines(path: &Path) -> Vec<Value> {
    let contents = std::fs::read(path).expect("access log exists");
    String::from_utf8_lossy(&contents)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("access log line is JSON"))
        .collect()
}

fn uri_and_logger(entries: &[Value]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|entry| {
            (
                entry["request"]["uri"]
                    .as_str()
                    .expect("entry carries the request uri")
                    .to_string(),
                entry["logger"]
                    .as_str()
                    .expect("entry carries a logger name")
                    .to_string(),
            )
        })
        .collect()
}

fn levels_by_uri(entries: &[Value]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|entry| {
            (
                entry["request"]["uri"]
                    .as_str()
                    .expect("entry carries the request uri")
                    .to_string(),
                entry["level"]
                    .as_str()
                    .expect("entry carries a level")
                    .to_string(),
            )
        })
        .collect()
}

fn file_sink(path: &Path) -> Value {
    json!({
        "writer": {"output": "file", "filename": path.to_string_lossy()},
        "encoder": {"format": "json"},
        "level": "DEBUG"
    })
}

/// Build a JSON config with one HTTP listener, the given routes and `logging.logs` object.
fn runtime_config(logs: Value, routes: Value, server_logs: Option<Value>) -> Config {
    let mut server = json!({
        "listen": ["127.0.0.1:0"],
        "routes": routes
    });
    if let Some(logs) = server_logs {
        server["logs"] = logs;
    }
    Config::from_value(json!({
        "admin": {"disabled": true},
        "logging": {"logs": logs},
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

#[tokio::test]
async fn vars_log_name_routes_the_entry_to_the_named_logger() {
    // Two file sinks: the default log excludes the named logger, the `admin` log is dedicated to
    // `http.log.access.admin`. A request that sets `access_logger_names` goes to the named sink
    // only; a plain request stays on the default logger. A name with no accepting sink is
    // dropped, exactly like Caddy's zap core.
    let directory = tempfile::tempdir().expect("tempdir");
    let default_log = directory.path().join("default.log");
    let admin_log = directory.path().join("admin.log");
    let mut admin_sink = file_sink(&admin_log);
    admin_sink["include"] = json!(["http.log.access.admin"]);
    let mut default_sink = file_sink(&default_log);
    default_sink["exclude"] = json!(["http.log.access.admin", "http.log.access.unconfigured"]);

    let config = runtime_config(
        json!({"default": default_sink, "admin": admin_sink}),
        json!([
            {"match": [{"path": ["/named"]}], "handle": [
                {"handler": "vars", "access_logger_names": ["admin"]},
                {"handler": "static_response", "body": "ok"}
            ]},
            {"match": [{"path": ["/no-sink"]}], "handle": [
                {"handler": "vars", "access_logger_names": ["unconfigured"]},
                {"handler": "static_response", "body": "ok"}
            ]},
            {"handle": [{"handler": "static_response", "body": "ok"}]}
        ]),
        None,
    );
    let (runtime, address) = start(config).await;

    for path in ["/named", "/no-sink", "/plain"] {
        let (status, _headers, body) = request_with_host(address, "GET", path, "example.com").await;
        assert_eq!(status, 200, "{path}");
        assert_eq!(body, Bytes::from_static(b"ok"), "{path}");
    }

    runtime.shutdown().await;
    assert_eq!(
        uri_and_logger(&read_log_lines(&default_log)),
        vec![("/plain".to_string(), "http.log.access".to_string())],
        "the plain request logs normally and the named request must not reach this sink"
    );
    assert_eq!(
        uri_and_logger(&read_log_lines(&admin_log)),
        vec![("/named".to_string(), "http.log.access.admin".to_string())],
        "the explicit logger name selects the dedicated sink"
    );
}

#[tokio::test]
async fn vars_log_name_overrides_the_per_server_host_mapping() {
    // Caddy's `wrapLogger` checks the request variable before the host mapping. A host mapped to
    // `mapped` logs under that logger without the directive, but the explicit list replaces it.
    let directory = tempfile::tempdir().expect("tempdir");
    let default_log = directory.path().join("default.log");
    let mapped_log = directory.path().join("mapped.log");
    let explicit_log = directory.path().join("explicit.log");
    let mut default_sink = file_sink(&default_log);
    default_sink["exclude"] = json!(["http.log.access.mapped", "http.log.access.explicit"]);
    let mut mapped_sink = file_sink(&mapped_log);
    mapped_sink["include"] = json!(["http.log.access.mapped"]);
    let mut explicit_sink = file_sink(&explicit_log);
    explicit_sink["include"] = json!(["http.log.access.explicit"]);

    let config = runtime_config(
        json!({
            "default": default_sink,
            "mapped": mapped_sink,
            "explicit": explicit_sink
        }),
        json!([
            {"match": [{"path": ["/explicit"]}], "handle": [
                {"handler": "vars", "access_logger_names": ["explicit"]},
                {"handler": "static_response", "body": "ok"}
            ]},
            {"handle": [{"handler": "static_response", "body": "ok"}]}
        ]),
        Some(json!({"logger_names": {"mapped.example.com": ["mapped"]}})),
    );
    let (runtime, address) = start(config).await;

    for path in ["/plain", "/explicit"] {
        let (status, _headers, _body) =
            request_with_host(address, "GET", path, "mapped.example.com").await;
        assert_eq!(status, 200, "{path}");
    }

    runtime.shutdown().await;
    assert_eq!(
        uri_and_logger(&read_log_lines(&mapped_log)),
        vec![("/plain".to_string(), "http.log.access.mapped".to_string())],
        "the per-host mapping applies when the request does not set a name"
    );
    assert_eq!(
        uri_and_logger(&read_log_lines(&explicit_log)),
        vec![(
            "/explicit".to_string(),
            "http.log.access.explicit".to_string()
        )],
        "the explicit list wins over the host mapping"
    );
    assert!(
        read_log_lines(&default_log).is_empty(),
        "neither request belongs to the default sink"
    );
}

#[tokio::test]
async fn vars_log_name_cannot_rescue_a_skipped_host() {
    // Caddy's `shouldLogRequest` decides before the handler chain and disables the access logger
    // for a skipped host, so a later `log_name` variable has no effect there. An unmapped host is
    // still logged and does honour the explicit name.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let config = runtime_config(
        json!({"default": file_sink(&log_path)}),
        json!([
            {"match": [{"path": ["/named"]}], "handle": [
                {"handler": "vars", "access_logger_names": ["admin"]},
                {"handler": "static_response", "body": "ok"}
            ]},
            {"handle": [{"handler": "static_response", "body": "ok"}]}
        ]),
        Some(json!({"skip_hosts": ["skipped.example.com"]})),
    );
    let (runtime, address) = start(config).await;

    let (status, _headers, _body) =
        request_with_host(address, "GET", "/named", "skipped.example.com").await;
    assert_eq!(status, 200);
    let (status, _headers, _body) =
        request_with_host(address, "GET", "/named", "logged.example.com").await;
    assert_eq!(status, 200);

    runtime.shutdown().await;
    assert_eq!(
        uri_and_logger(&read_log_lines(&log_path)),
        vec![("/named".to_string(), "http.log.access.admin".to_string())],
        "only the unmapped host's request is logged, with the explicit logger name"
    );
}

#[tokio::test]
async fn vars_log_level_sets_the_entry_level() {
    // The status-derived level (INFO, or ERROR for 5xx) is replaced by a valid `log_level`
    // variable in either direction; an invalid value keeps the status-derived level.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let config = runtime_config(
        json!({"default": file_sink(&log_path)}),
        json!([
            {"match": [{"path": ["/warn"]}], "handle": [
                {"handler": "vars", "log_level": "WARN"},
                {"handler": "static_response", "body": "ok"}
            ]},
            {"match": [{"path": ["/debug-500"]}], "handle": [
                {"handler": "vars", "log_level": "DEBUG"},
                {"handler": "static_response", "status_code": 500, "body": "boom"}
            ]},
            {"match": [{"path": ["/lower-500"]}], "handle": [
                {"handler": "vars", "log_level": "INFO"},
                {"handler": "static_response", "status_code": 500, "body": "boom"}
            ]},
            {"match": [{"path": ["/invalid"]}], "handle": [
                {"handler": "vars", "log_level": "verbose"},
                {"handler": "static_response", "body": "ok"}
            ]},
            {"handle": [{"handler": "static_response", "body": "ok"}]}
        ]),
        None,
    );
    let (runtime, address) = start(config).await;

    for path in ["/warn", "/debug-500", "/lower-500", "/invalid", "/plain"] {
        let (status, _headers, _body) =
            request_with_host(address, "GET", path, "example.com").await;
        assert!(status.is_success() || status == 500, "{path}: {status}");
    }

    runtime.shutdown().await;
    let levels = levels_by_uri(&read_log_lines(&log_path));
    assert_eq!(levels.get("/warn").map(String::as_str), Some("warn"));
    assert_eq!(levels.get("/debug-500").map(String::as_str), Some("debug"));
    assert_eq!(levels.get("/lower-500").map(String::as_str), Some("info"));
    assert_eq!(
        levels.get("/invalid").map(String::as_str),
        Some("info"),
        "an invalid level keeps the status-derived level"
    );
    assert_eq!(
        levels.get("/plain").map(String::as_str),
        Some("info"),
        "a request without the variable still logs normally"
    );
}

#[tokio::test]
async fn vars_log_level_is_filtered_by_the_sink_threshold() {
    // `logging.logs.default.level: ERROR` drops INFO entries. Raising a 200 to ERROR makes it
    // pass the same sink threshold, proving the level is applied before filtering.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let mut sink = file_sink(&log_path);
    sink["level"] = json!("ERROR");
    let config = runtime_config(
        json!({"default": sink}),
        json!([
            {"match": [{"path": ["/raise"]}], "handle": [
                {"handler": "vars", "log_level": "ERROR"},
                {"handler": "static_response", "body": "ok"}
            ]},
            {"match": [{"path": ["/plain"]}], "handle": [
                {"handler": "static_response", "body": "ok"}
            ]},
            {"match": [{"path": ["/error"]}], "handle": [
                {"handler": "static_response", "status_code": 500, "body": "boom"}
            ]}
        ]),
        None,
    );
    let (runtime, address) = start(config).await;

    for path in ["/raise", "/plain", "/error"] {
        let (status, _headers, _body) =
            request_with_host(address, "GET", path, "example.com").await;
        assert!(status.is_success() || status == 500, "{path}: {status}");
    }

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert_eq!(
        uri_and_logger(&entries),
        vec![
            ("/raise".to_string(), "http.log.access".to_string()),
            ("/error".to_string(), "http.log.access".to_string())
        ],
        "the raised 200 and the 500 pass ERROR; the plain 200 stays filtered: {entries:?}"
    );
}

#[tokio::test]
async fn vars_log_skip_suppresses_the_entry_despite_name_and_level() {
    // `log_skip` is checked first in Caddy's `logRequest`, so the other request-scoped controls
    // cannot make the entry appear anywhere.
    let directory = tempfile::tempdir().expect("tempdir");
    let default_log = directory.path().join("default.log");
    let admin_log = directory.path().join("admin.log");
    let mut admin_sink = file_sink(&admin_log);
    admin_sink["include"] = json!(["http.log.access.admin"]);
    let config = runtime_config(
        json!({"default": file_sink(&default_log), "admin": admin_sink}),
        json!([
            {"match": [{"path": ["/skip"]}], "handle": [
                {"handler": "vars", "log_skip": true, "access_logger_names": ["admin"], "log_level": "ERROR"},
                {"handler": "static_response", "body": "ok"}
            ]},
            {"handle": [{"handler": "static_response", "body": "ok"}]}
        ]),
        None,
    );
    let (runtime, address) = start(config).await;

    for path in ["/skip", "/plain"] {
        let (status, _headers, _body) =
            request_with_host(address, "GET", path, "example.com").await;
        assert_eq!(status, 200, "{path}");
    }

    runtime.shutdown().await;
    assert_eq!(
        uri_and_logger(&read_log_lines(&default_log)),
        vec![("/plain".to_string(), "http.log.access".to_string())],
        "the skipped request must not appear in any sink"
    );
    assert!(
        read_log_lines(&admin_log).is_empty(),
        "the skipped request must not appear in the named sink either"
    );
}

#[tokio::test]
async fn caddyfile_log_name_and_log_level_reach_the_runtime() {
    // End to end through the Caddyfile adapter: both directives must emit the generic `vars`
    // handler with Caddy's exact variables, and the runtime must honour them on real requests.
    let directory = tempfile::tempdir().expect("tempdir");
    let default_log = directory.path().join("default.log");
    let admin_log = directory.path().join("admin.log");
    let port = free_loopback_port();
    let caddyfile = format!(
        r#"{{
	admin 127.0.0.1:0
	auto_https off
}}

http://127.0.0.1:{port} {{
	@named path /named
	log_name @named admin
	@warn path /warn
	log_level @warn WARN
	respond "ok"
}}
"#
    );
    let adapted = caddy_rs_config::adapt_with_source(&caddyfile, None).expect("Caddyfile adapts");
    let required_handlers = json!([
        {"handler": "vars", "access_logger_names": ["admin"]},
        {"handler": "vars", "log_level": "warn"}
    ]);
    let routes =
        &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"];
    let handlers: Vec<&Value> = routes
        .as_array()
        .expect("subroute routes")
        .iter()
        .map(|route| &route["handle"][0])
        .filter(|handler| handler["handler"] == "vars")
        .collect();
    assert_eq!(
        Value::Array(handlers.into_iter().cloned().collect()),
        required_handlers,
        "the adapter emits Caddy's vars handlers"
    );

    let mut config_value = adapted.config;
    let mut admin_sink = file_sink(&admin_log);
    admin_sink["include"] = json!(["http.log.access.admin"]);
    let mut default_sink = file_sink(&default_log);
    default_sink["exclude"] = json!(["http.log.access.admin"]);
    config_value["logging"] = json!({"logs": {
        "default": default_sink,
        "admin": admin_sink
    }});
    let config = Config::from_value(config_value).expect("adapted JSON decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("adapted config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    runtime
        .listener_address(&format!(":{port}"))
        .expect("Caddyfile listener bound");
    let address = SocketAddr::from(([127, 0, 0, 1], port));

    for path in ["/named", "/warn", "/plain"] {
        let (status, _headers, body) = request_with_host(address, "GET", path, "127.0.0.1").await;
        assert_eq!(status, 200, "{path}");
        assert_eq!(body, Bytes::from_static(b"ok"), "{path}");
    }

    runtime.shutdown().await;
    assert_eq!(
        uri_and_logger(&read_log_lines(&admin_log)),
        vec![("/named".to_string(), "http.log.access.admin".to_string())],
        "the Caddyfile `log_name` reaches the named sink"
    );
    let default_entries = read_log_lines(&default_log);
    assert_eq!(
        uri_and_logger(&default_entries),
        vec![
            ("/warn".to_string(), "http.log.access".to_string()),
            ("/plain".to_string(), "http.log.access".to_string())
        ]
    );
    assert_eq!(
        levels_by_uri(&default_entries)
            .get("/warn")
            .map(String::as_str),
        Some("warn"),
        "the Caddyfile `log_level` reaches the entry"
    );
}
