//! End-to-end observability tests (T-ADMIN-024): the runtime wires the admin crate's metrics
//! recorder and access-log sinks into live listeners.
//!
//! Every test uses real TCP listeners and a real hyper client. Assertions are made through the
//! public surfaces the runtime exposes: the admin `GET /metrics` endpoint, the access-log files
//! written by the configured sinks, and `ServerRuntime::apply` returning located errors.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http::{HeaderMap, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::mpsc;

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
    request_with_body(address, method, path, headers, Bytes::new()).await
}

async fn request_with_body(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Bytes,
) -> (StatusCode, HeaderMap, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{address}{path}"))
        .header(http::header::HOST, "example.com");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Full::new(body)).expect("valid request");
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
async fn metrics_use_caddy_handler_label_request_size_and_time_to_first_byte() {
    let (_store, runtime, address) = start(observability_config(
        serde_json::json!({"listen": "127.0.0.1:0"}),
        None,
        "hello",
    ))
    .await;
    let admin = runtime.admin_address().expect("admin bound");

    let (status, _headers, body) = request(address, "GET", "/path?q=1", &[("X-Test", "1")]).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"hello"));

    let (status, _headers, metrics) = request(admin, "GET", "/metrics", &[]).await;
    assert_eq!(status, 200);
    let metrics = String::from_utf8_lossy(&metrics).into_owned();

    // Caddy labels the route observation with `route.Handlers[0]`, i.e. `static_response`
    // (`modules/caddyhttp/routes.go:174,320-323`); caddy-rs previously recorded an empty handler.
    assert!(
        metrics
            .contains("caddy_http_requests_total{handler=\"static_response\",server=\"srv0\"} 1"),
        "missing handler label:\n{metrics}"
    );
    // Caddy's `computeApproximateRequestSize`: GET (3) + HTTP/1.1 (8) + "/path?q=1" (9) +
    // "example.com" (11) + X-Test (6) + "1" (1) = 38, plus any transport-added headers.
    let request_size_line = metrics
        .lines()
        .find(|line| line.starts_with("caddy_http_request_size_bytes_sum{"))
        .expect("request-size histogram sum");
    let size: f64 = request_size_line
        .rsplit_once(' ')
        .expect("sum value")
        .1
        .parse()
        .expect("numeric sum");
    assert!(
        size >= 38.0,
        "request size must include the request line, host and headers: {request_size_line}"
    );
    // `caddy_http_response_duration_seconds` is time-to-first-byte (recorded once), not the
    // complete body duration.
    assert!(
        metrics.contains(
            "caddy_http_response_duration_seconds_count{code=\"200\",handler=\"static_response\",method=\"GET\",server=\"srv0\"} 1"
        ),
        "missing response-duration observation:\n{metrics}"
    );
    // `per_host` is off, so no `host` label is added.
    assert!(
        !metrics.contains("host=\""),
        "host label must be absent without per_host:\n{metrics}"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn chunked_request_logs_transfer_encoding() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("chunked.log");
    let (_store, runtime, address) = start(observability_config(
        serde_json::json!({"disabled": true}),
        Some(logging_section(&log_path)),
        "hello",
    ))
    .await;

    // A raw chunked upload: the request has no Content-Length, only `Transfer-Encoding: chunked`.
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\
              Content-Type: text/plain\r\nConnection: close\r\n\r\n\
              5\r\nhello\r\n0\r\n\r\n",
        )
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
        "unexpected response: {}",
        String::from_utf8_lossy(&response)
    );

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert_eq!(entries.len(), 1, "{entries:?}");
    let entry = &entries[0];
    // Go's net/http lifts `Transfer-Encoding` out of the header map and Caddy logs it as
    // `request.transfer_encoding` (`modules/caddyhttp/marshalers.go:55-57`).
    assert_eq!(
        entry["request"]["transfer_encoding"],
        serde_json::json!(["chunked"]),
        "chunked requests must record the transfer encoding: {entry}"
    );
    assert!(
        entry["request"]["headers"]
            .get("Transfer-Encoding")
            .is_none(),
        "the encoding is not repeated in request.headers: {entry}"
    );
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
    // Anonymous requests always carry the field, empty (Caddy's `server.go:1290`).
    assert_eq!(entry["user_id"], "");
    // The GET has no body, so the actual bytes-read count is 0 (not a declared length).
    assert_eq!(entry["bytes_read"], 0);
    // A successful write never emits `write_error`.
    assert!(entry.get("write_error").is_none());
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
async fn head_request_is_not_reported_as_a_failed_write() {
    // hyper never polls a response body it must not send for HEAD, so the observed body is dropped
    // without reaching end-of-stream. That is a normal bodiless response, not a write failure.
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let (_store, runtime, address) = start(observability_config(
        serde_json::json!({"disabled": true}),
        Some(logging_section(&log_path)),
        "hello",
    ))
    .await;

    let (status, _headers, body) = request(address, "HEAD", "/", &[]).await;
    assert_eq!(status, 200);
    assert!(body.is_empty());

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["status"], 200);
    assert!(
        entries[0].get("write_error").is_none(),
        "a HEAD response has no body to write: {}",
        entries[0]
    );
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

/// A mock upstream that commits headers and the first body chunk, then waits `delay` before the
/// last chunk. Proves `duration`/`size` are measured at the last body byte, not at headers.
async fn spawn_delayed_streaming_upstream(delay: Duration) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let address = listener.local_addr().expect("upstream address");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |_request: hyper::Request<hyper::body::Incoming>| async move {
                        let (sender, receiver) = mpsc::channel(4);
                        tokio::spawn(async move {
                            let _ = sender.send(Ok(Bytes::from_static(b"first-"))).await;
                            tokio::time::sleep(delay).await;
                            let _ = sender.send(Ok(Bytes::from_static(b"second"))).await;
                        });
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(StatusCode::OK)
                                .header(http::header::CONTENT_TYPE, "text/plain")
                                .body(caddy_rs_http::StreamingBody::from_chunks(receiver))
                                .expect("upstream response"),
                        )
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    address.to_string()
}

/// A mock upstream whose response body fails after one chunk, aborting the downstream write.
async fn spawn_failing_streaming_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let address = listener.local_addr().expect("upstream address");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |_request: hyper::Request<hyper::body::Incoming>| async move {
                        let (sender, receiver) = mpsc::channel(4);
                        tokio::spawn(async move {
                            let _ = sender.send(Ok(Bytes::from_static(b"partial"))).await;
                            let _ = sender.send(Err(caddy_rs_http::BodyError::Cancelled)).await;
                        });
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(StatusCode::OK)
                                .body(caddy_rs_http::StreamingBody::from_chunks(receiver))
                                .expect("upstream response"),
                        )
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    address.to_string()
}

fn logging_section(log_path: &std::path::Path) -> serde_json::Value {
    serde_json::json!({
        "logs": {
            "default": {
                "writer": {"output": "file", "filename": log_path.to_string_lossy()},
                "encoder": {"format": "json"},
                "level": "INFO"
            }
        }
    })
}

fn basic_authorization(username: &str, password: &str) -> String {
    use base64::Engine as _;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    format!("Basic {encoded}")
}

async fn start_proxy_config(config: Config) -> (ServerRuntime, SocketAddr) {
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
async fn proxied_authenticated_request_logs_user_bytes_body_duration_and_upstream() {
    let upstream_dial = spawn_delayed_streaming_upstream(Duration::from_millis(150)).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "logging": logging_section(&log_path),
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [
                {
                    "handler": "basic_auth",
                    "hash": {"algorithm": "plaintext"},
                    "accounts": [{"username": "alice", "password": "secret"}]
                },
                {"handler": "reverse_proxy", "upstreams": [{"dial": upstream_dial.clone()}]}
            ]}]
        }}}}
    }))
    .expect("test config decodes");

    let (runtime, address) = start_proxy_config(config).await;
    let authorization = basic_authorization("alice", "secret");
    let (status, _headers, body) = request_with_body(
        address,
        "POST",
        "/proxied",
        &[("Authorization", authorization.as_str())],
        Bytes::from_static(b"payload"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"first-second"));

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert_eq!(entries.len(), 1, "one access entry for the proxied request");
    let entry = &entries[0];

    // Authenticated identity from the basic_auth handler, not a placeholder.
    assert_eq!(entry["user_id"], "alice");
    // Actual bytes moved, not declared lengths.
    assert_eq!(entry["bytes_read"], 7, "request body bytes actually read");
    assert_eq!(entry["size"], 12, "response body bytes actually written");
    assert_eq!(entry["status"], 200);
    // The upstream commits headers, then waits 150ms before the last chunk: a header-time
    // duration would be far below this, so the assertion proves the body-end boundary.
    let duration = entry["duration"].as_f64().expect("duration is a number");
    assert!(
        duration >= 0.12,
        "duration must cover the whole body, got {duration}"
    );
    // A successful write omits write_error entirely.
    assert!(
        entry.get("write_error").is_none(),
        "successful writes must omit write_error: {entry}"
    );
    // The proxy records its upstream selection as the caddy-rs `upstream` extension.
    let upstream = entry
        .get("upstream")
        .expect("proxied request logs upstream");
    assert_eq!(upstream["dial"].as_str(), Some(upstream_dial.as_str()));
    assert_eq!(upstream["status"], 200);
    assert_eq!(upstream["remote_ip"], "127.0.0.1");
    assert!(upstream["duration"].is_number());
}

#[tokio::test]
async fn failed_response_write_logs_write_error() {
    let upstream_dial = spawn_failing_streaming_upstream().await;
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "logging": logging_section(&log_path),
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [
                {"handler": "reverse_proxy", "upstreams": [{"dial": upstream_dial.clone()}]}
            ]}]
        }}}}
    }))
    .expect("test config decodes");

    let (runtime, address) = start_proxy_config(config).await;
    // The upstream aborts its body mid-stream, so the downstream response cannot be completed.
    // The request may surface as a client error or a truncated response; either way the server
    // observes the failed write.
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://{address}/cut"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("valid request");
    if let Ok(response) = client.request(request).await {
        let _ = response.into_body().collect().await;
    }

    runtime.shutdown().await;
    let entries = read_log_lines(&log_path);
    assert_eq!(
        entries.len(),
        1,
        "one access entry for the aborted response"
    );
    let entry = &entries[0];
    assert_eq!(entry["status"], 200);
    let write_error = entry
        .get("write_error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("failed write must log write_error: {entry}"));
    assert!(
        write_error.contains("error after"),
        "write_error must describe the aborted body: {write_error}"
    );
}

fn logging_with_encoder(
    log_path: &std::path::Path,
    encoder: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "logs": {
            "default": {
                "writer": {"output": "file", "filename": log_path.to_string_lossy()},
                "encoder": encoder,
                "level": "INFO"
            }
        }
    })
}

fn observability_config_with_stock(
    logging: serde_json::Value,
    body: &str,
    stock_compat: bool,
) -> Config {
    let mut config = serde_json::json!({
        "admin": {"disabled": true},
        "logging": logging,
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": body}]}]
        }}}}
    });
    if stock_compat {
        config["stock_compat"] = serde_json::Value::Bool(true);
    }
    Config::from_value(config).expect("test config decodes")
}

/// Start one request against a fresh runtime and return the single access-log entry as JSON.
async fn single_access_entry(
    config: Config,
    path: &str,
    log_path: &std::path::Path,
) -> serde_json::Value {
    let (_store, runtime, address) = start(config).await;
    let (status, _headers, _body) = request(address, "GET", path, &[]).await;
    assert_eq!(status, 200);
    runtime.shutdown().await;
    let entries = read_log_lines(log_path);
    assert_eq!(entries.len(), 1, "one access entry per request");
    entries[0].clone()
}

#[tokio::test]
async fn access_log_redacts_builtin_query_parameters_by_default() {
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let logging = logging_with_encoder(&log_path, serde_json::json!({"format": "json"}));
    let config = observability_config_with_stock(logging, "ok", false);
    let entry = single_access_entry(
        config,
        "/callback?access_token=at&state=ok&token&api_key=k&Access_Token=mixed",
        &log_path,
    )
    .await;
    assert_eq!(
        entry["request"]["uri"],
        serde_json::json!(
            "/callback?access_token=REDACTED&state=ok&token=REDACTED&api_key=REDACTED&Access_Token=mixed"
        )
    );
}

#[tokio::test]
async fn explicit_empty_redaction_query_parameters_logs_the_query_verbatim() {
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let logging = logging_with_encoder(
        &log_path,
        serde_json::json!({
            "format": "json",
            "redaction": {"query_parameters": []}
        }),
    );
    let config = observability_config_with_stock(logging, "ok", false);
    let entry = single_access_entry(config, "/callback?access_token=at&token", &log_path).await;
    assert_eq!(
        entry["request"]["uri"],
        serde_json::json!("/callback?access_token=at&token")
    );
}

#[tokio::test]
async fn stock_compat_true_logs_the_query_verbatim() {
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let logging = logging_with_encoder(&log_path, serde_json::json!({"format": "json"}));
    let config = observability_config_with_stock(logging, "ok", true);
    let entry = single_access_entry(config, "/callback?access_token=at&token", &log_path).await;
    assert_eq!(
        entry["request"]["uri"],
        serde_json::json!("/callback?access_token=at&token")
    );
}

#[tokio::test]
async fn explicit_redaction_query_parameters_replace_the_builtin_default() {
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let logging = logging_with_encoder(
        &log_path,
        serde_json::json!({
            "format": "json",
            "redaction": {"query_parameters": ["my_token"]}
        }),
    );
    let config = observability_config_with_stock(logging, "ok", false);
    let entry = single_access_entry(config, "/callback?my_token=t&token=secret", &log_path).await;
    assert_eq!(
        entry["request"]["uri"],
        serde_json::json!("/callback?my_token=REDACTED&token=secret")
    );
}

#[tokio::test]
async fn filter_encoder_wrap_redacts_before_applying_filters() {
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let logging = logging_with_encoder(
        &log_path,
        serde_json::json!({
            "format": "filter",
            "wrap": {"format": "json", "redaction": {"query_parameters": ["my_token"]}},
            "fields": {}
        }),
    );
    let config = observability_config_with_stock(logging, "ok", false);
    let entry = single_access_entry(config, "/callback?my_token=t&state=ok", &log_path).await;
    assert_eq!(
        entry["request"]["uri"],
        serde_json::json!("/callback?my_token=REDACTED&state=ok")
    );
}

#[tokio::test]
async fn console_encoder_renders_the_redacted_query() {
    let directory = tempfile::tempdir().expect("tempdir");
    let log_path = directory.path().join("access.log");
    let logging = logging_with_encoder(&log_path, serde_json::json!({"format": "console"}));
    let config = observability_config_with_stock(logging, "ok", false);
    let (_store, runtime, address) = start(config).await;
    let (status, _headers, _body) =
        request(address, "GET", "/cb?access_token=at&state=ok", &[]).await;
    assert_eq!(status, 200);
    runtime.shutdown().await;
    let rendered = std::fs::read_to_string(&log_path).expect("console access log");
    assert!(
        rendered.contains("access_token=REDACTED"),
        "console output must carry the redacted query: {rendered}"
    );
    assert!(
        !rendered.contains("access_token=at"),
        "value must not leak: {rendered}"
    );
}
