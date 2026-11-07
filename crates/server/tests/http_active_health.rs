//! End-to-end active health checks: the server runtime starts a generation-scoped
//! `reverse_proxy.health_checks.active` scheduler when a generation is applied, stops it on reload
//! or shutdown, and the proxy state machine marks upstreams unhealthy/healthy so routing skips
//! failed upstreams and resumes after recovery.
//!
//! Caddy v2.11.7 source: `modules/caddyhttp/reverseproxy/healthchecks.go` (probe fields, status and
//! body expectations, pass/fail thresholds) and `reverseproxy.go` provisioning (active checkers
//! are started with the handler and stopped with its context).
//!
//! The admin endpoint `GET /reverse_proxy/upstreams` only exposes `address` / `num_requests` /
//! `fails` (matching Caddy's admin handler); it has no health field, so tests observe health
//! through routing and additionally assert the endpoint keeps reporting the configured address.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};

/// Shared state for one controllable test upstream.
struct UpstreamState {
    status: AtomicU16,
    body: Mutex<String>,
    hits: AtomicUsize,
    slow: AtomicBool,
}

impl UpstreamState {
    fn new(status: u16, body: &str) -> Arc<Self> {
        Arc::new(Self {
            status: AtomicU16::new(status),
            body: Mutex::new(body.to_string()),
            hits: AtomicUsize::new(0),
            slow: AtomicBool::new(false),
        })
    }

    fn set_status(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
    }

    fn set_body(&self, body: &str) {
        *self.body.lock().unwrap() = body.to_string();
    }

    fn set_slow(&self, slow: bool) {
        self.slow.store(slow, Ordering::SeqCst);
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// Spawn a controlable HTTP upstream. Returns the dial string and the shared state.
fn spawn_controllable_upstream(status: u16, body: &str) -> (String, Arc<UpstreamState>) {
    let state = UpstreamState::new(status, body);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let address = listener.local_addr().expect("upstream address");
    listener.set_nonblocking(true).expect("nonblocking");
    let serve_state = Arc::clone(&state);
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let state = Arc::clone(&serve_state);
            tokio::spawn(async move {
                let service = service_fn(move |_request: hyper::Request<hyper::body::Incoming>| {
                    let state = Arc::clone(&state);
                    async move {
                        state.hits.fetch_add(1, Ordering::SeqCst);
                        if state.slow.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                        }
                        let status = state.status.load(Ordering::SeqCst);
                        let body = state.body.lock().unwrap().clone();
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from(body)))
                                .expect("upstream response"),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address.to_string(), state)
}

fn config_with_health(upstream: &str, health: Option<serde_json::Value>) -> Config {
    let mut handler = serde_json::json!({
        "handler": "reverse_proxy",
        "upstreams": [{"dial": upstream}]
    });
    if let Some(health) = health {
        handler["health_checks"] = serde_json::json!({"active": health});
    }
    Config::from_value(serde_json::json!({
        "admin": {"listen": "127.0.0.1:0"},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [handler]}]
        }}}}
    }))
    .expect("test config decodes")
}

async fn request(address: std::net::SocketAddr, path: &str) -> (u16, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .uri(format!("http://{address}{path}"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("request builds");
    let response = client.request(request).await.expect("request succeeds");
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, body)
}

/// Poll the proxy listener until `predicate` accepts a response (bounded real-time wait).
async fn wait_for_response(
    address: std::net::SocketAddr,
    path: &str,
    predicate: impl Fn(u16, &Bytes) -> bool,
) {
    for _ in 0..250 {
        let (status, body) = request(address, path).await;
        if predicate(status, &body) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (status, body) = request(address, path).await;
    panic!(
        "condition not reached; last response: {status} {}",
        String::from_utf8_lossy(&body)
    );
}

fn configured_address(runtime: &ServerRuntime) -> std::net::SocketAddr {
    runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound")
}

fn generated_unavailable(status: u16, body: &Bytes) -> bool {
    status == 503 && body == &Bytes::from_static(b"503 Service Unavailable")
}

#[tokio::test]
async fn active_health_check_marks_upstream_unhealthy_skips_it_and_restores() {
    let (dial, state) = spawn_controllable_upstream(503, "upstream-down");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config_with_health(
            &dial,
            Some(serde_json::json!({
                "uri": "/health", "interval": 50_000_000u64, "timeout": 1_000_000_000u64,
                "fails": 1, "passes": 1
            })),
        ))
        .unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let listener = configured_address(&runtime);
    let admin = runtime.admin_address().expect("admin bound");

    // The scheduler is owned by the applied generation.
    assert_eq!(runtime.health_scheduler_count(), 1);
    assert_eq!(runtime.health_scheduler_generations(), vec![1]);

    // A failing probe flips the upstream unhealthy; balancer selection then skips it and the proxy
    // returns its own 503 instead of forwarding to the failing backend.
    wait_for_response(listener, "/", generated_unavailable).await;
    assert!(state.hits() >= 1, "health probes reached the upstream");

    // The admin endpoint keeps reporting the configured upstream address (Caddy's admin payload
    // has no health field; health is observable through routing).
    let (status, body) = request(admin, "/reverse_proxy/upstreams").await;
    assert_eq!(status, 200);
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&body).expect("admin JSON");
    assert!(
        entries.iter().any(|entry| entry["address"] == dial),
        "admin endpoint must list the configured upstream: {entries:?}"
    );

    // Recovery: a passing probe restores the upstream and traffic is forwarded again.
    state.set_status(200);
    state.set_body("upstream-ok");
    wait_for_response(listener, "/", |status, body| {
        status == 200 && body == &Bytes::from_static(b"upstream-ok")
    })
    .await;
    runtime.shutdown().await;
}

#[tokio::test]
async fn expect_status_expect_body_and_timeouts_are_failures() {
    let (dial, state) = spawn_controllable_upstream(200, "healthy-body");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    let load_health = |store: &GenerationStore, health: serde_json::Value| {
        store
            .load(config_with_health(&dial, Some(health)))
            .expect("config loads");
    };
    load_health(
        &store,
        serde_json::json!({
            "uri": "/health", "interval": 50_000_000u64, "timeout": 1_000_000_000u64,
            "expect_status": 201
        }),
    );
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let listener = configured_address(&runtime);
    // Status mismatch (200 vs expect 201) counts as a probe failure.
    wait_for_response(listener, "/", generated_unavailable).await;

    // Matching status but body mismatch also counts as a failure.
    store
        .load(config_with_health(
            &dial,
            Some(serde_json::json!({
                "uri": "/health", "interval": 50_000_000u64, "timeout": 1_000_000_000u64,
                "expect_body": "^ok$"
            })),
        ))
        .unwrap();
    runtime.apply().await.expect("reload applies");
    wait_for_response(listener, "/", generated_unavailable).await;

    // Matching expect_body restores health.
    state.set_body("ok");
    wait_for_response(listener, "/", |status, body| {
        status == 200 && body == &Bytes::from_static(b"ok")
    })
    .await;

    // Timeout: a slow backend with a short probe timeout is unhealthy.
    state.set_slow(true);
    state.set_body("slow");
    store
        .load(config_with_health(
            &dial,
            Some(serde_json::json!({
                "uri": "/health", "interval": 50_000_000u64, "timeout": 30_000_000u64
            })),
        ))
        .unwrap();
    runtime.apply().await.expect("reload applies");
    wait_for_response(listener, "/", generated_unavailable).await;

    // Recovering the backend restores health for the same forwarding generation.
    state.set_slow(false);
    wait_for_response(listener, "/", |status, body| {
        status == 200 && body == &Bytes::from_static(b"slow")
    })
    .await;
    runtime.shutdown().await;
}

#[tokio::test]
async fn no_active_health_checks_means_no_scheduler_and_no_probe_requests() {
    let (dial, state) = spawn_controllable_upstream(200, "upstream-ok");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config_with_health(&dial, None)).unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let listener = configured_address(&runtime);

    assert_eq!(runtime.health_scheduler_count(), 0);
    assert!(runtime.health_scheduler_generations().is_empty());

    // No scheduler means no probe traffic: only the real request below reaches the upstream.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        state.hits(),
        0,
        "no health-check requests without configuration"
    );

    let (status, body) = request(listener, "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"upstream-ok"));
    assert_eq!(state.hits(), 1);

    // Enabling active checks on a reload starts a generation-scoped checker...
    store
        .load(config_with_health(
            &dial,
            Some(serde_json::json!({
                "uri": "/health", "interval": 50_000_000u64, "timeout": 1_000_000_000u64
            })),
        ))
        .unwrap();
    runtime.apply().await.expect("reload applies");
    assert_eq!(runtime.health_scheduler_count(), 1);
    let before_probes = state.hits();
    for _ in 0..250 {
        if state.hits() > before_probes {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(state.hits() > before_probes, "reload must start probing");

    // ...and removing them on a later reload stops the checker (no leak, no probes).
    store.load(config_with_health(&dial, None)).unwrap();
    runtime.apply().await.expect("reload applies");
    assert_eq!(runtime.health_scheduler_count(), 0);
    assert!(runtime.health_scheduler_generations().is_empty());
    let after_removal = state.hits();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        state.hits(),
        after_removal,
        "removing active health checks must stop the generation's checker"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn health_schedulers_are_generation_scoped_across_reloads_and_shutdown() {
    let (first_dial, first) = spawn_controllable_upstream(200, "first");
    let (second_dial, second) = spawn_controllable_upstream(200, "second");
    let (third_dial, third) = spawn_controllable_upstream(200, "third");
    let health = || {
        serde_json::json!({
            "uri": "/health", "interval": 50_000_000u64, "timeout": 1_000_000_000u64
        })
    };
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config_with_health(&first_dial, Some(health())))
        .unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("initial apply");
    assert_eq!(runtime.health_scheduler_count(), 1);
    wait_for_hits(&first).await;

    // Reload: the old generation's checker is stopped and replaced by the new generation's.
    store
        .load(config_with_health(&second_dial, Some(health())))
        .unwrap();
    runtime.apply().await.expect("second apply");
    assert_eq!(runtime.health_scheduler_count(), 1, "no scheduler leak");
    assert_eq!(runtime.health_scheduler_generations(), vec![2]);
    wait_for_hits(&second).await;
    let first_hits = first.hits();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        first.hits(),
        first_hits,
        "the retired generation's health checker must stop probing"
    );

    // A second reload keeps exactly one live scheduler.
    store
        .load(config_with_health(&third_dial, Some(health())))
        .unwrap();
    runtime.apply().await.expect("third apply");
    assert_eq!(runtime.health_scheduler_count(), 1, "no scheduler leak");
    assert_eq!(runtime.health_scheduler_generations(), vec![3]);
    wait_for_hits(&third).await;

    // Shutdown stops every scheduler: no further probe requests arrive.
    runtime.shutdown().await;
    let third_hits = third.hits();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        third.hits(),
        third_hits,
        "shutdown must stop all generation-scoped health checkers"
    );
}

async fn wait_for_hits(state: &Arc<UpstreamState>) {
    for _ in 0..250 {
        if state.hits() > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("health checker never probed the upstream");
}

#[tokio::test]
async fn unsupported_active_health_fields_and_invalid_regex_fail_apply_loudly() {
    let (dial, _state) = spawn_controllable_upstream(200, "ok");
    for (health, expected) in [
        (
            serde_json::json!({"uri": "/health", "port": 8080}),
            "PROXY-HEALTH-PORT",
        ),
        (
            serde_json::json!({"uri": "/health", "follow_redirects": true}),
            "PROXY-HEALTH-REDIRECT",
        ),
        (
            serde_json::json!({"uri": "/health", "upstream": "localhost:9000"}),
            "PROXY-HEALTH-UPSTREAM",
        ),
        (
            serde_json::json!({"uri": "/health", "expect_body": "("}),
            "expect_body",
        ),
    ] {
        let store = Arc::new(GenerationStore::with_builtin_registry());
        store
            .load(config_with_health(&dial, Some(health)))
            .expect("config decodes");
        let mut runtime = ServerRuntime::new(Arc::clone(&store));
        let error = runtime
            .apply()
            .await
            .expect_err("unsupported active health check configuration must fail the apply");
        let message = error.to_string();
        assert!(
            message.contains(expected),
            "error must name `{expected}`: {message}"
        );
        assert_eq!(
            runtime.health_scheduler_count(),
            0,
            "a rejected configuration must not start checkers"
        );
        runtime.shutdown().await;
    }
}
