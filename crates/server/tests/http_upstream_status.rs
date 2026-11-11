//! End-to-end admin test: `GET /reverse_proxy/upstreams` reports live counters from the active
//! reverse_proxy generation, and a reload swaps the observed upstream pool.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};

/// A fixed loopback port that is currently free (released immediately before use).
fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Wait until nothing listens on `address` (after aborting the upstream task).
async fn wait_until_unreachable(address: &str) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(address).await.is_err() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("upstream `{address}` kept accepting connections after abort");
}

// The address must be known synchronously for the Caddy config, so this helper binds first and
// moves the listener into the serving task. The returned watch sender shuts the upstream down
// (listener plus established connections) so a request can observe a real dial failure.
fn spawn_upstream_bound(body: &'static str) -> (String, tokio::sync::watch::Sender<bool>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let (sender, mut shutdown) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let accepted = tokio::select! {
                _ = shutdown.changed() => return,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else {
                break;
            };
            let mut connection_shutdown = shutdown.clone();
            tokio::spawn(async move {
                let service = service_fn(
                    |_request: hyper::Request<hyper::body::Incoming>| async move {
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::from_static(body.as_bytes())))
                                .expect("response"),
                        )
                    },
                );
                let serving = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service);
                tokio::select! {
                    _ = serving => {}
                    _ = connection_shutdown.changed() => {}
                }
            });
        }
    });
    (address.to_string(), sender)
}

fn config(upstream: &str) -> Config {
    config_with_admin(upstream, "127.0.0.1:0")
}

fn config_with_admin(upstream: &str, admin: &str) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"listen": admin},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": upstream}]
            }]}]
        }}}}
    }))
    .expect("test config decodes")
}

async fn request(address: SocketAddr, path: &str) -> (u16, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .uri(format!("http://{address}{path}"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .unwrap();
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

async fn admin_upstreams(address: SocketAddr) -> Vec<serde_json::Value> {
    let (status, body) = request(address, "/reverse_proxy/upstreams").await;
    assert_eq!(status, 200);
    serde_json::from_slice(&body).expect("admin upstreams JSON")
}

fn upstream_entry(statuses: &[serde_json::Value], address: &str) -> serde_json::Value {
    statuses
        .iter()
        .find(|entry| entry["address"] == address)
        .unwrap_or_else(|| panic!("no admin upstream entry for `{address}`: {statuses:?}"))
        .clone()
}

#[tokio::test]
async fn admin_reports_live_upstream_counters() {
    let (dial, _shutdown) = spawn_upstream_bound("upstream-ok");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config(&dial)).unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let listener = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    let admin = runtime.admin_address().expect("admin bound");

    // Configured addresses are listed before any traffic, with zero counters.
    let statuses = admin_upstreams(admin).await;
    assert_eq!(statuses.len(), 1, "{statuses:?}");
    assert_eq!(statuses[0]["address"], dial);
    assert_eq!(statuses[0]["num_requests"], 0);
    assert_eq!(statuses[0]["fails"], 0);

    for path in ["/one", "/two"] {
        let (status, body) = request(listener, path).await;
        assert_eq!(status, 200);
        assert_eq!(body, Bytes::from_static(b"upstream-ok"));
    }
    let statuses = admin_upstreams(admin).await;
    let entry = upstream_entry(&statuses, &dial);
    assert_eq!(entry["num_requests"], 2, "{statuses:?}");
    assert_eq!(entry["fails"], 0, "{statuses:?}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn metrics_report_caddy_reverse_proxy_upstream_health() {
    let (dial, _shutdown) = spawn_upstream_bound("upstream-ok");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config(&dial)).unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let admin = runtime.admin_address().expect("admin bound");

    let (status, body) = request(admin, "/metrics").await;
    assert_eq!(status, 200);
    let metrics = String::from_utf8_lossy(&body).into_owned();
    // Caddy registers this family when a reverse_proxy handler is provisioned and refreshes it
    // from `Upstream.Healthy()` (`modules/caddyhttp/reverseproxy/metrics.go`). A configured
    // upstream that has not failed a health check starts healthy.
    assert!(
        metrics.contains(
            "# HELP caddy_reverse_proxy_upstreams_healthy Health status of reverse proxy upstreams."
        ),
        "missing help line:\n{metrics}"
    );
    assert!(
        metrics.contains(&format!(
            "caddy_reverse_proxy_upstreams_healthy{{upstream=\"{dial}\"}} 1"
        )),
        "healthy upstream gauge missing:\n{metrics}"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn admin_reports_failed_upstream_attempts() {
    let (dial, shutdown) = spawn_upstream_bound("upstream-ok");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config(&dial)).unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let listener = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    let admin = runtime.admin_address().expect("admin bound");

    let (status, _) = request(listener, "/before").await;
    assert_eq!(status, 200);

    // Take the upstream down: the next request is a dial failure and must be counted.
    shutdown.send(true).expect("upstream shuts down");
    wait_until_unreachable(&dial).await;
    let (status, _) = request(listener, "/after").await;
    assert_eq!(status, 502);

    let statuses = admin_upstreams(admin).await;
    let entry = upstream_entry(&statuses, &dial);
    assert!(
        entry["num_requests"].as_u64().unwrap() >= 2,
        "attempts must include both requests: {statuses:?}"
    );
    assert!(
        entry["fails"].as_u64().unwrap() >= 1,
        "the dial failure must be counted: {statuses:?}"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn reload_swaps_the_admin_upstream_source() {
    let (first_dial, _first_shutdown) = spawn_upstream_bound("first-upstream");
    let (second_dial, _second_shutdown) = spawn_upstream_bound("second-upstream");
    let admin_port = free_loopback_port();
    let admin_listen = format!("127.0.0.1:{admin_port}");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config_with_admin(&first_dial, &admin_listen))
        .unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("initial apply");
    let listener = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    let admin = runtime.admin_address().expect("admin bound");

    assert_eq!(request(listener, "/first").await.0, 200);
    let statuses = admin_upstreams(admin).await;
    assert_eq!(upstream_entry(&statuses, &first_dial)["num_requests"], 1);

    // Reload with a different upstream: the admin view must swap to the new generation's pool and
    // counters (the old generation's handlers are no longer observed).
    store
        .load(config_with_admin(&second_dial, &admin_listen))
        .unwrap();
    let status = runtime.apply().await.expect("reload applies");
    assert_eq!(status.generation_id, Some(2));
    let reloaded_admin = runtime.admin_address().expect("admin retained");
    assert_eq!(admin, reloaded_admin, "same admin listener is reused");
    let statuses = admin_upstreams(admin).await;
    assert_eq!(statuses.len(), 1, "{statuses:?}");
    let entry = upstream_entry(&statuses, &second_dial);
    assert_eq!(entry["num_requests"], 0, "{statuses:?}");
    assert_eq!(entry["fails"], 0, "{statuses:?}");

    assert_eq!(request(listener, "/second").await.0, 200);
    let statuses = admin_upstreams(admin).await;
    let entry = upstream_entry(&statuses, &second_dial);
    assert_eq!(entry["num_requests"], 1, "{statuses:?}");
    runtime.shutdown().await;
}
