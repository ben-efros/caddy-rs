//! End-to-end runtime tests: real TCP listeners, hyper serving, reload, and the admin API.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use caddy_rs_test_support::{free_port, retry_addr_in_use};

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

fn config(listen: &str, body: &str, admin_disabled: bool) -> Config {
    let admin = if admin_disabled {
        serde_json::json!({"disabled": true})
    } else {
        serde_json::json!({"listen": "127.0.0.1:0"})
    };
    config_with_admin(listen, body, admin)
}

fn config_with_admin(listen: &str, body: &str, admin: serde_json::Value) -> Config {
    Config::from_value(serde_json::json!({
        "admin": admin,
        "apps": {"http": {"servers": {"srv0": {
            "listen": [listen],
            "routes": [{"handle": [{"handler": "static_response", "body": body}]}]
        }}}}
    }))
    .expect("test config decodes")
}

async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{address}{path}"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::from(body.unwrap_or("").to_string())))
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

#[tokio::test]
async fn serves_static_response_on_ephemeral_port() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config("127.0.0.1:0", "hello", true)).unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    let status = runtime.apply().await.expect("runtime applies");
    assert_eq!(status.generation_id, Some(1));
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");

    let (code, body) = request(address, "GET", "/", None).await;
    assert_eq!(code, 200);
    assert_eq!(body, Bytes::from_static(b"hello"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn reload_keeps_listener_and_swaps_router() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config("127.0.0.1:0", "one", true)).unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("initial apply");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    assert_eq!(
        request(address, "GET", "/", None).await.1,
        Bytes::from_static(b"one")
    );

    store.load(config("127.0.0.1:0", "two", true)).unwrap();
    let status = runtime.apply().await.expect("reload applies");
    assert_eq!(status.generation_id, Some(2));
    let reloaded_address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener retained");
    assert_eq!(address, reloaded_address, "same listener must be reused");
    assert_eq!(
        request(address, "GET", "/", None).await.1,
        Bytes::from_static(b"two")
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn host_matching_routes_by_host_header() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(
            Config::from_value(serde_json::json!({
                "admin": {"disabled": true},
                "apps": {"http": {"servers": {"srv0": {
                    "listen": ["127.0.0.1:0"],
                    "automatic_https": {"disable": true},
                    "routes": [
                        {"match": [{"host": ["example.com"]}],
                         "handle": [{"handler": "static_response", "body": "matched"}]}
                    ]
                }}}}
            }))
            .unwrap(),
        )
        .unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("apply");
    let address = runtime.listener_address("127.0.0.1:0").unwrap();
    assert_eq!(
        request(address, "GET", "/", None).await.1,
        Bytes::from_static(b"matched")
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn admin_api_loads_configuration_end_to_end() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config("127.0.0.1:0", "before", false)).unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("apply");
    let admin = runtime.admin_address().expect("admin bound");
    let http_address = runtime.listener_address("127.0.0.1:0").unwrap();

    let (code, body) = request(admin, "GET", "/config/", None).await;
    assert_eq!(code, 200);
    let config_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        config_json["apps"]["http"]["servers"]["srv0"]["listen"][0],
        "127.0.0.1:0"
    );

    let new_config =
        String::from_utf8(config("127.0.0.1:0", "after", false).to_vec().unwrap()).unwrap();
    let (code, _body) = request(admin, "POST", "/load", Some(&new_config)).await;
    assert_eq!(code, 200);
    assert_eq!(store.current().unwrap().id(), 2);
    // In production `ServerRuntime::run` reacts to the admin API's reload notification; this test
    // drives the same reconciliation explicitly.
    runtime.apply().await.expect("reload applies");
    assert_eq!(
        request(http_address, "GET", "/", None).await.1,
        Bytes::from_static(b"after")
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn admin_rejects_invalid_config_with_400() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config("127.0.0.1:0", "ok", false)).unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("apply");
    let admin = runtime.admin_address().unwrap();
    let invalid = serde_json::json!({
        "apps": {"http": {"servers": {"srv0": {
            "listen": [":8080"],
            "routes": [{"handle": [{"handler": "unknown_module"}]}]
        }}}}
    });
    let (code, body) = request(admin, "POST", "/load", Some(&invalid.to_string())).await;
    assert_eq!(code, 400);
    assert!(String::from_utf8_lossy(&body).contains("unknown_module"));
    runtime.shutdown().await;
}

/// Caddy's hostless site addresses (`:PORT`, and therefore any Caddyfile `:PORT` site) listen on
/// all interfaces for both address families. caddy-rs used to bind `0.0.0.0` (IPv4 only) — with
/// older builds it even failed to resolve `:port` — so IPv6 clients saw connection refused.
#[tokio::test]
async fn hostless_listener_binds_wildcard_and_serves_both_address_families() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config(":0", "wildcard", true)).unwrap();
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    let status = runtime.apply().await.expect("hostless listener applies");
    let bound = runtime
        .listener_address(":0")
        .expect("hostless listener bound");
    assert!(
        bound.ip().is_unspecified(),
        "Caddy's `:port` binds the wildcard address, got {bound}"
    );
    assert_eq!(
        status.listeners.get(":0").map(String::as_str),
        Some(bound.to_string().as_str())
    );

    let ipv4 = SocketAddr::from((Ipv4Addr::LOCALHOST, bound.port()));
    let (code, body) = request(ipv4, "GET", "/", None).await;
    assert_eq!(code, 200);
    assert_eq!(body, Bytes::from_static(b"wildcard"));

    // The wildcard is dual-stack like Go's `net.Listen("tcp", ":port")`; when this platform has
    // IPv6, a loopback IPv6 client must be served too. (The bind has an IPv4 fallback for hosts
    // with IPv6 disabled, so only assert IPv6 when the environment supports it.)
    if ipv6_loopback_available() {
        let ipv6 = SocketAddr::from((Ipv6Addr::LOCALHOST, bound.port()));
        let (code, body) = request(ipv6, "GET", "/", None).await;
        assert_eq!(
            code, 200,
            "dual-stack wildcard must serve IPv6 clients at {ipv6}"
        );
        assert_eq!(body, Bytes::from_static(b"wildcard"));
        assert!(
            bound.is_ipv6(),
            "with IPv6 available the wildcard bind should be the dual-stack IPv6 socket, got {bound}"
        );
    }

    runtime.shutdown().await;
}

fn ipv6_loopback_available() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

/// Caddy exits the process when `POST /stop` unloads the configuration. The runtime supervisor
/// used to keep idling with no listeners, so the CLI process never exited (real-Caddy-oracle
/// finding `admin-stop#stop`, seen with the JSON adapter because the Caddyfile run exited only by
/// accident of external signals).
#[tokio::test]
async fn admin_stop_ends_the_runtime_loop() {
    // Use a fixed admin port: the supervisor re-applies once on entry, and an ephemeral admin
    // `:0` would be rebound to a new port on every apply (the test needs a stable address). The
    // fixed port can lose the allocation race, so retry the initial bind with a fresh one.
    let (runtime, admin, web) = retry_addr_in_use(|| {
        let admin_port = free_port();
        let store = Arc::new(GenerationStore::with_builtin_registry());
        store
            .load(config_with_admin(
                "127.0.0.1:0",
                "hello",
                serde_json::json!({"listen": format!("127.0.0.1:{admin_port}")}),
            ))
            .unwrap();
        let mut runtime = ServerRuntime::new(store);
        async move {
            runtime.apply().await?;
            let admin = runtime.admin_address().expect("admin listener bound");
            let web = runtime
                .listener_address("127.0.0.1:0")
                .expect("web listener bound");
            Ok::<_, caddy_rs_server::Error>((runtime, admin, web))
        }
    })
    .await
    .expect("apply");

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status, _) = request(admin, "POST", "/stop", None).await;
    assert_eq!(status, 200);

    let joined = tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("runtime loop must exit after POST /stop");
    joined
        .expect("runtime task")
        .expect("runtime run returns Ok");

    // The supervisor stopped both listeners before returning.
    assert!(
        wait_until_closed(admin),
        "admin listener must be closed after /stop"
    );
    assert!(
        wait_until_closed(web),
        "web listener must be closed after /stop"
    );
}

/// Wait (bounded) until nothing is accepting connections at `address`.
fn wait_until_closed(address: SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}
