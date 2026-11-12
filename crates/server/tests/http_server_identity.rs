//! Configurable HTTP `Server` response header (T-CONF-060).
//!
//! `apps.http.servers.<name>.server_identity` is a caddy-rs extension with five modes. These tests
//! drive a real listener and assert the emitted header (or its absence) per mode, and that a
//! malformed value fails configuration load with a located error.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::Full;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

fn config(identity: Option<serde_json::Value>) -> Config {
    let mut server = serde_json::json!({
        "listen": ["127.0.0.1:0"],
        // A small body limit lets a test force a response the router never sees (a pre-routing
        // 413), which is the path DIV-0126 covers.
        "max_request_body_size": 8,
        "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
    });
    if let Some(identity) = identity {
        server["server_identity"] = identity;
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": server}}}
    }))
    .expect("test config decodes")
}

async fn start(identity: Option<serde_json::Value>) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config(identity)).expect("test config validates");
    let mut runtime = ServerRuntime::new(store);
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (runtime, address)
}

async fn server_header(identity: Option<serde_json::Value>) -> Option<String> {
    let (runtime, address) = start(identity).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .uri(format!("http://{address}/probe"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("request builds");
    let response = client.request(request).await.expect("request succeeds");
    assert_eq!(response.status(), 200);
    let header = response
        .headers()
        .get(http::header::SERVER)
        .map(|value| value.to_str().expect("ascii header").to_string());
    runtime.shutdown().await;
    header
}

#[tokio::test]
async fn default_mode_identifies_caddy_rs_with_build_version() {
    let header = server_header(None).await;
    assert_eq!(header, Some(format!("caddy-rs/{}", caddy_rs_core::VERSION)));
}

#[tokio::test]
async fn name_only_mode_emits_the_bare_product_name() {
    assert_eq!(
        server_header(Some(serde_json::json!("name-only"))).await,
        Some("Caddy".to_string())
    );
}

#[tokio::test]
async fn compatible_mode_emits_caddy() {
    assert_eq!(
        server_header(Some(serde_json::json!("compatible"))).await,
        Some("Caddy".to_string())
    );
}

#[tokio::test]
async fn custom_mode_emits_the_operator_string() {
    assert_eq!(
        server_header(Some(serde_json::json!("Acme Server/2"))).await,
        Some("Acme Server/2".to_string())
    );
}

#[tokio::test]
async fn none_mode_omits_the_header() {
    assert_eq!(server_header(Some(serde_json::json!("none"))).await, None);
}

async fn pre_router_413_server_header(identity: Option<serde_json::Value>) -> Option<String> {
    let (runtime, address) = start(identity).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .method(http::Method::POST)
        .uri(format!("http://{address}/probe"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::from_static(&[b'x'; 64])))
        .expect("request builds");
    let response = client.request(request).await.expect("request succeeds");
    // The body limit is enforced before routing, so this response never reaches a handler.
    assert_eq!(response.status(), 413);
    let header = response
        .headers()
        .get(http::header::SERVER)
        .map(|value| value.to_str().expect("ascii header").to_string());
    runtime.shutdown().await;
    header
}

#[tokio::test]
async fn pre_router_413_carries_the_configured_identity() {
    assert_eq!(
        pre_router_413_server_header(Some(serde_json::json!("Acme Server/2"))).await,
        Some("Acme Server/2".to_string()),
        "a pre-routing 413 must carry the configured `Server` header like Caddy's pre-routing one"
    );
}

#[tokio::test]
async fn pre_router_413_in_none_mode_emits_no_header() {
    assert_eq!(
        pre_router_413_server_header(Some(serde_json::json!("none"))).await,
        None,
        "`none` mode must stay silent on pre-routing responses too"
    );
}

#[test]
fn malformed_identity_is_a_located_error() {
    for value in [
        serde_json::json!(""),
        serde_json::json!(42),
        serde_json::json!(null),
        // DIV-0126: a custom value that cannot be a header value is a config error, not a silent
        // drop at response time.
        serde_json::json!("Acme\u{7}Server"),
        serde_json::json!("Acme\u{0}Server"),
        serde_json::json!("Acme\u{7f}Server"),
        serde_json::json!("Acme\tServer"),
        serde_json::json!("caf\u{e9}"),
    ] {
        let store = Arc::new(GenerationStore::with_builtin_registry());
        let error = store
            .load(config(Some(value.clone())))
            .err()
            .unwrap_or_else(|| panic!("{value:?} must be rejected"));
        let message = error.to_string();
        assert!(
            message.contains("apps.http.servers.srv0.server_identity"),
            "{value:?} must be located, got {message}"
        );
    }
}
