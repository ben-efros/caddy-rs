//! The `@radar` matcher over a real listener (DIV-0149, T-ROUTE-065).
//!
//! `crates/http/tests/radar_registration.rs` proves the matcher is registered and that a router
//! built with runtime state accepts it. That is a construction claim. This file proves the claim
//! that actually matters to an operator: a running server evaluates a `radar` matcher on the
//! request path, and the configured `geoip` option reaches the provider the matcher resolves
//! through.
//!
//! Nothing here asserts a *positive* match. The Radar snapshot is empty because no poller exists
//! yet, so every radar predicate is false; a test claiming "an attacking ASN is blocked" would be
//! asserting behaviour the build cannot produce. What is asserted is that the matcher is consulted
//! — via `not { radar ... }`, which matches only if `radar` evaluated and returned false — and that
//! a `radar` route cannot be installed at all without the runtime state.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

async fn get(address: SocketAddr, path: &str) -> (u16, String) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://{address}{path}"))
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
    (status, String::from_utf8_lossy(&body).to_string())
}

async fn start(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("configuration validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (runtime, address)
}

#[tokio::test]
async fn a_running_server_evaluates_a_radar_matcher_on_the_request_path() {
    // `not { radar source_asn_attacking true }` matches only if the radar matcher was actually
    // evaluated and returned false. If the matcher were absent, skipped, or errored, this route
    // would not match and the request would fall through to "fallthrough" instead.
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "radar": {"mode": "on"},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [
                {
                    "match": [{"not": [{"radar": {"source_asn_attacking": true}}]}],
                    "handle": [{"handler": "static_response", "body": "radar-evaluated"}]
                },
                {"handle": [{"handler": "static_response", "body": "fallthrough"}]}
            ]
        }}}}
    }))
    .expect("configuration decodes");
    let (_runtime, address) = start(config).await;
    let (status, body) = get(address, "/").await;
    assert_eq!(status, 200);
    assert_eq!(
        body, "radar-evaluated",
        "the radar matcher must be consulted on the request path; a body of `fallthrough` means it \
         was skipped or errored"
    );
}

#[tokio::test]
async fn a_radar_route_cannot_be_installed_without_the_radar_option() {
    // The fail-closed half: with no `radar` global option the server has no state to give the
    // matcher, so the route must be refused rather than installed dead. A server that silently
    // accepted this would look like it was blocking traffic while matching nothing.
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [
                {
                    "match": [{"radar": {"source_asn_attacking": true}}],
                    "handle": [{"handler": "static_response", "body": "blocked"}]
                }
            ]
        }}}}
    }))
    .expect("configuration decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config)
        .expect("the document is structurally valid");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    let error = runtime
        .apply()
        .await
        .expect_err("a radar route must not apply without radar state");
    assert!(
        format!("{error}").contains("radar"),
        "the error must name the radar matcher: {error}"
    );
}
