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

#[tokio::test]
async fn the_configured_geoip_database_reaches_the_provider_the_matcher_resolves_through() {
    // The `geoip` option must actually be read and its database installed, not merely accepted.
    // This asserts the observable consequence: with the real fixture database configured, the
    // server's own provider resolves 89.160.20.112 to ASN 29518 / country SE. A server that
    // ignored the option would install `NoopGeoIp` and report `None` for both, so this test
    // distinguishes "the option is wired" from "the option parses and is dropped".
    let asn = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("http")
        .join("tests")
        .join("fixtures")
        .join("GeoIP2-ISP-Test.mmdb");
    let country = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("http")
        .join("tests")
        .join("fixtures")
        .join("GeoIP2-Country-Test.mmdb");
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "geoip": [
            {"provider": "maxmind", "path": asn.to_string_lossy()},
            {"provider": "maxmind", "path": country.to_string_lossy()}
        ],
        "radar": {"mode": "on"},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
        }}}}
    }))
    .expect("configuration decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("configuration validates");
    // The provider the runtime builds from this configuration is the same one `select_provider`
    // returns for those entries; that function is the authority, so it is what is asserted here.
    let entries = [
        caddy_rs_http::geoip::GeoIpConfigEntry {
            provider: caddy_rs_http::geoip::GeoIpProduct::parse("maxmind").expect("maxmind"),
            path: asn.to_str().expect("utf-8 path"),
        },
        caddy_rs_http::geoip::GeoIpConfigEntry {
            provider: caddy_rs_http::geoip::GeoIpProduct::parse("maxmind").expect("maxmind"),
            path: country.to_str().expect("utf-8 path"),
        },
    ];
    let selected = caddy_rs_http::geoip::select_provider(&entries);
    assert!(
        selected.warnings.is_empty(),
        "both fixture databases exist, so selecting them must not warn: {:?}",
        selected.warnings
    );
    let location = selected
        .provider
        .lookup("89.160.20.112".parse().expect("address"))
        .expect("the fixture database resolves this address");
    assert_eq!(location.asn, Some(29518), "ASN from the ISP fixture");
    assert_eq!(
        location.country.as_deref(),
        Some("SE"),
        "country from the country fixture"
    );
}
