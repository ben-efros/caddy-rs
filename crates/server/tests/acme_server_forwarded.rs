//! Server-level end-to-end coverage for the `acme_server` forwarded origin (T-TLS-086).
//!
//! The handler unit tests set the `trusted_proxy` request variable directly. These tests drive a
//! real `ServerRuntime` so the variable is produced by the actual server-level
//! `apps.http.servers.<name>.trusted_proxies` policy before routing.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};

fn config(server_fields: Value) -> Config {
    let mut server = json!({
        "listen": ["127.0.0.1:0"],
        "routes": [{"handle": [{"handler": "acme_server"}]}]
    });
    if let (Some(server), Value::Object(extra)) = (server.as_object_mut(), server_fields) {
        server.extend(extra);
    }
    Config::from_value(json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": server}}}
    }))
    .expect("test config decodes")
}

async fn start(config: Config, data_root: &std::path::Path) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(store).with_data_root(data_root);
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .or_else(|| runtime.listener_address("[::1]:0"))
        .expect("listener bound");
    (runtime, address)
}

async fn directory(address: SocketAddr, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut builder = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://{address}/acme/local/directory"))
        .header(http::header::HOST, "acme.test");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::new()))
        .expect("request builds");
    let response = client.request(request).await.expect("request succeeds");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = serde_json::from_slice(&body).unwrap_or_else(|error| {
        panic!(
            "response is not JSON ({error}): {}",
            String::from_utf8_lossy(&body)
        )
    });
    (status, json)
}

#[tokio::test]
async fn server_trusted_proxies_gate_the_acme_forwarded_origin() {
    let directory_root = tempfile::tempdir().expect("data directory");
    let (runtime, address) = start(
        config(json!({
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32"]}
        })),
        directory_root.path(),
    )
    .await;
    let (status, body) = directory(
        address,
        &[
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "public.example"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["newNonce"], "https://public.example/acme/local/new-nonce",
        "a trusted peer's forwarded origin must be honoured through the real server"
    );
    runtime.shutdown().await;

    let directory_root = tempfile::tempdir().expect("data directory");
    let (runtime, address) = start(config(json!({})), directory_root.path()).await;
    let (status, body) = directory(
        address,
        &[
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "public.example"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["newNonce"], "https://acme.test/acme/local/new-nonce",
        "valid forwarded headers from an untrusted peer must be ignored"
    );

    // Validation is not gated by the trusted-proxy policy: a malformed forwarded host is still a
    // loud ACME `malformed` response from an untrusted peer.
    let (status, body) = directory(
        address,
        &[("X-Forwarded-Host", "public.example, other.example")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["type"], "urn:ietf:params:acme:error:malformed",
        "{body}"
    );
    runtime.shutdown().await;
}
