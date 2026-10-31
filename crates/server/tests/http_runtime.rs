//! End-to-end runtime tests: real TCP listeners, hyper serving, reload, and the admin API.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

fn config(listen: &str, body: &str, admin_disabled: bool) -> Config {
    Config::from_value(serde_json::json!({
        "admin": if admin_disabled {
            serde_json::json!({"disabled": true})
        } else {
            serde_json::json!({"listen": "127.0.0.1:0"})
        },
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
