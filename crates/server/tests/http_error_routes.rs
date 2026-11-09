//! End-to-end error routes (`handle_errors`) and reverse_proxy `handle_response` over real
//! listeners (T-ROUTE-012).
//!
//! Caddy sources matched: `modules/caddyhttp/server.go` (error handler chain), `app.go`
//! (`apps.http.servers.*.errors`), `modules/caddyhttp/staticerror.go`, and
//! `modules/caddyhttp/reverseproxy/reverseproxy.go` (`handle_response` + copy handlers).

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

async fn request(address: SocketAddr, path: &str) -> (u16, Bytes) {
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
    (status, body)
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
async fn handle_errors_runs_for_error_handlers_over_a_real_listener() {
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [
                {
                    "match": [{"path": ["/boom*"]}],
                    "handle": [{"handler": "error", "status_code": 403, "error": "forbidden"}]
                },
                {"handle": [{"handler": "static_response", "body": "ok"}]}
            ],
            "errors": {"routes": [
                {
                    "match": [{"expression": "{http.error.status_code} in [403]"}],
                    "handle": [{"handler": "static_response", "status_code": 403,
                                "body": "handled {http.error.status_code} {http.error.status_text}: {http.error.message}"}]
                }
            ]}
        }}}}
    }))
    .expect("config decodes");
    let (runtime, address) = start(config).await;

    let (status, body) = request(address, "/boom").await;
    assert_eq!(status, 403);
    assert_eq!(
        body,
        Bytes::from_static(b"handled 403 Forbidden: forbidden")
    );

    let (status, body) = request(address, "/fine").await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"ok"));

    runtime.shutdown().await;
}

#[tokio::test]
async fn adapted_handle_errors_caddyfile_serves_end_to_end() {
    // Port 0 lets the adapter emit a wildcard ephemeral listener (`:0`); the runtime reports the
    // port the kernel assigned, so there is no fixed-port race.
    let caddyfile = r#"{
	auto_https off
}

http://127.0.0.1:0 {
	error /private* "Unauthorized" 403
	handle_errors 4xx {
		respond "custom error {http.error.status_code}" 403
	}
	respond "ok"
}
"#;
    let adapted = caddy_rs_config::adapt(&caddyfile).expect("Caddyfile adapts");
    let config = Config::from_value(adapted.config).expect("adapted config decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("adapted config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let bound = runtime
        .listener_address(":0")
        .expect("Caddyfile listener bound");
    let address = SocketAddr::from(([127, 0, 0, 1], bound.port()));
    let (status, body) = request(address, "/private/x").await;
    assert_eq!(status, 403);
    assert_eq!(body, Bytes::from_static(b"custom error 403"));
    let (status, body) = request(address, "/fine").await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"ok"));
    runtime.shutdown().await;
}

/// Upstream that answers every request with a fixed status/body/header.
async fn spawn_upstream(
    status: u16,
    body: &'static str,
    headers: Vec<(&'static str, &'static str)>,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let headers = headers.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_request| {
                    let headers = headers.clone();
                    async move {
                        let mut builder = hyper::Response::builder().status(status);
                        for (name, value) in headers {
                            builder = builder.header(name, value);
                        }
                        Ok::<_, Infallible>(
                            builder
                                .body(Full::new(Bytes::from_static(body.as_bytes())))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    address
}

#[tokio::test]
async fn upstream_error_status_triggers_handle_errors_and_handle_response() {
    let upstream = spawn_upstream(503, "down", vec![]).await;

    // 1) handle_response intercepts the upstream 503 and replaces the body.
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": upstream.to_string()}],
                "handle_response": [{
                    "match": {"status_code": [5]},
                    "routes": [{"handle": [
                        {"handler": "static_response", "status_code": 200, "body": "friendly"}
                    ]}]
                }]
            }]}]
        }}}}
    }))
    .expect("config decodes");
    let (runtime, address) = start(config).await;
    let (status, body) = request(address, "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"friendly"));
    runtime.shutdown().await;

    // 2) The proxy's 503 response enters the server error routes when configured.
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{"dial": upstream.to_string()}]
            }]}],
            "errors": {"routes": [
                {
                    "match": [{"expression": "{http.error.status_code} >= 500"}],
                    "handle": [{"handler": "static_response", "status_code": 502,
                                "body": "upstream error {http.error.status_code}"}]
                }
            ]}
        }}}}
    }))
    .expect("config decodes");
    let (runtime, address) = start(config).await;
    let (status, body) = request(address, "/").await;
    assert_eq!(status, 502);
    assert_eq!(body, Bytes::from_static(b"upstream error 503"));
    runtime.shutdown().await;
}
