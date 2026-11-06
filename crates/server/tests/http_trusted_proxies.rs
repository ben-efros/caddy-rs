//! Server-level `apps.http.servers.<name>.trusted_proxies` / `client_ip_headers` (T-PROXY-025).
//!
//! Caddy's `PrepareRequest` derives, once per request, whether the transport peer is a trusted
//! proxy and what the effective client IP is; the `trusted_proxy`/`client_ip` request variables
//! are then consumed by reverse_proxy (X-Forwarded-* handling, `client_ip_hash`) and by the
//! `{http.vars.client_ip}` placeholder. These tests drive real listeners and a real
//! reverse_proxy upstream, asserting the upstream-visible forwarded headers and the placeholder
//! value for trusted/untrusted peers, strict/non-strict parsing, custom header ordering, and
//! handler-level precedence.

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
use tokio::net::TcpListener;

/// HTTP/1.1 upstream echoing the proxy-generated headers and placeholder values.
async fn spawn_echo_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let service = service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async move {
                        let header = |name: &str| {
                            request
                                .headers()
                                .get_all(name)
                                .iter()
                                .filter_map(|value| value.to_str().ok())
                                .collect::<Vec<_>>()
                                .join(",")
                        };
                        let body = format!(
                            "xff={}\nxfp={}\nxfh={}\nclient_ip={}\ntrusted={}\nx_real_ip={}",
                            header("x-forwarded-for"),
                            header("x-forwarded-proto"),
                            header("x-forwarded-host"),
                            header("x-client-ip"),
                            header("x-trusted-proxy"),
                            header("x-real-ip"),
                        );
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::from(body)))
                                .expect("response"),
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

fn merge(base: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(base), serde_json::Value::Object(extra)) = (base.as_object_mut(), extra) {
        base.extend(extra);
    }
}

fn config(
    upstream: &str,
    listen: &str,
    server_fields: serde_json::Value,
    handler_extra: serde_json::Value,
) -> Config {
    let mut handler = serde_json::json!({
        "handler": "reverse_proxy",
        "upstreams": [{"dial": upstream}],
        "headers": {"request": {"set": {
            "X-Client-IP": ["{http.vars.client_ip}"],
            "X-Trusted-Proxy": ["{http.vars.trusted_proxy}"]
        }}}
    });
    merge(&mut handler, handler_extra);
    let mut server = serde_json::json!({
        "listen": [listen],
        "routes": [{"handle": [handler]}]
    });
    merge(&mut server, server_fields);
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": server}}}
    }))
    .expect("test config decodes")
}

async fn start(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(store);
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .or_else(|| runtime.listener_address("[::1]:0"))
        .expect("listener bound");
    (runtime, address)
}

async fn request(address: SocketAddr, headers: &[(&str, &str)]) -> String {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut builder = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://{address}/probe"))
        .header(http::header::HOST, "example.com");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::new()))
        .expect("request builds");
    let response = client.request(request).await.expect("request succeeds");
    assert_eq!(response.status(), 200);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8(body.to_vec()).expect("utf8 body")
}

fn value<'a>(body: &'a str, name: &str) -> &'a str {
    body.lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("missing `{name}` in body: {body}"))
}

#[tokio::test]
async fn server_trusted_proxies_derives_client_ip_and_trusts_forwarded_headers() {
    let upstream = spawn_echo_upstream().await;
    let (runtime, address) = start(config(
        &upstream,
        "127.0.0.1:0",
        serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32", "10.0.0.0/8"]}
        }),
        serde_json::Value::Null,
    ))
    .await;
    let body = request(
        address,
        &[
            ("X-Forwarded-For", "203.0.113.9, 10.0.0.2"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "prior.example"),
        ],
    )
    .await;
    assert_eq!(
        value(&body, "xff"),
        "203.0.113.9, 10.0.0.2, 127.0.0.1",
        "trusted peer must keep the prior X-Forwarded-For chain and append the peer: {body}"
    );
    assert_eq!(value(&body, "client_ip"), "203.0.113.9", "{body}");
    assert_eq!(value(&body, "trusted"), "true", "{body}");
    assert_eq!(value(&body, "xfp"), "https", "{body}");
    assert_eq!(value(&body, "xfh"), "prior.example", "{body}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn untrusted_peer_ignores_forwarded_headers() {
    let upstream = spawn_echo_upstream().await;
    let (runtime, address) = start(config(
        &upstream,
        "127.0.0.1:0",
        serde_json::json!({}),
        serde_json::Value::Null,
    ))
    .await;
    let body = request(
        address,
        &[
            ("X-Forwarded-For", "203.0.113.9"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "prior.example"),
        ],
    )
    .await;
    assert_eq!(value(&body, "xff"), "127.0.0.1", "{body}");
    assert_eq!(value(&body, "client_ip"), "127.0.0.1", "{body}");
    assert_eq!(value(&body, "trusted"), "false", "{body}");
    assert_eq!(value(&body, "xfh"), "example.com", "{body}");
    assert_eq!(value(&body, "xfp"), "http", "{body}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn strict_mode_walks_client_ip_headers_right_to_left() {
    let upstream = spawn_echo_upstream().await;
    let (runtime, address) = start(config(
        &upstream,
        "127.0.0.1:0",
        serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32", "10.0.0.0/8"]},
            "trusted_proxies_strict": 1
        }),
        serde_json::Value::Null,
    ))
    .await;
    let body = request(address, &[("X-Forwarded-For", "10.0.0.5, 203.0.113.9")]).await;
    assert_eq!(
        value(&body, "client_ip"),
        "203.0.113.9",
        "strict mode takes the right-most value outside the trusted ranges: {body}"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn default_non_strict_mode_uses_the_leftmost_value() {
    let upstream = spawn_echo_upstream().await;
    let (runtime, address) = start(config(
        &upstream,
        "127.0.0.1:0",
        serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32", "10.0.0.0/8"]}
        }),
        serde_json::Value::Null,
    ))
    .await;
    let body = request(address, &[("X-Forwarded-For", "10.0.0.5, 203.0.113.9")]).await;
    assert_eq!(
        value(&body, "client_ip"),
        "10.0.0.5",
        "default (non-strict) mode takes the first valid value left-to-right: {body}"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn client_ip_headers_order_is_honoured() {
    let upstream = spawn_echo_upstream().await;
    let (runtime, address) = start(config(
        &upstream,
        "127.0.0.1:0",
        serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32"]},
            "client_ip_headers": ["X-Real-IP", "X-Forwarded-For"]
        }),
        serde_json::Value::Null,
    ))
    .await;
    let body = request(
        address,
        &[
            ("X-Real-IP", "198.51.100.7"),
            ("X-Forwarded-For", "203.0.113.9"),
        ],
    )
    .await;
    assert_eq!(value(&body, "client_ip"), "198.51.100.7", "{body}");
    runtime.shutdown().await;

    let (runtime, address) = start(config(
        &upstream,
        "127.0.0.1:0",
        serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32"]},
            "client_ip_headers": ["X-Forwarded-For", "X-Real-IP"]
        }),
        serde_json::Value::Null,
    ))
    .await;
    let body = request(
        address,
        &[
            ("X-Real-IP", "198.51.100.7"),
            ("X-Forwarded-For", "203.0.113.9"),
        ],
    )
    .await;
    assert_eq!(value(&body, "client_ip"), "203.0.113.9", "{body}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn handler_level_trusted_proxies_widen_the_server_decision() {
    let upstream = spawn_echo_upstream().await;
    let (runtime, address) = start(config(
        &upstream,
        "127.0.0.1:0",
        serde_json::json!({}),
        serde_json::json!({"trusted_proxies": ["127.0.0.1/32"]}),
    ))
    .await;
    let body = request(
        address,
        &[
            ("X-Forwarded-For", "203.0.113.5"),
            ("X-Forwarded-Host", "prior.example"),
        ],
    )
    .await;
    assert_eq!(
        value(&body, "xff"),
        "203.0.113.5, 127.0.0.1",
        "handler-level trusted_proxies must trust a peer the server did not: {body}"
    );
    assert_eq!(value(&body, "xfh"), "prior.example", "{body}");
    // The server-level derived client IP variable is unchanged (Caddy's handler-level list only
    // widens the forwarded-header trust decision; it does not re-derive `client_ip`).
    assert_eq!(value(&body, "client_ip"), "127.0.0.1", "{body}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn handler_level_trusted_proxies_cannot_narrow_server_trust() {
    let upstream = spawn_echo_upstream().await;
    let (runtime, address) = start(config(
        &upstream,
        "127.0.0.1:0",
        serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32"]}
        }),
        serde_json::json!({"trusted_proxies": ["192.0.2.0/24"]}),
    ))
    .await;
    let body = request(address, &[("X-Forwarded-For", "203.0.113.9")]).await;
    assert_eq!(
        value(&body, "xff"),
        "203.0.113.9, 127.0.0.1",
        "Caddy unions the handler-level list with the server decision, so a narrower handler list \
         does not untrust the server-trusted peer: {body}"
    );
    assert_eq!(value(&body, "client_ip"), "203.0.113.9", "{body}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn ipv6_peer_and_trusted_range() {
    let upstream = spawn_echo_upstream().await;
    let (runtime, address) = start(config(
        &upstream,
        "[::1]:0",
        serde_json::json!({
            "trusted_proxies": {"source": "static", "ranges": ["::1/128"]}
        }),
        serde_json::Value::Null,
    ))
    .await;
    let body = request(address, &[("X-Forwarded-For", "2001:db8::1")]).await;
    assert_eq!(value(&body, "client_ip"), "2001:db8::1", "{body}");
    assert_eq!(value(&body, "trusted"), "true", "{body}");
    assert_eq!(value(&body, "xff"), "2001:db8::1, ::1", "{body}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn unknown_trusted_proxies_source_is_a_located_error() {
    let upstream = spawn_echo_upstream().await;
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config(
            &upstream,
            "127.0.0.1:0",
            serde_json::json!({"trusted_proxies": {"source": "magic", "ranges": []}}),
            serde_json::Value::Null,
        ))
        .expect("core model preserves the server field");
    let mut runtime = ServerRuntime::new(store);
    let error = runtime
        .apply()
        .await
        .expect_err("an unknown trusted_proxies source must fail the apply");
    let message = error.to_string();
    assert!(
        message.contains("apps.http.servers.srv0.trusted_proxies"),
        "error must be located at the trusted_proxies field: {message}"
    );
    assert!(
        message.contains("TRUSTED-PROXIES-SOURCE") && message.contains("magic"),
        "error must name the unsupported source module and tracking id: {message}"
    );
}
