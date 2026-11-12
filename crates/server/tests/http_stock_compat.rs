//! Secure-by-default response hardening for `reverse_proxy` (EP-PROXY-05, ADR-0010 §2/§3).
//!
//! These tests drive a real listener and a real (raw TCP) upstream, then assert on the response
//! headers a client actually receives:
//!
//! * the documented five-header profile (HSTS only over TLS) and fingerprint removal in
//!   secure-by-default mode;
//! * `stock_compat true` makes the profile inert (stock Caddy v2.11.9 passthrough);
//! * upstream values and explicit operator configuration win over the implicit profile;
//! * the ADR-0010 §3 identity matrix for the HTTP `Server` header.
//!
//! The normative literals live in `docs/compatibility/STOCK-COMPAT.md` (`DIV-0131`/`DIV-0132`) and
//! are pinned by the unit tests in `crates/http/src/security_profile.rs`; these tests prove the
//! wiring end to end.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http_body_util::Full;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const EXAMPLE_CERT: &str = include_str!("../../tls/testdata/https/example.com.pem");
const EXAMPLE_KEY: &str = include_str!("../../tls/testdata/https/example.com.key");

/// The exact `Permissions-Policy` value from the normative table (ADR-0010 §2).
const PERMISSIONS_POLICY_VALUE: &str =
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
     magnetometer=(), microphone=(), payment=(), usb=()";

/// Spawn a raw HTTP/1.1 upstream that answers every request with a fixed response carrying the
/// fingerprint headers a real application server emits, plus `extra_headers`.
///
/// A raw socket keeps the test independent of hyper's server-side header handling, so the
/// assertions are about what the proxy does to upstream bytes, not about two hyper versions
/// agreeing with each other.
fn spawn_upstream(extra_headers: &'static str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("upstream binds");
    let address = listener.local_addr().expect("upstream address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0u8; 8192];
            // One read is enough: every request in these tests is a header-only GET.
            let _ = stream.read(&mut buffer);
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: 2\r\n\
                 Connection: close\r\n\
                 Server: Kestrel\r\n\
                 X-Powered-By: ASP.NET\r\n\
                 {extra_headers}\r\n\
                 ok"
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    address.to_string()
}

/// One `reverse_proxy` route pointing at `upstream`.
fn reverse_proxy_route(upstream: &str) -> serde_json::Value {
    serde_json::json!({
        "handle": [{
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream}]
        }]
    })
}

/// Build a plaintext listener configuration serving `routes`.
fn config(
    routes: serde_json::Value,
    stock_compat: Option<bool>,
    server_identity: Option<serde_json::Value>,
) -> Config {
    let mut server = serde_json::json!({
        "listen": ["127.0.0.1:0"],
        "routes": routes
    });
    if let Some(identity) = server_identity {
        server["server_identity"] = identity;
    }
    let mut root = serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": server}}}
    });
    if let Some(flag) = stock_compat {
        root["stock_compat"] = serde_json::json!(flag);
    }
    Config::from_value(root).expect("test config decodes")
}

/// Build a TLS listener configuration serving `routes` with the fixture certificate.
fn tls_config(routes: serde_json::Value) -> Config {
    let mut http = serde_json::json!({
        "servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "tls_connection_policies": [{}],
            "routes": routes
        }},
        // Automatic HTTPS derives a cleartext listener for hostless TLS servers; port 0 keeps it
        // ephemeral so the test never binds the default port 80.
        "http_port": 0
    });
    http["https_port"] = serde_json::json!(0);
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {
            "http": http,
            "tls": {"certificates": {"load_pem": [
                {"certificate": EXAMPLE_CERT, "key": EXAMPLE_KEY}
            ]}}
        }
    }))
    .expect("test config decodes")
}

/// Start a runtime with a per-test data directory and return the bound listener address.
async fn start(config: Config) -> (ServerRuntime, SocketAddr, tempfile::TempDir) {
    let data_dir = tempfile::tempdir().expect("per-test data directory");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(store).with_data_root(data_dir.path());
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener is bound");
    (runtime, address, data_dir)
}

/// One cleartext GET; returns the status and response headers.
async fn get(address: SocketAddr, path: &str) -> (http::StatusCode, HeaderMap) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .uri(format!("http://{address}{path}"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("request builds");
    let response = client.request(request).await.expect("request succeeds");
    (response.status(), response.headers().clone())
}

/// One HTTPS/1.1 GET over a real rustls handshake; returns the response headers.
async fn tls_get(address: SocketAddr, host: &str) -> HeaderMap {
    let mut roots = RootCertStore::empty();
    for certificate in caddy_rs_tls::certificates_from_pem(EXAMPLE_CERT).expect("fixture PEM") {
        roots.add(certificate).expect("fixture is a valid root");
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address).await.expect("TCP connect");
    let server_name = ServerName::try_from(host.to_string()).expect("valid server name");
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("write request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("read response");
    parse_response_headers(&response)
}

/// Parse the header block of a raw HTTP/1.1 response.
fn parse_response_headers(response: &[u8]) -> HeaderMap {
    let text = String::from_utf8_lossy(response);
    let head = text.split("\r\n\r\n").next().expect("response head");
    let mut headers = HeaderMap::new();
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (Ok(name), Ok(value)) = (
            name.trim().parse::<HeaderName>(),
            HeaderValue::from_str(value.trim()),
        ) else {
            continue;
        };
        headers.append(name, value);
    }
    headers
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .map(|value| value.to_str().expect("ascii header").to_string())
}

/// Assert the documented profile minus HSTS (the cleartext case).
fn assert_cleartext_profile(headers: &HeaderMap) {
    assert_eq!(
        header(headers, "x-content-type-options").as_deref(),
        Some("nosniff")
    );
    assert_eq!(header(headers, "x-frame-options").as_deref(), Some("DENY"));
    assert_eq!(
        header(headers, "referrer-policy").as_deref(),
        Some("strict-origin-when-cross-origin")
    );
    assert_eq!(
        header(headers, "permissions-policy").as_deref(),
        Some(PERMISSIONS_POLICY_VALUE)
    );
    assert_eq!(
        header(headers, "strict-transport-security"),
        None,
        "HSTS must never be emitted on a cleartext response (ADR-0010 §2)"
    );
    assert_eq!(
        header(headers, "content-security-policy"),
        None,
        "the profile must never invent a CSP (ADR-0010 §8)"
    );
}

#[tokio::test]
async fn default_mode_adds_the_documented_profile_to_proxied_responses() {
    let upstream = spawn_upstream("");
    let (runtime, address, _data_dir) = start(config(
        serde_json::json!([reverse_proxy_route(&upstream)]),
        None,
        None,
    ))
    .await;
    let (status, headers) = get(address, "/").await;
    assert_eq!(status, 200);
    assert_cleartext_profile(&headers);
    // Fingerprints from the upstream are removed in secure-by-default mode (DIV-0131).
    assert_eq!(
        header(&headers, "server"),
        None,
        "upstream `Server` is stripped"
    );
    assert_eq!(
        header(&headers, "x-powered-by"),
        None,
        "upstream `X-Powered-By` is stripped"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn upstream_security_headers_are_never_overridden() {
    let upstream = spawn_upstream(
        "X-Frame-Options: SAMEORIGIN\r\n\
         Content-Security-Policy: default-src 'self'\r\n\
         Referrer-Policy: no-referrer\r\n",
    );
    let (runtime, address, _data_dir) = start(config(
        serde_json::json!([reverse_proxy_route(&upstream)]),
        None,
        None,
    ))
    .await;
    let (_status, headers) = get(address, "/").await;
    // Upstream values win; the profile only fills the gaps.
    assert_eq!(
        header(&headers, "x-frame-options").as_deref(),
        Some("SAMEORIGIN")
    );
    assert_eq!(
        header(&headers, "referrer-policy").as_deref(),
        Some("no-referrer")
    );
    assert_eq!(
        header(&headers, "content-security-policy").as_deref(),
        Some("default-src 'self'")
    );
    assert_eq!(
        header(&headers, "x-content-type-options").as_deref(),
        Some("nosniff")
    );
    assert_eq!(
        header(&headers, "permissions-policy").as_deref(),
        Some(PERMISSIONS_POLICY_VALUE)
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn stock_compat_true_makes_the_profile_inert() {
    let upstream = spawn_upstream("");
    let (runtime, address, _data_dir) = start(config(
        serde_json::json!([reverse_proxy_route(&upstream)]),
        Some(true),
        None,
    ))
    .await;
    let (status, headers) = get(address, "/").await;
    assert_eq!(status, 200);
    // Stock Caddy v2.11.9 behaviour: no profile headers, upstream fingerprints pass through.
    for name in [
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "strict-transport-security",
    ] {
        assert_eq!(header(&headers, name), None, "`{name}` must not be added");
    }
    assert_eq!(header(&headers, "server").as_deref(), Some("Kestrel"));
    assert_eq!(header(&headers, "x-powered-by").as_deref(), Some("ASP.NET"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn explicit_header_directive_wins_over_the_profile() {
    let upstream = spawn_upstream("");
    // The `headers` handler stages response headers and continues, so it must run before the
    // terminal `reverse_proxy` handler.
    let routes = serde_json::json!([{
        "handle": [
            {
                "handler": "headers",
                "response": {"set": {"X-Frame-Options": ["SAMEORIGIN"]}}
            },
            {"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]}
        ]
    }]);
    let (runtime, address, _data_dir) = start(config(routes, None, None)).await;
    let (_status, headers) = get(address, "/").await;
    // ADR-0010 §2 precedence 3: staged operator headers are merged after the handler returns, so
    // the operator value overwrites the profile value.
    assert_eq!(
        header(&headers, "x-frame-options").as_deref(),
        Some("SAMEORIGIN"),
        "an explicit `header` directive must win over the implicit profile"
    );
    assert_eq!(
        header(&headers, "x-content-type-options").as_deref(),
        Some("nosniff"),
        "unconfigured profile headers are still filled"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn header_down_delete_is_not_resurrected_by_the_profile() {
    let upstream = spawn_upstream("");
    let routes = serde_json::json!([{
        "handle": [{
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream}],
            "headers": {"response": {"delete": ["x-frame-options", "referrer-policy"]}}
        }]
    }]);
    let (runtime, address, _data_dir) = start(config(routes, None, None)).await;
    let (_status, headers) = get(address, "/").await;
    // Set-if-absent alone would re-add a deleted header; the profile skips names the operator
    // configured, so an explicit `header_down -Header` wins (ADR-0010 §2).
    assert_eq!(header(&headers, "x-frame-options"), None);
    assert_eq!(header(&headers, "referrer-policy"), None);
    assert_eq!(
        header(&headers, "x-content-type-options").as_deref(),
        Some("nosniff")
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn tls_proxied_response_carries_hsts_and_the_rest_of_the_profile() {
    let upstream = spawn_upstream("");
    let (runtime, address, _data_dir) =
        start(tls_config(serde_json::json!([reverse_proxy_route(
            &upstream
        )])))
        .await;
    let headers = tls_get(address, "example.com").await;
    assert_eq!(
        header(&headers, "strict-transport-security").as_deref(),
        Some("max-age=31536000"),
        "HSTS is emitted on TLS proxied responses"
    );
    assert_eq!(
        header(&headers, "x-content-type-options").as_deref(),
        Some("nosniff")
    );
    assert_eq!(header(&headers, "x-frame-options").as_deref(), Some("DENY"));
    assert_eq!(header(&headers, "server"), None);
    runtime.shutdown().await;
}

#[tokio::test]
async fn proxy_deployment_suppresses_the_server_header() {
    let upstream = spawn_upstream("");
    let (runtime, address, _data_dir) = start(config(
        serde_json::json!([reverse_proxy_route(&upstream)]),
        None,
        None,
    ))
    .await;
    let (_status, headers) = get(address, "/").await;
    // ADR-0010 §3: absent `server_identity` + secure-by-default + a reverse_proxy handler means no
    // `Server` header at all (the upstream's is stripped too).
    assert_eq!(header(&headers, "server"), None);
    runtime.shutdown().await;
}

#[tokio::test]
async fn static_only_server_keeps_the_build_identity() {
    let (runtime, address, _data_dir) = start(config(
        serde_json::json!([{"handle": [{"handler": "static_response", "body": "ok"}]}]),
        None,
        None,
    ))
    .await;
    let (status, headers) = get(address, "/").await;
    assert_eq!(status, 200);
    // No reverse_proxy in the configuration: the identity keeps `caddy-rs/<version>`.
    assert_eq!(
        header(&headers, "server"),
        Some(format!("caddy-rs/{}", caddy_rs_core::VERSION))
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn explicit_server_identity_wins_over_proxy_suppression() {
    let upstream = spawn_upstream("");
    let (runtime, address, _data_dir) = start(config(
        serde_json::json!([reverse_proxy_route(&upstream)]),
        None,
        Some(serde_json::json!("name-only")),
    ))
    .await;
    let (_status, headers) = get(address, "/").await;
    assert_eq!(
        header(&headers, "server").as_deref(),
        Some("Caddy"),
        "an explicit `server_identity` always wins over the reverse-proxy suppression"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn stock_compat_true_resolves_the_stock_caddy_identity() {
    let (runtime, address, _data_dir) = start(config(
        serde_json::json!([{"handle": [{"handler": "static_response", "body": "ok"}]}]),
        Some(true),
        None,
    ))
    .await;
    let (status, headers) = get(address, "/").await;
    assert_eq!(status, 200);
    // ADR-0010 §3: absent + `stock_compat true` is stock Caddy's `Caddy` header.
    assert_eq!(header(&headers, "server").as_deref(), Some("Caddy"));
    runtime.shutdown().await;
}

#[test]
fn malformed_stock_compat_is_a_located_error() {
    // `stock_compat` is decoded with a custom deserializer, so a non-boolean is rejected while the
    // configuration is decoded, with the offending field named.
    let base = serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
        }}}}
    });
    for value in [
        serde_json::json!("yes"),
        serde_json::json!(1),
        serde_json::json!(null),
    ] {
        let mut root = base.clone();
        root["stock_compat"] = value.clone();
        let error = Config::from_value(root)
            .err()
            .unwrap_or_else(|| panic!("`stock_compat: {value}` must be rejected"));
        let message = error.to_string();
        assert!(
            message.contains("stock_compat"),
            "the error must name the field, got {message}"
        );
    }
    // The boolean forms decode.
    for value in [true, false] {
        let mut root = base.clone();
        root["stock_compat"] = serde_json::json!(value);
        let config = Config::from_value(root).expect("a boolean `stock_compat` decodes");
        assert_eq!(config.stock_compat(), value);
    }
}
