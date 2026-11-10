//! End-to-end HTTPS termination tests: real TCP listeners, real rustls handshakes, hyper serving.
//!
//! These tests cover the listener policy implemented by the server supervisor:
//!
//! * a TCP listener terminates TLS when its HTTP server declares `tls_connection_policies` or
//!   when its port is the effective HTTPS port (`apps.http.https_port`, default 443);
//! * certificates come from typed `apps.tls.certificates.load_pem`/`load_files`;
//! * SNI selects the configured certificate (exact name);
//! * ALPN negotiates `h2` and `http/1.1`, and the negotiated protocol reaches the request context
//!   as the `tls.alpn` variable (`{http.vars.tls.alpn}`);
//! * cleartext listeners are unchanged (HTTP/1.1 and h2c);
//! * a TLS listener without certificates fails the apply loudly instead of serving cleartext.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const EXAMPLE_CERT: &str = include_str!("../../tls/testdata/https/example.com.pem");
const EXAMPLE_KEY: &str = include_str!("../../tls/testdata/https/example.com.key");
const OTHER_CERT: &str = include_str!("../../tls/testdata/https/other.example.pem");
const OTHER_KEY: &str = include_str!("../../tls/testdata/https/other.example.key");

/// The body template used by test routes: connection scheme plus negotiated ALPN.
const BODY_PLACEHOLDERS: &str = "{http.request.scheme} {http.vars.tls.alpn}";

/// An ephemeral loopback port for derived listeners (released before the runtime binds it).
fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local address")
        .port()
}

/// Build a configuration with one HTTP server and optional TLS material/policies.
fn config(
    listen: &str,
    with_policies: bool,
    https_port: Option<u16>,
    with_certificates: bool,
) -> Config {
    let mut server = serde_json::json!({
        "listen": [listen],
        "routes": [{"handle": [{"handler": "static_response", "body": BODY_PLACEHOLDERS}]}]
    });
    if with_policies {
        server["tls_connection_policies"] = serde_json::json!([{}]);
    }
    let mut http = serde_json::json!({"servers": {"srv0": server}});
    // Automatic HTTPS derives a cleartext redirect/challenge listener for hostless TLS servers
    // (Caddy's catch-all redirects). Tests must not bind the default port 80: an ephemeral
    // http_port keeps every test (and parallel test) on its own socket, exactly like the other
    // auto-HTTPS suites.
    http["http_port"] = serde_json::json!(free_loopback_port());
    if let Some(https_port) = https_port {
        http["https_port"] = serde_json::json!(https_port);
    }
    let mut apps = serde_json::json!({"http": http});
    if with_certificates {
        apps["tls"] = serde_json::json!({
            "certificates": {
                "load_pem": [
                    {"certificate": EXAMPLE_CERT, "key": EXAMPLE_KEY},
                    {"certificate": OTHER_CERT, "key": OTHER_KEY}
                ]
            }
        });
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": apps
    }))
    .expect("test config decodes")
}

/// Start a runtime with a data directory private to this test.
///
/// Every test used to preflight the process-wide `.caddy-rs` under `crates/server`; parallel tests
/// then raced to create the directory and their probe files. The returned `TempDir` keeps the
/// per-test root alive for as long as the runtime and removes it on drop, so a test never observes
/// (or leaves behind) another test's data directory.
async fn start(config: Config) -> (ServerRuntime, SocketAddr, tempfile::TempDir) {
    let data_dir = tempfile::tempdir().expect("per-test data directory");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store)).with_data_root(data_dir.path());
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener is bound");
    (runtime, address, data_dir)
}

/// Build a TLS listener serving exactly one `load_pem` certificate/key pair.
fn config_with_pem_certificate(certificate: &str, key: &str) -> Config {
    let mut http = serde_json::json!({
        "servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "tls_connection_policies": [{}],
            "routes": [{"handle": [{"handler": "static_response", "body": BODY_PLACEHOLDERS}]}]
        }}
    });
    http["http_port"] = serde_json::json!(free_loopback_port());
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {
            "http": http,
            "tls": {"certificates": {"load_pem": [
                {"certificate": certificate, "key": key}
            ]}}
        }
    }))
    .expect("test config decodes")
}

/// Build a TLS listener from `load_files` pairs (`(certificate path, key path)`), preserving
/// configuration order so a failure can name the offending index.
fn config_with_certificate_files(files: &[(String, String)]) -> Config {
    let load_files: Vec<serde_json::Value> = files
        .iter()
        .map(|(certificate, key)| serde_json::json!({"certificate": certificate, "key": key}))
        .collect();
    let mut http = serde_json::json!({
        "servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "tls_connection_policies": [{}],
            "routes": [{"handle": [{"handler": "static_response", "body": BODY_PLACEHOLDERS}]}]
        }}
    });
    http["http_port"] = serde_json::json!(free_loopback_port());
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {
            "http": http,
            "tls": {"certificates": {"load_files": load_files}}
        }
    }))
    .expect("test config decodes")
}

/// Apply a configuration that is expected to fail and return the error message.
///
/// The data directory is per call for the same reason as [`start`]: a failing apply still runs the
/// preflight, and the test must not race another test's directory.
async fn apply_error(config: Config) -> String {
    let data_dir = tempfile::tempdir().expect("per-test data directory");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(store).with_data_root(data_dir.path());
    runtime
        .apply()
        .await
        .expect_err("runtime apply must fail")
        .to_string()
}

fn client_config_with_roots(root_pems: &[&str], alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for pem in root_pems {
        for certificate in caddy_rs_tls::certificates_from_pem(pem).expect("fixture PEM parses") {
            roots.add(certificate).expect("fixture is a valid root");
        }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

fn client_config(alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    client_config_with_roots(&[EXAMPLE_CERT, OTHER_CERT], alpn)
}

async fn tls_connect_with_roots(
    address: SocketAddr,
    server_name: &str,
    alpn: &[&str],
    root_pems: &[&str],
) -> TlsStream<TcpStream> {
    let connector = TlsConnector::from(client_config_with_roots(
        root_pems,
        alpn.iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect(),
    ));
    let stream = TcpStream::connect(address).await.expect("TCP connect");
    let server_name = ServerName::try_from(server_name.to_string()).expect("valid server name");
    connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake")
}

/// Start a TLS listener with one certificate and complete a real HTTP/1.1 request over TLS.
async fn assert_certificate_handshake(name: &str, certificate: &str, key: &str) {
    let (runtime, address, _data_dir) = start(config_with_pem_certificate(certificate, key)).await;
    let mut stream =
        tls_connect_with_roots(address, "localhost", &["http/1.1"], &[certificate]).await;
    assert_eq!(
        negotiated_alpn(&stream).as_deref(),
        Some("http/1.1"),
        "{name}"
    );
    let (status, body) = http1_get(&mut stream, "localhost").await;
    assert_eq!(status, 200, "{name}");
    assert_eq!(body, "https http/1.1", "{name}");
    runtime.shutdown().await;
}

async fn tls_connect(
    address: SocketAddr,
    server_name: &str,
    alpn: &[&str],
) -> TlsStream<TcpStream> {
    tls_connect_with_roots(address, server_name, alpn, &[EXAMPLE_CERT, OTHER_CERT]).await
}

fn negotiated_alpn(stream: &TlsStream<TcpStream>) -> Option<String> {
    stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
}

fn peer_leaf_der(stream: &TlsStream<TcpStream>) -> Vec<u8> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .expect("server certificate present")[0]
        .as_ref()
        .to_vec()
}

fn fixture_leaf_der(pem: &str) -> Vec<u8> {
    caddy_rs_tls::certificates_from_pem(pem).expect("fixture PEM parses")[0]
        .as_ref()
        .to_vec()
}

/// Send one HTTP/1.1 request over `stream` and read the complete response.
async fn http1_get<S>(stream: &mut S, host: &str) -> (u16, String)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("read response");
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response has headers")
        + 4;
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line");
    (
        status,
        String::from_utf8_lossy(&response[split..]).into_owned(),
    )
}

async fn h2_get(stream: TlsStream<TcpStream>) -> (u16, Bytes) {
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("HTTP/2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("GET")
        .uri("https://example.com/")
        .body(Full::new(Bytes::new()))
        .expect("request builds");
    let response = sender.send_request(request).await.expect("h2 request");
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("h2 body")
        .to_bytes();
    (status, body)
}

async fn cleartext_get(address: SocketAddr) -> (u16, Bytes) {
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .uri(format!("http://{address}/"))
        .header(http::header::HOST, "example.com")
        .body(Full::new(Bytes::new()))
        .expect("request builds");
    let response = client.request(request).await.expect("cleartext request");
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
async fn https_http1_request_reports_tls_and_alpn() {
    let (runtime, address, _data_dir) = start(config("127.0.0.1:0", true, None, true)).await;
    let mut stream = tls_connect(address, "example.com", &["http/1.1"]).await;
    assert_eq!(negotiated_alpn(&stream).as_deref(), Some("http/1.1"));

    let (status, body) = http1_get(&mut stream, "example.com").await;
    assert_eq!(status, 200);
    assert_eq!(body, "https http/1.1");
    runtime.shutdown().await;
}

#[tokio::test]
async fn https_h2_request_end_to_end() {
    let (runtime, address, _data_dir) = start(config("127.0.0.1:0", true, None, true)).await;
    let stream = tls_connect(address, "example.com", &["h2"]).await;
    assert_eq!(negotiated_alpn(&stream).as_deref(), Some("h2"));
    let (status, body) = h2_get(stream).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"https h2"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn sni_selects_the_configured_certificate_for_two_names() {
    let (runtime, address, _data_dir) = start(config("127.0.0.1:0", true, None, true)).await;

    let mut example = tls_connect(address, "example.com", &["http/1.1"]).await;
    assert_eq!(peer_leaf_der(&example), fixture_leaf_der(EXAMPLE_CERT));
    let (status, body) = http1_get(&mut example, "example.com").await;
    assert_eq!(status, 200);
    assert_eq!(body, "https http/1.1");

    let mut other = tls_connect(address, "other.example", &["http/1.1"]).await;
    assert_eq!(peer_leaf_der(&other), fixture_leaf_der(OTHER_CERT));
    let (status, body) = http1_get(&mut other, "other.example").await;
    assert_eq!(status, 200);
    assert_eq!(body, "https http/1.1");
    runtime.shutdown().await;
}

#[tokio::test]
async fn unsupported_alpn_falls_back_to_configured_protocol() {
    // The server offers h2 and http/1.1; a client offering only http/1.1 must negotiate it even
    // though h2 is preferred by default.
    let (runtime, address, _data_dir) = start(config("127.0.0.1:0", true, None, true)).await;
    let stream = tls_connect(address, "example.com", &["http/1.1"]).await;
    assert_eq!(negotiated_alpn(&stream).as_deref(), Some("http/1.1"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn cleartext_listener_still_serves_http1() {
    let (runtime, address, _data_dir) = start(config("127.0.0.1:0", false, None, false)).await;
    let (status, body) = cleartext_get(address).await;
    assert_eq!(status, 200);
    // No TLS: `{http.request.scheme}` is `http` and the ALPN variable is empty.
    assert_eq!(body, Bytes::from_static(b"http "));
    runtime.shutdown().await;
}

#[tokio::test]
async fn certificates_alone_do_not_force_tls_on_an_http_listener() {
    // Certificates are configured, but the listener is neither the HTTPS port nor covered by a
    // connection policy: it must stay cleartext (TLS is opt-in per listener policy).
    let (runtime, address, _data_dir) = start(config("127.0.0.1:0", false, None, true)).await;
    let (status, body) = cleartext_get(address).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"http "));
    runtime.shutdown().await;
}

#[tokio::test]
async fn https_port_forces_tls_without_connection_policies() {
    // `https_port: 0` makes the ephemeral test listener the effective HTTPS port, exercising the
    // port-based half of the listener policy without binding a fixed privileged port.
    let (runtime, address, _data_dir) = start(config("127.0.0.1:0", false, Some(0), true)).await;
    let mut stream = tls_connect(address, "example.com", &["http/1.1"]).await;
    assert_eq!(negotiated_alpn(&stream).as_deref(), Some("http/1.1"));
    let (status, body) = http1_get(&mut stream, "example.com").await;
    assert_eq!(status, 200);
    assert_eq!(body, "https http/1.1");
    runtime.shutdown().await;
}

#[tokio::test]
async fn tls_listener_without_certificates_fails_loudly() {
    let data_dir = tempfile::tempdir().expect("per-test data directory");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config("127.0.0.1:0", true, None, false))
        .expect("config validates even without certificates");
    let mut runtime = ServerRuntime::new(store).with_data_root(data_dir.path());
    let error = runtime
        .apply()
        .await
        .expect_err("a TLS listener without certificates must fail the apply");
    let message = error.to_string();
    assert!(
        message.contains("apps.tls.certificates"),
        "error must point at the missing certificates: {message}"
    );
    assert!(message.contains("terminates TLS"), "{message}");
}

#[tokio::test]
async fn strict_sni_host_is_rejected_loudly() {
    // Caddy's `strict_sni_host` changes handshake rejection behaviour; this build does not
    // implement it, so a configuration relying on it must not be served with the fallback cert.
    let mut value = config("127.0.0.1:0", true, None, true)
        .to_value()
        .expect("config serializes");
    value["apps"]["http"]["servers"]["srv0"]["strict_sni_host"] = serde_json::json!(true);
    let config = Config::from_value(value).expect("config decodes");
    let data_dir = tempfile::tempdir().expect("per-test data directory");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(store).with_data_root(data_dir.path());
    let error = runtime
        .apply()
        .await
        .expect_err("strict_sni_host must fail the apply");
    assert!(error.to_string().contains("strict_sni_host"), "{error}");
    assert!(error.to_string().contains("TLS-STRICT-SNI"), "{error}");
}

#[tokio::test]
async fn unimplemented_connection_policy_field_fails_loudly() {
    let mut value = config("127.0.0.1:0", false, None, true)
        .to_value()
        .expect("config serializes");
    value["apps"]["http"]["servers"]["srv0"]["tls_connection_policies"] =
        serde_json::json!([{"default_sni": "example.com"}]);
    let config = Config::from_value(value).expect("config decodes");
    let data_dir = tempfile::tempdir().expect("per-test data directory");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(store).with_data_root(data_dir.path());
    let error = runtime
        .apply()
        .await
        .expect_err("an unimplemented policy field must fail the apply");
    assert!(
        error.to_string().contains("TLS connection policy field"),
        "{error}"
    );
    assert!(error.to_string().contains("TLS-CONN-POLICY"), "{error}");
}

#[tokio::test]
async fn proxy_protocol_header_is_consumed_before_the_tls_handshake() {
    // A TLS server with the proxy_protocol wrapper in REQUIRE mode: a PROXY header is mandatory and
    // must be consumed before rustls sees the ClientHello.
    let mut value = config("127.0.0.1:0", true, None, true)
        .to_value()
        .expect("config serializes");
    value["apps"]["http"]["servers"]["srv0"]["listener_wrappers"] = serde_json::json!([
        {"wrapper": "proxy_protocol", "fallback_policy": "REQUIRE"}
    ]);
    value["apps"]["http"]["servers"]["srv0"]["routes"] = serde_json::json!([{
        "handle": [{"handler": "static_response",
                    "body": "{http.request.remote.host}:{http.request.remote.port}"}]
    }]);
    let config = Config::from_value(value).expect("proxy protocol TLS config decodes");
    let (runtime, address, _data_dir) = start(config).await;

    // With a header the TLS handshake succeeds and the handler sees the header addresses.
    let stream = TcpStream::connect(address).await.expect("TCP connect");
    let mut stream = stream;
    stream
        .write_all(b"PROXY TCP4 203.0.113.7 198.51.100.1 44444 443\r\n")
        .await
        .expect("write PROXY header");
    let connector = TlsConnector::from(client_config(vec![b"http/1.1".to_vec()]));
    let server_name = ServerName::try_from("example.com".to_string()).expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake after a PROXY header");
    let (status, body) = http1_get(&mut tls, "example.com").await;
    assert_eq!(status, 200);
    assert_eq!(body.trim(), "203.0.113.7:44444");

    // Without a header REQUIRE rejects the connection before the TLS handshake.
    let stream = TcpStream::connect(address).await.expect("TCP connect");
    let connector = TlsConnector::from(client_config(vec![]));
    let server_name = ServerName::try_from("example.com".to_string()).expect("server name");
    let result = connector.connect(server_name, stream).await;
    assert!(
        result.is_err(),
        "a missing PROXY header must be rejected before TLS"
    );

    runtime.shutdown().await;
}

// ---------------------------------------------------------------------------
// T-TLS-089: per-algorithm certificate handshakes and key-type diagnostics.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rsa2048_pkcs1_certificate_completes_tls_handshake() {
    assert_certificate_handshake(
        "RSA-2048 PKCS#1",
        include_str!("../../tls/testdata/key-types/rsa2048-pkcs1.pem"),
        include_str!("../../tls/testdata/key-types/rsa2048-pkcs1.key"),
    )
    .await;
}

#[tokio::test]
async fn rsa2048_pkcs8_certificate_completes_tls_handshake() {
    assert_certificate_handshake(
        "RSA-2048 PKCS#8",
        include_str!("../../tls/testdata/key-types/rsa2048-pkcs8.pem"),
        include_str!("../../tls/testdata/key-types/rsa2048-pkcs8.key"),
    )
    .await;
}

#[tokio::test]
async fn rsa4096_certificate_completes_tls_handshake() {
    assert_certificate_handshake(
        "RSA-4096",
        include_str!("../../tls/testdata/key-types/rsa4096.pem"),
        include_str!("../../tls/testdata/key-types/rsa4096.key"),
    )
    .await;
}

#[tokio::test]
async fn ecdsa_p256_sec1_certificate_completes_tls_handshake() {
    assert_certificate_handshake(
        "ECDSA P-256 SEC1",
        include_str!("../../tls/testdata/key-types/p256-sec1.pem"),
        include_str!("../../tls/testdata/key-types/p256-sec1.key"),
    )
    .await;
}

#[tokio::test]
async fn ecdsa_p256_pkcs8_certificate_completes_tls_handshake() {
    assert_certificate_handshake(
        "ECDSA P-256 PKCS#8",
        include_str!("../../tls/testdata/key-types/p256-pkcs8.pem"),
        include_str!("../../tls/testdata/key-types/p256-pkcs8.key"),
    )
    .await;
}

#[tokio::test]
async fn ecdsa_p384_certificate_completes_tls_handshake() {
    assert_certificate_handshake(
        "ECDSA P-384",
        include_str!("../../tls/testdata/key-types/p384.pem"),
        include_str!("../../tls/testdata/key-types/p384.key"),
    )
    .await;
}

#[tokio::test]
async fn ecdsa_p521_sec1_certificate_completes_tls_handshake() {
    assert_certificate_handshake(
        "ECDSA P-521 SEC1",
        include_str!("../../tls/testdata/key-types/p521-sec1.pem"),
        include_str!("../../tls/testdata/key-types/p521-sec1.key"),
    )
    .await;
}

#[tokio::test]
async fn ecdsa_p521_pkcs8_certificate_completes_tls_handshake() {
    assert_certificate_handshake(
        "ECDSA P-521 PKCS#8",
        include_str!("../../tls/testdata/key-types/p521-pkcs8.pem"),
        include_str!("../../tls/testdata/key-types/p521-pkcs8.key"),
    )
    .await;
}

#[tokio::test]
async fn ed25519_certificate_completes_tls_handshake() {
    assert_certificate_handshake(
        "Ed25519",
        include_str!("../../tls/testdata/key-types/ed25519.pem"),
        include_str!("../../tls/testdata/key-types/ed25519.key"),
    )
    .await;
}

#[tokio::test]
async fn secp256k1_certificate_key_is_rejected_with_located_curve_error() {
    let message = apply_error(config_with_pem_certificate(
        include_str!("../../tls/testdata/key-types/secp256k1.pem"),
        include_str!("../../tls/testdata/key-types/secp256k1.key"),
    ))
    .await;
    assert!(
        message.contains("TLS configuration at `apps.tls.certificates.load_pem[0]`"),
        "{message}"
    );
    assert!(message.contains("localhost"), "{message}");
    assert!(message.contains("secp256k1"), "{message}");
    assert!(
        message.contains("x509: unsupported elliptic curve"),
        "{message}"
    );
}

#[tokio::test]
async fn ed448_certificate_key_is_rejected_naming_the_algorithm_oid() {
    let message = apply_error(config_with_pem_certificate(
        include_str!("../../tls/testdata/key-types/ed448.pem"),
        include_str!("../../tls/testdata/key-types/ed448.key"),
    ))
    .await;
    assert!(message.contains("TLS configuration at"), "{message}");
    assert!(message.contains("Ed448"), "{message}");
    assert!(message.contains("1.3.101.113"), "{message}");
    assert!(message.contains("localhost"), "{message}");
}

#[tokio::test]
async fn dsa_certificate_key_is_rejected_naming_the_algorithm_oid() {
    let message = apply_error(config_with_pem_certificate(
        include_str!("../../tls/testdata/key-types/dsa.pem"),
        include_str!("../../tls/testdata/key-types/dsa.key"),
    ))
    .await;
    assert!(message.contains("TLS configuration at"), "{message}");
    assert!(message.contains("DSA"), "{message}");
    assert!(message.contains("1.2.840.10040.4.1"), "{message}");
    assert!(message.contains("localhost"), "{message}");
}

#[tokio::test]
async fn encrypted_private_key_is_rejected_with_caddy_wording() {
    let message = apply_error(config_with_pem_certificate(
        include_str!("../../tls/testdata/key-types/encrypted-p256.pem"),
        include_str!("../../tls/testdata/key-types/encrypted-p256.key"),
    ))
    .await;
    assert!(message.contains("TLS configuration at"), "{message}");
    assert!(
        message.contains("encrypted private keys are not supported"),
        "{message}"
    );
    assert!(message.contains("localhost"), "{message}");
}

#[tokio::test]
async fn second_load_files_certificate_with_unsupported_key_is_named() {
    let directory = tempfile::tempdir().expect("tempdir");
    let first_certificate = directory.path().join("first.pem");
    let first_key = directory.path().join("first.key");
    let second_certificate = directory.path().join("second.pem");
    let second_key = directory.path().join("second.key");
    std::fs::write(
        &first_certificate,
        include_str!("../../tls/testdata/key-types/p256-sec1.pem"),
    )
    .expect("write first certificate");
    std::fs::write(
        &first_key,
        include_str!("../../tls/testdata/key-types/p256-sec1.key"),
    )
    .expect("write first key");
    std::fs::write(
        &second_certificate,
        include_str!("../../tls/testdata/key-types/secp256k1.pem"),
    )
    .expect("write second certificate");
    std::fs::write(
        &second_key,
        include_str!("../../tls/testdata/key-types/secp256k1.key"),
    )
    .expect("write second key");

    let message = apply_error(config_with_certificate_files(&[
        (
            first_certificate.display().to_string(),
            first_key.display().to_string(),
        ),
        (
            second_certificate.display().to_string(),
            second_key.display().to_string(),
        ),
    ]))
    .await;
    assert!(
        message.contains("apps.tls.certificates.load_files[1]"),
        "the error must name the second entry: {message}"
    );
    assert!(message.contains("second.pem"), "{message}");
    assert!(message.contains("localhost"), "{message}");
    assert!(message.contains("secp256k1"), "{message}");
    assert!(
        message.contains("x509: unsupported elliptic curve"),
        "{message}"
    );
}
