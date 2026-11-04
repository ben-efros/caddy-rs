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

async fn start(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener is bound");
    (runtime, address)
}

fn client_config(alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for pem in [EXAMPLE_CERT, OTHER_CERT] {
        for certificate in caddy_rs_tls::certificates_from_pem(pem).expect("fixture PEM parses") {
            roots.add(certificate).expect("fixture is a valid root");
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

async fn tls_connect(
    address: SocketAddr,
    server_name: &str,
    alpn: &[&str],
) -> TlsStream<TcpStream> {
    let connector = TlsConnector::from(client_config(
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
    let (runtime, address) = start(config("127.0.0.1:0", true, None, true)).await;
    let mut stream = tls_connect(address, "example.com", &["http/1.1"]).await;
    assert_eq!(negotiated_alpn(&stream).as_deref(), Some("http/1.1"));

    let (status, body) = http1_get(&mut stream, "example.com").await;
    assert_eq!(status, 200);
    assert_eq!(body, "https http/1.1");
    runtime.shutdown().await;
}

#[tokio::test]
async fn https_h2_request_end_to_end() {
    let (runtime, address) = start(config("127.0.0.1:0", true, None, true)).await;
    let stream = tls_connect(address, "example.com", &["h2"]).await;
    assert_eq!(negotiated_alpn(&stream).as_deref(), Some("h2"));
    let (status, body) = h2_get(stream).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"https h2"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn sni_selects_the_configured_certificate_for_two_names() {
    let (runtime, address) = start(config("127.0.0.1:0", true, None, true)).await;

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
    let (runtime, address) = start(config("127.0.0.1:0", true, None, true)).await;
    let stream = tls_connect(address, "example.com", &["http/1.1"]).await;
    assert_eq!(negotiated_alpn(&stream).as_deref(), Some("http/1.1"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn cleartext_listener_still_serves_http1() {
    let (runtime, address) = start(config("127.0.0.1:0", false, None, false)).await;
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
    let (runtime, address) = start(config("127.0.0.1:0", false, None, true)).await;
    let (status, body) = cleartext_get(address).await;
    assert_eq!(status, 200);
    assert_eq!(body, Bytes::from_static(b"http "));
    runtime.shutdown().await;
}

#[tokio::test]
async fn https_port_forces_tls_without_connection_policies() {
    // `https_port: 0` makes the ephemeral test listener the effective HTTPS port, exercising the
    // port-based half of the listener policy without binding a fixed privileged port.
    let (runtime, address) = start(config("127.0.0.1:0", false, Some(0), true)).await;
    let mut stream = tls_connect(address, "example.com", &["http/1.1"]).await;
    assert_eq!(negotiated_alpn(&stream).as_deref(), Some("http/1.1"));
    let (status, body) = http1_get(&mut stream, "example.com").await;
    assert_eq!(status, 200);
    assert_eq!(body, "https http/1.1");
    runtime.shutdown().await;
}

#[tokio::test]
async fn tls_listener_without_certificates_fails_loudly() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config("127.0.0.1:0", true, None, false))
        .expect("config validates even without certificates");
    let mut runtime = ServerRuntime::new(store);
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
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(store);
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
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(store);
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
    let (runtime, address) = start(config).await;

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
