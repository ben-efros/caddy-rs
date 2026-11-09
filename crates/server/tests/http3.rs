//! HTTP/3 over QUIC/UDP listener tests (T-HTTP-030).
//!
//! These are real-socket tests: a real `quinn` endpoint serves HTTP/3 through the same router as
//! HTTP/1.1/2, and a real `h3` client (with a real TLS 1.3 handshake) sends requests. The test
//! certificates are the fixtures used by `http_tls.rs`.

#![cfg(feature = "http3")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::BodyExt;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const EXAMPLE_CERT: &str = include_str!("../../tls/testdata/https/example.com.pem");
const EXAMPLE_KEY: &str = include_str!("../../tls/testdata/https/example.com.key");
const CLIENT_CA: &str = include_str!("../../tls/testdata/auto-https/ca.pem");
const CLIENT_CERT: &str = include_str!("../../tls/testdata/client-auth/client.pem");
const CLIENT_KEY: &str = include_str!("../../tls/testdata/client-auth/client.key");
const BODY: &str = "hello {http.vars.tls.alpn} {http.request.scheme} {http.request.uri.path}";
const CLIENT_CERT_BODY: &str =
    "subject=[{http.request.tls.client.subject}] issuer=[{http.request.tls.client.issuer}] \
     serial=[{http.request.tls.client.serial}] fingerprint=[{http.request.tls.client.fingerprint}] \
     san=[{http.request.tls.client.san.dns_names}] pem=[{http.request.tls.client.certificate_pem}]";

/// Hand out an ephemeral port that no other test in this process has taken.
///
/// Binding `:0` and dropping the socket is a time-of-check/time-of-use race: a parallel test can
/// claim the same number between the probe and the runtime's real bind (this showed up as a
/// sporadic `AddrInUse`). Recording every handed-out port makes intra-process reuse impossible;
/// the underlying TCP+UDP listeners then bind the same number in the two protocol spaces.
fn free_port() -> u16 {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};

    static ISSUED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let issued = ISSUED.get_or_init(|| Mutex::new(HashSet::new()));
    loop {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("bind ephemeral port")
            .local_addr()
            .expect("local addr")
            .port();
        // The runtime binds this number for TCP *and* QUIC/UDP, so a port that only looks free on
        // TCP can still collide with another process's UDP socket (a parallel test binary, or a
        // QUIC endpoint left by an earlier run). Probe both protocols; the UDP probe is closed
        // immediately, but it removes the case where a UDP port was never checked at all.
        let udp_free = std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok();
        let mut guard = issued.lock().expect("port registry");
        if udp_free && guard.insert(port) {
            return port;
        }
    }
}

/// Configuration with TLS material and optional UDP (HTTP/3) listener.
fn config(
    tcp_port: u16,
    udp_port: Option<u16>,
    protocols: Option<&[&str]>,
    routes: serde_json::Value,
) -> Config {
    config_with_options(tcp_port, udp_port, protocols, routes, serde_json::json!({}))
}

/// Like [`config`], but merges extra fields into the `srv0` server object (for example
/// `allow_0rtt` or an mTLS `tls_connection_policies` override).
fn config_with_options(
    tcp_port: u16,
    udp_port: Option<u16>,
    protocols: Option<&[&str]>,
    routes: serde_json::Value,
    server_options: serde_json::Value,
) -> Config {
    let mut listen = vec![format!("127.0.0.1:{tcp_port}")];
    if let Some(udp_port) = udp_port {
        listen.push(format!("udp/127.0.0.1:{udp_port}"));
    }
    let mut server = serde_json::json!({
        "listen": listen,
        "routes": routes,
        "tls_connection_policies": [{}]
    });
    if let Some(protocols) = protocols {
        server["protocols"] = serde_json::json!(protocols);
    }
    if let Some(options) = server_options.as_object() {
        for (key, value) in options {
            server[key] = value.clone();
        }
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {
            "http": {
                "http_port": free_port(),
                "https_port": tcp_port,
                "servers": {"srv0": server}
            },
            "tls": {"certificates": {"load_pem": [
                {"certificate": EXAMPLE_CERT, "key": EXAMPLE_KEY}
            ]}}
        }
    }))
    .expect("test config decodes")
}

/// Client-auth server configuration: `mode` against the fixture client CA, mirroring
/// `http_client_auth.rs` so the h3 assertions can be compared with the h1/h2 path.
fn mtls_config(tcp_port: u16, udp_port: u16, mode: &str, routes: serde_json::Value) -> Config {
    let client_authentication = serde_json::json!({
        "mode": mode,
        "ca": {"provider": "inline", "trusted_ca_certs": [client_ca_base64()]}
    });
    config_with_options(
        tcp_port,
        Some(udp_port),
        Some(&["h1", "h2", "h3"]),
        routes,
        serde_json::json!({
            "tls_connection_policies": [{"client_authentication": client_authentication}]
        }),
    )
}

fn client_ca_base64() -> String {
    use base64::Engine as _;
    let der = caddy_rs_tls::certificates_from_pem(CLIENT_CA)
        .expect("client CA parses")
        .remove(0);
    base64::engine::general_purpose::STANDARD.encode(der.as_ref())
}

fn static_routes() -> serde_json::Value {
    serde_json::json!([{"handle": [{"handler": "static_response", "body": BODY}]}])
}

/// Pick fresh ports for every `listen` entry in the configuration, keeping the `udp/` prefixes.
fn reallocate_ports(config: &Config) -> Config {
    let mut value = serde_json::to_value(config).expect("config to JSON");
    let http = match value.get_mut("apps").and_then(|apps| apps.get_mut("http")) {
        Some(http) => Some(http),
        None => value.get_mut("http"),
    };
    let servers = http
        .and_then(|http| http.get_mut("servers"))
        .and_then(|servers| servers.as_object_mut());
    if let Some(servers) = servers {
        for server in servers.values_mut() {
            if let Some(listen) = server
                .get_mut("listen")
                .and_then(|listen| listen.as_array_mut())
            {
                for entry in listen {
                    let Some(address) = entry.as_str() else {
                        continue;
                    };
                    let (prefix, host) = match address.rsplit_once(':') {
                        Some((head, _port)) => {
                            (head.to_string(), head.rsplit('/').next().unwrap_or(head))
                        }
                        None => continue,
                    };
                    let _ = host;
                    *entry = serde_json::json!(format!("{prefix}:{}", free_port()));
                }
            }
        }
    }
    serde_json::from_value(value).expect("config from JSON")
}

/// `AddrInUse` is the one apply failure the harness retries: the port probes are
/// time-of-check/time-of-use, so another process can claim a number between the probe and the
/// bind. Every other failure is a test bug and must surface.
fn is_addr_in_use(error: &str) -> bool {
    let lower = error.to_lowercase();
    lower.contains("address already in use")
        || lower.contains("addrinuse")
        || lower.contains("address in use")
}

async fn start(config: Config) -> (ServerRuntime, caddy_rs_server::RuntimeStatus) {
    let mut config = config;
    let mut last = None;
    for _ in 0..8 {
        let store = Arc::new(GenerationStore::with_builtin_registry());
        store.load(config.clone()).expect("test config validates");
        let mut runtime = ServerRuntime::new(Arc::clone(&store));
        match runtime.apply().await {
            Ok(status) => return (runtime, status),
            Err(error) => {
                let text = error.to_string();
                if !is_addr_in_use(&text) {
                    panic!("runtime applies: {text}");
                }
                last = Some(text);
                config = reallocate_ports(&config);
            }
        }
    }
    panic!(
        "h3 test listeners could not bind after 8 attempts: {}",
        last.unwrap_or_default()
    );
}

fn client_config(alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    client_config_with(alpn, None, false)
}

/// Build a QUIC client TLS configuration, optionally with a client identity and 0-RTT enabled.
///
/// `enable_early_data` is a rustls client switch: without it the client never offers 0-RTT even
/// when the server's session ticket allows it (quinn's own default client config sets it).
fn client_config_with(
    alpn: Vec<Vec<u8>>,
    identity: Option<(&str, &str)>,
    enable_early_data: bool,
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in caddy_rs_tls::certificates_from_pem(EXAMPLE_CERT).expect("fixture parses") {
        roots.add(certificate).expect("fixture is a valid root");
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(roots);
    let mut config = match identity {
        Some((certificate, key)) => {
            let chain = caddy_rs_tls::certificates_from_pem(certificate).expect("client cert");
            let key = caddy_rs_tls::TlsCertificate::from_pem(certificate, key)
                .expect("client key")
                .private_key()
                .clone_key();
            builder
                .with_client_auth_cert(chain, key)
                .expect("client identity")
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn;
    config.enable_early_data = enable_early_data;
    Arc::new(config)
}

/// A QUIC client endpoint using `config` (HTTP/3 ALPN expected).
fn quic_endpoint(config: Arc<ClientConfig>) -> quinn::Endpoint {
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from((*config).clone())
        .expect("QUIC client config");
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("local addr")).expect("QUIC endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    endpoint
}

async fn connect(
    endpoint: &quinn::Endpoint,
    address: SocketAddr,
) -> Result<quinn::Connection, String> {
    let connecting = endpoint
        .connect(address, "example.com")
        .map_err(|error| format!("QUIC connect: {error}"))?;
    tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .map_err(|_| "QUIC handshake timed out".to_string())?
        .map_err(|error| format!("QUIC handshake: {error}"))
}

struct Http3Response {
    status: u16,
    headers: http::HeaderMap,
    body: Bytes,
}

/// Send one HTTP/3 request over QUIC and return the response.
async fn h3_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<Http3Response, String> {
    let endpoint = quic_endpoint(client_config(vec![b"h3".to_vec()]));
    let connection = connect(&endpoint, address).await?;
    h3_request_on(
        &connection,
        method,
        &format!("https://example.com{path}"),
        &[],
        body,
        None,
    )
    .await
}

/// Send one HTTP/3 request on an existing QUIC connection.
///
/// `headers` are regular request headers; `protocol` inserts the RFC 8441 `:protocol`
/// pseudo-header (`h3` surfaces it as a request extension).
async fn h3_request_on(
    connection: &quinn::Connection,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
    protocol: Option<h3::ext::Protocol>,
) -> Result<Http3Response, String> {
    let (driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| format!("HTTP/3 client: {error}"))?;
    let mut builder = http::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder
        .body(())
        .map_err(|error| format!("request: {error}"))?;
    if let Some(protocol) = protocol {
        request.extensions_mut().insert(protocol);
    }
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|error| format!("send_request: {error}"))?;
    if let Some(body) = body {
        stream
            .send_data(Bytes::from(body.to_string()))
            .await
            .map_err(|error| format!("send_data: {error}"))?;
    }
    stream
        .finish()
        .await
        .map_err(|error| format!("finish: {error}"))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|error| format!("recv_response: {error}"))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut collected = BytesMut::new();
    while let Some(chunk) = stream
        .recv_data()
        .await
        .map_err(|error| format!("recv_data: {error}"))?
    {
        collected.extend_from_slice(chunk.chunk());
    }
    // Keep the driver alive until the request is complete (it owns the connection state).
    drop(driver);
    Ok(Http3Response {
        status,
        headers,
        body: collected.freeze(),
    })
}

/// One HTTP/1.1 TLS request, returning status, headers and body.
async fn h1_request(address: SocketAddr, path: &str) -> (u16, http::HeaderMap, Bytes) {
    let connector = TlsConnector::from(client_config(vec![b"http/1.1".to_vec()]));
    let stream = TcpStream::connect(address).await.expect("TCP connect");
    let server_name = ServerName::try_from("example.com".to_string()).expect("server name");
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");
    let request = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers end");
    let headers_text = String::from_utf8_lossy(&response[..split]).to_string();
    let body = Bytes::copy_from_slice(&response[split + 4..]);
    let mut lines = headers_text.lines();
    let status_line = lines.next().expect("status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .expect("status code");
    let mut headers = http::HeaderMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if let Ok(name) = name.trim().parse::<http::header::HeaderName>() {
                if let Ok(value) = value.trim().parse::<http::HeaderValue>() {
                    headers.append(name, value);
                }
            }
        }
    }
    (status, headers, body)
}

fn udp_address(status: &caddy_rs_server::RuntimeStatus, port: u16) -> SocketAddr {
    // Prefer the configured port; when `start`'s AddrInUse retry re-picked it, fall back to the
    // first bound QUIC listener.
    status
        .listener_address(&format!("udp/127.0.0.1:{port}"))
        .or_else(|| {
            status
                .listener_addresses()
                .find(|(configured, _)| configured.starts_with("udp/"))
                .map(|(_, address)| address)
        })
        .expect("UDP listener bound")
        .parse()
        .expect("UDP listener address")
}

fn tcp_address(status: &caddy_rs_server::RuntimeStatus, port: u16) -> SocketAddr {
    status
        .listener_address(&format!("127.0.0.1:{port}"))
        .or_else(|| {
            status
                .listener_addresses()
                .find(|(configured, _)| !configured.starts_with("udp/"))
                .map(|(_, address)| address)
        })
        .expect("TCP listener bound")
        .parse()
        .expect("TCP listener address")
}

/// One HTTP/2 request over TLS, returning status, headers and body.
async fn h2_request(address: SocketAddr, path: &str) -> (u16, http::HeaderMap, Bytes) {
    use http_body_util::Full;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let connector = TlsConnector::from(client_config(vec![b"h2".to_vec()]));
    let stream = TcpStream::connect(address).await.expect("TCP connect");
    let server_name = ServerName::try_from("example.com".to_string()).expect("server name");
    let stream = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("HTTP/2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!("https://example.com{path}"))
        .body(Full::new(Bytes::new()))
        .expect("request builds");
    let response = sender.send_request(request).await.expect("h2 request");
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("h2 body")
        .to_bytes();
    (status, headers, body)
}

#[tokio::test]
async fn http2_responses_also_advertise_alt_svc() {
    let tcp = free_port();
    let udp = free_port();
    let (runtime, status) = start(config(
        tcp,
        Some(udp),
        Some(&["h1", "h2", "h3"]),
        static_routes(),
    ))
    .await;
    let (status_code, headers, body) = h2_request(tcp_address(&status, tcp), "/h2").await;
    assert_eq!(status_code, 200);
    assert_eq!(String::from_utf8_lossy(&body), "hello h2 https /h2");
    assert_eq!(
        headers
            .get(http::header::ALT_SVC)
            .and_then(|value| value.to_str().ok()),
        Some(format!("h3=\":{udp}\"; ma=2592000").as_str()),
        "HTTP/2 responses advertise the HTTP/3 alternate service"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn http3_static_response_over_real_udp_listener() {
    let tcp = free_port();
    let udp = free_port();
    let (runtime, status) = start(config(
        tcp,
        Some(udp),
        Some(&["h1", "h2", "h3"]),
        static_routes(),
    ))
    .await;
    let address = udp_address(&status, udp);
    let response = h3_request(address, "GET", "/h3-only", None)
        .await
        .expect("HTTP/3 request");
    assert_eq!(response.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "hello h3 https /h3-only",
        "the router must see HTTP/3 with TLS enabled and the h3 ALPN"
    );
    assert_eq!(
        response
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some(response.body.len().to_string().as_str()),
        "HTTP/3 responses carry an explicit Content-Length like Go's server"
    );
    // Caddy does not advertise Alt-Svc on HTTP/3 responses themselves.
    assert!(!response.headers.contains_key(http::header::ALT_SVC));
    runtime.shutdown().await;
}

#[tokio::test]
async fn mixed_tcp_and_udp_listener_serves_both_protocols() {
    let tcp = free_port();
    let udp = free_port();
    let (runtime, status) = start(config(
        tcp,
        Some(udp),
        Some(&["h1", "h2", "h3"]),
        static_routes(),
    ))
    .await;
    let (status_code, headers, body) = h1_request(tcp_address(&status, tcp), "/mixed").await;
    assert_eq!(status_code, 200);
    assert_eq!(
        String::from_utf8_lossy(&body),
        "hello http/1.1 https /mixed"
    );
    assert_eq!(
        headers
            .get(http::header::ALT_SVC)
            .and_then(|value| value.to_str().ok()),
        Some(format!("h3=\":{udp}\"; ma=2592000").as_str()),
        "HTTP/1.1 responses advertise the UDP listener when h3 is enabled"
    );
    let response = h3_request(udp_address(&status, udp), "GET", "/mixed", None)
        .await
        .expect("HTTP/3 request");
    assert_eq!(response.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "hello h3 https /mixed"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn alt_svc_is_only_advertised_when_h3_is_enabled() {
    // h3 explicitly disabled: no h3 listener, no Alt-Svc on h1 responses.
    let tcp = free_port();
    let (runtime, status) = start(config(tcp, None, Some(&["h1", "h2"]), static_routes())).await;
    let (status_code, headers, _) = h1_request(tcp_address(&status, tcp), "/").await;
    assert_eq!(status_code, 200);
    assert!(
        !headers.contains_key(http::header::ALT_SVC),
        "Alt-Svc must not be advertised when protocols do not include h3"
    );
    runtime.shutdown().await;

    // h3 enabled on a TLS listener with no explicit `udp/...`: Caddy derives the UDP listener
    // automatically, so the same port must serve QUIC and be advertised (T-HTTP-046).
    let tcp = free_port();
    let (runtime, status) = start(config(
        tcp,
        None,
        Some(&["h1", "h2", "h3"]),
        static_routes(),
    ))
    .await;
    let (status_code, headers, _) = h1_request(tcp_address(&status, tcp), "/").await;
    assert_eq!(status_code, 200);
    let alt_svc = headers
        .get(http::header::ALT_SVC)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    assert_eq!(
        alt_svc,
        Some(format!("h3=\":{tcp}\"; ma=2592000")),
        "the derived UDP listener must be advertised on h1 responses"
    );
    let response = h3_request(udp_address(&status, tcp), "GET", "/derived", None)
        .await
        .expect("HTTP/3 request on the automatically derived UDP listener");
    assert_eq!(response.status, 200);
    // `BODY` expands the request placeholders, so the derived listener serving the router is
    // proven by the expanded path rather than by the raw template.
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "hello h3 https /derived"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn http3_requests_reach_the_protocol_matcher() {
    let tcp = free_port();
    let udp = free_port();
    let routes = serde_json::json!([
        {
            "match": [{"protocol": "http/3"}],
            "handle": [{"handler": "static_response", "body": "matched http/3"}]
        },
        {"handle": [{"handler": "static_response", "body": "other protocol"}]}
    ]);
    let (runtime, status) = start(config(tcp, Some(udp), Some(&["h1", "h2", "h3"]), routes)).await;
    let response = h3_request(udp_address(&status, udp), "GET", "/proto", None)
        .await
        .expect("HTTP/3 request");
    assert_eq!(String::from_utf8_lossy(&response.body), "matched http/3");
    let (_, _, body) = h1_request(tcp_address(&status, tcp), "/proto").await;
    assert_eq!(String::from_utf8_lossy(&body), "other protocol");
    runtime.shutdown().await;
}

#[tokio::test]
async fn http3_reverse_proxy_to_http1_upstream() {
    let upstream = spawn_upstream().await;
    let tcp = free_port();
    let udp = free_port();
    let routes = serde_json::json!([{
        "handle": [{
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream.to_string()}]
        }]
    }]);
    let (runtime, status) = start(config(tcp, Some(udp), Some(&["h1", "h2", "h3"]), routes)).await;
    let response = h3_request(udp_address(&status, udp), "GET", "/proxied", None)
        .await
        .expect("HTTP/3 proxied request");
    assert_eq!(response.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "upstream /proxied",
        "HTTP/3 requests must reach reverse_proxy and h1 upstreams"
    );
    runtime.shutdown().await;
}

async fn spawn_upstream() -> SocketAddr {
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async move {
                        let body = format!("upstream {}", request.uri().path());
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .body(http_body_util::Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    address
}

#[tokio::test]
async fn http3_head_and_request_bodies_use_the_router_pipeline() {
    let tcp = free_port();
    let udp = free_port();
    let routes = serde_json::json!([{
        "handle": [{"handler": "static_response", "body": BODY}]
    }]);
    let (runtime, status) = start(config(tcp, Some(udp), Some(&["h1", "h2", "h3"]), routes)).await;
    let address = udp_address(&status, udp);
    let response = h3_request(address, "HEAD", "/head", None)
        .await
        .expect("HTTP/3 HEAD request");
    assert_eq!(response.status, 200);
    assert!(
        response.body.is_empty(),
        "HEAD responses carry no body over HTTP/3"
    );
    runtime.shutdown().await;

    // Request bodies are collected and reach the buffered reverse_proxy path.
    let upstream = spawn_echo_upstream().await;
    let tcp = free_port();
    let udp = free_port();
    let routes = serde_json::json!([{
        "handle": [{
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream.to_string()}]
        }]
    }]);
    let (runtime, status) = start(config(tcp, Some(udp), Some(&["h1", "h2", "h3"]), routes)).await;
    let response = h3_request(
        udp_address(&status, udp),
        "POST",
        "/upload",
        Some("h3-body"),
    )
    .await
    .expect("HTTP/3 POST");
    assert_eq!(response.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "POST /upload body=h3-body"
    );
    runtime.shutdown().await;
}

async fn spawn_echo_upstream() -> SocketAddr {
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async move {
                        let method = request.method().to_string();
                        let path = request.uri().path().to_string();
                        let body = request
                            .into_body()
                            .collect()
                            .await
                            .map(|collected| collected.to_bytes())
                            .unwrap_or_default();
                        let response =
                            format!("{method} {path} body={}", String::from_utf8_lossy(&body));
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .body(http_body_util::Full::new(Bytes::from(response)))
                                .unwrap(),
                        )
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    address
}

#[tokio::test]
async fn udp_listener_supervision_keeps_and_removes_sockets() {
    let tcp = free_port();
    let udp = free_port();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config(
            tcp,
            Some(udp),
            Some(&["h1", "h2", "h3"]),
            static_routes(),
        ))
        .expect("config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    let first = runtime.apply().await.expect("first apply");
    let first_udp = udp_address(&first, udp);
    let first_tcp = tcp_address(&first, tcp);
    assert_eq!(first_udp.port(), udp, "the configured UDP port is bound");

    // A reload with the same addresses never rebinds: the bound addresses stay identical and the
    // HTTP/3 listener keeps serving.
    store
        .load(config(
            tcp,
            Some(udp),
            Some(&["h1", "h2", "h3"]),
            static_routes(),
        ))
        .expect("reload config validates");
    let second = runtime.apply().await.expect("reload applies");
    assert_eq!(udp_address(&second, udp), first_udp);
    assert_eq!(tcp_address(&second, tcp), first_tcp);
    let response = h3_request(first_udp, "GET", "/after-reload", None)
        .await
        .expect("HTTP/3 request after reload");
    assert_eq!(response.status, 200);

    // Removing the UDP listener from the config shuts it down; the socket is closed and new QUIC
    // connections are refused.
    store
        .load(config(tcp, None, Some(&["h1", "h2"]), static_routes()))
        .expect("removal config validates");
    let third = runtime.apply().await.expect("removal applies");
    assert!(
        third
            .listener_address(&format!("udp/127.0.0.1:{udp}"))
            .is_none(),
        "the removed UDP listener must be gone"
    );
    let refused = tokio::time::timeout(
        Duration::from_secs(2),
        h3_request(first_udp, "GET", "/", None),
    )
    .await;
    match refused {
        Err(_) => {}     // timed out: no listener is fine
        Ok(Err(_)) => {} // or an immediate connection error
        Ok(Ok(_)) => panic!("removed UDP listener still serves HTTP/3"),
    }
    runtime.shutdown().await;
}

#[test]
fn udp_listener_configuration_is_validated_loudly() {
    let tcp = free_port();
    let udp = free_port();
    let store = Arc::new(GenerationStore::with_builtin_registry());

    // Malformed `udp/` address.
    let mut malformed = config(tcp, None, Some(&["h1", "h2", "h3"]), static_routes());
    let caddy_rs_core::HttpApp { servers, .. } = malformed
        .apps
        .as_mut()
        .and_then(|apps| apps.http.as_mut())
        .unwrap();
    servers.get_mut("srv0").unwrap().listen = vec!["udp/127.0.0.1".to_string()];
    let error = store.load(malformed).expect_err("malformed udp address");
    assert!(
        error.to_string().contains("invalid listen address")
            || error.to_string().contains("expected `host:port`"),
        "{error}"
    );

    // UDP listener without h3 in protocols.
    let config_no_h3 = config(tcp, Some(udp), Some(&["h1", "h2"]), static_routes());
    let error = store.load(config_no_h3).expect_err("udp without h3");
    assert!(error.to_string().contains("h3"), "{error}");

    // UDP listener without TLS: no policies, non-HTTPS port.
    let mut config_cleartext = serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {
            "http_port": free_port(),
            "https_port": free_port(),
            "servers": {"srv0": {
                "listen": [format!("udp/127.0.0.1:{udp}")],
                "protocols": ["h3"],
                "routes": []
            }}
        }}
    });
    let error = store
        .load(Config::from_value(config_cleartext.take()).expect("decodes"))
        .expect_err("udp without TLS");
    assert!(error.to_string().contains("requires TLS"), "{error}");
}

// ---------------------------------------------------------------------------
// T-HTTP-048: client certificates, 0-RTT and upgrade responses over HTTP/3.
// ---------------------------------------------------------------------------

/// The 501 body shared with the buffered router path (`serve_internal_buffered`).
const H3_UPGRADE_BODY: &str =
    "501 Not Implemented: protocol upgrades are not supported over HTTP/3";

#[tokio::test]
async fn http3_client_certificate_placeholders_match_http1() {
    let tcp = free_port();
    let udp = free_port();
    let routes = serde_json::json!([{
        "handle": [{"handler": "static_response", "body": CLIENT_CERT_BODY}]
    }]);
    let (runtime, status) = start(mtls_config(tcp, udp, "require_and_verify", routes)).await;
    let address = udp_address(&status, udp);
    let endpoint = quic_endpoint(client_config_with(
        vec![b"h3".to_vec()],
        Some((CLIENT_CERT, CLIENT_KEY)),
        false,
    ));
    let connection = connect(&endpoint, address).await.expect("QUIC connect");
    let response = h3_request_on(
        &connection,
        "GET",
        "https://example.com/cert",
        &[],
        None,
        None,
    )
    .await
    .expect("HTTP/3 mTLS request");
    assert_eq!(response.status, 200);
    let body = String::from_utf8_lossy(&response.body);
    assert!(body.contains("subject=[CN=client.example.com]"), "{body}");
    assert!(
        body.contains("issuer=[CN=caddy-rs auto-HTTPS test CA]"),
        "{body}"
    );
    assert!(
        body.contains("serial=[") && !body.contains("serial=[]"),
        "serial placeholder must be populated: {body}"
    );
    assert!(
        body.contains("fingerprint=[") && !body.contains("fingerprint=[]"),
        "fingerprint placeholder must be populated: {body}"
    );
    assert!(body.contains("san=[client.example.com]"), "{body}");
    assert!(
        body.contains("pem=[-----BEGIN CERTIFICATE-----"),
        "PEM placeholder must be populated: {body}"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn http3_request_mode_without_client_certificate_expands_empty() {
    let tcp = free_port();
    let udp = free_port();
    let routes = serde_json::json!([{
        "handle": [{"handler": "static_response", "body": CLIENT_CERT_BODY}]
    }]);
    let (runtime, status) = start(mtls_config(tcp, udp, "request", routes)).await;
    let response = h3_request(udp_address(&status, udp), "GET", "/no-cert", None)
        .await
        .expect("HTTP/3 request without a client certificate");
    assert_eq!(response.status, 200);
    let body = String::from_utf8_lossy(&response.body);
    for empty in [
        "subject=[]",
        "issuer=[]",
        "serial=[]",
        "fingerprint=[]",
        "san=[]",
        "pem=[]",
    ] {
        assert!(
            body.contains(empty),
            "missing dummy-empty placeholder `{empty}`: {body}"
        );
    }
    runtime.shutdown().await;
}

/// Complete one HTTP/3 request and let rustls receive the server's TLS 1.3 session ticket, so a
/// following connection can attempt 0-RTT resumption.
async fn warm_up_for_0rtt(endpoint: &quinn::Endpoint, address: SocketAddr) {
    let connection = connect(endpoint, address).await.expect("warm-up connect");
    let response = h3_request_on(
        &connection,
        "GET",
        "https://example.com/warm-up",
        &[],
        None,
        None,
    )
    .await
    .expect("warm-up request");
    assert_eq!(response.status, 200, "warm-up request must succeed");
    drop(connection);
    // The NewSessionTicket arrives after the handshake; give the client a moment to store it.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
async fn start_retries_when_a_requested_port_is_taken() {
    // Hold a TCP port so the first apply fails with AddrInUse, exactly as a parallel test binary
    // can. `start` must re-pick ports and still return a serving runtime, and the address helpers
    // must report the port actually bound rather than the one we asked for.
    let occupied = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("hold a port");
    let taken = occupied.local_addr().expect("local addr").port();
    let (runtime, status) = start(config(taken, None, Some(&["h1", "h2"]), static_routes())).await;
    let address = tcp_address(&status, taken);
    assert_ne!(
        address.port(),
        taken,
        "start must re-pick a taken port instead of failing"
    );
    assert_eq!(address.ip().to_string(), "127.0.0.1");
    runtime.shutdown().await;
}

#[tokio::test]
async fn http3_accepts_0rtt_by_default_like_caddy() {
    let tcp = free_port();
    let udp = free_port();
    let (runtime, status) = start(config(
        tcp,
        Some(udp),
        Some(&["h1", "h2", "h3"]),
        static_routes(),
    ))
    .await;
    let address = udp_address(&status, udp);
    let endpoint = quic_endpoint(client_config_with(vec![b"h3".to_vec()], None, true));
    warm_up_for_0rtt(&endpoint, address).await;

    let connecting = endpoint
        .connect(address, "example.com")
        .expect("QUIC connect");
    let (connection, zero_rtt) = connecting
        .into_0rtt()
        .expect("Caddy's default allow_0rtt behaviour must issue 0-RTT-capable tickets");
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        h3_request_on(
            &connection,
            "GET",
            "https://example.com/zero-rtt",
            &[],
            None,
            None,
        ),
    )
    .await
    .expect("0-RTT request timed out")
    .expect("0-RTT request");
    assert_eq!(response.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "hello h3 https /zero-rtt"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), zero_rtt)
            .await
            .expect("handshake did not complete"),
        "the default HTTP/3 listener must accept early data (Caddy `allow0rtt := true`)"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn http3_allow_0rtt_false_disables_early_data() {
    let tcp = free_port();
    let udp = free_port();
    let (runtime, status) = start(config_with_options(
        tcp,
        Some(udp),
        Some(&["h1", "h2", "h3"]),
        static_routes(),
        serde_json::json!({"allow_0rtt": false}),
    ))
    .await;
    let address = udp_address(&status, udp);
    let endpoint = quic_endpoint(client_config_with(vec![b"h3".to_vec()], None, true));
    warm_up_for_0rtt(&endpoint, address).await;

    // The server's ticket must not advertise early data; if a client still attempts 0-RTT (with
    // keys cached from an earlier configuration), the server must not accept it.
    let connecting = endpoint
        .connect(address, "example.com")
        .expect("QUIC connect");
    match connecting.into_0rtt() {
        Ok((connection, zero_rtt)) => {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                h3_request_on(
                    &connection,
                    "GET",
                    "https://example.com/early-data",
                    &[],
                    None,
                    None,
                ),
            )
            .await;
            let accepted = tokio::time::timeout(Duration::from_secs(5), zero_rtt)
                .await
                .expect("handshake did not complete");
            assert!(
                !accepted,
                "`allow_0rtt: false` must reject early data, but the server accepted it"
            );
        }
        Err(_connecting) => {
            // Expected with a fresh ticket cache: the server did not allow early data at all.
        }
    }

    // Ordinary 1-RTT service still works on the same listener.
    let response = h3_request(address, "GET", "/after-0rtt", None)
        .await
        .expect("1-RTT request after a disabled-0-RTT handshake");
    assert_eq!(response.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "hello h3 https /after-0rtt"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn http3_allow_0rtt_must_be_a_boolean() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    let mut malformed = config(
        free_port(),
        Some(free_port()),
        Some(&["h1", "h2", "h3"]),
        static_routes(),
    );
    let caddy_rs_core::HttpApp { servers, .. } = malformed
        .apps
        .as_mut()
        .and_then(|apps| apps.http.as_mut())
        .unwrap();
    servers
        .get_mut("srv0")
        .unwrap()
        .extra
        .insert("allow_0rtt".to_string(), serde_json::json!("off"));
    store
        .load(malformed)
        .expect("unknown server fields are preserved for apply-time validation");
    let mut runtime = ServerRuntime::new(store);
    let error = runtime
        .apply()
        .await
        .expect_err("a non-boolean allow_0rtt must fail loudly");
    let message = error.to_string();
    assert!(
        message.contains("apps.http.servers.srv0.allow_0rtt"),
        "error must name the field path: {message}"
    );
    assert!(
        message.contains("boolean"),
        "error must explain the expected type: {message}"
    );
}

#[tokio::test]
async fn http3_websocket_upgrade_is_loudly_rejected() {
    let tcp = free_port();
    let udp = free_port();
    let (runtime, status) = start(config(
        tcp,
        Some(udp),
        Some(&["h1", "h2", "h3"]),
        static_routes(),
    ))
    .await;
    let endpoint = quic_endpoint(client_config(vec![b"h3".to_vec()]));
    let connection = connect(&endpoint, udp_address(&status, udp))
        .await
        .expect("QUIC connect");
    let response = h3_request_on(
        &connection,
        "GET",
        "https://example.com/ws",
        &[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-version", "13"),
        ],
        None,
        None,
    )
    .await
    .expect("HTTP/3 upgrade response");
    assert_eq!(response.status, http::StatusCode::NOT_IMPLEMENTED.as_u16());
    assert_eq!(
        response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(String::from_utf8_lossy(&response.body), H3_UPGRADE_BODY);
    runtime.shutdown().await;
}

#[tokio::test]
async fn http3_extended_connect_is_loudly_rejected() {
    let tcp = free_port();
    let udp = free_port();
    let (runtime, status) = start(config(
        tcp,
        Some(udp),
        Some(&["h1", "h2", "h3"]),
        static_routes(),
    ))
    .await;
    let endpoint = quic_endpoint(client_config(vec![b"h3".to_vec()]));
    let connection = connect(&endpoint, udp_address(&status, udp))
        .await
        .expect("QUIC connect");
    let response = h3_request_on(
        &connection,
        "CONNECT",
        "https://example.com/tunnel",
        &[],
        None,
        Some(h3::ext::Protocol::WEB_TRANSPORT),
    )
    .await
    .expect("HTTP/3 extended CONNECT response");
    assert_eq!(response.status, http::StatusCode::NOT_IMPLEMENTED.as_u16());
    assert_eq!(String::from_utf8_lossy(&response.body), H3_UPGRADE_BODY);
    runtime.shutdown().await;
}
