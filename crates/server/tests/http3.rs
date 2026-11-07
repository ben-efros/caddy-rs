//! HTTP/3 over QUIC/UDP listener tests (T-HTTP-030).
//!
//! These are real-socket tests: a real `quinn` endpoint serves HTTP/3 through the same router as
//! HTTP/1.1/2, and a real `h3` client (with a real TLS 1.3 handshake) sends requests. The test
//! certificates are the fixtures used by `http_tls.rs`.

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
const BODY: &str = "hello {http.vars.tls.alpn} {http.request.scheme} {http.request.uri.path}";

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Configuration with TLS material and optional UDP (HTTP/3) listener.
fn config(
    tcp_port: u16,
    udp_port: Option<u16>,
    protocols: Option<&[&str]>,
    routes: serde_json::Value,
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

fn static_routes() -> serde_json::Value {
    serde_json::json!([{"handle": [{"handler": "static_response", "body": BODY}]}])
}

async fn start(config: Config) -> (ServerRuntime, caddy_rs_server::RuntimeStatus) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    let status = runtime.apply().await.expect("runtime applies");
    (runtime, status)
}

fn client_config(alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in caddy_rs_tls::certificates_from_pem(EXAMPLE_CERT).expect("fixture parses") {
        roots.add(certificate).expect("fixture is a valid root");
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
    let client_config = client_config(vec![b"h3".to_vec()]);
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from((*client_config).clone())
        .map_err(|error| format!("QUIC client config: {error}"))?;
    let quic_client = quinn::ClientConfig::new(Arc::new(quic_client));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("local addr"))
        .map_err(|error| format!("QUIC endpoint: {error}"))?;
    endpoint.set_default_client_config(quic_client);
    let connecting = endpoint
        .connect(address, "example.com")
        .map_err(|error| format!("QUIC connect: {error}"))?;
    let connection = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .map_err(|_| "QUIC handshake timed out".to_string())?
        .map_err(|error| format!("QUIC handshake: {error}"))?;
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|error| format!("HTTP/3 client: {error}"))?;
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://example.com{path}"))
        .body(())
        .map_err(|error| format!("request: {error}"))?;
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
    while let Some(mut chunk) = stream
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
    status
        .listener_address(&format!("udp/127.0.0.1:{port}"))
        .expect("UDP listener bound")
        .parse()
        .expect("UDP listener address")
}

fn tcp_address(status: &caddy_rs_server::RuntimeStatus, port: u16) -> SocketAddr {
    status
        .listener_address(&format!("127.0.0.1:{port}"))
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

    // h3 enabled but no UDP listener configured: nothing to advertise (and no silent UDP bind).
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
    assert!(
        !headers.contains_key(http::header::ALT_SVC),
        "Alt-Svc requires a bound UDP listener"
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
    if let caddy_rs_core::HttpApp { servers, .. } = malformed
        .apps
        .as_mut()
        .and_then(|apps| apps.http.as_mut())
        .unwrap()
    {
        servers.get_mut("srv0").unwrap().listen = vec!["udp/127.0.0.1".to_string()];
    }
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
