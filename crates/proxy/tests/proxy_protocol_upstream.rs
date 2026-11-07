//! Upstream PROXY protocol (`transport.http.proxy_protocol`): the reverse proxy writes the v1
//! text / v2 binary header on every new upstream TCP connection, before any HTTP bytes and before
//! the TLS handshake. Caddy v2.11.7 source: `modules/caddyhttp/reverseproxy/httptransport.go`
//! (`ProxyProtocol`, `proxyProtocolInfo`, v1/v2 switch, `header.WriteTo(conn)`) and
//! `hosts.go`/`reverseproxy.go` (`ProxyProtocolInfo` from the resolved client IP; destination is
//! the all-zero address because the original destination is not knowable).
//!
//! The tests use real loopback sockets: a fake upstream reads the header, validates it, and (for
//! normal cases) then serves one HTTP/1.1 response.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use caddy_rs_http::{Request, Router};
use caddy_rs_proxy::handler_factory;

fn proxy_router(handler: serde_json::Value) -> Router {
    caddy_rs_http::RouterBuilder::new()
        .with_custom_handler(handler_factory())
        .build(&vec![serde_json::json!({"handle": [handler]})])
        .expect("router builds")
}

fn proxy_handler(dial: &str, transport: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "handler": "reverse_proxy",
        "upstreams": [{"dial": dial}],
        "transport": transport,
    })
}

fn get_request(remote: &str) -> Request {
    let mut request = Request::new(http::Method::GET, "/test".parse().unwrap());
    request.remote_addr = Some(remote.parse().unwrap());
    request
        .headers
        .insert(http::header::HOST, "example.com".parse().unwrap());
    request
}

/// One connection accepted by the fake upstream: the first bytes, split into the PROXY header and
/// the bytes that followed it.
#[derive(Debug, Clone)]
struct Captured {
    header: Vec<u8>,
    after: Vec<u8>,
}

/// Spawn a fake upstream that reads one PROXY protocol v1 header (terminated by CRLF), captures the
/// following bytes, and then serves a minimal HTTP/1.1 200 response. Returns the dial address and
/// the capture slot.
fn spawn_v1_upstream() -> (String, Arc<Mutex<Vec<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(false).unwrap();
    let captures = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captures);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                header.push(byte[0]);
                if header.ends_with(b"\r\n") {
                    break;
                }
            }
            // Read the HTTP request head so we can prove the header preceded it.
            let mut rest = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                rest.extend_from_slice(&chunk[..read]);
                if rest.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            sink.lock().unwrap().push(Captured {
                header: header.clone(),
                after: rest.clone(),
            });
            if String::from_utf8_lossy(&header).starts_with("GET ") {
                // No PROXY header; still answer so a regression is visible as a 200, not a hang.
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (address.to_string(), captures)
}

/// Spawn a fake upstream that validates a v2 binary header, captures the bytes that follow it, and
/// serves a minimal HTTP/1.1 200 response.
fn spawn_v2_upstream() -> (String, Arc<Mutex<Vec<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let address = listener.local_addr().unwrap();
    let captures = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captures);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut prefix = [0u8; 16];
            if stream.read_exact(&mut prefix).is_err() {
                break;
            }
            let length = u16::from_be_bytes([prefix[14], prefix[15]]) as usize;
            let mut body = vec![0u8; length];
            if stream.read_exact(&mut body).is_err() {
                break;
            }
            let mut rest = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                rest.extend_from_slice(&chunk[..read]);
                if rest.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let mut header = prefix.to_vec();
            header.extend_from_slice(&body);
            sink.lock().unwrap().push(Captured {
                header,
                after: rest,
            });
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (address.to_string(), captures)
}

fn respond(router: &Router, request: Request) -> caddy_rs_http::Response {
    // Tiny blocking adapter so the tests can stay synchronous while the router is async.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(router.handle(request))
        .expect("handler runs")
}

fn header_text(captured: &Captured) -> String {
    String::from_utf8(captured.header.clone()).expect("v1 header is UTF-8")
}

#[test]
fn sends_v1_header_with_client_source_and_zero_destination_before_http() {
    let (dial, captures) = spawn_v1_upstream();
    let router = proxy_router(proxy_handler(
        &dial,
        serde_json::json!({"protocol": "http", "proxy_protocol": "v1"}),
    ));
    let response = respond(&router, get_request("192.0.2.10:5555"));
    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(response.body, Bytes::from_static(b"ok"));

    let captured = captures.lock().unwrap();
    let captured = captured.first().expect("upstream accepted the connection");
    assert_eq!(
        header_text(captured),
        "PROXY TCP4 192.0.2.10 0.0.0.0 0 0\r\n",
        "Caddy sends the resolved client IP with port 0 and an all-zero destination"
    );
    let following = String::from_utf8_lossy(&captured.after);
    assert!(
        following.starts_with("GET /test HTTP/1.1\r\n"),
        "the PROXY header must precede the HTTP request bytes, got: {following:?}"
    );
    assert!(
        following.contains("host: example.com"),
        "the forwarded Host header is unchanged: {following:?}"
    );
}

#[test]
fn v1_source_uses_the_resolved_client_ip_variable() {
    // Caddy's `ProxyProtocolInfo` uses `client_ip` (trusted-proxy aware), not the direct peer.
    let (dial, captures) = spawn_v1_upstream();
    let router = proxy_router(proxy_handler(
        &dial,
        serde_json::json!({"protocol": "http", "proxy_protocol": "v1"}),
    ));
    let mut request = get_request("192.0.2.10:5555");
    request
        .vars
        .insert("client_ip".to_string(), "198.51.100.7".to_string());
    assert_eq!(respond(&router, request).status, http::StatusCode::OK);

    let captured = captures.lock().unwrap();
    assert_eq!(
        header_text(captured.first().expect("one connection")),
        "PROXY TCP4 198.51.100.7 0.0.0.0 0 0\r\n"
    );
}

#[test]
fn sends_v2_binary_header_with_ipv4_addresses_before_http() {
    let (dial, captures) = spawn_v2_upstream();
    let router = proxy_router(proxy_handler(
        &dial,
        serde_json::json!({"protocol": "http", "proxy_protocol": "v2"}),
    ));
    assert_eq!(
        respond(&router, get_request("192.0.2.10:5555")).status,
        http::StatusCode::OK
    );

    let captured = captures.lock().unwrap();
    let captured = captured.first().expect("upstream accepted the connection");
    assert_eq!(
        &captured.header[..12],
        b"\r\n\r\n\0\r\nQUIT\n",
        "v2 signature"
    );
    assert_eq!(captured.header[12], 0x21, "version 2 + PROXY command");
    assert_eq!(captured.header[13], 0x11, "AF_INET + STREAM");
    assert_eq!(
        u16::from_be_bytes([captured.header[14], captured.header[15]]),
        12,
        "IPv4 address block length"
    );
    assert_eq!(&captured.header[16..20], &[192, 0, 2, 10], "source address");
    assert_eq!(&captured.header[20..24], &[0, 0, 0, 0], "zero destination");
    assert_eq!(
        u16::from_be_bytes([captured.header[24], captured.header[25]]),
        0,
        "source port 0 (Caddy's client_ip carries no port)"
    );
    assert_eq!(
        u16::from_be_bytes([captured.header[26], captured.header[27]]),
        0,
        "destination port 0"
    );
    assert!(
        String::from_utf8_lossy(&captured.after).starts_with("GET /test HTTP/1.1\r\n"),
        "the v2 header must precede the HTTP request bytes"
    );
}

#[test]
fn sends_ipv6_v1_header_with_zero_destination_of_the_same_family() {
    let (dial, captures) = spawn_v1_upstream();
    let router = proxy_router(proxy_handler(
        &dial,
        serde_json::json!({"protocol": "http", "proxy_protocol": "v1"}),
    ));
    let mut request = get_request("192.0.2.10:5555");
    request
        .vars
        .insert("client_ip".to_string(), "2001:db8::1".to_string());
    assert_eq!(respond(&router, request).status, http::StatusCode::OK);
    let captured = captures.lock().unwrap();
    assert_eq!(
        header_text(captured.first().expect("one connection")),
        "PROXY TCP6 2001:db8::1 :: 0 0\r\n"
    );
}

#[test]
fn tls_upstream_receives_the_proxy_header_before_the_client_hello() {
    // The fake server is plain TCP: it reads the PROXY header and then the next byte, which must
    // be the TLS handshake record (0x16) — proving Caddy's ordering (header written before the
    // TLS client wraps the connection). The handshake then fails, which the proxy surfaces.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let address = listener.local_addr().unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&observed);
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut captured = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap_or(0) > 0 {
                captured.push(byte[0]);
                if captured.ends_with(b"\r\n") {
                    break;
                }
            }
            let mut first_tls_byte = [0u8; 1];
            let read = stream.read(&mut first_tls_byte).unwrap_or(0);
            sink.lock()
                .unwrap()
                .push((captured, read, first_tls_byte[0]));
        }
    });

    let router = proxy_router(proxy_handler(
        &address.to_string(),
        serde_json::json!({
            "protocol": "http",
            "tls": {"insecure_skip_verify": true},
            "proxy_protocol": "v1"
        }),
    ));
    // The TLS handshake fails, which the proxy reports as an upstream failure (502).
    assert_eq!(
        respond(&router, get_request("192.0.2.10:5555")).status,
        http::StatusCode::BAD_GATEWAY
    );
    for _ in 0..100 {
        if !observed.lock().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let observed = observed.lock().unwrap();
    let (header, read, first_tls_byte) =
        observed.first().expect("upstream accepted the connection");
    assert_eq!(*read, 1, "the TLS handshake started after the header");
    assert_eq!(
        String::from_utf8_lossy(header),
        "PROXY TCP4 192.0.2.10 0.0.0.0 0 0\r\n"
    );
    assert_eq!(
        *first_tls_byte, 0x16,
        "TLS handshake record follows the header"
    );
}

#[test]
fn h2c_upstream_receives_the_proxy_header_before_the_http2_preface() {
    // Cleartext HTTP/2 (prior knowledge) must still receive the PROXY header first (Caddy writes
    // it before the transport starts writing the HTTP/2 preface).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let address = listener.local_addr().unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&observed);
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap_or(0) > 0 {
                header.push(byte[0]);
                if header.ends_with(b"\r\n") {
                    break;
                }
            }
            let mut preface = vec![0u8; 24];
            let read = stream.read(&mut preface).unwrap_or(0);
            sink.lock().unwrap().push((header, read, preface));
        }
    });

    let router = proxy_router(proxy_handler(
        &address.to_string(),
        serde_json::json!({"protocol": "http", "versions": ["h2c"], "proxy_protocol": "v1"}),
    ));
    assert_eq!(
        respond(&router, get_request("192.0.2.10:5555")).status,
        http::StatusCode::BAD_GATEWAY,
        "the fake server does not complete an HTTP/2 exchange"
    );
    for _ in 0..100 {
        if !observed.lock().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let observed = observed.lock().unwrap();
    let (header, read, preface) = observed.first().expect("upstream accepted the connection");
    assert_eq!(
        String::from_utf8_lossy(header),
        "PROXY TCP4 192.0.2.10 0.0.0.0 0 0\r\n"
    );
    assert_eq!(*read, 24);
    assert_eq!(
        preface.as_slice(),
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        "the HTTP/2 client preface follows the PROXY header"
    );
}

#[test]
fn retries_send_a_proxy_header_on_every_connection() {
    // The first attempt dials a closed port (a real dial error, which Caddy retries), then the
    // listener is rebound on the same address and must receive the PROXY header on the retry
    // connection.
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let headers = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&headers);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        let listener = loop {
            match TcpListener::bind(address) {
                Ok(listener) => break listener,
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap_or(0) > 0 {
                header.push(byte[0]);
                if header.ends_with(b"\r\n") {
                    break;
                }
            }
            sink.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&header).to_string());
            let mut rest = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                rest.extend_from_slice(&chunk[..read]);
                if rest.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });

    let router = proxy_router(serde_json::json!({
        "handler": "reverse_proxy",
        "upstreams": [{"dial": address.to_string()}],
        "transport": {"protocol": "http", "proxy_protocol": "v1"},
        "load_balancing": {"retries": 1, "try_interval": 200000000u64}
    }));
    let response = respond(&router, get_request("192.0.2.10:5555"));
    assert_eq!(
        response.status,
        http::StatusCode::OK,
        "the retry after the dial error succeeded"
    );
    let headers = headers.lock().unwrap();
    assert_eq!(
        headers.as_slice(),
        &["PROXY TCP4 192.0.2.10 0.0.0.0 0 0\r\n".to_string()],
        "the retry connection carries the PROXY header"
    );
}

#[test]
fn unknown_proxy_protocol_values_are_located_config_errors() {
    let error = caddy_rs_proxy::ReverseProxyHandler::from_json(
        &serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "127.0.0.1:8080"}],
            "transport": {"protocol": "http", "proxy_protocol": "v3"}
        }),
        "handler",
    )
    .err()
    .expect("v3 must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("transport.proxy_protocol") && message.contains("v3"),
        "located error naming the value: {message}"
    );

    let error = caddy_rs_proxy::ReverseProxyHandler::from_json(
        &serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "127.0.0.1:8080"}],
            "transport": {"protocol": "http", "proxy_protocol": 42}
        }),
        "handler",
    )
    .err()
    .expect("non-string values must be rejected");
    assert!(error.to_string().contains("must be a string"), "{error}");
}

#[test]
fn unix_upstreams_reject_proxy_protocol_loudly() {
    let error = caddy_rs_proxy::ReverseProxyHandler::from_json(
        &serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "unix//run/app.sock"}],
            "transport": {"protocol": "http", "proxy_protocol": "v1"}
        }),
        "handler",
    )
    .err()
    .expect("Unix-socket upstreams cannot receive a PROXY protocol header");
    assert!(
        error.to_string().contains("Unix-socket upstreams"),
        "{error}"
    );
}

#[test]
fn fastcgi_transport_rejects_proxy_protocol_loudly() {
    let error = caddy_rs_proxy::ReverseProxyHandler::from_json(
        &serde_json::json!({
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "127.0.0.1:9000"}],
            "transport": {"protocol": "fastcgi", "proxy_protocol": "v1"}
        }),
        "handler",
    )
    .err()
    .expect("FastCGI has no PROXY protocol support");
    assert!(error.to_string().contains("proxy_protocol"), "{error}");
}
