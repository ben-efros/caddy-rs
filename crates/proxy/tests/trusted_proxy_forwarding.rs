//! End-to-end trusted-proxy behaviour observable in the proxy crate: `X-Forwarded-*` derivation
//! and `{http.vars.client_ip}` placeholder consumption use the server-derived trusted-proxy
//! context (`trusted_proxy`/`client_ip` request variables) rather than the raw peer alone.
//!
//! Caddy v2.11.7 source: `modules/caddyhttp/reverseproxy/reverseproxy.go::addForwardedHeaders`
//! (peer address for X-Forwarded-For with prior chains only for trusted peers, trusted prior
//! Proto/Host, Unix peer `"@"` special case) and `modules/caddyhttp/server.go`
//! (`determineTrustedProxy` sets `ClientIPVarKey`/`TrustedProxyVarKey` before routing).
//!
//! The server-level derivation itself is covered by `crates/server/tests/http_trusted_proxies.rs`
//! (T-PROXY-025); these tests pin the remaining proxy-side contract, including the Unix-socket
//! trusted peer case.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use caddy_rs_http::{Request, Router};
use caddy_rs_proxy::handler_factory;

fn proxy_router(upstream: &str) -> Router {
    let routes = vec![serde_json::json!({"handle": [{
        "handler": "reverse_proxy",
        "upstreams": [{"dial": upstream}],
        "headers": {"request": {"set": {
            "X-Forwarded-Client-Ip": ["{http.vars.client_ip}"],
            "X-Forwarded-Trusted": ["{http.vars.trusted_proxy}"]
        }}}
    }]})];
    caddy_rs_http::RouterBuilder::new()
        .with_custom_handler(handler_factory())
        .build(&routes)
        .expect("router builds")
}

/// Raw upstream that records the complete request head (request line + headers) of each request
/// and answers 200 with a two-byte body.
fn spawn_capturing_upstream() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&requests);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&chunk[..read]);
                if head.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            sink.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).into_owned());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (address.to_string(), requests)
}

struct TestRequest {
    remote: Option<&'static str>,
    trusted: bool,
    client_ip: &'static str,
    forwarded_for: Option<&'static str>,
    forwarded_proto: Option<&'static str>,
    forwarded_host: Option<&'static str>,
}

impl TestRequest {
    fn peer(trusted: bool, peer: &'static str, client_ip: &'static str) -> Self {
        Self {
            remote: Some(peer),
            trusted,
            client_ip,
            ..Self::no_forwarded_headers()
        }
    }

    fn unix(trusted: bool, client_ip: &'static str) -> Self {
        Self {
            remote: None,
            trusted,
            client_ip,
            ..Self::no_forwarded_headers()
        }
    }

    fn no_forwarded_headers() -> Self {
        Self {
            remote: Some("10.0.0.5:1234"),
            trusted: false,
            client_ip: "10.0.0.5",
            forwarded_for: None,
            forwarded_proto: None,
            forwarded_host: None,
        }
    }

    fn into_request(self) -> Request {
        let remote: Option<SocketAddr> = self.remote.map(|peer| peer.parse().expect("peer addr"));
        let mut request = Request::new(http::Method::GET, "/test".parse().unwrap());
        request.remote_addr = remote;
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request
            .vars
            .insert("trusted_proxy".to_string(), self.trusted.to_string());
        request
            .vars
            .insert("client_ip".to_string(), self.client_ip.to_string());
        if let Some(value) = self.forwarded_for {
            request
                .headers
                .insert("x-forwarded-for", value.parse().unwrap());
        }
        if let Some(value) = self.forwarded_proto {
            request
                .headers
                .insert("x-forwarded-proto", value.parse().unwrap());
        }
        if let Some(value) = self.forwarded_host {
            request
                .headers
                .insert("x-forwarded-host", value.parse().unwrap());
        }
        request
    }
}

fn respond(router: &Router, request: Request) -> caddy_rs_http::Response {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(router.handle(request))
        .expect("handler runs")
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn last_request(requests: &Arc<Mutex<Vec<String>>>) -> String {
    let requests = requests.lock().unwrap();
    requests
        .last()
        .cloned()
        .expect("upstream received a request")
}

#[test]
fn trusted_peer_keeps_and_extends_the_forwarded_chain() {
    let (dial, requests) = spawn_capturing_upstream();
    let router = proxy_router(&dial);
    let response = respond(
        &router,
        TestRequest {
            forwarded_for: Some("198.51.100.7"),
            forwarded_proto: Some("https"),
            forwarded_host: Some("public.example"),
            ..TestRequest::peer(true, "10.0.0.5:1234", "203.0.113.9")
        }
        .into_request(),
    );
    assert_eq!(response.status, http::StatusCode::OK);

    let head = last_request(&requests);
    assert_eq!(
        header_value(&head, "x-forwarded-for"),
        Some("198.51.100.7, 10.0.0.5"),
        "trusted peer keeps the prior chain and appends the transport peer (not client_ip): {head}"
    );
    assert_eq!(header_value(&head, "x-forwarded-proto"), Some("https"));
    assert_eq!(
        header_value(&head, "x-forwarded-host"),
        Some("public.example")
    );
    assert_eq!(
        header_value(&head, "x-forwarded-client-ip"),
        Some("203.0.113.9"),
        "placeholders consume the resolved client_ip variable: {head}"
    );
    assert_eq!(header_value(&head, "x-forwarded-trusted"), Some("true"));
}

#[test]
fn untrusted_peer_replaces_spoofed_forwarded_headers() {
    let (dial, requests) = spawn_capturing_upstream();
    let router = proxy_router(&dial);
    let response = respond(
        &router,
        TestRequest {
            forwarded_for: Some("198.51.100.7"),
            forwarded_proto: Some("https"),
            forwarded_host: Some("public.example"),
            ..TestRequest::peer(false, "10.0.0.5:1234", "10.0.0.5")
        }
        .into_request(),
    );
    assert_eq!(response.status, http::StatusCode::OK);

    let head = last_request(&requests);
    assert_eq!(
        header_value(&head, "x-forwarded-for"),
        Some("10.0.0.5"),
        "untrusted peer: spoofed chain is replaced by the peer: {head}"
    );
    assert_eq!(header_value(&head, "x-forwarded-proto"), Some("http"));
    assert_eq!(header_value(&head, "x-forwarded-host"), Some("example.com"));
    assert_eq!(
        header_value(&head, "x-forwarded-client-ip"),
        Some("10.0.0.5")
    );
    assert_eq!(header_value(&head, "x-forwarded-trusted"), Some("false"));
}

#[test]
fn trusted_unix_peer_keeps_forwarded_headers_without_appending_a_peer() {
    // Caddy: `req.RemoteAddr == "@"` with a trusted Unix peer keeps the prior X-Forwarded-*
    // values and has no peer address to append (clientIP stays empty).
    let (dial, requests) = spawn_capturing_upstream();
    let router = proxy_router(&dial);
    let response = respond(
        &router,
        TestRequest {
            forwarded_for: Some("198.51.100.7"),
            forwarded_proto: Some("https"),
            forwarded_host: Some("public.example"),
            ..TestRequest::unix(true, "203.0.113.9")
        }
        .into_request(),
    );
    assert_eq!(response.status, http::StatusCode::OK);

    let head = last_request(&requests);
    assert_eq!(
        header_value(&head, "x-forwarded-for"),
        Some("198.51.100.7"),
        "trusted Unix peer keeps the chain unchanged: {head}"
    );
    assert_eq!(header_value(&head, "x-forwarded-proto"), Some("https"));
    assert_eq!(
        header_value(&head, "x-forwarded-host"),
        Some("public.example")
    );
    assert_eq!(
        header_value(&head, "x-forwarded-client-ip"),
        Some("203.0.113.9"),
        "resolved client_ip from client_ip_headers is still available: {head}"
    );
}

#[test]
fn untrusted_unix_peer_strips_forwarded_headers() {
    let (dial, requests) = spawn_capturing_upstream();
    let router = proxy_router(&dial);
    let response = respond(
        &router,
        TestRequest {
            forwarded_for: Some("198.51.100.7"),
            forwarded_proto: Some("https"),
            forwarded_host: Some("public.example"),
            ..TestRequest::unix(false, "")
        }
        .into_request(),
    );
    assert_eq!(response.status, http::StatusCode::OK);

    let head = last_request(&requests);
    for header in ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"] {
        assert_eq!(
            header_value(&head, header),
            None,
            "untrusted Unix peer: {header} must be stripped: {head}"
        );
    }
    assert_eq!(
        header_value(&head, "x-forwarded-client-ip"),
        Some(""),
        "untrusted Unix peer has no resolved client IP"
    );
}

#[test]
fn remote_host_placeholder_is_still_the_transport_peer() {
    // Caddy keeps `http.request.remote.*` as the transport peer even when trusted_proxies
    // resolves a different client IP (DIV-0043). Verify through a header_up placeholder.
    let (dial, requests) = spawn_capturing_upstream();
    let routes = vec![serde_json::json!({"handle": [{
        "handler": "reverse_proxy",
        "upstreams": [{"dial": dial}],
        "headers": {"request": {"set": {
            "X-Remote-Host": ["{http.request.remote.host}"],
            "X-Remote-Port": ["{http.request.remote.port}"]
        }}}
    }]})];
    let router = caddy_rs_http::RouterBuilder::new()
        .with_custom_handler(handler_factory())
        .build(&routes)
        .expect("router builds");
    let request = TestRequest::peer(true, "10.0.0.5:1234", "203.0.113.9").into_request();
    assert_eq!(respond(&router, request).status, http::StatusCode::OK);

    let head = last_request(&requests);
    assert_eq!(header_value(&head, "x-remote-host"), Some("10.0.0.5"));
    assert_eq!(header_value(&head, "x-remote-port"), Some("1234"));
}

#[test]
fn ipv6_trusted_peer_extends_the_forwarded_chain() {
    let (dial, requests) = spawn_capturing_upstream();
    let router = proxy_router(&dial);
    let request = TestRequest {
        forwarded_for: Some("2001:db8::7"),
        ..TestRequest::peer(true, "[2001:db8::5]:443", "2001:db8::9")
    }
    .into_request();
    assert_eq!(respond(&router, request).status, http::StatusCode::OK);
    let head = last_request(&requests);
    assert_eq!(
        header_value(&head, "x-forwarded-for"),
        Some("2001:db8::7, 2001:db8::5"),
        "IPv6 trusted peer chain: {head}"
    );
    assert_eq!(
        header_value(&head, "x-forwarded-client-ip"),
        Some("2001:db8::9")
    );
}

#[test]
fn ipv4_mapped_peer_is_canonicalized_in_the_forwarded_chain() {
    let (dial, requests) = spawn_capturing_upstream();
    let router = proxy_router(&dial);
    let mut request = TestRequest::peer(true, "[::ffff:10.0.0.5]:1234", "203.0.113.9");
    request.remote = Some("[::ffff:10.0.0.5]:1234");
    assert_eq!(
        respond(&router, request.into_request()).status,
        http::StatusCode::OK
    );
    let head = last_request(&requests);
    assert_eq!(
        header_value(&head, "x-forwarded-for"),
        Some("10.0.0.5"),
        "IPv4-mapped peer renders as dotted IPv4 (DIV-0098): {head}"
    );
}
