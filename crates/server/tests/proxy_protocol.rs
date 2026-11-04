//! PROXY protocol listener wrapper tests (T-HTTP-043).
//!
//! Real TCP listeners and raw sockets: each test writes an optional PROXY protocol header before
//! the HTTP request and asserts the addresses seen by the handler (via `{http.request.remote.*}`
//! and the local-address request variables) and the policy behaviour for missing/malformed
//! headers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BODY: &str = "remote={http.request.remote.host}:{http.request.remote.port} \
                    local={http.vars.http.request.local.host}:{http.vars.http.request.local.port}";

/// One server with an optional `listener_wrappers` array and the address-echo body.
fn config(listener_wrappers: serde_json::Value) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "listener_wrappers": listener_wrappers,
            "routes": [{"handle": [{"handler": "static_response", "body": BODY}]}]
        }}}}
    }))
    .expect("test config decodes")
}

fn proxy_wrapper(options: serde_json::Value) -> serde_json::Value {
    let mut wrapper = serde_json::json!({"wrapper": "proxy_protocol"});
    if let serde_json::Value::Object(options) = options {
        for (key, value) in options {
            wrapper[key] = value;
        }
    }
    serde_json::json!([wrapper])
}

async fn start(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (runtime, address)
}

/// Send an optional PROXY header followed by a GET request; return the raw response bytes.
async fn raw_get(address: SocketAddr, header: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let mut request = header.to_vec();
    request.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    stream.write_all(&request).await.expect("write request");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(read)) => response.extend_from_slice(&chunk[..read]),
        }
    }
    response
}

fn body_text(response: &[u8]) -> String {
    let text = String::from_utf8_lossy(response);
    match text.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_string(),
        None => String::new(),
    }
}

/// Build a PROXY protocol v2 header.
fn v2_header(command: u8, family_protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    header.push(0x20 | command);
    header.push(family_protocol);
    header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    header.extend_from_slice(payload);
    header
}

fn v2_ipv4_payload(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&source);
    payload.extend_from_slice(&destination);
    payload.extend_from_slice(&source_port.to_be_bytes());
    payload.extend_from_slice(&destination_port.to_be_bytes());
    payload
}

#[tokio::test]
async fn v1_header_replaces_remote_and_local_addresses() {
    let (runtime, address) = start(config(proxy_wrapper(serde_json::json!({})))).await;
    let response = raw_get(
        address,
        b"PROXY TCP4 203.0.113.7 198.51.100.1 44444 443\r\n",
    )
    .await;
    let body = body_text(&response);
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "response: {}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(
        body.trim(),
        "remote=203.0.113.7:44444 local=198.51.100.1:443"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn v2_header_replaces_remote_and_local_addresses() {
    let (runtime, address) = start(config(proxy_wrapper(serde_json::json!({})))).await;
    let payload = v2_ipv4_payload([203, 0, 113, 9], [198, 51, 100, 2], 55555, 8443);
    let response = raw_get(address, &v2_header(0x01, 0x11, &payload)).await;
    assert_eq!(
        body_text(&response).trim(),
        "remote=203.0.113.9:55555 local=198.51.100.2:8443"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn v1_unknown_v2_local_and_unspec_keep_transport_addresses() {
    let (runtime, address) = start(config(proxy_wrapper(serde_json::json!({})))).await;

    // v1 UNKNOWN: no address information; transport addresses stay in effect.
    let response = raw_get(address, b"PROXY UNKNOWN\r\n").await;
    let body = body_text(&response);
    assert!(body.trim().starts_with("remote=127.0.0.1:"), "body: {body}");
    assert!(
        body.trim()
            .ends_with(&format!("local=127.0.0.1:{}", address.port())),
        "body: {body}"
    );

    // v2 LOCAL: the connection comes from the proxy itself.
    let response = raw_get(address, &v2_header(0x00, 0x00, &[])).await;
    assert!(body_text(&response).trim().starts_with("remote=127.0.0.1:"));

    // v2 AF_UNSPEC with an empty address block.
    let response = raw_get(address, &v2_header(0x01, 0x00, &[])).await;
    assert!(body_text(&response).trim().starts_with("remote=127.0.0.1:"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn no_header_is_accepted_with_the_default_policy() {
    let (runtime, address) = start(config(proxy_wrapper(serde_json::json!({})))).await;
    let response = raw_get(address, b"").await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let body = body_text(&response);
    let expected_local = format!("local=127.0.0.1:{}", address.port());
    assert!(body.trim().starts_with("remote=127.0.0.1:"));
    assert!(body.trim().ends_with(&expected_local), "body: {body}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn malformed_headers_are_rejected_loudly() {
    let (runtime, address) = start(config(proxy_wrapper(serde_json::json!({})))).await;

    for header in [
        b"PROXY BOGUS 1.2.3.4\r\n".to_vec(),
        b"PROXY TCP4 999.0.0.1 198.51.100.1 1 2\r\n".to_vec(),
        b"PROXY TCP4 203.0.113.7 198.51.100.1 44444\r\n".to_vec(),
        b"PROXY TCP4 203.0.113.7".to_vec(),
        // v2 with an unsupported version nibble.
        {
            let mut header = v2_header(
                0x01,
                0x11,
                &v2_ipv4_payload([1, 2, 3, 4], [5, 6, 7, 8], 1, 2),
            );
            header[12] = 0x11;
            header
        },
        // v2 declaring a payload it does not send (truncated header).
        {
            let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
            header
        },
    ] {
        let response = raw_get(address, &header).await;
        assert!(
            !response.starts_with(b"HTTP/1.1 200"),
            "malformed header `{}` must reject the connection, got: {}",
            String::from_utf8_lossy(&header),
            String::from_utf8_lossy(&response)
        );
    }
    runtime.shutdown().await;
}

#[tokio::test]
async fn require_policy_requires_a_header() {
    let (runtime, address) = start(config(proxy_wrapper(
        serde_json::json!({"fallback_policy": "REQUIRE"}),
    )))
    .await;
    let missing = raw_get(address, b"").await;
    assert!(!missing.starts_with(b"HTTP/1.1 200"), "header required");
    let present = raw_get(
        address,
        b"PROXY TCP4 203.0.113.7 198.51.100.1 44444 443\r\n",
    )
    .await;
    assert_eq!(
        body_text(&present).trim(),
        "remote=203.0.113.7:44444 local=198.51.100.1:443"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn reject_policy_rejects_connections_with_a_header() {
    let (runtime, address) = start(config(proxy_wrapper(
        serde_json::json!({"fallback_policy": "REJECT"}),
    )))
    .await;
    let with_header = raw_get(
        address,
        b"PROXY TCP4 203.0.113.7 198.51.100.1 44444 443\r\n",
    )
    .await;
    assert!(!with_header.starts_with(b"HTTP/1.1 200"));
    let without_header = raw_get(address, b"").await;
    assert!(without_header.starts_with(b"HTTP/1.1 200"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn skip_policy_does_not_read_a_header() {
    let (runtime, address) = start(config(proxy_wrapper(
        serde_json::json!({"fallback_policy": "SKIP"}),
    )))
    .await;
    // Without a header the request works normally.
    let response = raw_get(address, b"").await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    // With a header the unread bytes are parsed as HTTP, so it cannot succeed as a request.
    let with_header = raw_get(
        address,
        b"PROXY TCP4 203.0.113.7 198.51.100.1 44444 443\r\n",
    )
    .await;
    assert!(!with_header.starts_with(b"HTTP/1.1 200"));
    runtime.shutdown().await;
}

#[tokio::test]
async fn allow_and_deny_cidr_ranges_control_the_policy() {
    // Denied peer: a header is rejected, a headerless connection is still accepted.
    let (runtime, address) = start(config(proxy_wrapper(
        serde_json::json!({"deny": ["127.0.0.1/32"]}),
    )))
    .await;
    let with_header = raw_get(
        address,
        b"PROXY TCP4 203.0.113.7 198.51.100.1 44444 443\r\n",
    )
    .await;
    assert!(!with_header.starts_with(b"HTTP/1.1 200"));
    let without_header = raw_get(address, b"").await;
    assert!(without_header.starts_with(b"HTTP/1.1 200"));
    runtime.shutdown().await;

    // Allowed peer: a header is required (USE).
    let (runtime, address) = start(config(proxy_wrapper(
        serde_json::json!({"allow": ["127.0.0.1/32"]}),
    )))
    .await;
    let missing = raw_get(address, b"").await;
    assert!(!missing.starts_with(b"HTTP/1.1 200"));
    let present = raw_get(
        address,
        b"PROXY TCP4 203.0.113.7 198.51.100.1 44444 443\r\n",
    )
    .await;
    assert_eq!(
        body_text(&present).trim(),
        "remote=203.0.113.7:44444 local=198.51.100.1:443"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn wrapped_and_unwrapped_listeners_coexist() {
    let plain_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve plain port");
        listener.local_addr().expect("port").port()
    };
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {
            "wrapped": {
                "listen": ["127.0.0.1:0"],
                "listener_wrappers": [{"wrapper": "proxy_protocol"}],
                "routes": [{"handle": [{"handler": "static_response", "body": BODY}]}]
            },
            "plain": {
                "listen": [format!("127.0.0.1:{plain_port}")],
                "routes": [{"handle": [{"handler": "static_response", "body": BODY}]}]
            }
        }}}
    }))
    .expect("test config decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let wrapped = runtime
        .listener_address("127.0.0.1:0")
        .expect("wrapped listener");
    let plain = runtime
        .listener_address(&format!("127.0.0.1:{plain_port}"))
        .expect("plain listener");

    let response = raw_get(
        wrapped,
        b"PROXY TCP4 203.0.113.7 198.51.100.1 44444 443\r\n",
    )
    .await;
    assert_eq!(
        body_text(&response).trim(),
        "remote=203.0.113.7:44444 local=198.51.100.1:443"
    );

    // The unwrapped listener does not consume a PROXY header: the parser sees garbage.
    let plain_with_header =
        raw_get(plain, b"PROXY TCP4 203.0.113.7 198.51.100.1 44444 443\r\n").await;
    assert!(!plain_with_header.starts_with(b"HTTP/1.1 200"));
    let plain_without_header = raw_get(plain, b"").await;
    assert!(plain_without_header.starts_with(b"HTTP/1.1 200"));
    runtime.shutdown().await;
}
