//! HTTP/2 SETTINGS parity with Caddy v2.11.7 / Go (T-HTTP-021).
//!
//! Caddy v2.11.7 exposes no JSON tuning fields for HTTP/2 streams/frames/windows: it hands
//! `new(http2.Server)` to `http2.ConfigureServer` (Go defaults). Hyper's server defaults differ for
//! `SETTINGS_MAX_CONCURRENT_STREAMS` (200 vs Go's 250), so the connection layer sets the Go values
//! explicitly. These tests read the server's raw HTTP/2 SETTINGS frame over a real TCP listener, for
//! both prior-knowledge h2c and the HTTP/1.1 `Upgrade: h2c` path.
//!
//! Expected values (Go `x/net/http2` defaults):
//! * `SETTINGS_MAX_CONCURRENT_STREAMS` = 250
//! * `SETTINGS_MAX_FRAME_SIZE` = 1 MiB (1048576; Go's `MaxReadFrameSize` default)
//! * `SETTINGS_INITIAL_WINDOW_SIZE` = 1 MiB (server receive window per stream)
//! * `SETTINGS_MAX_HEADER_LIST_SIZE` = Caddy `MaxHeaderBytes` (default 16 KiB) + 320
//!   (Go `http2adjustHTTP1MaxHeaderSize`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SETTINGS_TYPE: u8 = 0x4;
const MAX_CONCURRENT_STREAMS: u16 = 0x3;
const INITIAL_WINDOW_SIZE: u16 = 0x4;
const MAX_FRAME_SIZE: u16 = 0x5;
const MAX_HEADER_LIST_SIZE: u16 = 0x6;

fn test_config(server_fields: serde_json::Value) -> Config {
    let mut server = serde_json::json!({
        "listen": ["127.0.0.1:0"],
        "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
    });
    let base = server.as_object_mut().expect("server object");
    for (name, value) in server_fields.as_object().expect("server fields object") {
        base.insert(name.clone(), value.clone());
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": server}}}
    }))
    .expect("test config decodes")
}

async fn start(server_fields: serde_json::Value) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(test_config(server_fields))
        .expect("test config validates");
    let mut runtime = ServerRuntime::new(store);
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (runtime, address)
}

/// Send the HTTP/2 client preface + empty SETTINGS and return the server's non-ACK SETTINGS.
async fn read_server_settings(stream: &mut TcpStream) -> HashMap<u16, u32> {
    stream
        .write_all(H2_PREFACE)
        .await
        .expect("write h2 preface");
    // Empty SETTINGS frame: length 0, type 4, flags 0, stream 0.
    stream
        .write_all(&[0, 0, 0, SETTINGS_TYPE, 0, 0, 0, 0, 0])
        .await
        .expect("write empty settings");

    let mut header = [0_u8; 9];
    loop {
        stream
            .read_exact(&mut header)
            .await
            .expect("read frame header");
        let length =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        let frame_type = header[3];
        let flags = header[4];
        let stream_id =
            u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
        let mut payload = vec![0_u8; length];
        stream
            .read_exact(&mut payload)
            .await
            .expect("read frame payload");
        if frame_type == SETTINGS_TYPE && flags & 0x1 == 0 && stream_id == 0 {
            let mut settings = HashMap::new();
            for entry in payload.chunks_exact(6) {
                let id = u16::from_be_bytes([entry[0], entry[1]]);
                let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
                settings.insert(id, value);
            }
            return settings;
        }
    }
}

async fn h2c_upgrade(stream: &mut TcpStream) {
    let request = "GET / HTTP/1.1\r\n\
                   Host: example.com\r\n\
                   Connection: Upgrade, HTTP2-Settings\r\n\
                   Upgrade: h2c\r\n\
                   HTTP2-Settings: AAMAAABkAAQAAP__\r\n\
                   \r\n";
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write upgrade request");
    // Read exactly the HTTP/1.1 response head so the following HTTP/2 server frames stay buffered.
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .expect("read upgrade head");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols"),
        "expected h2c 101, got: {head:?}"
    );
}

fn assert_go_defaults(settings: &HashMap<u16, u32>, expected_header_list: u32) {
    assert_eq!(
        settings.get(&MAX_CONCURRENT_STREAMS),
        Some(&250),
        "MAX_CONCURRENT_STREAMS must advertise Go's 250 default: {settings:?}"
    );
    assert_eq!(
        settings.get(&MAX_FRAME_SIZE),
        Some(&1_048_576),
        "MAX_FRAME_SIZE must advertise Go's 1 MiB MaxReadFrameSize default: {settings:?}"
    );
    assert_eq!(
        settings.get(&INITIAL_WINDOW_SIZE),
        Some(&1_048_576),
        "INITIAL_WINDOW_SIZE must advertise Go's 1 MiB server window: {settings:?}"
    );
    assert_eq!(
        settings.get(&MAX_HEADER_LIST_SIZE),
        Some(&expected_header_list),
        "MAX_HEADER_LIST_SIZE must follow Caddy MaxHeaderBytes + Go padding: {settings:?}"
    );
}

#[tokio::test]
async fn prior_knowledge_h2_advertises_go_default_settings() {
    let (runtime, address) = start(serde_json::json!({})).await;
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let settings = tokio::time::timeout(Duration::from_secs(5), read_server_settings(&mut stream))
        .await
        .expect("server SETTINGS timeout");
    // Caddy default MaxHeaderBytes = 16 KiB; Go advertises MaxHeaderBytes + 10*32.
    assert_go_defaults(&settings, 16_704);
    runtime.shutdown().await;
}

#[tokio::test]
async fn configured_max_header_bytes_changes_h2_header_list_size() {
    let (runtime, address) = start(serde_json::json!({
        "max_header_bytes": 32_768
    }))
    .await;
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let settings = tokio::time::timeout(Duration::from_secs(5), read_server_settings(&mut stream))
        .await
        .expect("server SETTINGS timeout");
    // 32 KiB + 10*32 padding; frame/stream/window tuning has no JSON field in Caddy and stays put.
    assert_go_defaults(&settings, 33_088);
    runtime.shutdown().await;
}

#[tokio::test]
async fn h2c_upgrade_advertises_the_same_settings() {
    let (runtime, address) = start(serde_json::json!({
        "protocols": ["h1", "h2c"]
    }))
    .await;
    let mut stream = TcpStream::connect(address).await.expect("connect");
    h2c_upgrade(&mut stream).await;
    let settings = tokio::time::timeout(Duration::from_secs(5), read_server_settings(&mut stream))
        .await
        .expect("h2c server SETTINGS timeout");
    assert_go_defaults(&settings, 16_704);
    runtime.shutdown().await;
}

#[tokio::test]
async fn invented_h2_tuning_fields_fail_loudly_at_apply() {
    // Caddy v2.11.7 has no JSON fields for h2 max streams/frame size; an invented field must not be
    // silently ignored by the server.
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(test_config(serde_json::json!({"max_streams": 100})))
        .expect("core model preserves the unknown field");
    let mut runtime = ServerRuntime::new(store);
    let error = runtime
        .apply()
        .await
        .expect_err("an invented h2 tuning field must fail the apply");
    let message = error.to_string();
    assert!(
        message.contains("apps.http.servers.srv0.max_streams"),
        "error must name the invented field, got: {message}"
    );
    assert!(
        message.contains("T-HTTP-021"),
        "error must reference the tracking task, got: {message}"
    );
}

#[tokio::test]
async fn configured_idle_timeout_closes_an_idle_h2_connection() {
    // Hyper's h2 builder has no idle-timeout knob; the server's connection-level idle watchdog
    // already applies to HTTP/2 connections too, so Caddy's per-server `idle_timeout` still maps.
    let (runtime, address) = start(serde_json::json!({"idle_timeout": "150ms"})).await;
    let mut stream = TcpStream::connect(address).await.expect("connect");
    // Complete enough of the h2 handshake to have a live connection, then stay idle.
    stream
        .write_all(H2_PREFACE)
        .await
        .expect("write h2 preface");
    stream
        .write_all(&[0, 0, 0, SETTINGS_TYPE, 0, 0, 0, 0, 0])
        .await
        .expect("write empty settings");
    let mut buffer = [0_u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "idle h2 connection was not closed");
        match tokio::time::timeout(remaining, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => continue,
            Ok(Err(error)) => panic!("h2 idle connection read failed: {error}"),
            Err(_) => panic!("idle h2 connection was not closed before the deadline"),
        }
    }
    runtime.shutdown().await;
}
