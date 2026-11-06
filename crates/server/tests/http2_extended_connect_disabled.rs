//! Default Caddy v2.11.7 / Go parity: HTTP/2 extended CONNECT is disabled unless the process runs
//! with `GODEBUG=http2xconnect=1`, so a default server neither advertises
//! `SETTINGS_ENABLE_CONNECT_PROTOCOL` (asserted in `http2_settings.rs`) nor accepts RFC 8441
//! CONNECT requests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http::Method;
use tokio::net::TcpStream;

fn config() -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
        }}}}
    }))
    .expect("test config decodes")
}

async fn start() -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config()).expect("test config validates");
    let mut runtime = ServerRuntime::new(store);
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener bound");
    (runtime, address)
}

#[tokio::test]
async fn extended_connect_is_rejected_without_the_godebug_gate() {
    // The test harness does not set GODEBUG=http2xconnect=1 for this binary.
    assert!(
        std::env::var("GODEBUG")
            .map(|value| !value.contains("http2xconnect=1"))
            .unwrap_or(true),
        "this test requires the default (disabled) GODEBUG state"
    );
    let (runtime, address) = start().await;
    let stream = TcpStream::connect(address).await.expect("connect");
    let (mut send_request, connection) = h2::client::handshake(stream).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut request = http::Request::builder()
        .method(Method::CONNECT)
        .uri("http://example.com/ws")
        .body(())
        .expect("request builds");
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("websocket"));
    let (response, _send_stream) = send_request
        .send_request(request, true)
        .expect("send extended CONNECT");
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("response timeout");
    match response {
        Ok(response) => panic!(
            "extended CONNECT must be rejected without GODEBUG=http2xconnect=1, got {}",
            response.status()
        ),
        Err(error) => {
            // Go's HTTP/2 server rejects an unadvertised `:protocol` with a stream-level
            // PROTOCOL_ERROR (h2_bundle.go: http2disableExtendedConnectProtocol path), and
            // hyper does the same when `enable_connect_protocol` is off.
            let message = format!("{error:?}");
            assert!(
                message.contains("PROTOCOL_ERROR"),
                "expected an HTTP/2 PROTOCOL_ERROR reset, got: {message}"
            );
        }
    }
    runtime.shutdown().await;
}
