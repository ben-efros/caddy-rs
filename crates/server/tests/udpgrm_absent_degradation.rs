//! The udpgrm-absent degradation path (T-CORE-114, ADR-0045 §5).
//!
//! On a host without the `udpgrm` daemon — including this program's sandbox — the presence probe
//! fails `ENOPROTOOPT`. That is **not** an error that prevents serving: UDP listeners must keep
//! serving HTTP/3 normally, and the operator must be told **once** that graceful UDP restart is
//! unavailable, because a restart will drop in-flight QUIC connections.
//!
//! These tests run where udpgrm is absent, which is exactly the case they are about. If udpgrm is
//! present the degradation cannot be exercised and the test says so rather than passing silently:
//! a green result from a test that never reached its subject would be worse than no test.

#![cfg(feature = "udpgrm")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Buf;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use caddy_rs_test_support::free_port;
use rustls::{ClientConfig, RootCertStore};

const EXAMPLE_CERT: &str = include_str!("../../tls/testdata/https/example.com.pem");
const EXAMPLE_KEY: &str = include_str!("../../tls/testdata/https/example.com.key");

/// Collects every tracing event on the current thread so a warning can be counted rather than
/// assumed. Same shape as `http_auto_https.rs`'s `CapturedWarnings`.
#[derive(Clone, Default)]
struct CapturedEvents(Arc<Mutex<Vec<String>>>);

impl CapturedEvents {
    fn events(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    /// Events whose message mentions udpgrm.
    fn udpgrm_events(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter(|event| event.contains("udpgrm"))
            .collect()
    }
}

impl tracing::Subscriber for CapturedEvents {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    // Without a level hint a thread-local subscriber can lose the race against the global level
    // filter, because other tests exercise the same callsite concurrently.
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Visitor {
            message: String,
            fields: Vec<String>,
        }
        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.message = format!("{value:?}");
                } else {
                    self.fields.push(format!("{}={value:?}", field.name()));
                }
            }
        }
        let mut visitor = Visitor {
            message: String::new(),
            fields: Vec::new(),
        };
        event.record(&mut visitor);
        self.0.lock().unwrap().push(format!(
            "{} {} | {}",
            event.metadata().level(),
            visitor.message,
            visitor.fields.join(" ")
        ));
    }

    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// True when this host has no udpgrm daemon, i.e. when the degradation path is the live behaviour.
///
/// Probed with the same `getsockopt` the server uses, so the test's premise is established by the
/// mechanism under test rather than by an environment variable.
fn udpgrm_is_absent() -> bool {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe socket binds");
    matches!(
        caddy_rs_server::udpgrm::working_generation(&socket),
        Err(caddy_rs_server::udpgrm::UdpgrmError::Absent)
    )
}

/// A configuration with two UDP (HTTP/3) listeners and one TCP listener, all on fresh ports.
///
/// Two UDP listeners matter: the "report once" property is about one warning per *process*, so a
/// single listener cannot distinguish "reported once" from "reported per listener".
fn config_with_two_udp_listeners() -> (Config, u16, u16, u16) {
    let tcp_port = free_port();
    let udp_a = free_port();
    let udp_b = free_port();
    let config = Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {
            "http": {
                "http_port": free_port(),
                "https_port": tcp_port,
                "servers": {
                    "srv0": {
                        "listen": [
                            format!("127.0.0.1:{tcp_port}"),
                            format!("udp/127.0.0.1:{udp_a}"),
                            format!("udp/127.0.0.1:{udp_b}")
                        ],
                        "routes": [{
                            "handle": [{
                                "handler": "static_response",
                                "body": "udp-ok"
                            }]
                        }],
                        "tls_connection_policies": [{}]
                    }
                }
            },
            "tls": {"certificates": {"load_pem": [
                {"certificate": EXAMPLE_CERT, "key": EXAMPLE_KEY}
            ]}}
        }
    }))
    .expect("test config validates");
    (config, tcp_port, udp_a, udp_b)
}

fn client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in caddy_rs_tls::certificates_from_pem(EXAMPLE_CERT).expect("fixture parses") {
        roots.add(certificate).expect("fixture is a valid root");
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
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

/// Fetch `/` over HTTP/3 and return the status and body.
async fn h3_get(port: u16) -> Result<(u16, String), String> {
    let endpoint = quic_endpoint(client_config());
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().expect("address");
    let connecting = endpoint
        .connect(address, "example.com")
        .map_err(|error| format!("QUIC connect: {error}"))?;
    let connection = tokio::time::timeout(Duration::from_secs(10), connecting)
        .await
        .map_err(|_| "QUIC handshake timed out".to_string())?
        .map_err(|error| format!("QUIC handshake: {error}"))?;

    let (driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|error| format!("HTTP/3 client: {error}"))?;
    let request = http::Request::builder()
        .method("GET")
        .uri("https://example.com/")
        .body(())
        .map_err(|error| format!("request: {error}"))?;
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|error| format!("send_request: {error}"))?;
    stream
        .finish()
        .await
        .map_err(|error| format!("finish: {error}"))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|error| format!("recv_response: {error}"))?;
    let status = response.status().as_u16();
    let mut collected = bytes::BytesMut::new();
    while let Some(chunk) = stream
        .recv_data()
        .await
        .map_err(|error| format!("recv_data: {error}"))?
    {
        collected.extend_from_slice(chunk.chunk());
    }
    // Keep the driver alive until the request is complete (it owns the connection state).
    drop(driver);
    Ok((status, String::from_utf8_lossy(&collected).to_string()))
}

/// With udpgrm absent, a udpgrm-enabled build still serves HTTP/3 over UDP, and the absence is
/// reported **exactly once** across two UDP listeners in a single apply.
#[tokio::test]
async fn udp_keeps_serving_and_the_absence_is_reported_once() {
    assert!(
        udpgrm_is_absent(),
        "this test is about the udpgrm-ABSENT path, but udpgrm is present on this host; \
         the degradation cannot be exercised here, so a pass would mean nothing"
    );

    let (config, _tcp_port, udp_a, udp_b) = config_with_two_udp_listeners();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config loads");

    let events = CapturedEvents::default();
    let guard = tracing::subscriber::set_default(events.clone());
    tracing::callsite::rebuild_interest_cache();

    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    let applied = runtime.apply().await;
    drop(guard);
    applied.expect("the runtime applies without udpgrm");

    // 1. UDP keeps serving. Measured with a real HTTP/3 request on each UDP listener, not by
    //    observing that a socket was bound -- a bound socket proves nothing about serving.
    for port in [udp_a, udp_b] {
        let (status, body) = h3_get(port)
            .await
            .unwrap_or_else(|error| panic!("HTTP/3 over UDP port {port} failed: {error}"));
        assert_eq!(status, 200, "HTTP/3 on udp/{port} served a non-200");
        assert_eq!(body, "udp-ok", "HTTP/3 on udp/{port} served the wrong body");
    }

    // 2. The absence was reported exactly once. Two listeners in one apply is what makes this a
    //    measurement: a per-listener report would give two, and a silent degradation would give
    //    zero. Both are non-zero-or-zero answers this assertion can actually distinguish.
    let absence = events.udpgrm_events();
    assert_eq!(
        absence.len(),
        1,
        "expected exactly one udpgrm warning for two UDP listeners, got {}: {absence:#?}",
        absence.len()
    );

    // 3. The single report says what an operator needs: the consequence, not just a status.
    let warning = &absence[0];
    for expected in ["unavailable", "restart", "QUIC"] {
        assert!(
            warning.contains(expected),
            "the udpgrm warning does not mention {expected:?}, so it does not tell the operator \
             what actually happens on restart: {warning}"
        );
    }
}
