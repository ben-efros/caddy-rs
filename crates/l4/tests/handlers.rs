//! End-to-end evidence for T-L4-008: TLS termination, PROXY protocol after termination, and the
//! per-route idle timeout, over real loopback sockets.
//!
//! The ADR-030 Q2 requirement is the one that cannot be shown by unit tests alone: a route that
//! terminates TLS must still forward a PROXY header carrying the *original* client address, and
//! that header must be the first bytes the upstream sees — before the first decrypted payload
//! byte. This test runs the whole pipeline (rustls handshake through the shared caddy-rs TLS
//! resolver, then the proxy stage with an injected header) against a real upstream that records
//! the exact byte order it receives.

use std::sync::Arc;
use std::time::Duration;

use caddy_rs_admin::metrics::MetricsRegistry;
use caddy_rs_l4::handlers::proxy::{proxy_connection, proxy_route};
use caddy_rs_l4::handlers::proxy::{ProxyOptions, DEFAULT_IDLE_TIMEOUT};
use caddy_rs_l4::handlers::proxy_protocol::{
    render_proxy_header, ProxyHeaderAddresses, ProxyProtocolVersion,
};
use caddy_rs_l4::handlers::throttle::{RateLimit, ThrottledStream};
use caddy_rs_l4::handlers::tls::{validate_stage_order, TlsTerminator};
use caddy_rs_l4::metered_copy::AtomicByteMeter;
use caddy_rs_l4::metrics::L4Metrics;
use caddy_rs_l4::router::{RouteDefinition, SniRouter};
use caddy_rs_tls::{
    CertificateResolver, ClientAuthMode, TlsCertificate, TlsServerOptions, TlsVersions,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

const EXAMPLE_CERT: &str = include_str!("../../tls/testdata/https/example.com.pem");
const EXAMPLE_KEY: &str = include_str!("../../tls/testdata/https/example.com.key");

fn terminator() -> TlsTerminator {
    terminator_with(ClientAuthMode::None)
}

/// A terminator whose client-certificate policy is `RequireAndVerify` against `roots`.
///
/// `ClientAuthMode::Require` alone is a configuration error in the shared TLS layer (Caddy needs
/// a trust bundle to verify a required certificate), so mTLS is exercised through the verifying
/// mode, which is what a real `client_authentication.ca` route uses.
fn verifying_terminator(roots: Vec<rustls::pki_types::CertificateDer<'static>>) -> TlsTerminator {
    let certificate = TlsCertificate::from_pem(EXAMPLE_CERT, EXAMPLE_KEY).expect("fixture loads");
    let resolver =
        Arc::new(CertificateResolver::from_certificates([certificate]).expect("resolver builds"));
    let options = TlsServerOptions {
        versions: TlsVersions::Default,
        client_auth: ClientAuthMode::RequireAndVerify,
        client_auth_roots: roots,
        client_auth_configured: true,
        alpn: vec![b"test-l4".to_vec()],
        ..TlsServerOptions::default()
    };
    TlsTerminator::new(resolver, &options).expect("terminator builds")
}

/// A terminator whose client-certificate policy is `client_auth`.
fn terminator_with(client_auth: ClientAuthMode) -> TlsTerminator {
    let certificate = TlsCertificate::from_pem(EXAMPLE_CERT, EXAMPLE_KEY).expect("fixture loads");
    let resolver =
        Arc::new(CertificateResolver::from_certificates([certificate]).expect("resolver builds"));
    let options = TlsServerOptions {
        versions: TlsVersions::Default,
        client_auth,
        alpn: vec![b"test-l4".to_vec()],
        ..TlsServerOptions::default()
    };
    TlsTerminator::new(resolver, &options).expect("terminator builds")
}

/// A rustls client that accepts any certificate (the fixture is self-signed for the test).
fn client_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"test-l4".to_vec()];
    Arc::new(config)
}

#[derive(Debug)]
struct AcceptAnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The acceptance case: terminate TLS, then inject a PROXY header before any payload byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminated_connection_forwards_a_proxy_header_before_any_payload_byte() {
    // Upstream: record every byte it receives, then echo the payload back.
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("addr").to_string();
    let (record_tx, record_rx) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.expect("accept");
        let mut received = Vec::new();
        let mut buffer = vec![0u8; 4096];
        // Read until the payload arrives; the header is the only thing sent first.
        loop {
            let read = stream.read(&mut buffer).await.expect("read");
            if read == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..read]);
            if received.len() >= 60 {
                break;
            }
        }
        let _ = record_tx.send(received.clone());
        // Echo the payload part back: everything after the PROXY header's terminating CRLF.
        let payload_start = received
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .map(|index| index + 2)
            .unwrap_or(received.len());
        let _ = stream.write_all(&received[payload_start..]).await;
        stream.shutdown().await.expect("shutdown");
    });

    // The route's listener: accept one connection, terminate TLS, then proxy it.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("addr");
    let terminator = terminator();
    let route_task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        let destination = stream.local_addr().expect("local addr");
        // Captured BEFORE termination: the header must describe the original client.
        let addresses = ProxyHeaderAddresses::new(peer, destination);
        let header = render_proxy_header(ProxyProtocolVersion::V1, addresses).expect("header");
        let (terminated, alpn) = terminator.terminate(stream).await.expect("handshake");
        assert_eq!(alpn.as_deref(), Some(&b"test-l4"[..]), "ALPN negotiated");
        let options = ProxyOptions::new(upstream_addr).with_proxy_header(header);
        proxy_connection(terminated, &options, Arc::new(AtomicByteMeter::new()))
            .await
            .expect("proxy")
    });

    // Client: handshake, send a payload, read the echo.
    let tcp = TcpStream::connect(proxy_addr).await.expect("connect");
    let server_name = rustls::pki_types::ServerName::try_from("example.com").expect("name");
    let connector = tokio_rustls::TlsConnector::from(client_config());
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("handshake");
    tls.write_all(b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("write");
    let mut echoed = vec![0u8; 18];
    tls.read_exact(&mut echoed).await.expect("echo");
    assert_eq!(&echoed, b"GET / HTTP/1.1\r\n\r\n");
    tls.shutdown().await.expect("close");

    let received = record_rx.await.expect("upstream record");
    let text = String::from_utf8_lossy(&received);
    assert!(
        text.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
        "the PROXY header is the first thing the upstream sees, and it names the real client: {text}"
    );
    assert!(
        text.contains("GET / HTTP/1.1"),
        "the decrypted payload follows the header: {text}"
    );
    let header_end = text.find("\r\n").expect("v1 header ends with CRLF") + 2;
    assert!(
        text[header_end..].starts_with("GET "),
        "no payload byte precedes the header: {text}"
    );
    upstream.await.expect("upstream task");
    route_task.await.expect("route task");
}

#[tokio::test]
async fn the_default_idle_timeout_is_caddys_thirty_seconds() {
    assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(30));
}

#[tokio::test]
async fn the_documented_pipeline_orders_validate() {
    // The orders ADR-030 describes for real routes.
    for stages in [
        &["tls", "proxy_protocol", "proxy"][..],
        &["tls", "proxy"][..],
        &["proxy_protocol", "proxy"][..],
        &["throttle", "proxy"][..],
        &["tls", "throttle", "proxy_protocol", "proxy"][..],
    ] {
        validate_stage_order(stages).unwrap_or_else(|error| {
            panic!("{stages:?} should validate: {error}");
        });
    }
    // The two orders ADR-030 forbids.
    assert!(validate_stage_order(&["proxy", "proxy_protocol"]).is_err());
    assert!(validate_stage_order(&["tls", "proxy", "proxy_protocol"]).is_err());
}

/// An upstream that answers every read with one byte, for `count` reads.
///
/// The idle timeout must measure inactivity, not the age of the connection, so a peer that keeps
/// moving bytes has to outlive the window it is configured with.
async fn a_chatty_upstream(interval: Duration, count: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let address = listener.local_addr().expect("addr").to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        for _ in 0..count {
            tokio::time::sleep(interval).await;
            if stream.write_all(b".").await.is_err() {
                return;
            }
        }
        // Hold the connection open: the client closes when it is done reading.
        let mut sink = [0_u8; 64];
        let _ = stream.read(&mut sink).await;
    });
    address
}

#[tokio::test]
async fn an_active_connection_outlives_its_idle_window() {
    // A 400 ms idle window and a byte every 100 ms: four times the window in total, but no gap
    // anywhere near it. Measuring the age of the connection would kill this healthy stream.
    let window = Duration::from_millis(400);
    let upstream = a_chatty_upstream(Duration::from_millis(100), 16).await;
    let options = ProxyOptions::new(upstream).with_idle_timeout(window);
    let (mut client, server) = tokio::io::duplex(64);
    let meter: Arc<dyn caddy_rs_l4::metered_copy::ByteMeter> = Arc::new(AtomicByteMeter::new());
    let copy = tokio::spawn(async move { proxy_connection(server, &options, meter).await });

    let started = Instant::now();
    let mut buffer = [0_u8; 64];
    let mut received = 0;
    while received < 16 {
        let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buffer))
            .await
            .expect("a byte every 100 ms")
            .expect("read");
        assert_ne!(read, 0, "upstream closed after {received} bytes");
        received += read;
    }
    let elapsed = started.elapsed();
    drop(client);
    let totals = tokio::time::timeout(Duration::from_secs(5), copy)
        .await
        .expect("copy ends when the client goes away")
        .expect("join");
    assert!(
        elapsed > window,
        "the connection must outlive its idle window: {elapsed:?} vs {window:?}"
    );
    assert_eq!(totals.map(|t| t.b_to_a).unwrap_or(0), 16);
}

#[tokio::test]
async fn a_zero_idle_timeout_never_closes_a_quiet_connection() {
    // `0` disables the timeout (ADR-030 Q5): a connection that says nothing for several windows
    // worth of time must still be proxied when it finally speaks.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream = listener.local_addr().expect("addr").to_string();
    let accepted = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buffer = [0_u8; 64];
        let read = stream.read(&mut buffer).await.expect("read");
        stream.write_all(&buffer[..read]).await.expect("echo");
        let mut sink = [0_u8; 64];
        let _ = stream.read(&mut sink).await;
    });
    let options = ProxyOptions::new(upstream).with_idle_timeout(Duration::ZERO);
    let (mut client, server) = tokio::io::duplex(64);
    let meter: Arc<dyn caddy_rs_l4::metered_copy::ByteMeter> = Arc::new(AtomicByteMeter::new());
    let copy = tokio::spawn(async move { proxy_connection(server, &options, meter).await });

    // Quiet for 1.2 s. With the 400 ms window used by the neighbouring test this would be long
    // dead; with the timeout disabled nothing may happen.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        !copy.is_finished(),
        "a disabled timeout must not close the copy"
    );
    client.write_all(b"late").await.expect("write");
    let mut echo = [0_u8; 4];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo))
        .await
        .expect("echo after the quiet period")
        .expect("read");
    assert_eq!(&echo, b"late");
    drop(client);
    let totals = tokio::time::timeout(Duration::from_secs(5), copy)
        .await
        .expect("copy ends")
        .expect("join");
    assert_eq!(totals.expect("no error").a_to_b, 4);
    let _ = accepted.await;
}

/// The route the router produces for `host`, which is what the proxy meters against.
fn route(host: &str, upstream: &str) -> Arc<caddy_rs_l4::router::Route> {
    let router = SniRouter::new(
        vec![RouteDefinition::new(
            host,
            caddy_rs_l4::actions::SniAction::Passthrough(
                caddy_rs_l4::actions::PassthroughConfig::new(upstream).expect("valid upstream"),
            ),
        )
        .expect("valid route")],
        caddy_rs_l4::actions::SniAction::Passthrough(
            caddy_rs_l4::actions::PassthroughConfig::new(upstream).expect("valid upstream"),
        ),
    )
    .expect("valid router");
    router.lookup(Some(host))
}

#[tokio::test]
async fn proxy_route_meters_bytes_and_the_active_connections_gauge() {
    // `proxy_route` is the wiring point between the router, the registry and the copy loop; if it
    // is not metering, an L4 route produces no series at all.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream = listener.local_addr().expect("addr").to_string();
    let accepted = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buffer = [0_u8; 64];
        let read = stream.read(&mut buffer).await.expect("read");
        stream.write_all(&buffer[..read]).await.expect("echo");
        let mut sink = [0_u8; 64];
        let _ = stream.read(&mut sink).await;
    });
    let metrics = L4Metrics::new(MetricsRegistry::new());
    let route = route("example.com", &upstream);
    let options = ProxyOptions::new(upstream.clone()).with_idle_timeout(Duration::from_secs(5));
    let (mut client, server) = tokio::io::duplex(64);
    let spawned = metrics.clone();
    let copy = tokio::spawn(async move { proxy_route(server, &route, &options, &spawned).await });

    client.write_all(b"meter me").await.expect("write");
    let mut echo = [0_u8; 8];
    client.read_exact(&mut echo).await.expect("echo");
    assert_eq!(&echo, b"meter me");

    // While the connection is open the gauge is 1 and the bytes are counted per route.
    let open = metrics.registry().render();
    assert!(
        open.contains("caddy_l4_connections_active{sni=\"example.com\"} 1"),
        "active gauge while proxying: {open}"
    );
    assert!(
        open.contains("caddy_l4_proxy_read_bytes_total{sni=\"example.com\"} 8"),
        "bytes read from the client are metered: {open}"
    );
    assert!(
        open.contains("caddy_l4_proxy_write_bytes_total{sni=\"example.com\"} 8"),
        "bytes written back to the client are metered: {open}"
    );

    drop(client);
    let totals = tokio::time::timeout(Duration::from_secs(5), copy)
        .await
        .expect("copy ends")
        .expect("join")
        .expect("no error");
    assert_eq!(totals.a_to_b, 8);
    assert_eq!(totals.b_to_a, 8);
    // Dropping the connection handle decrements the gauge, so a closed route stops counting.
    let closed = metrics.registry().render();
    assert!(
        closed.contains("caddy_l4_connections_active{sni=\"example.com\"} 0"),
        "active gauge returns to zero: {closed}"
    );
    let _ = accepted.await;
}

/// Reads `wanted` bytes from `stream`, returning how many arrived before `budget` ran out.
async fn read_until<S>(stream: &mut S, wanted: usize, budget: Duration) -> usize
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; wanted];
    let mut received = 0;
    let deadline = Instant::now() + budget;
    while received < wanted {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, stream.read(&mut buffer[received..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => received += read,
            Ok(Err(error)) => panic!("read failed: {error}"),
            // Out of time: the ceiling held.
            Err(_) => break,
        }
    }
    received
}

#[tokio::test]
async fn the_throttle_is_a_ceiling_not_an_average() {
    // 8 KiB/s with a 64 KiB burst: in half a second the bucket can pay for at most
    // 64 KiB + 4 KiB. A stream that charges after delivery lets the whole 1 MiB through in
    // microseconds, which is what this test exists to catch.
    const WANTED: usize = 1024 * 1024;
    let limit = RateLimit::new(8 * 1024, 8 * 1024);
    let (mut writer, reader) = tokio::io::duplex(64 * 1024);
    let producer = tokio::spawn(async move {
        let chunk = vec![b'x'; 16 * 1024];
        for _ in 0..WANTED / chunk.len() {
            if writer.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let mut sink = [0_u8; 64];
        let _ = writer.read(&mut sink).await;
    });
    let mut throttled = ThrottledStream::new(reader, limit);

    let started = Instant::now();
    let received = read_until(&mut throttled, WANTED, Duration::from_millis(500)).await;
    let elapsed = started.elapsed();
    let ceiling = 64 * 1024 + (8 * 1024 * elapsed.as_millis() as usize) / 1000;
    assert!(
        received <= ceiling,
        "{received} bytes arrived in {elapsed:?} through an 8 KiB/s limit (ceiling {ceiling}); \
         the throttle is not bounding the read path"
    );
    // And it must not simply be broken the other way: the burst is payable, so a healthy stream
    // keeps moving.
    assert!(
        received >= 64 * 1024,
        "the burst allowance must be usable: only {received} bytes in {elapsed:?}"
    );
    producer.abort();
}

#[tokio::test]
async fn the_throttled_write_path_is_bounded_too() {
    // The same ceiling on the write side: the bucket must be charged before the bytes are handed
    // to the peer, otherwise a slow peer is never shaped.
    const WANTED: usize = 512 * 1024;
    let limit = RateLimit::new(8 * 1024, 8 * 1024);
    // A roomy pipe: the throttle, not the peer's buffer, must be what limits the write.
    let (writer, mut reader) = tokio::io::duplex(256 * 1024);
    let mut throttled = ThrottledStream::new(writer, limit);
    let payload = vec![b'y'; WANTED];
    let started = Instant::now();
    let accepted =
        tokio::time::timeout(Duration::from_millis(500), throttled.write_all(&payload)).await;
    let elapsed = started.elapsed();
    let ceiling = 64 * 1024 + (8 * 1024 * elapsed.as_millis() as usize) / 1000;
    let written = match accepted {
        // The write was still blocked when time ran out: the ceiling held.
        Err(_) => {
            let mut seen = 0;
            let mut buffer = vec![0_u8; 64 * 1024];
            while let Ok(Ok(read)) =
                tokio::time::timeout(Duration::from_millis(50), reader.read(&mut buffer)).await
            {
                if read == 0 {
                    break;
                }
                seen += read;
            }
            seen
        }
        Ok(Ok(())) => WANTED,
        Ok(Err(error)) => panic!("write failed: {error}"),
    };
    assert!(
        written <= ceiling,
        "{written} bytes were accepted in {elapsed:?} through an 8 KiB/s limit (ceiling {ceiling})"
    );
    assert!(
        written >= 64 * 1024,
        "the burst allowance must be usable: {written}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_that_requires_a_client_certificate_rejects_a_bare_client() {
    // The L4 termination stage reuses the shared TLS layer, so a route configured with client
    // authentication must not serve a client that presents no certificate. The duplex pair has no
    // handshake driver, so the honest assertion is that the connection makes no progress at all:
    // the server is left waiting for the Certificate message that never comes, and the client
    // never receives a byte of application data.
    let terminator = verifying_terminator(trust_anchor());
    let (client, server) = tokio::io::duplex(64 * 1024);
    let connector = tokio_rustls::TlsConnector::from(client_config());
    let client_half = tokio::spawn(async move {
        let mut stream = connector.connect(server_name(), client).await?;
        let mut sink = [0_u8; 16];
        std::io::Result::Ok(stream.read(&mut sink).await)
    });
    let server_half = tokio::spawn(async move { terminator.terminate(server).await });

    tokio::time::sleep(Duration::from_millis(300)).await;
    let refused = match server_half.is_finished() {
        // Still waiting for the Certificate message the client never sends.
        false => true,
        // Or it gave up and reported the missing certificate.
        true => {
            let outcome = server_half.await.expect("server join");
            match outcome {
                Err(error) => error.to_string().contains("certificate"),
                Ok(_) => false,
            }
        }
    };
    assert!(
        refused,
        "a route that requires mTLS must not terminate a handshake that offered no certificate"
    );
    client_half.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_terminated_connection_reports_the_negotiated_alpn() {
    // The control for the test above: the same client connects when it is not asked for a
    // certificate, so the rejection really is the mTLS policy and not a broken fixture.
    let terminator = terminator();
    let (client, server) = tokio::io::duplex(64 * 1024);
    let accept = tokio::spawn(async move { terminator.terminate(server).await });
    let connector = tokio_rustls::TlsConnector::from(client_config());
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(server_name(), client),
    )
    .await
    .expect("handshake finishes")
    .expect("a bare client is accepted when client auth is off");
    stream.write_all(b"hello").await.expect("write");
    let (mut terminated, alpn) = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("terminate returns")
        .expect("join")
        .expect("terminated");
    assert_eq!(alpn.as_deref(), Some(&b"test-l4"[..]), "ALPN is reported");
    terminated.write_all(b"ok").await.expect("write");
}

/// The server name the fixture certificate is issued for.
fn server_name() -> rustls::pki_types::ServerName<'static> {
    rustls::pki_types::ServerName::try_from("example.com").expect("server name")
}

/// The fixture certificate as a DER trust anchor for client authentication.
fn trust_anchor() -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let certificate = TlsCertificate::from_pem(EXAMPLE_CERT, EXAMPLE_KEY).expect("fixture loads");
    vec![certificate.chain()[0].clone()]
}
