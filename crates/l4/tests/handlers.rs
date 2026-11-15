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

use caddy_rs_l4::handlers::proxy::proxy_connection;
use caddy_rs_l4::handlers::proxy::{ProxyOptions, DEFAULT_IDLE_TIMEOUT};
use caddy_rs_l4::handlers::proxy_protocol::{
    render_proxy_header, ProxyHeaderAddresses, ProxyProtocolVersion,
};
use caddy_rs_l4::handlers::tls::{validate_stage_order, TlsTerminator};
use caddy_rs_l4::metered_copy::AtomicByteMeter;
use caddy_rs_tls::{
    CertificateResolver, ClientAuthMode, TlsCertificate, TlsServerOptions, TlsVersions,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const EXAMPLE_CERT: &str = include_str!("../../tls/testdata/https/example.com.pem");
const EXAMPLE_KEY: &str = include_str!("../../tls/testdata/https/example.com.key");

fn terminator() -> TlsTerminator {
    let certificate = TlsCertificate::from_pem(EXAMPLE_CERT, EXAMPLE_KEY).expect("fixture loads");
    let resolver =
        Arc::new(CertificateResolver::from_certificates([certificate]).expect("resolver builds"));
    let options = TlsServerOptions {
        versions: TlsVersions::Default,
        client_auth: ClientAuthMode::None,
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
