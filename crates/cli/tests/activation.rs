//! T-SETUP-002: the single-use activation endpoint.
//!
//! Protocol logic is driven directly through `ActivationService` (valid, expired, unknown and
//! second-use tokens, plus every 4xx branch), and one loopback test boots the real activation
//! listener through `activation::serve` and talks to it over TCP, so a handler that never reaches
//! the socket cannot pass.

#[path = "../src/activation.rs"]
mod activation;
#[path = "../src/enrollment.rs"]
mod enrollment;
#[path = "../src/setup.rs"]
mod setup;
#[path = "../src/setup_tls.rs"]
mod setup_tls;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use activation::{is_well_formed_token, ActivationOutcome, ActivationService};
use setup::{AuthMethod, TokenStore, ACTIVATION_PATH};

fn service_with_token(timeout: Duration) -> (Arc<ActivationService>, String) {
    let mut store = TokenStore::new(timeout);
    let token = store.mint(SystemTime::now()).value;
    (
        Arc::new(ActivationService::new(store, AuthMethod::Totp)),
        token,
    )
}

fn activate_url(token: &str) -> String {
    format!("{ACTIVATION_PATH}?token={token}")
}

#[test]
fn a_valid_token_activates_once_and_replays_are_rejected() {
    let (service, token) = service_with_token(Duration::from_secs(900));
    assert_eq!(
        service.handle("GET", &activate_url(&token)),
        ActivationOutcome::Activated
    );
    // Second use of the same token: the token was consumed, so it is indistinguishable from one
    // that was never minted.
    assert_eq!(
        service.handle("GET", &activate_url(&token)),
        ActivationOutcome::Unknown
    );
    assert_eq!(
        service.handle("POST", &activate_url(&token)),
        ActivationOutcome::Unknown
    );
}

#[test]
fn an_expired_token_is_gone_and_is_discarded() {
    // `TokenStore` has no clock injection, so the expiry is exercised through a zero TTL: the token
    // is already past its deadline on the first use. A real 15m TTL is covered by the store's own
    // test in tests/setup.rs; this one pins the endpoint's behaviour for an elapsed TTL.
    let (service, token) = service_with_token(Duration::ZERO);
    assert_eq!(
        service.handle("GET", &activate_url(&token)),
        ActivationOutcome::Expired
    );
    // Expired and consumed are the same dead end: the token is discarded either way.
    assert_eq!(
        service.handle("GET", &activate_url(&token)),
        ActivationOutcome::Unknown
    );
    let expired = ActivationOutcome::Expired;
    assert_eq!(expired.status(), 410);
    assert_eq!(expired.error_code(), Some("token_expired"));
}

#[test]
fn an_unknown_token_is_not_found() {
    let (service, _token) = service_with_token(Duration::from_secs(900));
    let other = "0".repeat(32);
    assert_eq!(
        service.handle("GET", &activate_url(&other)),
        ActivationOutcome::Unknown
    );
}

#[test]
fn malformed_and_missing_tokens_are_bad_requests() {
    let (service, token) = service_with_token(Duration::from_secs(900));
    assert_eq!(
        service.handle("GET", ACTIVATION_PATH),
        ActivationOutcome::MissingToken
    );
    for malformed in [
        "short".to_string(),
        format!("{token}0"),          // 33 characters
        token.to_uppercase(),         // uppercase hex is not the documented shape
        "z".repeat(32),               // not hex
        format!("{} ", &token[..31]), // whitespace is not hex
    ] {
        assert_eq!(
            service.handle("GET", &activate_url(&malformed)),
            ActivationOutcome::MalformedToken,
            "`{malformed}` must be rejected as malformed"
        );
    }
    // A malformed token must not consume the real one.
    assert_eq!(
        service.handle("GET", &activate_url(&token)),
        ActivationOutcome::Activated
    );
}

#[test]
fn token_shape_is_exactly_32_lowercase_hex_characters() {
    assert!(is_well_formed_token(&"0123456789abcdef".repeat(2)));
    assert!(!is_well_formed_token(
        &"0123456789abcdef".repeat(2).to_uppercase()
    ));
    assert!(!is_well_formed_token("0123456789abcdef"));
    assert!(!is_well_formed_token(&format!("{}0", "0".repeat(32))));
}

#[test]
fn wrong_path_and_wrong_method_are_rejected() {
    let (service, token) = service_with_token(Duration::from_secs(900));
    assert_eq!(
        service.handle("GET", &format!("/other?token={token}")),
        ActivationOutcome::NotFound
    );
    let mut put = service.handle("PUT", &activate_url(&token));
    assert_eq!(put, ActivationOutcome::MethodNotAllowed);
    put = service.handle("DELETE", &activate_url(&token));
    assert_eq!(put, ActivationOutcome::MethodNotAllowed);
    // A rejected method must not consume the token.
    assert_eq!(
        service.handle("POST", &activate_url(&token)),
        ActivationOutcome::Activated
    );
}

#[test]
fn every_outcome_renders_status_headers_and_body() {
    let activated = ActivationOutcome::Activated;
    assert_eq!(activated.status(), 200);
    assert_eq!(activated.error_code(), None);
    let body: serde_json::Value =
        serde_json::from_str(&activated.body(AuthMethod::Webauthn)).expect("JSON body");
    assert_eq!(body["status"], serde_json::json!("activated"));
    assert_eq!(body["auth_method"], serde_json::json!("webauthn"));
    // Enrollment is T-SETUP-003; the response must not claim credentials exist.
    assert_eq!(body["enrollment"], serde_json::json!("pending"));

    let unknown = ActivationOutcome::Unknown;
    assert_eq!(unknown.status(), 404);
    let body: serde_json::Value =
        serde_json::from_str(&unknown.body(AuthMethod::Totp)).expect("JSON body");
    assert_eq!(body["error"], serde_json::json!("token_unknown"));

    let method = ActivationOutcome::MethodNotAllowed;
    assert_eq!(method.status(), 405);
    assert!(
        method.headers().contains(&("allow", "GET, POST")),
        "{:?}",
        method.headers()
    );
    assert_eq!(
        ActivationOutcome::MissingToken.status(),
        400,
        "a missing token is a client error"
    );
    assert_eq!(ActivationOutcome::MalformedToken.status(), 400);
    assert_eq!(ActivationOutcome::NotFound.status(), 404);
}

#[test]
fn a_response_body_never_contains_the_token() {
    let (service, token) = service_with_token(Duration::from_secs(900));
    for outcome in [
        service.handle("GET", &activate_url(&token)),
        service.handle("GET", &activate_url(&token)),
        service.handle("GET", &activate_url(&"f".repeat(32))),
    ] {
        let body = outcome.body(service.auth_method());
        assert!(!body.contains(&token), "token leaked into `{body}`");
    }
}

/// Boot the real activation listener on a loopback port and drive it over TLS.
///
/// T-SETUP-008: the endpoint serves the `https://` scheme its activation URL advertises, so this
/// test performs a real rustls handshake against a certificate the internal CA issued — a
/// cleartext listener would fail the handshake rather than pass.
///
/// `activation::serve_with` blocks on the runtime's shutdown channel, so the listener is started on
/// a current-thread runtime in a background thread and the runtime is dropped when the test ends.
#[test]
fn the_activation_listener_answers_over_tls() {
    let probe = TcpListener::bind("127.0.0.1:0").expect("pick a free port");
    let addr: SocketAddr = probe.local_addr().expect("local addr");
    drop(probe);

    let mut store = TokenStore::new(Duration::from_secs(900));
    let token = store.mint(SystemTime::now()).value;
    let service = Arc::new(ActivationService::new(store, AuthMethod::Webauthn));

    // Issue the leaf the way `setup` does, so the test proves the production certificate path.
    let data_dir = tempfile::tempdir().expect("temp data dir");
    let config = setup::generate_config(&setup::SetupArgs {
        domain: "localhost".to_string(),
        data_dir: Some(data_dir.path().to_path_buf()),
        listen_address: Some(addr.to_string()),
        ..Default::default()
    })
    .expect("generate_config");
    let tls = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(setup_tls::activate(&config))
        .expect("issue the activation certificate");
    let tls_app = setup_tls::tls_app_with(setup_tls::load_pem_pair(
        tls.certificate_pem().to_string(),
        tls.private_key_pem().to_string(),
    ));

    let listen = addr.to_string();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let registry = caddy_rs_core::ModuleRegistry::builtin_for_profile(false);
            let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
            let (_force_tx, force) = tokio::sync::watch::channel(false);
            let _keep = shutdown_tx;
            if let Err(error) =
                activation::serve_with(&listen, service, tls_app, registry, shutdown, force).await
            {
                eprintln!("activation serve failed: {error:#}");
            }
        });
    });

    let (response, served_fingerprint) =
        retry_tls_request(addr, &activate_url(&token)).expect("activation request");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got: {response}"
    );
    assert!(
        response.contains("\"status\":\"activated\""),
        "body: {response}"
    );
    // The fingerprint `setup` printed is the SHA-256 of the DER certificate the listener actually
    // presents, which is what makes it comparable with `openssl x509 -fingerprint -sha256`.
    assert_eq!(
        served_fingerprint,
        tls.fingerprint(),
        "the served certificate must be the one whose fingerprint setup printed"
    );
    drop(thread);
}

/// Perform one TLS request, returning the response and the served leaf's SHA-256 fingerprint.
///
/// The internal CA is not in the platform trust store, so the client accepts any certificate —
/// which is exactly the browser's position before the operator compares the printed fingerprint.
fn retry_tls_request(addr: SocketAddr, target: &str) -> Option<(String, String)> {
    // An empty root store: the internal CA is self-signed and is not a platform root.
    let roots = rustls::RootCertStore::empty();
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Accept the self-signed leaf: the test's job is to prove TLS is served and which certificate
    // is served, not to model the operator's out-of-band verification.
    client
        .dangerous()
        .set_certificate_verifier(Arc::new(AcceptAnyCertificate));
    let client = Arc::new(client);

    for _ in 0..100 {
        let Ok(mut tcp) = TcpStream::connect(addr) else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let mut conn = rustls::ClientConnection::new(Arc::clone(&client), server_name)
            .expect("client connection");
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        if stream.write_all(request.as_bytes()).is_err() {
            continue;
        }
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        let fingerprint = conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| setup_tls::sha256_fingerprint(leaf.as_ref()))
            .unwrap_or_default();
        if !response.is_empty() {
            return Some((response, fingerprint));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// A certificate verifier that accepts any chain.
///
/// The internal CA is self-signed, so a normal verifier rejects it — which is correct behaviour
/// and precisely why `setup` prints the fingerprint. The test only needs to know which certificate
/// was served, so verification is deliberately skipped here and nowhere else.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
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
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[test]
fn the_activation_listener_binds_the_address_it_was_given() {
    use setup::{activation_listen, SetupListen};

    // No `--listen-address`: loopback, port 443 (the URL default). Binding loopback by default is
    // the safe choice for a live single-use credential.
    assert_eq!(activation_listen(None, 443), "127.0.0.1:443");
    assert_eq!(activation_listen(None, 8443), "127.0.0.1:8443");

    // T-SETUP-007: an explicit IP is bound exactly, never widened to the wildcard. This is the
    // regression the old `listen_port`-only implementation had: `127.0.0.1:18443` became
    // `127.0.0.1:18443` only by accident of the hardcoded loopback default, while
    // `192.0.2.7:18443` silently bound every interface.
    assert_eq!(
        activation_listen(Some("127.0.0.1:18443"), 18443),
        "127.0.0.1:18443"
    );
    assert_eq!(
        activation_listen(Some("192.0.2.7:18443"), 18443),
        "192.0.2.7:18443"
    );
    assert_eq!(activation_listen(Some("192.0.2.7"), 443), "192.0.2.7:443");
    // A bare IP with no port means 443 (ADR-0039), not "any port".
    assert_eq!(activation_listen(Some("192.0.2.7"), 192), "192.0.2.7:192");

    // A host-less `:port` is the one spelling that means every interface, and it is honoured.
    assert_eq!(activation_listen(Some(":8443"), 8443), "0.0.0.0:8443");

    // Bracketed IPv6, with and without a port.
    assert_eq!(
        activation_listen(Some("[2001:db8::1]"), 443),
        "[2001:db8::1]:443"
    );
    assert_eq!(
        activation_listen(Some("[2001:db8::1]:9443"), 9443),
        "[2001:db8::1]:9443"
    );
    assert_eq!(activation_listen(Some("[::1]"), 443), "[::1]:443");
    assert_eq!(activation_listen(Some("[::1]:9443"), 9443), "[::1]:9443");
}

#[test]
fn a_bare_ipv6_address_is_accepted_with_the_default_port() {
    use setup::SetupListen;
    // ADR-0039 lists a bare `IP` as a valid form, and an IPv6 literal is an IP. Only a *port*
    // appended to an unbracketed IPv6 literal is ambiguous, and that is refused below.
    assert_eq!(
        SetupListen::parse(Some("2001:db8::1")).expect("bare IPv6 is valid"),
        SetupListen {
            ip: Some("2001:db8::1".parse().expect("ipv6")),
            port: 443
        }
    );
}

#[test]
fn an_unparseable_listen_address_is_a_located_error() {
    use setup::{SetupError, SetupListen};
    for bad in [
        "",
        "not-an-ip",
        "::1::2", // not a valid IPv6 address, so refused rather than guessed at
        "[not-an-ip]",
        "127.0.0.1:notaport",
        "127.0.0.1:",
        "[::1",
        "127.0.0.1:99999", // port above u16::MAX
        ":",
        "127.0.0.1:8443:1",
    ] {
        let error = SetupListen::parse(Some(bad))
            .expect_err(&format!("`{bad}` must be rejected as a listen address"));
        assert!(
            matches!(error, SetupError::InvalidListenAddress(_)),
            "`{bad}` produced {error:?}, expected InvalidListenAddress"
        );
    }
}
