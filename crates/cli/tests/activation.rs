//! T-SETUP-002: the single-use activation endpoint.
//!
//! Protocol logic is driven directly through `ActivationService` (valid, expired, unknown and
//! second-use tokens, plus every 4xx branch), and one loopback test boots the real activation
//! listener through `activation::serve` and talks to it over TCP, so a handler that never reaches
//! the socket cannot pass.

#[path = "../src/activation.rs"]
mod activation;
#[path = "../src/setup.rs"]
mod setup;

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

/// Boot the real activation listener on a loopback port and drive it over TCP.
///
/// `activation::serve` blocks on the runtime's shutdown channel, so the listener is started on a
/// current-thread runtime in a background thread and the runtime is dropped when the test ends.
#[test]
fn the_activation_listener_answers_over_tcp() {
    let probe = TcpListener::bind("127.0.0.1:0").expect("pick a free port");
    let addr: SocketAddr = probe.local_addr().expect("local addr");
    drop(probe);

    let mut store = TokenStore::new(Duration::from_secs(900));
    let token = store.mint(SystemTime::now()).value;
    let service = Arc::new(ActivationService::new(store, AuthMethod::Webauthn));

    let listen = addr.to_string();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            // A registry with the modules the activation app needs (the HTTP app), plus the
            // activation handler module, which `serve_with` registers on top of it.
            let registry = caddy_rs_core::ModuleRegistry::builtin_for_profile(false);
            // The runtime's router consults the module registry for the app; the handler itself is
            // built by the custom factory, so the router is wired explicitly for the test.
            let _ = &registry;
            let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
            let (_force_tx, force) = tokio::sync::watch::channel(false);
            let _keep = shutdown_tx;
            if let Err(error) =
                activation::serve_with(&listen, service, registry, shutdown, force).await
            {
                eprintln!("activation serve failed: {error:#}");
            }
        });
    });

    let response = retry_request(addr, &activate_url(&token)).expect("activation request");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got: {response}"
    );
    assert!(
        response.contains("\"status\":\"activated\""),
        "body: {response}"
    );

    let replay = retry_request(addr, &activate_url(&token)).expect("replay request");
    assert!(
        replay.starts_with("HTTP/1.1 404"),
        "a replayed token must be 404, got: {replay}"
    );

    drop(thread);
}

fn retry_request(addr: SocketAddr, target: &str) -> Option<String> {
    let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    for _ in 0..100 {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut response = String::new();
                if stream.read_to_string(&mut response).is_ok() && !response.is_empty() {
                    return Some(response);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn the_activation_listener_is_loopback_by_default() {
    use setup::activation_listen;
    // No `--listen-address`: loopback, port 443 (the URL default).
    assert_eq!(activation_listen(None, 443), "127.0.0.1:443");
    // A host-less `:port` still binds loopback, never the wildcard: the temporary endpoint has no
    // TLS yet (DIV-0151).
    assert_eq!(activation_listen(Some(":8443"), 8443), "127.0.0.1:8443");
    assert_eq!(activation_listen(Some("192.0.2.7"), 443), "192.0.2.7:443");
    assert_eq!(
        activation_listen(Some("192.0.2.7:9443"), 9443),
        "192.0.2.7:9443"
    );
    assert_eq!(
        activation_listen(Some("[2001:db8::1]"), 443),
        "[2001:db8::1]:443"
    );
    assert_eq!(
        activation_listen(Some("[2001:db8::1]:9443"), 9443),
        "[2001:db8::1]:9443"
    );
}
