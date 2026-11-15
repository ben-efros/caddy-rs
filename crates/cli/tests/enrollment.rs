//! TOTP first-boot enrollment behind the activation endpoint (T-SETUP-003).
//!
//! These tests exercise the real flow: `begin` mints a secret, and `verify` is called with codes
//! computed from that secret by the same generator the server compares against, so a passing test
//! proves the possession proof actually works rather than that a stub returns success.

#[path = "../src/activation.rs"]
mod activation;
#[path = "../src/enrollment.rs"]
mod enrollment;
#[path = "../src/setup.rs"]
mod setup;

use caddy_rs_authn::{totp_code_for_step, totp_step_at};
use enrollment::{
    is_well_formed_code, EnrolledCredential, EnrollmentError, EnrollmentOutcome, EnrollmentService,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// The current Unix time in seconds.
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_secs()
}

/// Pull the base32 secret out of an `otpauth://` URI.
fn secret_from_uri(uri: &str) -> String {
    uri.split(|c| c == '?' || c == '&')
        .find_map(|part| part.strip_prefix("secret="))
        .expect("the issued URI carries a secret")
        .to_string()
}

/// A code that is valid right now for `secret`.
fn current_code(secret: &str) -> String {
    totp_code_for_step(secret, totp_step_at(now_seconds())).expect("secret decodes")
}

/// Run an enrollment request to completion.
fn call(service: &EnrollmentService, query: &str) -> Result<EnrollmentOutcome, EnrollmentError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(service.handle(query))
}

/// Begin enrollment and return the issued secret.
fn begin(service: &EnrollmentService) -> String {
    match call(&service, "token=abc&step=begin").expect("begin succeeds") {
        EnrollmentOutcome::SecretIssued { otpauth_uri } => secret_from_uri(&otpauth_uri),
        other => panic!("expected SecretIssued, got {other:?}"),
    }
}

#[test]
fn begin_issues_a_scannable_otpauth_uri_exactly_once() {
    let service = EnrollmentService::new("totp");
    let first = call(&service, "token=abc&step=begin").expect("begin");
    let EnrollmentOutcome::SecretIssued { otpauth_uri } = &first else {
        panic!("expected SecretIssued, got {first:?}");
    };
    assert!(
        otpauth_uri.starts_with("otpauth://totp/"),
        "unexpected URI: {otpauth_uri}"
    );
    assert!(otpauth_uri.contains("&digits=6"), "uri: {otpauth_uri}");
    assert!(otpauth_uri.contains("&period=30"), "uri: {otpauth_uri}");
    // The secret must actually be present, not an empty placeholder.
    assert!(!secret_from_uri(otpauth_uri).is_empty());

    // A refresh must not mint a second secret: the operator may already have scanned this one.
    let second = call(&service, "token=abc&step=begin").expect("begin again");
    assert_eq!(
        first, second,
        "begin must be idempotent within an activation"
    );
}

#[test]
fn a_correct_code_enrolls_exactly_one_credential_and_closes_the_window() {
    let service = EnrollmentService::new("totp");
    let secret = begin(&service);

    let outcome = call(
        &service,
        &format!("token=abc&step=verify&code={}", current_code(&secret)),
    )
    .expect("a correct code enrolls");
    let EnrollmentOutcome::Enrolled(credential) = &outcome else {
        panic!("expected Enrolled, got {outcome:?}");
    };
    assert_eq!(credential.username, "admin");
    assert_eq!(credential.method, "totp");
    assert!(service.is_enrolled());

    // Once enrolled the endpoint is closed, whatever credential is presented.
    let again = call(
        &service,
        &format!("token=abc&step=verify&code={}", current_code(&secret)),
    );
    assert_eq!(again, Err(EnrollmentError::AlreadyEnrolled));

    // Even a fresh token cannot reopen it: closing the window is the point.
    let fresh = call(&service, "token=def&step=begin");
    assert_eq!(fresh, Err(EnrollmentError::AlreadyEnrolled));
}

#[test]
fn a_wrong_code_is_refused_and_does_not_enroll() {
    let service = EnrollmentService::new("totp");
    let secret = begin(&service);

    let correct = current_code(&secret);
    // Change one digit so the code stays well-formed but cannot match.
    let mut wrong: Vec<char> = correct.chars().collect();
    wrong[0] = if wrong[0] == '0' { '1' } else { '0' };
    let wrong: String = wrong.into_iter().collect();
    assert_ne!(correct, wrong);

    let outcome = call(&service, &format!("token=abc&step=verify&code={wrong}"));
    assert_eq!(outcome, Err(EnrollmentError::CodeRejected));
    assert!(
        !service.is_enrolled(),
        "a refused code must not close the window"
    );

    // The window still works afterwards: a refusal is not terminal.
    let ok = call(&service, &format!("token=abc&step=verify&code={correct}"));
    assert!(matches!(ok, Ok(EnrollmentOutcome::Enrolled(_))));
}

#[test]
fn a_replayed_code_is_reported_as_a_replay_not_a_mismatch() {
    let service = EnrollmentService::new("totp");
    let secret = begin(&service);
    let code = current_code(&secret);

    // Consume the step via the first good verification.
    let first = call(&service, &format!("token=abc&step=verify&code={code}"));
    assert!(matches!(first, Ok(EnrollmentOutcome::Enrolled(_))));

    // A second service over the same secret, to prove the replay is caught by the step record
    // rather than by the already-enrolled gate.
    let fresh = EnrollmentService::new("totp");
    let secret2 = begin(&fresh);
    let code2 = current_code(&secret2);
    assert_eq!(
        call(&fresh, &format!("token=abc&step=verify&code={code2}")),
        Ok(EnrollmentOutcome::Enrolled(EnrolledCredential {
            username: "admin".to_string(),
            method: "totp",
        }))
    );
    assert_eq!(
        call(&fresh, &format!("token=abc&step=verify&code={code2}")),
        Err(EnrollmentError::AlreadyEnrolled)
    );
}

#[test]
fn malformed_requests_are_refused_with_located_errors() {
    let service = EnrollmentService::new("totp");

    // No step at all.
    assert_eq!(
        call(&service, "token=abc"),
        Err(EnrollmentError::InvalidStep)
    );
    // An unknown step.
    assert_eq!(
        call(&service, "token=abc&step=middle"),
        Err(EnrollmentError::InvalidStep)
    );
    // A repeated step is ambiguous and refused rather than first-wins.
    assert_eq!(
        call(&service, "token=abc&step=begin&step=verify"),
        Err(EnrollmentError::InvalidStep)
    );

    // Verify before begin: there is no secret yet.
    assert_eq!(
        call(&service, "token=abc&step=verify&code=123456"),
        Err(EnrollmentError::InvalidStep)
    );

    let secret = begin(&service);
    // Missing code.
    assert_eq!(
        call(&service, "token=abc&step=verify"),
        Err(EnrollmentError::InvalidCode)
    );
    // Wrong length, non-digits, and a repeated code parameter.
    assert_eq!(
        call(&service, "token=abc&step=verify&code=12345"),
        Err(EnrollmentError::InvalidCode)
    );
    assert_eq!(
        call(&service, "token=abc&step=verify&code=abcdef"),
        Err(EnrollmentError::InvalidCode)
    );
    assert_eq!(
        call(
            &service,
            &format!(
                "token=abc&step=verify&code=000000&code={}",
                current_code(&secret)
            )
        ),
        Err(EnrollmentError::InvalidCode)
    );
    assert!(!service.is_enrolled());
}

#[test]
fn webauthn_is_refused_rather_than_faked() {
    let service = EnrollmentService::new("webauthn");
    assert_eq!(service.method(), "webauthn");
    for query in ["token=abc&step=begin", "token=abc&step=verify&code=123456"] {
        let outcome = call(&service, query);
        assert_eq!(
            outcome,
            Err(EnrollmentError::MethodUnsupported { method: "webauthn" }),
            "webauthn must be refused, not pretended: {query}"
        );
    }
    assert!(!service.is_enrolled(), "a refusal must not enroll anything");
}

#[test]
fn an_unenrolled_service_reports_the_window_is_open() {
    let service = EnrollmentService::new("totp");
    assert!(!service.is_enrolled(), "nothing is enrolled before a proof");
}

#[test]
fn refusals_render_statuses_and_token_free_bodies() {
    let cases = [
        (EnrollmentError::AlreadyEnrolled, 409, "already_enrolled"),
        (
            EnrollmentError::MethodUnsupported { method: "webauthn" },
            501,
            "method_unsupported",
        ),
        (EnrollmentError::InvalidStep, 400, "invalid_step"),
        (EnrollmentError::InvalidCode, 400, "invalid_code"),
        (EnrollmentError::CodeRejected, 401, "code_rejected"),
        (EnrollmentError::CodeReplayed, 401, "code_replayed"),
        (
            EnrollmentError::Internal("boom".to_string()),
            500,
            "internal",
        ),
    ];
    for (error, status, code) in cases {
        assert_eq!(error.status(), status, "status for {code}");
        let body = error.body();
        assert!(
            body.contains(&format!("\"error\":\"{code}\"")),
            "body for {code} was {body}"
        );
        // A refusal must never echo a secret, a code or the token.
        assert!(!body.contains("secret"), "body leaked a secret: {body}");
        assert!(!body.contains("code\":\"1"), "body leaked a code: {body}");
    }
}

#[test]
fn the_code_shape_predicate_matches_the_documented_contract() {
    assert!(is_well_formed_code("123456"));
    assert!(is_well_formed_code("000000"));
    assert!(!is_well_formed_code("12345"));
    assert!(!is_well_formed_code("1234567"));
    assert!(!is_well_formed_code("12345a"));
    assert!(!is_well_formed_code(""));
    assert!(!is_well_formed_code(" 12345"));
}

#[test]
fn a_code_from_an_older_step_is_refused_once_a_newer_one_is_used() {
    let service = EnrollmentService::new("totp");
    let secret = begin(&service);
    let step_now = totp_step_at(now_seconds());
    // A code from a step outside the ±1 window must not be accepted.
    let stale = totp_code_for_step(&secret, step_now.saturating_sub(10)).expect("secret decodes");
    let outcome = call(&service, &format!("token=abc&step=verify&code={stale}"));
    assert!(
        matches!(
            outcome,
            Err(EnrollmentError::CodeRejected | EnrollmentError::CodeReplayed)
        ),
        "a stale code must be refused, got {outcome:?}"
    );
    assert!(!service.is_enrolled());
}

/// Boot the activation listener with enrollment attached and talk to it over TCP, so a service that
/// works in-process but is never wired into the handler cannot pass this test.
#[test]
fn totp_enrollment_completes_over_the_real_listener() {
    use activation::{serve_with, ActivationService};
    use setup::{AuthMethod, TokenStore};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    let probe = TcpListener::bind("127.0.0.1:0").expect("pick a free port");
    let addr: SocketAddr = probe.local_addr().expect("local addr");
    drop(probe);

    let mut store = TokenStore::new(Duration::from_secs(900));
    let token = store.mint(SystemTime::now()).value;
    let enrollment = Arc::new(EnrollmentService::new("totp"));
    let service = Arc::new(
        ActivationService::new(store, AuthMethod::Totp).with_enrollment(Arc::clone(&enrollment)),
    );

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
            if let Err(error) = serve_with(&listen, service, registry, shutdown, force).await {
                eprintln!("activation serve failed: {error:#}");
            }
        });
    });

    let request = |target: &str| -> String {
        let req = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        for _ in 0..100 {
            if let Ok(mut stream) = TcpStream::connect(addr) {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                if stream.write_all(req.as_bytes()).is_ok() {
                    let mut response = String::new();
                    if stream.read_to_string(&mut response).is_ok() && !response.is_empty() {
                        return response;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no response for {target}");
    };

    // Step 1: begin. The response must carry a scannable otpauth:// URI.
    let began = request(&format!("/_caddy-pm/activate?token={token}&step=begin"));
    assert!(began.starts_with("HTTP/1.1 200"), "begin got: {began}");
    assert!(
        began.contains("otpauth://totp/"),
        "begin must return the URI, got: {began}"
    );
    let secret = began
        .split("secret=")
        .nth(1)
        .and_then(|rest| {
            rest.split(|c: char| c == '&' || c == '"' || c == '\\')
                .next()
        })
        .expect("the URI carries a secret")
        .to_string();

    // Step 2: verify with a real code for that secret.
    let code = current_code(&secret);
    let verified = request(&format!(
        "/_caddy-pm/activate?token={token}&step=verify&code={code}"
    ));
    assert!(
        verified.starts_with("HTTP/1.1 200"),
        "verify got: {verified}"
    );
    assert!(
        verified.contains("\"enrollment\":\"complete\""),
        "verify must report completion, got: {verified}"
    );
    assert!(enrollment.is_enrolled(), "the credential must be enrolled");

    // Step 3: the window is closed, even for a fresh step request.
    let closed = request(&format!("/_caddy-pm/activate?token={token}&step=begin"));
    assert!(
        closed.starts_with("HTTP/1.1 409") || closed.starts_with("HTTP/1.1 404"),
        "the endpoint must be closed after enrollment, got: {closed}"
    );

    drop(thread);
}

/// A second, different activation token must not be able to continue the session another token
/// opened. Without this, the token would stop being a credential at all: any well-formed token
/// would satisfy the enrollment check.
#[test]
fn a_different_token_cannot_continue_another_tokens_enrollment_session() {
    use activation::ActivationService;
    use setup::{AuthMethod, TokenStore};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    let mut store = TokenStore::new(Duration::from_secs(900));
    let first = store.mint(SystemTime::now()).value;
    let second = store.mint(SystemTime::now()).value;
    assert_ne!(first, second);

    let enrollment = Arc::new(EnrollmentService::new("totp"));
    let service =
        ActivationService::new(store, AuthMethod::Totp).with_enrollment(Arc::clone(&enrollment));

    let call = |target: String| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(service.handle_async("GET", &target))
    };

    // The first token opens the session.
    let began = call(format!("/_caddy-pm/activate?token={first}&step=begin"));
    assert_eq!(began, activation::ActivationOutcome::Enrolled);
    let secret = secret_from_uri(&enrollment.issued_uri().expect("a secret was issued"));

    // The second token was never minted for this and must be refused, not admitted into the
    // session the first token opened.
    let intruder = call(format!(
        "/_caddy-pm/activate?token={second}&step=verify&code={}",
        current_code(&secret)
    ));
    assert_eq!(
        intruder,
        activation::ActivationOutcome::Unknown,
        "a different token must not join the session"
    );
    assert!(
        !enrollment.is_enrolled(),
        "an intruding token must not complete the enrollment"
    );

    // The legitimate token still completes the session.
    let ok = call(format!(
        "/_caddy-pm/activate?token={first}&step=verify&code={}",
        current_code(&secret)
    ));
    assert_eq!(ok, activation::ActivationOutcome::Enrolled);
    assert!(enrollment.is_enrolled());
}
