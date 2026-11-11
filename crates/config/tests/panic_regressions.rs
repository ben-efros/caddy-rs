//! L9 panic regressions: inputs that used to reach a panicking construct in the adapter.
//!
//! Every case here is a *user-controlled* Caddyfile that either panicked before the fix or
//! traverses a site that was rewritten to return an error instead of aborting. The assertions pin
//! the observable behaviour, so a future regression fails the test instead of aborting the daemon.

use caddy_rs_config::adapt;
use serde_json::Value;

/// `php_fastcgi` builds a synthetic `reverse_proxy` handler; the transport override rejection must
/// stay a located error (the adapter used to `unreachable!` if the handler was not an object).
#[test]
fn php_fastcgi_transport_override_is_a_located_error() {
    let error = adapt(":80 {\n\tphp_fastcgi localhost:9000 {\n\t\ttransport fastcgi\n\t}\n}\n")
        .expect_err("`transport` override must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("does not accept a `transport` override"),
        "unexpected diagnostic: {message}"
    );
    assert!(
        message.contains("Caddyfile"),
        "diagnostic must stay located: {message}"
    );
}

/// A plain `php_fastcgi` site still adapts to a FastCGI transport.
#[test]
fn php_fastcgi_adapts_without_panicking() {
    let adapted = adapt(":80 {\n\tphp_fastcgi localhost:9000\n}\n").expect("adapt must succeed");
    let json = serde_json::to_string(&adapted.config).expect("serialisable");
    assert!(json.contains("\"fastcgi\""), "missing transport: {json}");
}

/// `acme_server { ca <id> }` merges a directive-level CA into the `pki` app. The merge used to
/// `expect` the `certificate_authorities` container to exist.
#[test]
fn acme_server_ca_merges_into_pki_app() {
    let adapted =
        adapt(":80 {\n\tacme_server {\n\t\tca my-ca\n\t}\n}\n").expect("adapt must succeed");
    let authorities = adapted
        .config
        .get("apps")
        .and_then(|apps| apps.get("pki"))
        .and_then(|pki| pki.get("certificate_authorities"))
        .and_then(Value::as_object)
        .expect("pki app must carry the directive CA container");
    assert!(
        authorities.contains_key("my-ca"),
        "directive CA missing: {authorities:?}"
    );
}

/// `µd` in a duration walked past a multi-byte rune: slicing the string at a byte index panicked
/// with `not a char boundary`. It must stay a located error naming the option.
#[test]
fn multi_byte_rune_in_duration_is_a_located_error() {
    let error = adapt("{\n\tgrace_period µd\n}\n:80 {\n\trespond ok\n}\n")
        .expect_err("`µd` is not a duration");
    let message = error.to_string();
    assert!(
        message.contains("grace_period"),
        "diagnostic must name the option: {message}"
    );
    assert!(
        message.contains("invalid syntax") || message.contains("parsing"),
        "unexpected diagnostic: {message}"
    );
}

/// The same multi-byte rune inside a `reverse_proxy` transport timeout (a different parser entry
/// point) must also return an error rather than panic.
#[test]
fn multi_byte_rune_in_transport_timeout_is_a_located_error() {
    let error = adapt(
        ":80 {\n\treverse_proxy localhost:9000 {\n\t\ttransport http {\n\t\t\tread_timeout µd\n\t\t}\n\t}\n}\n",
    )
    .expect_err("`µd` is not a duration");
    let message = error.to_string();
    assert!(
        message.contains("read_timeout") || message.contains("invalid"),
        "unexpected diagnostic: {message}"
    );
}
