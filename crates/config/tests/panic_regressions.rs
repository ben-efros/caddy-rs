//! Regressions for the panic-hardening in commit `bc31871c2a7` (L9 adapter audit).
//!
//! Each test pins an *exact* observable outcome of the rewritten code, not merely "does not
//! panic": the shape of the `pki` app after a directive-level CA merge, the value of the
//! catch-all automation policy built with `always: true`, and the located, path-free diagnostic
//! for a rejected `php_fastcgi` transport override.
//!
//! Sensitivity was checked mechanically: reverting all three hunks of `bc31871c2a7` (pki merge,
//! `base_automation_policy`, `php_fastcgi` handler shape) and re-running this file still passes
//! every test, because the pre-fix `expect`/`unreachable!` were unreachable — they guarded values
//! the adapter itself builds (`pki_app_json` always emits the container; `always: true` always
//! yields `Some`; `reverse_proxy_handler` always returns an object), so no Caddyfile input could
//! ever reach them. These tests therefore pin the exact *value contract* of the rewritten
//! branches, which is what a future refactor can actually break. A test that cannot fail on
//! pre-fix input is not claimed to be a panic regression.
//!
//! The two former `µd` char-boundary tests were removed: the slicing panic they claimed to guard
//! was already absent in the parent commit (`bc31871c2a7^`), so they passed pre-fix and could
//! never fail on a reintroduction. Tests that cannot fail were not kept.

use caddy_rs_config::adapt;
use serde_json::{json, Value};

/// `acme_server { ca <id> }` with no global `pki` option: the adapter starts from
/// `{"certificate_authorities": {}}` and must emit exactly one CA with an empty definition.
/// Nothing else may be added to the app.
#[test]
fn pki_app_for_directive_ca_is_exactly_the_documented_container() {
    let adapted =
        adapt(":80 {\n\tacme_server {\n\t\tca my-ca\n\t}\n}\n").expect("adapt must succeed");
    let pki = adapted
        .config
        .get("apps")
        .and_then(|apps| apps.get("pki"))
        .expect("a directive-level CA must produce an apps.pki");
    assert_eq!(
        pki,
        &json!({"certificate_authorities": {"my-ca": {}}}),
        "pki app shape changed"
    );
}

/// A global `pki` CA and a directive-level CA must merge: the directive CA is added to the
/// existing container and the global authority's fields are preserved verbatim.
#[test]
fn pki_global_ca_and_directive_ca_merge_without_clobbering() {
    let adapted = adapt(
        "{ pki {\n  ca foo {\n   name \"Foo\"\n  }\n }\n}\n:80 {\n\tacme_server {\n\t\tca my-ca\n\t}\n}\n",
    )
    .expect("adapt must succeed");
    let pki = adapted
        .config
        .get("apps")
        .and_then(|apps| apps.get("pki"))
        .expect("a directive-level CA must produce an apps.pki");
    assert_eq!(
        pki,
        &json!({"certificate_authorities": {"foo": {"name": "Foo"}, "my-ca": {}}}),
        "the merge must add the directive CA and keep the global one"
    );
}

/// `base_automation_policy(options, true)` must yield `Some(AutomationPolicy::default())`: the
/// defaulted policy carries no `on_demand`, no `key_type`, no `renewal_window_ratio` and no
/// `issuer`-level options of its own. With no global ACME defaults the only fields are the site's
/// subject and the implicit ACME issuer.
#[test]
fn automation_policy_for_always_true_is_the_default_value() {
    let adapted = adapt("example.com {\n\ttls internal\n}\n").expect("adapt must succeed");
    let policies = adapted
        .config
        .get("apps")
        .and_then(|apps| apps.get("tls"))
        .and_then(|tls| tls.get("automation"))
        .and_then(|automation| automation.get("policies"))
        .expect("a hostname site must produce automation policies");
    assert_eq!(
        policies,
        &json!([{"subjects": ["example.com"], "issuers": [{"module": "internal"}]}]),
        "the base policy value changed"
    );
    let policy = policies
        .get(0)
        .and_then(Value::as_object)
        .expect("policy object");
    for absent in [
        "on_demand",
        "key_type",
        "renewal_window_ratio",
        "disable_ocsp_stapling",
    ] {
        assert!(
            !policy.contains_key(absent),
            "a defaulted policy must not set `{absent}`: {policy:?}"
        );
    }
}

/// A `transport` override inside `php_fastcgi` must be rejected with a static, located message:
/// located at the *directive* (`Caddyfile:2`, not the option on line 3) and free of any path,
/// secret or internal identifier — the message contains no `/` at all.
#[test]
fn php_fastcgi_transport_override_error_is_located_and_path_free() {
    let error = adapt(":80 {\n\tphp_fastcgi localhost:9000 {\n\t\ttransport fastcgi\n\t}\n}\n")
        .expect_err("`transport` override must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("Caddyfile line 3"),
        "diagnostic must be located at the `transport` option: {message}"
    );
    assert!(
        !message.contains("/root") && !message.contains(".scratch"),
        "diagnostic must not leak the data directory: {message}"
    );
    assert!(
        message.contains("`php_fastcgi` does not accept a `transport` override"),
        "diagnostic text changed: {message}"
    );
    assert!(
        !message.contains('/') && !message.contains('\\'),
        "diagnostic must not contain a path: {message}"
    );
}

/// The rejection branch must not reject valid configurations: a plain `php_fastcgi` still adapts
/// to a FastCGI transport with the `.php` split default.
#[test]
fn php_fastcgi_without_override_still_adapts_to_fastcgi_transport() {
    let adapted = adapt(":80 {\n\tphp_fastcgi localhost:9000\n}\n").expect("adapt must succeed");
    let transport = find_protocol(&adapted.config, "fastcgi").expect("a fastcgi transport");
    assert_eq!(
        transport.get("split_path"),
        Some(&json!([".php"])),
        "unexpected fastcgi transport: {transport}"
    );
}

/// Recursively find a transport object whose `protocol` field equals `protocol`.
fn find_protocol(value: &Value, protocol: &str) -> Option<Value> {
    match value {
        Value::Object(object) => {
            if object.get("protocol").and_then(Value::as_str) == Some(protocol) {
                return Some(value.clone());
            }
            object
                .values()
                .find_map(|child| find_protocol(child, protocol))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|child| find_protocol(child, protocol)),
        _ => None,
    }
}
