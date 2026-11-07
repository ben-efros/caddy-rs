//! `caddy-rs validate` must provision like Caddy's `validate`.
//!
//! Caddy's `validate` provisions the apps before reporting success: handler/matcher modules,
//! listener wrappers, server limits and routers are constructed, so a configuration that cannot be
//! built fails `validate` instead of the first `run`. These tests exercise
//! [`ServerRuntime::validate_provisioning`] directly (it never binds sockets or obtains
//! certificates) for the cases the real-Caddy oracle exposed:
//!
//! 1. a healthy static configuration validates;
//! 2. `proxy_protocol` `allow`/`deny` entries must be CIDR prefixes, exactly like Caddy's
//!    `netip.ParsePrefix` (a bare address is rejected at provision time);
//! 3. an `expression` matcher outside the implemented subset is rejected with the tracked
//!    `NotImplemented` error instead of validating and failing at `run`;
//! 4. a configuration that terminates TLS without certificates still validates (Caddy obtains
//!    certificates at start, not at provision time).

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;

fn store_with(value: serde_json::Value) -> std::sync::Arc<GenerationStore> {
    let store = std::sync::Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(Config::from_value(value).expect("config decodes"))
        .expect("config validates");
    store
}

fn validate(value: serde_json::Value) -> Result<(), String> {
    let store = store_with(value);
    let runtime = ServerRuntime::new(store);
    runtime
        .validate_provisioning()
        .map_err(|error| error.to_string())
}

#[test]
fn valid_configuration_provisions_cleanly() {
    validate(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
        }}}}
    }))
    .expect("a healthy configuration must validate");
}

#[test]
fn proxy_protocol_allow_and_deny_require_cidr_prefixes() {
    // Caddy v2.11.7's listener wrapper parses these with `netip.ParsePrefix`, which requires an
    // explicit prefix length; a bare address fails at provision time.
    let error = validate(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "listener_wrappers": [{
                "wrapper": "proxy_protocol",
                "allow": ["10.0.0.0/8", "192.0.2.1"]
            }],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
        }}}}
    }))
    .expect_err("a bare allow address must be rejected");
    assert!(
        error.contains("invalid allow CIDR `192.0.2.1`"),
        "error must name the offending entry: {error}"
    );

    // CIDR prefixes are accepted.
    validate(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "listener_wrappers": [{
                "wrapper": "proxy_protocol",
                "allow": ["10.0.0.0/8", "192.0.2.0/24"],
                "deny": ["1.2.3.0/24"],
                "fallback_policy": "REQUIRE"
            }],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
        }}}}
    }))
    .expect("CIDR prefixes must validate");
}

#[test]
fn unsupported_expression_matcher_fails_validation() {
    // CEL backtick raw strings are not accepted by Caddy v2.11.9's expression matcher either
    // (the v2.11.9 oracle reports a CEL parse error), so caddy-rs rejects them with a syntax
    // error class that the oracle treats as the same rejection (`DIV-0107`).
    let error = validate(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "match": [{"expression": "{http.error.status_code} == `402`"}],
                "handle": [{"handler": "static_response", "body": "ok"}]
            }]
        }}}}
    }))
    .expect_err("an unsupported expression matcher must fail validation");
    assert!(
        error.contains("syntax error") && error.contains("unexpected character"),
        "error must name the syntax error and the offending character: {error}"
    );
}

#[test]
fn tls_without_certificates_still_validates() {
    // Certificate acquisition happens at start, not at provision time, so a TLS listener without
    // certificates must still validate (and fail at `apply`, which is covered by
    // `http_cutover_rollback`).
    validate(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "tls_connection_policies": [{}],
            "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
        }}}}
    }))
    .expect("TLS without certificates must validate");
}
