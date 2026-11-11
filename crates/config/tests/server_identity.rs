//! Caddyfile `servers { server_identity ... }` adaptation (T-CONF-060).
//!
//! The directive is a caddy-rs extension. It accepts five modes and emits the canonical JSON
//! spelling into the server object; every malformed spelling is a located error.

use caddy_rs_config::adapt;
use serde_json::{json, Value};

/// Adapt a Caddyfile with a global `servers { server_identity ... }` block and return the value
/// emitted into the first HTTP server object.
fn adapted_identity(directive: &str) -> Value {
    let caddyfile =
        format!("{{\n\tservers {{\n\t\t{directive}\n\t}}\n}}\n\n:8080 {{\n\trespond \"ok\"\n}}\n");
    let adapted = adapt(&caddyfile).unwrap_or_else(|error| panic!("{directive:?}: {error}"));
    let servers = adapted.config["apps"]["http"]["servers"]
        .as_object()
        .unwrap_or_else(|| panic!("{directive:?}: no servers in {}", adapted.config));
    let server = servers.values().next().expect("one server");
    server
        .get("server_identity")
        .cloned()
        .unwrap_or_else(|| panic!("{directive:?}: no server_identity in {server}"))
}

#[test]
fn every_mode_emits_its_canonical_json_spelling() {
    assert_eq!(adapted_identity("server_identity"), json!("default"));
    assert_eq!(
        adapted_identity("server_identity default"),
        json!("default")
    );
    assert_eq!(
        adapted_identity("server_identity name-only"),
        json!("name-only")
    );
    assert_eq!(
        adapted_identity("server_identity compatible"),
        json!("compatible")
    );
    assert_eq!(adapted_identity("server_identity none"), json!("none"));
    assert_eq!(
        adapted_identity("server_identity custom \"Acme Server/2\""),
        json!("Acme Server/2")
    );
}

#[test]
fn malformed_forms_are_located_errors() {
    let caddyfile = |directive: &str| {
        format!("{{\n\tservers {{\n\t\t{directive}\n\t}}\n}}\n\n:8080 {{\n\trespond \"ok\"\n}}\n")
    };
    for directive in [
        "server_identity {\n\t\t}",
        "server_identity bogus",
        "server_identity default extra",
        "server_identity custom",
        "server_identity custom \"\"",
    ] {
        let error = adapt(&caddyfile(directive))
            .err()
            .unwrap_or_else(|| panic!("{directive:?} must be rejected"));
        let message = error.to_string();
        assert!(
            message.contains("Caddyfile line"),
            "{directive:?} must be a located error, got {message}"
        );
        assert!(
            message.contains("server_identity"),
            "{directive:?} error must name the directive, got {message}"
        );
    }
}
