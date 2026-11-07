//! T-CONF-054 / DIV-0102: the `acme_server` directive adapts to Caddy's exact JSON.
//!
//! The runtime handler (`http.handlers.acme_server`) is implemented concurrently; these tests
//! only pin the adapter contract: the eight upstream v2.11.9 `acme_server_*` golden fixtures and
//! located errors for every argument Caddy rejects.

use caddy_rs_config::adapt;
use serde_json::Value;

const UPSTREAM_FIXTURES: &[&str] = &[
    "acme_server_custom_challenges.caddyfiletest",
    "acme_server_default_challenges.caddyfiletest",
    "acme_server_lifetime.caddyfiletest",
    "acme_server_multi_custom_challenges.caddyfiletest",
    "acme_server_policy-allow.caddyfiletest",
    "acme_server_policy-both.caddyfiletest",
    "acme_server_policy-deny.caddyfiletest",
    "acme_server_sign_with_root.caddyfiletest",
];

fn fixture(name: &str) -> (String, Value) {
    let path = format!(
        "{}/tests/fixtures/upstream/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let (caddyfile, expected) = raw
        .split_once("----------")
        .unwrap_or_else(|| panic!("fixture {name} has no `----------` separator"));
    let caddyfile = format!("{}\n", caddyfile.trim());
    let expected: Value = serde_json::from_str(expected.trim())
        .unwrap_or_else(|e| panic!("fixture {name} expected JSON: {e}"));
    (caddyfile, expected)
}

#[test]
fn all_upstream_acme_server_fixtures_match_caddy() {
    for name in UPSTREAM_FIXTURES {
        let (caddyfile, expected) = fixture(name);
        let adapted = adapt(&caddyfile).unwrap_or_else(|e| panic!("adapt {name}: {e}"));
        assert_eq!(adapted.config, expected, "adapted JSON differs for {name}");
    }
}

fn error(caddyfile: &str) -> String {
    adapt(caddyfile)
        .expect_err("Caddy rejects this Caddyfile, so adaptation must fail")
        .to_string()
}

#[test]
fn acme_server_takes_no_arguments_beyond_an_optional_matcher() {
    let message = error("example.com {\n\tacme_server foo\n}\n");
    assert!(
        message.contains("`acme_server` takes no arguments"),
        "{message}"
    );
    assert!(message.contains("foo"), "{message}");
    assert!(message.contains("Caddyfile line 2"), "{message}");
}

#[test]
fn acme_server_rejects_unknown_suboptions() {
    // Caddy v2.11.9 has no `template` suboption (`parseACMEServer` switch): it is rejected.
    let message = error("example.com {\n\tacme_server {\n\t\ttemplate foo\n\t}\n}\n");
    assert!(
        message.contains("unrecognized ACME server directive: template"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 3"), "{message}");
}

#[test]
fn acme_server_ca_requires_exactly_one_argument() {
    let message = error("example.com {\n\tacme_server {\n\t\tca\n\t}\n}\n");
    assert!(
        message.contains("option `ca` requires exactly one CA ID"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 3"), "{message}");

    let message = error("example.com {\n\tacme_server {\n\t\tca a b\n\t}\n}\n");
    assert!(
        message.contains("option `ca` requires exactly one CA ID"),
        "{message}"
    );
}

#[test]
fn acme_server_lifetime_requires_a_caddy_duration() {
    let message = error("example.com {\n\tacme_server {\n\t\tlifetime banana\n\t}\n}\n");
    assert!(
        message.contains("invalid `acme_server` lifetime `banana`"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 3"), "{message}");
}

#[test]
fn acme_server_resolvers_requires_at_least_one_address() {
    let message = error("example.com {\n\tacme_server {\n\t\tresolvers\n\t}\n}\n");
    assert!(
        message.contains("`resolvers` must specify at least one resolver address"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 3"), "{message}");
}

#[test]
fn acme_server_sign_with_root_rejects_arguments() {
    let message = error("example.com {\n\tacme_server {\n\t\tsign_with_root yes\n\t}\n}\n");
    assert!(
        message.contains("`sign_with_root` does not take arguments"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 3"), "{message}");
}

#[test]
fn acme_server_allow_rejects_unknown_subdirectives() {
    let message =
        error("example.com {\n\tacme_server {\n\t\tallow {\n\t\t\tbogus x\n\t\t}\n\t}\n}\n");
    assert!(
        message.contains("unrecognized 'allow' subdirective: bogus"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 4"), "{message}");
}

#[test]
fn acme_server_allow_rule_requires_a_value() {
    let message =
        error("example.com {\n\tacme_server {\n\t\tdeny {\n\t\t\tdomains\n\t\t}\n\t}\n}\n");
    assert!(
        message.contains("deny rule `domains` requires at least one domain"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 4"), "{message}");
}

#[test]
fn acme_server_with_ca_cannot_be_used_inside_route() {
    // Caddy's `parseRoute` rejects a `pki.ca` configuration value:
    // "only handler directives can be used in routes"
    // (caddyconfig/httpcaddyfile/builtins.go).
    let message = error("example.com {\n\troute {\n\t\tacme_server {\n\t\t\tca x\n\t\t}\n\t}\n}\n");
    assert!(
        message.contains("cannot be used inside `route`"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 3"), "{message}");

    // Without `ca` it is a plain handler route and adapts.
    adapt("example.com {\n\troute {\n\t\tacme_server\n\t}\n}\n")
        .expect("a ca-less acme_server is an ordinary handler route");
}
