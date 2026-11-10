//! Response-matcher declaration order, matching Caddy's two-phase resolution.
//!
//! `modules/caddyhttp/reverseproxy/caddyfile.go` (v2.11.7 and v2.11.9) treats the two reference
//! kinds differently:
//!
//! * `replace_status` looks the matcher up in `h.responseMatchers` while `UnmarshalCaddyfile`
//!   walks the block, so only matchers declared *before* it are visible. A forward reference
//!   fails with `no named response matcher defined with name '<name>'`.
//! * `handle_response` is only recorded as a segment and resolved in
//!   `FinalizeUnmarshalCaddyfile`, after the whole block has been parsed, so it sees every
//!   response matcher in the block. A forward reference is legal and adapts.
//!
//! `forward_auth` and `php_fastcgi` reuse the reverse-proxy unmarshaler, so both directives follow
//! the same rule. The exact adapted JSON for the valid orderings lives in
//! `fixtures/local/*response_matcher*.json` / `*handle_response_forward_reference.json` and is
//! oracle-generated; these tests name the rule so a regression points at the phase split.

use serde_json::Value;

fn adapt_error(caddyfile: &str) -> String {
    caddy_rs_config::adapt(caddyfile)
        .expect_err("a forward `replace_status` matcher reference must be rejected")
        .to_string()
}

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/local/{name}.caddyfile",
        env!("CARGO_MANIFEST_DIR")
    );
    let input = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    caddy_rs_config::adapt(&input)
        .unwrap_or_else(|e| panic!("adapt {name}: {e}"))
        .config
}

/// `replace_status` resolves as it parses, so a matcher declared after the reference is a located
/// error naming the matcher. Caddy's wording and class are preserved.
#[test]
fn replace_status_forward_reference_is_rejected_for_reverse_proxy() {
    let message = adapt_error(
        ":8080 {\n\treverse_proxy 127.0.0.1:9000 {\n\t\treplace_status @late 404\n\t\t@late status 500\n\t}\n}\n",
    );
    assert!(
        message.contains("no named response matcher defined with name 'late'"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 3"), "{message}");
    assert!(message.contains("invalid configuration"), "{message}");
}

#[test]
fn replace_status_forward_reference_is_rejected_for_forward_auth() {
    let message = adapt_error(
        ":8080 {\n\tforward_auth 127.0.0.1:9000 {\n\t\turi /auth\n\t\treplace_status @late 404\n\t\t@late status 500\n\t}\n}\n",
    );
    assert!(
        message.contains("no named response matcher defined with name 'late'"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 4"), "{message}");
}

#[test]
fn replace_status_forward_reference_is_rejected_for_php_fastcgi() {
    let message = adapt_error(
        ":8080 {\n\tphp_fastcgi 127.0.0.1:9000 {\n\t\treplace_status @late 404\n\t\t@late status 500\n\t}\n}\n",
    );
    assert!(
        message.contains("no named response matcher defined with name 'late'"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 3"), "{message}");
}

/// The error names the exact reference that failed: a matcher declared earlier is accepted, only
/// the forward reference is rejected, and the diagnostic points at the `replace_status` line.
#[test]
fn only_the_forward_reference_is_rejected() {
    let accepted = caddy_rs_config::adapt(
        ":8080 {\n\treverse_proxy 127.0.0.1:9000 {\n\t\t@late status 404\n\t\treplace_status @late 418\n\t}\n}\n",
    )
    .expect("a matcher declared before its `replace_status` use must adapt");
    assert_eq!(
        accepted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]
            ["handle_response"][0]["match"],
        serde_json::json!({"status_code": [404]})
    );

    let message = adapt_error(
        ":8080 {\n\treverse_proxy 127.0.0.1:9000 {\n\t\treplace_status @late 418\n\t\t@late status 404\n\t}\n}\n",
    );
    assert!(
        message.contains("no named response matcher defined with name 'late'"),
        "{message}"
    );
}

/// `handle_response` is finalized after the block is parsed, so its forward references stay legal
/// for every directive that reuses the reverse-proxy unmarshaler.
#[test]
fn handle_response_forward_reference_adapts_like_caddy() {
    for (name, expected_status) in [
        ("reverse_proxy_handle_response_forward_reference", 500),
        ("forward_auth_handle_response_forward_reference", 500),
        ("php_fastcgi_handle_response_forward_reference", 500),
    ] {
        let config = fixture(name);
        let entries = find_handle_response_entries(&config)
            .unwrap_or_else(|| panic!("{name} has no handle_response entries"));
        let matched: Vec<&Value> = entries
            .iter()
            .filter(|entry| {
                entry["match"]["status_code"]
                    .as_array()
                    .is_some_and(|codes| codes.contains(&serde_json::json!(expected_status)))
            })
            .collect();
        assert_eq!(matched.len(), 1, "{name}: {entries:?}");
        assert!(
            matched[0].get("routes").is_some(),
            "{name}: the forward-declared matcher must carry the handle_response routes"
        );
    }
}

/// Valid declaration order must adapt byte-identically to the pinned oracle; the fixture JSON is
/// Caddy v2.11.9 `adapt --pretty` output.
#[test]
fn valid_declaration_order_matches_the_oracle_fixture() {
    for name in [
        "reverse_proxy_response_matcher_declared_before_use",
        "forward_auth_response_matcher_declared_before_use",
        "php_fastcgi_response_matcher_declared_before_use",
        "reverse_proxy_handle_response_forward_reference",
        "forward_auth_handle_response_forward_reference",
        "php_fastcgi_handle_response_forward_reference",
    ] {
        let expected_path = format!(
            "{}/tests/fixtures/local/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let expected_text = std::fs::read_to_string(&expected_path)
            .unwrap_or_else(|e| panic!("read {expected_path}: {e}"));
        let expected: Value = serde_json::from_str(&expected_text)
            .unwrap_or_else(|e| panic!("expected JSON for {name}: {e}"));
        assert_eq!(
            fixture(name),
            expected,
            "adapted JSON differs from the oracle for {name}"
        );
    }
}

/// Locate the `handle_response` array in the adapted reverse-proxy handler, whether it is the
/// route's only handler (reverse_proxy) or nested in a `php_fastcgi` expansion.
fn find_handle_response_entries(config: &Value) -> Option<Vec<Value>> {
    fn walk(value: &Value) -> Option<Vec<Value>> {
        match value {
            Value::Object(object) => {
                if let Some(entries) = object.get("handle_response") {
                    return entries.as_array().cloned();
                }
                object.values().find_map(walk)
            }
            Value::Array(array) => array.iter().find_map(walk),
            _ => None,
        }
    }
    walk(config)
}
