//! The Caddyfile `@radar` matcher (ADR-0020, DIV-0149, T-ROUTE-065).
//!
//! These pin the adapter surface only: a named matcher whose block options become the
//! `{"radar": {...}}` object that `RadarPredicate::from_json` consumes. The matcher is a
//! caddy-rs extension (Caddy v2.11.9 has no radar matcher), so there is no upstream JSON shape to
//! mirror. Registering it in the adapter is only half the wiring: the server supplies the runtime
//! state the matcher evaluates against, and that half is proven in
//! `crates/http/tests/radar_registration.rs`.

use caddy_rs_config::adapt;
use serde_json::json;

fn adapted_routes(caddyfile: &str) -> serde_json::Value {
    let adapted = adapt(caddyfile).expect("Caddyfile adapts");
    adapted.config["apps"]["http"]["servers"]["srv0"]["routes"].clone()
}

fn adapt_error(caddyfile: &str) -> String {
    format!("{}", adapt(caddyfile).expect_err("adaptation must fail"))
}

#[test]
fn a_radar_matcher_adapts_its_block_options_to_a_predicate_object() {
    let routes = adapted_routes(
        r#"
:8080 {
	@attacked {
		radar source_asn_attacking true
	}
	respond @attacked "blocked"
}
"#,
    );
    assert_eq!(
        routes[0]["match"][0],
        json!({"radar": {"source_asn_attacking": true}}),
        "the block option becomes a predicate key with a real boolean, not the string \"true\""
    );
}

#[test]
fn several_predicates_preserve_written_order_and_type() {
    let routes = adapted_routes(
        r#"
:8080 {
	@attacked {
		radar source_asn_attacking true max_age 60
	}
	respond @attacked "blocked"
}
"#,
    );
    assert_eq!(
        routes[0]["match"][0],
        json!({"radar": {"source_asn_attacking": true, "max_age": "60"}}),
        "booleans stay booleans and numbers stay strings, because RadarPredicate::from_json is the \
         authority on each key's type"
    );
}

#[test]
fn a_radar_matcher_with_no_predicates_is_rejected() {
    // An empty predicate set would be a matcher that matches nothing for a reason the operator
    // cannot see from the Caddyfile, so it is refused at adapt time.
    let message = adapt_error(
        r#"
:8080 {
	@attacked {
		radar
	}
	respond @attacked "blocked"
}
"#,
    );
    assert!(
        message.contains("requires at least one predicate"),
        "expected the empty-block error, got: {message}"
    );
}

#[test]
fn an_odd_number_of_inline_arguments_is_rejected() {
    // Predicates are `name value` pairs; a dangling name has no value to compare against, and
    // defaulting it to something would silently change what the matcher means.
    let message = adapt_error(
        r#"
:8080 {
	@attacked {
		radar source_asn_attacking
	}
	respond @attacked "blocked"
}
"#,
    );
    assert!(
        message.contains("requires a value"),
        "expected the missing-value error, got: {message}"
    );
}

#[test]
fn a_block_predicate_without_a_value_is_rejected() {
    // The block form is one `name value` per line; a line with no value is refused rather than
    // treated as a flag.
    let message = adapt_error(
        r#"
:8080 {
	@attacked {
		radar {
			source_asn_attacking
		}
	}
	respond @attacked "blocked"
}
"#,
    );
    assert!(
        message.contains("requires a value"),
        "expected the missing-value error, got: {message}"
    );
}

#[test]
fn radar_also_adapts_inline_without_a_block() {
    // `@m radar ...` must reach the matcher arm rather than being read as a lone CEL expression.
    // Without `radar` in the adapter's known-matcher list, `@attacked radar source_asn_attacking
    // true` would silently become {"expression": {"expr": "radar"}} — a matcher that fails to
    // compile or matches nothing, for a reason invisible in the Caddyfile.
    let routes = adapted_routes(
        r#"
:8080 {
	@attacked radar source_asn_attacking true
	respond @attacked "blocked"
}
"#,
    );
    assert_eq!(
        routes[0]["match"][0],
        json!({"radar": {"source_asn_attacking": true}}),
        "the inline form must produce a radar matcher, not a CEL expression"
    );
}

#[test]
fn a_bare_radar_name_is_not_silently_read_as_a_cel_expression() {
    // `@attacked radar` with no predicates is a one-argument matcher. Without `radar` in the
    // adapter's known-matcher list it would be treated as an inline CEL expression named "radar",
    // which either fails to compile or matches nothing — the same silent-dead-matcher failure this
    // task exists to remove, one layer earlier.
    let message = adapt_error(
        r#"
:8080 {
	@attacked radar
	respond @attacked "blocked"
}
"#,
    );
    assert!(
        message.contains("matcher `radar` requires at least one predicate"),
        "a bare `radar` must be a radar error, not a CEL expression; got: {message}"
    );
}
