//! Nested traversal of the deprecated-alias scan (T-HTTP-051).
//!
//! `check_deprecated_directives` only enters blocks that Caddy itself parses as directive lists:
//! the bodies of `route`/`handle`/`handle_path`/`handle_errors`, and the `handle_response` bodies
//! under `reverse_proxy`/`forward_auth`/`php_fastcgi` (`nested_directive_lists` in `adapter.rs`).
//!
//! The reviewer mutation that drops `php_fastcgi` from that table leaves the rest of the adapter
//! suite green, so these tests pin the two paths that mutation would silently break: a deprecated
//! alias inside `php_fastcgi`'s `handle_response`, and one inside a `reverse_proxy` nested under
//! `route`. They also pin the unsupported placement (`handle_response` directly under `route`),
//! which must fail loudly rather than being skipped.
//!
//! Each accepted fixture is the exact `caddy adapt` output of the pinned Caddy v2.11.9 oracle
//! (`.scratch/oracle-eval-2.11.9/caddy`); both binaries were run over the same Caddyfile and their
//! parsed JSON diffed before the fixture was committed. The rejection case was run through the
//! oracle too: it exits 1 with `unrecognized directive: handle_response`.

use caddy_rs_config::{adapt, adapt_with_options, AdaptMode, AdaptOptions};
use serde_json::{json, Value};

const SKIP_LOG_WARNING: &str =
    "the 'skip_log' directive is deprecated, please use 'log_skip' instead!";

fn fixture(name: &str) -> (String, Value) {
    let dir = format!(
        "{}/tests/fixtures/nested_alias_scan",
        env!("CARGO_MANIFEST_DIR")
    );
    let caddyfile = std::fs::read_to_string(format!("{dir}/{name}.caddyfile"))
        .unwrap_or_else(|error| panic!("read {name}.caddyfile: {error}"));
    let expected = std::fs::read_to_string(format!("{dir}/{name}.json"))
        .unwrap_or_else(|error| panic!("read {name}.json: {error}"));
    let expected = serde_json::from_str(&expected)
        .unwrap_or_else(|error| panic!("parse oracle JSON for {name}: {error}"));
    (caddyfile, expected)
}

fn adapt_in(caddyfile: &str, mode: AdaptMode) -> caddy_rs_core::AdaptedConfig {
    adapt_with_options(caddyfile, None, AdaptOptions::new(mode))
        .unwrap_or_else(|error| panic!("adapt in {mode} mode: {error}"))
}

/// The route list produced by the site's `route { ... }` body.
fn route_body(config: &Value) -> &Value {
    &config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"][0]
        ["routes"]
}

/// A deprecated alias inside `php_fastcgi`'s `handle_response`, with `php_fastcgi` itself nested
/// under `route`, must be reached by the scan and the directive must still expand like Caddy.
///
/// Mutation: removing `php_fastcgi` from `nested_directive_lists` makes the compatible/warn
/// warnings empty and the strict case succeed, so this test fails.
#[test]
fn php_fastcgi_inside_route_is_expanded_and_its_handle_response_is_scanned() {
    let (caddyfile, expected) = fixture("php_fastcgi_handle_response_in_route");

    let compatible = adapt_in(&caddyfile, AdaptMode::Compatible);
    assert_eq!(
        compatible.config, expected,
        "nested php_fastcgi JSON differs from the v2.11.9 oracle"
    );
    assert_eq!(
        compatible.warnings,
        vec![SKIP_LOG_WARNING.to_string()],
        "the alias inside php_fastcgi's handle_response must be scanned"
    );

    let warn = adapt_in(&caddyfile, AdaptMode::Warn);
    assert_eq!(
        warn.warnings,
        vec![SKIP_LOG_WARNING.to_string()],
        "warn mode reports the nested alias exactly once"
    );

    // `php_fastcgi` is still expanded to Caddy's three canonical routes.
    let routes = route_body(&compatible.config);
    assert_eq!(routes.as_array().map(Vec::len), Some(3), "{routes}");
    assert_eq!(routes[0]["handle"][0]["status_code"], 308);
    assert_eq!(
        routes[1]["handle"][0],
        json!({"handler": "rewrite", "uri": "{http.matchers.file.relative}"})
    );
    let proxy = &routes[2]["handle"][0];
    assert_eq!(proxy["handler"], "reverse_proxy");
    assert_eq!(
        proxy["transport"],
        json!({"protocol": "fastcgi", "split_path": [".php"]})
    );
    assert_eq!(
        proxy["handle_response"],
        json!([{
            "routes": [{"handle": [{"handler": "vars", "log_skip": true}]}]
        }]),
        "the nested handle_response keeps the expanded log_skip handler"
    );

    let error = adapt_with_options(&caddyfile, None, AdaptOptions::new(AdaptMode::Strict))
        .expect_err("strict mode rejects the alias inside php_fastcgi's handle_response");
    let message = error.to_string();
    assert_eq!(error.code(), "config.invalid", "{message}");
    assert!(
        message.contains("deprecated alias for `log_skip`"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 5"), "{message}");
}

/// `handle_response` inside a `reverse_proxy` nested under `route` is reached by the scan, and
/// `replace_status @alias <status>` (Caddy's status-only response-handler shorthand, not a
/// deprecated spelling) stays in the emitted proxy block.
///
/// Mutation: removing `reverse_proxy` from `nested_directive_lists` makes the warnings empty and
/// the strict case succeed, so this test fails.
#[test]
fn reverse_proxy_handle_response_inside_route_is_scanned_with_replace_status_alias() {
    let (caddyfile, expected) = fixture("reverse_proxy_handle_response_in_route");

    let compatible = adapt_in(&caddyfile, AdaptMode::Compatible);
    assert_eq!(
        compatible.config, expected,
        "nested reverse_proxy JSON differs from the v2.11.9 oracle"
    );
    assert_eq!(
        compatible.warnings,
        vec![SKIP_LOG_WARNING.to_string()],
        "only skip_log is a deprecated alias; replace_status must not warn"
    );
    assert_eq!(
        adapt_in(&caddyfile, AdaptMode::Warn).warnings,
        vec![SKIP_LOG_WARNING.to_string()],
        "warn mode reports the nested alias exactly once"
    );

    let routes = route_body(&compatible.config);
    assert_eq!(routes.as_array().map(Vec::len), Some(1), "{routes}");
    let proxy = &routes[0]["handle"][0];
    assert_eq!(proxy["handler"], "reverse_proxy");
    let entries = proxy["handle_response"]
        .as_array()
        .unwrap_or_else(|| panic!("nested proxy has no handle_response array: {proxy}"));
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(
        entries[0],
        json!({"match": {"status_code": [500]}, "status_code": 400}),
        "replace_status @alias is kept in the nested proxy block"
    );
    assert_eq!(
        entries[1]["routes"][0]["handle"][0],
        json!({"handler": "vars", "log_skip": true}),
        "the alias scan reached route > reverse_proxy > handle_response"
    );

    let error = adapt_with_options(&caddyfile, None, AdaptOptions::new(AdaptMode::Strict))
        .expect_err("strict mode rejects the alias inside the nested handle_response");
    let message = error.to_string();
    assert_eq!(error.code(), "config.invalid", "{message}");
    assert!(
        message.contains("deprecated alias for `log_skip`"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 7"), "{message}");
}

/// `handle_response` is a `reverse_proxy` subdirective, not a directive of its own, so placing it
/// directly in a `route` body is unsupported. The adapter must fail loudly with a located error
/// instead of treating the body as a directive list (which would also silence aliases inside it).
///
/// Oracle v2.11.9 rejects the same Caddyfile with exit 1 and
/// `unrecognized directive: handle_response`; caddy-rs names the more precise line 3.
#[test]
fn handle_response_directly_under_route_is_rejected_with_a_located_error() {
    let caddyfile =
        "example.com {\n\troute {\n\t\thandle_response {\n\t\t\trespond \"x\"\n\t\t}\n\t}\n}\n";
    let error = adapt(caddyfile).expect_err("handle_response is not a route directive");
    let message = error.to_string();
    assert_eq!(error.code(), "config.unsupported", "{message}");
    assert!(message.contains("directive `handle_response`"), "{message}");
    assert!(message.contains("Caddyfile line 3"), "{message}");
}
