//! Caddyfile `header { security_headers { ... } }` adaptation (T-ROUTE-051).
//!
//! `security_headers` is the caddy-rs secure-defaults block of the `headers` handler
//! (T-ROUTE-050). The adapter emits exactly the `security_headers` object a hand-written JSON
//! configuration carries, so the Caddyfile form needs no separate runtime path; semantic
//! validation stays in the handler and Caddyfile *structure* errors are located at their line.

use caddy_rs_config::adapt;
use serde_json::{json, Value};

fn adapted_handler(caddyfile: &str) -> Value {
    let adapted = adapt(caddyfile).unwrap_or_else(|error| panic!("{caddyfile}\n{error}"));
    let mut found = Vec::new();
    collect_headers_handlers(&adapted.config, &mut found);
    assert_eq!(
        found.len(),
        1,
        "expected exactly one headers handler in {}",
        adapted.config
    );
    found.pop().expect("one handler")
}

fn collect_headers_handlers(value: &Value, found: &mut Vec<Value>) {
    match value {
        Value::Object(object) => {
            if object.get("handler").and_then(Value::as_str) == Some("headers") {
                found.push(Value::Object(object.clone()));
            }
            for child in object.values() {
                collect_headers_handlers(child, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_headers_handlers(item, found);
            }
        }
        _ => {}
    }
}

fn adapted_security_headers(block: &str) -> Value {
    let caddyfile =
        format!("example.com {{\n\theader {{\n\t\tsecurity_headers {{\n{block}\t\t}}\n\t}}\n}}\n");
    let handler = adapted_handler(&caddyfile);
    handler
        .get("security_headers")
        .cloned()
        .unwrap_or_else(|| panic!("no security_headers in {handler}"))
}

fn assert_located(error: &str, line: usize) {
    assert!(
        error.contains(&format!("Caddyfile line {line}")),
        "expected a located error at line {line}: {error}"
    );
}

#[test]
fn security_headers_block_emits_the_handler_json() {
    let security = adapted_security_headers(
        "\t\t\tx_frame_options DENY\n\
         \t\t\tx_content_type_options nosniff\n\
         \t\t\treferrer_policy strict-origin-when-cross-origin\n\
         \t\t\tcontent_security_policy {\n\
         \t\t\t\tdefault_src 'self'\n\
         \t\t\t\tscript_src 'self' 'nonce-{csp.nonce}'\n\
         \t\t\t}\n\
         \t\t\thsts {\n\
         \t\t\t\tmax_age 31536000\n\
         \t\t\t\tinclude_subdomains\n\
         \t\t\t\tpreload\n\
         \t\t\t}\n\
         \t\t\tpermissions_policy {\n\
         \t\t\t\tgeolocation=()\n\
         \t\t\t\tmicrophone=(self https://example.com)\n\
         \t\t\t}\n",
    );
    assert_eq!(
        security,
        json!({
            "x_frame_options": "DENY",
            "x_content_type_options": "nosniff",
            "referrer_policy": "strict-origin-when-cross-origin",
            "content_security_policy": {
                "default-src": ["'self'"],
                "script-src": ["'self'", "{csp.nonce}"],
            },
            "hsts": {
                "enabled": true,
                "max_age": 31536000,
                "include_subdomains": true,
                "preload": true,
            },
            "permissions_policy": {
                "geolocation": false,
                "microphone": ["self", "https://example.com"],
            },
        })
    );
}

#[test]
fn security_headers_combines_with_ordinary_header_operations() {
    let handler = adapted_handler(
        "example.com {\n\theader {\n\t\tsecurity_headers {\n\t\t\tx_frame_options DENY\n\t\t}\n\t\tX-Test ok\n\t}\n}\n",
    );
    assert_eq!(
        handler.get("security_headers"),
        Some(&json!({"x_frame_options": "DENY"}))
    );
    assert_eq!(
        handler
            .pointer("/response/set/X-Test")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1),
        "{handler}"
    );
}

#[test]
fn content_security_policy_accepts_a_header_value_string() {
    let security = adapted_security_headers(
        "\t\t\tcontent_security_policy \"default-src 'self'; script-src 'self' {csp.nonce}\"\n",
    );
    assert_eq!(
        security,
        json!({
            "content_security_policy":
                "default-src 'self'; script-src 'self' {csp.nonce}",
        })
    );
}

#[test]
fn security_headers_errors_are_located_at_the_offending_line() {
    let cases: &[(&str, usize, &str)] = &[
        ("\t\t\tx_frame_options\n", 4, "requires a value"),
        ("\t\t\tx_frame_options DENY extra\n", 4, "exactly one value"),
        ("\t\t\tunknown_option value\n", 4, "unknown `security_headers` option"),
        ("\t\t\thsts {\n\t\t\t\tmax_age soon\n\t\t\t}\n", 5, "non-negative integer"),
        ("\t\t\thsts {\n\t\t\t\tinclude_subdomains extra\n\t\t\t}\n", 5, "flag"),
        (
            "\t\t\tcontent_security_policy {\n\t\t\t\tdefault_src 'self'\n\t\t\t\tdefault-src 'self'\n\t\t\t}\n",
            6,
            "duplicate CSP directive",
        ),
        ("\t\t\tpermissions_policy {\n\t\t\t\tgeolocation\n\t\t\t}\n", 5, "feature=allowlist"),
        ("\t\t\tpermissions_policy {\n\t\t\t\tgeolocation=()\n\t\t\t\tgeolocation=()\n\t\t\t}\n", 6, "duplicate permissions policy feature"),
    ];
    for (block, line, needle) in cases {
        let caddyfile = format!(
            "example.com {{\n\theader {{\n\t\tsecurity_headers {{\n{block}\t\t}}\n\t}}\n}}\n"
        );
        let error = adapt(&caddyfile).expect_err(needle);
        assert!(
            error.to_string().contains(needle),
            "expected `{needle}` in: {error}"
        );
        assert_located(&error.to_string(), *line);
    }
}

#[test]
fn csp_nonce_placeholder_is_emitted_in_the_handler_spelling() {
    let security = adapted_security_headers(
        "\t\t\tcontent_security_policy {\n\t\t\t\tscript_src 'self' 'nonce-{csp.nonce}'\n\t\t\t}\n",
    );
    assert_eq!(
        security.pointer("/content_security_policy/script-src"),
        Some(&json!(["'self'", "{csp.nonce}"])),
        "{security}"
    );
}
