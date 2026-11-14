//! The Caddyfile `header { security_headers { ... } }` surface must produce JSON the `headers`
//! handler accepts (T-ROUTE-051).
//!
//! The adapter test in `caddy-rs-config` pins the exact emitted JSON; this test closes the loop by
//! handing that adapted handler object to the real handler constructor, which runs the full CSP /
//! HSTS / permissions-policy validation.

use caddy_rs_config::adapt;
use caddy_rs_http::HeadersHandler;
use serde_json::Value;

fn adapted_headers_handlers(caddyfile: &str) -> Vec<Value> {
    let adapted = adapt(caddyfile).unwrap_or_else(|error| panic!("{caddyfile}\n{error}"));
    let mut found = Vec::new();
    collect(&adapted.config, &mut found);
    found
}

fn collect(value: &Value, found: &mut Vec<Value>) {
    match value {
        Value::Object(object) => {
            if object.get("handler").and_then(Value::as_str) == Some("headers") {
                found.push(Value::Object(object.clone()));
            }
            for child in object.values() {
                collect(child, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect(item, found);
            }
        }
        _ => {}
    }
}

#[test]
fn adapted_security_headers_load_through_the_headers_handler() {
    let caddyfile = "\
example.com {
\theader {
\t\tsecurity_headers {
\t\t\tx_frame_options DENY
\t\t\tx_content_type_options nosniff
\t\t\treferrer_policy strict-origin-when-cross-origin
\t\t\tcontent_security_policy {
\t\t\t\tdefault_src 'self'
\t\t\t\tscript_src 'self' 'nonce-{csp.nonce}'
\t\t\t}
\t\t\thsts {
\t\t\t\tmax_age 31536000
\t\t\t\tinclude_subdomains
\t\t\t\tpreload
\t\t\t}
\t\t\tpermissions_policy {
\t\t\t\tgeolocation=()
\t\t\t\tmicrophone=(self https://example.com)
\t\t\t}
\t\t}
\t}
}
";
    let handlers = adapted_headers_handlers(caddyfile);
    assert_eq!(handlers.len(), 1, "{handlers:?}");
    HeadersHandler::from_json(&handlers[0], "handler")
        .unwrap_or_else(|error| panic!("handler rejected adapted JSON {handlers:?}: {error}"));
}
