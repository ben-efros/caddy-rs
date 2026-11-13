//! Caddyfile `rate_limit` directive adaptation (T-CONF-072, DIV-0104, ADR-0011).
//!
//! `rate_limit <rate> [burst] { burst | key | max_keys | status_code | headers | body }` is a
//! caddy-rs-only directive that maps 1:1 onto the `http.handlers.rate_limit` handler fields, so
//! the `(caddy-rs-ratelimit)` snippet from ADR-0011 §3 adapts to the same JSON a hand-written
//! configuration contains. The community caddy-ratelimit plugin's `zone`/`events`/`window` form is
//! not accepted, translated or emulated: it is a located error naming the extension, `DIV-0104`
//! and the operator page (`docs/operations/RATE-LIMITING.md`, planned `T-OPS-036`).

use caddy_rs_config::adapt;
use serde_json::{json, Value};

/// The `(caddy-rs-ratelimit)` snippet from ADR-0011 §3, verbatim.
const ADR_SNIPPET: &str = "(caddy-rs-ratelimit) {\n\trate_limit 100r/s {\n\t\tburst 200\n\t\tmax_keys 10000\n\t}\n}\n\nexample.com {\n\timport caddy-rs-ratelimit\n\treverse_proxy 127.0.0.1:8080\n}\n";

/// Collect every handler object with `"handler": "rate_limit"` in document order.
fn collect_handlers(value: &Value, handlers: &mut Vec<Value>) {
    match value {
        Value::Object(object) => {
            if object.get("handler").and_then(Value::as_str) == Some("rate_limit") {
                handlers.push(Value::Object(object.clone()));
            }
            for child in object.values() {
                collect_handlers(child, handlers);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_handlers(item, handlers);
            }
        }
        _ => {}
    }
}

/// The single `rate_limit` handler emitted for `caddyfile`.
fn adapted_handler(caddyfile: &str) -> Value {
    let adapted = adapt(caddyfile).unwrap_or_else(|error| panic!("{caddyfile}\n{error}"));
    let mut handlers = Vec::new();
    collect_handlers(&adapted.config, &mut handlers);
    assert_eq!(
        handlers.len(),
        1,
        "expected exactly one rate_limit handler in {}",
        adapted.config
    );
    handlers.pop().expect("one handler")
}

/// Adapt a site block containing exactly one `rate_limit` directive.
fn adapt_directive(directive: &str) -> Value {
    adapted_handler(&format!("example.com {{\n\t{directive}\n}}\n"))
}

/// The `rate_limit` directive is a located error: directive-level diagnostics point at line 2, and
/// block-option diagnostics at the option's own line.
fn assert_located(message: &str) {
    assert!(message.contains("Caddyfile line "), "{message}");
}

#[test]
fn adr_snippet_adapts_to_the_hand_written_handler_json() {
    let handler = adapted_handler(ADR_SNIPPET);
    assert_eq!(
        handler,
        json!({
            "handler": "rate_limit",
            "rate": "100r/s",
            "burst": 200,
            "max_keys": 10000,
        }),
        "the ADR-0011 snippet must adapt to the documented JSON, not an approximation"
    );
    // The limiter is a non-terminal middleware: the site's reverse_proxy route is still emitted.
    let adapted = adapt(ADR_SNIPPET).expect("snippet adapts");
    assert!(
        adapted.config.to_string().contains("\"reverse_proxy\""),
        "{}",
        adapted.config
    );
    // Everything the handler does not receive is left to its own documented default.
    for absent in ["key", "status_code", "headers", "body"] {
        assert!(
            handler.get(absent).is_none(),
            "`{absent}` must be omitted so the handler default applies: {handler}"
        );
    }
}

#[test]
fn every_option_maps_one_to_one_to_a_handler_field() {
    let handler = adapt_directive(
        "rate_limit 10r/s 20 {\n\tkey \"{http.request.header.X-Api-Key}\"\n\tmax_keys 500\n\t\
         status_code 503\n\theaders {\n\t\tX-RateLimit-Realm default\n\t\tRetry-After 1\n\t}\n\t\
         body \"slow down\"\n}",
    );
    assert_eq!(
        handler,
        json!({
            "handler": "rate_limit",
            "rate": "10r/s",
            "burst": 20,
            "key": "{http.request.header.X-Api-Key}",
            "max_keys": 500,
            "status_code": 503,
            "headers": {"X-RateLimit-Realm": "default", "Retry-After": "1"},
            "body": "slow down",
        })
    );
}

#[test]
fn omitted_options_are_omitted_so_the_handler_defaults_apply() {
    let handler = adapt_directive("rate_limit 10r/s");
    assert_eq!(handler, json!({"handler": "rate_limit", "rate": "10r/s"}));
    // The handler's JSON defaults are burst = ceil(rate) (10), key =
    // {http.request.remote.host}, max_keys = 10000, status_code = 429, no extra headers, empty
    // body; the adapter must not invent a different default.
    assert_eq!(handler.as_object().expect("object").len(), 2);
}

#[test]
fn burst_is_accepted_as_either_exactly_one_form() {
    let argument = adapt_directive("rate_limit 10r/s 20");
    assert_eq!(argument["burst"], json!(20));
    let option = adapt_directive("rate_limit 10r/s {\n\tburst 20\n}");
    assert_eq!(option["burst"], json!(20));
    assert_eq!(argument, option);
}

/// Adapt a site block containing one `rate_limit` directive and return the error message.
fn rejection(directive: &str) -> String {
    match adapt(&format!("example.com {{\n\t{directive}\n}}\n")) {
        Ok(adapted) => panic!("{directive:?} adapted unexpectedly: {}", adapted.config),
        Err(error) => error.to_string(),
    }
}

#[test]
fn specifying_burst_both_ways_is_a_located_error() {
    let message = rejection("rate_limit 10r/s 20 {\n\t\tburst 20\n\t}");
    assert!(message.contains("rate_limit"), "{message}");
    assert!(message.contains("exactly one form"), "{message}");
    assert!(message.contains("Caddyfile line 2"), "{message}");
    assert!(message.contains("DIV-0104"), "{message}");
    assert!(
        message.contains("docs/operations/RATE-LIMITING.md"),
        "{message}"
    );
}

#[test]
fn malformed_directives_are_located_errors_naming_the_extension_and_page() {
    for directive in [
        // Missing / invalid rate argument.
        "rate_limit",
        "rate_limit 10",
        "rate_limit 10x",
        "rate_limit 0r/s",
        "rate_limit xr/s",
        "rate_limit 10r/x",
        // Invalid burst argument.
        "rate_limit 10r/s 0",
        "rate_limit 10r/s abc",
        "rate_limit 10r/s 20 30",
        // Invalid block option values.
        "rate_limit 10r/s {\n\t\tburst 0\n\t}",
        "rate_limit 10r/s {\n\t\tkey\n\t}",
        "rate_limit 10r/s {\n\t\tkey a b\n\t}",
        "rate_limit 10r/s {\n\t\tmax_keys 0\n\t}",
        "rate_limit 10r/s {\n\t\tmax_keys nope\n\t}",
        "rate_limit 10r/s {\n\t\tstatus_code 200\n\t}",
        "rate_limit 10r/s {\n\t\tstatus_code nope\n\t}",
        "rate_limit 10r/s {\n\t\theaders default\n\t}",
        "rate_limit 10r/s {\n\t\theaders {\n\t\t\tX-Realm\n\t\t}\n\t}",
        "rate_limit 10r/s {\n\t\tburst 10\n\t\tburst 20\n\t}",
    ] {
        let message = rejection(directive);
        assert!(message.contains("rate_limit"), "{directive:?}: {message}");
        assert_located(&message);
        assert!(message.contains("DIV-0104"), "{directive:?}: {message}");
        assert!(
            message.contains("docs/operations/RATE-LIMITING.md"),
            "{directive:?}: {message}"
        );
    }
}

#[test]
fn community_zone_events_window_form_is_rejected_not_translated() {
    for (directive, option) in [
        ("rate_limit 10r/s {\n\t\tzone x\n\t}", "zone"),
        ("rate_limit 10r/s {\n\t\tevents 100\n\t}", "events"),
        ("rate_limit 10r/s {\n\t\twindow 1s\n\t}", "window"),
    ] {
        let message = rejection(directive);
        assert!(message.contains("caddy-ratelimit"), "{message}");
        assert!(message.contains(option), "{message}");
        assert!(
            message.contains("does not accept, translate or emulate"),
            "{message}"
        );
        assert_located(&message);
        assert!(message.contains("DIV-0104"), "{message}");
        assert!(
            message.contains("docs/operations/RATE-LIMITING.md"),
            "{message}"
        );
    }
}

#[test]
fn unknown_options_are_rejected_with_the_supported_list() {
    let message = rejection("rate_limit 10r/s {\n\t\tbogus 1\n\t}");
    assert!(
        message.contains("unknown `rate_limit` option `bogus`"),
        "{message}"
    );
    assert!(
        message.contains("burst, key, max_keys, status_code, headers, body"),
        "{message}"
    );
    assert_located(&message);
    assert!(message.contains("DIV-0104"), "{message}");
    assert!(
        message.contains("docs/operations/RATE-LIMITING.md"),
        "{message}"
    );
}

#[test]
fn the_directive_is_identical_in_both_stock_compat_modes() {
    let directive = "rate_limit 100r/s {\n\t\tburst 200\n\t\tmax_keys 10000\n\t}";
    let plain = adapt_directive(directive);
    let stock = adapted_handler(&format!(
        "{{\n\tstock_compat true\n}}\nexample.com {{\n\t{directive}\n}}\n"
    ));
    // ADR-0011 §5: rate limiting is an explicitly configured extension, not a stock Caddy feature,
    // so `stock_compat` neither enables nor disables it and the adapted handler is identical.
    assert_eq!(plain, stock);
    assert_eq!(plain["handler"], json!("rate_limit"));
}

#[test]
fn the_emitted_object_has_only_handler_fields() {
    // The adapter emits the handler object itself (inside `handle`), the same shape a hand-written
    // JSON configuration uses, with no adapter-only fields.
    let handler = adapt_directive("rate_limit 10r/s");
    assert_eq!(
        handler
            .as_object()
            .expect("object")
            .keys()
            .collect::<Vec<_>>(),
        vec!["handler", "rate"]
    );
}
