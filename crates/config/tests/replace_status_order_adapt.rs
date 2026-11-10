//! Caddy's two-phase ordering for `replace_status` and `handle_response`.
//!
//! In `modules/caddyhttp/reverseproxy/caddyfile.go`, `replace_status` is appended to
//! `Handler.HandleResponse` immediately while `UnmarshalCaddyfile` walks the block, whereas
//! `handle_response` segments are only recorded (`handleResponseSegments`) and appended in
//! `FinalizeUnmarshalCaddyfile`. The finalize step then moves entries without a response matcher
//! to the end, stably within each group. Interleaved declarations therefore adapt as
//! "all `replace_status`, then all `handle_response`", not in declaration order.
//!
//! `forward_auth` (`forwardauth/caddyfile.go`) seeds the canonical 2xx handler before calling the
//! reverse-proxy unmarshaler, so it stays first; the user's `replace_status`/`handle_response`
//! entries follow the same phase order.
//!
//! The exact adapted JSON lives in `fixtures/local/*replace_status*.json`; these tests name the
//! ordering rule so a regression points at the phase split rather than at a JSON diff.

use caddy_rs_config::adapt;
use serde_json::Value;

fn entries(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/tests/fixtures/local/{name}.caddyfile",
        env!("CARGO_MANIFEST_DIR")
    );
    let caddyfile = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let adapted = adapt(&caddyfile).unwrap_or_else(|e| panic!("adapt {name}: {e}"));
    adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["handle_response"]
        .as_array()
        .unwrap_or_else(|| panic!("{name} has no handle_response array"))
        .clone()
}

/// `replace_status` entries only carry `status_code`; `handle_response` entries always carry
/// parsed `routes`.
fn kinds(entries: &[Value]) -> Vec<&'static str> {
    entries
        .iter()
        .map(|entry| {
            if entry.get("routes").is_some() {
                "handle_response"
            } else {
                "replace_status"
            }
        })
        .collect()
}

fn body(entry: &Value) -> Option<&str> {
    entry
        .get("routes")?
        .as_array()?
        .first()?
        .get("handle")?
        .as_array()?
        .first()?
        .get("body")?
        .as_str()
}

#[test]
fn matcher_less_replace_status_precedes_handle_response_in_both_orders() {
    let entries = entries("reverse_proxy_replace_status_interleaved_plain");
    assert_eq!(
        kinds(&entries),
        [
            "replace_status",
            "replace_status",
            "handle_response",
            "handle_response"
        ],
        "declaration order is handle_response, replace_status, handle_response, replace_status"
    );
    assert_eq!(entries[0]["status_code"], 404);
    assert_eq!(entries[1]["status_code"], 500);
    assert_eq!(body(&entries[2]), Some("first"));
    assert_eq!(body(&entries[3]), Some("second"));
}

#[test]
fn response_matchers_do_not_break_the_phase_order() {
    let entries = entries("reverse_proxy_replace_status_interleaved_matchers");
    assert_eq!(
        kinds(&entries),
        [
            "replace_status",
            "replace_status",
            "handle_response",
            "handle_response"
        ]
    );
    assert_eq!(entries[0]["status_code"], 400);
    assert_eq!(entries[1]["status_code"], 401);
    assert_eq!(body(&entries[2]), Some("with matcher"));
    assert_eq!(body(&entries[3]), Some("with matcher 2"));
    for entry in &entries {
        assert_eq!(
            entry["match"],
            serde_json::json!({"status_code": [500]}),
            "every entry keeps its response matcher"
        );
    }
}

#[test]
fn matcher_less_entries_move_last_after_the_phase_order() {
    let entries = entries("reverse_proxy_replace_status_interleaved_mixed");
    assert_eq!(
        kinds(&entries),
        [
            "replace_status",
            "handle_response",
            "replace_status",
            "handle_response"
        ]
    );
    assert_eq!(entries[0]["status_code"], 503);
    assert!(entries[0].get("match").is_some());
    assert_eq!(body(&entries[1]), Some("matched"));
    assert!(entries[1].get("match").is_some());
    assert_eq!(entries[2]["status_code"], 502);
    assert!(entries[2].get("match").is_none());
    assert_eq!(body(&entries[3]), Some("plain"));
    assert!(entries[3].get("match").is_none());
}

#[test]
fn non_interleaved_replace_status_order_is_unchanged() {
    // Regression: a block that already declares every replace_status before every
    // handle_response keeps its previous order.
    let entries = entries("reverse_proxy_replace_status_noninterleaved");
    assert_eq!(
        kinds(&entries),
        [
            "replace_status",
            "handle_response",
            "replace_status",
            "handle_response"
        ]
    );
    assert_eq!(entries[0]["status_code"], 400);
    assert_eq!(body(&entries[1]), Some("matched"));
    assert_eq!(entries[2]["status_code"], 502);
    assert_eq!(body(&entries[3]), Some("plain"));
}

#[test]
fn forward_auth_canonical_handler_stays_first_and_phase_order_follows() {
    let entries = entries("forward_auth_replace_status_interleaved");
    assert_eq!(
        kinds(&entries),
        [
            "handle_response",
            "handle_response",
            "replace_status",
            "handle_response"
        ],
        "canonical 2xx, user @good handler, replace_status 403, matcher-less handler"
    );
    assert_eq!(entries[0]["match"], serde_json::json!({"status_code": [2]}));
    assert_eq!(
        entries[0]["routes"],
        serde_json::json!([{"handle": [{"handler": "vars"}]}])
    );
    assert_eq!(entries[1]["match"], serde_json::json!({"status_code": [2]}));
    assert_eq!(body(&entries[1]), Some("ok"));
    assert_eq!(entries[2]["status_code"], 403);
    assert_eq!(body(&entries[3]), Some("denied"));
}
