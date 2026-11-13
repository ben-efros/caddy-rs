//! T-CONF-013 advanced-directive residuals: directives whose Caddyfile shape is known but whose
//! runtime module is not implemented must fail with a located error naming the gap.
//!
//! `acme_server` was the other residual here; it now adapts faithfully (T-CONF-054 / DIV-0102,
//! covered by `tests/acme_server.rs`). `rate_limit` now adapts as the caddy-rs extension
//! (T-CONF-072 / DIV-0104, covered by `tests/rate_limit.rs`); the community `caddy-ratelimit`
//! plugin's `zone`/`events`/`window` form must still fail loudly.

use caddy_rs_config::adapt;

#[test]
fn rate_limit_community_form_still_fails_loudly() {
    let error = adapt("example.com {\n\trate_limit 10r/s {\n\t\tzone x\n\t}\n}\n")
        .expect_err("the community rate_limit form must fail loudly");
    let message = error.to_string();
    assert!(message.contains("rate_limit"), "{message}");
    assert!(message.contains("zone"), "{message}");
    assert!(message.contains("Caddyfile line "), "{message}");
    assert!(message.contains("DIV-0104"), "{message}");
    assert!(
        message.contains("docs/operations/RATE-LIMITING.md"),
        "{message}"
    );
}
