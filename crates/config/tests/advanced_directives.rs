//! T-CONF-013 advanced-directive residuals: directives whose Caddyfile shape is known but whose
//! runtime module is not implemented must fail with a located error naming the gap.
//!
//! `acme_server` was the other residual here; it now adapts faithfully (T-CONF-054 / DIV-0102,
//! covered by `tests/acme_server.rs`). `rate_limit` remains runtime-unsupported.

use caddy_rs_config::adapt;

#[test]
fn rate_limit_reports_the_runtime_gap() {
    let error = adapt("example.com {\n\trate_limit {\n\t\tzone x\n\t}\n}\n")
        .expect_err("rate_limit must fail loudly");
    let message = error.to_string();
    assert!(message.contains("rate_limit"), "{message}");
    assert!(message.contains("not supported by this build"), "{message}");
    assert!(message.contains("Caddyfile line 2"), "{message}");
}
