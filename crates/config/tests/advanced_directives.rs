//! T-CONF-013 advanced-directive residuals: directives whose Caddyfile shape is known but whose
//! runtime module is not implemented must fail with a located error naming the gap and tracking id.

use caddy_rs_config::adapt;

#[test]
fn acme_server_reports_the_runtime_gap() {
    let error =
        adapt("example.com {\n\tacme_server\n}\n").expect_err("acme_server must fail loudly");
    let message = error.to_string();
    assert!(message.contains("acme_server"), "{message}");
    assert!(message.contains("http.handlers.acme_server"), "{message}");
    assert!(message.contains("T-CONF-013"), "{message}");
}
