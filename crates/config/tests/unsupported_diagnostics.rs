//! Valid Caddy constructs that this build does not implement must read as *unsupported*, not as
//! a malformed configuration. A genuine typo must still be `config.invalid`.
//!
//! Regression context: `persist_config off` is valid Caddy v2.11.9 (it adapts to
//! `admin.config.persist = false`, tracked as T-CONF-055) but was reported as
//! `unrecognized global option`, which suggests the user's Caddyfile is broken.

use caddy_rs_config::adapt;

fn adapt_error(caddyfile: &str) -> caddy_rs_core::Error {
    adapt(caddyfile).expect_err("expected the adapter to reject this Caddyfile")
}

#[test]
fn persist_config_is_unsupported_with_its_tracking_task() {
    let error = adapt_error("{\n\tpersist_config off\n}\n\n:8080 {\n}\n");
    let message = error.to_string();

    assert_eq!(error.code(), "config.unsupported", "{message}");
    assert!(
        message.contains("global option `persist_config`"),
        "the error must name the option: {message}"
    );
    assert!(
        message.contains("not supported by this build"),
        "the error must say this build lacks the feature: {message}"
    );
    assert!(
        message.contains("tracked as T-CONF-055"),
        "the error must name the tracking task: {message}"
    );
    assert!(
        !message.contains("unrecognized") && !message.contains("unknown global option"),
        "a valid Caddy option must not read as a typo: {message}"
    );
}

#[test]
fn admin_global_option_block_adapts_like_caddy() {
    // The block form is implemented (T-CONF-055): only `persist_config` remains unsupported.
    let adapted = adapt("{\n\tadmin {\n\t\torigins localhost:2019\n\t}\n}\n\n:8080 {\n}\n")
        .expect("admin block adapts");
    assert_eq!(
        adapted.config["admin"],
        serde_json::json!({"listen": "localhost:2019", "origins": ["localhost:2019"]})
    );
}

#[test]
fn recognised_but_unscheduled_global_options_are_still_unsupported() {
    // `default_sni` is a real Caddy global option with no caddy-rs implementation task yet. It
    // must fail as unsupported (no credible tracking id), never as an unknown name.
    let error = adapt_error("{\n\tdefault_sni example.com\n}\n\n:8080 {\n}\n");
    let message = error.to_string();

    assert_eq!(error.code(), "config.unsupported", "{message}");
    assert!(
        message.contains("global option `default_sni`"),
        "the error must name the option: {message}"
    );
    assert!(
        message.contains("not supported by this build"),
        "the error must say this build lacks the feature: {message}"
    );
    assert!(
        !message.contains("unrecognized") && !message.contains("unknown global option"),
        "a valid Caddy option must not read as a typo: {message}"
    );
}

/// Every Caddy v2.11.9 global option outside the implemented subset must read as unsupported.
///
/// The list is the standard Caddy build's registered options
/// (`caddyconfig/httpcaddyfile/options.go` plus `modules/caddyfs` and `modules/caddyevents`)
/// minus the options this build implements (`auto_https`, `admin <address>`, `http_port`,
/// `https_port`, `grace_period`, `shutdown_delay`, `email`, `acme_ca`, `acme_ca_root`,
/// `acme_dns`, `pki`, `local_certs`, `log`, `metrics`, `debug`) and `servers` (handled by the
/// adapter's server-option pre-pass).
#[test]
fn every_recognised_unsupported_global_option_reports_unsupported() {
    const UNSUPPORTED: &[&str] = &[
        "acme_eab",
        "cert_issuer",
        "cert_lifetime",
        "default_bind",
        "default_sni",
        "dns",
        "ech",
        "events",
        "fallback_sni",
        "filesystem",
        "key_type",
        "ocsp_interval",
        "ocsp_stapling",
        "on_demand_tls",
        "order",
        "persist_config",
        "preferred_chains",
        "renew_interval",
        "renewal_window_ratio",
        "skip_install_trust",
        "storage",
        "storage_check",
        "storage_clean_interval",
        "tls_automate_names",
        "tls_resolvers",
    ];

    for option in UNSUPPORTED {
        let caddyfile = format!("{{\n\t{option} example\n}}\n\n:8080 {{\n}}\n");
        let error = adapt_error(&caddyfile);
        let message = error.to_string();

        assert_eq!(error.code(), "config.unsupported", "{option}: {message}");
        assert!(
            message.contains(&format!("global option `{option}`")),
            "{option}: the error must name the option: {message}"
        );
        assert!(
            message.contains("not supported by this build"),
            "{option}: the error must say this build lacks the feature: {message}"
        );
        assert!(
            message.contains("Caddyfile line 2"),
            "{option}: the error must stay located: {message}"
        );
        assert!(
            !message.contains("unknown global option") && !message.contains("unrecognized"),
            "{option}: a valid Caddy option must not read as a typo: {message}"
        );
    }
}

#[test]
fn a_genuinely_unknown_global_option_stays_invalid() {
    let error = adapt_error("{\n\tpersist_configg off\n}\n\n:8080 {\n}\n");
    let message = error.to_string();

    assert_eq!(error.code(), "config.invalid", "{message}");
    assert!(
        message.contains("unknown global option `persist_configg`"),
        "a typo must be reported as unknown: {message}"
    );
}
