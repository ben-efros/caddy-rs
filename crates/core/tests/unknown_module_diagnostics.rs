//! Unknown-module diagnostics: "did you mean" suggestions and stable error codes (T-CORE-004).
//!
//! Every unknown-module rejection goes through [`caddy_rs_core::ModuleRegistry::unknown_module`], so
//! the suggestion always comes from the registry actually in use (including custom overlays) and
//! can never contradict it. The message keeps Caddy's own shape (`unknown <kind> module \`name\``)
//! and gains a parenthetical hint; the machine-readable code (`module.unknown`) is stable so scripts
//! and editors can match on it instead of on wording.

use serde_json::json;

use caddy_rs_core::{Config, Error, ModuleKind, ModuleRegistry};

fn server_config(handler: &str) -> Config {
    Config::from_value(json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{"handle": [{"handler": handler}]}]
        }}}}
    }))
    .expect("config decodes")
}

fn validate(config: &Config) -> Error {
    caddy_rs_core::validate_config(config, &ModuleRegistry::builtin())
        .expect_err("configuration must be rejected")
}

#[test]
fn close_handler_name_suggests_the_registered_key() {
    let error = validate(&server_config("revers_proxy"));
    let message = error.to_string();
    assert!(
        message.contains("unknown HTTP handler module `revers_proxy`"),
        "message keeps the located unknown-module form: {message}"
    );
    assert!(
        message.contains("(did you mean `reverse_proxy`?)"),
        "a close name must suggest the registered key: {message}"
    );
    assert_eq!(error.code(), "module.unknown");
}

#[test]
fn unrelated_handler_name_has_no_suggestion() {
    let error = validate(&server_config("qqqqqqqqqqqqqqqq"));
    let message = error.to_string();
    assert!(
        !message.contains("did you mean"),
        "an unrelated name must not invent a suggestion: {message}"
    );
    assert_eq!(error.code(), "module.unknown");
}

#[test]
fn qualified_module_id_suggests_the_json_key() {
    // Caddy JSON uses short keys; a fully qualified id is unknown but its last segment is the key.
    let error = validate(&server_config("http.handlers.reverse_proxy"));
    let message = error.to_string();
    assert!(
        message.contains("(did you mean `reverse_proxy`?)"),
        "a qualified id must suggest the short JSON key: {message}"
    );
}

#[test]
fn matcher_key_typo_suggests_the_registered_matcher() {
    let config = Config::from_value(json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "routes": [{
                "match": [{"path_regepx": [".*"]}],
                "handle": [{"handler": "static_response", "body": "ok"}]
            }]
        }}}}
    }))
    .expect("config decodes");
    let error = validate(&config);
    let message = error.to_string();
    assert!(
        message.contains("unknown HTTP matcher module `path_regepx`"),
        "matcher errors keep their located form: {message}"
    );
    assert!(
        message.contains("(did you mean `path_regexp`?)"),
        "matcher typos must suggest the registered matcher: {message}"
    );
}

#[test]
fn suggestions_come_from_the_registry_in_use() {
    // A custom registry must only suggest names it actually knows: the suggestion algorithm takes
    // its candidates from the registry, not from a built-in table.
    let registry = ModuleRegistry::builtin()
        .overlay([caddy_rs_core::Module::owned(
            "http.handlers.magic_proxy",
            "magic_proxy",
            ModuleKind::HttpHandler,
            "test-only handler",
        )])
        .expect("overlay registers");
    let config = server_config("magic_proxi");
    let error = caddy_rs_core::validate_config(&config, &registry).expect_err("unknown handler");
    let message = error.to_string();
    assert!(
        message.contains("(did you mean `magic_proxy`?)"),
        "the overlay's own module must be suggested: {message}"
    );
}

#[test]
fn machine_readable_codes_are_stable_and_distinct() {
    // The codes are part of the diagnostics contract: tooling matches on them, so they must not
    // drift with message wording. One representative per variant, plus a uniqueness check.
    let invalid = Error::invalid("apps.http", "bad");
    let unknown = ModuleRegistry::builtin().unknown_module(ModuleKind::HttpHandler, "nope", "path");
    let unsupported = Error::unsupported("apps.http.x", "feature", "T-X");
    let not_implemented = Error::NotImplemented {
        feature: "feature",
        tracking_id: "T-X",
    };
    let listen = Error::InvalidListen {
        value: ":bad".into(),
        path: "apps.http.servers.srv0.listen[0]".into(),
        reason: "test".into(),
    };
    let cancelled = Error::LifecycleCancelled {
        generation: 1,
        phase: "cleanup",
    };

    assert_eq!(invalid.code(), "config.invalid");
    assert_eq!(unknown.code(), "module.unknown");
    assert_eq!(unsupported.code(), "config.unsupported");
    assert_eq!(not_implemented.code(), "not_implemented");
    assert_eq!(listen.code(), "listen.invalid");
    assert_eq!(cancelled.code(), "lifecycle.cancelled");

    let codes = [
        invalid.code(),
        unknown.code(),
        unsupported.code(),
        not_implemented.code(),
        listen.code(),
        cancelled.code(),
    ];
    let unique: std::collections::BTreeSet<&str> = codes.into_iter().collect();
    assert_eq!(
        unique.len(),
        codes.len(),
        "codes must be distinct: {codes:?}"
    );
    for code in codes {
        assert!(
            !code.is_empty()
                && code
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
            "code `{code}` must be a stable lowercase identifier"
        );
    }
}

#[test]
fn experimental_metrics_config_is_accepted_and_unsupported_options_are_loud() {
    // `apps.http.metrics` is Caddy's experimental opt-in for the `caddy_http_*` families. caddy-rs
    // records those metrics unconditionally, so the plain object is representable and must not be
    // rejected as an unknown HTTP-app field (the Caddyfile adapter emits it verbatim).
    fn validate_app(
        app: serde_json::Value,
    ) -> caddy_rs_core::Result<caddy_rs_core::ValidationReport> {
        let config =
            Config::from_value(json!({"admin": {"disabled": true}, "apps": {"http": app}}))
                .expect("config decodes");
        caddy_rs_core::validate_config(&config, &ModuleRegistry::builtin())
    }

    validate_app(json!({"metrics": {}, "servers": {}})).expect("empty metrics object validates");
    validate_app(json!({"metrics": {"observe_catchall_hosts": true}, "servers": {}}))
        .expect("observe_catchall_hosts without per_host is Caddy's no-op");

    // `per_host` and `otlp` need host labelling / OTLP export that caddy-rs does not have: loud,
    // named, tracked instead of silently ignored.
    for field in ["per_host", "otlp"] {
        let error = validate_app(json!({"metrics": {field: true}, "servers": {}}))
            .expect_err("unsupported metrics option must be rejected");
        let message = error.to_string();
        assert!(
            message.contains(field),
            "error must name `{field}`: {message}"
        );
        assert!(
            message.contains("T-ADMIN-031"),
            "error must name the tracking task: {message}"
        );
        assert_eq!(error.code(), "config.unsupported");
    }

    let error = validate_app(json!({"metrics": {"per_hosts": true}, "servers": {}}))
        .expect_err("unknown metrics field must be rejected");
    assert!(
        error
            .to_string()
            .contains("unknown experimental metrics field(s): per_hosts"),
        "{error}"
    );
}
