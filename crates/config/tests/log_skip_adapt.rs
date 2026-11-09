//! `log_skip` Caddyfile adaptation (T-HTTP-050).
//!
//! The expected JSON strings are the exact `caddy adapt` output of Caddy v2.11.9
//! (`.scratch/oracle-eval-2.11.9/caddy`), captured per case. They are parsed into
//! `serde_json::Value` because caddy-rs serialises JSON objects with sorted keys while Go emits
//! struct field order; the JSON *structure* must be identical, which is what the adapter contract
//! and every existing upstream golden test compare.

use caddy_rs_config::{adapt_with_options, AdaptMode, AdaptOptions};
use serde_json::{json, Value};

const BARE: &str = "example.com {\n\tlog_skip\n\trespond \"ok\"\n}\n";
const WITH_MATCHER: &str = "example.com {\n\t@m path /skip\n\tlog_skip @m\n\trespond \"ok\"\n}\n";
const DEPRECATED: &str = "example.com {\n\tskip_log\n\trespond \"ok\"\n}\n";
const WITH_BLOCK: &str = "example.com {\n\tlog_skip {\n\t\tfoo bar\n\t}\n\trespond \"ok\"\n}\n";
const WITH_ARGS: &str = "example.com {\n\tlog_skip extra\n\trespond \"ok\"\n}\n";

/// Exact v2.11.9 oracle output for `log_skip` with no matcher.
const BARE_ORACLE: &str = r#"{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["example.com"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"vars","log_skip":true},{"body":"ok","handler":"static_response"}]}]}],"terminal":true}]}}}}}"#;

/// Exact v2.11.9 oracle output for `log_skip @m`.
const WITH_MATCHER_ORACLE: &str = r#"{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["example.com"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"vars","log_skip":true}],"match":[{"path":["/skip"]}]},{"handle":[{"body":"ok","handler":"static_response"}]}]}],"terminal":true}]}}}}}"#;

fn oracle(raw: &str) -> Value {
    serde_json::from_str(raw).expect("oracle JSON parses")
}

fn adapt_in(caddyfile: &str, mode: AdaptMode) -> caddy_rs_core::AdaptedConfig {
    adapt_with_options(caddyfile, None, AdaptOptions::new(mode))
        .unwrap_or_else(|error| panic!("adapt in {mode} mode: {error}"))
}

#[test]
fn bare_log_skip_matches_the_v2_11_9_oracle() {
    let adapted = adapt_in(BARE, AdaptMode::Compatible);
    assert_eq!(adapted.config, oracle(BARE_ORACLE));
    assert!(adapted.warnings.is_empty(), "{:?}", adapted.warnings);
}

#[test]
fn log_skip_with_a_named_matcher_matches_the_v2_11_9_oracle() {
    let adapted = adapt_in(WITH_MATCHER, AdaptMode::Compatible);
    assert_eq!(adapted.config, oracle(WITH_MATCHER_ORACLE));
    assert!(adapted.warnings.is_empty(), "{:?}", adapted.warnings);
}

#[test]
fn deprecated_skip_log_adapts_to_the_same_json_as_log_skip() {
    for mode in [AdaptMode::Compatible, AdaptMode::Warn] {
        let adapted = adapt_in(DEPRECATED, mode);
        assert_eq!(
            adapted.config,
            oracle(BARE_ORACLE),
            "skip_log must adapt exactly like log_skip in {mode} mode"
        );
    }
}

#[test]
fn log_skip_rejects_a_block_with_a_located_error() {
    let error = adapt_with_options(WITH_BLOCK, None, AdaptOptions::default())
        .expect_err("log_skip blocks are rejected");
    let message = error.to_string();
    assert_eq!(error.code(), "config.invalid", "{message}");
    assert!(
        message.contains("log_skip directive does not accept blocks"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 3"), "{message}");
}

#[test]
fn log_skip_rejects_arguments_with_a_located_error() {
    let error = adapt_with_options(WITH_ARGS, None, AdaptOptions::default())
        .expect_err("log_skip arguments are rejected");
    let message = error.to_string();
    assert_eq!(error.code(), "config.invalid", "{message}");
    assert!(message.contains("takes no arguments"), "{message}");
    assert!(message.contains("Caddyfile line 2"), "{message}");
}

#[test]
fn log_skip_is_valid_in_every_adapt_mode() {
    for mode in [AdaptMode::Compatible, AdaptMode::Warn, AdaptMode::Strict] {
        let adapted = adapt_in(BARE, mode);
        assert_eq!(adapted.config, oracle(BARE_ORACLE), "{mode} mode");
        assert!(
            adapted.warnings.is_empty(),
            "{mode}: {:?}",
            adapted.warnings
        );
    }
}

#[test]
fn skip_log_warns_in_compatible_mode_like_caddy() {
    let adapted = adapt_in(DEPRECATED, AdaptMode::Compatible);
    assert_eq!(
        adapted.warnings,
        vec!["the 'skip_log' directive is deprecated, please use 'log_skip' instead!".to_string()]
    );
}

#[test]
fn skip_log_warns_in_warn_mode() {
    let adapted = adapt_in(DEPRECATED, AdaptMode::Warn);
    assert_eq!(
        adapted.warnings,
        vec!["the 'skip_log' directive is deprecated, please use 'log_skip' instead!".to_string()]
    );
}

#[test]
fn skip_log_is_rejected_in_strict_mode_with_a_located_error() {
    let error = adapt_with_options(DEPRECATED, None, AdaptOptions::new(AdaptMode::Strict))
        .expect_err("strict mode rejects the deprecated alias");
    let message = error.to_string();
    assert_eq!(error.code(), "config.invalid", "{message}");
    assert!(
        message.contains("`skip_log` is a deprecated alias for `log_skip`"),
        "{message}"
    );
    assert!(
        message.contains("strict mode rejects backward-compatibility aliases"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 2"), "{message}");
}

#[test]
fn basicauth_is_the_second_table_entry_and_is_mode_gated() {
    let caddyfile = "example.com {\n\tbasicauth {\n\t\talice $2a$14$01234567890123456789012345678901234567890123456789012\n\t}\n\trespond \"ok\"\n}\n";

    // Compatible (Caddy's default): accepted with Caddy's deprecation warning.
    let compatible = adapt_in(caddyfile, AdaptMode::Compatible);
    assert_eq!(
        compatible.warnings,
        vec![
            "the 'basicauth' directive is deprecated, please use 'basic_auth' instead!".to_string()
        ]
    );

    // Warn: accepted with the same deprecation warning naming both spellings.
    let warn = adapt_in(caddyfile, AdaptMode::Warn);
    assert_eq!(
        warn.warnings,
        vec![
            "the 'basicauth' directive is deprecated, please use 'basic_auth' instead!".to_string()
        ]
    );

    // Strict: rejected, proving the mechanism is a table rather than a `skip_log` special case.
    let error = adapt_with_options(caddyfile, None, AdaptOptions::new(AdaptMode::Strict))
        .expect_err("strict mode rejects the deprecated alias");
    let message = error.to_string();
    assert_eq!(error.code(), "config.invalid", "{message}");
    assert!(
        message.contains("`basicauth` is a deprecated alias for `basic_auth`"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 2"), "{message}");
}

#[test]
fn deprecated_alias_inside_a_route_block_is_also_mode_gated() {
    // The check walks nested directive blocks, so aliases in `route`/`handle` bodies are covered.
    let caddyfile = "example.com {\n\troute {\n\t\tskip_log\n\t\trespond \"ok\"\n\t}\n}\n";
    let compatible = adapt_in(caddyfile, AdaptMode::Compatible);
    assert_eq!(compatible.warnings.len(), 1, "{:?}", compatible.warnings);
    let warn = adapt_in(caddyfile, AdaptMode::Warn);
    assert_eq!(warn.warnings.len(), 1, "{:?}", warn.warnings);
    let error = adapt_with_options(caddyfile, None, AdaptOptions::new(AdaptMode::Strict))
        .expect_err("strict mode rejects nested aliases");
    assert!(error.to_string().contains("Caddyfile line 3"), "{error}");
}

/// Extract the first handler of the consolidated `vars` + `respond` route.
fn first_handler(config: &Value) -> &Value {
    &config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]["handle"][0]
}

#[test]
fn skip_log_inside_handle_response_is_mode_gated() {
    // `handle_response` bodies are parsed as subroutes, so aliases there are real directives and
    // Caddy warns for them. They sit under `reverse_proxy`, which the scan must enter.
    let caddyfile = "example.com {\n\treverse_proxy localhost:9000 {\n\t\thandle_response {\n\t\t\tskip_log\n\t\t}\n\t}\n}\n";
    let warning =
        "the 'skip_log' directive is deprecated, please use 'log_skip' instead!".to_string();

    let compatible = adapt_in(caddyfile, AdaptMode::Compatible);
    assert_eq!(compatible.warnings, vec![warning.clone()]);
    assert!(
        compatible.config.to_string().contains("\"log_skip\":true"),
        "{}",
        compatible.config
    );

    let warn = adapt_in(caddyfile, AdaptMode::Warn);
    assert_eq!(warn.warnings, vec![warning]);

    let error = adapt_with_options(caddyfile, None, AdaptOptions::new(AdaptMode::Strict))
        .expect_err("strict mode rejects an alias inside handle_response");
    let message = error.to_string();
    assert_eq!(error.code(), "config.invalid", "{message}");
    assert!(
        message.contains("deprecated alias for `log_skip`"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 4"), "{message}");
}

#[test]
fn skip_log_inside_forward_auth_handle_response_is_mode_gated() {
    let caddyfile = "example.com {\n\tforward_auth localhost:9000 {\n\t\turi /auth\n\t\thandle_response {\n\t\t\tskip_log\n\t\t}\n\t}\n}\n";
    let warning =
        "the 'skip_log' directive is deprecated, please use 'log_skip' instead!".to_string();
    assert_eq!(
        adapt_in(caddyfile, AdaptMode::Compatible).warnings,
        vec![warning.clone()]
    );
    assert_eq!(adapt_in(caddyfile, AdaptMode::Warn).warnings, vec![warning]);
    let error = adapt_with_options(caddyfile, None, AdaptOptions::new(AdaptMode::Strict))
        .expect_err("strict mode rejects an alias inside forward_auth handle_response");
    assert!(error.to_string().contains("Caddyfile line 5"), "{error}");
}

#[test]
fn basicauth_inside_handle_response_is_mode_gated() {
    let caddyfile = "example.com {\n\treverse_proxy localhost:9000 {\n\t\thandle_response {\n\t\t\tbasicauth {\n\t\t\t\talice $2a$14$01234567890123456789012345678901234567890123456789012\n\t\t\t}\n\t\t}\n\t}\n}\n";
    let warning =
        "the 'basicauth' directive is deprecated, please use 'basic_auth' instead!".to_string();
    assert_eq!(
        adapt_in(caddyfile, AdaptMode::Compatible).warnings,
        vec![warning.clone()]
    );
    assert_eq!(adapt_in(caddyfile, AdaptMode::Warn).warnings, vec![warning]);
    let error = adapt_with_options(caddyfile, None, AdaptOptions::new(AdaptMode::Strict))
        .expect_err("strict mode rejects basicauth inside handle_response");
    let message = error.to_string();
    assert!(
        message.contains("deprecated alias for `basic_auth`"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 4"), "{message}");
}

#[test]
fn non_alias_handle_response_body_is_untouched() {
    let caddyfile = "example.com {\n\treverse_proxy localhost:9000 {\n\t\thandle_response {\n\t\t\trespond \"upstream failed\" 502\n\t\t}\n\t}\n}\n";
    let compatible = adapt_in(caddyfile, AdaptMode::Compatible);
    assert!(compatible.warnings.is_empty(), "{:?}", compatible.warnings);
    let warn = adapt_in(caddyfile, AdaptMode::Warn);
    assert_eq!(warn.config, compatible.config);
    assert!(warn.warnings.is_empty(), "{:?}", warn.warnings);
    let strict = adapt_in(caddyfile, AdaptMode::Strict);
    assert_eq!(strict.config, compatible.config);
}

#[test]
fn vars_scalar_values_follow_caddys_scalar_conversion() {
    // Caddy's `Dispenser.ScalarVal`: quoted tokens stay strings; unquoted tokens use Go's
    // `strconv.ParseBool` spellings (so `TRUE`/`t` are booleans, `yes` is a string).
    for (token, expected) in [
        ("\"true\"", json!("true")),
        ("\"TRUE\"", json!("TRUE")),
        ("TRUE", json!(true)),
        ("t", json!(true)),
        ("yes", json!("yes")),
        // `vars` has no `-`-means-null sentinel (that is a `map` output rule).
        ("-", json!("-")),
        ("\"-\"", json!("-")),
    ] {
        let caddyfile = format!("example.com {{\n\tvars log_skip {token}\n\trespond \"ok\"\n}}\n");
        let adapted = adapt_in(&caddyfile, AdaptMode::Compatible);
        assert_eq!(
            first_handler(&adapted.config),
            &json!({"handler": "vars", "log_skip": expected}),
            "token `{token}`"
        );
    }
}

#[test]
fn vars_block_values_preserve_quoting() {
    let caddyfile =
        "example.com {\n\tvars {\n\t\tlog_skip \"true\"\n\t\tflag t\n\t}\n\trespond \"ok\"\n}\n";
    let adapted = adapt_in(caddyfile, AdaptMode::Compatible);
    assert_eq!(
        first_handler(&adapted.config),
        &json!({"handler": "vars", "log_skip": "true", "flag": true})
    );
}

#[test]
fn alias_spelling_as_an_option_value_is_not_a_directive() {
    // `vars { skip_log hello }` sets a variable named `skip_log`; it is not the deprecated
    // directive, so even strict mode must accept it (the scan only descends into directive lists).
    let caddyfile = "example.com {\n\tvars {\n\t\tskip_log hello\n\t}\n\trespond \"ok\"\n}\n";
    for mode in [AdaptMode::Compatible, AdaptMode::Warn, AdaptMode::Strict] {
        let adapted = adapt_in(caddyfile, mode);
        assert!(
            adapted.warnings.is_empty(),
            "{mode}: {:?}",
            adapted.warnings
        );
    }
}

#[test]
fn unknown_adapt_mode_is_rejected_with_the_three_names() {
    let error = AdaptMode::parse("reckless").expect_err("unknown modes are rejected");
    assert!(error.contains("compatible"), "{error}");
    assert!(error.contains("warn"), "{error}");
    assert!(error.contains("strict"), "{error}");
    assert!(error.contains("reckless"), "{error}");
    assert_eq!("warn".parse::<AdaptMode>(), Ok(AdaptMode::Warn));
}

#[test]
fn emitted_log_skip_handler_has_no_log_skip_module() {
    // The adapted JSON is a generic `vars` handler, exactly like Caddy; there is no
    // `http.handlers.log_skip` module in the registry.
    let adapted = adapt_in(BARE, AdaptMode::Compatible);
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]
        ["routes"][0]["handle"][0];
    assert_eq!(handler, &json!({"handler": "vars", "log_skip": true}));
}
