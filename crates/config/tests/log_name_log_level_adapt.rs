//! `log_name` / `log_level` Caddyfile adaptation (T-ADMIN-047).
//!
//! The expected JSON strings are the exact `caddy adapt` output of Caddy v2.11.9
//! (`.scratch/oracle-eval-2.11.9/caddy`), captured per case. They are parsed into
//! `serde_json::Value` because caddy-rs serialises JSON objects with sorted keys while Go emits
//! struct field order; the JSON *structure* must be identical, which is what the adapter contract
//! and the upstream golden fixtures compare.

use caddy_rs_config::{adapt_with_options, AdaptMode, AdaptOptions};
use serde_json::{json, Value};

const COMBINED: &str = "example.com {\n\tlog_name foo bar\n\tlog_level WARN\n\trespond \"ok\"\n}\n";
const COMBINED_ORACLE: &str = r#"{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["example.com"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"access_logger_names":["foo","bar"],"handler":"vars"},{"handler":"vars","log_level":"warn"},{"body":"ok","handler":"static_response"}]}]}],"terminal":true}]}}}}}"#;

const NAME_WITHOUT_NAMES: &str = "example.com {\n\tlog_name\n\trespond \"ok\"\n}\n";
const NAME_WITHOUT_NAMES_ORACLE: &str = r#"{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["example.com"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"access_logger_names":null,"handler":"vars"},{"body":"ok","handler":"static_response"}]}]}],"terminal":true}]}}}}}"#;

const NAME_WITH_MATCHER: &str =
    "example.com {\n\t@m path /logged\n\tlog_name @m foo\n\trespond \"ok\"\n}\n";
const NAME_WITH_MATCHER_ORACLE: &str = r#"{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["example.com"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"access_logger_names":["foo"],"handler":"vars"}],"match":[{"path":["/logged"]}]},{"handle":[{"body":"ok","handler":"static_response"}]}]}],"terminal":true}]}}}}}"#;

const NAME_WITH_BLOCK: &str =
    "example.com {\n\tlog_name foo {\n\t\tbar\n\t}\n\trespond \"ok\"\n}\n";

const LEVEL_SORT_PATHS: &str =
    ":80\n\nlog_level /foobar ERROR\nlog_level /foo WARN\nlog_level /foo* DEBUG\nlog_level INFO\n";
const LEVEL_SORT_PATHS_ORACLE: &str = r#"{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"vars","log_level":"info"}]},{"match":[{"path":["/foo*"]}],"handle":[{"handler":"vars","log_level":"debug"}]},{"match":[{"path":["/foo"]}],"handle":[{"handler":"vars","log_level":"warn"}]},{"match":[{"path":["/foobar"]}],"handle":[{"handler":"vars","log_level":"error"}]}]}}}}}"#;

/// Upstream `log_level_sort_named_matchers.caddyfiletest`: two `log_level` directives with the
/// same matcher merge into one route in source order, and non-path matchers keep that order.
const LEVEL_SORT_NAMED_MATCHERS: &str = ":80\n\n@first header X-Test a\n@second header X-Test a\n@third header X-Other b\n\nlog_level @first INFO\nlog_level @second WARN\nlog_level @third ERROR\n";
const LEVEL_SORT_NAMED_MATCHERS_ORACLE: &str = r#"{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[{"match":[{"header":{"X-Test":["a"]}}],"handle":[{"handler":"vars","log_level":"info"},{"handler":"vars","log_level":"warn"}]},{"match":[{"header":{"X-Other":["b"]}}],"handle":[{"handler":"vars","log_level":"error"}]}]}}}}}"#;

fn oracle(raw: &str) -> Value {
    serde_json::from_str(raw).expect("oracle JSON parses")
}

fn adapt_in(caddyfile: &str, mode: AdaptMode) -> caddy_rs_core::AdaptedConfig {
    adapt_with_options(caddyfile, None, AdaptOptions::new(mode))
        .unwrap_or_else(|error| panic!("adapt in {mode} mode: {error}"))
}

#[test]
fn log_name_and_log_level_match_the_v2_11_9_oracle() {
    let adapted = adapt_in(COMBINED, AdaptMode::Compatible);
    assert_eq!(adapted.config, oracle(COMBINED_ORACLE));
    assert!(adapted.warnings.is_empty(), "{:?}", adapted.warnings);
}

#[test]
fn log_name_without_names_emits_caddys_null_variable() {
    // Caddy's `RemainingArgs` returns a nil slice, which serialises as `null`; the runtime treats
    // that as an unset variable and keeps the per-host mapping.
    let adapted = adapt_in(NAME_WITHOUT_NAMES, AdaptMode::Compatible);
    assert_eq!(adapted.config, oracle(NAME_WITHOUT_NAMES_ORACLE));
}

#[test]
fn log_name_with_a_named_matcher_matches_the_v2_11_9_oracle() {
    let adapted = adapt_in(NAME_WITH_MATCHER, AdaptMode::Compatible);
    assert_eq!(adapted.config, oracle(NAME_WITH_MATCHER_ORACLE));
}

#[test]
fn log_name_ignores_a_block_like_caddy() {
    // Caddy's `parseLogName` never calls `NextBlock`, so a block is silently ignored rather than
    // rejected (unlike `log_level` and `log_skip`).
    let adapted = adapt_in(NAME_WITH_BLOCK, AdaptMode::Compatible);
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]
            ["handle"][0],
        json!({"handler": "vars", "access_logger_names": ["foo"]})
    );
}

#[test]
fn log_level_path_routes_sort_least_specific_first_like_caddy() {
    // Caddy swaps i/j for `vars`/`log_level` so the least-specific matcher runs first and the
    // last assignment wins: `/foo*` (DEBUG) then `/foo` (WARN) then `/foobar` (ERROR), with the
    // unmatched `INFO` first.
    let adapted = adapt_in(LEVEL_SORT_PATHS, AdaptMode::Compatible);
    assert_eq!(adapted.config, oracle(LEVEL_SORT_PATHS_ORACLE));
}

#[test]
fn log_level_named_matchers_keep_source_order_like_caddy() {
    let adapted = adapt_in(LEVEL_SORT_NAMED_MATCHERS, AdaptMode::Compatible);
    assert_eq!(adapted.config, oracle(LEVEL_SORT_NAMED_MATCHERS_ORACLE));
}

#[test]
fn log_level_is_accepted_in_every_adapt_mode() {
    for mode in [AdaptMode::Compatible, AdaptMode::Warn, AdaptMode::Strict] {
        let adapted = adapt_in(COMBINED, mode);
        assert_eq!(adapted.config, oracle(COMBINED_ORACLE), "{mode} mode");
    }
}

#[test]
fn log_level_rejects_invalid_names_with_caddys_message() {
    for name in ["INVALID", "verbose", "DPANIC", "FATAL", "infoo"] {
        let caddyfile = format!(":80\n\nlog_level {name}\n");
        let error =
            adapt_with_options(&caddyfile, None, AdaptOptions::default()).expect_err("rejected");
        let message = error.to_string();
        assert_eq!(error.code(), "config.invalid", "{message}");
        assert!(
            message.contains(&format!(
                "invalid log level \"{name}\": expected DEBUG, INFO, WARN, or ERROR"
            )),
            "{message}"
        );
    }
}

#[test]
fn log_level_rejects_missing_or_extra_arguments() {
    for (caddyfile, trailing) in [
        (":80\n\nlog_level\n", "log_level"),
        (":80\n\nlog_level INFO WARN\n", "WARN"),
    ] {
        let error = adapt_with_options(caddyfile, None, AdaptOptions::default())
            .expect_err("argument count rejected");
        let message = error.to_string();
        assert_eq!(error.code(), "config.invalid", "{message}");
        assert!(
            message.contains(&format!(
                "wrong argument count or unexpected line ending after '{trailing}'"
            )),
            "{message}"
        );
    }
}

#[test]
fn log_level_rejects_a_block_with_a_located_error() {
    let error = adapt_with_options(
        ":80\n\nlog_level WARN {\n\tfoo\n}\n",
        None,
        AdaptOptions::default(),
    )
    .expect_err("log_level blocks are rejected");
    let message = error.to_string();
    assert_eq!(error.code(), "config.invalid", "{message}");
    assert!(
        message.contains("log_level directive does not accept blocks"),
        "{message}"
    );
    assert!(message.contains("Caddyfile line 4"), "{message}");
}
