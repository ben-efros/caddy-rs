//! Caddyfile `log`/observability adaptation (T-CONF-012).
//!
//! The adapter emits Caddy's exact `logging` app and server `logs` JSON for the subset the runtime
//! access-log sink can back: `output stdout|stderr|discard|file <filename>`, `format json|console`,
//! `level`, `hostnames`, `no_hostname`, `sampling`, and global `include`/`exclude`; the global
//! `metrics { ... }` option maps to `apps.http.metrics`. Everything else fails loudly with a located
//! error naming the construct and its tracking id.

use caddy_rs_config::adapt;
use serde_json::{json, Value};

fn validate(config: &Value) -> Result<(), String> {
    let registry = caddy_rs_core::ModuleRegistry::builtin();
    let config =
        caddy_rs_core::Config::from_value(config.clone()).map_err(|error| error.to_string())?;
    caddy_rs_core::validate_config(&config, &registry).map_err(|error| error.to_string())?;
    Ok(())
}

#[test]
fn site_log_options_emit_server_logs_and_logging_app() {
    let adapted = adapt(
        "example.com {\n\tlog {\n\t\toutput file /var/log/access.log\n\t\tformat json\n\t\tlevel INFO\n\t\thostnames foo.example.com\n\t}\n\trespond \"ok\"\n}\n",
    )
    .expect("adapts");
    // Top-level logging app (Caddy config.Logging, not apps.logging).
    assert_eq!(
        adapted.config["logging"]["logs"],
        json!({
            "default": {"exclude": ["http.log.access.log0"]},
            "log0": {
                "writer": {"output": "file", "filename": "/var/log/access.log"},
                "encoder": {"format": "json"},
                "level": "INFO",
                "include": ["http.log.access.log0"],
            },
        })
    );
    // Server association.
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["logs"],
        json!({"logger_names": {"foo.example.com": ["log0"]}})
    );
    validate(&adapted.config).expect("adapted log config validates");
}

#[test]
fn global_only_log_caddyfile_emits_logging_without_apps() {
    // Caddy accepts a Caddyfile with only global options; a global `log` block is a complete config.
    let adapted = adapt("{\n\tlog {\n\t\toutput file foo.log\n\t}\n}\n").expect("adapts");
    assert_eq!(
        adapted.config,
        json!({"logging": {"logs": {"default": {"writer": {"output": "file", "filename": "foo.log"}}}}})
    );
    validate(&adapted.config).expect("logging-only config validates");
}

#[test]
fn debug_global_option_sets_the_default_log_level() {
    let adapted = adapt("{\n\tdebug\n}\n").expect("debug-only Caddyfile adapts");
    assert_eq!(
        adapted.config,
        json!({"logging": {"logs": {"default": {"level": "DEBUG"}}}})
    );
    validate(&adapted.config).expect("debug logging config validates");

    // With a custom log that has no explicit level, debug raises it; no implicit default is added
    // when the default logger is already customized.
    let adapted = adapt("{\n\tdebug\n\tlog custom {\n\t\toutput stdout\n\t}\n}\n").expect("adapts");
    assert_eq!(
        adapted.config["logging"]["logs"],
        json!({
            "default": {"level": "DEBUG"},
            "custom": {"writer": {"output": "stdout"}, "level": "DEBUG"},
        })
    );
}

#[test]
fn site_log_sampling_and_plain_log_mapping() {
    let adapted = adapt(
        r#"example.com {
	log {
		sampling {
			interval 5m
			first 50
			thereafter 40
		}
	}
}
"#,
    )
    .expect("adapts");
    assert_eq!(
        adapted.config["logging"]["logs"],
        json!({
            "default": {"exclude": ["http.log.access.log0"]},
            "log0": {
                "sampling": {"interval": 300_000_000_000_i64, "first": 50, "thereafter": 40},
                "include": ["http.log.access.log0"],
            },
        })
    );
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["logs"],
        json!({"logger_names": {"example.com": ["log0"]}})
    );
    validate(&adapted.config).expect("sampled log config validates");
}

#[test]
fn global_metrics_option_maps_to_apps_http_metrics() {
    let adapted = adapt(
        "{\n\tmetrics {\n\t\tper_host\n\t\tobserve_catchall_hosts\n\t\totlp\n\t}\n}\n:80 {\n\trespond \"ok\"\n}\n",
    )
    .expect("adapts");
    assert_eq!(
        adapted.config["apps"]["http"]["metrics"],
        json!({"per_host": true, "observe_catchall_hosts": true, "otlp": true})
    );
    // NOTE: core's HttpApp model does not have a `metrics` field yet (T-ADMIN-031), so validation
    // rejects it as an unknown HTTP app field; the adapter deliberately emits Caddy's exact JSON
    // rather than silently dropping it. This test records the emission, not validation.
}

#[test]
fn metrics_without_sites_produces_the_empty_config_like_caddy() {
    let adapted = adapt("{\n\tmetrics {\n\t\totlp\n\t}\n}\n").expect("adapts");
    assert_eq!(adapted.config, json!({}));
}

#[test]
fn unsupported_log_options_are_located_errors() {
    for (caddyfile, expected) in [
        (
            "{ log {\n\tformat filter {\n\t\twrap json\n\t}\n} }\n:80 {\n}\n",
            "log encoder `filter`",
        ),
        (
            "{ log {\n\tformat append {\n\t\twrap json\n\t}\n} }\n:80 {\n}\n",
            "log encoder `append`",
        ),
        (
            ":80 {\n\tlog {\n\t\toutput net localhost:9999\n\t}\n}\n",
            "log writer `net`",
        ),
        (
            ":80 {\n\tlog {\n\t\toutput file /x.log {\n\t\t\troll_keep 3\n\t\t}\n\t}\n}\n",
            "file writer option `roll_keep`",
        ),
        (
            ":80 {\n\tlog {\n\t\tcore mock\n\t}\n}\n",
            "`log` option `core`",
        ),
        (
            "{ log {\n\thostnames example.com\n} }\n:80 {\n}\n",
            "hostnames is not allowed in the log global options",
        ),
        (
            ":80 {\n\tlog {\n\t\tinclude http.log.access.foo\n\t}\n}\n",
            "include is not allowed in the log directive",
        ),
        (
            ":80 {\n\tlog {\n\t\tlevel LOUD\n\t}\n}\n",
            "unsupported log level",
        ),
        (
            ":80 {\n\tlog {\n\t\toutput stdout\n\t\toutput stderr\n\t}\n}\n",
            "'output' subdirective specified more than once",
        ),
        (
            "{\n\tlog {\n\t}\n\tlog {\n\t}\n}\n:80 {\n}\n",
            "duplicate global log option for: default",
        ),
        (
            "{ metrics {\n\tbogus\n} }\n:80 {\n}\n",
            "unrecognized metrics option `bogus`",
        ),
        (
            ":80 {\n\tmetrics /metrics\n}\n",
            "directive `metrics` is not supported",
        ),
    ] {
        let error = adapt(caddyfile).expect_err("unsupported form must fail loudly");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in: {error}"
        );
    }
}

#[test]
fn empty_caddyfile_still_fails_loudly() {
    let error = adapt("   \n\n").expect_err("empty input must fail");
    assert!(error.to_string().contains("Caddyfile is empty"), "{error}");
}
