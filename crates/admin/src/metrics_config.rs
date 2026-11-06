//! Caddy metrics configuration parsing and validation (T-ADMIN-031).
//!
//! Caddy v2.11.7 has two independent metrics knobs that this crate models:
//!
//! * `apps.http.metrics` — the experimental HTTP observation config
//!   (`modules/caddyhttp/metrics.go`, `type Metrics`). Its JSON fields are `per_host`,
//!   `observe_catchall_hosts` and `otlp`. Caddy emits the `caddy_http_*` series only when this
//!   object is present; `per_host` adds a bounded `host` label (with `_other` for catch-all hosts)
//!   and `otlp` additionally pushes the same series over OTLP. Caddy's per-server
//!   `apps.http.servers.<name>.metrics` is the deprecated spelling of the same shape.
//! * `http.handlers.metrics` — the `metrics` HTTP handler that serves a `/metrics` endpoint
//!   (`modules/metrics/metrics.go`). Its only JSON field is `disable_openmetrics`.
//!
//! The parser rejects unknown fields with a located error (Caddy's module decoder is strict too),
//! type-checks each field, and reports unsupported *behaviour* loudly with the tracking id instead
//! of silently accepting a configuration whose observable output would differ:
//!
//! * `otlp: true` — no OTLP exporter is implemented in this build.
//! * `per_host: true` — [`HttpMetrics`] can label series by host, but the router/runtime does not
//!   pass a host label yet, so accepting it would silently drop Caddy's `host` label.
//! * `observe_catchall_hosts: true` is accepted (like Caddy) but has no effect while `per_host` is
//!   off, which is Caddy's own behaviour for that combination.
//! * `disable_openmetrics: true` is accepted: the admin `/metrics` endpoint always serves the
//!   Prometheus text format and never negotiates OpenMetrics, which is compatible with the
//!   disabled setting. With it omitted/false Caddy would negotiate OpenMetrics for clients that
//!   request it; caddy-rs does not (DIV-0006).
//!
//! Wiring: the core configuration model must keep `apps.http.metrics` (currently it lands in
//! `HttpApp::extra` and `core::validate` rejects it as an unknown HTTP app field), call
//! [`HttpMetricsConfig::from_json`] during validation, and the server runtime must pass the parsed
//! enable/per-host policy into [`crate::HttpMetrics`] (and only record HTTP metrics when enabled,
//! like Caddy). Until then caddy-rs always records the HTTP series (DIV-0033) and any configuration
//! containing these objects is rejected loudly by the core validator.

use serde_json::Value;

/// Default JSON location of the HTTP app metrics config.
pub const HTTP_METRICS_CONFIG_PATH: &str = "apps.http.metrics";
/// JSON location of the `metrics` HTTP handler config (`http.handlers.metrics`).
pub const METRICS_HANDLER_CONFIG_PATH: &str = "http.handlers.metrics";
/// Tracking id used in unsupported-feature messages for this module.
pub const METRICS_CONFIG_TRACKING_ID: &str = "T-ADMIN-031";

/// Caddy `apps.http.metrics` configuration (the `per_host`/`observe_catchall_hosts`/`otlp` shape).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpMetricsConfig {
    /// Label `caddy_http_*` series with the request host (all other hosts aggregate under `_other`).
    pub per_host: bool,
    /// Allow catch-all hosts to get individual metrics labels when `per_host` is enabled.
    pub observe_catchall_hosts: bool,
    /// Additionally push metrics over OTLP.
    pub otlp: bool,
}

impl HttpMetricsConfig {
    /// Parse `apps.http.metrics` from its JSON value.
    ///
    /// `null` means "not configured" and returns `Ok(None)` (Caddy decodes it to a nil `*Metrics`);
    /// a JSON object returns the parsed config (all fields optional, defaulting to `false`, and
    /// `null` for an individual field behaves like Go's decoder and leaves it `false`).
    pub fn from_json(value: &Value) -> Result<Option<Self>, MetricsConfigError> {
        Self::from_json_at(value, HTTP_METRICS_CONFIG_PATH)
    }

    /// Parse the HTTP metrics configuration out of a decoded caddy-rs config.
    ///
    /// Returns `None` when neither `apps.http.metrics` nor a deprecated per-server `metrics` object
    /// is present. The core config model preserves these unknown fields in its `extra` maps (and
    /// currently rejects them during validation), so this is the single place the runtime/validator
    /// should consult. Per Caddy's deprecated per-server behaviour, any per-server object enables
    /// the app-level metrics and its `per_host` is OR-ed into the result.
    pub fn from_config(config: &caddy_rs_core::Config) -> Result<Option<Self>, MetricsConfigError> {
        let Some(http) = config.http() else {
            return Ok(None);
        };
        let app_level = match http.extra.get("metrics") {
            Some(value) => Self::from_json_at(value, HTTP_METRICS_CONFIG_PATH)?,
            None => None,
        };
        let mut merged = app_level;
        for (server_name, server) in &http.servers {
            let Some(value) = server.extra.get("metrics") else {
                continue;
            };
            let base = format!("apps.http.servers.{server_name}.metrics");
            let Some(server_config) = Self::from_json_at(value, &base)? else {
                continue;
            };
            let entry = merged.get_or_insert_with(Self::default);
            entry.per_host |= server_config.per_host;
            entry.observe_catchall_hosts |= server_config.observe_catchall_hosts;
            entry.otlp |= server_config.otlp;
        }
        Ok(merged)
    }

    /// Parse the same shape at an explicit JSON location.
    ///
    /// Use this for Caddy's deprecated per-server spelling
    /// (`apps.http.servers.<name>.metrics`), so located errors name the right path.
    pub fn from_json_at(
        value: &Value,
        base_path: &str,
    ) -> Result<Option<Self>, MetricsConfigError> {
        if value.is_null() {
            return Ok(None);
        }
        let object = value
            .as_object()
            .ok_or_else(|| MetricsConfigError::new(base_path, "expected a JSON object or null"))?;
        let mut config = Self::default();
        for (field, field_value) in object {
            match field.as_str() {
                "per_host" => config.per_host = parse_bool(field_value, base_path, field)?,
                "observe_catchall_hosts" => {
                    config.observe_catchall_hosts = parse_bool(field_value, base_path, field)?
                }
                "otlp" => config.otlp = parse_bool(field_value, base_path, field)?,
                other => {
                    return Err(MetricsConfigError::new(
                        format!("{base_path}.{other}"),
                        format!(
                            "unknown metrics field `{other}`; supported fields are `per_host`, \
                             `observe_catchall_hosts` and `otlp`"
                        ),
                    ))
                }
            }
        }

        if config.otlp {
            return Err(MetricsConfigError::new(
                format!("{base_path}.otlp"),
                format!(
                    "OTLP metrics export is not implemented in this build ({METRICS_CONFIG_TRACKING_ID})"
                ),
            ));
        }
        if config.per_host {
            return Err(MetricsConfigError::new(
                format!("{base_path}.per_host"),
                format!(
                    "per-host metric labels are not implemented: the HTTP runtime does not pass a \
                     host label to the metrics recorder ({METRICS_CONFIG_TRACKING_ID})"
                ),
            ));
        }
        Ok(Some(config))
    }
}

/// Caddy `http.handlers.metrics` handler configuration (`modules/metrics/metrics.go`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsHandlerConfig {
    /// Do not negotiate the OpenMetrics format (the endpoint then always serves Prometheus text).
    pub disable_openmetrics: bool,
}

impl MetricsHandlerConfig {
    /// Parse the `metrics` handler object.
    pub fn from_json(value: &Value) -> Result<Self, MetricsConfigError> {
        Self::from_json_at(value, METRICS_HANDLER_CONFIG_PATH)
    }

    /// Parse the same shape at an explicit JSON location.
    pub fn from_json_at(value: &Value, base_path: &str) -> Result<Self, MetricsConfigError> {
        let object = value.as_object().ok_or_else(|| {
            MetricsConfigError::new(base_path, "expected a JSON object for the metrics handler")
        })?;
        let mut config = Self::default();
        for (field, field_value) in object {
            match field.as_str() {
                "disable_openmetrics" => {
                    config.disable_openmetrics = parse_bool(field_value, base_path, field)?
                }
                other => {
                    return Err(MetricsConfigError::new(
                        format!("{base_path}.{other}"),
                        format!(
                            "unknown metrics handler field `{other}`; the supported field is \
                             `disable_openmetrics`"
                        ),
                    ))
                }
            }
        }
        Ok(config)
    }
}

fn parse_bool(value: &Value, base_path: &str, field: &str) -> Result<bool, MetricsConfigError> {
    match value {
        // Go's json decoder leaves a non-pointer bool at its zero value for JSON null, and Caddy's
        // strict decoder does not reject that, so accept it as `false`.
        Value::Null => Ok(false),
        Value::Bool(boolean) => Ok(*boolean),
        other => Err(MetricsConfigError::new(
            format!("{base_path}.{field}"),
            format!("expected a boolean, got `{other}`"),
        )),
    }
}

/// A located metrics-configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsConfigError {
    path: String,
    message: String,
}

impl MetricsConfigError {
    /// Create a located error.
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    /// JSON path of the offending value (for example `apps.http.metrics.otlp`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Human-readable explanation.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for MetricsConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            formatter.write_str(&self.message)
        } else {
            write!(formatter, "{}: {}", self.path, self.message)
        }
    }
}

impl std::error::Error for MetricsConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_empty_object_as_defaults_and_null_as_absent() {
        assert_eq!(
            HttpMetricsConfig::from_json(&json!({})).unwrap(),
            Some(HttpMetricsConfig::default())
        );
        assert_eq!(HttpMetricsConfig::from_json(&Value::Null).unwrap(), None);
        assert_eq!(
            HttpMetricsConfig::from_json(&json!({"otlp": false, "per_host": false})).unwrap(),
            Some(HttpMetricsConfig {
                per_host: false,
                observe_catchall_hosts: false,
                otlp: false,
            })
        );
    }

    #[test]
    fn accepts_observe_catchall_hosts_without_per_host_like_caddy() {
        // Caddy accepts this combination and it has no effect while per_host is off.
        assert_eq!(
            HttpMetricsConfig::from_json(&json!({"observe_catchall_hosts": true})).unwrap(),
            Some(HttpMetricsConfig {
                per_host: false,
                observe_catchall_hosts: true,
                otlp: false,
            })
        );
    }

    #[test]
    fn null_boolean_fields_default_to_false_like_go_json() {
        let config = HttpMetricsConfig::from_json(&json!({
            "per_host": null,
            "observe_catchall_hosts": null,
            "otlp": null
        }))
        .unwrap();
        assert_eq!(config, Some(HttpMetricsConfig::default()));
    }

    #[test]
    fn rejects_unsupported_otlp_loudly() {
        let error = HttpMetricsConfig::from_json(&json!({"otlp": true})).unwrap_err();
        assert_eq!(error.path(), "apps.http.metrics.otlp");
        assert!(error.message().contains("not implemented"), "{error}");
        assert!(error.message().contains("T-ADMIN-031"), "{error}");
    }

    #[test]
    fn rejects_per_host_labels_until_the_runtime_supplies_a_host() {
        let error = HttpMetricsConfig::from_json(&json!({"per_host": true})).unwrap_err();
        assert_eq!(error.path(), "apps.http.metrics.per_host");
        assert!(error.message().contains("not implemented"), "{error}");
        assert!(error.message().contains("T-ADMIN-031"), "{error}");
    }

    #[test]
    fn rejects_unknown_fields_with_a_located_error() {
        let error = HttpMetricsConfig::from_json(&json!({"per-host": true})).unwrap_err();
        assert_eq!(error.path(), "apps.http.metrics.per-host");
        assert!(error.message().contains("unknown metrics field"), "{error}");
        assert!(error.message().contains("per_host"), "{error}");
    }

    #[test]
    fn rejects_wrong_types_with_located_errors() {
        for (field, value) in [
            ("per_host", json!("yes")),
            ("observe_catchall_hosts", json!(1)),
            ("otlp", json!({})),
        ] {
            let error = HttpMetricsConfig::from_json(&json!({ field: value })).unwrap_err();
            assert_eq!(error.path(), format!("apps.http.metrics.{field}"));
            assert!(error.message().contains("expected a boolean"), "{error}");
        }
    }

    #[test]
    fn rejects_non_object_metrics_config() {
        let error = HttpMetricsConfig::from_json(&json!([])).unwrap_err();
        assert_eq!(error.path(), "apps.http.metrics");
        assert!(
            error.message().contains("expected a JSON object"),
            "{error}"
        );
    }

    #[test]
    fn from_config_reads_app_level_and_preserved_server_objects() {
        use caddy_rs_core::Config;

        let config = Config::from_value(json!({
            "apps": {"http": {
                "metrics": {"observe_catchall_hosts": true},
                "servers": {
                    "srv0": {"listen": [":8080"], "routes": []},
                    "srv1": {
                        "listen": [":8081"],
                        "routes": [],
                        "metrics": {"per_host": true}
                    }
                }
            }}
        }))
        .unwrap();
        // A per-server `per_host` is unsupported once merged, so the error names that object.
        let error = HttpMetricsConfig::from_config(&config).unwrap_err();
        assert_eq!(error.path(), "apps.http.servers.srv1.metrics.per_host");

        let config = Config::from_value(json!({
            "apps": {"http": {
                "metrics": {},
                "servers": {"srv0": {"listen": [":8080"], "routes": []}}
            }}
        }))
        .unwrap();
        assert_eq!(
            HttpMetricsConfig::from_config(&config).unwrap(),
            Some(HttpMetricsConfig::default())
        );

        let config = Config::from_value(json!({
            "apps": {"http": {"servers": {"srv0": {"listen": [":8080"], "routes": []}}}}
        }))
        .unwrap();
        assert_eq!(HttpMetricsConfig::from_config(&config).unwrap(), None);
    }

    #[test]
    fn parses_the_deprecated_per_server_location() {
        let value = json!({});
        assert_eq!(
            HttpMetricsConfig::from_json_at(&value, "apps.http.servers.srv0.metrics").unwrap(),
            Some(HttpMetricsConfig::default())
        );
        let error = HttpMetricsConfig::from_json_at(
            &json!({"otlp": true}),
            "apps.http.servers.srv0.metrics",
        )
        .unwrap_err();
        assert_eq!(error.path(), "apps.http.servers.srv0.metrics.otlp");
    }

    #[test]
    fn parses_the_metrics_handler_config() {
        assert_eq!(
            MetricsHandlerConfig::from_json(&json!({})).unwrap(),
            MetricsHandlerConfig {
                disable_openmetrics: false
            }
        );
        assert_eq!(
            MetricsHandlerConfig::from_json(&json!({"disable_openmetrics": true})).unwrap(),
            MetricsHandlerConfig {
                disable_openmetrics: true
            }
        );
        let error =
            MetricsHandlerConfig::from_json(&json!({"disable_openmetrics": "yes"})).unwrap_err();
        assert_eq!(error.path(), "http.handlers.metrics.disable_openmetrics");
        assert!(error.message().contains("expected a boolean"), "{error}");
        let error =
            MetricsHandlerConfig::from_json(&json!({"enable_openmetrics": true})).unwrap_err();
        assert_eq!(error.path(), "http.handlers.metrics.enable_openmetrics");
        assert!(
            error.message().contains("unknown metrics handler field"),
            "{error}"
        );
        let error = MetricsHandlerConfig::from_json(&json!(true)).unwrap_err();
        assert_eq!(error.path(), "http.handlers.metrics");
    }
}
