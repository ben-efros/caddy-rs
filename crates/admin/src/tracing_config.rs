//! Caddy OpenTelemetry tracing handler configuration (T-ADMIN-022).
//!
//! In Caddy v2.11.7 tracing is **not** a server-level setting: there is no
//! `apps.http.servers.<name>.tracing` key. It is the HTTP handler module
//! `http.handlers.tracing` (`modules/caddyhttp/tracing/module.go`), configured either inline in a
//! route's `handle` list or through the Caddyfile `tracing` directive. Its JSON shape is:
//!
//! ```json
//! {
//!   "handler": "tracing",
//!   "span": "handler",
//!   "span_attributes": {"key": "value"}
//! }
//! ```
//!
//! * `span` is the OpenTelemetry span name; when empty/absent Caddy defaults it to `"handler"`
//!   (`defaultSpanName` in `tracing/tracer.go`).
//! * `span_attributes` maps attribute names to placeholder-bearing string values that Caddy
//!   expands with the request replacer before setting span attributes.
//!
//! The exporter/endpoint and sampling are configured through the standard `OTEL_*` environment
//! variables consumed by `autoexport.NewSpanExporter`; there are no JSON fields for them.
//!
//! This module parses and validates the handler configuration with located errors (Caddy's module
//! decoder is strict about unknown fields). The handler itself is not implemented in caddy-rs: the
//! HTTP handler registry has no `tracing` module yet, so a configuration containing it is rejected
//! loudly by validation. Wiring the handler needs `crates/http` (an OpenTelemetry-compatible tracer
//! dependency is also unavailable in the offline cache) and the server request path (W3C
//! `traceparent`/`tracestate` injection into upstream requests, `trace_id`/`span_id` request vars,
//! and the `traceID`/`spanID` access-log fields modelled by
//! [`crate::access_log::AccessLogEntry`]). Those are reported as hooks with T-ADMIN-022 rather than
//! silently approximated.
//!
//! The other half of T-ADMIN-022 — Caddy's `{http.request.uuid}` correlation id — is implemented in
//! [`crate::access_log::RequestUuid`] (lazy random UUIDv4, log-only, Caddy's `uuid` field).

use std::collections::BTreeMap;

use serde_json::Value;

/// Default JSON location of the tracing HTTP handler config.
pub const TRACING_HANDLER_CONFIG_PATH: &str = "http.handlers.tracing";
/// Caddy's default span name when the configured `span` is empty (`defaultSpanName`).
pub const DEFAULT_TRACING_SPAN_NAME: &str = "handler";
/// Tracking id used in unsupported-feature messages for request correlation/tracing.
pub const TRACING_TRACKING_ID: &str = "T-ADMIN-022";
/// Documentation sentence explaining that Caddy v2.11.7 has no server-level tracing key.
pub const SERVER_LEVEL_TRACING_NOTE: &str =
    "Caddy v2.11.7 configures tracing with the `http.handlers.tracing` HTTP handler, not with an \
     `apps.http.servers.<name>.tracing` server field; a server-level `tracing` object is not a \
     Caddy configuration surface and is rejected as an unknown HTTP server field (T-ADMIN-022)";

/// Caddy `http.handlers.tracing` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracingConfig {
    /// OpenTelemetry span name (Caddy defaults an empty value to [`DEFAULT_TRACING_SPAN_NAME`]).
    pub span: String,
    /// Custom span attributes, with placeholder-bearing values expanded at request time.
    pub span_attributes: BTreeMap<String, String>,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            span: DEFAULT_TRACING_SPAN_NAME.to_string(),
            span_attributes: BTreeMap::new(),
        }
    }
}

impl TracingConfig {
    /// Parse `http.handlers.tracing` from its JSON value.
    pub fn from_json(value: &Value) -> Result<Self, TracingConfigError> {
        Self::from_json_at(value, TRACING_HANDLER_CONFIG_PATH)
    }

    /// Parse the same shape at an explicit JSON location.
    pub fn from_json_at(value: &Value, base_path: &str) -> Result<Self, TracingConfigError> {
        let object = value.as_object().ok_or_else(|| {
            TracingConfigError::new(base_path, "expected a JSON object for the tracing handler")
        })?;
        let mut span = String::new();
        let mut span_attributes = BTreeMap::new();
        for (field, field_value) in object {
            match field.as_str() {
                "handler" => {
                    // The handler discriminator is part of every HTTP handler object; validate it
                    // like Caddy's module loader does instead of silently ignoring it.
                    let name = field_value.as_str().ok_or_else(|| {
                        TracingConfigError::new(
                            format!("{base_path}.handler"),
                            "expected the string `tracing`",
                        )
                    })?;
                    if name != "tracing" {
                        return Err(TracingConfigError::new(
                            format!("{base_path}.handler"),
                            format!("expected the string `tracing`, got `{name}`"),
                        ));
                    }
                }
                "span" => {
                    span = match field_value {
                        // Go decodes JSON null into the zero-value string without error.
                        Value::Null => String::new(),
                        Value::String(value) => value.clone(),
                        other => {
                            return Err(TracingConfigError::new(
                                format!("{base_path}.span"),
                                format!("expected a string, got `{other}`"),
                            ))
                        }
                    };
                }
                "span_attributes" => {
                    let attributes = field_value.as_object().ok_or_else(|| {
                        TracingConfigError::new(
                            format!("{base_path}.span_attributes"),
                            "expected a JSON object of string attribute values",
                        )
                    })?;
                    for (name, attribute) in attributes {
                        let attribute = attribute.as_str().ok_or_else(|| {
                            TracingConfigError::new(
                                format!("{base_path}.span_attributes.{name}"),
                                format!("expected a string, got `{attribute}`"),
                            )
                        })?;
                        span_attributes.insert(name.clone(), attribute.to_string());
                    }
                }
                other => {
                    return Err(TracingConfigError::new(
                        format!("{base_path}.{other}"),
                        format!(
                            "unknown tracing field `{other}`; supported fields are `span` and \
                             `span_attributes`"
                        ),
                    ))
                }
            }
        }
        if span.is_empty() {
            span = DEFAULT_TRACING_SPAN_NAME.to_string();
        }
        Ok(Self {
            span,
            span_attributes,
        })
    }
}

/// A located tracing-configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracingConfigError {
    path: String,
    message: String,
}

impl TracingConfigError {
    /// Create a located error.
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    /// JSON path of the offending value (for example `http.handlers.tracing.span`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Human-readable explanation.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for TracingConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            formatter.write_str(&self.message)
        } else {
            write!(formatter, "{}: {}", self.path, self.message)
        }
    }
}

impl std::error::Error for TracingConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_defaults_and_the_handler_discriminator() {
        assert_eq!(
            TracingConfig::from_json(&json!({"handler": "tracing"})).unwrap(),
            TracingConfig::default()
        );
        // Empty span defaults to Caddy's `defaultSpanName`.
        assert_eq!(
            TracingConfig::from_json(&json!({"span": ""})).unwrap().span,
            "handler"
        );
        assert_eq!(
            TracingConfig::from_json(&json!({"span": null}))
                .unwrap()
                .span,
            "handler"
        );
    }

    #[test]
    fn parses_span_and_attributes() {
        let config = TracingConfig::from_json(&json!({
            "handler": "tracing",
            "span": "my-span",
            "span_attributes": {
                "http.route": "{http.request.uri.path}",
                "deployment": "test"
            }
        }))
        .unwrap();
        assert_eq!(config.span, "my-span");
        assert_eq!(
            config.span_attributes.get("http.route").map(String::as_str),
            Some("{http.request.uri.path}")
        );
        assert_eq!(
            config.span_attributes.get("deployment").map(String::as_str),
            Some("test")
        );
    }

    #[test]
    fn rejects_unknown_fields_and_wrong_types_with_located_errors() {
        let error = TracingConfig::from_json(&json!({"sample_rate": 0.5})).unwrap_err();
        assert_eq!(error.path(), "http.handlers.tracing.sample_rate");
        assert!(error.message().contains("unknown tracing field"), "{error}");

        let error = TracingConfig::from_json(&json!({"span": 5})).unwrap_err();
        assert_eq!(error.path(), "http.handlers.tracing.span");
        assert!(error.message().contains("expected a string"), "{error}");

        let error = TracingConfig::from_json(&json!({"span_attributes": []})).unwrap_err();
        assert_eq!(error.path(), "http.handlers.tracing.span_attributes");
        assert!(
            error.message().contains("expected a JSON object"),
            "{error}"
        );

        let error = TracingConfig::from_json(&json!({"span_attributes": {"a": 1}})).unwrap_err();
        assert_eq!(error.path(), "http.handlers.tracing.span_attributes.a");
        assert!(error.message().contains("expected a string"), "{error}");

        let error = TracingConfig::from_json(&json!({"handler": "reverse_proxy"})).unwrap_err();
        assert_eq!(error.path(), "http.handlers.tracing.handler");
        assert!(
            error.message().contains("expected the string `tracing`"),
            "{error}"
        );
    }

    #[test]
    fn rejects_non_object_config_and_names_an_explicit_base_path() {
        let error = TracingConfig::from_json(&json!([])).unwrap_err();
        assert_eq!(error.path(), "http.handlers.tracing");
        assert!(
            error.message().contains("expected a JSON object"),
            "{error}"
        );

        let error = TracingConfig::from_json_at(
            &json!({"span_attributes": {"a": 1}}),
            "apps.http.servers.srv0.routes[0].handle[0]",
        )
        .unwrap_err();
        assert_eq!(
            error.path(),
            "apps.http.servers.srv0.routes[0].handle[0].span_attributes.a"
        );
    }

    #[test]
    fn documents_that_tracing_is_not_a_server_level_surface() {
        assert!(SERVER_LEVEL_TRACING_NOTE.contains("http.handlers.tracing"));
        assert!(SERVER_LEVEL_TRACING_NOTE.contains("not a"));
    }
}
