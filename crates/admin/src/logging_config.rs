//! Caddy `logging` configuration -> access-log sink mapping (plan task T-ADMIN-025).
//!
//! Caddy configures structured logging through the top-level `logging` object
//! (`logging.logs.<name>`). This module parses and validates the subset that can be represented
//! by caddy-rs's access-log sink ([`AccessLogSinkConfig`](crate::AccessLogSinkConfig)) and builds
//! one sink per Caddy log that would receive access entries.
//!
//! ## Supported subset
//!
//! ```json
//! {
//!   "logging": {
//!     "logs": {
//!       "default": {
//!         "writer": {"output": "stderr"},
//!         "encoder": {"format": "json"},
//!         "level": "INFO",
//!         "include": ["http.log.access"],
//!         "exclude": [],
//!         "sampling": {"interval": 1000000000, "first": 100, "thereafter": 100}
//!       },
//!       "access": {
//!         "writer": {"output": "file", "filename": "/var/log/caddy/access.log"},
//!         "encoder": {"format": "filter", "wrap": {"format": "json"}, "fields": {
//!           "request>headers>Authorization": {"filter": "replace", "value": "REDACTED"},
//!           "request>headers>X-Debug": {"filter": "delete"},
//!           "resp_headers": {"filter": "delete"}
//!         }}
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! * `writer.output`: `stderr` (default), `stdout`, `discard`, `file` (requires `filename`).
//!   File rotation (`roll_*`), permissions (`mode`, `dir_mode`) and other writer modules (`net`)
//!   are rejected loudly (rotation is a documented sink gap, `T-ADMIN-025`).
//! * `encoder.format`: `json` (also the default when omitted) or `filter` wrapping `json`.
//!   `console`, `append`, `journald`, `nop`, nested filter encoders and non-default JSON encoder
//!   options are rejected loudly.
//! * Filter fields: `delete` of a selectable top-level entry field maps to
//!   [`AccessLogConfig::exclude`](crate::AccessLogConfig), `delete`/`replace` of
//!   `request>headers>Name` or `resp_headers>Name` maps to
//!   [`RedactionPolicy`](crate::RedactionPolicy) header rules. Every other filter/path is rejected
//!   loudly (hash/ip_mask/query/cookie/set_cookie/regexp/rename/multi_regexp are not implemented).
//! * `level`: `DEBUG`/`INFO`/`WARN`/`ERROR`/`PANIC`/`FATAL`, case-insensitive. The threshold is
//!   enforced by the sink ([`AccessLogSink::emit`](crate::AccessLogSink::emit) returns
//!   `FilteredOut`). `PANIC`/`FATAL` map to the highest access-entry level (`ERROR`): access
//!   entries are only `INFO`/`ERROR`, so this matches Caddy's effect for this log.
//! * `sampling`: interval (integer nanoseconds, Caddy's JSON form; `0`/absent -> 1s), `first`
//!   (`0`/absent -> 100), `thereafter` (`0`/absent -> 100), matching Caddy's provisioning
//!   defaults. Negative values and non-integer intervals are rejected.
//! * `include`/`exclude`: logger-name prefix filters, applied with Caddy's
//!   `loggerAllowed` semantics to decide whether the log receives `http.log.access`. Caddy's
//!   provisioning rules for contradictory include/exclude lists are enforced.
//!
//! ## Defaults
//!
//! Caddy always has a `default` log (stderr, JSON in non-terminal environments, INFO). When the
//! configuration omits `logging.logs.default`, the mapping produces that implicit default target.
//! Access entries are tee'd to *every* log that accepts the `http.log.access` logger, so the
//! result is an ordered list: `default` first (when eligible), then the remaining eligible logs
//! in name order.
//!
//! ## Not modelled here
//!
//! * `logging.sink` (the unstructured standard-library sink) is not an access-log target and is
//!   rejected rather than ignored.
//! * `core` modules, `with_caller`/`with_caller_skip`/`with_stacktrace` are rejected (the access
//!   entry shape has no caller/stacktrace fields).
//! * Encoder key remapping (`message_key`, `time_format`, ...) is rejected: caddy-rs emits the
//!   fixed Caddy default JSON field names.
//! * Terminal console auto-detection: caddy-rs always emits JSON, so a Caddy deployment whose
//!   implicit default encoder would be `console` (interactive terminal) gets JSON here. This is
//!   the documented sink divergence; an explicit `console` encoder is rejected rather than
//!   approximated silently.
//!
//! All failures are [`LoggingConfigError`]s naming the JSON path (`logging.logs.access.writer...`)
//! and, for unsupported-but-recognised Caddy features, the tracking id (`T-ADMIN-025`).

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use caddy_rs_core::{Config, CustomLog, LogEncoder, LogSampling, LogWriter, Logging};
use http::HeaderName;
use serde_json::Value;

use crate::access_log::{
    AccessLogConfig, AccessLogField, HeaderRedaction, HeaderTarget, LogLevel, RedactionPolicy,
    SamplingConfig, ACCESS_LOG_LOGGER,
};
use crate::sink::{
    AccessLogOutput, AccessLogSink, AccessLogSinkConfig, DEFAULT_ACCESS_LOG_BUFFER_BYTES,
};

/// Tracking id for the unsupported parts of Caddy's logging configuration.
pub const LOGGING_TRACKING_ID: &str = "T-ADMIN-025";

/// A located error from mapping Caddy's `logging` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfigError {
    path: String,
    message: String,
    tracking_id: Option<&'static str>,
}

impl LoggingConfigError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
            tracking_id: None,
        }
    }

    fn unsupported(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
            tracking_id: Some(LOGGING_TRACKING_ID),
        }
    }

    /// Located JSON path of the offending configuration value.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Human-readable diagnosis.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Tracking id for a recognised-but-unimplemented Caddy feature.
    pub fn tracking_id(&self) -> Option<&'static str> {
        self.tracking_id
    }
}

impl fmt::Display for LoggingConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "logging `{}`: {}", self.path, self.message)?;
        if let Some(tracking_id) = self.tracking_id {
            write!(formatter, " (tracking {tracking_id})")?;
        }
        Ok(())
    }
}

impl std::error::Error for LoggingConfigError {}

/// One access-log target derived from a Caddy log definition.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessLogTarget {
    name: String,
    config: AccessLogSinkConfig,
}

impl AccessLogTarget {
    /// The Caddy log name (`logging.logs.<name>`): `"default"` or a custom name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The sink configuration derived from the log definition.
    pub fn sink_config(&self) -> &AccessLogSinkConfig {
        &self.config
    }

    /// Build a working sink for this target.
    ///
    /// This opens the configured writer (creating/append-opening a file) and validates the encoder
    /// again, so a configuration that passed mapping can still fail here with a located
    /// [`crate::AccessLogError`] if the destination is not writable.
    pub fn build_sink(&self) -> Result<AccessLogSink, LoggingConfigError> {
        AccessLogSink::from_config(&self.config).map_err(|error| {
            LoggingConfigError::new(
                format!("logging.logs.{}.{}", self.name, error.path()),
                error.message().to_string(),
            )
        })
    }
}

/// A built access-log sink plus the Caddy log name it belongs to.
#[derive(Debug)]
pub struct BuiltAccessLogSink {
    /// Caddy log name this sink receives entries for.
    pub name: String,
    /// Constructed, ready-to-emit sink.
    pub sink: AccessLogSink,
}

/// Validated access-log targets derived from Caddy's `logging` configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LoggingConfig {
    targets: Vec<AccessLogTarget>,
}

impl LoggingConfig {
    /// Map the logging configuration of a full Caddy configuration document.
    pub fn from_config(config: &Config) -> Result<Self, LoggingConfigError> {
        Self::from_logging(config.logging.as_ref())
    }

    /// Map a typed Caddy [`Logging`] configuration (`None` means "use Caddy defaults").
    pub fn from_logging(logging: Option<&Logging>) -> Result<Self, LoggingConfigError> {
        let empty = Logging::default();
        let logging = logging.unwrap_or(&empty);
        validate_logging(logging)?;

        // Caddy always has a `default` log; custom logs are added on top. Access entries are tee'd
        // to every log whose include/exclude rules accept the access logger.
        let mut effective: BTreeMap<String, CustomLog> = logging.logs.clone();
        effective.entry("default".to_string()).or_default();

        let mut targets = Vec::new();
        for (name, log) in &effective {
            validate_custom_log(name, log)?;
            if !logger_allowed(ACCESS_LOG_LOGGER, &log.include, &log.exclude) {
                continue;
            }
            targets.push(AccessLogTarget {
                name: name.clone(),
                config: convert_log(name, log)?,
            });
        }
        // Caddy sets up the default log first, then custom logs in map iteration order; sort the
        // rest for deterministic output.
        targets.sort_by_key(|target| (target.name != "default", target.name.clone()));

        Ok(Self { targets })
    }

    /// Map a Caddy `logging` JSON object (the value of the top-level `logging` field).
    pub fn from_json(value: &Value) -> Result<Self, LoggingConfigError> {
        if value.is_null() {
            return Self::from_logging(None);
        }
        let logging: Logging = serde_json::from_value(value.clone()).map_err(|error| {
            LoggingConfigError::new("logging", format!("cannot decode logging JSON: {error}"))
        })?;
        Self::from_logging(Some(&logging))
    }

    /// The derived access-log targets in deterministic order (`default` first, then by name).
    pub fn targets(&self) -> &[AccessLogTarget] {
        &self.targets
    }

    /// Override the write-buffer size for every derived target.
    ///
    /// Caddy has no equivalent logging JSON field (its zap core writes synchronously); the server
    /// runtime can use this knob to tune buffering. A zero size is rejected with a located error,
    /// matching [`AccessLogSinkConfig::validate`].
    pub fn with_buffer_bytes(mut self, buffer_bytes: usize) -> Result<Self, LoggingConfigError> {
        for target in &mut self.targets {
            target.config.buffer_bytes = buffer_bytes;
            target.config.validate().map_err(|error| {
                LoggingConfigError::new(
                    format!("logging.logs.{}.{}", target.name, error.path()),
                    error.message().to_string(),
                )
            })?;
        }
        Ok(self)
    }

    /// Build one sink per target, in target order.
    ///
    /// The first failure aborts; previously built sinks have their `Drop` best-effort flush (call
    /// [`AccessLogSink::close`] explicitly on shutdown for observed flush errors).
    pub fn build_sinks(&self) -> Result<Vec<BuiltAccessLogSink>, LoggingConfigError> {
        let mut built: Vec<BuiltAccessLogSink> = Vec::with_capacity(self.targets.len());
        for target in &self.targets {
            built.push(BuiltAccessLogSink {
                name: target.name.clone(),
                sink: target.build_sink()?,
            });
        }
        Ok(built)
    }
}

fn validate_logging(logging: &Logging) -> Result<(), LoggingConfigError> {
    if logging.sink.is_some() {
        return Err(LoggingConfigError::unsupported(
            "logging.sink",
            "the unstructured standard-library log sink is not an access-log target and is not \
             mapped by this build",
        ));
    }
    if let Some((field, _)) = logging.extra.iter().next() {
        return Err(LoggingConfigError::unsupported(
            format!("logging.{field}"),
            format!("logging field `{field}` is not supported by this build"),
        ));
    }
    Ok(())
}

fn validate_custom_log(name: &str, log: &CustomLog) -> Result<(), LoggingConfigError> {
    let path = format!("logging.logs.{name}");

    if log.base.core.is_some() || !log.base.extra.is_empty() {
        let field = if log.base.core.is_some() {
            "core"
        } else {
            log.base
                .extra
                .keys()
                .next()
                .map(String::as_str)
                .unwrap_or("unknown")
        };
        return Err(LoggingConfigError::unsupported(
            format!("{path}.{field}"),
            format!("log field `{field}` is not supported by the access-log mapping"),
        ));
    }
    if log.base.with_caller || log.base.with_caller_skip.is_some() {
        return Err(LoggingConfigError::unsupported(
            format!("{path}.with_caller"),
            "caller information is not part of the caddy-rs access-log record",
        ));
    }
    if log.base.with_stacktrace.is_some() {
        return Err(LoggingConfigError::unsupported(
            format!("{path}.with_stacktrace"),
            "stacktraces are not part of the caddy-rs access-log record",
        ));
    }
    validate_logger_filters(&path, &log.include, &log.exclude)?;
    Ok(())
}

fn validate_logger_filters(
    path: &str,
    include: &[String],
    exclude: &[String],
) -> Result<(), LoggingConfigError> {
    for (field, names) in [("include", include), ("exclude", exclude)] {
        for (index, name) in names.iter().enumerate() {
            if name.is_empty() || name.chars().any(char::is_whitespace) {
                return Err(LoggingConfigError::new(
                    format!("{path}.{field}[{index}]"),
                    "logger name filters must be non-empty and contain no whitespace",
                ));
            }
        }
    }
    if include.is_empty() || exclude.is_empty() {
        return Ok(());
    }
    // Port of Caddy's `CustomLog.provision` contradiction checks.
    for allowed in include {
        if exclude.contains(allowed) {
            return Err(LoggingConfigError::new(
                format!("{path}.include"),
                format!("include and exclude must not intersect, but found `{allowed}` in both"),
            ));
        }
    }
    for allowed in include {
        let nested = exclude.iter().any(|denied| {
            allowed.starts_with(&format!("{denied}.")) || denied.starts_with(&format!("{allowed}."))
        });
        if !nested {
            return Err(LoggingConfigError::new(
                format!("{path}.include"),
                format!(
                    "when both include and exclude are populated, each element must be a \
                     superspace or subspace of one in the other list; check `{allowed}`"
                ),
            ));
        }
    }
    Ok(())
}

/// Port of Caddy's `CustomLog.loggerAllowed` for a concrete logger name (`is_module = false`).
fn logger_allowed(name: &str, include: &[String], exclude: &[String]) -> bool {
    if include.is_empty() && exclude.is_empty() {
        return true;
    }
    let mut name = name.to_string();
    if !name.is_empty() && name != "*" && name != "." {
        name.push('.');
    }
    let mut longest_accept = 0;
    let mut longest_reject = 0;

    if !include.is_empty() {
        for namespace in include {
            if name.starts_with(&format!("{namespace}.")) && namespace.len() > longest_accept {
                longest_accept = namespace.len();
            }
        }
        if longest_accept == 0 {
            return false;
        }
    }
    if !exclude.is_empty() {
        for namespace in exclude {
            if (namespace == "*" && name != ".") || (namespace == "." && name == ".") {
                return false;
            }
            if name.starts_with(&format!("{namespace}.")) && namespace.len() > longest_reject {
                longest_reject = namespace.len();
            }
        }
        if longest_reject > longest_accept {
            return false;
        }
    }
    longest_accept > longest_reject || (include.is_empty() && longest_reject == 0)
}

fn convert_log(name: &str, log: &CustomLog) -> Result<AccessLogSinkConfig, LoggingConfigError> {
    let path = format!("logging.logs.{name}");
    let (output, filename) = parse_writer(&path, log.base.writer.as_ref())?;
    let encoder = parse_encoder(&path, log.base.encoder.as_ref())?;
    let level = parse_level(&path, log.base.level.as_deref())?;
    let sampling = parse_sampling(&path, log.base.sampling.as_ref())?;

    let config = AccessLogSinkConfig {
        output,
        filename,
        encoder: AccessLogConfig {
            include: Vec::new(),
            exclude: encoder.exclude,
            log_credentials: false,
            redaction: encoder.redaction,
            sampling,
        },
        buffer_bytes: DEFAULT_ACCESS_LOG_BUFFER_BYTES,
        level,
    };
    config.validate().map_err(|error| {
        LoggingConfigError::new(
            format!("{path}.encoder.{}", error.path()),
            error.message().to_string(),
        )
    })?;
    Ok(config)
}

fn parse_writer(
    path: &str,
    writer: Option<&LogWriter>,
) -> Result<(AccessLogOutput, Option<PathBuf>), LoggingConfigError> {
    let Some(writer) = writer else {
        return Ok((AccessLogOutput::Stderr, None));
    };
    let writer_path = format!("{path}.writer");
    let Some(output) = writer.output.as_deref() else {
        return Err(LoggingConfigError::new(
            format!("{writer_path}.output"),
            "writer module is missing its inline `output` key",
        ));
    };

    match output {
        "stderr" | "stdout" | "discard" => {
            if let Some((field, _)) = writer.extra.iter().next() {
                return Err(LoggingConfigError::unsupported(
                    format!("{writer_path}.{field}"),
                    format!("writer option `{field}` is not supported for the `{output}` writer"),
                ));
            }
            let destination = match output {
                "stderr" => AccessLogOutput::Stderr,
                "stdout" => AccessLogOutput::Stdout,
                _ => AccessLogOutput::Discard,
            };
            Ok((destination, None))
        }
        "file" => {
            let filename = writer.extra.get("filename");
            let filename = match filename {
                Some(Value::String(filename)) if !filename.is_empty() => PathBuf::from(filename),
                Some(Value::String(_)) => {
                    return Err(LoggingConfigError::new(
                        format!("{writer_path}.filename"),
                        "file writer `filename` must not be empty",
                    ))
                }
                Some(_) => {
                    return Err(LoggingConfigError::new(
                        format!("{writer_path}.filename"),
                        "file writer `filename` must be a string",
                    ))
                }
                None => {
                    return Err(LoggingConfigError::new(
                        format!("{writer_path}.filename"),
                        "file writer requires a `filename`",
                    ))
                }
            };
            if let Some(field) = writer
                .extra
                .keys()
                .find(|field| field.as_str() != "filename")
            {
                let detail = if field.starts_with("roll")
                    || matches!(field.as_str(), "mode" | "dir_mode" | "backup_time_format")
                {
                    "log rotation/permission options are not implemented by the caddy-rs \
                     access-log sink"
                } else {
                    "writer option is not supported by the caddy-rs access-log sink"
                };
                return Err(LoggingConfigError::unsupported(
                    format!("{writer_path}.{field}"),
                    format!("file writer option `{field}` is not supported: {detail}"),
                ));
            }
            Ok((AccessLogOutput::File, Some(filename)))
        }
        "net" => Err(LoggingConfigError::unsupported(
            format!("{writer_path}.output"),
            "the `net` log writer is not supported by this build's access-log sink \
             (supported: stderr, stdout, discard, file)",
        )),
        other => Err(LoggingConfigError::unsupported(
            format!("{writer_path}.output"),
            format!("unknown log writer `{other}` (supported: stderr, stdout, discard, file)"),
        )),
    }
}

struct EncoderSelection {
    exclude: Vec<AccessLogField>,
    redaction: RedactionPolicy,
}

fn parse_encoder(
    path: &str,
    encoder: Option<&LogEncoder>,
) -> Result<EncoderSelection, LoggingConfigError> {
    let Some(encoder) = encoder else {
        return Ok(EncoderSelection {
            exclude: Vec::new(),
            redaction: RedactionPolicy::default(),
        });
    };
    let encoder_path = format!("{path}.encoder");
    let format = encoder.format.as_deref().ok_or_else(|| {
        LoggingConfigError::new(
            format!("{encoder_path}.format"),
            "encoder module is missing its inline `format` key",
        )
    })?;
    match format {
        "json" => {
            if let Some(field) = encoder.extra.keys().next() {
                return Err(LoggingConfigError::unsupported(
                    format!("{encoder_path}.{field}"),
                    format!(
                        "json encoder option `{field}` is not supported: caddy-rs emits the fixed \
                         Caddy default JSON field names"
                    ),
                ));
            }
            Ok(EncoderSelection {
                exclude: Vec::new(),
                redaction: RedactionPolicy::default(),
            })
        }
        "filter" => parse_filter_encoder(&encoder_path, &encoder.extra),
        "console" | "append" | "journald" | "nop" => Err(LoggingConfigError::unsupported(
            format!("{encoder_path}.format"),
            format!(
                "the `{format}` log encoder is not supported by this build's access-log sink \
                 (supported: json, filter-wrapping-json)"
            ),
        )),
        other => Err(LoggingConfigError::unsupported(
            format!("{encoder_path}.format"),
            format!("unknown log encoder `{other}` (supported: json, filter-wrapping-json)"),
        )),
    }
}

fn parse_filter_encoder(
    path: &str,
    extra: &BTreeMap<String, Value>,
) -> Result<EncoderSelection, LoggingConfigError> {
    for field in extra.keys() {
        if field != "wrap" && field != "fields" {
            return Err(LoggingConfigError::unsupported(
                format!("{path}.{field}"),
                format!("filter encoder option `{field}` is not supported"),
            ));
        }
    }

    // The wrapped encoder: only a plain JSON encoder; a nested filter is not supported.
    match extra.get("wrap") {
        None => {}
        Some(Value::Object(wrapped)) => {
            let wrapped = LogEncoder {
                format: wrapped
                    .get("format")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                extra: wrapped
                    .iter()
                    .filter(|(key, _)| key.as_str() != "format")
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            };
            let format = wrapped.format.as_deref().ok_or_else(|| {
                LoggingConfigError::new(
                    format!("{path}.wrap.format"),
                    "filter encoder `wrap` is missing its inline `format` key",
                )
            })?;
            if format != "json" {
                return Err(LoggingConfigError::unsupported(
                    format!("{path}.wrap.format"),
                    format!("filter encoder wraps `{format}`, but only json is supported"),
                ));
            }
            if let Some(field) = wrapped.extra.keys().next() {
                return Err(LoggingConfigError::unsupported(
                    format!("{path}.wrap.{field}"),
                    format!("json encoder option `{field}` is not supported"),
                ));
            }
        }
        Some(_) => {
            return Err(LoggingConfigError::new(
                format!("{path}.wrap"),
                "filter encoder `wrap` must be an encoder object",
            ))
        }
    }

    let mut selection = EncoderSelection {
        exclude: Vec::new(),
        redaction: RedactionPolicy::default(),
    };
    let Some(Value::Object(fields)) = extra.get("fields") else {
        if extra.contains_key("fields") {
            return Err(LoggingConfigError::new(
                format!("{path}.fields"),
                "filter encoder `fields` must be an object",
            ));
        }
        return Ok(selection);
    };
    for (field_path, filter_value) in fields {
        let filter_object = filter_value.as_object().ok_or_else(|| {
            LoggingConfigError::new(
                format!("{path}.fields.{field_path}"),
                "a field filter must be an object with a `filter` key",
            )
        })?;
        let filter_name = filter_object
            .get("filter")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                LoggingConfigError::new(
                    format!("{path}.fields.{field_path}.filter"),
                    "field filter is missing the inline `filter` key",
                )
            })?;
        apply_field_filter(path, field_path, filter_name, filter_object, &mut selection)?;
    }
    Ok(selection)
}

fn apply_field_filter(
    path: &str,
    field_path: &str,
    filter_name: &str,
    filter_object: &serde_json::Map<String, Value>,
    selection: &mut EncoderSelection,
) -> Result<(), LoggingConfigError> {
    let filter_path = format!("{path}.fields.{field_path}");
    match filter_name {
        "delete" => {
            reject_filter_options(&filter_path, filter_object, filter_name, &[])?;
            if let Some(header) = header_field_target(field_path) {
                selection.redaction.headers.push(HeaderRedaction::Delete {
                    header: header.0,
                    target: header.1,
                });
                return Ok(());
            }
            let Some(field) = access_log_field(field_path) else {
                return Err(LoggingConfigError::unsupported(
                    format!("{filter_path}.filter"),
                    format!(
                        "delete filter on `{field_path}` is not supported; only top-level access \
                         entry fields and request/response headers can be deleted"
                    ),
                ));
            };
            if matches!(
                field,
                AccessLogField::Ts
                    | AccessLogField::Level
                    | AccessLogField::Logger
                    | AccessLogField::Msg
            ) {
                return Err(LoggingConfigError::new(
                    format!("{filter_path}.filter"),
                    format!(
                        "fundamental log field `{}` cannot be filtered",
                        field.as_str()
                    ),
                ));
            }
            selection.exclude.push(field);
            Ok(())
        }
        "replace" => {
            reject_filter_options(&filter_path, filter_object, filter_name, &["value"])?;
            let value = match filter_object.get("value") {
                None => String::new(),
                Some(Value::String(value)) => value.clone(),
                Some(_) => {
                    return Err(LoggingConfigError::new(
                        format!("{filter_path}.value"),
                        "replace filter `value` must be a string",
                    ))
                }
            };
            let Some((header, target)) = header_field_target(field_path) else {
                return Err(LoggingConfigError::unsupported(
                    format!("{filter_path}.filter"),
                    format!(
                        "replace filter on `{field_path}` is not supported; only request and \
                         response header fields can be replaced"
                    ),
                ));
            };
            selection.redaction.headers.push(HeaderRedaction::Replace {
                header,
                value,
                target,
            });
            Ok(())
        }
        "hash" | "ip_mask" | "query" | "cookie" | "set_cookie" | "regexp" | "rename"
        | "multi_regexp" => Err(LoggingConfigError::unsupported(
            format!("{filter_path}.filter"),
            format!(
                "the `{filter_name}` log field filter is not implemented by this build \
                 (supported: delete, replace for headers)"
            ),
        )),
        other => Err(LoggingConfigError::new(
            format!("{filter_path}.filter"),
            format!("unknown log field filter `{other}` (supported: delete, replace)"),
        )),
    }
}

fn reject_filter_options(
    path: &str,
    filter_object: &serde_json::Map<String, Value>,
    filter_name: &str,
    allowed: &[&str],
) -> Result<(), LoggingConfigError> {
    for key in filter_object.keys() {
        if key == "filter" || allowed.contains(&key.as_str()) {
            continue;
        }
        return Err(LoggingConfigError::unsupported(
            format!("{path}.{key}"),
            format!("`{filter_name}` filter option `{key}` is not supported"),
        ));
    }
    Ok(())
}

/// Parse `request>headers>Name` / `resp_headers>Name` into a header redaction target.
fn header_field_target(field_path: &str) -> Option<(String, HeaderTarget)> {
    if let Some(header) = field_path.strip_prefix("request>headers>") {
        return valid_header_name(header).map(|name| (name, HeaderTarget::Request));
    }
    if let Some(header) = field_path.strip_prefix("resp_headers>") {
        return valid_header_name(header).map(|name| (name, HeaderTarget::Response));
    }
    None
}

fn valid_header_name(header: &str) -> Option<String> {
    if header.is_empty() {
        return None;
    }
    HeaderName::from_bytes(header.as_bytes())
        .ok()
        .map(|name| name.as_str().to_string())
}

fn access_log_field(field_path: &str) -> Option<AccessLogField> {
    Some(match field_path {
        "ts" => AccessLogField::Ts,
        "level" => AccessLogField::Level,
        "logger" => AccessLogField::Logger,
        "msg" => AccessLogField::Msg,
        "request" => AccessLogField::Request,
        "bytes_read" => AccessLogField::BytesRead,
        "user_id" => AccessLogField::UserId,
        "duration" => AccessLogField::Duration,
        "size" => AccessLogField::Size,
        "status" => AccessLogField::Status,
        "resp_headers" => AccessLogField::RespHeaders,
        "write_error" => AccessLogField::WriteError,
        "upstream" => AccessLogField::Upstream,
        _ => return None,
    })
}

fn parse_level(path: &str, level: Option<&str>) -> Result<Option<LogLevel>, LoggingConfigError> {
    let Some(level) = level else {
        // Caddy's default level for a log is INFO; access entries are INFO/ERROR, so this filters
        // nothing but keeps the mapping explicit.
        return Ok(Some(LogLevel::Info));
    };
    if level.trim().is_empty() {
        return Ok(Some(LogLevel::Info));
    }
    if level.contains('{') {
        return Err(LoggingConfigError::unsupported(
            format!("{path}.level"),
            "placeholder expansion in log levels is not supported by the access-log mapping",
        ));
    }
    Ok(Some(match level.to_ascii_lowercase().as_str() {
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        // Access entries are only INFO/ERROR; Caddy's panic/fatal thresholds also exclude INFO.
        "panic" | "fatal" => LogLevel::Error,
        other => {
            return Err(LoggingConfigError::new(
                format!("{path}.level"),
                format!(
                    "unrecognized log level `{other}` (expected DEBUG, INFO, WARN, ERROR, PANIC, \
                     or FATAL)"
                ),
            ))
        }
    }))
}

fn parse_sampling(
    path: &str,
    sampling: Option<&LogSampling>,
) -> Result<Option<SamplingConfig>, LoggingConfigError> {
    let Some(sampling) = sampling else {
        return Ok(None);
    };
    let sampling_path = format!("{path}.sampling");
    if let Some(field) = sampling.extra.keys().next() {
        return Err(LoggingConfigError::unsupported(
            format!("{sampling_path}.{field}"),
            format!("sampling option `{field}` is not supported"),
        ));
    }

    let interval =
        match &sampling.interval {
            None => Duration::from_secs(1),
            Some(Value::Number(number)) => {
                let nanos = number
                    .as_i64()
                    .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
                    .ok_or_else(|| {
                        LoggingConfigError::new(
                            format!("{sampling_path}.interval"),
                            "sampling interval must be an integer number of nanoseconds",
                        )
                    })?;
                if nanos < 0 {
                    return Err(LoggingConfigError::new(
                        format!("{sampling_path}.interval"),
                        "sampling interval must not be negative",
                    ));
                }
                if nanos == 0 {
                    Duration::from_secs(1)
                } else {
                    Duration::from_nanos(nanos as u64)
                }
            }
            Some(Value::String(_)) => return Err(LoggingConfigError::unsupported(
                format!("{sampling_path}.interval"),
                "string sampling intervals are not accepted; Caddy marshals durations as integer \
                 nanoseconds",
            )),
            Some(_) => {
                return Err(LoggingConfigError::new(
                    format!("{sampling_path}.interval"),
                    "sampling interval must be an integer number of nanoseconds",
                ))
            }
        };

    let first = parse_sampling_count(&sampling_path, "first", sampling.first)?;
    let thereafter = parse_sampling_count(&sampling_path, "thereafter", sampling.thereafter)?;
    SamplingConfig::new(interval, first, thereafter)
        .map(Some)
        .map_err(|error| {
            LoggingConfigError::new(
                format!("{sampling_path}.{}", error.path()),
                error.message().to_string(),
            )
        })
}

fn parse_sampling_count(
    path: &str,
    field: &str,
    value: Option<i64>,
) -> Result<usize, LoggingConfigError> {
    match value {
        None | Some(0) => Ok(100),
        Some(value) if value > 0 => usize::try_from(value).map_err(|_| {
            LoggingConfigError::new(format!("{path}.{field}"), "sampling count is too large")
        }),
        Some(value) => Err(LoggingConfigError::new(
            format!("{path}.{field}"),
            format!("sampling count must not be negative (found {value})"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use serde_json::{json, Value};

    use super::*;
    use crate::access_log::{AccessLogEntry, AccessLogRequest, SamplingConfig};
    use crate::sink::EmitOutcome;

    fn entry(status: u16, body: &str) -> AccessLogEntry {
        let mut request = AccessLogRequest::new("GET", "example.com", "/path?token=secret");
        request.headers.insert(
            "Authorization".to_string(),
            vec!["Bearer secret".to_string()],
        );
        request
            .headers
            .insert("X-Debug".to_string(), vec!["1".to_string()]);
        AccessLogEntry::new(request)
            .with_status(status)
            .with_size(body.len() as u64)
    }

    fn targets_from(logging: &Value) -> Vec<AccessLogTarget> {
        LoggingConfig::from_json(logging)
            .unwrap_or_else(|error| panic!("mapping failed: {error}"))
            .targets()
            .to_vec()
    }

    #[test]
    fn caddy_shaped_logging_json_parses_with_defaults() {
        let logging = json!({
            "logs": {
                "default": {
                    "writer": {"output": "stderr"},
                    "encoder": {"format": "json"},
                    "level": "INFO"
                }
            }
        });
        let targets = targets_from(&logging);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name(), "default");
        let config = targets[0].sink_config();
        assert_eq!(config.output, AccessLogOutput::Stderr);
        assert_eq!(config.filename, None);
        assert_eq!(config.level, Some(LogLevel::Info));
        assert_eq!(config.encoder.sampling, None);
        assert!(config.encoder.exclude.is_empty());
    }

    #[test]
    fn absent_logging_yields_the_implicit_caddy_default_sink() {
        let config = LoggingConfig::from_logging(None).expect("defaults");
        assert_eq!(config.targets().len(), 1);
        let target = &config.targets()[0];
        assert_eq!(target.name(), "default");
        assert_eq!(target.sink_config().output, AccessLogOutput::Stderr);
        assert_eq!(target.sink_config().level, Some(LogLevel::Info));
        // Empty JSON object behaves like None.
        assert_eq!(LoggingConfig::from_json(&json!({})).expect("empty"), config);
    }

    #[test]
    fn file_writer_maps_filename_and_builds_a_working_sink() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("access.log");
        let logging = json!({
            "logs": {
                "default": {
                    "writer": {"output": "file", "filename": path.to_string_lossy()},
                    "encoder": {"format": "json"}
                }
            }
        });
        let logging = LoggingConfig::from_json(&logging).expect("map");
        let target = &logging.targets()[0];
        assert_eq!(target.sink_config().output, AccessLogOutput::File);
        assert_eq!(
            target.sink_config().filename.as_deref(),
            Some(path.as_path())
        );

        let sink = target.build_sink().expect("build sink");
        assert_eq!(
            sink.emit(&entry(200, "hello")).expect("emit"),
            EmitOutcome::Written
        );
        sink.close().expect("close");

        let contents = std::fs::read(&path).expect("read log");
        let value: Value = serde_json::from_slice(&contents).expect("json line");
        assert_eq!(value["status"], 200);
        assert_eq!(value["request"]["method"], "GET");
        assert_eq!(value["level"], "info");
    }

    #[test]
    fn custom_logs_receive_access_entries_only_when_filters_accept_them() {
        let logging = json!({
            "logs": {
                "default": {"writer": {"output": "discard"}},
                "access": {
                    "writer": {"output": "discard"},
                    "include": ["http.log.access"]
                },
                "admin": {
                    "writer": {"output": "discard"},
                    "include": ["admin.api"]
                },
                "not-access": {
                    "writer": {"output": "discard"},
                    "exclude": ["http.log.access"]
                }
            }
        });
        let targets = targets_from(&logging);
        let names: Vec<&str> = targets.iter().map(AccessLogTarget::name).collect();
        assert_eq!(names, vec!["default", "access"]);
    }

    #[test]
    fn default_log_can_exclude_access_entries() {
        let logging = json!({
            "logs": {
                "default": {"exclude": ["http.log.access"]},
                "access": {"include": ["http.log.access"], "writer": {"output": "discard"}}
            }
        });
        let targets = targets_from(&logging);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name(), "access");
    }

    #[test]
    fn targets_and_sinks_are_deterministic_and_buildable() {
        let logging = json!({
            "logs": {
                "zeta": {"writer": {"output": "discard"}},
                "alpha": {"writer": {"output": "discard"}},
                "default": {"writer": {"output": "discard"}}
            }
        });
        let config = LoggingConfig::from_json(&logging).expect("map");
        let names: Vec<&str> = config.targets().iter().map(AccessLogTarget::name).collect();
        assert_eq!(names, vec!["default", "alpha", "zeta"]);

        let sinks = config.build_sinks().expect("build sinks");
        assert_eq!(sinks.len(), 3);
        assert_eq!(sinks[0].name, "default");
        for built in &sinks {
            assert_eq!(
                built.sink.emit(&entry(200, "ok")).expect("emit"),
                EmitOutcome::Written
            );
            built.sink.flush().expect("flush");
            built.sink.close().expect("close");
        }
    }

    #[test]
    fn unknown_and_unsupported_writers_fail_loudly() {
        let unknown = LoggingConfig::from_json(&json!({
            "logs": {"default": {"writer": {"output": "carrier-pigeon"}}}
        }))
        .expect_err("unknown writer");
        assert_eq!(unknown.path(), "logging.logs.default.writer.output");
        assert_eq!(unknown.tracking_id(), Some(LOGGING_TRACKING_ID));
        assert!(
            unknown.message().contains("unknown log writer"),
            "{unknown}"
        );

        let net = LoggingConfig::from_json(&json!({
            "logs": {"default": {"writer": {"output": "net", "address": "tcp/127.0.0.1:9999"}}}
        }))
        .expect_err("net writer unsupported");
        assert_eq!(net.tracking_id(), Some(LOGGING_TRACKING_ID));

        let missing_filename = LoggingConfig::from_json(&json!({
            "logs": {"default": {"writer": {"output": "file"}}}
        }))
        .expect_err("missing filename");
        assert_eq!(
            missing_filename.path(),
            "logging.logs.default.writer.filename"
        );
    }

    #[test]
    fn file_rotation_and_permission_options_are_rejected() {
        for option in ["roll_size_mb", "roll_keep", "roll", "mode", "dir_mode"] {
            let logging = json!({
                "logs": {"default": {"writer": {
                    "output": "file",
                    "filename": "/tmp/access.log",
                    option: 1
                }}}
            });
            let error = LoggingConfig::from_json(&logging).expect_err(option);
            assert!(
                error.path().ends_with(option),
                "path mentions the option: {error}"
            );
            assert_eq!(error.tracking_id(), Some(LOGGING_TRACKING_ID));
            assert!(error.message().contains("not supported"), "{error}");
        }
    }

    #[test]
    fn unknown_and_unsupported_encoders_fail_loudly() {
        for format in ["console", "append", "journald", "nop", "bogus"] {
            let logging = json!({
                "logs": {"default": {"encoder": {"format": format}}}
            });
            let error = LoggingConfig::from_json(&logging).expect_err(format);
            assert_eq!(error.path(), "logging.logs.default.encoder.format");
            assert_eq!(error.tracking_id(), Some(LOGGING_TRACKING_ID));
        }

        let remapped = LoggingConfig::from_json(&json!({
            "logs": {"default": {"encoder": {"format": "json", "message_key": "message"}}}
        }))
        .expect_err("json encoder option");
        assert!(remapped.path().contains("message_key"), "{remapped}");
        assert_eq!(remapped.tracking_id(), Some(LOGGING_TRACKING_ID));
    }

    #[test]
    fn filter_encoder_maps_delete_and_replace_to_access_log_config() {
        let logging = json!({
            "logs": {"default": {
                "writer": {"output": "discard"},
                "encoder": {
                    "format": "filter",
                    "wrap": {"format": "json"},
                    "fields": {
                        "request>headers>Authorization": {"filter": "replace", "value": "***"},
                        "request>headers>X-Debug": {"filter": "delete"},
                        "resp_headers": {"filter": "delete"},
                        "upstream": {"filter": "delete"}
                    }
                }
            }}
        });
        let targets = targets_from(&logging);
        let config = targets[0].sink_config();
        assert!(config
            .encoder
            .exclude
            .contains(&AccessLogField::RespHeaders));
        assert!(config.encoder.exclude.contains(&AccessLogField::Upstream));
        assert_eq!(config.encoder.redaction.headers.len(), 2);

        // Build an inspectable sink from the derived encoder config and verify emission applies it.
        let recorder = RecordingWriter::new();
        let sink = AccessLogSink::to_writer(recorder.clone(), config.encoder.clone())
            .expect("sink from mapped encoder");
        let mut log_entry = entry(200, "hello");
        log_entry
            .resp_headers
            .insert("Content-Type".to_string(), vec!["text/plain".to_string()]);
        sink.emit(&log_entry).expect("emit");
        sink.close().expect("close");
        let text = String::from_utf8(recorder.bytes()).expect("utf8");
        let value: Value = serde_json::from_str(text.trim()).expect("json");
        assert_eq!(
            value["request"]["headers"]["Authorization"][0],
            Value::String("***".to_string())
        );
        assert!(value["request"]["headers"].get("X-Debug").is_none());
        assert!(value.get("resp_headers").is_none());
        assert!(value.get("upstream").is_none());
    }

    #[test]
    fn unsupported_filter_encoders_and_fields_fail_loudly() {
        for filter in [
            "hash",
            "ip_mask",
            "query",
            "cookie",
            "set_cookie",
            "regexp",
            "rename",
            "multi_regexp",
        ] {
            let logging = json!({
                "logs": {"default": {"encoder": {
                    "format": "filter",
                    "fields": {"request>headers>Authorization": {"filter": filter}}
                }}}
            });
            let error = LoggingConfig::from_json(&logging).expect_err(filter);
            assert!(error.path().contains("fields"), "{error}");
            assert_eq!(
                error.tracking_id(),
                Some(LOGGING_TRACKING_ID),
                "filter {filter}"
            );
            assert!(
                error.message().contains(filter),
                "message names the filter: {error}"
            );
        }

        let unknown = LoggingConfig::from_json(&json!({
            "logs": {"default": {"encoder": {
                "format": "filter",
                "fields": {"request>headers>X": {"filter": "not-a-filter"}}
            }}}
        }))
        .expect_err("unknown filter");
        assert!(
            unknown.message().contains("unknown log field filter"),
            "{unknown}"
        );

        let fundamental = LoggingConfig::from_json(&json!({
            "logs": {"default": {"encoder": {
                "format": "filter",
                "fields": {"ts": {"filter": "delete"}}
            }}}
        }))
        .expect_err("fundamental field");
        assert!(
            fundamental.message().contains("fundamental"),
            "{fundamental}"
        );

        let replace_non_header = LoggingConfig::from_json(&json!({
            "logs": {"default": {"encoder": {
                "format": "filter",
                "fields": {"request>uri": {"filter": "replace", "value": "x"}}
            }}}
        }))
        .expect_err("replace non-header");
        assert_eq!(replace_non_header.tracking_id(), Some(LOGGING_TRACKING_ID));

        let nested = LoggingConfig::from_json(&json!({
            "logs": {"default": {"encoder": {
                "format": "filter",
                "wrap": {"format": "filter", "fields": {}}
            }}}
        }))
        .expect_err("nested filter");
        assert_eq!(nested.tracking_id(), Some(LOGGING_TRACKING_ID));
    }

    #[test]
    fn levels_map_case_insensitively_and_filter_entries() {
        for (input, expected) in [
            ("DEBUG", LogLevel::Debug),
            ("info", LogLevel::Info),
            ("WARN", LogLevel::Warn),
            ("error", LogLevel::Error),
            ("panic", LogLevel::Error),
            ("fatal", LogLevel::Error),
        ] {
            let targets = targets_from(&json!({
                "logs": {"default": {"level": input, "writer": {"output": "discard"}}}
            }));
            assert_eq!(targets[0].sink_config().level, Some(expected), "{input}");
        }

        // WARN drops INFO access entries but keeps ERROR (5xx) ones.
        let targets = targets_from(&json!({
            "logs": {"default": {"level": "WARN", "writer": {"output": "discard"}}}
        }));
        let sink = targets[0].build_sink().expect("sink");
        assert_eq!(
            sink.emit(&entry(200, "ok")).expect("emit"),
            EmitOutcome::FilteredOut
        );
        assert_eq!(
            sink.emit(&entry(500, "boom")).expect("emit"),
            EmitOutcome::Written
        );
        assert_eq!(sink.stats().filtered_out, 1);

        let error = LoggingConfig::from_json(&json!({
            "logs": {"default": {"level": "verbose"}}
        }))
        .expect_err("bad level");
        assert_eq!(error.path(), "logging.logs.default.level");

        let placeholder = LoggingConfig::from_json(&json!({
            "logs": {"default": {"level": "{$LOG_LEVEL}"}}
        }))
        .expect_err("placeholder level");
        assert_eq!(placeholder.tracking_id(), Some(LOGGING_TRACKING_ID));
    }

    #[test]
    fn sampling_defaults_and_validation() {
        // Empty sampler applies Caddy's provisioning defaults.
        let targets = targets_from(&json!({"logs": {"default": {"sampling": {}}}}));
        assert_eq!(
            targets[0].sink_config().encoder.sampling,
            Some(SamplingConfig {
                interval: Duration::from_secs(1),
                first: 100,
                thereafter: 100,
            })
        );
        // Explicit values are preserved; zero interval means Caddy's default 1s.
        let targets = targets_from(&json!({
            "logs": {"default": {"sampling": {"interval": 2_000_000_000u64, "first": 5, "thereafter": 10}}}
        }));
        assert_eq!(
            targets[0].sink_config().encoder.sampling,
            Some(SamplingConfig {
                interval: Duration::from_secs(2),
                first: 5,
                thereafter: 10,
            })
        );
        let targets = targets_from(&json!({
            "logs": {"default": {"sampling": {"interval": 0}}}
        }));
        assert_eq!(
            targets[0]
                .sink_config()
                .encoder
                .sampling
                .as_ref()
                .unwrap()
                .interval,
            Duration::from_secs(1)
        );

        let negative = LoggingConfig::from_json(&json!({
            "logs": {"default": {"sampling": {"interval": -1}}}
        }))
        .expect_err("negative interval");
        assert_eq!(negative.path(), "logging.logs.default.sampling.interval");

        let negative_first = LoggingConfig::from_json(&json!({
            "logs": {"default": {"sampling": {"first": -3}}}
        }))
        .expect_err("negative first");
        assert!(negative_first.path().ends_with("sampling.first"));

        let string_interval = LoggingConfig::from_json(&json!({
            "logs": {"default": {"sampling": {"interval": "1s"}}}
        }))
        .expect_err("string interval");
        assert_eq!(string_interval.tracking_id(), Some(LOGGING_TRACKING_ID));
    }

    #[test]
    fn include_exclude_contradictions_are_rejected() {
        let intersection = LoggingConfig::from_json(&json!({
            "logs": {"default": {"include": ["http"], "exclude": ["http"]}}
        }))
        .expect_err("intersection");
        assert!(
            intersection.message().contains("must not intersect"),
            "{intersection}"
        );

        let unrelated = LoggingConfig::from_json(&json!({
            "logs": {"default": {"include": ["admin.api"], "exclude": ["http.log"]}}
        }))
        .expect_err("unrelated namespaces");
        assert!(
            unrelated.message().contains("superspace or subspace"),
            "{unrelated}"
        );

        let empty = LoggingConfig::from_json(&json!({
            "logs": {"default": {"include": [""]}}
        }))
        .expect_err("empty filter");
        assert!(empty.path().contains("include[0]"), "{empty}");
    }

    #[test]
    fn logger_prefix_semantics_match_caddy() {
        let accepts = |include: &[&str], exclude: &[&str]| {
            logger_allowed(
                ACCESS_LOG_LOGGER,
                &include.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                &exclude.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        };
        assert!(accepts(&[], &[]));
        assert!(accepts(&["http"], &[]));
        assert!(accepts(&["http.log.access"], &[]));
        assert!(accepts(&["http.log"], &[])); // prefixes match whole namespace segments
        assert!(!accepts(&["http.lo"], &[])); // partial segments do not match
        assert!(!accepts(&["admin"], &[]));
        assert!(!accepts(&[], &["http"]));
        // The longest matching namespace wins when both lists are populated (Caddy semantics).
        assert!(!accepts(&["http"], &["http.log"]));
        assert!(accepts(&["http.log"], &["http"]));
        assert!(accepts(&["http.log.access"], &["http"]));
        assert!(!accepts(&["http"], &["http.log.access"]));
    }

    #[test]
    fn unsupported_base_options_and_sink_log_are_rejected() {
        let sink = LoggingConfig::from_json(&json!({
            "sink": {"writer": {"output": "stderr"}}
        }))
        .expect_err("sink log");
        assert_eq!(sink.path(), "logging.sink");
        assert_eq!(sink.tracking_id(), Some(LOGGING_TRACKING_ID));

        let caller = LoggingConfig::from_json(&json!({
            "logs": {"default": {"with_caller": true}}
        }))
        .expect_err("with_caller");
        assert!(caller.path().ends_with("with_caller"), "{caller}");

        let core = LoggingConfig::from_json(&json!({
            "logs": {"default": {"core": {"module": "some_core"}}}
        }))
        .expect_err("core");
        assert!(core.path().ends_with("core"), "{core}");

        let stacktrace = LoggingConfig::from_json(&json!({
            "logs": {"default": {"with_stacktrace": "ERROR"}}
        }))
        .expect_err("with_stacktrace");
        assert!(
            stacktrace.path().ends_with("with_stacktrace"),
            "{stacktrace}"
        );

        let unknown = LoggingConfig::from_json(&json!({"bogus_top_level": true}))
            .expect_err("unknown logging field");
        assert!(unknown.path().contains("bogus_top_level"), "{unknown}");
    }

    #[test]
    fn from_config_uses_the_logging_section() {
        let config = Config::from_value(json!({
            "logging": {
                "logs": {"default": {"writer": {"output": "discard"}}}
            },
            "apps": {"http": {"servers": {"srv0": {"listen": [":8080"], "routes": []}}}}
        }))
        .expect("config");
        let mapping = LoggingConfig::from_config(&config).expect("map");
        assert_eq!(mapping.targets().len(), 1);
        assert_eq!(
            mapping.targets()[0].sink_config().output,
            AccessLogOutput::Discard
        );
    }

    #[test]
    fn buffer_size_override_is_validated_and_applied() {
        let mapping = LoggingConfig::from_logging(None).expect("defaults");
        let error = mapping
            .clone()
            .with_buffer_bytes(0)
            .expect_err("zero buffer");
        assert!(error.path().ends_with("writer.buffer_bytes"), "{error}");

        let mapping = mapping.with_buffer_bytes(8 * 1024).expect("override");
        assert_eq!(mapping.targets()[0].sink_config().buffer_bytes, 8 * 1024);
        mapping.targets()[0]
            .build_sink()
            .expect("build with override");
    }

    #[test]
    fn core_logging_model_round_trips_the_supported_json() {
        let value = json!({
            "logs": {
                "default": {
                    "writer": {"output": "file", "filename": "/tmp/access.log"},
                    "encoder": {"format": "json"},
                    "level": "INFO",
                    "sampling": {"interval": 1000000000, "first": 10, "thereafter": 20}
                }
            }
        });
        let logging: Logging = serde_json::from_value(value.clone()).expect("decode");
        assert_eq!(serde_json::to_value(&logging).expect("encode"), value);
    }

    /// Minimal recording writer for asserting emitted bytes.
    #[derive(Clone, Default)]
    struct RecordingWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl RecordingWriter {
        fn new() -> Self {
            Self::default()
        }

        fn bytes(&self) -> Vec<u8> {
            self.bytes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
