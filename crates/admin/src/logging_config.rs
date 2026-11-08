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
//! * `writer.output`: `stderr` (default), `stdout`, `discard`, `file` and `net`.
//!   * File writers support `mode`/`dir_mode` (octal strings), `roll` (default true),
//!     `roll_size_mb`, `roll_keep`, `roll_keep_days`, and time-based rotation via `roll_interval`
//!     (ns), `roll_minutes` (UTC clock minutes) and `roll_at` (UTC `HH:MM` times). Missing parent
//!     directories are created (with `dir_mode`). Rotation renames the current file to
//!     `<filename>.<unix-millis>`; compression (`roll_compression` other than `none`,
//!     `roll_gzip`), `roll_local_time` (no timezone database) and `backup_time_format` are
//!     rejected loudly. Time schedules are UTC.
//!   * Net writers support `address` (`host:port` or Caddy's `tcp/`/`udp/`/`unix/`/`unixgram/`
//!     prefix), `dial_timeout` (ns, JSON number) and `soft_start`; TCP/Unix streams reconnect
//!     once and retry the failed line, and `soft_start` falls back to stderr while reconnecting.
//! * `encoder.format`: `json` (also the default when omitted), `console`, or `filter` wrapping
//!   `json`/`console`. Encoders support `message_key`, `level_key`, `time_key`, `name_key`,
//!   `line_ending`, `time_format` (wall_milli/wall/wall_nano/iso8601/rfc3339/rfc3339_nano/
//!   unix_seconds_float/unix_milli_float/unix_nano/common_log), `level_format`
//!   (lower/upper/color) and `duration_format` (seconds/ms/ns/string); `time_local=true` (no
//!   timezone database) and `caller_key`/`stacktrace_key` (no caller fields) are rejected loudly.
//!   The console encoder defaults to Caddy's console framing (colored level, UTC `wall_milli`
//!   time, spaced JSON fields); `append`/`journald`/`nop` encoders are rejected loudly.
//! * Filter fields: `delete` of a selectable top-level entry field maps to
//!   [`AccessLogConfig::exclude`](crate::AccessLogConfig), `delete`/`replace` of
//!   `request>headers>Name` or `resp_headers>Name` maps to
//!   [`RedactionPolicy`](crate::RedactionPolicy) header rules, and generic `delete`, `replace`,
//!   `rename`, `hash`, `ip_mask`, `query`, `cookie`, `set_cookie`, `regexp` and `multi_regexp`
//!   operations map to [`AccessLogConfig::filters`](crate::AccessLogConfig). `hash` is Caddy's
//!   SHA-256 first-4-bytes filter; `ip_mask` supports `ipv4_cidr`/`ipv6_cidr`; `query`/`cookie`/
//!   `set_cookie` apply replace/hash/delete actions; `regexp`/`multi_regexp` use the shared
//!   linear-time `regex` engine (see [`caddy_rs_core::regex`]) with Go-style `$N` expansion —
//!   unsupported regexp constructs fail loudly.
//!   Nested filter encoders are rejected loudly.
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
//! ## Per-request level override
//!
//! Caddy's `log_level` Caddyfile directive is not part of the `logging` JSON: it compiles to a
//! `vars` handler that sets the `log_level` request variable, and the server applies it while
//! building each access entry. The status default (`INFO`, or `ERROR` for `status >= 500`) is
//! *replaced* by a valid `DEBUG`/`INFO`/`WARN`/`ERROR` value, which both raises and lowers
//! verbosity; an absent or invalid variable keeps the default. This module models that override
//! ([`LOG_LEVEL_VAR`], [`LOG_LEVEL_NAMES`], [`LogLevelOverride`], [`access_log_level`],
//! [`apply_access_log_level`]) for the server and the Caddyfile adapter; the runtime hook that
//! captures the request variable lives in the HTTP/server crates.
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
    AccessLogConfig, AccessLogEntry, AccessLogField, HeaderRedaction, HeaderTarget, LogLevel,
    RedactionPolicy, SamplingConfig, ACCESS_LOG_LOGGER,
};
use crate::access_log::{
    FieldFilter, FieldFilterOperation, FilterAction, FilterActionKind, RegexpOperation,
};
use crate::sink::{
    AccessLogFormat, AccessLogOutput, AccessLogSink, AccessLogSinkConfig, FileWriterOptions,
    NetProtocol, NetWriterConfig, DEFAULT_ACCESS_LOG_BUFFER_BYTES,
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

    /// Validate the logging section of a decoded configuration without opening any sink.
    ///
    /// This is the hook the core/CLI configuration validation path should call (it applies the
    /// same checks and located errors as [`LoggingConfig::from_config`], notably Caddy's
    /// include/exclude contradiction rules). Keeping it separate lets the validator reject an
    /// adapted JSON document before any writer is opened.
    pub fn validate_config(config: &Config) -> Result<(), LoggingConfigError> {
        Self::from_config(config).map(|_| ())
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

/// Render a name list for located validation messages (backticked, comma-separated).
fn quote_list(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
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
    // Port of Caddy's `CustomLog.provision` contradiction checks. The located error names the
    // offending include entry (Caddy's message does not carry a JSON path) and, for the nesting
    // rule, the whole exclude list so both conflicting rules are visible.
    for (index, allowed) in include.iter().enumerate() {
        if exclude.contains(allowed) {
            return Err(LoggingConfigError::new(
                format!("{path}.include[{index}]"),
                format!(
                    "include and exclude must not intersect, but found `{allowed}` in both lists \
                     (exclude: {})",
                    quote_list(exclude)
                ),
            ));
        }
    }
    for (index, allowed) in include.iter().enumerate() {
        let nested = exclude.iter().any(|denied| {
            allowed.starts_with(&format!("{denied}.")) || denied.starts_with(&format!("{allowed}."))
        });
        if !nested {
            return Err(LoggingConfigError::new(
                format!("{path}.include[{index}]"),
                format!(
                    "when both include and exclude are populated, each element must be a \
                     superspace or subspace of one in the other list; check `{allowed}` in \
                     include against exclude {} (neither list entry is a parent or child \
                     namespace of it)",
                    quote_list(exclude)
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
    let writer = parse_writer(&path, log.base.writer.as_ref())?;
    let encoder = parse_encoder(&path, log.base.encoder.as_ref())?;
    let level = parse_level(&path, log.base.level.as_deref())?;
    let sampling = parse_sampling(&path, log.base.sampling.as_ref())?;

    let config = AccessLogSinkConfig {
        output: writer.output,
        filename: writer.filename,
        format: encoder.format,
        file: writer.file,
        net: writer.net,
        encoder: AccessLogConfig {
            filters: encoder.filters,
            include: Vec::new(),
            exclude: encoder.exclude,
            log_credentials: false,
            redaction: encoder.redaction,
            sampling,
            message_key: encoder.message_key,
            level_key: encoder.level_key,
            time_key: encoder.time_key,
            name_key: encoder.name_key,
            line_ending: encoder.line_ending,
            time_format: encoder.time_format,
            time_local: encoder.time_local,
            level_format: encoder.level_format,
            duration_format: encoder.duration_format,
        },
        buffer_bytes: DEFAULT_ACCESS_LOG_BUFFER_BYTES,
        level,
    };
    config.validate().map_err(|error| {
        LoggingConfigError::new(
            format!("{path}.{}", error.path()),
            error.message().to_string(),
        )
    })?;
    Ok(config)
}

/// Parsed `logging.logs.<name>.writer` selection.
struct WriterSelection {
    output: AccessLogOutput,
    filename: Option<PathBuf>,
    file: FileWriterOptions,
    net: Option<NetWriterConfig>,
}

fn parse_writer(
    path: &str,
    writer: Option<&LogWriter>,
) -> Result<WriterSelection, LoggingConfigError> {
    let Some(writer) = writer else {
        return Ok(WriterSelection {
            output: AccessLogOutput::Stderr,
            filename: None,
            file: FileWriterOptions::default(),
            net: None,
        });
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
            Ok(WriterSelection {
                output: destination,
                filename: None,
                file: FileWriterOptions::default(),
                net: None,
            })
        }
        "file" => {
            let filename = match writer.extra.get("filename") {
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
            let mut file = FileWriterOptions::default();
            for (field, value) in &writer.extra {
                let field_path = format!("{writer_path}.{field}");
                match field.as_str() {
                    "filename" => {}
                    "mode" => file.mode = Some(parse_octal_mode(value, &field_path)?),
                    "dir_mode" => {
                        if let Some(value) = value.as_str() {
                            if value == "inherit" || value == "from_file" {
                                return Err(LoggingConfigError::unsupported(
                                    field_path,
                                    format!(
                                        "file writer `dir_mode: {value:?}` is not implemented                                          (use a numeric octal mode)"
                                    ),
                                ));
                            }
                        }
                        file.dir_mode = Some(parse_octal_mode(value, &field_path)?);
                    }
                    "roll" => {
                        file.roll = value.as_bool().ok_or_else(|| {
                            LoggingConfigError::new(&field_path, "`roll` must be a boolean")
                        })?
                    }
                    "roll_size_mb" => file.roll_size_mb = Some(parse_u64(value, &field_path)?),
                    "roll_keep" => {
                        file.roll_keep =
                            usize::try_from(parse_u64(value, &field_path)?).map_err(|_| {
                                LoggingConfigError::new(
                                    &field_path,
                                    "`roll_keep` is too large for this platform",
                                )
                            })?
                    }
                    "roll_keep_days" => file.roll_keep_days = Some(parse_u64(value, &field_path)?),
                    "roll_interval" => file.roll_interval_ns = Some(parse_u64(value, &field_path)?),
                    "roll_minutes" => {
                        let Some(values) = value.as_array() else {
                            return Err(LoggingConfigError::new(
                                &field_path,
                                "`roll_minutes` must be an array of integers 0-59",
                            ));
                        };
                        let mut minutes = Vec::with_capacity(values.len());
                        for value in values {
                            let Some(minute) = value.as_u64().and_then(|v| u8::try_from(v).ok())
                            else {
                                return Err(LoggingConfigError::new(
                                    &field_path,
                                    "`roll_minutes` entries must be integers 0-59",
                                ));
                            };
                            if minute > 59 {
                                return Err(LoggingConfigError::new(
                                    &field_path,
                                    "`roll_minutes` entries must be 0-59",
                                ));
                            }
                            minutes.push(u32::from(minute));
                        }
                        file.roll_minutes = Some(minutes);
                    }
                    "roll_at" => {
                        let Some(values) = value.as_array() else {
                            return Err(LoggingConfigError::new(
                                &field_path,
                                "`roll_at` must be an array of \"HH:MM\" strings",
                            ));
                        };
                        let mut times = Vec::with_capacity(values.len());
                        for value in values {
                            let Some(text) = value.as_str() else {
                                return Err(LoggingConfigError::new(
                                    &field_path,
                                    "`roll_at` entries must be \"HH:MM\" strings",
                                ));
                            };
                            let valid = text.len() == 5
                                && text.as_bytes()[2] == b':'
                                && text[..2].parse::<u32>().map(|h| h < 24).unwrap_or(false)
                                && text[3..].parse::<u32>().map(|m| m < 60).unwrap_or(false);
                            if !valid {
                                return Err(LoggingConfigError::new(
                                    &field_path,
                                    format!("invalid `roll_at` time `{text}` (expected HH:MM)"),
                                ));
                            }
                            times.push(text.to_string());
                        }
                        file.roll_at = Some(times);
                    }
                    "roll_compression" => {
                        if value.as_str() != Some("none") {
                            return Err(LoggingConfigError::unsupported(
                                field_path,
                                "roll_compression is only supported with `none` (no compression \
                                 dependencies are available offline; gzip/zstd are rejected \
                                 loudly)",
                            ));
                        }
                    }
                    "roll_gzip" => {
                        if value.as_bool() != Some(false) {
                            return Err(LoggingConfigError::unsupported(
                                field_path,
                                "roll_gzip compression is not supported (use \
                                 `roll_compression: \"none\"`; gzip is rejected loudly)",
                            ));
                        }
                    }
                    "roll_local_time" => {
                        if value.as_bool() != Some(false) {
                            return Err(LoggingConfigError::unsupported(
                                field_path,
                                "roll_local_time=true is not supported by this build (rotation \
                                 schedules use UTC; no timezone database)",
                            ));
                        }
                    }
                    "backup_time_format" => {
                        return Err(LoggingConfigError::unsupported(
                            field_path,
                            "backup_time_format is not implemented (caddy-rs names rotated files \
                             `<filename>.<unix-millis>`)",
                        ))
                    }
                    other => {
                        return Err(LoggingConfigError::unsupported(
                            format!("{writer_path}.{other}"),
                            format!("file writer option `{other}` is not supported"),
                        ))
                    }
                }
            }
            Ok(WriterSelection {
                output: AccessLogOutput::File,
                filename: Some(filename),
                file,
                net: None,
            })
        }
        "net" => {
            let address = match writer.extra.get("address") {
                Some(Value::String(address)) if !address.is_empty() => address.clone(),
                Some(Value::String(_)) => {
                    return Err(LoggingConfigError::new(
                        format!("{writer_path}.address"),
                        "net writer `address` must not be empty",
                    ))
                }
                Some(_) => {
                    return Err(LoggingConfigError::new(
                        format!("{writer_path}.address"),
                        "net writer `address` must be a string",
                    ))
                }
                None => {
                    return Err(LoggingConfigError::new(
                        format!("{writer_path}.address"),
                        "net writer requires an `address`",
                    ))
                }
            };
            let (network, address) =
                parse_network_address(&address, &format!("{writer_path}.address"))?;
            let mut net = NetWriterConfig {
                address,
                network,
                dial_timeout_ns: None,
                soft_start: false,
            };
            for (field, value) in &writer.extra {
                if field == "address" {
                    continue;
                }
                let field_path = format!("{writer_path}.{field}");
                match field.as_str() {
                    "dial_timeout" => net.dial_timeout_ns = Some(parse_u64(value, &field_path)?),
                    "soft_start" => {
                        net.soft_start = value.as_bool().ok_or_else(|| {
                            LoggingConfigError::new(&field_path, "`soft_start` must be a boolean")
                        })?
                    }
                    other => {
                        return Err(LoggingConfigError::unsupported(
                            field_path,
                            format!("net writer option `{other}` is not supported"),
                        ))
                    }
                }
            }
            Ok(WriterSelection {
                output: AccessLogOutput::Net,
                filename: None,
                file: FileWriterOptions::default(),
                net: Some(net),
            })
        }
        other => Err(LoggingConfigError::unsupported(
            format!("{writer_path}.output"),
            format!("unknown log writer `{other}` (supported: stderr, stdout, discard, file, net)"),
        )),
    }
}

fn parse_octal_mode(value: &Value, path: &str) -> Result<u32, LoggingConfigError> {
    let Some(text) = value.as_str() else {
        return Err(LoggingConfigError::new(
            path,
            "file mode must be an octal string like \"0600\"",
        ));
    };
    u32::from_str_radix(text.trim_start_matches("0o"), 8).map_err(|error| {
        LoggingConfigError::new(path, format!("invalid octal file mode `{text}`: {error}"))
    })
}

fn parse_u64(value: &Value, path: &str) -> Result<u64, LoggingConfigError> {
    value
        .as_u64()
        .ok_or_else(|| LoggingConfigError::new(path, "expected a non-negative integer"))
}

/// Parse Caddy's network address (`tcp/host:port`, `udp/host:port`, `host:port`; unix unsupported).
fn parse_network_address(
    address: &str,
    path: &str,
) -> Result<(NetProtocol, String), LoggingConfigError> {
    match address.split_once('/') {
        None => Ok((NetProtocol::Tcp, address.to_string())),
        Some((prefix, rest)) => match prefix {
            "tcp" | "tcp4" | "tcp6" => {
                if prefix != "tcp" {
                    return Err(LoggingConfigError::unsupported(
                        path,
                        format!("net writer network `{prefix}` is not supported (use tcp/udp)"),
                    ));
                }
                Ok((NetProtocol::Tcp, rest.to_string()))
            }
            "udp" | "udp4" | "udp6" => {
                if prefix != "udp" {
                    return Err(LoggingConfigError::unsupported(
                        path,
                        format!("net writer network `{prefix}` is not supported (use tcp/udp)"),
                    ));
                }
                Ok((NetProtocol::Udp, rest.to_string()))
            }
            "unix" => Ok((NetProtocol::Unix, rest.to_string())),
            "unixgram" => Ok((NetProtocol::Unixgram, rest.to_string())),
            other => Err(LoggingConfigError::new(
                path,
                format!("unknown net writer network prefix `{other}`"),
            )),
        },
    }
}

/// Parsed `logging.logs.<name>.encoder` selection.
#[derive(Default)]
struct EncoderSelection {
    format: AccessLogFormat,
    exclude: Vec<AccessLogField>,
    redaction: RedactionPolicy,
    filters: Vec<FieldFilter>,
    message_key: Option<String>,
    level_key: Option<String>,
    time_key: Option<String>,
    name_key: Option<String>,
    line_ending: Option<String>,
    time_format: Option<String>,
    time_local: bool,
    level_format: Option<String>,
    duration_format: Option<String>,
}
fn parse_encoder(
    path: &str,
    encoder: Option<&LogEncoder>,
) -> Result<EncoderSelection, LoggingConfigError> {
    let Some(encoder) = encoder else {
        return Ok(EncoderSelection::default());
    };
    let encoder_path = format!("{path}.encoder");
    let format = encoder.format.as_deref().ok_or_else(|| {
        LoggingConfigError::new(
            format!("{encoder_path}.format"),
            "encoder module is missing its inline `format` key",
        )
    })?;
    match format {
        "json" => parse_json_encoder_options(&encoder_path, &encoder.extra, AccessLogFormat::Json),
        "console" => {
            parse_json_encoder_options(&encoder_path, &encoder.extra, AccessLogFormat::Console)
        }
        "filter" => parse_filter_encoder(&encoder_path, &encoder.extra),
        "append" | "journald" | "nop" => Err(LoggingConfigError::unsupported(
            format!("{encoder_path}.format"),
            format!(
                "the `{format}` log encoder is not supported by this build's access-log sink \
                 (supported: json, console, filter-wrapping-json/console)"
            ),
        )),
        other => Err(LoggingConfigError::unsupported(
            format!("{encoder_path}.format"),
            format!(
                "unknown log encoder `{other}` (supported: json, console, \
                 filter-wrapping-json/console)"
            ),
        )),
    }
}

fn parse_json_encoder_options(
    path: &str,
    extra: &BTreeMap<String, Value>,
    format: AccessLogFormat,
) -> Result<EncoderSelection, LoggingConfigError> {
    let mut selection = EncoderSelection {
        format,
        ..EncoderSelection::default()
    };
    for (field, value) in extra {
        let field_path = format!("{path}.{field}");
        let string = |required: bool| -> Result<Option<String>, LoggingConfigError> {
            match value {
                Value::String(text) if !text.is_empty() => Ok(Some(text.clone())),
                Value::String(_) if required => Err(LoggingConfigError::new(
                    &field_path,
                    "encoder key names must not be empty",
                )),
                Value::String(_) => Ok(None),
                _ => Err(LoggingConfigError::new(&field_path, "expected a string")),
            }
        };
        match field.as_str() {
            "message_key" => selection.message_key = string(true)?,
            "level_key" => selection.level_key = string(true)?,
            "time_key" => selection.time_key = string(true)?,
            "name_key" => selection.name_key = string(true)?,
            "line_ending" => selection.line_ending = Some(string(true)?.unwrap_or_default()),
            "caller_key" | "stacktrace_key" => {
                return Err(LoggingConfigError::unsupported(
                    field_path,
                    format!(
                        "`{field}` is not implemented: access entries have no caller/stacktrace \
                         fields"
                    ),
                ))
            }
            "time_format" => selection.time_format = Some(string(true)?.unwrap_or_default()),
            "duration_format" => {
                selection.duration_format = Some(string(true)?.unwrap_or_default())
            }
            "level_format" => selection.level_format = Some(string(true)?.unwrap_or_default()),
            "time_local" => {
                let local = value.as_bool().ok_or_else(|| {
                    LoggingConfigError::new(&field_path, "`time_local` must be a boolean")
                })?;
                if local {
                    return Err(LoggingConfigError::unsupported(
                        field_path,
                        "time_local=true is not supported by this build (no timezone database); \
                         timestamps are UTC",
                    ));
                }
                selection.time_local = false;
            }
            other => {
                return Err(LoggingConfigError::unsupported(
                    field_path,
                    format!("json encoder option `{other}` is not supported"),
                ))
            }
        }
    }
    Ok(selection)
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

    let mut selection = match extra.get("wrap") {
        None => EncoderSelection::default(),
        Some(Value::Object(wrapped)) => {
            let wrapped_format =
                wrapped
                    .get("format")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        LoggingConfigError::new(
                            format!("{path}.wrap.format"),
                            "filter encoder `wrap` is missing its inline `format` key",
                        )
                    })?;
            let wrapped_extra: BTreeMap<String, Value> = wrapped
                .iter()
                .filter(|(key, _)| key.as_str() != "format")
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            match wrapped_format {
                "json" => parse_json_encoder_options(
                    &format!("{path}.wrap"),
                    &wrapped_extra,
                    AccessLogFormat::Json,
                )?,
                "console" => parse_json_encoder_options(
                    &format!("{path}.wrap"),
                    &wrapped_extra,
                    AccessLogFormat::Console,
                )?,
                "filter" => {
                    return Err(LoggingConfigError::unsupported(
                        format!("{path}.wrap.format"),
                        "nested filter encoders are not supported by this build",
                    ))
                }
                other => {
                    return Err(LoggingConfigError::unsupported(
                        format!("{path}.wrap.format"),
                        format!(
                            "filter encoder wraps `{other}`, but only json and console are \
                             supported"
                        ),
                    ))
                }
            }
        }
        Some(_) => {
            return Err(LoggingConfigError::new(
                format!("{path}.wrap"),
                "filter encoder `wrap` must be an encoder object",
            ))
        }
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
    let segments = split_filter_path(field_path, &filter_path)?;
    if matches!(segments[0].as_str(), "ts" | "level" | "logger" | "msg") {
        return Err(LoggingConfigError::new(
            format!("{filter_path}.filter"),
            format!("fundamental log field `{}` cannot be filtered", segments[0]),
        ));
    }
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
            if let Some(field) = access_log_field(field_path) {
                selection.exclude.push(field);
                return Ok(());
            }
            selection.filters.push(FieldFilter {
                path: segments,
                operation: FieldFilterOperation::Delete,
            });
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
            if let Some((header, target)) = header_field_target(field_path) {
                selection.redaction.headers.push(HeaderRedaction::Replace {
                    header,
                    value,
                    target,
                });
                return Ok(());
            }
            selection.filters.push(FieldFilter {
                path: segments,
                operation: FieldFilterOperation::Replace { value },
            });
            Ok(())
        }
        "rename" => {
            reject_filter_options(&filter_path, filter_object, filter_name, &["name"])?;
            let name = match filter_object.get("name") {
                Some(Value::String(name)) if !name.is_empty() => name.clone(),
                Some(_) => {
                    return Err(LoggingConfigError::new(
                        format!("{filter_path}.name"),
                        "rename filter `name` must be a non-empty string",
                    ))
                }
                None => {
                    return Err(LoggingConfigError::new(
                        format!("{filter_path}.name"),
                        "rename filter requires a `name`",
                    ))
                }
            };
            selection.filters.push(FieldFilter {
                path: segments,
                operation: FieldFilterOperation::Rename { name },
            });
            Ok(())
        }
        "hash" => {
            reject_filter_options(&filter_path, filter_object, filter_name, &[])?;
            selection.filters.push(FieldFilter {
                path: segments,
                operation: FieldFilterOperation::Hash,
            });
            Ok(())
        }
        "ip_mask" => {
            reject_filter_options(
                &filter_path,
                filter_object,
                filter_name,
                &["ipv4_cidr", "ipv6_cidr"],
            )?;
            let mask = |field: &str| -> Result<Option<u8>, LoggingConfigError> {
                match filter_object.get(field) {
                    None | Some(Value::Null) => Ok(None),
                    Some(value) => value
                        .as_u64()
                        .and_then(|mask| u8::try_from(mask).ok())
                        .ok_or_else(|| {
                            LoggingConfigError::new(
                                format!("{filter_path}.{field}"),
                                "expected a CIDR prefix length (integer)",
                            )
                        })
                        .map(Some),
                }
            };
            selection.filters.push(FieldFilter {
                path: segments,
                operation: FieldFilterOperation::IpMask {
                    v4_mask: mask("ipv4_cidr")?,
                    v6_mask: mask("ipv6_cidr")?,
                },
            });
            Ok(())
        }
        "query" => {
            reject_filter_options(&filter_path, filter_object, filter_name, &["actions"])?;
            let actions = parse_filter_actions(&filter_path, filter_object, "parameter")?;
            selection.filters.push(FieldFilter {
                path: segments,
                operation: FieldFilterOperation::Query { actions },
            });
            Ok(())
        }
        "cookie" | "set_cookie" => {
            reject_filter_options(&filter_path, filter_object, filter_name, &["actions"])?;
            let actions = parse_filter_actions(&filter_path, filter_object, "name")?;
            selection.filters.push(FieldFilter {
                path: segments,
                operation: if filter_name == "cookie" {
                    FieldFilterOperation::Cookie { actions }
                } else {
                    FieldFilterOperation::SetCookie { actions }
                },
            });
            Ok(())
        }
        "regexp" => {
            reject_filter_options(
                &filter_path,
                filter_object,
                filter_name,
                &["regexp", "value"],
            )?;
            let pattern = filter_object
                .get("regexp")
                .and_then(Value::as_str)
                .filter(|pattern| !pattern.is_empty())
                .ok_or_else(|| {
                    LoggingConfigError::new(
                        format!("{filter_path}.regexp"),
                        "regexp filter requires a non-empty `regexp` pattern",
                    )
                })?;
            let replacement = filter_object
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or("");
            caddy_rs_core::regex::Regex::new(pattern).map_err(|error| {
                LoggingConfigError::new(
                    format!("{filter_path}.regexp"),
                    format!("invalid regexp filter pattern: {error}"),
                )
            })?;
            selection.filters.push(FieldFilter {
                path: segments,
                operation: FieldFilterOperation::Regexp {
                    pattern: pattern.to_string(),
                    replacement: replacement.to_string(),
                },
            });
            Ok(())
        }
        "multi_regexp" => {
            reject_filter_options(&filter_path, filter_object, filter_name, &["operations"])?;
            let Some(Value::Array(operations)) = filter_object.get("operations") else {
                return Err(LoggingConfigError::new(
                    format!("{filter_path}.operations"),
                    "multi_regexp requires an `operations` array",
                ));
            };
            if operations.is_empty() {
                return Err(LoggingConfigError::new(
                    format!("{filter_path}.operations"),
                    "multi_regexp requires at least one operation",
                ));
            }
            let parsed: Vec<RegexpOperation> = operations
                .iter()
                .enumerate()
                .map(|(index, operation)| {
                    let operation_path = format!("{filter_path}.operations[{index}]");
                    let object = operation.as_object().ok_or_else(|| {
                        LoggingConfigError::new(
                            &operation_path,
                            "a multi_regexp operation must be an object",
                        )
                    })?;
                    let pattern = object
                        .get("regexp")
                        .and_then(Value::as_str)
                        .filter(|pattern| !pattern.is_empty())
                        .ok_or_else(|| {
                            LoggingConfigError::new(
                                format!("{operation_path}.regexp"),
                                "multi_regexp operation requires a non-empty `regexp`",
                            )
                        })?;
                    if pattern.len() > 1000 {
                        return Err(LoggingConfigError::new(
                            format!("{operation_path}.regexp"),
                            "multi_regexp patterns must be at most 1000 characters",
                        ));
                    }
                    caddy_rs_core::regex::Regex::new(pattern).map_err(|error| {
                        LoggingConfigError::new(
                            format!("{operation_path}.regexp"),
                            format!("invalid multi_regexp pattern: {error}"),
                        )
                    })?;
                    let replacement = object
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    Ok(RegexpOperation {
                        pattern: pattern.to_string(),
                        replacement,
                    })
                })
                .collect::<Result<_, LoggingConfigError>>()?;
            selection.filters.push(FieldFilter {
                path: segments,
                operation: FieldFilterOperation::MultiRegexp { operations: parsed },
            });
            Ok(())
        }
        other => Err(LoggingConfigError::new(
            format!("{filter_path}.filter"),
            format!(
                "unknown log field filter `{other}` (supported: delete, replace, rename, hash, \
                 ip_mask)"
            ),
        )),
    }
}

/// Parse Caddy query/cookie filter `actions` arrays.
fn parse_filter_actions(
    filter_path: &str,
    filter_object: &serde_json::Map<String, Value>,
    name_field: &str,
) -> Result<Vec<FilterAction>, LoggingConfigError> {
    let Some(Value::Array(actions)) = filter_object.get("actions") else {
        return Err(LoggingConfigError::new(
            format!("{filter_path}.actions"),
            "filter requires an `actions` array",
        ));
    };
    if actions.is_empty() {
        return Err(LoggingConfigError::new(
            format!("{filter_path}.actions"),
            "filter requires at least one action",
        ));
    }
    actions
        .iter()
        .enumerate()
        .map(|(index, action)| {
            let action_path = format!("{filter_path}.actions[{index}]");
            let object = action.as_object().ok_or_else(|| {
                LoggingConfigError::new(&action_path, "a filter action must be an object")
            })?;
            let kind = match object.get("type").and_then(Value::as_str) {
                Some("replace") => FilterActionKind::Replace,
                Some("hash") => FilterActionKind::Hash,
                Some("delete") => FilterActionKind::Delete,
                Some(other) => {
                    return Err(LoggingConfigError::new(
                        format!("{action_path}.type"),
                        format!(
                            "unknown filter action `{other}` (supported: replace, hash, delete)"
                        ),
                    ))
                }
                None => {
                    return Err(LoggingConfigError::new(
                        format!("{action_path}.type"),
                        "filter action requires a `type`",
                    ))
                }
            };
            let name = object
                .get(name_field)
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    LoggingConfigError::new(
                        format!("{action_path}.{name_field}"),
                        format!("filter action requires a non-empty `{name_field}`"),
                    )
                })?;
            let value = object
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            Ok(FilterAction {
                action: kind,
                name: name.to_string(),
                value,
            })
        })
        .collect()
}

/// Split a Caddy filter field path (`request>headers>User-Agent`) into segments.
fn split_filter_path(
    field_path: &str,
    filter_path: &str,
) -> Result<Vec<String>, LoggingConfigError> {
    let segments: Vec<String> = field_path.split('>').map(str::to_string).collect();
    if segments.is_empty() || segments.iter().any(String::is_empty) {
        return Err(LoggingConfigError::new(
            format!("{filter_path}.filter"),
            "filter field path must not be empty",
        ));
    }
    Ok(segments)
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

/// Caddy's per-request access-log level override (the `log_level` request variable).
///
/// Caddy's `log_level` Caddyfile directive compiles to a `vars` handler that writes the
/// [`LOG_LEVEL_VAR`] request variable (`caddyconfig/httpcaddyfile/builtins.go:1277`,
/// `modules/caddyhttp/logging.go:315-317`). When the access entry is built, `Server.logRequest`
/// derives the default level from the response status (`INFO`, or `ERROR` for `status >= 500`) and
/// then *replaces* it with the parsed variable when the value is valid
/// (`modules/caddyhttp/server.go:1271-1282`). The override therefore raises and lowers verbosity
/// alike: `DEBUG` on a `200` logs at DEBUG, `ERROR` on a `200` is suppressed by an INFO threshold,
/// and `INFO` on a `500` logs at INFO.
pub const LOG_LEVEL_VAR: &str = "log_level";

/// The level names Caddy accepts for a `log_level` override, in severity order.
///
/// `zapcore.ParseLevel` also accepts `DPANIC`, `PANIC` and `FATAL`, but both the Caddyfile parser
/// and `Server.logRequest` restrict the override to `DEBUG..=ERROR`
/// (`caddyconfig/httpcaddyfile/builtins.go:1273`, `modules/caddyhttp/server.go:1278`).
pub const LOG_LEVEL_NAMES: [&str; 4] = ["DEBUG", "INFO", "WARN", "ERROR"];

/// A validated per-request access-log level override: Caddy's `log_level` request variable.
///
/// Parse with [`LogLevelOverride::parse`] for a located error (the Caddyfile `log_level` directive
/// and any strict validator need this), or with [`LogLevelOverride::from_request_var`] for Caddy's
/// request-time behaviour, where an absent or invalid variable is ignored and the status-derived
/// level is kept. Apply it to an entry with [`apply_access_log_level`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogLevelOverride(LogLevel);

impl LogLevelOverride {
    /// Parse one of the names Caddy accepts for `log_level`.
    ///
    /// The match is case-insensitive, mirroring `zapcore.ParseLevel` (which retries the
    /// lower-cased text), then restricted to `DEBUG..=ERROR` like both Caddy call sites. `DPANIC`,
    /// `PANIC` and `FATAL` are rejected: zap parses them, but Caddy's range check refuses them.
    /// An invalid name is a [`LoggingConfigError`] located at `path`, using Caddy's directive
    /// wording (`invalid log level %q: expected DEBUG, INFO, WARN, or ERROR`).
    pub fn parse(name: &str, path: impl Into<String>) -> Result<Self, LoggingConfigError> {
        parse_log_level_name(name).map(Self).ok_or_else(|| {
            LoggingConfigError::new(
                path,
                format!("invalid log level \"{name}\": expected DEBUG, INFO, WARN, or ERROR"),
            )
        })
    }

    /// Caddy's request-time lookup: parse an optional `log_level` variable leniently.
    ///
    /// Caddy only uses the variable when `zapcore.ParseLevel` succeeds and the level is in
    /// `DEBUG..=ERROR`; an absent or invalid value silently keeps the status-derived level
    /// (`modules/caddyhttp/server.go:1277-1281`). `None` is returned in those cases. This is not a
    /// located error: invalid request-time values are not configuration errors in Caddy, and the
    /// adapter/validator should use [`LogLevelOverride::parse`] instead.
    pub fn from_request_var(value: Option<&str>) -> Option<Self> {
        parse_log_level_name(value?).map(Self)
    }

    /// The mapped access-entry level.
    pub fn level(self) -> LogLevel {
        self.0
    }

    /// The canonical upper-case name Caddy documents (`DEBUG`, `INFO`, `WARN`, `ERROR`).
    pub fn as_str(self) -> &'static str {
        match self.0 {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }

    /// The canonical value Caddy writes into the request variable: `zapcore.Level.String()` is
    /// lower-case, which is also the spelling the adapted `vars` handler carries
    /// (`caddyconfig/httpcaddyfile/builtins.go:1277`).
    pub fn as_var_value(self) -> &'static str {
        match self.0 {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

fn parse_log_level_name(name: &str) -> Option<LogLevel> {
    // Caddy's `zapcore.ParseLevel` lower-cases the text before matching; do not trim, because
    // `" INFO"` is not a level zap accepts either.
    Some(match name.to_ascii_lowercase().as_str() {
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        _ => return None,
    })
}

/// The access-log level Caddy's `Server.logRequest` assigns to a finished request.
///
/// The default is status-derived ([`LogLevel::for_status`]: `ERROR` for `status >= 500`, otherwise
/// `INFO`). A valid [`LOG_LEVEL_VAR`] value *replaces* that default, in either direction; an
/// invalid value is ignored and the default stands (`modules/caddyhttp/server.go:1271-1282`).
#[must_use]
pub fn access_log_level(status: u16, log_level_var: Option<&str>) -> LogLevel {
    LogLevelOverride::from_request_var(log_level_var)
        .map_or_else(|| LogLevel::for_status(status), LogLevelOverride::level)
}

/// Apply the per-request [`LOG_LEVEL_VAR`] override to an [`AccessLogEntry`].
///
/// Call this after `AccessLogEntry::with_status`, which sets the status-derived level. The stored
/// level is what [`AccessLogEntry`] consumers serialise *and* what the sink's configured threshold
/// filters on, so this reproduces both halves of Caddy's behaviour (Caddy applies the level to
/// `logger.Check` before writing the entry). `None` keeps the status-derived level.
pub fn apply_access_log_level(entry: &mut AccessLogEntry, log_level_var: Option<&str>) {
    entry.level = access_log_level(entry.status, log_level_var);
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
    fn writer_modules_map_net_and_reject_unknown_options() {
        let targets = targets_from(&json!({
            "logs": {"default": {"writer": {
                "output": "net",
                "address": "tcp/127.0.0.1:9999",
                "dial_timeout": 250000000,
                "soft_start": true
            }}}
        }));
        let config = targets[0].sink_config();
        assert_eq!(config.output, AccessLogOutput::Net);
        let net = config.net.as_ref().expect("net config");
        assert_eq!(net.address, "127.0.0.1:9999");
        assert_eq!(net.dial_timeout_ns, Some(250_000_000));
        assert!(net.soft_start);

        let unknown = LoggingConfig::from_json(&json!({
            "logs": {"default": {"writer": {"output": "carrier-pigeon"}}}
        }))
        .expect_err("unknown writer");
        assert_eq!(unknown.path(), "logging.logs.default.writer.output");
        assert_eq!(unknown.tracking_id(), Some(LOGGING_TRACKING_ID));
        assert!(unknown.message().contains("unknown log writer"));

        // Unix sockets are supported (Unix platforms) and unsupported net options stay loud.
        let unix = targets_from(&json!({
            "logs": {"default": {"writer": {"output": "net", "address": "unix//tmp/caddy.sock"}}}
        }));
        let net = unix[0].sink_config().net.as_ref().expect("net config");
        assert_eq!(net.network, NetProtocol::Unix);
        assert_eq!(net.address, "/tmp/caddy.sock");

        let bad_option = LoggingConfig::from_json(&json!({
            "logs": {"default": {"writer": {"output": "net", "address": "127.0.0.1:1", "tls": true}}}
        }))
        .expect_err("net option");
        assert!(
            bad_option.message().contains("not supported"),
            "{bad_option}"
        );

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

    fn file_rotation_and_permission_options_map_and_reject_unsupported_ones() {
        let targets = targets_from(&json!({
            "logs": {"default": {"writer": {
                "output": "file",
                "filename": "/tmp/access.log",
                "mode": "0640",
                "dir_mode": "0750",
                "roll": true,
                "roll_size_mb": 100,
                "roll_keep": 5,
                "roll_keep_days": 30,
                "roll_interval": 3600000000000u64,
                "roll_minutes": [0, 30],
                "roll_at": ["12:00", "00:00"],
                "roll_compression": "none",
                "roll_gzip": false,
                "roll_local_time": false
            }}}
        }));
        let config = targets[0].sink_config();
        assert_eq!(config.file.mode, Some(0o640));
        assert_eq!(config.file.dir_mode, Some(0o750));
        assert!(config.file.roll);
        assert_eq!(config.file.roll_size_mb, Some(100));
        assert_eq!(config.file.roll_keep, 5);
        assert_eq!(config.file.roll_keep_days, Some(30));
        assert_eq!(config.file.roll_interval_ns, Some(3_600_000_000_000));
        assert_eq!(config.file.roll_minutes, Some(vec![0, 30]));
        assert_eq!(
            config.file.roll_at,
            Some(vec!["12:00".to_string(), "00:00".to_string()])
        );

        for option in ["backup_time_format"] {
            let logging = json!({
                "logs": {"default": {"writer": {
                    "output": "file",
                    "filename": "/tmp/access.log",
                    option: "x"
                }}}
            });
            let error = LoggingConfig::from_json(&logging).expect_err(option);
            assert!(
                error.path().ends_with(option),
                "path mentions the option: {error}"
            );
            assert_eq!(error.tracking_id(), Some(LOGGING_TRACKING_ID));
        }
        for (option, value) in [
            ("roll_compression", json!("gzip")),
            ("roll_gzip", json!(true)),
            ("roll_local_time", json!(true)),
        ] {
            let logging = json!({
                "logs": {"default": {"writer": {
                    "output": "file",
                    "filename": "/tmp/access.log",
                    option: value
                }}}
            });
            let error = LoggingConfig::from_json(&logging).expect_err(option);
            assert!(
                error.path().ends_with(option),
                "path mentions the option: {error}"
            );
            assert_eq!(error.tracking_id(), Some(LOGGING_TRACKING_ID), "{option}");
        }
        for (option, value) in [("roll_minutes", json!([60])), ("roll_at", json!(["25:00"]))] {
            let logging = json!({
                "logs": {"default": {"writer": {
                    "output": "file",
                    "filename": "/tmp/access.log",
                    option: value
                }}}
            });
            let error = LoggingConfig::from_json(&logging).expect_err(option);
            assert!(
                error.path().ends_with(option),
                "path mentions the option: {error}"
            );
        }
    }

    #[test]

    fn encoder_formats_and_key_options_map_and_unsupported_ones_fail() {
        let targets = targets_from(&json!({
            "logs": {"default": {"encoder": {"format": "console"}}}
        }));
        assert_eq!(targets[0].sink_config().format, AccessLogFormat::Console);

        let targets = targets_from(&json!({
            "logs": {"default": {"encoder": {
                "format": "json",
                "message_key": "message",
                "level_key": "severity",
                "time_key": "timestamp",
                "name_key": "logger_name",
                "line_ending": "\r\n"
            }}}
        }));
        let encoder = &targets[0].sink_config().encoder;
        assert_eq!(encoder.message_key.as_deref(), Some("message"));
        assert_eq!(encoder.level_key.as_deref(), Some("severity"));
        assert_eq!(encoder.time_key.as_deref(), Some("timestamp"));
        assert_eq!(encoder.name_key.as_deref(), Some("logger_name"));
        assert_eq!(encoder.line_ending.as_deref(), Some("\r\n"));

        for format in ["append", "journald", "nop", "bogus"] {
            let logging = json!({
                "logs": {"default": {"encoder": {"format": format}}}
            });
            let error = LoggingConfig::from_json(&logging).expect_err(format);
            assert_eq!(error.path(), "logging.logs.default.encoder.format");
            assert_eq!(error.tracking_id(), Some(LOGGING_TRACKING_ID));
        }

        // Format options are now mapped (console and JSON).
        let targets = targets_from(&json!({
            "logs": {"default": {"encoder": {
                "format": "console",
                "time_format": "rfc3339",
                "duration_format": "ms",
                "level_format": "upper",
                "time_local": false
            }}}
        }));
        let encoder = &targets[0].sink_config().encoder;
        assert_eq!(encoder.time_format.as_deref(), Some("rfc3339"));
        assert_eq!(encoder.duration_format.as_deref(), Some("ms"));
        assert_eq!(encoder.level_format.as_deref(), Some("upper"));
        assert!(!encoder.time_local);

        let caller = LoggingConfig::from_json(&json!({
            "logs": {"default": {"encoder": {"format": "json", "caller_key": "caller"}}}
        }))
        .expect_err("caller_key");
        assert!(caller.path().contains("caller_key"), "{caller}");
        assert_eq!(caller.tracking_id(), Some(LOGGING_TRACKING_ID));

        for (option, value) in [
            ("time_format", json!("bogus")),
            ("level_format", json!("bogus")),
            ("duration_format", json!("bogus")),
            ("time_local", json!(true)),
        ] {
            let logging = json!({
                "logs": {"default": {"encoder": {"format": "json", option: value}}}
            });
            let error = LoggingConfig::from_json(&logging).expect_err(option);
            assert!(
                error.path().contains("encoder") || error.path().contains(option),
                "{error}"
            );
        }
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
    fn filter_modules_map_and_unsupported_ones_fail_loudly() {
        let logging = json!({
            "logs": {"default": {"encoder": {
                "format": "filter",
                "wrap": {"format": "json"},
                "fields": {
                    "request>uri": {"filter": "hash"},
                    "request>remote_ip": {"filter": "ip_mask", "ipv4_cidr": 24, "ipv6_cidr": 64},
                    "request>headers>X-Debug": {"filter": "rename", "name": "X-Renamed"},
                    "request>headers>X-Secret": {"filter": "replace", "value": "***"}
                }
            }}}
        });
        let targets = targets_from(&logging);
        let filters = &targets[0].sink_config().encoder.filters;
        assert_eq!(
            filters.len(),
            3,
            "header rename/hash/ip_mask map to generic filters"
        );
        assert!(filters
            .iter()
            .any(|filter| matches!(filter.operation, FieldFilterOperation::Hash)));
        assert!(filters.iter().any(|filter| matches!(
            filter.operation,
            FieldFilterOperation::IpMask {
                v4_mask: Some(24),
                v6_mask: Some(64)
            }
        )));

        // The mapping actually applies through the encoder.
        let sink = AccessLogSink::to_writer(
            RecordingWriter::new(),
            targets[0].sink_config().encoder.clone(),
        )
        .expect("sink");
        let mut log_entry = entry(200, "hello");
        log_entry.request.uri = "/path?token=secret".to_string();
        log_entry.request.remote_ip = "192.0.2.10".to_string();
        log_entry
            .request
            .headers
            .insert("X-Debug".to_string(), vec!["value".to_string()]);
        sink.emit(&log_entry).expect("emit");
        let recorder = sink.encoder().config();
        assert!(!recorder.filters.is_empty());

        // Query/cookie/set_cookie/regexp/multi_regexp are mapped to generic field filters.
        let extended = LoggingConfig::from_json(&json!({
            "logs": {"default": {"encoder": {
                "format": "filter",
                "fields": {
                    "request>uri": {"filter": "query", "actions": [
                        {"type": "replace", "parameter": "token", "value": "***"},
                        {"type": "hash", "parameter": "id"},
                        {"type": "delete", "parameter": "secret"}
                    ]},
                    "request>headers>Cookie": {"filter": "cookie", "actions": [
                        {"type": "hash", "name": "session"}
                    ]},
                    "resp_headers>Set-Cookie": {"filter": "set_cookie", "actions": [
                        {"type": "replace", "name": "session", "value": "REDACTED"}
                    ]},
                    "request>uri>test": {"filter": "regexp", "regexp": "(?i)token=\\w+", "value": "token=***"},
                    "request>user_id": {"filter": "multi_regexp", "operations": [
                        {"regexp": "a+", "value": "A"},
                        {"regexp": "b+", "value": "B"}
                    ]}
                }
            }}}
        }))
        .expect("extended filters map");
        let filters = &extended.targets()[0].sink_config().encoder.filters;
        assert_eq!(filters.len(), 5);
        assert!(filters
            .iter()
            .any(|filter| matches!(filter.operation, FieldFilterOperation::Query { .. })));
        assert!(filters
            .iter()
            .any(|filter| matches!(filter.operation, FieldFilterOperation::Cookie { .. })));
        assert!(filters
            .iter()
            .any(|filter| matches!(filter.operation, FieldFilterOperation::SetCookie { .. })));
        assert!(filters
            .iter()
            .any(|filter| matches!(filter.operation, FieldFilterOperation::Regexp { .. })));
        assert!(filters
            .iter()
            .any(|filter| matches!(filter.operation, FieldFilterOperation::MultiRegexp { .. })));

        // Malformed filter shapes and unsupported regexp constructs fail loudly.
        for bad in [
            json!({"filter": "query"}),
            json!({"filter": "query", "actions": [{"type": "bogus", "parameter": "x"}]}),
            json!({"filter": "cookie", "actions": [{"type": "delete"}]}),
            json!({"filter": "regexp", "regexp": "(?=lookahead)"}),
            json!({"filter": "multi_regexp", "operations": []}),
        ] {
            let logging = json!({
                "logs": {"default": {"encoder": {
                    "format": "filter",
                    "fields": {"request>uri": bad}
                }}}
            });
            let error = LoggingConfig::from_json(&logging).expect_err("invalid filter");
            assert!(
                error.tracking_id() == Some(LOGGING_TRACKING_ID)
                    || error.message().contains("invalid regexp")
                    || error.message().contains("unknown filter action")
                    || error.message().contains("requires"),
                "{error}"
            );
        }

        let unknown = LoggingConfig::from_json(&json!({
            "logs": {"default": {"encoder": {
                "format": "filter",
                "fields": {"request>headers>X": {"filter": "not-a-filter"}}
            }}}
        }))
        .expect_err("unknown filter");
        assert!(unknown.message().contains("unknown log field filter"));

        let fundamental = LoggingConfig::from_json(&json!({
            "logs": {"default": {"encoder": {
                "format": "filter",
                "fields": {"ts": {"filter": "delete"}}
            }}}
        }))
        .expect_err("fundamental field");
        assert!(fundamental.message().contains("fundamental"));

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

    /// The adapted JSON from Caddy's `caddyfile_adapt/global_options_log_and_site.caddyfiletest`
    /// (DIV-0053). Caddy's validator rejects it because the `default` log's only include entry
    /// (`some-log-source`) is not a parent/child namespace of any exclude entry, so it is neither
    /// a rule nor an exception. caddy-rs's logging mapping rejects it with a located error.
    const GLOBAL_OPTIONS_LOG_AND_SITE_ADAPTED: &str = r#"{
        "logging": {
            "logs": {
                "custom-logger": {
                    "writer": {"filename": "caddy.log", "output": "file"},
                    "level": "WARN",
                    "include": ["custom-log-source"]
                },
                "default": {
                    "writer": {"filename": "caddy.log", "output": "file"},
                    "include": ["some-log-source"],
                    "exclude": ["admin.api", "admin2.api", "custom-log-source", "http.log.access.log0"]
                },
                "log0": {
                    "writer": {"filename": "access.log", "output": "file"},
                    "encoder": {"format": "json"},
                    "include": ["http.log.access.log0"]
                }
            }
        },
        "apps": {
            "http": {
                "servers": {
                    "srv0": {
                        "listen": [":8884"],
                        "logs": {"default_logger_name": "log0"}
                    }
                }
            }
        }
    }"#;

    #[test]
    fn adapted_global_options_log_and_site_fixture_is_rejected_like_caddy() {
        let value: serde_json::Value =
            serde_json::from_str(GLOBAL_OPTIONS_LOG_AND_SITE_ADAPTED).expect("fixture JSON");
        let config = Config::from_value(value).expect("core config model decodes the fixture");
        let error = LoggingConfig::validate_config(&config)
            .expect_err("Caddy rejects this include/exclude combination");
        assert_eq!(error.path(), "logging.logs.default.include[0]");
        assert!(error.message().contains("some-log-source"), "{error}");
        assert!(
            error.message().contains("superspace or subspace"),
            "{error}"
        );
        // Both conflicting rule sets are named: the include entry and the exclude list.
        assert!(error.message().contains("admin.api"), "{error}");
        assert!(error.message().contains("custom-log-source"), "{error}");
        assert!(error.message().contains("http.log.access.log0"), "{error}");
    }

    #[test]
    fn compatible_include_exclude_nesting_permutations_validate() {
        // Caddy only requires every include entry to be a parent or child namespace of some
        // exclude entry; both directions are valid.
        for (include, exclude) in [
            (vec!["http"], vec!["http.log"]),
            (vec!["http.log"], vec!["http"]),
            (vec!["http.log.access"], vec!["http"]),
        ] {
            let value = json!({
                "logging": {"logs": {"default": {
                    "include": include,
                    "exclude": exclude
                }}}
            });
            let config = Config::from_value(value).expect("config decodes");
            LoggingConfig::validate_config(&config)
                .unwrap_or_else(|error| panic!("compatible rules rejected: {error}"));
        }

        // A single unrelated include entry is rejected wherever it appears in the list.
        let value = json!({
            "logging": {"logs": {"default": {
                "include": ["http.log.access", "some-log-source"],
                "exclude": ["http.log"]
            }}}
        });
        let config = Config::from_value(value).expect("config decodes");
        let error = LoggingConfig::validate_config(&config).expect_err("unrelated include entry");
        assert_eq!(error.path(), "logging.logs.default.include[1]");
        assert!(error.message().contains("some-log-source"), "{error}");
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

    #[test]
    fn log_level_override_helper_names_match_caddy() {
        // Caddy's `caddyhttp.LogLevelVar` and the four names its directive/log-time checks accept.
        assert_eq!(LOG_LEVEL_VAR, "log_level");
        assert_eq!(LOG_LEVEL_NAMES, ["DEBUG", "INFO", "WARN", "ERROR"]);
    }

    #[test]
    fn every_accepted_log_level_name_parses_case_insensitively() {
        // The located path is the adapted `vars` handler a Caddyfile `log_level` compiles to.
        const PATH: &str = "apps.http.servers.srv0.routes.0.handle.0.log_level";
        for (name, expected) in [
            ("DEBUG", LogLevel::Debug),
            ("debug", LogLevel::Debug),
            ("Debug", LogLevel::Debug),
            ("INFO", LogLevel::Info),
            ("info", LogLevel::Info),
            ("WARN", LogLevel::Warn),
            ("warn", LogLevel::Warn),
            ("ERROR", LogLevel::Error),
            ("error", LogLevel::Error),
            ("ErRoR", LogLevel::Error),
        ] {
            let parsed = LogLevelOverride::parse(name, PATH)
                .unwrap_or_else(|error| panic!("{name:?} should parse: {error}"));
            assert_eq!(parsed.level(), expected, "{name:?}");
            // Directive help/validation spelling versus the lower-case value Caddy writes into
            // the request variable (`zapcore.Level.String()`).
            assert_eq!(
                parsed.as_str(),
                name.to_ascii_uppercase().as_str(),
                "{name:?}"
            );
            assert_eq!(
                parsed.as_var_value(),
                name.to_ascii_lowercase().as_str(),
                "{name:?}"
            );
            // The request-time lookup agrees with the strict parse for valid names.
            assert_eq!(
                LogLevelOverride::from_request_var(Some(name)),
                Some(parsed),
                "{name:?}"
            );
        }
    }

    #[test]
    fn invalid_log_level_names_are_located_errors() {
        const PATH: &str = "apps.http.servers.srv0.routes.0.handle.0.log_level";
        // `DPANIC`/`PANIC`/`FATAL` are zap levels but Caddy's `DEBUG..=ERROR` range check rejects
        // them; `" INFO"` is rejected because zap does not trim either.
        for name in [
            "", "verbose", "warning", "DPANIC", "panic", "FATAL", "5", " INFO",
        ] {
            let error = LogLevelOverride::parse(name, PATH).expect_err(name);
            assert_eq!(error.path(), PATH, "{name:?}");
            assert_eq!(
                error.message(),
                format!("invalid log level \"{name}\": expected DEBUG, INFO, WARN, or ERROR"),
                "{name:?}"
            );
            assert_eq!(error.tracking_id(), None, "{name:?}");
            // At request time Caddy silently ignores the invalid value.
            assert_eq!(
                LogLevelOverride::from_request_var(Some(name)),
                None,
                "{name:?}"
            );
        }
    }

    #[test]
    fn entry_with_a_log_level_override_uses_the_override_level() {
        // Caddy's override *replaces* the status-derived level in both directions: an ERROR
        // override suppresses a 200 at INFO sinks, a DEBUG override logs a 500 at DEBUG sinks.
        let mut raised = entry(200, "ok");
        assert_eq!(raised.level, LogLevel::Info);
        apply_access_log_level(&mut raised, Some("ERROR"));
        assert_eq!(raised.level, LogLevel::Error);
        assert_eq!(raised.status, 200);

        let mut lowered = entry(500, "boom");
        assert_eq!(lowered.level, LogLevel::Error);
        apply_access_log_level(&mut lowered, Some("debug"));
        assert_eq!(lowered.level, LogLevel::Debug);

        // WARN is a real level, not a synonym for ERROR (unlike the sink's threshold mapping).
        let mut warned = entry(404, "missing");
        apply_access_log_level(&mut warned, Some("WARN"));
        assert_eq!(warned.level, LogLevel::Warn);
    }

    #[test]
    fn entry_without_a_log_level_override_keeps_the_status_level() {
        let mut ok = entry(200, "ok");
        apply_access_log_level(&mut ok, None);
        assert_eq!(ok.level, LogLevel::Info);

        let mut server_error = entry(500, "boom");
        apply_access_log_level(&mut server_error, None);
        assert_eq!(server_error.level, LogLevel::Error);

        // An invalid request variable keeps the default, exactly like Caddy's `logRequest`.
        let mut invalid = entry(503, "down");
        apply_access_log_level(&mut invalid, Some("verbose"));
        assert_eq!(invalid.level, LogLevel::Error);

        // The status helper agrees with the entry helper.
        assert_eq!(access_log_level(200, Some("warn")), LogLevel::Warn);
        assert_eq!(access_log_level(500, None), LogLevel::Error);
        assert_eq!(access_log_level(500, Some("info")), LogLevel::Info);
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
