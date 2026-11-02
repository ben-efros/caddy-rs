//! Structured access-log record model (plan task T-ADMIN-020).
//!
//! Caddy emits one structured entry per handled request through its access logger. This module
//! models that entry as typed Rust values, with the field names and shapes Caddy v2.11.7 uses
//! (`modules/caddyhttp/marshalers.go` and `server.go::logRequest`):
//!
//! ```json
//! {"level":"info","ts":1700000000.5,"logger":"http.log.access","msg":"handled request",
//!  "request":{"remote_ip":"192.0.2.10","remote_port":"54321","proto":"HTTP/1.1",
//!             "method":"GET","host":"example.com","uri":"/","headers":{},
//!             "tls":{"resumed":false,"version":772,"cipher_suite":4865,
//!                    "proto":"h2","server_name":"example.com","ech":false}},
//!  "bytes_read":0,"user_id":"","duration":0.05,"size":123,"status":200,
//!  "resp_headers":{"Content-Type":["text/plain"]}}
//! ```
//!
//! On top of the record model the module provides the logging *primitives* the runtime needs to
//! configure a sink:
//!
//! * [`AccessLogConfig`] — field selection (`include`/`exclude`) and ordering policy,
//! * [`RedactionPolicy`] — credential, header, cookie and query-parameter redaction,
//! * [`SamplingConfig`]/[`AccessLogSampler`] — zap-compatible `first`/`thereafter` sampling per
//!   interval and per `(level, message)` bucket.
//!
//! ## Caddy compatibility notes
//!
//! * Credential headers (`Cookie`, `Set-Cookie`, `Authorization`, `Proxy-Authorization`) are
//!   replaced with `"REDACTED"` unless [`AccessLogConfig::log_credentials`] is set, exactly like
//!   Caddy's `LoggableHTTPHeader`.
//! * Header names are canonicalised (MIME header form) because caddy-rs's `http::HeaderMap` may
//!   store lowercase names, while Caddy emits canonical Go header names.
//! * `ts` and `duration` are floating-point seconds (zap's JSON encoder), not duration strings.
//! * The `upstream` field is a caddy-rs extension: Caddy v2.11.7 logs upstream selection only at
//!   DEBUG level via the proxy module, not in the access entry. See
//!   `docs/compatibility/BEHAVIOR-DIVERGENCES.md` DIV-0034.
//! * Field selection is a crate-level primitive; Caddy configures the same idea through
//!   `filter` encoder modules (`caddy.logging.encoders.filter`) applied to zap fields. The four
//!   fields zap itself owns (`ts`, `level`, `logger`, `msg`) cannot be filtered, matching Caddy's
//!   `FilterEncoder` documentation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, HeaderName};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Default access logger name, matching Caddy's `http.log.access`.
pub const DEFAULT_ACCESS_LOGGER: &str = "http.log.access";
/// Default access log message, matching Caddy's `logRequest`.
pub const DEFAULT_ACCESS_MESSAGE: &str = "handled request";
/// Replacement value for redacted fields, matching Caddy.
pub const REDACTED: &str = "REDACTED";

/// Headers Caddy redacts unless credentials are explicitly logged (`should_log_credentials`).
const CREDENTIAL_HEADERS: &[&str] = &[
    "Cookie",
    "Set-Cookie",
    "Authorization",
    "Proxy-Authorization",
];

/// Fields owned by the log encoder itself; Caddy's filter encoder cannot remove them.
const FUNDAMENTAL_FIELDS: &[&str] = &["ts", "level", "logger", "msg"];

/// A located access-log configuration or serialization error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLogError {
    path: String,
    message: String,
}

impl AccessLogError {
    pub(crate) fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    /// Located path of the offending value.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Human-readable diagnosis.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AccessLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "access log `{}`: {}", self.path, self.message)
    }
}

impl std::error::Error for AccessLogError {}

/// Log severity of an access entry. Caddy logs `500`+ responses at error level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Debug (only used by handler trace logs).
    Debug,
    /// Informational access entry (the normal case).
    Info,
    /// Warning.
    Warn,
    /// Error entry; Caddy uses this for `status >= 500`.
    Error,
}

impl LogLevel {
    /// The level Caddy uses for a response status.
    pub fn for_status(status: u16) -> Self {
        if status >= 500 {
            LogLevel::Error
        } else {
            LogLevel::Info
        }
    }
}

/// TLS connection information logged with a request (`request.tls`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccessLogTls {
    /// Whether the TLS session was resumed.
    pub resumed: bool,
    /// TLS protocol version number (for example `772` for TLS 1.3).
    pub version: u16,
    /// Negotiated cipher suite number.
    pub cipher_suite: u16,
    /// Negotiated ALPN protocol (for example `h2`).
    pub proto: String,
    /// SNI server name from the handshake.
    pub server_name: String,
    /// Whether ECH was accepted.
    pub ech: bool,
    /// Client certificate common name, when a client certificate was presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_common_name: Option<String>,
    /// Client certificate serial number, when a client certificate was presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_serial: Option<String>,
}

/// The `request` object of an access entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccessLogRequest {
    /// Peer IP address.
    pub remote_ip: String,
    /// Peer port, as a string (Caddy logs it as a string).
    pub remote_port: String,
    /// Client IP derived from a trusted proxy, when configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// HTTP protocol, for example `HTTP/1.1` or `HTTP/2.0`.
    pub proto: String,
    /// Request method.
    pub method: String,
    /// Request host.
    pub host: String,
    /// Request URI (path and query).
    pub uri: String,
    /// Request headers, canonicalised and with values as arrays.
    pub headers: BTreeMap<String, Vec<String>>,
    /// Transfer encodings (only non-identity encodings are set by hyper).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfer_encoding: Vec<String>,
    /// TLS details, when the request arrived over TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<AccessLogTls>,
}

impl AccessLogRequest {
    /// Build a request record with the common fields.
    pub fn new(method: &str, host: &str, uri: &str) -> Self {
        Self {
            remote_ip: String::new(),
            remote_port: String::new(),
            client_ip: None,
            proto: "HTTP/1.1".to_string(),
            method: method.to_string(),
            host: host.to_string(),
            uri: uri.to_string(),
            headers: BTreeMap::new(),
            transfer_encoding: Vec::new(),
            tls: None,
        }
    }

    /// Set the peer address (empty strings when unknown, matching a `parsed` split failure).
    pub fn with_remote(mut self, remote: Option<SocketAddr>) -> Self {
        let (ip, port) = remote_ip_port(remote);
        self.remote_ip = ip;
        self.remote_port = port;
        self
    }

    /// Copy headers into the canonicalised, value-array form used in logs.
    pub fn with_headers(mut self, headers: &HeaderMap) -> Self {
        self.headers = headers_to_loggable(headers);
        self
    }
}

/// The caddy-rs `upstream` extension object of an access entry.
///
/// Caddy v2.11.7 does not put upstream selection in access entries; caddy-rs adds it so a proxy
/// deployment can be diagnosed from its access log. Only bounded configuration values (the dial
/// address) are logged, never arbitrary peer addresses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessLogUpstream {
    /// Configured upstream dial address.
    pub dial: String,
    /// Resolved upstream peer IP, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    /// Resolved upstream peer port, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<String>,
    /// Time spent on the upstream request.
    #[serde(
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub duration: Duration,
    /// Upstream response status, when one was received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

/// One structured access-log entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessLogEntry {
    /// Log level.
    pub level: LogLevel,
    /// Unix timestamp in seconds.
    #[serde(
        rename = "ts",
        serialize_with = "serialize_timestamp",
        deserialize_with = "deserialize_timestamp"
    )]
    pub timestamp: SystemTime,
    /// Logger name (`http.log.access` by default).
    pub logger: String,
    /// Entry message (`handled request` by default).
    pub msg: String,
    /// Request details.
    pub request: AccessLogRequest,
    /// Number of request body bytes read.
    pub bytes_read: u64,
    /// Authenticated user id, empty when anonymous.
    pub user_id: String,
    /// Total request duration.
    #[serde(
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub duration: Duration,
    /// Response body size in bytes.
    pub size: u64,
    /// Response status code (0 when no response was written, as Caddy logs it).
    pub status: u16,
    /// Response headers, canonicalised and with values as arrays.
    pub resp_headers: BTreeMap<String, Vec<String>>,
    /// Write error, when the response could not be fully written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_error: Option<String>,
    /// caddy-rs extension: proxy upstream details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<AccessLogUpstream>,
}

impl Default for AccessLogEntry {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            timestamp: UNIX_EPOCH,
            logger: DEFAULT_ACCESS_LOGGER.to_string(),
            msg: DEFAULT_ACCESS_MESSAGE.to_string(),
            request: AccessLogRequest::default(),
            bytes_read: 0,
            user_id: String::new(),
            duration: Duration::ZERO,
            size: 0,
            status: 200,
            resp_headers: BTreeMap::new(),
            write_error: None,
            upstream: None,
        }
    }
}

impl AccessLogEntry {
    /// Start an entry for a request.
    pub fn new(request: AccessLogRequest) -> Self {
        Self {
            request,
            ..Self::default()
        }
    }

    /// Set the timestamp.
    pub fn with_timestamp(mut self, timestamp: SystemTime) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set the response status and the matching log level.
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self.level = LogLevel::for_status(status);
        self
    }

    /// Set the request duration.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Set the response size.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Set the response headers (canonicalised, value-array form).
    pub fn with_response_headers(mut self, headers: &HeaderMap) -> Self {
        self.resp_headers = headers_to_loggable(headers);
        self
    }

    /// Set the proxy upstream details (caddy-rs extension).
    pub fn with_upstream(mut self, upstream: AccessLogUpstream) -> Self {
        self.upstream = Some(upstream);
        self
    }

    /// Serialize the full entry without applying a log configuration.
    pub fn to_json_value(&self) -> Result<serde_json::Value, AccessLogError> {
        serde_json::to_value(self)
            .map_err(|error| AccessLogError::new("entry", format!("cannot serialize: {error}")))
    }

    /// Render the entry as configured: redaction first, then field selection.
    pub fn render(&self, config: &AccessLogConfig) -> Result<serde_json::Value, AccessLogError> {
        config.validate()?;
        let mut entry = self.clone();
        entry.apply_redaction(config);
        let mut value = entry.to_json_value()?;
        config.apply_field_selection(&mut value);
        Ok(value)
    }

    /// Render the entry to a compact JSON string.
    pub fn render_string(&self, config: &AccessLogConfig) -> Result<String, AccessLogError> {
        serde_json::to_string(&self.render(config)?)
            .map_err(|error| AccessLogError::new("entry", format!("cannot serialize: {error}")))
    }

    /// Render with the default configuration (credential redaction, all fields).
    pub fn render_default(&self) -> Result<serde_json::Value, AccessLogError> {
        self.render(&AccessLogConfig::default())
    }

    fn apply_redaction(&mut self, config: &AccessLogConfig) {
        if !config.log_credentials {
            for header in CREDENTIAL_HEADERS {
                redact_header(&mut self.request.headers, header, REDACTED);
                redact_header(&mut self.resp_headers, header, REDACTED);
            }
        }
        for rule in &config.redaction.headers {
            match rule {
                HeaderRedaction::Redact { header, target } => {
                    if target.requests() {
                        redact_header(&mut self.request.headers, header, REDACTED);
                    }
                    if target.responses() {
                        redact_header(&mut self.resp_headers, header, REDACTED);
                    }
                }
                HeaderRedaction::Replace {
                    header,
                    value,
                    target,
                } => {
                    if target.requests() {
                        replace_header(&mut self.request.headers, header, value);
                    }
                    if target.responses() {
                        replace_header(&mut self.resp_headers, header, value);
                    }
                }
                HeaderRedaction::Delete { header, target } => {
                    if target.requests() {
                        remove_header(&mut self.request.headers, header);
                    }
                    if target.responses() {
                        remove_header(&mut self.resp_headers, header);
                    }
                }
            }
        }
        if !config.redaction.cookies.is_empty() {
            redact_cookies(&mut self.request.headers, &config.redaction.cookies);
        }
        if !config.redaction.query_parameters.is_empty() {
            self.request.uri =
                redact_query_parameters(&self.request.uri, &config.redaction.query_parameters);
        }
    }
}

/// Top-level fields that can be selected into or out of an access entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLogField {
    /// `ts`
    Ts,
    /// `level`
    Level,
    /// `logger`
    Logger,
    /// `msg`
    Msg,
    /// `request`
    Request,
    /// `bytes_read`
    BytesRead,
    /// `user_id`
    UserId,
    /// `duration`
    Duration,
    /// `size`
    Size,
    /// `status`
    Status,
    /// `resp_headers`
    RespHeaders,
    /// `write_error`
    WriteError,
    /// `upstream` (caddy-rs extension)
    Upstream,
}

impl AccessLogField {
    /// The JSON key this field selects.
    pub fn as_str(self) -> &'static str {
        match self {
            AccessLogField::Ts => "ts",
            AccessLogField::Level => "level",
            AccessLogField::Logger => "logger",
            AccessLogField::Msg => "msg",
            AccessLogField::Request => "request",
            AccessLogField::BytesRead => "bytes_read",
            AccessLogField::UserId => "user_id",
            AccessLogField::Duration => "duration",
            AccessLogField::Size => "size",
            AccessLogField::Status => "status",
            AccessLogField::RespHeaders => "resp_headers",
            AccessLogField::WriteError => "write_error",
            AccessLogField::Upstream => "upstream",
        }
    }

    fn is_fundamental(self) -> bool {
        FUNDAMENTAL_FIELDS.contains(&self.as_str())
    }
}

/// Which header map a [`HeaderRedaction`] applies to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderTarget {
    /// Both request and response headers.
    #[default]
    Both,
    /// Request headers only.
    Request,
    /// Response headers only.
    Response,
}

impl HeaderTarget {
    fn requests(self) -> bool {
        matches!(self, HeaderTarget::Both | HeaderTarget::Request)
    }

    fn responses(self) -> bool {
        matches!(self, HeaderTarget::Both | HeaderTarget::Response)
    }
}

/// One header redaction rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HeaderRedaction {
    /// Replace every value with [`REDACTED`].
    Redact {
        /// Header name (case-insensitive).
        header: String,
        /// Which header map to redact.
        #[serde(default)]
        target: HeaderTarget,
    },
    /// Replace every value with a fixed string.
    Replace {
        /// Header name (case-insensitive).
        header: String,
        /// Replacement value.
        value: String,
        /// Which header map to redact.
        #[serde(default)]
        target: HeaderTarget,
    },
    /// Remove the header entirely.
    Delete {
        /// Header name (case-insensitive).
        header: String,
        /// Which header map to redact.
        #[serde(default)]
        target: HeaderTarget,
    },
}

impl HeaderRedaction {
    fn header(&self) -> &str {
        match self {
            HeaderRedaction::Redact { header, .. }
            | HeaderRedaction::Replace { header, .. }
            | HeaderRedaction::Delete { header, .. } => header,
        }
    }
}

/// Redaction primitives for access entries.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RedactionPolicy {
    /// Header redaction rules, applied in order after the default credential redaction.
    #[serde(default)]
    pub headers: Vec<HeaderRedaction>,
    /// Query parameters whose values are replaced with [`REDACTED`] in `request.uri`.
    #[serde(default)]
    pub query_parameters: Vec<String>,
    /// Request cookie names whose values are replaced with [`REDACTED`].
    #[serde(default)]
    pub cookies: Vec<String>,
}

/// Sampling configuration mirroring zap's `NewSamplerWithOptions`.
///
/// Every `interval`, the first `first` entries (per level and message) are logged, and after that
/// every `thereafter`-th entry is logged. Caddy applies these defaults when sampling is enabled:
/// interval 1s, first 100, thereafter 100.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Sampling window.
    #[serde(
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub interval: Duration,
    /// Entries logged per window before sampling starts.
    pub first: usize,
    /// Period of entries logged after the first ones.
    pub thereafter: usize,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            first: 100,
            thereafter: 100,
        }
    }
}

impl SamplingConfig {
    /// Build and validate a sampling configuration.
    pub fn new(
        interval: Duration,
        first: usize,
        thereafter: usize,
    ) -> Result<Self, AccessLogError> {
        let config = Self {
            interval,
            first,
            thereafter,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration (mirrors Caddy's provisioning defaults, but rejects zeros
    /// instead of silently substituting them).
    pub fn validate(&self) -> Result<(), AccessLogError> {
        if self.interval.is_zero() {
            return Err(AccessLogError::new(
                "sampling.interval",
                "must be greater than zero",
            ));
        }
        if self.first == 0 {
            return Err(AccessLogError::new(
                "sampling.first",
                "must be greater than zero",
            ));
        }
        if self.thereafter == 0 {
            return Err(AccessLogError::new(
                "sampling.thereafter",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Stateful sampler implementing [`SamplingConfig`].
#[derive(Debug)]
pub struct AccessLogSampler {
    config: SamplingConfig,
    state: Mutex<SamplerState>,
}

#[derive(Debug)]
struct SamplerState {
    window_start: Instant,
    counts: BTreeMap<(LogLevel, String), u64>,
}

impl AccessLogSampler {
    /// Create a sampler; the first window starts at `start`.
    pub fn new(config: SamplingConfig, start: Instant) -> Result<Self, AccessLogError> {
        config.validate()?;
        Ok(Self {
            config,
            state: Mutex::new(SamplerState {
                window_start: start,
                counts: BTreeMap::new(),
            }),
        })
    }

    /// The sampler configuration.
    pub fn config(&self) -> &SamplingConfig {
        &self.config
    }

    /// Whether the entry should be logged. Call with `Instant::now()` in production and with a
    /// controlled `now` in tests.
    pub fn should_log(&self, now: Instant, level: LogLevel, message: &str) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if now.saturating_duration_since(state.window_start) >= self.config.interval {
            state.window_start = now;
            state.counts.clear();
        }
        let counter = state
            .counts
            .entry((level, message.to_string()))
            .or_insert(0);
        *counter += 1;
        *counter <= self.config.first as u64 || *counter % self.config.thereafter as u64 == 0
    }
}

/// Field selection and redaction configuration for one access-log sink.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccessLogConfig {
    /// When non-empty, only these fields (plus `ts`/`level`/`logger`/`msg`) are emitted.
    #[serde(default)]
    pub include: Vec<AccessLogField>,
    /// Fields to remove. The fundamental fields cannot be removed.
    #[serde(default)]
    pub exclude: Vec<AccessLogField>,
    /// Log credential header values instead of redacting them (Caddy's
    /// `should_log_credentials`).
    #[serde(default)]
    pub log_credentials: bool,
    /// Extra redaction rules.
    #[serde(default)]
    pub redaction: RedactionPolicy,
    /// Optional sampling policy (no sampling when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<SamplingConfig>,
}

impl AccessLogConfig {
    /// Validate the configuration, returning the first located problem.
    pub fn validate(&self) -> Result<(), AccessLogError> {
        check_unique_fields(&self.include, "include")?;
        check_unique_fields(&self.exclude, "exclude")?;
        for field in &self.exclude {
            if field.is_fundamental() {
                return Err(AccessLogError::new(
                    format!("exclude.{}", field.as_str()),
                    "fundamental log fields (ts, level, logger, msg) cannot be removed",
                ));
            }
        }
        let mut seen_headers: BTreeSet<String> = BTreeSet::new();
        for (index, rule) in self.redaction.headers.iter().enumerate() {
            HeaderName::from_bytes(rule.header().as_bytes()).map_err(|error| {
                AccessLogError::new(
                    format!("redaction.headers[{index}].header"),
                    format!("invalid header name {:?}: {error}", rule.header()),
                )
            })?;
            if !seen_headers.insert(rule.header().to_ascii_lowercase()) {
                return Err(AccessLogError::new(
                    format!("redaction.headers[{index}].header"),
                    format!(
                        "header `{}` has more than one redaction rule",
                        rule.header()
                    ),
                ));
            }
        }
        check_unique_names(
            &self.redaction.query_parameters,
            "redaction.query_parameters",
        )?;
        check_unique_names(&self.redaction.cookies, "redaction.cookies")?;
        if let Some(sampling) = &self.sampling {
            sampling.validate()?;
        }
        Ok(())
    }

    fn apply_field_selection(&self, value: &mut serde_json::Value) {
        let serde_json::Value::Object(map) = value else {
            return;
        };
        if !self.include.is_empty() {
            let allowed: BTreeSet<&str> = self
                .include
                .iter()
                .map(|field| field.as_str())
                .chain(FUNDAMENTAL_FIELDS.iter().copied())
                .collect();
            map.retain(|key, _| allowed.contains(key.as_str()));
        }
        for field in &self.exclude {
            map.remove(field.as_str());
        }
    }
}

fn check_unique_fields(fields: &[AccessLogField], path: &str) -> Result<(), AccessLogError> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for field in fields {
        if !seen.insert(field.as_str()) {
            return Err(AccessLogError::new(
                format!("{path}.{}", field.as_str()),
                "field is listed more than once",
            ));
        }
    }
    Ok(())
}

fn check_unique_names(names: &[String], path: &str) -> Result<(), AccessLogError> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for name in names {
        if name.is_empty() {
            return Err(AccessLogError::new(path, "names must not be empty"));
        }
        if !seen.insert(name.as_str()) {
            return Err(AccessLogError::new(
                format!("{path}.{name}"),
                "name is listed more than once",
            ));
        }
    }
    Ok(())
}

/// Canonicalise a header name the way Go's `textproto.CanonicalMIMEHeaderKey` does: the first
/// letter and every letter after `-` is upper case, other ASCII letters are lower case, and
/// non-letters are preserved.
pub fn canonical_header_name(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut upper = true;
    for character in name.chars() {
        if character.is_ascii_alphabetic() {
            if upper {
                result.push(character.to_ascii_uppercase());
            } else {
                result.push(character.to_ascii_lowercase());
            }
        } else {
            result.push(character);
        }
        upper = character == '-';
    }
    result
}

/// Convert a header map into the canonicalised `name -> values` form Caddy logs.
pub fn headers_to_loggable(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut loggable: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        let name = canonical_header_name(name.as_str());
        loggable.entry(name).or_default().push(
            value
                .to_str()
                .unwrap_or("<non-UTF-8 header value>")
                .to_string(),
        );
    }
    loggable
}

/// Split a peer address into Caddy's `remote_ip`/`remote_port` strings.
pub fn remote_ip_port(remote: Option<SocketAddr>) -> (String, String) {
    match remote {
        Some(address) => (address.ip().to_string(), address.port().to_string()),
        None => (String::new(), String::new()),
    }
}

fn redact_header(headers: &mut BTreeMap<String, Vec<String>>, name: &str, replacement: &str) {
    if let Some(values) = header_values_mut(headers, name) {
        *values = vec![replacement.to_string()];
    }
}

fn replace_header(headers: &mut BTreeMap<String, Vec<String>>, name: &str, replacement: &str) {
    if let Some(values) = header_values_mut(headers, name) {
        *values = vec![replacement.to_string()];
    }
}

fn remove_header(headers: &mut BTreeMap<String, Vec<String>>, name: &str) {
    if let Some(key) = headers
        .keys()
        .find(|key| key.eq_ignore_ascii_case(name))
        .cloned()
    {
        headers.remove(&key);
    }
}

fn header_values_mut<'a>(
    headers: &'a mut BTreeMap<String, Vec<String>>,
    name: &str,
) -> Option<&'a mut Vec<String>> {
    let key = headers
        .keys()
        .find(|key| key.eq_ignore_ascii_case(name))
        .cloned()?;
    headers.get_mut(&key)
}

/// Replace the values of matching cookies in a request `Cookie` header.
fn redact_cookies(headers: &mut BTreeMap<String, Vec<String>>, names: &[String]) {
    if let Some(values) = header_values_mut(headers, "Cookie") {
        for value in values.iter_mut() {
            *value = redact_cookie_header(value, names);
        }
    }
}

fn redact_cookie_header(cookie: &str, names: &[String]) -> String {
    cookie
        .split(';')
        .map(|pair| {
            let trimmed = pair.trim();
            let name = trimmed
                .split_once('=')
                .map(|(name, _)| name)
                .unwrap_or(trimmed);
            if names.iter().any(|redact| redact == name) {
                format!("{name}={REDACTED}")
            } else {
                trimmed.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Replace the values of matching query parameters in a request URI.
fn redact_query_parameters(uri: &str, names: &[String]) -> String {
    let Some((path, query)) = uri.split_once('?') else {
        return uri.to_string();
    };
    let redacted: Vec<String> = query
        .split('&')
        .map(|pair| {
            if pair.is_empty() {
                return String::new();
            }
            let name = pair.split_once('=').map(|(name, _)| name).unwrap_or(pair);
            if names.iter().any(|redact| redact == name) {
                format!("{name}={REDACTED}")
            } else {
                pair.to_string()
            }
        })
        .collect();
    format!("{path}?{}", redacted.join("&"))
}

fn serialize_timestamp<S: Serializer>(
    timestamp: &SystemTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let seconds = timestamp
        .duration_since(UNIX_EPOCH)
        .map_err(serde::ser::Error::custom)?
        .as_secs_f64();
    serializer.serialize_f64(seconds)
}

fn deserialize_timestamp<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<SystemTime, D::Error> {
    let seconds = f64::deserialize(deserializer)?;
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(serde::de::Error::custom(
            "access log timestamp must be a non-negative finite Unix time in seconds",
        ));
    }
    Ok(UNIX_EPOCH + Duration::from_secs_f64(seconds))
}

fn serialize_duration<S: Serializer>(
    duration: &Duration,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_f64(duration.as_secs_f64())
}

fn deserialize_duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let seconds = f64::deserialize(deserializer)?;
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(serde::de::Error::custom(
            "access log duration must be a non-negative finite number of seconds",
        ));
    }
    Ok(Duration::from_secs_f64(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                value.parse().expect("valid header value"),
            );
        }
        headers
    }

    fn sample_entry() -> AccessLogEntry {
        let request_headers = headers(&[
            ("host", "example.com"),
            ("user-agent", "curl/8.5.0"),
            ("authorization", "Bearer secret"),
            ("cookie", "session=abc; theme=dark"),
        ]);
        let mut request = AccessLogRequest::new("GET", "example.com", "/a?b=c")
            .with_remote(Some("192.0.2.10:54321".parse().unwrap()))
            .with_headers(&request_headers);
        request.proto = "HTTP/2.0".to_string();
        request.tls = Some(AccessLogTls {
            resumed: true,
            version: 772,
            cipher_suite: 4865,
            proto: "h2".to_string(),
            server_name: "example.com".to_string(),
            ech: false,
            client_common_name: None,
            client_serial: None,
        });
        let mut entry = AccessLogEntry::new(request)
            .with_timestamp(UNIX_EPOCH + Duration::from_millis(1_700_000_000_500))
            .with_status(200)
            .with_duration(Duration::from_millis(50))
            .with_size(123)
            .with_response_headers(&headers(&[("content-type", "text/plain")]));
        entry.bytes_read = 7;
        entry.user_id = "user-1".to_string();
        entry
    }

    #[test]
    fn serializes_caddy_compatible_shape() {
        let entry = sample_entry();
        let value = entry.to_json_value().expect("serializes");
        let expected = json!({
            "level": "info",
            "ts": 1_700_000_000.5_f64,
            "logger": "http.log.access",
            "msg": "handled request",
            "request": {
                "remote_ip": "192.0.2.10",
                "remote_port": "54321",
                "proto": "HTTP/2.0",
                "method": "GET",
                "host": "example.com",
                "uri": "/a?b=c",
                "headers": {
                    "Host": ["example.com"],
                    "User-Agent": ["curl/8.5.0"],
                    "Authorization": ["Bearer secret"],
                    "Cookie": ["session=abc; theme=dark"],
                },
                "tls": {
                    "resumed": true,
                    "version": 772,
                    "cipher_suite": 4865,
                    "proto": "h2",
                    "server_name": "example.com",
                    "ech": false,
                },
            },
            "bytes_read": 7,
            "user_id": "user-1",
            "duration": 0.05,
            "size": 123,
            "status": 200,
            "resp_headers": {"Content-Type": ["text/plain"]},
        });
        assert_eq!(value, expected);

        // Direct struct serialization keeps Caddy's logical field order (level first).
        let direct = serde_json::to_string(&entry).unwrap();
        assert!(
            direct.starts_with("{\"level\":\"info\",\"ts\":1700000000.5,\"logger\":\"http.log.access\",\"msg\":\"handled request\",\"request\":"),
            "unexpected struct field order: {direct}"
        );
        // `serde_json::Value` maps are sorted, so configured rendering is byte-deterministic too.
        let rendered_a = entry.render_default().unwrap();
        let rendered_b = entry.render_default().unwrap();
        assert_eq!(rendered_a, rendered_b);
        assert_eq!(
            serde_json::to_string(&rendered_a).unwrap(),
            serde_json::to_string(&rendered_b).unwrap()
        );
    }

    #[test]
    fn credentials_are_redacted_by_default_and_logged_when_enabled() {
        let entry = sample_entry();
        let rendered = entry.render_default().expect("renders");
        assert_eq!(
            rendered["request"]["headers"]["Authorization"],
            json!(["REDACTED"])
        );
        assert_eq!(
            rendered["request"]["headers"]["Cookie"],
            json!(["REDACTED"])
        );
        // Non-credential headers are untouched.
        assert_eq!(
            rendered["request"]["headers"]["User-Agent"],
            json!(["curl/8.5.0"])
        );

        let config = AccessLogConfig {
            log_credentials: true,
            ..AccessLogConfig::default()
        };
        let rendered = entry.render(&config).expect("renders");
        assert_eq!(
            rendered["request"]["headers"]["Authorization"],
            json!(["Bearer secret"])
        );
        assert_eq!(
            rendered["request"]["headers"]["Cookie"],
            json!(["session=abc; theme=dark"])
        );
    }

    #[test]
    fn custom_redactions_cover_headers_cookies_and_query_parameters() {
        let entry = sample_entry();
        let config = AccessLogConfig {
            redaction: RedactionPolicy {
                headers: vec![
                    HeaderRedaction::Replace {
                        header: "User-Agent".to_string(),
                        value: "[replaced]".to_string(),
                        target: HeaderTarget::Both,
                    },
                    HeaderRedaction::Delete {
                        header: "Cookie".to_string(),
                        target: HeaderTarget::Both,
                    },
                ],
                query_parameters: vec!["b".to_string()],
                cookies: vec![],
            },
            ..AccessLogConfig::default()
        };
        let rendered = entry.render(&config).expect("renders");
        assert_eq!(
            rendered["request"]["headers"]["User-Agent"],
            json!(["[replaced]"])
        );
        assert!(rendered["request"]["headers"].get("Cookie").is_none());
        assert_eq!(rendered["request"]["uri"], json!("/a?b=REDACTED"));

        let cookie_config = AccessLogConfig {
            log_credentials: true,
            redaction: RedactionPolicy {
                cookies: vec!["session".to_string()],
                ..RedactionPolicy::default()
            },
            ..AccessLogConfig::default()
        };
        let rendered = entry.render(&cookie_config).expect("renders");
        assert_eq!(
            rendered["request"]["headers"]["Cookie"],
            json!(["session=REDACTED; theme=dark"])
        );
    }

    #[test]
    fn field_selection_keeps_fundamental_fields() {
        let entry = sample_entry();
        let config = AccessLogConfig {
            include: vec![AccessLogField::Request, AccessLogField::Status],
            exclude: vec![AccessLogField::UserId],
            ..AccessLogConfig::default()
        };
        let rendered = entry.render(&config).expect("renders");
        let object = rendered.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["level", "logger", "msg", "request", "status", "ts"]);

        let invalid = AccessLogConfig {
            exclude: vec![AccessLogField::Msg],
            ..AccessLogConfig::default()
        };
        let error = invalid.validate().expect_err("msg cannot be excluded");
        assert_eq!(error.path(), "exclude.msg");

        let duplicate = AccessLogConfig {
            include: vec![AccessLogField::Request, AccessLogField::Request],
            ..AccessLogConfig::default()
        };
        assert_eq!(duplicate.validate().unwrap_err().path(), "include.request");
    }

    #[test]
    fn sampling_matches_zap_first_then_thereafter() {
        let config = SamplingConfig::new(Duration::from_secs(1), 3, 2).unwrap();
        let start = Instant::now();
        let sampler = AccessLogSampler::new(config, start).unwrap();
        let logged: Vec<bool> = (0..8)
            .map(|index| {
                sampler.should_log(
                    start + Duration::from_millis(10 * index),
                    LogLevel::Info,
                    "handled request",
                )
            })
            .collect();
        // 1..=3 logged, then every 2nd: 4 logged, 5 dropped, 6 logged, 7 dropped, 8 logged.
        assert_eq!(logged, [true, true, true, true, false, true, false, true]);

        // A new window resets the counters.
        assert!(sampler.should_log(
            start + Duration::from_secs(1),
            LogLevel::Info,
            "handled request"
        ));

        // Different messages have independent buckets.
        assert!(sampler.should_log(
            start + Duration::from_secs(1),
            LogLevel::Error,
            "other message"
        ));
    }

    #[test]
    fn sampling_config_is_validated() {
        assert_eq!(
            SamplingConfig::new(Duration::ZERO, 1, 1)
                .unwrap_err()
                .path(),
            "sampling.interval"
        );
        assert_eq!(
            SamplingConfig::new(Duration::from_secs(1), 0, 1)
                .unwrap_err()
                .path(),
            "sampling.first"
        );
        assert_eq!(
            SamplingConfig::new(Duration::from_secs(1), 1, 0)
                .unwrap_err()
                .path(),
            "sampling.thereafter"
        );
        assert_eq!(SamplingConfig::default().first, 100);
    }

    #[test]
    fn config_validation_is_located() {
        let invalid_header = AccessLogConfig {
            redaction: RedactionPolicy {
                headers: vec![HeaderRedaction::Redact {
                    header: "bad header".to_string(),
                    target: HeaderTarget::Both,
                }],
                ..RedactionPolicy::default()
            },
            ..AccessLogConfig::default()
        };
        assert_eq!(
            invalid_header.validate().unwrap_err().path(),
            "redaction.headers[0].header"
        );

        let duplicate_header = AccessLogConfig {
            redaction: RedactionPolicy {
                headers: vec![
                    HeaderRedaction::Redact {
                        header: "Authorization".to_string(),
                        target: HeaderTarget::Both,
                    },
                    HeaderRedaction::Delete {
                        header: "authorization".to_string(),
                        target: HeaderTarget::Both,
                    },
                ],
                ..RedactionPolicy::default()
            },
            ..AccessLogConfig::default()
        };
        assert_eq!(
            duplicate_header.validate().unwrap_err().path(),
            "redaction.headers[1].header"
        );

        let empty_query = AccessLogConfig {
            redaction: RedactionPolicy {
                query_parameters: vec!["".to_string()],
                ..RedactionPolicy::default()
            },
            ..AccessLogConfig::default()
        };
        assert_eq!(
            empty_query.validate().unwrap_err().path(),
            "redaction.query_parameters"
        );

        let bad_sampling = AccessLogConfig {
            sampling: Some(SamplingConfig {
                interval: Duration::ZERO,
                first: 1,
                thereafter: 1,
            }),
            ..AccessLogConfig::default()
        };
        assert_eq!(
            bad_sampling.validate().unwrap_err().path(),
            "sampling.interval"
        );
    }

    #[test]
    fn upstream_extension_serializes_only_when_configured() {
        let plain = AccessLogEntry::default().to_json_value().unwrap();
        assert!(plain.get("upstream").is_none());

        let entry = AccessLogEntry::default().with_upstream(AccessLogUpstream {
            dial: "10.0.0.5:8080".to_string(),
            remote_ip: Some("10.0.0.5".to_string()),
            remote_port: Some("8080".to_string()),
            duration: Duration::from_millis(25),
            status: Some(200),
        });
        let value = entry.to_json_value().unwrap();
        assert_eq!(
            value["upstream"],
            json!({
                "dial": "10.0.0.5:8080",
                "remote_ip": "10.0.0.5",
                "remote_port": "8080",
                "duration": 0.025,
                "status": 200,
            })
        );
    }

    #[test]
    fn entry_round_trips_through_json() {
        let entry = sample_entry();
        let text = serde_json::to_string(&entry).unwrap();
        let decoded: AccessLogEntry = serde_json::from_str(&text).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn status_500_and_above_uses_error_level() {
        let entry = AccessLogEntry::default().with_status(500);
        assert_eq!(entry.level, LogLevel::Error);
        let entry = AccessLogEntry::default().with_status(204);
        assert_eq!(entry.level, LogLevel::Info);
    }

    #[test]
    fn canonicalises_header_names_like_go() {
        assert_eq!(canonical_header_name("user-agent"), "User-Agent");
        assert_eq!(canonical_header_name("HOST"), "Host");
        assert_eq!(canonical_header_name("x_forwarded_for"), "X_forwarded_for");
        assert_eq!(canonical_header_name("x-forwarded-for"), "X-Forwarded-For");
        assert_eq!(canonical_header_name(""), "");
    }

    #[test]
    fn remote_address_splits_like_caddy() {
        assert_eq!(
            remote_ip_port(Some("192.0.2.10:54321".parse().unwrap())),
            ("192.0.2.10".to_string(), "54321".to_string())
        );
        assert_eq!(remote_ip_port(None), (String::new(), String::new()));
    }

    #[test]
    fn config_round_trips_through_json_with_defaults() {
        let config = AccessLogConfig {
            include: vec![AccessLogField::Request, AccessLogField::Status],
            exclude: vec![AccessLogField::Upstream],
            log_credentials: true,
            redaction: RedactionPolicy {
                headers: vec![HeaderRedaction::Delete {
                    header: "Cookie".to_string(),
                    target: HeaderTarget::Both,
                }],
                query_parameters: vec!["token".to_string()],
                cookies: vec![],
            },
            sampling: Some(SamplingConfig::default()),
        };
        let text = serde_json::to_string(&config).expect("config serializes");
        assert!(text.contains("\"action\":\"delete\""), "got: {text}");
        assert!(
            text.contains("\"include\":[\"request\",\"status\"]"),
            "got: {text}"
        );
        let decoded: AccessLogConfig = serde_json::from_str(&text).expect("config deserializes");
        assert_eq!(decoded, config);

        // A redaction rule without `target` defaults to both header maps.
        let decoded: AccessLogConfig = serde_json::from_str(
            r#"{"redaction":{"headers":[{"action":"redact","header":"X-Secret"}]}}"#,
        )
        .expect("minimal config decodes");
        assert_eq!(
            decoded.redaction.headers,
            [HeaderRedaction::Redact {
                header: "X-Secret".to_string(),
                target: HeaderTarget::Both,
            }]
        );
        assert!(!decoded.log_credentials);
        assert!(decoded.sampling.is_none());
    }

    #[test]
    fn renders_default_json_string() {
        let entry = sample_entry();
        let text = entry.render_string(&AccessLogConfig::default()).unwrap();
        assert!(text.contains("\"Authorization\":[\"REDACTED\"]"));
        assert!(text.contains("\"status\":200"));
    }
}
