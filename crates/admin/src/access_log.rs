//! Structured access-log record model (plan task T-ADMIN-020).
//!
//! Caddy emits one structured entry per handled request through its access logger. This module
//! models that entry as typed Rust values, with the field names and shapes Caddy's access log uses
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
//!   Caddy's `LoggableHTTPHeader` — for the request headers *and* the `resp_headers` object
//!   (`modules/caddyhttp/server.go:1314`).
//! * Header names are canonicalised (MIME header form) because caddy-rs's `http::HeaderMap` may
//!   store lowercase names, while Caddy emits canonical Go header names.
//! * `ts` and `duration` are floating-point seconds (zap's JSON encoder), not duration strings.
//! * The `upstream` field is a caddy-rs extension: Caddy logs upstream selection only at
//!   DEBUG level via the proxy module (`reverseproxy.go:1125-1127`), not in the access entry.
//!   It is documented in the AS-09 schema (`docs/compatibility/ACCEPTANCE.md`) and tracked by
//!   DIV-0069.
//! * Field selection is a crate-level primitive; Caddy configures the same idea through
//!   `filter` encoder modules (`caddy.logging.encoders.filter`) applied to zap fields. The four
//!   fields zap itself owns (`ts`, `level`, `logger`, `msg`) cannot be filtered, matching Caddy's
//!   `FilterEncoder` documentation.
//!
//! ## Field coverage (T-ADMIN-043)
//!
//! Caddy's `logRequest` emits exactly these built-in top-level fields, in order
//! (`modules/caddyhttp/server.go:1309-1322`): `bytes_read`, `user_id`, `duration`, `size`, `status`,
//! `resp_headers`, `write_error` (only when the write failed) and then the `ExtraLogFields`
//! entries. [`AccessLogEntry`] models every one of them with the same JSON key and type.
//!
//! * `bytes_read` is the **actual** request-body bytes read, not the declared `Content-Length`
//!   (Caddy's `lengthReader`, `server.go:1600`). Use [`BodyBytes`] shared with the server's body
//!   pipeline.
//! * `size` is the **actual** response-body bytes written (Caddy's `ResponseRecorder.Size()`,
//!   `responsewriter.go:210`), also available through [`BodyBytes`].
//! * `duration` is time-to-last-byte, measured after the handler chain (`server.go:710`, `:715`),
//!   not time-to-headers; [`RequestTiming`] makes that boundary explicit.
//! * `user_id` is Caddy's `http.auth.user.id` (`server.go:1289-1290`), always emitted and empty
//!   when the request is anonymous.
//! * Optional fields (`write_error`, `client_ip`, `transfer_encoding`, `tls`, `uuid`, `traceID`,
//!   `spanID`, extras) are omitted when unset, exactly like Caddy; the always-emitted fields are
//!   never dropped.
//! * [`AccessLogContext`] is the shared per-request carrier for the values only the server and
//!   handlers can observe (byte counters, user id, upstream attempt, write error, extras), so the
//!   entry can be rendered after the response body has been streamed. It also carries Caddy's
//!   post-routing `log_skip`/`log_name`/`log_level` request variables
//!   ([`AccessLogContext::set_log_skip`], [`AccessLogContext::set_logger_names`],
//!   [`AccessLogContext::set_log_level`]) from the `vars` handler to the emission point.
//!
//! ## Request correlation and tracing (T-ADMIN-022)
//!
//! Caddy's `{http.request.uuid}` placeholder (`modules/caddyhttp/replacer.go`) lazily generates a
//! random UUIDv4 for the request, caches it for the request's lifetime and, on first access, adds a
//! top-level access-log field named `uuid` through `ExtraLogFields` (log-only; it is never injected
//! into request/response headers). Caddy's OpenTelemetry tracing handler
//! (`modules/caddyhttp/tracing/tracer.go`) adds top-level fields `traceID` and `spanID` when a
//! valid span context exists. [`RequestUuid`] reproduces the lazy/cached UUID value and
//! [`AccessLogEntry`] models all three fields with Caddy's exact names.
//!
//! The placeholder itself is expanded by `crates/http`'s replacer; wiring `{http.request.uuid}`
//! into that replacer, generating the id only when a placeholder/access-log config asks for it, and
//! populating the fields from the server request path are server/http hooks reported with
//! T-ADMIN-022 (this crate provides the id generation and log model).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, HeaderName};
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Default access logger name, matching Caddy's `http.log.access`.
pub const DEFAULT_ACCESS_LOGGER: &str = "http.log.access";
/// Caddy logger name that receives structured HTTP access entries.
pub const ACCESS_LOG_LOGGER: &str = DEFAULT_ACCESS_LOGGER;
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
    /// Client IP (`client_ip` in Caddy's log entry).
    ///
    /// Caddy always sets the `client_ip` request variable: it is the peer IP unless a
    /// `trusted_proxies` matcher rewrites it from a forwarding header. [`AccessLogRequest::with_remote`]
    /// therefore defaults it to the peer IP; a trusted-proxy-aware caller overrides it with
    /// [`AccessLogRequest::with_client_ip`].
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
    ///
    /// Also defaults `client_ip` to the peer IP, matching Caddy's default `client_ip` request
    /// variable (it is only replaced when a trusted-proxy matcher supplies a forwarded address).
    pub fn with_remote(mut self, remote: Option<SocketAddr>) -> Self {
        let (ip, port) = remote_ip_port(remote);
        if !ip.is_empty() {
            self.client_ip = Some(ip.clone());
        }
        self.remote_ip = ip;
        self.remote_port = port;
        self
    }

    /// Override the client IP derived from a trusted proxy (`trusted_proxies` support lives in the
    /// server layer; the admin crate only owns the log-request shape).
    pub fn with_client_ip(mut self, client_ip: Option<String>) -> Self {
        self.client_ip = client_ip;
        self
    }

    /// Copy headers into the canonicalised, value-array form used in logs.
    ///
    /// The `Host` request header is omitted: Caddy logs the request host as `request.host` and its
    /// `request.headers` object is Go's `http.Header`, which excludes `Host` by construction.
    pub fn with_headers(mut self, headers: &HeaderMap) -> Self {
        self.headers = headers_to_loggable(headers);
        self.headers.remove("Host");
        self
    }
}

/// The caddy-rs `upstream` extension object of an access entry.
///
/// Caddy does not put upstream selection in access entries; caddy-rs adds it so a proxy
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

/// Actual body byte count shared with the code that moves the bytes.
///
/// Caddy counts *actual* bytes, not declared lengths: the request body is wrapped in
/// `lengthReader` (`modules/caddyhttp/server.go:1600`) whose `Length` is incremented on every
/// `Read`, and the response size is the `ResponseRecorder`'s byte counter
/// (`modules/caddyhttp/responsewriter.go:210`). Both feed the access entry as `bytes_read` and
/// `size` (`server.go:1309`, `server.go:1312`); a streamed or unread body therefore logs `0`
/// rather than its `Content-Length`.
///
/// caddy-rs streams bodies, so the entry is rendered from a counter shared with the body pipeline:
/// the server clones this handle into its body wrapper (calling [`BodyBytes::add`] for every
/// chunk) and reads the same handle when the entry is built. Clones share one counter.
#[derive(Clone, Debug, Default)]
pub struct BodyBytes {
    count: Arc<AtomicU64>,
}

impl BodyBytes {
    /// A counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add bytes moved since the last update (called per body chunk).
    pub fn add(&self, bytes: u64) {
        self.count.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Overwrite the count (for a body whose exact size became known in one step).
    pub fn set(&self, bytes: u64) {
        self.count.store(bytes, Ordering::Relaxed);
    }

    /// The bytes counted so far.
    pub fn get(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// Monotonic request clock for Caddy's `duration` field.
///
/// Caddy computes the access entry's `duration` as `time.Since(start)` *after* the handler chain
/// returns (`modules/caddyhttp/server.go:710` and `:715`): time-to-last-byte, not time-to-headers.
/// The proxy's time-to-headers observation is a separate value (`http.reverse_proxy.upstream.latency`,
/// `modules/caddyhttp/reverseproxy/reverseproxy.go:1154`) and never becomes the access `duration`.
///
/// The server starts the clock when it takes ownership of the request, optionally marks when
/// response headers are committed (time-to-headers, for metrics/`response_duration`), and calls
/// [`RequestTiming::finish`] when the last byte of the response body has been written. The entry is
/// then rendered with [`RequestTiming::duration`]. Rendering an unfinished clock returns the
/// elapsed time so far, exactly like Caddy's `{http.request.duration}` placeholder
/// (`modules/caddyhttp/replacer.go:212`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestTiming {
    started: Instant,
    response_started: Option<Instant>,
    finished: Option<Instant>,
}

impl RequestTiming {
    /// Start the clock now.
    pub fn start() -> Self {
        Self::start_at(Instant::now())
    }

    /// Start the clock at an already captured instant.
    pub fn start_at(started: Instant) -> Self {
        Self {
            started,
            response_started: None,
            finished: None,
        }
    }

    /// When the clock started.
    pub fn started_at(&self) -> Instant {
        self.started
    }

    /// Mark response headers as committed and return the time-to-headers.
    pub fn mark_response_started(&mut self) -> Duration {
        self.mark_response_started_at(Instant::now())
    }

    /// Mark response headers as committed at `at` and return the time-to-headers.
    pub fn mark_response_started_at(&mut self, at: Instant) -> Duration {
        self.response_started = Some(at);
        at.saturating_duration_since(self.started)
    }

    /// When response headers were committed, if they were marked.
    pub fn response_started_at(&self) -> Option<Instant> {
        self.response_started
    }

    /// Record the last byte (or the end of the handler chain) and return the total duration.
    pub fn finish(&mut self) -> Duration {
        self.finish_at(Instant::now())
    }

    /// Record the last byte at `at` and return the total duration.
    pub fn finish_at(&mut self, at: Instant) -> Duration {
        self.finished = Some(at);
        at.saturating_duration_since(self.started)
    }

    /// Whether [`RequestTiming::finish`] has run.
    pub fn is_finished(&self) -> bool {
        self.finished.is_some()
    }

    /// The finished instant, when the response is complete.
    pub fn finished_at(&self) -> Option<Instant> {
        self.finished
    }

    /// Total duration: finished time-to-last-byte, or elapsed time so far.
    pub fn duration(&self) -> Duration {
        match self.finished {
            Some(at) => at.saturating_duration_since(self.started),
            None => Instant::now().saturating_duration_since(self.started),
        }
    }

    /// Time from request start to response headers, when that boundary was marked.
    pub fn time_to_headers(&self) -> Option<Duration> {
        self.response_started
            .map(|at| at.saturating_duration_since(self.started))
    }
}

/// One extra top-level access-log field (one entry of Caddy's `ExtraLogFields`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtraLogField {
    /// Top-level JSON key.
    pub key: String,
    /// JSON value (string, number, array or object).
    pub value: serde_json::Value,
}

/// Ordered extra top-level access-log fields, mirroring Caddy's `ExtraLogFields`.
///
/// Caddy attaches an `ExtraLogFields` value to the request context
/// (`modules/caddyhttp/logging.go:320`) and handlers add or replace fields during request
/// handling; `logRequest` appends them after the built-in fields (`server.go:1321`). Caddy's own
/// extras are `uuid` (`modules/caddyhttp/replacer.go:228`, `Set` semantics), `traceID`/`spanID`
/// (`modules/caddyhttp/tracing/tracer.go:111`, `Add` semantics) and arbitrary keys from
/// `log_append` (`modules/caddyhttp/logging/logappend.go:158`, `Add` semantics).
///
/// caddy-rs models `uuid`/`traceID`/`spanID` as dedicated typed fields on [`AccessLogEntry`]; this
/// container carries any further key the runtime contributes (for example a proxy observation),
/// serialised inline as a top-level key in insertion order, exactly like Caddy.
///
/// Keys must not collide with the built-in entry keys (`status`, `size`, `request`, ...); neither
/// Caddy's `log_append` nor this container rejects such a collision, but it produces a duplicate
/// JSON key.
///
/// [`AccessLogField`] is a closed enum of Caddy's built-in keys, so `include`/`exclude` field
/// selection cannot name an extra key (Caddy's filter encoder, which filters zap fields by key,
/// can). Explicit `include` selection therefore drops extras; targets `FieldFilter` operations
/// still address them by JSON path.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExtraLogFields {
    fields: Vec<ExtraLogField>,
}

impl ExtraLogFields {
    /// No extra fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether no extra field is present.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Number of extra fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Add a field, replacing an existing field with the same key in place.
    ///
    /// Caddy's `Add` appends unconditionally, so a duplicate key produces a duplicate JSON key;
    /// caddy-rs keeps a single slot per key (the last value wins for JSON consumers) and preserves
    /// the original position.
    pub fn add(&mut self, key: impl Into<String>, value: serde_json::Value) {
        let key = key.into();
        if let Some(existing) = self.fields.iter_mut().find(|field| field.key == key) {
            existing.value = value;
            return;
        }
        self.fields.push(ExtraLogField { key, value });
    }

    /// Replace an existing field, or append it (Caddy's `ExtraLogFields.Set`).
    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.add(key, value);
    }

    /// Value of one extra field.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| &field.value)
    }

    /// Iterate `(key, value)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &serde_json::Value)> {
        self.fields
            .iter()
            .map(|field| (field.key.as_str(), &field.value))
    }
}

impl Serialize for ExtraLogFields {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for field in &self.fields {
            map.serialize_entry(&field.key, &field.value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ExtraLogFields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ExtraLogFieldsVisitor;

        impl<'de> Visitor<'de> for ExtraLogFieldsVisitor {
            type Value = ExtraLogFields;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map of extra access-log fields")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    fields.push(ExtraLogField { key, value });
                }
                Ok(ExtraLogFields { fields })
            }
        }

        deserializer.deserialize_map(ExtraLogFieldsVisitor)
    }
}

/// Per-request access-log context shared between the server and the handler pipeline.
///
/// Caddy keeps the per-request logging state on the request context: the `ExtraLogFields` value is
/// installed before routing (`modules/caddyhttp/server.go:1422`) and handlers write to it, the
/// request body is wrapped in a `lengthReader` (`server.go:1600`) and the response in a
/// `ResponseRecorder` (`responsewriter.go:210`); `logRequest` reads all of it when the entry is
/// rendered (`server.go:1289-1322`). caddy-rs has the same shape of data but the server renders the
/// entry boundary-side, after the body has been streamed, so the observations must be shared.
///
/// A server creates one context per request when access logging is enabled, stores it on the
/// request (or a transport-owned per-request state), lets handlers contribute
/// (`set_user_id`, `set_upstream`, `add_extra_field`, `set_write_error`) and calls [`apply_to`]
/// when the response is complete (after [`AccessLogContext::finish`]). The context also carries
/// the post-routing access-log decision Caddy reads from the request context: [`set_log_skip`],
/// [`set_logger_names`] (`log_name`) and [`set_log_level`]. All clones share one state.
///
/// [`set_log_skip`]: AccessLogContext::set_log_skip
/// [`set_logger_names`]: AccessLogContext::set_logger_names
/// [`set_log_level`]: AccessLogContext::set_log_level
///
/// [`apply_to`]: AccessLogContext::apply_to
#[derive(Clone, Debug, Default)]
pub struct AccessLogContext {
    inner: Arc<Mutex<AccessLogContextState>>,
}

#[derive(Debug, Default)]
struct AccessLogContextState {
    timing: Option<RequestTiming>,
    request_bytes: BodyBytes,
    response_bytes: BodyBytes,
    user_id: Option<String>,
    upstream: Option<AccessLogUpstream>,
    write_error: Option<String>,
    /// Caddy's `log_skip` request variable: when true, only the access entry is suppressed.
    log_skip: bool,
    /// Caddy's `access_logger_names` request variable (`log_name`): the explicit logger names for
    /// this request. `None` means the variable is unset (or was assigned a non-array value), so
    /// the server's per-host mapping decides; `Some([])` selects no logger at all.
    logger_names: Option<Vec<String>>,
    /// Caddy's `log_level` request variable: the raw value the last assignment stored. Parsed
    /// leniently at emission time (`DEBUG`..=`ERROR`); `None` keeps the status-derived level.
    log_level: Option<String>,
    extra_fields: ExtraLogFields,
}

impl AccessLogContext {
    /// A context with no observations.
    pub fn new() -> Self {
        Self::default()
    }

    /// A context whose request clock starts now.
    pub fn started() -> Self {
        let context = Self::default();
        context.start(Instant::now());
        context
    }

    /// Start the request clock at `at`.
    pub fn start(&self, at: Instant) {
        self.state().timing = Some(RequestTiming::start_at(at));
    }

    /// The shared request-body byte counter (`bytes_read`).
    pub fn request_bytes(&self) -> BodyBytes {
        self.state().request_bytes.clone()
    }

    /// The shared response-body byte counter (`size`).
    pub fn response_bytes(&self) -> BodyBytes {
        self.state().response_bytes.clone()
    }

    /// The request clock, once started.
    pub fn timing(&self) -> Option<RequestTiming> {
        self.state().timing
    }

    /// Mark response headers as committed; returns the time-to-headers.
    pub fn mark_response_started(&self) -> Option<Duration> {
        self.state()
            .timing
            .as_mut()
            .map(RequestTiming::mark_response_started)
    }

    /// Record the last byte and return the total duration.
    pub fn finish(&self) -> Option<Duration> {
        self.state().timing.as_mut().map(RequestTiming::finish)
    }

    /// Total duration so far (finished or not).
    pub fn duration(&self) -> Option<Duration> {
        self.state().timing.map(|timing| timing.duration())
    }

    /// Replace the authenticated user id (`http.auth.user.id` / Caddy's `user_id`).
    ///
    /// Caddy reads this placeholder after the handler chain (`server.go:1289`) and always emits
    /// the field, with `""` for anonymous requests.
    pub fn set_user_id(&self, user_id: impl Into<String>) {
        self.state().user_id = Some(user_id.into());
    }

    /// The authenticated user id, when a handler set one.
    pub fn user_id(&self) -> Option<String> {
        self.state().user_id.clone()
    }

    /// Record the proxy attempt for the caddy-rs `upstream` extension.
    pub fn set_upstream(&self, upstream: AccessLogUpstream) {
        self.state().upstream = Some(upstream);
    }

    /// The recorded proxy attempt, when the request was proxied.
    pub fn upstream(&self) -> Option<AccessLogUpstream> {
        self.state().upstream.clone()
    }

    /// Record the error that prevented the response from being fully written.
    pub fn set_write_error(&self, error: impl Into<String>) {
        self.state().write_error = Some(error.into());
    }

    /// The recorded write error.
    pub fn write_error(&self) -> Option<String> {
        self.state().write_error.clone()
    }

    /// Record Caddy's `log_skip` request variable for the access logger.
    ///
    /// Caddy sets this variable through the generic `vars` handler and reads it after the handler
    /// chain (`modules/caddyhttp/server.go:1246-1253`); only the access-log entry is skipped, while
    /// metrics, the status code and the response are unaffected.
    pub fn set_log_skip(&self, skip: bool) {
        self.state().log_skip = skip;
    }

    /// Whether the request is excluded from the access log.
    pub fn log_skip(&self) -> bool {
        self.state().log_skip
    }

    /// Record Caddy's `access_logger_names` request variable (the `log_name` directive).
    ///
    /// Caddy's `ServerLogConfig.wrapLogger` checks this variable after the handler chain and, when
    /// it holds a JSON array, uses those names for the request instead of the per-host mapping
    /// (`modules/caddyhttp/logging.go:98-112`). `None` clears a previous assignment: Caddy's type
    /// assertion only accepts an array, so any other value leaves the per-host mapping in charge.
    /// An empty list selects no logger, which suppresses the entry exactly like Caddy.
    pub fn set_logger_names(&self, names: Option<Vec<String>>) {
        self.state().logger_names = names;
    }

    /// The explicit per-request logger names, when a valid `access_logger_names` array was set.
    pub fn logger_names(&self) -> Option<Vec<String>> {
        self.state().logger_names.clone()
    }

    /// Record Caddy's `log_level` request variable.
    ///
    /// Caddy stores the assignment verbatim and only uses it when the value is a string that
    /// parses to `DEBUG`..=`ERROR` (`modules/caddyhttp/server.go:1271-1282`). `None` clears a
    /// previous assignment, which is what a non-string value does at request time.
    pub fn set_log_level(&self, level: Option<String>) {
        self.state().log_level = level;
    }

    /// The raw `log_level` request variable value, when a string assignment was stored.
    pub fn log_level(&self) -> Option<String> {
        self.state().log_level.clone()
    }

    /// Add an extra top-level field (Caddy's `ExtraLogFields`).
    pub fn add_extra_field(&self, key: impl Into<String>, value: serde_json::Value) {
        self.state().extra_fields.add(key, value);
    }

    /// Add or replace an extra top-level field (Caddy's `ExtraLogFields.Set`).
    pub fn set_extra_field(&self, key: impl Into<String>, value: serde_json::Value) {
        self.state().extra_fields.set(key, value);
    }

    /// A copy of the extra fields collected so far.
    pub fn extra_fields(&self) -> ExtraLogFields {
        self.state().extra_fields.clone()
    }

    /// Copy every collected observation onto an entry.
    ///
    /// The context is authoritative for the fields it tracks: request/response byte counters,
    /// request duration, authenticated user id, upstream extension, write error and extra fields.
    /// Call this after [`AccessLogContext::finish`] and after the response body is complete.
    pub fn apply_to(&self, entry: &mut AccessLogEntry) {
        let state = self.state();
        entry.bytes_read = state.request_bytes.get();
        entry.size = state.response_bytes.get();
        if let Some(timing) = state.timing {
            entry.duration = timing.duration();
        }
        if let Some(user_id) = &state.user_id {
            entry.user_id = user_id.clone();
        }
        if let Some(upstream) = &state.upstream {
            entry.upstream = Some(upstream.clone());
        }
        if let Some(write_error) = &state.write_error {
            entry.write_error = Some(write_error.clone());
        }
        if !state.extra_fields.is_empty() {
            entry.extra_fields = state.extra_fields.clone();
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, AccessLogContextState> {
        // The access-log path must never panic; a poisoned lock still carries the observations.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
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
    /// Per-request correlation id from `{http.request.uuid}` (Caddy's extra log field `uuid`,
    /// log-only and only present when the request accessed the placeholder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// OpenTelemetry trace id from Caddy's tracing handler (extra log field `traceID`).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "traceID")]
    pub trace_id: Option<String>,
    /// OpenTelemetry span id from Caddy's tracing handler (extra log field `spanID`).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "spanID")]
    pub span_id: Option<String>,
    /// Additional top-level fields contributed by the runtime (Caddy's `ExtraLogFields`).
    ///
    /// Serialized inline after the built-in fields, in insertion order; absent when empty.
    #[serde(default, flatten)]
    pub extra_fields: ExtraLogFields,
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
            uuid: None,
            trace_id: None,
            span_id: None,
            extra_fields: ExtraLogFields::default(),
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

    /// Attach the per-request correlation id (`{http.request.uuid}` / extra field `uuid`).
    pub fn with_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    /// Attach OpenTelemetry trace/span ids (Caddy's `traceID`/`spanID` extra fields).
    pub fn with_trace_context(
        mut self,
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
    ) -> Self {
        self.trace_id = Some(trace_id.into());
        self.span_id = Some(span_id.into());
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

    /// Set the request duration from a [`RequestTiming`] clock.
    ///
    /// Caddy's `duration` is time-to-last-byte (`server.go:715`); finish the clock when the last
    /// response body byte has been written, not when headers are committed.
    pub fn with_timing(mut self, timing: RequestTiming) -> Self {
        self.duration = timing.duration();
        self
    }

    /// Set the authenticated user id (Caddy's `user_id`, from `http.auth.user.id`).
    ///
    /// Caddy always emits the field after the handler chain, with `""` when the request was not
    /// authenticated (`server.go:1290`); the default entry already has that empty value.
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = user_id.into();
        self
    }

    /// Set the actual number of request-body bytes read (Caddy's `bytes_read`).
    pub fn with_bytes_read(mut self, bytes: u64) -> Self {
        self.bytes_read = bytes;
        self
    }

    /// Set `bytes_read` from a counter shared with the request body pipeline.
    pub fn with_bytes_read_counter(mut self, counter: &BodyBytes) -> Self {
        self.bytes_read = counter.get();
        self
    }

    /// Set the response size.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Set `size` from a counter shared with the response body writer.
    pub fn with_size_counter(mut self, counter: &BodyBytes) -> Self {
        self.size = counter.get();
        self
    }

    /// Set the write error (Caddy's `write_error`, present only when the write failed).
    pub fn with_write_error(mut self, error: impl Into<String>) -> Self {
        self.write_error = Some(error.into());
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

    /// Add one extra top-level field (Caddy's `ExtraLogFields`).
    pub fn with_extra_field(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extra_fields.add(key, value);
        self
    }

    /// Replace the extra top-level fields (Caddy's `ExtraLogFields`).
    pub fn with_extra_fields(mut self, fields: ExtraLogFields) -> Self {
        self.extra_fields = fields;
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
        config.apply_field_filters(&mut value);
        config.apply_key_options(&mut value);
        config.apply_format_options(&mut value);
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
    /// `uuid` (`{http.request.uuid}` correlation id, Caddy extra log field)
    Uuid,
    /// `traceID` (OpenTelemetry trace id, Caddy tracing extra log field)
    TraceId,
    /// `spanID` (OpenTelemetry span id, Caddy tracing extra log field)
    SpanId,
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
            AccessLogField::Uuid => "uuid",
            AccessLogField::TraceId => "traceID",
            AccessLogField::SpanId => "spanID",
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

/// One Caddy `logging.encoders.filter` field rule applied to the rendered JSON entry.
///
/// This is caddy-rs's representation of Caddy's filter modules that operate on a named field
/// (`fields: {"<path>": {"filter": "<module>", ...}}`). Path segments are separated by `>` (for
/// example `request>headers>User-Agent`). The fundamental encoder fields (`ts`, `level`,
/// `logger`, `msg`) cannot be filtered, matching Caddy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldFilter {
    /// Field path segments (`>`-separated in Caddy JSON, already split here).
    pub path: Vec<String>,
    /// Operation to apply to the field value.
    pub operation: FieldFilterOperation,
}

/// A supported Caddy log-field filter operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldFilterOperation {
    /// Remove the field.
    Delete,
    /// Replace the value (or every element of a string array) with a fixed string.
    Replace {
        /// Replacement value.
        value: String,
    },
    /// Rename the field key (within its containing object).
    Rename {
        /// New field name.
        name: String,
    },
    /// Replace string value(s) with the first 4 bytes of their SHA-256 hash, hex-encoded
    /// (Caddy's `hash` filter: `fmt.Sprintf("%.4x", sha256.Sum256(...))`).
    Hash,
    /// Mask IP address(es) with CIDR prefix lengths (Caddy's `ip_mask` filter).
    IpMask {
        /// IPv4 prefix length (0-32); absent leaves the address unmasked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        v4_mask: Option<u8>,
        /// IPv6 prefix length (0-128); absent leaves the address unmasked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        v6_mask: Option<u8>,
    },
    /// Filter URL query parameters (Caddy's `query` filter) on string value(s).
    Query {
        /// Ordered actions applied to the query string.
        actions: Vec<FilterAction>,
    },
    /// Filter `Cookie` header values (Caddy's `cookie` filter).
    Cookie {
        /// Ordered cookie-name actions (first matching action per name wins, as in Caddy).
        actions: Vec<FilterAction>,
    },
    /// Filter `Set-Cookie` header values, preserving the attribute suffix verbatim (Caddy's
    /// `set_cookie` filter).
    SetCookie {
        /// Ordered cookie-name actions (first matching action per name wins).
        actions: Vec<FilterAction>,
    },
    /// Replace regexp matches using Go-style `$N`/`${N}` capture expansion (Caddy's `regexp`
    /// filter).
    Regexp {
        /// RE2-compatible pattern (see [`caddy_rs_core::regex`]).
        pattern: String,
        /// Replacement template.
        replacement: String,
    },
    /// Apply several regexp replacements in order (Caddy's `multi_regexp` filter).
    MultiRegexp {
        /// Ordered regexp replacements (Caddy caps this at 50).
        operations: Vec<RegexpOperation>,
    },
}

/// One `query`/`cookie`/`set_cookie` filter action (Caddy's `{type, parameter|name, value}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterAction {
    /// Action type (`replace`, `hash` or `delete`).
    pub action: FilterActionKind,
    /// Query parameter name or cookie name.
    pub name: String,
    /// Replacement value for `replace` (empty for the other actions).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
}

/// Supported query/cookie filter action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterActionKind {
    /// Replace the value with [`FilterAction::value`].
    Replace,
    /// Replace the value with the first 4 bytes of its SHA-256 (Caddy's hash helper).
    Hash,
    /// Remove the parameter/cookie.
    Delete,
}

/// One regexp replacement in a `multi_regexp` operation list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegexpOperation {
    /// Go/RE2-subset pattern.
    pub pattern: String,
    /// Replacement template (`$1` capture expansion).
    pub replacement: String,
}

/// Caddy's `multi_regexp` limits (security hardening from Caddy v2.11.7).
const MAX_REGEXP_OPERATIONS: usize = 50;
const MAX_REGEXP_PATTERN_LENGTH: usize = 1000;

/// Memoized regex compilation for filter patterns (compiled once per distinct pattern).
fn compiled_regex(pattern: &str) -> Option<caddy_rs_core::regex::Regex> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<std::collections::BTreeMap<String, caddy_rs_core::regex::Regex>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(std::collections::BTreeMap::new()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(regex) = cache.get(pattern) {
        return Some(regex.clone());
    }
    match caddy_rs_core::regex::Regex::new(pattern) {
        Ok(regex) => {
            cache.insert(pattern.to_string(), regex.clone());
            Some(regex)
        }
        Err(_) => None,
    }
}

/// Replace all regexp matches in `input` using Go-style capture expansion.
///
/// Delegates to [`caddy_rs_core::regex::Regex::replace_all`], whose match iterator follows Go's
/// `Regexp.ReplaceAllString` (`src/regexp/regexp.go`, `replaceAll`): it advances one UTF-8 code
/// point after a zero-length match and skips an empty match that immediately follows a non-empty
/// one. Re-running [`caddy_rs_core::regex::Regex::captures`] on the remaining suffix, as an earlier
/// implementation did, re-anchored `^`/`$` to every suffix and looped forever once a pattern that
/// can match the empty string (`a*`, `^`, `(?:)`) met an exhausted suffix; the `regex` crate
/// iterator guarantees forward progress, so there is no loop to bound here.
fn regexp_replace_all(pattern: &str, replacement: &str, input: &str) -> String {
    let Some(regex) = compiled_regex(pattern) else {
        return input.to_string();
    };
    regex.replace_all(input, replacement)
}

/// Convert days since 1970-01-01 to (year, month, day) (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (
        year + i64::from(month <= 2),
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// Format a Unix timestamp in one of Caddy/zap's named encoder formats (UTC; `time_local` is
/// rejected by validation because the offline build has no timezone database).
fn format_time(seconds: f64, format: &str) -> serde_json::Value {
    let whole = seconds.floor() as i64;
    let nanos = ((seconds - whole as f64) * 1_000_000_000.0)
        .round()
        .clamp(0.0, 999_999_999.0) as u32;
    let days = whole.div_euclid(86_400);
    let seconds_of_day = whole.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    let millis = nanos / 1_000_000;
    match format {
        "unix_seconds_float" => serde_json::Value::from(seconds),
        "unix_milli_float" => serde_json::Value::from(seconds * 1000.0),
        "unix_nano" => serde_json::Value::from((seconds * 1_000_000_000.0).round() as i64),
        "wall_milli" => serde_json::Value::String(format!(
            "{year:04}/{month:02}/{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03}"
        )),
        "wall" => serde_json::Value::String(format!(
            "{year:04}/{month:02}/{day:02} {hour:02}:{minute:02}:{second:02}"
        )),
        "wall_nano" => serde_json::Value::String(format!(
            "{year:04}/{month:02}/{day:02} {hour:02}:{minute:02}:{second:02}.{nanos:09}"
        )),
        "iso8601" | "rfc3339" => serde_json::Value::String(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        )),
        "rfc3339_nano" => serde_json::Value::String(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z"
        )),
        "common_log" => {
            const MONTHS: [&str; 12] = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            let month_name = MONTHS[usize::try_from(month).unwrap_or(1) - 1];
            serde_json::Value::String(format!(
                "{day:02}/{month_name}/{year:04}:{hour:02}:{minute:02}:{second:02} +0000"
            ))
        }
        _ => serde_json::Value::String(format!(
            "{year:04}/{month:02}/{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03}"
        )),
    }
}

fn level_color(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "error" | "fatal" | "panic" | "dpanic" => 31,
        "warn" => 33,
        "info" => 34,
        _ => 35,
    }
}

/// Render a duration the way zap's string duration encoder does for common magnitudes.
fn format_duration(seconds: f64) -> String {
    let nanos = (seconds * 1_000_000_000.0) as i128;
    if nanos.abs() >= 1_000_000_000 {
        format!("{seconds}s")
    } else if nanos.abs() >= 1_000_000 {
        format!("{}ms", seconds * 1000.0)
    } else if nanos.abs() >= 1000 {
        format!("{}µs", seconds * 1_000_000.0)
    } else {
        format!("{nanos}ns")
    }
}

/// Apply query-parameter actions to one URL/path string (preserving pair order).
fn filter_query(value: &str, actions: &[FilterAction]) -> String {
    let (before_fragment, fragment) = match value.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (value, None),
    };
    let (path, query) = match before_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (before_fragment, None),
    };
    let Some(query) = query else {
        return value.to_string();
    };
    let mut pairs: Vec<String> = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, _original_value) = match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        };
        let mut removed = false;
        let mut replacement: Option<String> = None;
        for action in actions {
            if action.name != name {
                continue;
            }
            match action.action {
                FilterActionKind::Replace => replacement = Some(action.value.clone()),
                FilterActionKind::Hash => {
                    replacement = Some(short_sha256(pair.split_once('=').map_or("", |(_, v)| v)))
                }
                FilterActionKind::Delete => removed = true,
            }
            break; // Caddy applies the first matching action per parameter.
        }
        if removed {
            continue;
        }
        match replacement {
            Some(value) => pairs.push(format!("{name}={value}")),
            None => pairs.push(pair.to_string()),
        }
    }
    let mut result = path.to_string();
    if !pairs.is_empty() {
        result.push('?');
        result.push_str(&pairs.join("&"));
    }
    if let Some(fragment) = fragment {
        result.push('#');
        result.push_str(fragment);
    }
    result
}

/// Apply cookie actions to a `Cookie` header value.
fn filter_cookie_header(value: &str, actions: &[FilterAction]) -> String {
    let mut cookies = Vec::new();
    for cookie in value.split(';') {
        let cookie = cookie.trim();
        if cookie.is_empty() {
            continue;
        }
        let (name, cookie_value) = match cookie.split_once('=') {
            Some((name, value)) => (name.trim(), value),
            None => (cookie, ""),
        };
        let mut removed = false;
        let mut replacement: Option<String> = None;
        for action in actions {
            if action.name != name {
                continue;
            }
            match action.action {
                FilterActionKind::Replace => replacement = Some(action.value.clone()),
                FilterActionKind::Hash => replacement = Some(short_sha256(cookie_value)),
                FilterActionKind::Delete => removed = true,
            }
            break;
        }
        if removed {
            continue;
        }
        match replacement {
            Some(value) => cookies.push(format!("{name}={value}")),
            None => cookies.push(cookie.to_string()),
        }
    }
    cookies.join("; ")
}

/// Apply cookie actions to a `Set-Cookie` value, preserving the attribute suffix verbatim.
fn filter_set_cookie(value: &str, actions: &[FilterAction]) -> String {
    let (cookie, attributes) = match value.split_once(';') {
        Some((cookie, attributes)) => (cookie, Some(attributes)),
        None => (value, None),
    };
    let Some((name, cookie_value)) = cookie.split_once('=') else {
        return value.to_string();
    };
    let mut removed = false;
    let mut replacement: Option<String> = None;
    for action in actions {
        if action.name != name.trim() {
            continue;
        }
        match action.action {
            FilterActionKind::Replace => replacement = Some(action.value.clone()),
            FilterActionKind::Hash => replacement = Some(short_sha256(cookie_value)),
            FilterActionKind::Delete => removed = true,
        }
        break;
    }
    if removed {
        return String::new();
    }
    let cookie = format!("{name}={}", replacement.as_deref().unwrap_or(cookie_value));
    match attributes {
        Some(attributes) => format!("{cookie};{attributes}"),
        None => cookie,
    }
}

/// Caddy's `hash` filter: first 4 bytes of SHA-256, lower-case hex (8 characters).
fn short_sha256(value: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
    digest.as_ref()[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn mask_ip(value: &str, v4_mask: Option<u8>, v6_mask: Option<u8>) -> String {
    value
        .split(',')
        .map(|part| {
            let part = part.trim();
            let (host, port) = if let Some((host, port)) = part.rsplit_once(':') {
                if port.parse::<u16>().is_ok() {
                    let host = host
                        .strip_prefix('[')
                        .and_then(|host| host.strip_suffix(']'))
                        .unwrap_or(host);
                    (host, Some(port))
                } else {
                    (part, None)
                }
            } else {
                (part, None)
            };
            let Ok(address) = host.parse::<std::net::IpAddr>() else {
                return part.to_string();
            };
            let masked = match address {
                std::net::IpAddr::V4(address) => match v4_mask {
                    Some(mask) => {
                        let shift = 32u32.saturating_sub(u32::from(mask.min(32)));
                        let masked = u32::MAX.checked_shl(shift).unwrap_or(0);
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from(address) & masked))
                    }
                    None => std::net::IpAddr::V4(address),
                },
                std::net::IpAddr::V6(address) => match v6_mask {
                    Some(mask) => {
                        let shift = 128u32.saturating_sub(u32::from(mask.min(128)));
                        let masked = u128::MAX.checked_shl(shift).unwrap_or(0);
                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(address) & masked))
                    }
                    None => std::net::IpAddr::V6(address),
                },
            };
            match port {
                Some(port) if masked.is_ipv6() => format!("[{masked}]:{port}"),
                Some(port) => format!("{masked}:{port}"),
                None => masked.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl FieldFilter {
    fn validate(&self) -> Result<(), AccessLogError> {
        if self.path.is_empty() || self.path.iter().any(String::is_empty) {
            return Err(AccessLogError::new(
                "filter.path",
                "filter field path must not be empty",
            ));
        }
        if FUNDAMENTAL_FIELDS.contains(&self.path[0].as_str()) {
            return Err(AccessLogError::new(
                format!("filter.{}", self.path.join(">")),
                "fundamental log fields (ts, level, logger, msg) cannot be filtered",
            ));
        }
        match &self.operation {
            FieldFilterOperation::Rename { name } if name.is_empty() => Err(AccessLogError::new(
                format!("filter.{}", self.path.join(">")),
                "rename filter requires a non-empty `name`",
            )),
            FieldFilterOperation::Query { actions }
            | FieldFilterOperation::Cookie { actions }
            | FieldFilterOperation::SetCookie { actions } => {
                if actions.is_empty() {
                    return Err(AccessLogError::new(
                        format!("filter.{}", self.path.join(">")),
                        "filter requires at least one action",
                    ));
                }
                if actions.iter().any(|action| action.name.is_empty()) {
                    return Err(AccessLogError::new(
                        format!("filter.{}", self.path.join(">")),
                        "filter action parameter/name must not be empty",
                    ));
                }
                Ok(())
            }
            FieldFilterOperation::Regexp { pattern, .. } => {
                caddy_rs_core::regex::Regex::new(pattern).map_err(|error| {
                    AccessLogError::new(
                        format!("filter.{}", self.path.join(">")),
                        format!("invalid regexp filter pattern: {}", error),
                    )
                })?;
                Ok(())
            }
            FieldFilterOperation::MultiRegexp { operations } => {
                if operations.is_empty() {
                    return Err(AccessLogError::new(
                        format!("filter.{}", self.path.join(">")),
                        "multi_regexp requires at least one operation",
                    ));
                }
                if operations.len() > MAX_REGEXP_OPERATIONS {
                    return Err(AccessLogError::new(
                        format!("filter.{}", self.path.join(">")),
                        format!("multi_regexp supports at most {MAX_REGEXP_OPERATIONS} operations"),
                    ));
                }
                for operation in operations {
                    if operation.pattern.is_empty()
                        || operation.pattern.len() > MAX_REGEXP_PATTERN_LENGTH
                    {
                        return Err(AccessLogError::new(
                            format!("filter.{}", self.path.join(">")),
                            "multi_regexp patterns must be non-empty and at most 1000 characters",
                        ));
                    }
                    caddy_rs_core::regex::Regex::new(&operation.pattern).map_err(|error| {
                        AccessLogError::new(
                            format!("filter.{}", self.path.join(">")),
                            format!("invalid multi_regexp pattern: {}", error),
                        )
                    })?;
                }
                Ok(())
            }
            FieldFilterOperation::IpMask { v4_mask, v6_mask } => {
                if v4_mask.is_some_and(|mask| mask > 32) {
                    return Err(AccessLogError::new(
                        format!("filter.{}", self.path.join(">")),
                        "ip_mask v4_mask must be <= 32",
                    ));
                }
                if v6_mask.is_some_and(|mask| mask > 128) {
                    return Err(AccessLogError::new(
                        format!("filter.{}", self.path.join(">")),
                        "ip_mask v6_mask must be <= 128",
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn apply(&self, value: &mut serde_json::Value) {
        let Some(parent) = path_parent(value, &self.path) else {
            return;
        };
        let key = &self.path[self.path.len() - 1];
        match &self.operation {
            FieldFilterOperation::Delete => {
                if let serde_json::Value::Object(map) = parent {
                    map.remove(key);
                }
            }
            FieldFilterOperation::Replace { value: replacement } => {
                map_strings(parent, key, |_| Some(replacement.clone()));
            }
            FieldFilterOperation::Rename { name } => {
                if let serde_json::Value::Object(map) = parent {
                    if let Some(entry) = map.remove(key) {
                        map.insert(name.clone(), entry);
                    }
                }
            }
            FieldFilterOperation::Hash => {
                map_strings(parent, key, |existing| Some(short_sha256(existing)));
            }
            FieldFilterOperation::IpMask { v4_mask, v6_mask } => {
                map_strings(parent, key, |existing| {
                    Some(mask_ip(existing, *v4_mask, *v6_mask))
                });
            }
            FieldFilterOperation::Query { actions } => {
                map_strings(parent, key, |existing| {
                    Some(filter_query(existing, actions))
                });
            }
            FieldFilterOperation::Cookie { actions } => {
                map_strings(parent, key, |existing| {
                    Some(filter_cookie_header(existing, actions))
                });
            }
            FieldFilterOperation::SetCookie { actions } => {
                map_set_cookie(parent, key, actions);
            }
            FieldFilterOperation::Regexp {
                pattern,
                replacement,
            } => {
                map_strings(parent, key, |existing| {
                    Some(regexp_replace_all(pattern, replacement, existing))
                });
            }
            FieldFilterOperation::MultiRegexp { operations } => {
                map_strings(parent, key, |existing| {
                    let mut value = existing.to_string();
                    for operation in operations {
                        value =
                            regexp_replace_all(&operation.pattern, &operation.replacement, &value);
                    }
                    Some(value)
                });
            }
        }
    }
}

/// Navigate to the parent container of a `>`-separated field path.
fn path_parent<'a>(
    value: &'a mut serde_json::Value,
    path: &[String],
) -> Option<&'a mut serde_json::Value> {
    let (_, parents) = path.split_last()?;
    let mut current = value;
    for segment in parents {
        current = match current {
            serde_json::Value::Object(map) => map.get_mut(segment)?,
            serde_json::Value::Array(items) => items.get_mut(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

fn map_strings(
    parent: &mut serde_json::Value,
    key: &str,
    transform: impl Fn(&str) -> Option<String>,
) {
    match parent {
        serde_json::Value::Object(map) => {
            if let Some(value) = map.get_mut(key) {
                apply_to_value(value, &transform);
            }
        }
        serde_json::Value::Array(items) => {
            if let Ok(index) = key.parse::<usize>() {
                if let Some(value) = items.get_mut(index) {
                    apply_to_value(value, &transform);
                }
            }
        }
        _ => {}
    }
}

fn map_set_cookie(parent: &mut serde_json::Value, key: &str, actions: &[FilterAction]) {
    match parent {
        serde_json::Value::Object(map) => {
            if let Some(value) = map.get_mut(key) {
                apply_set_cookie_value(value, actions);
            }
        }
        serde_json::Value::Array(items) => {
            if let Ok(index) = key.parse::<usize>() {
                if let Some(value) = items.get_mut(index) {
                    apply_set_cookie_value(value, actions);
                }
            }
        }
        _ => {}
    }
}

fn apply_set_cookie_value(value: &mut serde_json::Value, actions: &[FilterAction]) {
    match value {
        serde_json::Value::String(existing) => {
            *existing = filter_set_cookie(existing, actions);
        }
        serde_json::Value::Array(items) => {
            items.retain_mut(|item| {
                if let serde_json::Value::String(existing) = item {
                    *existing = filter_set_cookie(existing, actions);
                    !existing.is_empty()
                } else {
                    true
                }
            });
        }
        _ => {}
    }
}

fn apply_to_value(value: &mut serde_json::Value, transform: &impl Fn(&str) -> Option<String>) {
    match value {
        serde_json::Value::String(existing) => {
            if let Some(replacement) = transform(existing) {
                *existing = replacement;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                if let serde_json::Value::String(existing) = item {
                    if let Some(replacement) = transform(existing) {
                        *existing = replacement;
                    }
                }
            }
        }
        _ => {}
    }
}

/// Lazily generated, cached per-request UUID matching `{http.request.uuid}` semantics.
///
/// Caddy generates the UUID on first placeholder access so requests that never reference it pay no
/// allocation, and reuses the same value for every later reference in the request. Call
/// [`RequestUuid::evaluate`] wherever the placeholder is expanded, and
/// [`RequestUuid::apply_to_entry`] when building the access entry (the value is only present in the
/// log if the placeholder was accessed).
#[derive(Debug, Default, Clone)]
pub struct RequestUuid {
    value: Option<String>,
}

impl RequestUuid {
    /// A request with no UUID generated yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The request's UUID, generating and caching a random UUIDv4 on first access.
    ///
    /// Returns `None` only if the operating system random source fails (never in normal operation);
    /// Caddy's `requestID.String` returns an empty string in that case.
    pub fn evaluate(&mut self) -> Option<&str> {
        if self.value.is_none() {
            self.value = generate_uuid_v4();
        }
        self.value.as_deref()
    }

    /// The already-generated UUID, if any (does not generate).
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Copy the generated UUID into `entry` when it was generated for this request.
    pub fn apply_to_entry(&self, entry: &mut AccessLogEntry) {
        if let Some(value) = &self.value {
            entry.uuid = Some(value.clone());
        }
    }
}

/// Generate a random UUIDv4 string (`8-4-4-4-12` lowercase hex), matching `google/uuid`'s
/// `NewRandom` layout used by Caddy's `{http.request.uuid}`.
pub fn generate_uuid_v4() -> Option<String> {
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).ok()?;
    // RFC 4122 version 4 / variant 10xx, matching google/uuid's random UUID.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
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
    /// Caddy filter-encoder field operations, applied after field selection.
    #[serde(default)]
    pub filters: Vec<FieldFilter>,
    /// Encoder key renaming (Caddy `message_key`/`level_key`/`time_key`/`name_key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_key: Option<String>,
    /// Encoder key for the level field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level_key: Option<String>,
    /// Encoder key for the timestamp field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_key: Option<String>,
    /// Encoder key for the logger name field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_key: Option<String>,
    /// Line terminator written after each encoded entry (Caddy `line_ending`, default `\n`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_ending: Option<String>,
    /// Encoder timestamp format (Caddy `time_format`; e.g. `wall_milli`, `rfc3339`,
    /// `unix_seconds_float`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_format: Option<String>,
    /// Use local time instead of UTC for timestamps (only `false` is supported; `true` fails
    /// loudly because the offline build has no timezone database).
    #[serde(default)]
    pub time_local: bool,
    /// Encoder level format (Caddy `level_format`: `lower`, `upper`, `color`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level_format: Option<String>,
    /// Encoder duration format (Caddy `duration_format`: `seconds`, `ms`, `ns`, `string`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_format: Option<String>,
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
        for filter in &self.filters {
            filter.validate()?;
        }
        for (index, key) in [
            &self.message_key,
            &self.level_key,
            &self.time_key,
            &self.name_key,
        ]
        .into_iter()
        .enumerate()
        {
            if key.as_deref() == Some("") {
                return Err(AccessLogError::new(
                    format!("key_options[{index}]"),
                    "encoder key names must not be empty",
                ));
            }
        }
        if self.line_ending.as_deref() == Some("") {
            return Err(AccessLogError::new(
                "line_ending",
                "line ending must not be empty",
            ));
        }
        if self.time_local {
            return Err(AccessLogError::new(
                "time_local",
                "time_local is not supported by this build (no timezone database); timestamps are UTC",
            ));
        }
        if let Some(format) = &self.time_format {
            if !matches!(
                format.as_str(),
                "wall_milli"
                    | "wall"
                    | "wall_nano"
                    | "iso8601"
                    | "rfc3339"
                    | "rfc3339_nano"
                    | "unix_seconds_float"
                    | "unix_milli_float"
                    | "unix_nano"
                    | "common_log"
            ) {
                return Err(AccessLogError::new(
                    "time_format",
                    format!(
                        "unsupported time_format `{format}` (supported: wall_milli, wall, \
                         wall_nano, iso8601, rfc3339, rfc3339_nano, unix_seconds_float, \
                         unix_milli_float, unix_nano, common_log)"
                    ),
                ));
            }
        }
        if let Some(format) = &self.level_format {
            if !matches!(format.as_str(), "lower" | "upper" | "color") {
                return Err(AccessLogError::new(
                    "level_format",
                    format!("unsupported level_format `{format}` (supported: lower, upper, color)"),
                ));
            }
        }
        if let Some(format) = &self.duration_format {
            if !matches!(format.as_str(), "seconds" | "ms" | "ns" | "string") {
                return Err(AccessLogError::new(
                    "duration_format",
                    format!(
                        "unsupported duration_format `{format}` (supported: seconds, ms, ns, \
                         string)"
                    ),
                ));
            }
        }
        Ok(())
    }

    fn apply_format_options(&self, value: &mut serde_json::Value) {
        let serde_json::Value::Object(map) = value else {
            return;
        };
        for key in ["ts", "time"] {
            let Some(seconds) = map.get(key).and_then(serde_json::Value::as_f64) else {
                continue;
            };
            let Some(format) = &self.time_format else {
                continue;
            };
            let formatted = format_time(seconds, format);
            map.insert(key.to_string(), formatted);
        }
        if self.level_format.as_deref() == Some("color") {
            if let Some(serde_json::Value::String(level)) = map.get("level").cloned() {
                map.insert(
                    "level".to_string(),
                    serde_json::Value::String(format!(
                        "\u{1b}[{}m{}\u{1b}[0m",
                        level_color(&level),
                        level.to_ascii_uppercase()
                    )),
                );
            }
        } else if let Some(format) = &self.level_format {
            if let Some(serde_json::Value::String(level)) = map.get("level").cloned() {
                let rendered = if format == "upper" {
                    level.to_ascii_uppercase()
                } else {
                    level.to_ascii_lowercase()
                };
                map.insert("level".to_string(), serde_json::Value::String(rendered));
            }
        }
        if let Some(seconds) = map.get("duration").and_then(serde_json::Value::as_f64) {
            if let Some(format) = &self.duration_format {
                let formatted = match format.as_str() {
                    "ms" => serde_json::Value::from(seconds * 1000.0),
                    "ns" => serde_json::Value::from((seconds * 1_000_000_000.0).round() as u64),
                    "string" => serde_json::Value::String(format_duration(seconds)),
                    _ => serde_json::Value::from(seconds),
                };
                map.insert("duration".to_string(), formatted);
            }
        }
    }

    fn apply_key_options(&self, value: &mut serde_json::Value) {
        let serde_json::Value::Object(map) = value else {
            return;
        };
        for (original, renamed) in [
            ("msg", &self.message_key),
            ("level", &self.level_key),
            ("ts", &self.time_key),
            ("logger", &self.name_key),
        ] {
            if let Some(renamed) = renamed {
                if let Some(entry) = map.remove(original) {
                    map.insert(renamed.clone(), entry);
                }
            }
        }
    }

    fn apply_field_filters(&self, value: &mut serde_json::Value) {
        for filter in &self.filters {
            filter.apply(value);
        }
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
                "client_ip": "192.0.2.10",
                "proto": "HTTP/2.0",
                "method": "GET",
                "host": "example.com",
                "uri": "/a?b=c",
                "headers": {
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
    fn correlation_and_trace_fields_use_caddy_names() {
        let mut entry = AccessLogEntry::new(AccessLogRequest::new("GET", "example.com", "/"));
        assert_eq!(entry.to_json_value().unwrap().get("uuid"), None);
        assert_eq!(entry.to_json_value().unwrap().get("traceID"), None);
        assert_eq!(entry.to_json_value().unwrap().get("spanID"), None);

        let mut request_uuid = RequestUuid::new();
        assert!(
            request_uuid.value().is_none(),
            "no generation before access"
        );
        let generated = request_uuid.evaluate().expect("uuid").to_string();
        request_uuid.apply_to_entry(&mut entry);
        entry = entry.with_trace_context("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7");

        let value = entry.to_json_value().unwrap();
        // Caddy's ExtraLogFields use the zap keys `uuid`, `traceID` and `spanID`.
        assert_eq!(value["uuid"], generated);
        assert_eq!(value["traceID"], "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(value["spanID"], "00f067aa0ba902b7");

        // Round-trips with the exact field names too.
        let text = serde_json::to_string(&entry).unwrap();
        let decoded: AccessLogEntry = serde_json::from_str(&text).unwrap();
        assert_eq!(decoded.uuid, Some(generated));
        assert_eq!(
            decoded.trace_id.as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        assert_eq!(decoded.span_id.as_deref(), Some("00f067aa0ba902b7"));
    }

    #[test]
    fn request_uuid_is_lazy_cached_unique_and_uuid_v4_shaped() {
        let mut first = RequestUuid::new();
        assert!(first.value().is_none(), "UUID must be generated lazily");
        let generated = first.evaluate().expect("uuid").to_string();
        assert_eq!(
            first.evaluate(),
            Some(generated.as_str()),
            "cached per request"
        );
        assert_eq!(first.value(), Some(generated.as_str()));

        // UUIDv4 layout: 36 chars, version nibble `4`, variant nibble in 8..b.
        assert_eq!(generated.len(), 36, "{generated}");
        let bytes = generated.as_bytes();
        assert_eq!(bytes[8], b'-');
        assert_eq!(bytes[13], b'-');
        assert_eq!(bytes[18], b'-');
        assert_eq!(bytes[23], b'-');
        assert_eq!(bytes[14], b'4', "version 4: {generated}");
        let variant = generated.as_bytes()[19];
        assert!(
            matches!(variant, b'8' | b'9' | b'a' | b'b'),
            "RFC 4122 variant 10xx: {generated}"
        );

        let mut second = RequestUuid::new();
        assert_ne!(second.evaluate(), Some(generated.as_str()));
    }

    #[test]
    fn correlation_ids_are_unique_per_request_in_rendered_entries() {
        let mut seen = std::collections::BTreeSet::new();
        for index in 0..16 {
            let mut request_uuid = RequestUuid::new();
            let mut entry = AccessLogEntry::new(AccessLogRequest::new("GET", "example.com", "/"));
            request_uuid.apply_to_entry(&mut entry);
            assert_eq!(entry.uuid, None, "entry before placeholder access");
            request_uuid.evaluate().expect("uuid");
            request_uuid.apply_to_entry(&mut entry);
            let rendered = entry.render_default().unwrap();
            let uuid = rendered["uuid"]
                .as_str()
                .unwrap_or_else(|| panic!("entry {index} has no uuid: {rendered}"));
            assert!(seen.insert(uuid.to_string()), "duplicate uuid {uuid}");
        }
        assert_eq!(seen.len(), 16);
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
    fn request_headers_omit_host_and_client_ip_defaults_to_peer() {
        let request_headers = headers(&[("host", "example.com"), ("x-test", "1")]);
        let request = AccessLogRequest::new("GET", "example.com", "/")
            .with_remote(Some("192.0.2.10:54321".parse().unwrap()))
            .with_headers(&request_headers);
        assert_eq!(request.client_ip.as_deref(), Some("192.0.2.10"));
        assert!(
            !request.headers.contains_key("Host"),
            "Caddy's request.headers excludes the Host header: {:?}",
            request.headers
        );
        assert_eq!(request.headers.get("X-Test"), Some(&vec!["1".to_string()]));

        let request = request.with_client_ip(Some("203.0.113.9".to_string()));
        assert_eq!(request.client_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(request.remote_ip, "192.0.2.10");
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
            ..AccessLogConfig::default()
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

    #[test]
    fn field_filters_apply_hash_ip_mask_rename_and_delete() {
        let config = AccessLogConfig {
            filters: vec![
                FieldFilter {
                    path: vec!["request".to_string(), "uri".to_string()],
                    operation: FieldFilterOperation::Hash,
                },
                FieldFilter {
                    path: vec!["request".to_string(), "remote_ip".to_string()],
                    operation: FieldFilterOperation::IpMask {
                        v4_mask: Some(24),
                        v6_mask: Some(64),
                    },
                },
                FieldFilter {
                    path: vec![
                        "request".to_string(),
                        "headers".to_string(),
                        "X-Debug".to_string(),
                    ],
                    operation: FieldFilterOperation::Rename {
                        name: "X-Renamed".to_string(),
                    },
                },
                FieldFilter {
                    path: vec![
                        "request".to_string(),
                        "headers".to_string(),
                        "X-Secret".to_string(),
                    ],
                    operation: FieldFilterOperation::Delete,
                },
                FieldFilter {
                    path: vec!["upstream".to_string()],
                    operation: FieldFilterOperation::Replace {
                        value: "removed".to_string(),
                    },
                },
            ],
            ..AccessLogConfig::default()
        };
        let mut entry = AccessLogEntry::new(AccessLogRequest::default());
        entry.request.uri = "secret".to_string();
        entry.request.remote_ip = "192.0.2.10".to_string();
        entry
            .request
            .headers
            .insert("X-Debug".to_string(), vec!["debug".to_string()]);
        entry
            .request
            .headers
            .insert("X-Secret".to_string(), vec!["secret".to_string()]);
        let rendered = entry.render(&config).expect("render");
        // Caddy hash filter: first 4 bytes of SHA-256, hex (sha256("secret") = 2bb80d53...).
        assert_eq!(rendered["request"]["uri"], "2bb80d53");
        assert_eq!(rendered["request"]["remote_ip"], "192.0.2.0");
        let headers = rendered["request"]["headers"].as_object().expect("headers");
        assert!(headers.get("X-Debug").is_none());
        assert_eq!(headers["X-Renamed"][0], "debug");
        assert!(headers.get("X-Secret").is_none());
        // Arrays of strings are transformed element-wise; missing fields are no-ops.
        assert!(
            rendered.get("upstream").is_none(),
            "absent field is a no-op"
        );
    }

    #[test]
    fn query_cookie_and_regexp_filters_apply() {
        let config = AccessLogConfig {
            // Cookie/Set-Cookie logs are credential-redacted by default; allow them so the
            // filter behavior is observable (Caddy's `should_log_credentials`).
            log_credentials: true,
            filters: vec![
                FieldFilter {
                    path: vec!["request".to_string(), "uri".to_string()],
                    operation: FieldFilterOperation::Query {
                        actions: vec![
                            FilterAction {
                                action: FilterActionKind::Replace,
                                name: "token".to_string(),
                                value: "***".to_string(),
                            },
                            FilterAction {
                                action: FilterActionKind::Delete,
                                name: "secret".to_string(),
                                value: String::new(),
                            },
                            FilterAction {
                                action: FilterActionKind::Hash,
                                name: "id".to_string(),
                                value: String::new(),
                            },
                        ],
                    },
                },
                FieldFilter {
                    path: vec![
                        "request".to_string(),
                        "headers".to_string(),
                        "Cookie".to_string(),
                    ],
                    operation: FieldFilterOperation::Cookie {
                        actions: vec![FilterAction {
                            action: FilterActionKind::Hash,
                            name: "session".to_string(),
                            value: String::new(),
                        }],
                    },
                },
                FieldFilter {
                    path: vec!["resp_headers".to_string(), "Set-Cookie".to_string()],
                    operation: FieldFilterOperation::SetCookie {
                        actions: vec![FilterAction {
                            action: FilterActionKind::Replace,
                            name: "sid".to_string(),
                            value: "REDACTED".to_string(),
                        }],
                    },
                },
                FieldFilter {
                    path: vec!["user_id".to_string()],
                    operation: FieldFilterOperation::Regexp {
                        pattern: "(?i)admin_(\\w+)".to_string(),
                        replacement: "user_$1".to_string(),
                    },
                },
                FieldFilter {
                    path: vec!["request".to_string(), "host".to_string()],
                    operation: FieldFilterOperation::MultiRegexp {
                        operations: vec![
                            RegexpOperation {
                                pattern: "a+".to_string(),
                                replacement: "A".to_string(),
                            },
                            RegexpOperation {
                                pattern: "b+".to_string(),
                                replacement: "B".to_string(),
                            },
                        ],
                    },
                },
            ],
            ..AccessLogConfig::default()
        };
        let mut entry = AccessLogEntry::new(AccessLogRequest::default());
        entry.request.uri = "/path?token=abc&id=secret&secret=x&keep=1".to_string();
        entry.request.headers.insert(
            "Cookie".to_string(),
            vec!["session=topsecret; other=1".to_string()],
        );
        entry.resp_headers.insert(
            "Set-Cookie".to_string(),
            vec!["sid=abc; Path=/; HttpOnly".to_string()],
        );
        entry.user_id = "admin_role".to_string();
        entry.request.host = "aaabbb.example".to_string();
        let rendered = entry.render(&config).expect("render");
        assert_eq!(
            rendered["request"]["uri"],
            "/path?token=***&id=2bb80d53&keep=1"
        );
        let cookie = rendered["request"]["headers"]["Cookie"][0]
            .as_str()
            .expect("cookie");
        assert!(cookie.contains("session=53336a67"), "{cookie}");
        assert!(cookie.contains("other=1"), "{cookie}");
        assert_eq!(
            rendered["resp_headers"]["Set-Cookie"][0],
            "sid=REDACTED; Path=/; HttpOnly"
        );
        assert_eq!(rendered["user_id"], "user_role");
        assert_eq!(rendered["request"]["host"], "AB.exAmple");
    }

    // ---- T-ADMIN-048: zero-length regexp-filter matches ---------------------------------------

    #[test]
    fn regexp_filter_zero_length_matches_match_go() {
        // Go's `Regexp.ReplaceAllString` copies the input between matches, advances one UTF-8
        // code point after a zero-length match and skips an empty match that immediately follows
        // a non-empty one (Go `src/regexp/regexp.go`, `replaceAll`). Caddy's `regexp` filter
        // delegates to that function, so these outputs are the reference behaviour; they were
        // computed with Go 1.26.4 (`regexp.MustCompile(...).ReplaceAllString`).
        assert_eq!(regexp_replace_all("a*", "X", "bbb"), "XbXbXbX");
        assert_eq!(regexp_replace_all("a*", "X", "aaa"), "X");
        assert_eq!(regexp_replace_all("a*", "X", ""), "X");
        assert_eq!(regexp_replace_all("(?:)", "X", "abc"), "XaXbXcX");
        assert_eq!(regexp_replace_all("(?:)", ".", "ab"), ".a.b.");
        // Empty matches iterate by UTF-8 code point, not byte (Go advances one rune).
        assert_eq!(regexp_replace_all("(?:)", "X", "é"), "XéX");
        // Anchors apply to the whole input: rerunning the pattern on each remaining suffix
        // would re-anchor `^`/`$` at every position.
        assert_eq!(regexp_replace_all("^", "X", "abc"), "Xabc");
        assert_eq!(regexp_replace_all("$", "X", "abc"), "abcX");
        assert_eq!(regexp_replace_all("^$", "X", ""), "X");
        assert_eq!(regexp_replace_all("^$", "X", "abc"), "abc");
        // Capture expansion still works when the only match is empty.
        assert_eq!(regexp_replace_all("(a*)", "[$1]", "b"), "[]b[]");
    }

    #[test]
    fn regexp_filter_zero_length_match_terminates() {
        // The previous manual loop reset `rest` to "" after a trailing empty match but kept
        // re-running the regex on "", so `^`, `a*` and `(?:)` never terminated. Run the calls on
        // a worker thread so a regression fails this test by name instead of hanging the test
        // binary. The leaked worker is harmless once the test process exits.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send((
                regexp_replace_all("^", "X", "abc"),
                regexp_replace_all("a*", "X", ""),
                regexp_replace_all("(?:)", "X", "b"),
            ));
        });
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("zero-length regexp matches must terminate");
        assert_eq!(
            result,
            ("Xabc".to_string(), "X".to_string(), "XbX".to_string())
        );
    }

    #[test]
    fn regexp_and_multi_regexp_filters_handle_zero_length_matches() {
        let config = AccessLogConfig {
            filters: vec![
                FieldFilter {
                    path: vec!["request".to_string(), "uri".to_string()],
                    operation: FieldFilterOperation::Regexp {
                        pattern: "a*".to_string(),
                        replacement: "X".to_string(),
                    },
                },
                FieldFilter {
                    path: vec!["request".to_string(), "host".to_string()],
                    operation: FieldFilterOperation::MultiRegexp {
                        operations: vec![RegexpOperation {
                            pattern: "(?:)".to_string(),
                            replacement: ".".to_string(),
                        }],
                    },
                },
            ],
            ..AccessLogConfig::default()
        };
        let mut entry = AccessLogEntry::new(AccessLogRequest::default());
        entry.request.uri = "banana".to_string();
        entry.request.host = "ab".to_string();
        let rendered = entry.render(&config).expect("render");
        // Go: `a*` over "banana" replaces the leading empty match and each `a`, but not the empty
        // match immediately following an `a`.
        assert_eq!(rendered["request"]["uri"], "XbXnXnX");
        assert_eq!(rendered["request"]["host"], ".a.b.");
    }

    // ---- T-ADMIN-049: named captures, word boundaries and mixed expansion ----------------------

    #[test]
    fn regexp_filter_malformed_reference_parsing() {
        // Divergences from Go's `Regexp.ReplaceAllString` for malformed references, with pattern
        // `(a)` and input `a`. Go gives "", "", "${}", "${a b}" and "" respectively (U+00E9 counts
        // as a Unicode reference name for Go); caddy-rs expands the numeric forms to group 1,
        // drops the empty/space-containing braces, and leaves `$<letter>` literal. Registered as
        // the DIV-0015 reference-parsing residual, so this asserts our side rather than Go's.
        for (template, ours) in [
            ("$01", "a"),
            ("${01}", "a"),
            ("${}", ""),
            ("${a b}", ""),
            ("$\u{e9}", "$\u{e9}"),
        ] {
            assert_eq!(
                regexp_replace_all("(a)", template, "a"),
                ours,
                "caddy-rs expansion of `{template}` changed; see the DIV-0015 residual table"
            );
        }
    }

    #[test]
    fn regexp_filter_named_captures_match_go() {
        // Caddy's `regexp` filter calls Go's `Regexp.ReplaceAllString`, so the replacement
        // expansion below is the reference behaviour. Every expected value was computed with the
        // Go 1.26.4 oracle (`regexp.MustCompile(pattern).ReplaceAllString(input, replacement)`),
        // not from the Rust engine.
        assert_eq!(
            regexp_replace_all("(?P<user>[a-z]+)", "$user", "alice"),
            "alice"
        );
        assert_eq!(
            regexp_replace_all("(?P<user>[a-z]+)", "${user}", "alice"),
            "alice"
        );
        assert_eq!(
            regexp_replace_all("(?P<user>[a-z]+)", "<${user}>", "alice bob"),
            "<alice> <bob>"
        );
        assert_eq!(
            regexp_replace_all(
                "(?P<user>[a-z]+)@(?P<host>[a-z.]+)",
                "$host/$user",
                "alice@example.com bob@test.io"
            ),
            "example.com/alice test.io/bob"
        );
        assert_eq!(
            regexp_replace_all(
                "^(?P<method>[A-Z]+) (?P<path>\\S+)$",
                "${method} ${path}",
                "GET /x"
            ),
            "GET /x"
        );
        assert_eq!(
            regexp_replace_all("(?P<word>[a-z]+)", "$word$word", "ab"),
            "abab"
        );
        // A group that did not participate in the match expands to the empty string.
        assert_eq!(
            regexp_replace_all("(?P<a>foo)|(?P<b>bar)", "[$a|$b]", "foo bar"),
            "[foo|] [|bar]"
        );
        // An unbraced `$name` consumes the longest run of word characters: `$userX` names the
        // absent group `userX`, not `$user` followed by "X". Braces disambiguate the two, exactly
        // like Go's `extract`.
        assert_eq!(
            regexp_replace_all("(?P<user>[a-z]+)", "$userX", "alice"),
            ""
        );
        assert_eq!(
            regexp_replace_all("(?P<user>[a-z]+)", "${user}X", "alice"),
            "aliceX"
        );
        // `$$` is a literal `$`; the following `$x` is the named capture.
        assert_eq!(regexp_replace_all("(?P<x>a)", "$$$x", "a"), "$a");
        // An unknown group name expands to nothing but keeps the surrounding template text.
        assert_eq!(
            regexp_replace_all("(?P<user>[a-z]+)", "<${nope}>", "alice"),
            "<>"
        );
    }

    #[test]
    fn regexp_filter_word_boundaries_match_go() {
        // Go's `\b`/`\B` are ASCII word boundaries (word characters are `[0-9A-Za-z_]`). These
        // ASCII inputs therefore exercise the same boundaries in the shared wrapper; the
        // Unicode-aware class residual for non-ASCII input is the pre-existing DIV-0015 one.
        assert_eq!(
            regexp_replace_all("\\bfoo\\b", "X", "foo foe foo_bar barfoo foo"),
            "X foe foo_bar barfoo X"
        );
        assert_eq!(
            regexp_replace_all("\\bcat\\b", "CAT", "cat concatenate cat."),
            "CAT concatenate CAT."
        );
        assert_eq!(
            regexp_replace_all("\\b(?P<num>\\d+)\\b", "[${num}]", "a 12 b 345"),
            "a [12] b [345]"
        );
        // Underscore is a word character, so `_word` and `word_` keep their underscores; only the
        // bare token has a boundary on both sides.
        assert_eq!(
            regexp_replace_all("\\bword\\b", "WORD", "_word word word_"),
            "_word WORD word_"
        );
        // A bare boundary is a zero-length match at every boundary position.
        assert_eq!(regexp_replace_all("\\b", "|", "ab cd"), "|ab| |cd|");
        assert_eq!(regexp_replace_all("\\B", "|", "ab cd"), "a|b c|d");
    }

    #[test]
    fn regexp_filter_mixed_numeric_and_named_expansion_matches_go() {
        // Numeric and named references address the same groups (group 1 is `user`), and a
        // replacement may freely mix `$N`, `${N}`, `$name` and `${name}`.
        assert_eq!(
            regexp_replace_all(
                "^(?P<user>[a-z]+)/(\\d+)/(?P<rest>.*)$",
                "${2}-$user-${rest}-$1",
                "alice/42/x/y"
            ),
            "42-alice-x/y-alice"
        );
        assert_eq!(
            regexp_replace_all(
                "(?P<first>\\w+)\\s+(?P<last>\\w+)",
                "$2, $1",
                "Ada Lovelace"
            ),
            "Lovelace, Ada"
        );
        assert_eq!(
            regexp_replace_all("(?P<a>a)(b)(?P<c>c)", "<${a}-$2-${c}>", "abcz"),
            "<a-b-c>z"
        );
        assert_eq!(
            regexp_replace_all("(?P<id>\\d+)-(\\d+)", "$id/$2", "12-34"),
            "12/34"
        );
        assert_eq!(
            regexp_replace_all("(?P<a>a)(b)(c)", "$1${2}$3", "abc"),
            "abc"
        );
    }

    #[test]
    fn regexp_and_multi_regexp_filters_apply_named_captures_and_word_boundaries() {
        // The end-to-end filter path: `regexp` rewrites the URI with named captures,
        // `multi_regexp` applies a named-capture rewrite followed by a `\b`-anchored one, and a
        // second `regexp` mixes numeric and named references. Expected values are Go 1.26.4
        // `ReplaceAllString` outputs.
        let config = AccessLogConfig {
            filters: vec![
                FieldFilter {
                    path: vec!["request".to_string(), "uri".to_string()],
                    operation: FieldFilterOperation::Regexp {
                        pattern: "^/api/v(?P<version>\\d+)/users/(?P<id>\\d+)$".to_string(),
                        replacement: "/v${version}/u/${id}".to_string(),
                    },
                },
                FieldFilter {
                    path: vec!["request".to_string(), "host".to_string()],
                    operation: FieldFilterOperation::MultiRegexp {
                        operations: vec![
                            RegexpOperation {
                                pattern: "^(?P<sub>[a-z0-9-]+)\\.example\\.com$".to_string(),
                                replacement: "$sub.internal".to_string(),
                            },
                            RegexpOperation {
                                pattern: "\\b(?P<env>internal)\\b".to_string(),
                                replacement: "${env}.test".to_string(),
                            },
                        ],
                    },
                },
                FieldFilter {
                    path: vec!["user_id".to_string()],
                    operation: FieldFilterOperation::Regexp {
                        pattern: "^(?P<role>admin)_(\\w+)$".to_string(),
                        replacement: "${2}:$role".to_string(),
                    },
                },
            ],
            ..AccessLogConfig::default()
        };
        let mut entry = AccessLogEntry::new(AccessLogRequest::default());
        entry.request.uri = "/api/v2/users/42".to_string();
        entry.request.host = "api.example.com".to_string();
        entry.user_id = "admin_read".to_string();
        let rendered = entry.render(&config).expect("render");
        assert_eq!(rendered["request"]["uri"], "/v2/u/42");
        assert_eq!(rendered["request"]["host"], "api.internal.test");
        assert_eq!(rendered["user_id"], "read:admin");
    }

    #[test]
    fn encoder_format_options_apply_to_json_rendering() {
        let config = AccessLogConfig {
            time_format: Some("rfc3339".to_string()),
            level_format: Some("upper".to_string()),
            duration_format: Some("ms".to_string()),
            ..AccessLogConfig::default()
        };
        let mut entry = AccessLogEntry::new(AccessLogRequest::default());
        entry.timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        entry.duration = std::time::Duration::from_millis(1234);
        let rendered = entry.render(&config).expect("render");
        assert_eq!(rendered["ts"], "2023-11-14T22:13:20Z");
        assert_eq!(rendered["level"], "INFO");
        assert_eq!(rendered["duration"].as_f64().unwrap(), 1234.0);
    }

    // ---- T-ADMIN-043: complete Caddy access-log field coverage ---------------------------------

    #[test]
    fn user_id_is_always_emitted_and_settable() {
        // Caddy always emits `user_id`, empty for anonymous requests (`server.go:1290`).
        let anonymous = AccessLogEntry::new(AccessLogRequest::new("GET", "example.com", "/"))
            .to_json_value()
            .unwrap();
        assert_eq!(anonymous["user_id"], "");

        // The authenticated identity comes from `http.auth.user.id` (`caddyauth.go:170`).
        let entry = AccessLogEntry::new(AccessLogRequest::new("GET", "example.com", "/"))
            .with_user_id("alice");
        assert_eq!(entry.to_json_value().unwrap()["user_id"], "alice");
        assert_eq!(entry.to_json_value().unwrap()["user_id"], json!("alice"));
        // It is a plain string field, never omitted and never null.
        let decoded: AccessLogEntry =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
        assert_eq!(decoded.user_id, "alice");
    }

    #[test]
    fn bytes_read_counts_actual_body_bytes_not_declared_content_length() {
        // `Content-Length` is only a declaration; Caddy counts bytes read by `lengthReader`
        // (`server.go:1600`) and reports that number (`server.go:1309`).
        let request_headers = headers(&[("content-length", "1000")]);
        let request = AccessLogRequest::new("POST", "example.com", "/upload")
            .with_remote(Some("192.0.2.10:54321".parse().unwrap()))
            .with_headers(&request_headers);

        let counter = BodyBytes::new();
        counter.add(7);
        counter.add(35);
        assert_eq!(counter.get(), 42, "the counter accumulates actual reads");

        let read = AccessLogEntry::new(request.clone()).with_bytes_read_counter(&counter);
        let value = read.to_json_value().unwrap();
        assert_eq!(value["bytes_read"], 42);
        assert_ne!(value["bytes_read"], 1000, "declared length is not used");

        // A handler that never reads the body logs 0 even with a declared Content-Length.
        let unread = AccessLogEntry::new(request).with_bytes_read_counter(&BodyBytes::new());
        assert_eq!(unread.to_json_value().unwrap()["bytes_read"], 0);

        // Clones share one counter, so the body pipeline can keep the handle while the
        // server reads it when the entry is rendered.
        let pipeline = counter.clone();
        pipeline.add(1);
        assert_eq!(counter.get(), 43);
        assert_eq!(pipeline.get(), 43, "clones share one counter");
        assert_eq!(
            AccessLogEntry::new(AccessLogRequest::default())
                .with_bytes_read(11)
                .to_json_value()
                .unwrap()["bytes_read"],
            11
        );
    }

    #[test]
    fn size_counts_actual_response_bytes_written() {
        // Caddy's `size` is the ResponseRecorder's written-byte counter
        // (`responsewriter.go:210`), not the body's declared length (`server.go:1312`).
        let counter = BodyBytes::new();
        counter.add(100);
        counter.add(23);
        let entry = AccessLogEntry::new(AccessLogRequest::default()).with_size_counter(&counter);
        let value = entry.to_json_value().unwrap();
        assert_eq!(value["size"], 123);
        assert_eq!(
            AccessLogEntry::new(AccessLogRequest::default())
                .with_size(7)
                .to_json_value()
                .unwrap()["size"],
            7
        );
        // A stream that produced no bytes (for example a failed/aborted write) logs 0 even when
        // the handler declared a longer body.
        let aborted =
            AccessLogEntry::new(AccessLogRequest::default()).with_size_counter(&BodyBytes::new());
        assert_eq!(aborted.to_json_value().unwrap()["size"], 0);
    }

    #[test]
    fn duration_is_time_to_last_byte_not_time_to_headers() {
        let started = Instant::now();
        let mut timing = RequestTiming::start_at(started);
        assert_eq!(timing.time_to_headers(), None, "headers not marked yet");

        timing.mark_response_started_at(started + Duration::from_millis(10));
        assert_eq!(
            timing.time_to_headers(),
            Some(Duration::from_millis(10)),
            "time-to-headers is a separate observation"
        );
        // The unfinished clock grows with elapsed time, like `{http.request.duration}`; it is not
        // the headers boundary.
        assert!(!timing.is_finished());
        assert!(timing.duration() >= Duration::ZERO);

        timing.finish_at(started + Duration::from_millis(50));
        assert_eq!(timing.duration(), Duration::from_millis(50));
        assert_eq!(
            timing.time_to_headers(),
            Some(Duration::from_millis(10)),
            "marking the last byte does not move the headers boundary"
        );
        assert!(timing.is_finished());
        assert_eq!(timing.started_at(), started);
        assert_eq!(
            timing.finished_at(),
            Some(started + Duration::from_millis(50))
        );

        // Caddy's access `duration` is the total, serialized as float seconds
        // (`server.go:1311`; zap `NewProductionEncoderConfig`).
        let entry = AccessLogEntry::new(AccessLogRequest::default()).with_timing(timing);
        assert_eq!(entry.duration, Duration::from_millis(50));
        assert_eq!(entry.to_json_value().unwrap()["duration"], 0.05);

        // An unfinished clock grows like Caddy's `{http.request.duration}`.
        let running = RequestTiming::start_at(Instant::now() - Duration::from_millis(5));
        assert!(running.duration() >= Duration::from_millis(5));
    }

    #[test]
    fn write_error_is_present_only_when_the_write_failed() {
        let clean = AccessLogEntry::new(AccessLogRequest::default());
        assert!(clean.to_json_value().unwrap().get("write_error").is_none());

        let failed = AccessLogEntry::new(AccessLogRequest::default())
            .with_write_error("write tcp 127.0.0.1: i/o timeout");
        let value = failed.to_json_value().unwrap();
        // Caddy appends `zap.NamedError("write_error", ...)` only when the write failed
        // (`server.go:1320`).
        assert_eq!(value["write_error"], "write tcp 127.0.0.1: i/o timeout");
        assert!(value.as_object().unwrap().contains_key("write_error"));
    }

    #[test]
    fn response_headers_redact_credentials_and_obey_custom_rules() {
        let entry =
            AccessLogEntry::new(AccessLogRequest::default()).with_response_headers(&headers(&[
                ("content-type", "text/plain"),
                ("set-cookie", "sid=abc; Path=/"),
                ("authorization", "Bearer secret"),
                ("proxy-authorization", "Basic secret"),
                ("cookie", "session=abc"),
                ("x-internal", "trace"),
            ]));

        // Caddy passes the same `should_log_credentials` flag to the response-header object as to
        // the request one (`server.go:1314`, `internal/logmarshalers.go:20-35`).
        let redacted = entry.render_default().unwrap();
        for header in [
            "Set-Cookie",
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
        ] {
            assert_eq!(redacted["resp_headers"][header], json!(["REDACTED"]));
        }
        assert_eq!(
            redacted["resp_headers"]["Content-Type"],
            json!(["text/plain"])
        );

        let credentials = AccessLogConfig {
            log_credentials: true,
            ..AccessLogConfig::default()
        };
        let logged = entry.render(&credentials).unwrap();
        assert_eq!(
            logged["resp_headers"]["Set-Cookie"],
            json!(["sid=abc; Path=/"])
        );
        assert_eq!(
            logged["resp_headers"]["Authorization"],
            json!(["Bearer secret"])
        );

        // Custom response-header rules use Caddy's `resp_headers` target and never touch the
        // request header map.
        let mut request = AccessLogRequest::new("GET", "example.com", "/");
        request
            .headers
            .insert("Content-Type".to_string(), vec!["text/plain".to_string()]);
        let entry = AccessLogEntry::new(request).with_response_headers(&headers(&[
            ("content-type", "text/plain"),
            ("x-internal", "1"),
        ]));
        let config = AccessLogConfig {
            redaction: RedactionPolicy {
                headers: vec![
                    HeaderRedaction::Replace {
                        header: "Content-Type".to_string(),
                        value: "hidden".to_string(),
                        target: HeaderTarget::Response,
                    },
                    HeaderRedaction::Delete {
                        header: "X-Internal".to_string(),
                        target: HeaderTarget::Response,
                    },
                ],
                ..RedactionPolicy::default()
            },
            ..AccessLogConfig::default()
        };
        let rendered = entry.render(&config).unwrap();
        assert_eq!(rendered["resp_headers"]["Content-Type"], json!(["hidden"]));
        assert!(rendered["resp_headers"].get("X-Internal").is_none());
        assert_eq!(
            rendered["request"]["headers"]["Content-Type"],
            json!(["text/plain"])
        );
        assert!(entry.render_default().unwrap()["resp_headers"]
            .get("X-Internal")
            .is_some());
    }

    #[test]
    fn full_representative_entry_matches_caddy_documented_shape() {
        let mut request = AccessLogRequest::new("POST", "example.com", "/api?q=1")
            .with_remote(Some("192.0.2.10:54321".parse().unwrap()))
            .with_headers(&headers(&[
                ("host", "example.com"),
                ("content-type", "application/json"),
                ("authorization", "Bearer secret"),
            ]));
        request.proto = "HTTP/2.0".to_string();
        request.tls = Some(AccessLogTls {
            resumed: false,
            version: 772,
            cipher_suite: 4865,
            proto: "h2".to_string(),
            server_name: "example.com".to_string(),
            ech: false,
            client_common_name: Some("client".to_string()),
            client_serial: Some("1234".to_string()),
        });

        let started = Instant::now();
        let mut timing = RequestTiming::start_at(started);
        timing.finish_at(started + Duration::from_millis(50));

        let entry = AccessLogEntry::new(request)
            .with_timestamp(UNIX_EPOCH + Duration::from_millis(1_700_000_000_500))
            .with_status(502)
            .with_timing(timing)
            .with_user_id("alice")
            .with_bytes_read(42)
            .with_size(123)
            .with_write_error("write tcp 127.0.0.1: i/o timeout")
            .with_response_headers(&headers(&[
                ("content-type", "application/json"),
                ("set-cookie", "sid=abc"),
            ]))
            .with_upstream(AccessLogUpstream {
                dial: "10.0.0.5:8080".to_string(),
                remote_ip: Some("10.0.0.5".to_string()),
                remote_port: Some("8080".to_string()),
                duration: Duration::from_millis(25),
                status: Some(200),
            })
            .with_uuid("a3f1c2d4-1b2c-4d5e-8f90-1234567890ab")
            .with_trace_context("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7")
            .with_extra_field("proxy_attempt", json!(2));

        let expected = json!({
            "level": "error",
            "ts": 1_700_000_000.5_f64,
            "logger": "http.log.access",
            "msg": "handled request",
            "request": {
                "remote_ip": "192.0.2.10",
                "remote_port": "54321",
                "client_ip": "192.0.2.10",
                "proto": "HTTP/2.0",
                "method": "POST",
                "host": "example.com",
                "uri": "/api?q=1",
                "headers": {
                    "Content-Type": ["application/json"],
                    "Authorization": ["REDACTED"],
                },
                "tls": {
                    "resumed": false,
                    "version": 772,
                    "cipher_suite": 4865,
                    "proto": "h2",
                    "server_name": "example.com",
                    "ech": false,
                    "client_common_name": "client",
                    "client_serial": "1234",
                },
            },
            "bytes_read": 42,
            "user_id": "alice",
            "duration": 0.05,
            "size": 123,
            "status": 502,
            "resp_headers": {
                "Content-Type": ["application/json"],
                "Set-Cookie": ["REDACTED"],
            },
            "write_error": "write tcp 127.0.0.1: i/o timeout",
            "upstream": {
                "dial": "10.0.0.5:8080",
                "remote_ip": "10.0.0.5",
                "remote_port": "8080",
                "duration": 0.025,
                "status": 200,
            },
            "uuid": "a3f1c2d4-1b2c-4d5e-8f90-1234567890ab",
            "traceID": "4bf92f3577b34da6a3ce929d0e0e4736",
            "spanID": "00f067aa0ba902b7",
            "proxy_attempt": 2,
        });
        let rendered = entry.render_default().unwrap();
        for (key, expected_value) in expected.as_object().unwrap() {
            assert_eq!(
                rendered.get(key),
                Some(expected_value),
                "top-level field `{key}` diverges: {rendered}"
            );
        }
        assert_eq!(rendered, expected);

        // Caddy's logical field order: encoder fields first, then `request`, then the built-in
        // fields in `logRequest` order, then the extra fields.
        let direct = serde_json::to_string(&entry).unwrap();
        let positions: Vec<usize> = [
            "\"level\"",
            "\"ts\"",
            "\"request\"",
            "\"bytes_read\"",
            "\"user_id\"",
            "\"duration\"",
            "\"size\"",
            "\"status\"",
            "\"resp_headers\"",
            "\"write_error\"",
            "\"upstream\"",
            "\"uuid\"",
            "\"traceID\"",
            "\"spanID\"",
            "\"proxy_attempt\"",
        ]
        .iter()
        .map(|key| {
            direct
                .find(key)
                .unwrap_or_else(|| panic!("missing {key}: {direct}"))
        })
        .collect();
        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "unexpected field order: {direct}"
        );
    }

    #[test]
    fn missing_values_omit_optional_fields_exactly_like_caddy() {
        let entry =
            AccessLogEntry::new(AccessLogRequest::new("GET", "example.com", "/")).with_status(0);
        let value = entry.to_json_value().unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "bytes_read",
                "duration",
                "level",
                "logger",
                "msg",
                "request",
                "resp_headers",
                "size",
                "status",
                "ts",
                "user_id",
            ],
            "only Caddy's always-present fields are emitted"
        );
        // Caddy logs `status: 0` when no response was written (`server.go:1313`,
        // `responsewriter.go:204`).
        assert_eq!(value["status"], 0);
        assert_eq!(value["level"], "info");
        // Optional fields are absent, never null or empty.
        for absent in ["write_error", "upstream", "uuid", "traceID", "spanID"] {
            assert!(value.get(absent).is_none(), "`{absent}` must be omitted");
        }
        // The `request` object omits `client_ip` (unresolved), `transfer_encoding` and `tls`
        // like Caddy's marshalers (`marshalers.go:44-60`).
        let request = value["request"].as_object().unwrap();
        for absent in ["client_ip", "transfer_encoding", "tls"] {
            assert!(
                request.get(absent).is_none(),
                "`request.{absent}` must be omitted"
            );
        }
        // Extra fields never add an `extra` wrapper object of their own.
        assert!(!value.as_object().unwrap().contains_key("extra_fields"));
    }

    #[test]
    fn extra_log_fields_serialize_inline_and_round_trip() {
        let mut extras = ExtraLogFields::new();
        assert!(extras.is_empty());
        extras.add("upstream_addr", json!("10.0.0.5:8080"));
        extras.add("attempt", json!(2));
        assert_eq!(extras.len(), 2);
        assert_eq!(extras.get("attempt"), Some(&json!(2)));
        // A repeated `Add` keeps one slot (last value wins, position preserved).
        extras.add("attempt", json!(3));
        assert_eq!(extras.len(), 2);
        assert_eq!(extras.get("attempt"), Some(&json!(3)));
        extras.set("upstream_addr", json!("10.0.0.6:8080"));
        assert_eq!(
            extras.iter().map(|(key, _)| key).collect::<Vec<_>>(),
            vec!["upstream_addr", "attempt"]
        );

        let entry = AccessLogEntry::new(AccessLogRequest::new("GET", "example.com", "/"))
            .with_extra_fields(extras.clone());
        let value = entry.to_json_value().unwrap();
        // Caddy's `ExtraLogFields` are inline top-level keys (`server.go:1321`).
        assert_eq!(value["upstream_addr"], "10.0.0.6:8080");
        assert_eq!(value["attempt"], 3);
        assert!(!value.as_object().unwrap().contains_key("extra_fields"));

        let decoded: AccessLogEntry =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
        assert_eq!(decoded.extra_fields, extras);
        // Unknown keys are preserved as extra fields when decoding a Caddy-shaped entry.
        let mut caddy_shaped = entry.to_json_value().unwrap();
        caddy_shaped
            .as_object_mut()
            .unwrap()
            .insert("unknown_key".to_string(), json!("kept"));
        let decoded: AccessLogEntry = serde_json::from_value(caddy_shaped).unwrap();
        assert_eq!(
            decoded.extra_fields.get("unknown_key"),
            Some(&json!("kept"))
        );
    }

    #[test]
    fn access_log_context_shares_server_and_handler_observations() {
        let context = AccessLogContext::started();
        let handler = context.clone();

        // The server wraps the request body and hands the counter to the body pipeline; handlers
        // record the authenticated user, proxy attempt, write error and extra fields.
        handler.request_bytes().add(42);
        handler.set_user_id("alice");
        handler.set_upstream(AccessLogUpstream {
            dial: "10.0.0.5:8080".to_string(),
            remote_ip: Some("10.0.0.5".to_string()),
            remote_port: Some("8080".to_string()),
            duration: Duration::from_millis(25),
            status: Some(200),
        });
        handler.mark_response_started();
        handler.response_bytes().add(123);
        handler.set_write_error("connection reset by peer");
        handler.add_extra_field("proxy_attempt", json!(2));
        assert_eq!(context.user_id().as_deref(), Some("alice"));
        let finished = context.finish();
        assert!(finished.is_some());
        assert_eq!(context.duration(), finished);

        // The server builds the ordinary entry from its request snapshot and then overlays the
        // shared observations.
        let mut entry = AccessLogEntry::new(AccessLogRequest::new("GET", "example.com", "/"))
            .with_status(200)
            .with_response_headers(&headers(&[("content-type", "text/plain")]));
        context.apply_to(&mut entry);

        assert_eq!(entry.bytes_read, 42);
        assert_eq!(entry.size, 123);
        assert_eq!(entry.user_id, "alice");
        assert_eq!(entry.duration, finished.unwrap());
        assert_eq!(
            entry
                .upstream
                .as_ref()
                .map(|upstream| upstream.dial.as_str()),
            Some("10.0.0.5:8080")
        );
        assert_eq!(
            entry.write_error.as_deref(),
            Some("connection reset by peer")
        );
        assert_eq!(entry.extra_fields.get("proxy_attempt"), Some(&json!(2)));

        let value = entry.render_default().unwrap();
        assert_eq!(value["bytes_read"], 42);
        assert_eq!(value["size"], 123);
        assert_eq!(value["user_id"], "alice");
        assert_eq!(value["upstream"]["dial"], "10.0.0.5:8080");
        assert_eq!(value["proxy_attempt"], 2);
        // Headers were not touched by the context.
        assert_eq!(value["resp_headers"]["Content-Type"], json!(["text/plain"]));
    }

    #[test]
    fn access_log_context_carries_request_scoped_log_controls() {
        let context = AccessLogContext::new();
        assert!(!context.log_skip());
        assert_eq!(context.logger_names(), None);
        assert_eq!(context.log_level(), None);

        context.set_log_skip(true);
        context.set_logger_names(Some(vec!["access".to_string(), "admin".to_string()]));
        context.set_log_level(Some("WARN".to_string()));
        assert!(context.log_skip());
        assert_eq!(
            context.logger_names(),
            Some(vec!["access".to_string(), "admin".to_string()])
        );
        assert_eq!(context.log_level().as_deref(), Some("WARN"));

        // An explicit empty list is distinct from "unset": it selects no logger at all, while
        // `None` restores the per-host mapping (Caddy's `GetVar` returns nil only when unset).
        context.set_logger_names(Some(Vec::new()));
        assert_eq!(context.logger_names(), Some(Vec::new()));
        context.set_logger_names(None);
        assert_eq!(context.logger_names(), None);

        // A non-string assignment clears a previous string value; the raw accepted spelling is
        // preserved so the emission-time parser (case-insensitive, `DEBUG`..=`ERROR`) decides.
        context.set_log_level(Some("warn".to_string()));
        assert_eq!(context.log_level().as_deref(), Some("warn"));
        context.set_log_level(None);
        assert_eq!(context.log_level(), None);
        context.set_log_skip(false);
        assert!(!context.log_skip());
    }

    #[test]
    fn access_log_context_is_thread_safe_and_anonymous_by_default() {
        // The server shares these across its task boundary and handlers write from async tasks.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AccessLogContext>();
        assert_send_sync::<BodyBytes>();
        assert_send_sync::<ExtraLogFields>();
        assert_send_sync::<AccessLogEntry>();

        let context = AccessLogContext::new();
        assert_eq!(context.user_id(), None);
        assert_eq!(context.timing(), None);
        assert!(context.extra_fields().is_empty());
        // A fresh context leaves Caddy's always-emitted defaults intact.
        let mut entry = AccessLogEntry::new(AccessLogRequest::default());
        context.apply_to(&mut entry);
        assert_eq!(entry.user_id, "");
        assert_eq!(entry.bytes_read, 0);
        assert_eq!(entry.size, 0);

        std::thread::scope(|scope| {
            for _ in 0..4 {
                let context = context.clone();
                scope.spawn(move || {
                    for _ in 0..1_000 {
                        context.request_bytes().add(1);
                    }
                });
            }
            let context = context.clone();
            scope.spawn(move || context.set_user_id("alice"));
        });
        assert_eq!(context.request_bytes().get(), 4_000);
        assert_eq!(context.user_id().as_deref(), Some("alice"));
    }
}
