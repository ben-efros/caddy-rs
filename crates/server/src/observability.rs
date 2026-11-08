//! Server-side observability wiring (plan task T-ADMIN-024).
//!
//! The admin crate owns the primitives: [`caddy_rs_admin::MetricsRegistry`]/[`HttpMetrics`] render
//! `GET /metrics`, the [`SharedRequestRecorder`] is the per-request metrics seam, and
//! [`caddy_rs_admin::LoggingConfig`]/[`AccessLogSink`] turn Caddy's `logging` configuration into
//! working access-log sinks. This module is the runtime half:
//!
//! * [`AccessLogRuntime`] owns the sinks built for one active generation. It is shared with every
//!   listener state (`Arc`), emits one entry per request, and flushes/closes on reload and
//!   shutdown (closing is idempotent; in-flight connections that still hold a handle finish
//!   emitting before the last `Arc` drops).
//! * [`RequestSnapshot`] captures the access-log-relevant request fields *before* the request is
//!   consumed by the router (method, host, URI, headers, peer, TLS handshake details).
//! * [`TlsLogInfo`] carries the rustls handshake metadata needed for Caddy's `request.tls` object.
//! * [`PendingObservation`] renders the metrics observation and the access entry when the response
//!   body completes (attached through `caddy_rs_http::Body::observe`), so `duration` is
//!   time-to-last-byte and `size` is the actual response body length. [`observe_request`] is the
//!   immediate variant for responses whose body is not observed (protocol upgrades and synthetic
//!   error bodies).
//!
//! Metrics are always recorded (the recorder is cheap; with no active sinks the access-log half is
//! skipped), matching caddy-rs's documented always-on metrics extension (DIV-0033). Access-log
//! entries are only emitted when the active configuration contains a `logging` section: building a
//! sink from the implicit Caddy default would otherwise write every request to stderr even though
//! the operator never configured access logging.
//!
//! ## Access-log field population (T-ADMIN-045)
//!
//! The server creates one `caddy_rs_admin::access_log::AccessLogContext` per request when logging
//! is enabled and attaches it to the internal request. Authentication handlers publish `user_id`,
//! `reverse_proxy` publishes the caddy-rs `upstream` extension, the server attaches the request
//! body byte counter (actual bytes read) and the response body observer (actual bytes written,
//! body-end `duration`), and a write that cannot be completed records `write_error`. The entry is
//! rendered from the context after the body completes; anonymous requests still emit `user_id: ""`
//! and successful writes omit `write_error`.
//!
//! Remaining gaps: the transport does not expose the underlying socket write error, so a
//! `write_error` records the observable fact (body error text, or the bytes written before the
//! connection closed) rather than Go's `write tcp ...: broken pipe`; certificate metrics are
//! recorded as a snapshot at generation apply time (ongoing renewal outcomes are picked up on the
//! next apply, which the supervisor performs every poll interval); and HTTP/3 write failures are
//! detected from `send_data` errors while the entry is rendered after the body is sent.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use http::HeaderMap;

use caddy_rs_admin::access_log::AccessLogContext;
use caddy_rs_admin::{
    AccessLogEntry, AccessLogRequest, AccessLogTls, BuiltAccessLogSink, CertificateMetrics,
    LoggingConfig, LoggingConfigError, RequestObservation, SharedRequestRecorder,
    ACCESS_LOG_LOGGER,
};
use caddy_rs_http::body::{BodyCompletion, BodyStatus, ResponseBodyObserver};
use hyper::body::Incoming;

/// Access-log sinks active for one configuration generation.
pub(crate) struct AccessLogRuntime {
    sinks: Vec<BuiltAccessLogSink>,
}

impl std::fmt::Debug for AccessLogRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccessLogRuntime")
            .field(
                "sinks",
                &self
                    .sinks
                    .iter()
                    .map(|sink| sink.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl AccessLogRuntime {
    /// A runtime with no sinks: access-log emission is disabled.
    pub(crate) fn disabled() -> Arc<Self> {
        Arc::new(Self { sinks: Vec::new() })
    }

    /// A runtime owning `sinks` built from a generation's logging configuration.
    pub(crate) fn new(sinks: Vec<BuiltAccessLogSink>) -> Arc<Self> {
        Arc::new(Self { sinks })
    }

    /// Build the access-log runtime for one configuration generation.
    ///
    /// `None` means access logging is disabled: Caddy only emits access entries for servers whose
    /// logging was explicitly configured, so the implicit default sink is not opened for a
    /// configuration that never mentions logging.
    pub(crate) fn build(
        config: Option<&LoggingConfig>,
    ) -> Result<Option<Arc<Self>>, LoggingConfigError> {
        let Some(config) = config else {
            return Ok(None);
        };
        let sinks = config.build_sinks()?;
        Ok(Some(Self::new(sinks)))
    }

    /// Whether any sink will receive entries.
    pub(crate) fn is_enabled(&self) -> bool {
        !self.sinks.is_empty()
    }

    /// Number of configured sinks (diagnostics and tests).
    pub(crate) fn sink_count(&self) -> usize {
        self.sinks.len()
    }

    /// Emit one access entry to every sink.
    ///
    /// Encoding/write failures are logged and counted by the sink; they must never fail a request.
    pub(crate) fn emit(&self, entry: &AccessLogEntry) {
        for built in &self.sinks {
            if let Err(error) = built.sink.emit(entry) {
                eprintln!(
                    "caddy-rs: access log `{}` could not write an entry: {error}",
                    built.name
                );
            }
        }
    }

    /// Flush every sink. Errors are logged; flush is best effort on the reload path.
    pub(crate) fn flush(&self) {
        for built in &self.sinks {
            if let Err(error) = built.sink.flush() {
                eprintln!(
                    "caddy-rs: access log `{}` could not flush: {error}",
                    built.name
                );
            }
        }
    }

    /// Flush and close every sink. Idempotent; called on reload (for the old generation) and
    /// shutdown.
    pub(crate) fn close(&self) {
        for built in &self.sinks {
            if let Err(error) = built.sink.close() {
                eprintln!(
                    "caddy-rs: access log `{}` could not close cleanly: {error}",
                    built.name
                );
            }
        }
    }
}

impl Drop for AccessLogRuntime {
    fn drop(&mut self) {
        self.close();
    }
}

/// Per-server access-log association from `apps.http.servers.*.logs`.
///
/// Caddy's `ServerLogConfig` decides *which logger* a request host belongs to and whether the host
/// is skipped; the global `logging.logs[]` sinks decide where that logger is written. An absent
/// per-server `logs` object keeps caddy-rs's historical behaviour (emit with the base
/// `http.log.access` logger when any logging is configured).
#[derive(Debug, Clone, Default)]
pub(crate) struct ServerAccessLogPolicy {
    /// Whether the server declared a `logs` object (per-server semantics apply only then).
    configured: bool,
    default_logger_name: String,
    logger_names: Vec<(String, Vec<String>)>,
    skip_hosts: Vec<String>,
    skip_unmapped_hosts: bool,
}

/// What the per-server policy decided for one request host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AccessLogRoute {
    /// Do not emit an access entry for this request (metrics are still recorded).
    Skip,
    /// Emit one entry per logger name; an empty name is the base `http.log.access` logger.
    Loggers(Vec<String>),
}

impl ServerAccessLogPolicy {
    /// Build the policy for one server; `None` means the server has no per-server log config.
    pub(crate) fn from_config(logs: Option<&caddy_rs_core::ServerLogConfig>) -> Self {
        let Some(logs) = logs else {
            return Self::default();
        };
        Self {
            configured: true,
            default_logger_name: logs.default_logger_name.clone().unwrap_or_default(),
            logger_names: logs
                .logger_names
                .iter()
                .map(|(host, names)| (normalize_host_pattern(host), names.as_slice().to_vec()))
                .collect(),
            skip_hosts: logs
                .skip_hosts
                .iter()
                .map(|host| normalize_host_pattern(host))
                .collect(),
            skip_unmapped_hosts: logs.skip_unmapped_hosts,
            // `should_log_credentials` and `trace` are modeled in core but not applied here; the
            // sink encoder owns credential redaction (see the module docs / DIV for T-CONF-030).
        }
    }

    /// Decide how the request host is logged.
    pub(crate) fn route(&self, host: &str) -> AccessLogRoute {
        if !self.configured {
            // No per-server association: historical default logger for every host.
            return AccessLogRoute::Loggers(vec![String::new()]);
        }
        let host = normalize_host(host);
        // Caddy's `shouldLogRequest` checks the logger_names mapping first, so a mapped host is
        // always logged even when it also matches skip_hosts.
        if let Some(names) = self.logger_hosts(&host) {
            return AccessLogRoute::Loggers(names.to_vec());
        }
        if self
            .skip_hosts
            .iter()
            .any(|pattern| host_matches(&host, pattern))
        {
            return AccessLogRoute::Skip;
        }
        if self.skip_unmapped_hosts {
            return AccessLogRoute::Skip;
        }
        AccessLogRoute::Loggers(vec![self.default_logger_name.clone()])
    }

    /// Caddy's `getLoggerHosts`: exact host first, then wildcard variants replacing each label with
    /// `*` from left to right.
    fn logger_hosts(&self, host: &str) -> Option<&[String]> {
        if let Some((_, names)) = self
            .logger_names
            .iter()
            .find(|(pattern, _)| pattern == host)
        {
            return Some(names);
        }
        let mut labels: Vec<String> = host.split('.').map(str::to_string).collect();
        for index in 0..labels.len() {
            if labels[index].is_empty() {
                continue;
            }
            labels[index] = "*".to_string();
            let wildcard = labels.join(".");
            if let Some((_, names)) = self
                .logger_names
                .iter()
                .find(|(pattern, _)| *pattern == wildcard)
            {
                return Some(names);
            }
        }
        None
    }
}

/// The full zap logger name for an access logger component: empty is the base access logger.
pub(crate) fn logger_name(component: &str) -> String {
    if component.is_empty() {
        ACCESS_LOG_LOGGER.to_string()
    } else {
        format!("{ACCESS_LOG_LOGGER}.{component}")
    }
}

/// Normalize a request host: lowercase, strip port, strip trailing dot.
fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host.rsplit_once(':').map(|(name, _)| name).unwrap_or(host)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Normalize a configured host pattern the same way (without stripping `*`).
fn normalize_host_pattern(pattern: &str) -> String {
    pattern.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Caddy/certmagic-style wildcard match: same label count, `*` labels match anything.
fn host_matches(host: &str, pattern: &str) -> bool {
    if host == pattern {
        return true;
    }
    let host_labels: Vec<&str> = host.split('.').collect();
    let pattern_labels: Vec<&str> = pattern.split('.').collect();
    if host_labels.len() != pattern_labels.len() {
        return false;
    }
    host_labels
        .iter()
        .zip(pattern_labels.iter())
        .all(|(host_label, pattern_label)| *pattern_label == "*" || host_label == pattern_label)
}

/// TLS handshake details for the access-log `request.tls` object.
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsLogInfo {
    /// Whether the session was resumed.
    pub(crate) resumed: bool,
    /// Negotiated protocol version number (for example `772` for TLS 1.3).
    pub(crate) version: u16,
    /// Negotiated cipher suite number.
    pub(crate) cipher_suite: u16,
    /// Negotiated ALPN protocol (`h2`, `http/1.1`, ...).
    pub(crate) proto: String,
    /// SNI server name.
    pub(crate) server_name: String,
    /// Whether ECH was accepted (never in this build).
    pub(crate) ech: bool,
}

impl TlsLogInfo {
    fn to_access_tls(&self) -> AccessLogTls {
        AccessLogTls {
            resumed: self.resumed,
            version: self.version,
            cipher_suite: self.cipher_suite,
            proto: self.proto.clone(),
            server_name: self.server_name.clone(),
            ech: self.ech,
            client_common_name: None,
            client_serial: None,
        }
    }
}

/// The request fields captured before the request is consumed by the router.
#[derive(Debug, Clone)]
pub(crate) struct RequestSnapshot {
    method: String,
    host: String,
    uri: String,
    proto: String,
    headers: HeaderMap,
    remote: Option<SocketAddr>,
    tls: Option<TlsLogInfo>,
    timestamp: SystemTime,
    /// Declared request body size (`Content-Length`), 0 when the body is chunked/unknown.
    ///
    /// Caddy's `bytes_read` is the *actual* bytes read, which the request-scoped byte counter
    /// reports while a streamed body is consumed (and which the server sets in one step for a
    /// buffered body). This declared value is only the fallback for a caller that renders a
    /// snapshot without an `AccessLogContext` (it also feeds the metrics request size fallback).
    content_length: u64,
    /// Caddy's `client_ip` request variable: the trusted-proxy-resolved client IP (bare address,
    /// never a port). `None` until [`RequestSnapshot::resolve_client_ip`] runs; Caddy resolves it
    /// in `PrepareRequest` before any handler, so it is the peer IP unless the peer is trusted.
    resolved_client_ip: Option<String>,
}

impl RequestSnapshot {
    /// Capture the access-log-relevant request fields.
    pub(crate) fn capture(
        request: &hyper::Request<Incoming>,
        remote: Option<SocketAddr>,
        tls: Option<&TlsLogInfo>,
    ) -> Self {
        Self::capture_fields(
            request.method(),
            request.version(),
            request.uri(),
            request.headers(),
            remote,
            tls,
        )
    }

    /// Capture an HTTP/3 request before its body is read/buffered (the `h3` resolver hands out an
    /// `http::Request<()>`; access logging still needs the request fields).
    #[cfg(feature = "http3")]
    pub(crate) fn capture_http3(
        request: &http::Request<()>,
        remote: Option<SocketAddr>,
        tls: Option<&TlsLogInfo>,
    ) -> Self {
        Self::capture_fields(
            request.method(),
            request.version(),
            request.uri(),
            request.headers(),
            remote,
            tls,
        )
    }

    fn capture_fields(
        method: &http::Method,
        version: http::Version,
        uri: &http::Uri,
        headers: &HeaderMap,
        remote: Option<SocketAddr>,
        tls: Option<&TlsLogInfo>,
    ) -> Self {
        let host = headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .or_else(|| uri.authority().map(|authority| authority.to_string()))
            .unwrap_or_default();
        let uri = uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let content_length = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0);
        Self {
            method: method.as_str().to_string(),
            host,
            uri,
            proto: proto_name(version),
            headers: headers.clone(),
            content_length,
            remote,
            tls: tls.cloned(),
            timestamp: SystemTime::now(),
            resolved_client_ip: None,
        }
    }

    /// Resolve Caddy's `client_ip` request variable exactly like `PrepareRequest` does:
    /// the peer IP unless the peer is a trusted proxy, in which case the configured
    /// `client_ip_headers` value (bare address; port stripped). Only called when access logging is
    /// enabled, so the no-logging path pays nothing.
    pub(crate) fn resolve_client_ip(
        &mut self,
        trusted_proxies: &caddy_rs_proxy::trusted_proxies::ServerTrustedProxies,
    ) {
        let mut probe = caddy_rs_http::Request::new(http::Method::GET, http::Uri::from_static("/"));
        probe.version = http::Version::HTTP_11;
        probe.headers = self.headers.clone();
        probe.remote_addr = self.remote;
        let (_, client_ip) = trusted_proxies.determine(&probe);
        self.resolved_client_ip = Some(client_ip);
    }

    fn access_entry(
        &self,
        status: u16,
        duration: Duration,
        size: u64,
        response_headers: &HeaderMap,
    ) -> AccessLogEntry {
        let mut request = AccessLogRequest::new(&self.method, &self.host, &self.uri)
            .with_remote(self.remote)
            .with_headers(&self.headers);
        // Go's net/http sets `RemoteAddr` to "@" for Unix-socket peers; Caddy logs
        // `remote_ip: "@"`, `remote_port: ""` in that case. caddy-rs has no peer `SocketAddr` for
        // Unix listeners, so represent the missing address the same way.
        if self.remote.is_none() {
            request.remote_ip = "@".to_string();
            request.remote_port = String::new();
        }
        // Caddy resolves `client_ip` in `PrepareRequest` and logs the resolved value; a transport
        // peer that is not a trusted proxy resolves to itself, a trusted proxy resolves through
        // `client_ip_headers` (never a port). See `resolve_client_ip`.
        request.client_ip = self.resolved_client_ip.clone();
        request.proto = self.proto.clone();
        request.tls = self.tls.as_ref().map(TlsLogInfo::to_access_tls);
        AccessLogEntry::new(request)
            .with_timestamp(self.timestamp)
            .with_status(status)
            .with_duration(duration)
            .with_size(size)
            .with_response_headers(response_headers)
    }

    /// Caddy's `bytes_read` fallback when no per-request access-log context is available.
    ///
    /// The live server always attaches a context (so the actual bytes are reported); this
    /// declared-length value is only used by callers that render a snapshot without one.
    fn declared_bytes_read(&self) -> u64 {
        self.content_length
    }
}

fn proto_name(version: http::Version) -> String {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
    .to_string()
}

/// Start recording one request. The caller keeps the guard for the request's lifetime.
pub(crate) fn request_started(
    recorder: &SharedRequestRecorder,
    server_name: &str,
) -> caddy_rs_admin::RequestGuard {
    recorder
        .request_started(server_name, "")
        .unwrap_or_else(|error| {
            eprintln!("caddy-rs: cannot record request start: {error}");
            caddy_rs_admin::RequestGuard::noop()
        })
}

/// One request observation, finished when the response body completes.
///
/// The connection boundary hands the response body to hyper and returns, so it cannot render the
/// access entry there: Caddy measures `duration` at the last byte and counts the bytes actually
/// handed to the transport (`modules/caddyhttp/server.go:710-715`,
/// `responsewriter.go:185-210`). The server attaches this observer to the final response body
/// (`Body::observe`); hyper calls it exactly once when the body ends, fails, or is dropped.
///
/// Metrics are recorded at the same body-end boundary, so `response_duration`/`response_size`
/// describe the complete response.
pub(crate) struct PendingObservation {
    recorder: SharedRequestRecorder,
    access_log: Arc<AccessLogRuntime>,
    policy: Arc<ServerAccessLogPolicy>,
    server_name: String,
    method: String,
    snapshot: Option<RequestSnapshot>,
    started: Instant,
    status: u16,
    response_headers: HeaderMap,
    context: Option<Arc<AccessLogContext>>,
    completed: AtomicBool,
}

impl PendingObservation {
    /// Capture the observation for one response.
    ///
    /// `snapshot` is only present when access logging is enabled; the metrics half works without
    /// it (falling back to the declared request size).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        recorder: &SharedRequestRecorder,
        access_log: &Arc<AccessLogRuntime>,
        policy: &Arc<ServerAccessLogPolicy>,
        server_name: &str,
        method: &str,
        snapshot: Option<RequestSnapshot>,
        started: Instant,
        status: u16,
        response_headers: HeaderMap,
        context: Option<Arc<AccessLogContext>>,
    ) -> Self {
        Self {
            recorder: Arc::clone(recorder),
            access_log: Arc::clone(access_log),
            policy: Arc::clone(policy),
            server_name: server_name.to_string(),
            method: method.to_string(),
            snapshot,
            started,
            status,
            response_headers,
            context,
            completed: AtomicBool::new(false),
        }
    }

    /// Finish immediately for a response whose body is not observed by the server (an upgraded
    /// connection or a small synthetic error body).
    pub(crate) fn finish_now(&self, response_size: u64, write_error: Option<&str>) {
        self.finish(response_size, write_error);
    }

    /// Derive Caddy's `write_error` from how the observed body stopped.
    ///
    /// * an error frame is a failed write (the response could not be completed),
    /// * a drop after every advertised byte was written is a normal fixed-length completion; hyper
    ///   drops such bodies after the last frame instead of polling an extra end-of-stream,
    /// * `HEAD`/`1xx`/`204`/`304` responses never carry a body, so a drop is not an error,
    /// * a drop after some bytes were polled is a truncated response (usually a client disconnect).
    ///
    /// The transport does not expose the underlying socket error, so the message records the
    /// observable fact (bytes written and the body's error, when any) rather than inventing one.
    fn write_error_for(&self, completion: &BodyCompletion) -> Option<String> {
        match &completion.status {
            BodyStatus::Ended => None,
            BodyStatus::Failed(error) => Some(format!(
                "response body ended with an error after {} bytes: {error}",
                completion.bytes
            )),
            BodyStatus::Dropped => {
                if completion.expected == Some(completion.bytes) {
                    return None;
                }
                if self.method == "HEAD" || matches!(self.status, 100..=199 | 204 | 304) {
                    return None;
                }
                if !completion.polled {
                    return None;
                }
                let expected = completion
                    .expected
                    .map_or_else(String::new, |expected| format!(" of {expected}"));
                Some(format!(
                    "response body was not fully written: connection closed after {} bytes{expected}",
                    completion.bytes
                ))
            }
        }
    }

    /// Record metrics and emit the access entry exactly once.
    fn finish(&self, response_size: u64, write_error: Option<&str>) {
        if self.completed.swap(true, Ordering::SeqCst) {
            return;
        }
        let duration = self.started.elapsed();
        let request_size = self.context.as_ref().map_or_else(
            || {
                self.snapshot
                    .as_ref()
                    .map_or(0, RequestSnapshot::declared_bytes_read)
            },
            |context| context.request_bytes().get(),
        );
        if let Err(error) = self.recorder.request_finished(&RequestObservation {
            server: &self.server_name,
            handler: "",
            method: &self.method,
            status: self.status,
            duration,
            request_size,
            response_size,
            response_duration: duration,
            // Handler errors are mapped to 500 by the connection boundary; counting those as
            // errors matches Caddy's `request_errors_total` intent closely enough for alerting.
            error: self.status >= 500,
        }) {
            eprintln!("caddy-rs: cannot record request metrics: {error}");
        }

        if !self.access_log.is_enabled() {
            return;
        }
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        if let Some(context) = &self.context {
            // `apply_to` reads the shared counters; finish the clock first so the entry's
            // `duration` is time-to-last-byte, not time-to-headers.
            context.response_bytes().set(response_size);
            context.finish();
        }
        let AccessLogRoute::Loggers(loggers) = self.policy.route(&snapshot.host) else {
            return;
        };
        for component in loggers {
            let mut entry =
                snapshot.access_entry(self.status, duration, response_size, &self.response_headers);
            if let Some(context) = &self.context {
                context.apply_to(&mut entry);
            } else {
                entry.bytes_read = snapshot.declared_bytes_read();
            }
            if let Some(error) = write_error {
                entry.write_error = Some(error.to_string());
            }
            entry.logger = logger_name(&component);
            self.access_log.emit(&entry);
        }
    }
}

impl ResponseBodyObserver for PendingObservation {
    fn complete(&self, completion: BodyCompletion) {
        let write_error = self.write_error_for(&completion);
        self.finish(completion.bytes, write_error.as_deref());
    }
}

/// Record the finished request and emit its access-log entry immediately.
///
/// Used for responses whose body the server does not observe (protocol upgrades and small
/// synthetic error responses). Normal responses use [`PendingObservation`] attached to the body,
/// so `duration`/`size` cover the complete response body. Metric/encoding failures are best-effort:
/// printed and swallowed so observability never changes the served response.
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_request(
    recorder: &SharedRequestRecorder,
    access_log: &Arc<AccessLogRuntime>,
    policy: &Arc<ServerAccessLogPolicy>,
    server_name: &str,
    method: &str,
    snapshot: Option<&RequestSnapshot>,
    started: Instant,
    status: u16,
    response_size: u64,
    response_headers: &HeaderMap,
    context: Option<&Arc<AccessLogContext>>,
    write_error: Option<&str>,
) {
    PendingObservation::new(
        recorder,
        access_log,
        policy,
        server_name,
        method,
        snapshot.cloned(),
        started,
        status,
        response_headers.clone(),
        context.cloned(),
    )
    .finish_now(response_size, write_error);
}

/// Content length of a buffered body, if known.
pub(crate) fn body_len(body: &caddy_rs_http::Body) -> u64 {
    body.exact_size().unwrap_or(0)
}

/// Certificate expiry/renewal metrics snapshot for the active renewal scheduler.
///
/// Called after a generation with automatic HTTPS becomes active. Expiry gauges are rewritten on
/// every call (gauge semantics); renewal counters are only advanced for outcomes not seen before.
pub(crate) fn record_certificate_metrics(
    metrics: &CertificateMetrics,
    renewals: &caddy_rs_tls::AutomaticHttpsRenewals,
    now: SystemTime,
    seen_renewals: &mut usize,
) {
    for certificate in renewals.store().certificates() {
        let subject = certificate
            .domains
            .first()
            .cloned()
            .unwrap_or_else(|| certificate.domains.join(","));
        let _ = metrics.certificate_expiry_at(
            &certificate.issuer,
            &subject,
            certificate.not_after,
            now,
        );
    }

    let history = renewals.scheduler().history();
    for outcome in history.iter().skip(*seen_renewals) {
        let (success, domains) = match outcome {
            caddy_rs_tls::RenewalOutcome::Renewed { domains, .. } => (true, domains),
            caddy_rs_tls::RenewalOutcome::Failed { domains, .. } => (false, domains),
            // Not-due/skipped outcomes are not renewal attempts.
            _ => continue,
        };
        let subject = domains.first().cloned().unwrap_or_default();
        let _ = metrics.certificate_renewal("", &subject, success, Duration::ZERO);
    }
    *seen_renewals = history.len();
}

#[cfg(test)]
mod write_error_tests {
    use super::*;

    fn pending_observation(method: &str, status: u16) -> PendingObservation {
        PendingObservation::new(
            &caddy_rs_admin::noop_recorder(),
            &AccessLogRuntime::disabled(),
            &Arc::new(ServerAccessLogPolicy::default()),
            "srv0",
            method,
            None,
            Instant::now(),
            status,
            HeaderMap::new(),
            None,
        )
    }

    fn completion(
        bytes: u64,
        expected: Option<u64>,
        polled: bool,
        status: BodyStatus,
    ) -> BodyCompletion {
        BodyCompletion {
            bytes,
            expected,
            polled,
            status,
        }
    }

    #[test]
    fn successful_bodies_omit_write_error() {
        let observation = pending_observation("GET", 200);
        // A streamed body that reaches end of stream.
        assert_eq!(
            observation.write_error_for(&completion(12, None, true, BodyStatus::Ended)),
            None
        );
        // hyper drops fixed-length bodies right after the last data frame instead of polling an
        // extra end-of-stream; every advertised byte was written, so this is still a success.
        assert_eq!(
            observation.write_error_for(&completion(12, Some(12), true, BodyStatus::Dropped)),
            None
        );
        // Bodies the transport must not send (HEAD, 1xx, 204, 304) are dropped unread.
        assert_eq!(
            observation.write_error_for(&completion(0, Some(5), false, BodyStatus::Dropped)),
            None
        );
        assert_eq!(
            pending_observation("HEAD", 200).write_error_for(&completion(
                0,
                Some(5),
                false,
                BodyStatus::Dropped
            )),
            None
        );
        assert_eq!(
            pending_observation("GET", 204).write_error_for(&completion(
                0,
                None,
                false,
                BodyStatus::Dropped
            )),
            None
        );
    }

    #[test]
    fn failed_and_truncated_bodies_record_write_error() {
        let observation = pending_observation("GET", 200);
        let failed = observation
            .write_error_for(&completion(
                3,
                None,
                true,
                BodyStatus::Failed("body stream was cancelled".to_string()),
            ))
            .expect("an errored body is a failed write");
        assert!(failed.contains("body stream was cancelled"), "{failed}");

        let truncated = observation
            .write_error_for(&completion(3, Some(10), true, BodyStatus::Dropped))
            .expect("a truncated body is a failed write");
        assert!(truncated.contains("3 bytes"), "{truncated}");
        assert!(truncated.contains("of 10"), "{truncated}");
    }
}
