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
//! * [`observe_request`] records the finished-request metric observation and emits the access
//!   entry, with errors logged but never propagated into the request path ("best-effort
//!   observability never breaks serving").
//!
//! Metrics are always recorded (the recorder is cheap; with no active sinks the access-log half is
//! skipped), matching caddy-rs's documented always-on metrics extension (DIV-0033). Access-log
//! entries are only emitted when the active configuration contains a `logging` section: building a
//! sink from the implicit Caddy default would otherwise write every request to stderr even though
//! the operator never configured access logging.
//!
//! Gaps (reported with T-ADMIN-024): proxy upstream observations need a recorder handle inside
//! `caddy-rs-proxy` (not reachable from this crate); certificate metrics are recorded as a snapshot
//! at generation apply time (ongoing renewal outcomes are picked up on the next apply, which the
//! supervisor performs every poll interval); streaming response sizes/`bytes_read` are only known
//! when the body reports an exact size.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use http::HeaderMap;

use caddy_rs_admin::{
    AccessLogEntry, AccessLogRequest, AccessLogTls, BuiltAccessLogSink, CertificateMetrics,
    LoggingConfig, LoggingConfigError, RequestObservation, SharedRequestRecorder,
};
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
#[derive(Debug)]
pub(crate) struct RequestSnapshot {
    method: String,
    host: String,
    uri: String,
    proto: String,
    headers: HeaderMap,
    remote: Option<SocketAddr>,
    tls: Option<TlsLogInfo>,
    timestamp: SystemTime,
}

impl RequestSnapshot {
    /// Capture the access-log-relevant request fields.
    pub(crate) fn capture(
        request: &hyper::Request<Incoming>,
        remote: Option<SocketAddr>,
        tls: Option<&TlsLogInfo>,
    ) -> Self {
        let host = request
            .headers()
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .or_else(|| {
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.to_string())
            })
            .unwrap_or_default();
        let uri = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        Self {
            method: request.method().as_str().to_string(),
            host,
            uri,
            proto: proto_name(request.version()),
            headers: request.headers().clone(),
            remote,
            tls: tls.cloned(),
            timestamp: SystemTime::now(),
        }
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
        request.proto = self.proto.clone();
        request.tls = self.tls.as_ref().map(TlsLogInfo::to_access_tls);
        AccessLogEntry::new(request)
            .with_timestamp(self.timestamp)
            .with_status(status)
            .with_duration(duration)
            .with_size(size)
            .with_response_headers(response_headers)
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

/// Record the finished request and emit its access-log entry (when access logging is enabled).
///
/// Best-effort: metric/encoding failures are printed and swallowed so observability can never
/// change the served response. `handler` is currently always empty because the router does not
/// expose the matched route id at the connection boundary.
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_request(
    recorder: &SharedRequestRecorder,
    access_log: &AccessLogRuntime,
    server_name: &str,
    method: &str,
    snapshot: Option<&RequestSnapshot>,
    started: Instant,
    status: u16,
    response_size: u64,
    response_headers: &HeaderMap,
) {
    let duration = started.elapsed();
    // Request-body accounting is not surfaced across the router boundary yet (T-PROXY-039).
    let request_size = 0;
    if let Err(error) = recorder.request_finished(&RequestObservation {
        server: server_name,
        handler: "",
        method,
        status,
        duration,
        request_size,
        response_size,
        response_duration: duration,
        // Handler errors are mapped to 500 by the connection boundary; counting those as errors
        // matches Caddy's `request_errors_total` intent closely enough for alerting.
        error: status >= 500,
    }) {
        eprintln!("caddy-rs: cannot record request metrics: {error}");
    }

    if !access_log.is_enabled() {
        return;
    }
    let Some(snapshot) = snapshot else {
        return;
    };
    access_log.emit(&snapshot.access_entry(status, duration, response_size, response_headers));
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
