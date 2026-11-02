//! Runtime request-recording API (plan task T-ADMIN-022).
//!
//! The server runtime owns the request lifecycle; the admin crate owns the metric primitives
//! ([`HttpMetrics`]) and the Prometheus rendering behind `GET /metrics`. This module is the seam
//! between them: a small observer trait the server calls per request/proxy exchange/TLS event, a
//! no-op implementation for tests and un-instrumented builds, and a metrics-backed implementation
//! sharing one [`HttpMetrics`] handle.
//!
//! ```text
//! server request task                      admin crate
//! ------------------                      -----------
//! let guard = recorder.request_started(server, handler);
//! ... handle request ...
//! recorder.request_finished(&RequestObservation { .. });
//! drop(guard);                              -> caddy_http_requests_in_flight gauge
//! ```
//!
//! Design rules:
//!
//! * **Best-effort observability never breaks serving.** Failures (only possible for inconsistent
//!   metric registration) are returned, not panicked on; callers may ignore them.
//! * **In-flight accounting is RAII.** [`RequestGuard`]/[`ProxyRequestGuard`] decrement their
//!   gauge on drop, including on early returns and cancellation paths.
//! * **No high-cardinality labels.** The recorder only forwards the bounded labels already used by
//!   [`HttpMetrics`] (server, handler, method, status, upstream dial, issuer, subject).
//! * **Shared handle.** [`SharedRequestRecorder`] is a clonable `Arc<dyn RequestRecorder>` the
//!   runtime stores once and clones per task; the no-op recorder is a unit struct.
//!
//! Caddy publishes its HTTP metrics only when `apps.http.metrics` is enabled; caddy-rs keeps the
//! same switch at the server-runtime level (see `docs/compatibility/BEHAVIOR-DIVERGENCES.md`
//! DIV-0033 for the extension metrics). See the crate docs for the server wiring recipe.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::metrics::{
    HttpMetrics, InFlightGuard, MetricsError, ProxyInFlightGuard, ProxyObservation,
    RequestObservation,
};

/// RAII handle for one in-flight HTTP request.
///
/// Dropping the guard decrements `caddy_http_requests_in_flight` for the recorded server/handler
/// pair. A guard created by the no-op recorder is inert.
#[derive(Debug)]
pub struct RequestGuard {
    inner: Option<InFlightGuard>,
}

impl RequestGuard {
    /// An inert guard that does not touch any metric (used by [`NoopRequestRecorder`]).
    pub fn noop() -> Self {
        Self { inner: None }
    }

    fn instrumented(guard: InFlightGuard) -> Self {
        Self { inner: Some(guard) }
    }

    /// Whether dropping this guard will decrement an in-flight gauge.
    pub fn is_instrumented(&self) -> bool {
        self.inner.is_some()
    }
}

/// RAII handle for one in-flight proxy upstream request.
///
/// Dropping the guard decrements `caddy_rs_proxy_active_requests` for the upstream. A guard created
/// by the no-op recorder is inert.
#[derive(Debug)]
pub struct ProxyRequestGuard {
    inner: Option<ProxyInFlightGuard>,
}

impl ProxyRequestGuard {
    /// An inert guard that does not touch any metric (used by [`NoopRequestRecorder`]).
    pub fn noop() -> Self {
        Self { inner: None }
    }

    fn instrumented(guard: ProxyInFlightGuard) -> Self {
        Self { inner: Some(guard) }
    }

    /// Whether dropping this guard will decrement an in-flight gauge.
    pub fn is_instrumented(&self) -> bool {
        self.inner.is_some()
    }
}

/// Observer interface for the server runtime's request lifecycle.
///
/// Every method has a no-op default so an implementation can override only what it needs; the
/// blanket defaults make [`NoopRequestRecorder`] a single line. Implementations must be cheap and
/// non-blocking on the request path.
pub trait RequestRecorder: Send + Sync + 'static {
    /// Record that a request started. Keep the returned guard for the request's lifetime.
    fn request_started(&self, _server: &str, _handler: &str) -> Result<RequestGuard, MetricsError> {
        Ok(RequestGuard::noop())
    }

    /// Record one completed request (counters, error counter, latency/size histograms).
    fn request_finished(&self, _observation: &RequestObservation<'_>) -> Result<(), MetricsError> {
        Ok(())
    }

    /// Record that a proxy upstream request started. Keep the guard for its lifetime.
    fn proxy_request_started(&self, _upstream: &str) -> Result<ProxyRequestGuard, MetricsError> {
        Ok(ProxyRequestGuard::noop())
    }

    /// Record one completed proxy upstream request.
    fn proxy_request_finished(
        &self,
        _observation: &ProxyObservation<'_>,
    ) -> Result<(), MetricsError> {
        Ok(())
    }

    /// Record how many seconds remain until a managed certificate expires.
    fn certificate_expiry(
        &self,
        _issuer: &str,
        _subject: &str,
        _seconds_until_expiry: f64,
    ) -> Result<(), MetricsError> {
        Ok(())
    }

    /// Record one certificate renewal attempt and its duration.
    fn certificate_renewal(
        &self,
        _issuer: &str,
        _subject: &str,
        _success: bool,
        _duration: Duration,
    ) -> Result<(), MetricsError> {
        Ok(())
    }
}

/// Type-erased recorder handle stored by the runtime and cloned per task.
pub type SharedRequestRecorder = Arc<dyn RequestRecorder>;

/// A recorder that intentionally records nothing (unit-instrumented builds, tests).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopRequestRecorder;

impl RequestRecorder for NoopRequestRecorder {}

/// A recorder backed by a shared [`HttpMetrics`].
#[derive(Debug, Clone)]
pub struct MetricsRequestRecorder {
    metrics: Arc<HttpMetrics>,
}

impl MetricsRequestRecorder {
    /// Wrap a shared metrics handle.
    pub fn new(metrics: Arc<HttpMetrics>) -> Self {
        Self { metrics }
    }

    /// Wrap `metrics` and return the type-erased handle the runtime stores.
    pub fn shared(metrics: Arc<HttpMetrics>) -> SharedRequestRecorder {
        Arc::new(Self::new(metrics))
    }

    /// The shared metrics handle.
    pub fn metrics(&self) -> &Arc<HttpMetrics> {
        &self.metrics
    }
}

impl RequestRecorder for MetricsRequestRecorder {
    fn request_started(&self, server: &str, handler: &str) -> Result<RequestGuard, MetricsError> {
        self.metrics
            .request_started(server, handler)
            .map(RequestGuard::instrumented)
    }

    fn request_finished(&self, observation: &RequestObservation<'_>) -> Result<(), MetricsError> {
        self.metrics.request_finished(observation)
    }

    fn proxy_request_started(&self, upstream: &str) -> Result<ProxyRequestGuard, MetricsError> {
        self.metrics
            .proxy_request_started(upstream)
            .map(ProxyRequestGuard::instrumented)
    }

    fn proxy_request_finished(
        &self,
        observation: &ProxyObservation<'_>,
    ) -> Result<(), MetricsError> {
        self.metrics.proxy_request_finished(observation)
    }

    fn certificate_expiry(
        &self,
        issuer: &str,
        subject: &str,
        seconds_until_expiry: f64,
    ) -> Result<(), MetricsError> {
        self.metrics
            .certificate_expiry(issuer, subject, seconds_until_expiry)
    }

    fn certificate_renewal(
        &self,
        issuer: &str,
        subject: &str,
        success: bool,
        duration: Duration,
    ) -> Result<(), MetricsError> {
        self.metrics
            .certificate_renewal(issuer, subject, success, duration)
    }
}

/// Return a shared no-op recorder.
pub fn noop_recorder() -> SharedRequestRecorder {
    Arc::new(NoopRequestRecorder)
}

/// A small handle for certificate expiry/renewal metrics.
///
/// TLS code (certificate management, renewal scheduler) can hold this instead of the whole
/// recorder when it only publishes certificate series. Cloning is cheap and shares the registry.
#[derive(Debug, Clone)]
pub struct CertificateMetrics {
    metrics: Arc<HttpMetrics>,
}

impl CertificateMetrics {
    /// Wrap a shared metrics handle.
    pub fn new(metrics: Arc<HttpMetrics>) -> Self {
        Self { metrics }
    }

    /// Wrap `metrics` and return a type-erased recorder (which also exposes the certificate hooks).
    pub fn recorder(metrics: Arc<HttpMetrics>) -> SharedRequestRecorder {
        MetricsRequestRecorder::shared(metrics)
    }

    /// Record seconds until expiry (negative when already expired, useful for alerting).
    pub fn certificate_expiry(
        &self,
        issuer: &str,
        subject: &str,
        seconds_until_expiry: f64,
    ) -> Result<(), MetricsError> {
        self.metrics
            .certificate_expiry(issuer, subject, seconds_until_expiry)
    }

    /// Convenience for TLS renewal code: record seconds between `now` and `expires_at`.
    ///
    /// Expired certificates yield a negative value (Caddy exposes a positive "expires in" gauge;
    /// a negative value is the unambiguous caddy-rs way to surface an already-expired cert).
    pub fn certificate_expiry_at(
        &self,
        issuer: &str,
        subject: &str,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> Result<(), MetricsError> {
        let seconds = match expires_at.duration_since(now) {
            Ok(remaining) => remaining.as_secs_f64(),
            Err(expired) => -expired.duration().as_secs_f64(),
        };
        self.certificate_expiry(issuer, subject, seconds)
    }

    /// Record one renewal attempt (success or failure) and its duration.
    pub fn certificate_renewal(
        &self,
        issuer: &str,
        subject: &str,
        success: bool,
        duration: Duration,
    ) -> Result<(), MetricsError> {
        self.metrics
            .certificate_renewal(issuer, subject, success, duration)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::metrics::{HttpMetrics, MetricsRegistry};

    fn shared_metrics() -> (MetricsRegistry, Arc<HttpMetrics>) {
        let registry = MetricsRegistry::new();
        let metrics = Arc::new(HttpMetrics::new(registry.clone()));
        (registry, metrics)
    }

    #[test]
    fn noop_recorder_is_inert_and_infallible() {
        let recorder = noop_recorder();
        let guard = recorder.request_started("srv0", "route0").expect("noop");
        assert!(!guard.is_instrumented());
        let proxy_guard = recorder
            .proxy_request_started("127.0.0.1:9000")
            .expect("noop");
        assert!(!proxy_guard.is_instrumented());
        recorder
            .request_finished(&RequestObservation::new(
                "srv0",
                "route0",
                "GET",
                200,
                Duration::from_millis(1),
            ))
            .expect("noop");
        recorder
            .proxy_request_finished(&ProxyObservation {
                upstream: "127.0.0.1:9000",
                method: "GET",
                status: 200,
                duration: Duration::from_millis(1),
                success: true,
            })
            .expect("noop");
        recorder
            .certificate_expiry("acme", "example.com", 60.0)
            .expect("noop");
        recorder
            .certificate_renewal("acme", "example.com", true, Duration::from_secs(1))
            .expect("noop");
        // No-op guards drop cleanly and never touched a registry.
        drop(guard);
        drop(proxy_guard);
    }

    #[test]
    fn metrics_recorder_increments_request_metrics_and_in_flight_gauges() {
        let (registry, metrics) = shared_metrics();
        let recorder = MetricsRequestRecorder::new(Arc::clone(&metrics));

        let first = recorder.request_started("srv0", "route0").expect("start");
        let second = recorder.request_started("srv0", "route0").expect("start");
        assert!(first.is_instrumented());
        assert!(registry
            .render()
            .contains("caddy_http_requests_in_flight{handler=\"route0\",server=\"srv0\"} 2"));

        recorder
            .request_finished(&RequestObservation {
                server: "srv0",
                handler: "route0",
                method: "get",
                status: 200,
                duration: Duration::from_millis(20),
                request_size: 100,
                response_size: 200,
                response_duration: Duration::from_millis(5),
                error: false,
            })
            .expect("finish");
        recorder
            .request_finished(&RequestObservation {
                error: true,
                ..RequestObservation::new("srv0", "route0", "POST", 500, Duration::from_millis(30))
            })
            .expect("finish");

        drop(first);
        assert!(registry
            .render()
            .contains("caddy_http_requests_in_flight{handler=\"route0\",server=\"srv0\"} 1"));
        drop(second);
        let rendered = registry.render();
        assert!(rendered
            .contains("caddy_http_requests_in_flight{handler=\"route0\",server=\"srv0\"} 0"));
        assert!(
            rendered.contains("caddy_http_requests_total{handler=\"route0\",server=\"srv0\"} 2")
        );
        assert!(rendered
            .contains("caddy_http_request_errors_total{handler=\"route0\",server=\"srv0\"} 1"));
        assert!(rendered.contains(
            "caddy_http_request_duration_seconds_count{code=\"200\",handler=\"route0\",method=\"GET\",server=\"srv0\"} 1"
        ));
        assert!(rendered.contains(
            "caddy_http_request_duration_seconds_count{code=\"500\",handler=\"route0\",method=\"POST\",server=\"srv0\"} 1"
        ));
    }

    #[test]
    fn metrics_recorder_records_proxy_observations_and_guards() {
        let (registry, metrics) = shared_metrics();
        let recorder = MetricsRequestRecorder::shared(Arc::clone(&metrics));

        let guard = recorder
            .proxy_request_started("10.0.0.5:8080")
            .expect("proxy start");
        assert!(guard.is_instrumented());
        assert!(registry
            .render()
            .contains("caddy_rs_proxy_active_requests{upstream=\"10.0.0.5:8080\"} 1"));
        drop(guard);
        assert!(registry
            .render()
            .contains("caddy_rs_proxy_active_requests{upstream=\"10.0.0.5:8080\"} 0"));

        recorder
            .proxy_request_finished(&ProxyObservation {
                upstream: "10.0.0.5:8080",
                method: "GET",
                status: 200,
                duration: Duration::from_millis(10),
                success: true,
            })
            .expect("proxy finish");
        recorder
            .proxy_request_finished(&ProxyObservation {
                upstream: "10.0.0.5:8080",
                method: "GET",
                status: 502,
                duration: Duration::from_millis(2),
                success: false,
            })
            .expect("proxy finish");
        let rendered = registry.render();
        assert!(rendered.contains(
            "caddy_rs_proxy_requests_total{code=\"200\",method=\"GET\",upstream=\"10.0.0.5:8080\"} 1"
        ));
        assert!(
            rendered.contains("caddy_rs_proxy_request_errors_total{upstream=\"10.0.0.5:8080\"} 1")
        );
    }

    #[test]
    fn certificate_metrics_handle_records_expiry_and_renewal() {
        let (registry, metrics) = shared_metrics();
        let certificates = CertificateMetrics::new(Arc::clone(&metrics));

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let expires = now + Duration::from_secs(86_400);
        certificates
            .certificate_expiry_at("acme", "example.com", expires, now)
            .expect("expiry");
        // Already expired: negative seconds, still recorded (supports alerting on < 0).
        certificates
            .certificate_expiry_at(
                "acme",
                "expired.example",
                now - Duration::from_secs(30),
                now,
            )
            .expect("expired");
        certificates
            .certificate_renewal("acme", "example.com", true, Duration::from_secs(2))
            .expect("renewal ok");
        certificates
            .certificate_renewal("acme", "example.com", false, Duration::from_secs(3))
            .expect("renewal failed");

        let rendered = registry.render();
        assert!(rendered.contains(
            "caddy_rs_tls_certificate_expiration_seconds{issuer=\"acme\",subject=\"example.com\"} 86400"
        ));
        assert!(rendered.contains(
            "caddy_rs_tls_certificate_expiration_seconds{issuer=\"acme\",subject=\"expired.example\"} -30"
        ));
        assert!(rendered.contains(
            "caddy_rs_tls_certificate_renewal_total{issuer=\"acme\",result=\"success\",subject=\"example.com\"} 1"
        ));
        assert!(rendered.contains(
            "caddy_rs_tls_certificate_renewal_total{issuer=\"acme\",result=\"error\",subject=\"example.com\"} 1"
        ));
        assert!(rendered.contains(
            "caddy_rs_tls_certificate_renewal_duration_seconds_count{issuer=\"acme\",subject=\"example.com\"} 2"
        ));
        // The recorder trait exposes the same hooks for TLS code holding the shared handle.
        let recorder = CertificateMetrics::recorder(Arc::clone(&metrics));
        recorder
            .certificate_renewal(
                "internal",
                "internal.example",
                true,
                Duration::from_millis(1),
            )
            .expect("recorder renewal");
        assert!(registry.render().contains(
            "caddy_rs_tls_certificate_renewal_total{issuer=\"internal\",result=\"success\",subject=\"internal.example\"} 1"
        ));
    }

    #[test]
    fn recorder_handles_are_send_sync_for_runtime_wiring() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SharedRequestRecorder>();
        assert_send_sync::<RequestGuard>();
        assert_send_sync::<ProxyRequestGuard>();
        assert_send_sync::<CertificateMetrics>();
        assert_send_sync::<MetricsRequestRecorder>();
        assert_send_sync::<NoopRequestRecorder>();
    }

    #[test]
    fn concurrent_recording_through_a_shared_handle_is_thread_safe() {
        let (registry, metrics) = shared_metrics();
        let recorder = MetricsRequestRecorder::shared(Arc::clone(&metrics));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let recorder = Arc::clone(&recorder);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        let guard = recorder.request_started("srv0", "route0").expect("start");
                        recorder
                            .request_finished(&RequestObservation::new(
                                "srv0",
                                "route0",
                                "GET",
                                200,
                                Duration::from_micros(10),
                            ))
                            .expect("finish");
                        drop(guard);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("thread");
        }
        let rendered = registry.render();
        assert!(
            rendered.contains("caddy_http_requests_total{handler=\"route0\",server=\"srv0\"} 800")
        );
        assert!(rendered
            .contains("caddy_http_requests_in_flight{handler=\"route0\",server=\"srv0\"} 0"));
    }
}
