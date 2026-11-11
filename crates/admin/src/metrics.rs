//! Prometheus text-format metrics primitives (plan task T-ADMIN-021).
//!
//! Caddy exposes metrics through `prometheus/client_golang`. That crate is not available in this
//! build's dependency cache, so this module implements the small part of the ecosystem caddy-rs
//! needs by hand:
//!
//! * [`MetricsRegistry`] — a registry of counters, gauges and histograms with label sets,
//! * [`Counter`], [`Gauge`], [`Histogram`] — cheap handles that mutate a registered series,
//! * [`render`](MetricsRegistry::render) — deterministic [Prometheus text format][format] (0.0.4)
//!   exposition, ordered by metric name and then by sorted label set,
//! * [`HttpMetrics`] — typed instrumentation for the Caddy HTTP metric names plus caddy-rs
//!   proxy/certificate extensions.
//!
//! The text format is implemented rather than delegated so the output is deterministic: metric
//! families are sorted by name, series by their sorted label set, and variable labels are printed
//! in alphabetical order with the histogram `le` label last (matching Go's `expfmt` writer). Float
//! values and bucket bounds use Go's `strconv.FormatFloat(v, 'g', -1, 64)` presentation, and the
//! exposition content type matches Caddy v2.11.7's `promhttp` response. Two registries with the
//! same contents therefore render byte-identical text, and a `/metrics` scrape of the
//! `caddy_http_*` families is byte-compatible with Caddy's for the same observations and labels.
//!
//! ## Caddy compatibility
//!
//! The `caddy_http_*` series mirror Caddy v2.11.9's `modules/caddyhttp/metrics.go` names, help
//! text, label names and bucket choices (`caddy_http_requests_total`,
//! `caddy_http_request_duration_seconds`, …).
//!
//! Caddy only emits them when `apps.http.metrics` is present; [`HttpMetricsPolicy`] is that gate.
//! [`HttpMetricsPolicy::Disabled`] makes every `caddy_http_*` recording method a no-op, so a
//! configuration without the object never registers a family (the admin `/metrics` endpoint keeps
//! serving whatever the registry holds, exactly like Caddy's admin handler keeps serving the
//! process registry). [`HttpMetrics::new`] keeps the historical always-on policy for callers that
//! are not driven by a configuration; configuration-driven runtimes use
//! [`crate::metrics_config::http_metrics_for_config`].
//!
//! With `per_host` configured, [`HostLabelPolicy`] adds Caddy's bounded `host` label: only hosts
//! named by a non-fuzzy host matcher are individually labelled, unknown hosts aggregate under
//! [`CATCHALL_HOST_LABEL`] (`_other`), and `observe_catchall_hosts` (or an HTTPS request on a
//! server with TLS connection policies) lets a catch-all host keep its own label. The scan and the
//! rules mirror `scanConfigForHosts`/`shouldAllowHostMetrics` (metrics.go:232-285) and
//! `MatchHost.fuzzy` (`matchers.go:395`).
//!
//! Proxy and certificate series (`caddy_rs_proxy_*`, `caddy_rs_tls_*`) are caddy-rs extensions
//! because Caddy v2.11.9 does not publish them; they stay available regardless of the HTTP
//! metrics gate. See `docs/compatibility/BEHAVIOR-DIVERGENCES.md` DIV-0033/DIV-0052.
//!
//! ## Cardinality
//!
//! The registry accepts arbitrary label sets, but the typed [`HttpMetrics`] layer only uses
//! bounded labels: server name, handler name, HTTP method (sanitized), status code, upstream dial
//! address, certificate issuer/subject and renewal result. The only request-controlled label is
//! `host`, and only when `per_host` is configured and Caddy's allow-list/catch-all rule permits it;
//! URI, peer IP and user IDs are deliberately never used as labels.
//!
//! [format]: https://prometheus.io/docs/instrumenting/exposition_formats/

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// Content type of the Prometheus text exposition format (version 0.0.4).
///
/// Matches the header Caddy v2.11.7's `promhttp` handler returns for a default scrape
/// (`escaping=underscores` is client_golang's default name-escaping scheme; caddy-rs only emits
/// names and label names that are already valid, so the scheme does not change the rendered text).
pub const METRICS_CONTENT_TYPE: &str =
    "text/plain; version=0.0.4; charset=utf-8; escaping=underscores";

/// Default histogram buckets for latencies in seconds, matching `prometheus.DefBuckets` as used by
/// Caddy's HTTP metrics.
pub const DEFAULT_DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Default histogram buckets for sizes in bytes, matching Caddy's
/// `ExponentialBuckets(256, 4, 8)` choice: 256 B … 4 MiB.
pub const DEFAULT_SIZE_BUCKETS: &[f64] = &[
    256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0,
];

/// Counter of HTTP(S) requests made (Caddy-compatible name).
pub const HTTP_REQUESTS_TOTAL: &str = "caddy_http_requests_total";
/// Number of requests resulting in middleware errors (Caddy-compatible name).
pub const HTTP_REQUEST_ERRORS_TOTAL: &str = "caddy_http_request_errors_total";
/// Number of requests currently handled by this server (Caddy-compatible name).
pub const HTTP_REQUESTS_IN_FLIGHT: &str = "caddy_http_requests_in_flight";
/// Histogram of round-trip request durations (Caddy-compatible name).
pub const HTTP_REQUEST_DURATION_SECONDS: &str = "caddy_http_request_duration_seconds";
/// Histogram of request sizes (Caddy-compatible name).
pub const HTTP_REQUEST_SIZE_BYTES: &str = "caddy_http_request_size_bytes";
/// Histogram of response sizes (Caddy-compatible name).
pub const HTTP_RESPONSE_SIZE_BYTES: &str = "caddy_http_response_size_bytes";
/// Histogram of times to first byte in response bodies (Caddy-compatible name).
pub const HTTP_RESPONSE_DURATION_SECONDS: &str = "caddy_http_response_duration_seconds";

/// Label value Caddy uses for every host without its own allowed label.
///
/// `shouldAllowHostMetrics`/`ServeHTTP` collapse unknown hosts into `_other`
/// (`modules/caddyhttp/metrics.go:331-334`) to bound cardinality.
pub const CATCHALL_HOST_LABEL: &str = "_other";

/// caddy-rs extension: proxy requests per upstream.
pub const PROXY_REQUESTS_TOTAL: &str = "caddy_rs_proxy_requests_total";
/// caddy-rs extension: proxy request errors per upstream.
pub const PROXY_REQUEST_ERRORS_TOTAL: &str = "caddy_rs_proxy_request_errors_total";
/// caddy-rs extension: proxy requests currently in flight per upstream.
pub const PROXY_ACTIVE_REQUESTS: &str = "caddy_rs_proxy_active_requests";
/// caddy-rs extension: proxy upstream latency histogram.
pub const PROXY_REQUEST_DURATION_SECONDS: &str = "caddy_rs_proxy_request_duration_seconds";

/// caddy-rs extension: seconds until a managed certificate expires.
pub const TLS_CERTIFICATE_EXPIRATION_SECONDS: &str = "caddy_rs_tls_certificate_expiration_seconds";
/// caddy-rs extension: certificate renewal attempts.
pub const TLS_CERTIFICATE_RENEWAL_TOTAL: &str = "caddy_rs_tls_certificate_renewal_total";
/// caddy-rs extension: certificate renewal duration histogram.
pub const TLS_CERTIFICATE_RENEWAL_DURATION_SECONDS: &str =
    "caddy_rs_tls_certificate_renewal_duration_seconds";

/// A located metrics error (invalid name/label/bucket or inconsistent re-registration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsError {
    path: String,
    message: String,
}

impl MetricsError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    /// The offending metric name or series.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Human-readable diagnosis.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MetricsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "metric `{}`: {}", self.path, self.message)
    }
}

impl std::error::Error for MetricsError {}

/// The Prometheus metric kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// Monotonically increasing counter.
    Counter,
    /// Value that can go up and down.
    Gauge,
    /// Bucketed observations with sum and count.
    Histogram,
}

impl MetricKind {
    /// The `# TYPE` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
            MetricKind::Histogram => "histogram",
        }
    }
}

/// Label set of one series, sorted by label name so rendering is deterministic.
type Labels = BTreeMap<String, String>;

#[derive(Debug, Default)]
struct RegistryState {
    families: BTreeMap<String, Family>,
}

#[derive(Debug)]
struct Family {
    help: String,
    kind: MetricKind,
    series: BTreeMap<Labels, Series>,
}

#[derive(Debug)]
enum Series {
    Counter(u64),
    Gauge(f64),
    Histogram(HistogramState),
}

#[derive(Debug)]
struct HistogramState {
    /// Upper bounds, strictly ascending and finite. The `+Inf` bucket is implicit.
    buckets: Vec<f64>,
    /// Cumulative counts: `counts[i]` is the number of observations `<= buckets[i]`.
    counts: Vec<u64>,
    count: u64,
    sum: f64,
}

impl HistogramState {
    fn new(buckets: &[f64]) -> Self {
        Self {
            buckets: buckets.to_vec(),
            counts: vec![0; buckets.len()],
            count: 0,
            sum: 0.0,
        }
    }

    fn observe(&mut self, value: f64) {
        for (index, bound) in self.buckets.iter().enumerate() {
            if value <= *bound {
                self.counts[index] = self.counts[index].saturating_add(1);
            }
        }
        self.count = self.count.saturating_add(1);
        self.sum += value;
    }
}

/// A registry of metric families and their label series.
///
/// Cloning a registry is cheap (the state is shared), which is how the admin API hands the same
/// registry to the server runtime for population.
#[derive(Debug, Clone, Default)]
pub struct MetricsRegistry {
    inner: Arc<Mutex<RegistryState>>,
}

impl MetricsRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Register (or look up) a counter series and return a handle to it.
    pub fn counter(
        &self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
    ) -> Result<Counter, MetricsError> {
        let labels = self.ensure_family(name, help, MetricKind::Counter, labels)?;
        Ok(Counter {
            registry: self.clone(),
            name: name.to_string(),
            labels,
        })
    }

    /// Register (or look up) a gauge series and return a handle to it.
    pub fn gauge(
        &self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
    ) -> Result<Gauge, MetricsError> {
        let labels = self.ensure_family(name, help, MetricKind::Gauge, labels)?;
        Ok(Gauge {
            registry: self.clone(),
            name: name.to_string(),
            labels,
        })
    }

    /// Register (or look up) a histogram series and return a handle to it.
    ///
    /// `buckets` must be finite, strictly ascending and non-empty; the `+Inf` bucket is implicit.
    pub fn histogram(
        &self,
        name: &str,
        help: &str,
        buckets: &[f64],
        labels: &[(&str, &str)],
    ) -> Result<Histogram, MetricsError> {
        validate_buckets(name, buckets)?;
        let labels = self.ensure_family(name, help, MetricKind::Histogram, labels)?;
        {
            let mut state = self.lock();
            let family = state
                .families
                .get_mut(name)
                // INFEASIBLE: `ensure_family` just inserted this family.
                .expect("family was just registered");
            match family.series.entry(labels.clone()) {
                std::collections::btree_map::Entry::Occupied(entry) => match entry.get() {
                    Series::Histogram(existing) if existing.buckets == buckets => {}
                    Series::Histogram(_) => {
                        return Err(MetricsError::new(
                            name,
                            "histogram buckets differ from the already registered series",
                        ))
                    }
                    _ => return Err(MetricsError::new(name, "series kind mismatch")),
                },
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Series::Histogram(HistogramState::new(buckets)));
                }
            }
        }
        Ok(Histogram {
            registry: self.clone(),
            name: name.to_string(),
            labels,
        })
    }

    fn ensure_family(
        &self,
        name: &str,
        help: &str,
        kind: MetricKind,
        labels: &[(&str, &str)],
    ) -> Result<Labels, MetricsError> {
        validate_metric_name(name)?;
        let labels = validate_labels(name, labels)?;
        let mut state = self.lock();
        match state.families.get_mut(name) {
            Some(family) => {
                if family.kind != kind {
                    return Err(MetricsError::new(
                        name,
                        format!(
                            "already registered as {}, cannot re-register as {}",
                            family.kind.as_str(),
                            kind.as_str()
                        ),
                    ));
                }
                if family.help != help {
                    return Err(MetricsError::new(
                        name,
                        "registered with different help text",
                    ));
                }
                let series = family.series.entry(labels.clone());
                match (series, kind) {
                    (std::collections::btree_map::Entry::Occupied(_), _) => {}
                    (std::collections::btree_map::Entry::Vacant(entry), MetricKind::Counter) => {
                        entry.insert(Series::Counter(0));
                    }
                    (std::collections::btree_map::Entry::Vacant(entry), MetricKind::Gauge) => {
                        entry.insert(Series::Gauge(0.0));
                    }
                    (std::collections::btree_map::Entry::Vacant(_), MetricKind::Histogram) => {
                        // `histogram()` inserts the series itself (it needs the buckets).
                        return Ok(labels);
                    }
                }
            }
            None => {
                let mut family = Family {
                    help: help.to_string(),
                    kind,
                    series: BTreeMap::new(),
                };
                match kind {
                    MetricKind::Counter => {
                        family.series.insert(labels.clone(), Series::Counter(0));
                    }
                    MetricKind::Gauge => {
                        family.series.insert(labels.clone(), Series::Gauge(0.0));
                    }
                    MetricKind::Histogram => {
                        // Inserted by `histogram()` once buckets are known.
                    }
                }
                state.families.insert(name.to_string(), family);
            }
        }
        Ok(labels)
    }

    /// Render every family in Prometheus text format (deterministic order).
    pub fn render(&self) -> String {
        let state = self.lock();
        let mut output = String::new();
        for (name, family) in &state.families {
            output.push_str("# HELP ");
            output.push_str(name);
            output.push(' ');
            escape_help(&family.help, &mut output);
            output.push('\n');
            output.push_str("# TYPE ");
            output.push_str(name);
            output.push(' ');
            output.push_str(family.kind.as_str());
            output.push('\n');
            for (labels, series) in &family.series {
                match series {
                    Series::Counter(value) => {
                        write_sample(&mut output, name, labels, &value.to_string());
                    }
                    Series::Gauge(value) => {
                        write_sample(&mut output, name, labels, &format_float(*value));
                    }
                    Series::Histogram(histogram) => {
                        for (index, bound) in histogram.buckets.iter().enumerate() {
                            let mut bucket_labels = labels.clone();
                            bucket_labels.insert("le".to_string(), format_float(*bound));
                            write_sample(
                                &mut output,
                                &format!("{name}_bucket"),
                                &bucket_labels,
                                &histogram.counts[index].to_string(),
                            );
                        }
                        let mut infinite = labels.clone();
                        infinite.insert("le".to_string(), "+Inf".to_string());
                        write_sample(
                            &mut output,
                            &format!("{name}_bucket"),
                            &infinite,
                            &histogram.count.to_string(),
                        );
                        write_sample(
                            &mut output,
                            &format!("{name}_sum"),
                            labels,
                            &format_float(histogram.sum),
                        );
                        write_sample(
                            &mut output,
                            &format!("{name}_count"),
                            labels,
                            &histogram.count.to_string(),
                        );
                    }
                }
            }
        }
        output
    }

    /// Whether the registry has no families.
    pub fn is_empty(&self) -> bool {
        self.lock().families.is_empty()
    }

    /// Number of registered metric families.
    pub fn family_count(&self) -> usize {
        self.lock().families.len()
    }
}

/// A handle to one counter series.
#[derive(Debug, Clone)]
pub struct Counter {
    registry: MetricsRegistry,
    name: String,
    labels: Labels,
}

impl Counter {
    /// Increment the counter by one.
    pub fn inc(&self) -> Result<(), MetricsError> {
        self.add(1)
    }

    /// Increment the counter, saturating at `u64::MAX`.
    pub fn add(&self, value: u64) -> Result<(), MetricsError> {
        let mut state = self.registry.lock();
        match series_mut(&mut state, &self.name, &self.labels) {
            Some(Series::Counter(counter)) => {
                *counter = counter.saturating_add(value);
                Ok(())
            }
            _ => Err(MetricsError::new(
                &self.name,
                "counter series is not registered as a counter",
            )),
        }
    }

    /// Metric name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A handle to one gauge series.
#[derive(Debug, Clone)]
pub struct Gauge {
    registry: MetricsRegistry,
    name: String,
    labels: Labels,
}

impl Gauge {
    /// Set the gauge to an absolute value.
    pub fn set(&self, value: f64) -> Result<(), MetricsError> {
        self.update(|current| *current = value)
    }

    /// Add to the gauge (the value may be negative).
    pub fn add(&self, value: f64) -> Result<(), MetricsError> {
        self.update(|current| *current += value)
    }

    /// Increment the gauge by one.
    pub fn inc(&self) -> Result<(), MetricsError> {
        self.add(1.0)
    }

    /// Decrement the gauge by one.
    pub fn dec(&self) -> Result<(), MetricsError> {
        self.add(-1.0)
    }

    /// Read the current value.
    pub fn get(&self) -> Result<f64, MetricsError> {
        let state = self.registry.lock();
        match series(&state, &self.name, &self.labels) {
            Some(Series::Gauge(value)) => Ok(*value),
            _ => Err(MetricsError::new(
                &self.name,
                "gauge series is not registered as a gauge",
            )),
        }
    }

    fn update(&self, update: impl FnOnce(&mut f64)) -> Result<(), MetricsError> {
        let mut state = self.registry.lock();
        match series_mut(&mut state, &self.name, &self.labels) {
            Some(Series::Gauge(current)) => {
                update(current);
                Ok(())
            }
            _ => Err(MetricsError::new(
                &self.name,
                "gauge series is not registered as a gauge",
            )),
        }
    }

    /// Metric name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A handle to one histogram series.
#[derive(Debug, Clone)]
pub struct Histogram {
    registry: MetricsRegistry,
    name: String,
    labels: Labels,
}

impl Histogram {
    /// Record one observation. Non-finite values are rejected.
    pub fn observe(&self, value: f64) -> Result<(), MetricsError> {
        if !value.is_finite() {
            return Err(MetricsError::new(
                &self.name,
                "histogram observations must be finite",
            ));
        }
        let mut state = self.registry.lock();
        match series_mut(&mut state, &self.name, &self.labels) {
            Some(Series::Histogram(histogram)) => {
                histogram.observe(value);
                Ok(())
            }
            _ => Err(MetricsError::new(
                &self.name,
                "histogram series is not registered as a histogram",
            )),
        }
    }

    /// Metric name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

fn series<'a>(state: &'a RegistryState, name: &str, labels: &Labels) -> Option<&'a Series> {
    state
        .families
        .get(name)
        .and_then(|family| family.series.get(labels))
}

fn series_mut<'a>(
    state: &'a mut RegistryState,
    name: &str,
    labels: &Labels,
) -> Option<&'a mut Series> {
    state
        .families
        .get_mut(name)
        .and_then(|family| family.series.get_mut(labels))
}

fn validate_metric_name(name: &str) -> Result<(), MetricsError> {
    if name.is_empty() {
        return Err(MetricsError::new("(empty)", "metric name is empty"));
    }
    let mut characters = name.chars();
    // INFEASIBLE: emptiness was rejected just above.
    let first = characters.next().expect("name is not empty");
    if !(first.is_ascii_alphabetic() || first == '_' || first == ':') {
        return Err(MetricsError::new(
            name,
            "metric name must start with a letter, `_` or `:`",
        ));
    }
    if let Some(invalid) = characters.find(|character| {
        !(character.is_ascii_alphanumeric() || *character == '_' || *character == ':')
    }) {
        return Err(MetricsError::new(
            name,
            format!("metric name contains the invalid character {invalid:?}"),
        ));
    }
    Ok(())
}

fn validate_labels(name: &str, labels: &[(&str, &str)]) -> Result<Labels, MetricsError> {
    let mut set = Labels::new();
    for (label, value) in labels {
        if label.is_empty() {
            return Err(MetricsError::new(name, "label name is empty"));
        }
        if label.starts_with("__") {
            return Err(MetricsError::new(
                name,
                format!("label name `{label}` uses the reserved `__` prefix"),
            ));
        }
        let mut characters = label.chars();
        // INFEASIBLE: emptiness was rejected just above.
        let first = characters.next().expect("label is not empty");
        if !(first.is_ascii_alphabetic() || first == '_') {
            return Err(MetricsError::new(
                name,
                format!("label name `{label}` must start with a letter or `_`"),
            ));
        }
        if let Some(invalid) =
            characters.find(|character| !(character.is_ascii_alphanumeric() || *character == '_'))
        {
            return Err(MetricsError::new(
                name,
                format!("label name `{label}` contains the invalid character {invalid:?}"),
            ));
        }
        if set.insert(label.to_string(), value.to_string()).is_some() {
            return Err(MetricsError::new(
                name,
                format!("label `{label}` is specified more than once"),
            ));
        }
    }
    Ok(set)
}

fn validate_buckets(name: &str, buckets: &[f64]) -> Result<(), MetricsError> {
    if buckets.is_empty() {
        return Err(MetricsError::new(
            name,
            "histogram needs at least one bucket",
        ));
    }
    let mut previous = f64::NEG_INFINITY;
    for bound in buckets {
        if !bound.is_finite() {
            return Err(MetricsError::new(
                name,
                "histogram bucket bounds must be finite",
            ));
        }
        if *bound <= previous {
            return Err(MetricsError::new(
                name,
                "histogram bucket bounds must be strictly ascending",
            ));
        }
        previous = *bound;
    }
    Ok(())
}

fn write_sample(output: &mut String, name: &str, labels: &Labels, value: &str) {
    output.push_str(name);
    if !labels.is_empty() {
        output.push('{');
        // Prometheus/Go `expfmt` renders variable labels in sorted order and appends the histogram
        // `le` label last (it is part of the bucket's series identity, not a variable label). Match
        // that so a scrape is byte-compatible with Caddy's exposition.
        let mut first = true;
        for (label, label_value) in labels.iter().filter(|(label, _)| *label != "le") {
            if !first {
                output.push(',');
            }
            first = false;
            output.push_str(label);
            output.push_str("=\"");
            escape_label_value(label_value, output);
            output.push('"');
        }
        if let Some(label_value) = labels.get("le") {
            if !first {
                output.push(',');
            }
            output.push_str("le=\"");
            escape_label_value(label_value, output);
            output.push('"');
        }
        output.push('}');
    }
    output.push(' ');
    output.push_str(value);
    output.push('\n');
}

fn escape_help(help: &str, output: &mut String) {
    for character in help.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            other => output.push(other),
        }
    }
}

fn escape_label_value(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            other => output.push(other),
        }
    }
}

/// Format a float the way Go's `strconv.FormatFloat(value, 'g', -1, 64)` does, which is what
/// Prometheus' Go exposition writer uses for sample values and bucket bounds (`±Inf`/`NaN` use the
/// Prometheus spellings). Matching Go matters for byte-compatible scrapes: Go switches to
/// exponent form when the decimal exponent is below `-4` or at least `6` (e.g. `1048576` is
/// rendered `1.048576e+06`), and pads the exponent to two digits (`1e+06`, `8.6e-05`).
pub fn format_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value == f64::INFINITY {
        return "+Inf".to_string();
    }
    if value == f64::NEG_INFINITY {
        return "-Inf".to_string();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0".to_string()
        } else {
            "0".to_string()
        };
    }

    let negative = value.is_sign_negative();
    let magnitude = value.abs();
    // Rust's `LowerExp` yields the shortest round-trip digits, the same digit sequence Go's
    // shortest-mode formatting produces; only the exponent/decimal presentation differs.
    let scientific = format!("{magnitude:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        // INFEASIBLE: Rust's `LowerExp` always emits `e<exponent>`.
        .expect("LowerExp always contains an exponent");
    // INFEASIBLE: `LowerExp` exponents are decimal integers.
    let exponent: i32 = exponent.parse().expect("LowerExp exponent is an integer");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits_len = digits.len() as i32;

    // Go's shortest `%g` uses an effective precision of 6: exponent form for exp < -4 || exp >= 6,
    // where exp is the `d.ddd` exponent.
    let use_exponent = exponent < -4 || exponent >= 6;
    let mut output = String::new();
    if negative {
        output.push('-');
    }
    if use_exponent {
        output.push_str(&digits[..1]);
        if digits_len > 1 {
            output.push('.');
            output.push_str(&digits[1..]);
        }
        output.push('e');
        output.push(if exponent < 0 { '-' } else { '+' });
        let absolute = exponent.unsigned_abs();
        if absolute < 10 {
            output.push('0');
        }
        output.push_str(&absolute.to_string());
    } else if exponent >= 0 {
        let integer_digits = (exponent + 1) as usize;
        if digits_len as usize > integer_digits {
            output.push_str(&digits[..integer_digits]);
            output.push('.');
            output.push_str(&digits[integer_digits..]);
        } else {
            output.push_str(&digits);
            for _ in 0..(integer_digits - digits_len as usize) {
                output.push('0');
            }
        }
    } else {
        output.push_str("0.");
        for _ in 0..(-exponent - 1) {
            output.push('0');
        }
        output.push_str(&digits);
    }
    output
}

/// Sanitize an HTTP method for use as a metric label, matching Caddy's
/// `internal/metrics.SanitizeMethod`: known methods are uppercase, everything else is `OTHER`.
pub fn sanitize_method(method: &str) -> String {
    const KNOWN: &[&str] = &[
        "GET", "HEAD", "PUT", "POST", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    ];
    let uppercase = method.to_ascii_uppercase();
    if KNOWN.contains(&uppercase.as_str()) {
        uppercase
    } else {
        "OTHER".to_string()
    }
}

/// Sanitize an HTTP status code for use as a metric label, matching Caddy's
/// `internal/metrics.SanitizeCode` (an unset status is reported as `200`).
pub fn sanitize_status_code(status: u16) -> String {
    match status {
        0 => "200".to_string(),
        other => other.to_string(),
    }
}

/// One completed HTTP request observed by [`HttpMetrics`].
#[derive(Debug, Clone, Copy)]
pub struct RequestObservation<'a> {
    /// Server name (`apps.http.servers.<name>`).
    pub server: &'a str,
    /// Handler/route name; `""` when the request did not match one.
    pub handler: &'a str,
    /// Request method (sanitized before use as a label).
    pub method: &'a str,
    /// Response status (0 when no response was written; reported as 200, matching Caddy).
    pub status: u16,
    /// Total request duration.
    pub duration: Duration,
    /// Approximate request size in bytes.
    pub request_size: u64,
    /// Response body size in bytes.
    pub response_size: u64,
    /// Time to first response byte; use [`RequestObservation::duration`] when unknown.
    pub response_duration: Duration,
    /// Whether the request resulted in a middleware error.
    pub error: bool,
}

impl<'a> RequestObservation<'a> {
    /// A minimal observation with sizes and response duration defaulted from `duration`.
    pub fn new(
        server: &'a str,
        handler: &'a str,
        method: &'a str,
        status: u16,
        duration: Duration,
    ) -> Self {
        Self {
            server,
            handler,
            method,
            status,
            duration,
            request_size: 0,
            response_size: 0,
            response_duration: duration,
            error: false,
        }
    }
}

/// One completed proxy upstream request observed by [`HttpMetrics`].
#[derive(Debug, Clone, Copy)]
pub struct ProxyObservation<'a> {
    /// Upstream dial address (bounded by configuration, unlike a peer IP).
    pub upstream: &'a str,
    /// Request method (sanitized before use as a label).
    pub method: &'a str,
    /// Upstream response status (0 when the transport failed).
    pub status: u16,
    /// Time spent on the upstream request.
    pub duration: Duration,
    /// Whether the upstream exchange succeeded (transport + retry policy).
    pub success: bool,
}

/// Caddy's bounded `host` label policy (`per_host`).
///
/// Mirrors `Metrics.shouldAllowHostMetrics` (`modules/caddyhttp/metrics.go:270-285`): a request host
/// is individually labelled when it names an explicitly configured host matcher, when
/// `observe_catchall_hosts` is set, or when it arrives over HTTPS and the configuration has at
/// least one server with TLS connection policies. Everything else is labelled
/// [`CATCHALL_HOST_LABEL`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostLabelPolicy {
    allowed_hosts: BTreeSet<String>,
    has_https_server: bool,
    observe_catchall_hosts: bool,
}

impl HostLabelPolicy {
    /// Build a policy from Caddy's scanned state (`scanConfigForHosts`, metrics.go:232-263).
    ///
    /// `allowed_hosts` are the non-fuzzy matcher hosts already lowercased by the scanner;
    /// `has_https_server` is true when any server has a non-empty `tls_connection_policies` list.
    pub fn new(
        allowed_hosts: impl IntoIterator<Item = impl Into<String>>,
        has_https_server: bool,
        observe_catchall_hosts: bool,
    ) -> Self {
        Self {
            allowed_hosts: allowed_hosts.into_iter().map(Into::into).collect(),
            has_https_server,
            observe_catchall_hosts,
        }
    }

    /// The explicitly allowed (non-fuzzy, lowercased) host matcher values.
    pub fn allowed_hosts(&self) -> &BTreeSet<String> {
        &self.allowed_hosts
    }

    /// Whether any server has TLS connection policies (Caddy's `hasHTTPSServer`).
    pub fn has_https_server(&self) -> bool {
        self.has_https_server
    }

    /// Whether catch-all hosts get their own label (`observe_catchall_hosts`).
    pub fn observe_catchall_hosts(&self) -> bool {
        self.observe_catchall_hosts
    }

    /// Whether `host` keeps its own label instead of aggregating under `_other`.
    ///
    /// `is_https` is Caddy's `r.TLS != nil` test.
    pub fn should_label(&self, host: &str, is_https: bool) -> bool {
        if self.allowed_hosts.contains(&host.to_lowercase()) {
            return true;
        }
        self.observe_catchall_hosts || (is_https && self.has_https_server)
    }

    /// The `host` label value: the lowercased request host, or `_other` when it is not allowed.
    pub fn label_for(&self, host: &str, is_https: bool) -> String {
        if self.should_label(host, is_https) {
            host.to_lowercase()
        } else {
            CATCHALL_HOST_LABEL.to_string()
        }
    }
}

/// Caddy's `apps.http.metrics` runtime gate and per-host policy.
///
/// Caddy registers and records the `caddy_http_*` families only when the object is present
/// (`modules/caddyhttp/app.go:216-222`); [`Disabled`](Self::Disabled) reproduces the absent case as
/// a no-op. [`Enabled`](Self::Enabled) records the families and adds the `host` label only when a
/// [`HostLabelPolicy`] is supplied (`per_host: true`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum HttpMetricsPolicy {
    /// `apps.http.metrics` absent: every `caddy_http_*` recording method is a no-op.
    #[default]
    Disabled,
    /// `apps.http.metrics` present; `per_host` is `Some` only when host labels are configured.
    Enabled {
        /// Host-label cardinality policy, `None` when `per_host` is off (Caddy's default).
        per_host: Option<HostLabelPolicy>,
    },
}

impl HttpMetricsPolicy {
    /// The policy for a present `apps.http.metrics` object without `per_host`.
    pub fn enabled() -> Self {
        Self::Enabled { per_host: None }
    }

    /// The policy for a present `apps.http.metrics` object with `per_host`.
    pub fn with_per_host(policy: HostLabelPolicy) -> Self {
        Self::Enabled {
            per_host: Some(policy),
        }
    }

    /// Whether the `caddy_http_*` families are recorded at all.
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }

    /// The per-host policy, or `None` when `per_host` is off (or metrics are disabled).
    pub fn per_host(&self) -> Option<&HostLabelPolicy> {
        match self {
            Self::Enabled { per_host } => per_host.as_ref(),
            Self::Disabled => None,
        }
    }
}

/// Typed Caddy HTTP metrics, plus caddy-rs proxy and certificate extensions.
///
/// The typed layer owns no state: it borrows a [`MetricsRegistry`], so the admin API can render
/// exactly the series the server records. `caddy_http_*` recording obeys [`HttpMetricsPolicy`];
/// the caddy-rs proxy/certificate extensions are always recorded.
#[derive(Debug, Clone)]
pub struct HttpMetrics {
    registry: MetricsRegistry,
    policy: HttpMetricsPolicy,
}

impl HttpMetrics {
    /// Instrument a registry with the historical always-on policy (no `host` label).
    ///
    /// Configuration-driven runtimes should build the handle with
    /// [`crate::metrics_config::http_metrics_for_config`] so an absent `apps.http.metrics` object
    /// leaves the `caddy_http_*` families unregistered.
    pub fn new(registry: MetricsRegistry) -> Self {
        Self {
            registry,
            policy: HttpMetricsPolicy::enabled(),
        }
    }

    /// Instrument a registry with Caddy's opt-in gate, recording no `caddy_http_*` series.
    pub fn disabled(registry: MetricsRegistry) -> Self {
        Self {
            registry,
            policy: HttpMetricsPolicy::Disabled,
        }
    }

    /// Instrument a registry with an explicit policy.
    pub fn with_policy(registry: MetricsRegistry, policy: HttpMetricsPolicy) -> Self {
        Self { registry, policy }
    }

    /// The underlying registry.
    pub fn registry(&self) -> &MetricsRegistry {
        &self.registry
    }

    /// The active gate/per-host policy.
    pub fn policy(&self) -> &HttpMetricsPolicy {
        &self.policy
    }

    /// Whether `caddy_http_*` families are recorded (Caddy's `apps.http.metrics` gate).
    pub fn is_http_recording(&self) -> bool {
        self.policy.is_enabled()
    }

    /// Whether the `host` label is added to `caddy_http_*` series (`per_host`).
    pub fn is_per_host(&self) -> bool {
        self.policy.per_host().is_some()
    }

    fn host_label(&self, host: &str, is_https: bool) -> Option<String> {
        self.policy
            .per_host()
            .map(|policy| policy.label_for(host, is_https))
    }

    fn basic_labels<'a>(
        &self,
        server: &'a str,
        handler: &'a str,
        host_label: Option<&'a str>,
    ) -> Vec<(&'a str, &'a str)> {
        let mut labels = vec![("server", server), ("handler", handler)];
        if let Some(host) = host_label {
            labels.push(("host", host));
        }
        labels
    }

    fn status_labels<'a>(
        &self,
        server: &'a str,
        handler: &'a str,
        code: &'a str,
        method: &'a str,
        host_label: Option<&'a str>,
    ) -> Vec<(&'a str, &'a str)> {
        let mut labels = vec![
            ("server", server),
            ("handler", handler),
            ("code", code),
            ("method", method),
        ];
        if let Some(host) = host_label {
            labels.push(("host", host));
        }
        labels
    }

    /// Mark one request as in flight. The returned guard decrements the gauge when dropped.
    ///
    /// Without a host this records `host="_other"` when `per_host` is enabled; the server seam
    /// should call [`request_started_for_host`](Self::request_started_for_host).
    pub fn request_started(
        &self,
        server: &str,
        handler: &str,
    ) -> Result<InFlightGuard, MetricsError> {
        self.request_started_for_host(server, handler, "", false)
    }

    /// Mark one request as in flight, including the bounded `host` label when `per_host` is on.
    pub fn request_started_for_host(
        &self,
        server: &str,
        handler: &str,
        host: &str,
        is_https: bool,
    ) -> Result<InFlightGuard, MetricsError> {
        if !self.is_http_recording() {
            return Ok(InFlightGuard::noop());
        }
        let host_label = self.host_label(host, is_https);
        let labels = self.basic_labels(server, handler, host_label.as_deref());
        let gauge = self.registry.gauge(
            HTTP_REQUESTS_IN_FLIGHT,
            "Number of requests currently handled by this server.",
            &labels,
        )?;
        gauge.inc()?;
        Ok(InFlightGuard { gauge: Some(gauge) })
    }

    /// Record one completed request: counters, error counter and the latency/size histograms.
    ///
    /// Without a host this records `host="_other"` when `per_host` is enabled; the server seam
    /// should call [`request_finished_for_host`](Self::request_finished_for_host).
    pub fn request_finished(
        &self,
        observation: &RequestObservation<'_>,
    ) -> Result<(), MetricsError> {
        self.request_finished_for_host(observation, "", false)
    }

    /// Record one completed request, including the bounded `host` label when `per_host` is on.
    pub fn request_finished_for_host(
        &self,
        observation: &RequestObservation<'_>,
        host: &str,
        is_https: bool,
    ) -> Result<(), MetricsError> {
        if !self.is_http_recording() {
            return Ok(());
        }
        let code = sanitize_status_code(observation.status);
        let method = sanitize_method(observation.method);
        let host_label = self.host_label(host, is_https);
        let basic = self.basic_labels(
            observation.server,
            observation.handler,
            host_label.as_deref(),
        );
        let status = self.status_labels(
            observation.server,
            observation.handler,
            &code,
            &method,
            host_label.as_deref(),
        );

        self.registry
            .counter(
                HTTP_REQUESTS_TOTAL,
                "Counter of HTTP(S) requests made.",
                &basic,
            )?
            .inc()?;

        if observation.error {
            self.registry
                .counter(
                    HTTP_REQUEST_ERRORS_TOTAL,
                    "Number of requests resulting in middleware errors.",
                    &basic,
                )?
                .inc()?;
        }

        self.registry
            .histogram(
                HTTP_REQUEST_DURATION_SECONDS,
                "Histogram of round-trip request durations.",
                DEFAULT_DURATION_BUCKETS,
                &status,
            )?
            .observe(duration_seconds(observation.duration))?;
        self.registry
            .histogram(
                HTTP_REQUEST_SIZE_BYTES,
                "Total size of the request. Includes body",
                DEFAULT_SIZE_BUCKETS,
                &status,
            )?
            .observe(observation.request_size as f64)?;
        self.registry
            .histogram(
                HTTP_RESPONSE_SIZE_BYTES,
                "Size of the returned response.",
                DEFAULT_SIZE_BUCKETS,
                &status,
            )?
            .observe(observation.response_size as f64)?;
        self.registry
            .histogram(
                HTTP_RESPONSE_DURATION_SECONDS,
                "Histogram of times to first byte in response bodies.",
                DEFAULT_DURATION_BUCKETS,
                &status,
            )?
            .observe(duration_seconds(observation.response_duration))?;

        Ok(())
    }

    /// Mark one proxy upstream request as in flight. The guard decrements the gauge on drop.
    pub fn proxy_request_started(
        &self,
        upstream: &str,
    ) -> Result<ProxyInFlightGuard, MetricsError> {
        let gauge = self.registry.gauge(
            PROXY_ACTIVE_REQUESTS,
            "Number of proxy requests currently in flight per upstream.",
            &[("upstream", upstream)],
        )?;
        gauge.inc()?;
        Ok(ProxyInFlightGuard { gauge })
    }

    /// Record one completed proxy upstream request.
    pub fn proxy_request_finished(
        &self,
        observation: &ProxyObservation<'_>,
    ) -> Result<(), MetricsError> {
        let code = sanitize_status_code(observation.status);
        let method = sanitize_method(observation.method);
        let labels = [
            ("upstream", observation.upstream),
            ("method", method.as_str()),
            ("code", code.as_str()),
        ];

        self.registry
            .counter(
                PROXY_REQUESTS_TOTAL,
                "Counter of reverse proxy requests per upstream.",
                &labels,
            )?
            .inc()?;

        if !observation.success {
            self.registry
                .counter(
                    PROXY_REQUEST_ERRORS_TOTAL,
                    "Counter of reverse proxy upstream errors.",
                    &[("upstream", observation.upstream)],
                )?
                .inc()?;
        }

        self.registry
            .histogram(
                PROXY_REQUEST_DURATION_SECONDS,
                "Histogram of reverse proxy upstream request durations.",
                DEFAULT_DURATION_BUCKETS,
                &labels,
            )?
            .observe(duration_seconds(observation.duration))?;

        Ok(())
    }

    /// Record how many seconds remain until a managed certificate expires.
    pub fn certificate_expiry(
        &self,
        issuer: &str,
        subject: &str,
        seconds_until_expiry: f64,
    ) -> Result<(), MetricsError> {
        self.registry
            .gauge(
                TLS_CERTIFICATE_EXPIRATION_SECONDS,
                "Seconds until a managed certificate expires.",
                &[("issuer", issuer), ("subject", subject)],
            )?
            .set(seconds_until_expiry)
    }

    /// Record one certificate renewal attempt and how long it took.
    pub fn certificate_renewal(
        &self,
        issuer: &str,
        subject: &str,
        success: bool,
        duration: Duration,
    ) -> Result<(), MetricsError> {
        let result = if success { "success" } else { "error" };
        self.registry
            .counter(
                TLS_CERTIFICATE_RENEWAL_TOTAL,
                "Counter of certificate renewal attempts.",
                &[("issuer", issuer), ("subject", subject), ("result", result)],
            )?
            .inc()?;
        self.registry
            .histogram(
                TLS_CERTIFICATE_RENEWAL_DURATION_SECONDS,
                "Histogram of certificate renewal durations.",
                DEFAULT_DURATION_BUCKETS,
                &[("issuer", issuer), ("subject", subject)],
            )?
            .observe(duration_seconds(duration))
    }
}

fn duration_seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

/// Keeps one [`HTTP_REQUESTS_IN_FLIGHT`] series incremented until dropped.
///
/// A guard created while the `apps.http.metrics` gate is off ([`InFlightGuard::noop`]) holds no
/// series and is inert.
#[derive(Debug)]
pub struct InFlightGuard {
    gauge: Option<Gauge>,
}

impl InFlightGuard {
    /// An inert guard that does not touch any metric (the recording gate is off).
    pub fn noop() -> Self {
        Self { gauge: None }
    }

    /// Whether dropping this guard will decrement an in-flight gauge.
    pub fn is_instrumented(&self) -> bool {
        self.gauge.is_some()
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        // A failing decrement would mean the gauge series vanished from the shared registry, which
        // cannot happen while this guard holds a clone. Ignore the result rather than panic in Drop.
        if let Some(gauge) = &self.gauge {
            let _ = gauge.dec();
        }
    }
}

/// Keeps one [`PROXY_ACTIVE_REQUESTS`] series incremented until dropped.
#[derive(Debug)]
pub struct ProxyInFlightGuard {
    gauge: Gauge,
}

impl Drop for ProxyInFlightGuard {
    fn drop(&mut self) {
        let _ = self.gauge.dec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counter_and_gauge_deterministically() {
        let registry = MetricsRegistry::new();
        // Insert out of alphabetical order to prove rendering is sorted.
        registry
            .counter("z_requests_total", "Requests.", &[("b", "2"), ("a", "1")])
            .unwrap()
            .add(3)
            .unwrap();
        registry
            .counter("a_requests_total", "Other requests.", &[])
            .unwrap()
            .inc()
            .unwrap();
        registry
            .gauge("m_gauge", "A gauge.", &[("state", "on")])
            .unwrap()
            .set(1.5)
            .unwrap();

        let expected = "\
# HELP a_requests_total Other requests.
# TYPE a_requests_total counter
a_requests_total 1
# HELP m_gauge A gauge.
# TYPE m_gauge gauge
m_gauge{state=\"on\"} 1.5
# HELP z_requests_total Requests.
# TYPE z_requests_total counter
z_requests_total{a=\"1\",b=\"2\"} 3
";
        assert_eq!(registry.render(), expected);
        assert_eq!(
            registry.render(),
            registry.render(),
            "rendering is repeatable"
        );
    }

    #[test]
    fn gauges_can_go_down_and_carry_special_values() {
        let registry = MetricsRegistry::new();
        let gauge = registry.gauge("g", "Gauge.", &[]).unwrap();
        gauge.set(5.0).unwrap();
        gauge.dec().unwrap();
        gauge.add(-1.5).unwrap();
        assert_eq!(gauge.get().unwrap(), 2.5);
        gauge.set(f64::INFINITY).unwrap();
        let rendered = registry.render();
        assert!(rendered.contains("g +Inf"), "got: {rendered}");
        gauge.set(f64::NEG_INFINITY).unwrap();
        assert!(registry.render().contains("g -Inf"));
        gauge.set(f64::NAN).unwrap();
        assert!(registry.render().contains("g NaN"));
    }

    #[test]
    fn renders_cumulative_histogram_buckets_sum_and_count() {
        let registry = MetricsRegistry::new();
        let histogram = registry
            .histogram(
                "latency_seconds",
                "Latency.",
                &[0.1, 1.0],
                &[("code", "200")],
            )
            .unwrap();
        histogram.observe(0.05).unwrap();
        histogram.observe(0.5).unwrap();
        histogram.observe(2.0).unwrap();

        let expected = "\
# HELP latency_seconds Latency.
# TYPE latency_seconds histogram
latency_seconds_bucket{code=\"200\",le=\"0.1\"} 1
latency_seconds_bucket{code=\"200\",le=\"1\"} 2
latency_seconds_bucket{code=\"200\",le=\"+Inf\"} 3
latency_seconds_sum{code=\"200\"} 2.55
latency_seconds_count{code=\"200\"} 3
";
        assert_eq!(registry.render(), expected);
    }

    #[test]
    fn histogram_renders_le_last_with_caddy_labels() {
        let registry = MetricsRegistry::new();
        let histogram = registry
            .histogram(
                "caddy_http_request_duration_seconds",
                "Histogram of round-trip request durations.",
                &[0.005, 1048576.0],
                &[
                    ("server", "srv0"),
                    ("handler", "static_response"),
                    ("code", "200"),
                    ("method", "GET"),
                ],
            )
            .unwrap();
        histogram.observe(0.25).unwrap();
        let rendered = registry.render();
        let expected_bucket = "caddy_http_request_duration_seconds_bucket{code=\"200\",handler=\"static_response\",method=\"GET\",server=\"srv0\",le=\"0.005\"} 0";
        let expected_large = "caddy_http_request_duration_seconds_bucket{code=\"200\",handler=\"static_response\",method=\"GET\",server=\"srv0\",le=\"1.048576e+06\"} 1";
        assert!(rendered.contains(expected_bucket), "got: {rendered}");
        assert!(rendered.contains(expected_large), "got: {rendered}");
        assert_prometheus_text_parses(&rendered);
    }

    #[test]
    fn escapes_help_and_label_values() {
        let registry = MetricsRegistry::new();
        registry
            .counter(
                "escaped_total",
                "line one\nline \"two\" \\ end",
                &[("path", "a\"b\\c\nd")],
            )
            .unwrap()
            .inc()
            .unwrap();
        let rendered = registry.render();
        assert!(
            rendered.contains("# HELP escaped_total line one\\nline \"two\" \\\\ end"),
            "got: {rendered}"
        );
        assert!(
            rendered.contains("escaped_total{path=\"a\\\"b\\\\c\\nd\"} 1"),
            "got: {rendered}"
        );
    }

    #[test]
    fn rejects_invalid_metric_and_label_definitions() {
        let registry = MetricsRegistry::new();
        assert_eq!(
            registry.counter("", "help", &[]).unwrap_err().path(),
            "(empty)"
        );
        assert!(registry.counter("1bad", "help", &[]).is_err());
        assert!(registry.counter("bad-name", "help", &[]).is_err());
        assert!(registry
            .counter("ok_total", "help", &[("bad-label", "v")])
            .is_err());
        assert!(registry
            .counter("ok_total", "help", &[("__reserved", "v")])
            .is_err());
        assert!(registry
            .counter("ok_total", "help", &[("a", "1"), ("a", "2")])
            .is_err());
        // Same family with a different kind or help is a programming error, detected loudly.
        registry.counter("kind_total", "help", &[]).unwrap();
        assert!(registry.gauge("kind_total", "help", &[]).is_err());
        assert!(registry
            .counter("kind_total", "different help", &[])
            .is_err());
        assert!(registry.histogram("h", "help", &[1.0, 1.0], &[]).is_err());
        assert!(registry.histogram("h", "help", &[], &[]).is_err());
        assert!(registry
            .histogram("h", "help", &[f64::INFINITY], &[])
            .is_err());
    }

    #[test]
    fn histogram_observations_must_be_finite_and_buckets_stable() {
        let registry = MetricsRegistry::new();
        let histogram = registry
            .histogram("h_seconds", "help", &[1.0], &[])
            .unwrap();
        assert!(histogram.observe(f64::NAN).is_err());
        assert!(histogram.observe(f64::INFINITY).is_err());
        // Re-registering the same series is fine; changing buckets is not.
        registry
            .histogram("h_seconds", "help", &[1.0], &[])
            .unwrap();
        assert!(registry
            .histogram("h_seconds", "help", &[2.0], &[])
            .is_err());
    }

    #[test]
    fn shared_registry_is_thread_safe() {
        let registry = MetricsRegistry::new();
        let counter = registry.counter("concurrent_total", "help", &[]).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let counter = counter.clone();
                scope.spawn(move || {
                    for _ in 0..1000 {
                        counter.inc().unwrap();
                    }
                });
            }
        });
        assert!(registry.render().contains("concurrent_total 4000"));
    }

    #[test]
    fn sanitizers_match_caddy() {
        assert_eq!(sanitize_method("get"), "GET");
        assert_eq!(sanitize_method("PROPFIND"), "OTHER");
        assert_eq!(sanitize_status_code(0), "200");
        assert_eq!(sanitize_status_code(200), "200");
        assert_eq!(sanitize_status_code(404), "404");
        assert_eq!(format_float(0.005), "0.005");
        assert_eq!(format_float(1.0), "1");
        assert_eq!(format_float(f64::INFINITY), "+Inf");
        assert_eq!(format_float(f64::NAN), "NaN");
        // Go `strconv.FormatFloat(v, 'g', -1, 64)`: exponent form for exp < -4 || exp >= 6, with a
        // two-digit-minimum signed exponent; shortest round-trip digits otherwise.
        assert_eq!(format_float(256.0), "256");
        assert_eq!(format_float(65536.0), "65536");
        assert_eq!(format_float(262144.0), "262144");
        assert_eq!(format_float(1048576.0), "1.048576e+06");
        assert_eq!(format_float(4194304.0), "4.194304e+06");
        assert_eq!(format_float(1000000.0), "1e+06");
        assert_eq!(format_float(0.0001), "0.0001");
        assert_eq!(format_float(0.00001), "1e-05");
        assert_eq!(format_float(0.007756129), "0.007756129");
        assert_eq!(format_float(-2.5), "-2.5");
        assert_eq!(format_float(123456.0), "123456");
    }

    /// Minimal Prometheus text-format parser: every non-comment line must be
    /// `name[{labels}] value`, labels must be sorted and quoted, and values must be floats.
    fn assert_prometheus_text_parses(text: &str) {
        let mut seen_families: Vec<String> = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("# HELP ") {
                let name = rest.split(' ').next().unwrap_or("");
                assert!(!name.is_empty(), "HELP line without name: {line}");
                seen_families.push(name.to_string());
                continue;
            }
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let mut parts = rest.split(' ');
                let name = parts.next().unwrap_or("");
                let kind = parts.next().unwrap_or("");
                assert!(!name.is_empty(), "TYPE line without name: {line}");
                assert!(
                    matches!(kind, "counter" | "gauge" | "histogram"),
                    "unknown TYPE {kind:?} in {line}"
                );
                continue;
            }
            let (series, value) = line
                .rsplit_once(' ')
                .unwrap_or_else(|| panic!("sample line without value: {line}"));
            assert!(
                value.parse::<f64>().is_ok() || matches!(value, "+Inf" | "-Inf" | "NaN"),
                "sample value is not a float: {line}"
            );
            if let Some((_, label_part)) = series.split_once('{') {
                let label_part = label_part
                    .strip_suffix('}')
                    .unwrap_or_else(|| panic!("unterminated labels: {line}"));
                let mut names = Vec::new();
                for pair in split_labels(label_part) {
                    let (name, raw_value) = pair
                        .split_once('=')
                        .unwrap_or_else(|| panic!("label without value: {line}"));
                    assert!(!name.is_empty(), "empty label name: {line}");
                    assert!(
                        raw_value.starts_with('"') && raw_value.ends_with('"'),
                        "label value is not quoted: {line}"
                    );
                    names.push(name.to_string());
                }
                // Go `expfmt` sorts variable labels but appends the histogram `le` label last.
                let mut expected = names.clone();
                if let Some(position) = expected.iter().position(|name| name == "le") {
                    let le = expected.remove(position);
                    expected.sort();
                    expected.push(le);
                } else {
                    expected.sort();
                }
                assert_eq!(names, expected, "labels are not in expfmt order: {line}");
            }
        }
        assert!(
            !seen_families.is_empty() || text.is_empty(),
            "no families were rendered"
        );
    }

    fn split_labels(value: &str) -> Vec<&str> {
        let mut parts = Vec::new();
        let mut start = 0;
        let mut in_quotes = false;
        let bytes = value.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'\\' if in_quotes => index += 1,
                b'"' => in_quotes = !in_quotes,
                b',' if !in_quotes => {
                    parts.push(&value[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
            index += 1;
        }
        if start < value.len() {
            parts.push(&value[start..]);
        }
        parts
    }

    #[test]
    fn typed_layer_emits_caddy_series_that_parse() {
        let registry = MetricsRegistry::new();
        let metrics = HttpMetrics::new(registry.clone());

        let guard = metrics.request_started("srv0", "route0").unwrap();
        assert!(registry
            .render()
            .contains("caddy_http_requests_in_flight{handler=\"route0\",server=\"srv0\"} 1"));
        drop(guard);
        assert!(registry
            .render()
            .contains("caddy_http_requests_in_flight{handler=\"route0\",server=\"srv0\"} 0"));

        metrics
            .request_finished(&RequestObservation {
                server: "srv0",
                handler: "route0",
                method: "get",
                status: 204,
                duration: Duration::from_millis(50),
                request_size: 300,
                response_size: 700,
                response_duration: Duration::from_millis(10),
                error: false,
            })
            .unwrap();
        metrics
            .request_finished(&RequestObservation {
                error: true,
                status: 502,
                ..RequestObservation::new("srv0", "route0", "PROPFIND", 502, Duration::from_secs(1))
            })
            .unwrap();

        let rendered = registry.render();
        assert_prometheus_text_parses(&rendered);
        assert!(
            rendered.contains("caddy_http_requests_total{handler=\"route0\",server=\"srv0\"} 2")
        );
        assert!(rendered
            .contains("caddy_http_request_errors_total{handler=\"route0\",server=\"srv0\"} 1"));
        assert!(rendered.contains(
            "caddy_http_request_duration_seconds_count{code=\"204\",handler=\"route0\",method=\"GET\",server=\"srv0\"} 1"
        ));
        assert!(rendered.contains(
            "caddy_http_request_duration_seconds_count{code=\"502\",handler=\"route0\",method=\"OTHER\",server=\"srv0\"} 1"
        ));
        assert!(rendered.contains(
            "caddy_http_request_size_bytes_sum{code=\"204\",handler=\"route0\",method=\"GET\",server=\"srv0\"} 300"
        ));
        assert!(rendered.contains(
            "caddy_http_response_size_bytes_sum{code=\"204\",handler=\"route0\",method=\"GET\",server=\"srv0\"} 700"
        ));
        // No high-cardinality labels (host/uri/peer/user) in any series.
        for forbidden in [
            "host=",
            "uri=",
            "remote_ip=",
            "client_ip=",
            "user_id=",
            "path=",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "unexpected high-cardinality label {forbidden} in:\n{rendered}"
            );
        }
        assert_prometheus_text_parses(&rendered);
    }

    #[test]
    fn typed_proxy_and_certificate_series_parse() {
        let registry = MetricsRegistry::new();
        let metrics = HttpMetrics::new(registry.clone());

        let guard = metrics.proxy_request_started("10.0.0.5:8080").unwrap();
        assert!(registry
            .render()
            .contains("caddy_rs_proxy_active_requests{upstream=\"10.0.0.5:8080\"} 1"));
        drop(guard);
        assert!(registry
            .render()
            .contains("caddy_rs_proxy_active_requests{upstream=\"10.0.0.5:8080\"} 0"));

        metrics
            .proxy_request_finished(&ProxyObservation {
                upstream: "10.0.0.5:8080",
                method: "GET",
                status: 200,
                duration: Duration::from_millis(25),
                success: true,
            })
            .unwrap();
        metrics
            .proxy_request_finished(&ProxyObservation {
                upstream: "10.0.0.5:8080",
                method: "GET",
                status: 502,
                duration: Duration::from_millis(5),
                success: false,
            })
            .unwrap();
        metrics
            .certificate_expiry("acme", "example.com", 86_400.0)
            .unwrap();
        metrics
            .certificate_renewal("acme", "example.com", true, Duration::from_secs(2))
            .unwrap();
        metrics
            .certificate_renewal("acme", "example.com", false, Duration::from_secs(3))
            .unwrap();

        let rendered = registry.render();
        assert_prometheus_text_parses(&rendered);
        assert!(rendered.contains(
            "caddy_rs_proxy_requests_total{code=\"200\",method=\"GET\",upstream=\"10.0.0.5:8080\"} 1"
        ));
        assert!(rendered.contains(
            "caddy_rs_proxy_requests_total{code=\"502\",method=\"GET\",upstream=\"10.0.0.5:8080\"} 1"
        ));
        assert!(
            rendered.contains("caddy_rs_proxy_request_errors_total{upstream=\"10.0.0.5:8080\"} 1")
        );
        assert!(rendered.contains(
            "caddy_rs_tls_certificate_expiration_seconds{issuer=\"acme\",subject=\"example.com\"} 86400"
        ));
        assert!(rendered.contains(
            "caddy_rs_tls_certificate_renewal_total{issuer=\"acme\",result=\"success\",subject=\"example.com\"} 1"
        ));
        assert!(rendered.contains(
            "caddy_rs_tls_certificate_renewal_total{issuer=\"acme\",result=\"error\",subject=\"example.com\"} 1"
        ));
    }

    #[test]
    fn empty_registry_renders_nothing() {
        let registry = MetricsRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.render(), "");
    }
}
