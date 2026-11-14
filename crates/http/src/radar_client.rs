//! Cloudflare Radar client: DDoS/BGP/anomaly polling, TTL cache, persistent storage, auto mode.
//!
//! Radar is an *advisory* signal: the entries it produces feed the radar matchers and are never
//! allowed to make protection fail closed. A poll that fails keeps serving the last cached data
//! (counted as `radar_stale_serves_total`) and the process keeps running with whatever it has.
//!
//! # Configuration
//!
//! [`RadarConfig`] is built from JSON (see [`RadarConfig::from_json`]) or from the defaults:
//!
//! ```text
//! mode          auto | on | off                       (default auto)
//! interval      seconds or "60s"/"2m"                 (default 60s, clamped to >= 30s)
//! cache_ttl     seconds or "120s"                     (default 120s)
//! api_token     optional bearer token
//! base_url      default https://api.cloudflare.com/client/v4/radar
//! filters       { min_magnitude, countries, asns }
//! storage       "file{path=...}" | "redis{url=...,prefix=...}" | "memory"  (default file)
//! ```
//!
//! `interval` is **clamped** to [`MIN_POLL_INTERVAL`] (30 s) rather than rejected: a too-small
//! value is an operator mistake with an obvious safe correction, and refusing to start protection
//! over it would be worse than polling at the minimum rate. The clamp is applied in
//! [`RadarClient::new`] and is visible through [`RadarClient::config`]. Every other malformed
//! field is a located error ([`RadarConfigError`] names the field).
//!
//! # Modes
//!
//! * `auto` (default): no polling, no storage reads and no Cloudflare request at startup; the log
//!   line is exactly `radar: mode=auto (waiting for Internet-routable client IP)`. The first
//!   *Internet-routable* client IP reported through [`RadarClient::on_client_ip`] enables radar:
//!   it logs `radar: enabling (Internet-routable IP detected: X.X.X.X, ASN NNNNN)` (the ASN suffix
//!   is omitted when unknown), loads the persisted cache, starts the polling task and increments
//!   `radar_auto_enables_total`. Later IPs are ignored, so the gate is idempotent.
//! * `on`: logs `radar: mode=on (polling started)`, loads the persisted cache and polls
//!   immediately.
//! * `off`: no polling, no cache, no storage reads, no log line.
//!
//! Routability is a pure function ([`is_internet_routable`]) so it is testable without sockets; it
//! excludes RFC 1918, loopback, link-local, unique-local, unspecified and multicast addresses.
//!
//! # Cache
//!
//! The cache is a map keyed by endpoint (`ddos/l7`, `ddos/l34`, `bgp/hijacks`,
//! `traffic/anomalies`). An endpoint is refreshed by [`RadarClient::poll_once`] only when its
//! cached copy is older than `cache_ttl`; a failed refresh leaves the previous copy in place. After
//! a successful poll every refreshed endpoint is persisted through [`RadarStorage`].
//!
//! # Transport seam
//!
//! [`RadarTransport`] is the only network seam. [`HyperRadarTransport`] is the production
//! implementation (hyper HTTP/1 over plain TCP for `http://`, hyper over
//! [`tokio_rustls`] with platform-verifier roots for `https://`); tests substitute a stub, so no
//! test requires Internet access.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use http::{header, Method, Request, Uri};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::radar_store::{RadarStorage, StorageError, StorageSpec};

/// Default Radar API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4/radar";

/// Default poll interval.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Smallest accepted poll interval. Smaller configured values are clamped up to this.
pub const MIN_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Default cache TTL.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(120);

/// Per-request HTTP timeout for [`HyperRadarTransport`].
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The four Radar endpoints the client polls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RadarEndpoint {
    /// `GET /ddos/l7` — layer-7 DDoS activity.
    DdosL7,
    /// `GET /ddos/l34` — layer-3/4 DDoS activity.
    DdosL34,
    /// `GET /bgp/hijacks` — BGP hijack events.
    BgpHijacks,
    /// `GET /traffic/anomalies` — traffic anomalies.
    TrafficAnomalies,
}

impl RadarEndpoint {
    /// Every endpoint, in poll order.
    pub const ALL: [RadarEndpoint; 4] = [
        Self::DdosL7,
        Self::DdosL34,
        Self::BgpHijacks,
        Self::TrafficAnomalies,
    ];

    /// Path below the configured base URL.
    pub fn path(self) -> &'static str {
        match self {
            Self::DdosL7 => "/ddos/l7",
            Self::DdosL34 => "/ddos/l34",
            Self::BgpHijacks => "/bgp/hijacks",
            Self::TrafficAnomalies => "/traffic/anomalies",
        }
    }

    /// Cache key (also the storage key), without the leading slash.
    pub fn cache_key(self) -> &'static str {
        match self {
            Self::DdosL7 => "ddos/l7",
            Self::DdosL34 => "ddos/l34",
            Self::BgpHijacks => "bgp/hijacks",
            Self::TrafficAnomalies => "traffic/anomalies",
        }
    }
}

impl fmt::Display for RadarEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.path())
    }
}

/// One parsed Radar record.
///
/// Every field except [`Self::endpoint`] is optional: Radar's payloads differ per endpoint and gain
/// fields over time, so parsing tolerates unknown keys and missing ones.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RadarEntry {
    /// Endpoint the entry came from.
    pub endpoint: RadarEndpoint,
    /// Autonomous system number, when the record carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u64>,
    /// ISO 3166-1 alpha-2 country code, upper-cased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Magnitude/severity as reported by Radar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magnitude: Option<f64>,
    /// Anomaly type/kind (e.g. `dns`, `hijack`, `volumetric`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Per-entry timestamp, kept as Radar sent it (RFC 3339 text or a Unix number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Entry filters applied before an entry enters the cache.
///
/// `countries` and `asns` are allowlists: an empty list accepts everything, a non-empty list keeps
/// only matching entries. `min_magnitude` drops entries whose magnitude is known and below the
/// threshold; entries with no magnitude are kept because their severity cannot be judged.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RadarFilters {
    /// Minimum magnitude.
    pub min_magnitude: Option<f64>,
    /// Accepted country codes (case-insensitive).
    pub countries: Vec<String>,
    /// Accepted ASNs.
    pub asns: Vec<u64>,
}

impl RadarFilters {
    /// Whether `entry` passes every configured filter.
    pub fn matches(&self, entry: &RadarEntry) -> bool {
        if let Some(minimum) = self.min_magnitude {
            if let Some(magnitude) = entry.magnitude {
                if magnitude < minimum {
                    return false;
                }
            }
        }
        if !self.countries.is_empty() {
            let country = entry
                .country
                .as_deref()
                .map(|country| country.to_ascii_uppercase());
            let accepted = country.as_deref().is_some_and(|country| {
                self.countries
                    .iter()
                    .any(|wanted| wanted.eq_ignore_ascii_case(country))
            });
            if !accepted {
                return false;
            }
        }
        if !self.asns.is_empty() {
            let accepted = entry.asn.is_some_and(|asn| self.asns.contains(&asn));
            if !accepted {
                return false;
            }
        }
        true
    }
}

/// Radar operating mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RadarMode {
    /// Start idle; the first Internet-routable client IP enables radar (default).
    #[default]
    Auto,
    /// Poll from startup.
    On,
    /// Disabled: no polling, no storage, no matchers.
    Off,
}

impl RadarMode {
    /// Lower-case name used in logs and configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::On => "on",
            Self::Off => "off",
        }
    }

    /// Parse `auto`/`on`/`off`.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            other => Err(format!(
                "unknown radar mode '{other}' (expected auto, on, or off)"
            )),
        }
    }
}

impl fmt::Display for RadarMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A configuration problem, located at the offending field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadarConfigError {
    field: String,
    message: String,
}

impl RadarConfigError {
    /// Build an error for `field`.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }

    /// The offending field path.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The problem.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RadarConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "radar config: {}: {}", self.field, self.message)
    }
}

impl std::error::Error for RadarConfigError {}

/// Radar configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct RadarConfig {
    /// Operating mode.
    pub mode: RadarMode,
    /// Poll interval; values below [`MIN_POLL_INTERVAL`] are clamped by [`RadarClient::new`].
    pub interval: Duration,
    /// How long a cached endpoint stays fresh.
    pub cache_ttl: Duration,
    /// Optional Cloudflare API token, sent as `Authorization: Bearer <token>`.
    pub api_token: Option<String>,
    /// Radar API base URL.
    pub base_url: String,
    /// Entry filters.
    pub filters: RadarFilters,
    /// Cache persistence backend.
    pub storage: StorageSpec,
}

impl Default for RadarConfig {
    fn default() -> Self {
        Self {
            mode: RadarMode::Auto,
            interval: DEFAULT_POLL_INTERVAL,
            cache_ttl: DEFAULT_CACHE_TTL,
            api_token: None,
            base_url: DEFAULT_BASE_URL.to_string(),
            filters: RadarFilters::default(),
            storage: StorageSpec::default(),
        }
    }
}

impl RadarConfig {
    /// Parse configuration from JSON. Unknown fields are ignored; malformed fields produce a
    /// [`RadarConfigError`] naming the field.
    pub fn from_json(text: &str) -> Result<Self, RadarConfigError> {
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|error| RadarConfigError::new("<document>", error.to_string()))?;
        let object = value
            .as_object()
            .ok_or_else(|| RadarConfigError::new("<document>", "expected a JSON object"))?;
        let mut config = Self::default();
        if let Some(mode) = object.get("mode") {
            let mode = mode
                .as_str()
                .ok_or_else(|| RadarConfigError::new("mode", "expected a string"))?;
            config.mode =
                RadarMode::parse(mode).map_err(|message| RadarConfigError::new("mode", message))?;
        }
        if let Some(interval) = object.get("interval") {
            config.interval = parse_duration(interval, "interval")?;
        }
        if let Some(ttl) = object.get("cache_ttl") {
            config.cache_ttl = parse_duration(ttl, "cache_ttl")?;
        }
        if let Some(token) = object.get("api_token") {
            if token.is_null() {
                config.api_token = None;
            } else {
                let token = token
                    .as_str()
                    .ok_or_else(|| RadarConfigError::new("api_token", "expected a string"))?;
                config.api_token = Some(token.to_string());
            }
        }
        if let Some(base_url) = object.get("base_url") {
            let base_url = base_url
                .as_str()
                .ok_or_else(|| RadarConfigError::new("base_url", "expected a string"))?;
            if base_url.trim().is_empty() {
                return Err(RadarConfigError::new("base_url", "must not be empty"));
            }
            config.base_url = base_url.trim_end_matches('/').to_string();
        }
        if let Some(filters) = object.get("filters") {
            config.filters = parse_filters(filters)?;
        }
        if let Some(storage) = object.get("storage") {
            config.storage = parse_storage(storage)?;
        }
        Ok(config)
    }

    /// URL polled for `endpoint`.
    pub fn endpoint_url(&self, endpoint: RadarEndpoint) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), endpoint.path())
    }
}

fn parse_filters(value: &serde_json::Value) -> Result<RadarFilters, RadarConfigError> {
    let object = value
        .as_object()
        .ok_or_else(|| RadarConfigError::new("filters", "expected an object"))?;
    let mut filters = RadarFilters::default();
    if let Some(magnitude) = object.get("min_magnitude") {
        let magnitude = magnitude
            .as_f64()
            .ok_or_else(|| RadarConfigError::new("filters.min_magnitude", "expected a number"))?;
        filters.min_magnitude = Some(magnitude);
    }
    if let Some(countries) = object.get("countries") {
        let countries = countries
            .as_array()
            .ok_or_else(|| RadarConfigError::new("filters.countries", "expected an array"))?;
        for country in countries {
            let country = country.as_str().ok_or_else(|| {
                RadarConfigError::new("filters.countries", "expected an array of strings")
            })?;
            filters.countries.push(country.to_ascii_uppercase());
        }
    }
    if let Some(asns) = object.get("asns") {
        let asns = asns
            .as_array()
            .ok_or_else(|| RadarConfigError::new("filters.asns", "expected an array"))?;
        for asn in asns {
            let asn = asn
                .as_u64()
                .ok_or_else(|| RadarConfigError::new("filters.asns", "expected an array of u64"))?;
            filters.asns.push(asn);
        }
    }
    Ok(filters)
}

fn parse_storage(value: &serde_json::Value) -> Result<StorageSpec, RadarConfigError> {
    match value {
        serde_json::Value::String(spec) => StorageSpec::parse(spec)
            .map_err(|error| RadarConfigError::new("storage", error.message())),
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(|kind| kind.as_str())
                .ok_or_else(|| RadarConfigError::new("storage.type", "expected a string"))?;
            match kind {
                "memory" => Ok(StorageSpec::Memory),
                "file" => {
                    let path = object
                        .get("path")
                        .and_then(|path| path.as_str())
                        .unwrap_or(crate::radar_store::DEFAULT_CACHE_PATH);
                    Ok(StorageSpec::File {
                        path: std::path::PathBuf::from(path),
                    })
                }
                "redis" => {
                    let url = object
                        .get("url")
                        .and_then(|url| url.as_str())
                        .ok_or_else(|| RadarConfigError::new("storage.url", "expected a string"))?;
                    let prefix = object
                        .get("prefix")
                        .and_then(|prefix| prefix.as_str())
                        .unwrap_or("radar:");
                    Ok(StorageSpec::Redis {
                        url: url.to_string(),
                        prefix: prefix.to_string(),
                    })
                }
                other => Err(RadarConfigError::new(
                    "storage.type",
                    format!("unknown backend '{other}' (expected file, redis, or memory)"),
                )),
            }
        }
        _ => Err(RadarConfigError::new(
            "storage",
            "expected a spec string or an object",
        )),
    }
}

/// Parse a duration from a JSON number (seconds) or a string (`90`, `90s`, `2m`, `1h`).
fn parse_duration(value: &serde_json::Value, field: &str) -> Result<Duration, RadarConfigError> {
    let seconds = match value {
        serde_json::Value::Number(number) => number
            .as_f64()
            .ok_or_else(|| RadarConfigError::new(field, "expected a number of seconds"))?,
        serde_json::Value::String(text) => {
            let text = text.trim();
            let (digits, multiplier) = match text.strip_suffix(['s', 'S']) {
                Some(digits) => (digits, 1.0),
                None => match text.strip_suffix(['m', 'M']) {
                    Some(digits) => (digits, 60.0),
                    None => match text.strip_suffix(['h', 'H']) {
                        Some(digits) => (digits, 3600.0),
                        None => (text, 1.0),
                    },
                },
            };
            let digits = digits.trim();
            if digits.is_empty() {
                return Err(RadarConfigError::new(field, "expected a duration"));
            }
            digits
                .parse::<f64>()
                .map_err(|_| RadarConfigError::new(field, format!("'{text}' is not a duration")))?
                * multiplier
        }
        _ => {
            return Err(RadarConfigError::new(
                field,
                "expected seconds or a duration string",
            ))
        }
    };
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(RadarConfigError::new(
            field,
            "duration must be a finite, non-negative number",
        ));
    }
    Ok(Duration::from_secs_f64(seconds))
}

/// Per-endpoint cache record; also the persisted document.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedEndpoint {
    /// Unix milliseconds at which the endpoint was last refreshed successfully.
    fetched_at_ms: u64,
    /// Filtered entries.
    entries: Vec<RadarEntry>,
}

/// Cache map: endpoint cache key -> record.
type Cache = BTreeMap<String, CachedEndpoint>;

/// Metrics for the Radar client. No admin registry is wired in this task; the values are exposed
/// through [`RadarMetrics::snapshot`] and the individual getters.
#[derive(Debug, Default)]
pub struct RadarMetrics {
    polls_total: AtomicU64,
    errors_total: AtomicU64,
    entries_cached: AtomicU64,
    stale_serves_total: AtomicU64,
    storage_writes_total: AtomicU64,
    storage_reads_total: AtomicU64,
    auto_enables_total: AtomicU64,
}

/// Point-in-time copy of [`RadarMetrics`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RadarMetricsSnapshot {
    /// `radar_polls_total`
    pub radar_polls_total: u64,
    /// `radar_errors_total`
    pub radar_errors_total: u64,
    /// `radar_entries_cached`
    pub radar_entries_cached: u64,
    /// `radar_stale_serves_total`
    pub radar_stale_serves_total: u64,
    /// `radar_storage_writes_total`
    pub radar_storage_writes_total: u64,
    /// `radar_storage_reads_total`
    pub radar_storage_reads_total: u64,
    /// `radar_auto_enables_total`
    pub radar_auto_enables_total: u64,
}

impl RadarMetrics {
    /// `radar_polls_total`: completed poll cycles.
    pub fn radar_polls_total(&self) -> u64 {
        self.polls_total.load(Ordering::Relaxed)
    }

    /// `radar_errors_total`: failed endpoint polls and storage errors.
    pub fn radar_errors_total(&self) -> u64 {
        self.errors_total.load(Ordering::Relaxed)
    }

    /// `radar_entries_cached`: entries currently in the cache (fresh or stale).
    pub fn radar_entries_cached(&self) -> u64 {
        self.entries_cached.load(Ordering::Relaxed)
    }

    /// `radar_stale_serves_total`: failed refreshes that were served from the previous cache.
    pub fn radar_stale_serves_total(&self) -> u64 {
        self.stale_serves_total.load(Ordering::Relaxed)
    }

    /// `radar_storage_writes_total`: endpoint documents written.
    pub fn radar_storage_writes_total(&self) -> u64 {
        self.storage_writes_total.load(Ordering::Relaxed)
    }

    /// `radar_storage_reads_total`: endpoint documents read (or found absent).
    pub fn radar_storage_reads_total(&self) -> u64 {
        self.storage_reads_total.load(Ordering::Relaxed)
    }

    /// `radar_auto_enables_total`: auto-mode enables triggered by a routable client IP.
    pub fn radar_auto_enables_total(&self) -> u64 {
        self.auto_enables_total.load(Ordering::Relaxed)
    }

    /// Copy every counter.
    pub fn snapshot(&self) -> RadarMetricsSnapshot {
        RadarMetricsSnapshot {
            radar_polls_total: self.radar_polls_total(),
            radar_errors_total: self.radar_errors_total(),
            radar_entries_cached: self.radar_entries_cached(),
            radar_stale_serves_total: self.radar_stale_serves_total(),
            radar_storage_writes_total: self.radar_storage_writes_total(),
            radar_storage_reads_total: self.radar_storage_reads_total(),
            radar_auto_enables_total: self.radar_auto_enables_total(),
        }
    }
}

/// Log sink for the exact mode/enable lines the task specifies (and poll diagnostics).
///
/// The trait exists so tests can capture lines instead of scraping stderr.
pub trait RadarLog: Send + Sync + fmt::Debug {
    /// Record one already-formatted line.
    fn info(&self, line: &str);
}

/// Production sink: one line per event on stderr.
#[derive(Debug, Default, Clone, Copy)]
pub struct StderrRadarLog;

impl RadarLog for StderrRadarLog {
    fn info(&self, line: &str) {
        eprintln!("{line}");
    }
}

/// Network seam: one GET returning `(status, body)`.
#[async_trait]
pub trait RadarTransport: Send + Sync + fmt::Debug {
    /// GET `url`, adding `Authorization: Bearer <token>` when a token is configured.
    async fn get(&self, url: &str, token: Option<&str>) -> Result<(u16, Vec<u8>), String>;
}

/// Production transport: hyper HTTP/1 over TCP, with rustls (platform roots) for `https://`.
#[derive(Debug, Default, Clone, Copy)]
pub struct HyperRadarTransport;

#[async_trait]
impl RadarTransport for HyperRadarTransport {
    async fn get(&self, url: &str, token: Option<&str>) -> Result<(u16, Vec<u8>), String> {
        let uri: Uri = url
            .parse()
            .map_err(|error| format!("radar: invalid URL '{url}': {error}"))?;
        let scheme = uri.scheme_str().unwrap_or("https").to_string();
        let host = uri
            .host()
            .ok_or_else(|| format!("radar: URL '{url}' has no host"))?
            .to_string();
        let default_port = if scheme == "https" { 443 } else { 80 };
        let port = uri.port_u16().unwrap_or(default_port);
        let authority = format!("{host}:{port}");
        let tcp = tokio::time::timeout(HTTP_TIMEOUT, TcpStream::connect(&authority))
            .await
            .map_err(|_| format!("radar: connect to {authority} timed out"))?
            .map_err(|error| format!("radar: connect to {authority} failed: {error}"))?;
        let _ = tcp.set_nodelay(true);
        let request = async move {
            match scheme.as_str() {
                "http" => send_http1(TokioIo::new(tcp), &uri, &authority, token).await,
                "https" => {
                    let tls = tls_connect(&host, tcp).await?;
                    send_http1(TokioIo::new(tls), &uri, &authority, token).await
                }
                other => Err(format!("radar: unsupported URL scheme '{other}'")),
            }
        };
        tokio::time::timeout(HTTP_TIMEOUT, request)
            .await
            .map_err(|_| format!("radar: request to {url} timed out"))?
    }
}

/// One HTTP/1.1 exchange over an already-connected stream.
async fn send_http1<S>(
    stream: TokioIo<S>,
    uri: &Uri,
    authority: &str,
    token: Option<&str>,
) -> Result<(u16, Vec<u8>), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(stream)
        .await
        .map_err(|error| format!("radar: HTTP handshake failed: {error}"))?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    // Origin-form request target: hyper would otherwise send the absolute URI, which is legal but
    // unusual for a direct client and rejected by some intermediaries.
    let target = uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(target)
        .header(header::HOST, authority)
        .header(header::ACCEPT, "application/json")
        .header(header::USER_AGENT, "caddy-rs-radar/1");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder
        .body(Empty::<bytes::Bytes>::new())
        .map_err(|error| format!("radar: cannot build request: {error}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| format!("radar: request failed: {error}"))?;
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|error| format!("radar: reading response body failed: {error}"))?
        .to_bytes()
        .to_vec();
    drop(sender);
    driver.abort();
    Ok((status, body))
}

/// TLS handshake with platform-verifier roots.
async fn tls_connect(
    host: &str,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let config = tls_client_config()?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|error| format!("radar: invalid TLS server name '{host}': {error}"))?;
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|error| format!("radar: TLS handshake with {host} failed: {error}"))
}

fn tls_client_config() -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls_platform_verifier::BuilderVerifierExt;
    static CONFIG: std::sync::OnceLock<Result<Arc<rustls::ClientConfig>, String>> =
        std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|error| format!("radar: rustls provider error: {error}"))?
                .with_platform_verifier()
                .map_err(|error| format!("radar: platform trust store unavailable: {error}"))?
                .with_no_client_auth();
            Ok(Arc::new(config))
        })
        .clone()
}

/// Result of one poll cycle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PollOutcome {
    /// Entries in the cache after the cycle.
    pub entries: usize,
    /// Endpoints refreshed successfully.
    pub endpoints_ok: usize,
    /// Endpoints that failed (their previous cache is kept).
    pub endpoints_failed: usize,
    /// Failures served from the previous cache.
    pub stale_serves: usize,
}

/// Radar client: mode gate, polling loop, TTL cache, persistence and metrics.
#[derive(Debug)]
pub struct RadarClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: RadarConfig,
    transport: Arc<dyn RadarTransport>,
    storage: Arc<dyn RadarStorage>,
    log: Arc<dyn RadarLog>,
    metrics: Arc<RadarMetrics>,
    cache: Mutex<Cache>,
    enabled: AtomicBool,
    started: AtomicBool,
    poller: StdMutex<Option<JoinHandle<()>>>,
}

impl RadarClient {
    /// Build a client. `interval` is clamped to [`MIN_POLL_INTERVAL`]; nothing is polled and no
    /// storage is touched until [`Self::start`] (and, in auto mode, [`Self::on_client_ip`]).
    pub fn new(
        mut config: RadarConfig,
        transport: Arc<dyn RadarTransport>,
        storage: Arc<dyn RadarStorage>,
        log: Arc<dyn RadarLog>,
    ) -> Self {
        if config.interval < MIN_POLL_INTERVAL {
            config.interval = MIN_POLL_INTERVAL;
        }
        config.base_url = config.base_url.trim_end_matches('/').to_string();
        Self {
            inner: Arc::new(Inner {
                config,
                transport,
                storage,
                log,
                metrics: Arc::new(RadarMetrics::default()),
                cache: Mutex::new(Cache::new()),
                enabled: AtomicBool::new(false),
                started: AtomicBool::new(false),
                poller: StdMutex::new(None),
            }),
        }
    }

    /// Convenience constructor using [`HyperRadarTransport`], the configured storage backend and
    /// stderr logging.
    pub fn from_config(config: RadarConfig) -> Result<Self, StorageError> {
        let storage = config.storage.build()?;
        Ok(Self::new(
            config,
            Arc::new(HyperRadarTransport),
            storage,
            Arc::new(StderrRadarLog),
        ))
    }

    /// The effective configuration (after clamping).
    pub fn config(&self) -> &RadarConfig {
        &self.inner.config
    }

    /// Current mode.
    pub fn mode(&self) -> RadarMode {
        self.inner.config.mode
    }

    /// Whether polling is running.
    pub fn is_enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::SeqCst)
    }

    /// Shared metrics.
    pub fn metrics(&self) -> Arc<RadarMetrics> {
        Arc::clone(&self.inner.metrics)
    }

    /// Apply the configured mode. Call once at startup:
    ///
    /// * `off` — nothing at all;
    /// * `auto` — log the waiting line, stay idle;
    /// * `on` — log the started line, load the persisted cache and poll immediately.
    ///
    /// Repeated calls are no-ops.
    pub async fn start(&self) {
        if self.inner.started.swap(true, Ordering::SeqCst) {
            return;
        }
        match self.inner.config.mode {
            RadarMode::Off => {}
            RadarMode::Auto => self
                .inner
                .log
                .info("radar: mode=auto (waiting for Internet-routable client IP)"),
            RadarMode::On => {
                self.inner.log.info("radar: mode=on (polling started)");
                self.inner.load_persisted().await;
                self.inner.enable();
                self.inner.spawn_poller();
            }
        }
    }

    /// Auto-mode gate. Enables radar for the first Internet-routable IP and returns `true`; returns
    /// `false` for private/loopback/link-local/unspecified/multicast addresses, for repeated calls,
    /// and outside `auto` mode.
    pub async fn on_client_ip(&self, ip: IpAddr, asn: Option<u64>) -> bool {
        if self.inner.config.mode != RadarMode::Auto {
            return false;
        }
        if !is_internet_routable(ip) {
            return false;
        }
        if self.inner.enabled.swap(true, Ordering::SeqCst) {
            return false;
        }
        // An IP reported before `start` must not be followed by the auto "waiting" line.
        self.inner.started.store(true, Ordering::SeqCst);
        let line = match asn {
            Some(asn) => {
                format!("radar: enabling (Internet-routable IP detected: {ip}, ASN {asn})")
            }
            None => format!("radar: enabling (Internet-routable IP detected: {ip})"),
        };
        self.inner.log.info(&line);
        self.inner
            .metrics
            .auto_enables_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.load_persisted().await;
        self.inner.spawn_poller();
        true
    }

    /// Run one poll cycle: refresh every endpoint whose cache is older than `cache_ttl`, keep the
    /// previous entries for endpoints that fail, and persist refreshed endpoints. Never fails.
    pub async fn poll_once(&self) -> PollOutcome {
        self.inner.poll_once().await
    }

    /// Cached entries for `endpoint`, fresh or stale.
    pub async fn cached_entries(&self, endpoint: RadarEndpoint) -> Option<Vec<RadarEntry>> {
        self.inner
            .cache
            .lock()
            .await
            .get(endpoint.cache_key())
            .map(|cached| cached.entries.clone())
    }

    /// Every cached entry, in endpoint order.
    pub async fn all_entries(&self) -> Vec<RadarEntry> {
        self.inner
            .cache
            .lock()
            .await
            .values()
            .flat_map(|cached| cached.entries.iter().cloned())
            .collect()
    }

    /// Stop the polling task (idempotent).
    pub fn shutdown(&self) {
        self.inner.stop_poller();
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(mut poller) = self.poller.lock() {
            if let Some(handle) = poller.take() {
                handle.abort();
            }
        }
    }
}

impl Inner {
    fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    fn spawn_poller(self: &Arc<Self>) {
        if self
            .poller
            .lock()
            .map(|poller| poller.is_some())
            .unwrap_or(false)
        {
            return;
        }
        let inner = Arc::clone(self);
        let handle = tokio::spawn(async move {
            loop {
                inner.poll_once().await;
                tokio::time::sleep(inner.config.interval).await;
            }
        });
        if let Ok(mut poller) = self.poller.lock() {
            *poller = Some(handle);
        }
    }

    fn stop_poller(&self) {
        if let Ok(mut poller) = self.poller.lock() {
            if let Some(handle) = poller.take() {
                handle.abort();
            }
        }
    }

    /// Read persisted endpoint documents into the cache. Existing (newer) cache entries win.
    async fn load_persisted(&self) {
        let mut loaded = 0usize;
        for endpoint in RadarEndpoint::ALL {
            let key = endpoint.cache_key();
            match self.storage.load(key).await {
                Ok(Some(json)) => {
                    self.metrics
                        .storage_reads_total
                        .fetch_add(1, Ordering::Relaxed);
                    match serde_json::from_str::<CachedEndpoint>(&json) {
                        Ok(cached) => {
                            let mut cache = self.cache.lock().await;
                            cache.entry(key.to_string()).or_insert(cached);
                            loaded += 1;
                        }
                        Err(error) => {
                            self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                            self.log.info(&format!(
                                "radar: ignoring unreadable persisted cache for {key}: {error}"
                            ));
                        }
                    }
                }
                Ok(None) => {
                    self.metrics
                        .storage_reads_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                    self.log
                        .info(&format!("radar: cache load failed for {key}: {error}"));
                }
            }
        }
        self.refresh_entries_gauge().await;
        if loaded > 0 {
            self.log.info(&format!(
                "radar: loaded {loaded} cached endpoint(s) from {}",
                self.storage.describe()
            ));
        }
    }

    async fn refresh_entries_gauge(&self) -> usize {
        let entries: usize = self
            .cache
            .lock()
            .await
            .values()
            .map(|cached| cached.entries.len())
            .sum();
        self.metrics
            .entries_cached
            .store(entries as u64, Ordering::Relaxed);
        entries
    }

    async fn poll_once(&self) -> PollOutcome {
        self.metrics.polls_total.fetch_add(1, Ordering::Relaxed);
        let mut outcome = PollOutcome::default();
        let mut refreshed: BTreeMap<String, String> = BTreeMap::new();
        let ttl_ms = self.config.cache_ttl.as_millis().min(u128::from(u64::MAX)) as u64;
        for endpoint in RadarEndpoint::ALL {
            let key = endpoint.cache_key();
            {
                let cache = self.cache.lock().await;
                if let Some(cached) = cache.get(key) {
                    if now_ms().saturating_sub(cached.fetched_at_ms) < ttl_ms {
                        outcome.endpoints_ok += 1;
                        continue;
                    }
                }
            }
            let url = self.config.endpoint_url(endpoint);
            let token = self.config.api_token.as_deref();
            match self.transport.get(&url, token).await {
                Ok((status, body)) if (200..300).contains(&status) => {
                    match parse_entries(endpoint, &body) {
                        Ok(entries) => {
                            let entries: Vec<RadarEntry> = entries
                                .into_iter()
                                .filter(|entry| self.config.filters.matches(entry))
                                .collect();
                            let cached = CachedEndpoint {
                                fetched_at_ms: now_ms(),
                                entries,
                            };
                            match serde_json::to_string(&cached) {
                                Ok(json) => {
                                    refreshed.insert(key.to_string(), json);
                                }
                                Err(error) => {
                                    self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                                    self.log.info(&format!(
                                        "radar: cannot encode cache for {key}: {error}"
                                    ));
                                }
                            }
                            self.cache.lock().await.insert(key.to_string(), cached);
                            outcome.endpoints_ok += 1;
                        }
                        Err(message) => {
                            self.record_failure(&mut outcome, key, &message).await;
                        }
                    }
                }
                Ok((status, _)) => {
                    self.record_failure(&mut outcome, key, &format!("HTTP status {status}"))
                        .await;
                }
                Err(message) => {
                    self.record_failure(&mut outcome, key, &message).await;
                }
            }
        }
        if !refreshed.is_empty() {
            match self.storage.save_all(&refreshed).await {
                Ok(()) => {
                    self.metrics
                        .storage_writes_total
                        .fetch_add(refreshed.len() as u64, Ordering::Relaxed);
                }
                Err(error) => {
                    self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                    self.log
                        .info(&format!("radar: cache persist failed: {error}"));
                }
            }
        }
        outcome.entries = self.refresh_entries_gauge().await;
        outcome
    }

    /// Count a failed refresh; when the endpoint has a previous cache record it is served stale.
    async fn record_failure(&self, outcome: &mut PollOutcome, key: &str, message: &str) {
        self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
        outcome.endpoints_failed += 1;
        let has_cache = self.cache.lock().await.contains_key(key);
        if has_cache {
            self.metrics
                .stale_serves_total
                .fetch_add(1, Ordering::Relaxed);
            outcome.stale_serves += 1;
            self.log
                .info(&format!("radar: serving stale {key} ({message})"));
        } else {
            self.log
                .info(&format!("radar: poll failed for {key}: {message}"));
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Whether `ip` is an Internet-routable unicast address.
///
/// Excluded: IPv4 RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`), link-local
/// (`169.254/16`), `0/8`, broadcast and multicast; IPv6 unique-local (`fc00::/7`), link-local
/// (`fe80::/10`), loopback (`::1/128`), unspecified and multicast. IPv4-mapped IPv6 addresses are
/// judged as IPv4.
pub fn is_internet_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_routable_v4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_routable_v4(mapped);
            }
            is_routable_v6(address)
        }
    }
}

fn is_routable_v4(address: Ipv4Addr) -> bool {
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_unspecified()
        || address.octets()[0] == 0)
}

fn is_routable_v6(address: Ipv6Addr) -> bool {
    if address.is_loopback() || address.is_unspecified() || address.is_multicast() {
        return false;
    }
    let segments = address.segments();
    let unique_local = segments[0] & 0xfe00 == 0xfc00;
    let link_local = segments[0] & 0xffc0 == 0xfe80;
    !(unique_local || link_local)
}

/// Parse a Radar response body into entries.
///
/// Radar wraps payloads as `{"success": true, "result": ...}`; `result` may be an array, an object
/// holding arrays (e.g. `top`, `events`, `anomalies`), or an array nested one level deeper. Unknown
/// fields are ignored. A `success: false` payload and a non-JSON body are errors.
pub fn parse_entries(endpoint: RadarEndpoint, body: &[u8]) -> Result<Vec<RadarEntry>, String> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| format!("radar: {endpoint} returned invalid JSON: {error}"))?;
    if value.get("success").and_then(|success| success.as_bool()) == Some(false) {
        let detail = value
            .get("errors")
            .map(|errors| errors.to_string())
            .unwrap_or_else(|| "no error detail".to_string());
        return Err(format!("radar: {endpoint} reported failure: {detail}"));
    }
    let records = match find_records(&value, 0) {
        Some(records) => records,
        None => return Ok(Vec::new()),
    };
    let mut entries = Vec::new();
    for record in records {
        if !record.is_object() {
            continue;
        }
        entries.push(RadarEntry {
            endpoint,
            asn: first_u64(record, &ASN_KEYS),
            country: first_string(record, &COUNTRY_KEYS)
                .map(|country| country.to_ascii_uppercase()),
            magnitude: first_f64(record, &MAGNITUDE_KEYS),
            kind: first_string(record, &KIND_KEYS),
            timestamp: first_string(record, &TIMESTAMP_KEYS)
                .or_else(|| first_number_text(record, &TIMESTAMP_KEYS)),
        });
    }
    Ok(entries)
}

const ASN_KEYS: [&[&str]; 7] = [
    &["asn"],
    &["asn_number"],
    &["asnNumber"],
    &["origin", "asn"],
    &["origin_asn"],
    &["client", "asn"],
    &["target", "asn"],
];
const COUNTRY_KEYS: [&[&str]; 6] = [
    &["country"],
    &["country_code"],
    &["countryCode"],
    &["location", "country"],
    &["origin", "country"],
    &["target", "country"],
];
const MAGNITUDE_KEYS: [&[&str]; 3] = [&["magnitude"], &["value"], &["score"]];
const KIND_KEYS: [&[&str]; 6] = [
    &["kind"],
    &["type"],
    &["anomaly_type"],
    &["anomalyType"],
    &["event_type"],
    &["category"],
];
const TIMESTAMP_KEYS: [&[&str]; 5] = [
    &["timestamp"],
    &["start"],
    &["start_time"],
    &["date"],
    &["time"],
];

/// Find the record array in a Radar payload: `result` first, then the first array anywhere below
/// `result` (depth-limited), then a top-level array.
fn find_records(value: &serde_json::Value, depth: usize) -> Option<&Vec<serde_json::Value>> {
    if let Some(array) = value.as_array() {
        return Some(array);
    }
    let object = value.as_object()?;
    if let Some(result) = object.get("result") {
        if result.is_array() {
            return result.as_array();
        }
        if depth < 2 {
            if let Some(records) = find_records(result, depth + 1) {
                return Some(records);
            }
        }
    }
    for key in [
        "events",
        "anomalies",
        "hijacks",
        "attacks",
        "top",
        "data",
        "items",
        "series",
        "records",
    ] {
        if let Some(records) = object.get(key).and_then(|value| value.as_array()) {
            return Some(records);
        }
    }
    if depth < 2 {
        for nested in object.values() {
            if nested.is_array() {
                return nested.as_array();
            }
        }
        for nested in object.values() {
            if nested.is_object() {
                if let Some(records) = find_records(nested, depth + 1) {
                    return Some(records);
                }
            }
        }
    }
    None
}

fn lookup<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    Some(current)
}

fn first_u64(value: &serde_json::Value, keys: &[&[&str]]) -> Option<u64> {
    keys.iter()
        .find_map(|path| lookup(value, path).and_then(as_u64))
}

fn first_f64(value: &serde_json::Value, keys: &[&[&str]]) -> Option<f64> {
    keys.iter()
        .find_map(|path| lookup(value, path).and_then(as_f64))
}

fn first_string(value: &serde_json::Value, keys: &[&[&str]]) -> Option<String> {
    keys.iter()
        .find_map(|path| lookup(value, path).and_then(as_text))
}

fn first_number_text(value: &serde_json::Value, keys: &[&[&str]]) -> Option<String> {
    keys.iter().find_map(|path| {
        lookup(value, path).and_then(|found| match found {
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
    })
}

fn as_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => {
            let text = text.trim();
            let text = text
                .strip_prefix("AS")
                .or_else(|| text.strip_prefix("as"))
                .unwrap_or(text);
            text.parse::<u64>().ok()
        }
        _ => None,
    }
}

fn as_f64(value: &serde_json::Value) -> Option<f64> {
    match value {
        serde_json::Value::Number(number) => number.as_f64(),
        serde_json::Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn as_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routability_table_matches_the_documented_exclusions() {
        let routable = [
            "203.0.113.5",
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700::1111",
        ];
        for address in routable {
            assert!(
                is_internet_routable(address.parse().unwrap()),
                "{address} must be routable"
            );
        }
        let excluded = [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.255.255",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.1.1",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "::ffff:203.0.113.5",
        ];
        for address in excluded {
            let parsed: IpAddr = address.parse().unwrap();
            let expected = address == "::ffff:203.0.113.5";
            assert_eq!(
                is_internet_routable(parsed),
                expected,
                "{address} routability mismatch"
            );
        }
    }

    #[test]
    fn interval_is_clamped_and_json_errors_are_located() {
        let client = RadarClient::new(
            RadarConfig {
                interval: Duration::from_secs(5),
                ..RadarConfig::default()
            },
            Arc::new(HyperRadarTransport),
            Arc::new(crate::radar_store::MemoryStorage::new()),
            Arc::new(StderrRadarLog),
        );
        assert_eq!(client.config().interval, MIN_POLL_INTERVAL);
        let error = RadarConfig::from_json(r#"{"mode":"sometimes"}"#).unwrap_err();
        assert_eq!(error.field(), "mode");
        let error = RadarConfig::from_json(r#"{"interval":"soon"}"#).unwrap_err();
        assert_eq!(error.field(), "interval");
    }

    #[test]
    fn filters_apply_magnitude_country_and_asn() {
        let entry = RadarEntry {
            endpoint: RadarEndpoint::DdosL7,
            asn: Some(64500),
            country: Some("DE".to_string()),
            magnitude: Some(12.5),
            kind: Some("volumetric".to_string()),
            timestamp: None,
        };
        assert!(RadarFilters::default().matches(&entry));
        assert!(RadarFilters {
            min_magnitude: Some(10.0),
            ..RadarFilters::default()
        }
        .matches(&entry));
        assert!(!RadarFilters {
            min_magnitude: Some(20.0),
            ..RadarFilters::default()
        }
        .matches(&entry));
        assert!(RadarFilters {
            countries: vec!["de".to_string()],
            ..RadarFilters::default()
        }
        .matches(&entry));
        assert!(!RadarFilters {
            countries: vec!["US".to_string()],
            ..RadarFilters::default()
        }
        .matches(&entry));
        assert!(RadarFilters {
            asns: vec![64500],
            ..RadarFilters::default()
        }
        .matches(&entry));
        assert!(!RadarFilters {
            asns: vec![64501],
            ..RadarFilters::default()
        }
        .matches(&entry));
    }

    #[test]
    fn parsing_tolerates_unknown_fields_and_nested_payloads() {
        let body = br#"{
            "success": true,
            "result": {
                "top": [
                    {"asn": "AS64500", "country": "us", "magnitude": 9.5,
                     "kind": "volumetric", "timestamp": "2025-01-01T00:00:00Z",
                     "brand_new_field": {"nested": true}}
                ]
            },
            "unknown": 1
        }"#;
        let entries = parse_entries(RadarEndpoint::DdosL7, body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].asn, Some(64500));
        assert_eq!(entries[0].country.as_deref(), Some("US"));
        assert_eq!(entries[0].magnitude, Some(9.5));
        assert_eq!(entries[0].kind.as_deref(), Some("volumetric"));
        assert_eq!(
            entries[0].timestamp.as_deref(),
            Some("2025-01-01T00:00:00Z")
        );
        assert!(parse_entries(RadarEndpoint::DdosL7, b"not json").is_err());
        assert!(parse_entries(
            RadarEndpoint::DdosL7,
            br#"{"success": false, "errors": [{"message": "nope"}]}"#
        )
        .is_err());
    }
}
