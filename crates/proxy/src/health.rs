//! Upstream health checks.
//!
//! Two kinds of health checks exist in Caddy's `reverse_proxy`:
//!
//! * **Active** checks probe each upstream in the background (`health_checks.active`). This module
//!   owns the probe configuration ([`HealthCheck`]), the single-shot probe ([`HealthCheck::check_once`])
//!   and a scheduler with cooperative cancellation ([`HealthCheckScheduler`]) that the server
//!   runtime can drive. The scheduler tracks consecutive passes/fails and flips an upstream's
//!   health flag only when the configured thresholds are reached.
//! * **Passive** checks observe real proxied requests; that state machine lives in
//!   [`crate::passive`].
//!
//! Caddy configuration shape (v2.11.7):
//!
//! ```json
//! "health_checks": {
//!   "active": {
//!     "uri": "/health", "method": "GET", "headers": {"X-Probe": ["1"]},
//!     "body": "", "interval": 30000000000, "timeout": 5000000000,
//!     "passes": 1, "fails": 1, "expect_status": 200
//!   }
//! }
//! ```
//!
//! The deprecated `path` field is accepted as an alias for `uri`. Active checks are enabled when
//! `uri`/`path` is set (Caddy also enables them for a health-check `port`, which is not implemented
//! here and fails loudly).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper_util::client::legacy::connect::Connect;
use hyper_util::client::legacy::Client;
use serde_json::Value;
use tokio::sync::watch;

use caddy_rs_http::{Error as HttpError, Result as HttpResult};

use crate::client::ClientBody;
use crate::upstream::Upstream;

/// Caddy's `caddyhttp.StatusCodeMatches`: an exact match, or — when the configured value is below
/// 100 — a whole status class (`5` matches every 5xx).
pub fn status_matches(actual: http::StatusCode, configured: u16) -> bool {
    let actual = actual.as_u16();
    actual == configured
        || (configured < 100 && actual >= configured * 100 && actual < (configured + 1) * 100)
}

/// Active health-check configuration (Caddy `health_checks.active`).
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Path and query requested on each upstream (normalized to start with `/`).
    pub uri: String,
    /// Optional request body (raw bytes; `body_template` carries the config placeholder form).
    pub body: Bytes,
    /// Original configured body string, expanded per probe with Caddy's global `ReplaceKnown`
    /// placeholders (like Caddy's active health-check body).
    pub body_template: Option<String>,
    /// Delay between rounds.
    pub interval: Duration,
    /// Per-request timeout.
    pub timeout: Duration,
    /// HTTP method.
    pub method: http::Method,
    /// Expected status code; `None` accepts any 2xx. Values below 100 match a status class.
    pub expected_status: Option<u16>,
    /// Extra request headers.
    pub headers: Vec<(String, String)>,
    /// Consecutive passes required before marking a previously unhealthy upstream healthy.
    pub passes: u32,
    /// Consecutive failures required before marking a previously healthy upstream unhealthy.
    pub fails: u32,
    /// Maximum response body size to inspect (Caddy `max_size`); only meaningful with body checks.
    pub max_size: Option<u64>,
    /// Compiled Caddy `expect_body` regular expression; the response body must match it.
    pub expected_body: Option<caddy_rs_http::regex_lite::Regex>,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            uri: "/".to_string(),
            body: Bytes::new(),
            body_template: None,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            method: http::Method::GET,
            expected_status: None,
            headers: Vec::new(),
            passes: 1,
            fails: 1,
            max_size: None,
            expected_body: None,
        }
    }
}

impl HealthCheck {
    /// Parse one `health_checks.active` object.
    ///
    /// Returns `Ok(None)` when the object does not enable active checks (Caddy's `IsEnabled`:
    /// neither `uri`/`path` nor `port` set), so a stray `{"interval": ...}` object is inert just
    /// like in Caddy.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Option<Self>> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`health_checks.active` must be an object"))?;

        if object
            .get("upstream")
            .and_then(Value::as_str)
            .is_some_and(|upstream| !upstream.is_empty())
        {
            return Err(HttpError::NotImplemented {
                feature:
                    "active health checks against an alternative `health_checks.active.upstream`",
                tracking_id: "PROXY-HEALTH-UPSTREAM",
            });
        }
        if object
            .get("port")
            .and_then(Value::as_u64)
            .is_some_and(|port| port != 0)
        {
            return Err(HttpError::NotImplemented {
                feature: "active health checks against an alternative `health_checks.active.port`",
                tracking_id: "PROXY-HEALTH-PORT",
            });
        }
        if object
            .get("follow_redirects")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(HttpError::NotImplemented {
                feature: "active health checks following redirects",
                tracking_id: "PROXY-HEALTH-REDIRECT",
            });
        }

        let uri = object
            .get("uri")
            .and_then(Value::as_str)
            .or_else(|| object.get("path").and_then(Value::as_str))
            .unwrap_or_default();
        if uri.is_empty() {
            return Ok(None);
        }
        let uri = normalize_health_uri(uri).map_err(|message| invalid(path, message))?;

        let mut check = Self {
            uri,
            ..Self::default()
        };

        if let Some(body) = object.get("body").and_then(Value::as_str) {
            check.body = Bytes::copy_from_slice(body.as_bytes());
            check.body_template = Some(body.to_string());
        }
        if let Some(interval) = object
            .get("interval")
            .and_then(Value::as_u64)
            .filter(|interval| *interval > 0)
        {
            check.interval = Duration::from_nanos(interval);
        }
        if let Some(timeout) = object
            .get("timeout")
            .and_then(Value::as_u64)
            .filter(|timeout| *timeout > 0)
        {
            check.timeout = Duration::from_nanos(timeout);
        }
        if let Some(method) = object.get("method").and_then(Value::as_str) {
            check.method = method.parse().map_err(|error| {
                invalid(
                    &format!("{path}.method"),
                    format!("invalid method: {error}"),
                )
            })?;
        }
        if let Some(expected_status) = object
            .get("expect_status")
            .and_then(Value::as_u64)
            .filter(|status| *status > 0)
        {
            check.expected_status = Some(u16::try_from(expected_status).map_err(|_| {
                invalid(&format!("{path}.expect_status"), "status must fit in a u16")
            })?);
        }
        if let Some(headers) = object.get("headers") {
            check.headers = parse_health_headers(headers, &format!("{path}.headers"))?;
        }
        if let Some(passes) = object.get("passes").and_then(Value::as_u64) {
            check.passes = u32::try_from(passes).unwrap_or(u32::MAX).max(1);
        }
        if let Some(fails) = object.get("fails").and_then(Value::as_u64) {
            check.fails = u32::try_from(fails).unwrap_or(u32::MAX).max(1);
        }
        if let Some(max_size) = object.get("max_size").and_then(Value::as_i64) {
            if max_size > 0 {
                check.max_size = Some(max_size as u64);
            }
        }
        if let Some(expect_body) = object
            .get("expect_body")
            .and_then(Value::as_str)
            .filter(|expect_body| !expect_body.is_empty())
        {
            // Caddy compiles `expect_body` as a Go regular expression and marks the upstream
            // unhealthy when the response body does not match. caddy-rs uses the crate's bounded
            // regex engine; unsupported constructs fail loudly at configuration load.
            check.expected_body = Some(
                caddy_rs_http::regex_lite::Regex::new(expect_body).map_err(|error| {
                    invalid(
                        &format!("{path}.expect_body"),
                        format!("invalid regular expression: {error}"),
                    )
                })?,
            );
        }
        Ok(Some(check))
    }

    /// Perform one check. Returns whether the upstream passed.
    ///
    /// The check uses the same client/connector as proxying (generic over the connector so each
    /// upstream's bound client can be used), so TCP, Unix-socket, TLS and HTTP/2 upstreams are all
    /// supported. Unix-socket checks use `localhost` as the Host, matching Caddy's active health
    /// checker.
    pub async fn check_once<C>(&self, client: &Client<C, ClientBody>, upstream: &Upstream) -> bool
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        // Caddy expands active-check bodies/headers with a replacer that has only global
        // placeholders (env/system/time), plus `{http.reverse_proxy.active.target_upstream}` in
        // headers. Bodies and header values use `ReplaceKnown` (unknown `{...}` kept, which
        // matters for JSON bodies); header names and the special Host value use `ReplaceAll`.
        let target_upstream = upstream.dial.clone();
        let body = match &self.body_template {
            Some(template) => Bytes::from(expand_health_placeholders(
                template,
                None,
                PlaceholderMode::ReplaceKnown,
            )),
            None => self.body.clone(),
        };
        let mut headers = http::HeaderMap::new();
        let Ok(default_host) = http::HeaderValue::from_str(upstream.fallback_host()) else {
            return false;
        };
        headers.insert(http::header::HOST, default_host);
        let mut configured_host: Option<String> = None;
        for (raw_name, raw_value) in &self.headers {
            let name_text = expand_health_placeholders(
                raw_name,
                Some(&target_upstream),
                PlaceholderMode::ReplaceAll,
            );
            if name_text.is_empty() {
                continue;
            }
            if name_text.eq_ignore_ascii_case("host") {
                // Caddy sets `req.Host` (and therefore the HTTP/2 :authority) from this value.
                configured_host = Some(expand_health_placeholders(
                    raw_value,
                    Some(&target_upstream),
                    PlaceholderMode::ReplaceAll,
                ));
                continue;
            }
            let Some(name) = name_text.parse::<http::HeaderName>().ok() else {
                return false;
            };
            let value = expand_health_placeholders(
                raw_value,
                Some(&target_upstream),
                PlaceholderMode::ReplaceKnown,
            );
            let Ok(value) = http::HeaderValue::from_str(&value) else {
                return false;
            };
            headers.append(name, value);
        }
        if configured_host
            .as_deref()
            .is_some_and(|host| !host.is_empty())
        {
            // The URI authority carries the configured Host for both HTTP/1.1 and HTTP/2.
            headers.remove(http::header::HOST);
        }
        let url = match configured_host.as_deref().filter(|host| !host.is_empty()) {
            Some(host) => match upstream.url(&self.uri).parse::<http::Uri>() {
                Ok(uri) => format!(
                    "{}://{host}{}",
                    uri.scheme_str().unwrap_or("http"),
                    uri.path_and_query()
                        .map(|value| value.as_str())
                        .unwrap_or("/")
                ),
                Err(_) => return false,
            },
            None => upstream.url(&self.uri),
        };
        let Ok(mut request) = hyper::Request::builder()
            .method(self.method.clone())
            .uri(url)
            .body(crate::client::ClientBody::buffered(body))
        else {
            return false;
        };
        *request.headers_mut() = headers;
        // The timeout covers the round trip and the body inspection/drain, mirroring Go's
        // `http.Client.Timeout` used by Caddy's active health checker.
        let result = tokio::time::timeout(self.timeout, async {
            let response = client.request(request).await.map_err(|_| ())?;
            let status = response.status();
            // Caddy evaluates the status first and only inspects the body for matching statuses.
            let status_ok = match self.expected_status {
                Some(expected) => status_matches(status, expected),
                None => status.is_success(),
            };
            if !status_ok {
                let _ = response.into_body().collect().await;
                return Ok::<bool, ()>(false);
            }
            match &self.expected_body {
                Some(regexp) => {
                    let body = read_body_limited(response.into_body(), self.max_size).await;
                    let Some(body) = body else {
                        return Ok(false);
                    };
                    let text = String::from_utf8_lossy(&body);
                    Ok(regexp.captures(&text).is_some())
                }
                None => {
                    let _ = response.into_body().collect().await;
                    Ok(true)
                }
            }
        })
        .await;
        matches!(result, Ok(Ok(true)))
    }

    /// Apply one probe result to an upstream, respecting the `passes`/`fails` thresholds.
    ///
    /// Pure apart from mutating `upstream`'s health flag and `counters`, so it is tested without
    /// sockets or clocks.
    pub fn apply_probe(
        &self,
        counters: &mut ProbeCounters,
        probe_healthy: bool,
        upstream: &Upstream,
    ) {
        if probe_healthy {
            counters.fails = 0;
            counters.passes = counters.passes.saturating_add(1);
            if counters.passes >= self.passes {
                upstream.set_healthy(true);
                counters.passes = 0;
            }
        } else {
            counters.passes = 0;
            counters.fails = counters.fails.saturating_add(1);
            if counters.fails >= self.fails {
                upstream.set_healthy(false);
                counters.fails = 0;
            }
        }
    }
}

/// Read a probe response body, honouring Caddy's `max_size` byte limit (unlimited when unset).
async fn read_body_limited(body: hyper::body::Incoming, max_size: Option<u64>) -> Option<Bytes> {
    let mut collected = BytesMut::new();
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        match max_size {
            Some(max_size) => {
                let remaining = max_size.saturating_sub(collected.len() as u64);
                if remaining == 0 {
                    break;
                }
                let take = usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .min(data.len());
                collected.extend_from_slice(&data[..take]);
                if (take as u64) == remaining {
                    break;
                }
            }
            None => collected.extend_from_slice(&data),
        }
    }
    Some(collected.freeze())
}

/// How unknown placeholders are treated when expanding health-check values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlaceholderMode {
    /// Caddy `ReplaceKnown`: unknown placeholders stay verbatim.
    ReplaceKnown,
    /// Caddy `ReplaceAll`: unknown/empty placeholders disappear.
    ReplaceAll,
}

/// Expand Caddy's global placeholders in an active health-check body/header value.
///
/// The request-based replacer is unavailable at health-check time; Caddy's check creates a
/// `caddy.NewReplacer()` (env/system/time/file placeholders) and optionally exposes
/// `{http.reverse_proxy.active.target_upstream}` to header expansion. caddy-rs supports the
/// env/system/time subset here; unsupported global placeholders follow the selected mode's
/// unknown-placeholder rule (documented in DIV-0101).
fn expand_health_placeholders(
    input: &str,
    target_upstream: Option<&str>,
    mode: PlaceholderMode,
) -> String {
    let mut output = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'{' {
            if let Some(close) = input[index + 1..].find('}') {
                let close = index + 1 + close;
                let token = input[index + 1..close].trim();
                match resolve_health_placeholder(token, target_upstream) {
                    Some(value) => {
                        output.push_str(&value);
                        index = close + 1;
                    }
                    None => match mode {
                        PlaceholderMode::ReplaceKnown => {
                            // Caddy's ReplaceKnown leaves the unknown `{` in place and keeps
                            // scanning, so a known placeholder nested inside JSON braces (for
                            // example `{"token":"{env.TOKEN}"}`) still expands while the JSON
                            // braces are preserved.
                            output.push('{');
                            index += 1;
                        }
                        PlaceholderMode::ReplaceAll => {
                            index = close + 1;
                        }
                    },
                }
                continue;
            }
        }
        let ch = input[index..]
            .chars()
            .next()
            .expect("index at char boundary");
        output.push(ch);
        index += ch.len_utf8();
    }
    output
}

fn resolve_health_placeholder(token: &str, target_upstream: Option<&str>) -> Option<String> {
    if let Some(name) = token.strip_prefix("env.") {
        return Some(std::env::var(name).unwrap_or_default());
    }
    if token == "http.reverse_proxy.active.target_upstream" {
        return target_upstream.map(str::to_string);
    }
    match token {
        "system.hostname" => Some(
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|name| name.trim().to_string())
                .unwrap_or_default(),
        ),
        "system.slash" => Some(std::path::MAIN_SEPARATOR.to_string()),
        "system.os" => Some(std::env::consts::OS.to_string()),
        "system.wd" => Some(
            std::env::current_dir()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ),
        "system.arch" => Some(
            match std::env::consts::ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                "x86" => "386",
                "arm" => "arm",
                "powerpc64" => "ppc64",
                other => other,
            }
            .to_string(),
        ),
        "time.now.unix" => Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs().to_string())
                .unwrap_or_default(),
        ),
        "time.now.unix_ms" => Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis().to_string())
                .unwrap_or_default(),
        ),
        _ => None,
    }
}

/// Consecutive pass/fail counters for one upstream's active checker.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProbeCounters {
    /// Consecutive passes observed so far.
    pub passes: u32,
    /// Consecutive failures observed so far.
    pub fails: u32,
}

/// A running active-health-check scheduler.
///
/// The task probes every upstream on the configured interval (starting immediately, like Caddy),
/// then waits for the next tick. [`shutdown`](Self::shutdown) cooperatively stops it, so a server
/// config reload can tear down the old checker generation without leaking tasks.
pub struct HealthCheckScheduler {
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl HealthCheckScheduler {
    /// Spawn the periodic checker for `targets` (upstream + that upstream's bound client).
    ///
    /// Takes a snapshot of the upstream list: callers create one scheduler per handler generation.
    pub fn spawn<C>(
        check: Arc<HealthCheck>,
        targets: Vec<(Arc<Upstream>, Client<C, ClientBody>)>,
    ) -> Self
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        let (shutdown, mut receiver) = watch::channel(false);
        let interval = check.interval;
        let handle = tokio::spawn(async move {
            let mut counters: HashMap<String, ProbeCounters> = HashMap::new();
            let mut timer = tokio::time::interval(interval);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    // Err means the scheduler handle was dropped; stop just the same.
                    _ = receiver.changed() => break,
                    _ = timer.tick() => {}
                }
                for (upstream, client) in &targets {
                    if *receiver.borrow() {
                        return;
                    }
                    let probe_healthy = check.check_once(client, upstream).await;
                    check.apply_probe(
                        counters.entry(upstream.dial.clone()).or_default(),
                        probe_healthy,
                        upstream,
                    );
                }
            }
        });
        Self { shutdown, handle }
    }

    /// Stop the scheduler and wait for the task to finish.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }
}

/// Normalize a health-check URI to the path-and-query form.
///
/// Caddy parses the configured URI with `url.Parse` and only uses its path and query. Absolute
/// URLs therefore contribute their path; a bare path without a leading `/` gains one.
fn normalize_health_uri(uri: &str) -> Result<String, String> {
    if uri.starts_with('/') {
        return Ok(uri.to_string());
    }
    if uri.contains("://") {
        let parsed: http::Uri = uri
            .parse()
            .map_err(|error| format!("invalid health-check uri `{uri}`: {error}"))?;
        let mut path_and_query = parsed
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        if !path_and_query.starts_with('/') {
            path_and_query.insert(0, '/');
        }
        return Ok(path_and_query);
    }
    Ok(format!("/{uri}"))
}

fn parse_health_headers(value: &Value, path: &str) -> HttpResult<Vec<(String, String)>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "`headers` must be an object"))?;
    let mut headers = Vec::new();
    for (field, values) in object {
        // Reject invalid header names eagerly so a bad config fails at load time. Placeholder
        // header names (Caddy expands keys with `ReplaceAll` at probe time) are validated after
        // expansion instead.
        if !field.contains('{') {
            let _: http::header::HeaderName = field.parse().map_err(|error| {
                invalid(path, format!("invalid header name `{field}`: {error}"))
            })?;
        }
        let values = match values {
            Value::String(value) => vec![value.as_str()],
            Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| invalid(path, "health-check header values must be strings"))
                })
                .collect::<HttpResult<Vec<_>>>()?,
            _ => {
                return Err(invalid(
                    path,
                    "health-check header values must be a string or array of strings",
                ))
            }
        };
        for value in values {
            http::header::HeaderValue::from_str(value).map_err(|error| {
                invalid(path, format!("invalid header value for `{field}`: {error}"))
            })?;
            headers.push((field.clone(), value.to_string()));
        }
    }
    Ok(headers)
}

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// Quick request-body drain helper used by tests and the proxy path.
pub async fn drain(body: hyper::body::Incoming) -> Result<Bytes, hyper::Error> {
    body.collect().await.map(|collected| collected.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn health_client(upstream: &Upstream) -> crate::client::UpstreamClient {
        crate::client::build_upstream_client(upstream, None, false, false)
            .expect("health-check client builds")
    }

    async fn spawn_health_upstream(status: u16) -> String {
        spawn_upstream(move |_request| async move { status }).await
    }

    /// Spawn a TCP upstream that answers each request with the next status from `statuses`
    /// (clamped to the last entry) and counts requests.
    async fn spawn_upstream<F, Fut>(respond: F) -> String
    where
        F: Fn(hyper::Request<hyper::body::Incoming>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = u16> + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let respond = respond.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let respond = respond.clone();
                        async move {
                            let status = respond(request).await;
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        address.to_string()
    }

    /// Upstream that always answers `status` with `body` (for `expect_body` checks).
    /// Spawn a TCP upstream that builds a complete hyper response (status/headers/body) and can
    /// capture the probe request.
    async fn spawn_response_upstream<F, Fut>(respond: F) -> String
    where
        F: Fn(hyper::Request<hyper::body::Incoming>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = hyper::Response<Full<Bytes>>> + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let respond = respond.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let respond = respond.clone();
                        async move { Ok::<_, Infallible>(respond(request).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        address.to_string()
    }

    async fn spawn_body_upstream(status: u16, body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let service = service_fn(
                        move |_request: hyper::Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from_static(body.as_bytes())))
                                    .unwrap(),
                            )
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        address.to_string()
    }

    #[test]
    fn expect_body_is_compiled_and_invalid_regex_fails_loudly() {
        let check = HealthCheck::from_json(
            &serde_json::json!({"uri": "/health", "expect_body": "^ok$"}),
            "health_checks.active",
        )
        .unwrap()
        .expect("active check enabled");
        assert!(check.expected_body.is_some());

        let error = HealthCheck::from_json(
            &serde_json::json!({"uri": "/health", "expect_body": "("}),
            "health_checks.active",
        )
        .expect_err("invalid expect_body regex must fail loudly");
        assert!(
            error.to_string().contains("expect_body"),
            "error must be located at expect_body: {error}"
        );
    }

    #[tokio::test]
    async fn check_once_matches_expect_body_with_max_size_truncation() {
        let matching = spawn_body_upstream(200, "healthy").await;
        let upstream = Arc::new(Upstream::new(matching, false));
        let client = health_client(&upstream);
        let check = HealthCheck::from_json(
            &serde_json::json!({"uri": "/", "expect_body": "^healthy$"}),
            "health_checks.active",
        )
        .unwrap()
        .unwrap();
        assert!(check.check_once(&client, &upstream).await);

        // max_size truncates before matching, like Caddy's `io.LimitReader`.
        let long = spawn_body_upstream(200, "healthy-trailing").await;
        let upstream = Arc::new(Upstream::new(long, false));
        let client = health_client(&upstream);
        let check = HealthCheck::from_json(
            &serde_json::json!({
                "uri": "/", "expect_body": "^healthy$", "max_size": 7
            }),
            "health_checks.active",
        )
        .unwrap()
        .unwrap();
        assert!(check.check_once(&client, &upstream).await);

        // A body that does not match is a failed check.
        let mismatch = spawn_body_upstream(200, "unhealthy").await;
        let upstream = Arc::new(Upstream::new(mismatch, false));
        let client = health_client(&upstream);
        let check = HealthCheck::from_json(
            &serde_json::json!({"uri": "/", "expect_body": "^healthy$"}),
            "health_checks.active",
        )
        .unwrap()
        .unwrap();
        assert!(!check.check_once(&client, &upstream).await);
    }

    #[test]
    fn status_matching_supports_exact_codes_and_classes() {
        assert!(status_matches(http::StatusCode::OK, 200));
        assert!(!status_matches(http::StatusCode::OK, 201));
        assert!(status_matches(http::StatusCode::BAD_GATEWAY, 5));
        assert!(status_matches(http::StatusCode::INTERNAL_SERVER_ERROR, 5));
        assert!(!status_matches(http::StatusCode::NOT_FOUND, 5));
        assert!(status_matches(http::StatusCode::NO_CONTENT, 2));
    }

    #[test]
    fn parses_active_health_check_configuration() {
        let check = HealthCheck::from_json(
            &serde_json::json!({
                "uri": "/healthz?probe=1",
                "method": "POST",
                "body": "ping",
                "interval": 1_500_000_000u64,
                "timeout": 250_000_000u64,
                "passes": 3,
                "fails": 2,
                "expect_status": 2,
                "headers": {"X-Probe": ["1", "2"], "X-Other": "yes"}
            }),
            "health_checks.active",
        )
        .unwrap()
        .expect("active checks enabled");

        assert_eq!(check.uri, "/healthz?probe=1");
        assert_eq!(check.method, http::Method::POST);
        assert_eq!(check.body, Bytes::from_static(b"ping"));
        assert_eq!(check.interval, Duration::from_millis(1500));
        assert_eq!(check.timeout, Duration::from_millis(250));
        assert_eq!(check.passes, 3);
        assert_eq!(check.fails, 2);
        assert_eq!(check.expected_status, Some(2));
        // serde_json map ordering is not significant: compare as a sorted multiset.
        let mut headers = check.headers.clone();
        headers.sort();
        assert_eq!(
            headers,
            vec![
                ("X-Other".to_string(), "yes".to_string()),
                ("X-Probe".to_string(), "1".to_string()),
                ("X-Probe".to_string(), "2".to_string()),
            ]
        );
    }

    #[test]
    fn parses_deprecated_path_alias_and_normalizes_uri() {
        let check = HealthCheck::from_json(
            &serde_json::json!({"path": "health"}),
            "health_checks.active",
        )
        .unwrap()
        .expect("enabled");
        assert_eq!(check.uri, "/health");

        let check = HealthCheck::from_json(
            &serde_json::json!({"uri": "http://example.com/probe?x=1"}),
            "health_checks.active",
        )
        .unwrap()
        .expect("enabled");
        assert_eq!(check.uri, "/probe?x=1");
    }

    #[test]
    fn active_config_without_uri_is_disabled_like_caddy() {
        let parsed = HealthCheck::from_json(
            &serde_json::json!({"interval": 1_000_000_000u64}),
            "health_checks.active",
        )
        .unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn defaults_match_caddy() {
        let check =
            HealthCheck::from_json(&serde_json::json!({"uri": "/"}), "health_checks.active")
                .unwrap()
                .unwrap();
        assert_eq!(check.method, http::Method::GET);
        assert_eq!(check.interval, Duration::from_secs(30));
        assert_eq!(check.timeout, Duration::from_secs(5));
        assert_eq!(check.passes, 1);
        assert_eq!(check.fails, 1);
        assert_eq!(check.expected_status, None);
    }

    #[test]
    fn unsupported_active_options_fail_loudly() {
        for (config, tracking_id) in [
            (
                serde_json::json!({"uri": "/", "port": 9000}),
                "PROXY-HEALTH-PORT",
            ),
            (
                serde_json::json!({"uri": "/", "upstream": "localhost:9000"}),
                "PROXY-HEALTH-UPSTREAM",
            ),
            (
                serde_json::json!({"uri": "/", "follow_redirects": true}),
                "PROXY-HEALTH-REDIRECT",
            ),
        ] {
            let error = HealthCheck::from_json(&config, "health_checks.active")
                .expect_err("unsupported option must fail");
            assert!(error.to_string().contains(tracking_id), "{error}");
        }
    }

    #[test]
    fn probe_thresholds_flip_and_reset_health() {
        let upstream = Upstream::new("localhost:9", false);
        let check = HealthCheck {
            fails: 2,
            passes: 2,
            ..HealthCheck::default()
        };
        let mut counters = ProbeCounters::default();

        check.apply_probe(&mut counters, false, &upstream);
        assert!(upstream.is_healthy(), "one failure below the threshold");
        check.apply_probe(&mut counters, true, &upstream);
        assert_eq!(counters.fails, 0, "a pass resets the consecutive failures");

        check.apply_probe(&mut counters, false, &upstream);
        check.apply_probe(&mut counters, false, &upstream);
        assert!(
            !upstream.is_healthy(),
            "two consecutive failures mark it down"
        );
        assert_eq!(counters.fails, 0, "counters reset when health flips");

        check.apply_probe(&mut counters, true, &upstream);
        assert!(
            !upstream.is_healthy(),
            "one pass below the recovery threshold"
        );
        check.apply_probe(&mut counters, true, &upstream);
        assert!(upstream.is_healthy(), "two consecutive passes restore it");
        assert_eq!(counters.passes, 0);
    }

    #[tokio::test]
    async fn active_check_marks_healthy_upstream() {
        let dial = spawn_health_upstream(200).await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck::default();
        let client = health_client(&upstream);
        assert!(check.check_once(&client, &upstream).await);
    }

    #[tokio::test]
    async fn active_check_marks_unhealthy_on_error_status() {
        let dial = spawn_health_upstream(500).await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck::default();
        let client = health_client(&upstream);
        assert!(!check.check_once(&client, &upstream).await);
    }

    #[tokio::test]
    async fn active_check_honours_expected_status_and_headers() {
        let seen_header = Arc::new(std::sync::Mutex::new(String::new()));
        let seen_header_server = Arc::clone(&seen_header);
        let dial = spawn_upstream(move |request: hyper::Request<hyper::body::Incoming>| {
            let seen_header = Arc::clone(&seen_header_server);
            async move {
                if let Some(value) = request.headers().get("x-probe") {
                    *seen_header.lock().unwrap() = value.to_str().unwrap_or_default().to_string();
                }
                if request.method() == http::Method::HEAD {
                    204
                } else {
                    200
                }
            }
        })
        .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck {
            method: http::Method::HEAD,
            headers: vec![("X-Probe".to_string(), "yes".to_string())],
            expected_status: Some(204),
            ..HealthCheck::default()
        };
        let client = health_client(&upstream);
        assert!(check.check_once(&client, &upstream).await);
        assert_eq!(*seen_header.lock().unwrap(), "yes");
    }

    #[tokio::test]
    async fn configured_host_header_overrides_probe_host() {
        let seen_host = Arc::new(std::sync::Mutex::new(String::new()));
        let server_host = Arc::clone(&seen_host);
        let dial = spawn_upstream(move |request: hyper::Request<hyper::body::Incoming>| {
            let seen_host = Arc::clone(&server_host);
            async move {
                *seen_host.lock().unwrap() = request
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("missing")
                    .to_string();
                200
            }
        })
        .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck {
            headers: vec![("Host".to_string(), "probe.example".to_string())],
            ..HealthCheck::default()
        };
        let client = health_client(&upstream);
        assert!(check.check_once(&client, &upstream).await);
        assert_eq!(*seen_host.lock().unwrap(), "probe.example");
    }

    #[tokio::test]
    async fn active_check_sends_configured_body() {
        let seen_body = Arc::new(std::sync::Mutex::new(String::new()));
        let server_body = Arc::clone(&seen_body);
        let dial = spawn_upstream(move |request: hyper::Request<hyper::body::Incoming>| {
            let seen_body = Arc::clone(&server_body);
            async move {
                let body = request
                    .into_body()
                    .collect()
                    .await
                    .map(|collected| collected.to_bytes())
                    .unwrap_or_default();
                *seen_body.lock().unwrap() = String::from_utf8_lossy(&body).into_owned();
                200
            }
        })
        .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck {
            method: http::Method::POST,
            body: Bytes::from_static(b"probe-body"),
            ..HealthCheck::default()
        };
        let client = health_client(&upstream);
        assert!(check.check_once(&client, &upstream).await);
        assert_eq!(*seen_body.lock().unwrap(), "probe-body");
    }

    #[tokio::test]
    async fn active_check_times_out_slow_upstream() {
        let dial = spawn_upstream(move |_request| async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            200
        })
        .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck {
            timeout: Duration::from_millis(20),
            ..HealthCheck::default()
        };
        let client = health_client(&upstream);
        assert!(!check.check_once(&client, &upstream).await);
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_probes_immediately_and_stops_on_shutdown() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let dial = spawn_upstream(move |_request| {
            let hits = Arc::clone(&server_hits);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                200
            }
        })
        .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = Arc::new(HealthCheck {
            interval: Duration::from_secs(1),
            ..HealthCheck::default()
        });
        let scheduler = HealthCheckScheduler::spawn(
            check,
            vec![(Arc::clone(&upstream), crate::client::build_client())],
        );

        wait_until(|| hits.load(Ordering::SeqCst) >= 1).await;
        assert!(upstream.is_healthy(), "passing probes keep it healthy");

        // A couple of interval ticks should produce more probes.
        wait_until(|| hits.load(Ordering::SeqCst) >= 3).await;
        scheduler.shutdown().await;
        let after_shutdown = hits.load(Ordering::SeqCst);

        // Time keeps moving but the scheduler is gone: no more probes.
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(hits.load(Ordering::SeqCst), after_shutdown);
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_marks_failing_upstream_unhealthy() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let dial = spawn_upstream(move |_request| {
            let hits = Arc::clone(&server_hits);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                500
            }
        })
        .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = Arc::new(HealthCheck {
            interval: Duration::from_secs(1),
            fails: 2,
            ..HealthCheck::default()
        });
        let scheduler = HealthCheckScheduler::spawn(
            check,
            vec![(Arc::clone(&upstream), crate::client::build_client())],
        );

        wait_until(|| hits.load(Ordering::SeqCst) >= 1).await;
        assert!(upstream.is_healthy(), "one failure is below the threshold");
        wait_until(|| hits.load(Ordering::SeqCst) >= 2).await;
        wait_until(|| !upstream.is_healthy()).await;
        scheduler.shutdown().await;
    }

    /// Advance paused time in small steps and yield until `condition` holds.
    async fn wait_until(condition: impl Fn() -> bool) {
        for _ in 0..200 {
            if condition() {
                return;
            }
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
        }
        panic!("condition did not become true within the test's virtual time budget");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn active_check_works_over_unix_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("health.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let service = service_fn(move |_request| async move {
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        let upstream =
            Arc::new(Upstream::parse_dial(&format!("unix/{}", socket.display()), false).unwrap());
        let check = HealthCheck::default();
        let client = health_client(&upstream);
        assert!(check.check_once(&client, &upstream).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn active_check_fails_when_unix_socket_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("missing.sock");
        let upstream =
            Arc::new(Upstream::parse_dial(&format!("unix/{}", socket.display()), false).unwrap());
        let check = HealthCheck::default();
        let client = health_client(&upstream);
        assert!(!check.check_once(&client, &upstream).await);
    }

    #[tokio::test]
    async fn active_check_sends_configured_body_placeholders_and_content_headers() {
        std::env::set_var("CADDY_RS_W20_HEALTH_TOKEN", "s3cret");
        std::env::set_var("CADDY_RS_W20_HEADER", "Suffix");
        #[derive(Debug, Default)]
        struct Captured {
            method: String,
            body: String,
            content_length: Option<String>,
            content_type: Option<String>,
            token: Option<String>,
            suffix: Option<String>,
        }
        let captured = Arc::new(std::sync::Mutex::new(Captured::default()));
        let sink = Arc::clone(&captured);
        let dial =
            spawn_response_upstream(move |request: hyper::Request<hyper::body::Incoming>| {
                let sink = Arc::clone(&sink);
                async move {
                    let method = request.method().as_str().to_string();
                    let headers = request.headers().clone();
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .map(|collected| collected.to_bytes())
                        .unwrap_or_default();
                    let text = String::from_utf8_lossy(&body).into_owned();
                    if let Ok(mut captured) = sink.lock() {
                        *captured = Captured {
                            method,
                            body: text,
                            content_length: headers
                                .get(http::header::CONTENT_LENGTH)
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_string),
                            content_type: headers
                                .get(http::header::CONTENT_TYPE)
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_string),
                            token: headers
                                .get("x-token")
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_string),
                            suffix: headers
                                .get("x-suffix")
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_string),
                        };
                    }
                    hyper::Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::new()))
                        .expect("response")
                }
            })
            .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck::from_json(
            &serde_json::json!({
                "uri": "/health?probe=1",
                "method": "POST",
                // JSON body: known placeholders expand, unknown braces stay verbatim.
                "body": "{\"token\":\"{env.CADDY_RS_W20_HEALTH_TOKEN}\",\"keep\":\"{literal}\"}",
                "headers": {
                    "X-Token": "{env.CADDY_RS_W20_HEALTH_TOKEN}",
                    // Header names use ReplaceAll, so known env placeholders expand.
                    "X-{env.CADDY_RS_W20_HEADER}": "yes"
                }
            }),
            "health_checks.active",
        )
        .unwrap()
        .expect("active check enabled");
        let client = health_client(&upstream);
        assert!(check.check_once(&client, &upstream).await);

        let captured = captured.lock().unwrap();
        let expected_body = "{\"token\":\"s3cret\",\"keep\":\"{literal}\"}";
        assert_eq!(captured.method, "POST");
        assert_eq!(captured.body, expected_body);
        assert_eq!(
            captured.content_length.as_deref(),
            Some(expected_body.len().to_string().as_str()),
            "the probe body must carry an accurate Content-Length"
        );
        assert_eq!(
            captured.content_type, None,
            "Caddy does not set Content-Type on health probes implicitly"
        );
        assert_eq!(captured.token.as_deref(), Some("s3cret"));
        assert_eq!(captured.suffix.as_deref(), Some("yes"));
    }

    #[tokio::test(start_paused = true)]
    async fn expect_body_failures_respect_the_fails_and_passes_thresholds() {
        let body = Arc::new(std::sync::Mutex::new("bad".to_string()));
        let hits = Arc::new(AtomicUsize::new(0));
        let server_body = Arc::clone(&body);
        let server_hits = Arc::clone(&hits);
        let dial = spawn_response_upstream(move |_request| {
            let body = Arc::clone(&server_body);
            let hits = Arc::clone(&server_hits);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let body = body.lock().unwrap().clone();
                hyper::Response::builder()
                    .status(200)
                    .body(Full::new(Bytes::from(body)))
                    .expect("response")
            }
        })
        .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = Arc::new(
            HealthCheck::from_json(
                &serde_json::json!({
                    "uri": "/", "expect_body": "^ok$", "fails": 2, "passes": 2,
                    "interval": 1_000_000_000u64
                }),
                "health_checks.active",
            )
            .unwrap()
            .unwrap(),
        );
        let scheduler = HealthCheckScheduler::spawn(
            check,
            vec![(Arc::clone(&upstream), crate::client::build_client())],
        );
        wait_until(|| hits.load(Ordering::SeqCst) >= 1).await;
        assert!(
            upstream.is_healthy(),
            "one body mismatch is below the fails=2 threshold"
        );
        wait_until(|| hits.load(Ordering::SeqCst) >= 2).await;
        wait_until(|| !upstream.is_healthy()).await;

        // Recover: two matching bodies satisfy passes=2.
        *body.lock().unwrap() = "ok".to_string();
        wait_until(|| upstream.is_healthy()).await;
        scheduler.shutdown().await;
    }

    #[tokio::test]
    async fn active_check_evaluates_status_before_the_body() {
        let status_upstream = |status: u16, body: &'static str| {
            spawn_response_upstream(move |_request| async move {
                hyper::Response::builder()
                    .status(status)
                    .body(Full::new(Bytes::from_static(body.as_bytes())))
                    .expect("response")
            })
        };
        let check = HealthCheck::from_json(
            &serde_json::json!({"uri": "/", "expect_status": 200, "expect_body": "^ok$"}),
            "health_checks.active",
        )
        .unwrap()
        .unwrap();
        for (status, body, expected) in [(500, "ok", false), (200, "bad", false), (200, "ok", true)]
        {
            let dial = status_upstream(status, body).await;
            let upstream = Arc::new(Upstream::new(dial, false));
            let client = health_client(&upstream);
            assert_eq!(
                check.check_once(&client, &upstream).await,
                expected,
                "status {status} body {body:?}"
            );
        }
    }

    #[tokio::test]
    async fn expect_body_max_size_bounds_a_large_body_read() {
        let huge = {
            let mut body = b"healthy".to_vec();
            body.extend(std::iter::repeat_n(b'x', 1_048_576));
            Bytes::from(body)
        };
        let dial = spawn_response_upstream(move |_request| {
            let huge = huge.clone();
            async move {
                hyper::Response::builder()
                    .status(200)
                    .body(Full::new(huge))
                    .expect("response")
            }
        })
        .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck::from_json(
            &serde_json::json!({"uri": "/", "expect_body": "^healthy$", "max_size": 7}),
            "health_checks.active",
        )
        .unwrap()
        .unwrap();
        let client = health_client(&upstream);
        assert!(
            check.check_once(&client, &upstream).await,
            "only the first max_size bytes are inspected even for a 1 MiB body"
        );
    }

    #[tokio::test]
    async fn active_check_does_not_follow_redirects_by_default() {
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let dial = spawn_response_upstream(move |_request| {
            let hits = Arc::clone(&server_hits);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                hyper::Response::builder()
                    .status(302)
                    .header(http::header::LOCATION, "/elsewhere")
                    .body(Full::new(Bytes::from_static(b"redirect")))
                    .expect("response")
            }
        })
        .await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let client = health_client(&upstream);
        let accepts_redirect = HealthCheck::from_json(
            &serde_json::json!({"uri": "/", "expect_status": 302}),
            "health_checks.active",
        )
        .unwrap()
        .unwrap();
        assert!(accepts_redirect.check_once(&client, &upstream).await);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "Caddy's default CheckRedirect (ErrUseLastResponse) does not follow the Location"
        );
        let rejects_redirect =
            HealthCheck::from_json(&serde_json::json!({"uri": "/"}), "health_checks.active")
                .unwrap()
                .unwrap();
        assert!(!rejects_redirect.check_once(&client, &upstream).await);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
}
