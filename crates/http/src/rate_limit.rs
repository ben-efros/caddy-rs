//! caddy-rs extension: token-bucket rate limiting (`http.handlers.rate_limit`).
//!
//! **This is not a Caddy v2.11.7 built-in module.** Upstream Caddy has no `rate_limit` module in
//! `modules/caddyhttp/` or in the shipped Caddyfile directive list in this checkout; rate limiting
//! upstream is a plugin (`github.com/mholt/caddy-ratelimit`). caddy-rs therefore implements this
//! handler as a clearly-marked extension using Caddy's handler module conventions, with no claim of
//! Caddy configuration parity. The extension is registered only in this crate (the `crates/core`
//! module inventory/node registry is not edited by this task; see the task report for the entry the
//! Lead should add).
//!
//! # JSON configuration
//!
//! ```json
//! {
//!   "handler": "rate_limit",
//!   "rate": "10r/s",
//!   "burst": 20,
//!   "key": "{http.request.remote.host}",
//!   "max_keys": 10000,
//!   "status_code": 429,
//!   "headers": {"X-RateLimit-Realm": ["default"]},
//!   "body": "rate limit exceeded"
//! }
//! ```
//!
//! * `rate` (required): token replenishment rate written as `<count>/<duration>`; the optional `r`
//!   suffix is accepted (`10r/s`, `60/m`, `2r/500ms`, `1/2s`). Durations support `ms`, `s`, `m`,
//!   `h`, and plain seconds.
//! * `burst` (optional): token-bucket capacity in requests; defaults to `ceil(rate)` clamped to at
//!   least 1.
//! * `key` (optional): placeholder expression used to select a bucket, expanded with `ReplaceAll`
//!   semantics at request time; defaults to `{http.request.remote.host}`. An empty expansion is
//!   keyed as `"<unknown>"` so requests without a peer address share one bucket. Expansions longer
//!   than 256 bytes are hashed to `sha256:<64 lowercase hex chars>` before use as the bucket key,
//!   so attacker-controlled placeholders cannot inflate per-bucket memory.
//! * `max_keys` (optional): bound on the number of live buckets (default 10000). At the bound,
//!   fully refilled (idle) buckets are evicted oldest-first; if every bucket is still consuming
//!   tokens, new keys are rate limited rather than growing the map without bound.
//! * `status_code` (optional): response status for limited requests (default `429`).
//! * `headers` (optional): response headers for limited requests, values expanded as placeholders
//!   and appended in order.
//! * `body` (optional): response body for limited requests, expanded as placeholders.
//!
//! Limited responses always include `Retry-After` with the whole-second wait until one token is
//! available (at least 1). Allowed requests continue down the handler chain (the handler is a
//! non-terminal middleware); place it in a route before the handlers it should protect, optionally
//! under a path/host matcher so those routes bypass the limiter. The limiter is process-local (not
//! distributed across instances/reloads) and refills from a monotonic clock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use sha2::{Digest, Sha256};

use crate::types::{Error, Handler, Outcome, Request, Response, Result};

/// Monotonic clock abstraction used by the limiter. Tests inject [`ManualClock`] for deterministic
/// refill/eviction behaviour; production uses [`SystemClock`].
pub trait RateLimitClock: Send + Sync {
    /// Current monotonic time.
    fn now(&self) -> Instant;
}

/// Production clock backed by [`Instant::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl RateLimitClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Manually advanced clock for deterministic tests.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<Instant>,
}

impl ManualClock {
    /// Create a clock starting at the current monotonic instant.
    pub fn new() -> Self {
        Self {
            now: Mutex::new(Instant::now()),
        }
    }

    /// Advance the clock, ignoring overflow (tests only advance small amounts).
    pub fn advance(&self, duration: Duration) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *now += duration;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitClock for ManualClock {
    fn now(&self) -> Instant {
        *self
            .now
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Debug)]
struct RateLimitConfig {
    rate_per_second: f64,
    burst: u32,
    key: String,
    max_keys: usize,
    status: StatusCode,
    headers: Vec<(HeaderName, String)>,
    body: String,
}

/// A single token bucket. `tokens` may be fractional; a request consumes one whole token.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
struct LimiterState {
    buckets: HashMap<String, Bucket>,
}

/// Token-bucket limiter with per-key buckets and a bounded idle-evicting map.
struct TokenBucketLimiter {
    config: Arc<RateLimitConfig>,
    clock: Arc<dyn RateLimitClock>,
    state: Mutex<LimiterState>,
}

impl std::fmt::Debug for TokenBucketLimiter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenBucketLimiter")
            .field("config", &self.config)
            .field(
                "buckets",
                &self.state.lock().map(|state| state.buckets.len()),
            )
            .finish()
    }
}

/// Result of one admission attempt.
#[derive(Debug, Clone, Copy)]
struct Admission {
    allowed: bool,
    retry_after: Duration,
}

impl TokenBucketLimiter {
    fn new(config: Arc<RateLimitConfig>, clock: Arc<dyn RateLimitClock>) -> Self {
        Self {
            config,
            clock,
            state: Mutex::new(LimiterState {
                buckets: HashMap::new(),
            }),
        }
    }

    fn check(&self, key: &str) -> Admission {
        let now = self.clock.now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let rate = self.config.rate_per_second;
        let burst = f64::from(self.config.burst);

        if !state.buckets.contains_key(key) && state.buckets.len() >= self.config.max_keys {
            evict_idle_buckets(&mut state.buckets, now, rate, burst, self.config.max_keys);
            if state.buckets.len() >= self.config.max_keys {
                // The map is full of active buckets: fail closed for a *new* key so memory stays
                // bounded and existing keys keep their exact bucket state.
                return Admission {
                    allowed: false,
                    retry_after: Duration::from_secs(1),
                };
            }
        }

        let bucket = state.buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
        });
        refill(bucket, now, rate, burst);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Admission {
                allowed: true,
                retry_after: Duration::ZERO,
            }
        } else {
            // Clamp before constructing a `Duration` so an extremely small configured rate cannot
            // panic on out-of-range seconds; a century is already far beyond a useful Retry-After.
            let seconds = ((1.0 - bucket.tokens) / rate)
                .max(0.0)
                .min(f64::from(u32::MAX));
            Admission {
                allowed: false,
                retry_after: Duration::from_secs_f64(seconds),
            }
        }
    }

    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .buckets
            .len()
    }
}

/// Refill a bucket up to its capacity.
fn refill(bucket: &mut Bucket, now: Instant, rate: f64, burst: f64) {
    if now <= bucket.last_refill {
        // `Instant` is monotonic; a non-advancing clock must not subtract tokens.
        return;
    }
    let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
    bucket.last_refill = now;
}

/// Evict fully refilled buckets, oldest first, until the map is below its bound. This is only
/// called when a new key arrives at capacity; it cannot delete an active (token-consuming) bucket.
fn evict_idle_buckets(
    buckets: &mut HashMap<String, Bucket>,
    now: Instant,
    rate: f64,
    burst: f64,
    max_keys: usize,
) {
    let mut idle: Vec<(String, Instant)> = Vec::new();
    for (key, bucket) in buckets.iter_mut() {
        refill(bucket, now, rate, burst);
        if bucket.tokens >= burst {
            idle.push((key.clone(), bucket.last_refill));
        }
    }
    idle.sort_by_key(|(_, last_refill)| *last_refill);
    for (key, _) in idle {
        if buckets.len() < max_keys {
            break;
        }
        buckets.remove(&key);
    }
}

/// The `rate_limit` handler.
#[derive(Debug)]
pub struct RateLimitHandler {
    config: Arc<RateLimitConfig>,
    limiter: TokenBucketLimiter,
}

impl RateLimitHandler {
    /// Build from caddy-rs extension JSON using the production monotonic clock.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        Self::from_json_with_clock(value, path, Arc::new(SystemClock))
    }

    /// Build from JSON with an injected monotonic clock (deterministic tests).
    pub fn from_json_with_clock(
        value: &serde_json::Value,
        path: &str,
        clock: Arc<dyn RateLimitClock>,
    ) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "rate_limit handler must be an object"))?;
        for field in object.keys() {
            if !matches!(
                field.as_str(),
                "handler"
                    | "rate"
                    | "burst"
                    | "key"
                    | "max_keys"
                    | "status_code"
                    | "headers"
                    | "body"
            ) {
                return Err(invalid(
                    path,
                    format!(
                        "unknown rate_limit field `{field}` (supported: rate, burst, key, max_keys, status_code, headers, body)"
                    ),
                ));
            }
        }
        let rate = object
            .get("rate")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                invalid(
                    path,
                    "`rate` is required and must be a string such as `10r/s` or `60/m`",
                )
            })?;
        let rate_per_second =
            parse_rate(rate).map_err(|message| invalid(format!("{path}.rate"), message))?;

        let burst = match object.get("burst") {
            None | Some(serde_json::Value::Null) => default_burst(rate_per_second),
            Some(value) => {
                let configured = value.as_u64().ok_or_else(|| {
                    invalid(
                        format!("{path}.burst"),
                        "`burst` must be a positive integer",
                    )
                })?;
                if configured == 0 {
                    return Err(invalid(
                        format!("{path}.burst"),
                        "`burst` must be at least 1",
                    ));
                }
                u32::try_from(configured).map_err(|_| {
                    invalid(format!("{path}.burst"), "`burst` does not fit in a u32")
                })?
            }
        };

        let key = match object.get("key") {
            None | Some(serde_json::Value::Null) => "{http.request.remote.host}".to_string(),
            Some(value) => {
                let key = value.as_str().ok_or_else(|| {
                    invalid(
                        format!("{path}.key"),
                        "`key` must be a placeholder expression string",
                    )
                })?;
                if key.is_empty() {
                    return Err(invalid(
                        format!("{path}.key"),
                        "`key` must not be empty; use a placeholder such as \
                         `{http.request.remote.host}` or a literal",
                    ));
                }
                key.to_string()
            }
        };

        let max_keys = match object.get("max_keys") {
            None | Some(serde_json::Value::Null) => 10_000usize,
            Some(value) => {
                let configured = value.as_u64().ok_or_else(|| {
                    invalid(
                        format!("{path}.max_keys"),
                        "`max_keys` must be a positive integer",
                    )
                })?;
                if configured == 0 {
                    return Err(invalid(
                        format!("{path}.max_keys"),
                        "`max_keys` must be at least 1",
                    ));
                }
                usize::try_from(configured).map_err(|_| {
                    invalid(
                        format!("{path}.max_keys"),
                        "`max_keys` does not fit in usize",
                    )
                })?
            }
        };

        let status = match object.get("status_code") {
            None | Some(serde_json::Value::Null) => StatusCode::TOO_MANY_REQUESTS,
            Some(value) => {
                let configured = value.as_u64().ok_or_else(|| {
                    invalid(
                        format!("{path}.status_code"),
                        "`status_code` must be an HTTP status integer",
                    )
                })?;
                let configured = u16::try_from(configured).map_err(|_| {
                    invalid(
                        format!("{path}.status_code"),
                        "`status_code` does not fit in u16",
                    )
                })?;
                StatusCode::from_u16(configured).map_err(|error| {
                    invalid(
                        format!("{path}.status_code"),
                        format!("invalid HTTP status {configured}: {error}"),
                    )
                })?
            }
        };
        if status.as_u16() < 400 {
            return Err(invalid(
                format!("{path}.status_code"),
                "`status_code` must be an HTTP error status (>= 400)",
            ));
        }

        let mut headers = Vec::new();
        if let Some(configured) = object.get("headers") {
            let configured = configured.as_object().ok_or_else(|| {
                invalid(
                    format!("{path}.headers"),
                    "`headers` must be an object of header name to string or array of strings",
                )
            })?;
            for (name, values) in configured {
                let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                    invalid(
                        format!("{path}.headers"),
                        format!("invalid response header name `{name}`: {error}"),
                    )
                })?;
                let values: Vec<&serde_json::Value> = match values {
                    serde_json::Value::Array(values) => values.iter().collect(),
                    other => vec![other],
                };
                for value in values {
                    let value = value.as_str().ok_or_else(|| {
                        invalid(
                            format!("{path}.headers.{}", name.as_str()),
                            "response header values must be strings",
                        )
                    })?;
                    validate_header_template(value).map_err(|message| {
                        invalid(
                            format!("{path}.headers.{}", name.as_str()),
                            format!("invalid response header value: {message}"),
                        )
                    })?;
                    headers.push((name.clone(), value.to_string()));
                }
            }
        }

        let body = match object.get("body") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(value) => value
                .as_str()
                .ok_or_else(|| invalid(format!("{path}.body"), "`body` must be a string"))?
                .to_string(),
        };

        let config = Arc::new(RateLimitConfig {
            rate_per_second,
            burst,
            key,
            max_keys,
            status,
            headers,
            body,
        });
        Ok(Self {
            limiter: TokenBucketLimiter::new(Arc::clone(&config), clock),
            config,
        })
    }

    fn bucket_key(&self, request: &Request) -> String {
        let expanded = request.replace_all(&self.config.key);
        if expanded.is_empty() {
            "<unknown>".to_string()
        } else if expanded.len() > 256 {
            let hash = Sha256::digest(expanded.as_bytes());
            let mut hex = String::with_capacity(64);
            for byte in hash {
                hex.push_str(&format!("{:02x}", byte));
            }
            format!("sha256:{}", hex)
        } else {
            expanded
        }
    }

    fn limited_response(&self, request: &Request, admission: Admission) -> Outcome {
        let retry_after_seconds = admission.retry_after.as_secs_f64().ceil().max(1.0) as u64;
        let mut response = Response {
            status: self.config.status,
            headers: HeaderMap::new(),
            body: Bytes::from(request.replace_all(&self.config.body)),
        };
        // Explicit configuration wins for Retry-After as well (headers are applied after the
        // default so a configured value replaces it).
        if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
            response.headers.insert(header::RETRY_AFTER, value);
        }
        for (name, template) in &self.config.headers {
            let value = request.replace_all(template);
            if let Ok(value) = HeaderValue::from_str(&value) {
                if name == header::RETRY_AFTER {
                    response.headers.insert(name.clone(), value);
                } else {
                    response.headers.append(name.clone(), value);
                }
            }
        }
        Outcome::Respond(response)
    }
}

#[async_trait]
impl Handler for RateLimitHandler {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        let key = self.bucket_key(&request);
        let admission = self.limiter.check(&key);
        if admission.allowed {
            // Non-terminal middleware: allowed requests continue to the protected handlers.
            Ok(Outcome::Continue(request))
        } else {
            Ok(self.limited_response(&request, admission))
        }
    }
}

fn invalid(path: impl Into<String>, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.into(),
        message: message.into(),
    }
}

/// Parse `<count>[/]<duration>` (the `r` suffix is optional): `10r/s`, `60/m`, `2r/500ms`,
/// `1/2s`. The result is tokens per second and must be finite and positive.
fn parse_rate(input: &str) -> std::result::Result<f64, String> {
    let (count, duration) = input.split_once('/').ok_or_else(|| {
        format!("rate `{input}` must use `<count>/<duration>` (for example `10r/s`)")
    })?;
    let count = count.trim();
    let count = count.strip_suffix('r').unwrap_or(count).trim();
    let count: f64 = count
        .parse()
        .map_err(|_| format!("rate `{input}` has an invalid request count `{count}`"))?;
    if !count.is_finite() || count <= 0.0 {
        return Err(format!("rate `{input}` must have a positive request count"));
    }
    let seconds = parse_duration_seconds(duration.trim()).ok_or_else(|| {
        format!(
            "rate `{input}` has an invalid duration `{}`",
            duration.trim()
        )
    })?;
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err(format!("rate `{input}` must have a positive duration"));
    }
    Ok(count / seconds)
}

fn parse_duration_seconds(input: &str) -> Option<f64> {
    match input {
        "ms" => return Some(0.001),
        "s" => return Some(1.0),
        "m" => return Some(60.0),
        "h" => return Some(3600.0),
        _ => {}
    }
    if let Some(value) = input.strip_suffix("ms") {
        return value.trim().parse::<f64>().ok().map(|value| value / 1000.0);
    }
    for (suffix, multiplier) in [("s", 1.0), ("m", 60.0), ("h", 3600.0)] {
        if let Some(value) = input.strip_suffix(suffix) {
            return value
                .trim()
                .parse::<f64>()
                .ok()
                .map(|value| value * multiplier);
        }
    }
    input.parse::<f64>().ok()
}

fn default_burst(rate_per_second: f64) -> u32 {
    let burst = rate_per_second.ceil();
    if !burst.is_finite() || burst <= 0.0 {
        return 1;
    }
    if burst >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        burst as u32
    }
}

/// Validate a response header value template without expanding placeholders:
/// placeholder braces are ignored, the remaining literal must be a valid header value.
fn validate_header_template(value: &str) -> std::result::Result<(), String> {
    if value.contains('\r') || value.contains('\n') {
        return Err("header value must not contain CR/LF".to_string());
    }
    // HeaderValue rejects non-visible ASCII; placeholders are ASCII structural text, so validate
    // the template as-is (it is a valid value when braces are present).
    HeaderValue::from_str(value)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{header, Method};

    use crate::types::Request;

    fn handler(value: serde_json::Value, clock: Arc<ManualClock>) -> RateLimitHandler {
        RateLimitHandler::from_json_with_clock(&value, "handler", clock)
            .expect("valid rate_limit config")
    }

    fn manual(value: serde_json::Value) -> (RateLimitHandler, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new());
        (handler(value, Arc::clone(&clock)), clock)
    }

    fn request(key: &str) -> Request {
        let mut request = Request::new(Method::GET, "/".parse().unwrap());
        request
            .headers
            .insert("x-key", HeaderValue::from_str(key).unwrap());
        request
    }

    fn config(clock: Arc<ManualClock>, extra: serde_json::Value) -> RateLimitHandler {
        let mut value = serde_json::json!({
            "handler": "rate_limit",
            "rate": "2r/s",
            "burst": 2,
            "key": "{http.request.header.X-Key}"
        });
        if let (Some(value), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
            for (key, extra) in extra {
                value.insert(key.clone(), extra.clone());
            }
        }
        handler(value, clock)
    }

    async fn outcome(handler: &RateLimitHandler, key: &str) -> Outcome {
        handler.handle(request(key)).await.expect("rate limit")
    }

    #[tokio::test]
    async fn burst_then_rate_limited_then_refill() {
        let clock = Arc::new(ManualClock::new());
        let handler = config(
            Arc::clone(&clock),
            serde_json::json!({"body": "slow down", "headers": {"X-Reason": ["limit"]}}),
        );
        assert!(matches!(outcome(&handler, "a").await, Outcome::Continue(_)));
        assert!(matches!(outcome(&handler, "a").await, Outcome::Continue(_)));
        // Burst exhausted at t0: one token is 0.5s away, reported as 1 whole second.
        let Outcome::Respond(response) = outcome(&handler, "a").await else {
            panic!("third request must be limited");
        };
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers[header::RETRY_AFTER], "1");
        assert_eq!(response.headers["x-reason"], "limit");
        assert_eq!(response.body, Bytes::from_static(b"slow down"));

        // Half a second refills exactly one token at 2 r/s.
        clock.advance(Duration::from_millis(500));
        assert!(matches!(outcome(&handler, "a").await, Outcome::Continue(_)));
        let Outcome::Respond(response) = outcome(&handler, "a").await else {
            panic!("token consumed again");
        };
        assert_eq!(response.headers[header::RETRY_AFTER], "1");
    }

    #[tokio::test]
    async fn refill_after_interval_and_retry_after_rounds_up() {
        let clock = Arc::new(ManualClock::new());
        let handler = config(
            Arc::clone(&clock),
            serde_json::json!({"rate": "0.5r/s", "burst": 1}),
        );
        assert!(matches!(outcome(&handler, "a").await, Outcome::Continue(_)));
        let Outcome::Respond(response) = outcome(&handler, "a").await else {
            panic!("limited");
        };
        // One token needs 2s at 0.5 r/s.
        assert_eq!(response.headers[header::RETRY_AFTER], "2");
        clock.advance(Duration::from_secs(2));
        assert!(matches!(outcome(&handler, "a").await, Outcome::Continue(_)));
    }

    #[tokio::test]
    async fn independent_keys_have_independent_buckets() {
        let clock = Arc::new(ManualClock::new());
        let handler = config(
            Arc::clone(&clock),
            serde_json::json!({"rate": "1r/s", "burst": 1}),
        );
        assert!(matches!(
            outcome(&handler, "alice").await,
            Outcome::Continue(_)
        ));
        assert!(matches!(
            outcome(&handler, "bob").await,
            Outcome::Continue(_)
        ));
        let Outcome::Respond(_) = outcome(&handler, "alice").await else {
            panic!("alice exhausted");
        };
        assert!(matches!(
            outcome(&handler, "bob").await,
            Outcome::Respond(_)
        ));
    }

    #[tokio::test]
    async fn idle_buckets_are_evicted_at_the_bound() {
        let clock = Arc::new(ManualClock::new());
        let handler = config(
            Arc::clone(&clock),
            serde_json::json!({"rate": "1r/s", "burst": 1, "max_keys": 2}),
        );
        assert!(matches!(outcome(&handler, "a").await, Outcome::Continue(_)));
        assert!(matches!(outcome(&handler, "b").await, Outcome::Continue(_)));
        assert_eq!(handler.limiter.bucket_count(), 2);

        // Both buckets are still active at t0: a third key must not grow the map.
        let Outcome::Respond(response) = outcome(&handler, "c").await else {
            panic!("new key at capacity with no idle buckets must be limited");
        };
        assert_eq!(response.headers[header::RETRY_AFTER], "1");
        assert_eq!(handler.limiter.bucket_count(), 2);

        // After a full refill both old buckets are idle and evictable; a new key may take a slot.
        clock.advance(Duration::from_secs(1));
        assert!(matches!(outcome(&handler, "c").await, Outcome::Continue(_)));
        assert!(handler.limiter.bucket_count() <= 2);
    }

    #[tokio::test]
    async fn concurrent_requests_never_over_admit_the_bucket() {
        let clock = Arc::new(ManualClock::new());
        // Negligible refill so the 5-token burst is exact for this test.
        let handler = Arc::new(config(
            Arc::clone(&clock),
            serde_json::json!({"rate": "0.000001r/s", "burst": 5, "key": "global"}),
        ));
        let mut tasks = Vec::new();
        for _ in 0..50 {
            let handler = Arc::clone(&handler);
            tasks.push(tokio::spawn(async move {
                matches!(
                    handler.handle(request("global")).await.expect("rate limit"),
                    Outcome::Continue(_)
                )
            }));
        }
        let mut allowed = 0;
        let mut limited = 0;
        for task in tasks {
            if task.await.expect("task") {
                allowed += 1;
            } else {
                limited += 1;
            }
        }
        assert_eq!(allowed, 5, "exactly the burst must be admitted");
        assert_eq!(limited, 45);
    }

    #[tokio::test]
    async fn default_key_uses_remote_host_and_unknown_peers_share_one_bucket() {
        let clock = Arc::new(ManualClock::new());
        let handler = handler(
            serde_json::json!({
                "handler": "rate_limit",
                "rate": "1r/s",
                "burst": 1
            }),
            Arc::clone(&clock),
        );
        let mut first = Request::new(Method::GET, "/".parse().unwrap());
        first.remote_addr = Some("203.0.113.7:5555".parse().unwrap());
        assert!(matches!(
            handler.handle(first).await.unwrap(),
            Outcome::Continue(_)
        ));
        let mut second = Request::new(Method::GET, "/".parse().unwrap());
        second.remote_addr = Some("203.0.113.7:6666".parse().unwrap());
        let Outcome::Respond(_) = handler.handle(second).await.unwrap() else {
            panic!("same host must share the bucket");
        };
        // A request with no peer address uses the shared `<unknown>` bucket, not an empty key that
        // silently collides with other literal empty keys.
        let mut other = Request::new(Method::GET, "/".parse().unwrap());
        other.remote_addr = None;
        assert!(matches!(
            handler.handle(other).await.unwrap(),
            Outcome::Continue(_)
        ));
    }

    #[tokio::test]
    async fn key_can_use_http_vars_placeholders() {
        let clock = Arc::new(ManualClock::new());
        let handler = handler(
            serde_json::json!({
                "handler": "rate_limit",
                "rate": "1r/s",
                "burst": 1,
                "key": "{http.vars.tenant}"
            }),
            Arc::clone(&clock),
        );
        let mut alice = Request::new(Method::GET, "/".parse().unwrap());
        alice.vars.insert("tenant".to_string(), "alice".to_string());
        let mut bob = Request::new(Method::GET, "/".parse().unwrap());
        bob.vars.insert("tenant".to_string(), "bob".to_string());
        assert!(matches!(
            handler.handle(alice.clone()).await.unwrap(),
            Outcome::Continue(_)
        ));
        assert!(matches!(
            handler.handle(bob).await.unwrap(),
            Outcome::Continue(_)
        ));
        assert!(matches!(
            handler.handle(alice).await.unwrap(),
            Outcome::Respond(_)
        ));
    }

    #[test]
    fn invalid_configuration_is_rejected_loudly() {
        let clock: Arc<dyn RateLimitClock> = Arc::new(ManualClock::new());
        let cases = [
            serde_json::json!({"handler": "rate_limit"}),
            serde_json::json!({"handler": "rate_limit", "rate": "10"}),
            serde_json::json!({"handler": "rate_limit", "rate": "0r/s"}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/0s"}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/s", "burst": 0}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/s", "burst": -1}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/s", "max_keys": 0}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/s", "key": ""}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/s", "status_code": 200}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/s", "status_code": 99}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/s", "headers": {"Bad Header": ["x"]}}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/s", "headers": {"X-Test": [1]}}),
            serde_json::json!({"handler": "rate_limit", "rate": "10r/s", "unknown": true}),
        ];
        for config in cases {
            let error =
                RateLimitHandler::from_json_with_clock(&config, "handler", Arc::clone(&clock))
                    .expect_err("config must be rejected");
            assert!(
                matches!(error, Error::InvalidConfig { .. }),
                "located config error for {config}: {error}"
            );
        }
    }

    #[test]
    fn rate_and_duration_parsing_supports_r_suffix_and_units() {
        assert!((parse_rate("10r/s").unwrap() - 10.0).abs() < 1e-9);
        assert!((parse_rate("60/m").unwrap() - 1.0).abs() < 1e-9);
        assert!((parse_rate("2r/500ms").unwrap() - 4.0).abs() < 1e-9);
        assert!((parse_rate("1/2s").unwrap() - 0.5).abs() < 1e-9);
        assert!((parse_rate("0.5r/s").unwrap() - 0.5).abs() < 1e-9);
        assert!((parse_rate("1r/h").unwrap() - (1.0 / 3600.0)).abs() < 1e-12);
        assert!(parse_rate("10r/x").is_err());
        assert!(parse_rate("xr/s").is_err());
        assert_eq!(default_burst(10.0), 10);
        assert_eq!(default_burst(0.1), 1);
    }

    #[test]
    fn default_max_keys_is_ten_thousand() {
        let clock: Arc<dyn RateLimitClock> = Arc::new(ManualClock::new());
        let value = serde_json::json!({"handler": "rate_limit", "rate": "10r/s"});
        let handler = RateLimitHandler::from_json_with_clock(&value, "handler", Arc::clone(&clock))
            .expect("valid config");
        assert_eq!(handler.config.max_keys, 10_000);
    }

    #[tokio::test]
    async fn very_long_keys_are_hashed_before_bucketing() {
        let clock = Arc::new(ManualClock::new());
        let handler = config(
            Arc::clone(&clock),
            serde_json::json!({"rate": "1r/s", "burst": 1}),
        );
        let long_key = "a".repeat(500);
        // Two distinct request objects carrying the same 500-byte header must share one hashed
        // bucket, and the second must be limited: `handle` runs `bucket_key`, so this exercises
        // the production hashing path instead of calling the limiter with a precomputed key.
        assert!(matches!(
            outcome(&handler, &long_key).await,
            Outcome::Continue(_)
        ));
        assert!(matches!(
            outcome(&handler, &long_key).await,
            Outcome::Respond(_)
        ));
        let state = handler.limiter.state.lock().unwrap();
        assert_eq!(state.buckets.len(), 1);
        let stored = state.buckets.keys().next().expect("one bucket");
        assert_eq!(
            stored,
            "sha256:69206a472a1f384259f2c387211f123d3cb308ec3c29c9892333814c3ebeba22"
        );
        assert_eq!(stored.len(), 71, "sha256: + 64 lowercase hex chars");
        assert!(!state.buckets.contains_key(&long_key));
    }

    #[tokio::test]
    async fn short_keys_are_not_hashed() {
        let clock = Arc::new(ManualClock::new());
        let handler = config(Arc::clone(&clock), serde_json::json!({}));
        assert!(matches!(
            outcome(&handler, "user-1").await,
            Outcome::Continue(_)
        ));
        let state = handler.limiter.state.lock().unwrap();
        assert!(state.buckets.contains_key("user-1"));
    }
}
