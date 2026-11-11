//! Passive health checks.
//!
//! Passive checks observe real proxied requests instead of probing in the background. A failed
//! request (transport error, a configured `unhealthy_status`, or a roundtrip slower than
//! `unhealthy_latency`) is remembered for `fail_duration`; while the number of remembered
//! failures is at least `max_fails`, selection policies skip the upstream. Once the failures age
//! out, the upstream is available again — Caddy's "remove temporarily, restore automatically"
//! recovery model.
//!
//! Caddy stores this state in a `Host` struct keyed by dial address and shared globally through a
//! usage pool; caddy-rs keeps one [`PassiveHealth`] per handler. That is behaviourally equivalent
//! for a single handler and documented as a divergence for multi-handler configs.
//!
//! The state machine is clock-injected: every method takes the current [`Instant`], so tests can
//! drive transitions with a fake clock and no sleeps.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use caddy_rs_http::{Error as HttpError, Result as HttpResult};
use http::StatusCode;
use serde_json::Value;

use crate::health::status_matches;

/// Caddy `health_checks.passive` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassiveHealthConfig {
    /// How long a failed request is remembered. `0` disables passive health checking.
    pub fail_duration: Duration,
    /// Number of remembered failures at which an upstream is considered down (default 1).
    pub max_fails: u32,
    /// Response status codes that count as failed requests. Values below 100 match a status class.
    pub unhealthy_status: Vec<u16>,
    /// Roundtrip latency at or above which a request counts as failed.
    pub unhealthy_latency: Duration,
    /// Maximum number of simultaneous requests to an upstream; `0` means unlimited.
    pub unhealthy_request_count: usize,
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        Self {
            fail_duration: Duration::ZERO,
            max_fails: 1,
            unhealthy_status: Vec::new(),
            unhealthy_latency: Duration::ZERO,
            unhealthy_request_count: 0,
        }
    }
}

impl PassiveHealthConfig {
    /// Parse a `health_checks.passive` object. Caddy applies `max_fails: 1` when it is unset or 0.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`health_checks.passive` must be an object"))?;
        let mut config = Self {
            fail_duration: object
                .get("fail_duration")
                .and_then(Value::as_u64)
                .map(Duration::from_nanos)
                .unwrap_or(Duration::ZERO),
            ..Self::default()
        };
        config.max_fails = object
            .get("max_fails")
            .and_then(Value::as_u64)
            .map(|max_fails| u32::try_from(max_fails).unwrap_or(u32::MAX))
            .unwrap_or(1)
            .max(1);
        if let Some(statuses) = object.get("unhealthy_status") {
            let entries = statuses.as_array().ok_or_else(|| {
                invalid(
                    &format!("{path}.unhealthy_status"),
                    "`unhealthy_status` must be an array of status codes",
                )
            })?;
            for (index, entry) in entries.iter().enumerate() {
                let code = entry.as_u64().ok_or_else(|| {
                    invalid(
                        &format!("{path}.unhealthy_status[{index}]"),
                        "status codes must be non-negative integers",
                    )
                })?;
                config
                    .unhealthy_status
                    .push(u16::try_from(code).map_err(|_| {
                        invalid(
                            &format!("{path}.unhealthy_status[{index}]"),
                            "status code must fit in a u16",
                        )
                    })?);
            }
        }
        config.unhealthy_latency = object
            .get("unhealthy_latency")
            .and_then(Value::as_u64)
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);
        config.unhealthy_request_count = object
            .get("unhealthy_request_count")
            .and_then(Value::as_u64)
            .map(|count| usize::try_from(count).unwrap_or(usize::MAX))
            .unwrap_or(0);
        Ok(config)
    }

    /// Whether passive failure counting is enabled (Caddy requires a non-zero `fail_duration`).
    pub fn is_failure_tracking_enabled(&self) -> bool {
        !self.fail_duration.is_zero()
    }
}

/// Mutable per-upstream passive-check state.
#[derive(Debug, Default)]
struct HostState {
    /// Unexpired failure timestamps, oldest first.
    failures: Vec<Instant>,
}

/// Passive health-check state for the upstreams of one handler.
#[derive(Debug)]
pub struct PassiveHealth {
    config: PassiveHealthConfig,
    hosts: Mutex<HashMap<String, HostState>>,
}

impl PassiveHealth {
    /// Create a state machine from parsed configuration.
    pub fn new(config: PassiveHealthConfig) -> Self {
        Self {
            config,
            hosts: Mutex::new(HashMap::new()),
        }
    }

    /// Parse `health_checks.passive` directly into a state machine.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        Ok(Self::new(PassiveHealthConfig::from_json(value, path)?))
    }

    /// The configuration backing this state machine.
    pub fn config(&self) -> &PassiveHealthConfig {
        &self.config
    }

    /// Remember one failed request for `host` at `now`.
    ///
    /// Returns whether a failure was counted (it is a no-op when `fail_duration` is 0).
    pub fn record_failure(&self, host: &str, now: Instant) -> bool {
        if !self.config.is_failure_tracking_enabled() {
            return false;
        }
        // INFEASIBLE: the guarded section only touches a BTreeMap/Vec, so the mutex cannot be poisoned.
        let mut hosts = self.hosts.lock().expect("passive health state lock");
        let state = hosts.entry(host.to_string()).or_default();
        prune_expired(state, now, self.config.fail_duration);
        state.failures.push(now);
        true
    }

    /// Observe one completed upstream response.
    ///
    /// Counts one failure per matching `unhealthy_status` entry (Caddy iterates all entries and
    /// calls `countFailure` for each match) plus one when the roundtrip latency reached
    /// `unhealthy_latency`. Returns the number of failures counted.
    pub fn record_response(
        &self,
        host: &str,
        status: StatusCode,
        latency: Duration,
        now: Instant,
    ) -> u32 {
        if !self.config.is_failure_tracking_enabled() {
            return 0;
        }
        let mut failures = 0;
        for configured in &self.config.unhealthy_status {
            if status_matches(status, *configured) {
                failures += 1;
            }
        }
        if !self.config.unhealthy_latency.is_zero() && latency >= self.config.unhealthy_latency {
            failures += 1;
        }
        if failures == 0 {
            return 0;
        }
        // INFEASIBLE: the guarded section only touches a BTreeMap/Vec, so the mutex cannot be poisoned.
        let mut hosts = self.hosts.lock().expect("passive health state lock");
        let state = hosts.entry(host.to_string()).or_default();
        prune_expired(state, now, self.config.fail_duration);
        for _ in 0..failures {
            state.failures.push(now);
        }
        failures
    }

    /// Number of failures still remembered for `host` at `now`.
    pub fn failures(&self, host: &str, now: Instant) -> usize {
        if !self.config.is_failure_tracking_enabled() {
            return 0;
        }
        // INFEASIBLE: the guarded section only touches a BTreeMap/Vec, so the mutex cannot be poisoned.
        let mut hosts = self.hosts.lock().expect("passive health state lock");
        let Some(state) = hosts.get_mut(host) else {
            return 0;
        };
        prune_expired(state, now, self.config.fail_duration);
        state.failures.len()
    }

    /// Caddy `Upstream.Healthy()`'s passive part: fewer than `max_fails` remembered failures.
    pub fn is_healthy(&self, host: &str, now: Instant) -> bool {
        if !self.config.is_failure_tracking_enabled() {
            return true;
        }
        (self.failures(host, now) as u64) < u64::from(self.config.max_fails)
    }

    /// Caddy `Upstream.Available()`'s passive part: healthy and below the simultaneous-request
    /// limit when one is configured.
    pub fn is_available(&self, host: &str, now: Instant, in_flight: usize) -> bool {
        if !self.is_healthy(host, now) {
            return false;
        }
        self.config.unhealthy_request_count == 0 || in_flight < self.config.unhealthy_request_count
    }
}

fn prune_expired(state: &mut HostState, now: Instant, fail_duration: Duration) {
    state.failures.retain(|recorded| {
        now.checked_duration_since(*recorded)
            .is_none_or(|age| age < fail_duration)
    });
}

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use caddy_rs_http::Response;
    use http::HeaderMap;

    fn config() -> PassiveHealthConfig {
        PassiveHealthConfig {
            fail_duration: Duration::from_secs(10),
            max_fails: 2,
            ..PassiveHealthConfig::default()
        }
    }

    #[test]
    fn failures_are_remembered_until_the_window_expires() {
        let passive = PassiveHealth::new(config());
        let start = Instant::now();

        assert!(passive.record_failure("upstream:9000", start));
        assert!(passive.is_healthy("upstream:9000", start));
        assert_eq!(passive.failures("upstream:9000", start), 1);

        passive.record_failure("upstream:9000", start + Duration::from_secs(1));
        assert!(
            !passive.is_healthy("upstream:9000", start + Duration::from_secs(1)),
            "two failures reach max_fails"
        );

        assert!(
            passive.is_healthy("upstream:9000", start + Duration::from_secs(10)),
            "the first failure expires exactly at fail_duration"
        );
        assert!(
            passive.is_healthy("upstream:9000", start + Duration::from_secs(12)),
            "all failures eventually expire and the upstream is restored"
        );
    }

    #[test]
    fn failure_state_is_per_upstream() {
        let passive = PassiveHealth::new(config());
        let start = Instant::now();
        passive.record_failure("a:1", start);
        passive.record_failure("a:1", start);
        assert!(!passive.is_healthy("a:1", start));
        assert!(passive.is_healthy("b:2", start));
    }

    #[test]
    fn zero_fail_duration_disables_failure_tracking() {
        let passive = PassiveHealth::new(PassiveHealthConfig {
            fail_duration: Duration::ZERO,
            max_fails: 1,
            ..PassiveHealthConfig::default()
        });
        let now = Instant::now();
        assert!(!passive.record_failure("a:1", now));
        assert_eq!(passive.failures("a:1", now), 0);
        assert!(passive.is_healthy("a:1", now));
    }

    #[test]
    fn unhealthy_status_matches_exact_codes_and_classes() {
        let passive = PassiveHealth::new(PassiveHealthConfig {
            unhealthy_status: vec![502, 5, 429],
            ..config()
        });
        let now = Instant::now();

        assert_eq!(
            passive.record_response("a:1", StatusCode::BAD_GATEWAY, Duration::ZERO, now),
            2,
            "502 matches both the exact code and class 5"
        );
        assert_eq!(
            passive.record_response("a:1", StatusCode::SERVICE_UNAVAILABLE, Duration::ZERO, now),
            1,
            "503 matches class 5"
        );
        assert_eq!(
            passive.record_response("a:1", StatusCode::TOO_MANY_REQUESTS, Duration::ZERO, now),
            1
        );
        assert_eq!(
            passive.record_response("a:1", StatusCode::OK, Duration::ZERO, now),
            0
        );
        assert_eq!(
            passive.record_response("a:1", StatusCode::NOT_FOUND, Duration::ZERO, now),
            0
        );
    }

    #[test]
    fn unhealthy_latency_counts_failure_at_threshold() {
        let passive = PassiveHealth::new(PassiveHealthConfig {
            unhealthy_latency: Duration::from_millis(100),
            ..config()
        });
        let now = Instant::now();
        assert_eq!(
            passive.record_response("a:1", StatusCode::OK, Duration::from_millis(99), now),
            0
        );
        assert_eq!(
            passive.record_response("a:1", StatusCode::OK, Duration::from_millis(100), now),
            1,
            "latency at the threshold counts as failed"
        );
    }

    #[test]
    fn unavailable_while_at_the_simultaneous_request_limit() {
        let passive = PassiveHealth::new(PassiveHealthConfig {
            unhealthy_request_count: 2,
            ..config()
        });
        let now = Instant::now();
        assert!(passive.is_available("a:1", now, 0));
        assert!(passive.is_available("a:1", now, 1));
        assert!(
            !passive.is_available("a:1", now, 2),
            "reaching unhealthy_request_count removes the upstream"
        );
    }

    #[test]
    fn response_failures_remove_upstream_until_window_expires() {
        let passive = PassiveHealth::new(PassiveHealthConfig {
            max_fails: 1,
            unhealthy_status: vec![502],
            ..config()
        });
        let start = Instant::now();
        assert_eq!(
            passive.record_response("a:1", StatusCode::BAD_GATEWAY, Duration::ZERO, start),
            1
        );
        assert!(!passive.is_healthy("a:1", start));
        assert!(passive.is_healthy("a:1", start + Duration::from_secs(10)));
    }

    #[test]
    fn parses_passive_configuration() {
        let config = PassiveHealthConfig::from_json(
            &serde_json::json!({
                "fail_duration": 10_000_000_000u64,
                "max_fails": 3,
                "unhealthy_status": [502, 5],
                "unhealthy_latency": 2_000_000_000u64,
                "unhealthy_request_count": 16
            }),
            "health_checks.passive",
        )
        .unwrap();
        assert_eq!(config.fail_duration, Duration::from_secs(10));
        assert_eq!(config.max_fails, 3);
        assert_eq!(config.unhealthy_status, vec![502, 5]);
        assert_eq!(config.unhealthy_latency, Duration::from_secs(2));
        assert_eq!(config.unhealthy_request_count, 16);
    }

    #[test]
    fn max_fails_defaults_to_one_like_caddy() {
        let config = PassiveHealthConfig::from_json(
            &serde_json::json!({"fail_duration": 1_000_000u64}),
            "health_checks.passive",
        )
        .unwrap();
        assert_eq!(config.max_fails, 1);
        let config = PassiveHealthConfig::from_json(
            &serde_json::json!({"max_fails": 0}),
            "health_checks.passive",
        )
        .unwrap();
        assert_eq!(config.max_fails, 1);
    }

    #[test]
    fn record_response_is_a_no_op_without_fail_duration() {
        let passive = PassiveHealth::new(PassiveHealthConfig {
            max_fails: 1,
            unhealthy_status: vec![502],
            ..PassiveHealthConfig::default()
        });
        let now = Instant::now();
        assert_eq!(
            passive.record_response("a:1", StatusCode::BAD_GATEWAY, Duration::ZERO, now),
            0
        );
        assert!(passive.is_healthy("a:1", now));
    }

    #[test]
    fn response_type_is_usable_for_handler_hooks() {
        // Guards the integration contract: the handler counts failures from a `Response`.
        let response = Response {
            status: StatusCode::BAD_GATEWAY,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        let passive = PassiveHealth::new(PassiveHealthConfig {
            unhealthy_status: vec![502],
            ..config()
        });
        let now = Instant::now();
        assert_eq!(
            passive.record_response("a:1", response.status, Duration::ZERO, now),
            1
        );
    }
}
