//! Upstream selection policies.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::upstream::Upstream;

/// A load-balancing policy.
pub trait Balancer: Send + Sync {
    /// Policy name as it appears in Caddy configuration.
    fn name(&self) -> &'static str;

    /// Choose an upstream, considering only healthy ones.
    fn select(&self, upstreams: &[Arc<Upstream>]) -> Option<Arc<Upstream>>;
}

/// `first`: always the first healthy upstream.
pub struct First;

impl Balancer for First {
    fn name(&self) -> &'static str {
        "first"
    }

    fn select(&self, upstreams: &[Arc<Upstream>]) -> Option<Arc<Upstream>> {
        upstreams.iter().find(|u| u.is_healthy()).cloned()
    }
}

/// `round_robin`: rotate through healthy upstreams.
pub struct RoundRobin {
    next: AtomicUsize,
}

impl RoundRobin {
    /// Create a round-robin balancer.
    pub fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
        }
    }
}

impl Default for RoundRobin {
    fn default() -> Self {
        Self::new()
    }
}

impl Balancer for RoundRobin {
    fn name(&self) -> &'static str {
        "round_robin"
    }

    fn select(&self, upstreams: &[Arc<Upstream>]) -> Option<Arc<Upstream>> {
        if upstreams.is_empty() {
            return None;
        }
        for _ in 0..upstreams.len() {
            let index = self.next.fetch_add(1, Ordering::AcqRel) % upstreams.len();
            let upstream = &upstreams[index];
            if upstream.is_healthy() {
                return Some(Arc::clone(upstream));
            }
        }
        None
    }
}

/// `least_conn`: fewest in-flight requests.
pub struct LeastConnections;

impl Balancer for LeastConnections {
    fn name(&self) -> &'static str {
        "least_conn"
    }

    fn select(&self, upstreams: &[Arc<Upstream>]) -> Option<Arc<Upstream>> {
        upstreams
            .iter()
            .filter(|upstream| upstream.is_healthy())
            .min_by_key(|upstream| upstream.active_connections())
            .cloned()
    }
}

/// Build a balancer from Caddy's policy name. `None` returns the default (`round_robin`, which is
/// also Caddy's reverse_proxy default).
pub fn from_policy(policy: Option<&str>) -> Result<Box<dyn Balancer>, String> {
    match policy.unwrap_or("round_robin") {
        "round_robin" => Ok(Box::new(RoundRobin::new())),
        "first" => Ok(Box::new(First)),
        "least_conn" => Ok(Box::new(LeastConnections)),
        other => Err(format!(
            "load-balancing policy `{other}` is not implemented by this build"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(count: usize) -> Vec<Arc<Upstream>> {
        (0..count)
            .map(|index| Arc::new(Upstream::new(format!("localhost:{}", 9000 + index), false)))
            .collect()
    }

    #[test]
    fn first_prefers_first_healthy() {
        let pool = pool(3);
        pool[0].set_healthy(false);
        let selected = First.select(&pool).unwrap();
        assert_eq!(selected.dial, "localhost:9001");
    }

    #[test]
    fn round_robin_rotates() {
        let pool = pool(3);
        let balancer = RoundRobin::new();
        let first = balancer.select(&pool).unwrap();
        let second = balancer.select(&pool).unwrap();
        let third = balancer.select(&pool).unwrap();
        assert_ne!(first.dial, second.dial);
        assert_ne!(second.dial, third.dial);
        assert_eq!(balancer.select(&pool).unwrap().dial, first.dial);
    }

    #[test]
    fn round_robin_skips_unhealthy() {
        let pool = pool(2);
        pool[0].set_healthy(false);
        let balancer = RoundRobin::new();
        for _ in 0..4 {
            assert_eq!(balancer.select(&pool).unwrap().dial, "localhost:9001");
        }
    }

    #[test]
    fn least_connections_picks_least_busy() {
        let pool = pool(2);
        let _busy = pool[0].connection_started();
        let _busy2 = pool[0].connection_started();
        assert_eq!(
            LeastConnections.select(&pool).unwrap().dial,
            "localhost:9001"
        );
    }

    #[test]
    fn unsupported_policy_fails_by_name() {
        let error = from_policy(Some("weighted_round_robin"))
            .err()
            .expect("not implemented");
        assert!(error.contains("weighted_round_robin"), "{error}");
    }

    #[test]
    fn no_healthy_upstream_returns_none() {
        let pool = pool(2);
        pool.iter().for_each(|upstream| upstream.set_healthy(false));
        assert!(RoundRobin::new().select(&pool).is_none());
    }
}
