//! Live `reverse_proxy` upstream counters for the admin API.
//!
//! The proxy crate owns the counters: each [`ReverseProxyHandler`](caddy_rs_proxy::ReverseProxyHandler)
//! keeps atomic per-upstream attempts/failures, and an [`UpstreamStatusSink`] tracks the handlers
//! built for one configuration generation. This module adapts the active generation's sink to the
//! admin crate's [`UpstreamStatusSource`] so `GET /reverse_proxy/upstreams` reports live values.
//!
//! The runtime builds a fresh sink for every apply and installs it only after the generation is
//! serving; a reload therefore atomically swaps the admin view and counters start from zero for the
//! new generation (Caddy likewise recreates its host pool on configuration load).

use std::sync::{Arc, RwLock};

use caddy_rs_admin::{UpstreamStatus as AdminUpstreamStatus, UpstreamStatusSource};
use caddy_rs_proxy::{UpstreamStatus, UpstreamStatusSink};

/// Adapts the active configuration generation's proxy handlers to the admin API.
#[derive(Debug, Default)]
pub struct ProxyUpstreamStatusSource {
    active: RwLock<Option<Arc<UpstreamStatusSink>>>,
}

impl ProxyUpstreamStatusSource {
    /// Create a source with no active generation (the admin endpoint reports zeros).
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Install the sink for a successfully applied generation.
    pub fn install(&self, sink: Arc<UpstreamStatusSink>) {
        *self
            .active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sink);
    }

    /// Snapshot the active generation's live counters.
    pub fn snapshot(&self) -> Vec<UpstreamStatus> {
        self.active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|sink| sink.snapshot())
            .unwrap_or_default()
    }
}

impl UpstreamStatusSource for ProxyUpstreamStatusSource {
    fn upstream_status(&self) -> Vec<AdminUpstreamStatus> {
        self.snapshot()
            .into_iter()
            .map(|status| AdminUpstreamStatus {
                address: status.address,
                num_requests: status.num_requests,
                fails: status.fails,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_source_reports_nothing() {
        let source = ProxyUpstreamStatusSource::new();
        assert!(source.upstream_status().is_empty());
    }
}
