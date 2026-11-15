//! Per-SNI L4 proxy metrics (T-L4-005), following ADR-029's cardinality rule.
//!
//! The SNI a client sends is attacker-controlled, so a metric labelled with it directly is an
//! unbounded-cardinality memory sink: a client can open one connection per random SNI and create
//! one time series each. [`L4Metrics`] therefore labels every series with a **route label** that
//! comes from configuration (the route's declared host pattern), never from the connection:
//!
//! - an exact route keeps its pattern (`example.com`);
//! - a wildcard route keeps its declared suffix (`*.example.com`), so all of its subdomains
//!   aggregate into one series;
//! - the fallback route (no SNI, or no match) is [`OTHER_LABEL`] (`_other`), matching ADR-029's
//!   allowlist + `_other` fallback.
//!
//! The label set is therefore bounded by the route table, which is bounded by the configuration.
//!
//! Exported series (all with the single `sni` label carrying the route label):
//!
//! | Name | Kind | Meaning |
//! |---|---|---|
//! | `caddy_l4_proxy_read_bytes_total` | counter | bytes read from clients |
//! | `caddy_l4_proxy_write_bytes_total` | counter | bytes written to clients |
//! | `caddy_l4_connections_active` | gauge | connections currently proxied |
//! | `caddy_l4_handshake_duration_seconds` | histogram | ClientHello peek/parse time |
//!
//! [`L4Metrics::connection`] hands out an [`L4Connection`], which is itself the [`ByteMeter`] the
//! metered copy charges; dropping it decrements the active gauge, so a panicked or aborted
//! connection cannot leak the gauge.

use std::sync::Arc;

use caddy_rs_admin::metrics::{Counter, Gauge, MetricsError, MetricsRegistry};

use crate::metered_copy::ByteMeter;
use crate::router::Route;

/// The label value for connections that matched no configured route (no SNI, or no match).
pub const OTHER_LABEL: &str = "_other";

/// The label name on every L4 series.
pub const SNI_LABEL: &str = "sni";

/// Metric names exported by the L4 proxy.
pub const READ_BYTES_TOTAL: &str = "caddy_l4_proxy_read_bytes_total";
/// Metric name for bytes written back to clients.
pub const WRITE_BYTES_TOTAL: &str = "caddy_l4_proxy_write_bytes_total";
/// Metric name for the live proxied-connection gauge.
pub const CONNECTIONS_ACTIVE: &str = "caddy_l4_connections_active";
/// Metric name for the ClientHello peek/parse histogram.
pub const HANDSHAKE_DURATION_SECONDS: &str = "caddy_l4_handshake_duration_seconds";

/// ADR-029's duration buckets (seconds), the same boundaries the HTTP histograms use.
pub const HANDSHAKE_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// The route label for a matched route: the configured pattern, or `_other` for the fallback.
///
/// The value is derived from configuration only — never from the connection's SNI — so the
/// series count is bounded by the route table.
pub fn route_label(route: &Route) -> &str {
    if route.host().is_empty() {
        OTHER_LABEL
    } else {
        route.host()
    }
}

/// One connection's handles into the L4 metric series.
#[derive(Debug)]
pub struct L4Connection {
    read: Counter,
    write: Counter,
    active: Gauge,
}

impl ByteMeter for L4Connection {
    fn record_read(&self, bytes: u64) {
        // A registry error here means the series was registered with a different kind, which is a
        // programming error; the copy path must not fail a connection over telemetry.
        let _ = self.read.add(bytes);
    }

    fn record_write(&self, bytes: u64) {
        let _ = self.write.add(bytes);
    }
}

impl Drop for L4Connection {
    fn drop(&mut self) {
        let _ = self.active.add(-1.0);
    }
}

/// The L4 proxy's metric registry handle.
#[derive(Clone, Debug)]
pub struct L4Metrics {
    registry: MetricsRegistry,
}

impl L4Metrics {
    /// Creates a handle onto `registry`.
    pub fn new(registry: MetricsRegistry) -> Self {
        Self { registry }
    }

    /// The underlying registry.
    pub fn registry(&self) -> &MetricsRegistry {
        &self.registry
    }

    /// Starts metering a connection matched to `route` and increments the active gauge.
    ///
    /// The returned connection must be kept alive for the duration of the copy: dropping it
    /// decrements the gauge.
    pub fn connection(&self, route: &Route) -> Result<L4Connection, MetricsError> {
        let label = route_label(route);
        let read = self.registry.counter(
            READ_BYTES_TOTAL,
            "Total bytes read from L4 clients, by route.",
            &[(SNI_LABEL, label)],
        )?;
        let write = self.registry.counter(
            WRITE_BYTES_TOTAL,
            "Total bytes written to L4 clients, by route.",
            &[(SNI_LABEL, label)],
        )?;
        let active = self.registry.gauge(
            CONNECTIONS_ACTIVE,
            "L4 proxy connections currently open, by route.",
            &[(SNI_LABEL, label)],
        )?;
        active.add(1.0)?;
        Ok(L4Connection {
            read,
            write,
            active,
        })
    }

    /// Records a completed ClientHello peek/parse for `route`.
    pub fn observe_handshake(&self, route: &Route, seconds: f64) -> Result<(), MetricsError> {
        let histogram = self.registry.histogram(
            HANDSHAKE_DURATION_SECONDS,
            "Time to peek and parse the TLS ClientHello, by route.",
            HANDSHAKE_BUCKETS,
            &[(SNI_LABEL, route_label(route))],
        )?;
        histogram.observe(seconds)
    }
}

/// A registry shared between the proxy and the admin metrics endpoint.
pub type SharedL4Metrics = Arc<L4Metrics>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{PassthroughConfig, SniAction};
    use crate::router::{RouteDefinition, SniRouter};

    /// The route the router produces for `host`, which is what the proxy meters against.
    fn route(host: &str) -> Arc<Route> {
        let router = SniRouter::new(
            vec![RouteDefinition::new(
                host,
                SniAction::Passthrough(
                    PassthroughConfig::new("127.0.0.1:9000").expect("valid upstream"),
                ),
            )
            .expect("valid route")],
            SniAction::Passthrough(
                PassthroughConfig::new("127.0.0.1:9001").expect("valid upstream"),
            ),
        )
        .expect("valid router");
        router.lookup(Some(host))
    }

    #[test]
    fn the_route_label_comes_from_configuration_not_the_connection() {
        assert_eq!(route_label(&route("example.com")), "example.com");
        assert_eq!(route_label(&route("*.example.com")), "*.example.com");
    }

    #[test]
    fn the_fallback_route_is_the_other_bucket() {
        let metrics = L4Metrics::new(MetricsRegistry::new());
        let router = SniRouter::empty(SniAction::Passthrough(
            PassthroughConfig::new("127.0.0.1:9000").expect("valid upstream"),
        ));
        let fallback = router.lookup(Some("unknown.example"));
        assert_eq!(route_label(&fallback), OTHER_LABEL);
        let _connection = metrics.connection(&fallback).expect("series registers");
        let rendered = metrics.registry().render();
        assert!(
            rendered.contains("sni=\"_other\""),
            "fallback series uses the _other bucket: {rendered}"
        );
    }
}
