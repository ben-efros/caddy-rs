//! Per-route UDP packet and byte counters.
//!
//! The counters follow ADR-029's cardinality rule: a label value comes from the operator's allowlist
//! when it is there and falls back to the static `_other` value when it is not, so a spoofed source
//! address cannot create an unbounded set of time series. UDP makes that rule load-bearing rather
//! than merely tidy, because a datagram peer address is attacker-chosen on every packet.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use caddy_rs_admin::metrics::{Counter, MetricsError, MetricsRegistry};

/// The metric name for datagrams received per route.
pub const PACKETS_TOTAL: &str = "caddy_l4_udp_packets_total";
/// The metric name for payload bytes received per route.
pub const BYTES_TOTAL: &str = "caddy_l4_udp_bytes_total";
/// The label naming the matched route.
pub const ROUTE_LABEL: &str = "route";
/// The label value used for a peer whose route is not in the allowlist.
pub const OTHER_LABEL: &str = "_other";

/// Maps a route identity to the label value used in metrics.
///
/// When the allowlist is empty every route reports as `_other`; that is the documented behaviour of
/// a disabled allowlist and keeps the series count at exactly one.
#[derive(Clone, Debug, Default)]
pub struct RouteAllowlist {
    allowed: BTreeMap<String, String>,
}

impl RouteAllowlist {
    /// An allowlist that names no routes, so every route reports as `_other`.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds an allowlist from `route id -> label value` pairs.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            allowed: pairs
                .into_iter()
                .map(|(id, label)| (id.into(), label.into()))
                .collect(),
        }
    }

    /// The label value for `route_id`.
    pub fn label_for(&self, route_id: &str) -> &str {
        self.allowed
            .get(route_id)
            .map(String::as_str)
            .unwrap_or(OTHER_LABEL)
    }

    /// The number of allowlisted routes.
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Whether the allowlist is empty.
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

/// A per-route counter pair.
#[derive(Clone, Debug)]
pub struct UdpRouteCounters {
    packets: Counter,
    bytes: Counter,
    route_label: String,
}

impl UdpRouteCounters {
    /// Adds one datagram of `bytes` payload to the route's counters.
    ///
    /// A registry error means the series was registered with a different kind, which is a programming
    /// error; telemetry must never fail a datagram, so the error is deliberately swallowed the same
    /// way the established L4 byte meter does.
    pub fn observe(&self, packets: u64, bytes: u64) {
        let _ = self.packets.add(packets);
        let _ = self.bytes.add(bytes);
    }

    /// The label value these counters are reported under.
    pub fn route_label(&self) -> &str {
        &self.route_label
    }
}

/// The UDP metrics handle: per-route counters, bounded by the allowlist.
#[derive(Clone, Debug)]
pub struct UdpMetrics {
    registry: MetricsRegistry,
    allowlist: RouteAllowlist,
}

impl UdpMetrics {
    /// Builds a metrics handle over `registry`, labelling routes through `allowlist`.
    pub fn new(registry: MetricsRegistry, allowlist: RouteAllowlist) -> Self {
        Self {
            registry,
            allowlist,
        }
    }

    /// The allowlist.
    pub fn allowlist(&self) -> &RouteAllowlist {
        &self.allowlist
    }

    /// The counters for `route_id`, registered on first use.
    pub fn counters(&self, route_id: &str) -> Result<UdpRouteCounters, MetricsError> {
        let label = self.allowlist.label_for(route_id).to_string();
        let packets = self.registry.counter(
            PACKETS_TOTAL,
            "Total UDP datagrams received, by route.",
            &[(ROUTE_LABEL, label.as_str())],
        )?;
        let bytes = self.registry.counter(
            BYTES_TOTAL,
            "Total UDP payload bytes received, by route.",
            &[(ROUTE_LABEL, label.as_str())],
        )?;
        Ok(UdpRouteCounters {
            packets,
            bytes,
            route_label: label,
        })
    }
}

/// A UDP telemetry error, naming what failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpMetricsError {
    /// The metrics registry rejected the series.
    Registry(String),
}

impl fmt::Display for UdpMetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(message) => write!(f, "cannot register UDP metric series: {message}"),
        }
    }
}

impl std::error::Error for UdpMetricsError {}

impl From<MetricsError> for UdpMetricsError {
    fn from(error: MetricsError) -> Self {
        Self::Registry(error.to_string())
    }
}

/// Keeps a `UdpMetrics` reachable from a shared cell without cloning the registry on each datagram.
pub type SharedUdpMetrics = Arc<UdpMetrics>;
