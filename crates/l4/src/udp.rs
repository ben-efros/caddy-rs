//! UDP routing: datagram routes matched on peer IP and ASN, with proxy and close actions.
//!
//! UDP has no connection handshake and no SNI, so the L4 router's host-keyed [`crate::router::SniTable`]
//! cannot serve it: a datagram is routed on the fields the operator can actually match, which are the
//! peer address and its resolved autonomous system. [`UdpRouteTable`] therefore keeps its own routes
//! in configuration order.
//!
//! Order is the contract. The first route whose every matcher matches wins, and a route with no
//! matchers matches everything, so it acts as the catch-all. That mirrors Caddy's `layer4` route
//! semantics, where route order is significant and the first match terminates the search.
//!
//! QUIC ClientHello sniffing is deliberately absent: it is gated on the UDP/QUIC ADR (T-L4-012), so a
//! UDP route here matches on address metadata only and never inspects the payload.
//!
//! These tables are the routing and metering engine, not the listener. [`UdpRouteTable::dispatch`]
//! decides *what* to do with a datagram — forward it to a named upstream or drop it — and returns
//! that verdict as a [`UdpDispatch`], so the decision is verifiable without a socket; performing the
//! I/O does not live here. Binding a UDP socket, executing the verdict, and adapting `layer4`'s
//! `udp/<addr>` and `<addr>/udp` forms onto [`UdpRouteTable`] belong to T-L4-011 (the full layer4
//! config adapter), which is why `crates/config/src/layer4.rs` still rejects a UDP listener with a
//! located error naming that task. Nothing here is reachable from a Caddyfile until then; the engine
//! is built and tested first so T-L4-011 has a target to adapt onto.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use crate::matchers::ConnectionMeta;

/// What a UDP route does with a datagram once it matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpAction {
    /// Forward datagrams to an upstream and relay replies back to the peer.
    Proxy(UdpProxyConfig),
    /// Drop matched datagrams without replying.
    ///
    /// This is the "close" action for UDP: a datagram socket has no close handshake, so refusing
    /// service means discarding the datagram and, by not replying, letting the peer's own timer expire.
    Close,
}

impl UdpAction {
    /// Short, stable name used in logs, metrics labels and tests.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Proxy(_) => "proxy",
            Self::Close => "close",
        }
    }

    /// The upstream address for a proxy action, if this action proxies.
    pub fn upstream(&self) -> Option<&str> {
        match self {
            Self::Proxy(config) => Some(&config.upstream),
            Self::Close => None,
        }
    }
}

/// Where a matched datagram is proxied to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpProxyConfig {
    /// Upstream `host:port`. Validated by [`UdpProxyConfig::new`], never re-parsed on the hot path.
    upstream: String,
}

impl UdpProxyConfig {
    /// Validates an upstream `host:port`.
    ///
    /// A UDP upstream is resolved and dialled per session, so an empty host or a missing port is a
    /// configuration error the operator must see at load time rather than as silently dropped traffic.
    pub fn new(upstream: impl Into<String>) -> Result<Self, UdpRouteError> {
        let upstream = upstream.into();
        let (host, port) = upstream.rsplit_once(':').ok_or_else(|| {
            UdpRouteError::InvalidUpstream(format!(
                "upstream `{upstream}` has no port; expected host:port"
            ))
        })?;
        if host.is_empty() {
            return Err(UdpRouteError::InvalidUpstream(format!(
                "upstream `{upstream}` has an empty host"
            )));
        }
        let port: u16 = port.parse().map_err(|_| {
            UdpRouteError::InvalidUpstream(format!("upstream `{upstream}` has a non-numeric port"))
        })?;
        if port == 0 {
            return Err(UdpRouteError::InvalidUpstream(format!(
                "upstream `{upstream}` uses port 0, which cannot receive datagrams"
            )));
        }
        Ok(Self { upstream })
    }

    /// The upstream `host:port`.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }
}

/// A datagram matcher: decides whether a route applies to the peer described by [`ConnectionMeta`].
///
/// The trait is intentionally narrower than [`crate::matchers::ConnMatcher`]: a datagram matcher
/// cannot see the payload at all, which is what keeps QUIC parsing out of routing until T-L4-012.
pub trait UdpMatcher: Send + Sync {
    /// Short name used in diagnostics and route descriptions.
    fn name(&self) -> &'static str;

    /// Decides the match against the peer metadata.
    fn matches(&self, peer: &ConnectionMeta) -> bool;
}

/// Matches a peer within one IP network, in CIDR form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpMatcher {
    network: IpAddr,
    prefix: u8,
}

impl IpMatcher {
    /// Parses `addr/prefix` (or a bare address, meaning a single host).
    pub fn parse(spec: &str) -> Result<Self, UdpRouteError> {
        let (addr, prefix) = match spec.split_once('/') {
            Some((addr, prefix)) => {
                let prefix: u8 = prefix.parse().map_err(|_| {
                    UdpRouteError::InvalidMatcher(format!(
                        "`{spec}` has a non-numeric prefix length"
                    ))
                })?;
                (addr, Some(prefix))
            }
            None => (spec, None),
        };
        let network: IpAddr = addr.parse().map_err(|_| {
            UdpRouteError::InvalidMatcher(format!("`{spec}` does not contain a valid IP address"))
        })?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return Err(UdpRouteError::InvalidMatcher(format!(
                "`{spec}` has prefix length {prefix}, which exceeds {max} for {}",
                if network.is_ipv4() { "IPv4" } else { "IPv6" }
            )));
        }
        Ok(Self { network, prefix })
    }

    /// The network address this matcher covers.
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` falls inside the network.
    ///
    /// An IPv4-mapped IPv6 peer is also compared as the IPv4 address it stands for; otherwise an
    /// address family mismatch never matches.
    fn contains(&self, ip: IpAddr) -> bool {
        caddy_rs_core::net::ip_in_net(self.network, self.prefix, ip)
    }
}

impl UdpMatcher for IpMatcher {
    fn name(&self) -> &'static str {
        "ip"
    }

    fn matches(&self, peer: &ConnectionMeta) -> bool {
        peer.peer.is_some_and(|ip| self.contains(ip))
    }
}

/// Matches a peer whose resolved ASN equals `asn`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsnMatcher {
    asn: u32,
}

impl AsnMatcher {
    /// Builds a matcher for one autonomous system number.
    pub fn new(asn: u32) -> Self {
        Self { asn }
    }

    /// The ASN this matcher requires.
    pub fn asn(&self) -> u32 {
        self.asn
    }
}

impl UdpMatcher for AsnMatcher {
    fn name(&self) -> &'static str {
        "asn"
    }

    fn matches(&self, peer: &ConnectionMeta) -> bool {
        peer.asn == Some(self.asn)
    }
}

/// One UDP route: all of its matchers must match, then `action` applies.
#[derive(Clone)]
pub struct UdpRoute {
    matchers: Vec<Arc<dyn UdpMatcher>>,
    action: UdpAction,
}

impl fmt::Debug for UdpRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpRoute")
            .field(
                "matchers",
                &self.matchers.iter().map(|m| m.name()).collect::<Vec<_>>(),
            )
            .field("action", &self.action)
            .finish()
    }
}

impl UdpRoute {
    /// Builds a route from its matchers and action.
    ///
    /// An empty matcher list is allowed and means "match every datagram", which is how a catch-all
    /// route is spelled; this is a documented behaviour rather than an oversight.
    pub fn new(matchers: Vec<Arc<dyn UdpMatcher>>, action: UdpAction) -> Self {
        Self { matchers, action }
    }

    /// The route's action.
    pub fn action(&self) -> &UdpAction {
        &self.action
    }

    /// The number of matchers; zero means the route matches everything.
    pub fn matcher_count(&self) -> usize {
        self.matchers.len()
    }

    /// Whether every matcher matches `peer`.
    pub fn matches(&self, peer: &ConnectionMeta) -> bool {
        self.matchers.iter().all(|m| m.matches(peer))
    }
}

/// The set of UDP routes, searched in configuration order.
#[derive(Clone, Debug, Default)]
pub struct UdpRouteTable {
    routes: Vec<UdpRoute>,
}

impl UdpRouteTable {
    /// An empty table: every datagram is unmatched.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a table from routes in configuration order.
    pub fn from_routes(routes: Vec<UdpRoute>) -> Self {
        Self { routes }
    }

    /// Appends a route; order determines precedence.
    pub fn push(&mut self, route: UdpRoute) {
        self.routes.push(route);
    }

    /// The first route that matches `peer`, or `None` when nothing matches.
    ///
    /// First-match-wins is the same rule Caddy's `layer4` applies, so an operator's route order
    /// carries the same meaning here.
    pub fn lookup(&self, peer: &ConnectionMeta) -> Option<Arc<UdpRoute>> {
        self.routes
            .iter()
            .find(|route| route.matches(peer))
            .map(|route| Arc::new(route.clone()))
    }

    /// The index of the first matching route, for telemetry that labels by route.
    pub fn lookup_index(&self, peer: &ConnectionMeta) -> Option<usize> {
        self.routes.iter().position(|route| route.matches(peer))
    }

    /// Decides what to do with a datagram from `peer`: the first matching route's action, as a
    /// [`UdpDispatch`] a socket-binding caller can execute.
    ///
    /// Returns `None` when no route matches, which is a drop with no route to attribute it to — the
    /// caller decides whether to count it as unmatched rather than silently applying a fallback.
    pub fn dispatch(&self, peer: &ConnectionMeta) -> Option<UdpDispatch> {
        let index = self.lookup_index(peer)?;
        let route = self.routes.get(index)?;
        Some(match route.action() {
            UdpAction::Proxy(config) => UdpDispatch::Proxy {
                upstream: config.upstream().to_string(),
                route_index: index,
            },
            UdpAction::Close => UdpDispatch::Close { route_index: index },
        })
    }

    /// The number of routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the table has no routes.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// What the caller should do with one datagram, as decided by [`UdpRouteTable::dispatch`].
///
/// This is the routing verdict, deliberately not the I/O: it names the action and the route so a
/// caller binding a socket (T-L4-011) executes it, while routing stays testable without a socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpDispatch {
    /// Forward the datagram to this upstream and relay replies.
    Proxy {
        /// The upstream `host:port`.
        upstream: String,
        /// The matched route's index, for telemetry.
        route_index: usize,
    },
    /// Drop the datagram without replying.
    Close {
        /// The matched route's index, for telemetry.
        route_index: usize,
    },
}

impl UdpDispatch {
    /// The action's short name: `proxy` or `close`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Proxy { .. } => "proxy",
            Self::Close { .. } => "close",
        }
    }

    /// The matched route's index.
    pub fn route_index(&self) -> usize {
        match self {
            Self::Proxy { route_index, .. } | Self::Close { route_index } => *route_index,
        }
    }

    /// The upstream for a proxied datagram.
    pub fn upstream(&self) -> Option<&str> {
        match self {
            Self::Proxy { upstream, .. } => Some(upstream),
            Self::Close { .. } => None,
        }
    }

    /// Whether the datagram is dropped.
    pub fn is_close(&self) -> bool {
        matches!(self, Self::Close { .. })
    }
}

/// A UDP routing or configuration error, naming the offending input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpRouteError {
    /// An upstream address is not usable.
    InvalidUpstream(String),
    /// An `ip` matcher specification is not usable.
    InvalidMatcher(String),
}

impl fmt::Display for UdpRouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUpstream(message) => write!(f, "invalid UDP upstream: {message}"),
            Self::InvalidMatcher(message) => write!(f, "invalid UDP matcher: {message}"),
        }
    }
}

impl std::error::Error for UdpRouteError {}

#[cfg(test)]
mod mapped_peer_tests {
    use super::*;

    fn meta(peer: &str) -> ConnectionMeta {
        ConnectionMeta {
            peer: Some(peer.parse().unwrap()),
            asn: None,
        }
    }

    /// Datagram sockets are dual-stack too: an IPv4 peer can arrive as `::ffff:a.b.c.d`
    /// (SEC-MEDIUM-PROXY C2 review).
    #[test]
    fn udp_ip_matcher_matches_ipv4_mapped_peers() {
        let matcher = IpMatcher::parse("203.0.113.0/24").unwrap();
        assert!(matcher.matches(&meta("203.0.113.5")));
        assert!(matcher.matches(&meta("::ffff:203.0.113.5")));
        assert!(!matcher.matches(&meta("::ffff:198.51.100.5")));
        let mapped = IpMatcher::parse("::ffff:203.0.113.0/120").unwrap();
        assert!(mapped.matches(&meta("203.0.113.5")));
    }
}
