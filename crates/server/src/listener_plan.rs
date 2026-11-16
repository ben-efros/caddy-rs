//! The single source of truth turning a parsed configuration into its listener set.
//!
//! ADR-0047 §1 and ADR-0048 S2 require one module that decides *which* listeners a configuration
//! produces — network, host, port — so that the consumers that need that answer (the systemd
//! socket-activation matcher in [`crate::activation`] today, and the `bind-fds` helper in
//! `T-CORE-132`) cannot drift apart. Drift here is not cosmetic: a socket uploaded under one
//! identity and looked up under another is exactly the failure the no-second-source-of-truth goal
//! exists to prevent.
//!
//! # What this module is, and is not
//!
//! It computes the listener *set*. It does not bind sockets, resolve hostnames for a bind, or choose
//! socket options — those stay where they are. Keeping the plan a pure description of the configured
//! listeners is what lets it be shared safely.
//!
//! # Port ranges: supported where the configuration accepts them, expanded here
//!
//! Caddy's `ParseNetworkAddress` accepts an inclusive port **range** (`:8000-8005`) and its HTTP app
//! treats every port in the range as a distinct listener when checking for duplicates
//! (`modules/caddyhttp/app.go`, `Validate`). In caddy-rs the configuration-facing parser
//! [`ListenAddr::parse`] deliberately accepts a single `u16` port only, while `caddy respond`
//! supports ranges through its own parser (`crates/cli/src/respond.rs`, `parse_port_range`).
//!
//! This module therefore **does not reject a range as unplannable**: it expands one whenever the
//! caller supplies it, using the same inclusive semantics and the same
//! `end >= start` rule as the existing `respond` parser, so the two cannot disagree. A range that
//! reaches [`plan_listen_spec`] is expanded to its concrete ports; the plain
//! [`plan_listeners`] entry point accepts the single-port strings that `ListenAddr` parses today.
//!
//! # Scope: Unix and `fd/` sockets are excluded
//!
//! A Unix socket is matched by path, not by port, and an `fd/` bind names an inherited descriptor
//! directly. Neither has a planned port identity, so both are excluded (not rejected) and keep their
//! existing code paths. Rejecting them would make any configuration with a Unix admin socket
//! unplannable.

use std::collections::BTreeMap;
use std::fmt;

use caddy_rs_core::listen::{ListenAddr, Network};

/// Caddy's `maxPortSpan` (`external/caddy/listeners.go`): the widest range one listener may name.
const MAX_PORT_SPAN: u32 = 65535;

/// One concrete listener the configuration asks for.
///
/// This is the planned *identity* of a listener: the network, the host as configured (which may be a
/// hostname, or empty for a wildcard), and one concrete port. A port range produces one of these per
/// port, so nothing downstream has to reason about ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedListener {
    /// Transport network. Never [`Network::Unix`]: Unix sockets are outside the plan.
    pub network: Network,
    /// Host exactly as configured: `""` for a wildcard, otherwise an IP literal or a hostname.
    pub host: String,
    /// The concrete port, expanded out of any configured range.
    pub port: u16,
    /// The configured listen string this listener came from, for located errors.
    pub origin: String,
}

impl PlannedListener {
    /// The address served by this listener, in `host:port` form (`:80` for a wildcard).
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Whether this listener covers every interface (a hostless wildcard).
    pub fn is_wildcard(&self) -> bool {
        self.host.is_empty()
    }
}

impl fmt::Display for PlannedListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.network.as_str())?;
        f.write_str("/")?;
        f.write_str(&self.address())
    }
}

/// A located error produced while building the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerPlanError {
    /// The configured listen string the error is about.
    pub listen: String,
    /// Why the listener could not be planned.
    pub reason: String,
}

impl ListenerPlanError {
    fn new(listen: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            listen: listen.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ListenerPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "listener `{}`: {}", self.listen, self.reason)
    }
}

impl std::error::Error for ListenerPlanError {}

/// A listener the configuration asks for, before port ranges are expanded.
///
/// `start_port..=end_port` is inclusive; a single configured port has `start_port == end_port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenSpec {
    /// Transport network of the spec.
    pub network: Network,
    /// Host as configured (`""` for a wildcard).
    pub host: String,
    /// First port of the (possibly single-port) range.
    pub start_port: u16,
    /// Last port of the range.
    pub end_port: u16,
    /// The configured listen string this spec came from, for located errors.
    pub origin: String,
}

/// The planned listener set for a configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerPlan {
    listeners: Vec<PlannedListener>,
}

impl ListenerPlan {
    /// The concrete listeners, in a deterministic order (network, host, then port).
    pub fn listeners(&self) -> &[PlannedListener] {
        &self.listeners
    }

    /// The number of concrete listeners the plan covers. A port range contributes more than one.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Whether the configuration produced no planned listeners at all.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }

    /// The planned listener serving exactly `network`, `host` and `port`, if the configuration asks
    /// for it.
    ///
    /// This is the whole matching surface the activation code needs; it replaces the previous
    /// bespoke comparison rather than sitting beside it (ADR-0047 §1).
    pub fn find(&self, network: Network, host: &str, port: u16) -> Option<&PlannedListener> {
        self.listeners.iter().find(|listener| {
            listener.network == network && listener.host == host && listener.port == port
        })
    }

    /// Planned listeners grouped by network name, for callers that need the set per transport.
    ///
    /// Keyed by [`Network::as_str`] rather than by [`Network`] itself: `Network` derives `Hash` but
    /// not `Ord`, and widening a shared core enum's trait set to serve this grouping would be a
    /// wider change than the refactor needs.
    pub fn by_network(&self) -> BTreeMap<&'static str, Vec<&PlannedListener>> {
        let mut grouped: BTreeMap<&'static str, Vec<&PlannedListener>> = BTreeMap::new();
        for listener in &self.listeners {
            grouped
                .entry(listener.network.as_str())
                .or_default()
                .push(listener);
        }
        grouped
    }
}

/// Build the listener plan for a set of configured listen strings (one port each).
///
/// This is the entry point for the strings [`ListenAddr::parse`] accepts, which is what the HTTP
/// server's `listen` configuration holds today. Listen strings are processed in sorted order so the
/// plan is deterministic regardless of the order the configuration supplied them in.
///
/// Unix sockets and `fd/` binds are skipped rather than rejected — they are outside the plan's scope
/// (see the module documentation).
///
/// Port `0` is **planned, not rejected, on this entry point**. A configured `:0` is a legitimate
/// caddy-rs configuration that asks the kernel for a free port and then binds it; the activation
/// matcher must still plan it so that listener falls through to a normal bind rather than failing
/// the whole apply. Such a listener can never match an inherited socket, because an inherited
/// descriptor always has a concrete port. Rejecting port 0 here would break the documented
/// `unmatched_configured_listener_falls_back_to_binding` behaviour. The refusal belongs to callers
/// that need a stable identity (the `bind-fds` plan output), which is `plan_listen_specs`.
pub fn plan_listeners<'a, I>(listens: I) -> Result<ListenerPlan, ListenerPlanError>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut keys: Vec<&String> = listens.into_iter().collect();
    keys.sort();

    let mut listeners = Vec::new();
    for listen in keys {
        let parsed =
            ListenAddr::parse(listen).map_err(|reason| ListenerPlanError::new(listen, reason))?;
        if is_outside_plan(&parsed) {
            continue;
        }
        let host = parsed.host().to_string();
        let port = parsed.port().ok_or_else(|| {
            ListenerPlanError::new(
                listen,
                "expected `host:port`; a planned listener needs a numeric port",
            )
        })?;
        listeners.push(PlannedListener {
            network: parsed.network,
            host,
            port,
            origin: listen.clone(),
        });
    }

    sort_listeners(&mut listeners);
    Ok(ListenerPlan { listeners })
}

/// Build the listener plan for listen specs that may carry a port range.
///
/// This is the entry point for a caller that has already parsed a range (for example
/// `caddy respond`, whose parser accepts `host:8000-8005`). Each spec expands to one
/// [`PlannedListener`] per port in its inclusive range, so a range never leaks downstream as an
/// opaque entry. Port `0` is rejected, as in [`plan_listeners`], and Unix specs are excluded.
pub fn plan_listen_specs<I>(specs: I) -> Result<ListenerPlan, ListenerPlanError>
where
    I: IntoIterator<Item = ListenSpec>,
{
    let mut specs: Vec<ListenSpec> = specs.into_iter().collect();
    specs.sort_by(|a, b| {
        a.network
            .as_str()
            .cmp(b.network.as_str())
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.start_port.cmp(&b.start_port))
            .then_with(|| a.origin.cmp(&b.origin))
    });

    let mut listeners = Vec::new();
    for spec in specs {
        if spec.network == Network::Unix {
            continue;
        }
        let ports = expand_port_range(&spec.origin, spec.start_port, spec.end_port)?;
        for port in ports {
            listeners.push(PlannedListener {
                network: spec.network,
                host: spec.host.clone(),
                port,
                origin: spec.origin.clone(),
            });
        }
    }

    sort_listeners(&mut listeners);
    Ok(ListenerPlan { listeners })
}

fn sort_listeners(listeners: &mut [PlannedListener]) {
    listeners.sort_by(|a, b| {
        a.network
            .as_str()
            .cmp(b.network.as_str())
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.port.cmp(&b.port))
    });
}

fn port_zero_error(listen: &str) -> ListenerPlanError {
    ListenerPlanError::new(
        listen,
        "port 0 asks the kernel to choose a port, which has no stable identity to plan, match \
         against an inherited socket, or inherit across an exec; use a concrete port",
    )
}

/// Whether a parsed address belongs to a socket type the plan does not describe.
///
/// Unix sockets are matched by path and `fd/` binds name an inherited descriptor, so neither has a
/// planned port identity. Both keep their existing, separate handling.
fn is_outside_plan(parsed: &ListenAddr) -> bool {
    parsed.network == Network::Unix || parsed.address.starts_with("fd/")
}

/// Expand an inclusive port range to its concrete ports.
///
/// Shares the rules of the existing `caddy respond` parser (`crates/cli/src/respond.rs`,
/// `parse_port_range`) — `end >= start`, inclusive on both ends — and adds Caddy's
/// `maxPortSpan` ceiling and the plan's port-0 refusal. A single-port range yields exactly one port,
/// so a boundary range such as `8080-8080` is not an empty span.
pub fn expand_port_range(
    listen: &str,
    start: u16,
    end: u16,
) -> Result<Vec<u16>, ListenerPlanError> {
    if end < start {
        return Err(ListenerPlanError::new(
            listen,
            format!("end port {end} must not be less than start port {start}"),
        ));
    }
    if start == 0 {
        return Err(port_zero_error(listen));
    }
    let span = u32::from(end) - u32::from(start) + 1;
    if span > MAX_PORT_SPAN {
        return Err(ListenerPlanError::new(
            listen,
            format!("port range exceeds {MAX_PORT_SPAN} ports"),
        ));
    }
    Ok((start..=end).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(listens: &[&str]) -> ListenerPlan {
        let owned: Vec<String> = listens.iter().map(|s| (*s).to_string()).collect();
        plan_listeners(&owned).expect("plan should build")
    }

    fn spec(network: Network, host: &str, start: u16, end: u16) -> ListenSpec {
        ListenSpec {
            network,
            host: host.to_string(),
            start_port: start,
            end_port: end,
            origin: format!("{host}:{start}-{end}"),
        }
    }

    #[test]
    fn a_plain_tcp_listen_plans_one_concrete_listener() {
        let plan = plan(&["localhost:8080"]);
        assert_eq!(plan.len(), 1);
        let listener = &plan.listeners()[0];
        assert_eq!(listener.network, Network::Tcp);
        assert_eq!(listener.host, "localhost");
        assert_eq!(listener.port, 8080);
        assert_eq!(listener.address(), "localhost:8080");
        assert!(!listener.is_wildcard());
    }

    #[test]
    fn a_hostless_listen_plans_a_wildcard_listener() {
        let plan = plan(&[":443"]);
        assert!(plan.listeners()[0].is_wildcard());
        assert_eq!(plan.listeners()[0].address(), ":443");
    }

    #[test]
    fn the_network_prefix_selects_the_planned_network() {
        let plan = plan(&["udp/:443", "tcp/:8443"]);
        assert!(plan.find(Network::Udp, "", 443).is_some());
        assert!(plan.find(Network::Tcp, "", 8443).is_some());
        assert!(plan.find(Network::Tcp, "", 443).is_none());
    }

    #[test]
    fn unix_sockets_are_excluded_from_the_plan() {
        let plan = plan(&["unix//run/caddy.sock", ":8080"]);
        assert_eq!(plan.len(), 1, "only the TCP listener is planned");
        assert!(plan
            .listeners()
            .iter()
            .all(|listener| listener.network != Network::Unix));
    }

    #[test]
    fn port_zero_is_planned_so_it_can_fall_back_to_a_normal_bind() {
        // A configured `:0` asks the kernel for a free port. It must stay plannable: the activation
        // matcher has to see it so the listener falls through to a normal bind instead of failing
        // the apply. It can never match an inherited socket, because those always carry a port.
        let plan = plan(&["127.0.0.1:0"]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.listeners()[0].port, 0);
    }

    #[test]
    fn port_zero_is_refused_where_a_stable_identity_is_required() {
        // The ranged/spec entry point is for callers that need a stable planned identity (the
        // `bind-fds` plan output), where a kernel-chosen port cannot be inherited or matched.
        let error = expand_port_range(":0", 0, 0).expect_err("port 0 has no stable identity");
        assert!(
            error.reason.contains("port 0"),
            "the reason should name port 0, got: {}",
            error.reason
        );
    }

    #[test]
    fn a_port_range_expands_to_its_exact_concrete_ports_including_both_boundaries() {
        let plan =
            plan_listen_specs([spec(Network::Tcp, "127.0.0.1", 8000, 8005)]).expect("valid range");
        let ports: Vec<u16> = plan.listeners().iter().map(|l| l.port).collect();
        assert_eq!(ports, vec![8000, 8001, 8002, 8003, 8004, 8005]);
        // Boundary: a range whose bounds are equal yields exactly one port, not an empty span.
        let single = plan_listen_specs([spec(Network::Tcp, "", 8080, 8080)]).expect("single port");
        assert_eq!(single.len(), 1);
        assert_eq!(single.listeners()[0].port, 8080);
    }

    #[test]
    fn an_inverted_range_is_refused() {
        let error = expand_port_range(":8005-8000", 8005, 8000).expect_err("inverted range");
        assert!(error.reason.contains("less than start port"));
    }

    #[test]
    fn a_range_at_caddy_max_span_is_accepted() {
        let ports = expand_port_range(":1-65535", 1, 65535).expect("exactly maxPortSpan");
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports.first(), Some(&1));
        assert_eq!(ports.last(), Some(&65535));
    }

    #[test]
    fn unix_specs_are_excluded_from_a_ranged_plan() {
        let plan = plan_listen_specs([
            spec(Network::Unix, "", 0, 0),
            spec(Network::Tcp, "", 8080, 8081),
        ])
        .expect("valid specs");
        assert_eq!(plan.len(), 2);
        assert!(plan
            .listeners()
            .iter()
            .all(|listener| listener.network == Network::Tcp));
    }

    #[test]
    fn a_ranged_plan_groups_by_network() {
        let plan = plan_listen_specs([
            spec(Network::Tcp, "", 80, 81),
            spec(Network::Udp, "", 443, 443),
        ])
        .expect("valid specs");
        let grouped = plan.by_network();
        assert_eq!(grouped["tcp"].len(), 2);
        assert_eq!(grouped["udp"].len(), 1);
    }

    #[test]
    fn the_plan_is_deterministic_regardless_of_input_order() {
        let a = plan(&[":8080", "localhost:9090"]);
        let b = plan(&["localhost:9090", ":8080"]);
        assert_eq!(a, b);
        // Sorting is by host, so a wildcard (empty host) sorts before a hostname.
        assert!(a.listeners()[0].is_wildcard());
    }
}
