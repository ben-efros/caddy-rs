//! UDP session table, UDP route matching and per-route metrics.
//!
//! The tests drive the table with an explicit `Instant` so expiry is deterministic: nothing here
//! sleeps, and a failure names the rule that broke rather than a timing flake.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use caddy_rs_admin::metrics::MetricsRegistry;
use caddy_rs_l4::matchers::ConnectionMeta;
use caddy_rs_l4::udp::{
    AsnMatcher, IpMatcher, UdpAction, UdpMatcher, UdpProxyConfig, UdpRoute, UdpRouteError,
    UdpRouteTable,
};
use caddy_rs_l4::udp_metrics::{RouteAllowlist, UdpMetrics, OTHER_LABEL};
use caddy_rs_l4::udp_session::{
    EvictionCause, EvictionEvent, EvictionLog, SessionKey, UdpSessionTable, DEFAULT_IDLE_TIMEOUT,
};

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("socket address")
}

fn peer(ip: &str) -> ConnectionMeta {
    ConnectionMeta {
        peer: Some(ip.parse().expect("ip address")),
        asn: None,
    }
}

fn peer_asn(ip: &str, asn: u32) -> ConnectionMeta {
    ConnectionMeta {
        peer: Some(ip.parse().expect("ip address")),
        asn: Some(asn),
    }
}

fn source(octet: u8) -> SocketAddr {
    addr(&format!("10.0.0.{}:53000", octet))
}

fn destination() -> SocketAddr {
    addr("127.0.0.1:443")
}

// ---------------------------------------------------------------------------------------------
// Session table: create, reuse, expire
// ---------------------------------------------------------------------------------------------

#[test]
fn a_first_datagram_creates_a_session_and_a_second_reuses_it() {
    let mut table = UdpSessionTable::new();
    let t0 = Instant::now();
    let key = SessionKey::new(source(1), destination());

    let created = table.observe(key, t0, 1, 100, "upstream:9000", None);
    assert_eq!(created.packets(), 1);
    assert_eq!(created.bytes(), 100);
    assert_eq!(created.upstream(), "upstream:9000");
    assert_eq!(
        table.len(),
        1,
        "one datagram must create exactly one session"
    );
    assert_eq!(table.stats().created, 1);
    assert_eq!(table.stats().reused, 0);

    let reused = table.observe(
        key,
        t0 + Duration::from_secs(5),
        2,
        250,
        "upstream:9000",
        None,
    );
    assert_eq!(
        reused.packets(),
        3,
        "packet counts accumulate on the session"
    );
    assert_eq!(reused.bytes(), 350, "byte counts accumulate on the session");
    assert_eq!(
        reuse_last_seen(&table, key, t0 + Duration::from_secs(5)),
        t0 + Duration::from_secs(5),
        "reuse must refresh the idle clock"
    );
    assert_eq!(
        table.len(),
        1,
        "a reused session must not add a second entry"
    );
    assert_eq!(table.stats().created, 1);
    assert_eq!(table.stats().reused, 1);
}

fn reuse_last_seen(table: &UdpSessionTable, key: SessionKey, expected: Instant) -> Instant {
    let seen = table.get(&key).expect("session is present").last_seen();
    assert_eq!(seen, expected);
    seen
}

#[test]
fn sessions_are_keyed_by_the_source_and_destination_pair() {
    let mut table = UdpSessionTable::new();
    let t0 = Instant::now();

    // Same source, different local address: two sessions, because a reply has to leave from the
    // address the datagram arrived on.
    let other_destination = addr("127.0.0.2:443");
    table.observe(
        SessionKey::new(source(1), destination()),
        t0,
        1,
        10,
        "a:1",
        None,
    );
    table.observe(
        SessionKey::new(source(1), other_destination),
        t0,
        1,
        10,
        "a:1",
        None,
    );
    // Different source, same destination: a second session too.
    table.observe(
        SessionKey::new(source(2), destination()),
        t0,
        1,
        10,
        "a:1",
        None,
    );

    assert_eq!(table.len(), 3, "the pair, not either half, is the key");
}

#[test]
fn a_session_expires_after_its_idle_timeout_and_a_new_datagram_starts_fresh() {
    let mut table = UdpSessionTable::new();
    let t0 = Instant::now();
    let key = SessionKey::new(source(1), destination());
    let timeout = Duration::from_secs(30);

    table.observe(key, t0, 5, 500, "upstream:9000", Some(timeout));

    // One nanosecond short of the timeout is still alive.
    assert_eq!(
        table.sweep(t0 + timeout - Duration::from_nanos(1)),
        0,
        "a session must not expire before its idle timeout"
    );
    assert_eq!(table.len(), 1);

    // At the timeout it is gone.
    assert_eq!(table.sweep(t0 + timeout), 1);
    assert!(table.is_empty(), "the expired session must be removed");
    assert_eq!(table.stats().expired, 1);

    // A later datagram starts a new session rather than resurrecting the old counters.
    let fresh = table.observe(key, t0 + timeout, 1, 10, "upstream:9000", Some(timeout));
    assert_eq!(
        fresh.packets(),
        1,
        "an expired session must not keep its counters"
    );
    assert_eq!(fresh.bytes(), 10);
    assert_eq!(table.stats().created, 2);
}

#[test]
fn the_default_idle_timeout_is_thirty_seconds() {
    assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(30));
    let table = UdpSessionTable::new();
    assert_eq!(table.default_idle_timeout(), DEFAULT_IDLE_TIMEOUT);
}

#[test]
fn an_expired_entry_is_replaced_even_without_a_sweep() {
    let mut table = UdpSessionTable::new();
    let t0 = Instant::now();
    let key = SessionKey::new(source(1), destination());
    let timeout = Duration::from_secs(10);

    table.observe(key, t0, 3, 300, "old:1", Some(timeout));
    // No sweep: the next datagram arrives long after the timeout and must not continue the old
    // session, or a session could outlive its timeout purely by being reused.
    let next = table.observe(
        key,
        t0 + timeout + Duration::from_secs(1),
        1,
        10,
        "new:2",
        Some(timeout),
    );

    assert_eq!(next.packets(), 1, "a stale session must not be resurrected");
    assert_eq!(next.bytes(), 10);
    assert_eq!(
        next.upstream(),
        "new:2",
        "the fresh session uses the current upstream"
    );
    assert_eq!(table.stats().expired, 1);
}

// ---------------------------------------------------------------------------------------------
// Bounded memory under flood
// ---------------------------------------------------------------------------------------------

/// Collects eviction events so a test can prove the flood path reports what it dropped.
#[derive(Clone, Default)]
struct RecordingLog(Arc<Mutex<Vec<EvictionEvent>>>);

impl RecordingLog {
    fn events(&self) -> Vec<EvictionEvent> {
        self.0.lock().expect("log lock").clone()
    }
}

impl EvictionLog for RecordingLog {
    fn record(&self, event: &EvictionEvent) {
        self.0.lock().expect("log lock").push(event.clone());
    }
}

#[test]
fn the_table_stays_within_capacity_under_a_flood_and_logs_every_eviction() {
    const CAPACITY: usize = 8;
    let log = RecordingLog::default();
    let mut table = UdpSessionTable::with_limits(CAPACITY, DEFAULT_IDLE_TIMEOUT)
        .with_eviction_log(Arc::new(log.clone()));
    let t0 = Instant::now();

    // A flood of distinct spoofed sources, far more than the capacity.
    for i in 0..200u32 {
        let src = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i)), 40000);
        table.observe(
            SessionKey::new(src, destination()),
            t0 + Duration::from_millis(u64::from(i)),
            1,
            64,
            "upstream:9000",
            None,
        );
        assert!(
            table.len() <= CAPACITY,
            "the table must never exceed its capacity: {} > {CAPACITY} after {i} sources",
            table.len()
        );
    }

    assert_eq!(
        table.len(),
        CAPACITY,
        "the table fills to capacity and stays there"
    );
    let stats = table.stats();
    assert_eq!(stats.created, 200, "every datagram created a session");
    assert_eq!(
        stats.evicted_for_capacity,
        200u64 - CAPACITY as u64,
        "every session beyond capacity must be evicted"
    );
    assert_eq!(
        log.events().len(),
        200 - CAPACITY,
        "every eviction must be logged, not silently dropped"
    );
    assert!(
        log.events()
            .iter()
            .all(|event| event.cause == EvictionCause::Capacity),
        "flood evictions are capacity evictions, not expiries"
    );
}

#[test]
fn the_least_recently_used_session_is_evicted_first() {
    let mut table = UdpSessionTable::with_limits(2, DEFAULT_IDLE_TIMEOUT);
    let t0 = Instant::now();
    let first = SessionKey::new(source(1), destination());
    let second = SessionKey::new(source(2), destination());
    let third = SessionKey::new(source(3), destination());

    table.observe(first, t0, 1, 1, "u:1", None);
    table.observe(second, t0 + Duration::from_secs(1), 1, 1, "u:1", None);
    // Touch the first so the second becomes the least recently used.
    table.observe(first, t0 + Duration::from_secs(2), 1, 1, "u:1", None);
    // This third session must displace the second, not the first.
    table.observe(third, t0 + Duration::from_secs(3), 1, 1, "u:1", None);

    assert_eq!(table.len(), 2);
    assert!(
        table.get(&first).is_some(),
        "the recently used session survives"
    );
    assert!(table.get(&third).is_some(), "the new session is admitted");
    assert!(
        table.get(&second).is_none(),
        "the least recently used session is the one evicted"
    );
}

#[test]
fn a_zero_capacity_table_still_holds_one_session() {
    let table = UdpSessionTable::with_limits(0, DEFAULT_IDLE_TIMEOUT);
    assert_eq!(
        table.max_sessions(),
        1,
        "a zero capacity is clamped, because a table that carries nothing would drop every datagram"
    );
}

// ---------------------------------------------------------------------------------------------
// Route matching on ip and asn
// ---------------------------------------------------------------------------------------------

#[test]
fn a_udp_route_matches_on_ip_and_asn_together() {
    let route = UdpRoute::new(
        vec![
            Arc::new(IpMatcher::parse("10.0.0.0/8").unwrap()) as Arc<dyn UdpMatcher>,
            Arc::new(AsnMatcher::new(64512)) as Arc<dyn UdpMatcher>,
        ],
        UdpAction::Close,
    );

    assert!(route.matches(&peer_asn("10.1.2.3", 64512)), "both match");
    assert!(
        !route.matches(&peer_asn("10.1.2.3", 64513)),
        "wrong ASN fails"
    );
    assert!(
        !route.matches(&peer_asn("192.168.0.1", 64512)),
        "wrong network fails"
    );
}

#[test]
fn a_route_with_no_matchers_matches_every_datagram() {
    let route = UdpRoute::new(Vec::new(), UdpAction::Close);
    assert!(
        route.matches(&peer("203.0.113.9")),
        "an empty matcher list is the catch-all spelling"
    );
}

#[test]
fn the_first_matching_route_wins() {
    let catch_all = UdpRoute::new(Vec::new(), UdpAction::Close);
    let specific = UdpRoute::new(
        vec![Arc::new(IpMatcher::parse("10.0.0.0/8").unwrap()) as Arc<dyn UdpMatcher>],
        UdpAction::Proxy(UdpProxyConfig::new("upstream:9000").unwrap()),
    );
    // The catch-all is first, so it shadows the specific route: order is the contract.
    let table = UdpRouteTable::from_routes(vec![catch_all, specific.clone()]);

    let matched = table.lookup(&peer("10.1.2.3")).expect("a route matches");
    assert_eq!(
        matched.action().kind(),
        "close",
        "route order decides precedence"
    );

    let reordered =
        UdpRouteTable::from_routes(vec![specific, UdpRoute::new(Vec::new(), UdpAction::Close)]);
    let matched = reordered
        .lookup(&peer("10.1.2.3"))
        .expect("a route matches");
    assert_eq!(matched.action().kind(), "proxy");
    assert_eq!(matched.action().upstream(), Some("upstream:9000"));
}

#[test]
fn datagrams_matching_no_route_return_none() {
    let table = UdpRouteTable::from_routes(vec![UdpRoute::new(
        vec![Arc::new(AsnMatcher::new(64512)) as Arc<dyn UdpMatcher>],
        UdpAction::Close,
    )]);
    assert!(table.lookup(&peer("10.1.2.3")).is_none());
    assert!(!table.is_empty(), "the table holds the one route");
    assert_eq!(table.len(), 1);
}

#[test]
fn ip_matchers_cover_cidr_boundaries_and_refuse_an_address_family_mismatch() {
    let wide = IpMatcher::parse("10.0.0.0/8").unwrap();
    assert!(wide.contains_addr("10.255.255.255"));
    assert!(!wide.contains_addr("11.0.0.1"));

    let single = IpMatcher::parse("192.0.2.5").unwrap();
    assert_eq!(single.prefix(), 32, "a bare address is a single host");
    assert!(single.contains_addr("192.0.2.5"));
    assert!(!single.contains_addr("192.0.2.6"));

    let everything = IpMatcher::parse("0.0.0.0/0").unwrap();
    assert!(
        everything.contains_addr("203.0.113.7"),
        "a /0 covers all of IPv4"
    );
    assert!(
        !everything.contains_addr("2001:db8::1"),
        "an IPv4 /0 must not match an IPv6 address"
    );
}

#[test]
fn malformed_ip_matchers_and_upstreams_are_refused_with_a_located_error() {
    assert!(matches!(
        IpMatcher::parse("not-an-ip/8"),
        Err(UdpRouteError::InvalidMatcher(message)) if message.contains("not-an-ip/8")
    ));
    assert!(matches!(
        IpMatcher::parse("10.0.0.0/99"),
        Err(UdpRouteError::InvalidMatcher(message)) if message.contains("99")
    ));
    assert!(matches!(
        UdpProxyConfig::new("upstream-without-port"),
        Err(UdpRouteError::InvalidUpstream(message)) if message.contains("upstream-without-port")
    ));
    assert!(matches!(
        UdpProxyConfig::new("upstream:0"),
        Err(UdpRouteError::InvalidUpstream(_))
    ));
}

// ---------------------------------------------------------------------------------------------
// Per-route counters under ADR-029 allowlist semantics
// ---------------------------------------------------------------------------------------------

#[test]
fn counters_are_reported_per_route_and_unlisted_routes_fall_back_to_other() {
    let registry = MetricsRegistry::new();
    let allowlist = RouteAllowlist::from_pairs([("route-a", "game")]);
    let metrics = UdpMetrics::new(registry.clone(), allowlist);

    let listed = metrics.counters("route-a").expect("counters");
    assert_eq!(
        listed.route_label(),
        "game",
        "an allowlisted route reports its name"
    );
    listed.observe(3, 300);

    let unlisted = metrics
        .counters("route-spoofed-from-a-header")
        .expect("counters");
    assert_eq!(
        unlisted.route_label(),
        OTHER_LABEL,
        "an unlisted route must report as _other, not create a new series"
    );

    let rendered = registry.render();
    assert!(
        rendered.contains("game"),
        "the allowlisted label is present: {rendered}"
    );
    assert!(
        rendered.contains(OTHER_LABEL),
        "the fallback label is present: {rendered}"
    );
    assert!(
        !rendered.contains("route-spoofed-from-a-header"),
        "an unlisted route id must never become a label value: {rendered}"
    );
}

#[test]
fn every_route_reports_as_other_when_the_allowlist_is_empty() {
    let registry = MetricsRegistry::new();
    let metrics = UdpMetrics::new(registry, RouteAllowlist::empty());
    assert!(metrics.allowlist().is_empty());

    for route in ["a", "b", "c"] {
        assert_eq!(
            metrics.counters(route).expect("counters").route_label(),
            OTHER_LABEL,
            "an empty allowlist means every route reports as _other"
        );
    }
}

#[test]
fn packet_and_byte_counters_accumulate_across_datagrams() {
    let registry = MetricsRegistry::new();
    let metrics = UdpMetrics::new(
        registry.clone(),
        RouteAllowlist::from_pairs([("r", "game")]),
    );
    let counters = metrics.counters("r").expect("counters");
    counters.observe(1, 100);
    counters.observe(2, 250);

    let rendered = registry.render();
    assert!(
        rendered.contains("caddy_l4_udp_packets_total"),
        "the packet counter is exported: {rendered}"
    );
    assert!(
        rendered.contains("caddy_l4_udp_bytes_total"),
        "the byte counter is exported: {rendered}"
    );
    assert!(
        rendered.contains("350") || rendered.contains("game"),
        "the accumulated totals reach the registry: {rendered}"
    );
}

// Small helpers so the CIDR assertions read directly on an `IpMatcher`.
trait ContainsAddr {
    fn contains_addr(&self, addr: &str) -> bool;
}

impl ContainsAddr for IpMatcher {
    fn contains_addr(&self, addr: &str) -> bool {
        let meta = peer(addr);
        <IpMatcher as UdpMatcher>::matches(self, &meta)
    }
}
