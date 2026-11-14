//! The `@radar` matcher: answer a request against the current Radar snapshot.
//!
//! # What this module owns
//!
//! * [`GeoIpProvider`] — the IP → ASN/country seam. The shipped default is [`NoopGeoIp`] (nothing is
//!   known); [`StaticGeoIp`] is the test-only table. Production providers are intentionally *not*
//!   part of this crate: a MaxMind/DB-IP reader lives behind the same one-method trait (a
//!   `maxminddb` reader opens the `.mmdb` file once and looks up `city`/`asn` records), and the
//!   runtime row chooses it. No network or new crate dependency is wired here.
//! * [`TrustCdnResolver`] — the `trust_cdn` seam. When the immediate peer is a trusted CDN edge,
//!   the client IP comes from `CF-Connecting-IP`/`True-Client-IP`/`X-Forwarded-For`; otherwise the
//!   peer address is the client. Production providers should match the CDN's published egress
//!   ranges (Cloudflare, Fastly, Akamai, CloudFront); [`StaticTrustCdn`] is the test seam.
//! * [`RadarState`] — a lock-free-on-the-request-path snapshot of the entries the
//!   [`RadarClient`](crate::radar_client::RadarClient) has cached, plus the enabled flag. The
//!   runtime row publishes a fresh snapshot after each `radar` poll (`sync_from_client`), so the
//!   sync matcher never blocks on the client's async cache mutex.
//! * [`RadarPredicate`] — the predicate fields shared by the matcher and the default protection
//!   rules (`radar_protect`): `source_asn_attacking`, `target_asn_attacked`,
//!   `source_asn_attacking_l34`, `source_country_attacking`, `target_country_attacked`,
//!   `source_asn_hijacking`, `target_prefix_hijacked`, `source_asn_leaking`,
//!   `source_asn_anomalous`, `anomaly_type`, `min_magnitude`, `max_age`.
//! * [`RadarMatcher`] — the `Matcher` implementation. **When radar is not enabled,
//!   `matches()` is false for every configuration** (the auto-mode idle case), and the
//!   variables module reports empty strings.
//!
//! # Direction of a record
//!
//! [`RadarEntry`] carries one ASN/country per record and has no source/target role or prefix field,
//! so the endpoint decides the direction: `ddos/l7` and `ddos/l34` records are attack **sources**,
//! `traffic/anomalies` records are **targets** (and "anomalous" sources), `bgp/hijacks` records are
//! **hijacks**. `target_prefix_hijacked` therefore keys on the hijack record's target ASN: the
//! snapshot model has no prefix text to compare against, and this is exactly the information
//! GeoIP can supply for a client IP. Extending [`RadarEntry`] with a role/prefix field is the
//! follow-up that would make the prefix comparison literal.
//!
//! # Wiring
//!
//! The matcher is constructed with a [`RadarState`] handle; `matchers::build_matcher_set` has no
//! such handle (route construction is config-only today), so registering `"radar"` there is the
//! runtime row's job. Nothing in this module reaches the network.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use serde_json::Value;

use crate::radar_client::{RadarClient, RadarEndpoint, RadarEntry};
use crate::types::{Matcher, MatcherError, Request};

/// Headers a trusted CDN edge uses to report the real client IP, in priority order.
pub const TRUSTED_CLIENT_IP_HEADERS: [&str; 3] =
    ["cf-connecting-ip", "true-client-ip", "x-forwarded-for"];

/// The ASN/country a GeoIP lookup resolved for one IP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoLocation {
    /// Autonomous system number.
    pub asn: Option<u64>,
    /// ISO 3166-1 alpha-2 country code (upper-cased by the provider).
    pub country: Option<String>,
}

/// IP → ASN/country lookup.
///
/// Implementations must be cheap and non-blocking: the request path calls them on every matched
/// request (limit `@radar` to routes that need it). Production implementations read a local
/// MaxMind/DB-IP database; this crate ships [`NoopGeoIp`] (nothing known) and [`StaticGeoIp`]
/// (tests).
pub trait GeoIpProvider: Send + Sync {
    /// Resolve `ip`, or `None` when the address is not in the database.
    fn lookup(&self, ip: IpAddr) -> Option<GeoLocation>;
}

/// Default provider: no database, so no ASN and no country are ever known.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopGeoIp;

impl GeoIpProvider for NoopGeoIp {
    fn lookup(&self, _ip: IpAddr) -> Option<GeoLocation> {
        None
    }
}

/// Test-only provider backed by a fixed lookup table.
#[derive(Debug, Clone, Default)]
pub struct StaticGeoIp {
    table: BTreeMap<IpAddr, GeoLocation>,
}

impl StaticGeoIp {
    /// Build from `(ip, asn, country)` triples; `None` leaves the attribute unknown.
    pub fn new(
        entries: impl IntoIterator<Item = (IpAddr, Option<u64>, Option<&'static str>)>,
    ) -> Self {
        let table = entries
            .into_iter()
            .map(|(ip, asn, country)| {
                (
                    ip,
                    GeoLocation {
                        asn,
                        country: country.map(str::to_ascii_uppercase),
                    },
                )
            })
            .collect();
        Self { table }
    }

    /// Insert or replace one entry.
    pub fn insert(&mut self, ip: IpAddr, location: GeoLocation) {
        self.table.insert(ip, location);
    }
}

impl GeoIpProvider for StaticGeoIp {
    fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        self.table.get(&ip).cloned()
    }
}

/// Whether the immediate peer is a trusted CDN edge.
///
/// The resolver answers for the *peer* address (the socket the CDN opened), never for a forwarded
/// address: trusting a forwarded header from an untrusted peer would let any client spoof its IP.
pub trait TrustCdnResolver: Send + Sync {
    /// Whether `peer` belongs to a configured CDN.
    fn is_trusted_cdn(&self, peer: IpAddr) -> bool;
}

/// Default resolver: no CDN is trusted, forwarded client-IP headers are ignored.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTrustCdn;

impl TrustCdnResolver for NoopTrustCdn {
    fn is_trusted_cdn(&self, _peer: IpAddr) -> bool {
        false
    }
}

/// Test-only resolver with a fixed peer set (a production resolver matches published ranges).
#[derive(Debug, Clone, Default)]
pub struct StaticTrustCdn {
    trusted: Vec<IpAddr>,
}

impl StaticTrustCdn {
    /// Trust exactly these peer addresses.
    pub fn new(peers: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            trusted: peers.into_iter().collect(),
        }
    }
}

impl TrustCdnResolver for StaticTrustCdn {
    fn is_trusted_cdn(&self, peer: IpAddr) -> bool {
        self.trusted.iter().any(|trusted| *trusted == peer)
    }
}

/// The address the request came from, after `trust_cdn` handling.
///
/// The peer address is `request.remote_addr` (falling back to the textual override transports such
/// as PROXY protocol provide). Only a trusted CDN peer may substitute a header value; the first
/// parseable address in [`TRUSTED_CLIENT_IP_HEADERS`] wins and a missing/invalid header falls back
/// to the peer.
pub fn resolve_client_ip(request: &Request, trust_cdn: &dyn TrustCdnResolver) -> Option<IpAddr> {
    let peer = request
        .remote_addr
        .map(|addr| addr.ip())
        .or_else(|| request.remote_addr_text.as_deref()?.trim().parse().ok())?;
    if !trust_cdn.is_trusted_cdn(peer) {
        return Some(peer);
    }
    for header in TRUSTED_CLIENT_IP_HEADERS {
        let Some(value) = request
            .headers
            .get(header)
            .and_then(|value| value.to_str().ok())
        else {
            continue;
        };
        for candidate in value.split(',') {
            if let Ok(ip) = candidate.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    Some(peer)
}

/// The request's client identity: its IP plus what GeoIP knows about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadarClientIdentity {
    /// Client IP (peer, or the CDN-forwarded address for a trusted peer).
    pub ip: IpAddr,
    /// Client ASN, when GeoIP knows it.
    pub asn: Option<u64>,
    /// Client country, when GeoIP knows it.
    pub country: Option<String>,
}

/// The handles a Radar decision needs: the snapshot, GeoIP and `trust_cdn`.
#[derive(Clone, Copy)]
pub struct RadarContext<'a> {
    /// Current snapshot + enabled flag.
    pub state: &'a RadarState,
    /// IP → ASN/country lookup.
    pub geoip: &'a dyn GeoIpProvider,
    /// Which peers may forward the client IP.
    pub trust_cdn: &'a dyn TrustCdnResolver,
}

impl<'a> RadarContext<'a> {
    /// Build a context.
    pub fn new(
        state: &'a RadarState,
        geoip: &'a dyn GeoIpProvider,
        trust_cdn: &'a dyn TrustCdnResolver,
    ) -> Self {
        Self {
            state,
            geoip,
            trust_cdn,
        }
    }

    /// Resolve the request's client IP and GeoIP attributes.
    ///
    /// `None` only when the request carries no peer address at all; unknown GeoIP attributes are
    /// `None` on the identity, so field checks that need them simply fail.
    pub fn identify(&self, request: &Request) -> Option<RadarClientIdentity> {
        let ip = resolve_client_ip(request, self.trust_cdn)?;
        let location = self.geoip.lookup(ip).unwrap_or_default();
        Some(RadarClientIdentity {
            ip,
            asn: location.asn,
            country: location.country.map(|country| country.to_ascii_uppercase()),
        })
    }
}

/// A published Radar snapshot: cached entries per endpoint plus when they were captured.
#[derive(Debug, Clone)]
pub struct RadarSnapshot {
    fetched_at: SystemTime,
    entries: BTreeMap<RadarEndpoint, Vec<RadarEntry>>,
}

impl RadarSnapshot {
    /// Build a snapshot captured at `fetched_at`.
    pub fn new(entries: BTreeMap<RadarEndpoint, Vec<RadarEntry>>, fetched_at: SystemTime) -> Self {
        Self {
            entries,
            fetched_at,
        }
    }

    /// An empty snapshot captured now.
    pub fn empty() -> Self {
        Self::new(BTreeMap::new(), SystemTime::now())
    }

    /// When the snapshot was captured (the age clock for `max_age` and `data_age`).
    pub fn fetched_at(&self) -> SystemTime {
        self.fetched_at
    }

    /// Entries of one endpoint (empty slice when that endpoint has none).
    pub fn entries(&self, endpoint: RadarEndpoint) -> &[RadarEntry] {
        self.entries
            .get(&endpoint)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Every entry, in endpoint order.
    pub fn all_entries(&self) -> impl Iterator<Item = &RadarEntry> {
        self.entries.values().flatten()
    }

    /// Total number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    /// Age of the snapshot at `now` (zero when the clock went backwards).
    pub fn age(&self, now: SystemTime) -> Duration {
        now.duration_since(self.fetched_at).unwrap_or_default()
    }
}

/// The result of syncing a [`RadarState`] from the client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RadarTransition {
    /// Radar is enabled after the sync.
    pub enabled: bool,
    /// The sync moved the state from idle/disabled to enabled (the lazy-registration trigger).
    pub idle_to_enabled: bool,
    /// Entries in the published snapshot.
    pub entries: usize,
}

/// The radar snapshot the request path reads, plus its enabled flag.
///
/// The state starts disabled and empty (auto mode is idle until the first public client IP). A
/// snapshot is published as a whole behind an `RwLock<Arc<_>>`, so a request either sees the
/// previous snapshot or the next one, never a half-updated map, and the lock is never held across
/// an await.
#[derive(Debug)]
pub struct RadarState {
    enabled: AtomicBool,
    snapshot: RwLock<Arc<RadarSnapshot>>,
}

impl Default for RadarState {
    fn default() -> Self {
        Self::new()
    }
}

impl RadarState {
    /// A disabled, empty state (the auto-mode idle state).
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            snapshot: RwLock::new(Arc::new(RadarSnapshot::empty())),
        }
    }

    /// Whether radar is enabled; false means every matcher is false and every variable empty.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Force the enabled flag (runtime row, or tests). Prefer [`Self::sync_from_client`], which
    /// follows the client.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
        if !enabled {
            self.publish(RadarSnapshot::empty());
        }
    }

    /// Publish a snapshot; returns its entry count.
    pub fn publish(&self, snapshot: RadarSnapshot) -> usize {
        let entries = snapshot.entry_count();
        let mut current = self
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = Arc::new(snapshot);
        entries
    }

    /// The current snapshot (cheap `Arc` clone, no async lock).
    pub fn snapshot(&self) -> Arc<RadarSnapshot> {
        Arc::clone(
            &self
                .snapshot
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// Pull the client's cached entries into a fresh snapshot and follow its enabled flag.
    ///
    /// This is the runtime row's integration point: call it after a poll (or before dispatching
    /// requests) so the sync matcher/variables/hook see the current data. It never enables radar by
    /// itself — the flag comes from [`RadarClient::is_enabled`], i.e. from the client's own
    /// auto/on/off gate.
    pub async fn sync_from_client(&self, client: &RadarClient) -> RadarTransition {
        let was_enabled = self.is_enabled();
        let enabled = client.is_enabled();
        if !enabled {
            self.set_enabled(false);
            return RadarTransition {
                enabled: false,
                idle_to_enabled: false,
                entries: 0,
            };
        }
        let mut entries = BTreeMap::new();
        for endpoint in RadarEndpoint::ALL {
            if let Some(cached) = client.cached_entries(endpoint).await {
                entries.insert(endpoint, cached);
            }
        }
        let entries = self.publish(RadarSnapshot::new(entries, SystemTime::now()));
        self.enabled.store(true, Ordering::Release);
        RadarTransition {
            enabled: true,
            idle_to_enabled: !was_enabled,
            entries,
        }
    }
}

/// How an ASN field selects the ASN to look up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsnSelector {
    /// Use the client's GeoIP-resolved ASN (a bare `field true`).
    Client,
    /// Require the client to be this ASN, then look it up (`field 13335`).
    Asn(u64),
}

impl AsnSelector {
    /// The ASN to search Radar for, or `None` when the client cannot satisfy the selector.
    pub fn resolve(self, identity: &RadarClientIdentity) -> Option<u64> {
        match self {
            Self::Client => identity.asn,
            Self::Asn(asn) => identity.asn.filter(|resolved| *resolved == asn),
        }
    }
}

/// How a country field selects the country to look up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountrySelector {
    /// Use the client's GeoIP-resolved country.
    Client,
    /// Require the client to be from this country, then look it up.
    Country(String),
}

impl CountrySelector {
    /// The country to search Radar for, or `None` when the client cannot satisfy the selector.
    pub fn resolve(&self, identity: &RadarClientIdentity) -> Option<String> {
        let client = identity.country.as_deref()?;
        match self {
            Self::Client => Some(client.to_ascii_uppercase()),
            Self::Country(country) => client
                .eq_ignore_ascii_case(country)
                .then(|| country.to_ascii_uppercase()),
        }
    }
}

/// The `@radar` predicate: an AND of every field that is set.
///
/// Field semantics (all lookups are on the entries of the listed endpoint, with `anomaly_type`,
/// `min_magnitude` and `max_age` applied as entry-level filters):
///
/// | Field | Endpoint(s) | Meaning |
/// | --- | --- | --- |
/// | `source_asn_attacking` | `ddos/l7` | the ASN is an L7 attack source |
/// | `source_asn_attacking_l34` | `ddos/l34` | the ASN is an L3/4 attack source |
/// | `source_country_attacking` | `ddos/l7`, `ddos/l34` | the country is an attack source |
/// | `target_asn_attacked` | `traffic/anomalies` | the ASN is targeted by an anomaly |
/// | `target_country_attacked` | `traffic/anomalies` | the country is targeted by an anomaly |
/// | `source_asn_hijacking` | `bgp/hijacks` | the ASN appears in a hijack record |
/// | `target_prefix_hijacked` | `bgp/hijacks` | the ASN's prefixes are hijacked (see module docs) |
/// | `source_asn_leaking` | `bgp/hijacks`, `traffic/anomalies` | a record names the ASN with a route-leak kind |
/// | `source_asn_anomalous` | `ddos/l7`, `ddos/l34`, `traffic/anomalies` | any attack/anomaly record names the ASN |
///
/// `min_magnitude` requires a known magnitude at or above the threshold (a record without a
/// magnitude cannot satisfy a magnitude threshold). `max_age` rejects the whole snapshot when it is
/// older than the threshold. With no primary field set, the predicate matches any entry that
/// passes the entry-level filters; with nothing set at all it never matches.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RadarPredicate {
    /// The client's ASN is an L7 attack source.
    pub source_asn_attacking: Option<AsnSelector>,
    /// The client's ASN is an L3/4 attack source.
    pub source_asn_attacking_l34: Option<AsnSelector>,
    /// The client's country is an attack source.
    pub source_country_attacking: Option<CountrySelector>,
    /// The client's ASN is targeted.
    pub target_asn_attacked: Option<AsnSelector>,
    /// The client's country is targeted.
    pub target_country_attacked: Option<CountrySelector>,
    /// The client's ASN is recorded as hijacking.
    pub source_asn_hijacking: Option<AsnSelector>,
    /// The client's ASN has hijacked prefixes.
    pub target_prefix_hijacked: Option<AsnSelector>,
    /// The client's ASN is leaking routes.
    pub source_asn_leaking: Option<AsnSelector>,
    /// The client's ASN is involved in any attack/anomaly record.
    pub source_asn_anomalous: Option<AsnSelector>,
    /// Accepted anomaly kinds (case-insensitive; `-`/space also match `_`).
    pub anomaly_type: Vec<String>,
    /// Minimum entry magnitude.
    pub min_magnitude: Option<f64>,
    /// Maximum snapshot age.
    pub max_age: Option<Duration>,
}

impl RadarPredicate {
    /// Whether no predicate field is configured (such a predicate never matches).
    pub fn is_empty(&self) -> bool {
        self.source_asn_attacking.is_none()
            && self.source_asn_attacking_l34.is_none()
            && self.source_country_attacking.is_none()
            && self.target_asn_attacked.is_none()
            && self.target_country_attacked.is_none()
            && self.source_asn_hijacking.is_none()
            && self.target_prefix_hijacked.is_none()
            && self.source_asn_leaking.is_none()
            && self.source_asn_anomalous.is_none()
            && self.anomaly_type.is_empty()
            && self.min_magnitude.is_none()
            && self.max_age.is_none()
    }

    /// Whether any primary (endpoint-selecting) field is set.
    fn has_primary_field(&self) -> bool {
        self.source_asn_attacking.is_some()
            || self.source_asn_attacking_l34.is_some()
            || self.source_country_attacking.is_some()
            || self.target_asn_attacked.is_some()
            || self.target_country_attacked.is_some()
            || self.source_asn_hijacking.is_some()
            || self.target_prefix_hijacked.is_some()
            || self.source_asn_leaking.is_some()
            || self.source_asn_anomalous.is_some()
    }

    /// Parse a predicate object (JSON `match` value or a protection rule's `predicate`).
    pub fn from_json(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "radar predicate must be a JSON object".to_string())?;
        let mut predicate = Self::default();
        for (key, value) in object {
            match key.as_str() {
                "source_asn_attacking" => predicate.source_asn_attacking = asn_selector(value)?,
                "source_asn_attacking_l34" => {
                    predicate.source_asn_attacking_l34 = asn_selector(value)?
                }
                "target_asn_attacked" => predicate.target_asn_attacked = asn_selector(value)?,
                "source_asn_hijacking" => predicate.source_asn_hijacking = asn_selector(value)?,
                "target_prefix_hijacked" => predicate.target_prefix_hijacked = asn_selector(value)?,
                "source_asn_leaking" => predicate.source_asn_leaking = asn_selector(value)?,
                "source_asn_anomalous" => predicate.source_asn_anomalous = asn_selector(value)?,
                "source_country_attacking" => {
                    predicate.source_country_attacking = country_selector(value)?
                }
                "target_country_attacked" => {
                    predicate.target_country_attacked = country_selector(value)?
                }
                "anomaly_type" => predicate.anomaly_type = string_list(value, "anomaly_type")?,
                "min_magnitude" => predicate.min_magnitude = Some(number(value, "min_magnitude")?),
                "max_age" => predicate.max_age = Some(duration(value, "max_age")?),
                other => return Err(format!("unknown radar predicate field `{other}`")),
            }
        }
        Ok(predicate)
    }

    /// Human-readable description, for `Matcher::describe` and logs.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        let mut asn = |name: &str, selector: Option<AsnSelector>| {
            if let Some(selector) = selector {
                parts.push(match selector {
                    AsnSelector::Client => name.to_string(),
                    AsnSelector::Asn(asn) => format!("{name}={asn}"),
                });
            }
        };
        asn("source_asn_attacking", self.source_asn_attacking);
        asn("source_asn_attacking_l34", self.source_asn_attacking_l34);
        asn("target_asn_attacked", self.target_asn_attacked);
        asn("source_asn_hijacking", self.source_asn_hijacking);
        asn("target_prefix_hijacked", self.target_prefix_hijacked);
        asn("source_asn_leaking", self.source_asn_leaking);
        asn("source_asn_anomalous", self.source_asn_anomalous);
        if let Some(selector) = &self.source_country_attacking {
            parts.push(match selector {
                CountrySelector::Client => "source_country_attacking".to_string(),
                CountrySelector::Country(country) => {
                    format!("source_country_attacking={country}")
                }
            });
        }
        if let Some(selector) = &self.target_country_attacked {
            parts.push(match selector {
                CountrySelector::Client => "target_country_attacked".to_string(),
                CountrySelector::Country(country) => format!("target_country_attacked={country}"),
            });
        }
        if !self.anomaly_type.is_empty() {
            parts.push(format!("anomaly_type={}", self.anomaly_type.join("|")));
        }
        if let Some(minimum) = self.min_magnitude {
            parts.push(format!("min_magnitude={minimum}"));
        }
        if let Some(max_age) = self.max_age {
            parts.push(format!("max_age={}s", max_age.as_secs()));
        }
        parts.join(" ")
    }

    /// Whether the predicate holds for `identity` against `snapshot` at `now`.
    ///
    /// The caller is responsible for the enabled gate; this method only evaluates data.
    pub fn matches_snapshot(
        &self,
        snapshot: &RadarSnapshot,
        identity: &RadarClientIdentity,
        now: SystemTime,
    ) -> bool {
        if self.is_empty() {
            return false;
        }
        if let Some(max_age) = self.max_age {
            if snapshot.age(now) > max_age {
                return false;
            }
        }
        if !self.has_primary_field() {
            // Entry-level filters only: any entry passing them matches.
            return snapshot.all_entries().any(|entry| self.entry_ok(entry));
        }
        if let Some(selector) = self.source_asn_attacking {
            let Some(asn) = selector.resolve(identity) else {
                return false;
            };
            if !self.any_entry(snapshot, &[RadarEndpoint::DdosL7], |entry| {
                entry.asn == Some(asn)
            }) {
                return false;
            }
        }
        if let Some(selector) = self.source_asn_attacking_l34 {
            let Some(asn) = selector.resolve(identity) else {
                return false;
            };
            if !self.any_entry(snapshot, &[RadarEndpoint::DdosL34], |entry| {
                entry.asn == Some(asn)
            }) {
                return false;
            }
        }
        if let Some(selector) = &self.source_country_attacking {
            let Some(country) = selector.resolve(identity) else {
                return false;
            };
            if !self.any_entry(
                snapshot,
                &[RadarEndpoint::DdosL7, RadarEndpoint::DdosL34],
                |entry| country_matches(entry, &country),
            ) {
                return false;
            }
        }
        if let Some(selector) = self.target_asn_attacked {
            let Some(asn) = selector.resolve(identity) else {
                return false;
            };
            if !self.any_entry(snapshot, &[RadarEndpoint::TrafficAnomalies], |entry| {
                entry.asn == Some(asn)
            }) {
                return false;
            }
        }
        if let Some(selector) = &self.target_country_attacked {
            let Some(country) = selector.resolve(identity) else {
                return false;
            };
            if !self.any_entry(snapshot, &[RadarEndpoint::TrafficAnomalies], |entry| {
                country_matches(entry, &country)
            }) {
                return false;
            }
        }
        if let Some(selector) = self.source_asn_hijacking {
            let Some(asn) = selector.resolve(identity) else {
                return false;
            };
            if !self.any_entry(snapshot, &[RadarEndpoint::BgpHijacks], |entry| {
                entry.asn == Some(asn) && kind_contains(entry, "hijack")
            }) {
                return false;
            }
        }
        if let Some(selector) = self.target_prefix_hijacked {
            let Some(asn) = selector.resolve(identity) else {
                return false;
            };
            if !self.any_entry(snapshot, &[RadarEndpoint::BgpHijacks], |entry| {
                entry.asn == Some(asn) && !kind_contains(entry, "leak")
            }) {
                return false;
            }
        }
        if let Some(selector) = self.source_asn_leaking {
            let Some(asn) = selector.resolve(identity) else {
                return false;
            };
            if !self.any_entry(
                snapshot,
                &[RadarEndpoint::BgpHijacks, RadarEndpoint::TrafficAnomalies],
                |entry| entry.asn == Some(asn) && kind_contains(entry, "leak"),
            ) {
                return false;
            }
        }
        if let Some(selector) = self.source_asn_anomalous {
            let Some(asn) = selector.resolve(identity) else {
                return false;
            };
            if !self.any_entry(
                snapshot,
                &[
                    RadarEndpoint::DdosL7,
                    RadarEndpoint::DdosL34,
                    RadarEndpoint::TrafficAnomalies,
                ],
                |entry| entry.asn == Some(asn),
            ) {
                return false;
            }
        }
        true
    }

    /// Whether any entry of `endpoints` satisfies `extra` plus the entry-level filters.
    fn any_entry(
        &self,
        snapshot: &RadarSnapshot,
        endpoints: &[RadarEndpoint],
        extra: impl Fn(&RadarEntry) -> bool,
    ) -> bool {
        endpoints
            .iter()
            .flat_map(|endpoint| snapshot.entries(*endpoint))
            .any(|entry| self.entry_ok(entry) && extra(entry))
    }

    /// Entry-level filters: magnitude threshold and anomaly kind.
    fn entry_ok(&self, entry: &RadarEntry) -> bool {
        if let Some(minimum) = self.min_magnitude {
            match entry.magnitude {
                Some(magnitude) if magnitude >= minimum => {}
                _ => return false,
            }
        }
        if !self.anomaly_type.is_empty() {
            let Some(kind) = entry.kind.as_deref() else {
                return false;
            };
            if !self
                .anomaly_type
                .iter()
                .any(|wanted| normalize_kind(kind) == normalize_kind(wanted))
            {
                return false;
            }
        }
        true
    }
}

/// Whether an entry's country equals `country` (case-insensitive).
fn country_matches(entry: &RadarEntry, country: &str) -> bool {
    entry
        .country
        .as_deref()
        .is_some_and(|entry_country| entry_country.eq_ignore_ascii_case(country))
}

/// Whether an entry's kind contains `needle` (case-insensitive, `_`/`-`/space are equivalent).
fn kind_contains(entry: &RadarEntry, needle: &str) -> bool {
    let Some(kind) = entry.kind.as_deref() else {
        return false;
    };
    normalize_kind(kind).contains(&normalize_kind(needle))
}

/// Lowercase and fold `-`/space into `_` so `route-leak`, `route leak` and `route_leak` agree.
fn normalize_kind(kind: &str) -> String {
    kind.to_ascii_lowercase().replace(['-', ' '], "_")
}

/// Parse an ASN selector: `true` means "the client's ASN", a number/string names an ASN.
fn asn_selector(value: &Value) -> Result<Option<AsnSelector>, String> {
    match value {
        Value::Bool(true) => Ok(Some(AsnSelector::Client)),
        Value::Bool(false) | Value::Null => Ok(None),
        Value::Number(number) => number
            .as_u64()
            .map(|asn| Some(AsnSelector::Asn(asn)))
            .ok_or_else(|| "ASN must be a non-negative integer".to_string()),
        Value::String(text) => text
            .trim()
            .parse::<u64>()
            .map(|asn| Some(AsnSelector::Asn(asn)))
            .map_err(|_| format!("`{text}` is not an ASN")),
        _ => Err("ASN field expects true, a number or a numeric string".to_string()),
    }
}

/// Parse a country selector: `true` means "the client's country", a string names one.
fn country_selector(value: &Value) -> Result<Option<CountrySelector>, String> {
    match value {
        Value::Bool(true) => Ok(Some(CountrySelector::Client)),
        Value::Bool(false) | Value::Null => Ok(None),
        Value::String(country) if !country.trim().is_empty() => Ok(Some(CountrySelector::Country(
            country.trim().to_ascii_uppercase(),
        ))),
        Value::String(_) => Err("country code must not be empty".to_string()),
        _ => Err("country field expects true or an ISO 3166-1 alpha-2 code".to_string()),
    }
}

/// Parse a string or array of strings.
fn string_list(value: &Value, field: &str) -> Result<Vec<String>, String> {
    match value {
        Value::String(text) => Ok(vec![text.clone()]),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{field}` must be a string or an array of strings"))
            })
            .collect(),
        _ => Err(format!("`{field}` must be a string or an array of strings")),
    }
}

/// Parse a number, accepting a numeric string (Caddyfile adapters emit text).
fn number(value: &Value, field: &str) -> Result<f64, String> {
    match value {
        Value::Number(number) => number
            .as_f64()
            .ok_or_else(|| format!("`{field}` is not a number")),
        Value::String(text) => text
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("`{field}` is not a number")),
        _ => Err(format!("`{field}` must be a number")),
    }
}

/// Parse a duration: seconds as a number, or `500ms`/`30s`/`5m`/`2h`.
fn duration(value: &Value, field: &str) -> Result<Duration, String> {
    match value {
        Value::Number(number) => number
            .as_f64()
            .filter(|seconds| *seconds >= 0.0)
            .map(Duration::from_secs_f64)
            .ok_or_else(|| format!("`{field}` must be a non-negative number of seconds")),
        Value::String(text) => {
            let text = text.trim();
            let (digits, unit) = match text
                .find(|character: char| !character.is_ascii_digit() && character != '.')
            {
                Some(index) => text.split_at(index),
                None => (text, ""),
            };
            let amount = digits
                .parse::<f64>()
                .map_err(|_| format!("`{field}` is not a duration: `{text}`"))?;
            let multiplier = match unit.trim() {
                "" | "s" => 1.0,
                "ms" => 0.001,
                "m" => 60.0,
                "h" => 3600.0,
                "d" => 86_400.0,
                other => return Err(format!("`{field}` has unknown unit `{other}`")),
            };
            let seconds = amount * multiplier;
            (seconds >= 0.0)
                .then(|| Duration::from_secs_f64(seconds))
                .ok_or_else(|| format!("`{field}` must not be negative"))
        }
        _ => Err(format!(
            "`{field}` must be a number of seconds or a duration string"
        )),
    }
}

/// The `@radar` matcher.
///
/// When the state is disabled the matcher is false for every configuration; on a match,
/// [`Matcher::matches_mut`] publishes the [`radar variables`](crate::radar_vars) into
/// [`Request::vars`] so access logs, headers and rate-limit keys can use them.
pub struct RadarMatcher {
    predicate: RadarPredicate,
    state: Arc<RadarState>,
    geoip: Arc<dyn GeoIpProvider>,
    trust_cdn: Arc<dyn TrustCdnResolver>,
}

impl RadarMatcher {
    /// Build a matcher over `state`.
    pub fn new(
        predicate: RadarPredicate,
        state: Arc<RadarState>,
        geoip: Arc<dyn GeoIpProvider>,
        trust_cdn: Arc<dyn TrustCdnResolver>,
    ) -> Self {
        Self {
            predicate,
            state,
            geoip,
            trust_cdn,
        }
    }

    /// Build a matcher from its JSON form (the `match` object under `@radar`).
    pub fn from_json(
        value: &Value,
        state: Arc<RadarState>,
        geoip: Arc<dyn GeoIpProvider>,
        trust_cdn: Arc<dyn TrustCdnResolver>,
    ) -> Result<Self, MatcherError> {
        let predicate = RadarPredicate::from_json(value).map_err(|message| MatcherError {
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
            message,
        })?;
        Ok(Self::new(predicate, state, geoip, trust_cdn))
    }

    /// The configured predicate.
    pub fn predicate(&self) -> &RadarPredicate {
        &self.predicate
    }

    /// The state this matcher reads.
    pub fn state(&self) -> &Arc<RadarState> {
        &self.state
    }

    fn context(&self) -> RadarContext<'_> {
        RadarContext::new(
            self.state.as_ref(),
            self.geoip.as_ref(),
            self.trust_cdn.as_ref(),
        )
    }
}

impl fmt::Debug for RadarMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RadarMatcher")
            .field("predicate", &self.predicate)
            .field("enabled", &self.state.is_enabled())
            .finish()
    }
}

impl Matcher for RadarMatcher {
    fn matches(&self, request: &Request) -> bool {
        if !self.state.is_enabled() || self.predicate.is_empty() {
            return false;
        }
        let context = self.context();
        let Some(identity) = context.identify(request) else {
            return false;
        };
        self.predicate
            .matches_snapshot(&context.state.snapshot(), &identity, SystemTime::now())
    }

    fn matches_mut(&self, request: &mut Request) -> bool {
        let matched = self.matches(request);
        if matched {
            let variables = crate::radar_vars::RadarVars::from_context(self.context());
            variables.populate(request);
        }
        matched
    }

    fn describe(&self) -> String {
        let fields = self.predicate.describe();
        if fields.is_empty() {
            "radar(empty)".to_string()
        } else {
            format!("radar({fields})")
        }
    }
}
