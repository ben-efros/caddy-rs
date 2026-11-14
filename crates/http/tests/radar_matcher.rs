//! Integration tests for the `@radar` matcher and `{http.request.radar.*}` variables.
//!
//! The fixture is a realistic snapshot of the four Radar endpoints plus a static GeoIP table; no
//! test reaches the network. Every predicate field is exercised true and false, thresholds are
//! probed on their boundaries, and the disabled (auto-mode idle) state must match nothing and
//! report empty variables.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use caddy_rs_http::{
    resolve_radar_variable, variable_names, GeoIpProvider, Matcher, NoopGeoIp, NoopTrustCdn,
    RadarEndpoint, RadarEntry, RadarMatcher, RadarPredicate, RadarSnapshot, RadarState, RadarVars,
    Replacer, Request, StaticGeoIp, StaticTrustCdn, TrustCdnResolver,
};
use http::{header, Method};
use serde_json::{json, Value};

const AS_ATTACKER: u64 = 13335;
const AS_HIJACKED: u64 = 64500;
const AS_ANOMALOUS: u64 = 64510;
const AS_RATE_LIMITED: u64 = 64511;
const AS_L34_ATTACKER: u64 = 64520;
const AS_EXACT_THRESHOLD: u64 = 64501;
const AS_BELOW_THRESHOLD: u64 = 64502;
const AS_LEAKER: u64 = 4134;

const IP_ATTACKER: &str = "203.0.113.10";
const IP_HIJACKED: &str = "198.51.100.7";
const IP_ANOMALOUS: &str = "198.51.100.8";
const IP_RATE_LIMITED: &str = "198.51.100.9";
const IP_L34_ATTACKER: &str = "198.51.100.10";
const IP_EXACT_THRESHOLD: &str = "203.0.113.20";
const IP_BELOW_THRESHOLD: &str = "203.0.113.21";
const IP_LEAKER: &str = "192.0.2.1";
const IP_UNKNOWN: &str = "192.0.2.99";

fn entry(
    endpoint: RadarEndpoint,
    asn: u64,
    country: &str,
    magnitude: Option<f64>,
    kind: &str,
) -> RadarEntry {
    RadarEntry {
        endpoint,
        asn: Some(asn),
        country: Some(country.to_string()),
        magnitude,
        kind: Some(kind.to_string()),
        timestamp: None,
    }
}

fn entries() -> BTreeMap<RadarEndpoint, Vec<RadarEntry>> {
    let mut entries = BTreeMap::new();
    entries.insert(
        RadarEndpoint::DdosL7,
        vec![
            entry(
                RadarEndpoint::DdosL7,
                AS_ATTACKER,
                "US",
                Some(12_000.0),
                "volumetric",
            ),
            entry(
                RadarEndpoint::DdosL7,
                AS_HIJACKED,
                "RU",
                Some(12_000.0),
                "volumetric",
            ),
            entry(
                RadarEndpoint::DdosL7,
                AS_EXACT_THRESHOLD,
                "US",
                Some(5_000.0),
                "volumetric",
            ),
            entry(
                RadarEndpoint::DdosL7,
                AS_BELOW_THRESHOLD,
                "US",
                Some(4_999.0),
                "volumetric",
            ),
        ],
    );
    entries.insert(
        RadarEndpoint::DdosL34,
        vec![entry(
            RadarEndpoint::DdosL34,
            AS_L34_ATTACKER,
            "BR",
            Some(8_000.0),
            "syn_flood",
        )],
    );
    entries.insert(
        RadarEndpoint::BgpHijacks,
        vec![
            entry(
                RadarEndpoint::BgpHijacks,
                AS_HIJACKED,
                "RU",
                Some(0.0),
                "hijack",
            ),
            entry(
                RadarEndpoint::BgpHijacks,
                AS_LEAKER,
                "CN",
                Some(0.0),
                "route_leak",
            ),
        ],
    );
    entries.insert(
        RadarEndpoint::TrafficAnomalies,
        vec![
            entry(
                RadarEndpoint::TrafficAnomalies,
                AS_ANOMALOUS,
                "RU",
                Some(9_000.0),
                "scanning",
            ),
            entry(
                RadarEndpoint::TrafficAnomalies,
                AS_RATE_LIMITED,
                "DE",
                Some(1_000.0),
                "dns",
            ),
            entry(
                RadarEndpoint::TrafficAnomalies,
                AS_ATTACKER,
                "US",
                Some(2_000.0),
                "dns",
            ),
        ],
    );
    entries
}

fn geoip() -> StaticGeoIp {
    StaticGeoIp::new([
        (IP_ATTACKER.parse().unwrap(), Some(AS_ATTACKER), Some("US")),
        (IP_HIJACKED.parse().unwrap(), Some(AS_HIJACKED), Some("RU")),
        (
            IP_ANOMALOUS.parse().unwrap(),
            Some(AS_ANOMALOUS),
            Some("RU"),
        ),
        (
            IP_RATE_LIMITED.parse().unwrap(),
            Some(AS_RATE_LIMITED),
            Some("DE"),
        ),
        (
            IP_L34_ATTACKER.parse().unwrap(),
            Some(AS_L34_ATTACKER),
            Some("BR"),
        ),
        (
            IP_EXACT_THRESHOLD.parse().unwrap(),
            Some(AS_EXACT_THRESHOLD),
            Some("US"),
        ),
        (
            IP_BELOW_THRESHOLD.parse().unwrap(),
            Some(AS_BELOW_THRESHOLD),
            Some("US"),
        ),
        (IP_LEAKER.parse().unwrap(), Some(AS_LEAKER), Some("CN")),
    ])
}

struct Fixture {
    state: Arc<RadarState>,
    geoip: Arc<StaticGeoIp>,
    trust_cdn: Arc<dyn TrustCdnResolver>,
}

impl Fixture {
    fn enabled() -> Self {
        Self::with_entries(entries(), true)
    }

    fn disabled() -> Self {
        Self::with_entries(entries(), false)
    }

    fn with_entries(entries: BTreeMap<RadarEndpoint, Vec<RadarEntry>>, enabled: bool) -> Self {
        let state = Arc::new(RadarState::new());
        if enabled {
            state.set_enabled(true);
        }
        state.publish(RadarSnapshot::new(entries, SystemTime::now()));
        Self {
            state,
            geoip: Arc::new(geoip()),
            trust_cdn: Arc::new(NoopTrustCdn),
        }
    }

    fn matcher(&self, predicate: Value) -> RadarMatcher {
        let predicate = RadarPredicate::from_json(&predicate).expect("predicate");
        RadarMatcher::new(
            predicate,
            Arc::clone(&self.state),
            Arc::clone(&self.geoip) as Arc<dyn GeoIpProvider>,
            Arc::clone(&self.trust_cdn),
        )
    }

    fn matches(&self, predicate: Value, ip: &str) -> bool {
        self.matcher(predicate).matches(&request(ip))
    }

    fn variables(&self, _ip: &str) -> RadarVars<'_> {
        RadarVars::new(
            self.state.as_ref(),
            self.geoip.as_ref(),
            self.trust_cdn.as_ref(),
        )
    }

    fn request(&self, ip: &str) -> Request {
        request(ip)
    }
}

fn request(ip: &str) -> Request {
    let mut request = Request::new(Method::GET, "/".parse().unwrap());
    request.remote_addr = Some(SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 40_000));
    request
}

/// Assert which client IPs match, for the "every field true and false" table.
fn assert_matches(fixture: &Fixture, predicate: Value, yes: &[&str], no: &[&str]) {
    for ip in yes {
        assert!(
            fixture.matches(predicate.clone(), ip),
            "expected {predicate} to match {ip}"
        );
    }
    for ip in no {
        assert!(
            !fixture.matches(predicate.clone(), ip),
            "expected {predicate} to not match {ip}"
        );
    }
}

#[test]
fn source_asn_attacking_requires_an_l7_attack_source() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"source_asn_attacking": true}),
        &[IP_ATTACKER, IP_HIJACKED],
        &[IP_L34_ATTACKER, IP_ANOMALOUS, IP_LEAKER],
    );
}

#[test]
fn source_asn_attacking_l34_uses_the_l34_endpoint() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"source_asn_attacking_l34": true}),
        &[IP_L34_ATTACKER],
        &[IP_ATTACKER, IP_HIJACKED, IP_ANOMALOUS],
    );
}

#[test]
fn source_country_attacking_uses_the_client_country() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"source_country_attacking": true}),
        &[
            IP_ATTACKER,
            IP_HIJACKED,
            IP_L34_ATTACKER,
            IP_ANOMALOUS,
            IP_EXACT_THRESHOLD,
        ],
        &[IP_RATE_LIMITED, IP_LEAKER],
    );
}

#[test]
fn target_asn_attacked_uses_the_anomalies_endpoint() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"target_asn_attacked": true}),
        &[IP_ANOMALOUS, IP_RATE_LIMITED, IP_ATTACKER],
        &[IP_L34_ATTACKER, IP_LEAKER, IP_HIJACKED],
    );
}

#[test]
fn target_country_attacked_uses_the_anomalies_endpoint() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"target_country_attacked": true}),
        &[IP_ANOMALOUS, IP_RATE_LIMITED, IP_ATTACKER, IP_HIJACKED],
        &[IP_L34_ATTACKER, IP_LEAKER],
    );
}

#[test]
fn source_asn_hijacking_requires_a_hijack_record() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"source_asn_hijacking": true}),
        &[IP_HIJACKED],
        &[IP_LEAKER, IP_ATTACKER, IP_ANOMALOUS],
    );
}

#[test]
fn target_prefix_hijacked_keys_on_the_target_asn() {
    let fixture = Fixture::enabled();
    // The snapshot model has no prefix text, so the target ASN is the key; a route-leak record is
    // not a hijacked prefix.
    assert_matches(
        &fixture,
        json!({"target_prefix_hijacked": true}),
        &[IP_HIJACKED],
        &[IP_LEAKER, IP_ATTACKER],
    );
}

#[test]
fn source_asn_leaking_requires_a_leak_kind() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"source_asn_leaking": true}),
        &[IP_LEAKER],
        &[IP_HIJACKED, IP_ATTACKER],
    );
}

#[test]
fn source_asn_anomalous_covers_attack_and_anomaly_records() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"source_asn_anomalous": true}),
        &[IP_ATTACKER, IP_HIJACKED, IP_ANOMALOUS, IP_L34_ATTACKER],
        // A BGP-only record is not an L7/L34/anomaly source.
        &[IP_LEAKER],
    );
}

#[test]
fn explicit_asn_and_country_selectors_constrain_the_client() {
    let fixture = Fixture::enabled();
    assert!(fixture.matches(json!({"source_asn_attacking": AS_ATTACKER}), IP_ATTACKER));
    assert!(!fixture.matches(json!({"source_asn_attacking": AS_ATTACKER}), IP_HIJACKED));
    assert!(fixture.matches(json!({"source_asn_attacking": "13335"}), IP_ATTACKER));
    assert!(fixture.matches(json!({"source_country_attacking": "us"}), IP_ATTACKER));
    assert!(!fixture.matches(json!({"source_country_attacking": "US"}), IP_HIJACKED));
}

#[test]
fn anomaly_type_accepts_a_list_or_a_single_value() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"source_asn_anomalous": true, "anomaly_type": ["scanning", "botnet", "credential_stuffing"]}),
        &[IP_ANOMALOUS],
        &[IP_RATE_LIMITED, IP_L34_ATTACKER, IP_ATTACKER],
    );
    assert_matches(
        &fixture,
        json!({"source_asn_anomalous": true, "anomaly_type": "dns"}),
        &[IP_RATE_LIMITED, IP_ATTACKER],
        &[IP_ANOMALOUS],
    );
    // `route-leak`, `route leak` and `route_leak` all compare equal. Without a primary field the
    // kind filter is a global predicate: it matches while any cached entry has that kind.
    assert!(fixture.matches(json!({"anomaly_type": "route-leak"}), IP_UNKNOWN));
    assert!(!fixture.matches(json!({"anomaly_type": "credential_stuffing"}), IP_UNKNOWN));
}

#[test]
fn min_magnitude_is_inclusive() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"source_asn_attacking": true, "min_magnitude": 5000}),
        &[IP_ATTACKER, IP_HIJACKED, IP_EXACT_THRESHOLD],
        &[IP_BELOW_THRESHOLD, IP_L34_ATTACKER],
    );
    assert!(!fixture.matches(json!({"min_magnitude": 999_999}), IP_ATTACKER));
}

#[test]
fn max_age_rejects_a_stale_snapshot() {
    let state = Arc::new(RadarState::new());
    state.set_enabled(true);
    state.publish(RadarSnapshot::new(
        entries(),
        SystemTime::now() - Duration::from_secs(120),
    ));
    let geoip = Arc::new(geoip());
    let trust_cdn: Arc<dyn TrustCdnResolver> = Arc::new(NoopTrustCdn);
    let matcher = |predicate: Value| {
        RadarMatcher::new(
            RadarPredicate::from_json(&predicate).unwrap(),
            Arc::clone(&state),
            Arc::clone(&geoip) as Arc<dyn GeoIpProvider>,
            Arc::clone(&trust_cdn),
        )
    };
    assert!(
        !matcher(json!({"source_asn_attacking": true, "max_age": 60}))
            .matches(&request(IP_ATTACKER))
    );
    assert!(
        matcher(json!({"source_asn_attacking": true, "max_age": 300}))
            .matches(&request(IP_ATTACKER))
    );
    // String durations are accepted too.
    assert!(
        !matcher(json!({"source_asn_attacking": true, "max_age": "1m"}))
            .matches(&request(IP_ATTACKER))
    );
}

#[test]
fn multiple_fields_are_anded() {
    let fixture = Fixture::enabled();
    assert_matches(
        &fixture,
        json!({"source_asn_attacking": true, "target_asn_attacked": true}),
        &[IP_ATTACKER],
        &[IP_HIJACKED, IP_ANOMALOUS],
    );
    assert_matches(
        &fixture,
        json!({"target_asn_attacked": true, "anomaly_type": "dns"}),
        &[IP_ATTACKER, IP_RATE_LIMITED],
        &[IP_ANOMALOUS, IP_HIJACKED],
    );
}

#[test]
fn empty_predicate_never_matches() {
    let fixture = Fixture::enabled();
    assert!(!fixture.matches(json!({}), IP_ATTACKER));
}

#[test]
fn disabled_radar_matches_nothing() {
    let fixture = Fixture::disabled();
    for predicate in [
        json!({"source_asn_attacking": true}),
        json!({"target_prefix_hijacked": true}),
        json!({"anomaly_type": "dns"}),
        json!({"min_magnitude": 1}),
        json!({"source_asn_attacking": AS_ATTACKER}),
    ] {
        assert!(
            !fixture.matches(predicate.clone(), IP_ATTACKER),
            "disabled radar must not match {predicate}"
        );
    }
}

#[test]
fn trust_cdn_forwarded_ip_is_used_only_for_trusted_peers() {
    let fixture = Fixture::enabled();
    let predicate = RadarPredicate::from_json(&json!({"source_asn_attacking": true})).unwrap();
    let trusted: Arc<dyn TrustCdnResolver> =
        Arc::new(StaticTrustCdn::new(["10.0.0.5".parse().unwrap()]));
    let matcher = |trust_cdn: Arc<dyn TrustCdnResolver>| {
        RadarMatcher::new(
            predicate.clone(),
            Arc::clone(&fixture.state),
            Arc::clone(&fixture.geoip) as Arc<dyn GeoIpProvider>,
            trust_cdn,
        )
    };
    let mut forwarded = request("10.0.0.5");
    forwarded.headers.insert(
        "cf-connecting-ip",
        header::HeaderValue::from_static(IP_ATTACKER),
    );
    assert!(matcher(Arc::clone(&trusted)).matches(&forwarded));
    // The same header from an untrusted peer is ignored: the peer has no GeoIP entry.
    let mut spoofed = request("10.0.0.6");
    spoofed.headers.insert(
        "cf-connecting-ip",
        header::HeaderValue::from_static(IP_ATTACKER),
    );
    assert!(!matcher(Arc::clone(&trusted)).matches(&spoofed));
    // NoopTrustCdn never trusts the header.
    let noop: Arc<dyn TrustCdnResolver> = Arc::new(NoopTrustCdn);
    assert!(!matcher(noop).matches(&forwarded));
}

#[test]
fn matches_mut_publishes_request_variables() {
    let fixture = Fixture::enabled();
    let matcher = fixture.matcher(json!({"source_asn_attacking": true}));
    let mut request = fixture.request(IP_ATTACKER);
    assert!(matcher.matches_mut(&mut request));
    assert_eq!(
        request
            .vars
            .get("http.request.radar.source_asn_attacking")
            .map(String::as_str),
        Some("13335")
    );
    let replacer = Replacer::new(&request);
    assert_eq!(
        replacer.replace_all("{http.request.radar.anomaly_types}"),
        "dns,volumetric"
    );
    // A non-match publishes nothing.
    let mut request = fixture.request(IP_LEAKER);
    assert!(!matcher.matches_mut(&mut request));
    assert!(request.vars.is_empty());
}

#[test]
fn variables_report_each_name_for_a_known_client() {
    let fixture = Fixture::enabled();
    let variables = fixture.variables(IP_ATTACKER);
    let request = request(IP_ATTACKER);
    for (name, expected) in [
        ("source_asn_attacking", "13335"),
        ("source_asn_attacking_l34", ""),
        ("source_country_attacking", "US"),
        ("target_asn_attacked", "13335"),
        ("source_asn_hijacking", ""),
        ("target_prefix_hijacked", ""),
        ("source_asn_leaking", ""),
        ("source_asn_anomalous", "13335"),
        ("anomaly_types", "dns,volumetric"),
        ("attack_magnitude_l7", "12000"),
        ("attack_magnitude_l34", ""),
    ] {
        assert_eq!(
            variables.resolve(&request, name),
            expected,
            "variable {name}"
        );
        assert_eq!(
            variables.resolve(&request, &format!("http.request.radar.{name}")),
            expected,
            "prefixed variable {name}"
        );
    }
    let age = variables
        .resolve(&request, "data_age")
        .parse::<u64>()
        .expect("data_age is seconds");
    assert!(age <= 5, "data_age {age}");
}

#[test]
fn variables_follow_the_client_attributes() {
    let fixture = Fixture::enabled();
    let variables = |ip: &str| {
        let request = request(ip);
        let values: Vec<String> = variable_names()
            .iter()
            .map(|name| fixture.variables(ip).resolve(&request, name))
            .collect();
        values
    };
    let hijacked = variables(IP_HIJACKED);
    assert_eq!(hijacked[4], "64500", "source_asn_hijacking");
    assert_eq!(hijacked[5], "64500", "target_prefix_hijacked");
    assert_eq!(hijacked[8], "hijack,volumetric", "anomaly_types");
    let anomalous = variables(IP_ANOMALOUS);
    assert_eq!(anomalous[3], "64510", "target_asn_attacked");
    assert_eq!(anomalous[8], "scanning", "anomaly_types");
    assert_eq!(anomalous[9], "", "attack_magnitude_l7");
    let l34 = variables(IP_L34_ATTACKER);
    assert_eq!(l34[1], "64520", "source_asn_attacking_l34");
    assert_eq!(l34[10], "8000", "attack_magnitude_l34");
    let leaker = variables(IP_LEAKER);
    assert_eq!(leaker[6], "4134", "source_asn_leaking");
    assert_eq!(leaker[5], "", "target_prefix_hijacked");
    assert_eq!(leaker[8], "route_leak", "anomaly_types");
}

#[test]
fn variables_are_empty_when_radar_is_disabled() {
    let fixture = Fixture::disabled();
    let request = request(IP_ATTACKER);
    for name in variable_names() {
        assert_eq!(
            fixture.variables(IP_ATTACKER).resolve(&request, name),
            "",
            "{name} must be empty while radar is idle"
        );
    }
}

#[test]
fn variables_are_empty_when_nothing_is_known() {
    let fixture = Fixture::enabled();
    let request = request(IP_UNKNOWN);
    for name in variable_names() {
        if *name == "data_age" {
            continue;
        }
        assert_eq!(
            fixture.variables(IP_UNKNOWN).resolve(&request, name),
            "",
            "{name} must be empty for an unknown client"
        );
    }
    // No peer address at all: still empty, never a panic.
    let mut no_peer = Request::new(Method::GET, "/".parse().unwrap());
    no_peer.remote_addr = None;
    assert_eq!(
        fixture
            .variables(IP_UNKNOWN)
            .resolve(&no_peer, "source_asn_attacking"),
        ""
    );
    // Unknown names are empty as well.
    assert_eq!(fixture.variables(IP_ATTACKER).resolve(&request, "nope"), "");
}

#[test]
fn data_age_reports_snapshot_age() {
    let state = Arc::new(RadarState::new());
    state.set_enabled(true);
    state.publish(RadarSnapshot::new(
        entries(),
        SystemTime::now() - Duration::from_secs(42),
    ));
    let geoip = NoopGeoIp;
    let trust_cdn = NoopTrustCdn;
    let request = request(IP_ATTACKER);
    let variables = RadarVars::new(state.as_ref(), &geoip, &trust_cdn);
    let age = variables
        .resolve(&request, "data_age")
        .parse::<u64>()
        .expect("seconds");
    assert!((42..=44).contains(&age), "data_age {age}");
    // An empty snapshot has no data age.
    state.publish(RadarSnapshot::empty());
    assert_eq!(variables.resolve(&request, "data_age"), "");
}

#[test]
fn populate_writes_every_variable_and_the_free_function_agrees() {
    let fixture = Fixture::enabled();
    let mut request = fixture.request(IP_ATTACKER);
    let written = fixture.variables(IP_ATTACKER).populate(&mut request);
    assert_eq!(written, variable_names().len());
    assert_eq!(request.vars.len(), variable_names().len());
    let replacer = Replacer::new(&request);
    assert_eq!(
        replacer.replace_all("{http.request.radar.attack_magnitude_l7}"),
        "12000"
    );
    // The free-function form resolves the same value for a log/header/rate-limit key call site.
    assert_eq!(
        resolve_radar_variable(
            fixture.state.as_ref(),
            fixture.geoip.as_ref(),
            fixture.trust_cdn.as_ref(),
            &request,
            "source_asn_attacking",
        ),
        "13335"
    );
}

#[test]
fn invalid_predicate_fields_are_rejected() {
    assert!(RadarPredicate::from_json(&json!({"nope": true})).is_err());
    assert!(RadarPredicate::from_json(&json!({"min_magnitude": "abc"})).is_err());
    assert!(RadarPredicate::from_json(&json!({"source_asn_attacking": -1})).is_err());
    assert!(RadarPredicate::from_json(&json!({"source_country_attacking": 5})).is_err());
    assert!(RadarPredicate::from_json(&json!({"max_age": "1w"})).is_err());
    assert!(RadarPredicate::from_json(&json!([])).is_err());
}
