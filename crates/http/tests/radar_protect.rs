//! Integration tests for the lazy default protection handlers.
//!
//! The registry must stay empty/inactive until radar is enabled, then expose exactly the defaults
//! (with opt-outs and thresholds applied), and `guard` must pick the first matching rule in
//! `handler_order` — user-defined handlers before the defaults.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use caddy_rs_http::{
    default_rules, ProtectionAction, ProtectionConfig, RadarEndpoint, RadarEntry, RadarPredicate,
    RadarProtection, RadarSnapshot, RadarState, RULE_HIJACKED_PREFIX, RULE_POW_CHALLENGE_ANOMALOUS,
    RULE_RATE_LIMIT_SUSPICIOUS, RULE_TARPIT_ATTACKER,
};
use http::Method;
use serde_json::json;

const AS_ATTACKER: u64 = 13335;
const AS_HIJACKED: u64 = 64500;
const AS_ANOMALOUS: u64 = 64510;
const AS_RATE_LIMITED: u64 = 64511;
const AS_L34_ATTACKER: u64 = 64520;
const AS_BELOW_THRESHOLD: u64 = 64502;

const IP_ATTACKER: &str = "203.0.113.10";
const IP_HIJACKED: &str = "198.51.100.7";
const IP_ANOMALOUS: &str = "198.51.100.8";
const IP_RATE_LIMITED: &str = "198.51.100.9";
const IP_L34_ATTACKER: &str = "198.51.100.10";
const IP_BELOW_THRESHOLD: &str = "203.0.113.21";
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
        vec![entry(
            RadarEndpoint::BgpHijacks,
            AS_HIJACKED,
            "RU",
            Some(0.0),
            "hijack",
        )],
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

fn geoip() -> caddy_rs_http::StaticGeoIp {
    caddy_rs_http::StaticGeoIp::new([
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
            IP_BELOW_THRESHOLD.parse().unwrap(),
            Some(AS_BELOW_THRESHOLD),
            Some("US"),
        ),
    ])
}

struct Harness {
    state: Arc<RadarState>,
    geoip: Arc<caddy_rs_http::StaticGeoIp>,
    trust_cdn: Arc<caddy_rs_http::NoopTrustCdn>,
    protection: Arc<RadarProtection>,
}

impl Harness {
    fn new(config: ProtectionConfig, radar_enabled: bool) -> Self {
        let state = Arc::new(RadarState::new());
        if radar_enabled {
            state.set_enabled(true);
        }
        state.publish(RadarSnapshot::new(entries(), SystemTime::now()));
        let protection = Arc::new(RadarProtection::new(config));
        if radar_enabled {
            protection.refresh(true);
        }
        Self {
            state,
            geoip: Arc::new(geoip()),
            trust_cdn: Arc::new(caddy_rs_http::NoopTrustCdn),
            protection,
        }
    }

    fn guard(&self, ip: &str) -> Option<caddy_rs_http::ProtectionDecision> {
        let mut request = caddy_rs_http::Request::new(Method::GET, "/".parse().unwrap());
        request.remote_addr = Some(SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 40_000));
        let context = caddy_rs_http::RadarContext::new(
            self.state.as_ref(),
            self.geoip.as_ref(),
            self.trust_cdn.as_ref(),
        );
        self.protection.guard(context, &request)
    }

    fn rule_ids(&self) -> Vec<String> {
        self.protection
            .active_rules()
            .into_iter()
            .map(|rule| rule.id)
            .collect()
    }
}

fn defaults() -> Vec<String> {
    default_rules().into_iter().map(|rule| rule.id).collect()
}

#[test]
fn registry_is_lazy_empty_until_radar_enables() {
    let harness = Harness::new(ProtectionConfig::default(), false);
    assert!(!harness.protection.is_active());
    assert!(harness.protection.active_rules().is_empty());
    assert!(harness.guard(IP_ATTACKER).is_none());
    // The idle→enabled transition registers the defaults.
    assert!(harness.protection.refresh(true));
    assert!(harness.protection.is_active());
    assert_eq!(harness.rule_ids(), defaults());
    assert_eq!(
        harness.rule_ids(),
        vec![
            RULE_HIJACKED_PREFIX,
            RULE_TARPIT_ATTACKER,
            RULE_POW_CHALLENGE_ANOMALOUS,
            RULE_RATE_LIMIT_SUSPICIOUS,
        ]
    );
    // Going idle again empties the registry (per-server radar off / auto mode idle).
    assert!(!harness.protection.refresh(false));
    assert!(harness.protection.active_rules().is_empty());
    assert!(harness.guard(IP_ATTACKER).is_none());
}

#[test]
fn defaults_fire_in_order_for_each_action() {
    let harness = Harness::new(ProtectionConfig::default(), true);
    let decision = harness.guard(IP_HIJACKED).expect("hijacked prefix blocks");
    assert_eq!(decision.rule_id, RULE_HIJACKED_PREFIX);
    assert_eq!(decision.action, ProtectionAction::Block);

    let decision = harness
        .guard(IP_ATTACKER)
        .expect("active attacker is tarpitted");
    assert_eq!(decision.rule_id, RULE_TARPIT_ATTACKER);
    assert_eq!(decision.action, ProtectionAction::Tarpit);

    let decision = harness
        .guard(IP_ANOMALOUS)
        .expect("scanning source gets a challenge");
    assert_eq!(decision.rule_id, RULE_POW_CHALLENGE_ANOMALOUS);
    assert_eq!(decision.action, ProtectionAction::PowChallenge);

    let decision = harness
        .guard(IP_RATE_LIMITED)
        .expect("suspicious source is rate limited");
    assert_eq!(decision.rule_id, RULE_RATE_LIMIT_SUSPICIOUS);
    assert_eq!(
        decision.action,
        ProtectionAction::RateLimit {
            rate: 100,
            burst: 20
        }
    );

    // An L3/4-only attacker is "anomalous" but not an L7 attacker: the tarpit does not fire, the
    // rate-limit default does.
    let decision = harness.guard(IP_L34_ATTACKER).expect("rate limited");
    assert_eq!(decision.rule_id, RULE_RATE_LIMIT_SUSPICIOUS);

    // No GeoIP entry and no peer address: nothing fires.
    assert!(harness.guard(IP_UNKNOWN).is_none());
    let mut request = caddy_rs_http::Request::new(Method::GET, "/".parse().unwrap());
    request.remote_addr = None;
    let context = caddy_rs_http::RadarContext::new(
        harness.state.as_ref(),
        harness.geoip.as_ref(),
        harness.trust_cdn.as_ref(),
    );
    assert!(harness.protection.guard(context, &request).is_none());
}

#[test]
fn protect_false_removes_all_handlers() {
    let mut config = ProtectionConfig::default();
    config.enabled = false;
    let harness = Harness::new(config, true);
    assert!(harness.protection.active_rules().is_empty());
    assert!(!harness.protection.is_active());
    assert!(harness.guard(IP_HIJACKED).is_none());
    // `protect false` parses from JSON too.
    let config = ProtectionConfig::from_json(&json!(false)).unwrap();
    assert!(!config.enabled);
}

#[test]
fn per_server_radar_off_wins() {
    let mut config = ProtectionConfig::default();
    config.server_radar_off = true;
    let harness = Harness::new(config, true);
    assert!(!harness.protection.refresh(true));
    assert!(harness.guard(IP_HIJACKED).is_none());
    // Even with radar enabled in the runtime, the state gate is checked again in `guard`.
    let mut config = ProtectionConfig::default();
    config.server_radar_off = false;
    let harness = Harness::new(config, false);
    harness.protection.refresh(true); // rules built, but the state is idle
    assert!(harness.guard(IP_HIJACKED).is_none());
}

#[test]
fn per_rule_disable_removes_one_rule() {
    let config = ProtectionConfig::from_json(&json!({
        "rule": {
            "hijacked_prefix": {"enabled": false},
            "pow_challenge_anomalous": {"enabled": false}
        }
    }))
    .unwrap();
    let harness = Harness::new(config, true);
    assert_eq!(
        harness.rule_ids(),
        vec![RULE_TARPIT_ATTACKER, RULE_RATE_LIMIT_SUSPICIOUS]
    );
    // A hijacked client now falls through to the tarpit (it is also an L7 attacker).
    let decision = harness.guard(IP_HIJACKED).expect("tarpit");
    assert_eq!(decision.rule_id, RULE_TARPIT_ATTACKER);
    // The disabled proof-of-work rule no longer fires; the rate limit catches the source.
    let decision = harness.guard(IP_ANOMALOUS).expect("rate limit");
    assert_eq!(decision.rule_id, RULE_RATE_LIMIT_SUSPICIOUS);
}

#[test]
fn custom_thresholds_change_the_rules() {
    let config = ProtectionConfig::from_json(&json!({
        "rule": {
            "tarpit_attacker": {"min_magnitude": 20000},
            "rate_limit_suspicious": {"rate": 5, "burst": 1}
        }
    }))
    .unwrap();
    let harness = Harness::new(config, true);
    let tarpit = harness
        .protection
        .active_rules()
        .into_iter()
        .find(|rule| rule.id == RULE_TARPIT_ATTACKER)
        .expect("tarpit rule");
    assert_eq!(tarpit.predicate.min_magnitude, Some(20_000.0));
    let rate_limit = harness
        .protection
        .active_rules()
        .into_iter()
        .find(|rule| rule.id == RULE_RATE_LIMIT_SUSPICIOUS)
        .expect("rate limit rule");
    assert_eq!(
        rate_limit.action,
        ProtectionAction::RateLimit { rate: 5, burst: 1 }
    );

    // 12000 < 20000: no tarpit, the suspicious rate limit applies.
    let decision = harness.guard(IP_ATTACKER).expect("rate limit");
    assert_eq!(decision.rule_id, RULE_RATE_LIMIT_SUSPICIOUS);
    // Just below the default 5000 threshold never tarpits, with the default config either.
    let harness = Harness::new(ProtectionConfig::default(), true);
    let decision = harness.guard(IP_BELOW_THRESHOLD).expect("rate limit");
    assert_ne!(decision.rule_id, RULE_TARPIT_ATTACKER);
}

#[test]
fn user_defined_handlers_run_before_defaults() {
    let config = ProtectionConfig::from_json(&json!({
        "handler": [
            {
                "name": "deny_ddos_sources",
                "action": "block",
                "predicate": {"source_asn_attacking": true}
            }
        ]
    }))
    .unwrap();
    let harness = Harness::new(config, true);
    assert_eq!(harness.rule_ids()[0], "deny_ddos_sources");
    let decision = harness.guard(IP_ATTACKER).expect("user rule wins");
    assert_eq!(decision.rule_id, "deny_ddos_sources");
    assert_eq!(decision.action, ProtectionAction::Block);
    assert!(decision.handler_order < 100, "user order precedes defaults");
    // Unaffected clients still reach the default rules.
    assert_eq!(
        harness.guard(IP_RATE_LIMITED).unwrap().rule_id,
        RULE_RATE_LIMIT_SUSPICIOUS
    );
    // An explicit order sorts a user rule after the defaults it outranks.
    let config = ProtectionConfig::from_json(&json!({
        "handler": [
            {
                "name": "late_block",
                "order": 900,
                "action": "block",
                "predicate": {"source_asn_attacking": true}
            }
        ]
    }))
    .unwrap();
    let harness = Harness::new(config, true);
    assert_eq!(harness.rule_ids().last().unwrap(), "late_block");
    assert_eq!(
        harness.guard(IP_ATTACKER).unwrap().rule_id,
        RULE_TARPIT_ATTACKER
    );
}

#[test]
fn config_parses_the_protect_block() {
    let config = ProtectionConfig::from_json(&json!({
        "enabled": true,
        "server_radar_off": false,
        "rule": {
            "hijacked_prefix": {"enabled": false},
            "tarpit_attacker": {"min_magnitude": "8000"},
            "pow_challenge_anomalous": {"anomaly_type": ["scanning", "botnet"]}
        },
        "handler": [{
            "name": "deny_anomalous",
            "order": 1,
            "action": "rate_limit",
            "rate": 10,
            "burst": 2,
            "predicate": {"source_asn_anomalous": true}
        }]
    }))
    .unwrap();
    assert!(config.enabled);
    assert!(!config.server_radar_off);
    assert!(config.rule_disabled(RULE_HIJACKED_PREFIX));
    assert_eq!(config.user_rules.len(), 1);
    assert_eq!(
        config.user_rules[0].action,
        ProtectionAction::RateLimit { rate: 10, burst: 2 }
    );
    assert_eq!(
        config.user_rules[0].predicate,
        RadarPredicate {
            source_asn_anomalous: Some(caddy_rs_http::AsnSelector::Client),
            ..RadarPredicate::default()
        }
    );
    assert!(ProtectionConfig::from_json(&json!({"nope": true})).is_err());
    assert!(ProtectionConfig::from_json(&json!({"handler": [{"predicate": {}}]})).is_err());
}

#[derive(Debug)]
struct StubTransport;

#[async_trait::async_trait]
impl caddy_rs_http::RadarTransport for StubTransport {
    async fn get(&self, url: &str, _token: Option<&str>) -> Result<(u16, Vec<u8>), String> {
        let body = if url.ends_with("/ddos/l7") {
            r#"{"result":[{"asn":13335,"country":"US","magnitude":12000,"kind":"volumetric"}]}"#
        } else {
            r#"{"result":[]}"#
        };
        Ok((200, body.as_bytes().to_vec()))
    }
}

#[derive(Debug)]
struct TestLog;

impl caddy_rs_http::RadarLog for TestLog {
    fn info(&self, _line: &str) {}
}

fn request(ip: &str) -> caddy_rs_http::Request {
    let mut request = caddy_rs_http::Request::new(Method::GET, "/".parse().unwrap());
    request.remote_addr = Some(SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 40_000));
    request
}

#[tokio::test]
async fn runtime_sync_is_the_lazy_registration_trigger() {
    let mut config = caddy_rs_http::RadarConfig::default();
    config.mode = caddy_rs_http::RadarMode::Auto;
    let client = caddy_rs_http::RadarClient::new(
        config,
        Arc::new(StubTransport),
        Arc::new(caddy_rs_http::MemoryStorage::new()),
        Arc::new(TestLog),
    );
    let protection = Arc::new(RadarProtection::new(ProtectionConfig::default()));
    let runtime = caddy_rs_http::RadarRuntime::new(
        Arc::new(RadarState::new()),
        Arc::new(geoip()),
        Arc::new(caddy_rs_http::NoopTrustCdn),
        Arc::clone(&protection),
    );

    // Auto mode is idle: no snapshot, no handlers, no decisions.
    let transition = runtime.sync(&client).await;
    assert!(!transition.enabled);
    assert!(!transition.idle_to_enabled);
    assert!(protection.active_rules().is_empty());
    assert!(runtime.guard(&request(IP_ATTACKER)).is_none());

    // The auto-mode gate opens on the first Internet-routable client IP; the next sync publishes
    // the polled snapshot and registers the defaults.
    assert!(
        client
            .on_client_ip("203.0.113.10".parse().unwrap(), Some(AS_ATTACKER))
            .await
    );
    client.poll_once().await;
    let transition = runtime.sync(&client).await;
    assert!(transition.enabled);
    assert!(transition.idle_to_enabled);
    assert_eq!(transition.entries, 1);
    assert!(protection.is_active());
    assert_eq!(protection.active_rules().len(), 4);
    let decision = runtime.guard(&request(IP_ATTACKER)).expect("tarpit");
    assert_eq!(decision.rule_id, RULE_TARPIT_ATTACKER);
    // The gated hook is the only pipeline entry point; a disabled state disarms it again.
    runtime.state.set_enabled(false);
    protection.refresh(false);
    assert!(runtime.guard(&request(IP_ATTACKER)).is_none());
}
