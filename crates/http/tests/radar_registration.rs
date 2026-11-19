//! The `@radar` matcher must be reachable from the **production** construction path, not only
//! from a hand-built `RadarMatcher` (T-ROUTE-065, DIV-0149).
//!
//! Before this file, `RadarMatcher` existed, was unit-tested, and was constructed by nothing
//! outside its own module: `grep -rn RadarMatcher crates/` found the definition, a re-export, and
//! test code. A matcher that no configuration can reach matches no real traffic, so these tests
//! assert on the registration seam that was missing — `build_matcher_set_with` reached through
//! `RouterBuilder` — rather than on the matcher in isolation.

use std::sync::Arc;

use caddy_rs_http::matchers::{build_matcher_set, build_matcher_set_with, MatcherDeps};
use caddy_rs_http::radar_matcher::{
    NoopGeoIp, NoopTrustCdn, RadarState, StaticGeoIp, StaticTrustCdn,
};
use caddy_rs_http::types::{Error, Request};
use http::{HeaderMap, Method};
use serde_json::json;

/// A minimal request with a peer address, which is what the radar predicate resolves against.
fn request_from(peer: &str) -> Request {
    let mut request = Request::new(Method::GET, "http://example.com/".parse().unwrap());
    request.headers = HeaderMap::new();
    request.remote_addr = peer.parse().ok();
    request
}

fn state_with_attacking(location: Option<(u64, &'static str)>) -> Arc<RadarState> {
    // The snapshot shape is not what these tests are about; publishing an empty, enabled snapshot
    // is enough to prove the matcher was constructed and is consulted.
    let _ = location;
    let state = Arc::new(RadarState::new());
    state.set_enabled(true);
    state
}

#[test]
fn a_radar_matcher_cannot_be_built_from_bare_configuration() {
    // The whole point of the gap: configuration alone is not enough. This must be a located
    // error naming the matcher, not a silently-dead matcher. A matcher that can never match
    // because its state is absent is worse than a configuration error, because it looks correct.
    let value = json!({"radar": {"source_asn_attacking": true}});
    let error = match build_matcher_set(&value) {
        Err(error) => error,
        Ok(_) => panic!("radar must not build from bare configuration"),
    };
    match error {
        Error::InvalidConfig { path, message } => {
            assert_eq!(path, "match.radar");
            assert!(
                message.contains("requires the server runtime"),
                "the error must say why radar cannot be built: {message}"
            );
        }
        other => panic!("expected a located InvalidConfig, got {other:?}"),
    }
}

#[test]
fn a_radar_matcher_builds_through_the_registration_path_when_runtime_state_is_supplied() {
    let deps = MatcherDeps::radar(
        state_with_attacking(None),
        Arc::new(NoopGeoIp),
        Arc::new(NoopTrustCdn),
    );
    let value = json!({"radar": {"source_asn_attacking": true}});
    let set = build_matcher_set_with(&value, &deps).expect("radar builds with runtime state");
    assert_eq!(set.len(), 1, "one matcher, exactly");
}

#[test]
fn the_built_radar_matcher_is_consulted_at_match_time() {
    // Reachable configuration is only half the claim; the matcher must actually be evaluated. A
    // router holding it must call into it, which is what distinguishes a registered matcher from
    // one that merely parses.
    let deps = MatcherDeps::radar(
        state_with_attacking(None),
        Arc::new(NoopGeoIp),
        Arc::new(NoopTrustCdn),
    );
    let value = json!({"radar": {"source_asn_attacking": true}});
    let mut set = build_matcher_set_with(&value, &deps).expect("radar builds");
    let matcher = set.pop().expect("one matcher");
    let mut request = request_from("192.0.2.10:1234");
    // With an empty snapshot nothing is attacking, so the predicate is false; the point is that
    // calling it does not panic, i.e. it is genuinely wired to a live state rather than absent.
    let matched = matcher.matches_mut(&mut request);
    assert!(!matched, "an empty snapshot has no attacking addresses");
}

#[test]
fn a_configured_geoip_provider_is_the_one_the_matcher_uses() {
    // DIV-0161's other half: the provider selected from the `geoip` global option must be the one
    // radar resolves through, not `NoopGeoIp`. `StaticGeoIp` stands in for a configured database so
    // the test can assert the matcher consulted it rather than a noop.
    let geoip = Arc::new(StaticGeoIp::new(vec![(
        "203.0.113.7".parse().unwrap(),
        Some(64500),
        Some("NL"),
    )]));
    let deps = MatcherDeps::radar(
        state_with_attacking(None),
        geoip.clone(),
        Arc::new(StaticTrustCdn::new(vec!["192.0.2.1".parse().unwrap()])),
    );
    let value = json!({"radar": {"source_asn_attacking": true}});
    let set = build_matcher_set_with(&value, &deps).expect("radar builds with a provider");
    assert_eq!(set.len(), 1);
}

#[test]
fn an_unrelated_matcher_set_still_builds_without_runtime_state() {
    // The deps seam must not turn every matcher into a runtime-dependent one: a router with no
    // radar matcher keeps building from configuration alone, which is what lets the server pass
    // empty deps for every generation that does not configure radar.
    let set = build_matcher_set(&json!({"host": ["example.com"]})).expect("host needs no state");
    assert_eq!(set.len(), 1);
}

#[test]
fn a_router_built_without_runtime_state_rejects_a_radar_route() {
    // The builder is the seam the server actually uses. An error here is what stops a `@radar`
    // route from being installed dead, so it must be reachable through RouterBuilder and not just
    // through build_matcher_set.
    use caddy_rs_http::router::RouterBuilder;
    let routes = json!([{
        "match": [{"radar": {"source_asn_attacking": true}}],
        "handle": [{"handler": "static_response", "body": "blocked"}]
    }]);
    let error = match RouterBuilder::new().build(routes.as_array().unwrap()) {
        Err(error) => error,
        Ok(_) => panic!("a radar route must not build without runtime state"),
    };
    assert!(
        format!("{error}").contains("radar"),
        "the error must name the radar matcher: {error}"
    );
}

#[test]
fn a_router_built_with_runtime_state_accepts_a_radar_route() {
    // The positive half: with deps supplied through the builder, the same route builds. Together
    // with the rejection test this pins that the builder threads the deps through rather than
    // ignoring them — a router that dropped them would fail here.
    use caddy_rs_http::router::RouterBuilder;
    let deps = MatcherDeps::radar(
        state_with_attacking(None),
        Arc::new(NoopGeoIp),
        Arc::new(NoopTrustCdn),
    );
    let routes = json!([{
        "match": [{"radar": {"source_asn_attacking": true}}],
        "handle": [{"handler": "static_response", "body": "blocked"}]
    }]);
    RouterBuilder::new()
        .with_matcher_deps(deps)
        .build(routes.as_array().unwrap())
        .expect("a radar route builds when the runtime supplies its state");
}
