//! `{http.request.radar.*}` request variables.
//!
//! Caddy's replacer resolves a placeholder by asking the request-scoped [`Replacer`] and finally
//! falling back to [`Request::vars`]; the `file` matcher already publishes
//! `matchers.file.*` that way. This module follows the same idiom:
//!
//! * [`RadarVars::populate`] writes every `http.request.radar.*` value into [`Request::vars`], so
//!   [`Replacer`](crate::placeholders::Replacer), the `headers` handler and any rate-limit key
//!   resolve `{http.request.radar.source_asn_attacking}` with no extra plumbing.
//! * [`RadarVars::resolve`] returns one value directly for callers that hold a request and want a
//!   single string (log fields, header values, key templates).
//! * [`resolve_radar_variable`] is the free-function form of the same lookup.
//!
//! Values are empty when radar is disabled (the auto-mode idle case), when the request has no peer
//! address, or when Radar knows nothing about the client. See [`crate::radar_matcher`] for how the
//! client IP → ASN/country resolution works (`GeoIpProvider` + `trust_cdn`).

use std::collections::BTreeSet;
use std::time::SystemTime;

use crate::radar_client::RadarEndpoint;
use crate::radar_matcher::{
    AsnSelector, GeoIpProvider, RadarClientIdentity, RadarContext, RadarPredicate, RadarSnapshot,
    RadarState, TrustCdnResolver,
};
use crate::types::Request;

/// Prefix of every Radar request variable.
pub const VARIABLE_PREFIX: &str = "http.request.radar.";

/// The variable names, without [`VARIABLE_PREFIX`].
pub const RADAR_VARIABLES: [&str; 12] = [
    "source_asn_attacking",
    "source_asn_attacking_l34",
    "source_country_attacking",
    "target_asn_attacked",
    "source_asn_hijacking",
    "target_prefix_hijacked",
    "source_asn_leaking",
    "source_asn_anomalous",
    "anomaly_types",
    "attack_magnitude_l7",
    "attack_magnitude_l34",
    "data_age",
];

/// The variable names, without the `http.request.radar.` prefix.
pub fn variable_names() -> &'static [&'static str] {
    &RADAR_VARIABLES
}

/// The Radar variables for one request.
///
/// Construct one with [`RadarVars::new`] (state + GeoIP + `trust_cdn`) or
/// [`RadarVars::from_context`] when a [`RadarContext`] is already available.
#[derive(Clone, Copy)]
pub struct RadarVars<'a> {
    context: RadarContext<'a>,
}

impl<'a> RadarVars<'a> {
    /// Build from the three request-path handles.
    pub fn new(
        state: &'a RadarState,
        geoip: &'a dyn GeoIpProvider,
        trust_cdn: &'a dyn TrustCdnResolver,
    ) -> Self {
        Self {
            context: RadarContext::new(state, geoip, trust_cdn),
        }
    }

    /// Build from an existing context.
    pub fn from_context(context: RadarContext<'a>) -> Self {
        Self { context }
    }

    /// Resolve one variable.
    ///
    /// `name` may be the bare name (`source_asn_attacking`) or the full placeholder name
    /// (`http.request.radar.source_asn_attacking`). Unknown names and known-but-unknown values both
    /// return `""`, mirroring Caddy's known-but-empty placeholders.
    pub fn resolve(&self, request: &Request, name: &str) -> String {
        let name = name.strip_prefix(VARIABLE_PREFIX).unwrap_or(name);
        if !RADAR_VARIABLES.contains(&name) {
            return String::new();
        }
        if !self.context.state.is_enabled() {
            return String::new();
        }
        let snapshot = self.context.state.snapshot();
        if snapshot.entry_count() == 0 {
            return String::new();
        }
        if name == "data_age" {
            return snapshot.age(SystemTime::now()).as_secs().to_string();
        }
        let Some(identity) = self.context.identify(request) else {
            return String::new();
        };
        match name {
            "source_asn_attacking" => self.asn_variable(&snapshot, &identity, |predicate| {
                predicate.source_asn_attacking = Some(AsnSelector::Client);
            }),
            "source_asn_attacking_l34" => self.asn_variable(&snapshot, &identity, |predicate| {
                predicate.source_asn_attacking_l34 = Some(AsnSelector::Client);
            }),
            "target_asn_attacked" => self.asn_variable(&snapshot, &identity, |predicate| {
                predicate.target_asn_attacked = Some(AsnSelector::Client);
            }),
            "source_asn_hijacking" => self.asn_variable(&snapshot, &identity, |predicate| {
                predicate.source_asn_hijacking = Some(AsnSelector::Client);
            }),
            "target_prefix_hijacked" => self.asn_variable(&snapshot, &identity, |predicate| {
                predicate.target_prefix_hijacked = Some(AsnSelector::Client);
            }),
            "source_asn_leaking" => self.asn_variable(&snapshot, &identity, |predicate| {
                predicate.source_asn_leaking = Some(AsnSelector::Client);
            }),
            "source_asn_anomalous" => self.asn_variable(&snapshot, &identity, |predicate| {
                predicate.source_asn_anomalous = Some(AsnSelector::Client);
            }),
            "source_country_attacking" => {
                self.country_variable(&snapshot, &identity, |predicate| {
                    predicate.source_country_attacking =
                        Some(crate::radar_matcher::CountrySelector::Client);
                })
            }
            "anomaly_types" => self.anomaly_types(&snapshot, &identity),
            "attack_magnitude_l7" => {
                magnitude_variable(&snapshot, &identity, RadarEndpoint::DdosL7)
            }
            "attack_magnitude_l34" => {
                magnitude_variable(&snapshot, &identity, RadarEndpoint::DdosL34)
            }
            _ => String::new(),
        }
    }

    /// Write every variable into [`Request::vars`] under its full
    /// `http.request.radar.` name, and return how many were written.
    ///
    /// Doing this from the matcher's `matches_mut` (and from the protection hook) means a `headers`
    /// handler or a rate-limit key later in the same request resolves the placeholders through the
    /// normal [`Replacer`](crate::placeholders::Replacer) fallback.
    pub fn populate(&self, request: &mut Request) -> usize {
        for name in RADAR_VARIABLES {
            let value = self.resolve(request, name);
            request
                .vars
                .insert(format!("{VARIABLE_PREFIX}{name}"), value);
        }
        RADAR_VARIABLES.len()
    }

    /// The ASN text when `predicate` holds for the client, else `""`.
    fn asn_variable(
        &self,
        snapshot: &RadarSnapshot,
        identity: &RadarClientIdentity,
        set: impl Fn(&mut RadarPredicate),
    ) -> String {
        let Some(asn) = identity.asn else {
            return String::new();
        };
        let mut predicate = RadarPredicate::default();
        set(&mut predicate);
        if predicate.matches_snapshot(snapshot, identity, SystemTime::now()) {
            asn.to_string()
        } else {
            String::new()
        }
    }

    /// The country text when `predicate` holds for the client, else `""`.
    fn country_variable(
        &self,
        snapshot: &RadarSnapshot,
        identity: &RadarClientIdentity,
        set: impl Fn(&mut RadarPredicate),
    ) -> String {
        let Some(country) = identity.country.as_deref() else {
            return String::new();
        };
        let mut predicate = RadarPredicate::default();
        set(&mut predicate);
        if predicate.matches_snapshot(snapshot, identity, SystemTime::now()) {
            country.to_ascii_uppercase()
        } else {
            String::new()
        }
    }

    /// Comma-separated, sorted, deduplicated anomaly kinds naming the client's ASN.
    fn anomaly_types(&self, snapshot: &RadarSnapshot, identity: &RadarClientIdentity) -> String {
        let Some(asn) = identity.asn else {
            return String::new();
        };
        let kinds: BTreeSet<&str> = snapshot
            .all_entries()
            .filter(|entry| entry.asn == Some(asn))
            .filter_map(|entry| entry.kind.as_deref())
            .collect();
        kinds.into_iter().collect::<Vec<_>>().join(",")
    }
}

/// Highest magnitude Radar reports for the client's ASN on `endpoint`, as text.
fn magnitude_variable(
    snapshot: &RadarSnapshot,
    identity: &RadarClientIdentity,
    endpoint: RadarEndpoint,
) -> String {
    let Some(asn) = identity.asn else {
        return String::new();
    };
    let maximum = snapshot
        .entries(endpoint)
        .iter()
        .filter(|entry| entry.asn == Some(asn))
        .filter_map(|entry| entry.magnitude)
        .fold(None::<f64>, |current, magnitude| {
            Some(current.map_or(magnitude, |current| current.max(magnitude)))
        });
    maximum.map(|value| value.to_string()).unwrap_or_default()
}

/// Resolve one Radar variable for callers that do not want to build [`RadarVars`] (log fields,
/// header values, rate-limit key templates). Empty string when radar is disabled or unknown.
pub fn resolve_radar_variable(
    state: &RadarState,
    geoip: &dyn GeoIpProvider,
    trust_cdn: &dyn TrustCdnResolver,
    request: &Request,
    name: &str,
) -> String {
    RadarVars::new(state, geoip, trust_cdn).resolve(request, name)
}
