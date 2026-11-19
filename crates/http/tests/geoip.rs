//! End-to-end tests for the production GeoIP provider (T-ROUTE-062, ADR-0020, DIV-0151).
//!
//! These run against the **real** MaxMind DB fixtures in `tests/fixtures/` (see the README there),
//! so they exercise the actual `.mmdb` parser rather than a fake. The expected values are the ones
//! the upstream fixture databases actually contain; they were read out of the files with a probe
//! before being written down here, not assumed.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use caddy_rs_http::geoip::{GeoIpPaths, GeoIpProduct, GeoIpStats, MmdbGeoIp};
use caddy_rs_http::{GeoIpProvider, NoopGeoIp};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn both_databases() -> GeoIpPaths {
    GeoIpPaths {
        asn: Some(fixture("GeoIP2-ISP-Test.mmdb")),
        country: Some(fixture("GeoIP2-Country-Test.mmdb")),
    }
}

fn provider(paths: &GeoIpPaths) -> Arc<dyn GeoIpProvider> {
    Arc::new(
        MmdbGeoIp::open(paths, |message: &str| eprintln!("{message}"))
            .expect("fixture databases must open")
            .expect("fixture databases exist, so a provider must be built"),
    )
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("test address must parse")
}

#[test]
fn resolves_asn_and_country_for_a_known_address() {
    // The acceptance criterion: a real database resolves ASN and country for a known IP.
    let provider = provider(&both_databases());
    let location = provider
        .lookup(ip("89.160.20.112"))
        .expect("89.160.20.112 is in both fixture databases");

    assert_eq!(location.asn, Some(29518), "ASN from the ISP fixture");
    assert_eq!(
        location.country.as_deref(),
        Some("SE"),
        "country from the country fixture, upper-cased"
    );
}

#[test]
fn resolves_asn_when_only_the_asn_database_is_configured() {
    // A partial configuration is useful: ASN resolves, country reports unknown, and the lookup
    // still returns Some because one attribute was found.
    let paths = GeoIpPaths {
        asn: Some(fixture("GeoIP2-ISP-Test.mmdb")),
        country: None,
    };
    let provider = provider(&paths);
    let location = provider.lookup(ip("1.128.0.1")).expect("ASN is known");
    assert_eq!(location.asn, Some(1221));
    assert_eq!(
        location.country, None,
        "no country database means country is unknown, not an error"
    );
}

#[test]
fn resolves_country_when_only_the_country_database_is_configured() {
    let paths = GeoIpPaths {
        asn: None,
        country: Some(fixture("GeoIP2-Country-Test.mmdb")),
    };
    let provider = provider(&paths);
    let location = provider
        .lookup(ip("2.125.160.216"))
        .expect("country is known");
    assert_eq!(location.asn, None, "no ASN database means ASN is unknown");
    assert_eq!(location.country.as_deref(), Some("GB"));
}

#[test]
fn an_unknown_address_resolves_to_none() {
    // The "unknown IP" criterion. 10.0.0.1 is private and 203.0.113.5 is TEST-NET-3; neither is in
    // the fixture databases. None is distinct from a provider with no database at all.
    let provider = provider(&both_databases());
    assert_eq!(
        provider.lookup(ip("10.0.0.1")),
        None,
        "a private address has no record"
    );
    assert_eq!(
        provider.lookup(ip("203.0.113.5")),
        None,
        "a documentation address has no record"
    );
}

#[test]
fn a_known_asn_address_reports_unknown_country_rather_than_none() {
    // Distinguishes "this address is covered, but only for ASN" from "this address is unknown":
    // the first returns Some with country None, the second returns None. The radar matcher depends
    // on that difference, because `country == XX` must not match an address it has never seen.
    let provider = provider(&both_databases());
    let location = provider
        .lookup(ip("1.128.0.1"))
        .expect("ASN is known for 1.128.0.1");
    assert_eq!(location.asn, Some(1221));
    assert_eq!(location.country, None);
}

#[test]
fn no_database_configured_falls_back_to_noop_and_never_panics() {
    // The no-database criterion: open returns Ok(None), the caller installs NoopGeoIp, and lookups
    // continue returning None instead of failing.
    let paths = GeoIpPaths {
        asn: Some(fixture("does-not-exist-asn.mmdb")),
        country: Some(fixture("does-not-exist-country.mmdb")),
    };
    let opened = MmdbGeoIp::open(&paths, |message: &str| eprintln!("{message}"))
        .expect("missing optional databases must not be a hard error");
    assert!(
        opened.is_none(),
        "with no usable database the caller must be told to use NoopGeoIp"
    );

    // The fallback provider the caller installs behaves as the no-database case requires.
    let noop = NoopGeoIp;
    assert_eq!(noop.lookup(ip("89.160.20.112")), None);
    assert_eq!(noop.lookup(ip("10.0.0.1")), None);
}

#[test]
fn counters_distinguish_lookups_hits_and_misses() {
    let paths = both_databases();
    let mmdb = MmdbGeoIp::open(&paths, |_: &str| {}).unwrap().unwrap();

    assert_eq!(mmdb.stats(), GeoIpStats::default(), "no lookups yet");

    let hit = mmdb.lookup(ip("89.160.20.112"));
    assert!(hit.is_some());
    let miss = mmdb.lookup(ip("10.0.0.1"));
    assert!(miss.is_none());

    let stats = mmdb.stats();
    assert_eq!(stats.lookups, 2);
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
    assert_eq!(
        stats.lookups,
        stats.hits + stats.misses,
        "every lookup must be exactly one hit or one miss"
    );
}

#[test]
fn a_missing_optional_database_warns_once_naming_the_path() {
    use std::sync::Mutex;
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let paths = GeoIpPaths {
        asn: Some(fixture("absent-asn.mmdb")),
        country: Some(fixture("GeoIP2-Country-Test.mmdb")),
    };
    let opened = MmdbGeoIp::open(&paths, move |message: &str| {
        recorder.lock().unwrap().push(message.to_string());
    })
    .expect("a missing optional database is not a hard error");
    assert!(opened.is_some(), "the country database is usable");

    let messages = seen.lock().unwrap();
    assert_eq!(
        messages.len(),
        1,
        "exactly one warning for one missing database: {messages:?}"
    );
    assert!(
        messages[0].contains("absent-asn.mmdb"),
        "the warning must name the path: {:?}",
        messages[0]
    );
}

#[test]
fn provider_is_usable_as_the_trait_object_the_matcher_takes() {
    // The wiring path: RadarMatcher::new takes Arc<dyn GeoIpProvider>, so the provider must
    // coerce and be callable through the trait.
    let boxed: Arc<dyn GeoIpProvider> = provider(&both_databases());
    assert!(boxed.lookup(ip("89.160.20.112")).is_some());
}

#[test]
fn products_are_the_two_documented_words() {
    assert_eq!(GeoIpProduct::parse("dbip"), Some(GeoIpProduct::DbIp));
    assert_eq!(GeoIpProduct::parse("maxmind"), Some(GeoIpProduct::MaxMind));
    assert_eq!(GeoIpProduct::DbIp.as_str(), "dbip");
    assert_eq!(GeoIpProduct::MaxMind.as_str(), "maxmind");
}

// ---------------------------------------------------------------------------------------------
// Provider selection: turning the adapted `geoip` option into the trait object the matcher takes.
// ---------------------------------------------------------------------------------------------

use caddy_rs_http::geoip::{select_provider, GeoIpConfigEntry};

#[test]
fn no_configured_entries_selects_noop_without_warning() {
    // Nothing configured is the default and is not a mistake, so it must not warn.
    let selected = select_provider(&[]);
    assert!(
        selected.mmdb.is_none(),
        "no database means no concrete provider"
    );
    assert!(
        selected.warnings.is_empty(),
        "an unconfigured geoip option must be silent: {:?}",
        selected.warnings
    );
    assert_eq!(selected.provider.lookup(ip("89.160.20.112")), None);
}

#[test]
fn configured_entries_select_a_real_provider_that_resolves() {
    // The wiring criterion: given the adapted config, selection produces a provider that actually
    // resolves, so the matcher would get a working lookup rather than NoopGeoIp.
    let asn = fixture("GeoIP2-ISP-Test.mmdb");
    let country = fixture("GeoIP2-Country-Test.mmdb");
    let entries = [
        GeoIpConfigEntry {
            provider: GeoIpProduct::MaxMind,
            path: asn.to_str().unwrap(),
        },
        GeoIpConfigEntry {
            provider: GeoIpProduct::MaxMind,
            path: country.to_str().unwrap(),
        },
    ];
    let selected = select_provider(&entries);
    assert!(selected.mmdb.is_some(), "a real provider must be selected");
    assert!(selected.warnings.is_empty(), "{:?}", selected.warnings);

    let location = selected
        .provider
        .lookup(ip("89.160.20.112"))
        .expect("the selected provider resolves the fixture address");
    assert_eq!(location.asn, Some(29518));
    assert_eq!(location.country.as_deref(), Some("SE"));
}

#[test]
fn selection_classifies_asn_and_country_paths_by_name() {
    // One entry per database: the ASN path supplies ASN, the country path supplies country. If
    // classification were wrong the wrong reader would be asked and one attribute would be lost.
    let asn = fixture("GeoIP2-ISP-Test.mmdb");
    let country = fixture("GeoIP2-Country-Test.mmdb");
    let entries = [
        GeoIpConfigEntry {
            provider: GeoIpProduct::MaxMind,
            path: asn.to_str().unwrap(),
        },
        GeoIpConfigEntry {
            provider: GeoIpProduct::MaxMind,
            path: country.to_str().unwrap(),
        },
    ];
    let selected = select_provider(&entries);
    let mmdb = selected.mmdb.as_ref().expect("a provider was selected");

    // ASN comes from the ISP database, country from the country database.
    let location = mmdb.lookup(ip("89.160.20.112")).expect("known address");
    assert_eq!(
        location.asn,
        Some(29518),
        "ASN must come from the ASN database"
    );
    assert_eq!(
        location.country.as_deref(),
        Some("SE"),
        "country must come from the country database"
    );
}

#[test]
fn a_single_asn_entry_selects_a_provider_that_resolves_asn_only() {
    let asn = fixture("GeoIP2-ISP-Test.mmdb");
    let entries = [GeoIpConfigEntry {
        provider: GeoIpProduct::DbIp,
        path: asn.to_str().unwrap(),
    }];
    let selected = select_provider(&entries);
    let location = selected
        .provider
        .lookup(ip("1.128.0.1"))
        .expect("ASN known");
    assert_eq!(location.asn, Some(1221));
    assert_eq!(location.country, None, "no country database was configured");
}

#[test]
fn entries_that_cannot_open_fall_back_to_noop_and_explain_why() {
    // Fail open: the server keeps serving, but the operator is told. Silence here would leave ASN
    // predicates permanently unmatchable with no clue why.
    let entries = [GeoIpConfigEntry {
        provider: GeoIpProduct::DbIp,
        path: "/nonexistent/dbip-asn-lite.mmdb",
    }];
    let selected = select_provider(&entries);
    assert!(selected.mmdb.is_none(), "no database opened");
    assert!(
        !selected.warnings.is_empty(),
        "a failed selection must explain itself"
    );
    assert!(
        selected
            .warnings
            .iter()
            .any(|w| w.contains("/nonexistent/dbip-asn-lite.mmdb")),
        "the warning must name the path: {:?}",
        selected.warnings
    );
    assert_eq!(selected.provider.lookup(ip("89.160.20.112")), None);
}

#[test]
fn selection_exposes_counters_through_the_concrete_provider() {
    let asn = fixture("GeoIP2-ISP-Test.mmdb");
    let entries = [GeoIpConfigEntry {
        provider: GeoIpProduct::MaxMind,
        path: asn.to_str().unwrap(),
    }];
    let selected = select_provider(&entries);
    let mmdb = selected.mmdb.as_ref().expect("provider selected");

    assert_eq!(mmdb.stats().lookups, 0);
    let _ = selected.provider.lookup(ip("1.128.0.1"));
    let _ = selected.provider.lookup(ip("10.0.0.1"));
    let stats = mmdb.stats();
    assert_eq!(
        stats.lookups, 2,
        "counters must observe lookups made through the trait object"
    );
    assert_eq!(stats.hits + stats.misses, 2);
}

#[test]
fn uncovered_addresses_never_warn_on_the_request_path() {
    // The module docs previously claimed a per-request lookup error "is logged once per provider"
    // through a warning-setter method that never existed. The truth is that lookups never emit
    // anything: an uncovered address is the ordinary case, so warning once would a name a single
    // unremarkable address and then stay silent. This test pins the real contract so the doc
    // cannot drift back into promising a warning that no code produces.
    use std::sync::Mutex;

    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let opened = MmdbGeoIp::open(&both_databases(), move |message: &str| {
        recorder.lock().unwrap().push(message.to_string());
    })
    .expect("both fixture databases are valid");
    let provider = opened.expect("both fixture databases are present");

    // Startup must be silent: nothing is missing, so there is nothing to warn about. Any message
    // recorded from here on would therefore belong to the lookups below.
    assert!(
        seen.lock().unwrap().is_empty(),
        "opening two valid databases must not warn: {:?}",
        seen.lock().unwrap()
    );

    // Many uncovered addresses, through both the concrete type and the trait object, because the
    // request path holds the trait object.
    let boxed: &dyn GeoIpProvider = &provider;
    for _ in 0..10 {
        for addr in [
            "10.0.0.1",
            "203.0.113.5",
            "192.0.2.7",
            "198.51.100.9",
            "::1",
        ] {
            assert_eq!(provider.lookup(ip(addr)), None, "{addr} has no record");
            assert_eq!(boxed.lookup(ip(addr)), None, "{addr} has no record");
        }
    }

    assert!(
        seen.lock().unwrap().is_empty(),
        "lookups must never warn, got: {:?}",
        seen.lock().unwrap()
    );
}

#[test]
fn the_counters_still_record_every_uncovered_lookup_it_did_not_warn_about() {
    // Failing open silently must not mean failing open invisibly: the counters are how an operator
    // learns that the database is not covering their traffic. This is the observable substitute for
    // the warning the docs used to promise.
    let provider = caddy_rs_http::geoip::MmdbGeoIp::open(&both_databases(), |_| {})
        .expect("both fixture databases are valid")
        .expect("both fixture databases are present");

    let before = provider.stats();
    assert_eq!(
        before.lookups, 0,
        "a fresh provider has not looked up anything"
    );

    for _ in 0..5 {
        assert_eq!(provider.lookup(ip("203.0.113.5")), None);
    }

    let after = provider.stats();
    assert_eq!(after.lookups, 5, "every lookup is counted");
    assert_eq!(after.misses, 5, "uncovered addresses count as misses");
    assert_eq!(after.hits, 0, "an uncovered address is never a hit");
}
