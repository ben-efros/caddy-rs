//! Behavioural tests for the SNI router and its generation-scoped reloads.

use std::sync::Arc;

use caddy_rs_l4::{
    FallbackConfig, FallbackReason, HttpConfig, PassthroughConfig, RouteDefinition, RouteError,
    SniAction, SniRouter, TerminateConfig,
};

fn terminate(host: &str) -> SniAction {
    SniAction::Terminate(TerminateConfig::new(host).unwrap())
}

fn passthrough(upstream: &str) -> SniAction {
    SniAction::Passthrough(PassthroughConfig::new(upstream).unwrap())
}

fn fallback() -> SniAction {
    SniAction::Fallback(FallbackConfig::new(FallbackReason::NoRoute))
}

fn route(host: &str, action: SniAction) -> RouteDefinition {
    RouteDefinition::new(host, action).expect("valid route definition")
}

#[test]
fn matches_exact_and_wildcard_patterns_with_longest_suffix_first() {
    let router = SniRouter::new(
        vec![
            route("example.com", terminate("example.com")),
            route("*.example.com", terminate("example.com")),
            route("*.b.example.com", passthrough("127.0.0.1:8443")),
            route("*.example.net", passthrough("127.0.0.1:8444")),
        ],
        fallback(),
    )
    .unwrap();

    // Exact beats wildcard.
    assert_eq!(router.lookup(Some("example.com")).host(), "example.com");
    // Case-insensitive SNI.
    assert_eq!(router.lookup(Some("ExAmPlE.CoM")).host(), "example.com");
    // Wildcard at a label boundary; the apex is not matched by the wildcard.
    assert_eq!(
        router.lookup(Some("www.example.com")).host(),
        "*.example.com"
    );
    assert_eq!(
        router.lookup(Some("badexample.com")).action_kind(),
        "fallback"
    );
    // Longest suffix wins for a nested name.
    assert_eq!(
        router.lookup(Some("x.b.example.com")).host(),
        "*.b.example.com"
    );
    assert_eq!(
        router.lookup(Some("x.b.example.com")).action_kind(),
        "passthrough"
    );
    // Wildcards are scoped to their suffix.
    assert_eq!(router.lookup(Some("x.example.net")).host(), "*.example.net");
    assert_eq!(
        router.lookup(Some("x.example.org")).action_kind(),
        "fallback"
    );
}

#[test]
fn unmatched_and_missing_sni_go_to_the_fallback_action() {
    let router = SniRouter::new(
        vec![route("example.com", terminate("example.com"))],
        SniAction::Http(HttpConfig::new(None).unwrap().with_h2c(true)),
    )
    .unwrap();
    for sni in [None, Some(""), Some("unknown.example")] {
        let matched = router.lookup(sni);
        assert_eq!(matched.host(), "");
        assert_eq!(matched.action_kind(), "http");
        assert_eq!(matched.action(), router.fallback().action());
    }
    assert_eq!(router.generation().len(), 1);
}

#[test]
fn reload_swaps_the_whole_generation_and_old_routes_keep_serving() {
    let router = SniRouter::new(
        vec![route("old.example", terminate("old.example"))],
        fallback(),
    )
    .unwrap();

    // A connection that matched before the reload holds this Arc<Route>.
    let in_flight = router.lookup(Some("old.example"));
    assert_eq!(in_flight.action_kind(), "terminate");

    let previous = router
        .load(vec![
            route("old.example", passthrough("127.0.0.1:9443")),
            route("new.example", terminate("new.example")),
        ])
        .expect("valid reload");
    assert_eq!(previous.len(), 1, "the replaced generation is returned");
    assert_eq!(
        previous.lookup(Some("old.example")).action_kind(),
        "terminate"
    );

    // The in-flight connection keeps the generation it matched...
    assert_eq!(in_flight.host(), "old.example");
    assert_eq!(in_flight.action_kind(), "terminate");
    // ...while new lookups see the new generation.
    assert_eq!(
        router.lookup(Some("old.example")).action_kind(),
        "passthrough"
    );
    assert_eq!(
        router.lookup(Some("new.example")).action_kind(),
        "terminate"
    );
    assert_eq!(router.generation().len(), 2);
}

#[test]
fn a_failed_reload_leaves_the_active_generation_untouched() {
    let router = SniRouter::new(
        vec![route("example.com", terminate("example.com"))],
        fallback(),
    )
    .unwrap();
    let before = router.generation();

    // A reload whose table cannot be built (duplicate pattern) is rejected before the swap.
    let error = router
        .load(vec![
            route("example.com", passthrough("127.0.0.1:9443")),
            route("EXAMPLE.com", terminate("example.com")),
        ])
        .expect_err("duplicate host must be rejected");
    assert!(matches!(error, RouteError::DuplicateHost(_)));

    assert_eq!(router.generation().len(), before.len());
    assert_eq!(
        router.lookup(Some("example.com")).action_kind(),
        "terminate"
    );
    assert_eq!(
        router.lookup(Some("unknown.example")).action_kind(),
        "fallback"
    );
}

#[test]
fn duplicate_patterns_and_invalid_configs_are_typed_errors() {
    let duplicate = SniRouter::new(
        vec![
            route("example.com", terminate("example.com")),
            route("Example.COM", terminate("example.com")),
        ],
        fallback(),
    )
    .expect_err("duplicate exact host");
    assert!(matches!(duplicate, RouteError::DuplicateHost(_)));

    let invalid = RouteDefinition::new("*.", terminate("example.com"));
    assert!(matches!(invalid, Err(RouteError::InvalidHost { .. })));

    let invalid_config = TerminateConfig::new("bad name");
    assert!(invalid_config.is_err());
}

#[test]
fn atomic_reload_serves_old_and_new_generations_to_concurrent_lookups() {
    let router = Arc::new(
        SniRouter::new(
            vec![route("example.com", terminate("example.com"))],
            fallback(),
        )
        .unwrap(),
    );

    let mut readers = Vec::new();
    for _ in 0..8 {
        let router = Arc::clone(&router);
        readers.push(std::thread::spawn(move || {
            for _ in 0..2_000 {
                let matched = router.lookup(Some("example.com"));
                assert_eq!(matched.host(), "example.com");
                // The table always contains a complete, validated route.
                assert!(
                    matches!(matched.action_kind(), "terminate" | "passthrough"),
                    "unexpected action {}",
                    matched.action_kind()
                );
            }
        }));
    }

    for generation in 0..50 {
        let action = if generation % 2 == 0 {
            passthrough("127.0.0.1:9443")
        } else {
            terminate("example.com")
        };
        router
            .load(vec![
                route("example.com", action),
                route("extra.example", terminate("extra.example")),
            ])
            .expect("valid reload");
        assert_eq!(router.generation().len(), 2);
    }
    for reader in readers {
        reader.join().expect("reader thread");
    }
}

#[test]
fn route_and_table_expose_their_compiled_shape() {
    let router = SniRouter::new(
        vec![
            route("example.com", terminate("example.com")),
            route("*.example.com", terminate("example.com")),
        ],
        fallback(),
    )
    .unwrap();
    let table = router.generation();
    assert_eq!(table.len(), 2);
    assert_eq!(table.wildcard_count(), 1);
    assert!(!table.is_empty());
    assert_eq!(table.fallback().host(), "");
    let wildcard = table.lookup(Some("a.example.com"));
    assert!(wildcard.is_wildcard());
    assert_eq!(wildcard.wildcard_suffix(), Some(".example.com"));
    let exact = table.lookup(Some("example.com"));
    assert!(!exact.is_wildcard());
    assert_eq!(exact.wildcard_suffix(), None);
}
