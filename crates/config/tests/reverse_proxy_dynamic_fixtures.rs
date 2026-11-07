//! Exact-output fixtures for `reverse_proxy { dynamic ... }` (T-CONF-052).
//!
//! These live outside `fixtures/local` because core validation deliberately still rejects
//! `dynamic_upstreams` with T-PROXY-036 (the runtime support landed separately); the adapter
//! output is compared against Caddy v2.11.9 here, while the validation gate is tracked outside
//! this task's scope.

use std::path::PathBuf;

use serde_json::Value;

#[test]
fn dynamic_upstream_fixtures_match_caddy_exactly() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dynamic");
    let mut fixtures: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "caddyfile")
        })
        .collect();
    fixtures.sort();
    assert!(
        !fixtures.is_empty(),
        "no dynamic fixtures in {}",
        dir.display()
    );
    for caddyfile in fixtures {
        let name = caddyfile.file_stem().expect("stem").to_string_lossy();
        let input = std::fs::read_to_string(&caddyfile)
            .unwrap_or_else(|error| panic!("read {}: {error}", caddyfile.display()));
        let expected_text = std::fs::read_to_string(caddyfile.with_extension("json"))
            .unwrap_or_else(|error| panic!("read expected JSON for {name}: {error}"));
        let expected: Value = serde_json::from_str(&expected_text)
            .unwrap_or_else(|error| panic!("expected JSON for {name}: {error}"));
        let adapted =
            caddy_rs_config::adapt(&input).unwrap_or_else(|error| panic!("adapt {name}: {error}"));
        assert_eq!(adapted.config, expected, "adapted JSON differs for {name}");
    }
}
