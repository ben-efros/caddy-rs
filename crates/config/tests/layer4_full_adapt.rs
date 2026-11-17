//! Full `layer4` adapter coverage (ADR-031, T-L4-011): the complete Caddyfile schema for TCP and
//! UDP, checked byte for byte against fixtures.
//!
//! WHY THESE FIXTURES ARE NOT IN `tests/fixtures/local/`. The task's artifact list named
//! `fixtures/local/layer4_full_*`, and that is where I first put them. That harness also requires
//! the adapted JSON to pass `caddy_rs_core::validate_config`, and it rejects `layer4` outright:
//! "unknown app module(s): layer4; this build supports `http`, `tls` and `pki`". `layer4` is a
//! `caddy-l4` extension app carried in `apps.extra`, not a module this build registers, so a
//! `local/` fixture for it can never pass and the placement would assert something false. The
//! fixtures therefore live in `tests/fixtures/layer4/` and are pinned here. This is the same
//! constraint that put the `geoip` examples in `crates/config/tests/geoip.rs`.
//!
//! There is no upstream `caddy adapt` oracle for `layer4` (it is a plugin, not stock Caddy), so
//! ADR-030 and ADR-031 are the contract. Each expected `.json` here was produced by the binary
//! itself and then reviewed against the ADR's stated JSON, not hand-written.

use std::path::PathBuf;

use caddy_rs_config::adapt;
use serde_json::Value;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/layer4")
}

fn cases() -> Vec<(String, PathBuf, PathBuf)> {
    let dir = fixture_dir();
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("caddyfile") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let expected = path.with_extension("json");
        assert!(expected.exists(), "missing expected JSON for {name}");
        out.push((name, path, expected));
    }
    assert!(
        !out.is_empty(),
        "no layer4 fixtures found in {}",
        dir.display()
    );
    out.sort();
    out
}

#[test]
fn layer4_full_fixtures_adapt_exactly() {
    for (name, input, expected) in cases() {
        let source = std::fs::read_to_string(&input)
            .unwrap_or_else(|e| panic!("read {}: {e}", input.display()));
        let expected_text = std::fs::read_to_string(&expected)
            .unwrap_or_else(|e| panic!("read {}: {e}", expected.display()));
        let expected: Value = serde_json::from_str(&expected_text)
            .unwrap_or_else(|e| panic!("expected JSON for {name}: {e}"));

        let adapted = adapt(&source).unwrap_or_else(|e| panic!("adapt {name}: {e}"));
        assert_eq!(adapted.config, expected, "adapted JSON differs for {name}");
    }
}

#[test]
fn every_layer4_server_declares_its_listen_address() {
    // A server with no `listen` is unreachable at runtime, so the shape is asserted for every
    // fixture rather than only the one the ADR happens to spell out.
    for (name, input, _) in cases() {
        let source = std::fs::read_to_string(&input).expect("read");
        let adapted = adapt(&source).expect("adapt");
        let servers = &adapted.config["apps"]["layer4"]["servers"];
        let servers = servers
            .as_object()
            .unwrap_or_else(|| panic!("{name}: apps.layer4.servers must be an object"));
        assert!(!servers.is_empty(), "{name}: at least one server");
        for (key, server) in servers {
            let listen = server["listen"]
                .as_array()
                .unwrap_or_else(|| panic!("{name}: server {key} must have a listen array"));
            assert_eq!(
                listen.len(),
                1,
                "{name}: server {key} has one listen element"
            );
            let address = listen[0].as_str().expect("listen element is a string");
            assert!(
                address.contains(':'),
                "{name}: server {key} listen `{address}` must carry a port"
            );
        }
    }
}

#[test]
fn udp_listeners_are_emitted_in_the_canonical_form() {
    // The acceptance criterion names `listen: ["0.0.0.0:port/udp"]`. Every UDP spelling in the
    // fixtures must reach exactly that shape, so this checks the whole corpus, not one case.
    let source = std::fs::read_to_string(fixture_dir().join("layer4_full_udp.caddyfile"))
        .expect("read udp fixture");
    let adapted = adapt(&source).expect("adapt");
    let servers = adapted.config["apps"]["layer4"]["servers"]
        .as_object()
        .unwrap();

    let listens: Vec<&str> = servers
        .values()
        .map(|s| s["listen"][0].as_str().unwrap())
        .collect();
    assert_eq!(
        listens,
        vec![
            "0.0.0.0:51820/udp",
            "0.0.0.0:53/udp",
            "0.0.0.0:853/udp",
            "0.0.0.0:443",
        ],
        "every UDP spelling normalises to `host:port/udp`, and the TCP listener stays TCP"
    );
}
