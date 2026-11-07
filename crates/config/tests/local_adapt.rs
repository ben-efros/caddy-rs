//! Locally authored adapter fixtures for the supported directive subset.
//!
//! Each `.caddyfile` has a `.json` sibling holding the exact JSON this build emits. The pairs are
//! the reviewed shape of our compatibility contract; changing one is a contract change.

use std::path::PathBuf;

use caddy_rs_config::adapt;
use serde_json::Value;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/local")
}

/// Registry used for the validation half of the check.
///
/// The `acme_server` runtime handler is being implemented concurrently with the adapter
/// (T-CONF-054). Until the HTTP runtime registers `http.handlers.acme_server`, the fixtures that
/// emit that handler are validated against a metadata-only module record, so their adapted shape
/// is still checked without pretending the runtime module exists. Once the real module is
/// registered this stub is skipped.
fn validation_registry() -> caddy_rs_core::ModuleRegistry {
    let registry = caddy_rs_core::ModuleRegistry::builtin();
    if registry.contains("http.handlers.acme_server") {
        return registry;
    }
    registry
        .overlay([caddy_rs_core::Module::new(
            "http.handlers.acme_server",
            "acme_server",
            caddy_rs_core::ModuleKind::HttpHandler,
            "ACME server handler (adapt-only; runtime handler in progress)",
        )])
        .expect("register acme_server metadata stub")
}

fn local_fixtures() -> Vec<(String, PathBuf, PathBuf)> {
    let dir = fixture_dir();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "caddyfile"))
        .collect();
    entries.sort();
    assert!(
        !entries.is_empty(),
        "no local fixtures in {}",
        dir.display()
    );
    entries
        .into_iter()
        .map(|caddyfile| {
            let expected = caddyfile.with_extension("json");
            let name = caddyfile
                .file_stem()
                .expect("stem")
                .to_string_lossy()
                .to_string();
            (name, caddyfile, expected)
        })
        .collect()
}

#[test]
fn local_fixtures_have_exact_output_and_validate() {
    let registry = validation_registry();
    for (name, caddyfile, expected_path) in local_fixtures() {
        let input = std::fs::read_to_string(&caddyfile)
            .unwrap_or_else(|e| panic!("read {}: {e}", caddyfile.display()));
        let expected_text = std::fs::read_to_string(&expected_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", expected_path.display()));
        let expected: Value = serde_json::from_str(&expected_text)
            .unwrap_or_else(|e| panic!("expected JSON for {name}: {e}"));

        let adapted = adapt(&input).unwrap_or_else(|e| panic!("adapt {name}: {e}"));
        assert_eq!(adapted.config, expected, "adapted JSON differs for {name}");

        let config = caddy_rs_core::Config::from_value(expected)
            .unwrap_or_else(|e| panic!("decode adapted config for {name}: {e}"));
        caddy_rs_core::validate_config(&config, &registry)
            .unwrap_or_else(|e| panic!("adapted config for {name} must validate: {e}"));
    }
}
