//! Differential tests against Caddy's own `caddyfile_adapt` golden outputs.
//!
//! Each fixture is split into a Caddyfile and the JSON Caddy v2.11.7 emits for it. The adapter
//! must produce semantically identical JSON (object key order is not significant).

use caddy_rs_config::adapt;
use serde_json::Value;

fn fixture(name: &str) -> (String, Value) {
    let path = format!(
        "{}/tests/fixtures/upstream/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let (caddyfile, expected) = raw
        .split_once("----------")
        .unwrap_or_else(|| panic!("fixture {name} has no `----------` separator"));
    let caddyfile = format!("{}\n", caddyfile.trim());
    let expected: Value = serde_json::from_str(expected.trim())
        .unwrap_or_else(|e| panic!("fixture {name} expected JSON: {e}"));
    (caddyfile, expected)
}

/// Route group names are internal identifiers and caddy-rs may number them differently; DIV-0022
/// documents this. Everything else is compared exactly.
fn normalize_groups(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, item) in object {
                if key == "group" && item.is_string() {
                    *item = Value::String("<group>".to_string());
                } else {
                    normalize_groups(item);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize_groups),
        _ => {}
    }
}

fn assert_adapts_like_caddy(name: &str) {
    let (caddyfile, expected) = fixture(name);
    let adapted = adapt(&caddyfile).unwrap_or_else(|e| panic!("adapt {name}: {e}"));
    let mut actual = adapted.config;
    let mut expected = expected;
    normalize_groups(&mut actual);
    normalize_groups(&mut expected);
    assert_eq!(actual, expected, "adapted JSON differs for {name}");
}

#[test]
fn method_directive_matches_caddy() {
    assert_adapts_like_caddy("method_directive.caddyfiletest");
}

#[test]
fn file_server_pass_thru_matches_caddy() {
    assert_adapts_like_caddy("file_server_pass_thru.caddyfiletest");
}

#[test]
fn reverse_proxy_buffers_matches_caddy() {
    assert_adapts_like_caddy("reverse_proxy_buffers.caddyfiletest");
}

#[test]
fn handle_path_matches_caddy() {
    assert_adapts_like_caddy("handle_path.caddyfiletest");
}

#[test]
fn reverse_proxy_load_balance_matches_caddy() {
    assert_adapts_like_caddy("reverse_proxy_load_balance.caddyfiletest");
}

#[test]
fn not_block_merging_matches_caddy() {
    assert_adapts_like_caddy("not_block_merging.caddyfiletest");
}

#[test]
fn http_only_on_hostless_block_matches_caddy() {
    // Hostless and host keys in one block collapse to a single catch-all route (issue #4113).
    assert_adapts_like_caddy("http_only_on_hostless_block.caddyfiletest");
}

#[test]
fn portless_upstream_matches_caddy() {
    // Upstream shorthand normalisation plus Caddy's site-block specificity ordering.
    assert_adapts_like_caddy("portless_upstream.caddyfiletest");
}

#[test]
fn site_block_sorting_matches_caddy() {
    // Site blocks are ordered by host specificity and a host sharing a hostless key is added to
    // `apps.tls.certificates.automate`.
    assert_adapts_like_caddy("site_block_sorting.caddyfiletest");
}

#[test]
fn sort_directives_within_handle_matches_caddy() {
    // handle/handle_path order by Caddy's path-length rule (`/strip` before `/strip*`).
    assert_adapts_like_caddy("sort_directives_within_handle.caddyfiletest");
}

#[test]
fn all_curated_upstream_fixtures_match_caddy() {
    let directory = format!("{}/tests/fixtures/upstream", env!("CARGO_MANIFEST_DIR"));
    let mut fixtures: Vec<String> = std::fs::read_dir(&directory)
        .unwrap_or_else(|e| panic!("read {directory}: {e}"))
        .map(|entry| {
            entry
                .expect("fixture directory entry")
                .file_name()
                .into_string()
                .expect("utf-8 fixture name")
        })
        .collect();
    fixtures.sort();
    assert!(!fixtures.is_empty(), "no curated upstream fixtures");
    for name in fixtures {
        assert_adapts_like_caddy(&name);
    }
}

#[test]
fn internal_name_shared_with_hostless_key_is_rejected_loudly() {
    // Caddy would emit an internal automation policy for this; caddy-rs does not implement that
    // path yet, so it rejects the configuration with a located error (DIV-0016) rather than
    // silently omitting the policy.
    let error = adapt(":443, localhost {\n\trespond \"hi\"\n}\n")
        .expect_err("internal name shared with a hostless key must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("internal name `localhost`") && message.contains("not supported"),
        "unexpected error: {message}"
    );
}
