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

fn assert_adapts_like_caddy(name: &str) {
    let (caddyfile, expected) = fixture(name);
    let adapted = adapt(&caddyfile).unwrap_or_else(|e| panic!("adapt {name}: {e}"));
    assert_eq!(adapted.config, expected, "adapted JSON differs for {name}");
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
