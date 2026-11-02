//! Differential tests against Caddy's own `caddyfile_adapt` golden outputs.
//!
//! Each fixture is split into a Caddyfile and the JSON Caddy v2.11.7 emits for it. The adapter
//! must produce semantically identical JSON (object key order is not significant).

use caddy_rs_config::adapt;
use serde_json::{json, Value};

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
fn internal_name_shared_with_hostless_key_gets_internal_policy() {
    // A hostname on a block with a hostless key is not a route-matcher host, so Caddy manages its
    // certificate explicitly and uses the internal issuer for non-public names.
    let adapted = adapt(":443, localhost {\n\trespond \"hi\"\n}\n")
        .expect("internal name shared with a hostless key adapts");
    let tls = &adapted.config["apps"]["tls"];
    assert_eq!(tls["certificates"]["automate"], json!(["localhost"]));
    assert_eq!(
        tls["automation"]["policies"],
        json!([{
            "subjects": ["localhost"],
            "issuers": [{"module": "internal"}],
        }])
    );
}

#[test]
fn reverse_proxy_h2c_shorthand_matches_caddy() {
    // `unix+h2c//run/app.sock` adapts to a `unix//...` dial plus an h2c transport.
    assert_adapts_like_caddy("reverse_proxy_h2c_shorthand.caddyfiletest");
}

#[test]
fn unix_upstream_dials_are_verbatim_without_default_ports() {
    // Caddy parses network addresses with SplitNetworkAddress: everything before the first `/`
    // is the network, the rest is the host verbatim, and unix networks never get a default port
    // appended. `unix+h2c` becomes a `unix/...` dial plus an h2c transport.
    for (target, expected_dial, expected_h2c) in [
        ("unix//run/app.sock", "unix//run/app.sock", false),
        ("unix/run/app.sock", "unix/run/app.sock", false),
        ("unix+h2c//run/app.sock", "unix//run/app.sock", true),
        ("unix+h2c/run/app.sock", "unix/run/app.sock", true),
    ] {
        let caddyfile = format!(":8080 {{\n\treverse_proxy {target}\n}}\n");
        let adapted = adapt(&caddyfile).unwrap_or_else(|error| panic!("adapt `{target}`: {error}"));
        let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
        let dial = handler["upstreams"][0]["dial"]
            .as_str()
            .unwrap_or_else(|| panic!("no dial string for `{target}`"));
        assert_eq!(dial, expected_dial, "dial for `{target}`");
        assert!(
            !dial.ends_with(":80"),
            "unix dial for `{target}` must not get a default port: {dial}"
        );
        if expected_h2c {
            assert_eq!(
                handler["transport"]["versions"],
                json!(["h2c", "2"]),
                "h2c transport for `{target}`"
            );
        } else {
            assert!(
                handler.get("transport").is_none(),
                "unexpected transport for `{target}`"
            );
        }
    }
}

#[test]
fn reverse_proxy_health_method_matches_caddy() {
    assert_adapts_like_caddy("reverse_proxy_health_method.caddyfiletest");
}

#[test]
fn reverse_proxy_health_path_query_matches_caddy() {
    assert_adapts_like_caddy("reverse_proxy_health_path_query.caddyfiletest");
}

#[test]
fn reverse_proxy_health_request_body_matches_caddy() {
    assert_adapts_like_caddy("reverse_proxy_health_reqbody.caddyfiletest");
}

#[test]
fn reverse_proxy_health_headers_values_match_caddy() {
    // Mirrors Caddy's reverse_proxy_health_headers fixture, with the value that this build's
    // lexer cannot tokenise unquoted (`{system.hostname}`) written quoted instead.
    let caddyfile = ":8884\n\nreverse_proxy 127.0.0.1:65535 {\n\thealth_headers {\n\t\tHost example.com\n\t\tX-Header-Key 95ca39e3cbe7\n\t\tX-Header-Keys VbG4NZwWnipo 335Q9/MhqcNU3s2TO\n\t\tX-Empty-Value\n\t\tSame-Key 1\n\t\tSame-Key 2\n\t\tX-System-Hostname \"{system.hostname}\"\n\t}\n\thealth_uri /health\n}\n";
    let adapted = adapt(caddyfile).unwrap_or_else(|error| panic!("adapt health_headers: {error}"));
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
    assert_eq!(
        handler["health_checks"]["active"],
        json!({
            "uri": "/health",
            "headers": {
                "Host": ["example.com"],
                "X-Header-Key": ["95ca39e3cbe7"],
                "X-Header-Keys": ["VbG4NZwWnipo", "335Q9/MhqcNU3s2TO"],
                "X-Empty-Value": [""],
                "Same-Key": ["1", "2"],
                "X-System-Hostname": ["{system.hostname}"],
            }
        })
    );
}

#[test]
fn reverse_proxy_health_headers_matches_caddy() {
    // Unquoted `{system.hostname}` is a normal word now that the lexer only treats standalone
    // braces as structural (Caddy parity).
    assert_adapts_like_caddy("reverse_proxy_health_headers.caddyfiletest");
}

#[test]
fn reverse_proxy_health_options_emit_caddy_health_checks_shape() {
    let caddyfile = ":8884\n\nreverse_proxy 127.0.0.1:65535 {\n\thealth_uri /health?ready=1\n\thealth_interval 10s\n\thealth_timeout 2s\n\thealth_status 2xx\n\thealth_method HEAD\n\thealth_request_body \"ping\"\n\thealth_body ok\n\thealth_follow_redirects\n\thealth_passes 3\n\thealth_fails 2\n\tmax_fails 4\n\tfail_duration 30s\n\tunhealthy_status 502 5xx\n\tunhealthy_latency 1s\n\tunhealthy_request_count 8\n}\n";
    let adapted = adapt(caddyfile).unwrap_or_else(|error| panic!("adapt health options: {error}"));
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
    assert_eq!(
        handler["health_checks"],
        json!({
            "active": {
                "uri": "/health?ready=1",
                "interval": 10_000_000_000u64,
                "timeout": 2_000_000_000u64,
                "expect_status": 2,
                "method": "HEAD",
                "body": "ping",
                "expect_body": "ok",
                "follow_redirects": true,
                "passes": 3,
                "fails": 2,
            },
            "passive": {
                "max_fails": 4,
                "fail_duration": 30_000_000_000u64,
                "unhealthy_status": [502, 5],
                "unhealthy_latency": 1_000_000_000u64,
                "unhealthy_request_count": 8,
            }
        })
    );
}

#[test]
fn tls_internal_and_email_policies_match_caddy() {
    // `tls internal`, `tls <email>` and global `local_certs` automation policies.
    assert_adapts_like_caddy("tls_automation_policies_3.caddyfiletest");
}

#[test]
fn tls_on_demand_and_local_certs_policies_match_caddy() {
    // `tls { on_demand }` with global `local_certs`; policy consolidation/order.
    assert_adapts_like_caddy("tls_automation_policies_1.caddyfiletest");
}

#[test]
fn tls_global_email_policies_match_caddy() {
    // Global `email` populates the default ACME issuers of the automation policies.
    assert_adapts_like_caddy("tls_automation_policies_4.caddyfiletest");
    assert_adapts_like_caddy("tls_automation_policies_global_email_localhost.caddyfiletest");
}

#[test]
fn tls_ca_and_on_demand_policies_match_caddy() {
    // `tls { ca ... }` (implicit ACME issuer) and a catch-all on-demand block.
    assert_adapts_like_caddy("tls_automation_policies_6.caddyfiletest");
    assert_adapts_like_caddy("tls_automation_policies_5.caddyfiletest");
}

#[test]
fn tls_certificate_files_and_connection_policies_match_caddy() {
    // `tls <cert> <key>` emits certificates.load_files plus a certificate-selection connection
    // policy, including Caddy's SNI shields for wildcard certificates.
    assert_adapts_like_caddy("tls_automation_policies_10.caddyfiletest");
    assert_adapts_like_caddy("tls_automation_wildcard_shadowing.caddyfiletest");
    assert_adapts_like_caddy("tls_conn_policy_consolidate.caddyfiletest");
}

#[test]
fn tls_catch_all_site_enables_connection_policy() {
    // A `tls` directive on a catch-all non-standard port site emits an empty server connection
    // policy plus the internal automation policy.
    assert_adapts_like_caddy("enable_tls_for_catch_all_site.caddyfiletest");
}

#[test]
fn global_acme_dns_maps_to_issuer_dns_challenge() {
    assert_adapts_like_caddy("acme_dns_configured.caddyfiletest");
}

#[test]
fn unsupported_tls_options_are_rejected_loudly() {
    let error =
        adapt("example.com {\n\ttls {\n\t\tclient_auth {\n\t\t\tmode require\n\t\t}\n\t}\n}\n")
            .expect_err("unsupported tls subdirective must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("`tls` option `client_auth`") && message.contains("not supported"),
        "unexpected error: {message}"
    );
}

#[test]
fn tls_inside_a_route_block_is_rejected_loudly() {
    let error = adapt("example.com {\n\troute {\n\t\ttls internal\n\t}\n}\n")
        .expect_err("tls inside a route block must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("`tls`") && message.contains("site block"),
        "unexpected error: {message}"
    );
}

#[test]
fn forward_auth_authelia_matches_caddy() {
    // `forward_auth` adapts to Caddy's canonical reverse_proxy expansion: rewrite to the auth
    // service, forward the original method/URI, and copy response headers on 2xx.
    assert_adapts_like_caddy("forward_auth_authelia.caddyfiletest");
}

#[test]
fn forward_auth_copy_headers_matches_caddy() {
    assert_adapts_like_caddy("forward_auth_copy_headers_strip.caddyfiletest");
    assert_adapts_like_caddy("forward_auth_rename_headers.caddyfiletest");
}

#[test]
fn forward_auth_duplicate_uri_is_rejected_like_caddy() {
    let error = adapt(
        "localhost:9080 {\n\tforward_auth :9091 {\n\t\turi /first\n\t\turi /second\n\t\tcopy_headers Remote-User\n\t}\n\n\trespond \"ok\" 200\n}\n",
    )
    .expect_err("duplicate forward_auth uri must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("cannot re-declare uri: /second"),
        "unexpected error: {message}"
    );
}

#[test]
fn basic_auth_rejects_unknown_hash_algorithm_loudly() {
    let error = adapt(":8085 {\n\tbasic_auth sha256 {\n\t\talice hash\n\t}\n}\n")
        .expect_err("unknown hash algorithm must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("unrecognized hash algorithm: sha256"),
        "unexpected error: {message}"
    );
}
