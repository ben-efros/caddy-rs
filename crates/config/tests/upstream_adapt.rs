//! Differential tests against Caddy's own `caddyfile_adapt` golden outputs.
//!
//! Each fixture is split into a Caddyfile and the JSON Caddy v2.11.7 emits for it. The adapter
//! must produce semantically identical JSON (object key order is not significant).

use caddy_rs_config::{adapt, adapt_with_source};
use serde_json::{json, Value};
use std::path::Path;

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

#[test]
fn invoke_named_routes_match_caddy() {
    // `&(name)` definitions become per-server `named_routes`; `invoke` emits the invoke handler.
    assert_adapts_like_caddy("invoke_named_routes.caddyfiletest");
    assert_adapts_like_caddy("invoke_nested_named_routes.caddyfiletest");
    assert_adapts_like_caddy("import_inside_named_route.caddyfiletest");
    assert_adapts_like_caddy("import_inside_named_route_args.caddyfiletest");
    assert_adapts_like_caddy("import_inside_named_route_block.caddyfiletest");
    assert_adapts_like_caddy("import_inside_named_route_nested.caddyfiletest");
}

#[test]
fn vars_routes_sort_least_specific_first_like_caddy() {
    // Caddy reverses matcher specificity for `vars` so later matching routes win.
    assert_adapts_like_caddy("sort_vars_in_reverse.caddyfiletest");
}

/// File-import fixtures need the Caddyfile's source path so `import testdata/...` resolves the
/// same way as in Caddy's test working directory.
fn assert_adapts_file_fixture_like_caddy(name: &str) {
    let path = format!(
        "{}/tests/fixtures/upstream-imports/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    let (caddyfile, expected) = raw
        .split_once("----------")
        .unwrap_or_else(|| panic!("fixture {name} has no `----------` separator"));
    let caddyfile = format!("{}\n", caddyfile.trim());
    let expected: Value = serde_json::from_str(expected.trim())
        .unwrap_or_else(|error| panic!("fixture {name} expected JSON: {error}"));
    let adapted = adapt_with_source(&caddyfile, Some(Path::new(&path)))
        .unwrap_or_else(|error| panic!("adapt {name}: {error}"));
    let mut actual = adapted.config;
    let mut expected = expected;
    normalize_groups(&mut actual);
    normalize_groups(&mut expected);
    assert_eq!(actual, expected, "adapted JSON differs for {name}");
}

#[test]
fn file_imports_match_caddy() {
    assert_adapts_file_fixture_like_caddy("import_args_file.caddyfiletest");
    assert_adapts_file_fixture_like_caddy(
        "import_block_snippet_non_replaced_block_from_separate_file.caddyfiletest",
    );
}

#[test]
fn header_forms_match_caddy() {
    // `header -Field` one-arg delete, defer, ?field require, response match and `>` deferred
    // set/replace forms all emit Caddy's headers handler JSON.
    assert_adapts_like_caddy("header.caddyfiletest");
}

#[test]
fn file_server_precompressed_and_status_match_caddy() {
    // Empty `precompressed` defaults to br,zstd,gzip (module map + order); `status` is a
    // WeakString that may hold a placeholder.
    assert_adapts_like_caddy("file_server_precompressed.caddyfiletest");
    assert_adapts_like_caddy("file_server_status.caddyfiletest");
}

#[test]
fn matcher_syntax_and_inline_not_match_caddy() {
    // Inline `not <matcher>`, vars/vars_regexp, header null matchers, query merging, inline
    // expression matchers and private_ranges expansion.
    assert_adapts_like_caddy("matcher_syntax.caddyfiletest");
    assert_adapts_like_caddy("sort_directives_with_any_matcher_first.caddyfiletest");
}

#[test]
fn named_matchers_defined_inside_route_match_caddy() {
    assert_adapts_like_caddy("root_directive_permutations.caddyfiletest");
}

#[test]
fn dynamic_upstreams_fail_with_a_construct_specific_error() {
    for name in [
        "reverse_proxy_dynamic_upstreams.caddyfiletest",
        "reverse_proxy_dynamic_upstreams_grace_period.caddyfiletest",
    ] {
        let path = format!(
            "{}/tests/fixtures/unsupported/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw =
            std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
        let (caddyfile, _) = raw
            .split_once("----------")
            .unwrap_or_else(|| panic!("fixture {name} has no `----------` separator"));
        let error = adapt(&caddyfile).expect_err("dynamic upstreams must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("dynamic upstreams are not supported")
                && message.contains("T-PROXY-036"),
            "unexpected error for {name}: {message}"
        );
    }
}

#[test]
fn global_ports_are_emitted_into_apps_http_like_caddy() {
    // The expected values below were confirmed against `caddy adapt` v2.11.7 (release oracle):
    // caddyhttp.App carries http_port/https_port only when the global options set them.
    let both =
        adapt("{\n\thttp_port 8080\n\thttps_port 8443\n}\n\nlocalhost {\n\trespond \"ok\"\n}\n")
            .expect("adapt both ports");
    assert_eq!(both.config["apps"]["http"]["http_port"], json!(8080));
    assert_eq!(both.config["apps"]["http"]["https_port"], json!(8443));

    let https_only = adapt("{\n\thttps_port 8443\n}\n\nlocalhost {\n\trespond \"ok\"\n}\n")
        .expect("adapt https port");
    assert_eq!(https_only.config["apps"]["http"]["https_port"], json!(8443));
    assert!(https_only.config["apps"]["http"].get("http_port").is_none());

    let http_only = adapt("{\n\thttp_port 8080\n}\n\nlocalhost:8080 {\n\trespond \"ok\"\n}\n")
        .expect("adapt http port");
    assert_eq!(http_only.config["apps"]["http"]["http_port"], json!(8080));
    assert!(http_only.config["apps"]["http"].get("https_port").is_none());

    let none = adapt("localhost {\n\trespond \"ok\"\n}\n").expect("adapt defaults");
    assert!(none.config["apps"]["http"].get("http_port").is_none());
    assert!(none.config["apps"]["http"].get("https_port").is_none());
}

#[test]
fn tls_cert_key_emits_caddys_connection_policies() {
    // Verified byte-identical to `caddy adapt` v2.11.7 for this Caddyfile: tag-qualified
    // certificate selection plus an SNI matcher, followed by Caddy's catch-all policy.
    let adapted = adapt("https://localhost:8443 {\n\ttls cert.pem key.pem\n\trespond \"ok\"\n}\n")
        .expect("adapt tls cert/key");
    assert_eq!(
        adapted.config["apps"]["tls"]["certificates"]["load_files"],
        json!([{
            "certificate": "cert.pem",
            "key": "key.pem",
            "tags": ["cert0"],
        }])
    );
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["tls_connection_policies"],
        json!([
            {
                "certificate_selection": {"any_tag": ["cert0"]},
                "match": {"sni": ["localhost"]},
            },
            {},
        ])
    );
}

#[test]
fn bind_ipv6_matches_caddy() {
    assert_adapts_like_caddy("bind_ipv6.caddyfiletest");
}

#[test]
fn log_skip_hosts_matches_caddy() {
    assert_adapts_like_caddy("log_skip_hosts.caddyfiletest");
}

#[test]
fn try_files_matches_real_caddy_v2_11_7() {
    // Golden output from `caddy adapt` v2.11.7 (release oracle) with route groups normalised.
    let adapted =
        adapt("example.com {\n\troot * /srv\n\ttry_files {path} {path}/ /index.html\n}\n")
            .expect("adapt try_files");
    let mut actual = adapted.config;
    normalize_groups(&mut actual);
    let expected: Value = serde_json::from_str(
        r#"{
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "routes": [{
                    "match": [{"host": ["example.com"]}],
                    "handle": [{
                        "handler": "subroute",
                        "routes": [
                            {"handle": [{"handler": "vars", "root": "/srv"}]},
                            {"handle": [{"handler": "rewrite", "uri": "{http.matchers.file.relative}"}],
                             "match": [{"file": {"try_files": [
                                 "{http.request.uri.path}",
                                 "{http.request.uri.path}/",
                                 "/index.html"
                             ]}}]}
                        ]
                    }],
                    "terminal": true
                }]
            }}}}
        }"#,
    )
    .expect("golden JSON");
    assert_eq!(actual, expected);
}

#[test]
fn try_files_with_query_groups_routes_like_real_caddy_v2_11_7() {
    // `caddy adapt` v2.11.7: consecutive non-query entries form one route, then each entry with a
    // query string gets its own route with that query appended to the rewrite URI; all grouped.
    let adapted =
        adapt("example.com {\n\troot * /srv\n\ttry_files {path} index.php?{query}&p={path}\n}\n")
            .expect("adapt try_files with query");
    let mut actual = adapted.config;
    normalize_groups(&mut actual);
    let routes = actual["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"]
        .as_array()
        .expect("subroute routes");
    assert_eq!(
        routes.len(),
        3,
        "one root route plus two grouped rewrite routes"
    );
    assert_eq!(
        routes[1],
        json!({
            "match": [{"file": {"try_files": ["{http.request.uri.path}"]}}],
            "handle": [{"handler": "rewrite", "uri": "{http.matchers.file.relative}"}],
            "group": "<group>",
        })
    );
    assert_eq!(
        routes[2],
        json!({
            "match": [{"file": {"try_files": ["index.php"]}}],
            "handle": [{"handler": "rewrite",
                        "uri": "{http.matchers.file.relative}?{http.request.uri.query}&p={http.request.uri.path}"}],
            "group": "<group>",
        })
    );
}

#[test]
fn request_body_matches_caddy() {
    assert_adapts_like_caddy("request_body.caddyfiletest");
}

fn adapted_request_body(directive: &str) -> Value {
    let adapted = adapt(&format!("localhost {{\n\t{directive}\n}}\n"))
        .unwrap_or_else(|e| panic!("adapt `{directive}`: {e}"));
    adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]
        ["handle"]
        .clone()
}

#[test]
fn request_body_size_suffixes_match_real_caddy_v2_11_7() {
    // Cases verified against `caddy adapt` v2.11.7: decimal suffixes are powers of 1000, `i`
    // suffixes powers of 1024, bare k/m/g/t/p/e accepted, fractions and comma separators allowed,
    // zero is omitted (Caddy's `omitempty`), and a duplicate subdirective takes the last value.
    let cases: &[(&str, u64)] = &[
        ("max_size 1MB", 1_000_000),
        ("max_size 1MiB", 1_048_576),
        ("max_size 1000", 1000),
        ("max_size 1kb", 1_000),
        ("max_size 1KiB", 1_024),
        ("max_size 1.5MB", 1_500_000),
        ("max_size .5MB", 500_000),
        ("max_size 1,000KB", 1_000_000),
        ("max_size 1g", 1_000_000_000),
        ("max_size 1GiB", 1_073_741_824),
        ("max_size 1t", 1_000_000_000_000),
    ];
    for (directive, expected) in cases {
        assert_eq!(
            adapted_request_body(&format!("request_body {{\n\t\t{directive}\n\t}}")),
            json!([{"handler": "request_body", "max_size": expected}]),
            "size parsing differs for `{directive}`"
        );
    }
    assert_eq!(
        adapted_request_body("request_body {\n\t\tmax_size 1MB\n\t\tmax_size 2MB\n\t}"),
        json!([{"handler": "request_body", "max_size": 2_000_000}]),
        "duplicate max_size must take the last value"
    );
    assert_eq!(
        adapted_request_body("request_body {\n\t\tmax_size 0\n\t}"),
        json!([{"handler": "request_body"}]),
        "max_size 0 is omitted by Caddy's omitempty"
    );
}

#[test]
fn request_body_set_and_matcher_match_real_caddy_v2_11_7() {
    // Golden from `caddy adapt` v2.11.7: handler-directive matcher token, `set` placeholder is
    // qualified like every other Caddyfile placeholder.
    let adapted =
        adapt("localhost {\n\trequest_body /api/* {\n\t\tmax_size 1MB\n\t\tset {path}\n\t}\n}\n")
            .expect("adapt request_body with matcher and set");
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0],
        json!({
            "match": [{"path": ["/api/*"]}],
            "handle": [{
                "handler": "request_body",
                "max_size": 1_000_000,
                "set": "{http.request.uri.path}",
            }],
        })
    );
}

#[test]
fn request_body_invalid_forms_fail_loudly() {
    for (directive, expected) in [
        ("request_body {\n\t\tmax_size abc\n\t}", "parsing max_size"),
        (
            "request_body {\n\t\tmax_size 1z\n\t}",
            "unhandled size name: z",
        ),
        (
            "request_body {\n\t\tmax_size 1e3\n\t}",
            "unhandled size name: e3",
        ),
        ("request_body {\n\t\tmax_size -1MB\n\t}", "parsing max_size"),
        (
            "request_body {\n\t\tbogus x\n\t}",
            "unrecognized request_body subdirective",
        ),
        ("request_body {\n\t\tset a b\n\t}", "wrong argument count"),
        (
            "request_body {\n\t\tmax_size 1MB 2MB\n\t}",
            "wrong argument count",
        ),
    ] {
        let error = adapt(&format!("localhost {{\n\t{directive}\n}}\n"))
            .expect_err(&format!("`{directive}` must fail"));
        let rendered = error.to_string();
        assert!(
            rendered.contains(expected),
            "error for `{directive}` should contain {expected:?}, got: {rendered}"
        );
    }
}

#[test]
fn request_body_directive_arguments_are_ignored_like_caddy() {
    // Caddy's parseCaddyfile only reads the block; extra non-matcher arguments are ignored.
    assert_eq!(
        adapted_request_body("request_body 1MB"),
        json!([{"handler": "request_body"}])
    );
}
