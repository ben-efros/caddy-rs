//! Caddyfile adaptation and builtin-registry validation for the network/TLS matchers
//! (`remote_ip`, `client_ip`, `protocol`, `tls`, `local_ip`), T-ROUTE-038.
//!
//! Expected JSON follows real Caddy v2.11.7 for the forms it accepts: `MatchProtocol` is a
//! single string (`{"protocol": "http/2"}`) and `MatchTLS` only exposes `handshake_complete`
//! (`{"tls": {}}`; `tls early_data` → `{"tls": {"handshake_complete": false}}`). `local_ip`
//! is a caddy-rs extension (Caddy v2.11.7 has no HTTP `local_ip` matcher; it exists only as
//! a TLS connection-policy matcher) that mirrors the `remote_ip`/`client_ip` shape.

use caddy_rs_config::adapt;
use serde_json::json;

fn adapted_routes(caddyfile: &str) -> serde_json::Value {
    let adapted = adapt(caddyfile).expect("Caddyfile adapts");
    adapted.config["apps"]["http"]["servers"]["srv0"]["routes"].clone()
}

#[test]
fn protocol_tls_and_local_ip_matchers_adapt_to_caddy_shapes() {
    let caddyfile = r#"
:8080 {
	@h2 protocol http/2
	respond @h2 "h2"

	@sec tls
	respond @sec "tls"

	@early tls early_data
	respond @early "early data"

	@li local_ip 10.0.0.0/8
	respond @li "local"
}
"#;
    let routes = adapted_routes(caddyfile);
    let expected = json!([
        {
            "match": [{"protocol": "http/2"}],
            "handle": [{"body": "h2", "handler": "static_response"}]
        },
        {
            "match": [{"tls": {}}],
            "handle": [{"body": "tls", "handler": "static_response"}]
        },
        {
            "match": [{"tls": {"handshake_complete": false}}],
            "handle": [{"body": "early data", "handler": "static_response"}]
        },
        {
            "match": [{"local_ip": {"ranges": ["10.0.0.0/8"]}}],
            "handle": [{"body": "local", "handler": "static_response"}]
        }
    ]);
    assert_eq!(routes, expected, "adapted JSON must match (got: {routes})");
}

#[test]
fn local_ip_matcher_expands_private_ranges_like_remote_ip() {
    let routes = adapted_routes(":8080 {\n\t@li local_ip private_ranges\n\trespond @li ok\n}\n");
    let expected = json!([
        {
            "match": [{
                "local_ip": {"ranges": [
                    "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8",
                    "127.0.0.1/8", "fd00::/8", "::1"
                ]}
            }],
            "handle": [{"body": "ok", "handler": "static_response"}]
        }
    ]);
    assert_eq!(routes, expected, "adapted JSON must match (got: {routes})");
}

#[test]
fn named_matcher_set_combines_new_matchers_and_not() {
    let routes = adapted_routes(":8080 {\n\t@x {\n\t\tprotocol http/2\n\t\ttls\n\t\tnot local_ip 10.0.0.0/8\n\t}\n\trespond @x ok\n}\n");
    let expected = json!([
        {
            "match": [{
                "not": [{"local_ip": {"ranges": ["10.0.0.0/8"]}}],
                "protocol": "http/2",
                "tls": {}
            }],
            "handle": [{"body": "ok", "handler": "static_response"}]
        }
    ]);
    assert_eq!(routes, expected, "adapted JSON must match (got: {routes})");
}

#[test]
fn protocol_matcher_rejects_missing_or_multiple_protocols() {
    let error = adapt(":8080 {\n\t@x protocol\n\trespond @x ok\n}\n")
        .expect_err("protocol matcher needs a value");
    let message = error.to_string();
    assert!(message.contains("Caddyfile line 2"), "{message}");
    assert!(
        message.contains("matcher `protocol` requires exactly one protocol"),
        "{message}"
    );

    // Caddy v2.11.7's MatchProtocol reads a single argument and silently drops the rest; caddy-rs
    // fails loudly instead of emitting a config the engine cannot honour.
    let error = adapt(":8080 {\n\t@x protocol http/1.1 http/2.0\n\trespond @x ok\n}\n")
        .expect_err("protocol matcher accepts exactly one protocol");
    let message = error.to_string();
    assert!(message.contains("Caddyfile line 2"), "{message}");
    assert!(message.contains("exactly one protocol"), "{message}");
}

#[test]
fn tls_matcher_rejects_sni_client_auth_and_blocks_with_located_errors() {
    // Caddy v2.11.7: MatchTLS.UnmarshalCaddyfile accepts only `early_data`; any other option is
    // an "unrecognized option" error. `sni`/`client_auth` are TLS connection-policy fields, not
    // HTTP route matcher fields, and the caddy-rs engine rejects them loudly (TLS-MATCHER-METADATA).
    let error = adapt(":8080 {\n\t@x tls sni example.com\n\trespond @x ok\n}\n")
        .expect_err("sni is not an http.matchers.tls Caddyfile option");
    let message = error.to_string();
    assert!(message.contains("Caddyfile line 2"), "{message}");
    assert!(message.contains("unrecognized option 'sni'"), "{message}");

    let error = adapt(":8080 {\n\t@x tls client_auth\n\trespond @x ok\n}\n")
        .expect_err("client_auth is not an http.matchers.tls Caddyfile option");
    let message = error.to_string();
    assert!(
        message.contains("unrecognized option 'client_auth'"),
        "{message}"
    );

    // Block form: the block contents are parsed as a matcher set, and `sni` is not an HTTP
    // matcher in Caddy v2.11.7 either (unknown module http.matchers.sni).
    let error = adapt(":8080 {\n\t@x tls {\n\t\tsni example.com\n\t}\n\trespond @x ok\n}\n")
        .expect_err("tls matcher block form is unsupported");
    let message = error.to_string();
    assert!(
        message.contains("matcher `sni` is not supported by this build"),
        "{message}"
    );
}

#[test]
fn adapted_matchers_validate_with_the_builtin_registry() {
    let caddyfile = r#"
:8080 {
	@h2 protocol http/2
	respond @h2 "h2"

	@sec tls
	respond @sec "tls"

	@early tls early_data
	respond @early "early"

	@li local_ip 10.0.0.0/8
	respond @li "local"

	@net remote_ip 192.0.2.0/24
	respond @net "net"

	@client client_ip 10.0.0.0/8
	respond @client "client"
}
"#;
    let adapted = adapt(caddyfile).expect("Caddyfile adapts");
    let config =
        caddy_rs_core::Config::from_value(adapted.config).expect("configuration model decodes");
    let report = caddy_rs_core::validate_config(&config, &caddy_rs_core::ModuleRegistry::builtin())
        .expect("every adapted matcher module id is a builtin registry entry");
    assert_eq!(
        report.matchers, 6,
        "all six adapted matchers are counted by validation"
    );
}

#[test]
fn file_matcher_block_forms_and_errors() {
    // Caddy's `file` matcher: inline arguments and the block's root/try_files/try_policy/
    // split_path (T-CONF-013). Shorthand placeholders are expanded before parsing.
    let adapted = adapt(
        ":8080 {\n\t@php {\n\t\tfile {\n\t\t\ttry_files {path} {path}/index.php index.php\n\t\t\tsplit_path .php\n\t\t\ttry_policy first_exist_fallback\n\t\t}\n\t}\n\trespond @php \"php\"\n}\n",
    )
    .expect("file matcher adapts");
    let routes = adapted.config["apps"]["http"]["servers"]["srv0"]["routes"]
        .as_array()
        .expect("routes");
    assert_eq!(
        routes[0]["match"][0]["file"],
        json!({
            "try_files": [
                "{http.request.uri.path}",
                "{http.request.uri.path}/index.php",
                "index.php",
            ],
            "split_path": [".php"],
            "try_policy": "first_exist_fallback",
        })
    );

    for (caddyfile, expected) in [
        (
            ":8080 {\n\t@f {\n\t\tfile {\n\t\t\tbogus x\n\t\t}\n\t}\n\trespond @f x\n}\n",
            "unrecognized `file` matcher subdirective: bogus",
        ),
        (
            ":8080 {\n\t@f {\n\t\tfile {\n\t\t\ttry_files\n\t\t}\n\t}\n\trespond @f x\n}\n",
            "requires at least one file argument",
        ),
        (
            ":8080 {\n\t@f {\n\t\tfile {\n\t\t\tsplit_path\n\t\t}\n\t}\n\trespond @f x\n}\n",
            "requires at least one suffix",
        ),
    ] {
        let error = adapt(caddyfile).expect_err("invalid file matcher must fail loudly");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in: {error}"
        );
    }
}

#[test]
fn named_expression_matcher_matches_real_caddy_v2_11_9() {
    // Caddy keeps raw tokens for multi-token expressions (bare JSON string) and the cleaned
    // single token for one-argument expressions (object with `expr`, named by the @matcher).
    let multi = adapt(
        ":8080 {\n\t@multi expression {http.request.method} == 'GET'\n\trespond @multi \"ok\"\n}\n",
    )
    .expect("adapt multi-token expression matcher");
    let route = &multi.config["apps"]["http"]["servers"]["srv0"]["routes"][0];
    assert_eq!(
        route["match"][0],
        json!({"expression": "{http.request.method} == 'GET'"})
    );

    let single = adapt(":8080 {\n\t@single expression true\n\trespond @single \"ok\"\n}\n")
        .expect("adapt single-token expression matcher");
    let route = &single.config["apps"]["http"]["servers"]["srv0"]["routes"][0];
    assert_eq!(
        route["match"][0],
        json!({"expression": {"expr": "true", "name": "single"}})
    );

    let header = adapt(
        ":8080 {\n\t@h expression {http.request.header.X-Test} == \"yes\"\n\trespond @h \"ok\"\n}\n",
    )
    .expect("adapt quoted-token expression matcher");
    let route = &header.config["apps"]["http"]["servers"]["srv0"]["routes"][0];
    assert_eq!(
        route["match"][0],
        json!({"expression": "{http.request.header.X-Test} == \"yes\""})
    );

    let error = adapt(":8080 {\n\t@e expression\n\trespond @e \"ok\"\n}\n")
        .expect_err("an expression matcher without an expression must fail");
    assert!(
        error.to_string().contains("requires a CEL expression"),
        "unexpected error: {error}"
    );
}
