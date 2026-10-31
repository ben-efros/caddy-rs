//! End-to-end tests for Caddyfile snippet definitions, `import`, named routes and `invoke`.
//!
//! The golden cases are upstream Caddy v2.11.7 fixtures from
//! `caddytest/integration/caddyfile_adapt/`, so the expected JSON is what Caddy itself emits.
//! Fixtures that encode adapter features which are still unsupported (file imports, `log`,
//! `invoke` JSON emission, Caddy's header-name canonicalisation) are covered at the parser level in
//! `crates/config/src/parser.rs` or asserted to fail loudly here.

use caddy_rs_config::{adapt, parse};
use serde_json::Value;

/// Upstream `import_args_snippet_env_placeholder.caddyfiletest`.
const SNIPPET_ENV_PLACEHOLDER_CADDYFILE: &str = "\
(foo) {
\trespond {env.FOO}
}

:80 {
\timport foo
}
";

const SNIPPET_ENV_PLACEHOLDER_EXPECTED_JSON: &str = r#"{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":80"
					],
					"routes": [
						{
							"handle": [
								{
									"body": "{env.FOO}",
									"handler": "static_response"
								}
							]
						}
					]
				}
			}
		}
	}
}"#;

/// Upstream `import_block_with_site_block.caddyfiletest`.
const IMPORT_SITE_BLOCK_CADDYFILE: &str = "\
(site) {
\thttps://{args[0]} {
\t\t{block}
\t}
}

import site test.domain {
\treverse_proxy http://192.168.1.1:8080 {
\t\theader_up Host {host}
\t}
}
";

const IMPORT_SITE_BLOCK_EXPECTED_JSON: &str = r#"{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":443"
					],
					"routes": [
						{
							"match": [
								{
									"host": [
										"test.domain"
									]
								}
							],
							"handle": [
								{
									"handler": "subroute",
									"routes": [
										{
											"handle": [
												{
													"handler": "reverse_proxy",
													"headers": {
														"request": {
															"set": {
																"Host": [
																	"{http.request.host}"
																]
															}
														}
													},
													"upstreams": [
														{
															"dial": "192.168.1.1:8080"
														}
													]
												}
											]
										}
									]
								}
							],
							"terminal": true
						}
					]
				}
			}
		}
	}
}"#;

fn adapt_error(caddyfile: &str) -> String {
    adapt(caddyfile)
        .expect_err("adapter must reject this Caddyfile")
        .to_string()
}

#[test]
fn snippet_import_with_placeholder_body_matches_caddy_golden_json() {
    let expected: Value =
        serde_json::from_str(SNIPPET_ENV_PLACEHOLDER_EXPECTED_JSON).expect("golden JSON");
    let adapted = adapt(SNIPPET_ENV_PLACEHOLDER_CADDYFILE).expect("fixture adapts");
    assert_eq!(adapted.config, expected);
    assert!(adapted.warnings.is_empty(), "{:?}", adapted.warnings);
}

#[test]
fn top_level_import_block_with_site_block_matches_caddy_golden_json() {
    let expected: Value =
        serde_json::from_str(IMPORT_SITE_BLOCK_EXPECTED_JSON).expect("golden JSON");
    let adapted = adapt(IMPORT_SITE_BLOCK_CADDYFILE).expect("fixture adapts");
    assert_eq!(adapted.config, expected);
    assert!(adapted.warnings.is_empty(), "{:?}", adapted.warnings);
}

#[test]
fn import_with_arguments_expands_before_adaptation() {
    // The snippet is expanded at parse time, so the adapter sees ordinary directives.
    let adapted = adapt(
        "(responder) {\n respond \"{args[0]} {args[1]}\"\n}\n:80 {\n import responder hello world\n}\n",
    )
    .expect("adapts");
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
    assert_eq!(handler["body"], Value::String("hello world".to_string()));
}

#[test]
fn duplicate_named_route_error_through_adapt() {
    let error = adapt_error(
        "&(api) {\n respond a\n}\n&(api) {\n respond b\n}\nlocalhost {\n respond ok\n}\n",
    );
    assert!(
        error.contains("cannot have duplicate named_routes: api"),
        "{error}"
    );
}

#[test]
fn undefined_invoke_error_through_adapt() {
    let error = adapt_error("example.com {\n invoke foo\n}\n");
    assert!(
        error.contains("cannot invoke named route 'foo', which was not defined"),
        "{error}"
    );
}

#[test]
fn import_cycle_error_through_adapt() {
    let error = adapt_error(
        "(import1) {\n import import2\n}\n(import2) {\n import import1\n}\nimport import1\n",
    );
    assert!(
        error.contains("a cycle of imports exists between Caddyfile:import2 and Caddyfile:import1"),
        "{error}"
    );
}

#[test]
fn file_imports_fail_loudly_through_adapt() {
    let error = adapt_error(":80 {\n import /etc/caddy/snippets.caddy\n}\n");
    assert!(
        error.contains("File to import not found: /etc/caddy/snippets.caddy"),
        "{error}"
    );
    assert!(error.contains("not supported by this build"), "{error}");
}

#[test]
fn named_routes_do_not_leak_into_the_adapted_config() {
    // The parser records named routes; the adapter does not emit them. A Caddyfile that defines
    // named routes but never invokes them produces the same config Caddy would (named routes are
    // only attached to servers that invoke them), and invoking one fails loudly (tested above).
    let file = parse("&(unused) {\n respond nope\n}\n:80 {\n respond ok\n}\n").expect("parses");
    assert_eq!(file.named_routes.len(), 1);
    assert_eq!(file.named_routes[0].name, "unused");

    let adapted = adapt("&(unused) {\n respond nope\n}\n:80 {\n respond ok\n}\n").expect("adapts");
    assert!(adapted.config["apps"]["http"]["servers"]["srv0"]
        .get("named_routes")
        .is_none());
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["body"],
        Value::String("ok".to_string())
    );
}

#[test]
fn import_argument_warnings_surface_through_the_adapter() {
    let adapted = adapt("(snippet) {\n respond {args.0}\n}\n:80 {\n import snippet hi\n}\n")
        .expect("adapts with a warning");
    assert!(
        adapted
            .warnings
            .iter()
            .any(|warning| warning.contains("deprecated")),
        "{:?}",
        adapted.warnings
    );
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
    assert_eq!(handler["body"], Value::String("hi".to_string()));
}

#[test]
fn import_inside_a_named_route_is_expanded() {
    let file = parse(
        "(common) {\n route /api/* {\n  respond api\n }\n}\n&(foo) {\n import common\n}\n:80 {\n invoke foo\n}\n",
    )
    .expect("parses");
    assert_eq!(file.named_routes[0].directives[0].name, "route");
    assert_eq!(
        file.named_routes[0].directives[0].args,
        vec!["/api/*".to_string()]
    );
}

#[test]
fn anonymous_import_block_fails_loudly() {
    let error = adapt_error(
        "(site) {\n http://{args[0]} {\n  {block}\n }\n}\nimport site test.domain {\n {\n  header_up Host {host}\n }\n}\n",
    );
    assert!(
        error.contains("anonymous blocks are not supported"),
        "{error}"
    );
}
