//! End-to-end adaptation of the global `layer4 { ... }` option (ADR-030, T-L4-004).
//!
//! These tests drive the public `adapt` entry point rather than the module, so they also cover the
//! parser arm, the `apps.layer4` insertion point and the `stock_compat` interaction.
//!
//! The expected JSON follows ADR-030's "JSON (`apps.layer4`)" section. `layer4` is a `caddy-l4`
//! surface with no stock Caddy v2.11.9 equivalent, so there is no upstream `caddy adapt` oracle for
//! these fixtures: the development plan is the contract.

use serde_json::{json, Value};

fn layer4_app(caddyfile: &str) -> Value {
    let adapted = caddy_rs_config::adapt(caddyfile).expect("Caddyfile adapts");
    adapted.config["apps"]["layer4"].clone()
}

const ADR_EXAMPLE: &str = r#"{
	layer4 {
		0.0.0.0:443 {
			@blocked_asns asn 16509 14061
			@blocked_ips remote_ip 192.0.2.0/24
			route @blocked_asns @blocked_ips {
				close
			}

			@passthrough tls sni internal.example.com
			route @passthrough {
				proxy 10.0.0.12:8443
			}

			@web tls sni *.web.example.com
			route @web {
				http
			}

			route {
				proxy :2222
			}
		}
	}
}
"#;

#[test]
fn the_adr_030_caddyfile_example_adapts_to_its_json_shape() {
    assert_eq!(
        layer4_app(ADR_EXAMPLE),
        json!({
            "servers": {
                "srv0": {
                    "listen": ["0.0.0.0:443"],
                    "routes": [
                        {
                            "match": [
                                { "asn": [16509, 14061] },
                                { "remote_ip": { "ranges": ["192.0.2.0/24"] } }
                            ],
                            "handle": [{ "handler": "close" }]
                        },
                        {
                            "match": [{ "tls": { "sni": ["internal.example.com"] } }],
                            "handle": [{
                                "handler": "proxy",
                                "upstreams": [{ "dial": "10.0.0.12:8443" }]
                            }]
                        },
                        {
                            "match": [{ "tls": { "sni": ["*.web.example.com"] } }],
                            "handle": [{ "handler": "http", "tls": false }]
                        },
                        {
                            "handle": [{
                                "handler": "proxy",
                                "upstreams": [{ "dial": ":2222" }]
                            }]
                        }
                    ]
                }
            }
        })
    );
}

#[test]
fn a_layer4_only_caddyfile_emits_no_http_app() {
    let adapted = caddy_rs_config::adapt(ADR_EXAMPLE).expect("adapts");
    assert!(
        adapted
            .config
            .get("apps")
            .and_then(|apps| apps.get("http"))
            .is_none(),
        "an L4-only configuration must not invent an HTTP app: {}",
        adapted.config
    );
    assert_eq!(adapted.warnings.len(), 0, "{:?}", adapted.warnings);
}

#[test]
fn alpn_and_wildcard_patterns_carry_through() {
    let app = layer4_app(
        r#"{
	layer4 {
		0.0.0.0:8443 {
			@h2 tls alpn h2 http/1.1
			route @h2 {
				proxy 127.0.0.1:8080
			}
			@mixed tls sni (a.example.com b.example.com) *.example.org
			route @mixed {
				proxy_protocol v2
				proxy 127.0.0.1:9090
			}
		}
	}
}
"#,
    );
    let routes = &app["servers"]["srv0"]["routes"];
    assert_eq!(
        routes[0]["match"],
        json!([{ "tls": { "alpn": ["h2", "http/1.1"] } }])
    );
    assert_eq!(
        routes[1]["match"],
        json!([{ "tls": { "sni": ["a.example.com", "b.example.com", "*.example.org"] } }])
    );
    assert_eq!(
        routes[1]["handle"],
        json!([
            { "handler": "proxy_protocol", "version": "v2" },
            { "handler": "proxy", "upstreams": [{ "dial": "127.0.0.1:9090" }] }
        ])
    );
}

#[test]
fn tls_client_auth_and_banner_matchers_adapt() {
    let app = layer4_app(
        r#"{
	layer4 {
		0.0.0.0:22 {
			@ssh ssh
			@web http
			@pp proxy_protocol
			route @ssh @web @pp {
				tls client_auth /etc/caddy/ssh-ca.pem
				close
			}
		}
	}
}
"#,
    );
    let route = &app["servers"]["srv0"]["routes"][0];
    assert_eq!(
        route["match"],
        json!([{ "ssh": {} }, { "http": {} }, { "proxy_protocol": {} }])
    );
    assert_eq!(route["handle"][0]["handler"], json!("tls"));
    assert_eq!(
        route["handle"][0]["client_auth"]["trusted_ca_cert_file"],
        json!(["/etc/caddy/ssh-ca.pem"])
    );
}

#[test]
fn listener_without_routing_gets_the_implicit_close_route() {
    let app = layer4_app("{\n\tlayer4 {\n\t\t0.0.0.0:443 {\n\t\t}\n\t}\n}\n");
    // The implicit route keeps the `routes` element shape (`{"handle": [...]}`), not a bare handler.
    assert_eq!(
        app["servers"]["srv0"]["routes"],
        json!([{ "handle": [{ "handler": "close" }] }])
    );
}

#[test]
fn unsupported_layer4_input_is_a_located_error() {
    let cases = [
        (
            "{\n\tlayer4 {\n\t\tudp/0.0.0.0:443 {\n\t\t\tclose\n\t\t}\n\t}\n}\n",
            "T-L4-011",
        ),
        (
            "{\n\tlayer4 {\n\t\t0.0.0.0:443 {\n\t\t\tfrobnicate\n\t\t}\n\t}\n}\n",
            "unknown layer4 directive",
        ),
        (
            "{\n\tlayer4 {\n\t\t0.0.0.0:443 {\n\t\t\troute @missing {\n\t\t\t\tclose\n\t\t\t}\n\t\t}\n\t}\n}\n",
            "undefined matcher",
        ),
    ];
    for (source, needle) in cases {
        let error = caddy_rs_config::adapt(source).expect_err("unsupported input must fail");
        let text = error.to_string();
        assert!(text.contains(needle), "{needle}: {text}");
        assert!(
            text.contains("Caddyfile line"),
            "error is not located: {text}"
        );
    }
}

#[test]
fn stock_compat_true_rejects_the_layer4_option() {
    // `layer4` belongs to the `caddy-l4` plugin, which stock Caddy v2.11.9 does not have; under
    // `stock_compat true` the option is a located error, like the other caddy-rs extensions.
    let source =
        "{\n\tstock_compat true\n\tlayer4 {\n\t\t0.0.0.0:443 {\n\t\t\tclose\n\t\t}\n\t}\n}\n";
    let error = caddy_rs_config::adapt(source).expect_err("rejected under stock_compat");
    let text = error.to_string();
    assert!(text.contains("layer4"), "{text}");
    assert!(text.contains("stock_compat"), "{text}");
}

#[test]
fn an_empty_layer4_block_configures_nothing() {
    // Upstream allows an empty global options block; `layer4 {}` therefore adds no app rather than
    // failing the adapter after parsing succeeded.
    let adapted = caddy_rs_config::adapt("{\n\tlayer4 {\n\t}\n}\n:8080 {\n\trespond \"ok\"\n}\n")
        .expect("adapts");
    assert!(adapted.config["apps"].get("layer4").is_none());
    assert!(adapted.config["apps"]["http"]["servers"]["srv0"].is_object());
}
