//! `reverse_proxy { dynamic ... }` adaptation (T-CONF-052), against Caddy v2.11.9's upstream
//! `SRVUpstreams`/`AUpstreams`/`MultiUpstreams` `UnmarshalCaddyfile` methods.

use serde_json::json;

fn adapt_error(caddyfile: &str) -> String {
    caddy_rs_config::adapt(caddyfile)
        .expect_err("Caddyfile must be rejected")
        .to_string()
}

#[test]
fn srv_source_emits_exact_caddy_shape() {
    let adapted = caddy_rs_config::adapt(
        r#":8080 {
	reverse_proxy {
		dynamic srv {
			service api
			proto tcp
			name example.com
			refresh 5m
			grace_period 5s
			resolvers 8.8.8.8 8.8.4.4
			dial_timeout 1s
			dial_fallback_delay -1s
		}
	}
}
"#,
    )
    .expect("srv dynamic upstream adapts");
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]
            ["dynamic_upstreams"],
        json!({
            "source": "srv",
            "service": "api",
            "proto": "tcp",
            "name": "example.com",
            "refresh": 300_000_000_000_i64,
            "grace_period": 5_000_000_000_i64,
            "resolver": {"addresses": ["8.8.8.8", "8.8.4.4"]},
            "dial_timeout": 1_000_000_000_i64,
            "dial_fallback_delay": -1_000_000_000_i64
        })
    );
}

#[test]
fn a_source_emits_exact_caddy_shape_and_versions() {
    let adapted = caddy_rs_config::adapt(
        r#":8080 {
	reverse_proxy {
		dynamic a foo 9000 {
			refresh 5m
			resolvers 1.1.1.1
			dial_timeout 2s
			dial_fallback_delay 300ms
			versions ipv4 ipv6
		}
	}
}
"#,
    )
    .expect("a dynamic upstream adapts");
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]
            ["dynamic_upstreams"],
        json!({
            "source": "a",
            "name": "foo",
            "port": "9000",
            "refresh": 300_000_000_000_i64,
            "resolver": {"addresses": ["1.1.1.1"]},
            "dial_timeout": 2_000_000_000_i64,
            "dial_fallback_delay": 300_000_000_i64,
            "versions": {"ipv4": true, "ipv6": true}
        })
    );
}

#[test]
fn multi_source_nests_sources_in_order() {
    let adapted = caddy_rs_config::adapt(
        r#":8080 {
	reverse_proxy {
		dynamic multi {
			a backend.example 8080
			srv {
				service api
				proto tcp
				name example.com
				refresh 5m
			}
		}
	}
}
"#,
    )
    .expect("multi dynamic upstream adapts");
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]
            ["dynamic_upstreams"],
        json!({
            "source": "multi",
            "sources": [
                {"source": "a", "name": "backend.example", "port": "8080"},
                {
                    "source": "srv",
                    "service": "api",
                    "proto": "tcp",
                    "name": "example.com",
                    "refresh": 300_000_000_000_i64
                }
            ]
        })
    );
}

#[test]
fn dynamic_requires_a_source_and_rejects_unknown_sources() {
    assert!(adapt_error(":8080 { reverse_proxy { dynamic } }\n")
        .contains("requires an upstream source"));
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic nope foo } }\n")
            .contains("unrecognized dynamic upstream source")
    );
    // Caddy's parser takes at most one srv name, two a args, and none for multi.
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic srv one two } }\n")
            .contains("at most one name")
    );
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic a one two three } }\n")
            .contains("at most a name")
    );
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic multi extra } }\n")
            .contains("does not take arguments")
    );
}

#[test]
fn dynamic_rejects_unknown_options_with_the_source_name() {
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic srv { nope x } } }\n")
            .contains("unrecognized srv option `nope`")
    );
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic a foo { nope x } } }\n")
            .contains("unrecognized a option `nope`")
    );
    // Caddy v2.11.9's Caddyfile parser does not accept `dial_network` (the JSON field exists but is
    // not exposed by the directive); matching Caddy means rejecting it.
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic srv { dial_network tcp4 } } }\n")
            .contains("unrecognized srv option `dial_network`")
    );
}

#[test]
fn dynamic_rejects_bad_values_and_duplicates() {
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic srv { refresh nope } } }\n")
            .contains("numeric")
    );
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic a { versions ipv5 } } }\n")
            .contains("unsupported version")
    );
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic a { versions } } }\n")
            .contains("at least one version")
    );
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic a { resolvers } } }\n")
            .contains("at least one resolver address")
    );
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic a foo { name bar } } }\n")
            .contains("a name has already been specified")
    );
    assert!(
        adapt_error(":8080 { reverse_proxy { dynamic a foo 80 { port 81 } } }\n")
            .contains("a port has already been specified")
    );
    assert!(
        adapt_error(":8080 { reverse_proxy {\n dynamic a foo\n dynamic a bar\n} }\n")
            .contains("dynamic upstreams already specified")
    );
}

#[test]
fn dynamic_alone_does_not_emit_an_empty_upstreams_array() {
    let adapted =
        caddy_rs_config::adapt(":8080 { reverse_proxy { dynamic a foo 9000 } }\n").expect("adapts");
    let handler = &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0];
    assert!(
        handler.get("upstreams").is_none(),
        "upstreams must be omitted for a dynamic-only proxy: {handler}"
    );
    assert_eq!(handler["dynamic_upstreams"]["source"], "a");
}
