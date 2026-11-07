//! Caddyfile `tls { issuer acme { ... } }` adaptation (T-CONF-053), matching Caddy v2.11.9's
//! `ACMEIssuer.UnmarshalCaddyfile` for the options the caddy-rs runtime honours.

use serde_json::json;

fn adapt_error(caddyfile: &str) -> String {
    caddy_rs_config::adapt(caddyfile)
        .expect_err("Caddyfile must be rejected")
        .to_string()
}

#[test]
fn timeout_maps_to_acme_timeout_nanoseconds() {
    let adapted = caddy_rs_config::adapt(
        "example.com {\n tls {\n  issuer acme {\n   timeout 10s\n  }\n }\n}\n",
    )
    .expect("issuer acme timeout adapts");
    assert_eq!(
        adapted.config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0],
        json!({"module": "acme", "acme_timeout": 10_000_000_000_i64})
    );
}

#[test]
fn supported_acme_options_match_caddy_json() {
    let adapted = caddy_rs_config::adapt(
        r#"{
	local_certs
}
example.com {
	tls {
		issuer acme {
			dir https://acme.example/directory
			email ops@example.com
			timeout 10s
			disable_http_challenge
			disable_tlsalpn_challenge
			trusted_roots /etc/ssl/ca.pem
		}
	}
}
"#,
    )
    .expect("combined issuer acme options adapt");
    assert_eq!(
        adapted.config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0],
        json!({
            "module": "acme",
            "ca": "https://acme.example/directory",
            "email": "ops@example.com",
            "acme_timeout": 10_000_000_000_i64,
            "challenges": {
                "http": {"disabled": true},
                "tls-alpn": {"disabled": true}
            },
            "trusted_roots_pem_files": ["/etc/ssl/ca.pem"]
        })
    );
}

#[test]
fn positional_ca_argument_is_the_directory() {
    let adapted = caddy_rs_config::adapt(
        "example.com {\n tls {\n  issuer acme https://acme.example/directory\n }\n}\n",
    )
    .expect("positional ACME CA adapts");
    assert_eq!(
        adapted.config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0],
        json!({"module": "acme", "ca": "https://acme.example/directory"})
    );
}

#[test]
fn eab_maps_to_external_account() {
    let adapted = caddy_rs_config::adapt(
        "example.com {\n tls {\n  issuer acme {\n   eab kid_123 mac_456\n  }\n }\n}\n",
    )
    .expect("issuer acme eab adapts");
    assert_eq!(
        adapted.config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0],
        json!({
            "module": "acme",
            "external_account": {"key_id": "kid_123", "mac_key": "mac_456"}
        })
    );
}

#[test]
fn unsupported_acme_options_are_located_errors_naming_the_construct() {
    for (option, expected) in [
        ("preferred_chains", "preferred_chains"),
        ("lifetime 24h", "lifetime"),
        ("profile shortlived", "profile"),
        ("dns cloudflare", "dns"),
        ("test_dir https://staging.example", "test_dir"),
        ("distributed false", "distributed"),
    ] {
        let message = adapt_error(&format!(
            "example.com {{\n tls {{\n  issuer acme {{\n   {option}\n  }}\n }}\n}}\n"
        ));
        assert!(
            message.contains(expected) && message.contains("not supported"),
            "unexpected error for {option}: {message}"
        );
    }
}

#[test]
fn malformed_acme_options_are_located_errors() {
    for (option, expected) in [
        ("timeout nope", "invalid"),
        ("timeout", "requires exactly one duration"),
        ("dir", "requires exactly one directory URL"),
        ("email", "requires exactly one address"),
        ("disable_http_challenge yes", "does not take arguments"),
        ("bogus x", "not supported by this build"),
        ("eab only_one", "requires exactly a key ID"),
    ] {
        let message = adapt_error(&format!(
            "example.com {{\n tls {{\n  issuer acme {{\n   {option}\n  }}\n }}\n}}\n"
        ));
        assert!(
            message.contains(expected),
            "unexpected error for {option}: {message}"
        );
    }
    // Positional CA plus `dir` is Caddy's "directory is already specified" error.
    let message = adapt_error(
        "example.com {\n tls {\n  issuer acme https://a.example {\n   dir https://b.example\n  }\n }\n}\n",
    );
    assert!(
        message.contains("directory is already specified"),
        "{message}"
    );
    // Caddy rejects mixing an explicit issuer block with `tls { ca ... }`.
    let message = adapt_error(
        "example.com {\n tls {\n  ca https://ca.example\n  issuer acme {\n   timeout 1s\n  }\n }\n}\n",
    );
    assert!(message.contains("cannot mix"), "{message}");
}

#[test]
fn multiple_issuer_blocks_are_rejected() {
    let message = adapt_error("example.com {\n tls {\n  issuer acme\n  issuer internal\n }\n}\n");
    assert!(message.contains("multiple `tls` issuers"), "{message}");
}
