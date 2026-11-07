//! PKI app (`apps.pki`) adaptation and internal-issuer CA validation.
//!
//! Covers the upstream adapter fixture `tls_internal_options` (now exact) and the Caddyfile
//! `pki`/`issuer internal` mapping added for T-TLS-034, plus the validation rule that an internal
//! issuer must reference a configured CA (or the implicit default `local` CA, DIV-0070).

use caddy_rs_config::adapt;
use serde_json::{json, Value};

/// Upstream Caddy v2.11.7 fixture `tls_internal_options.caddyfiletest`.
const TLS_INTERNAL_OPTIONS_CADDYFILE: &str = "\
a.example.com {
\ttls {
\t\tissuer internal {
\t\t\tca foo
\t\t\tlifetime 24h
\t\t\tsign_with_root
\t\t}
\t}
}
";

const TLS_INTERNAL_OPTIONS_EXPECTED_JSON: &str = r#"{
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
										"a.example.com"
									]
								}
							],
							"terminal": true
						}
					]
				}
			}
		},
		"tls": {
			"automation": {
				"policies": [
					{
						"subjects": [
							"a.example.com"
						],
						"issuers": [
							{
								"ca": "foo",
								"lifetime": 86400000000000,
								"module": "internal",
								"sign_with_root": true
							}
						]
					}
				]
			}
		}
	}
}"#;

fn validate(config: &Value) -> Result<(), String> {
    let registry = caddy_rs_core::ModuleRegistry::builtin();
    let config = caddy_rs_core::Config::from_value(config.clone()).map_err(|e| e.to_string())?;
    caddy_rs_core::validate_config(&config, &registry).map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn tls_internal_options_matches_upstream_fixture() {
    let expected: Value = serde_json::from_str(TLS_INTERNAL_OPTIONS_EXPECTED_JSON).expect("golden");
    let adapted = adapt(TLS_INTERNAL_OPTIONS_CADDYFILE).expect("fixture adapts");
    assert_eq!(adapted.config, expected);
    // Caddy adapts this fixture but its validator rejects it (CA `foo` is not configured); the
    // validation behaviour is covered below with an explicit `pki` app.
}

#[test]
fn pki_global_option_adapts_to_apps_pki() {
    let adapted = adapt(
        "{ pki {\n  ca {\n   name \"Local\"\n   root_cn \"Root\"\n   intermediate_lifetime 24h\n   root {\n    cert /path/cert.pem\n    key /path/key.pem\n    format pem_file\n   }\n  }\n  ca foo {\n   name \"Foo\"\n  }\n } }\na.example.com {\n tls internal\n}\n",
    )
    .expect("pki option adapts");
    let pki = &adapted.config["apps"]["pki"];
    assert_eq!(
        pki["certificate_authorities"]["local"]["name"],
        json!("Local")
    );
    assert_eq!(
        pki["certificate_authorities"]["local"]["root_common_name"],
        json!("Root")
    );
    assert_eq!(
        pki["certificate_authorities"]["local"]["intermediate_lifetime"],
        json!(86400000000000_i64)
    );
    assert_eq!(
        pki["certificate_authorities"]["local"]["root"],
        json!({"certificate": "/path/cert.pem", "private_key": "/path/key.pem", "format": "pem_file"})
    );
    assert_eq!(pki["certificate_authorities"]["foo"]["name"], json!("Foo"));
    assert_eq!(
        adapted.config["apps"]["tls"]["automation"]["policies"][0]["issuers"],
        json!([{"module": "internal"}])
    );
    validate(&adapted.config).expect("explicit local CA + internal issuer validates");
}

#[test]
fn repeated_pki_ca_id_last_definition_wins() {
    let adapted = adapt("{ pki {\n  ca foo {\n   name \"First\"\n  }\n  ca foo {\n   name \"Second\"\n  }\n } }\n:80 {\n respond ok\n}\n")
        .expect("adapts");
    assert_eq!(
        adapted.config["apps"]["pki"]["certificate_authorities"]["foo"]["name"],
        json!("Second")
    );
}

#[test]
fn explicit_internal_issuer_without_ca_is_rejected_at_validation() {
    // Same shape as the upstream fixture: adapt succeeds (like Caddy), validation rejects because
    // the referenced CA does not exist. Caddy reports this at provisioning time; we report it at
    // validation time with Caddy's message (DIV-0070).
    let adapted = adapt(TLS_INTERNAL_OPTIONS_CADDYFILE).expect("adapts like Caddy");
    let error = validate(&adapted.config).expect_err("missing CA must fail validation");
    assert!(
        error.contains("no certificate authority configured with id: foo"),
        "{error}"
    );
    assert!(
        error.contains("apps.tls.automation.policies[0].issuers[0].ca"),
        "{error}"
    );
}

#[test]
fn implicit_local_ca_is_accepted_and_not_emitted() {
    // `tls internal` without a `pki` option relies on Caddy's implicit default `local` CA: the
    // adapted JSON contains no apps.pki and validation accepts it.
    let adapted = adapt("a.example.com {\n tls internal\n}\n").expect("adapts");
    assert!(adapted.config["apps"].get("pki").is_none());
    validate(&adapted.config).expect("implicit local CA validates");
}

#[test]
fn pki_defining_only_other_cas_rejects_implicit_local_issuer() {
    let adapted = adapt(
        "{ pki {\n  ca foo {\n   name \"Foo\"\n  }\n } }\na.example.com {\n tls internal\n}\n",
    )
    .expect("adapts");
    let error = validate(&adapted.config).expect_err("local CA is not implicit with pki CAs");
    assert!(
        error.contains("no certificate authority configured with id: local"),
        "{error}"
    );
}

#[test]
fn local_certs_with_explicit_local_pki_ca_validates() {
    let adapted = adapt("{ local_certs\n pki {\n  ca {\n   name \"Local\"\n  }\n } }\n:443 {\n}\n")
        .expect("adapts");
    validate(&adapted.config).expect("local_certs uses the explicit local CA");
}

#[test]
fn pki_syntax_errors_are_loud() {
    for (caddyfile, expected) in [
        (
            "{ pki {\n  bogus_option\n } }\n:80 {\n}\n",
            "unrecognized pki option",
        ),
        (
            "{ pki {\n  ca {\n   bogus_option\n  }\n } }\n:80 {\n}\n",
            "unrecognized pki ca option",
        ),
        (
            "{ pki {\n  ca {\n   intermediate_lifetime not-a-duration\n  }\n } }\n:80 {\n}\n",
            "invalid duration",
        ),
        (
            "{ pki {\n  ca {\n   renewal_window_ratio 2\n  }\n } }\n:80 {\n}\n",
            "renewal_window_ratio",
        ),
        (
            "{ pki {\n  ca {\n   root {\n    bogus_option x\n   }\n  }\n } }\n:80 {\n}\n",
            "unrecognized pki ca root option",
        ),
        (
            "a.example.com {\n tls {\n  issuer zerossl\n }\n}\n",
            "supports `internal` and `acme`",
        ),
    ] {
        let error = adapt(caddyfile).expect_err("must be rejected");
        assert!(
            error.to_string().contains(expected),
            "expected `{expected}` in: {error}"
        );
    }
}

#[test]
fn pki_round_trips_through_the_typed_model() {
    // Adapt, decode through the typed core model, re-encode, and compare: the new apps.pki model
    // must not lose CA fields.
    // `install_trust` is a JSON-only field (Caddy's Caddyfile syntax has no such pki option), so
    // the round-trip test starts from an adapted Caddyfile and then exercises the typed model.
    let adapted = adapt("{ pki {\n  ca {\n   name \"Local\"\n  }\n } }\n:80 {\n respond ok\n}\n")
        .expect("adapts");
    let config = caddy_rs_core::Config::from_value(adapted.config.clone()).expect("typed model");
    assert_eq!(config.to_value().expect("serializes"), adapted.config);
    assert!(config.pki().is_some());
}
