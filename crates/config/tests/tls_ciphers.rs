//! `tls { ciphers ...; curves ... }` adaptation to the runtime's connection-policy fields.
//!
//! The adapter emits Caddy's `tls_connection_policies[].cipher_suites`/`curves`, restricted to the
//! suites and groups the caddy-rs rustls terminator can configure. Names Caddy v2.11.9 accepts but
//! the runtime cannot honour (TLS 1.3 suites, ECDHE CBC suites, secp521r1) fail loudly with a
//! tracking marker instead of being silently dropped. `x25519mlkem768` is supported by aws-lc-rs.

use caddy_rs_config::adapt;
use serde_json::{json, Value};

fn validate(config: &Value) -> Result<(), String> {
    let registry = caddy_rs_core::ModuleRegistry::builtin();
    let config =
        caddy_rs_core::Config::from_value(config.clone()).map_err(|error| error.to_string())?;
    caddy_rs_core::validate_config(&config, &registry).map_err(|error| error.to_string())?;
    Ok(())
}

#[test]
fn ciphers_and_curves_land_in_the_connection_policy() {
    let adapted = adapt(
        "example.com {\n\ttls {\n\t\tciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n\t\tcurves x25519 secp256r1 secp384r1\n\t}\n\trespond \"ok\"\n}\n",
    )
    .expect("adapts");
    let policies = &adapted.config["apps"]["http"]["servers"]["srv0"]["tls_connection_policies"];
    assert_eq!(
        policies[0],
        json!({
            "match": {"sni": ["example.com"]},
            "cipher_suites": [
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
            "curves": ["x25519", "secp256r1", "secp384r1"],
        })
    );
    assert_eq!(policies[1], json!({}));
    validate(&adapted.config).expect("adapted config validates");
}

#[test]
fn hostless_site_policy_has_no_sni_match() {
    let adapted = adapt(
        ":8443 {\n\ttls {\n\t\tciphers TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\n\t\tcurves x25519 secp384r1\n\t}\n\trespond ok\n}\n",
    )
    .expect("adapts");
    let policies = &adapted.config["apps"]["http"]["servers"]["srv0"]["tls_connection_policies"];
    assert_eq!(
        policies,
        &json!([{
            "cipher_suites": ["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"],
            "curves": ["x25519", "secp384r1"],
        }])
    );
    validate(&adapted.config).expect("hostless policy validates");
}

#[test]
fn repeated_options_append_in_order() {
    let adapted = adapt(
        "example.com {\n\ttls {\n\t\tciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\n\t\tciphers TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n\t\tcurves x25519\n\t\tcurves secp256r1\n\t}\n}\n",
    )
    .expect("adapts");
    let policy = &adapted.config["apps"]["http"]["servers"]["srv0"]["tls_connection_policies"][0];
    assert_eq!(
        policy["cipher_suites"],
        json!([
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ])
    );
    assert_eq!(policy["curves"], json!(["x25519", "secp256r1"]));
}

#[test]
fn empty_options_are_no_ops_like_caddy() {
    let adapted =
        adapt("example.com {\n\ttls {\n\t\tciphers\n\t\tcurves\n\t}\n}\n").expect("adapts");
    let server = &adapted.config["apps"]["http"]["servers"]["srv0"];
    assert!(server.get("tls_connection_policies").is_none());
    validate(&adapted.config).expect("empty options validate");
}

#[test]
fn caddy_accepted_but_runtime_unsupported_ciphers_fail_loudly() {
    for name in [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    ] {
        let error = adapt(&format!(
            "example.com {{\n\ttls {{\n\t\tciphers {name}\n\t}}\n}}\n"
        ))
        .expect_err("Caddy-accepted but runtime-unsupported cipher must fail loudly");
        let message = error.to_string();
        assert!(message.contains(name), "{message}");
        assert_eq!(error.code(), "config.unsupported", "{message}");
        assert!(message.contains("not supported by this build"), "{message}");
        assert!(message.contains("tracked as TLS-POLICY"), "{message}");
    }
}

#[test]
fn caddy_accepted_but_runtime_unsupported_curves_fail_loudly() {
    let name = "secp521r1";
    let error = adapt(&format!(
        "example.com {{\n\ttls {{\n\t\tcurves {name}\n\t}}\n}}\n"
    ))
    .expect_err("Caddy-accepted but runtime-unsupported curve must fail loudly");
    let message = error.to_string();
    assert!(message.contains(name), "{message}");
    assert_eq!(error.code(), "config.unsupported", "{message}");
    assert!(message.contains("aws-lc-rs"), "{message}");
    assert!(message.contains("tracked as TLS-POLICY"), "{message}");
}

#[test]
fn mlkem_curve_lands_in_the_connection_policy() {
    let adapted = adapt(
        "example.com {\n\ttls {\n\t\tcurves x25519mlkem768 x25519 secp256r1 secp384r1\n\t}\n\trespond ok\n}\n",
    )
    .expect("x25519mlkem768 is supported by aws-lc-rs");
    let policies = &adapted.config["apps"]["http"]["servers"]["srv0"]["tls_connection_policies"];
    assert_eq!(
        policies[0]["curves"],
        json!(["x25519mlkem768", "x25519", "secp256r1", "secp384r1"])
    );
    validate(&adapted.config).expect("adapted config validates");
}

#[test]
fn names_caddy_itself_rejects_fail_loudly() {
    for (option, name) in [("ciphers", "BOGUS_CIPHER"), ("curves", "P-256")] {
        let error = adapt(&format!(
            "example.com {{\n\ttls {{\n\t\t{option} {name}\n\t}}\n}}\n"
        ))
        .expect_err("unknown TLS policy name must fail loudly");
        let message = error.to_string();
        assert!(message.contains(name), "{message}");
    }
}
