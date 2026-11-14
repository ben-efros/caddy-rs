//! Route-level tests for the security-headers documentation surfaces.
//!
//! The registry tests live next to the data (`security_headers_docs::tests`); these tests only
//! assert that both public surfaces serve it and that its defaults agree with the stored config.

use axum::http::{header, StatusCode};
use axum_test::TestServer;
use caddy_rs_authn::{Argon2Config, AuthnConfig, AuthnService, JwtSecretSource, MemoryUserStore};
use caddy_rs_pm_core::SecurityHeadersConfig;
use caddy_rs_pm_runtime::{PmRuntime, RuntimeConfig};
use serde_json::Value;
use tempfile::TempDir;

use crate::security_headers::SecurityHeadersDto;
use crate::security_headers_docs::{self, DOCUMENTED_FIELDS};
use crate::ApiState;

fn authn() -> AuthnService<MemoryUserStore> {
    // The docs routes are read-only and unauthenticated: the authn service is only needed to build
    // the router's state.
    let authn_config = AuthnConfig {
        jwt_secret_source: JwtSecretSource::Ephemeral,
        argon2_params: Argon2Config {
            memory_cost: 4096,
            time_cost: 1,
            parallelism: 1,
        },
        ..AuthnConfig::default()
    };
    AuthnService::new(MemoryUserStore::new(), authn_config).expect("create authn service")
}

fn server() -> (TempDir, TestServer) {
    let temp_dir = TempDir::new().expect("create temp dir");
    let runtime =
        PmRuntime::open(RuntimeConfig::new(temp_dir.path().join("data"))).expect("open runtime");
    let state = ApiState::new(runtime, authn());
    (temp_dir, TestServer::new(crate::create_router(state)))
}

#[tokio::test]
async fn the_docs_route_serves_every_documented_option() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/security-headers/docs").await;
    assert_eq!(
        response.status_code(),
        StatusCode::OK,
        "{}",
        response.text()
    );

    let body: Value = response.json();
    let options = body["options"].as_array().expect("options array");
    let documented: Vec<&str> = options
        .iter()
        .map(|option| option["field"].as_str().expect("field name"))
        .collect();
    assert_eq!(documented, DOCUMENTED_FIELDS);

    for option in options {
        for key in [
            "description",
            "default",
            "valid_values",
            "examples",
            "security_implications",
            "common_misconfigurations",
            "caddy_headers_handler",
            "divergences",
        ] {
            let value = &option[key];
            assert!(
                !value.is_null() && value != &Value::Array(vec![]),
                "option {} is missing {key}",
                option["field"]
            );
        }
    }

    // The three content areas the acceptance criteria name explicitly.
    assert!(body["csp_directives"]
        .as_array()
        .is_some_and(|d| !d.is_empty()));
    assert!(body["hsts"]["preload_warning"]
        .as_str()
        .is_some_and(|text| text.contains("irreversible") && text.contains("preload")));
    assert!(body["frame_options"]["deny_vs_sameorigin"]
        .as_str()
        .is_some_and(|text| text.contains("SAMEORIGIN") && text.contains("DENY")));

    let divergences: Vec<&str> = body["divergences"]
        .as_array()
        .expect("divergences")
        .iter()
        .map(|entry| entry["id"].as_str().expect("divergence id"))
        .collect();
    for expected in ["DIV-0120", "DIV-0121", "DIV-0122", "DIV-0131"] {
        assert!(divergences.contains(&expected), "missing {expected}");
    }
}

#[tokio::test]
async fn documented_defaults_match_the_stored_config() {
    let (_dir, server) = server();
    let docs: Value = server.get("/api/v1/security-headers/docs").await.json();
    let option = |field: &str| -> &str {
        docs["options"]
            .as_array()
            .expect("options")
            .iter()
            .find(|option| option["field"] == field)
            .and_then(|option| option["default"].as_str())
            .expect("documented default")
    };

    // The API default for a body that omits a field is the serde default of the config type, which
    // is the strict baseline for the three low-risk headers.
    let config: SecurityHeadersConfig =
        serde_json::from_value(serde_json::json!({})).expect("empty config uses serde defaults");
    assert_eq!(
        config.x_frame_options.as_deref(),
        Some("DENY"),
        "config default changed; the docs must follow it"
    );
    assert_eq!(config.x_content_type_options.as_deref(), Some("nosniff"));
    assert_eq!(
        config.referrer_policy.as_deref(),
        Some("strict-origin-when-cross-origin")
    );
    assert!(config.content_security_policy.is_none());
    assert!(config.strict_transport_security.is_none());
    assert!(config.permissions_policy.is_none());

    for (field, value) in [
        ("x_frame_options", "DENY"),
        ("x_content_type_options", "nosniff"),
        ("referrer_policy", "strict-origin-when-cross-origin"),
    ] {
        let documented = option(field);
        assert!(
            documented.starts_with(value),
            "documented default for {field} ({documented}) disagrees with the config default {value}"
        );
    }
    for field in [
        "content_security_policy",
        "strict_transport_security",
        "permissions_policy",
    ] {
        assert!(
            option(field).contains("none (opt-in)"),
            "documented default for {field} must state that it is opt-in"
        );
    }

    // The documented HSTS rules must be the rules the service actually enforces.
    let invalid: SecurityHeadersConfig = serde_json::from_value(serde_json::json!({
        "strict_transport_security": {
            "max_age": 15551999,
            "include_subdomains": true,
            "preload": false
        }
    }))
    .expect("parse hsts config");
    assert!(
        invalid.validate().is_err(),
        "short max_age must be rejected"
    );
    assert!(security_headers_docs::docs()
        .hsts
        .validation
        .iter()
        .any(|rule| rule.contains("15552000") && rule.contains("180 days")));

    let preload_without_subdomains: SecurityHeadersConfig =
        serde_json::from_value(serde_json::json!({
            "strict_transport_security": {
                "max_age": 31536000,
                "include_subdomains": false,
                "preload": true
            }
        }))
        .expect("parse hsts config");
    assert!(preload_without_subdomains.validate().is_err());
}

#[tokio::test]
async fn the_ui_serves_the_docs_page_and_the_existing_routes_still_work() {
    let (_dir, server) = server();

    let page = server.get("/security-headers/docs").await;
    assert_eq!(page.status_code(), StatusCode::OK, "{}", page.text());
    assert_eq!(
        page.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static(
            "text/html; charset=utf-8"
        ))
    );
    let html = page.text();
    for option in security_headers_docs::docs().options {
        assert!(html.contains(option.field), "page misses {}", option.field);
    }
    assert!(html.contains("Content-Security-Policy"));
    assert!(html.contains("Strict-Transport-Security"));
    assert!(html.contains("X-Frame-Options"));
    assert!(html.contains("/api/v1/security-headers/docs"));
    assert!(html.contains("Preload warning"));

    // The config routes this documentation describes are untouched and unauthenticated reads.
    let config = server.get("/api/v1/security-headers").await;
    assert_eq!(config.status_code(), StatusCode::OK, "{}", config.text());

    // A docs route never leaks into the API 404 contract.
    let missing = server.get("/api/v1/security-headers/docs/nope").await;
    assert_eq!(missing.status_code(), StatusCode::NOT_FOUND);
    assert_eq!(
        missing.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("application/json"))
    );

    // And the DTO serializes exactly the fields the docs claim to cover.
    let populated: SecurityHeadersDto = serde_json::from_value(serde_json::json!({
        "content_security_policy": "default-src 'self'",
        "strict_transport_security": {
            "max_age": 31536000,
            "include_subdomains": true,
            "preload": false
        },
        "permissions_policy": "geolocation=()",
        "x_frame_options": "DENY",
        "x_content_type_options": "nosniff",
        "referrer_policy": "no-referrer"
    }))
    .expect("parse dto");
    let mut fields: Vec<String> = serde_json::to_value(&populated)
        .expect("serialize dto")
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect();
    fields.sort();
    let mut documented: Vec<String> = DOCUMENTED_FIELDS.iter().map(|f| f.to_string()).collect();
    documented.sort();
    assert_eq!(fields, documented);
}
