//! Integration tests for the PM API.
//!
//! The router is exercised through `axum-test`, so these tests go through the same middleware,
//! extractors and serialization the daemon uses. Assertions are on observable HTTP behaviour
//! (status, headers, body shape), not on private helpers alone.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::dto::{HostResponse, HostSpecDto, HostTlsDto, HostWriteRequest};
use axum_test::TestServer;
use caddy_rs_pm_runtime::{
    ConfigApplyService, ConfigApplyStatus, ConfigRevision, PmRuntime, RuntimeConfig,
};
use tempfile::TempDir;

fn runtime() -> (TempDir, ApiState) {
    let temp_dir = TempDir::new().expect("create temp dir");
    let config = RuntimeConfig::new(temp_dir.path().join("data"));
    let runtime = PmRuntime::open(config).expect("open runtime");
    (temp_dir, ApiState::new(runtime))
}

fn server() -> (TempDir, TestServer) {
    let (temp_dir, state) = runtime();
    (temp_dir, TestServer::new(create_router(state)))
}

#[tokio::test]
async fn health_reports_ok() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: HealthResponse = response.json();
    assert_eq!(body.status, "ok");
    assert!(!body.setup, "no user store means setup is not complete");
}

#[tokio::test]
async fn setup_is_not_configured_without_a_user_store() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/setup").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: SetupResponse = response.json();
    assert!(!body.configured);
}

#[tokio::test]
async fn version_reports_api_and_core_versions() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/version").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: VersionResponse = response.json();
    assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(body.caddy_rs, caddy_rs_core::VERSION);
}

#[tokio::test]
async fn request_id_is_returned_on_every_response() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/health").await;
    let request_id = response.header("x-request-id");
    assert!(!request_id.to_str().expect("ascii").is_empty());
}

#[tokio::test]
async fn hosts_is_empty_and_paginated() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/hosts").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: PaginatedResponse<HostSummary> = response.json();
    assert!(body.items.is_empty());
    assert_eq!(body.total, 0);
    assert_eq!(body.limit, DEFAULT_LIMIT);
    assert_eq!(body.offset, 0);
}

#[tokio::test]
async fn hosts_clamps_an_oversized_limit_and_echoes_it() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/hosts?limit=9999&offset=0").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: PaginatedResponse<HostSummary> = response.json();
    assert_eq!(body.limit, MAX_LIMIT);
}

#[tokio::test]
async fn hosts_rejects_a_non_numeric_limit_with_a_typed_error() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/hosts?limit=abc").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert!(response
        .header("content-type")
        .to_str()
        .expect("ascii")
        .starts_with("application/json"));
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Validation);
    assert_eq!(body.error.location.as_deref(), Some("limit"));
}

#[tokio::test]
async fn hosts_rejects_a_negative_limit_with_a_typed_error() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/hosts?limit=-1").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Validation);
    assert_eq!(body.error.location.as_deref(), Some("limit"));
}

#[tokio::test]
async fn config_has_a_stable_etag() {
    let (_dir, server) = server();
    let first = server.get("/api/v1/config").await;
    assert_eq!(first.status_code(), StatusCode::OK);
    let etag = first.header("etag").to_str().expect("ascii").to_owned();
    assert!(etag.starts_with("W/\""), "weak etag, got {etag}");

    let second = server.get("/api/v1/config").await;
    assert_eq!(second.header("etag").to_str().expect("ascii"), etag);
    assert_eq!(first.text(), second.text());
}

#[tokio::test]
async fn config_if_none_match_returns_not_modified() {
    let (_dir, server) = server();
    let etag = server
        .get("/api/v1/config")
        .await
        .header("etag")
        .to_str()
        .expect("ascii")
        .to_owned();

    let response = server
        .get("/api/v1/config")
        .add_header("If-None-Match", etag.as_str())
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_MODIFIED);
    assert_eq!(response.text(), "");
}

#[tokio::test]
async fn config_if_none_match_with_a_different_etag_returns_the_body() {
    let (_dir, server) = server();
    let response = server
        .get("/api/v1/config")
        .add_header("If-None-Match", r#"W/"stale""#)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(!response.text().is_empty());
}

#[tokio::test]
async fn config_if_match_mismatch_is_412_with_a_typed_error() {
    let (_dir, server) = server();
    let response = server
        .get("/api/v1/config")
        .add_header("If-Match", r#"W/"stale""#)
        .await;
    assert_eq!(response.status_code(), StatusCode::PRECONDITION_FAILED);

    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::PreconditionFailed);
    assert!(body.error.message.contains("If-Match"));
}

#[tokio::test]
async fn config_if_match_star_matches_any_representation() {
    let (_dir, server) = server();
    let response = server
        .get("/api/v1/config")
        .add_header("If-Match", "*")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn config_if_match_with_the_current_etag_succeeds() {
    let (_dir, server) = server();
    let etag = server
        .get("/api/v1/config")
        .await
        .header("etag")
        .to_str()
        .expect("ascii")
        .to_owned();
    let response = server
        .get("/api/v1/config")
        .add_header("If-Match", etag.as_str())
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn if_match_is_evaluated_before_if_none_match() {
    // RFC 9110 order: a failing If-Match must win over a matching If-None-Match.
    let (_dir, server) = server();
    let etag = server
        .get("/api/v1/config")
        .await
        .header("etag")
        .to_str()
        .expect("ascii")
        .to_owned();

    let response = server
        .get("/api/v1/config")
        .add_header("If-Match", r#"W/"stale""#)
        .add_header("If-None-Match", etag.as_str())
        .await;
    assert_eq!(response.status_code(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn malformed_if_match_fails_closed() {
    let (_dir, server) = server();
    let response = server
        .get("/api/v1/config")
        .add_header("If-Match", "not an etag at all")
        .await;
    assert_eq!(response.status_code(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn non_utf8_if_match_fails_closed_instead_of_being_treated_as_absent() {
    let (_dir, server) = server();
    // A header value that is present but not valid UTF-8. Returning 200 here would be the
    // fail-open path: an unparseable precondition must never mean "no precondition".
    let value = HeaderValue::from_bytes(b"\xff\xfe").expect("opaque header");
    let response = server
        .get("/api/v1/config")
        .add_header("If-Match", value)
        .await;
    assert_eq!(response.status_code(), StatusCode::PRECONDITION_FAILED);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::PreconditionFailed);
}

#[test]
fn require_if_match_rejects_a_missing_header() {
    let headers = HeaderMap::new();
    let error = require_if_match(&headers, r#"W/"7""#).expect_err("missing header must fail");
    assert!(matches!(error, ApiError::PreconditionFailed(_)));
    assert_eq!(error.status_code(), StatusCode::PRECONDITION_FAILED);
}

#[test]
fn require_if_match_rejects_a_stale_revision() {
    let mut headers = HeaderMap::new();
    headers.insert(header::IF_MATCH, r#"W/"6""#.parse().expect("header"));
    let error = require_if_match(&headers, r#"W/"7""#).expect_err("stale revision must fail");
    assert_eq!(error.error_code(), ErrorCode::PreconditionFailed);
}

#[test]
fn require_if_match_accepts_the_current_revision_and_star() {
    let mut headers = HeaderMap::new();
    headers.insert(header::IF_MATCH, r#"W/"7""#.parse().expect("header"));
    require_if_match(&headers, r#"W/"7""#).expect("current revision");

    let mut headers = HeaderMap::new();
    headers.insert(header::IF_MATCH, HeaderValue::from_static("*"));
    require_if_match(&headers, r#"W/"7""#).expect("star");
}

#[test]
fn error_shape_is_stable() {
    let body = ApiErrorResponse {
        error: ApiErrorDetail {
            code: ErrorCode::Validation,
            message: "invalid domain".to_owned(),
            location: Some("domains[0]".to_owned()),
        },
    };
    let json = serde_json::to_value(&body).expect("serialize");
    assert_eq!(json["error"]["code"], "VALIDATION");
    assert_eq!(json["error"]["message"], "invalid domain");
    assert_eq!(json["error"]["location"], "domains[0]");

    let without_location = ApiErrorResponse {
        error: ApiErrorDetail {
            code: ErrorCode::NotFound,
            message: "missing".to_owned(),
            location: None,
        },
    };
    let json = serde_json::to_value(&without_location).expect("serialize");
    assert!(json["error"].get("location").is_none());
}

#[tokio::test]
async fn validation_error_response_carries_the_location() {
    let error = ApiError::validation("must be a hostname", "domains[0]");
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: ApiErrorResponse = serde_json::from_slice(&bytes).expect("parse");
    assert_eq!(body.error.code, ErrorCode::Validation);
    assert_eq!(body.error.location.as_deref(), Some("domains[0]"));
}

#[test]
fn paginate_handles_out_of_range_offsets() {
    let params = PaginationParams {
        limit: 10,
        offset: 50,
    };
    let page = params.paginate(&[1, 2, 3]);
    assert!(page.items.is_empty());
    assert_eq!(page.total, 3);
    assert_eq!(page.offset, 50);

    let params = PaginationParams {
        limit: 2,
        offset: 1,
    };
    let page = params.paginate(&[1, 2, 3]);
    assert_eq!(page.items, vec![2, 3]);
    assert_eq!(page.total, 3);
}

#[test]
fn weak_etag_normalization_accepts_common_forms() {
    assert_eq!(normalize_etag_member(r#"W/"abc""#), "abc");
    assert_eq!(normalize_etag_member(r#""abc""#), "abc");
    assert_eq!(normalize_etag_member("abc"), "abc");
    assert_eq!(normalize_etag_member(" * "), "*");
    assert_eq!(format_weak_etag("abc"), r#"W/"abc""#);
}

// ---------------------------------------------------------------------------------------------
// Host CRUD
// ---------------------------------------------------------------------------------------------

fn server_with_runtime() -> (TempDir, TestServer, PmRuntime) {
    let temp_dir = TempDir::new().expect("create temp dir");
    let config = RuntimeConfig::new(temp_dir.path().join("data"));
    let runtime = PmRuntime::open(config).expect("open runtime");
    let state = ApiState::new(runtime.clone());
    let app = create_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    (temp_dir, TestServer::new(app), runtime)
}

fn dead_body(domain: &str) -> serde_json::Value {
    serde_json::json!({
        "domains": [domain],
        "tls": {"mode": "disabled"},
        "spec": {"kind": "dead"}
    })
}

async fn create_dead(server: &TestServer, domain: &str) -> HostResponse {
    let response = server.post("/api/v1/hosts").json(&dead_body(domain)).await;
    assert_eq!(
        response.status_code(),
        StatusCode::CREATED,
        "create {domain}: {}",
        response.text()
    );
    response.json()
}

#[tokio::test]
async fn create_host_returns_201_location_and_a_strong_etag() {
    let (_dir, server, runtime) = server_with_runtime();
    let response = server
        .post("/api/v1/hosts")
        .json(&serde_json::json!({
            "domains": ["app.example.com"],
            "spec": {"kind": "dead"}
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    assert_eq!(response.header("location"), "/api/v1/hosts/1");
    assert_eq!(response.header("etag"), "\"h1-r1\"");
    assert_eq!(response.header("cache-control"), "no-store");
    let body: HostResponse = response.json();
    assert_eq!(body.id, 1);
    assert_eq!(body.revision, 1);
    assert!(body.enabled, "enabled defaults to true");
    assert_eq!(body.tls.mode, caddy_rs_pm_core::TlsMode::Disabled);
    assert_eq!(body.spec, HostSpecDto::Dead, "dead spec round-trips");

    let stored = runtime.hosts().get(caddy_rs_pm_core::HostId(1)).unwrap();
    assert!(stored.is_some());
}

#[tokio::test]
async fn create_rejects_a_duplicate_domain_with_409() {
    let (_dir, server, _runtime) = server_with_runtime();
    let _ = create_dead(&server, "taken.example.com").await;

    let response = server
        .post("/api/v1/hosts")
        .json(&dead_body("taken.example.com"))
        .await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Conflict);
}

#[tokio::test]
async fn create_rejects_npm_fields_and_wrong_content_types() {
    let (_dir, server, _runtime) = server_with_runtime();

    let response = server
        .post("/api/v1/hosts")
        .json(&serde_json::json!({
            "domains": ["app.example.com"],
            "forward_host": "10.0.0.5",
            "spec": {"kind": "dead"}
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Validation);
    assert_eq!(body.error.location.as_deref(), Some("body"));

    let response = server
        .post("/api/v1/hosts")
        .content_type("text/plain")
        .text("not json")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::UnsupportedMediaType);

    let response = server
        .post("/api/v1/hosts")
        .text("{")
        .content_type("application/json")
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_host_serves_detail_and_honours_weak_if_none_match() {
    let (_dir, server, _runtime) = server_with_runtime();
    let created = create_dead(&server, "detail.example.com").await;

    let response = server.get("/api/v1/hosts/1").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.header("etag"), "\"h1-r1\"");
    let body: HostResponse = response.json();
    assert_eq!(body, created);

    let response = server
        .get("/api/v1/hosts/1")
        .add_header(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("W/\"h1-r1\""),
        )
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_MODIFIED);

    let response = server.get("/api/v1/hosts/999").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let response = server.get("/api/v1/hosts/not-a-number").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.location.as_deref(), Some("id"));
}

#[tokio::test]
async fn replace_requires_a_strong_matching_if_match_and_bumps_the_revision() {
    let (_dir, server, _runtime) = server_with_runtime();
    let _ = create_dead(&server, "replace.example.com").await;

    let stale = server
        .put("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r0\""))
        .json(&dead_body("replace.example.com"))
        .await;
    assert_eq!(stale.status_code(), StatusCode::PRECONDITION_FAILED);

    let weak = server
        .put("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("W/\"h1-r1\""))
        .json(&dead_body("replace.example.com"))
        .await;
    assert_eq!(weak.status_code(), StatusCode::PRECONDITION_FAILED);

    let missing = server
        .put("/api/v1/hosts/1")
        .json(&dead_body("replace.example.com"))
        .await;
    assert_eq!(missing.status_code(), StatusCode::PRECONDITION_REQUIRED);

    let response = server
        .put("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r1\""))
        .json(&serde_json::json!({
            "domains": ["replace.example.com"],
            "enabled": false,
            "spec": {"kind": "dead"}
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.header("etag"), "\"h1-r2\"");
    let body: HostResponse = response.json();
    assert_eq!(body.revision, 2);
    assert!(!body.enabled, "PUT replaces the enabled flag");

    let stale_again = server
        .put("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r1\""))
        .json(&dead_body("replace.example.com"))
        .await;
    assert_eq!(stale_again.status_code(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn patch_changes_only_the_named_fields_and_keeps_the_rest() {
    let (_dir, server, _runtime) = server_with_runtime();
    let created = create_dead(&server, "patch.example.com").await;

    let response = server
        .patch("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r1\""))
        .json(&serde_json::json!({"enabled": false}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: HostResponse = response.json();
    assert_eq!(body.revision, 2);
    assert!(!body.enabled);
    assert_eq!(body.domains, created.domains);
    assert_eq!(body.spec, created.spec);
    assert_eq!(body.tls, created.tls);

    let empty = server
        .patch("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r2\""))
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(empty.status_code(), StatusCode::BAD_REQUEST);

    let stale = server
        .patch("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r1\""))
        .json(&serde_json::json!({"enabled": true}))
        .await;
    assert_eq!(stale.status_code(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn enable_and_disable_are_set_operations_not_blind_flips() {
    let (_dir, server, _runtime) = server_with_runtime();
    let _ = create_dead(&server, "toggle.example.com").await;

    let disabled = server
        .post("/api/v1/hosts/1/disable")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r1\""))
        .await;
    assert_eq!(disabled.status_code(), StatusCode::OK);
    let body: HostResponse = disabled.json();
    assert!(!body.enabled);
    assert_eq!(body.revision, 2);

    // Repeating disable while sending the new ETag is idempotent in effect, but still a revision.
    let disabled_again = server
        .post("/api/v1/hosts/1/disable")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r2\""))
        .await;
    assert_eq!(disabled_again.status_code(), StatusCode::OK);
    let body: HostResponse = disabled_again.json();
    assert!(!body.enabled);
    assert_eq!(body.revision, 3);

    let enabled = server
        .post("/api/v1/hosts/1/enable")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r3\""))
        .await;
    assert_eq!(enabled.status_code(), StatusCode::OK);
    let body: HostResponse = enabled.json();
    assert!(body.enabled);
    assert_eq!(body.revision, 4);
}

#[tokio::test]
async fn delete_retires_the_id_and_next_create_skips_it() {
    let (_dir, server, runtime) = server_with_runtime();
    let _ = create_dead(&server, "delete.example.com").await;

    let missing = server.delete("/api/v1/hosts/1").await;
    assert_eq!(missing.status_code(), StatusCode::PRECONDITION_REQUIRED);

    let stale = server
        .delete("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r0\""))
        .await;
    assert_eq!(stale.status_code(), StatusCode::PRECONDITION_FAILED);

    let response = server
        .delete("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r1\""))
        .await;
    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);
    assert!(runtime
        .hosts()
        .get(caddy_rs_pm_core::HostId(1))
        .unwrap()
        .is_none());

    let second = create_dead(&server, "second.example.com").await;
    assert_eq!(second.id, 2, "retired ids are never reused");

    let gone = server.get("/api/v1/hosts/1").await;
    assert_eq!(gone.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_filters_are_applied_before_pagination() {
    let (_dir, server, _runtime) = server_with_runtime();
    let _ = create_dead(&server, "one.example.com").await;
    let _ = create_dead(&server, "two.example.com").await;

    let response = server
        .post("/api/v1/hosts")
        .json(&serde_json::json!({
            "domains": ["proxy.example.com"],
            "enabled": false,
            "spec": {
                "kind": "proxy",
                "spec": {
                    "upstream": {"scheme": "http", "host": "10.0.0.5", "port": 8080}
                }
            }
        }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::CREATED,
        "{}",
        response.text()
    );

    let response = server.get("/api/v1/hosts?enabled=false").await;
    let body: PaginatedResponse<HostSummary> = response.json();
    assert_eq!(body.total, 1);
    assert_eq!(body.items[0].id, 3);

    let response = server.get("/api/v1/hosts?kind=dead&limit=1&offset=1").await;
    let body: PaginatedResponse<HostSummary> = response.json();
    assert_eq!(body.total, 2);
    assert_eq!(body.items.len(), 1);
    assert_eq!(body.items[0].id, 2);

    let response = server.get("/api/v1/hosts?domain=TWO.example").await;
    let body: PaginatedResponse<HostSummary> = response.json();
    assert_eq!(body.total, 1);
    assert_eq!(body.items[0].id, 2);

    let response = server.get("/api/v1/hosts?enabled=maybe").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let response = server.get("/api/v1/hosts?nope=1").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revisions_are_monotonic_across_every_mutation() {
    let (_dir, server, _runtime) = server_with_runtime();
    let _ = create_dead(&server, "mono.example.com").await;

    let patched = server
        .patch("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r1\""))
        .json(&serde_json::json!({"domains": ["mono2.example.com"]}))
        .await;
    assert_eq!(patched.status_code(), StatusCode::OK);
    assert_eq!(patched.json::<HostResponse>().revision, 2);
    assert_eq!(patched.header("etag"), "\"h1-r2\"");

    let disabled = server
        .post("/api/v1/hosts/1/disable")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r2\""))
        .await;
    assert_eq!(disabled.json::<HostResponse>().revision, 3);
}

#[tokio::test]
async fn a_stale_read_cannot_overwrite_a_newer_write() {
    let (_dir, server, runtime) = server_with_runtime();
    let _ = create_dead(&server, "race.example.com").await;
    let first = runtime
        .hosts()
        .get(caddy_rs_pm_core::HostId(1))
        .unwrap()
        .unwrap();
    let second = first.clone();

    let draft = HostWriteRequest {
        domains: vec!["race.example.com".to_owned()],
        tls: HostTlsDto::default(),
        spec: HostSpecDto::Dead,
        enabled: true,
    }
    .into_draft();
    runtime
        .service()
        .update(caddy_rs_pm_core::HostId(1), first.revision, draft)
        .expect("first writer wins");

    let stale = runtime.service().update(
        caddy_rs_pm_core::HostId(1),
        second.revision,
        HostWriteRequest {
            domains: vec!["race.example.com".to_owned()],
            tls: HostTlsDto::default(),
            spec: HostSpecDto::Dead,
            enabled: false,
        }
        .into_draft(),
    );
    assert!(stale.is_err(), "the second writer must fail CAS");
}

#[tokio::test]
async fn update_to_an_owned_domain_is_409_not_412() {
    let (_dir, server, _runtime) = server_with_runtime();
    let _ = create_dead(&server, "first.example.com").await;
    let _ = create_dead(&server, "second.example.com").await;

    let response = server
        .put("/api/v1/hosts/1")
        .add_header(header::IF_MATCH, HeaderValue::from_static("\"h1-r1\""))
        .json(&dead_body("second.example.com"))
        .await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Conflict);

    // The failed update must leave host 1 on its original domain and revision.
    let response = server.get("/api/v1/hosts/1").await;
    let body: HostResponse = response.json();
    assert_eq!(body.domains, vec!["first.example.com".to_string()]);
    assert_eq!(body.revision, 1);
}

// ---------------------------------------------------------------------------------------------
// Certificate intents
// ---------------------------------------------------------------------------------------------

struct FakeInventory {
    records: Vec<CertificateRecord>,
}

/// Inventory that the test can change between requests, to prove validators track the body.
struct MutableInventory(std::sync::Mutex<Vec<CertificateRecord>>);

impl MutableInventory {
    fn set(&self, records: Vec<CertificateRecord>) {
        *self.0.lock().expect("lock inventory") = records;
    }
}

impl CertificateInventorySource for MutableInventory {
    fn list_certificates(&self) -> Result<Vec<CertificateRecord>, InventoryError> {
        Ok(self.0.lock().expect("lock inventory").clone())
    }
}

impl CertificateInventorySource for FakeInventory {
    fn list_certificates(&self) -> Result<Vec<CertificateRecord>, InventoryError> {
        Ok(self.records.clone())
    }
}

fn server_with_inventory(records: Vec<CertificateRecord>) -> (TempDir, TestServer, PmRuntime) {
    let temp_dir = TempDir::new().expect("create temp dir");
    let config = RuntimeConfig::new(temp_dir.path().join("data"));
    let runtime = PmRuntime::open(config).expect("open runtime");
    let state = ApiState::new(runtime.clone()).with_inventory(Arc::new(FakeInventory { records }));
    let app = create_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    (temp_dir, TestServer::new(app), runtime)
}

fn now_unix() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    i64::try_from(seconds).expect("timestamp fits i64")
}

fn days(seconds: i64) -> i64 {
    seconds * 24 * 60 * 60
}

fn intent_body(domains: &[&str], issuer: &str, challenge: &str) -> serde_json::Value {
    serde_json::json!({
        "domains": domains,
        "issuer": issuer,
        "challenge": challenge
    })
}

async fn create_intent(
    server: &TestServer,
    domains: &[&str],
    issuer: &str,
    challenge: &str,
) -> CertificateIntentSummary {
    let response = server
        .post("/api/v1/certificates/intent")
        .json(&intent_body(domains, issuer, challenge))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::CREATED,
        "create intent {domains:?}: {}",
        response.text()
    );
    response.json()
}

fn record(domains: &[&str], sans: &[&str], expires_at_unix: Option<i64>) -> CertificateRecord {
    CertificateRecord {
        domains: domains.iter().map(|value| (*value).to_string()).collect(),
        sans: sans.iter().map(|value| (*value).to_string()).collect(),
        issuer: "local".to_string(),
        expires_at_unix,
        source: "managed".to_string(),
        renewal_error: None,
    }
}

#[tokio::test]
async fn create_certificate_intent_returns_201_location_etag_and_persists_a_policy() {
    let (_dir, server, runtime) = server_with_runtime();
    let response = server
        .post("/api/v1/certificates/intent")
        .json(&intent_body(&["api.example.com"], "letsencrypt", "http01"))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    assert_eq!(response.header("location"), "/api/v1/certificates/1");
    let etag = response.header("etag").to_str().expect("ascii").to_owned();
    assert!(etag.starts_with("\"c1-"), "unexpected etag {etag}");
    let body: CertificateIntentSummary = response.json();
    assert_eq!(body.policy_id, 1);
    assert_eq!(body.domains, vec!["api.example.com".to_string()]);
    assert_eq!(body.issuer, "letsencrypt");
    assert_eq!(body.challenge, caddy_rs_pm_core::AcmeChallenge::Http01);
    assert_eq!(body.status, CertificateIntentStatus::Pending);
    assert!(body.enabled);
    assert_eq!(body.name, "Certificate intent for api.example.com");

    let stored = runtime
        .policies()
        .get(caddy_rs_pm_core::PolicyId(1))
        .expect("read policy")
        .expect("policy persisted");
    assert_eq!(stored.policy.mode, caddy_rs_pm_core::AutoMode::Eager);
    assert_eq!(stored.policy.issuer.as_deref(), Some("letsencrypt"));
    assert_eq!(
        stored.policy.challenge,
        caddy_rs_pm_core::AcmeChallenge::Http01
    );
    assert!(stored.policy.key_type.is_none());
    assert!(stored.policy.enabled);
}

#[tokio::test]
async fn create_certificate_intent_rejects_dns01_with_a_located_400() {
    let (_dir, server, runtime) = server_with_runtime();
    let response = server
        .post("/api/v1/certificates/intent")
        .json(&intent_body(&["example.com"], "letsencrypt", "dns01"))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Validation);
    assert_eq!(body.error.location.as_deref(), Some("challenge"));
    assert!(body.error.message.contains("DNS provider credentials"));
    assert!(
        runtime.policies().list().expect("list policies").is_empty(),
        "rejected DNS-01 must not persist anything"
    );
}

#[tokio::test]
async fn create_certificate_intent_rejects_npm_and_unknown_fields() {
    let (_dir, server, _runtime) = server_with_runtime();
    for payload in [
        serde_json::json!({
            "domains": ["example.com"],
            "issuer": "letsencrypt",
            "challenge": "http01",
            "provider": "letsencrypt"
        }),
        serde_json::json!({
            "domains": ["example.com"],
            "issuer": "letsencrypt",
            "challenge": "http01",
            "certificate": "PEM"
        }),
    ] {
        let response = server
            .post("/api/v1/certificates/intent")
            .json(&payload)
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        let body: ApiErrorResponse = response.json();
        assert_eq!(body.error.code, ErrorCode::Validation);
        assert_eq!(body.error.location.as_deref(), Some("body"));
    }
}

#[tokio::test]
async fn create_certificate_intent_validates_domains() {
    let (_dir, server, _runtime) = server_with_runtime();
    let duplicate = server
        .post("/api/v1/certificates/intent")
        .json(&intent_body(
            &["example.com", "EXAMPLE.com"],
            "letsencrypt",
            "http01",
        ))
        .await;
    assert_eq!(duplicate.status_code(), StatusCode::BAD_REQUEST);
    let body: ApiErrorResponse = duplicate.json();
    assert_eq!(body.error.code, ErrorCode::Validation);
    assert_eq!(body.error.location.as_deref(), Some("domains"));
    assert!(body.error.message.contains("duplicate domain"));

    let wildcard = server
        .post("/api/v1/certificates/intent")
        .json(&intent_body(&["*.example.com"], "letsencrypt", "http01"))
        .await;
    assert_eq!(wildcard.status_code(), StatusCode::BAD_REQUEST);
    let body: ApiErrorResponse = wildcard.json();
    assert_eq!(body.error.location.as_deref(), Some("domains"));
}

#[tokio::test]
async fn certificate_intent_mutations_require_connect_info() {
    let (_dir, server) = server();
    let response = server
        .post("/api/v1/certificates/intent")
        .json(&intent_body(&["example.com"], "letsencrypt", "http01"))
        .await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Forbidden);
}

#[tokio::test]
async fn certificate_intent_mutations_reject_a_remote_peer() {
    use axum::extract::Request;
    use axum::middleware::Next;
    use axum::routing::post;

    let (_dir, state) = runtime();
    let app = Router::new()
        .route(
            "/api/v1/certificates/intent",
            post(crate::certificates::create_handler),
        )
        .layer(axum::middleware::from_fn(
            |mut request: Request, next: Next| async move {
                request
                    .extensions_mut()
                    .insert(PeerAddr(Some(std::net::SocketAddr::from((
                        [192, 0, 2, 10],
                        5000,
                    )))));
                next.run(request).await
            },
        ))
        .with_state(state);
    let server = TestServer::new(app);

    let response = server
        .post("/api/v1/certificates/intent")
        .json(&intent_body(&["example.com"], "letsencrypt", "http01"))
        .await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.json::<ApiErrorResponse>().error.code,
        ErrorCode::Forbidden
    );
}

#[tokio::test]
async fn certificate_list_reports_pending_without_an_inventory_source() {
    let (_dir, server, _runtime) = server_with_runtime();
    create_intent(&server, &["pending.example.com"], "internal", "http01").await;

    let response = server.get("/api/v1/certificates").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: PaginatedResponse<CertificateIntentSummary> = response.json();
    assert_eq!(body.total, 1);
    assert_eq!(body.items[0].status, CertificateIntentStatus::Pending);
    assert!(body.items[0].expires_at_unix.is_none());
    assert!(body.items[0].certificate_issuer.is_none());
}

#[tokio::test]
async fn certificate_list_derives_issued_expiring_expired_and_renewal_error_statuses() {
    let now = now_unix();
    let (_dir, server, _runtime) = server_with_inventory(vec![
        record(&["issued.example.com"], &[], Some(now + days(90))),
        record(&["expiring.example.com"], &[], Some(now + days(10))),
        record(&["expired.example.com"], &[], Some(now - 1)),
        CertificateRecord {
            renewal_error: Some("account is rate limited".to_string()),
            ..record(&["failing.example.com"], &[], Some(now + days(90)))
        },
        record(&["noexpiry.example.com"], &[], None),
    ]);

    for domain in [
        "issued.example.com",
        "expiring.example.com",
        "expired.example.com",
        "failing.example.com",
        "noexpiry.example.com",
    ] {
        create_intent(&server, &[domain], "letsencrypt", "http01").await;
    }

    let statuses = |body: &PaginatedResponse<CertificateIntentSummary>, domain: &str| {
        body.items
            .iter()
            .find(|item| item.domains == vec![domain.to_string()])
            .map(|item| item.status)
            .expect("intent present")
    };

    let body: PaginatedResponse<CertificateIntentSummary> =
        server.get("/api/v1/certificates").await.json();
    assert_eq!(body.total, 5);
    assert_eq!(
        statuses(&body, "issued.example.com"),
        CertificateIntentStatus::Issued
    );
    assert_eq!(
        statuses(&body, "expiring.example.com"),
        CertificateIntentStatus::ExpiringSoon
    );
    assert_eq!(
        statuses(&body, "expired.example.com"),
        CertificateIntentStatus::Expired
    );
    assert_eq!(
        statuses(&body, "failing.example.com"),
        CertificateIntentStatus::RenewalError
    );
    assert_eq!(
        statuses(&body, "noexpiry.example.com"),
        CertificateIntentStatus::Issued,
        "an observation without expiry is issued, never fabricated as expired"
    );

    let filtered: PaginatedResponse<CertificateIntentSummary> = server
        .get("/api/v1/certificates?status=expiring_soon")
        .await
        .json();
    assert_eq!(filtered.total, 1);
    assert_eq!(filtered.items[0].domains, vec!["expiring.example.com"]);
    assert!(filtered.items[0].expires_at_unix.is_some());
    assert_eq!(
        filtered.items[0].certificate_issuer.as_deref(),
        Some("local")
    );
}

#[tokio::test]
async fn certificate_list_filters_before_paginating() {
    let now = now_unix();
    let (_dir, server, _runtime) = server_with_inventory(vec![
        record(&["one.example.com"], &[], Some(now + days(90))),
        record(&["two.example.com"], &[], Some(now + days(90))),
    ]);
    for domain in ["one.example.com", "two.example.com", "three.other.net"] {
        create_intent(&server, &[domain], "internal", "http01").await;
    }

    let page: PaginatedResponse<CertificateIntentSummary> = server
        .get("/api/v1/certificates?domain=example.com&limit=1&offset=1")
        .await
        .json();
    assert_eq!(
        page.total, 2,
        "the domain filter is applied before the window"
    );
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].domains, vec!["two.example.com"]);
    assert_eq!(page.limit, 1);
    assert_eq!(page.offset, 1);

    let page: PaginatedResponse<CertificateIntentSummary> = server
        .get("/api/v1/certificates?domain=other.net")
        .await
        .json();
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].domains, vec!["three.other.net"]);
}

#[tokio::test]
async fn certificate_detail_serves_an_etag_and_404_for_unknown_intents() {
    let (_dir, server, _runtime) = server_with_runtime();
    create_intent(&server, &["detail.example.com"], "internal", "http01").await;

    let response = server.get("/api/v1/certificates/1").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let etag = response.header("etag").to_str().expect("ascii").to_owned();
    assert!(etag.starts_with("\"c1-"), "unexpected etag {etag}");
    let body: CertificateIntentSummary = response.json();
    assert_eq!(body.policy_id, 1);
    assert_eq!(body.status, CertificateIntentStatus::Pending);

    let not_modified = server
        .get("/api/v1/certificates/1")
        .add_header("If-None-Match", etag.as_str())
        .await;
    assert_eq!(not_modified.status_code(), StatusCode::NOT_MODIFIED);

    let missing = server.get("/api/v1/certificates/99").await;
    assert_eq!(missing.status_code(), StatusCode::NOT_FOUND);
    let body: ApiErrorResponse = missing.json();
    assert_eq!(body.error.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn certificate_list_rejects_an_unknown_status_filter() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/certificates?status=renewing").await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Validation);
    assert_eq!(body.error.location.as_deref(), Some("status"));
}

#[tokio::test]
async fn config_after_an_intent_contains_tls_automation_and_disabled_host_skip() {
    let (_dir, server, _runtime) = server_with_runtime();
    create_intent(&server, &["app.example.com"], "letsencrypt", "http01").await;
    let _ = create_dead(&server, "plain.example.com").await;

    let config: serde_json::Value = server.get("/api/v1/config").await.json();
    assert_eq!(
        config["apps"]["tls"]["certificates"]["automate"],
        serde_json::json!(["app.example.com"])
    );
    assert_eq!(
        config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["module"],
        serde_json::json!("acme")
    );
    assert_eq!(
        config["apps"]["http"]["servers"]["pm_https"]["automatic_https"]["skip"],
        serde_json::json!(["plain.example.com"])
    );
}

#[tokio::test]
async fn certificate_detail_etag_tracks_inventory_changes_not_just_policy_revision() {
    let inventory = Arc::new(MutableInventory(std::sync::Mutex::new(Vec::new())));
    let temp_dir = TempDir::new().expect("create temp dir");
    let runtime = PmRuntime::open(RuntimeConfig::new(temp_dir.path().join("data"))).expect("open");
    let state = ApiState::new(runtime).with_inventory(inventory.clone());
    let server = TestServer::new(
        create_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

    create_intent(&server, &["etag.example.com"], "letsencrypt", "http01").await;
    let first = server.get("/api/v1/certificates/1").await;
    let first_etag = first.header("etag").to_str().expect("ascii").to_owned();
    let first_body: CertificateIntentSummary = first.json();
    assert_eq!(first_body.status, CertificateIntentStatus::Pending);

    inventory.set(vec![record(
        &["etag.example.com"],
        &[],
        Some(now_unix() + 90 * 24 * 60 * 60),
    )]);

    let refreshed = server.get("/api/v1/certificates/1").await;
    let refreshed_etag = refreshed.header("etag").to_str().expect("ascii").to_owned();
    let refreshed_body: CertificateIntentSummary = refreshed.json();
    assert_eq!(refreshed_body.status, CertificateIntentStatus::Issued);
    assert_ne!(
        refreshed_etag, first_etag,
        "inventory changed the representation"
    );

    let conditional = server
        .get("/api/v1/certificates/1")
        .add_header("If-None-Match", first_etag.as_str())
        .await;
    assert_eq!(conditional.status_code(), StatusCode::OK);
    let conditional_body: CertificateIntentSummary = conditional.json();
    assert_eq!(conditional_body.status, CertificateIntentStatus::Issued);
}

#[tokio::test]
async fn config_maps_a_stored_policy_assembly_error_to_typed_409() {
    let (_dir, server, runtime) = server_with_runtime();
    runtime
        .policies()
        .create(caddy_rs_pm_core::AutoCertificatePolicy {
            id: caddy_rs_pm_core::PolicyId(1),
            name: "broken".to_string(),
            subjects: vec!["broken.example.com".to_string()],
            mode: caddy_rs_pm_core::AutoMode::Eager,
            issuer: Some("corporate-acme".to_string()),
            key_type: None,
            renewal_window_ratio: None,
            challenge: caddy_rs_pm_core::AcmeChallenge::Http01,
            enabled: true,
        })
        .expect("store policy accepted by the repository");

    let response = server.get("/api/v1/config").await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Conflict);
    assert!(
        body.error.message.contains("corporate-acme"),
        "{}",
        body.error.message
    );
}

// ---------------------------------------------------------------------------------------------
// Manual certificates
// ---------------------------------------------------------------------------------------------

fn manual_fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()))
}

fn manual_body(domains: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "domains": domains,
        "certificate": manual_fixture("manual-valid.crt.pem"),
        "privateKey": manual_fixture("manual-valid.key.pem"),
    })
}

#[tokio::test]
async fn create_manual_certificate_returns_metadata_without_key_material() {
    let (dir, server, _runtime) = server_with_runtime();
    let response = server
        .post("/api/v1/certificates/custom")
        .json(&manual_body(&[
            "manual.example.com",
            "www.manual.example.com",
        ]))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::CREATED,
        "{}",
        response.text()
    );
    assert_eq!(response.header("location"), "/api/v1/certificates/custom/1");
    let text = response.text();
    assert!(
        !text.contains("PRIVATE KEY"),
        "response leaked a private key"
    );
    assert!(
        !text.contains("BEGIN CERTIFICATE"),
        "response leaked PEM material"
    );
    let body: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(body["id"], 1);
    assert_eq!(body["origin"], "manual");
    assert_eq!(body["status"], "pending");
    assert_eq!(
        body["domains"],
        serde_json::json!(["manual.example.com", "www.manual.example.com"])
    );

    let state = std::fs::read_to_string(dir.path().join("data/pm/state.json")).expect("state");
    assert!(!state.contains("PRIVATE KEY"), "state leaked a private key");
    assert!(
        !state.contains("BEGIN CERTIFICATE"),
        "state leaked certificate bytes"
    );
    let secrets = dir.path().join("data/pm/secrets");
    let dir_meta = std::fs::metadata(&secrets).expect("secrets dir");
    let key_path = secrets.join("manual-1.key.pem");
    let key_meta = std::fs::metadata(&key_path).expect("key file");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
    assert_eq!(key_meta.permissions().mode() & 0o777, 0o600);
}

#[tokio::test]
async fn manual_certificate_rejects_a_mismatched_key_with_a_located_400() {
    let (_dir, server, _runtime) = server_with_runtime();
    let response = server
        .post("/api/v1/certificates/custom")
        .json(&serde_json::json!({
            "domains": ["manual.example.com"],
            "certificate": manual_fixture("manual-valid.crt.pem"),
            "privateKey": manual_fixture("manual-other.key.pem"),
        }))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::Validation);
    assert!(!body.error.message.contains("PRIVATE KEY"));
    let list: serde_json::Value = server.get("/api/v1/certificates").await.json();
    assert_eq!(list["total"], 0, "rejected material must not be persisted");
}

#[tokio::test]
async fn manual_certificate_lists_and_is_loaded_by_config() {
    let (_dir, server, runtime) = server_with_runtime();
    let response = server
        .post("/api/v1/certificates/custom")
        .json(&manual_body(&[
            "manual.example.com",
            "www.manual.example.com",
        ]))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::CREATED,
        "{}",
        response.text()
    );
    let etag = response.header("etag").to_str().expect("ascii").to_owned();

    let list: serde_json::Value = server.get("/api/v1/certificates").await.json();
    assert_eq!(list["total"], 1);
    assert_eq!(list["items"][0]["origin"], "manual");
    assert_eq!(list["items"][0]["status"], "pending");

    let detail = server.get("/api/v1/certificates/1").await;
    assert_eq!(detail.status_code(), StatusCode::OK);
    let detail_body: serde_json::Value = detail.json();
    assert_eq!(detail_body["origin"], "manual");
    let not_modified = server
        .get("/api/v1/certificates/custom/1")
        .add_header("If-None-Match", etag.as_str())
        .await;
    assert_eq!(not_modified.status_code(), StatusCode::NOT_MODIFIED);

    let host = server
        .post("/api/v1/hosts")
        .json(&serde_json::json!({
            "domains": ["manual.example.com"],
            "tls": {"mode": "manual", "certificateId": 1},
            "spec": {"kind": "dead"}
        }))
        .await;
    assert_eq!(host.status_code(), StatusCode::CREATED, "{}", host.text());

    let config: serde_json::Value = server.get("/api/v1/config").await.json();
    let load = &config["apps"]["tls"]["certificates"]["load_files"][0];
    assert_eq!(load["tags"], serde_json::json!(["pm-cert-1"]));
    assert!(load["certificate"]
        .as_str()
        .expect("cert path")
        .ends_with("manual-1.crt.pem"));
    assert!(load["key"]
        .as_str()
        .expect("key path")
        .ends_with("manual-1.key.pem"));
    let policies = config["apps"]["http"]["servers"]["pm_https"]["tls_connection_policies"]
        .as_array()
        .expect("policies");
    assert_eq!(
        policies[0]["certificate_selection"]["any_tag"],
        serde_json::json!(["pm-cert-1"])
    );
    assert_eq!(
        policies[0]["match"]["sni"],
        serde_json::json!(["manual.example.com", "www.manual.example.com"])
    );
    assert_eq!(policies.last(), Some(&serde_json::json!({})));

    let _ = runtime;
}

#[tokio::test]
async fn manual_certificate_delete_requires_if_match_and_refuses_a_referencing_host() {
    let (dir, server, _runtime) = server_with_runtime();
    let response = server
        .post("/api/v1/certificates/custom")
        .json(&manual_body(&["manual.example.com"]))
        .await;
    assert_eq!(
        response.status_code(),
        StatusCode::CREATED,
        "{}",
        response.text()
    );
    let etag = response.header("etag").to_str().expect("ascii").to_owned();

    let host = server
        .post("/api/v1/hosts")
        .json(&serde_json::json!({
            "domains": ["manual.example.com"],
            "tls": {"mode": "manual", "certificateId": 1},
            "spec": {"kind": "dead"}
        }))
        .await;
    assert_eq!(host.status_code(), StatusCode::CREATED, "{}", host.text());

    let missing = server.delete("/api/v1/certificates/custom/1").await;
    assert_eq!(missing.status_code(), StatusCode::PRECONDITION_FAILED);
    let referenced = server
        .delete("/api/v1/certificates/custom/1")
        .add_header("If-Match", etag.as_str())
        .await;
    assert_eq!(
        referenced.status_code(),
        StatusCode::CONFLICT,
        "{}",
        referenced.text()
    );

    // Remove the host, then delete for real.
    let host_etag = server
        .get("/api/v1/hosts/1")
        .await
        .header("etag")
        .to_str()
        .expect("host etag")
        .to_owned();
    let deleted_host = server
        .delete("/api/v1/hosts/1")
        .add_header("If-Match", host_etag.as_str())
        .await;
    assert_eq!(deleted_host.status_code(), StatusCode::NO_CONTENT);
    let deleted = server
        .delete("/api/v1/certificates/custom/1")
        .add_header("If-Match", etag.as_str())
        .await;
    assert_eq!(
        deleted.status_code(),
        StatusCode::NO_CONTENT,
        "{}",
        deleted.text()
    );
    assert!(!dir.path().join("data/pm/secrets/manual-1.key.pem").exists());
    assert_eq!(
        server.get("/api/v1/certificates/1").await.status_code(),
        StatusCode::NOT_FOUND
    );
}

// ---------------------------------------------------------------------------------------------
// Config apply
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct FakeAdmin {
    current: Arc<std::sync::Mutex<serde_json::Value>>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

impl FakeAdmin {
    fn fail(&self, fail: bool) {
        self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    fn current(&self) -> serde_json::Value {
        self.current.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl caddy_rs_pm_runtime::CaddyAdmin for FakeAdmin {
    type Error = caddy_rs_pm_runtime::AdminError;

    async fn load(
        &self,
        config: &serde_json::Value,
    ) -> Result<(), caddy_rs_pm_runtime::AdminError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(caddy_rs_pm_runtime::AdminError::Http(500));
        }
        *self.current.lock().unwrap() = config.clone();
        Ok(())
    }

    async fn current(&self) -> Result<serde_json::Value, caddy_rs_pm_runtime::AdminError> {
        Ok(self.current())
    }
}

fn server_with_apply() -> (TempDir, TestServer, FakeAdmin) {
    let temp_dir = TempDir::new().expect("create temp dir");
    let config = RuntimeConfig::new(temp_dir.path().join("data"));
    let runtime = PmRuntime::open(config).expect("open runtime");
    let admin = FakeAdmin::default();
    let applier = ConfigApplyService::new(
        runtime.clone(),
        Arc::new(admin.clone()),
        ConfigSettings::default(),
    );
    let app = create_router(ApiState::new(runtime).with_applier(applier))
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    (temp_dir, TestServer::new(app), admin)
}

#[tokio::test]
async fn apply_is_unavailable_without_a_pipeline() {
    let (_dir, state) = runtime();
    let app = create_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let server = TestServer::new(app);
    let response = server.post("/api/v1/config/apply").await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::ServiceUnavailable);
}

#[tokio::test]
async fn apply_loads_verifies_and_exposes_the_durable_revision() {
    let (_dir, server, admin) = server_with_apply();
    let expected = server
        .get("/api/v1/config")
        .await
        .json::<serde_json::Value>();

    let response = server.post("/api/v1/config/apply").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: ApplyResponse = response.json();
    assert_eq!(body.revision, 1);
    assert!(body.changed);
    assert_eq!(admin.current(), expected);

    let history = server.get("/api/v1/config/revisions").await;
    assert_eq!(history.status_code(), StatusCode::OK);
    let history: PaginatedResponse<ConfigRevision> = history.json();
    assert_eq!(history.total, 1);
    assert_eq!(history.items[0].status, ConfigApplyStatus::Applied);
    assert_eq!(history.items[0].hash, body.hash);
}

#[tokio::test]
async fn failed_apply_returns_503_and_records_a_failed_revision() {
    let (_dir, server, admin) = server_with_apply();
    server.post("/api/v1/config/apply").await.assert_status_ok();
    let before = admin.current();
    admin.fail(true);

    let response = server.post("/api/v1/config/apply").await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let body: ApiErrorResponse = response.json();
    assert_eq!(body.error.code, ErrorCode::ServiceUnavailable);
    assert_eq!(admin.current(), before, "previous config stays active");

    let history: PaginatedResponse<ConfigRevision> =
        server.get("/api/v1/config/revisions").await.json();
    assert_eq!(history.total, 2);
    assert_eq!(
        history.items.last().unwrap().status,
        ConfigApplyStatus::Failed
    );
}

#[tokio::test]
async fn failed_apply_leaves_the_uploaded_certificate_pending() {
    let (_dir, server, admin) = server_with_apply();
    let upload = server
        .post("/api/v1/certificates/custom")
        .json(&manual_body(&["manual.example.com"]))
        .await;
    assert_eq!(upload.status_code(), StatusCode::CREATED);
    admin.fail(true);

    let response = server.post("/api/v1/config/apply").await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);

    let detail = server.get("/api/v1/certificates/custom/1").await;
    assert_eq!(detail.status_code(), StatusCode::OK);
    let body: serde_json::Value = detail.json();
    assert_eq!(body["status"], "pending");
}

#[tokio::test]
async fn successful_apply_marks_the_uploaded_certificate_issued() {
    let (_dir, server, admin) = server_with_apply();
    let upload = server
        .post("/api/v1/certificates/custom")
        .json(&manual_body(&["manual.example.com"]))
        .await;
    assert_eq!(upload.status_code(), StatusCode::CREATED);

    let response = server.post("/api/v1/config/apply").await;
    assert_eq!(
        response.status_code(),
        StatusCode::OK,
        "{}",
        response.text()
    );
    let config = admin.current();
    assert_eq!(
        config["apps"]["tls"]["certificates"]["load_files"][0]["certificate"],
        serde_json::json!(_dir
            .path()
            .join("data/pm/secrets/manual-1.crt.pem")
            .display()
            .to_string())
    );

    let detail = server.get("/api/v1/certificates/custom/1").await;
    assert_eq!(detail.status_code(), StatusCode::OK);
    let body: serde_json::Value = detail.json();
    assert_eq!(body["status"], "issued");
}

// ---------------------------------------------------------------------------------------------
// UI serving
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn unknown_api_route_is_a_json_404_and_never_the_ui() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/definitely-not-a-route").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.header(header::CONTENT_TYPE),
        "application/json",
        "an API client that mistypes a route must not receive HTML"
    );
    let body: serde_json::Value = response.json();
    assert_eq!(body["error"]["code"], "NOT_FOUND");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("/api/v1/definitely-not-a-route")),
        "the error names the path that did not match"
    );
}

#[tokio::test]
async fn api_root_is_a_json_404_for_the_same_reason() {
    let (_dir, server) = server();
    let response = server.get("/api/v1").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    assert_eq!(response.header(header::CONTENT_TYPE), "application/json");
}

#[tokio::test]
async fn the_shell_is_served_at_root_with_the_security_headers() {
    if !crate::ui::EMBEDDED {
        // No bundle was built for this target: `not_built` answers instead and is covered by the
        // unit tests in `ui`. Nothing to assert about embedded assets here.
        return;
    }
    let (_dir, server) = server();
    let response = server.get("/").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.header(header::CONTENT_TYPE),
        "text/html; charset=utf-8"
    );
    assert_eq!(response.header(header::CACHE_CONTROL), "no-cache");
    assert_eq!(response.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    assert_eq!(response.header(header::REFERRER_POLICY), "no-referrer");
    assert!(
        response
            .header(header::CONTENT_SECURITY_POLICY)
            .to_str()
            .is_ok_and(|value| value.contains("default-src 'self'")),
        "the shell must carry the CSP"
    );
    assert!(
        response.text().contains("/assets/"),
        "the shell is the bundle's index.html"
    );
}

#[tokio::test]
async fn a_client_side_page_route_falls_back_to_the_shell() {
    if !crate::ui::EMBEDDED {
        return;
    }
    let (_dir, server) = server();
    let response = server.get("/hosts/7").await;
    assert_eq!(
        response.status_code(),
        StatusCode::OK,
        "a reload on a client-side route must not 404"
    );
    assert_eq!(
        response.header(header::CONTENT_TYPE),
        "text/html; charset=utf-8"
    );
}

#[tokio::test]
async fn a_missing_asset_is_a_real_404() {
    let (_dir, server) = server();
    let response = server.get("/assets/missing-BdEf0123.js").await;
    assert_eq!(
        response.status_code(),
        StatusCode::NOT_FOUND,
        "serving the shell for a missing .js file turns a broken deploy into a syntax error"
    );
}

#[tokio::test]
async fn an_embedded_asset_is_served_immutable() {
    if !crate::ui::EMBEDDED {
        return;
    }
    let Some((route, bytes, _)) = crate::ui::ASSETS
        .iter()
        .find(|(route, _, _)| route.starts_with("/assets/"))
    else {
        return;
    };
    let (_dir, server) = server();
    let response = server.get(route).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.header(header::CACHE_CONTROL),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(response.as_bytes().len(), bytes.len());
}

#[tokio::test]
async fn the_ui_answers_a_non_read_method_with_405() {
    if !crate::ui::EMBEDDED {
        return;
    }
    let (_dir, server) = server();
    let response = server.post("/").await;
    assert_eq!(response.status_code(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.header(header::ALLOW), "GET, HEAD");
}
