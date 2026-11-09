//! Integration tests for the PM API.
//!
//! The router is exercised through `axum-test`, so these tests go through the same middleware,
//! extractors and serialization the daemon uses. Assertions are on observable HTTP behaviour
//! (status, headers, body shape), not on private helpers alone.

use super::*;
use crate::dto::{HostResponse, HostSpecDto, HostTlsDto, HostWriteRequest};
use axum_test::TestServer;
use caddy_rs_pm_runtime::{PmRuntime, RuntimeConfig};
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
