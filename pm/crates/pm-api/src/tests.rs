//! Integration tests for the PM API.
//!
//! The router is exercised through `axum-test`, so these tests go through the same middleware,
//! extractors and serialization the daemon uses. Assertions are on observable HTTP behaviour
//! (status, headers, body shape), not on private helpers alone.

use super::*;
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
    assert!(body.setup);
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
async fn hosts_rejects_a_non_numeric_limit() {
    let (_dir, server) = server();
    let response = server.get("/api/v1/hosts?limit=abc").await;
    // Axum's query extractor rejects this before the handler; that is a 400, not a 500.
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
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
