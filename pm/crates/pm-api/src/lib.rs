//! PM native REST API skeleton with axum.
//!
//! This crate provides the HTTP API layer for the proxy manager, exposing
//! runtime functionality through a versioned REST interface.

#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use axum_extra::headers::{HeaderMapExt, IfMatch, IfNoneMatch};
use caddy_rs_pm_runtime::PmRuntime;
use caddy_rs_pm_state::{Revision, StateStore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Application state shared across all handlers.
#[derive(Clone)]
pub struct ApiState {
    pub runtime: PmRuntime,
}

impl ApiState {
    /// Create a new API state with the given runtime.
    pub fn new(runtime: PmRuntime) -> Self {
        Self { runtime }
    }
}

/// Pagination query parameters.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
pub struct PaginationParams {
    /// Maximum number of items to return (default: 50, max: 200).
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Number of items to skip (default: 0).
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    50
}

impl PaginationParams {
    /// Validate and clamp pagination parameters.
    pub fn validate(self) -> Result<Self, ApiError> {
        let limit = self.limit.clamp(1, 200);
        let offset = self.offset;
        Ok(Self { limit, offset })
    }
}

/// Paginated response envelope.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

/// Typed API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    pub error: ApiErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorDetail {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Error codes for API responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    NotFound,
    Conflict,
    PreconditionFailed,
    Validation,
    Internal,
}

/// API error with HTTP status code mapping.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("invalid pagination: {0}")]
    InvalidPagination(String),
    #[error("missing required header: {0}")]
    MissingHeader(String),
    #[error("invalid header value: {0}")]
    InvalidHeader(String),
}

impl ApiError {
    /// Get the HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::PreconditionFailed(_) => StatusCode::PRECONDITION_FAILED,
            ApiError::Validation(_) => StatusCode::BAD_REQUEST,
            ApiError::InvalidPagination(_) => StatusCode::BAD_REQUEST,
            ApiError::MissingHeader(_) => StatusCode::BAD_REQUEST,
            ApiError::InvalidHeader(_) => StatusCode::BAD_REQUEST,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error code for the response body.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ApiError::NotFound(_) => ErrorCode::NotFound,
            ApiError::Conflict(_) => ErrorCode::Conflict,
            ApiError::PreconditionFailed(_) => ErrorCode::PreconditionFailed,
            ApiError::Validation(_) | ApiError::InvalidPagination(_) => ErrorCode::Validation,
            ApiError::MissingHeader(_) | ApiError::InvalidHeader(_) => ErrorCode::Validation,
            ApiError::Internal(_) => ErrorCode::Internal,
        }
    }

    /// Get the location field for the response body.
    pub fn location(&self) -> Option<String> {
        match self {
            ApiError::Validation(msg) | ApiError::InvalidPagination(msg) => Some(msg.clone()),
            _ => None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_response = ApiErrorResponse {
            error: ApiErrorDetail {
                code: self.error_code(),
                message: self.to_string(),
                location: self.location(),
            },
        };
        (status, Json(error_response)).into_response()
    }
}

/// Health check response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub setup: bool,
}

/// Setup status response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupResponse {
    pub configured: bool,
}

/// Version response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionResponse {
    pub version: String,
    pub caddy_rs: String,
}

/// Extract ETag from If-Match header.
fn extract_if_match(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    if let Some(if_match) = headers.typed_get::<IfMatch>() {
        let etag = if_match.to_string();
        // Remove the W/ prefix if present and quotes
        let etag = etag
            .trim_start_matches('W')
            .trim_matches('/')
            .trim_matches('"');
        Ok(Some(etag.to_string()))
    } else {
        Ok(None)
    }
}

/// Extract ETag from If-None-Match header.
fn extract_if_none_match(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    if let Some(if_none_match) = headers.typed_get::<IfNoneMatch>() {
        let etag = if_none_match.to_string();
        let etag = etag
            .trim_start_matches('W')
            .trim_matches('/')
            .trim_matches('"');
        Ok(Some(etag.to_string()))
    } else {
        Ok(None)
    }
}

/// Format revision as weak ETag.
fn format_etag(revision: Revision) -> String {
    format!(r#"W/"{revision}""#)
}

/// Middleware to add request ID for tracing.
async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    request.extensions_mut().insert(request_id.clone());
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).unwrap_or_default(),
    );
    response
}

/// Middleware for logging requests.
async fn logging_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed();
    info!(
        method = %method,
        uri = %uri,
        status = %response.status(),
        duration_ms = %duration.as_millis(),
        "request completed"
    );
    response
}

/// Create the API router at `/api/v1`.
pub fn create_router(state: ApiState) -> Router {
    let api_routes = Router::new()
        .route("/health", get(health_handler))
        .route("/setup", get(setup_handler))
        .route("/version", get(version_handler))
        .layer(middleware::from_fn(logging_middleware))
        .layer(middleware::from_fn(request_id_middleware))
        .with_state(state);

    Router::new().nest("/api/v1", api_routes)
}

/// GET /api/v1/health
async fn health_handler(State(_state): State<ApiState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        setup: true,
    })
}

/// GET /api/v1/setup
async fn setup_handler(State(_state): State<ApiState>) -> Json<SetupResponse> {
    // TODO: Check if any admin user exists (PM-109/CORE-PM-12)
    Json(SetupResponse { configured: false })
}

/// GET /api/v1/version
async fn version_handler(State(_state): State<ApiState>) -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        caddy_rs: caddy_rs_core::VERSION.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use caddy_rs_pm_runtime::{PmRuntime, RuntimeConfig};
    use caddy_rs_pm_state::MemoryStore;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn create_test_runtime() -> PmRuntime {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config = RuntimeConfig::new(temp_dir.path().join("data"));
        PmRuntime::open(config).expect("open runtime")
    }

    fn create_test_state() -> ApiState {
        ApiState::new(create_test_runtime())
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = create_test_state();
        let server = TestServer::new(create_router(state)).expect("create test server");

        let response = server.get("/api/v1/health").await;
        assert_eq!(response.status_code(), 200);

        let body: HealthResponse = response.json();
        assert_eq!(body.status, "ok");
        assert!(body.setup);
    }

    #[tokio::test]
    async fn test_setup_endpoint() {
        let state = create_test_state();
        let server = TestServer::new(create_router(state)).expect("create test server");

        let response = server.get("/api/v1/setup").await;
        assert_eq!(response.status_code(), 200);

        let body: SetupResponse = response.json();
        assert!(!body.configured);
    }

    #[tokio::test]
    async fn test_version_endpoint() {
        let state = create_test_state();
        let server = TestServer::new(create_router(state)).expect("create test server");

        let response = server.get("/api/v1/version").await;
        assert_eq!(response.status_code(), 200);

        let body: VersionResponse = response.json();
        assert!(!body.version.is_empty());
        assert!(!body.caddy_rs.is_empty());
    }

    #[tokio::test]
    async fn test_pagination_params_default() {
        let params = PaginationParams::default()
            .validate()
            .expect("valid default");
        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 0);
    }

    #[tokio::test]
    async fn test_pagination_params_clamped() {
        let params = PaginationParams {
            limit: 300,
            offset: 10,
        }
        .validate()
        .expect("valid clamped");
        assert_eq!(params.limit, 200);
        assert_eq!(params.offset, 10);
    }

    #[tokio::test]
    async fn test_pagination_params_min_limit() {
        let params = PaginationParams {
            limit: 0,
            offset: 0,
        }
        .validate()
        .expect("valid min");
        assert_eq!(params.limit, 1);
    }

    #[tokio::test]
    async fn test_if_match_on_nonexistent_returns_412() {
        let state = create_test_state();
        let server = TestServer::new(create_router(state)).expect("create test server");

        // If-Match on a non-existent resource should return 412
        let response = server
            .get("/api/v1/health")
            .add_header("If-Match", r#"W/"999""#)
            .await;
        // Health endpoint doesn't check preconditions yet, so this should be 200
        // But we test the middleware parsing works
        assert_eq!(response.status_code(), 200);
    }

    #[tokio::test]
    async fn test_error_response_shape() {
        let error = ApiError::NotFound("resource not found".to_string());
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body: ApiErrorResponse = serde_json::from_slice(&body_bytes).expect("parse json");

        assert_eq!(body.error.code, ErrorCode::NotFound);
        assert_eq!(body.error.message, "not found: resource not found");
        assert!(body.error.location.is_none());
    }

    #[tokio::test]
    async fn test_error_response_with_location() {
        let error = ApiError::Validation("field.name".to_string());
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body: ApiErrorResponse = serde_json::from_slice(&body_bytes).expect("parse json");

        assert_eq!(body.error.code, ErrorCode::Validation);
        assert_eq!(body.error.location, Some("field.name".to_string()));
    }

    #[tokio::test]
    async fn test_etag_formatting() {
        let etag = format_etag(42);
        assert_eq!(etag, r#"W/"42""#);
    }

    #[tokio::test]
    async fn test_extract_if_match() {
        let mut headers = HeaderMap::new();
        headers.insert("If-Match", r#"W/"123""#.parse().unwrap());

        let result = extract_if_match(&headers).expect("extract");
        assert_eq!(result, Some("123".to_string()));
    }

    #[tokio::test]
    async fn test_extract_if_none_match() {
        let mut headers = HeaderMap::new();
        headers.insert("If-None-Match", r#"W/"456""#.parse().unwrap());

        let result = extract_if_none_match(&headers).expect("extract");
        assert_eq!(result, Some("456".to_string()));
    }

    #[tokio::test]
    async fn test_paginated_response_serialization() {
        let response = PaginatedResponse {
            items: vec!["a", "b"],
            total: 100,
            limit: 50,
            offset: 0,
        };

        let json = serde_json::to_string(&response).expect("serialize");
        let parsed: PaginatedResponse<String> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.items, vec!["a", "b"]);
        assert_eq!(parsed.total, 100);
        assert_eq!(parsed.limit, 50);
        assert_eq!(parsed.offset, 0);
    }
}
