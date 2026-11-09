//! Native REST API skeleton for the caddy-rs proxy manager.
//!
//! This crate is the HTTP presentation layer only. It owns no state, no validation and no
//! persistence: every read goes through [`PmRuntime`], which composes the repositories and the
//! route compiler. Keeping the mapping in one thin module is what lets the native API and a later
//! `--compat npm` adapter share the same service layer instead of duplicating it.
//!
//! # Endpoints
//!
//! | Method | Path | Behaviour |
//! |---|---|---|
//! | `GET` | `/api/v1/health` | Liveness probe; always `200` while the process serves requests |
//! | `GET` | `/api/v1/setup` | Whether first-run setup has completed (no user store yet, so `false`) |
//! | `GET` | `/api/v1/version` | API version and the embedded caddy-rs version |
//! | `GET` | `/api/v1/hosts` | Read-only host summaries, paginated |
//! | `GET` | `/api/v1/config` | Assembled Caddy JSON with a weak `ETag`; supports conditional requests |
//!
//! # Preconditions
//!
//! The skeleton implements the precondition primitives that mutation routes (host create/update,
//! certificate intent) reuse, and exercises them on the two document endpoints:
//!
//! * `If-None-Match` matching the current `ETag` returns `304 Not Modified`;
//! * `If-Match` that does not match the current `ETag` returns `412 Precondition Failed`;
//! * `If-Match` matching returns the representation;
//! * `*` matches any current representation, and an absent header never fails.
//!
//! ETags are weak (`W/"<hash>"`) and derived from the response bytes, so they change exactly when
//! the representation changes. [`evaluate_get_preconditions`] is the single place that implements
//! the rules, so mutation routes cannot grow a second, subtly different copy.
//!
//! # Pagination
//!
//! List responses use [`PaginatedResponse`] and [`PaginationParams`]. An out-of-range `limit` is
//! clamped into `1..=MAX_LIMIT` and the effective window is echoed in the envelope, so a client
//! never has to guess what it actually received.
//!
//! # Scope
//!
//! No authentication or authorization: that belongs to `caddy-rs-authn` and is wired in a later
//! slice. No mutation routes yet (host CRUD is the next slice). Errors are typed and carry a
//! `location` when a field is at fault; no response body contains secret material.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    extract::{rejection::QueryRejection, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use caddy_rs_pm_config::ConfigSettings;
use caddy_rs_pm_runtime::PmRuntime;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

/// Default page size when the caller does not ask for one.
pub const DEFAULT_LIMIT: u32 = 50;
/// Upper bound on a page size; larger requests are clamped, never rejected.
pub const MAX_LIMIT: u32 = 200;

/// Shared state for every handler. Cloning is cheap: the runtime shares one store.
#[derive(Clone)]
pub struct ApiState {
    pub runtime: PmRuntime,
}

impl ApiState {
    pub fn new(runtime: PmRuntime) -> Self {
        Self { runtime }
    }
}

/// `?limit=&offset=` for list endpoints.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct PaginationParams {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_LIMIT,
            offset: 0,
        }
    }
}

fn default_limit() -> u32 {
    DEFAULT_LIMIT
}

impl PaginationParams {
    /// Clamp the page size into `1..=MAX_LIMIT`.
    ///
    /// Clamping rather than rejecting keeps a list endpoint from failing because a client asked for
    /// more than the server will serve; the effective values are echoed in the envelope.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            limit: self.limit.clamp(1, MAX_LIMIT),
            offset: self.offset,
        }
    }

    /// Apply the window to a full collection, returning the envelope.
    #[must_use]
    pub fn paginate<T: Clone>(self, all: &[T]) -> PaginatedResponse<T> {
        let params = self.clamped();
        let total = all.len() as u64;
        let start = (params.offset as usize).min(all.len());
        let end = start.saturating_add(params.limit as usize).min(all.len());
        PaginatedResponse {
            items: all[start..end].to_vec(),
            total,
            limit: params.limit,
            offset: params.offset,
        }
    }
}

/// List envelope: the page, the total before pagination, and the effective window.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

/// Stable machine-readable error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    NotFound,
    Conflict,
    PreconditionFailed,
    Validation,
    Internal,
}

/// A failed request. `location` names the offending field when there is one.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
    #[error("validation error: {message}")]
    Validation {
        message: String,
        location: Option<String>,
    },
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn validation(message: impl Into<String>, location: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
            location: Some(location.into()),
        }
    }

    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PreconditionFailed(_) => StatusCode::PRECONDITION_FAILED,
            Self::Validation { .. } => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::PreconditionFailed(_) => ErrorCode::PreconditionFailed,
            Self::Validation { .. } => ErrorCode::Validation,
            Self::Internal(_) => ErrorCode::Internal,
        }
    }

    #[must_use]
    pub fn location(&self) -> Option<&str> {
        match self {
            Self::Validation { location, .. } => location.as_deref(),
            _ => None,
        }
    }
}

/// Wire shape of an error: `{"error":{"code":..,"message":..,"location":..}}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ApiErrorResponse {
            error: ApiErrorDetail {
                code: self.error_code(),
                message: self.to_string(),
                location: self.location().map(ToOwned::to_owned),
            },
        };
        (status, Json(body)).into_response()
    }
}

impl From<caddy_rs_pm_runtime::RuntimeError> for ApiError {
    fn from(source: caddy_rs_pm_runtime::RuntimeError) -> Self {
        Self::Internal(source.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub setup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupResponse {
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionResponse {
    pub version: String,
    pub caddy_rs: String,
}

/// One host as listed by `GET /api/v1/hosts`.
///
/// Deliberately a summary: the full host document with TLS references is served by the detail route
/// in the CRUD slice, so a list response never grows with every host's TLS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSummary {
    pub id: u64,
    pub domains: Vec<String>,
    pub kind: String,
    pub enabled: bool,
    pub revision: u64,
    pub tls_mode: String,
}

// ---------------------------------------------------------------------------------------------
// Preconditions
// ---------------------------------------------------------------------------------------------

/// Format a representation hash as a weak ETag, the shape caddy-rs core uses for config.
#[must_use]
pub fn format_weak_etag(hash: &str) -> String {
    format!("W/\"{hash}\"")
}

/// Normalize one `If-Match`/`If-None-Match` member to its opaque value.
///
/// Accepts `W/"x"`, `"x"`, `x`, and `*`. A malformed member is kept verbatim so it simply fails to
/// match instead of being silently dropped.
fn normalize_etag_member(member: &str) -> &str {
    let member = member.trim();
    let member = member.strip_prefix("W/").unwrap_or(member);
    member.trim_matches('"')
}

/// Split a comma-separated ETag header into its members.
///
/// A header that is present but not valid UTF-8 is an error, not an absent header. Treating it as
/// absent would make an unparseable `If-Match` succeed, which is the fail-open case a precondition
/// must never have.
fn etag_members(
    headers: &HeaderMap,
    name: header::HeaderName,
) -> Result<Option<Vec<String>>, ApiError> {
    let Some(value) = headers.get(&name) else {
        return Ok(None);
    };
    let raw = value
        .to_str()
        .map_err(|_| ApiError::PreconditionFailed(format!("{name} is not a valid header value")))?;
    Ok(Some(
        raw.split(',')
            .map(|member| normalize_etag_member(member).to_owned())
            .collect(),
    ))
}

fn matches_any(members: &[String], current: &str) -> bool {
    members
        .iter()
        .any(|member| member == "*" || member == current)
}

/// Evaluate `If-Match`/`If-None-Match` for a `GET`.
///
/// Returns `Ok(Some(response))` when the request must be short-circuited (`304` or `412`),
/// `Ok(None)` when the representation should be served, and `Err` when a present header value
/// cannot be parsed (a present but unreadable `If-Match` must fail closed, not look absent).
/// `If-Match` is evaluated before `If-None-Match`, the order RFC 9110 requires.
pub fn evaluate_get_preconditions(
    headers: &HeaderMap,
    current_etag: &str,
) -> Result<Option<Response>, ApiError> {
    let current = normalize_etag_member(current_etag).to_owned();

    if let Some(members) = etag_members(headers, header::IF_MATCH)? {
        if !matches_any(&members, &current) {
            return Ok(Some(
                ApiError::PreconditionFailed(format!(
                    "If-Match does not match the current representation ({current_etag})"
                ))
                .into_response(),
            ));
        }
    }

    if let Some(members) = etag_members(headers, header::IF_NONE_MATCH)? {
        if matches_any(&members, &current) {
            return Ok(Some(not_modified(current_etag)));
        }
    }

    Ok(None)
}

/// Evaluate `If-Match` for an unsafe method that requires one.
///
/// A missing header is an error here, unlike on `GET`: mutating without an expected revision is
/// exactly the lost-update race the precondition exists to prevent.
pub fn require_if_match(headers: &HeaderMap, current_etag: &str) -> Result<(), ApiError> {
    let members = etag_members(headers, header::IF_MATCH)?.ok_or_else(|| {
        ApiError::PreconditionFailed(
            "If-Match is required for this request; fetch the resource and send its ETag"
                .to_owned(),
        )
    })?;
    let current = normalize_etag_member(current_etag).to_owned();
    if matches_any(&members, &current) {
        Ok(())
    } else {
        Err(ApiError::PreconditionFailed(format!(
            "If-Match does not match the current revision ({current_etag})"
        )))
    }
}

fn not_modified(current_etag: &str) -> Response {
    let mut response = StatusCode::NOT_MODIFIED.into_response();
    if let Ok(value) = HeaderValue::from_str(current_etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

// ---------------------------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------------------------

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Attach a process-local request id and log one completion line.
///
/// The id is a counter, not a UUID: it is diagnostic only, contains no client input, and cannot
/// fail to convert to a header value.
async fn observe_middleware(mut request: axum::extract::Request, next: Next) -> Response {
    let request_id = format!("req-{}", REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed));
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request
            .extensions_mut()
            .insert(RequestId(request_id.clone()));
        request.headers_mut().insert("x-request-id", value);
    }

    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = std::time::Instant::now();
    let mut response = next.run(request).await;
    let elapsed = started.elapsed();

    info!(
        %method,
        %path,
        status = response.status().as_u16(),
        elapsed_ms = elapsed.as_millis() as u64,
        request_id = %request_id,
        "pm api request"
    );

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

/// Request id carried in request extensions.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

// ---------------------------------------------------------------------------------------------
// Router and handlers
// ---------------------------------------------------------------------------------------------

/// Build the `/api/v1` router.
pub fn create_router(state: ApiState) -> Router {
    let api = Router::new()
        .route("/health", get(health_handler))
        .route("/setup", get(setup_handler))
        .route("/version", get(version_handler))
        .route("/hosts", get(hosts_handler))
        .route("/config", get(config_handler))
        .layer(middleware::from_fn(observe_middleware))
        .with_state(state);

    Router::new().nest("/api/v1", api)
}

async fn health_handler(State(_state): State<ApiState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        // Keep this consistent with `/setup`: no user store is wired, so the server is not
        // configured and a client must not skip the setup wizard.
        setup: false,
    })
}

async fn setup_handler(State(_state): State<ApiState>) -> Json<SetupResponse> {
    // No user store is wired yet (caddy-rs-authn lands in a later slice), so setup is never
    // complete. Reporting `true` here would let a client skip the setup wizard against a server
    // that has no administrator.
    Json(SetupResponse { configured: false })
}

async fn version_handler(State(_state): State<ApiState>) -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        caddy_rs: caddy_rs_core::VERSION.to_owned(),
    })
}

/// `GET /api/v1/hosts` — read-only host summaries.
async fn hosts_handler(
    State(state): State<ApiState>,
    query: Result<Query<PaginationParams>, QueryRejection>,
) -> Result<Json<PaginatedResponse<HostSummary>>, ApiError> {
    let Query(params) =
        query.map_err(|rejection| ApiError::validation(rejection.body_text(), "limit"))?;
    let stored = state
        .runtime
        .hosts()
        .list()
        .map_err(|error| ApiError::Internal(error.to_string()))?;
    let summaries: Vec<HostSummary> = stored
        .iter()
        .map(|stored| HostSummary {
            id: stored.host.id.0,
            domains: stored.host.domains.clone(),
            kind: host_kind(&stored.host.spec).to_owned(),
            enabled: stored.host.enabled,
            revision: stored.revision,
            tls_mode: tls_mode(&stored.host.tls),
        })
        .collect();
    Ok(Json(params.paginate(&summaries)))
}

fn host_kind(spec: &caddy_rs_pm_core::HostSpec) -> &'static str {
    match spec {
        caddy_rs_pm_core::HostSpec::Proxy(_) => "proxy",
        caddy_rs_pm_core::HostSpec::Redirect(_) => "redirect",
        caddy_rs_pm_core::HostSpec::Dead(_) => "dead",
    }
}

fn tls_mode(tls: &caddy_rs_pm_core::HostTls) -> String {
    use caddy_rs_pm_core::TlsMode;
    match tls.mode {
        TlsMode::Disabled => "disabled",
        TlsMode::Auto => "auto",
        TlsMode::Manual => "manual",
        TlsMode::AcmeConfigured => "acme_configured",
        TlsMode::InternalCa => "internal_ca",
    }
    .to_owned()
}

/// `GET /api/v1/config` — the assembled Caddy configuration with conditional-request support.
async fn config_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let config = state.runtime.assemble(ConfigSettings::default())?;
    let bytes = serde_json::to_vec(&config)
        .map_err(|error| ApiError::Internal(format!("serialize config: {error}")))?;
    let etag = format_weak_etag(&hash_bytes(&bytes));

    if let Some(response) = evaluate_get_preconditions(&headers, &etag)? {
        return Ok(response);
    }

    let mut response = Json(config).into_response();
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(response)
}

/// 64-bit FNV-1a over the response bytes.
///
/// An ETag only has to change when the representation changes; this is a change detector, not a
/// security primitive. caddy-rs core keeps xxhash64 for Caddy-compatible admin `ETag` parity, but
/// the PM API has no Caddy-side ETag to match, so a dependency-free hash avoids a new crate.
fn hash_bytes(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests;
