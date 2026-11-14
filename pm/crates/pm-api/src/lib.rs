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
//! | `GET` | `/api/v1/setup` | Whether first-run setup has completed (at least one user exists) |
//! | `POST` | `/api/v1/auth/setup` | Create the first administrator; `201` once, then `409 Conflict` |
//! | `GET` | `/api/v1/users` | Paginated `PublicUser` list; requires the `users:view` capability |
//! | `PATCH` | `/api/v1/users/{id}` | Change a role; requires `users:update`; the new epoch invalidates old tokens |
//! | `DELETE` | `/api/v1/users/{id}` | Delete and revoke refresh tokens; requires `users:delete`; the last administrator is `409` |
//! | `GET` | `/api/v1/version` | API version and the embedded caddy-rs version |
//! | `GET` | `/api/v1/hosts` | Host summaries, paginated and filterable |
//! | `POST` | `/api/v1/hosts` | Create a host; `201` plus `Location` and a strong `ETag` |
//! | `GET` | `/api/v1/hosts/{id}` | Full host document; supports `If-None-Match` |
//! | `PUT` | `/api/v1/hosts/{id}` | Replace a host under a strong `If-Match` |
//! | `PATCH` | `/api/v1/hosts/{id}` | Partial update under a strong `If-Match` |
//! | `DELETE` | `/api/v1/hosts/{id}` | Delete under a strong `If-Match` |
//! | `POST` | `/api/v1/hosts/{id}/enable` | Set enabled under a strong `If-Match` |
//! | `POST` | `/api/v1/hosts/{id}/disable` | Set disabled under a strong `If-Match` |
//! | `GET` | `/api/v1/config` | Assembled Caddy JSON with a weak `ETag`; supports conditional requests |
//! | `POST` | `/api/v1/config/apply` | Apply the assembled config to the loopback caddy-rs admin API |
//! | `GET` | `/api/v1/config/revisions` | Durable apply history |
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
//! # Host revision preconditions
//!
//! Hosts use a strong `"h<id>-r<revision>"` ETag. Every mutation reads the host, requires a strong
//! `If-Match` matching that revision, then passes the same revision to the service as its CAS
//! expectation. Missing is `428`, stale/weak/unparseable is `412`, and a CAS conflict after the
//! read is `412`. There is no automatic retry.
//!
//! # Scope and exposure
//!
//! The user-administration routes authenticate with a `Authorization: Bearer <access token>`
//! header: a missing, malformed, expired or epoch-stale token is `401`, and a valid token without
//! the required `users` capability is `403` (an editor may list users, but not change a role or
//! delete one). The token is verified against the store on every request, so a role change or
//! revocation invalidates previously issued tokens through the authentication epoch.
//!
//! Every other mutation stays loopback-only until its management-auth slice lands: [`create_router`]
//! must be served with `into_make_service_with_connect_info::<SocketAddr>()`, and a missing or
//! non-loopback socket peer is `403`. Forwarding headers are never trusted. This is a fail-closed
//! boundary, not authentication, so the management port must not be published. Errors are typed and
//! carry a `location` when a field is at fault; no response body contains secret material.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::{
    extract::{connect_info::ConnectInfo, OriginalUri, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use caddy_rs_authn::{AuthnService, MemoryUserStore};
use caddy_rs_pm_config::ConfigSettings;
use caddy_rs_pm_runtime::{ConfigApplyService, PmRuntime};
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
    pub authn: AuthnService<MemoryUserStore>,
    inventory: Option<SharedCertificateInventory>,
    applier: Option<Arc<ConfigApplyService>>,
}

impl ApiState {
    /// State with no certificate inventory. Every intent is reported as `pending` until the
    /// daemon injects a source with [`ApiState::with_inventory`].
    pub fn new(runtime: PmRuntime, authn: AuthnService<MemoryUserStore>) -> Self {
        Self {
            runtime,
            authn,
            inventory: None,
            applier: None,
        }
    }

    /// Inject the certificate inventory the daemon reads from the caddy-rs admin endpoint.
    #[must_use]
    pub fn with_inventory(mut self, inventory: SharedCertificateInventory) -> Self {
        self.inventory = Some(inventory);
        self
    }

    /// The injected inventory, if any.
    pub fn inventory(&self) -> Option<&SharedCertificateInventory> {
        self.inventory.as_ref()
    }

    /// Inject the config apply pipeline. Without one, `/config/apply` is a typed `503`; merely
    /// running the API never changes the live caddy-rs config.
    #[must_use]
    pub fn with_applier(mut self, applier: ConfigApplyService) -> Self {
        self.applier = Some(Arc::new(applier));
        self
    }

    /// The injected apply pipeline, if any.
    pub fn applier(&self) -> Option<&Arc<ConfigApplyService>> {
        self.applier.as_ref()
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
    PreconditionRequired,
    Forbidden,
    Unauthorized,
    UnsupportedMediaType,
    Validation,
    ServiceUnavailable,
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
    #[error("precondition required: {0}")]
    PreconditionRequired(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),
    #[error("validation error: {message}")]
    Validation {
        message: String,
        location: Option<String>,
    },
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
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
            Self::PreconditionRequired(_) => StatusCode::PRECONDITION_REQUIRED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Validation { .. } => StatusCode::BAD_REQUEST,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::PreconditionFailed(_) => ErrorCode::PreconditionFailed,
            Self::PreconditionRequired(_) => ErrorCode::PreconditionRequired,
            Self::Forbidden(_) => ErrorCode::Forbidden,
            Self::Unauthorized(_) => ErrorCode::Unauthorized,
            Self::UnsupportedMediaType(_) => ErrorCode::UnsupportedMediaType,
            Self::Validation { .. } => ErrorCode::Validation,
            Self::ServiceUnavailable(_) => ErrorCode::ServiceUnavailable,
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
        let unauthorized = matches!(self, Self::Unauthorized(_));
        let body = ApiErrorResponse {
            error: ApiErrorDetail {
                code: self.error_code(),
                message: self.to_string(),
                location: self.location().map(ToOwned::to_owned),
            },
        };
        let mut response = (status, Json(body)).into_response();
        if unauthorized {
            // RFC 9110 requires a 401 to carry a challenge; the only scheme this API accepts is
            // Bearer, so the challenge is not configurable.
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

impl From<caddy_rs_pm_runtime::RuntimeError> for ApiError {
    fn from(source: caddy_rs_pm_runtime::RuntimeError) -> Self {
        use caddy_rs_pm_runtime::RuntimeError;
        match source {
            // A stored policy or host that no longer compiles is a state conflict, not a server
            // failure. The message names the offending policy/host; `GET /config` therefore
            // returns a typed 409 instead of an opaque 500.
            RuntimeError::Config { source, .. } => Self::Conflict(format!(
                "stored certificate policy cannot be assembled: {source}"
            )),
            RuntimeError::Compile { source, .. } => {
                Self::Conflict(format!("stored hosts cannot be compiled: {source}"))
            }
            other => Self::Internal(other.to_string()),
        }
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
pub(crate) fn normalize_etag_member(member: &str) -> &str {
    let member = member.trim();
    let member = member.strip_prefix("W/").unwrap_or(member);
    member.trim_matches('"')
}

/// Split a comma-separated ETag header into its members.
///
/// A header that is present but not valid UTF-8 is an error, not an absent header. Treating it as
/// absent would make an unparseable `If-Match` succeed, which is the fail-open case a precondition
/// must never have.
pub(crate) fn etag_members(
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

pub(crate) fn matches_any(members: &[String], current: &str) -> bool {
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

/// Peer address captured before routing.
///
/// The API does not trust forwarding headers: only the socket peer counts. `None` means the server
/// was mounted without `into_make_service_with_connect_info`, which is treated as remote.
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub Option<SocketAddr>);

async fn capture_peer_middleware(mut request: axum::extract::Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0);
    request.extensions_mut().insert(PeerAddr(peer));
    next.run(request).await
}

/// Mutations are local-only until the management authentication slice is wired.
///
/// A loopback socket is not authentication, but it is a fail-closed boundary: the management port
/// must not be published, and a future auth layer replaces this guard rather than relaxing it.
pub(crate) fn require_local_peer(peer: PeerAddr) -> Result<(), ApiError> {
    match peer.0 {
        Some(address) if address.ip().is_loopback() => Ok(()),
        Some(address) => Err(ApiError::Forbidden(format!(
            "management mutations are local-only; peer {address} is not loopback"
        ))),
        None => Err(ApiError::Forbidden(
            "management mutations require a known socket peer; serve the router with connect info"
                .to_owned(),
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// Router and handlers
// ---------------------------------------------------------------------------------------------

/// Build the `/api/v1` router.
pub fn create_router(state: ApiState) -> Router {
    let api = Router::new()
        .route("/health", get(health_handler))
        .route("/setup", get(setup_handler))
        .route("/auth/setup", post(auth_setup_handler))
        .route("/users", get(users::list_handler))
        .route(
            "/users/{id}",
            axum::routing::patch(users::update_role_handler).delete(users::delete_handler),
        )
        .route("/version", get(version_handler))
        .route(
            "/hosts",
            get(hosts::list_handler).post(hosts::create_handler),
        )
        .route(
            "/hosts/{id}",
            get(hosts::get_handler)
                .put(hosts::replace_handler)
                .patch(hosts::patch_handler)
                .delete(hosts::delete_handler),
        )
        .route("/hosts/{id}/enable", post(hosts::enable_handler))
        .route("/hosts/{id}/disable", post(hosts::disable_handler))
        .route("/certificates", get(certificates::list_handler))
        .route("/certificates/intent", post(certificates::create_handler))
        .route(
            "/certificates/intent/{id}",
            get(certificates::get_intent_handler),
        )
        .route(
            "/certificates/custom",
            post(certificates::create_custom_handler),
        )
        .route(
            "/certificates/custom/{id}",
            get(certificates::get_custom_handler).delete(certificates::delete_custom_handler),
        )
        .route("/certificates/{id}", get(certificates::get_handler))
        .route(
            "/security-headers",
            get(security_headers::get_global_handler).put(security_headers::put_global_handler),
        )
        // Documentation for every option above, served from the same registry the UI page renders.
        .route(
            "/security-headers/docs",
            get(security_headers_docs::docs_handler),
        )
        .route(
            "/hosts/{id}/security-headers",
            get(security_headers::get_host_handler).put(security_headers::put_host_handler),
        )
        .route("/config", get(config_handler))
        .route("/config/apply", post(apply::apply_handler))
        .route("/config/revisions", get(apply::revisions_handler))
        // The router fallback is the UI (`ui::serve_ui`), which answers unknown paths with the
        // single-page shell. An API client must never receive HTML, so the nested API router claims
        // its own fallback and keeps the typed JSON error contract for a mistyped route.
        .fallback(api_not_found)
        .layer(middleware::from_fn(observe_middleware))
        .layer(middleware::from_fn(capture_peer_middleware))
        .with_state(state);

    Router::new()
        .nest("/api/v1", api)
        // The security-headers documentation is rendered from the same registry as
        // `/api/v1/security-headers/docs`, so the page operators read and the JSON their tooling
        // reads cannot drift. It is linked from the API payload and served on the UI origin.
        .route(
            "/security-headers/docs",
            get(security_headers_docs::docs_page_handler),
        )
        // The web UI is served from the same origin as the API so the browser never needs CORS or
        // a second port. It is embedded at build time (see `build.rs`); without a built bundle the
        // fallback answers with an explanatory page instead of a 404.
        .fallback(ui::serve_ui)
}

/// Unknown `/api/v1` route: a located JSON `404`, never the UI shell.
///
/// `OriginalUri` is the path the client asked for: inside a nested router the request URI has the
/// `/api/v1` prefix stripped, and an error that named the stripped path would send a client looking
/// for a route it never requested.
async fn api_not_found(OriginalUri(uri): OriginalUri) -> ApiError {
    ApiError::NotFound(format!("no route matches {}", uri.path()))
}

/// True when at least one user exists, i.e. first-run setup has completed.
///
/// A store error is reported as "not configured" on purpose: this is only the setup-wizard hint,
/// and reporting `true` on a read failure would let a client skip the wizard against a server
/// whose user store cannot be read.
async fn setup_complete(state: &ApiState) -> bool {
    state
        .authn
        .list_users()
        .await
        .map(|users| !users.is_empty())
        .unwrap_or(false)
}

async fn health_handler(State(state): State<ApiState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        setup: setup_complete(&state).await,
    })
}

async fn setup_handler(State(state): State<ApiState>) -> Json<SetupResponse> {
    Json(SetupResponse {
        configured: setup_complete(&state).await,
    })
}

/// Request body for `POST /api/v1/auth/setup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
}

/// Response body for `POST /api/v1/auth/setup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserResponse {
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
}

/// `POST /api/v1/auth/setup` — first-run administrator creation.
///
/// Succeeds with `201 Created` exactly once. Every later attempt is `409 Conflict` with the
/// standard [`ApiError`] body (`{"error":{"code":"CONFLICT","message":...}}`): the store-level
/// compare-and-set in [`caddy_rs_authn::MemoryUserStore::create_first_admin`] is what makes
/// concurrent callers collapse to a single winner. The route stays loopback-only: it runs before
/// any administrator exists, so it cannot require a token.
async fn auth_setup_handler(
    State(state): State<ApiState>,
    _peer: hosts::LocalPeer,
    Json(request): Json<SetupRequest>,
) -> Result<(StatusCode, Json<CreateUserResponse>), ApiError> {
    let (user, token_pair) = state
        .authn
        .create_first_admin(&request.username, &request.password)
        .await
        .map_err(|error| match error {
            caddy_rs_authn::AuthError::UsernameExists => {
                ApiError::Conflict("first-run setup is already complete".to_owned())
            }
            other => ApiError::Internal(other.to_string()),
        })?;

    Ok((
        StatusCode::CREATED,
        Json(CreateUserResponse {
            user_id: user.id.0.to_string(),
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
        }),
    ))
}

async fn version_handler(State(_state): State<ApiState>) -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        caddy_rs: caddy_rs_core::VERSION.to_owned(),
    })
}

pub(crate) fn host_kind(spec: &caddy_rs_pm_core::HostSpec) -> &'static str {
    match spec {
        caddy_rs_pm_core::HostSpec::Proxy(_) => "proxy",
        caddy_rs_pm_core::HostSpec::Redirect(_) => "redirect",
        caddy_rs_pm_core::HostSpec::Dead(_) => "dead",
    }
}

pub(crate) fn tls_mode(tls: &caddy_rs_pm_core::HostTls) -> String {
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

mod apply;
mod certificates;
mod dto;
mod hosts;
mod security_headers;
mod security_headers_docs;
mod ui;
mod users;

pub use apply::ApplyResponse;
pub use certificates::{
    derive_intent_status, CertificateIntentRequest, CertificateIntentStatus,
    CertificateIntentSummary, CertificateInventorySource, CertificateRecord, CertificateSummary,
    CustomCertificateRequest, EmptyCertificateInventory, InventoryError, ManualCertificateSummary,
    SharedCertificateInventory, EXPIRING_SOON_SECONDS,
};
pub use security_headers::{SecurityHeadersDto, SecurityHeadersHstsDto};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_security_headers_docs;
