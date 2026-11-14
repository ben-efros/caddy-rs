//! User administration: list, change a role and delete.
//!
//! Every route requires a bearer access token with a capability in [`Section::Users`]; the token is
//! verified against the store on every request, so a role change or a revocation invalidates the
//! caller's previous tokens through the authentication epoch. Responses are [`PublicUser`] views
//! only: a password hash or TOTP secret never leaves this module.
//!
//! The last-administrator invariant is enforced for deletes: the read and the delete are serialized
//! through [`ADMIN_MUTATION_LOCK`], so two concurrent deletes cannot both observe another
//! administrator and remove the last two. Role changes are not locked; demoting the last
//! administrator through `PATCH` is not refused in this slice (see `pm/README.md`).

use std::collections::HashMap;

use axum::{
    extract::{
        rejection::{JsonRejection, PathRejection, QueryRejection},
        Path, Query, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use caddy_rs_authn::{Action, AuthError, Claims, PublicUser, Role, Section, UserId};
use serde::{Deserialize, Serialize};

use crate::{hosts::LocalPeer, ApiError, ApiState, PaginatedResponse, PaginationParams};

/// Serializes the check-then-delete pair that protects the last administrator.
///
/// The store has no compare-and-set for "delete only if another administrator exists", so the
/// invariant is kept by making the read and the delete mutually exclusive inside this process. The
/// API is served by one process, which is the same boundary the loopback guard relies on.
static ADMIN_MUTATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `GET /api/v1/users` — paginated [`PublicUser`] list, sorted by username.
pub async fn list_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<Json<PaginatedResponse<PublicUser>>, ApiError> {
    require_capability(&state, &headers, Section::Users, Action::View).await?;

    let page = parse_page(query)?;
    let mut users = state
        .authn
        .list_users()
        .await
        .map_err(|error| ApiError::Internal(error.to_string()))?;
    users.sort_by(|left, right| left.username.cmp(&right.username));
    let total = users.len() as u64;
    let items = users
        .into_iter()
        .skip(page.offset as usize)
        .take(page.limit as usize)
        .map(|user| user.public())
        .collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit: page.limit,
        offset: page.offset,
    }))
}

/// Request body for `PATCH /api/v1/users/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateUserRoleRequest {
    /// Role name: `admin`, `editor` or `viewer`.
    pub role: String,
}

/// `PATCH /api/v1/users/{id}` — change a user's role.
///
/// Changing the role increments the user's authentication epoch, so every access token issued
/// before the change is rejected. Refresh tokens are not revoked by a role change: refreshing mints
/// a pair carrying the user's current role and epoch, which is why the README states the effect on
/// access tokens only.
pub async fn update_role_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<UpdateUserRoleRequest>, JsonRejection>,
) -> Result<Json<PublicUser>, ApiError> {
    require_capability(&state, &headers, Section::Users, Action::Update).await?;

    let id = parse_path_id(path)?;
    let request = parse_json(body)?;
    let user_id = parse_user_id(&id)?;
    let role = parse_role(&request.role)?;
    let user = state
        .authn
        .update_role(user_id, role)
        .await
        .map_err(|error| match error {
            AuthError::UserNotFound => ApiError::NotFound(format!("user {id}")),
            other => ApiError::Internal(other.to_string()),
        })?;

    Ok(Json(user.public()))
}

/// `DELETE /api/v1/users/{id}` — delete a user and revoke their refresh tokens.
///
/// The last remaining administrator is refused with `409 Conflict`; deleting any other user
/// succeeds with `204 No Content` and no longer accepts that user's refresh tokens.
pub async fn delete_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
) -> Result<impl IntoResponse, ApiError> {
    require_capability(&state, &headers, Section::Users, Action::Delete).await?;

    let id = parse_path_id(path)?;
    let user_id = parse_user_id(&id)?;
    let _guard = ADMIN_MUTATION_LOCK.lock().await;

    let users = state
        .authn
        .list_users()
        .await
        .map_err(|error| ApiError::Internal(error.to_string()))?;
    let target = users
        .iter()
        .find(|user| user.id == user_id)
        .ok_or_else(|| ApiError::NotFound(format!("user {id}")))?;
    let administrators = users
        .iter()
        .filter(|user| user.role.name == "admin")
        .count();
    if target.role.name == "admin" && administrators <= 1 {
        return Err(ApiError::Conflict(
            "refusing to delete the last administrator".to_owned(),
        ));
    }

    state
        .authn
        .delete_user(user_id)
        .await
        .map_err(|error| match error {
            AuthError::UserNotFound => ApiError::NotFound(format!("user {id}")),
            other => ApiError::Internal(other.to_string()),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Parse `?limit=&offset=` into a clamped page, keeping the typed error envelope.
///
/// The query is parsed by hand instead of through `Query<PaginationParams>` so a malformed or
/// unknown parameter is a located `ApiError::Validation` rather than axum's plain-text rejection.
fn parse_page(
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<PaginationParams, ApiError> {
    let Query(query) = query.map_err(|rejection| {
        ApiError::validation(format!("invalid query: {}", rejection.body_text()), "query")
    })?;
    let mut page = PaginationParams::default();
    for (key, value) in query {
        match key.as_str() {
            "limit" => {
                page.limit = value.parse::<u32>().map_err(|_| {
                    ApiError::validation("limit must be a non-negative integer", "limit")
                })?;
            }
            "offset" => {
                page.offset = value.parse::<u32>().map_err(|_| {
                    ApiError::validation("offset must be a non-negative integer", "offset")
                })?;
            }
            other => {
                return Err(ApiError::validation(
                    format!("unknown query parameter `{other}`"),
                    "query",
                ))
            }
        }
    }
    Ok(page.clamped())
}

/// Unwrap a path parameter, mapping axum's rejection into the standard envelope.
fn parse_path_id(path: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    let Path(value) = path.map_err(|rejection| {
        ApiError::validation(format!("invalid user id: {}", rejection.body_text()), "id")
    })?;
    Ok(value)
}

/// Unwrap a JSON body, mapping axum's rejection into the standard envelope.
///
/// A wrong `Content-Type` is `415 UnsupportedMediaType`; a malformed, wrong-typed or
/// unknown-field body is a located `400 Validation` at `body`, matching the other resources.
fn parse_json<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    match body {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE => Err(
            ApiError::UnsupportedMediaType("expected application/json".to_owned()),
        ),
        Err(rejection) => Err(ApiError::validation(rejection.body_text(), "body")),
    }
}

/// Parse a path user id, reporting an invalid UUID as a located validation error.
fn parse_user_id(value: &str) -> Result<UserId, ApiError> {
    value
        .parse::<UserId>()
        .map_err(|_| ApiError::validation("id must be a UUID", "id"))
}

/// Parse the documented role names; custom roles are not assignable through this endpoint.
fn parse_role(name: &str) -> Result<Role, ApiError> {
    match name {
        "admin" => Ok(Role::admin()),
        "editor" => Ok(Role::editor()),
        "viewer" => Ok(Role::viewer()),
        other => Err(ApiError::validation(
            format!("unknown role `{other}`; expected admin, editor or viewer"),
            "role",
        )),
    }
}

/// Extract the bearer token, verify it and require `action` in `section`.
///
/// The error split is deliberate: a missing, malformed, expired or epoch-stale token is `401` (the
/// caller is not authenticated), while a valid token that lacks the capability is `403` (the
/// caller is authenticated but not allowed).
async fn require_capability(
    state: &ApiState,
    headers: &HeaderMap,
    section: Section,
    action: Action,
) -> Result<Claims, ApiError> {
    let token = bearer_token(headers)?;
    let claims = state
        .authn
        .verify_access_token(token)
        .await
        .map_err(|error| match error {
            AuthError::TokenExpired => ApiError::Unauthorized("access token expired".to_owned()),
            AuthError::InvalidToken | AuthError::InvalidSignature | AuthError::UserNotFound => {
                ApiError::Unauthorized("invalid access token".to_owned())
            }
            // A store failure is not the caller's fault; reporting it as 401 would tell an
            // operator to re-authenticate instead of fixing the store.
            other => ApiError::Internal(other.to_string()),
        })?;

    if !claims.has_capability(section, action) {
        return Err(ApiError::Forbidden(format!(
            "the {} capability is required on {}",
            action_name(action),
            section_name(section)
        )));
    }
    Ok(claims)
}

/// The `Authorization: Bearer <token>` value, with the scheme matched case-insensitively.
fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ApiError::Unauthorized("a bearer access token is required".to_owned()))?;
    let text = value
        .to_str()
        .map_err(|_| ApiError::Unauthorized("the Authorization header is not valid".to_owned()))?;
    let (scheme, token) = text.split_once(' ').ok_or_else(|| {
        ApiError::Unauthorized("the Authorization header is not valid".to_owned())
    })?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(ApiError::Unauthorized(
            "the Authorization header must use the Bearer scheme".to_owned(),
        ));
    }
    Ok(token)
}

/// Stable snake_case name for a section, used in `403` messages.
fn section_name(section: Section) -> &'static str {
    match section {
        Section::Hosts => "hosts",
        Section::Certificates => "certificates",
        Section::AccessLists => "access_lists",
        Section::Users => "users",
        Section::Logs => "logs",
        Section::Settings => "settings",
    }
}

/// Stable lowercase name for an action, used in `403` messages.
fn action_name(action: Action) -> &'static str {
    match action {
        Action::View => "view",
        Action::Create => "create",
        Action::Update => "update",
        Action::Delete => "delete",
        Action::Manage => "manage",
        Action::Admin => "admin",
    }
}
