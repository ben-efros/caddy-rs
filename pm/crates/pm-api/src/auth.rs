//! Session endpoints: login, refresh, logout and the current-user view.
//!
//! The access token is a short-lived JWT carried as a bearer token; the refresh token is opaque
//! and rotates on every use. Field names are snake_case to match the embedded UI client
//! (`pm/ui/src/api.ts`); `camelCase` aliases on the request side keep hand-written clients working.
//!
//! Failure messages never distinguish an unknown username from a wrong password. A TOTP-specific
//! message is only reachable after the password matched, so it does not become an account oracle.
//! Login failures are rate limited per username: five failures inside a minute answer `429` with
//! `Retry-After`, which also bounds online TOTP guessing (every TOTP failure is a login failure).
//!
//! Every handler takes [`LocalPeer`] first, like the rest of the management API: a non-loopback
//! peer is refused before the body is parsed. `Cache-Control: no-store` keeps token pairs and the
//! current-user view out of browser and intermediary caches.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use caddy_rs_authn::{AuthError, Claims, TokenPair};
use serde::{Deserialize, Serialize};

use crate::{hosts::LocalPeer, users::require_claims, ApiError, ApiState};

/// Failed logins allowed per username inside [`LOGIN_FAILURE_WINDOW`] before `429`.
const MAX_LOGIN_FAILURES: usize = 5;
/// Sliding window over which failed logins are counted.
const LOGIN_FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// Hard cap on tracked usernames; beyond it expired entries are swept, so a caller cannot grow the
/// map for free by inventing usernames.
const MAX_TRACKED_USERNAMES: usize = 10_000;

/// Per-username sliding-window limiter for failed logins.
///
/// Process-local and reset on restart on purpose: the threat is online guessing against a running
/// daemon, and a restart also discards the in-memory user store.
#[derive(Debug, Default)]
pub(crate) struct LoginLimiter {
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

impl LoginLimiter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Reserve one attempt for `username`, or report how long to wait when the window is full.
    ///
    /// Reserving under the same lock as the budget check is what makes the limit hold under
    /// concurrency: concurrent callers cannot all observe `len < MAX` and then each burn a verify.
    /// A reserved attempt is the count itself, so the caller must not record a second failure.
    fn reserve_attempt(&self, username: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if failures.len() > MAX_TRACKED_USERNAMES {
            failures.retain(|_, entries| {
                entries.retain(|at| now.duration_since(*at) < LOGIN_FAILURE_WINDOW);
                !entries.is_empty()
            });
        }
        let entries = failures.entry(normalize(username)).or_default();
        entries.retain(|at| now.duration_since(*at) < LOGIN_FAILURE_WINDOW);
        if entries.len() >= MAX_LOGIN_FAILURES {
            let oldest = entries.first().copied().unwrap_or(now);
            let wait = LOGIN_FAILURE_WINDOW.saturating_sub(now.duration_since(oldest));
            return Err(wait.as_secs().max(1));
        }
        entries.push(now);
        Ok(())
    }

    /// A successful login ends the streak; the budget starts clean for the next session.
    fn clear(&self, username: &str) {
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        failures.remove(&normalize(username));
    }
}

/// Usernames are matched case-sensitively by the store, but a limiter keyed case-insensitively
/// cannot be dodged by changing the spelling of the same account.
fn normalize(username: &str) -> String {
    username.to_ascii_lowercase()
}

/// Request body for `POST /api/v1/auth/login`.
#[derive(Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// Required only when the account has TOTP enabled.
    #[serde(default, alias = "totpCode")]
    pub totp_code: Option<String>,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field(
                "totp_code",
                &self.totp_code.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// The token pair returned by both login and refresh.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub access_token: String,
    pub refresh_token: String,
}

impl From<TokenPair> for SessionResponse {
    fn from(tokens: TokenPair) -> Self {
        Self {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        }
    }
}

impl std::fmt::Debug for SessionResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionResponse")
            .field("access_token", &"[redacted]")
            .field("refresh_token", &"[redacted]")
            .finish()
    }
}

/// Request body for `POST /api/v1/auth/refresh`.
#[derive(Clone, Deserialize)]
pub struct RefreshRequest {
    #[serde(alias = "refreshToken")]
    pub refresh_token: String,
}

impl std::fmt::Debug for RefreshRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RefreshRequest")
            .field("refresh_token", &"[redacted]")
            .finish()
    }
}

/// Request body for `POST /api/v1/auth/logout`.
///
/// Empty bodies and unknown tokens are accepted on purpose: logout is idempotent and must not be
/// an oracle for whether a refresh token was ever valid.
#[derive(Clone, Default, Deserialize)]
pub struct LogoutRequest {
    #[serde(default, alias = "refreshToken")]
    pub refresh_token: Option<String>,
}

impl std::fmt::Debug for LogoutRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogoutRequest")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// The caller's own account, without credential material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeResponse {
    /// The user UUID as a string (the UI never does arithmetic on it).
    pub id: String,
    pub username: String,
    /// The role name, matching the shape the UI reads (`role.name`).
    pub role: RoleView,
    pub totp_enabled: bool,
    pub auth_epoch: u64,
}

/// The public part of a role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleView {
    pub name: String,
}

/// `POST /api/v1/auth/login` — exchange credentials for a token pair.
///
/// `Cache-Control: no-store` keeps the token pair out of any browser or intermediary cache; the
/// response is the one place in the API that carries a long-lived credential.
pub(crate) async fn login_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .login_limiter
        .reserve_attempt(&body.username)
        .map_err(|retry_after_seconds| ApiError::RateLimited {
            retry_after_seconds,
        })?;

    let result = state
        .authn
        .login(&body.username, &body.password, body.totp_code.as_deref())
        .await;
    match result {
        Ok(tokens) => {
            state.login_limiter.clear(&body.username);
            Ok((
                [(header::CACHE_CONTROL, "no-store")],
                Json(SessionResponse::from(tokens)),
            ))
        }
        Err(error) => {
            // The attempt was already reserved before the verify, so a TOTP guess gets exactly the
            // same budget as a password guess; nothing to record here.
            Err(login_error(error))
        }
    }
}

/// Map a login failure without turning it into an account oracle.
fn login_error(error: AuthError) -> ApiError {
    match error {
        // One message for "no such user" and "wrong password": the pair must not reveal which
        // usernames exist.
        AuthError::InvalidCredentials => {
            ApiError::Unauthorized("invalid username or password".to_owned())
        }
        AuthError::InvalidTotpCode => ApiError::Unauthorized("invalid TOTP code".to_owned()),
        AuthError::TotpReplay => ApiError::Unauthorized("TOTP code already used".to_owned()),
        other => internal_error(other),
    }
}

/// `POST /api/v1/auth/refresh` — rotate the pair.
pub(crate) async fn refresh_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    Json(body): Json<RefreshRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let tokens = state
        .authn
        .refresh(&body.refresh_token)
        .await
        .map_err(|error| match error {
            AuthError::TokenExpired => ApiError::Unauthorized("refresh token expired".to_owned()),
            // Reused, revoked, unknown and malformed tokens are one case to the caller: present a
            // new login. Reporting the difference would let a stolen token be probed for validity.
            AuthError::RefreshTokenRevoked
            | AuthError::RefreshTokenNotFound
            | AuthError::InvalidToken
            | AuthError::InvalidSignature
            | AuthError::UserNotFound => ApiError::Unauthorized("invalid refresh token".to_owned()),
            other => internal_error(other),
        })?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(SessionResponse::from(tokens)),
    ))
}

/// `POST /api/v1/auth/logout` — revoke this browser's refresh token.
///
/// Always `204` for a well-formed request: unknown, already-revoked and expired tokens are success,
/// because the session is over either way. Only a store failure is reported, and as `500`.
///
/// The access token is stateless and stays valid until it expires (15 minutes by default); logout
/// revokes the refresh token so the session cannot be extended. The UI drops both tokens on
/// success. Bumping the authentication epoch instead would sign out every device of the user, which
/// is not what this endpoint means.
pub(crate) async fn logout_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    body: Option<Json<LogoutRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let token = body
        .and_then(|Json(body)| body.refresh_token)
        .filter(|token| !token.is_empty());
    if let Some(token) = token {
        match state.authn.revoke_refresh_token(&token).await {
            Ok(()) => {}
            Err(AuthError::RefreshTokenRevoked | AuthError::RefreshTokenNotFound) => {}
            // Expiry only means the credential could no longer be used; logout still succeeded.
            Err(AuthError::TokenExpired) => {}
            Err(other) => return Err(internal_error(other)),
        }
    }
    Ok(([(header::CACHE_CONTROL, "no-store")], StatusCode::NO_CONTENT))
}

/// `GET /api/v1/auth/me` — describe the caller.
pub(crate) async fn me_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let Claims { sub, .. } = require_claims(&state, &headers).await?;
    let user = state.authn.get_user(sub).await.map_err(|error| match error {
        // The token verified but its user is gone: treat it as an invalid token, not a 500.
        AuthError::UserNotFound => ApiError::Unauthorized("invalid access token".to_owned()),
        other => internal_error(other),
    })?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(MeResponse {
            id: user.id.0.to_string(),
            username: user.username,
            role: RoleView {
                name: user.role.name,
            },
            totp_enabled: user.totp_enabled,
            auth_epoch: user.auth_epoch,
        }),
    ))
}

/// Log the store failure and return a fixed message: an unauthenticated caller of a session
/// endpoint must not receive internal store or crypto text in the error body.
pub(crate) fn internal_error(error: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %error, "session endpoint failed");
    ApiError::Internal("internal error".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_accept_both_field_spellings() {
        let snake: LoginRequest = serde_json::from_value(serde_json::json!({
            "username": "alice",
            "password": "secret",
            "totp_code": "123456"
        }))
        .expect("snake_case login body");
        assert_eq!(snake.totp_code.as_deref(), Some("123456"));

        let camel: LoginRequest = serde_json::from_value(serde_json::json!({
            "username": "alice",
            "password": "secret",
            "totpCode": "123456"
        }))
        .expect("camelCase login body");
        assert_eq!(camel.totp_code.as_deref(), Some("123456"));

        let refresh: RefreshRequest =
            serde_json::from_value(serde_json::json!({"refreshToken": "token"}))
                .expect("camelCase refresh body");
        assert_eq!(refresh.refresh_token, "token");

        let logout: LogoutRequest =
            serde_json::from_value(serde_json::json!({"refreshToken": "token"}))
                .expect("camelCase logout body");
        assert_eq!(logout.refresh_token.as_deref(), Some("token"));

        let empty: LogoutRequest =
            serde_json::from_value(serde_json::json!({})).expect("empty logout body");
        assert_eq!(empty.refresh_token, None);
    }

    #[test]
    fn responses_use_the_snake_case_shape_the_ui_reads() {
        let session = serde_json::to_value(SessionResponse {
            access_token: "access".to_owned(),
            refresh_token: "refresh".to_owned(),
        })
        .expect("serialize the session");
        assert_eq!(session["access_token"], "access");
        assert_eq!(session["refresh_token"], "refresh");
        assert!(session.get("accessToken").is_none());

        let me = serde_json::to_value(MeResponse {
            id: "user-id".to_owned(),
            username: "alice".to_owned(),
            role: RoleView {
                name: "admin".to_owned(),
            },
            totp_enabled: true,
            auth_epoch: 3,
        })
        .expect("serialize the current user");
        assert_eq!(me["role"]["name"], "admin");
        assert_eq!(me["totp_enabled"], true);
        assert_eq!(me["auth_epoch"], 3);
        assert!(
            me.get("password_hash").is_none() && me.get("totp_secret").is_none(),
            "the session view never carries credential material"
        );
    }

    #[test]
    fn debug_impls_never_print_credentials() {
        let login = LoginRequest {
            username: "alice".to_owned(),
            password: "hunter2".to_owned(),
            totp_code: Some("123456".to_owned()),
        };
        let rendered = format!("{login:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("123456"), "{rendered}");

        let session = SessionResponse {
            access_token: "access-token".to_owned(),
            refresh_token: "refresh-token".to_owned(),
        };
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("access-token"), "{rendered}");
        assert!(!rendered.contains("refresh-token"), "{rendered}");

        let refresh = RefreshRequest {
            refresh_token: "refresh-token".to_owned(),
        };
        assert!(!format!("{refresh:?}").contains("refresh-token"));
    }

    #[test]
    fn the_login_limiter_blocks_one_username_and_spares_another() {
        let limiter = LoginLimiter::new();
        for _ in 0..MAX_LOGIN_FAILURES {
            assert!(limiter.reserve_attempt("alice").is_ok());
        }
        assert!(
            limiter.reserve_attempt("alice").is_err(),
            "five attempts exhaust the window"
        );
        assert!(
            limiter.reserve_attempt("ALICE").is_err(),
            "spelling changes must not dodge the limiter"
        );
        assert!(
            limiter.reserve_attempt("bob").is_ok(),
            "another account is unaffected"
        );

        limiter.clear("alice");
        assert!(
            limiter.reserve_attempt("alice").is_ok(),
            "a success clears the streak"
        );
    }
}
