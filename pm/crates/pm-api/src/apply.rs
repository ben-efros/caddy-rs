//! `POST /config/apply` and `GET /config/revisions` handlers.
//!
//! This is the only endpoint that mutates the live caddy-rs configuration. It is loopback-only
//! and never echoes a config, a certificate/key, or an admin response body.

use axum::{extract::State, http::StatusCode, Json};
use caddy_rs_pm_runtime::{ApplyError, ApplyFailureKind, ApplyOutcome, ConfigRevision};
use serde::{Deserialize, Serialize};

use crate::hosts::LocalPeer;
use crate::{ApiError, ApiState, PaginatedResponse, PaginationParams};

/// Successful apply response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyResponse {
    pub revision: u64,
    pub hash: String,
    pub changed: bool,
}

impl From<ApplyOutcome> for ApplyResponse {
    fn from(outcome: ApplyOutcome) -> Self {
        Self {
            revision: outcome.revision,
            hash: outcome.hash,
            changed: outcome.changed,
        }
    }
}

/// Apply the assembled config to the live caddy-rs admin endpoint.
pub async fn apply_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
) -> Result<(StatusCode, Json<ApplyResponse>), ApiError> {
    let applier = state.applier().ok_or_else(|| {
        ApiError::ServiceUnavailable(
            "config apply is not configured; start the PM with a loopback caddy admin URL"
                .to_owned(),
        )
    })?;
    match applier.apply().await {
        Ok(outcome) => Ok((StatusCode::OK, Json(outcome.into()))),
        Err(error) => Err(map_apply_error(error)),
    }
}

/// Return the durable apply history, newest last.
pub async fn revisions_handler(
    State(state): State<ApiState>,
    params: axum::extract::Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<ConfigRevision>>, ApiError> {
    let applier = state.applier().ok_or_else(|| {
        ApiError::ServiceUnavailable(
            "config apply is not configured; no apply revisions exist".to_owned(),
        )
    })?;
    let revisions = applier.revisions().map_err(map_apply_error)?;
    Ok(Json(params.paginate(&revisions)))
}

fn map_apply_error(error: ApplyError) -> ApiError {
    match error {
        ApplyError::Assemble(error) => error.into(),
        ApplyError::Pipeline(failure) => match failure.kind {
            ApplyFailureKind::Transaction(error) => ApiError::Conflict(error.to_string()),
            ApplyFailureKind::Target(error) => {
                ApiError::ServiceUnavailable(format!("caddy admin apply failed: {error}"))
            }
            ApplyFailureKind::Verification => ApiError::Conflict(
                "loaded config did not match the staged generation; the previous config was restored"
                    .to_owned(),
            ),
            ApplyFailureKind::Rollback(error) => ApiError::ServiceUnavailable(format!(
                "apply failed and restoring the previous config failed: {error}"
            )),
        },
        ApplyError::State(error) => ApiError::Internal(format!("config state: {error}")),
        ApplyError::Serialization(error) => {
            ApiError::Internal(format!("config revision serialization: {error}"))
        }
    }
}
