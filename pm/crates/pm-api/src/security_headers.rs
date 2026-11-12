//! Security headers API endpoints.
//!
//! ```text
//! GET    /api/v1/security-headers          global config (defaults applied)
//! PUT    /api/v1/security-headers          validate + update global config
//! GET    /api/v1/hosts/{id}/security-headers per-host config (inherits global)
//! PUT    /api/v1/hosts/{id}/security-headers validate + update per-host config
//!
//! The schema mirrors `caddy_rs_http::security_headers::SecurityHeadersConfig` so the PM can
//! store and serve the same schema Caddy's `headers` handler consumes. Global config is
//! persisted in the state store under namespace `config`, key `security_headers`.
//!
//! HSTS `preload` requires `max_age >= 15552000` (180 days) and `include_subdomains`.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Json;
use caddy_rs_pm_core::{SecurityHeadersConfig, SecurityHeadersHstsConfig};
use caddy_rs_pm_service::HostDraft;
use serde::{Deserialize, Serialize};

use crate::{ApiError, ApiState};

/// Namespace for global (non-host) configuration in the state store.
const CONFIG_NAMESPACE: &str = "config";
/// Key for the global security headers configuration.
const SECURITY_HEADERS_KEY: &str = "security_headers";

/// `GET /api/v1/security-headers` — returns the global config with defaults applied.
pub async fn get_global_handler(
    State(state): State<ApiState>,
) -> Result<Json<SecurityHeadersDto>, ApiError> {
    let config = load_global_config(state.runtime.state_store())?;
    Ok(Json(SecurityHeadersDto::from(&config)))
}

/// `PUT /api/v1/security-headers` — validates and updates the global config.
pub async fn put_global_handler(
    State(state): State<ApiState>,
    body: Result<Json<SecurityHeadersDto>, JsonRejection>,
) -> Result<Json<SecurityHeadersDto>, ApiError> {
    let request = parse_json(body)?.0;
    let config = SecurityHeadersConfig::from(&request);
    config.validate().map_err(validation_error)?;
    save_global_config(state.runtime.state_store(), &config)?;
    Ok(Json(SecurityHeadersDto::from(&config)))
}

/// `GET /api/v1/hosts/{id}/security-headers` — returns per-host config, inheriting global.
pub async fn get_host_handler(
    State(state): State<ApiState>,
    Path(host_id): Path<u64>,
) -> Result<Json<SecurityHeadersDto>, ApiError> {
    let stored = state
        .runtime
        .hosts()
        .get(caddy_rs_pm_core::HostId(host_id))
        .map_err(map_repository_error)?
        .ok_or_else(|| ApiError::NotFound(format!("host {host_id}")))?;
    let config = stored
        .host
        .security_headers
        .clone()
        .unwrap_or_else(|| load_global_config(state.runtime.state_store()).unwrap_or_default());
    Ok(Json(SecurityHeadersDto::from(&config)))
}

/// `PUT /api/v1/hosts/{id}/security-headers` — validates and updates per-host config.
pub async fn put_host_handler(
    State(state): State<ApiState>,
    Path(host_id): Path<u64>,
    body: Result<Json<SecurityHeadersDto>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request = parse_json(body)?.0;
    let config = SecurityHeadersConfig::from(&request);
    config.validate().map_err(validation_error)?;

    let id = caddy_rs_pm_core::HostId(host_id);
    let stored = state
        .runtime
        .hosts()
        .get(id)
        .map_err(map_repository_error)?
        .ok_or_else(|| ApiError::NotFound(format!("host {host_id}")))?;

    let revision = stored.revision;
    let mut host = stored.host.clone();
    host.security_headers = Some(config);

    let draft = HostDraft {
        domains: host.domains.clone(),
        tls: host.tls.clone(),
        spec: host.spec.clone(),
        enabled: host.enabled,
        security_headers: host.security_headers.clone(),
    };

    let stored = state
        .runtime
        .service()
        .update(id, revision, draft)
        .map_err(map_service_error)?;

    let final_config = stored.host.security_headers.unwrap_or_default();
    let mut response = Json(SecurityHeadersDto::from(&final_config)).into_response();
    response.headers_mut().insert(
        axum::http::header::ETAG,
        axum::http::HeaderValue::from_str(&format!(
            "\"h{}-r{}\"",
            stored.host.id.0, stored.revision
        ))
        .map_err(|_| ApiError::Internal("invalid etag".to_string()))?,
    );
    Ok(response)
}

/// Load the global security headers config from the state store.
fn load_global_config(
    store: std::sync::Arc<dyn caddy_rs_pm_state::StateStore>,
) -> Result<SecurityHeadersConfig, ApiError> {
    match store.get(CONFIG_NAMESPACE, SECURITY_HEADERS_KEY) {
        Ok(Some(document)) => {
            let config: SecurityHeadersConfig = serde_json::from_value(document.value.clone())
                .map_err(|error| {
                    ApiError::Internal(format!("cannot decode stored config: {error}"))
                })?;
            Ok(config)
        }
        Ok(None) => Ok(SecurityHeadersConfig::default()),
        Err(error) => Err(ApiError::Internal(format!("cannot read config: {error}"))),
    }
}

/// Save the global security headers config to the state store.
fn save_global_config(
    store: std::sync::Arc<dyn caddy_rs_pm_state::StateStore>,
    config: &SecurityHeadersConfig,
) -> Result<(), ApiError> {
    let value = serde_json::to_value(config)
        .map_err(|error| ApiError::Internal(format!("cannot encode config: {error}")))?;
    store
        .transact(caddy_rs_pm_state::Transaction::new().put(
            CONFIG_NAMESPACE,
            SECURITY_HEADERS_KEY,
            value,
        ))
        .map_err(|error| ApiError::Internal(format!("cannot write config: {error}")))?;
    Ok(())
}

fn parse_json<T, E>(result: Result<T, E>) -> Result<T, ApiError>
where
    E: std::fmt::Display,
{
    result.map_err(|error| ApiError::validation(error.to_string(), "body"))
}

fn validation_error(error: caddy_rs_pm_core::CoreError) -> ApiError {
    ApiError::validation(error.to_string(), "security_headers")
}

fn map_repository_error(error: caddy_rs_pm_hosts::HostError) -> ApiError {
    match error {
        caddy_rs_pm_hosts::HostError::NotFound(id) => ApiError::NotFound(format!("host {id}")),
        caddy_rs_pm_hosts::HostError::AlreadyExists(id) => {
            ApiError::Conflict(format!("host {id} already exists"))
        }
        _ => ApiError::Internal(error.to_string()),
    }
}

fn map_service_error(error: caddy_rs_pm_service::ServiceError) -> ApiError {
    ApiError::Internal(error.to_string())
}

/// Public DTO for security headers configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityHeadersDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_security_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict_transport_security: Option<SecurityHeadersHstsDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_frame_options: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_content_type_options: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer_policy: Option<String>,
}

/// Public DTO for HSTS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityHeadersHstsDto {
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
}

impl From<&SecurityHeadersConfig> for SecurityHeadersDto {
    fn from(config: &SecurityHeadersConfig) -> Self {
        Self {
            content_security_policy: config.content_security_policy.clone(),
            strict_transport_security: config.strict_transport_security.as_ref().map(|hsts| {
                SecurityHeadersHstsDto {
                    max_age: hsts.max_age,
                    include_subdomains: hsts.include_subdomains,
                    preload: hsts.preload,
                }
            }),
            permissions_policy: config.permissions_policy.clone(),
            x_frame_options: config.x_frame_options.clone(),
            x_content_type_options: config.x_content_type_options.clone(),
            referrer_policy: config.referrer_policy.clone(),
        }
    }
}

impl From<&SecurityHeadersDto> for SecurityHeadersConfig {
    fn from(dto: &SecurityHeadersDto) -> Self {
        Self {
            content_security_policy: dto.content_security_policy.clone(),
            strict_transport_security: dto.strict_transport_security.as_ref().map(|hsts| {
                SecurityHeadersHstsConfig {
                    max_age: hsts.max_age,
                    include_subdomains: hsts.include_subdomains,
                    preload: hsts.preload,
                }
            }),
            permissions_policy: dto.permissions_policy.clone(),
            x_frame_options: dto.x_frame_options.clone(),
            x_content_type_options: dto.x_content_type_options.clone(),
            referrer_policy: dto.referrer_policy.clone(),
        }
    }
}

impl Default for SecurityHeadersDto {
    fn default() -> Self {
        Self::from(&SecurityHeadersConfig::default())
    }
}
