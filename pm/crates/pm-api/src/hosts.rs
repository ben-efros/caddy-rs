//! CRUD, revision preconditions and enable/disable for `/api/v1/hosts`.
//!
//! Every mutation first reads the stored host, requires a strong `If-Match` matching that
//! revision, then passes the same revision to `pm-service` as its compare-and-swap expectation.
//! A conflict after the read is reported as `412`, never retried: an automatic retry of a `PATCH`
//! would silently overwrite a concurrent edit.

use std::collections::HashMap;
use std::future::Future;
#[cfg(test)]
use std::net::SocketAddr;

use crate::{
    etag_members, host_kind, matches_any, normalize_etag_member, require_local_peer, tls_mode,
    ApiError, ApiState, HostSummary, PaginationParams, PeerAddr,
};
use axum::{
    extract::{
        rejection::{JsonRejection, PathRejection, QueryRejection},
        FromRequestParts, Path, Query, State,
    },
    http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use caddy_rs_pm_core::{Host, HostId};
use caddy_rs_pm_hosts::{HostError, StoredHost};
use caddy_rs_pm_service::{HostDraft, ServiceError};
use caddy_rs_pm_state::StateError;

use super::dto::{HostPatchRequest, HostResponse, HostWriteRequest};

/// Extractor that rejects a mutation unless the socket peer is loopback.
///
/// It runs before the JSON body extractor, so a remote caller learns nothing about body validity.
pub struct LocalPeer;

impl<S> FromRequestParts<S> for LocalPeer
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let peer = parts
            .extensions
            .get::<PeerAddr>()
            .copied()
            .unwrap_or(PeerAddr(None));
        let result = require_local_peer(peer).map(|()| Self);
        async move { result }
    }
}

fn strong_etag(stored: &StoredHost) -> String {
    format!("\"h{}-r{}\"", stored.host.id.0, stored.revision)
}

fn set_host_headers(response: &mut Response, etag: &str) {
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// Strong `If-Match`: exact opaque-tag match or `*`. A weak `W/"..."` never satisfies it.
fn require_strong_if_match(headers: &HeaderMap, current: &str) -> Result<(), ApiError> {
    let mut seen = false;
    let mut matched = false;
    for value in headers.get_all(header::IF_MATCH) {
        seen = true;
        let raw = value.to_str().map_err(|_| {
            ApiError::PreconditionFailed("If-Match is not a valid header value".to_owned())
        })?;
        if raw
            .split(',')
            .map(str::trim)
            .any(|member| member == "*" || member == current)
        {
            matched = true;
        }
    }
    if !seen {
        return Err(ApiError::PreconditionRequired(
            "If-Match is required; fetch the host and send its strong ETag".to_owned(),
        ));
    }
    if matched {
        Ok(())
    } else {
        Err(ApiError::PreconditionFailed(format!(
            "If-Match does not match the current host revision ({current})"
        )))
    }
}

/// Evaluate `If-Match` and `If-None-Match` for a host `GET`.
fn evaluate_host_get(headers: &HeaderMap, current: &str) -> Result<Option<Response>, ApiError> {
    if headers.contains_key(header::IF_MATCH) {
        require_strong_if_match(headers, current)?;
    }
    if let Some(members) = etag_members(headers, header::IF_NONE_MATCH)? {
        let normalized = normalize_etag_member(current).to_owned();
        if matches_any(&members, &normalized) {
            let mut response = StatusCode::NOT_MODIFIED.into_response();
            if let Ok(value) = HeaderValue::from_str(current) {
                response.headers_mut().insert(header::ETAG, value);
            }
            return Ok(Some(response));
        }
    }
    Ok(None)
}

fn parse_path_id(path: Result<Path<u64>, PathRejection>) -> Result<HostId, ApiError> {
    let Path(value) = path.map_err(|rejection| {
        ApiError::validation(format!("invalid host id: {}", rejection.body_text()), "id")
    })?;
    HostId::new(value).map_err(|error| ApiError::validation(error.to_string(), "id"))
}

fn parse_json<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    match body {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE => Err(
            ApiError::UnsupportedMediaType("expected application/json".to_owned()),
        ),
        Err(rejection) => Err(ApiError::validation(rejection.body_text(), "body")),
    }
}

fn map_repository_error(error: HostError) -> ApiError {
    match error {
        HostError::NotFound(id) => ApiError::NotFound(format!("host {id}")),
        HostError::DomainInUse(domain) => {
            ApiError::Conflict(format!("domain `{domain}` is already used by another host"))
        }
        HostError::AlreadyExists(id) => ApiError::Conflict(format!("host {id} already exists")),
        HostError::IdRetired(id) => {
            ApiError::Conflict(format!("host id {id} is retired and cannot be reused"))
        }
        HostError::Core(error) => ApiError::validation(error.to_string(), "host"),
        HostError::State(StateError::Conflict { namespace, .. })
            if namespace == "pm.host-domains" =>
        {
            ApiError::Conflict("a requested domain is already used by another host".to_owned())
        }
        HostError::State(StateError::Conflict { .. }) => ApiError::PreconditionFailed(
            "the host changed after it was read; fetch it again and retry".to_owned(),
        ),
        HostError::State(error) => ApiError::Internal(error.to_string()),
        HostError::Json(error) => ApiError::Internal(error.to_string()),
        HostError::InvalidDocument(error) => ApiError::Internal(error),
    }
}

fn map_service_error(error: ServiceError) -> ApiError {
    match error {
        ServiceError::Host(error) => map_repository_error(error),
        ServiceError::PolicyValidationUnavailable => ApiError::validation(
            "auto TLS cannot be validated by this service".to_owned(),
            "tls",
        ),
        ServiceError::PolicyNotFound { host_id, policy_id } => ApiError::validation(
            format!("host {host_id} references unknown auto policy {policy_id}"),
            "tls.autoPolicyId",
        ),
        ServiceError::UnsupportedExplicitCertificate { mode, .. } => ApiError::validation(
            format!("TLS mode {mode:?} requires a certificate repository"),
            "tls.mode",
        ),
        ServiceError::Tls { source, .. } => ApiError::validation(source.to_string(), "tls"),
        ServiceError::Compile(error) => ApiError::Internal(error.to_string()),
        ServiceError::Policy(error) => ApiError::Internal(error.to_string()),
        ServiceError::Certificate(error) => ApiError::Internal(error.to_string()),
        ServiceError::CertificateNotFound {
            host_id,
            certificate_id,
        } => ApiError::validation(
            format!("host {host_id} references unknown manual certificate {certificate_id}"),
            "tls.certificateId",
        ),
    }
}

fn fetch_host(state: &ApiState, id: HostId) -> Result<StoredHost, ApiError> {
    state
        .runtime
        .hosts()
        .get(id)
        .map_err(map_repository_error)?
        .ok_or_else(|| ApiError::NotFound(format!("host {}", id.0)))
}

fn host_response(stored: &StoredHost, status: StatusCode) -> Result<Response, ApiError> {
    let etag = strong_etag(stored);
    let location = format!("/api/v1/hosts/{}", stored.host.id.0);
    let mut response = (status, Json(HostResponse::from(stored))).into_response();
    set_host_headers(&mut response, &etag);
    if status == StatusCode::CREATED {
        let value = HeaderValue::from_str(&location)
            .map_err(|error| ApiError::Internal(format!("location header: {error}")))?;
        response.headers_mut().insert(header::LOCATION, value);
    }
    Ok(response)
}

fn draft_from_host(host: &Host, enabled: bool) -> HostDraft {
    HostDraft {
        domains: host.domains.clone(),
        tls: host.tls.clone(),
        spec: host.spec.clone(),
        enabled,
    }
}

// ---------------------------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KindFilter {
    Proxy,
    Redirect,
    Dead,
}

impl KindFilter {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "proxy" => Ok(Self::Proxy),
            "redirect" => Ok(Self::Redirect),
            "dead" => Ok(Self::Dead),
            other => Err(ApiError::validation(
                format!("unknown host kind `{other}`; expected proxy, redirect or dead"),
                "kind",
            )),
        }
    }

    fn matches(self, spec: &caddy_rs_pm_core::HostSpec) -> bool {
        matches!(
            (self, spec),
            (Self::Proxy, caddy_rs_pm_core::HostSpec::Proxy(_))
                | (Self::Redirect, caddy_rs_pm_core::HostSpec::Redirect(_))
                | (Self::Dead, caddy_rs_pm_core::HostSpec::Dead(_))
        )
    }
}

struct ListFilter {
    page: PaginationParams,
    enabled: Option<bool>,
    kind: Option<KindFilter>,
    domain: Option<String>,
}

fn parse_list_query(
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<ListFilter, ApiError> {
    let Query(values) = query.map_err(|rejection| {
        ApiError::validation(format!("invalid query: {}", rejection.body_text()), "query")
    })?;
    let mut page = PaginationParams::default();
    let mut enabled = None;
    let mut kind = None;
    let mut domain = None;

    for (key, value) in values {
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
            "enabled" => {
                enabled = Some(value.parse::<bool>().map_err(|_| {
                    ApiError::validation("enabled must be true or false", "enabled")
                })?);
            }
            "kind" => kind = Some(KindFilter::parse(&value)?),
            "domain" => domain = Some(value),
            other => {
                return Err(ApiError::validation(
                    format!("unknown query parameter `{other}`"),
                    "query",
                ))
            }
        }
    }

    Ok(ListFilter {
        page,
        enabled,
        kind,
        domain,
    })
}

pub async fn list_handler(
    State(state): State<ApiState>,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<Json<crate::PaginatedResponse<HostSummary>>, ApiError> {
    let filter = parse_list_query(query)?;
    let stored = state.runtime.hosts().list().map_err(map_repository_error)?;

    let mut summaries: Vec<HostSummary> = stored
        .iter()
        .filter(|entry| {
            filter
                .enabled
                .is_none_or(|value| entry.host.enabled == value)
        })
        .filter(|entry| {
            filter
                .kind
                .is_none_or(|value| value.matches(&entry.host.spec))
        })
        .filter(|entry| {
            filter.domain.as_ref().is_none_or(|needle| {
                let needle = needle.to_ascii_lowercase();
                entry
                    .host
                    .domains
                    .iter()
                    .any(|domain| domain.to_ascii_lowercase().contains(&needle))
            })
        })
        .map(|entry| HostSummary {
            id: entry.host.id.0,
            domains: entry.host.domains.clone(),
            kind: host_kind(&entry.host.spec).to_owned(),
            enabled: entry.host.enabled,
            revision: entry.revision,
            tls_mode: tls_mode(&entry.host.tls),
        })
        .collect();
    summaries.sort_unstable_by_key(|summary| summary.id);

    Ok(Json(filter.page.paginate(&summaries)))
}

// ---------------------------------------------------------------------------------------------
// Create / detail / replace / patch / delete / toggle
// ---------------------------------------------------------------------------------------------

pub async fn create_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    body: Result<Json<HostWriteRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request = parse_json(body)?;
    let stored = state
        .runtime
        .service()
        .create(request.into_draft())
        .map_err(map_service_error)?;
    host_response(&stored, StatusCode::CREATED)
}

pub async fn get_handler(
    State(state): State<ApiState>,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_path_id(path)?;
    let stored = fetch_host(&state, id)?;
    let etag = strong_etag(&stored);
    if let Some(response) = evaluate_host_get(&headers, &etag)? {
        return Ok(response);
    }
    let mut response = Json(HostResponse::from(&stored)).into_response();
    set_host_headers(&mut response, &etag);
    Ok(response)
}

pub async fn replace_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
    body: Result<Json<HostWriteRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let id = parse_path_id(path)?;
    let request = parse_json(body)?;
    let current = fetch_host(&state, id)?;
    require_strong_if_match(&headers, &strong_etag(&current))?;
    let stored = state
        .runtime
        .service()
        .update(id, current.revision, request.into_draft())
        .map_err(map_service_error)?;
    host_response(&stored, StatusCode::OK)
}

pub async fn patch_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
    body: Result<Json<HostPatchRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let id = parse_path_id(path)?;
    let patch = parse_json(body)?;
    let current = fetch_host(&state, id)?;
    if patch.is_empty() {
        return Err(ApiError::validation(
            "PATCH must change at least one field",
            "body",
        ));
    }
    require_strong_if_match(&headers, &strong_etag(&current))?;
    let draft = patch.apply_to(&current.host);
    let stored = state
        .runtime
        .service()
        .update(id, current.revision, draft)
        .map_err(map_service_error)?;
    host_response(&stored, StatusCode::OK)
}

pub async fn delete_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_path_id(path)?;
    let current = fetch_host(&state, id)?;
    require_strong_if_match(&headers, &strong_etag(&current))?;
    state
        .runtime
        .service()
        .delete(id, current.revision)
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn set_enabled(
    state: ApiState,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
    enabled: bool,
) -> Result<Response, ApiError> {
    let id = parse_path_id(path)?;
    let current = fetch_host(&state, id)?;
    require_strong_if_match(&headers, &strong_etag(&current))?;
    let draft = draft_from_host(&current.host, enabled);
    let stored = state
        .runtime
        .service()
        .update(id, current.revision, draft)
        .map_err(map_service_error)?;
    host_response(&stored, StatusCode::OK)
}

pub async fn enable_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    set_enabled(state, path, headers, true).await
}

pub async fn disable_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    set_enabled(state, path, headers, false).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_if_match_rejects_weak_and_stale_tags() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("W/\"h1-r1\""));
        let error = require_strong_if_match(&headers, "\"h1-r1\"").unwrap_err();
        assert_eq!(error.status_code(), StatusCode::PRECONDITION_FAILED);

        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"h1-r0\""));
        let error = require_strong_if_match(&headers, "\"h1-r1\"").unwrap_err();
        assert_eq!(error.status_code(), StatusCode::PRECONDITION_FAILED);

        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"h1-r1\""));
        require_strong_if_match(&headers, "\"h1-r1\"").unwrap();

        headers.insert(header::IF_MATCH, HeaderValue::from_static("*"));
        require_strong_if_match(&headers, "\"h1-r1\"").unwrap();
    }

    #[test]
    fn strong_if_match_requires_the_header() {
        let error = require_strong_if_match(&HeaderMap::new(), "\"h1-r1\"").unwrap_err();
        assert_eq!(error.status_code(), StatusCode::PRECONDITION_REQUIRED);
    }

    #[test]
    fn list_query_rejects_unknown_and_bad_filters() {
        let values = Query(HashMap::from([("nope".to_string(), "1".to_string())]));
        assert_eq!(
            parse_list_query(Ok(values)).err().unwrap().status_code(),
            StatusCode::BAD_REQUEST
        );

        let values = Query(HashMap::from([("kind".to_string(), "ftp".to_string())]));
        assert_eq!(
            parse_list_query(Ok(values)).err().unwrap().status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn list_query_parses_filters_and_clamps_page() {
        let values = Query(HashMap::from([
            ("limit".to_string(), "9999".to_string()),
            ("offset".to_string(), "2".to_string()),
            ("enabled".to_string(), "false".to_string()),
            ("kind".to_string(), "proxy".to_string()),
            ("domain".to_string(), "Example".to_string()),
        ]));
        let filter = parse_list_query(Ok(values)).unwrap();
        assert_eq!(filter.page.offset, 2);
        assert_eq!(filter.page.clamped().limit, crate::MAX_LIMIT);
        assert_eq!(filter.enabled, Some(false));
        assert!(filter
            .kind
            .unwrap()
            .matches(&caddy_rs_pm_core::HostSpec::Proxy(
                caddy_rs_pm_core::ProxySpec::new(caddy_rs_pm_core::Upstream::new(
                    caddy_rs_pm_core::UpstreamScheme::Http,
                    "10.0.0.5",
                    80,
                ))
            )));
        assert_eq!(filter.domain.as_deref(), Some("Example"));
    }

    #[test]
    fn peer_guard_only_accepts_loopback() {
        let loopback = PeerAddr(Some(SocketAddr::from(([127, 0, 0, 1], 5000))));
        require_local_peer(loopback).unwrap();

        let remote = PeerAddr(Some(SocketAddr::from(([192, 0, 2, 1], 5000))));
        let error = require_local_peer(remote).unwrap_err();
        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);

        let error = require_local_peer(PeerAddr(None)).unwrap_err();
        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);
    }

    // Serialize-only smoke test: this catches an accidental rename of the public JSON shape.
    #[test]
    fn host_response_has_a_stable_shape() {
        let stored = StoredHost {
            host: Host::new(
                HostId(1),
                vec!["app.example.com".to_owned()],
                caddy_rs_pm_core::HostTls::disabled(),
                caddy_rs_pm_core::HostSpec::Dead(caddy_rs_pm_core::DeadSpec),
            ),
            revision: 2,
        };
        assert_eq!(strong_etag(&stored), "\"h1-r2\"");
        let value = serde_json::to_value(HostResponse::from(&stored)).unwrap();
        assert_eq!(value["spec"], serde_json::json!({"kind": "dead"}));
        assert_eq!(value["revision"], 2);
    }
}
