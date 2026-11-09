//! Certificate intent recording and inventory-derived status.
//!
//! # What this slice does
//!
//! `POST /api/v1/certificates/intent` records a certificate **intent** as an eager
//! [`AutoCertificatePolicy`]. It never performs ACME issuance, stores no PEM or private key and
//! returns no secret material. The policy is compiled into Caddy TLS automation by
//! [`caddy_rs_pm_config::assemble_with_tls`] (through [`PmRuntime::assemble`]).
//!
//! `GET /api/v1/certificates` lists recorded intents and derives their status from an injected
//! [`CertificateInventorySource`]. The PM does not own issuance state: the daemon that owns the
//! caddy-rs admin URL implements the trait against `/runtime/inventory`. Without a source the
//! inventory is empty, so every intent is reported as `pending`; nothing is ever fabricated.
//!
//! # Status derivation
//!
//! A certificate covers an intent when every policy subject is covered by one record (a wildcard
//! record covers a wildcard subject and exactly one label below it). With no covering record the
//! status is `pending`. Otherwise:
//!
//! 1. a reported `renewal_error` is `renewal_error`;
//! 2. an expiry in the past is `expired`;
//! 3. less than [`EXPIRING_SOON_SECONDS`] remaining is `expiring_soon`;
//! 4. otherwise `issued`.
//!
//! The current caddy-rs inventory payload (`crates/admin/src/inventory.rs`) has no issuance-state
//! or renewal-error field: it reports `subject`, `sans`, `issuer`, `source` and `not_after`. This
//! slice therefore derives everything it can from expiry and exposes `renewal_error` only when a
//! future source provides it.
//!
//! [`PmRuntime::assemble`]: caddy_rs_pm_runtime::PmRuntime::assemble

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        rejection::{JsonRejection, PathRejection, QueryRejection},
        Path, Query, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use caddy_rs_pm_core::{
    normalize_domain, pattern_covers, AcmeChallenge, AutoCertificatePolicy, AutoMode, PolicyId,
};
use caddy_rs_pm_policies::{PolicyError, StoredPolicy};
use caddy_rs_pm_state::StateError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hosts::LocalPeer;
use crate::{evaluate_get_preconditions, ApiError, ApiState, PaginationParams};

/// A certificate reported by the runtime inventory.
///
/// No field contains private-key material: the inventory is a certificate *observation*, not
/// storage. `domains` and `sans` are both checked because sources differ in which they populate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRecord {
    /// Primary names the source associates with the certificate.
    pub domains: Vec<String>,
    /// Subject alternative names.
    pub sans: Vec<String>,
    /// Issuer reported by the source (for example `local` or an ACME CA).
    pub issuer: String,
    /// Certificate expiry as a Unix timestamp, when the source reports one.
    ///
    /// The caddy-rs inventory `not_after` is optional. A record without an expiry still proves an
    /// issuance observation but cannot be classified as expired or expiring; it is reported
    /// `issued` with no `expiresAt`, never as a fabricated epoch date.
    pub expires_at_unix: Option<i64>,
    /// Where the certificate lives (`managed`, `loaded`, ...).
    pub source: String,
    /// Renewal failure reported by the source, if it reports one.
    pub renewal_error: Option<String>,
}

/// The inventory could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("certificate inventory unavailable: {message}")]
pub struct InventoryError {
    message: String,
}

impl InventoryError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Read-only certificate inventory.
///
/// The daemon that owns the caddy-rs admin endpoint implements this trait over
/// `GET /runtime/inventory` (or certificate storage) and injects it with
/// [`ApiState::with_inventory`]. The API crate deliberately has no HTTP client: the transport and
/// its timeouts belong to the daemon.
pub trait CertificateInventorySource: Send + Sync {
    fn list_certificates(&self) -> Result<Vec<CertificateRecord>, InventoryError>;
}

/// Status of one recorded certificate intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateIntentStatus {
    Pending,
    Issued,
    ExpiringSoon,
    Expired,
    RenewalError,
}

impl CertificateIntentStatus {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "pending" => Ok(Self::Pending),
            "issued" => Ok(Self::Issued),
            "expiring_soon" => Ok(Self::ExpiringSoon),
            "expired" => Ok(Self::Expired),
            "renewal_error" => Ok(Self::RenewalError),
            other => Err(ApiError::validation(
                format!(
                    "unknown certificate status `{other}`; expected pending, issued, \
                     expiring_soon, expired or renewal_error"
                ),
                "status",
            )),
        }
    }
}

/// Renewal window used for `expiring_soon`: 30 days.
pub const EXPIRING_SOON_SECONDS: i64 = 30 * 24 * 60 * 60;

/// One list/detail item. Deliberately contains no PEM or private-key fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateIntentSummary {
    pub policy_id: u64,
    pub name: String,
    pub domains: Vec<String>,
    pub issuer: String,
    pub challenge: AcmeChallenge,
    pub enabled: bool,
    pub revision: u64,
    pub status: CertificateIntentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renewal_error: Option<String>,
}

/// `POST /api/v1/certificates/intent` body. Unknown fields (including NPM's legacy certificate
/// fields) are rejected rather than ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateIntentRequest {
    pub domains: Vec<String>,
    pub issuer: String,
    pub challenge: String,
}

fn record_covers(record: &CertificateRecord, subject: &str) -> bool {
    record
        .domains
        .iter()
        .chain(record.sans.iter())
        .any(|name| pattern_covers(name, subject))
}

/// Every subject must be covered, and different subjects may be covered by different records.
///
/// One intent can legitimately be satisfied by several certificates (for example an exact-name
/// certificate plus a wildcard for the remaining SANs). Coverage is therefore computed per
/// subject; a subject with no covering record makes the aggregate `pending`. All covering records
/// are returned so a renewal error on any certificate backing the intent is visible.
fn covering_records<'a>(
    subjects: &'a [String],
    records: &'a [CertificateRecord],
) -> Option<Vec<&'a CertificateRecord>> {
    if subjects.is_empty() {
        return None;
    }
    let mut covering: Vec<&CertificateRecord> = Vec::new();
    for subject in subjects {
        let mut found = false;
        for record in records {
            if !record_covers(record, subject) {
                continue;
            }
            found = true;
            if !covering.iter().any(|seen| std::ptr::eq(*seen, record)) {
                covering.push(record);
            }
        }
        if !found {
            return None;
        }
    }
    Some(covering)
}

/// Derive the status from the observations available in this slice.
#[must_use]
pub fn derive_intent_status<'a>(
    subjects: &'a [String],
    records: &'a [CertificateRecord],
    now_unix: i64,
) -> (CertificateIntentStatus, Option<&'a CertificateRecord>) {
    let Some(covering) = covering_records(subjects, records) else {
        return (CertificateIntentStatus::Pending, None);
    };
    // The aggregate record is the latest-expiring observation; split certificates are all
    // evidence, but expiry is reported for the one that outlives the others.
    let Some(record) = covering
        .iter()
        .copied()
        .max_by_key(|record| record.expires_at_unix)
    else {
        return (CertificateIntentStatus::Pending, None);
    };
    if covering.iter().any(|record| record.renewal_error.is_some()) {
        return (CertificateIntentStatus::RenewalError, Some(record));
    }
    let Some(expires_at) = record.expires_at_unix else {
        return (CertificateIntentStatus::Issued, Some(record));
    };
    if expires_at <= now_unix {
        return (CertificateIntentStatus::Expired, Some(record));
    }
    if expires_at - now_unix < EXPIRING_SOON_SECONDS {
        return (CertificateIntentStatus::ExpiringSoon, Some(record));
    }
    (CertificateIntentStatus::Issued, Some(record))
}

fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

fn summary_for(
    stored: &StoredPolicy,
    records: &[CertificateRecord],
    now_unix: i64,
) -> CertificateIntentSummary {
    let subjects = &stored.policy.subjects;
    let (status, record) = derive_intent_status(subjects, records, now_unix);
    CertificateIntentSummary {
        policy_id: stored.policy.id.0,
        name: stored.policy.name.clone(),
        domains: subjects.clone(),
        issuer: stored
            .policy
            .issuer
            .clone()
            .unwrap_or_else(|| "letsencrypt".to_string()),
        challenge: stored.policy.challenge,
        enabled: stored.policy.enabled,
        revision: stored.revision,
        status,
        expires_at_unix: record.and_then(|record| record.expires_at_unix),
        certificate_issuer: record.map(|record| record.issuer.clone()),
        certificate_source: record.map(|record| record.source.clone()),
        // The status is `renewal_error` when *any* covering certificate reports one. Surface that
        // reason even when the latest-expiring observation is a different, healthy certificate.
        renewal_error: covering_records(subjects, records).and_then(|covering| {
            covering
                .iter()
                .find_map(|record| record.renewal_error.clone())
        }),
    }
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

fn map_policy_error(error: PolicyError) -> ApiError {
    match error {
        PolicyError::Core(error) => ApiError::validation(error.to_string(), "body"),
        PolicyError::NotFound(id) => ApiError::NotFound(format!("certificate intent {id}")),
        PolicyError::AlreadyExists(id) => {
            ApiError::Conflict(format!("certificate intent {id} already exists"))
        }
        PolicyError::IdRetired(id) => {
            ApiError::Conflict(format!("certificate intent id {id} is retired"))
        }
        PolicyError::IdExhausted => {
            ApiError::Conflict("auto-certificate policy ids are exhausted".to_string())
        }
        PolicyError::State(StateError::Conflict { .. }) => ApiError::Conflict(
            "the certificate policy store changed concurrently; retry the request".to_string(),
        ),
        PolicyError::State(error) => ApiError::Internal(error.to_string()),
        PolicyError::Json(error) => ApiError::Internal(error.to_string()),
        PolicyError::InvalidDocument(error) => ApiError::Internal(error),
    }
}

fn parse_intent_issuer(raw: &str) -> Result<&'static str, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "letsencrypt" => Ok("letsencrypt"),
        "zerossl" => Ok("zerossl"),
        "internal" => Ok("internal"),
        other => Err(ApiError::validation(
            format!("unsupported issuer `{other}`; expected letsencrypt, zerossl or internal"),
            "issuer",
        )),
    }
}

fn parse_intent_challenge(raw: &str) -> Result<AcmeChallenge, ApiError> {
    let challenge = AcmeChallenge::parse(raw)
        .map_err(|error| ApiError::validation(error.to_string(), "challenge"))?;
    if challenge == AcmeChallenge::Dns01 {
        return Err(ApiError::validation(
            "dns01 requires DNS provider credentials, which this slice does not store; choose \
             http01 or tls-alpn01",
            "challenge",
        ));
    }
    Ok(challenge)
}

fn validate_intent_domains(raw: &[String]) -> Result<Vec<String>, ApiError> {
    if raw.is_empty() {
        return Err(ApiError::validation(
            "at least one domain is required",
            "domains",
        ));
    }
    if raw.len() > 100 {
        return Err(ApiError::validation(
            "at most 100 domains are supported",
            "domains",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut domains = Vec::with_capacity(raw.len());
    for value in raw {
        let normalized = normalize_domain(value)
            .map_err(|error| ApiError::validation(error.to_string(), "domains"))?;
        if !seen.insert(normalized.clone()) {
            return Err(ApiError::validation(
                format!("duplicate domain `{normalized}`"),
                "domains",
            ));
        }
        domains.push(normalized);
    }
    Ok(domains)
}

fn intent_name(domains: &[String]) -> String {
    let primary = domains.first().map_or("", String::as_str);
    let mut name = match domains.len() {
        0 | 1 => format!("Certificate intent for {primary}"),
        count => format!("Certificate intent for {primary} (+{} more)", count - 1),
    };
    if name.chars().count() > 120 {
        name = name.chars().take(120).collect();
    }
    name
}

fn set_intent_headers(response: &mut Response, etag: &str) {
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// A strong validator over the *whole* representation, including inventory-derived status,
/// expiry, certificate issuer/source and renewal error. A policy revision alone is insufficient:
/// inventory can change the body without touching the stored policy.
fn summary_etag(summary: &CertificateIntentSummary) -> Result<String, ApiError> {
    let bytes = serde_json::to_vec(summary)
        .map_err(|error| ApiError::Internal(format!("serialize certificate intent: {error}")))?;
    Ok(format!(
        "\"c{}-{}\"",
        summary.policy_id,
        crate::hash_bytes(&bytes)
    ))
}

fn records_for(state: &ApiState) -> Result<Vec<CertificateRecord>, ApiError> {
    match state.inventory() {
        None => Ok(Vec::new()),
        Some(source) => source
            .list_certificates()
            .map_err(|error| ApiError::Internal(error.to_string())),
    }
}

/// Create an intent policy, retrying only on an id raced by another writer.
fn create_intent_policy(
    state: &ApiState,
    domains: Vec<String>,
    issuer: &'static str,
    challenge: AcmeChallenge,
) -> Result<StoredPolicy, ApiError> {
    for _ in 0..3 {
        let id = state
            .runtime
            .policies()
            .next_id()
            .map_err(map_policy_error)?;
        let policy = AutoCertificatePolicy {
            id: PolicyId(id),
            name: intent_name(&domains),
            subjects: domains.clone(),
            mode: AutoMode::Eager,
            issuer: Some(issuer.to_string()),
            key_type: None,
            renewal_window_ratio: None,
            challenge,
            enabled: true,
        };
        match state.runtime.policies().create(policy) {
            Ok(stored) => return Ok(stored),
            Err(PolicyError::AlreadyExists(_) | PolicyError::IdRetired(_)) => continue,
            Err(error) => return Err(map_policy_error(error)),
        }
    }
    Err(ApiError::Conflict(
        "could not allocate a free auto-certificate policy id; retry the request".to_string(),
    ))
}

/// `POST /api/v1/certificates/intent`.
pub async fn create_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    body: Result<Json<CertificateIntentRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request = parse_json(body)?;
    let domains = validate_intent_domains(&request.domains)?;
    let issuer = parse_intent_issuer(&request.issuer)?;
    let challenge = parse_intent_challenge(&request.challenge)?;

    let stored = create_intent_policy(&state, domains, issuer, challenge)?;
    let summary = summary_for(&stored, &[], now_unix());
    debug_assert_eq!(summary.status, CertificateIntentStatus::Pending);

    let etag = summary_etag(&summary)?;
    let location = format!("/api/v1/certificates/{}", stored.policy.id.0);
    let mut response = (StatusCode::CREATED, Json(summary)).into_response();
    set_intent_headers(&mut response, &etag);
    let value = HeaderValue::from_str(&location)
        .map_err(|error| ApiError::Internal(format!("location header: {error}")))?;
    response.headers_mut().insert(header::LOCATION, value);
    Ok(response)
}

struct IntentListFilter {
    page: PaginationParams,
    domain: Option<String>,
    status: Option<CertificateIntentStatus>,
}

fn parse_list_query(
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<IntentListFilter, ApiError> {
    let Query(values) = query.map_err(|rejection| {
        ApiError::validation(format!("invalid query: {}", rejection.body_text()), "query")
    })?;
    let mut page = PaginationParams::default();
    let mut domain = None;
    let mut status = None;
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
            "domain" => domain = Some(value),
            "status" => status = Some(CertificateIntentStatus::parse(&value)?),
            other => {
                return Err(ApiError::validation(
                    format!("unknown query parameter `{other}`"),
                    "query",
                ));
            }
        }
    }
    Ok(IntentListFilter {
        page,
        domain,
        status,
    })
}

/// `GET /api/v1/certificates` — paginated, filterable intent list.
pub async fn list_handler(
    State(state): State<ApiState>,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<Json<crate::PaginatedResponse<CertificateIntentSummary>>, ApiError> {
    let filter = parse_list_query(query)?;
    let records = records_for(&state)?;
    let now = now_unix();
    let stored = state.runtime.policies().list().map_err(map_policy_error)?;

    let summaries: Vec<CertificateIntentSummary> = stored
        .iter()
        .map(|entry| summary_for(entry, &records, now))
        .filter(|summary| {
            filter.domain.as_ref().is_none_or(|needle| {
                let needle = needle.to_ascii_lowercase();
                summary
                    .domains
                    .iter()
                    .any(|domain| domain.to_ascii_lowercase().contains(&needle))
            })
        })
        .filter(|summary| filter.status.is_none_or(|value| summary.status == value))
        .collect();

    Ok(Json(filter.page.paginate(&summaries)))
}

/// `GET /api/v1/certificates/{id}` — one intent with the same inventory-derived status.
pub async fn get_handler(
    State(state): State<ApiState>,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|rejection| {
        ApiError::validation(
            format!("invalid certificate intent id: {}", rejection.body_text()),
            "id",
        )
    })?;
    if id == 0 {
        return Err(ApiError::validation(
            "certificate intent id must be greater than zero",
            "id",
        ));
    }
    let stored = state
        .runtime
        .policies()
        .get(PolicyId(id))
        .map_err(map_policy_error)?
        .ok_or_else(|| ApiError::NotFound(format!("certificate intent {id}")))?;
    let records = records_for(&state)?;
    let summary = summary_for(&stored, &records, now_unix());
    let etag = summary_etag(&summary)?;
    if let Some(response) = evaluate_get_preconditions(&headers, &etag)? {
        return Ok(response);
    }
    let mut response = Json(summary).into_response();
    set_intent_headers(&mut response, &etag);
    Ok(response)
}

/// Empty inventory used when no source is injected.
#[derive(Debug, Default)]
pub struct EmptyCertificateInventory;

impl CertificateInventorySource for EmptyCertificateInventory {
    fn list_certificates(&self) -> Result<Vec<CertificateRecord>, InventoryError> {
        Ok(Vec::new())
    }
}

/// Shared handle to an injected inventory.
pub type SharedCertificateInventory = Arc<dyn CertificateInventorySource>;

#[cfg(test)]
mod tests {
    use super::*;

    fn record(domain: &str, expires_at_unix: Option<i64>) -> CertificateRecord {
        CertificateRecord {
            domains: vec![domain.to_string()],
            sans: Vec::new(),
            issuer: "local".to_string(),
            expires_at_unix,
            source: "managed".to_string(),
            renewal_error: None,
        }
    }

    #[test]
    fn split_certificates_collectively_cover_a_multi_domain_intent() {
        let subjects = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        let records = vec![
            record("a.example.com", Some(100_000_000)),
            record("b.example.com", Some(200_000_000)),
        ];
        let (status, observation) = derive_intent_status(&subjects, &records, 0);
        assert_eq!(status, CertificateIntentStatus::Issued);
        assert_eq!(
            observation.and_then(|record| record.expires_at_unix),
            Some(200_000_000)
        );
    }

    #[test]
    fn one_uncovered_subject_makes_the_intent_pending() {
        let subjects = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        let records = vec![record("a.example.com", Some(1_000))];
        assert_eq!(
            derive_intent_status(&subjects, &records, 0).0,
            CertificateIntentStatus::Pending
        );
    }

    #[test]
    fn a_record_without_expiry_is_issued_and_not_made_up() {
        let subjects = vec!["a.example.com".to_string()];
        let records = vec![record("a.example.com", None)];
        let (status, observation) = derive_intent_status(&subjects, &records, i64::MAX);
        assert_eq!(status, CertificateIntentStatus::Issued);
        assert_eq!(observation.and_then(|record| record.expires_at_unix), None);
    }

    #[test]
    fn a_renewal_error_on_any_covering_record_wins() {
        let subjects = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        let mut failing = record("b.example.com", Some(5_000));
        failing.renewal_error = Some("rate limited".to_string());
        let records = vec![record("a.example.com", Some(4_000)), failing];
        assert_eq!(
            derive_intent_status(&subjects, &records, 0).0,
            CertificateIntentStatus::RenewalError
        );
    }

    #[test]
    fn id_exhaustion_and_conflicts_are_typed_409s() {
        assert_eq!(
            map_policy_error(PolicyError::IdExhausted).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            map_policy_error(PolicyError::AlreadyExists(4)).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            map_policy_error(PolicyError::IdRetired(4)).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            map_policy_error(PolicyError::InvalidDocument("bad".to_string())).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
