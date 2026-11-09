//! Certificate intent recording and inventory-derived status.
//!
//! # What this slice does
//!
//! `POST /api/v1/certificates/intent` records a certificate **intent** as an eager
//! [`AutoCertificatePolicy`]. It never performs ACME issuance, stores no PEM or private key and
//! returns no secret material. The policy is compiled into Caddy TLS automation by
//! [`caddy_rs_pm_config::assemble_with_tls`] (through [`PmRuntime::assemble`]).
//!
//! `POST /api/v1/certificates/custom` accepts a PEM certificate chain and private key, validates
//! them (see [`caddy_rs_pm_certificates::validate_manual_certificate`]), stores metadata with
//! origin `manual` and writes the key to a separate `0600` file below `<data>/pm/secrets/`. The
//! key never appears in a response, an error or the state document. A stored manual certificate is
//! reported `pending`: this slice assembles `load_files`, but it has no apply path and never
//! fabricates an `issued` status.
//!
//! `GET /api/v1/certificates` lists recorded intents and manual certificates. Intent status is
//! derived from an injected [`CertificateInventorySource`]. The PM does not own issuance state: the
//! daemon that owns the caddy-rs admin URL implements the trait against `/runtime/inventory`.
//! Without a source the inventory is empty, so every intent is reported as `pending`; nothing is
//! ever fabricated. Manual entries are `pending` (or `expired` once their notAfter has passed).
//!
//! Because intent and manual ids are allocated in separate namespaces, `/certificates/{id}` is
//! ambiguous when both exist. It returns a typed `409`; use `/certificates/intent/{id}` or
//! `/certificates/custom/{id}` for an unambiguous read.
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
use caddy_rs_pm_certificates::{CertificateError, StoredCertificate};
use caddy_rs_pm_core::{
    normalize_domain, pattern_covers, AcmeChallenge, AutoCertificatePolicy, AutoMode,
    CertificateId, CertificateOrigin, KeyType, PolicyId,
};
use caddy_rs_pm_policies::{PolicyError, StoredPolicy};
use caddy_rs_pm_state::StateError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hosts::LocalPeer;
use crate::{evaluate_get_preconditions, require_if_match, ApiError, ApiState, PaginationParams};

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
    /// Always `auto_generated`; present so a mixed list is self-describing.
    #[serde(default = "default_auto_origin")]
    pub origin: CertificateOrigin,
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

fn default_auto_origin() -> CertificateOrigin {
    CertificateOrigin::AutoGenerated
}

/// One manual-certificate list/detail item. Contains metadata only; never PEM or key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualCertificateSummary {
    pub id: u64,
    pub origin: CertificateOrigin,
    pub name: String,
    pub domains: Vec<String>,
    pub status: CertificateIntentStatus,
    pub revision: u64,
    pub key_type: KeyType,
    pub fingerprint_sha256: String,
    pub not_before_unix: i64,
    pub expires_at_unix: i64,
    pub created_at_unix: i64,
}

/// A mixed certificate list entry. Intent members serialize exactly like
/// [`CertificateIntentSummary`], so existing clients keep working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum CertificateSummary {
    Intent(CertificateIntentSummary),
    Manual(ManualCertificateSummary),
}

impl CertificateSummary {
    fn id(&self) -> u64 {
        match self {
            Self::Intent(summary) => summary.policy_id,
            Self::Manual(summary) => summary.id,
        }
    }

    fn origin_rank(&self) -> u8 {
        match self {
            Self::Intent(_) => 1,
            Self::Manual(_) => 0,
        }
    }

    fn domains(&self) -> &[String] {
        match self {
            Self::Intent(summary) => &summary.domains,
            Self::Manual(summary) => &summary.domains,
        }
    }

    fn status(&self) -> CertificateIntentStatus {
        match self {
            Self::Intent(summary) => summary.status,
            Self::Manual(summary) => summary.status,
        }
    }
}

/// `POST /api/v1/certificates/custom` body. Unknown fields (including NPM's legacy certificate
/// fields) are rejected rather than ignored. `privateKey` is never echoed by any response.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomCertificateRequest {
    pub domains: Vec<String>,
    pub certificate: String,
    pub private_key: String,
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
        origin: CertificateOrigin::AutoGenerated,
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

/// `GET /api/v1/certificates` — paginated, filterable list of intents and manual certificates.
pub async fn list_handler(
    State(state): State<ApiState>,
    query: Result<Query<HashMap<String, String>>, QueryRejection>,
) -> Result<Json<crate::PaginatedResponse<CertificateSummary>>, ApiError> {
    let filter = parse_list_query(query)?;
    let records = records_for(&state)?;
    let now = now_unix();
    let policies = state.runtime.policies().list().map_err(map_policy_error)?;
    let manual = state
        .runtime
        .certificates()
        .list()
        .map_err(map_certificate_error)?;

    let mut summaries: Vec<CertificateSummary> = policies
        .iter()
        .map(|entry| CertificateSummary::Intent(summary_for(entry, &records, now)))
        .chain(
            manual
                .iter()
                .map(|entry| CertificateSummary::Manual(manual_summary(entry, now))),
        )
        .filter(|summary| {
            filter.domain.as_ref().is_none_or(|needle| {
                let needle = needle.to_ascii_lowercase();
                summary
                    .domains()
                    .iter()
                    .any(|domain| domain.to_ascii_lowercase().contains(&needle))
            })
        })
        .filter(|summary| filter.status.is_none_or(|value| summary.status() == value))
        .collect();
    // Deterministic mixed order: numeric id first, manual before an intent at the same id.
    summaries.sort_by_key(|summary| (summary.id(), summary.origin_rank()));

    Ok(Json(filter.page.paginate(&summaries)))
}

fn intent_detail_response(
    state: &ApiState,
    id: u64,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let stored = state
        .runtime
        .policies()
        .get(PolicyId(id))
        .map_err(map_policy_error)?
        .ok_or_else(|| ApiError::NotFound(format!("certificate intent {id}")))?;
    let records = records_for(state)?;
    let summary = summary_for(&stored, &records, now_unix());
    let etag = summary_etag(&summary)?;
    if let Some(response) = evaluate_get_preconditions(headers, &etag)? {
        return Ok(response);
    }
    let mut response = Json(summary).into_response();
    set_intent_headers(&mut response, &etag);
    Ok(response)
}

/// `GET /api/v1/certificates/{id}` — one intent or manual certificate.
///
/// Intent and manual ids are allocated independently, so a shared id is ambiguous. That case is a
/// typed `409`; use `/certificates/intent/{id}` or `/certificates/custom/{id}` instead.
pub async fn get_handler(
    State(state): State<ApiState>,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let Path(id) = path.map_err(|rejection| {
        ApiError::validation(
            format!("invalid certificate id: {}", rejection.body_text()),
            "id",
        )
    })?;
    if id == 0 {
        return Err(ApiError::validation(
            "certificate id must be greater than zero",
            "id",
        ));
    }
    let manual = state
        .runtime
        .certificates()
        .get(CertificateId(id))
        .map_err(map_certificate_error)?;
    let policy = state
        .runtime
        .policies()
        .get(PolicyId(id))
        .map_err(map_policy_error)?;
    match (manual, policy) {
        (Some(_), Some(_)) => Err(ApiError::Conflict(format!(
            "certificate id {id} exists as both a manual certificate and an intent; use \
             /api/v1/certificates/custom/{id} or /api/v1/certificates/intent/{id}"
        ))),
        (Some(manual), None) => manual_detail_response(&manual, &headers),
        (None, Some(_)) => intent_detail_response(&state, id, &headers),
        (None, None) => Err(ApiError::NotFound(format!("certificate {id}"))),
    }
}

/// `GET /api/v1/certificates/intent/{id}` — unambiguous intent detail.
pub async fn get_intent_handler(
    State(state): State<ApiState>,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_certificate_id(path, "intent")?;
    intent_detail_response(&state, id, &headers)
}

fn map_certificate_error(error: CertificateError) -> ApiError {
    match error {
        CertificateError::Validation(error) => {
            ApiError::validation(error.to_string(), error.location())
        }
        CertificateError::NotFound(id) => ApiError::NotFound(format!("manual certificate {id}")),
        CertificateError::AlreadyExists(id) | CertificateError::IdRetired(id) => {
            ApiError::Conflict(format!("manual certificate id {id} is not available"))
        }
        CertificateError::IdExhausted => {
            ApiError::Conflict("manual certificate ids are exhausted".to_string())
        }
        CertificateError::State(StateError::Conflict { .. }) => ApiError::Conflict(
            "the certificate store changed concurrently; retry the request".to_string(),
        ),
        CertificateError::State(error) => ApiError::Internal(error.to_string()),
        CertificateError::Json(error) => ApiError::Internal(error.to_string()),
        CertificateError::InvalidDocument(error) => ApiError::Internal(error),
        CertificateError::UnsafeSecretPath { path, reason } => ApiError::Internal(format!(
            "unsafe certificate secret path {}: {reason}",
            path.display()
        )),
        CertificateError::SecretFile { path, source } => ApiError::Internal(format!(
            "certificate secret file {}: {source}",
            path.display()
        )),
    }
}

fn manual_summary(stored: &StoredCertificate, now_unix: i64) -> ManualCertificateSummary {
    let certificate = &stored.certificate;
    let status = if certificate.expires_at_unix <= now_unix {
        CertificateIntentStatus::Expired
    } else if certificate.status == caddy_rs_pm_core::CertificateStatus::Issued {
        // Only a verified config apply advances the stored status; storing bytes alone stays
        // pending. This keeps the API from claiming a certificate is live before `/load`.
        CertificateIntentStatus::Issued
    } else {
        CertificateIntentStatus::Pending
    };
    let mut name = match certificate.domains.len() {
        0 => "Custom certificate".to_string(),
        1 => format!("Custom certificate for {}", certificate.domains[0]),
        count => format!(
            "Custom certificate for {} (+{} more)",
            certificate.domains[0],
            count - 1
        ),
    };
    if name.chars().count() > 120 {
        name = name.chars().take(120).collect();
    }
    ManualCertificateSummary {
        id: certificate.id.0,
        origin: CertificateOrigin::Manual,
        name,
        domains: certificate.domains.clone(),
        status,
        revision: stored.revision,
        key_type: certificate.key_type,
        fingerprint_sha256: certificate.fingerprint_sha256.clone(),
        not_before_unix: certificate.not_before_unix,
        expires_at_unix: certificate.expires_at_unix,
        created_at_unix: certificate.created_at_unix,
    }
}

fn manual_etag(stored: &StoredCertificate) -> String {
    format!("\"m{}-r{}\"", stored.certificate.id.0, stored.revision)
}

fn set_manual_headers(response: &mut Response, etag: &str) {
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// `POST /api/v1/certificates/custom`.
pub async fn create_custom_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    body: Result<Json<CustomCertificateRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request = parse_json(body)?;
    let now = now_unix();
    let material = caddy_rs_pm_certificates::validate_manual_certificate(
        &request.certificate,
        &request.private_key,
        &request.domains,
        now,
    )
    .map_err(|error| ApiError::validation(error.to_string(), error.location()))?;
    let stored = state
        .runtime
        .certificates()
        .create(material, now)
        .map_err(map_certificate_error)?;
    let summary = manual_summary(&stored, now);
    debug_assert_eq!(summary.status, CertificateIntentStatus::Pending);

    let etag = manual_etag(&stored);
    let location = format!("/api/v1/certificates/custom/{}", stored.certificate.id.0);
    let mut response = (StatusCode::CREATED, Json(summary)).into_response();
    set_manual_headers(&mut response, &etag);
    let value = HeaderValue::from_str(&location)
        .map_err(|error| ApiError::Internal(format!("location header: {error}")))?;
    response.headers_mut().insert(header::LOCATION, value);
    Ok(response)
}

fn parse_certificate_id(
    path: Result<Path<u64>, PathRejection>,
    kind: &str,
) -> Result<u64, ApiError> {
    let Path(id) = path.map_err(|rejection| {
        ApiError::validation(
            format!("invalid {kind} certificate id: {}", rejection.body_text()),
            "id",
        )
    })?;
    if id == 0 {
        return Err(ApiError::validation(
            format!("{kind} certificate id must be greater than zero"),
            "id",
        ));
    }
    Ok(id)
}

fn manual_detail_response(
    stored: &StoredCertificate,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let etag = manual_etag(stored);
    if let Some(response) = evaluate_get_preconditions(headers, &etag)? {
        return Ok(response);
    }
    let mut response = Json(manual_summary(stored, now_unix())).into_response();
    set_manual_headers(&mut response, &etag);
    Ok(response)
}

/// `GET /api/v1/certificates/custom/{id}`.
pub async fn get_custom_handler(
    State(state): State<ApiState>,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_certificate_id(path, "manual")?;
    let stored = state
        .runtime
        .certificates()
        .get(CertificateId(id))
        .map_err(map_certificate_error)?
        .ok_or_else(|| ApiError::NotFound(format!("manual certificate {id}")))?;
    manual_detail_response(&stored, &headers)
}

/// `DELETE /api/v1/certificates/custom/{id}`.
///
/// Requires a strong `If-Match`. Refuses to delete a certificate referenced by a stored host;
/// the host check and the metadata delete are separate transactions, so a concurrent host create
/// can still race the delete. That narrow window is documented rather than hidden.
pub async fn delete_custom_handler(
    State(state): State<ApiState>,
    _peer: LocalPeer,
    path: Result<Path<u64>, PathRejection>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let id = parse_certificate_id(path, "manual")?;
    let stored = state
        .runtime
        .certificates()
        .get(CertificateId(id))
        .map_err(map_certificate_error)?
        .ok_or_else(|| ApiError::NotFound(format!("manual certificate {id}")))?;
    let etag = manual_etag(&stored);
    require_if_match(&headers, &etag)?;

    let hosts = state.runtime.hosts().list().map_err(|error| {
        ApiError::Internal(format!("read hosts before certificate delete: {error}"))
    })?;
    if let Some(host) = hosts.iter().find(|host| {
        host.host.tls.mode != caddy_rs_pm_core::TlsMode::Disabled
            && host.host.tls.certificate_id == Some(CertificateId(id))
    }) {
        return Err(ApiError::Conflict(format!(
            "manual certificate {id} is referenced by host {}; remove or retarget the host first",
            host.host.id.0
        )));
    }

    state
        .runtime
        .certificates()
        .delete(CertificateId(id), stored.revision)
        .map_err(map_certificate_error)?;
    Ok(StatusCode::NO_CONTENT)
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
