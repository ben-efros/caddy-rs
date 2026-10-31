//! Cloudflare DNS-01 provider (Cloudflare API v4).
//!
//! Implements the [`DnsProvider`] trait against the Cloudflare v4 API:
//!
//! * zone discovery by domain suffix (`GET /zones?name=<candidate>`), cached per provider
//!   instance;
//! * TXT record create (`POST /zones/<zone>/dns_records`), list
//!   (`GET /zones/<zone>/dns_records?type=TXT&name=<fqdn>`) and delete
//!   (`DELETE /zones/<zone>/dns_records/<id>`);
//! * bearer-token authentication (`api_token`) and the legacy global-key authentication
//!   (`email` + `api_key`);
//! * idempotent cleanup: deleting a record Cloudflare no longer knows about (HTTP 404 or error
//!   code 81044) is reported as success, so challenge cleanup can be retried safely;
//! * typed [`DnsError`]s; secrets are redacted from `Debug` output and never included in errors.
//!
//! # Transport
//!
//! All HTTP goes through the crate's transport-neutral [`AcmeTransport`] (a request/response
//! trait). Production code plugs in a real HTTP client; tests use a scripted mock. This module
//! performs no network I/O itself.
//!
//! # Configuration
//!
//! Provider settings come from Caddy's `challenges.dns.provider` module object, i.e. the
//! `dns.providers.cloudflare` module settings:
//!
//! ```json
//! { "name": "cloudflare", "api_token": "{env.CF_API_TOKEN}" }
//! ```
//!
//! `{$CF_API_TOKEN}` and `{env.CF_API_TOKEN:default}` placeholder forms are also resolved, matching
//! the Caddyfile env-placeholder style. A missing variable without a default is a located
//! configuration error naming the variable; the variable value itself is never echoed.
//!
//! Deliberate limitations (reported as divergences from Caddy v2.11.7 + caddy-dns/cloudflare):
//!
//! * only the `api_token` and legacy `email`/`api_key` authentication methods are supported;
//! * no live HTTP client is wired here ([`AcmeTransport`] is the boundary), and the
//!   `dns.providers` module registry is not implemented in this build;
//! * TXT values longer than 255 characters (multi-string records) are not chunked: ACME DNS-01
//!   values are ~43 characters, and Cloudflare handles values up to the API limit verbatim.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::RwLock;
use std::time::Duration;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::acme::{AcmeTransport, HttpMethod, HttpRequest, HttpResponse};
use crate::dns::{
    validate_record_name, zone_candidates, DnsChallengeConfig, DnsError, DnsProvider, DnsResult,
    RecordId, TxtRecord,
};

/// Module name Caddy uses for this provider (`dns.providers.cloudflare`).
pub const CLOUDFLARE_PROVIDER_NAME: &str = "cloudflare";

/// Base URL of the Cloudflare API v4.
pub const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare rejects TXT TTLs between 1 and 59 seconds; use automatic TTL (1) or >= 60.
pub const CLOUDFLARE_MIN_TTL_SECONDS: u32 = 60;

/// Cloudflare error code returned when a DNS record does not exist.
const CLOUDFLARE_NOT_FOUND_CODE: i64 = 81044;

/// Cloudflare error code returned when the same record already exists.
const CLOUDFLARE_DUPLICATE_RECORD_CODE: i64 = 81058;

/// Upper bound on pagination loops for record listings (defensive against a misbehaving server).
const MAX_LIST_PAGES: u32 = 100;

/// Authentication method for the Cloudflare API.
#[derive(Clone)]
enum CloudflareAuth {
    /// API token, sent as `Authorization: Bearer <token>` (recommended).
    BearerToken(String),
    /// Legacy global API key, sent as `X-Auth-Email` / `X-Auth-Key`.
    LegacyKey { email: String, api_key: String },
}

impl CloudflareAuth {
    fn description(&self) -> &'static str {
        match self {
            Self::BearerToken(_) => "bearer API token (redacted)",
            Self::LegacyKey { .. } => "legacy email/API key (redacted)",
        }
    }

    fn headers(&self) -> Vec<(String, String)> {
        match self {
            Self::BearerToken(token) => {
                vec![("Authorization".to_string(), format!("Bearer {token}"))]
            }
            Self::LegacyKey { email, api_key } => vec![
                ("X-Auth-Email".to_string(), email.clone()),
                ("X-Auth-Key".to_string(), api_key.clone()),
            ],
        }
    }
}

// Never derive Debug for authentication material: it would leak tokens into logs.
impl fmt::Debug for CloudflareAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

/// Cloudflare provider configuration (authentication).
///
/// Construct from Caddy's module settings with [`CloudflareConfig::from_settings`], or directly
/// with [`CloudflareConfig::api_token`] / [`CloudflareConfig::legacy_key`].
#[derive(Clone)]
pub struct CloudflareConfig {
    auth: CloudflareAuth,
}

impl CloudflareConfig {
    /// Bearer API-token authentication.
    pub fn api_token(token: impl Into<String>) -> Self {
        Self {
            auth: CloudflareAuth::BearerToken(token.into()),
        }
    }

    /// Legacy global-key authentication (`email` + `api_key`).
    pub fn legacy_key(email: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            auth: CloudflareAuth::LegacyKey {
                email: email.into(),
                api_key: api_key.into(),
            },
        }
    }

    /// Parse Cloudflare provider settings from the Caddy `dns.providers.cloudflare` module object
    /// (the contents of `challenges.dns.provider` after `name` is removed).
    ///
    /// Exactly one authentication method is required: `api_token`, or `email` + `api_key`.
    /// String values may contain `{env.NAME}`, `{$NAME}`, `{env.NAME:default}` and
    /// `{$NAME:default}` placeholders, resolved against the process environment.
    pub fn from_settings(settings: &Map<String, Value>) -> DnsResult<Self> {
        let api_token = optional_string(settings, "api_token")?;
        let email = optional_string(settings, "email")?;
        let api_key = optional_string(settings, "api_key")?;

        match (api_token, email, api_key) {
            (Some(token), None, None) => {
                if token.trim().is_empty() {
                    return Err(config_error(
                        "Cloudflare provider `api_token` must not be empty",
                    ));
                }
                Ok(Self::api_token(token))
            }
            (Some(_), _, _) => Err(config_error(
                "Cloudflare provider settings must use either `api_token` or `email` + `api_key`, \
                 not both",
            )),
            (None, Some(email), Some(api_key)) => {
                if email.trim().is_empty() {
                    return Err(config_error(
                        "Cloudflare provider `email` must not be empty",
                    ));
                }
                if api_key.trim().is_empty() {
                    return Err(config_error(
                        "Cloudflare provider `api_key` must not be empty",
                    ));
                }
                Ok(Self::legacy_key(email, api_key))
            }
            (None, Some(_), None) | (None, None, Some(_)) => Err(config_error(
                "Cloudflare provider legacy authentication requires both `email` and `api_key`",
            )),
            (None, None, None) => Err(config_error(
                "Cloudflare provider requires an `api_token` (or `email` + `api_key`)",
            )),
        }
    }

    /// Alias for [`CloudflareConfig::from_settings`] naming the Caddy JSON shape explicitly.
    pub fn from_caddy_settings(settings: &Map<String, Value>) -> DnsResult<Self> {
        Self::from_settings(settings)
    }

    /// Authentication method description (never the secret itself).
    pub fn auth_description(&self) -> &'static str {
        self.auth.description()
    }
}

impl fmt::Debug for CloudflareConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareConfig")
            .field("auth", &self.auth)
            .field("api_base", &CLOUDFLARE_API_BASE)
            .finish()
    }
}

/// Resolve `{env.NAME}` / `{$NAME}` (optionally with `:default`) placeholders in a configuration
/// string using the process environment.
///
/// Strings without placeholders are returned unchanged. A reference to an unset variable without
/// a default produces a [`DnsError::Config`] that names the variable but never its value.
pub fn resolve_env_placeholders(value: &str) -> DnsResult<String> {
    resolve_env_placeholders_with(value, |name| std::env::var(name).ok())
}

fn resolve_env_placeholders_with(
    value: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> DnsResult<String> {
    let mut output = String::with_capacity(value.len());
    let mut position = 0;
    while let Some(relative_open) = value[position..].find('{') {
        let open = position + relative_open;
        output.push_str(&value[position..open]);
        let Some(relative_close) = value[open..].find('}') else {
            // Not a complete placeholder; keep the remainder verbatim.
            output.push_str(&value[open..]);
            return Ok(output);
        };
        let close = open + relative_close;
        let inner = &value[open + 1..close];
        let reference = if let Some(spec) = inner.strip_prefix("env.") {
            Some(spec)
        } else {
            inner.strip_prefix('$')
        };
        match reference {
            Some(spec) => {
                let (name, default) = match spec.split_once(':') {
                    Some((name, default)) => (name, Some(default)),
                    None => (spec, None),
                };
                if name.is_empty() {
                    return Err(config_error(
                        "Cloudflare provider configuration contains an empty environment variable \
                         reference",
                    ));
                }
                match lookup(name) {
                    Some(resolved) => output.push_str(&resolved),
                    None => match default {
                        Some(default) => output.push_str(default),
                        None => {
                            return Err(config_error(format!(
                                "environment variable `{name}` referenced by the Cloudflare \
                                 provider is not set"
                            )))
                        }
                    },
                }
            }
            // Unknown placeholder syntax is preserved literally.
            None => output.push_str(&value[open..=close]),
        }
        position = close + 1;
    }
    output.push_str(&value[position..]);
    Ok(output)
}

fn optional_string(settings: &Map<String, Value>, field: &str) -> DnsResult<Option<String>> {
    match settings.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(resolve_env_placeholders(value)?)),
        Some(_) => Err(config_error(format!(
            "Cloudflare provider setting `{field}` must be a string"
        ))),
    }
}

fn config_error(message: impl Into<String>) -> DnsError {
    DnsError::Config {
        message: message.into(),
    }
}

fn provider_error(message: impl Into<String>) -> DnsError {
    DnsError::Provider {
        provider: CLOUDFLARE_PROVIDER_NAME.to_string(),
        message: message.into(),
    }
}

/// Cloudflare API response envelope (`{ success, errors, result, result_info }`).
#[derive(Debug, Deserialize)]
struct ApiEnvelope<R> {
    success: bool,
    errors: Vec<ApiError>,
    result: Option<R>,
    result_info: Option<ResultInfo>,
}

/// The envelope as it appears on the wire: `result` is decoded separately so a missing or `null`
/// result is valid regardless of the concrete result type.
#[derive(Debug, Deserialize)]
struct RawApiEnvelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct ResultInfo {
    #[serde(default)]
    total_pages: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct CloudflareZone {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CloudflareDnsRecord {
    id: String,
    name: String,
    content: String,
    #[serde(default, rename = "type")]
    record_type: Option<String>,
}

/// Cloudflare DNS-01 provider.
///
/// The HTTP transport is generic so tests can drive the provider with a scripted mock; any
/// [`AcmeTransport`] implementation (including a future hyper-backed client) can be plugged in.
pub struct CloudflareProvider<T: AcmeTransport> {
    transport: T,
    config: CloudflareConfig,
    ttl_seconds: Option<u32>,
    /// Positive zone lookup cache: zone name (lowercase) -> Cloudflare zone.
    zone_cache: RwLock<BTreeMap<String, CloudflareZone>>,
}

impl<T: AcmeTransport> CloudflareProvider<T> {
    /// Create a provider for `config` using `transport`.
    pub fn new(transport: T, config: CloudflareConfig) -> Self {
        Self {
            transport,
            config,
            ttl_seconds: None,
            zone_cache: RwLock::new(BTreeMap::new()),
        }
    }

    /// Create a provider from Caddy's `challenges.dns` configuration.
    ///
    /// The provider must be `cloudflare`; authentication comes from the module settings and the
    /// record TTL from `challenges.dns.ttl` (0 means Cloudflare's automatic TTL).
    pub fn from_challenge_config(transport: T, challenge: &DnsChallengeConfig) -> DnsResult<Self> {
        if challenge.provider != CLOUDFLARE_PROVIDER_NAME {
            return Err(config_error(format!(
                "expected the `{CLOUDFLARE_PROVIDER_NAME}` DNS provider, got `{}`",
                challenge.provider
            )));
        }
        let config = CloudflareConfig::from_settings(&challenge.settings)?;
        let ttl_seconds = challenge
            .ttl
            .map(ttl_seconds_from_duration)
            .transpose()?
            .flatten();
        Ok(Self::new(transport, config).with_ttl_seconds(ttl_seconds))
    }

    /// Override the TXT record TTL. `None` means Cloudflare's default (automatic) TTL.
    pub fn with_ttl_seconds(mut self, ttl_seconds: Option<u32>) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }

    /// The configured TXT record TTL in seconds (`None` = automatic).
    pub fn ttl_seconds(&self) -> Option<u32> {
        self.ttl_seconds
    }

    /// The provider configuration (secrets remain redacted when formatted with `Debug`).
    pub fn config(&self) -> &CloudflareConfig {
        &self.config
    }

    fn request_headers(&self, json_body: bool) -> Vec<(String, String)> {
        let mut headers = vec![("Accept".to_string(), "application/json".to_string())];
        headers.extend(self.config.auth.headers());
        if json_body {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }
        headers
    }

    async fn send(&self, request: HttpRequest) -> DnsResult<HttpResponse> {
        self.transport
            .request(request)
            .await
            .map_err(|error| provider_error(format!("transport error: {error}")))
    }

    fn decode<R: DeserializeOwned>(
        &self,
        url: &str,
        response: &HttpResponse,
    ) -> DnsResult<ApiEnvelope<R>> {
        let raw: RawApiEnvelope = serde_json::from_slice(&response.body).map_err(|error| {
            provider_error(format!(
                "invalid Cloudflare API response for `{url}` (HTTP {}): {error}",
                response.status
            ))
        })?;
        let result = match raw.result {
            Some(value) => Some(serde_json::from_value::<R>(value).map_err(|error| {
                provider_error(format!(
                    "invalid Cloudflare API result for `{url}` (HTTP {}): {error}",
                    response.status
                ))
            })?),
            None => None,
        };
        Ok(ApiEnvelope {
            success: raw.success,
            errors: raw.errors,
            result,
            result_info: raw.result_info,
        })
    }

    /// Build a typed error from a failed response without echoing request headers.
    fn http_error(&self, url: &str, response: &HttpResponse) -> DnsError {
        let errors = serde_json::from_slice::<RawApiEnvelope>(&response.body)
            .map(|envelope| envelope.errors)
            .unwrap_or_default();
        let detail = if errors.is_empty() {
            "no API error details".to_string()
        } else {
            errors
                .iter()
                .map(|error| format!("{}: {}", error.code, error.message))
                .collect::<Vec<_>>()
                .join("; ")
        };
        provider_error(format!("HTTP {} for `{url}` ({detail})", response.status))
    }

    fn ensure_success<R>(
        &self,
        url: &str,
        response: &HttpResponse,
        envelope: &ApiEnvelope<R>,
    ) -> DnsResult<()> {
        if response.is_success() && envelope.success {
            Ok(())
        } else {
            Err(self.http_error(url, response))
        }
    }

    async fn list_zones(&self, candidate: &str) -> DnsResult<Vec<CloudflareZone>> {
        let url = format!("{CLOUDFLARE_API_BASE}/zones?name={candidate}&per_page=50");
        let request = HttpRequest {
            method: HttpMethod::Get,
            url: url.clone(),
            headers: self.request_headers(false),
            body: Vec::new(),
        };
        let response = self.send(request).await?;
        if !response.is_success() {
            return Err(self.http_error(&url, &response));
        }
        let envelope: ApiEnvelope<Vec<CloudflareZone>> = self.decode(&url, &response)?;
        self.ensure_success(&url, &response, &envelope)?;
        Ok(envelope.result.unwrap_or_default())
    }

    /// Find the Cloudflare zone that contains `fqdn`, most specific first.
    async fn zone_for_fqdn(&self, fqdn: &str) -> DnsResult<CloudflareZone> {
        let candidates = cloudflare_zone_candidates(fqdn);
        {
            let cache = self
                .zone_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for candidate in &candidates {
                if let Some(zone) = cache.get(candidate) {
                    return Ok(zone.clone());
                }
            }
        }
        for candidate in candidates {
            let zones = self.list_zones(&candidate).await?;
            if let Some(zone) = zones
                .into_iter()
                .find(|zone| zone.name.eq_ignore_ascii_case(&candidate))
            {
                self.zone_cache
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(candidate.to_ascii_lowercase(), zone.clone());
                return Ok(zone);
            }
        }
        Err(DnsError::ZoneNotFound {
            provider: CLOUDFLARE_PROVIDER_NAME.to_string(),
            fqdn: fqdn.to_string(),
        })
    }

    /// Resolve a known zone name to its Cloudflare zone (used when deleting by recorded zone).
    async fn zone_by_name(&self, zone_name: &str) -> DnsResult<CloudflareZone> {
        let key = zone_name.to_ascii_lowercase();
        if let Some(zone) = self
            .zone_cache
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
        {
            return Ok(zone.clone());
        }
        let zones = self.list_zones(&key).await?;
        if let Some(zone) = zones
            .into_iter()
            .find(|zone| zone.name.eq_ignore_ascii_case(zone_name))
        {
            self.zone_cache
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(key, zone.clone());
            return Ok(zone);
        }
        Err(DnsError::ZoneNotFound {
            provider: CLOUDFLARE_PROVIDER_NAME.to_string(),
            fqdn: zone_name.to_string(),
        })
    }

    async fn delete_record(&self, zone: &CloudflareZone, record_id: &RecordId) -> DnsResult<()> {
        let url = format!(
            "{CLOUDFLARE_API_BASE}/zones/{}/dns_records/{}",
            zone.id, record_id
        );
        let request = HttpRequest {
            method: HttpMethod::Delete,
            url: url.clone(),
            headers: self.request_headers(false),
            body: Vec::new(),
        };
        let response = self.send(request).await?;
        let decoded: DnsResult<ApiEnvelope<Value>> = self.decode(&url, &response);
        let already_gone = response.status == 404
            || matches!(&decoded, Ok(envelope) if envelope
                .errors
                .iter()
                .any(|error| error.code == CLOUDFLARE_NOT_FOUND_CODE));
        if already_gone {
            // Idempotent cleanup: the challenge record is no longer present, which is success.
            return Ok(());
        }
        let envelope = match decoded {
            Ok(envelope) => envelope,
            Err(error) => {
                return Err(if response.is_success() {
                    error
                } else {
                    self.http_error(&url, &response)
                })
            }
        };
        self.ensure_success(&url, &response, &envelope)?;
        Ok(())
    }
}

impl<T: AcmeTransport> fmt::Debug for CloudflareProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareProvider")
            .field("provider", &CLOUDFLARE_PROVIDER_NAME)
            .field("config", &self.config)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<T: AcmeTransport> DnsProvider for CloudflareProvider<T> {
    fn name(&self) -> &str {
        CLOUDFLARE_PROVIDER_NAME
    }

    async fn find_zone(&self, fqdn: &str) -> DnsResult<String> {
        validate_record_name(fqdn)?;
        let fqdn = normalize_fqdn(fqdn);
        Ok(self.zone_for_fqdn(&fqdn).await?.name)
    }

    async fn create_txt(&self, fqdn: &str, value: &str) -> DnsResult<TxtRecord> {
        validate_record_name(fqdn)?;
        let fqdn = normalize_fqdn(fqdn);
        let zone = self.zone_for_fqdn(&fqdn).await?;
        let url = format!("{CLOUDFLARE_API_BASE}/zones/{}/dns_records", zone.id);
        let mut body = json!({
            "type": "TXT",
            "name": fqdn,
            "content": value,
        });
        if let Some(ttl) = self.ttl_seconds {
            body["ttl"] = json!(ttl);
        }
        let payload = serde_json::to_vec(&body)
            .map_err(|error| provider_error(format!("cannot encode TXT record body: {error}")))?;
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: url.clone(),
            headers: self.request_headers(true),
            body: payload,
        };
        let response = self.send(request).await?;
        let decoded: DnsResult<ApiEnvelope<CloudflareDnsRecord>> = self.decode(&url, &response);
        match decoded {
            Err(error) => Err(if response.is_success() {
                error
            } else {
                self.http_error(&url, &response)
            }),
            Ok(envelope) => {
                if envelope
                    .errors
                    .iter()
                    .any(|error| error.code == CLOUDFLARE_DUPLICATE_RECORD_CODE)
                {
                    return Err(DnsError::RecordExists {
                        fqdn,
                        value: value.to_string(),
                    });
                }
                self.ensure_success(&url, &response, &envelope)?;
                let record = envelope.result.ok_or_else(|| {
                    provider_error(format!(
                        "Cloudflare API response for `{url}` has no `result`"
                    ))
                })?;
                Ok(TxtRecord {
                    id: RecordId::new(record.id),
                    fqdn,
                    zone: zone.name,
                    value: normalize_txt_content(&record.content),
                })
            }
        }
    }

    async fn delete_txt(&self, record: &TxtRecord) -> DnsResult<()> {
        validate_record_name(&record.fqdn)?;
        let zone = self.zone_by_name(&record.zone).await?;
        self.delete_record(&zone, &record.id).await
    }

    async fn list_txt(&self, fqdn: &str) -> DnsResult<Vec<TxtRecord>> {
        validate_record_name(fqdn)?;
        let fqdn = normalize_fqdn(fqdn);
        let zone = self.zone_for_fqdn(&fqdn).await?;
        let mut records = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!(
                "{CLOUDFLARE_API_BASE}/zones/{}/dns_records?type=TXT&name={fqdn}&per_page=100&page={page}",
                zone.id
            );
            let request = HttpRequest {
                method: HttpMethod::Get,
                url: url.clone(),
                headers: self.request_headers(false),
                body: Vec::new(),
            };
            let response = self.send(request).await?;
            if !response.is_success() {
                return Err(self.http_error(&url, &response));
            }
            let envelope: ApiEnvelope<Vec<CloudflareDnsRecord>> = self.decode(&url, &response)?;
            self.ensure_success(&url, &response, &envelope)?;
            let result_info = envelope.result_info;
            for record in envelope.result.unwrap_or_default() {
                let is_txt = record
                    .record_type
                    .as_deref()
                    .map(|record_type| record_type.eq_ignore_ascii_case("TXT"))
                    .unwrap_or(true);
                if is_txt && record.name.eq_ignore_ascii_case(&fqdn) {
                    records.push(TxtRecord {
                        id: RecordId::new(record.id),
                        fqdn: fqdn.clone(),
                        zone: zone.name.clone(),
                        value: normalize_txt_content(&record.content),
                    });
                }
            }
            let total_pages = result_info.map(|info| info.total_pages.max(1)).unwrap_or(1);
            if page >= total_pages || page >= MAX_LIST_PAGES {
                break;
            }
            page += 1;
        }
        Ok(records)
    }
}

fn normalize_fqdn(fqdn: &str) -> String {
    fqdn.trim_end_matches('.').to_ascii_lowercase()
}

/// Zone candidates that Cloudflare could plausibly own.
///
/// DNS zones never contain labels that start with `_` (e.g. `_acme-challenge`), so those
/// candidates are removed before querying the API; this also avoids asking Cloudflare to validate
/// underscore-led names as zone names.
fn cloudflare_zone_candidates(fqdn: &str) -> Vec<String> {
    zone_candidates(fqdn)
        .into_iter()
        .filter(|candidate| {
            candidate
                .split('.')
                .all(|label| !label.is_empty() && !label.starts_with('_'))
        })
        .collect()
}

/// Convert Caddy's challenge TTL duration to Cloudflare's TTL seconds.
///
/// `0` (Caddy's default) means automatic TTL; Cloudflare requires >= 60 seconds otherwise.
fn ttl_seconds_from_duration(ttl: Duration) -> DnsResult<Option<u32>> {
    let seconds = ttl.as_secs();
    if seconds == 0 {
        return Ok(None);
    }
    if seconds < u64::from(CLOUDFLARE_MIN_TTL_SECONDS) {
        return Err(config_error(format!(
            "Cloudflare requires a TXT record TTL of 0 (automatic) or at least \
             {CLOUDFLARE_MIN_TTL_SECONDS} seconds, got {seconds}s"
        )));
    }
    u32::try_from(seconds)
        .map(Some)
        .map_err(|_| config_error(format!("TXT record TTL {seconds}s is too large")))
}

/// Cloudflare returns TXT content with surrounding double quotes for some record forms; strip one
/// surrounding pair so propagation comparisons use the plain value.
fn normalize_txt_content(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use serde_json::json;

    // ---------------------------------------------------------------------------------------------
    // Scripted transport
    // ---------------------------------------------------------------------------------------------

    struct ScriptedResponse {
        status: u16,
        body: Vec<u8>,
    }

    #[derive(Default)]
    struct ScriptedTransport {
        responses: Mutex<VecDeque<ScriptedResponse>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl ScriptedTransport {
        fn new() -> Self {
            Self::default()
        }

        fn expect_json(&self, status: u16, body: Value) {
            self.responses.lock().unwrap().push_back(ScriptedResponse {
                status,
                body: serde_json::to_vec(&body).unwrap(),
            });
        }

        fn expect_raw(&self, status: u16, body: impl Into<Vec<u8>>) {
            self.responses.lock().unwrap().push_back(ScriptedResponse {
                status,
                body: body.into(),
            });
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AcmeTransport for ScriptedTransport {
        async fn request(&self, request: HttpRequest) -> crate::Result<HttpResponse> {
            self.requests.lock().unwrap().push(request);
            let response = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted transport ran out of responses");
            Ok(HttpResponse::new(response.status).with_body(response.body))
        }
    }

    /// Transport that fails every request below the HTTP layer.
    struct FailingTransport;

    #[async_trait]
    impl AcmeTransport for FailingTransport {
        async fn request(&self, _request: HttpRequest) -> crate::Result<HttpResponse> {
            Err(Error::Issuer("connection refused".to_string()))
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------

    fn ok(result: Value) -> Value {
        json!({ "success": true, "errors": [], "messages": [], "result": result })
    }

    fn api_failure(code: i64, message: &str) -> Value {
        json!({
            "success": false,
            "errors": [{ "code": code, "message": message }],
            "messages": [],
            "result": null
        })
    }

    fn zone_json(name: &str, id: &str) -> Value {
        json!({ "id": id, "name": name })
    }

    fn record_json(id: &str, name: &str, content: &str) -> Value {
        json!({ "id": id, "name": name, "content": content, "type": "TXT" })
    }

    fn provider(transport: ScriptedTransport) -> CloudflareProvider<ScriptedTransport> {
        CloudflareProvider::new(transport, CloudflareConfig::api_token("test-token-123"))
    }

    const ZONE_NAME: &str = "example.com";
    const RECORD_NAME: &str = "_acme-challenge.example.com";

    fn zone_lookup(transport: &ScriptedTransport) {
        transport.expect_json(200, ok(json!([zone_json(ZONE_NAME, "zone-1")])));
    }

    // ---------------------------------------------------------------------------------------------
    // Zone discovery
    // ---------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn zone_discovery_picks_most_specific_zone() {
        let transport = ScriptedTransport::new();
        transport.expect_json(200, ok(json!([zone_json("api.example.com", "zone-api")])));
        let provider = provider(transport);

        let zone = provider
            .find_zone("_acme-challenge.api.example.com")
            .await
            .unwrap();
        assert_eq!(zone, "api.example.com");
        let requests = provider.transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url,
            "https://api.cloudflare.com/client/v4/zones?name=api.example.com&per_page=50"
        );
        assert_eq!(
            requests[0].header("Authorization"),
            Some("Bearer test-token-123")
        );
        assert_eq!(requests[0].method, HttpMethod::Get);
    }

    #[tokio::test]
    async fn zone_discovery_falls_back_to_parent_zone() {
        let transport = ScriptedTransport::new();
        transport.expect_json(200, ok(json!([])));
        zone_lookup(&transport);
        let provider = provider(transport);

        let zone = provider
            .find_zone("_acme-challenge.api.example.com")
            .await
            .unwrap();
        assert_eq!(zone, ZONE_NAME);
        let requests = provider.transport.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].url.contains("name=api.example.com"));
        assert!(requests[1].url.contains("name=example.com"));
    }

    #[tokio::test]
    async fn zone_lookup_is_cached() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        let provider = provider(transport);

        assert_eq!(provider.find_zone(RECORD_NAME).await.unwrap(), ZONE_NAME);
        assert_eq!(provider.find_zone(RECORD_NAME).await.unwrap(), ZONE_NAME);
        assert_eq!(provider.transport.requests().len(), 1);
    }

    #[tokio::test]
    async fn zone_not_found_is_typed() {
        let transport = ScriptedTransport::new();
        transport.expect_json(200, ok(json!([])));
        let provider = provider(transport);

        let error = provider.find_zone(RECORD_NAME).await.unwrap_err();
        assert!(
            matches!(
                &error,
                DnsError::ZoneNotFound { provider, fqdn }
                    if provider == CLOUDFLARE_PROVIDER_NAME && fqdn == RECORD_NAME
            ),
            "unexpected error: {error:?}"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Create / list / delete
    // ---------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn create_list_delete_flow() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        transport.expect_json(200, ok(record_json("rec-1", RECORD_NAME, "token-value")));
        transport.expect_json(
            200,
            ok(json!([record_json("rec-1", RECORD_NAME, "token-value")])),
        );
        transport.expect_json(200, ok(json!({ "id": "rec-1" })));
        let provider = provider(transport);

        let record = provider
            .create_txt(RECORD_NAME, "token-value")
            .await
            .unwrap();
        assert_eq!(record.id, RecordId::new("rec-1"));
        assert_eq!(record.fqdn, RECORD_NAME);
        assert_eq!(record.zone, ZONE_NAME);
        assert_eq!(record.value, "token-value");

        let listed = provider.list_txt(RECORD_NAME).await.unwrap();
        assert_eq!(listed, vec![record.clone()]);

        provider.delete_txt(&record).await.unwrap();

        let requests = provider.transport.requests();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.method)
                .collect::<Vec<_>>(),
            vec![
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Get,
                HttpMethod::Delete
            ]
        );
        assert_eq!(
            requests[1].url,
            "https://api.cloudflare.com/client/v4/zones/zone-1/dns_records"
        );
        assert_eq!(requests[1].header("Content-Type"), Some("application/json"));
        let body: Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(
            body,
            json!({
                "type": "TXT",
                "name": RECORD_NAME,
                "content": "token-value"
            })
        );
        assert!(requests[2]
            .url
            .contains("/zones/zone-1/dns_records?type=TXT&name=_acme-challenge.example.com"));
        assert_eq!(
            requests[3].url,
            "https://api.cloudflare.com/client/v4/zones/zone-1/dns_records/rec-1"
        );
    }

    #[tokio::test]
    async fn ttl_is_sent_when_configured_from_challenge_config() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        transport.expect_json(200, ok(record_json("rec-1", RECORD_NAME, "token-value")));
        let challenge = DnsChallengeConfig::from_caddy_json(&json!({
            "provider": { "name": "cloudflare", "api_token": "test-token-123" },
            "ttl": 120_000_000_000_i64
        }))
        .unwrap();
        let provider = CloudflareProvider::from_challenge_config(transport, &challenge).unwrap();
        assert_eq!(provider.ttl_seconds(), Some(120));

        provider
            .create_txt(RECORD_NAME, "token-value")
            .await
            .unwrap();
        let requests = provider.transport.requests();
        let body: Value = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(body["ttl"], json!(120));
    }

    #[tokio::test]
    async fn duplicate_create_maps_to_record_exists() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        transport.expect_json(
            400,
            api_failure(CLOUDFLARE_DUPLICATE_RECORD_CODE, "Record already exists"),
        );
        let provider = provider(transport);

        let error = provider
            .create_txt(RECORD_NAME, "token-value")
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                DnsError::RecordExists { fqdn, value }
                    if fqdn == RECORD_NAME && value == "token-value"
            ),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn quoted_txt_content_is_normalized() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        transport.expect_json(
            200,
            ok(json!([record_json(
                "rec-1",
                RECORD_NAME,
                "\"token-value\""
            )])),
        );
        let provider = provider(transport);

        let listed = provider.list_txt(RECORD_NAME).await.unwrap();
        assert_eq!(listed[0].value, "token-value");
    }

    #[tokio::test]
    async fn list_paginates_when_the_api_reports_more_pages() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        transport.expect_json(
            200,
            json!({
                "success": true,
                "errors": [],
                "result": [record_json("rec-1", RECORD_NAME, "one")],
                "result_info": { "page": 1, "total_pages": 2 }
            }),
        );
        transport.expect_json(
            200,
            json!({
                "success": true,
                "errors": [],
                "result": [record_json("rec-2", RECORD_NAME, "two")],
                "result_info": { "page": 2, "total_pages": 2 }
            }),
        );
        let provider = provider(transport);

        let listed = provider.list_txt(RECORD_NAME).await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|record| record.value.as_str())
                .collect::<Vec<_>>(),
            vec!["one", "two"]
        );
        let requests = provider.transport.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].url.contains("page=1"));
        assert!(requests[2].url.contains("page=2"));
    }

    // ---------------------------------------------------------------------------------------------
    // Idempotent delete
    // ---------------------------------------------------------------------------------------------

    fn record_for_delete() -> TxtRecord {
        TxtRecord {
            id: RecordId::new("rec-1"),
            fqdn: RECORD_NAME.to_string(),
            zone: ZONE_NAME.to_string(),
            value: "token-value".to_string(),
        }
    }

    #[tokio::test]
    async fn delete_succeeds_when_record_is_already_gone() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        transport.expect_json(
            404,
            api_failure(CLOUDFLARE_NOT_FOUND_CODE, "Record does not exist"),
        );
        let provider = provider(transport);

        provider.delete_txt(&record_for_delete()).await.unwrap();
        let requests = provider.transport.requests();
        assert_eq!(requests[0].method, HttpMethod::Get);
        assert_eq!(requests[1].method, HttpMethod::Delete);
    }

    #[tokio::test]
    async fn delete_succeeds_on_404_with_non_json_body() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        transport.expect_raw(404, "not found".as_bytes().to_vec());
        let provider = provider(transport);

        provider.delete_txt(&record_for_delete()).await.unwrap();
    }

    #[tokio::test]
    async fn delete_twice_is_successful() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        transport.expect_json(200, ok(json!({ "id": "rec-1" })));
        transport.expect_json(
            404,
            api_failure(CLOUDFLARE_NOT_FOUND_CODE, "Record does not exist"),
        );
        let provider = provider(transport);
        let record = record_for_delete();

        provider.delete_txt(&record).await.unwrap();
        provider.delete_txt(&record).await.unwrap();
        let requests = provider.transport.requests();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.method)
                .collect::<Vec<_>>(),
            vec![HttpMethod::Get, HttpMethod::Delete, HttpMethod::Delete]
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Error mapping and secret redaction
    // ---------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn api_errors_map_to_typed_errors_without_leaking_tokens() {
        let transport = ScriptedTransport::new();
        transport.expect_json(
            403,
            api_failure(10000, "Authentication error: invalid token"),
        );
        let provider = provider(transport);

        let error = provider.find_zone(RECORD_NAME).await.unwrap_err();
        let message = error.to_string();
        assert!(matches!(error, DnsError::Provider { .. }), "{error:?}");
        assert!(message.contains("HTTP 403"), "{message}");
        assert!(message.contains("Authentication error"), "{message}");
        assert!(!message.contains("test-token-123"), "{message}");
    }

    #[tokio::test]
    async fn transport_failures_map_to_provider_errors() {
        let provider = CloudflareProvider::new(
            FailingTransport,
            CloudflareConfig::api_token("test-token-123"),
        );
        let error = provider.find_zone(RECORD_NAME).await.unwrap_err();
        assert!(matches!(error, DnsError::Provider { .. }), "{error:?}");
        assert!(error.to_string().contains("transport error"), "{error}");
        assert!(!error.to_string().contains("test-token-123"));
    }

    #[tokio::test]
    async fn malformed_response_body_is_a_provider_error() {
        let transport = ScriptedTransport::new();
        transport.expect_raw(502, "<html>bad gateway</html>".as_bytes().to_vec());
        let provider = provider(transport);

        let error = provider.find_zone(RECORD_NAME).await.unwrap_err();
        let message = error.to_string();
        assert!(matches!(error, DnsError::Provider { .. }), "{error:?}");
        assert!(message.contains("HTTP 502"), "{message}");
        assert!(!message.contains("test-token-123"), "{message}");
    }

    #[test]
    fn config_and_provider_debug_output_redacts_secrets() {
        let config = CloudflareConfig::api_token("super-secret-token");
        let debug = format!("{config:?}");
        assert!(!debug.contains("super-secret-token"), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");

        let legacy = CloudflareConfig::legacy_key("me@example.com", "super-secret-key");
        let debug = format!("{legacy:?}");
        assert!(!debug.contains("super-secret-key"), "{debug}");

        let provider = CloudflareProvider::new(
            FailingTransport,
            CloudflareConfig::api_token("super-secret-token"),
        );
        let debug = format!("{provider:?}");
        assert!(!debug.contains("super-secret-token"), "{debug}");
        assert_eq!(
            provider.config().auth_description(),
            "bearer API token (redacted)"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn config_parses_api_token_settings() {
        let settings = json!({ "api_token": "token-from-settings" });
        let config = CloudflareConfig::from_settings(settings.as_object().unwrap()).unwrap();
        assert_eq!(config.auth_description(), "bearer API token (redacted)");
        assert!(!format!("{config:?}").contains("token-from-settings"));
    }

    #[test]
    fn config_parses_legacy_email_and_api_key() {
        let settings = json!({ "email": "me@example.com", "api_key": "global-key" });
        let config = CloudflareConfig::from_settings(settings.as_object().unwrap()).unwrap();
        assert_eq!(config.auth_description(), "legacy email/API key (redacted)");
    }

    #[test]
    fn config_rejects_missing_or_conflicting_auth() {
        for settings in [
            json!({}),
            json!({ "email": "me@example.com" }),
            json!({ "api_key": "global-key" }),
            json!({ "api_token": "token", "email": "me@example.com" }),
            json!({ "api_token": "" }),
            json!({ "api_token": 42 }),
        ] {
            let result = CloudflareConfig::from_settings(settings.as_object().unwrap());
            assert!(
                matches!(result, Err(DnsError::Config { .. })),
                "settings {settings} should be rejected"
            );
        }
    }

    #[test]
    fn env_placeholders_are_resolved() {
        let resolved = resolve_env_placeholders_with("Bearer {env.CF_TOKEN}", |name| {
            (name == "CF_TOKEN").then(|| "secret-value".to_string())
        })
        .unwrap();
        assert_eq!(resolved, "Bearer secret-value");

        let dollar = resolve_env_placeholders_with("{$CF_TOKEN}", |name| {
            (name == "CF_TOKEN").then(|| "secret-value".to_string())
        })
        .unwrap();
        assert_eq!(dollar, "secret-value");

        let default = resolve_env_placeholders_with("{env.CF_TOKEN:fallback}", |_| None).unwrap();
        assert_eq!(default, "fallback");

        let literal = resolve_env_placeholders_with("plain-token", |_| None).unwrap();
        assert_eq!(literal, "plain-token");

        let error = resolve_env_placeholders_with("{env.CF_UNSET}", |_| None).unwrap_err();
        assert!(matches!(error, DnsError::Config { .. }));
        assert!(error.to_string().contains("CF_UNSET"));
    }

    #[test]
    fn env_placeholders_resolve_from_the_process_environment() {
        // A unique variable name keeps this test independent of the rest of the process.
        std::env::set_var("CADDY_RS_TEST_CF_API_TOKEN", "token-from-env");
        let resolved = resolve_env_placeholders("{env.CADDY_RS_TEST_CF_API_TOKEN}").unwrap();
        assert_eq!(resolved, "token-from-env");
        std::env::remove_var("CADDY_RS_TEST_CF_API_TOKEN");
    }

    #[test]
    fn from_challenge_config_requires_cloudflare_and_valid_ttl() {
        let other = DnsChallengeConfig::from_caddy_json(&json!({
            "provider": { "name": "route53" }
        }))
        .unwrap();
        let error = CloudflareProvider::from_challenge_config(ScriptedTransport::new(), &other)
            .unwrap_err();
        assert!(matches!(error, DnsError::Config { .. }));

        for ttl_nanos in [0_i64, 30_000_000_000_i64] {
            let challenge = DnsChallengeConfig::from_caddy_json(&json!({
                "provider": { "name": "cloudflare", "api_token": "token" },
                "ttl": ttl_nanos
            }))
            .unwrap();
            let result =
                CloudflareProvider::from_challenge_config(ScriptedTransport::new(), &challenge);
            if ttl_nanos == 0 {
                assert_eq!(result.unwrap().ttl_seconds(), None);
            } else {
                assert!(matches!(result, Err(DnsError::Config { .. })));
            }
        }
    }

    #[tokio::test]
    async fn legacy_auth_uses_email_and_key_headers() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        let provider = CloudflareProvider::new(
            transport,
            CloudflareConfig::legacy_key("me@example.com", "global-key"),
        );
        provider.find_zone(RECORD_NAME).await.unwrap();
        let requests = provider.transport.requests();
        assert_eq!(requests[0].header("X-Auth-Email"), Some("me@example.com"));
        assert_eq!(requests[0].header("X-Auth-Key"), Some("global-key"));
        assert_eq!(requests[0].header("Authorization"), None);
    }

    #[tokio::test]
    async fn provider_is_usable_as_a_trait_object() {
        let transport = ScriptedTransport::new();
        zone_lookup(&transport);
        let provider: Box<dyn DnsProvider> = Box::new(provider(transport));
        assert_eq!(provider.name(), CLOUDFLARE_PROVIDER_NAME);
        assert_eq!(provider.find_zone(RECORD_NAME).await.unwrap(), ZONE_NAME);
    }

    #[tokio::test]
    async fn invalid_record_names_are_rejected() {
        let provider = provider(ScriptedTransport::new());
        assert!(matches!(
            provider.find_zone("not a name").await,
            Err(DnsError::InvalidName { .. })
        ));
        assert!(matches!(
            provider.create_txt("example", "value").await,
            Err(DnsError::InvalidName { .. })
        ));
        assert!(matches!(
            provider.list_txt("_acme-challenge..example.com").await,
            Err(DnsError::InvalidName { .. })
        ));
    }
}
