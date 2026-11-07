//! DigitalOcean DNS-01 provider (v2 API).
//!
//! Implements the [`DnsProvider`] contract against DigitalOcean's v2 DNS API:
//! `GET /v2/domains` for zone discovery, `POST /v2/domains/{zone}/records` for TXT creation,
//! `GET /v2/domains/{zone}/records` for listing and `DELETE .../records/{id}` for cleanup.
//! Authentication is a bearer API token; the token is redacted from `Debug` output and is never
//! included in error messages.
//!
//! The HTTP transport is generic ([`AcmeTransport`]) so every flow is exercised with scripted
//! offline mocks; production uses the ACME hyper/rustls transport.

use std::fmt;
use std::sync::RwLock;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::acme::{AcmeTransport, HttpMethod, HttpRequest, HttpResponse};
use crate::cloudflare::resolve_env_placeholders;
use crate::dns::{
    validate_record_name, zone_candidates, DnsError, DnsProvider, DnsResult, RecordId, TxtRecord,
};

/// Caddy module name (`dns.providers.digitalocean`).
pub const DIGITALOCEAN_PROVIDER_NAME: &str = "digitalocean";
/// DigitalOcean API v2 base URL.
pub const DIGITALOCEAN_API_BASE: &str = "https://api.digitalocean.com/v2";
const DIGITALOCEAN_PAGE_SIZE: u32 = 200;
const MAX_PAGES: u32 = 20;

/// DigitalOcean provider configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct DigitalOceanConfig {
    api_token: String,
}

impl DigitalOceanConfig {
    /// Bearer-token configuration.
    pub fn api_token(token: impl Into<String>) -> Self {
        Self {
            api_token: token.into(),
        }
    }

    /// Provider settings understood by this client.
    pub const SUPPORTED_SETTINGS: &'static [&'static str] = &["api_token"];

    /// Parse the Caddy `dns.providers.digitalocean` module settings.
    ///
    /// `api_token` is required; values accept Caddy's `{env.NAME}`/`{$NAME}` placeholders.
    /// Unknown keys fail loudly instead of silently changing which account is used.
    pub fn from_settings(settings: &Map<String, Value>) -> DnsResult<Self> {
        for key in settings.keys() {
            if !Self::SUPPORTED_SETTINGS.contains(&key.as_str()) {
                return Err(DnsError::UnsupportedOption {
                    provider: DIGITALOCEAN_PROVIDER_NAME.to_string(),
                    option: key.clone(),
                });
            }
        }
        let api_token = match settings.get("api_token") {
            Some(Value::String(value)) => Some(resolve_env_placeholders(value)?),
            Some(_) => {
                return Err(config_error(
                    "DigitalOcean provider `api_token` must be a string",
                ))
            }
            None => None,
        }
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            config_error(
                "DigitalOcean provider requires a non-empty `api_token` (or an env placeholder)",
            )
        })?;
        Ok(Self::api_token(api_token))
    }
}

impl fmt::Debug for DigitalOceanConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigitalOceanConfig")
            .field("api_token", &"<redacted>")
            .field("api_base", &DIGITALOCEAN_API_BASE)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Domain {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DomainList {
    #[serde(default)]
    domains: Vec<Domain>,
}

#[derive(Debug, Clone, Deserialize)]
struct DomainRecord {
    id: u64,
    name: String,
    data: String,
    #[serde(default, rename = "type")]
    record_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordList {
    #[serde(default)]
    domain_records: Vec<DomainRecord>,
}

/// DigitalOcean DNS-01 provider.
pub struct DigitalOceanProvider<T: AcmeTransport> {
    transport: T,
    config: DigitalOceanConfig,
    ttl_seconds: Option<u32>,
    /// Cached domain names (longest suffix lookup).
    domains: RwLock<Option<Vec<String>>>,
}

impl<T: AcmeTransport> DigitalOceanProvider<T> {
    /// Create a provider with `config` and `transport`.
    pub fn new(transport: T, config: DigitalOceanConfig) -> Self {
        Self {
            transport,
            config,
            ttl_seconds: None,
            domains: RwLock::new(None),
        }
    }

    /// Create from Caddy's `challenges.dns` object (provider must be `digitalocean`).
    pub fn from_challenge_config(
        transport: T,
        challenge: &crate::dns::DnsChallengeConfig,
    ) -> DnsResult<Self> {
        if challenge.provider != DIGITALOCEAN_PROVIDER_NAME {
            return Err(config_error(format!(
                "expected the `{DIGITALOCEAN_PROVIDER_NAME}` DNS provider, got `{}`",
                challenge.provider
            )));
        }
        let config = DigitalOceanConfig::from_settings(&challenge.settings)?;
        let ttl_seconds = match challenge.ttl {
            Some(ttl) if !ttl.is_zero() => Some(
                u32::try_from(ttl.as_secs())
                    .map_err(|_| config_error("DigitalOcean TXT TTL is too large"))?,
            ),
            _ => None,
        };
        Ok(Self::new(transport, config).with_ttl_seconds(ttl_seconds))
    }

    /// Override the TXT record TTL in seconds (`None` = DigitalOcean default 1800).
    pub fn with_ttl_seconds(mut self, ttl_seconds: Option<u32>) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }

    /// The redacted configuration.
    pub fn config(&self) -> &DigitalOceanConfig {
        &self.config
    }

    fn headers(&self, json_body: bool) -> Vec<(String, String)> {
        let mut headers = vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", self.config.api_token),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
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

    /// Map a failed response to a typed API error, never echoing credentials.
    fn api_error(&self, url: &str, response: &HttpResponse) -> DnsError {
        #[derive(Deserialize)]
        struct ErrorBody {
            #[serde(default)]
            id: Option<String>,
            #[serde(default)]
            message: Option<String>,
        }
        let body = serde_json::from_slice::<ErrorBody>(&response.body).ok();
        let detail = body
            .as_ref()
            .and_then(|body| {
                body.message
                    .as_deref()
                    .or(body.id.as_deref())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "no error detail".to_string());
        provider_error(format!("HTTP {} for `{url}` ({detail})", response.status))
    }

    async fn fetch_domains(&self) -> DnsResult<Vec<String>> {
        if let Some(domains) = self
            .domains
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            return Ok(domains.clone());
        }
        let mut domains = Vec::new();
        for page in 1..=MAX_PAGES {
            let url = format!(
                "{DIGITALOCEAN_API_BASE}/domains?page={page}&per_page={DIGITALOCEAN_PAGE_SIZE}"
            );
            let request = HttpRequest {
                method: HttpMethod::Get,
                url: url.clone(),
                headers: self.headers(false),
                body: Vec::new(),
            };
            let response = self.send(request).await?;
            if !response.is_success() {
                return Err(self.api_error(&url, &response));
            }
            let list: DomainList = serde_json::from_slice(&response.body).map_err(|error| {
                provider_error(format!(
                    "invalid DigitalOcean domains response for `{url}`: {error}"
                ))
            })?;
            let count = list.domains.len();
            domains.extend(
                list.domains
                    .into_iter()
                    .map(|domain| normalize_fqdn(&domain.name)),
            );
            if count < DIGITALOCEAN_PAGE_SIZE as usize {
                break;
            }
        }
        domains.sort();
        domains.dedup();
        *self
            .domains
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(domains.clone());
        Ok(domains)
    }

    async fn zone_for_fqdn(&self, fqdn: &str) -> DnsResult<String> {
        let domains = self.fetch_domains().await?;
        let candidates = zone_candidates(fqdn);
        for candidate in candidates {
            if domains
                .iter()
                .any(|domain| domain.eq_ignore_ascii_case(&candidate))
            {
                return Ok(candidate);
            }
        }
        Err(DnsError::ZoneNotFound {
            provider: DIGITALOCEAN_PROVIDER_NAME.to_string(),
            fqdn: fqdn.to_string(),
        })
    }

    fn relative_name(fqdn: &str, zone: &str) -> String {
        if fqdn.eq_ignore_ascii_case(zone) {
            "@".to_string()
        } else {
            fqdn.strip_suffix(&format!(".{}", zone.to_ascii_lowercase()))
                .unwrap_or(fqdn)
                .trim_end_matches('.')
                .to_ascii_lowercase()
        }
    }

    fn record_fqdn(name: &str, zone: &str) -> String {
        let name = name.trim_end_matches('.');
        if name == "@" || name.is_empty() {
            zone.to_string()
        } else if name.eq_ignore_ascii_case(zone)
            || name
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", zone.to_ascii_lowercase()))
        {
            normalize_fqdn(name)
        } else {
            format!("{}.{}", name.to_ascii_lowercase(), zone)
        }
    }
}

impl<T: AcmeTransport> fmt::Debug for DigitalOceanProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigitalOceanProvider")
            .field("provider", &DIGITALOCEAN_PROVIDER_NAME)
            .field("config", &self.config)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<T: AcmeTransport> DnsProvider for DigitalOceanProvider<T> {
    fn name(&self) -> &str {
        DIGITALOCEAN_PROVIDER_NAME
    }

    async fn find_zone(&self, fqdn: &str) -> DnsResult<String> {
        validate_record_name(fqdn)?;
        self.zone_for_fqdn(&normalize_fqdn(fqdn)).await
    }

    async fn create_txt(&self, fqdn: &str, value: &str) -> DnsResult<TxtRecord> {
        validate_record_name(fqdn)?;
        let fqdn = normalize_fqdn(fqdn);
        let zone = self.zone_for_fqdn(&fqdn).await?;
        let relative = Self::relative_name(&fqdn, &zone);
        let mut body = json!({
            "type": "TXT",
            "name": relative,
            "data": value,
        });
        if let Some(ttl) = self.ttl_seconds {
            body["ttl"] = json!(ttl);
        }
        let payload = serde_json::to_vec(&body)
            .map_err(|error| provider_error(format!("cannot encode TXT record body: {error}")))?;
        let url = format!("{DIGITALOCEAN_API_BASE}/domains/{zone}/records");
        let request = HttpRequest {
            method: HttpMethod::Post,
            url: url.clone(),
            headers: self.headers(true),
            body: payload,
        };
        let response = self.send(request).await?;
        if !response.is_success() {
            return Err(self.api_error(&url, &response));
        }
        #[derive(Deserialize)]
        struct Created {
            domain_record: DomainRecord,
        }
        let created: Created = serde_json::from_slice(&response.body).map_err(|error| {
            provider_error(format!(
                "invalid DigitalOcean record-creation response for `{url}`: {error}"
            ))
        })?;
        Ok(TxtRecord {
            id: RecordId::new(created.domain_record.id.to_string()),
            fqdn,
            zone,
            value: created.domain_record.data,
        })
    }

    async fn delete_txt(&self, record: &TxtRecord) -> DnsResult<()> {
        validate_record_name(&record.fqdn)?;
        let zone = normalize_fqdn(&record.zone);
        let url = format!(
            "{DIGITALOCEAN_API_BASE}/domains/{zone}/records/{}",
            record.id
        );
        let request = HttpRequest {
            method: HttpMethod::Delete,
            url: url.clone(),
            headers: self.headers(false),
            body: Vec::new(),
        };
        let response = self.send(request).await?;
        // Idempotent cleanup: an already-absent record is success.
        if response.status == 404 || response.is_success() {
            return Ok(());
        }
        Err(self.api_error(&url, &response))
    }

    async fn list_txt(&self, fqdn: &str) -> DnsResult<Vec<TxtRecord>> {
        validate_record_name(fqdn)?;
        let fqdn = normalize_fqdn(fqdn);
        let zone = self.zone_for_fqdn(&fqdn).await?;
        let relative = Self::relative_name(&fqdn, &zone);
        let mut records = Vec::new();
        for page in 1..=MAX_PAGES {
            let url = format!(
                "{DIGITALOCEAN_API_BASE}/domains/{zone}/records?type=TXT&name={relative}&page={page}&per_page={DIGITALOCEAN_PAGE_SIZE}"
            );
            let request = HttpRequest {
                method: HttpMethod::Get,
                url: url.clone(),
                headers: self.headers(false),
                body: Vec::new(),
            };
            let response = self.send(request).await?;
            if !response.is_success() {
                return Err(self.api_error(&url, &response));
            }
            let list: RecordList = serde_json::from_slice(&response.body).map_err(|error| {
                provider_error(format!(
                    "invalid DigitalOcean records response for `{url}`: {error}"
                ))
            })?;
            let count = list.domain_records.len();
            for record in list.domain_records {
                if record
                    .record_type
                    .as_deref()
                    .is_some_and(|record_type| !record_type.eq_ignore_ascii_case("TXT"))
                {
                    continue;
                }
                if Self::record_fqdn(&record.name, &zone).eq_ignore_ascii_case(&fqdn) {
                    records.push(TxtRecord {
                        id: RecordId::new(record.id.to_string()),
                        fqdn: fqdn.clone(),
                        zone: zone.clone(),
                        value: record.data,
                    });
                }
            }
            if count < DIGITALOCEAN_PAGE_SIZE as usize {
                break;
            }
        }
        Ok(records)
    }

    fn propagation_poll_interval(&self) -> Duration {
        Duration::from_secs(2)
    }
}

fn normalize_fqdn(fqdn: &str) -> String {
    fqdn.trim_end_matches('.').to_ascii_lowercase()
}

/// Reject provider configuration with a typed error.
fn config_error(message: impl Into<String>) -> DnsError {
    DnsError::Config {
        message: message.into(),
    }
}

/// Typed provider API error.
fn provider_error(message: impl Into<String>) -> DnsError {
    DnsError::Provider {
        provider: DIGITALOCEAN_PROVIDER_NAME.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsChallengeConfig;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct ScriptedTransport {
        responses: Mutex<VecDeque<(u16, Value)>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl ScriptedTransport {
        fn new() -> Self {
            Self {
                responses: Mutex::new(VecDeque::new()),
                requests: Mutex::new(Vec::new()),
            }
        }
        fn expect(&self, status: u16, body: Value) {
            self.responses.lock().unwrap().push_back((status, body));
        }
        fn requests(&self) -> Vec<HttpRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AcmeTransport for ScriptedTransport {
        async fn request(&self, request: HttpRequest) -> crate::Result<HttpResponse> {
            self.requests.lock().unwrap().push(request);
            let (status, body) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((500, json!({"message": "unexpected request"})));
            HttpResponse::with_json(status, &body).map_err(Into::into)
        }
    }

    fn challenge(settings: Value) -> DnsChallengeConfig {
        DnsChallengeConfig::from_caddy_json(&json!({
            "provider": settings,
        }))
        .unwrap()
    }

    fn provider(transport: ScriptedTransport) -> DigitalOceanProvider<ScriptedTransport> {
        DigitalOceanProvider::from_challenge_config(
            transport,
            &challenge(json!({"name": DIGITALOCEAN_PROVIDER_NAME, "api_token": "do-token"})),
        )
        .unwrap()
    }

    const RECORD: &str = "_acme-challenge.api.example.com";
    const ZONE: &str = "example.com";

    #[tokio::test]
    async fn zone_discovery_uses_longest_suffix_and_handles_trailing_dots() {
        let transport = ScriptedTransport::new();
        transport.expect(
            200,
            json!({"domains": [
                {"name": "com"},
                {"name": "example.com"},
                {"name": "api.example.com"}
            ]}),
        );
        let provider = provider(transport);
        assert_eq!(
            provider
                .find_zone("_acme-challenge.api.example.com.")
                .await
                .unwrap(),
            "api.example.com"
        );
        let requests = provider.transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, HttpMethod::Get);
        assert_eq!(requests[0].header("Authorization"), Some("Bearer do-token"));
    }

    #[tokio::test]
    async fn zone_not_found_is_typed() {
        let transport = ScriptedTransport::new();
        transport.expect(200, json!({"domains": [{"name": "example.net"}]}));
        let provider = provider(transport);
        let error = provider.find_zone(RECORD).await.unwrap_err();
        assert!(matches!(error, DnsError::ZoneNotFound { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn propagation_timeout_is_typed() {
        let transport = ScriptedTransport::new();
        transport.expect(200, json!({"domains": [{"name": ZONE}]}));
        transport.expect(200, json!({"domain_records": []}));
        let provider = provider(transport);
        let record = TxtRecord {
            id: RecordId::new("42"),
            fqdn: RECORD.to_string(),
            zone: ZONE.to_string(),
            value: "digest".to_string(),
        };
        let error = provider
            .wait_for_propagation(&record, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(
            matches!(error, DnsError::PropagationTimeout { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn create_list_delete_flow_and_ttl() {
        let transport = ScriptedTransport::new();
        transport.expect(200, json!({"domains": [{"name": ZONE}]}));
        transport.expect(
            201,
            json!({"domain_record": {"id": 42, "type": "TXT", "name": "_acme-challenge.api", "data": "digest"}}),
        );
        transport.expect(
            200,
            json!({"domain_records": [{"id": 42, "type": "TXT", "name": "_acme-challenge.api", "data": "digest"}]}),
        );
        transport.expect(204, json!({}));
        let mut provider = provider(transport);
        provider = provider.with_ttl_seconds(Some(120));

        let record = provider.create_txt(RECORD, "digest").await.unwrap();
        assert_eq!(record.id, RecordId::new("42"));
        assert_eq!(record.fqdn, RECORD);
        assert_eq!(record.zone, ZONE);
        assert_eq!(record.value, "digest");
        let listed = provider.list_txt(RECORD).await.unwrap();
        assert_eq!(listed, vec![record.clone()]);
        provider.delete_txt(&record).await.unwrap();

        let requests = provider.transport.requests();
        let create = requests
            .iter()
            .find(|request| request.method == HttpMethod::Post)
            .expect("create request");
        let body: Value = serde_json::from_slice(&create.body).unwrap();
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], "_acme-challenge.api");
        assert_eq!(body["data"], "digest");
        assert_eq!(body["ttl"], 120);
        let delete = requests
            .iter()
            .find(|request| request.method == HttpMethod::Delete)
            .expect("delete request");
        assert!(delete.url.ends_with("/domains/example.com/records/42"));
    }

    #[tokio::test]
    async fn delete_is_idempotent_for_absent_records() {
        let transport = ScriptedTransport::new();
        transport.expect(
            404,
            json!({"id": "not_found", "message": "The resource was not found"}),
        );
        let provider = provider(transport);
        let record = TxtRecord {
            id: RecordId::new("999"),
            fqdn: RECORD.to_string(),
            zone: ZONE.to_string(),
            value: "digest".to_string(),
        };
        provider.delete_txt(&record).await.unwrap();
    }

    #[tokio::test]
    async fn api_errors_are_typed_and_do_not_leak_the_token() {
        let transport = ScriptedTransport::new();
        transport.expect(200, json!({"domains": [{"name": ZONE}]}));
        transport.expect(
            401,
            json!({"id": "unauthorized", "message": "Unable to authenticate you"}),
        );
        let provider = provider(transport);
        let error = provider.create_txt(RECORD, "digest").await.unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("DigitalOcean") || text.contains("digitalocean"),
            "{text}"
        );
        assert!(!text.contains("do-token"), "token leaked in error: {text}");
        let debug = format!("{provider:?}");
        assert!(
            !debug.contains("do-token"),
            "token leaked in Debug: {debug}"
        );
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[tokio::test]
    async fn rejects_unknown_settings_and_missing_credentials() {
        let error = DigitalOceanConfig::from_settings(
            json!({"api_token": "x", "extra": true})
                .as_object()
                .unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(error, DnsError::UnsupportedOption { .. }),
            "{error:?}"
        );
        let error = DigitalOceanConfig::from_settings(json!({}).as_object().unwrap()).unwrap_err();
        assert!(error.to_string().contains("api_token"), "{error}");
    }
}
