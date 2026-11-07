//! AWS Route 53 DNS-01 provider with SigV4 request signing.
//!
//! Supports the Route 53 REST API used by certmagic/Caddy's `route53` provider:
//! `ListHostedZonesByName` for zone discovery, `ChangeResourceRecordSets` (UPSERT/DELETE) for TXT
//! records, `ListResourceRecordSets` for listing and `GetChange` for propagation. Requests are
//! signed with AWS Signature Version 4; credentials come from the provider settings or the
//! standard `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`/`AWS_REGION` variables.
//!
//! All HTTP traffic flows through [`AcmeTransport`], so tests use scripted offline mocks and the
//! SigV4 implementation is checked against a fixed AWS vector (S3 GET example from the AWS
//! Signature Version 4 documentation).

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::sigv4::{canonical_query, format_amz_date, sign_sigv4, AwsCredentials, SigV4Request};

use crate::acme::{AcmeTransport, HttpMethod, HttpRequest, HttpResponse};
use crate::cloudflare::resolve_env_placeholders;
use crate::dns::{
    validate_record_name, zone_candidates, DnsError, DnsProvider, DnsResult, RecordId, TxtRecord,
};

/// Caddy module name (`dns.providers.route53`).
pub const ROUTE53_PROVIDER_NAME: &str = "route53";
/// Route 53 API version/path prefix.
pub const ROUTE53_API_VERSION: &str = "2013-04-01";
/// Route 53 API host.
pub const ROUTE53_HOST: &str = "route53.amazonaws.com";
/// Route 53 service name used in SigV4.
const ROUTE53_SERVICE: &str = "route53";
/// Default AWS region when neither config nor environment supplies one.
const DEFAULT_ROUTE53_REGION: &str = "us-east-1";
const DEFAULT_TXT_TTL: u32 = 300;
const MAX_PAGES: u32 = 20;

/// AWS credentials for SigV4.
#[derive(Clone, PartialEq, Eq)]
pub struct Route53Credentials {
    /// AWS access key ID.
    pub access_key_id: String,
    /// AWS secret access key.
    secret_access_key: String,
    /// Optional temporary-session token.
    pub session_token: Option<String>,
}

impl fmt::Debug for Route53Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Route53Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Route53Credentials {
    /// Shared SigV4 credential view.
    fn sigv4_credentials(&self) -> AwsCredentials {
        AwsCredentials {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
        }
    }
}

/// Route 53 provider configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct Route53Config {
    credentials: Route53Credentials,
    region: String,
}

impl Route53Config {
    /// Explicit credential configuration.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
        region: impl Into<String>,
    ) -> Self {
        Self {
            credentials: Route53Credentials {
                access_key_id: access_key_id.into(),
                secret_access_key: secret_access_key.into(),
                session_token,
            },
            region: region.into(),
        }
    }

    /// Settings understood by this Route 53 client.
    pub const SUPPORTED_SETTINGS: &'static [&'static str] = &[
        "access_key_id",
        "secret_access_key",
        "session_token",
        "region",
    ];

    /// Parse Caddy's `dns.providers.route53` module settings.
    ///
    /// Credentials may be provided in settings or through the standard AWS environment
    /// variables. Missing credentials are a located configuration error; unknown settings are
    /// rejected loudly.
    pub fn from_settings(settings: &Map<String, Value>) -> DnsResult<Self> {
        for key in settings.keys() {
            if !Self::SUPPORTED_SETTINGS.contains(&key.as_str()) {
                return Err(DnsError::UnsupportedOption {
                    provider: ROUTE53_PROVIDER_NAME.to_string(),
                    option: key.clone(),
                });
            }
        }
        let setting = |key: &str| -> DnsResult<Option<String>> {
            match settings.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(value)) => Ok(Some(resolve_env_placeholders(value)?)),
                Some(_) => Err(config_error(format!(
                    "Route 53 provider `{key}` must be a string"
                ))),
            }
        };
        let access_key_id = setting("access_key_id")?
            .or_else(|| std::env::var("AWS_ACCESS_KEY_ID").ok())
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                config_error("Route 53 provider requires `access_key_id` (or AWS_ACCESS_KEY_ID)")
            })?;
        let secret_access_key = setting("secret_access_key")?
            .or_else(|| std::env::var("AWS_SECRET_ACCESS_KEY").ok())
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                config_error(
                    "Route 53 provider requires `secret_access_key` (or AWS_SECRET_ACCESS_KEY)",
                )
            })?;
        let session_token = setting("session_token")?
            .or_else(|| std::env::var("AWS_SESSION_TOKEN").ok())
            .filter(|value| !value.trim().is_empty());
        let region = setting("region")?
            .or_else(|| std::env::var("AWS_REGION").ok())
            .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_ROUTE53_REGION.to_string());
        Ok(Self::new(
            access_key_id,
            secret_access_key,
            session_token,
            region,
        ))
    }

    /// Access key ID (safe to display).
    pub fn access_key_id(&self) -> &str {
        &self.credentials.access_key_id
    }

    /// Region used for SigV4.
    pub fn region(&self) -> &str {
        &self.region
    }
}

impl fmt::Debug for Route53Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Route53Config")
            .field("credentials", &self.credentials)
            .field("region", &self.region)
            .field("host", &ROUTE53_HOST)
            .finish()
    }
}

#[derive(Debug, Clone)]
struct HostedZone {
    id: String,
    name: String,
}

/// Route 53 DNS-01 provider.
pub struct Route53Provider<T: AcmeTransport> {
    transport: T,
    config: Route53Config,
    ttl_seconds: u32,
}

impl<T: AcmeTransport> Route53Provider<T> {
    /// Create a provider.
    pub fn new(transport: T, config: Route53Config) -> Self {
        Self {
            transport,
            config,
            ttl_seconds: DEFAULT_TXT_TTL,
        }
    }

    /// Create from Caddy's `challenges.dns` object.
    pub fn from_challenge_config(
        transport: T,
        challenge: &crate::dns::DnsChallengeConfig,
    ) -> DnsResult<Self> {
        if challenge.provider != ROUTE53_PROVIDER_NAME {
            return Err(config_error(format!(
                "expected the `{ROUTE53_PROVIDER_NAME}` DNS provider, got `{}`",
                challenge.provider
            )));
        }
        let config = Route53Config::from_settings(&challenge.settings)?;
        let ttl_seconds = match challenge.ttl {
            Some(ttl) if !ttl.is_zero() => u32::try_from(ttl.as_secs())
                .map_err(|_| config_error("Route 53 TXT record TTL is too large for the API"))?,
            _ => DEFAULT_TXT_TTL,
        };
        Ok(Self::new(transport, config).with_ttl_seconds(ttl_seconds))
    }

    /// Override the TXT record TTL (seconds). The same TTL is used for DELETE requests because
    /// Route 53 requires the exact record set to be specified.
    pub fn with_ttl_seconds(mut self, ttl_seconds: u32) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }

    /// The redacted configuration.
    pub fn config(&self) -> &Route53Config {
        &self.config
    }

    async fn send(&self, request: HttpRequest) -> DnsResult<HttpResponse> {
        self.transport
            .request(request)
            .await
            .map_err(|error| provider_error(format!("transport error: {error}")))
    }

    fn amz_date(&self) -> String {
        format_amz_date(SystemTime::now())
    }

    /// Sign one Route 53 request and return all headers (including `Authorization`).
    fn signed_headers(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(String, String)],
        payload: &[u8],
        extra_headers: &[(&str, &str)],
        amz_date: &str,
    ) -> Vec<(String, String)> {
        let credentials = self.config.credentials.sigv4_credentials();
        let mut headers = sign_sigv4(SigV4Request {
            method: method.as_str(),
            host: ROUTE53_HOST,
            path,
            query,
            payload,
            extra_headers,
            credentials: &credentials,
            region: &self.config.region,
            service: ROUTE53_SERVICE,
            amz_date,
        });
        headers.push(("Accept".to_string(), "text/xml".to_string()));
        headers
    }

    fn api_url(&self, path: &str, query: &[(String, String)]) -> String {
        format!(
            "https://{ROUTE53_HOST}/{ROUTE53_API_VERSION}{path}{}",
            if query.is_empty() {
                String::new()
            } else {
                let encoded = canonical_query(query);
                format!("?{encoded}")
            }
        )
    }

    fn api_error(&self, url: &str, response: &HttpResponse) -> DnsError {
        let body = String::from_utf8_lossy(&response.body);
        let code = xml_tag(&body, "Code").unwrap_or_default();
        let message = xml_tag(&body, "Message").unwrap_or_default();
        let detail = match (code.is_empty(), message.is_empty()) {
            (false, false) => format!("{code}: {message}"),
            (false, true) => code,
            (true, false) => message,
            (true, true) => "no error detail".to_string(),
        };
        provider_error(format!("HTTP {} for `{url}` ({detail})", response.status))
    }

    /// Find the hosted zone whose name is the longest suffix of `fqdn`.
    async fn find_zone_internal(&self, fqdn: &str) -> DnsResult<String> {
        let candidates = zone_candidates(fqdn);
        let mut zones: Vec<HostedZone> = Vec::new();
        let mut dns_name: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut query = vec![("maxitems".to_string(), "100".to_string())];
            if let Some(name) = &dns_name {
                query.push(("dnsname".to_string(), name.clone()));
            }
            let path = "/hostedzonesbyname";
            let url = self.api_url(path, &query);
            let amz_date = self.amz_date();
            let headers = self.signed_headers(HttpMethod::Get, path, &query, &[], &[], &amz_date);
            let response = self
                .send(HttpRequest {
                    method: HttpMethod::Get,
                    url: url.clone(),
                    headers,
                    body: Vec::new(),
                })
                .await?;
            if !response.is_success() {
                return Err(self.api_error(&url, &response));
            }
            let body = String::from_utf8_lossy(&response.body);
            zones.extend(parse_hosted_zones(&body)?);
            let truncated = xml_tag(&body, "IsTruncated")
                .map(|value| value.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !truncated {
                break;
            }
            dns_name = xml_tag(&body, "NextDNSName");
            if dns_name.is_none() {
                break;
            }
        }
        for candidate in candidates {
            if zones.iter().any(|zone| {
                zone.name
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(&candidate)
            }) {
                return Ok(candidate);
            }
        }
        Err(DnsError::ZoneNotFound {
            provider: ROUTE53_PROVIDER_NAME.to_string(),
            fqdn: fqdn.to_string(),
        })
    }

    async fn zone_id(&self, zone: &str) -> DnsResult<String> {
        // Re-list to obtain the hosted-zone id for the chosen zone. This is one extra request per
        // operation but keeps the provider stateless and provider-instance-safe.
        let mut zones = Vec::new();
        let mut dns_name: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut query = vec![("maxitems".to_string(), "100".to_string())];
            if let Some(name) = &dns_name {
                query.push(("dnsname".to_string(), name.clone()));
            }
            let path = "/hostedzonesbyname";
            let url = self.api_url(path, &query);
            let amz_date = self.amz_date();
            let headers = self.signed_headers(HttpMethod::Get, path, &query, &[], &[], &amz_date);
            let response = self
                .send(HttpRequest {
                    method: HttpMethod::Get,
                    url: url.clone(),
                    headers,
                    body: Vec::new(),
                })
                .await?;
            if !response.is_success() {
                return Err(self.api_error(&url, &response));
            }
            let body = String::from_utf8_lossy(&response.body);
            zones.extend(parse_hosted_zones(&body)?);
            let truncated = xml_tag(&body, "IsTruncated")
                .map(|value| value.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !truncated {
                break;
            }
            dns_name = xml_tag(&body, "NextDNSName");
            if dns_name.is_none() {
                break;
            }
        }
        zones
            .into_iter()
            .find(|hosted| hosted.name.trim_end_matches('.').eq_ignore_ascii_case(zone))
            .map(|hosted| hosted.id)
            .ok_or_else(|| DnsError::ZoneNotFound {
                provider: ROUTE53_PROVIDER_NAME.to_string(),
                fqdn: zone.to_string(),
            })
    }

    fn change_body(&self, action: &str, fqdn: &str, value: &str) -> Vec<u8> {
        let name = format!("{fqdn}.");
        let escaped = xml_escape(value);
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/{ROUTE53_API_VERSION}/"><ChangeBatch><Changes><Change><Action>{action}</Action><ResourceRecordSet><Name>{name}</Name><Type>TXT</Type><TTL>{}</TTL><ResourceRecords><ResourceRecord><Value>"{escaped}"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"#,
            self.ttl_seconds
        )
        .into_bytes()
    }

    async fn change(
        &self,
        action: &str,
        zone: &str,
        fqdn: &str,
        value: &str,
    ) -> DnsResult<Option<String>> {
        let zone_id = self.zone_id(zone).await?;
        let path = Self::rrset_path(&zone_id);
        let payload = self.change_body(action, fqdn, value);
        let url = self.api_url(&path, &[]);
        let amz_date = self.amz_date();
        let headers = self.signed_headers(
            HttpMethod::Post,
            &path,
            &[],
            &payload,
            &[("content-type", "text/xml")],
            &amz_date,
        );
        let response = self
            .send(HttpRequest {
                method: HttpMethod::Post,
                url: url.clone(),
                headers,
                body: payload,
            })
            .await?;
        if !response.is_success() {
            let body = String::from_utf8_lossy(&response.body);
            let message = xml_tag(&body, "Message").unwrap_or_default();
            if action == "DELETE"
                && (response.status == 404
                    || message.to_ascii_lowercase().contains("not found")
                    || message.to_ascii_lowercase().contains("does not exist"))
            {
                return Ok(None);
            }
            return Err(self.api_error(&url, &response));
        }
        let body = String::from_utf8_lossy(&response.body);
        Ok(xml_tag(&body, "Id"))
    }

    fn rrset_path(zone_id: &str) -> String {
        let id = zone_id.trim_start_matches('/');
        let id = id.strip_prefix("hostedzone/").unwrap_or(id);
        format!("/hostedzone/{id}/rrset/")
    }

    async fn change_status(&self, change_id: &str) -> DnsResult<String> {
        let id = change_id
            .trim_start_matches('/')
            .trim_start_matches("change/");
        let path = format!("/change/{id}");
        let url = self.api_url(&path, &[]);
        let amz_date = self.amz_date();
        let headers = self.signed_headers(HttpMethod::Get, &path, &[], &[], &[], &amz_date);
        let response = self
            .send(HttpRequest {
                method: HttpMethod::Get,
                url: url.clone(),
                headers,
                body: Vec::new(),
            })
            .await?;
        if !response.is_success() {
            return Err(self.api_error(&url, &response));
        }
        let body = String::from_utf8_lossy(&response.body);
        Ok(xml_tag(&body, "Status").unwrap_or_default())
    }
}

impl<T: AcmeTransport> fmt::Debug for Route53Provider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Route53Provider")
            .field("provider", &ROUTE53_PROVIDER_NAME)
            .field("config", &self.config)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<T: AcmeTransport> DnsProvider for Route53Provider<T> {
    fn name(&self) -> &str {
        ROUTE53_PROVIDER_NAME
    }

    async fn find_zone(&self, fqdn: &str) -> DnsResult<String> {
        validate_record_name(fqdn)?;
        let fqdn = fqdn.trim_end_matches('.').to_ascii_lowercase();
        self.find_zone_internal(&fqdn).await
    }

    async fn create_txt(&self, fqdn: &str, value: &str) -> DnsResult<TxtRecord> {
        validate_record_name(fqdn)?;
        let fqdn = fqdn.trim_end_matches('.').to_ascii_lowercase();
        let zone = self.find_zone_internal(&fqdn).await?;
        let change_id = self
            .change("UPSERT", &zone, &fqdn, value)
            .await?
            .unwrap_or_default();
        Ok(TxtRecord {
            id: RecordId::new(change_id),
            fqdn,
            zone,
            value: value.to_string(),
        })
    }

    async fn delete_txt(&self, record: &TxtRecord) -> DnsResult<()> {
        validate_record_name(&record.fqdn)?;
        self.change("DELETE", &record.zone, &record.fqdn, &record.value)
            .await
            .map(|_| ())
    }

    async fn list_txt(&self, fqdn: &str) -> DnsResult<Vec<TxtRecord>> {
        validate_record_name(fqdn)?;
        let fqdn = fqdn.trim_end_matches('.').to_ascii_lowercase();
        let zone = self.find_zone_internal(&fqdn).await?;
        let zone_id = self.zone_id(&zone).await?;
        let path = Self::rrset_path(&zone_id);
        let query = vec![
            ("name".to_string(), format!("{fqdn}.")),
            ("type".to_string(), "TXT".to_string()),
            ("maxitems".to_string(), "100".to_string()),
        ];
        let url = self.api_url(&path, &query);
        let amz_date = self.amz_date();
        let headers = self.signed_headers(HttpMethod::Get, &path, &query, &[], &[], &amz_date);
        let response = self
            .send(HttpRequest {
                method: HttpMethod::Get,
                url: url.clone(),
                headers,
                body: Vec::new(),
            })
            .await?;
        if !response.is_success() {
            return Err(self.api_error(&url, &response));
        }
        let body = String::from_utf8_lossy(&response.body);
        let mut records = Vec::new();
        for block in xml_blocks(&body, "ResourceRecordSet") {
            let name = xml_tag(&block, "Name")
                .unwrap_or_default()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let record_type = xml_tag(&block, "Type").unwrap_or_default();
            if !record_type.eq_ignore_ascii_case("TXT") || !name.eq_ignore_ascii_case(&fqdn) {
                continue;
            }
            for value_block in xml_blocks(&block, "ResourceRecord") {
                if let Some(value) = xml_tag(&value_block, "Value") {
                    records.push(TxtRecord {
                        id: RecordId::new(""),
                        fqdn: fqdn.clone(),
                        zone: zone.clone(),
                        value: unquote_txt(&value),
                    });
                }
            }
        }
        Ok(records)
    }

    fn propagation_poll_interval(&self) -> Duration {
        Duration::from_secs(1)
    }

    async fn wait_for_propagation(&self, record: &TxtRecord, timeout: Duration) -> DnsResult<()> {
        if record.id.0.trim().is_empty() {
            return Ok(());
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let status = self.change_status(&record.id.0).await?;
            if status.eq_ignore_ascii_case("INSYNC") {
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(DnsError::PropagationTimeout {
                    fqdn: record.fqdn.clone(),
                    timeout,
                });
            }
            tokio::time::sleep((deadline - now).min(Duration::from_secs(1))).await;
        }
    }
}

// ---- tiny XML helpers -----------------------------------------------------------------------

fn xml_tag(document: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = document.find(&open)? + open.len();
    let end = document[start..].find(&close)? + start;
    Some(xml_unescape(document[start..end].trim()))
}

fn xml_blocks(document: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut blocks = Vec::new();
    let mut position = 0;
    while let Some(relative_start) = document[position..].find(&open) {
        let start = position + relative_start + open.len();
        let Some(relative_end) = document[start..].find(&close) else {
            break;
        };
        let end = start + relative_end;
        blocks.push(document[start..end].to_string());
        position = end + close.len();
    }
    blocks
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn unquote_txt(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_hosted_zones(document: &str) -> DnsResult<Vec<HostedZone>> {
    let mut zones = Vec::new();
    for block in xml_blocks(document, "HostedZone") {
        let id = xml_tag(&block, "Id").ok_or_else(|| {
            provider_error("Route 53 ListHostedZonesByName response has a HostedZone without an Id")
        })?;
        let name = xml_tag(&block, "Name").ok_or_else(|| {
            provider_error(
                "Route 53 ListHostedZonesByName response has a HostedZone without a Name",
            )
        })?;
        zones.push(HostedZone { id, name });
    }
    Ok(zones)
}

fn config_error(message: impl Into<String>) -> DnsError {
    DnsError::Config {
        message: message.into(),
    }
}

fn provider_error(message: impl Into<String>) -> DnsError {
    DnsError::Provider {
        provider: ROUTE53_PROVIDER_NAME.to_string(),
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
        responses: Mutex<VecDeque<(u16, String)>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl ScriptedTransport {
        fn new() -> Self {
            Self {
                responses: Mutex::new(VecDeque::new()),
                requests: Mutex::new(Vec::new()),
            }
        }
        fn expect_xml(&self, status: u16, body: impl Into<String>) {
            self.responses
                .lock()
                .unwrap()
                .push_back((status, body.into()));
        }
    }

    #[async_trait]
    impl AcmeTransport for ScriptedTransport {
        async fn request(&self, request: HttpRequest) -> crate::Result<HttpResponse> {
            self.requests.lock().unwrap().push(request);
            let (status, body) = self.responses.lock().unwrap().pop_front().unwrap_or((
                500,
                "<Error><Code>Unexpected</Code><Message>unexpected request</Message></Error>"
                    .to_string(),
            ));
            Ok(HttpResponse::new(status)
                .with_header("Content-Type", "text/xml")
                .with_body(body.into_bytes()))
        }
    }

    fn provider(transport: ScriptedTransport) -> Route53Provider<ScriptedTransport> {
        let challenge = DnsChallengeConfig::from_caddy_json(&serde_json::json!({
            "provider": {
                "name": ROUTE53_PROVIDER_NAME,
                "access_key_id": "AKIDEXAMPLE",
                "secret_access_key": "SECRETEXAMPLE",
                "region": "us-east-1"
            }
        }))
        .unwrap();
        Route53Provider::from_challenge_config(transport, &challenge).unwrap()
    }

    const ZONE_NAME: &str = "example.com";
    const RECORD: &str = "_acme-challenge.example.com";

    fn zones_response() -> String {
        zones_response_with(&[(ZONE_NAME, "Z123")])
    }

    fn zones_response_with(zones: &[(&str, &str)]) -> String {
        let hosted = zones
            .iter()
            .map(|(name, id)| {
                format!("<HostedZone><Id>/hostedzone/{id}</Id><Name>{name}.</Name></HostedZone>")
            })
            .collect::<String>();
        format!(
            "<ListHostedZonesByNameResponse><HostedZones>{hosted}</HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListHostedZonesByNameResponse>"
        )
    }

    fn change_response(id: &str, status: &str) -> String {
        format!(
            r#"<ChangeResourceRecordSetsResponse><ChangeInfo><Id>/change/{id}</Id><Status>{status}</Status></ChangeInfo></ChangeResourceRecordSetsResponse>"#
        )
    }

    fn rrset_response(name: &str, value: &str) -> String {
        format!(
            r#"<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet><Name>{name}.</Name><Type>TXT</Type><TTL>300</TTL><ResourceRecords><ResourceRecord><Value>"{value}"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>"#
        )
    }

    #[test]
    fn sigv4_matches_aws_published_vector() {
        let credentials = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };
        let headers = sign_sigv4(SigV4Request {
            method: "GET",
            host: "examplebucket.s3.amazonaws.com",
            path: "/test.txt",
            query: &[],
            payload: b"",
            extra_headers: &[("range", "bytes=0-9")],
            credentials: &credentials,
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
        });
        let authorization = headers
            .iter()
            .find(|(name, _)| name == "Authorization")
            .map(|(_, value)| value.as_str())
            .expect("Authorization header");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(
            headers
                .iter()
                .find(|(name, _)| name == "X-Amz-Date")
                .map(|(_, value)| value.as_str()),
            Some("20130524T000000Z")
        );
        assert_eq!(
            headers
                .iter()
                .find(|(name, _)| name == "X-Amz-Content-Sha256")
                .map(|(_, value)| value.as_str()),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[tokio::test]
    async fn zone_discovery_picks_longest_suffix_and_trailing_dot() {
        let transport = ScriptedTransport::new();
        transport.expect_xml(
            200,
            zones_response_with(&[("example.com", "Z1"), ("api.example.com", "Z2")]),
        );
        let provider = provider(transport);
        assert_eq!(
            provider
                .find_zone("_acme-challenge.api.example.com.")
                .await
                .unwrap(),
            "api.example.com"
        );
        let requests = provider.transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, HttpMethod::Get);
        assert_eq!(requests[0].header("X-Amz-Date").is_some(), true);
        assert!(requests[0]
            .header("Authorization")
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
    }

    #[tokio::test]
    async fn zone_not_found_is_typed() {
        let transport = ScriptedTransport::new();
        transport.expect_xml(
            200,
            "<ListHostedZonesByNameResponse><HostedZones></HostedZones><IsTruncated>false</IsTruncated></ListHostedZonesByNameResponse>",
        );
        let provider = provider(transport);
        let error = provider.find_zone(RECORD).await.unwrap_err();
        assert!(matches!(error, DnsError::ZoneNotFound { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn create_list_delete_and_change_flow() {
        let transport = ScriptedTransport::new();
        transport.expect_xml(200, zones_response()); // find_zone
        transport.expect_xml(200, zones_response()); // zone_id
        transport.expect_xml(200, change_response("C1", "PENDING"));
        transport.expect_xml(200, zones_response()); // list find_zone
        transport.expect_xml(200, zones_response()); // list zone_id
        transport.expect_xml(200, rrset_response(RECORD, "digest"));
        transport.expect_xml(200, zones_response()); // delete find_zone
        transport.expect_xml(200, zones_response()); // delete zone_id
        transport.expect_xml(200, change_response("C2", "PENDING"));
        transport.expect_xml(200, change_response("C1", "INSYNC"));
        let provider = provider(transport);

        let record = provider.create_txt(RECORD, "digest").await.unwrap();
        assert_eq!(record.zone, ZONE_NAME);
        assert_eq!(record.id, RecordId::new("/change/C1"));
        assert_eq!(record.value, "digest");
        let listed = provider.list_txt(RECORD).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].value, "digest");
        provider.delete_txt(&record).await.unwrap();
        provider
            .wait_for_propagation(&record, Duration::from_secs(5))
            .await
            .unwrap();

        let requests = provider.transport.requests.lock().unwrap();
        let create = requests
            .iter()
            .find(|request| request.method == HttpMethod::Post)
            .expect("change POST");
        assert_eq!(
            create.url,
            "https://route53.amazonaws.com/2013-04-01/hostedzone/Z123/rrset/"
        );
        let body = String::from_utf8_lossy(&create.body);
        assert!(body.contains("<Action>UPSERT</Action>"), "{body}");
        assert!(body.contains("_acme-challenge.example.com."), "{body}");
        assert!(body.contains("<Value>\"digest\"</Value>"), "{body}");
    }

    #[tokio::test]
    async fn propagation_times_out_for_pending_change() {
        let transport = ScriptedTransport::new();
        transport.expect_xml(200, change_response("C1", "PENDING"));
        let provider = provider(transport);
        let record = TxtRecord {
            id: RecordId::new("/change/C1"),
            fqdn: RECORD.to_string(),
            zone: ZONE_NAME.to_string(),
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
    async fn delete_is_idempotent_when_route53_reports_absent_record() {
        let transport = ScriptedTransport::new();
        transport.expect_xml(200, zones_response());
        transport.expect_xml(200, zones_response());
        transport.expect_xml(
            400,
            "<ErrorResponse><Error><Code>InvalidChangeBatch</Code><Message>but it does not exist</Message></Error></ErrorResponse>",
        );
        let provider = provider(transport);
        let record = TxtRecord {
            id: RecordId::new(""),
            fqdn: RECORD.to_string(),
            zone: ZONE_NAME.to_string(),
            value: "digest".to_string(),
        };
        provider.delete_txt(&record).await.unwrap();
    }

    #[tokio::test]
    async fn api_errors_are_typed_and_secrets_are_redacted() {
        let transport = ScriptedTransport::new();
        transport.expect_xml(
            403,
            "<ErrorResponse><Error><Code>AccessDenied</Code><Message>not authorized</Message></Error></ErrorResponse>",
        );
        let provider = provider(transport);
        let error = provider.find_zone(RECORD).await.unwrap_err();
        assert!(error.to_string().contains("AccessDenied"), "{error}");
        let debug = format!("{provider:?}");
        assert!(!debug.contains("SECRETEXAMPLE"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn config_rejects_unknown_settings_and_missing_credentials() {
        let error = Route53Config::from_settings(
            serde_json::json!({"access_key_id": "a", "secret_access_key": "b", "profile": "x"})
                .as_object()
                .unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(error, DnsError::UnsupportedOption { .. }),
            "{error:?}"
        );
        if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
            let error = Route53Config::from_settings(serde_json::json!({}).as_object().unwrap())
                .unwrap_err();
            assert!(error.to_string().contains("access_key_id"), "{error}");
        }
    }

    #[test]
    fn amz_date_format_is_stable() {
        let time = UNIX_EPOCH + Duration::from_secs(1_369_353_600);
        assert_eq!(format_amz_date(time), "20130524T000000Z");
    }
    #[test]
    fn env_credentials_and_region_are_used_when_settings_are_absent() {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved = [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
        ]
        .map(|name| (name, std::env::var(name).ok()));
        std::env::set_var("AWS_ACCESS_KEY_ID", "ENVACCESS");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "ENVSECRET");
        std::env::set_var("AWS_SESSION_TOKEN", "ENVTOKEN");
        std::env::set_var("AWS_REGION", "eu-west-1");
        let config = Route53Config::from_settings(serde_json::json!({}).as_object().unwrap());
        for (name, value) in saved {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        let config = config.expect("env credentials");
        assert_eq!(config.access_key_id(), "ENVACCESS");
        assert_eq!(config.region(), "eu-west-1");
        assert!(!format!("{config:?}").contains("ENVSECRET"));
        assert!(format!("{config:?}").contains("<redacted>"));
    }
}
