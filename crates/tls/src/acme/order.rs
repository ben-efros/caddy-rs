//! ACME order, authorization, challenge, finalization and certificate-download client.
//!
//! This builds on [`AcmeClient`](super::AcmeClient) (directory, JWS signing, nonces, problem
//! documents) and [`AcmeAccountClient`] adds the account URL as the JWS `kid`. The flow mirrors
//! RFC 8555 §7.4:
//!
//! 1. `newOrder` with DNS/IP identifiers (and optional `notBefore`/`notAfter`);
//! 2. fetch the authorizations, select an enabled challenge type, acknowledge it, poll the
//!    authorization until it is valid;
//! 3. poll the order until it is `ready`, finalize with a [`CertificateRequest`], poll until
//!    `valid`, then download and split the PEM certificate chain.
//!
//! Polling honours the server's `Retry-After` header (both delta-seconds and HTTP-date forms) and
//! is driven through the [`AcmeClock`] trait so tests record the delays instead of sleeping.
//!
//! Challenge solving itself (serving `/.well-known/acme-challenge/...`, the TLS-ALPN certificate,
//! DNS TXT records) is handled by the solver tasks T-TLS-042/T-TLS-043/T-TLS-044; this module only selects
//! and acknowledges the challenge.

use std::fmt;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{
    response_error, AcmeClient, AcmeError, AcmeTransport, CertificateRequest, HttpResponse,
    Problem, StoredAccount,
};
use crate::{Error, Result};

/// Header used by ACME servers (and RFC 8555 §6.6) to throttle polling.
pub const RETRY_AFTER_HEADER: &str = "Retry-After";

/// Media type of a downloaded PEM certificate chain (RFC 8555 §7.4.2).
pub const PEM_CERTIFICATE_CHAIN_CONTENT_TYPE: &str = "application/pem-certificate-chain";

// ---- identifier / order types ----------------------------------------------------------------

/// An order identifier (`{"type":"dns","value":"example.com"}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identifier {
    /// Identifier type (`dns` or `ip`; unknown types are preserved but not orderable).
    #[serde(rename = "type")]
    pub identifier_type: String,
    /// Identifier value.
    pub value: String,
}

impl Identifier {
    /// A DNS identifier.
    pub fn dns(value: impl Into<String>) -> Self {
        Self {
            identifier_type: "dns".to_string(),
            value: value.into(),
        }
    }

    /// An IP address identifier.
    pub fn ip(value: impl Into<String>) -> Self {
        Self {
            identifier_type: "ip".to_string(),
            value: value.into(),
        }
    }

    /// Classify `value` as an IP identifier when it parses as an IP address, DNS otherwise.
    pub fn for_domain(value: impl Into<String>) -> Self {
        let value = value.into();
        if value.parse::<std::net::IpAddr>().is_ok() {
            Self::ip(value)
        } else {
            Self::dns(value)
        }
    }

    /// The identifier value when this is a DNS identifier.
    pub fn as_dns(&self) -> Option<&str> {
        (self.identifier_type == "dns").then_some(self.value.as_str())
    }
}

/// The `newOrder` request payload (RFC 8555 §7.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrderRequest {
    /// Identifiers the certificate must cover.
    pub identifiers: Vec<Identifier>,
    /// Optional RFC 3339 `notBefore`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Optional RFC 3339 `notAfter`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

impl NewOrderRequest {
    /// An order for `domains` (IP literals become `ip` identifiers, everything else `dns`).
    pub fn for_domains(domains: &[String]) -> Self {
        let mut identifiers = Vec::with_capacity(domains.len());
        for domain in domains {
            let identifier = Identifier::for_domain(domain.trim().to_ascii_lowercase());
            if !identifiers.contains(&identifier) {
                identifiers.push(identifier);
            }
        }
        Self {
            identifiers,
            not_before: None,
            not_after: None,
        }
    }

    /// Request a specific validity window (RFC 3339 timestamps, CA support permitting).
    pub fn with_validity(mut self, not_before: Option<String>, not_after: Option<String>) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }
}

/// Order status (RFC 8555 §7.1.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    /// Authorizations still need to be completed.
    #[default]
    Pending,
    /// All authorizations are valid; the order can be finalized.
    Ready,
    /// The order has been finalized and the CA is issuing.
    Processing,
    /// The certificate is issued and can be downloaded.
    Valid,
    /// The order failed and cannot be used.
    Invalid,
    /// A status introduced by a future extension.
    #[serde(other)]
    Unknown,
}

impl OrderStatus {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        }
    }

    /// Whether polling should continue for this status.
    pub fn is_in_progress(self) -> bool {
        matches!(self, Self::Pending | Self::Processing)
    }
}

impl fmt::Display for OrderStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An ACME order object (RFC 8555 §7.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// Order status.
    #[serde(default)]
    pub status: OrderStatus,
    /// Expiry timestamp (RFC 3339 string; kept verbatim).
    #[serde(default)]
    pub expires: Option<String>,
    /// Identifiers the order covers.
    #[serde(default)]
    pub identifiers: Vec<Identifier>,
    /// Authorization URLs.
    #[serde(default)]
    pub authorizations: Vec<String>,
    /// Finalization URL.
    #[serde(default)]
    pub finalize: String,
    /// Certificate URL, present when the order is valid.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Error object when the order is invalid.
    #[serde(default)]
    pub error: Option<Problem>,
    /// Requested `notBefore`.
    #[serde(default)]
    pub not_before: Option<String>,
    /// Requested `notAfter`.
    #[serde(default)]
    pub not_after: Option<String>,
    /// Requested profile (ACME profiles extension).
    #[serde(default)]
    pub profile: Option<String>,
}

/// A freshly created order and its URL (from the `Location` header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderHandle {
    /// Order resource URL.
    pub url: String,
    /// Current order object.
    pub order: Order,
}

/// Authorization status (RFC 8555 §7.1.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    /// A challenge still needs to be completed.
    #[default]
    Pending,
    /// All required challenges are complete.
    Valid,
    /// The authorization failed.
    Invalid,
    /// The account deactivated the authorization.
    Deactivated,
    /// The authorization expired.
    Expired,
    /// The CA revoked the authorization.
    Revoked,
    /// A status introduced by a future extension.
    #[serde(other)]
    Unknown,
}

impl AuthorizationStatus {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Deactivated => "deactivated",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for AuthorizationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Challenge status (RFC 8555 §7.1.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    /// Not yet acknowledged.
    #[default]
    Pending,
    /// Acknowledged and being validated.
    Processing,
    /// Validation succeeded.
    Valid,
    /// Validation failed.
    Invalid,
    /// A status introduced by a future extension.
    #[serde(other)]
    Unknown,
}

/// An ACME authorization object (RFC 8555 §7.1.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// Authorization status.
    #[serde(default)]
    pub status: AuthorizationStatus,
    /// Expiry timestamp (kept verbatim).
    #[serde(default)]
    pub expires: Option<String>,
    /// Identifier this authorization is for.
    #[serde(default)]
    pub identifier: Option<Identifier>,
    /// Offered challenges.
    #[serde(default)]
    pub challenges: Vec<Challenge>,
    /// Whether this authorization is for a wildcard name.
    #[serde(default)]
    pub wildcard: Option<bool>,
}

/// An ACME challenge object (RFC 8555 §7.1.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    /// Challenge type (`http-01`, `tls-alpn-01`, `dns-01`, ...).
    #[serde(rename = "type")]
    pub challenge_type: String,
    /// Challenge URL used to acknowledge/poll it.
    #[serde(default)]
    pub url: String,
    /// Challenge status.
    #[serde(default)]
    pub status: ChallengeStatus,
    /// Challenge token (use with the solver).
    #[serde(default)]
    pub token: String,
    /// Validation timestamp once valid.
    #[serde(default)]
    pub validated: Option<String>,
    /// Error object once invalid.
    #[serde(default)]
    pub error: Option<Problem>,
}

impl Challenge {
    /// The typed challenge kind, when it is one this build knows.
    pub fn kind(&self) -> Option<ChallengeType> {
        ChallengeType::from_wire(&self.challenge_type)
    }
}

/// Challenge types this build can select (RFC 8555 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChallengeType {
    /// `http-01`
    #[serde(rename = "http-01")]
    Http01,
    /// `tls-alpn-01`
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// `dns-01`
    #[serde(rename = "dns-01")]
    Dns01,
}

impl ChallengeType {
    /// Wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::TlsAlpn01 => "tls-alpn-01",
            Self::Dns01 => "dns-01",
        }
    }

    /// Parse a wire spelling; unknown challenge types are not selectable.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "http-01" => Some(Self::Http01),
            "tls-alpn-01" => Some(Self::TlsAlpn01),
            "dns-01" => Some(Self::Dns01),
            _ => None,
        }
    }
}

impl fmt::Display for ChallengeType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which challenges the client is willing to solve, and in what preference order.
///
/// The defaults follow a Caddy-deployment-friendly policy: DNS-01 when a provider is configured,
/// otherwise HTTP-01, with TLS-ALPN-01 as the fallback. Use [`Self::with_preference`] to override
/// the order explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengePolicy {
    /// Whether `http-01` may be selected.
    pub http01: bool,
    /// Whether `tls-alpn-01` may be selected.
    pub tls_alpn01: bool,
    /// Whether `dns-01` may be selected.
    pub dns01: bool,
    /// Preference order tried for each authorization.
    preference: Vec<ChallengeType>,
}

impl Default for ChallengePolicy {
    fn default() -> Self {
        Self {
            http01: true,
            tls_alpn01: true,
            dns01: false,
            preference: vec![
                ChallengeType::Dns01,
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01,
            ],
        }
    }
}

impl ChallengePolicy {
    /// HTTP-01 only.
    pub fn http_only() -> Self {
        Self {
            http01: true,
            tls_alpn01: false,
            dns01: false,
            preference: vec![ChallengeType::Http01],
        }
    }

    /// DNS-01 only.
    pub fn dns_only() -> Self {
        Self {
            http01: false,
            tls_alpn01: false,
            dns01: true,
            preference: vec![ChallengeType::Dns01],
        }
    }

    /// TLS-ALPN-01 only.
    pub fn tls_alpn_only() -> Self {
        Self {
            http01: false,
            tls_alpn01: true,
            dns01: false,
            preference: vec![ChallengeType::TlsAlpn01],
        }
    }

    /// Enable/disable DNS-01 (for example when a DNS provider is configured).
    pub fn with_dns01(mut self, enabled: bool) -> Self {
        self.dns01 = enabled;
        if enabled && !self.preference.contains(&ChallengeType::Dns01) {
            self.preference.insert(0, ChallengeType::Dns01);
        }
        self
    }

    /// Replace the preference order.
    pub fn with_preference(mut self, preference: Vec<ChallengeType>) -> Self {
        self.preference = preference;
        self
    }

    /// Whether `challenge_type` is enabled by this policy.
    pub fn is_enabled(&self, challenge_type: ChallengeType) -> bool {
        match challenge_type {
            ChallengeType::Http01 => self.http01,
            ChallengeType::TlsAlpn01 => self.tls_alpn01,
            ChallengeType::Dns01 => self.dns01,
        }
    }

    /// Enabled challenge types in preference order.
    pub fn ordered_types(&self) -> Vec<ChallengeType> {
        self.preference
            .iter()
            .copied()
            .filter(|challenge_type| self.is_enabled(*challenge_type))
            .collect()
    }

    /// Select the challenge to solve for `authorization`.
    pub fn select<'authorization>(
        &self,
        authorization: &'authorization Authorization,
    ) -> Result<&'authorization Challenge> {
        for challenge_type in self.ordered_types() {
            if let Some(challenge) = authorization
                .challenges
                .iter()
                .find(|challenge| challenge.kind() == Some(challenge_type))
            {
                return Ok(challenge);
            }
        }
        let offered: Vec<String> = authorization
            .challenges
            .iter()
            .map(|challenge| challenge.challenge_type.clone())
            .collect();
        let identifier = authorization
            .identifier
            .as_ref()
            .map(|identifier| identifier.value.clone())
            .unwrap_or_else(|| "unknown identifier".to_string());
        Err(AcmeError::NoSupportedChallenge {
            identifier,
            offered,
        }
        .into())
    }

    /// Select the challenges to solve for every authorization.
    pub fn select_all<'authorization>(
        &self,
        authorizations: &'authorization [Authorization],
    ) -> Result<Vec<&'authorization Challenge>> {
        authorizations
            .iter()
            .map(|authorization| self.select(authorization))
            .collect()
    }
}

// ---- polling ---------------------------------------------------------------------------------

/// Asynchronous sleep abstraction used by polling loops, so tests do not wait in real time.
#[async_trait]
pub trait AcmeClock: Send + Sync {
    /// Sleep for `duration`.
    async fn sleep(&self, duration: Duration);
}

/// Real-time clock backed by tokio.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioClock;

#[async_trait]
impl AcmeClock for TokioClock {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Polling policy for order and authorization resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollPolicy {
    /// Delay used when the server sends no `Retry-After` header.
    pub default_interval: Duration,
    /// Legacy fallback bound (retained for API compatibility). Caddy/acmez honour the server's
    /// `Retry-After` exactly, so [`Self::delay`] no longer clamps it; this value is unused by the
    /// polling loop.
    pub max_interval: Duration,
    /// Maximum number of polls before giving up.
    pub max_attempts: u32,
}

impl Default for PollPolicy {
    fn default() -> Self {
        Self {
            default_interval: Duration::from_secs(2),
            max_interval: Duration::from_secs(10),
            max_attempts: 30,
        }
    }
}

impl PollPolicy {
    /// Create a policy with explicit values.
    pub fn new(default_interval: Duration, max_interval: Duration, max_attempts: u32) -> Self {
        Self {
            default_interval,
            max_interval,
            max_attempts,
        }
    }

    fn delay(&self, retry_after: Option<Duration>) -> Duration {
        // Caddy/acmez honour the CA's Retry-After verbatim (`retryAfter` in acmez returns
        // time.Until(raTime)); clamping it would poll earlier than the CA asked and diverge from
        // their polling behaviour.
        retry_after.unwrap_or(self.default_interval)
    }
}

/// Parse an HTTP `Retry-After` header value (delta-seconds or HTTP-date).
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = httpdate::parse_http_date(value)?;
    Some(
        date.duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO),
    )
}

/// Extract the `Retry-After` duration from a response.
pub fn retry_after(response: &HttpResponse) -> Option<Duration> {
    parse_retry_after(response.header(RETRY_AFTER_HEADER)?)
}

// ---- fetch results ---------------------------------------------------------------------------

/// A fetched order plus its polling hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderFetch {
    /// Order URL.
    pub url: String,
    /// Order object.
    pub order: Order,
    /// `Retry-After` from the response, when present.
    pub retry_after: Option<Duration>,
}

/// A fetched authorization plus its polling hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationFetch {
    /// Authorization URL.
    pub url: String,
    /// Authorization object.
    pub authorization: Authorization,
    /// `Retry-After` from the response, when present.
    pub retry_after: Option<Duration>,
}

/// A challenge acknowledgement response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeFetch {
    /// Challenge object returned by the CA.
    pub challenge: Challenge,
    /// `Retry-After` from the response, when present.
    pub retry_after: Option<Duration>,
}

/// A downloaded certificate chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    /// Certificate URL the chain was downloaded from.
    pub url: String,
    /// Raw PEM body returned by the CA.
    pub pem_chain: String,
    /// Individual PEM certificate blocks, leaf first.
    pub certificates_pem: Vec<String>,
}

impl IssuedCertificate {
    /// The leaf certificate PEM, when the chain contains one.
    pub fn leaf_pem(&self) -> Option<&str> {
        self.certificates_pem.first().map(String::as_str)
    }

    /// Number of certificates in the chain.
    pub fn len(&self) -> usize {
        self.certificates_pem.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.certificates_pem.is_empty()
    }
}

/// Split a PEM certificate chain into individual certificate blocks, leaf first.
pub fn parse_pem_certificate_chain(pem: &str) -> Result<Vec<String>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed == BEGIN {
            if current.is_some() {
                return Err(AcmeError::Decode {
                    url: "certificate chain".to_string(),
                    reason: "nested BEGIN CERTIFICATE block".to_string(),
                }
                .into());
            }
            current = Some(format!("{BEGIN}\n"));
        } else if trimmed == END {
            let Some(mut block) = current.take() else {
                return Err(AcmeError::Decode {
                    url: "certificate chain".to_string(),
                    reason: "END CERTIFICATE without BEGIN".to_string(),
                }
                .into());
            };
            block.push_str(END);
            block.push('\n');
            blocks.push(block);
        } else if let Some(block) = current.as_mut() {
            block.push_str(trimmed);
            block.push('\n');
        }
    }
    if current.is_some() {
        return Err(AcmeError::Decode {
            url: "certificate chain".to_string(),
            reason: "unterminated CERTIFICATE block".to_string(),
        }
        .into());
    }
    if blocks.is_empty() {
        return Err(AcmeError::Decode {
            url: "certificate chain".to_string(),
            reason: "response does not contain a PEM certificate".to_string(),
        }
        .into());
    }
    Ok(blocks)
}

// ---- account-bound client --------------------------------------------------------------------

/// An [`AcmeClient`] bound to a registered account, which supplies the JWS `kid`.
pub struct AcmeAccountClient<T: AcmeTransport> {
    client: AcmeClient<T>,
    account: StoredAccount,
}

impl<T: AcmeTransport> AcmeAccountClient<T> {
    /// Bind `client` to `account`.
    ///
    /// Fails when the account was registered against a different directory URL.
    pub fn new(client: AcmeClient<T>, account: StoredAccount) -> Result<Self> {
        if client.directory_url() != account.directory_url {
            return Err(AcmeError::MismatchedAccountDirectory {
                account_directory_url: account.directory_url.clone(),
                directory_url: client.directory_url().to_string(),
            }
            .into());
        }
        Ok(Self { client, account })
    }

    /// The underlying ACME client.
    pub fn client(&self) -> &AcmeClient<T> {
        &self.client
    }

    /// The registered account.
    pub fn account(&self) -> &StoredAccount {
        &self.account
    }

    /// The account URL used as the JWS `kid`.
    pub fn account_url(&self) -> &str {
        &self.account.account_url
    }

    /// Fetch `url` with an authenticated POST-as-GET (RFC 8555 §6.3).
    async fn post_as_get(&self, url: &str) -> Result<HttpResponse> {
        self.client
            .post_signed(url, Some(self.account_url()), b"")
            .await
    }

    /// Signed POST of a JSON payload.
    async fn post_json(&self, url: &str, payload: &[u8]) -> Result<HttpResponse> {
        self.client
            .post_signed(url, Some(self.account_url()), payload)
            .await
    }

    /// Create a new order (RFC 8555 §7.4).
    pub async fn new_order(&self, request: &NewOrderRequest) -> Result<OrderHandle> {
        let url = self.client.directory().new_order.clone();
        let payload = serde_json::to_vec(request).map_err(|error| AcmeError::Decode {
            url: url.clone(),
            reason: error.to_string(),
        })?;
        let response = self.post_json(&url, &payload).await?;
        if !response.is_success() {
            return Err(response_error(&url, &response));
        }
        let order: Order = response.json(&url)?;
        check_order_not_invalid(&url, &order, &response)?;
        let order_url = response
            .location()
            .ok_or_else(|| AcmeError::MissingHeader {
                url: url.clone(),
                header: "Location",
            })?
            .to_string();
        Ok(OrderHandle {
            url: order_url,
            order,
        })
    }

    /// Fetch an order with POST-as-GET.
    pub async fn fetch_order(&self, order_url: &str) -> Result<OrderFetch> {
        let response = self.post_as_get(order_url).await?;
        if !response.is_success() {
            return Err(response_error(order_url, &response));
        }
        let order: Order = response.json(order_url)?;
        Ok(OrderFetch {
            url: order_url.to_string(),
            order,
            retry_after: retry_after(&response),
        })
    }

    /// Fetch an authorization with POST-as-GET.
    pub async fn fetch_authorization(&self, authorization_url: &str) -> Result<AuthorizationFetch> {
        let response = self.post_as_get(authorization_url).await?;
        if !response.is_success() {
            return Err(response_error(authorization_url, &response));
        }
        let authorization: Authorization = response.json(authorization_url)?;
        Ok(AuthorizationFetch {
            url: authorization_url.to_string(),
            authorization,
            retry_after: retry_after(&response),
        })
    }

    /// Acknowledge a challenge: POST `{}` to its URL (RFC 8555 §7.5.1).
    pub async fn acknowledge_challenge(&self, challenge: &Challenge) -> Result<ChallengeFetch> {
        let url = challenge.url.clone();
        if url.is_empty() {
            return Err(AcmeError::MissingHeader {
                url: "challenge".to_string(),
                header: "url",
            }
            .into());
        }
        let response = self.post_json(&url, b"{}").await?;
        if !response.is_success() {
            return Err(response_error(&url, &response));
        }
        let acknowledged: Challenge = response.json(&url)?;
        if acknowledged.status == ChallengeStatus::Invalid {
            return Err(challenge_invalid_error(&url, &acknowledged, &response));
        }
        Ok(ChallengeFetch {
            challenge: acknowledged,
            retry_after: retry_after(&response),
        })
    }

    /// Fetch every authorization of `order`.
    pub async fn fetch_authorizations(&self, order: &Order) -> Result<Vec<AuthorizationFetch>> {
        let mut fetched = Vec::with_capacity(order.authorizations.len());
        for url in &order.authorizations {
            fetched.push(self.fetch_authorization(url).await?);
        }
        Ok(fetched)
    }

    /// Poll an authorization until it is `valid`.
    ///
    /// Honours `Retry-After` exactly and returns a typed
    /// [`AcmeError::InvalidAuthorization`] when the CA rejects a challenge.
    pub async fn poll_authorization(
        &self,
        authorization_url: &str,
        policy: &PollPolicy,
        clock: &dyn AcmeClock,
    ) -> Result<AuthorizationFetch> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let fetched = self.fetch_authorization(authorization_url).await?;
            match fetched.authorization.status {
                AuthorizationStatus::Valid => return Ok(fetched),
                AuthorizationStatus::Invalid => {
                    return Err(authorization_invalid_error(
                        authorization_url,
                        &fetched.authorization,
                    ));
                }
                AuthorizationStatus::Pending => {
                    if attempts >= policy.max_attempts {
                        return Err(AcmeError::PollingTimeout {
                            url: authorization_url.to_string(),
                            attempts,
                        }
                        .into());
                    }
                    clock.sleep(policy.delay(fetched.retry_after)).await;
                }
                other => {
                    return Err(AcmeError::UnexpectedAuthorizationStatus {
                        url: authorization_url.to_string(),
                        status: other.as_str().to_string(),
                    }
                    .into())
                }
            }
        }
    }

    /// Poll an order until it reaches `ready` or `valid`.
    pub async fn poll_order_ready(
        &self,
        order_url: &str,
        policy: &PollPolicy,
        clock: &dyn AcmeClock,
    ) -> Result<OrderFetch> {
        self.poll_order_until(
            order_url,
            policy,
            clock,
            &[OrderStatus::Ready, OrderStatus::Valid],
        )
        .await
    }

    /// Poll an order until it is `valid`.
    pub async fn poll_order_valid(
        &self,
        order_url: &str,
        policy: &PollPolicy,
        clock: &dyn AcmeClock,
    ) -> Result<OrderFetch> {
        self.poll_order_until(order_url, policy, clock, &[OrderStatus::Valid])
            .await
    }

    async fn poll_order_until(
        &self,
        order_url: &str,
        policy: &PollPolicy,
        clock: &dyn AcmeClock,
        wanted: &[OrderStatus],
    ) -> Result<OrderFetch> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let fetched = self.fetch_order(order_url).await?;
            if wanted.contains(&fetched.order.status) {
                return Ok(fetched);
            }
            match fetched.order.status {
                OrderStatus::Invalid => {
                    return Err(order_invalid_error(order_url, &fetched.order));
                }
                OrderStatus::Pending | OrderStatus::Processing | OrderStatus::Ready => {
                    if attempts >= policy.max_attempts {
                        return Err(AcmeError::PollingTimeout {
                            url: order_url.to_string(),
                            attempts,
                        }
                        .into());
                    }
                    clock.sleep(policy.delay(fetched.retry_after)).await;
                }
                OrderStatus::Unknown => {
                    return Err(AcmeError::UnexpectedOrderStatus {
                        url: order_url.to_string(),
                        status: fetched.order.status.as_str().to_string(),
                        expected: wanted
                            .iter()
                            .map(|status| status.as_str())
                            .collect::<Vec<_>>()
                            .join(" or "),
                    }
                    .into())
                }
                // INFEASIBLE: the outer match handles every ACME order status.
                _ => unreachable!("all order statuses are handled above"),
            }
        }
    }

    /// Finalize `order` with `csr` (RFC 8555 §7.4).
    pub async fn finalize_order(
        &self,
        order: &OrderHandle,
        csr: &CertificateRequest,
    ) -> Result<OrderFetch> {
        if order.order.finalize.is_empty() {
            return Err(AcmeError::UnexpectedOrderStatus {
                url: order.url.clone(),
                status: order.order.status.as_str().to_string(),
                expected: "an order with a finalize URL".to_string(),
            }
            .into());
        }
        let payload = serde_json::json!({ "csr": URL_SAFE_NO_PAD.encode(csr.der()) });
        let payload = serde_json::to_vec(&payload).map_err(|error| AcmeError::Decode {
            url: order.url.clone(),
            reason: error.to_string(),
        })?;
        let response = self.post_json(&order.order.finalize, &payload).await?;
        if !response.is_success() {
            return Err(response_error(&order.order.finalize, &response));
        }
        let finalized: Order = response.json(&order.order.finalize)?;
        check_order_not_invalid(&order.order.finalize, &finalized, &response)?;
        if !matches!(
            finalized.status,
            OrderStatus::Processing | OrderStatus::Valid | OrderStatus::Ready
        ) {
            return Err(AcmeError::UnexpectedOrderStatus {
                url: order.order.finalize.clone(),
                status: finalized.status.as_str().to_string(),
                expected: "processing or valid".to_string(),
            }
            .into());
        }
        Ok(OrderFetch {
            url: order.url.clone(),
            order: finalized,
            retry_after: retry_after(&response),
        })
    }

    /// Download the certificate chain for a `valid` order (RFC 8555 §7.4.2).
    pub async fn download_certificate(&self, order: &Order) -> Result<IssuedCertificate> {
        let Some(certificate_url) = order.certificate.clone() else {
            return Err(AcmeError::MissingCertificateUrl {
                url: "order".to_string(),
                status: order.status.as_str().to_string(),
            }
            .into());
        };
        let response = self
            .client
            .post_signed_headers(
                &certificate_url,
                Some(self.account_url()),
                b"",
                &[(
                    "Accept".to_string(),
                    PEM_CERTIFICATE_CHAIN_CONTENT_TYPE.to_string(),
                )],
            )
            .await?;
        if !response.is_success() {
            return Err(response_error(&certificate_url, &response));
        }
        let pem_chain = response.body_text();
        let certificates_pem = parse_pem_certificate_chain(&pem_chain)?;
        Ok(IssuedCertificate {
            url: certificate_url,
            pem_chain,
            certificates_pem,
        })
    }

    /// Poll `order_url` until valid and download its chain.
    pub async fn wait_for_certificate(
        &self,
        order_url: &str,
        policy: &PollPolicy,
        clock: &dyn AcmeClock,
    ) -> Result<IssuedCertificate> {
        let fetched = self.poll_order_valid(order_url, policy, clock).await?;
        self.download_certificate(&fetched.order).await
    }
}

fn check_order_not_invalid(url: &str, order: &Order, response: &HttpResponse) -> Result<()> {
    if order.status != OrderStatus::Invalid {
        return Ok(());
    }
    // Prefer the order's error object; fall back to any problem document in the response body.
    let problem = order.error.clone().or_else(|| response.problem());
    let detail = problem
        .as_ref()
        .map(crate::acme::Problem::diagnostic)
        .unwrap_or_else(|| "order is invalid".to_string());
    Err(AcmeError::InvalidOrder {
        url: url.to_string(),
        detail,
        problem,
    }
    .into())
}

fn order_invalid_error(url: &str, order: &Order) -> Error {
    let problem = order.error.clone();
    let detail = problem
        .as_ref()
        .map(crate::acme::Problem::diagnostic)
        .unwrap_or_else(|| "order is invalid".to_string());
    AcmeError::InvalidOrder {
        url: url.to_string(),
        detail,
        problem,
    }
    .into()
}

fn authorization_invalid_error(url: &str, authorization: &Authorization) -> Error {
    let failed = authorization
        .challenges
        .iter()
        .find(|challenge| challenge.error.is_some());
    let problem = failed.and_then(|challenge| challenge.error.clone());
    let detail = problem
        .as_ref()
        .map(crate::acme::Problem::diagnostic)
        .unwrap_or_else(|| "authorization is invalid".to_string());
    AcmeError::InvalidAuthorization {
        url: url.to_string(),
        detail,
        problem,
    }
    .into()
}

fn challenge_invalid_error(url: &str, challenge: &Challenge, response: &HttpResponse) -> Error {
    let problem = challenge.error.clone().or_else(|| response.problem());
    let detail = problem
        .as_ref()
        .map(crate::acme::Problem::diagnostic)
        .unwrap_or_else(|| "challenge is invalid".to_string());
    AcmeError::InvalidChallenge {
        url: url.to_string(),
        challenge_type: challenge.challenge_type.clone(),
        detail,
        problem,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use crate::acme::{AccountKey, AccountStatus, HttpMethod, HttpRequest};

    // ---- scripted transport ------------------------------------------------------------------

    #[derive(Debug)]
    struct ScriptedTransport {
        script: Mutex<VecDeque<(HttpMethod, String, HttpResponse)>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl ScriptedTransport {
        fn new(script: Vec<(HttpMethod, &str, HttpResponse)>) -> Self {
            Self {
                script: Mutex::new(
                    script
                        .into_iter()
                        .map(|(method, url, response)| (method, url.to_string(), response))
                        .collect(),
                ),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn remaining(&self) -> usize {
            self.script
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
        }
    }

    #[async_trait]
    impl AcmeTransport for Arc<ScriptedTransport> {
        async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request.clone());
            let next = self
                .script
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or_else(|| {
                    panic!(
                        "scripted transport exhausted at {} {}",
                        request.method, request.url
                    )
                });
            assert_eq!(
                next.0, request.method,
                "unexpected method for {}",
                request.url
            );
            assert_eq!(next.1, request.url, "unexpected request URL");
            Ok(next.2)
        }
    }

    // ---- mock clock --------------------------------------------------------------------------

    #[derive(Debug, Default)]
    struct MockClock {
        sleeps: Mutex<Vec<Duration>>,
    }

    impl MockClock {
        fn sleeps(&self) -> Vec<Duration> {
            self.sleeps
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[async_trait]
    impl AcmeClock for MockClock {
        async fn sleep(&self, duration: Duration) {
            self.sleeps
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(duration);
        }
    }

    // ---- fixtures ----------------------------------------------------------------------------

    const DIRECTORY_URL: &str = "https://acme.test/directory";
    const ORDER_URL: &str = "https://acme.test/acme/order/1";
    const AUTHZ_URL: &str = "https://acme.test/acme/authz/1";
    const CHALLENGE_URL: &str = "https://acme.test/acme/chall/1";
    const FINALIZE_URL: &str = "https://acme.test/acme/order/1/finalize";
    const CERT_URL: &str = "https://acme.test/acme/cert/1";
    const ACCOUNT_URL: &str = "https://acme.test/acme/account/1";

    fn directory_response() -> HttpResponse {
        HttpResponse::with_json(
            200,
            &serde_json::json!({
                "newNonce": "https://acme.test/acme/new-nonce",
                "newAccount": "https://acme.test/acme/new-account",
                "newOrder": "https://acme.test/acme/new-order",
                "revokeCert": "https://acme.test/acme/revoke-cert",
                "meta": {"termsOfService": "https://acme.test/terms"}
            }),
        )
        .unwrap()
        .with_header("Replay-Nonce", "nonce-directory")
    }

    fn account() -> StoredAccount {
        StoredAccount {
            directory_url: DIRECTORY_URL.to_string(),
            account_url: ACCOUNT_URL.to_string(),
            contact: vec!["mailto:ops@example.com".to_string()],
            status: AccountStatus::Valid,
            terms_of_service_agreed: true,
            key_thumbprint: String::new(),
        }
    }

    fn order_json(status: &str) -> serde_json::Value {
        let mut order = serde_json::json!({
            "status": status,
            "expires": "2026-01-01T00:00:00Z",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": [AUTHZ_URL],
            "finalize": FINALIZE_URL
        });
        if status == "valid" {
            order["certificate"] = serde_json::json!(CERT_URL);
        }
        order
    }

    fn authorization_json(
        status: &str,
        challenge_status: &str,
        error: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut challenge = serde_json::json!({
            "type": "http-01",
            "url": CHALLENGE_URL,
            "status": challenge_status,
            "token": "token-1"
        });
        if let Some(error) = error {
            challenge["error"] = error;
        }
        serde_json::json!({
            "status": status,
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [challenge],
            "wildcard": false
        })
    }

    fn challenge_json(status: &str) -> HttpResponse {
        HttpResponse::with_json(
            200,
            &serde_json::json!({
                "type": "http-01",
                "url": CHALLENGE_URL,
                "status": status,
                "token": "token-1"
            }),
        )
        .unwrap()
        .with_header("Replay-Nonce", "nonce-reply")
    }

    fn json_response(status: u16, value: &serde_json::Value) -> HttpResponse {
        HttpResponse::with_json(status, value)
            .unwrap()
            .with_header("Replay-Nonce", "nonce-reply")
    }

    fn signed_payload(request: &HttpRequest) -> serde_json::Value {
        let jws: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let payload = jws["payload"].as_str().unwrap();
        if payload.is_empty() {
            return serde_json::Value::Null;
        }
        let bytes = URL_SAFE_NO_PAD.decode(payload.as_bytes()).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn jws_field(request: &HttpRequest, field: &str) -> String {
        let jws: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        jws[field].as_str().unwrap().to_string()
    }

    fn signed_header(request: &HttpRequest) -> serde_json::Value {
        let protected = jws_field(request, "protected");
        let bytes = URL_SAFE_NO_PAD.decode(protected.as_bytes()).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn account_client(
        script: Vec<(HttpMethod, &str, HttpResponse)>,
    ) -> (
        Arc<ScriptedTransport>,
        AcmeAccountClient<Arc<ScriptedTransport>>,
    ) {
        let transport = Arc::new(ScriptedTransport::new(script));
        let client = AcmeClient::connect(
            transport.clone(),
            DIRECTORY_URL,
            AccountKey::generate().unwrap(),
        )
        .await
        .unwrap();
        let account_client = AcmeAccountClient::new(client, account()).unwrap();
        (transport, account_client)
    }

    // ---- tests -------------------------------------------------------------------------------

    #[test]
    fn parses_retry_after_seconds_and_http_date() {
        assert_eq!(parse_retry_after("3"), Some(Duration::from_secs(3)));
        assert_eq!(parse_retry_after(" 0 "), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("not-a-date"), None);
        let future = SystemTime::now() + Duration::from_secs(30);
        let header = httpdate::fmt_http_date(future);
        let parsed = parse_retry_after(&header).unwrap();
        assert!(parsed <= Duration::from_secs(30), "{parsed:?}");
        assert!(parsed >= Duration::from_secs(25), "{parsed:?}");
        // Retry-After is honoured exactly, matching Caddy/acmez (no policy clamp).
        let policy = PollPolicy::new(Duration::from_secs(2), Duration::from_secs(5), 3);
        assert_eq!(
            policy.delay(Some(Duration::from_secs(120))),
            Duration::from_secs(120)
        );
        assert_eq!(policy.delay(None), Duration::from_secs(2));
    }

    #[test]
    fn new_order_request_identifies_dns_and_ip() {
        let request = NewOrderRequest::for_domains(&[
            "Example.COM".to_string(),
            "example.com".to_string(),
            "127.0.0.1".to_string(),
        ])
        .with_validity(
            Some("2026-01-01T00:00:00Z".to_string()),
            Some("2026-03-01T00:00:00Z".to_string()),
        );
        assert_eq!(
            request.identifiers,
            vec![Identifier::dns("example.com"), Identifier::ip("127.0.0.1")]
        );
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["notBefore"], "2026-01-01T00:00:00Z");
        assert_eq!(value["notAfter"], "2026-03-01T00:00:00Z");
        assert_eq!(value["identifiers"][0]["type"], "dns");
    }

    #[tokio::test]
    async fn new_order_signs_request_with_account_kid_and_captures_location() {
        let (transport, client) = account_client(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Post,
                "https://acme.test/acme/new-order",
                json_response(201, &order_json("pending"))
                    .with_header("Location", ORDER_URL)
                    .with_header("Replay-Nonce", "nonce-2"),
            ),
        ])
        .await;
        let request = NewOrderRequest::for_domains(&["example.com".to_string()]).with_validity(
            Some("2026-01-01T00:00:00Z".to_string()),
            Some("2026-03-01T00:00:00Z".to_string()),
        );
        let handle = client.new_order(&request).await.unwrap();
        assert_eq!(handle.url, ORDER_URL);
        assert_eq!(handle.order.status, OrderStatus::Pending);
        assert_eq!(handle.order.finalize, FINALIZE_URL);
        assert_eq!(handle.order.authorizations, vec![AUTHZ_URL.to_string()]);

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        let post = &requests[1];
        let header = signed_header(post);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], ACCOUNT_URL);
        assert_eq!(header["url"], "https://acme.test/acme/new-order");
        assert!(header.get("jwk").is_none(), "account requests must use kid");
        let payload = signed_payload(post);
        assert_eq!(payload["identifiers"][0]["value"], "example.com");
        assert_eq!(payload["notBefore"], "2026-01-01T00:00:00Z");
        assert_eq!(payload["notAfter"], "2026-03-01T00:00:00Z");
        assert_eq!(transport.remaining(), 0);
    }

    #[tokio::test]
    async fn order_lifecycle_success_polls_pending_ready_processing_valid_and_downloads_chain() {
        let pem_chain = concat!(
            "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n"
        );
        let (transport, client) = account_client(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Post,
                "https://acme.test/acme/new-order",
                json_response(201, &order_json("pending")).with_header("Location", ORDER_URL),
            ),
            (
                HttpMethod::Post,
                AUTHZ_URL,
                json_response(200, &authorization_json("pending", "pending", None)),
            ),
            (
                HttpMethod::Post,
                CHALLENGE_URL,
                challenge_json("processing"),
            ),
            (
                HttpMethod::Post,
                AUTHZ_URL,
                json_response(200, &authorization_json("valid", "valid", None)),
            ),
            (
                HttpMethod::Post,
                ORDER_URL,
                json_response(200, &order_json("ready")),
            ),
            (
                HttpMethod::Post,
                FINALIZE_URL,
                json_response(200, &order_json("processing")),
            ),
            (
                HttpMethod::Post,
                ORDER_URL,
                json_response(200, &order_json("valid")).with_header("Replay-Nonce", "nonce-3"),
            ),
            (
                HttpMethod::Post,
                CERT_URL,
                HttpResponse::new(200)
                    .with_header("Content-Type", PEM_CERTIFICATE_CHAIN_CONTENT_TYPE)
                    .with_body(pem_chain.as_bytes().to_vec()),
            ),
        ])
        .await;
        let policy = PollPolicy::default();
        let clock = MockClock::default();

        let handle = client
            .new_order(&NewOrderRequest::for_domains(&["example.com".to_string()]))
            .await
            .unwrap();
        let authorizations = client.fetch_authorizations(&handle.order).await.unwrap();
        assert_eq!(authorizations.len(), 1);
        let challenge = ChallengePolicy::default()
            .select(&authorizations[0].authorization)
            .unwrap()
            .clone();
        assert_eq!(challenge.kind(), Some(ChallengeType::Http01));
        client.acknowledge_challenge(&challenge).await.unwrap();
        client
            .poll_authorization(AUTHZ_URL, &policy, &clock)
            .await
            .unwrap();
        client
            .poll_order_ready(ORDER_URL, &policy, &clock)
            .await
            .unwrap();

        let csr = CertificateRequest::generate(&["example.com".to_string()]).unwrap();
        client.finalize_order(&handle, &csr).await.unwrap();
        let certificate = client
            .wait_for_certificate(ORDER_URL, &policy, &clock)
            .await
            .unwrap();
        assert_eq!(certificate.url, CERT_URL);
        assert_eq!(certificate.len(), 2);
        assert!(certificate.leaf_pem().unwrap().contains("LEAF"));
        assert!(certificate
            .certificates_pem
            .get(1)
            .unwrap()
            .contains("INTERMEDIATE"));

        // All requests after the directory GET were signed POSTs with the account kid.
        let requests = transport.requests();
        for request in &requests[1..] {
            assert_eq!(request.method, HttpMethod::Post);
            assert_eq!(
                request.header("Content-Type"),
                Some("application/jose+json")
            );
            assert_eq!(signed_header(request)["kid"], ACCOUNT_URL);
        }
        // The certificate download asked for the PEM chain media type.
        let download = requests.last().unwrap();
        assert_eq!(download.url, CERT_URL);
        assert_eq!(
            download.header("Accept"),
            Some(PEM_CERTIFICATE_CHAIN_CONTENT_TYPE)
        );
        assert_eq!(signed_payload(download), serde_json::Value::Null);
        assert_eq!(transport.remaining(), 0);
    }

    #[tokio::test]
    async fn poll_authorization_honours_retry_after_delays() {
        let (_, client) = account_client(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Post,
                AUTHZ_URL,
                json_response(200, &authorization_json("pending", "processing", None))
                    .with_header("Retry-After", "3"),
            ),
            (
                HttpMethod::Post,
                AUTHZ_URL,
                json_response(200, &authorization_json("pending", "processing", None)),
            ),
            (
                HttpMethod::Post,
                AUTHZ_URL,
                json_response(200, &authorization_json("valid", "valid", None)),
            ),
        ])
        .await;
        let clock = MockClock::default();
        let policy = PollPolicy::new(Duration::from_secs(2), Duration::from_secs(10), 10);
        client
            .poll_authorization(AUTHZ_URL, &policy, &clock)
            .await
            .unwrap();
        assert_eq!(
            clock.sleeps(),
            vec![Duration::from_secs(3), Duration::from_secs(2)]
        );
    }

    #[tokio::test]
    async fn poll_authorization_surfaces_invalid_challenge_problem() {
        let (_, client) = account_client(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Post,
                AUTHZ_URL,
                json_response(
                    200,
                    &authorization_json(
                        "invalid",
                        "invalid",
                        Some(serde_json::json!({
                            "type": "urn:ietf:params:acme:error:unauthorized",
                            "detail": "Invalid response from http://example.com/.well-known/acme-challenge/token-1",
                            "status": 403
                        })),
                    ),
                ),
            ),
        ])
        .await;
        let clock = MockClock::default();
        let error = client
            .poll_authorization(AUTHZ_URL, &PollPolicy::default(), &clock)
            .await
            .unwrap_err();
        let Error::Acme(acme_error) = error else {
            panic!("expected AcmeError, got {error:?}");
        };
        let AcmeError::InvalidAuthorization {
            url,
            detail,
            problem,
        } = acme_error.as_ref()
        else {
            panic!("expected InvalidAuthorization, got {acme_error:?}");
        };
        assert_eq!(url, AUTHZ_URL);
        assert!(detail.contains("Invalid response"), "{detail}");
        assert_eq!(
            problem.as_ref().unwrap().problem_type,
            "urn:ietf:params:acme:error:unauthorized"
        );
    }

    #[tokio::test]
    async fn poll_order_surfaces_invalid_order_error() {
        let mut invalid = order_json("invalid");
        invalid["error"] = serde_json::json!({
            "type": "urn:ietf:params:acme:error:orderNotReady",
            "detail": "Order is not ready for finalization",
            "status": 403
        });
        let (_, client) = account_client(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (HttpMethod::Post, ORDER_URL, json_response(200, &invalid)),
        ])
        .await;
        let clock = MockClock::default();
        let error = client
            .poll_order_ready(ORDER_URL, &PollPolicy::default(), &clock)
            .await
            .unwrap_err();
        let Error::Acme(acme_error) = error else {
            panic!("expected AcmeError, got {error:?}");
        };
        assert!(
            matches!(acme_error.as_ref(), AcmeError::InvalidOrder { .. }),
            "expected InvalidOrder, got {acme_error:?}"
        );
        assert!(acme_error
            .to_string()
            .contains("not ready for finalization"));
        assert!(clock.sleeps().is_empty(), "invalid orders are terminal");
    }

    #[tokio::test]
    async fn poll_order_times_out_after_attempt_budget() {
        let (transport, client) = account_client(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Post,
                ORDER_URL,
                json_response(200, &order_json("processing")),
            ),
            (
                HttpMethod::Post,
                ORDER_URL,
                json_response(200, &order_json("processing")),
            ),
        ])
        .await;
        let clock = MockClock::default();
        let policy = PollPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 2);
        let error = client
            .poll_order_valid(ORDER_URL, &policy, &clock)
            .await
            .unwrap_err();
        let Error::Acme(acme_error) = error else {
            panic!("expected AcmeError, got {error:?}");
        };
        assert!(
            matches!(
                acme_error.as_ref(),
                AcmeError::PollingTimeout { attempts: 2, .. }
            ),
            "expected PollingTimeout, got {acme_error:?}"
        );
        assert_eq!(clock.sleeps(), vec![Duration::from_secs(1)]);
        assert_eq!(transport.remaining(), 0);
    }

    #[tokio::test]
    async fn acknowledge_invalid_challenge_surfaces_problem() {
        let (_, client) = account_client(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Post,
                CHALLENGE_URL,
                HttpResponse::with_json(
                    200,
                    &serde_json::json!({
                        "type": "http-01",
                        "url": CHALLENGE_URL,
                        "status": "invalid",
                        "error": {
                            "type": "urn:ietf:params:acme:error:connection",
                            "detail": "connection refused",
                            "status": 400
                        }
                    }),
                )
                .unwrap(),
            ),
        ])
        .await;
        let challenge = Challenge {
            challenge_type: "http-01".to_string(),
            url: CHALLENGE_URL.to_string(),
            status: ChallengeStatus::Pending,
            token: "token-1".to_string(),
            validated: None,
            error: None,
        };
        let error = client.acknowledge_challenge(&challenge).await.unwrap_err();
        let Error::Acme(acme_error) = error else {
            panic!("expected AcmeError, got {error:?}");
        };
        let AcmeError::InvalidChallenge {
            challenge_type,
            detail,
            ..
        } = acme_error.as_ref()
        else {
            panic!("expected InvalidChallenge, got {acme_error:?}");
        };
        assert_eq!(challenge_type, "http-01");
        assert_eq!(detail, "connection refused");
    }

    #[test]
    fn challenge_selection_respects_policy_and_preference() {
        let authorization = Authorization {
            status: AuthorizationStatus::Pending,
            expires: None,
            identifier: Some(Identifier::dns("example.com")),
            challenges: vec![
                Challenge {
                    challenge_type: "tls-alpn-01".to_string(),
                    url: "https://acme.test/chall/alpn".to_string(),
                    status: ChallengeStatus::Pending,
                    token: "t".to_string(),
                    validated: None,
                    error: None,
                },
                Challenge {
                    challenge_type: "http-01".to_string(),
                    url: "https://acme.test/chall/http".to_string(),
                    status: ChallengeStatus::Pending,
                    token: "h".to_string(),
                    validated: None,
                    error: None,
                },
                Challenge {
                    challenge_type: "dns-01".to_string(),
                    url: "https://acme.test/chall/dns".to_string(),
                    status: ChallengeStatus::Pending,
                    token: "d".to_string(),
                    validated: None,
                    error: None,
                },
            ],
            wildcard: None,
        };
        // Default policy: DNS disabled, HTTP preferred over TLS-ALPN.
        assert_eq!(
            ChallengePolicy::default()
                .select(&authorization)
                .unwrap()
                .url,
            "https://acme.test/chall/http"
        );
        // DNS enabled wins the preference order.
        assert_eq!(
            ChallengePolicy::default()
                .with_dns01(true)
                .select(&authorization)
                .unwrap()
                .url,
            "https://acme.test/chall/dns"
        );
        // TLS-ALPN-only policy picks TLS-ALPN even though HTTP is offered first.
        assert_eq!(
            ChallengePolicy::tls_alpn_only()
                .select(&authorization)
                .unwrap()
                .url,
            "https://acme.test/chall/alpn"
        );
        // Explicit preference order is honoured.
        assert_eq!(
            ChallengePolicy::default()
                .with_preference(vec![
                    ChallengeType::TlsAlpn01,
                    ChallengeType::Http01,
                    ChallengeType::Dns01,
                ])
                .select(&authorization)
                .unwrap()
                .url,
            "https://acme.test/chall/alpn"
        );
        // Nothing enabled: located error listing what the CA offered.
        let policy = ChallengePolicy {
            http01: false,
            tls_alpn01: false,
            dns01: false,
            preference: Vec::new(),
        };
        let error = policy.select(&authorization).unwrap_err();
        assert_eq!(
            error.to_string(),
            "ACME error: authorization for `example.com` offers no enabled challenge (offered: [\"tls-alpn-01\", \"http-01\", \"dns-01\"])"
        );
    }

    #[test]
    fn challenge_selection_handles_unknown_and_missing_identifier() {
        let authorization = Authorization {
            status: AuthorizationStatus::Pending,
            expires: None,
            identifier: None,
            challenges: vec![Challenge {
                challenge_type: "proof-of-work-99".to_string(),
                url: "https://acme.test/chall/future".to_string(),
                status: ChallengeStatus::Pending,
                token: "f".to_string(),
                validated: None,
                error: None,
            }],
            wildcard: None,
        };
        let error = ChallengePolicy::default()
            .select(&authorization)
            .unwrap_err();
        assert!(error.to_string().contains("unknown identifier"), "{error}");
        assert!(error.to_string().contains("proof-of-work-99"), "{error}");
    }

    #[tokio::test]
    async fn finalize_posts_base64url_csr_and_rejects_bad_order_state() {
        let csr = CertificateRequest::generate(&["example.com".to_string()]).unwrap();
        let (transport, client) = account_client(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Post,
                FINALIZE_URL,
                json_response(200, &order_json("processing")),
            ),
        ])
        .await;
        let handle = OrderHandle {
            url: ORDER_URL.to_string(),
            order: serde_json::from_value(order_json("ready")).unwrap(),
        };
        let fetched = client.finalize_order(&handle, &csr).await.unwrap();
        assert_eq!(fetched.order.status, OrderStatus::Processing);
        let requests = transport.requests();
        let payload = signed_payload(requests.last().unwrap());
        let encoded = payload["csr"].as_str().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(encoded).unwrap(), csr.der());
        assert!(!encoded.contains('='));

        // An order with no finalize URL is rejected before any request is sent.
        let mut broken = handle.clone();
        broken.order.finalize.clear();
        let error = client.finalize_order(&broken, &csr).await.unwrap_err();
        assert!(error.to_string().contains("finalize URL"), "{error}");
    }

    #[tokio::test]
    async fn download_certificate_rejects_order_without_certificate_url() {
        let (_, client) =
            account_client(vec![(HttpMethod::Get, DIRECTORY_URL, directory_response())]).await;
        let order: Order = serde_json::from_value(order_json("ready")).unwrap();
        let error = client.download_certificate(&order).await.unwrap_err();
        let Error::Acme(acme_error) = error else {
            panic!("expected AcmeError, got {error:?}");
        };
        assert!(matches!(
            acme_error.as_ref(),
            AcmeError::MissingCertificateUrl { .. }
        ));
    }

    #[test]
    fn parses_pem_certificate_chain_independent_of_whitespace() {
        let pem = "\n-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n\n\
                   -----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n";
        let chain = parse_pem_certificate_chain(pem).unwrap();
        assert_eq!(chain.len(), 2);
        assert!(chain[0].starts_with("-----BEGIN CERTIFICATE-----\nLEAF"));
        assert!(chain[1].ends_with("-----END CERTIFICATE-----\n"));
        let error = parse_pem_certificate_chain("no certs here").unwrap_err();
        assert!(error
            .to_string()
            .contains("does not contain a PEM certificate"));
    }

    #[tokio::test]
    async fn account_client_rejects_mismatched_directory() {
        let transport = Arc::new(ScriptedTransport::new(vec![(
            HttpMethod::Get,
            DIRECTORY_URL,
            directory_response(),
        )]));
        let client = AcmeClient::connect(transport, DIRECTORY_URL, AccountKey::generate().unwrap())
            .await
            .unwrap();
        let mut other = account();
        other.directory_url = "https://other.test/directory".to_string();
        let error = match AcmeAccountClient::new(client, other) {
            Ok(_) => panic!("a client must reject an account from another directory"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("does not belong to directory"),
            "{error}"
        );
    }

    #[test]
    fn statuses_round_trip_from_wire_values() {
        let order: Order = serde_json::from_value(order_json("processing")).unwrap();
        assert_eq!(order.status, OrderStatus::Processing);
        assert!(order.status.is_in_progress());
        let authorization: Authorization =
            serde_json::from_value(authorization_json("valid", "valid", None)).unwrap();
        assert_eq!(authorization.status, AuthorizationStatus::Valid);
        assert_eq!(
            authorization.challenges[0].kind(),
            Some(ChallengeType::Http01)
        );
        assert_eq!(
            ChallengeType::from_wire("dns-01"),
            Some(ChallengeType::Dns01)
        );
        assert_eq!(ChallengeType::from_wire("unknown-99"), None);
    }
}
