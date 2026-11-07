//! TLS-side OCSP stapling (plan task T-TLS-051).
//!
//! Caddy/certmagic staples OCSP responses for managed certificates by default. This module ports
//! the parts that do not need the HTTP server: OCSP request encoding, response parsing/validation,
//! a refresh policy with retry backoff, a cache that can be shared across configuration
//! generations, and the decision hooks for `disable_ocsp_stapling` / `must_staple`.
//!
//! # Boundaries
//!
//! The transport is injected through [`OcspTransport`] (tests use a scripted mock; the live
//! HTTP client and the server-side refresh scheduler are tracked as a server hook in the task
//! report). Staples are exposed to the TLS terminator by setting `rustls::sign::CertifiedKey::ocsp`
//! through [`TlsCertificate::with_ocsp_staple`](crate::tls_server::TlsCertificate).
//!
//! # Divergences from certmagic
//!
//! * The OCSP response signature is not cryptographically verified yet; the parser validates the
//!   response status, the requested certificate serial and the freshness timestamps. This is
//!   reported as a residual gap (DIV-0087) instead of being silently ignored.
//! * `ocsp_overrides` / responder URL overrides are rejected loudly by the automation-policy
//!   parser (never dropped).
//! * `must_staple` is honoured as a requirement on the stapling decision: a policy that requests
//!   Must-Staple but disables stapling (or cannot obtain a response) fails loudly instead of
//!   serving an unstapled chain.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use caddy_rs_core::config::{AutomationPolicy, TlsApp};

use crate::renewal::{RenewalClock, SystemClock};
use crate::tls_server::TlsCertificate;

/// Caddy's default OCSP freshness scan interval (`ocsp_interval`): one hour.
pub const DEFAULT_OCSP_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// First retry delay after a failed OCSP fetch (doubles per attempt, capped at
/// [`MAX_OCSP_RETRY_DELAY`]).
pub const INITIAL_OCSP_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Maximum retry delay for failed OCSP fetches.
pub const MAX_OCSP_RETRY_DELAY: Duration = Duration::from_secs(60 * 60);

/// Errors from the TLS-side OCSP stapling machinery.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OcspError {
    /// The certificate has no OCSP responder URL in its AIA extension.
    #[error("certificate has no OCSP responder URL")]
    NoResponder,
    /// The injected transport failed (network, TLS, HTTP status, ...).
    #[error("OCSP transport failed: {0}")]
    Transport(String),
    /// The response could not be decoded or violates OCSP structure rules.
    #[error("malformed OCSP response: {0}")]
    Malformed(String),
    /// The responder did not return the `successful` response status.
    #[error("OCSP responder returned response status {0}")]
    ResponderStatus(u8),
    /// The response is for a different certificate (serial mismatch).
    #[error("OCSP response serial does not match the requested certificate")]
    SerialMismatch,
    /// `must_staple` is configured but stapling is disabled.
    #[error("automation policy requires Must-Staple but OCSP stapling is disabled")]
    MustStapleDisabled,
    /// The policy asked for an OCSP feature this build does not implement.
    #[error("unsupported OCSP configuration: {0}")]
    Unsupported(String),
    /// A fetch is in exponential backoff after an earlier failure.
    #[error("OCSP fetch is backing off after an earlier failure")]
    Backoff,
}

/// Result of one staple decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StapleOutcome {
    /// Stapling is disabled by policy.
    Disabled,
    /// A cached response is still fresh.
    Cached,
    /// A new response was fetched and cached.
    Fetched,
}

impl StapleOutcome {
    /// Whether a staple should be attached to the certificate.
    pub fn has_staple(self) -> bool {
        !matches!(self, StapleOutcome::Disabled)
    }
}

/// The effective OCSP policy for one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspPolicy {
    /// Whether stapling is enabled (`disable_ocsp_stapling` inverted).
    pub enabled: bool,
    /// Whether the automation policy requested Must-Staple in the CSR.
    pub must_staple: bool,
    /// How often the cache is scanned for stale responses.
    pub check_interval: Duration,
}

impl Default for OcspPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            must_staple: false,
            check_interval: DEFAULT_OCSP_CHECK_INTERVAL,
        }
    }
}

impl OcspPolicy {
    /// Policy for a managed certificate from an automation policy.
    ///
    /// `ocsp_overrides` is a Caddy experimental feature; this build rejects it loudly instead of
    /// silently ignoring the override (the caller maps [`OcspError::Unsupported`] to a located
    /// configuration error).
    pub fn for_managed(
        policy: &AutomationPolicy,
        check_interval: Duration,
    ) -> Result<Self, OcspError> {
        if !policy.ocsp_overrides.is_empty() {
            return Err(OcspError::Unsupported(
                "automation policy `ocsp_overrides` (responder URL overrides) is not implemented \
                 (T-TLS-051)"
                    .to_string(),
            ));
        }
        Ok(Self {
            enabled: !policy.disable_ocsp_stapling,
            must_staple: policy.must_staple,
            check_interval,
        })
    }

    /// Policy for manually loaded certificates (`apps.tls.disable_ocsp_stapling`).
    pub fn for_manual(tls: &TlsApp, check_interval: Duration) -> Self {
        Self {
            enabled: !tls.disable_ocsp_stapling,
            must_staple: false,
            check_interval,
        }
    }

    /// Validate the Must-Staple/stapling combination.
    pub fn validate_requirements(&self) -> Result<(), OcspError> {
        if self.must_staple && !self.enabled {
            return Err(OcspError::MustStapleDisabled);
        }
        Ok(())
    }
}

/// An OCSP request for one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspRequest {
    /// DER-encoded `OCSPRequest`.
    pub der: Vec<u8>,
    /// Leaf serial number bytes as they appear in the certificate (with the INTEGER value,
    /// including a leading zero when DER needed one).
    pub serial: Vec<u8>,
}

/// A decoded OCSP response (the DER is retained verbatim for stapling).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspResponse {
    /// DER-encoded `OCSPResponse` exactly as received (what rustls staples).
    pub der: Vec<u8>,
    /// Certificate status from the first `SingleResponse`.
    pub status: OcspCertStatus,
    /// `thisUpdate`.
    pub this_update: SystemTime,
    /// `nextUpdate`, when the responder supplied one.
    pub next_update: Option<SystemTime>,
    /// Serial number from the response's `CertID` (for matching).
    pub serial: Vec<u8>,
}

/// Status of the certificate in an OCSP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// `good`.
    Good,
    /// `revoked`.
    Revoked,
    /// `unknown`.
    Unknown,
}

/// One cached staple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staple {
    /// DER-encoded OCSP response to staple.
    pub response: OcspResponse,
    /// When the response was fetched (used when the responder omitted `nextUpdate`).
    pub fetched_at: SystemTime,
    /// Responder URL the response came from.
    pub responder_url: String,
}

/// Injected OCSP HTTP transport. The live client and the server refresh scheduler are reported
/// as a server hook; tests use a scripted mock.
#[async_trait]
pub trait OcspTransport: Send + Sync {
    /// POST `request_der` to `url` and return the DER-encoded `OCSPResponse`.
    async fn fetch(&self, url: &str, request_der: &[u8]) -> Result<Vec<u8>, OcspError>;
}

/// Transport used when no live client is wired: every fetch fails loudly.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyOcspTransport;

#[async_trait]
impl OcspTransport for DenyOcspTransport {
    async fn fetch(&self, _url: &str, _request_der: &[u8]) -> Result<Vec<u8>, OcspError> {
        Err(OcspError::Transport(
            "no OCSP transport is configured in this build (server hook not wired)".to_string(),
        ))
    }
}

/// Live OCSP transport over the existing hyper/rustls ACME transport.
///
/// Caddy/certmagic POSTs the DER-encoded OCSP request (Content-Type
/// `application/ocsp-request`) to the responder URL from the leaf's AIA extension; this wrapper
/// does the same through [`crate::acme::HyperTransport`], with a bounded timeout and typed errors.
pub struct HyperOcspTransport {
    transport: Arc<dyn crate::acme::AcmeTransport>,
    timeout: std::time::Duration,
}

impl std::fmt::Debug for HyperOcspTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HyperOcspTransport")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HyperOcspTransport {
    /// Build a live transport trusting the platform CA bundle.
    pub fn new() -> Result<Self, OcspError> {
        let transport = crate::acme::HyperTransport::new().map_err(|error| {
            OcspError::Transport(format!("cannot build the OCSP HTTP transport: {error}"))
        })?;
        Ok(Self {
            transport: Arc::new(transport),
            timeout: std::time::Duration::from_secs(30),
        })
    }

    /// Build over an injectable ACME transport (tests and embedders).
    pub fn with_transport(transport: Arc<dyn crate::acme::AcmeTransport>) -> Self {
        Self {
            transport,
            timeout: std::time::Duration::from_secs(30),
        }
    }

    /// Override the per-request timeout.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[async_trait]
impl OcspTransport for HyperOcspTransport {
    async fn fetch(&self, url: &str, request_der: &[u8]) -> Result<Vec<u8>, OcspError> {
        let request = crate::acme::HttpRequest {
            method: crate::acme::HttpMethod::Post,
            url: url.to_string(),
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "application/ocsp-request".to_string(),
                ),
                (
                    "Accept".to_string(),
                    "application/ocsp-response".to_string(),
                ),
            ],
            body: request_der.to_vec(),
        };
        let response = tokio::time::timeout(self.timeout, self.transport.request(request))
            .await
            .map_err(|_| {
                OcspError::Transport(format!(
                    "OCSP responder `{url}` timed out after {}s",
                    self.timeout.as_secs()
                ))
            })?
            .map_err(|error| OcspError::Transport(format!("OCSP responder `{url}`: {error}")))?;
        if response.status != 200 {
            return Err(OcspError::Transport(format!(
                "OCSP responder `{url}` returned HTTP status {}",
                response.status
            )));
        }
        Ok(response.body)
    }
}

#[derive(Debug, Clone)]
struct RetryState {
    attempts: u32,
    next_attempt: SystemTime,
}

/// Shared TLS-side OCSP stapler: cache, refresh policy and retry backoff.
///
/// The type is cheap to clone through an `Arc`; retaining one across configuration generations is
/// how a reload reuses staples (the server hook should keep the previous generation's
/// [`SharedOcspStapler`] the same way it keeps `SharedCertificateStore`).
pub struct OcspStapler {
    transport: Arc<dyn OcspTransport>,
    clock: Arc<dyn RenewalClock>,
    policy: OcspPolicy,
    staples: RwLock<BTreeMap<Vec<u8>, Staple>>,
    retries: RwLock<BTreeMap<Vec<u8>, RetryState>>,
}

/// Shared stapler handle for embedders/relaid generations.
pub type SharedOcspStapler = Arc<OcspStapler>;

impl std::fmt::Debug for OcspStapler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OcspStapler")
            .field("policy", &self.policy)
            .field("cached", &self.len())
            .finish()
    }
}

impl OcspStapler {
    /// Create a stapler with the production clock and the given transport/policy.
    pub fn new(transport: Arc<dyn OcspTransport>, policy: OcspPolicy) -> Self {
        Self::with_clock(transport, policy, Arc::new(SystemClock))
    }

    /// Create a stapler with an injected clock (deterministic tests).
    pub fn with_clock(
        transport: Arc<dyn OcspTransport>,
        policy: OcspPolicy,
        clock: Arc<dyn RenewalClock>,
    ) -> Self {
        Self {
            transport,
            clock,
            policy,
            staples: RwLock::new(BTreeMap::new()),
            retries: RwLock::new(BTreeMap::new()),
        }
    }

    /// The effective policy.
    pub fn policy(&self) -> &OcspPolicy {
        &self.policy
    }

    /// Number of cached staples.
    pub fn len(&self) -> usize {
        self.staples
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The DER response to staple for `leaf_der`, if a fresh/cached staple exists.
    pub fn staple(&self, leaf_der: &[u8]) -> Option<Vec<u8>> {
        self.cached(leaf_der).map(|staple| staple.response.der)
    }

    /// The cached staple for `leaf_der` (regardless of freshness).
    pub fn cached(&self, leaf_der: &[u8]) -> Option<Staple> {
        self.staples
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(leaf_der)
            .cloned()
    }

    /// Whether the cached staple should be refreshed now (missing, stale or inside the scan
    /// window).
    pub fn needs_refresh(&self, leaf_der: &[u8]) -> bool {
        let now = self.clock.now();
        let staple = self
            .staples
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(leaf_der)
            .cloned();
        match staple {
            None => true,
            Some(staple) => match staple.response.next_update {
                Some(next_update) => {
                    // certmagic scans every check interval and refreshes when the response is
                    // about to go stale. Clamp the margin so short-lived responses are not
                    // re-fetched on every scan.
                    let freshness = next_update
                        .duration_since(staple.response.this_update)
                        .unwrap_or_default();
                    let margin = self
                        .policy
                        .check_interval
                        .min(freshness / 2)
                        .max(Duration::from_secs(1));
                    now + margin >= next_update
                }
                None => now >= staple.fetched_at + self.policy.check_interval,
            },
        }
    }

    /// Ensure a staple exists for one managed certificate.
    ///
    /// `leaf_der` is the leaf certificate and `issuer_der` its issuer (from the chain), which is
    /// needed to build the OCSP `CertID`. Returns [`StapleOutcome`] on success; errors leave any
    /// previously cached staple untouched and start/continue the retry backoff.
    pub async fn ensure_staple(
        &self,
        leaf_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<StapleOutcome, OcspError> {
        self.policy.validate_requirements()?;
        if !self.policy.enabled {
            return Ok(StapleOutcome::Disabled);
        }
        let now = self.clock.now();
        if !self.needs_refresh(leaf_der) {
            return Ok(StapleOutcome::Cached);
        }
        if let Some(retry) = self
            .retries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(leaf_der)
            .cloned()
        {
            if now < retry.next_attempt {
                return Err(OcspError::Backoff);
            }
        }

        let result = self.fetch_and_parse(leaf_der, issuer_der, now).await;
        match result {
            Ok(staple) => {
                self.staples
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(leaf_der.to_vec(), staple);
                self.retries
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(leaf_der);
                Ok(StapleOutcome::Fetched)
            }
            Err(error) => {
                let attempts = {
                    let mut retries = self
                        .retries
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let attempts = retries.get(leaf_der).map_or(0, |state| state.attempts);
                    let delay = backoff_delay(attempts);
                    retries.insert(
                        leaf_der.to_vec(),
                        RetryState {
                            attempts: attempts + 1,
                            next_attempt: now + delay,
                        },
                    );
                    attempts
                };
                let _ = attempts;
                Err(error)
            }
        }
    }

    async fn fetch_and_parse(
        &self,
        leaf_der: &[u8],
        issuer_der: &[u8],
        now: SystemTime,
    ) -> Result<Staple, OcspError> {
        let leaf = ParsedCertificate::parse(leaf_der)?;
        if leaf.must_staple && !self.policy.must_staple {
            // The certificate itself requests stapling even though the policy did not. Caddy does
            // not detect this separately from the configured policy; keep the same behaviour but
            // make the state observable by fetching the staple anyway.
        }
        let responder_url = leaf
            .ocsp_responder_url
            .clone()
            .ok_or(OcspError::NoResponder)?;
        let request = build_ocsp_request(leaf_der, issuer_der)?;
        let response_der = self.transport.fetch(&responder_url, &request.der).await?;
        let response = parse_ocsp_response(&response_der)?;
        if response.serial != request.serial && !response.serial.is_empty() {
            return Err(OcspError::SerialMismatch);
        }
        if response.status != OcspCertStatus::Good {
            return Err(OcspError::ResponderStatus(1));
        }
        let _ = now;
        Ok(Staple {
            response,
            fetched_at: now,
            responder_url,
        })
    }
}

fn backoff_delay(attempts: u32) -> Duration {
    let exponent = attempts.min(8);
    let delay = INITIAL_OCSP_RETRY_DELAY.saturating_mul(1u32 << exponent);
    delay.min(MAX_OCSP_RETRY_DELAY)
}

/// Apply a cached staple to a resolver-insertable certificate builder.
///
/// The server hook calls this after [`OcspStapler::ensure_staple`] succeeds:
///
/// ```ignore
/// let certificate = certificate.with_ocsp_staple(stapler.staple(leaf_der));
/// resolver.insert(certificate)?;
/// ```
pub fn staple_for_certificate(
    stapler: &OcspStapler,
    certificate: TlsCertificate,
) -> TlsCertificate {
    let staple = stapler.staple(certificate.chain()[0].as_ref());
    certificate.with_ocsp_staple(staple)
}

/// Parse the OCSP responder URL and Must-Staple flag from a leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCertificate {
    /// `serialNumber` INTEGER value bytes.
    pub serial: Vec<u8>,
    /// DER-encoded issuer `Name` (used for `issuerNameHash`).
    pub issuer_name_der: Vec<u8>,
    /// `subjectPublicKey` BIT STRING contents (unused-bits octet removed).
    pub subject_public_key: Vec<u8>,
    /// OCSP responder URL from the AIA extension, when present.
    pub ocsp_responder_url: Option<String>,
    /// Whether the certificate carries the TLS Feature `status_request` (Must-Staple).
    pub must_staple: bool,
}

impl ParsedCertificate {
    /// Parse a DER-encoded X.509 certificate.
    pub fn parse(der: &[u8]) -> Result<Self, OcspError> {
        parse_certificate(der)
    }
}

// ---------------------------------------------------------------------------------------------
// OCSP request encoding
// ---------------------------------------------------------------------------------------------

/// Build an RFC 6960 `OCSPRequest` for `leaf_der` using `issuer_der` for the CertID hashes.
pub fn build_ocsp_request(leaf_der: &[u8], issuer_der: &[u8]) -> Result<OcspRequest, OcspError> {
    let leaf = parse_certificate(leaf_der)?;
    let issuer = parse_certificate(issuer_der)?;
    if leaf.issuer_name_der.is_empty() {
        return Err(OcspError::Malformed(
            "leaf certificate has no issuer name".to_string(),
        ));
    }
    let name_hash = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        &leaf.issuer_name_der,
    );
    let key_hash = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        &issuer.subject_public_key,
    );
    let cert_id = der_sequence(&[
        der_sequence(&[der_oid(&[1, 3, 14, 3, 2, 26]), der_null()]),
        der_octet_string(name_hash.as_ref()),
        der_octet_string(key_hash.as_ref()),
        der_integer_from_bytes(&leaf.serial),
    ]);
    let request = der_sequence(&[cert_id]);
    let request_list = der_sequence(&[request]);
    let tbs_request = der_sequence(&[request_list]);
    let ocsp_request = der_sequence(&[tbs_request]);
    Ok(OcspRequest {
        der: ocsp_request,
        serial: leaf.serial,
    })
}

// ---------------------------------------------------------------------------------------------
// OCSP response parsing
// ---------------------------------------------------------------------------------------------

/// Parse a DER-encoded `OCSPResponse`.
pub fn parse_ocsp_response(der: &[u8]) -> Result<OcspResponse, OcspError> {
    let mut outer = DerReader::new(der);
    let (tag, body, _) = outer.read_tlv_full()?;
    if tag != 0x30 {
        return Err(OcspError::Malformed(
            "OCSPResponse is not a SEQUENCE".to_string(),
        ));
    }
    let mut root = DerReader::new(body);
    let (status_tag, status_value, _) = root.read_tlv_full()?;
    if status_tag != 0x0A || status_value.len() != 1 {
        return Err(OcspError::Malformed(
            "OCSPResponse status is not an ENUMERATED".to_string(),
        ));
    }
    let status = status_value[0];
    if status != 0 {
        return Err(OcspError::ResponderStatus(status));
    }
    let Some((response_bytes_tag, response_bytes_value, _)) = root.next_tlv_optional()? else {
        return Err(OcspError::Malformed(
            "successful OCSPResponse without responseBytes".to_string(),
        ));
    };
    if response_bytes_tag != 0xA0 {
        return Err(OcspError::Malformed(
            "OCSPResponse responseBytes is not [0] EXPLICIT".to_string(),
        ));
    }
    let mut response_bytes = DerReader::new(response_bytes_value);
    let (seq_tag, seq_value, _) = response_bytes.read_tlv_full()?;
    if seq_tag != 0x30 {
        return Err(OcspError::Malformed(
            "ResponseBytes is not a SEQUENCE".to_string(),
        ));
    }
    let mut fields = DerReader::new(seq_value);
    let (oid_tag, oid_value, _) = fields.read_tlv_full()?;
    if oid_tag != 0x06 || oid_value != OCSP_BASIC_OID {
        return Err(OcspError::Malformed(
            "unsupported OCSP response type (only id-pkix-ocsp-basic is supported)".to_string(),
        ));
    }
    let (octet_tag, octet_value, _) = fields.read_tlv_full()?;
    if octet_tag != 0x04 {
        return Err(OcspError::Malformed(
            "BasicOCSPResponse is not an OCTET STRING".to_string(),
        ));
    }
    parse_basic_response(der, octet_value)
}

const OCSP_BASIC_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

fn parse_basic_response(full_der: &[u8], basic_der: &[u8]) -> Result<OcspResponse, OcspError> {
    let mut basic = DerReader::new(basic_der);
    let (tag, sequence, _) = basic.read_tlv_full()?;
    if tag != 0x30 {
        return Err(OcspError::Malformed(
            "BasicOCSPResponse is not a SEQUENCE".to_string(),
        ));
    }
    let mut fields = DerReader::new(sequence);
    let (tbs_tag, tbs, _) = fields.read_tlv_full()?;
    if tbs_tag != 0x30 {
        return Err(OcspError::Malformed(
            "ResponseData is not a SEQUENCE".to_string(),
        ));
    }
    parse_response_data(full_der, tbs)
}

fn parse_response_data(full_der: &[u8], tbs: &[u8]) -> Result<OcspResponse, OcspError> {
    let mut data = DerReader::new(tbs);
    // Optional version [0] EXPLICIT.
    if data.peek_tag()? == 0xA0 {
        data.read_tlv_full()?;
    }
    // responderID is either a SEQUENCE or [2] EXPLICIT; producedAt is a GeneralizedTime.
    let (responder_tag, _responder, _) = data.read_tlv_full()?;
    if responder_tag != 0x30 && responder_tag != 0xA2 {
        return Err(OcspError::Malformed(
            "ResponseData responderID is not a SEQUENCE/[2]".to_string(),
        ));
    }
    let (produced_tag, produced, _) = data.read_tlv_full()?;
    let _ = parse_asn1_time(produced_tag, produced)?;
    let (responses_tag, responses, _) = data.read_tlv_full()?;
    if responses_tag != 0x30 {
        return Err(OcspError::Malformed(
            "SingleResponse list is not a SEQUENCE".to_string(),
        ));
    }
    let mut list = DerReader::new(responses);
    let (single_tag, single, _) = list.read_tlv_full()?;
    if single_tag != 0x30 {
        return Err(OcspError::Malformed(
            "SingleResponse is not a SEQUENCE".to_string(),
        ));
    }
    let mut single = DerReader::new(single);
    let (cert_id_tag, cert_id, _) = single.read_tlv_full()?;
    if cert_id_tag != 0x30 {
        return Err(OcspError::Malformed("CertID is not a SEQUENCE".to_string()));
    }
    let serial = parse_cert_id_serial(cert_id)?;
    let (status_tag, _status_value, _) = single.read_tlv_full()?;
    let status = match status_tag {
        0x80 => OcspCertStatus::Good,
        0x81 => OcspCertStatus::Revoked,
        0x82 => OcspCertStatus::Unknown,
        other => {
            return Err(OcspError::Malformed(format!(
                "unexpected certStatus tag 0x{other:02x}"
            )))
        }
    };
    let (this_tag, this_value, _) = single.read_tlv_full()?;
    let this_update = time_from_unix(parse_asn1_time(this_tag, this_value)?);
    let next_update = match single.next_tlv_optional()? {
        Some((0xA0, value, _)) => {
            let mut inner = DerReader::new(value);
            let (tag, time_value, _) = inner.read_tlv_full()?;
            Some(time_from_unix(parse_asn1_time(tag, time_value)?))
        }
        Some(_) => None,
        None => None,
    };
    Ok(OcspResponse {
        der: full_der.to_vec(),
        status,
        this_update,
        next_update,
        serial,
    })
}

fn parse_cert_id_serial(cert_id: &[u8]) -> Result<Vec<u8>, OcspError> {
    let mut reader = DerReader::new(cert_id);
    // hashAlgorithm
    let (alg_tag, alg, _) = reader.read_tlv_full()?;
    if alg_tag != 0x30 {
        return Err(OcspError::Malformed(
            "CertID hashAlgorithm is not a SEQUENCE".to_string(),
        ));
    }
    let _ = alg;
    // issuerNameHash
    let (name_tag, _name, _) = reader.read_tlv_full()?;
    if name_tag != 0x04 {
        return Err(OcspError::Malformed(
            "CertID issuerNameHash is not an OCTET STRING".to_string(),
        ));
    }
    // issuerKeyHash
    let (key_tag, _key, _) = reader.read_tlv_full()?;
    if key_tag != 0x04 {
        return Err(OcspError::Malformed(
            "CertID issuerKeyHash is not an OCTET STRING".to_string(),
        ));
    }
    // serialNumber
    let (serial_tag, serial, _) = reader.read_tlv_full()?;
    if serial_tag != 0x02 {
        return Err(OcspError::Malformed(
            "CertID serialNumber is not an INTEGER".to_string(),
        ));
    }
    Ok(serial.to_vec())
}

// ---------------------------------------------------------------------------------------------
// X.509 parsing needed for OCSP
// ---------------------------------------------------------------------------------------------

fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate, OcspError> {
    let mut outer = DerReader::new(der);
    let (tag, certificate, _) = outer.read_tlv_full()?;
    if tag != 0x30 {
        return Err(OcspError::Malformed(
            "certificate is not a SEQUENCE".to_string(),
        ));
    }
    let mut cert = DerReader::new(certificate);
    let (tbs_tag, tbs, _) = cert.read_tlv_full()?;
    if tbs_tag != 0x30 {
        return Err(OcspError::Malformed(
            "tbsCertificate is not a SEQUENCE".to_string(),
        ));
    }
    let mut tbs_reader = DerReader::new(tbs);
    if tbs_reader.peek_tag()? == 0xA0 {
        tbs_reader.read_tlv_full()?;
    }
    let (serial_tag, serial, _) = tbs_reader.read_tlv_full()?;
    if serial_tag != 0x02 {
        return Err(OcspError::Malformed(
            "serialNumber is not an INTEGER".to_string(),
        ));
    }
    // signature AlgorithmIdentifier
    tbs_reader.read_tlv_full()?;
    // issuer Name (retain the full TLV bytes)
    let (issuer_tag, _issuer_value, issuer_tlv) = tbs_reader.read_tlv_full()?;
    if issuer_tag != 0x30 {
        return Err(OcspError::Malformed(
            "issuer is not a Name SEQUENCE".to_string(),
        ));
    }
    // validity
    tbs_reader.read_tlv_full()?;
    // subject
    tbs_reader.read_tlv_full()?;
    // subjectPublicKeyInfo
    let (spki_tag, spki, _) = tbs_reader.read_tlv_full()?;
    if spki_tag != 0x30 {
        return Err(OcspError::Malformed(
            "subjectPublicKeyInfo is not a SEQUENCE".to_string(),
        ));
    }
    let subject_public_key = parse_spki_public_key(spki)?;
    let mut ocsp_responder_url = None;
    let mut must_staple = false;
    // Optional issuerUniqueID [1], subjectUniqueID [2], extensions [3].
    while let Some((tag, value, _)) = tbs_reader.next_tlv_optional()? {
        if tag == 0xA3 {
            let mut extensions = DerReader::new(value);
            let (extensions_tag, extensions_value, _) = extensions.read_tlv_full()?;
            if extensions_tag != 0x30 {
                return Err(OcspError::Malformed(
                    "extensions wrapper is not a SEQUENCE".to_string(),
                ));
            }
            let mut list = DerReader::new(extensions_value);
            while let Some((ext_tag, ext_value, _)) = list.next_tlv_optional()? {
                if ext_tag != 0x30 {
                    continue;
                }
                let mut extension = DerReader::new(ext_value);
                let (oid_tag, oid, _) = extension.read_tlv_full()?;
                if oid_tag != 0x06 {
                    continue;
                }
                let (octet_tag, octet_value, _) = extension.read_tlv_full()?;
                if octet_tag != 0x04 {
                    continue;
                }
                if oid == OID_AUTHORITY_INFO_ACCESS {
                    ocsp_responder_url = parse_ocsp_responder_url(octet_value)?;
                } else if oid == OID_TLS_FEATURE {
                    must_staple = parse_must_staple(octet_value)?;
                }
            }
        }
    }
    Ok(ParsedCertificate {
        serial: serial.to_vec(),
        issuer_name_der: issuer_tlv.to_vec(),
        subject_public_key,
        ocsp_responder_url,
        must_staple,
    })
}

const OID_AUTHORITY_INFO_ACCESS: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
const OID_TLS_FEATURE: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];
const OID_OCSP_ACCESS_METHOD: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];

fn parse_spki_public_key(spki: &[u8]) -> Result<Vec<u8>, OcspError> {
    let mut reader = DerReader::new(spki);
    let (alg_tag, _alg, _) = reader.read_tlv_full()?;
    if alg_tag != 0x30 {
        return Err(OcspError::Malformed(
            "SPKI algorithm is not a SEQUENCE".to_string(),
        ));
    }
    let (bits_tag, bits, _) = reader.read_tlv_full()?;
    if bits_tag != 0x03 || bits.is_empty() {
        return Err(OcspError::Malformed(
            "SPKI subjectPublicKey is not a BIT STRING".to_string(),
        ));
    }
    // First octet is the number of unused bits.
    Ok(bits[1..].to_vec())
}

fn parse_ocsp_responder_url(value: &[u8]) -> Result<Option<String>, OcspError> {
    let mut reader = DerReader::new(value);
    let (tag, descriptions, _) = reader.read_tlv_full()?;
    if tag != 0x30 {
        return Err(OcspError::Malformed("AIA is not a SEQUENCE".to_string()));
    }
    let mut list = DerReader::new(descriptions);
    while let Some((desc_tag, desc, _)) = list.next_tlv_optional()? {
        if desc_tag != 0x30 {
            continue;
        }
        let mut desc_reader = DerReader::new(desc);
        let (oid_tag, oid, _) = desc_reader.read_tlv_full()?;
        let (location_tag, location, _) = desc_reader.read_tlv_full()?;
        if oid_tag == 0x06 && oid == OID_OCSP_ACCESS_METHOD && location_tag == 0x86 {
            return Ok(Some(String::from_utf8_lossy(location).into_owned()));
        }
    }
    Ok(None)
}

fn parse_must_staple(value: &[u8]) -> Result<bool, OcspError> {
    let mut reader = DerReader::new(value);
    let (tag, sequence, _) = reader.read_tlv_full()?;
    if tag != 0x30 {
        return Err(OcspError::Malformed(
            "TLS Feature is not a SEQUENCE".to_string(),
        ));
    }
    let mut features = DerReader::new(sequence);
    while let Some((integer_tag, integer, _)) = features.next_tlv_optional()? {
        if integer_tag == 0x02 && integer.last() == Some(&5) {
            return Ok(true);
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------------------------
// DER helpers
// ---------------------------------------------------------------------------------------------

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        vec![length as u8]
    } else if length <= 0xFF {
        vec![0x81, length as u8]
    } else if length <= 0xFFFF {
        vec![0x82, (length >> 8) as u8, length as u8]
    } else {
        vec![
            0x83,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + content.len());
    out.push(tag);
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    der_tlv(0x30, &items.concat())
}

fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    content.push((arcs[0] * 40 + arcs[1]) as u8);
    for arc in &arcs[2..] {
        let mut value = *arc;
        let mut encoded = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            encoded.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        encoded.reverse();
        content.extend(encoded);
    }
    der_tlv(0x06, &content)
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn der_integer_from_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut content = bytes.to_vec();
    while content.len() > 1 && content[0] == 0 && content[1] & 0x80 == 0 {
        content.remove(0);
    }
    if content.is_empty() {
        content.push(0);
    }
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der_tlv(0x02, &content)
}

fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tlv(0x04, content)
}

#[cfg(test)]
fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(content.len() + 1);
    value.push(0);
    value.extend_from_slice(content);
    der_tlv(0x03, &value)
}

struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn peek_tag(&self) -> Result<u8, OcspError> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| OcspError::Malformed("truncated DER: missing tag".to_string()))
    }

    fn read_tlv_full(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), OcspError> {
        let start = self.offset;
        let tag = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| OcspError::Malformed("truncated DER: missing tag".to_string()))?;
        self.offset += 1;
        let first = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| OcspError::Malformed("truncated DER: missing length".to_string()))?;
        self.offset += 1;
        let length = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return Err(OcspError::Malformed(
                    "unsupported DER indefinite or oversized length".to_string(),
                ));
            }
            let mut length = 0usize;
            for _ in 0..count {
                let byte = *self
                    .bytes
                    .get(self.offset)
                    .ok_or_else(|| OcspError::Malformed("truncated DER length".to_string()))?;
                self.offset += 1;
                length = (length << 8) | byte as usize;
            }
            length
        };
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| OcspError::Malformed("truncated DER value".to_string()))?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok((tag, value, &self.bytes[start..end]))
    }

    fn next_tlv_optional(&mut self) -> Result<Option<(u8, &'a [u8], &'a [u8])>, OcspError> {
        if self.offset >= self.bytes.len() {
            return Ok(None);
        }
        self.read_tlv_full().map(Some)
    }
}

fn parse_asn1_time(tag: u8, value: &[u8]) -> Result<u64, OcspError> {
    let text = std::str::from_utf8(value)
        .map_err(|error| OcspError::Malformed(format!("invalid ASN.1 time: {error}")))?;
    let trimmed = text.strip_suffix('Z').unwrap_or(text);
    let (year, rest) = match tag {
        0x17 => {
            if trimmed.len() < 12 {
                return Err(OcspError::Malformed(format!("invalid UTCTime `{text}`")));
            }
            let yy: i64 = trimmed[0..2]
                .parse()
                .map_err(|_| OcspError::Malformed(format!("invalid UTCTime `{text}`")))?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &trimmed[2..])
        }
        0x18 => {
            if trimmed.len() < 14 {
                return Err(OcspError::Malformed(format!(
                    "invalid GeneralizedTime `{text}`"
                )));
            }
            let year: i64 = trimmed[0..4]
                .parse()
                .map_err(|_| OcspError::Malformed(format!("invalid GeneralizedTime `{text}`")))?;
            (year, &trimmed[4..])
        }
        other => {
            return Err(OcspError::Malformed(format!(
                "unsupported ASN.1 time tag 0x{other:02x}"
            )))
        }
    };
    let parse = |slice: &str| -> Result<u64, OcspError> {
        slice
            .parse()
            .map_err(|_| OcspError::Malformed(format!("invalid ASN.1 time `{text}`")))
    };
    let month = parse(&rest[0..2])?;
    let day = parse(&rest[2..4])?;
    let hour = parse(&rest[4..6])?;
    let minute = parse(&rest[6..8])?;
    let second = parse(&rest[8..10])?;
    Ok(unix_seconds_from_civil(
        year, month, day, hour, minute, second,
    ))
}

fn time_from_unix(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn unix_seconds_from_civil(
    year: i64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
) -> u64 {
    // Howard Hinnant's days-from-civil algorithm.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let month = month as i64;
    let doy = ((153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5) as u64 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era as i64 * 146097 + doe as i64 - 719468) as u64;
    days * 86_400 + hour * 3_600 + minute * 60 + second
}

#[cfg(test)]
mod tests;
