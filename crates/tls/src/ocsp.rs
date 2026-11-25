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
//! * The OCSP response is fully verified before it is cached or stapled (SEC-MEDIUM D1, closing
//!   DIV-0087): signature under the issuer key or a delegated id-kp-OCSPSigning responder, the whole
//!   `CertID` (serial, issuerNameHash, issuerKeyHash), and `thisUpdate <= now < nextUpdate`. This
//!   is stock parity (certmagic parses with `ocsp.ParseResponse(body, issuer)`), so there is no
//!   `stock_compat` switch.
//! * `ocsp_overrides` / responder URL overrides are rejected loudly by the automation-policy
//!   parser (never dropped).
//! * `must_staple` is honoured as a requirement on the stapling decision: a policy that requests
//!   Must-Staple but disables stapling (or cannot obtain a response) fails loudly instead of
//!   serving an unstapled chain.

use sha1::{Digest, Sha1};
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
    /// The response's CertID names a different issuer (name or key hash mismatch).
    #[error("OCSP response CertID does not match the issuer of the requested certificate")]
    IssuerMismatch,
    /// The BasicOCSPResponse signature is missing, uses an unsupported algorithm, or does not
    /// verify against the issuer / delegated responder key.
    #[error("OCSP response signature is invalid: {0}")]
    SignatureInvalid(String),
    /// The response is signed by a delegated responder certificate that is not authorised to sign
    /// OCSP responses for this issuer.
    #[error("OCSP responder is not authorised: {0}")]
    UnauthorizedResponder(String),
    /// `nextUpdate` is not in the future: the response is stale.
    #[error("OCSP response has expired (nextUpdate is in the past)")]
    Expired,
    /// `thisUpdate` lies in the future beyond the permitted clock skew.
    #[error("OCSP response is not yet valid (thisUpdate is in the future)")]
    NotYetValid,
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
    /// `CertID.hashAlgorithm` OID content bytes.
    pub hash_algorithm_oid: Vec<u8>,
    /// `CertID.issuerNameHash`.
    pub issuer_name_hash: Vec<u8>,
    /// `CertID.issuerKeyHash`.
    pub issuer_key_hash: Vec<u8>,
    /// `ResponseData.responderID`.
    pub responder_id: ResponderId,
    /// The complete DER TLV of `tbsResponseData` (the exact bytes the signature covers).
    pub tbs_response_data: Vec<u8>,
    /// `signatureAlgorithm` OID content bytes.
    pub signature_algorithm_oid: Vec<u8>,
    /// `signature` BIT STRING contents (unused-bits octet removed).
    pub signature: Vec<u8>,
    /// `certs`: DER certificates a delegated responder shipped with the response.
    pub certs: Vec<Vec<u8>>,
}

/// `ResponseData.responderID` (RFC 6960 section 4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderId {
    /// `byName [1] EXPLICIT Name`: the responder certificate's subject, as DER.
    ByName(Vec<u8>),
    /// `byKey [2] EXPLICIT KeyHash`: SHA-1 of the responder's public key BIT STRING contents.
    ByKey(Vec<u8>),
    /// Not a recognised `ResponderID` encoding (accepted by the lenient parser, never verifiable).
    Unrecognised,
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
        // The responder URL comes from the certificate and is usually plain `http://`, so the
        // response is untrusted until the issuer's (or its delegate's) signature, the full CertID
        // and the freshness window have been verified (SEC-MEDIUM D1). This happens BEFORE the
        // status is looked at, so a forged `revoked`/`unknown` cannot be told apart from a genuine
        // one by an attacker who wants to influence the cache.
        let issuer = ParsedCertificate::parse(issuer_der)?;
        verify_ocsp_response(&response, &leaf, &issuer, now)?;
        if response.status != OcspCertStatus::Good {
            return Err(OcspError::ResponderStatus(1));
        }
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
    /// DER-encoded subject `Name` (matched against a `byName` responder ID).
    pub subject_der: Vec<u8>,
    /// The complete DER TLV of `tbsCertificate` (what the issuer's signature covers).
    pub tbs_der: Vec<u8>,
    /// `signatureAlgorithm` OID content bytes.
    pub signature_algorithm_oid: Vec<u8>,
    /// `signatureValue` BIT STRING contents (unused-bits octet removed).
    pub signature: Vec<u8>,
    /// `notBefore`, or `None` when it cannot be represented (pre-1970 or malformed).
    pub not_before: Option<SystemTime>,
    /// `notAfter`, or `None` when it cannot be represented (malformed).
    pub not_after: Option<SystemTime>,
    /// ExtendedKeyUsage purpose OIDs (content bytes), or `None` when the extension is absent.
    pub extended_key_usage: Option<Vec<Vec<u8>>>,
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
    // SHA-1 is mandated here by RFC 6960 (CertID), not a choice: it must stay SHA-1, so this is a
    // provider swap only. Byte-identical to the previous `ring::digest::digest(&SHA1, ..)` calls.
    let name_hash = Sha1::digest(&leaf.issuer_name_der);
    let key_hash = Sha1::digest(&issuer.subject_public_key);
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
    let (tbs_tag, tbs, tbs_tlv) = fields.read_tlv_full()?;
    if tbs_tag != 0x30 {
        return Err(OcspError::Malformed(
            "ResponseData is not a SEQUENCE".to_string(),
        ));
    }
    // signatureAlgorithm AlgorithmIdentifier, signature BIT STRING, certs [0] EXPLICIT OPTIONAL.
    let (alg_tag, alg, _) = fields.read_tlv_full().map_err(|_| {
        OcspError::Malformed("BasicOCSPResponse has no signatureAlgorithm".to_string())
    })?;
    if alg_tag != 0x30 {
        return Err(OcspError::Malformed(
            "BasicOCSPResponse signatureAlgorithm is not a SEQUENCE".to_string(),
        ));
    }
    let signature_algorithm_oid = algorithm_oid(alg)?;
    let (sig_tag, sig_bits, _) = fields
        .read_tlv_full()
        .map_err(|_| OcspError::Malformed("BasicOCSPResponse has no signature".to_string()))?;
    let signature = bit_string_contents(sig_tag, sig_bits, "BasicOCSPResponse signature")?;
    let mut certs = Vec::new();
    if let Some((certs_tag, certs_value, _)) = fields.next_tlv_optional()? {
        if certs_tag != 0xA0 {
            return Err(OcspError::Malformed(
                "BasicOCSPResponse certs is not [0] EXPLICIT".to_string(),
            ));
        }
        let mut wrapper = DerReader::new(certs_value);
        let (list_tag, list_value, _) = wrapper.read_tlv_full()?;
        if list_tag != 0x30 {
            return Err(OcspError::Malformed(
                "BasicOCSPResponse certs is not a SEQUENCE OF Certificate".to_string(),
            ));
        }
        let mut list = DerReader::new(list_value);
        while let Some((cert_tag, _value, cert_tlv)) = list.next_tlv_optional()? {
            if cert_tag != 0x30 {
                return Err(OcspError::Malformed(
                    "BasicOCSPResponse certs entry is not a Certificate".to_string(),
                ));
            }
            certs.push(cert_tlv.to_vec());
        }
    }
    let mut response = parse_response_data(full_der, tbs)?;
    response.tbs_response_data = tbs_tlv.to_vec();
    response.signature_algorithm_oid = signature_algorithm_oid;
    response.signature = signature;
    response.certs = certs;
    Ok(response)
}

fn parse_response_data(full_der: &[u8], tbs: &[u8]) -> Result<OcspResponse, OcspError> {
    let mut data = DerReader::new(tbs);
    // Optional version [0] EXPLICIT.
    if data.peek_tag()? == 0xA0 {
        data.read_tlv_full()?;
    }
    // responderID is `byName [1] EXPLICIT Name` or `byKey [2] EXPLICIT KeyHash`. A bare SEQUENCE
    // is not a legal encoding, but the lenient parser keeps accepting it (it can never match a
    // responder, so it only ever verifies under the issuer key); producedAt is a GeneralizedTime.
    let (responder_tag, responder_value, _) = data.read_tlv_full()?;
    let responder_id = match responder_tag {
        // `[1] EXPLICIT Name`: the content is the Name SEQUENCE TLV.
        0xA1 => ResponderId::ByName(responder_value.to_vec()),
        // `[2] EXPLICIT KeyHash`: the content is an OCTET STRING TLV.
        0xA2 => {
            let mut inner = DerReader::new(responder_value);
            match inner.read_tlv_full()? {
                (0x04, hash, _) => ResponderId::ByKey(hash.to_vec()),
                _ => {
                    return Err(OcspError::Malformed(
                        "ResponseData byKey responderID is not an OCTET STRING".to_string(),
                    ))
                }
            }
        }
        0x30 => ResponderId::Unrecognised,
        _ => {
            return Err(OcspError::Malformed(
                "ResponseData responderID is not [1]/[2]".to_string(),
            ))
        }
    };
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
    let parsed_cert_id = parse_cert_id(cert_id)?;
    let (status_tag, _status_value, _) = single.read_tlv_full()?;
    let status = match status_tag {
        0x80 => OcspCertStatus::Good,
        // `revoked [1] IMPLICIT RevokedInfo`: RevokedInfo is a SEQUENCE, so a real responder sends
        // the constructed form 0xA1; 0x81 is kept for the primitive form older fixtures use.
        0x81 | 0xA1 => OcspCertStatus::Revoked,
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
        serial: parsed_cert_id.serial,
        hash_algorithm_oid: parsed_cert_id.hash_algorithm_oid,
        issuer_name_hash: parsed_cert_id.issuer_name_hash,
        issuer_key_hash: parsed_cert_id.issuer_key_hash,
        responder_id,
        // Filled in by `parse_basic_response`, which owns the surrounding BasicOCSPResponse.
        tbs_response_data: Vec::new(),
        signature_algorithm_oid: Vec::new(),
        signature: Vec::new(),
        certs: Vec::new(),
    })
}

struct ParsedCertId {
    hash_algorithm_oid: Vec<u8>,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    serial: Vec<u8>,
}

fn parse_cert_id(cert_id: &[u8]) -> Result<ParsedCertId, OcspError> {
    let mut reader = DerReader::new(cert_id);
    // hashAlgorithm
    let (alg_tag, alg, _) = reader.read_tlv_full()?;
    if alg_tag != 0x30 {
        return Err(OcspError::Malformed(
            "CertID hashAlgorithm is not a SEQUENCE".to_string(),
        ));
    }
    let hash_algorithm_oid = algorithm_oid(alg)?;
    // issuerNameHash
    let (name_tag, name, _) = reader.read_tlv_full()?;
    if name_tag != 0x04 {
        return Err(OcspError::Malformed(
            "CertID issuerNameHash is not an OCTET STRING".to_string(),
        ));
    }
    // issuerKeyHash
    let (key_tag, key, _) = reader.read_tlv_full()?;
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
    // A DER INTEGER is never empty. The old matcher treated an empty serial as "matches
    // anything" (`response.serial != request.serial && !response.serial.is_empty()`), which let a
    // forged response skip serial matching entirely.
    if serial.is_empty() {
        return Err(OcspError::Malformed(
            "CertID serialNumber INTEGER is empty".to_string(),
        ));
    }
    Ok(ParsedCertId {
        hash_algorithm_oid,
        issuer_name_hash: name.to_vec(),
        issuer_key_hash: key.to_vec(),
        serial: serial.to_vec(),
    })
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
    let (tbs_tag, tbs, tbs_tlv) = cert.read_tlv_full()?;
    if tbs_tag != 0x30 {
        return Err(OcspError::Malformed(
            "tbsCertificate is not a SEQUENCE".to_string(),
        ));
    }
    let (sig_alg_tag, sig_alg, _) = cert.read_tlv_full()?;
    if sig_alg_tag != 0x30 {
        return Err(OcspError::Malformed(
            "certificate signatureAlgorithm is not a SEQUENCE".to_string(),
        ));
    }
    let signature_algorithm_oid = algorithm_oid(sig_alg)?;
    let (sig_tag, sig_bits, _) = cert.read_tlv_full()?;
    let signature = bit_string_contents(sig_tag, sig_bits, "certificate signatureValue")?;
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
    let (validity_tag, validity, _) = tbs_reader.read_tlv_full()?;
    let (not_before, not_after) = if validity_tag == 0x30 {
        parse_validity(validity)
    } else {
        (None, None)
    };
    // subject
    let (_subject_tag, _subject_value, subject_tlv) = tbs_reader.read_tlv_full()?;
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
    let mut extended_key_usage = None;
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
                let (mut octet_tag, mut octet_value, _) = extension.read_tlv_full()?;
                if octet_tag == 0x01 {
                    // `critical BOOLEAN DEFAULT FALSE` precedes the extnValue when present.
                    (octet_tag, octet_value, _) = extension.read_tlv_full()?;
                }
                if octet_tag != 0x04 {
                    continue;
                }
                if oid == OID_AUTHORITY_INFO_ACCESS {
                    ocsp_responder_url = parse_ocsp_responder_url(octet_value)?;
                } else if oid == OID_TLS_FEATURE {
                    must_staple = parse_must_staple(octet_value)?;
                } else if oid == OID_EXTENDED_KEY_USAGE {
                    extended_key_usage = Some(parse_extended_key_usage(octet_value)?);
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
        subject_der: subject_tlv.to_vec(),
        tbs_der: tbs_tlv.to_vec(),
        signature_algorithm_oid,
        signature,
        not_before,
        not_after,
        extended_key_usage,
    })
}

/// `validity ::= SEQUENCE { notBefore Time, notAfter Time }`. A time that cannot be represented
/// is reported as `None` (the responder-certificate check then fails closed); a leaf/issuer
/// certificate never needs its validity here, so a malformed one must not break request building.
fn parse_validity(validity: &[u8]) -> (Option<SystemTime>, Option<SystemTime>) {
    let mut reader = DerReader::new(validity);
    let mut next_time = || {
        let (tag, value, _) = reader.read_tlv_full().ok()?;
        parse_asn1_time(tag, value).ok().map(time_from_unix)
    };
    let not_before = next_time();
    let not_after = next_time();
    (not_before, not_after)
}

/// The algorithm OID content bytes of an `AlgorithmIdentifier` body.
fn algorithm_oid(algorithm: &[u8]) -> Result<Vec<u8>, OcspError> {
    let mut reader = DerReader::new(algorithm);
    let (tag, oid, _) = reader.read_tlv_full()?;
    if tag != 0x06 {
        return Err(OcspError::Malformed(
            "AlgorithmIdentifier does not start with an OID".to_string(),
        ));
    }
    Ok(oid.to_vec())
}

/// BIT STRING contents with the unused-bits octet removed; only whole-octet strings are valid for
/// signatures.
fn bit_string_contents(tag: u8, value: &[u8], what: &str) -> Result<Vec<u8>, OcspError> {
    if tag != 0x03 || value.is_empty() {
        return Err(OcspError::Malformed(format!("{what} is not a BIT STRING")));
    }
    if value[0] != 0 {
        return Err(OcspError::Malformed(format!(
            "{what} has unused bits (not a whole number of octets)"
        )));
    }
    Ok(value[1..].to_vec())
}

fn parse_extended_key_usage(value: &[u8]) -> Result<Vec<Vec<u8>>, OcspError> {
    let mut reader = DerReader::new(value);
    let (tag, purposes, _) = reader.read_tlv_full()?;
    if tag != 0x30 {
        return Err(OcspError::Malformed(
            "ExtendedKeyUsage is not a SEQUENCE".to_string(),
        ));
    }
    let mut list = DerReader::new(purposes);
    let mut oids = Vec::new();
    while let Some((oid_tag, oid, _)) = list.next_tlv_optional()? {
        if oid_tag == 0x06 {
            oids.push(oid.to_vec());
        }
    }
    Ok(oids)
}

const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
/// id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9).
const OID_KP_OCSP_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
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

/// Encode `bytes` as a DER INTEGER, stripping redundant leading zeros.
///
/// The strip is a single scan to the first byte that must be kept, not a `remove(0)` loop. The loop
/// shifted the whole `Vec` once per stripped byte, so it cost O(n^2) in the length of the leading
/// zero run; the serial comes from the certificate's INTEGER content and `parse_certificate` puts no
/// length bound on it, so a certificate could choose an arbitrarily long run and make
/// `build_ocsp_request` quadratic. Found by fuzzing (`T-FUZZ-DEFECT-OCSP-REQUEST-QUADRATIC`).
///
/// Redundant leading zeros are those where the value would still be a valid DER INTEGER without
/// them: a zero byte is kept when it is the last byte, or when the next byte has its high bit set
/// (dropping it would flip the sign).
fn der_integer_from_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 && bytes[start + 1] & 0x80 == 0 {
        start += 1;
    }
    let content = &bytes[start..];
    if content.is_empty() {
        // Only reachable for an empty input; DER INTEGER content is never empty.
        return der_tlv(0x02, &[0]);
    }
    if content[0] & 0x80 != 0 {
        // A positive value whose top bit is set needs a leading zero so it stays positive.
        let mut prefixed = Vec::with_capacity(content.len() + 1);
        prefixed.push(0);
        prefixed.extend_from_slice(content);
        return der_tlv(0x02, &prefixed);
    }
    der_tlv(0x02, content)
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
    unix_seconds_from_civil(year, month, day, hour, minute, second).ok_or_else(|| {
        OcspError::Malformed(format!(
            "ASN.1 time `{text}` is before the Unix epoch and cannot be represented"
        ))
    })
}

fn time_from_unix(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// Seconds since the Unix epoch for a civil UTC date-time, or `None` when the instant is before
/// 1970-01-01 and therefore has no representation as a `u64`.
///
/// The return type is deliberately fallible. An earlier version cast the day count to `u64` before
/// scaling it to seconds:
///
/// ```text
/// let days = (era * 146097 + doe as i64 - 719468) as u64;   // wraps to ~1.8e19 for pre-1970
/// days * 86_400 + ...                                        // overflows
/// ```
///
/// For any date before the epoch the day count is negative, the cast wrapped it, and the
/// multiplication overflowed — a panic in debug builds and a silent wrap to a nonsense timestamp in
/// release. It was reachable from `parse_ocsp_response` with ordinary DER: a UTCTime with `YY >= 50`
/// denotes year `19YY`, so a plain 1950-1969 date in a responder's `thisUpdate`/`nextUpdate` was
/// enough, with no malformed encoding required (T-FUZZ-DEFECT-OCSP-PRE-EPOCH).
///
/// Rejecting is the right outcome rather than clamping to zero: the result feeds
/// [`time_from_unix`], which builds a `SystemTime` from a `u64`, and the freshness check in
/// `staple_for_certificate` compares `next_update` against `this_update`. Clamping would turn
/// "unrepresentable" into "1970", silently changing what the freshness comparison means. Go's
/// `encoding/asn1` (what Caddy uses) represents these instants fine because `time.Time` is signed;
/// caddy-rs cannot, so it reports a typed error instead of guessing.
fn unix_seconds_from_civil(
    year: i64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
) -> Option<u64> {
    // Howard Hinnant's days-from-civil algorithm.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let month = month as i64;
    let doy = ((153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5) as u64 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    // Keep the day count signed all the way through the epoch conversion: it is negative for
    // every date before 1970-01-01, and that is exactly the case the cast used to break.
    let days = era * 146097 + doe as i64 - 719468;
    if days < 0 {
        return None;
    }
    let days = days as u64;
    days.checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)
}

// ---------------------------------------------------------------------------------------------
// OCSP response verification (SEC-MEDIUM D1)
// ---------------------------------------------------------------------------------------------

/// Clock skew tolerated for `thisUpdate` (and a delegated responder certificate's `notBefore`).
/// `nextUpdate` gets no skew: a response is stale the moment it is reached.
pub const OCSP_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

const OID_HASH_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
const OID_HASH_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// Verify an untrusted, parsed OCSP response for `leaf` issued by `issuer`, as certmagic does
/// through `ocsp.ParseResponse(body, issuer)` plus its `NextUpdate` check:
///
/// 1. the `CertID` names this certificate: serial (non-empty), issuerNameHash and issuerKeyHash;
/// 2. the `BasicOCSPResponse` signature verifies under the issuer's key, or under a delegated
///    responder certificate that the issuer signed, that is valid now and that carries
///    id-kp-OCSPSigning (RFC 6960 section 4.2.2.2);
/// 3. `thisUpdate <= now + skew` and, when present, `now < nextUpdate`.
///
/// The certificate status is intentionally not judged here.
pub fn verify_ocsp_response(
    response: &OcspResponse,
    leaf: &ParsedCertificate,
    issuer: &ParsedCertificate,
    now: SystemTime,
) -> Result<(), OcspError> {
    verify_cert_id(response, leaf, issuer)?;
    verify_response_signature(response, issuer, now)?;
    if response.this_update > now + OCSP_CLOCK_SKEW {
        return Err(OcspError::NotYetValid);
    }
    if let Some(next_update) = response.next_update {
        if now >= next_update {
            return Err(OcspError::Expired);
        }
    }
    Ok(())
}

/// A serial's value, ignoring redundant leading zero octets (DER INTEGERs are canonical, but a
/// responder that echoes a non-minimal encoding still names the same number).
fn serial_value(serial: &[u8]) -> &[u8] {
    let start = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    &serial[start..]
}

fn cert_id_hash(algorithm_oid: &[u8], data: &[u8]) -> Result<Vec<u8>, OcspError> {
    if algorithm_oid == OID_HASH_SHA1 {
        Ok(Sha1::digest(data).to_vec())
    } else if algorithm_oid == OID_HASH_SHA256 {
        Ok(sha2::Sha256::digest(data).to_vec())
    } else {
        Err(OcspError::Malformed(
            "unsupported CertID hash algorithm (only SHA-1 and SHA-256)".to_string(),
        ))
    }
}

fn verify_cert_id(
    response: &OcspResponse,
    leaf: &ParsedCertificate,
    issuer: &ParsedCertificate,
) -> Result<(), OcspError> {
    let response_serial = serial_value(&response.serial);
    if response.serial.is_empty()
        || leaf.serial.is_empty()
        || response_serial != serial_value(&leaf.serial)
    {
        return Err(OcspError::SerialMismatch);
    }
    let expected_name = cert_id_hash(&response.hash_algorithm_oid, &leaf.issuer_name_der)?;
    let expected_key = cert_id_hash(&response.hash_algorithm_oid, &issuer.subject_public_key)?;
    if response.issuer_name_hash != expected_name || response.issuer_key_hash != expected_key {
        return Err(OcspError::IssuerMismatch);
    }
    Ok(())
}

fn responder_matches(id: &ResponderId, certificate: &ParsedCertificate) -> bool {
    match id {
        ResponderId::ByName(name) => *name == certificate.subject_der,
        ResponderId::ByKey(hash) => {
            *hash == Sha1::digest(&certificate.subject_public_key).as_slice()
        }
        ResponderId::Unrecognised => false,
    }
}

fn verify_response_signature(
    response: &OcspResponse,
    issuer: &ParsedCertificate,
    now: SystemTime,
) -> Result<(), OcspError> {
    // Signed by the issuer itself: the common case.
    let delegate = if responder_matches(&response.responder_id, issuer) {
        None
    } else {
        // A delegated responder: the certificate the response ships with whose identity the
        // responderID names. When none matches the response is verified under the issuer's key
        // (as Go's `ocsp.ParseResponse` does): a valid issuer signature is authority enough,
        // and anything else fails the signature check.
        response
            .certs
            .iter()
            .filter_map(|der| ParsedCertificate::parse(der).ok())
            .find(|candidate| responder_matches(&response.responder_id, candidate))
    };
    let signer_key = match &delegate {
        None => &issuer.subject_public_key,
        Some(certificate) => {
            authorize_delegated_responder(certificate, issuer, now)?;
            &certificate.subject_public_key
        }
    };
    verify_signature(
        &response.signature_algorithm_oid,
        signer_key,
        &response.tbs_response_data,
        &response.signature,
    )
}

/// RFC 6960 section 4.2.2.2: a delegated responder certificate must be issued directly by the CA
/// the response speaks for, be valid now, and carry id-kp-OCSPSigning.
fn authorize_delegated_responder(
    certificate: &ParsedCertificate,
    issuer: &ParsedCertificate,
    now: SystemTime,
) -> Result<(), OcspError> {
    verify_signature(
        &certificate.signature_algorithm_oid,
        &issuer.subject_public_key,
        &certificate.tbs_der,
        &certificate.signature,
    )
    .map_err(|_| {
        OcspError::UnauthorizedResponder(
            "delegated responder certificate was not issued by the certificate's issuer"
                .to_string(),
        )
    })?;
    let has_ocsp_signing = certificate
        .extended_key_usage
        .as_ref()
        .is_some_and(|purposes| purposes.iter().any(|oid| oid == OID_KP_OCSP_SIGNING));
    if !has_ocsp_signing {
        return Err(OcspError::UnauthorizedResponder(
            "delegated responder certificate lacks the id-kp-OCSPSigning extended key usage"
                .to_string(),
        ));
    }
    match (certificate.not_before, certificate.not_after) {
        (Some(not_before), Some(not_after))
            if now + OCSP_CLOCK_SKEW >= not_before && now < not_after => {}
        _ => {
            return Err(OcspError::UnauthorizedResponder(
                "delegated responder certificate is not valid at this time".to_string(),
            ))
        }
    }
    Ok(())
}

/// Verify `signature` over `message` with `public_key` (the SPKI BIT STRING contents) under the
/// X.509 signature algorithm `algorithm_oid`.
///
/// Supported: ECDSA with SHA-256/384/512, RSA PKCS#1 v1.5 with SHA-256/384/512 (2048-8192 bit
/// keys) and Ed25519, i.e. the algorithms certmagic-managed issuers use. SHA-1 based signatures
/// and anything else fail closed.
fn verify_signature(
    algorithm_oid: &[u8],
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), OcspError> {
    use aws_lc_rs::signature as sig;
    use sig::VerificationAlgorithm;
    // ECDSA OIDs name only the hash; the curve comes from the key, so try each curve that the hash
    // is defined for (a wrong-curve key simply fails to verify).
    let candidates: &[&'static dyn VerificationAlgorithm] = match algorithm_oid {
        // ecdsa-with-SHA256 / 384 / 512
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02] => {
            &[&sig::ECDSA_P256_SHA256_ASN1, &sig::ECDSA_P384_SHA256_ASN1]
        }
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03] => {
            &[&sig::ECDSA_P384_SHA384_ASN1, &sig::ECDSA_P256_SHA384_ASN1]
        }
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04] => {
            &[&sig::ECDSA_P521_SHA512_ASN1, &sig::ECDSA_P384_SHA512_ASN1]
        }
        // sha256WithRSAEncryption / sha384 / sha512
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B] => {
            &[&sig::RSA_PKCS1_2048_8192_SHA256]
        }
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C] => {
            &[&sig::RSA_PKCS1_2048_8192_SHA384]
        }
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D] => {
            &[&sig::RSA_PKCS1_2048_8192_SHA512]
        }
        // id-Ed25519
        [0x2B, 0x65, 0x70] => &[&sig::ED25519],
        _ => {
            return Err(OcspError::SignatureInvalid(
                "unsupported signature algorithm".to_string(),
            ))
        }
    };
    for algorithm in candidates {
        if sig::UnparsedPublicKey::new(*algorithm, public_key)
            .verify(message, signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(OcspError::SignatureInvalid(
        "signature does not verify under the issuer / responder key".to_string(),
    ))
}

#[cfg(test)]
mod tests;
