//! Certificate issuer interface and ACME issuance runtime.
//!
//! The [`CertificateIssuer`] trait is the boundary the rest of the runtime uses. This module
//! implements the ACME issuer end to end against a transport-neutral client:
//!
//! 1. load (or create) the ACME account key and account from [`AcmeStorage`], registering the
//!    account with the CA when it does not exist yet;
//! 2. create an order for the requested identifiers;
//! 3. for every authorization, select a challenge according to the configured
//!    [`ChallengePolicy`] and let the matching [`ChallengeSolver`] install evidence (HTTP-01 token
//!    or DNS-01 TXT record), then acknowledge and poll the authorization;
//! 4. finalize with a freshly generated CSR, download the PEM chain, and persist the certificate
//!    and private key through [`CertificateStorage`] in the Caddy data-directory layout;
//! 5. withdraw all challenge evidence, including when validation/finalization fails.
//!
//! Tests drive the whole path with a scripted [`AcmeTransport`]; production wiring constructs a
//! [`HyperTransport`] and [`crate::storage::FileStorage`] via [`AcmeIssuer::from_config`].
//!
//! Deliberate limitations (reported as divergences from Caddy v2.11.7/certmagic):
//!
//! * TLS-ALPN-01 generates the challenge certificate and publishes it in a domain-keyed store
//!   ([`AcmeIssuer::tls_alpn01_token_store`]); the TLS listener must serve it over the
//!   `acme-tls/1` ALPN protocol (server wiring is a follow-up, see [`crate::tls_alpn`]).
//! * `preferred_chains` is not applied: the chain is downloaded in CA preference order.
//! * `test_ca` fallback (retry on a staging CA after a production failure) is not implemented.
//! * Challenge cleanup errors are not surfaced (there is no logger in this crate); cleanup is
//!   best effort, matching certmagic's log-and-continue cleanup behaviour.
//! * DNS-01 provider modules are constructed from `challenges.dns.provider` configuration by
//!   [`AcmeIssuer::with_configured_dns_solver`] (currently Cloudflare); a caller can still attach
//!   its own [`DnsProvider`] with [`AcmeIssuer::with_dns01_solver`].

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use caddy_rs_core::duration::CaddyDuration;
use rustls::pki_types::CertificateDer;

use crate::acme::adaptive_challenge::AdaptiveChallengeSelector;
use crate::acme::ari::RenewalInfo;
use crate::acme::csr::CertificateKeyType;
use crate::acme::{
    AccountRegistration, AcmeAccountClient, AcmeClient, AcmeClock, AcmeError, AcmeStorage,
    AcmeTransport, Authorization, AuthorizationStatus, CertificateRequest, Challenge,
    ChallengePolicy, ChallengeType, HyperTransport, IssuedCertificate, NewOrderRequest,
    OrderHandle, OrderStatus, PollPolicy, TokioClock,
};
use crate::certificate::{Certificate, CertificateKeySource};
use crate::dns::{DnsChallengeConfig, DnsProvider};
use crate::solver::{
    key_authorization, ChallengeHandle, ChallengeSolver, Dns01Solver, Http01Solver,
    Http01TokenStore, SolverRegistry, TlsAlpn01Solver,
};
use crate::storage::{
    caddy_certificate_storage_name, caddy_issuer_key, certificate_chain_der,
    certificate_validity_unix, private_key_der, CertificateStorage, StoredCertificate,
};
use crate::tls_alpn::TlsAlpn01TokenStore;
use crate::{Error, Result};

/// Request to issue a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceRequest {
    /// Domains to cover; the first is the subject.
    pub domains: Vec<String>,
    /// Whether the certificate may be obtained from an internal CA.
    pub internal: bool,
    /// Key type for the certificate's private key (Caddy automation policy `key_type`).
    pub key_type: CertificateKeyType,
}

/// Certificate issuer.
#[async_trait]
pub trait CertificateIssuer: Send + Sync {
    /// Module name (`acme`, `internal`).
    fn name(&self) -> &'static str;

    /// Obtain a new certificate.
    async fn obtain(&self, request: &IssuanceRequest) -> Result<Certificate>;

    /// Fetch ACME Renewal Information for `certificate`, when this issuer supports it.
    ///
    /// The default returns `None` (no ARI), so the renewal scheduler keeps its local heuristic.
    /// ARI errors are surfaced to the scheduler, which falls back to the local schedule.
    async fn renewal_info(&self, certificate: &Certificate) -> Result<Option<RenewalInfo>> {
        let _ = certificate;
        Ok(None)
    }

    /// Renew an existing certificate.
    async fn renew(&self, certificate: &Certificate) -> Result<Certificate> {
        let key_type = CertificateKeyType::from_private_key_der(&certificate.private_key_der)
            .unwrap_or(CertificateKeyType::P256);
        self.obtain(&IssuanceRequest {
            domains: certificate.domains.clone(),
            internal: certificate.issuer == "internal",
            key_type,
        })
        .await
    }
}

/// ACME issuer configuration, matching Caddy's `tls.issuance.acme` JSON shape for the fields this
/// build understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeIssuerConfig {
    /// ACME directory URL (default: Let's Encrypt production).
    pub ca: String,
    /// Test directory URL used for retries after a primary-CA failure (Caddy's `test_ca`).
    pub test_ca: Option<String>,
    /// ACME account email.
    pub email: Option<String>,
    /// PEM-encoded existing account private key (Caddy's `account_key` placeholder).
    pub account_key_pem: Option<String>,
    /// CA-provided external account binding credentials (Caddy's `external_account`).
    pub external_account: Option<crate::acme::ExternalAccount>,
    /// PEM bundle files used to verify the ACME CA's HTTPS certificate (Caddy's
    /// `trusted_roots_pem_files`, emitted from `acme_ca_root`). When non-empty these roots
    /// **replace** the platform trust store for ACME connections, matching certmagic.
    pub trusted_roots_pem_files: Vec<PathBuf>,
    /// Preferred certificate chains.
    pub preferred_chains: Vec<String>,
    /// DNS challenge provider module name, if any.
    pub dns_provider: Option<String>,
    /// Full `challenges.dns` configuration (provider settings, TTL, propagation options), when a
    /// DNS challenge provider is configured. Used by [`AcmeIssuer::with_configured_dns_solver`]
    /// to construct the provider from configuration alone.
    pub dns_challenge: Option<DnsChallengeConfig>,
    /// Whether Caddy's `challenges.http.disabled` is set.
    pub http_challenge_disabled: bool,
    /// Whether Caddy's `challenges.tls-alpn.disabled` is set.
    pub tls_alpn_challenge_disabled: bool,
    /// Renewal window override.
    pub renewal_window: Option<Duration>,
    /// Caddy's `acme_timeout`: per-request timeout for ACME HTTP traffic (default: none).
    pub acme_timeout: Option<Duration>,
    /// Caddy's `network_proxy` module URL (`caddy.network_proxy.url`): route ACME HTTP traffic
    /// through an `http://host:port` forward proxy.
    pub network_proxy: Option<String>,
}

impl Default for AcmeIssuerConfig {
    fn default() -> Self {
        Self {
            ca: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            test_ca: None,
            email: None,
            account_key_pem: None,
            external_account: None,
            trusted_roots_pem_files: Vec::new(),
            preferred_chains: Vec::new(),
            dns_provider: None,
            dns_challenge: None,
            http_challenge_disabled: false,
            tls_alpn_challenge_disabled: false,
            renewal_window: None,
            acme_timeout: None,
            network_proxy: None,
        }
    }
}

/// Parse Caddy's `network_proxy` module object (`{"from":"url","url":"http://host:port"}` or
/// `{"from":"none"}`). Only the `url` source with an `http://` proxy is implemented; the `none`
/// source disables proxying. Malformed/unsupported forms are located errors (T-TLS-070).
fn parse_network_proxy(value: Option<&serde_json::Value>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value.as_object().ok_or_else(|| {
        Error::Issuer(
            "invalid `network_proxy`: expected a caddy.network_proxy module object".to_string(),
        )
    })?;
    let from = object
        .get("from")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::Issuer("invalid `network_proxy`: missing `from` module field".to_string())
        })?;
    match from {
        "none" => Ok(None),
        "url" => {
            let url = object
                .get("url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    Error::Issuer("invalid `network_proxy.url`: missing URL".to_string())
                })?;
            let Some(rest) = url.strip_prefix("http://") else {
                return Err(Error::Unsupported {
                    path: "apps.tls.automation.policies[].issuers[].network_proxy.url".to_string(),
                    feature: "network_proxy schemes other than http:// (https/socks5 proxies)"
                        .to_string(),
                    tracking_id: "T-TLS-070",
                });
            };
            if rest.is_empty() || rest.starts_with('/') {
                return Err(Error::Issuer(
                    "invalid `network_proxy.url`: missing host".to_string(),
                ));
            }
            Ok(Some(url.to_string()))
        }
        other => Err(Error::Unsupported {
            path: "apps.tls.automation.policies[].issuers[].network_proxy.from".to_string(),
            feature: format!("network_proxy source module `{other}`"),
            tracking_id: "T-TLS-070",
        }),
    }
}

impl AcmeIssuerConfig {
    /// Decode Caddy `apps.tls.automation.policies[].issuers[]` JSON for the ACME module.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| Error::Issuer("ACME issuer config must be an object".to_string()))?;
        let mut config = Self::default();
        if let Some(ca) = object.get("ca").and_then(serde_json::Value::as_str) {
            config.ca = ca.to_string();
        }
        config.test_ca = object
            .get("test_ca")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        config.email = object
            .get("email")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        config.account_key_pem = object
            .get("account_key")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        config.external_account = object
            .get("external_account")
            .map(|value| {
                serde_json::from_value(value.clone()).map_err(|error| {
                    Error::Issuer(format!("invalid `external_account` config: {error}"))
                })
            })
            .transpose()?;
        config.trusted_roots_pem_files =
            parse_trusted_roots_pem_files(object.get("trusted_roots_pem_files"))?;
        config.preferred_chains = object
            .get("preferred_chains")
            .and_then(|chains| chains.get("smallest"))
            .and_then(serde_json::Value::as_bool)
            .map(|smallest| {
                vec![if smallest {
                    "smallest".to_string()
                } else {
                    "any".to_string()
                }]
            })
            .unwrap_or_default();
        if let Some(challenges) = object.get("challenges") {
            let challenges = challenges
                .as_object()
                .ok_or_else(|| Error::Issuer("`challenges` must be an object".to_string()))?;
            for (name, value) in challenges {
                match name.as_str() {
                    "http" | "tls-alpn" => {
                        let challenge_path = format!("challenges.{name}");
                        let options = value.as_object().ok_or_else(|| {
                            Error::Issuer(format!("`{challenge_path}` must be an object"))
                        })?;
                        for (option, option_value) in options {
                            match option.as_str() {
                                "disabled" => {
                                    if !option_value.is_boolean() {
                                        return Err(Error::Issuer(format!(
                                            "`{challenge_path}.disabled` must be a boolean"
                                        )));
                                    }
                                }
                                "alternate_port" => {
                                    return Err(Error::Unsupported {
                                        path: format!("{challenge_path}.alternate_port"),
                                        feature: "alternate ACME challenge ports".to_string(),
                                        tracking_id: "TLS-ACME-CHALLENGE",
                                    });
                                }
                                other => {
                                    return Err(Error::Unsupported {
                                        path: format!("{challenge_path}.{other}"),
                                        feature: format!("ACME challenge option `{other}`"),
                                        tracking_id: "TLS-ACME-CHALLENGE",
                                    });
                                }
                            }
                        }
                    }
                    "dns" => {}
                    other => {
                        return Err(Error::Unsupported {
                            path: format!("challenges.{other}"),
                            feature: format!("ACME challenge type `{other}`"),
                            tracking_id: "TLS-ACME-CHALLENGE",
                        });
                    }
                }
            }
            if let Some(dns) = challenges.get("dns") {
                // Parse Caddy's complete `challenges.dns` object: the provider is an inline module
                // object ({"name":"cloudflare", "api_token": ...}) or a legacy string, and the
                // challenge-level settings (ttl, propagation_delay/timeout, resolvers,
                // override_domain) drive the solver this issuer builds.
                let challenge = DnsChallengeConfig::from_caddy_json(dns).map_err(|error| {
                    Error::Issuer(format!("invalid `challenges.dns` configuration: {error}"))
                })?;
                config.dns_provider = Some(challenge.provider.clone());
                config.dns_challenge = Some(challenge);
            }
            config.http_challenge_disabled = challenges
                .get("http")
                .and_then(|http| http.get("disabled"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            config.tls_alpn_challenge_disabled = challenges
                .get("tls-alpn")
                .and_then(|tls_alpn| tls_alpn.get("disabled"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
        }
        if let Some(window) = object.get("renewal_window") {
            let duration =
                serde_json::from_value::<CaddyDuration>(window.clone()).map_err(|error| {
                    Error::Issuer(format!("invalid `renewal_window` configuration: {error}"))
                })?;
            config.renewal_window = Some(duration.as_duration());
        }
        config.acme_timeout = match object.get("acme_timeout") {
            None => None,
            Some(value) => {
                let duration =
                    serde_json::from_value::<CaddyDuration>(value.clone()).map_err(|error| {
                        Error::Issuer(format!("invalid `acme_timeout` configuration: {error}"))
                    })?;
                if duration.as_nanos() == 0 {
                    return Err(Error::Issuer(
                        "invalid `acme_timeout`: must be greater than zero".to_string(),
                    ));
                }
                Some(duration.as_duration())
            }
        };
        config.network_proxy = parse_network_proxy(object.get("network_proxy"))?;
        Ok(config)
    }

    /// Whether explicit ACME trust roots were configured.
    pub fn has_trusted_roots(&self) -> bool {
        !self.trusted_roots_pem_files.is_empty()
    }

    /// Read the configured trusted roots into DER certificates.
    ///
    /// Returns an empty vector when no explicit roots are configured. With explicit roots every
    /// file must exist and contain at least one certificate: errors are located and there is no
    /// silent fallback to the platform trust store.
    pub fn read_trusted_roots(&self) -> Result<Vec<CertificateDer<'static>>> {
        if self.trusted_roots_pem_files.is_empty() {
            return Ok(Vec::new());
        }
        crate::acme::read_root_certificates_pem_files(&self.trusted_roots_pem_files).map_err(
            |error| {
                Error::Issuer(format!(
                    "invalid trusted roots for ACME CA `{}`: {error}",
                    self.ca
                ))
            },
        )
    }
}

/// Parse Caddy's `trusted_roots_pem_files` JSON array into paths.
fn parse_trusted_roots_pem_files(value: Option<&serde_json::Value>) -> Result<Vec<PathBuf>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let array = value.as_array().ok_or_else(|| {
        Error::Issuer(
            "invalid `trusted_roots_pem_files`: expected an array of PEM file paths".to_string(),
        )
    })?;
    let mut paths = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        let path = entry.as_str().ok_or_else(|| {
            Error::Issuer(format!(
                "invalid `trusted_roots_pem_files[{index}]`: expected a string path"
            ))
        })?;
        if path.trim().is_empty() {
            return Err(Error::Issuer(format!(
                "invalid `trusted_roots_pem_files[{index}]`: path is empty"
            )));
        }
        paths.push(PathBuf::from(path));
    }
    Ok(paths)
}

/// The ACME issuer: account management, order flow, challenge solving and certificate storage.
///
/// `T` is the HTTP transport, usually [`HyperTransport`] in production and a scripted mock in
/// tests. Construct with [`AcmeIssuer::new`] (or [`AcmeIssuer::from_config`] for the production
/// wiring) and attach a DNS-01 solver with [`AcmeIssuer::with_dns01_solver`] when DNS challenges
/// are configured.
pub struct AcmeIssuer<T: AcmeTransport> {
    /// Issuer configuration.
    pub config: AcmeIssuerConfig,
    transport: T,
    account_storage: Arc<dyn AcmeStorage>,
    certificate_storage: Box<dyn CertificateStorage>,
    solvers: SolverRegistry,
    http01_tokens: Arc<Http01TokenStore>,
    tls_alpn01_tokens: Arc<TlsAlpn01TokenStore>,
    clock: Arc<dyn AcmeClock>,
    poll_policy: PollPolicy,
    challenge_policy: Option<ChallengePolicy>,
    challenge_selector: AdaptiveChallengeSelector,
    /// Where the certificate key comes from: a fresh process-held key (default) or a token-held
    /// key whose CSR signature is produced inside the PKCS#11 token (T-TLS-101).
    certificate_key: CertificateKeySource,
}

/// Production ACME issuer using the hyper/rustls HTTP transport.
pub type ProductionAcmeIssuer = AcmeIssuer<HyperTransport>;

impl<T: AcmeTransport> AcmeIssuer<T> {
    /// Create an issuer.
    ///
    /// The issuer starts with an HTTP-01 solver (backed by its own [`Http01TokenStore`], see
    /// [`AcmeIssuer::http01_token_store`]) and a TLS-ALPN-01 solver (see
    /// [`AcmeIssuer::tls_alpn01_token_store`]). Attach DNS-01 with
    /// [`AcmeIssuer::with_dns01_solver`].
    ///
    /// This constructor takes the transport as given; `config.trusted_roots_pem_files` is not
    /// applied here. Use [`AcmeIssuer::from_config`] for production wiring or pass a transport
    /// built with explicit roots (automatic HTTPS does this per issuer policy).
    pub fn new(
        config: AcmeIssuerConfig,
        transport: T,
        account_storage: Arc<dyn AcmeStorage>,
        certificate_storage: Box<dyn CertificateStorage>,
    ) -> Self {
        let http01_tokens = Arc::new(Http01TokenStore::new());
        let tls_alpn01_tokens = Arc::new(TlsAlpn01TokenStore::new());
        let mut solvers = SolverRegistry::new();
        solvers.insert(Arc::new(Http01Solver::new(Arc::clone(&http01_tokens))));
        solvers.insert(Arc::new(TlsAlpn01Solver::new(Arc::clone(
            &tls_alpn01_tokens,
        ))));
        Self {
            config,
            transport,
            account_storage,
            certificate_storage,
            solvers,
            http01_tokens,
            tls_alpn01_tokens,
            clock: Arc::new(TokioClock),
            poll_policy: PollPolicy::default(),
            challenge_policy: None,
            challenge_selector: AdaptiveChallengeSelector::default(),
            certificate_key: CertificateKeySource::ProcessHeld,
        }
    }

    /// Attach a DNS-01 solver using `provider` and Caddy's default propagation timeout.
    pub fn with_dns01_solver(mut self, provider: Arc<dyn DnsProvider>) -> Self {
        self.solvers.insert(Arc::new(Dns01Solver::new(provider)));
        self
    }

    /// Attach a DNS-01 solver with an explicit propagation timeout and pre-check delay.
    pub fn with_dns01_solver_and_propagation(
        mut self,
        provider: Arc<dyn DnsProvider>,
        timeout: Duration,
        delay: Duration,
    ) -> Self {
        self.solvers.insert(Arc::new(
            Dns01Solver::new(provider).with_propagation(timeout, delay),
        ));
        self
    }

    /// Attach the DNS-01 solver described by this issuer's `challenges.dns` configuration.
    ///
    /// This is how automatic HTTPS selects DNS-01 from configuration alone: the provider module
    /// (`cloudflare`) is constructed from its settings and paired with authoritative propagation
    /// checks (DNS-over-HTTPS) using the same HTTP transport. Unknown providers or provider
    /// options fail loudly (T-TLS-063). Callers that already have a [`DnsProvider`] instance can
    /// use [`AcmeIssuer::with_dns01_solver`] instead.
    pub fn with_configured_dns_solver(mut self, transport: Arc<dyn AcmeTransport>) -> Result<Self> {
        if let Some(challenge) = &self.config.dns_challenge {
            let solver = crate::dns_providers::build_dns01_solver(challenge, transport)?;
            self.solvers.insert(Arc::new(solver));
        }
        Ok(self)
    }

    /// Attach an arbitrary challenge solver (replacing one for the same challenge type).
    pub fn with_solver(mut self, solver: Arc<dyn ChallengeSolver>) -> Self {
        self.solvers.insert(solver);
        self
    }

    /// Override the clock used for polling (tests use a no-sleep clock).
    pub fn with_clock(mut self, clock: Arc<dyn AcmeClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Issue certificates for a token-held key: the CSR is signed inside the PKCS#11 token
    /// through [`crate::acme::csr::CsrSigner`] and no private key is generated or exported
    /// (T-TLS-101). The same source is reused for every renewal, so the token key and its session
    /// are reused instead of a new key being generated.
    pub fn with_certificate_key_source(mut self, source: CertificateKeySource) -> Self {
        self.certificate_key = source;
        self
    }

    /// The configured certificate key source.
    pub fn certificate_key_source(&self) -> &CertificateKeySource {
        &self.certificate_key
    }

    /// Override the order/authorization polling policy.
    pub fn with_poll_policy(mut self, poll_policy: PollPolicy) -> Self {
        self.poll_policy = poll_policy;
        self
    }

    /// Override challenge selection. By default DNS-01 is used when a DNS provider is configured,
    /// otherwise HTTP-01 with TLS-ALPN-01 as fallback.
    pub fn with_challenge_policy(mut self, challenge_policy: ChallengePolicy) -> Self {
        self.challenge_policy = Some(challenge_policy);
        self
    }

    /// The HTTP-01 token store, for the HTTP server to answer validation requests.
    pub fn http01_token_store(&self) -> &Arc<Http01TokenStore> {
        &self.http01_tokens
    }

    /// The TLS-ALPN-01 challenge-certificate store, for the TLS listener to answer `acme-tls/1`
    /// handshakes (see [`crate::tls_alpn::AcmeTlsAlpnResolver`]).
    pub fn tls_alpn01_token_store(&self) -> &Arc<TlsAlpn01TokenStore> {
        &self.tls_alpn01_tokens
    }

    /// The registered challenge solvers.
    pub fn solvers(&self) -> &SolverRegistry {
        &self.solvers
    }

    /// The polling policy used for orders and authorizations.
    pub fn poll_policy(&self) -> &PollPolicy {
        &self.poll_policy
    }

    /// The effective challenge selection policy.
    pub fn challenge_policy(&self) -> ChallengePolicy {
        if let Some(policy) = &self.challenge_policy {
            return policy.clone();
        }
        if self.config.dns_provider.is_some() {
            // A configured DNS provider means DNS-01 only, matching Caddy's intent when the
            // operator explicitly selects a DNS challenge provider.
            return ChallengePolicy::dns_only();
        }
        // Adaptive order (DIV-0097 / T-TLS-076): once authorization offers have been recorded,
        // the selector's order — one-time shuffle, then stable descending success ratio —
        // becomes the preference, matching acmez's adaptive randomized selection. Fresh
        // issuers fall back to HTTP-01 with TLS-ALPN-01 second.
        let adaptive = self.challenge_selector.ordered();
        let preference = if adaptive.is_empty() {
            vec![ChallengeType::Http01, ChallengeType::TlsAlpn01]
        } else {
            adaptive
        };
        let mut policy = ChallengePolicy::default().with_preference(preference);
        policy.dns01 = false;
        policy.http01 =
            !self.config.http_challenge_disabled && self.solvers.contains(ChallengeType::Http01);
        policy.tls_alpn01 = !self.config.tls_alpn_challenge_disabled
            && self.solvers.contains(ChallengeType::TlsAlpn01);
        policy
    }

    fn account_registration(&self) -> AccountRegistration {
        let mut registration = AccountRegistration {
            terms_of_service_agreed: true,
            ..AccountRegistration::default()
        };
        if let Some(email) = &self.config.email {
            registration.contact = vec![format!("mailto:{email}")];
        }
        registration.external_account = self.config.external_account.clone();
        registration
    }

    async fn issue(&self, request: &IssuanceRequest) -> Result<Certificate> {
        if request.internal {
            return Err(Error::Issuer(
                "ACME issuer cannot obtain certificates from Caddy's internal CA".to_string(),
            ));
        }
        let domains = normalize_domains(&request.domains)?;
        if let Some(provider) = &self.config.dns_provider {
            if !self.solvers.contains(ChallengeType::Dns01) {
                return Err(Error::Issuer(format!(
                    "ACME DNS challenge provider `{provider}` is configured but no DnsProvider \
                     solver was attached to the issuer"
                )));
            }
        }

        let directory_url = self.config.ca.clone();
        let account_store = crate::acme::AccountStore::new(
            Arc::clone(&self.account_storage),
            self.config.email.clone(),
        );
        let (account_key, _) = account_store
            .account_key(&directory_url, self.config.account_key_pem.as_deref())
            .await?;
        let client =
            AcmeClient::connect(&self.transport, directory_url.clone(), account_key).await?;
        let account = match account_store.load_account(&directory_url).await? {
            Some(account) => account,
            None => {
                let registration = self.account_registration();
                account_store
                    .register_account(&client, &registration)
                    .await?
            }
        };
        let account_client = AcmeAccountClient::new(client, account)?;

        let mut presented: Vec<(Arc<dyn ChallengeSolver>, ChallengeHandle)> = Vec::new();
        let result = self
            .run_order(
                &account_client,
                &domains,
                request.key_type,
                &self.certificate_key,
                &mut presented,
            )
            .await;
        // Withdraw challenge evidence in reverse order, whether issuance succeeded or not.
        for (solver, handle) in presented.iter().rev() {
            let _ = solver.withdraw(handle).await;
        }
        result
    }

    async fn run_order<U: AcmeTransport + ?Sized>(
        &self,
        account_client: &AcmeAccountClient<&U>,
        domains: &[String],
        key_type: CertificateKeyType,
        certificate_key: &CertificateKeySource,
        presented: &mut Vec<(Arc<dyn ChallengeSolver>, ChallengeHandle)>,
    ) -> Result<Certificate> {
        let order_request = NewOrderRequest::for_domains(domains);

        // acmez `ObtainCertificate` parity (DIV-0097 / T-TLS-076): retry the whole order
        // transaction up to `MAX_ATTEMPTS` times. Each attempt creates a fresh order and
        // remembers which challenge types failed for each identifier, so a later attempt can
        // pick the next-best type instead of failing the issuance outright.
        const MAX_ATTEMPTS: u32 = 3;
        let mut failed_challenge_types: HashMap<String, Vec<ChallengeType>> = HashMap::new();
        let mut order: Option<OrderHandle> = None;
        let mut attempt_error: Option<Error> = None;

        for attempt in 1..=MAX_ATTEMPTS {
            if attempt > 1 {
                // acmez waits one second between order attempts.
                self.clock.sleep(Duration::from_secs(1)).await;
            }
            let candidate = account_client.new_order(&order_request).await?;
            if candidate.order.status == OrderStatus::Valid {
                // A valid order has no local CSR/private key, so the certificate cannot be
                // stored.
                return Err(Error::Issuer(
                    "ACME order is already valid but no local private key exists; start a new \
                     order"
                        .to_string(),
                ));
            }
            if candidate.order.status == OrderStatus::Pending {
                let attempt_start = presented.len();
                match self
                    .solve_order_authorizations(
                        account_client,
                        &candidate,
                        presented,
                        &mut failed_challenge_types,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(SolveAttemptError::Retryable(error)) => {
                        // Clean up this attempt's evidence before retrying, mirroring acmez's
                        // `defer CleanUp` in `solveChallenges`.
                        let failed_attempt: Vec<_> = presented.drain(attempt_start..).collect();
                        for (solver, handle) in failed_attempt.into_iter().rev() {
                            let _ = solver.withdraw(&handle).await;
                        }
                        attempt_error = Some(error);
                        continue;
                    }
                    Err(SolveAttemptError::Fatal(error)) => return Err(error),
                }
            }
            order = Some(candidate);
            break;
        }

        let order = order.ok_or_else(|| {
            attempt_error.unwrap_or_else(|| {
                Error::Issuer(format!(
                    "ACME order was not solved after {MAX_ATTEMPTS} attempts"
                ))
            })
        })?;

        account_client
            .poll_order_ready(&order.url, &self.poll_policy, self.clock.as_ref())
            .await?;
        // Token-held keys sign the CSR inside the token; no process-held key is generated and
        // there is no PEM fallback when the signer is unavailable or the sign times out.
        let csr = match certificate_key.token_key() {
            Some(token) => {
                CertificateRequest::build_with_signer(domains, token.key_type(), token.signer())?
            }
            None => CertificateRequest::generate_with_key_type(domains, key_type)?,
        };
        account_client.finalize_order(&order, &csr).await?;
        let issued = account_client
            .wait_for_certificate(&order.url, &self.poll_policy, self.clock.as_ref())
            .await?;

        // CertMagic stores the ACME certificate resource metadata alongside the chain. Mirror
        // acmez's `acme.Certificate` JSON so Caddy tooling (and ARI/replacement tooling) can read
        // where the certificate came from after a caddy-rs issuance or renewal.
        let issuer_data = Some(serde_json::json!({
            "url": issued.url,
            "ca": self.config.ca,
            "account": account_client.account_url(),
        }));
        let stored = stored_certificate(&issued, &csr, domains, issuer_data, certificate_key)?;
        self.certificate_storage
            .store(&self.storage_key(domains), &stored)
            .await?;
        self.build_certificate(&issued, &csr, domains)
    }

    /// Solve every pending authorization of one order attempt (acmez `solveChallenges`).
    ///
    /// Records the failed challenge type per identifier and returns
    /// [`SolveAttemptError::Retryable`] when the CA reports a retryable problem and another
    /// solver-backed challenge type remains for the authorization; the caller then recreates
    /// the order (acmez `ObtainCertificate`).
    async fn solve_order_authorizations<U: AcmeTransport + ?Sized>(
        &self,
        account_client: &AcmeAccountClient<&U>,
        order: &OrderHandle,
        presented: &mut Vec<(Arc<dyn ChallengeSolver>, ChallengeHandle)>,
        failed_challenge_types: &mut HashMap<String, Vec<ChallengeType>>,
    ) -> std::result::Result<(), SolveAttemptError> {
        let authorizations = account_client
            .fetch_authorizations(&order.order)
            .await
            .map_err(SolveAttemptError::Fatal)?;
        // DIV-0097 / T-TLS-076: feed every offered challenge type into the adaptive selector
        // before selecting (acmez `getAuthzObjects` initial fill), so the preference order
        // reflects what the CA actually offers and later issuances prefer higher-success types.
        for fetched in &authorizations {
            let offered: Vec<ChallengeType> = fetched
                .authorization
                .challenges
                .iter()
                .filter_map(|challenge| challenge.kind())
                .collect();
            if !offered.is_empty() {
                self.challenge_selector
                    .record_offered(&offered)
                    .map_err(SolveAttemptError::Fatal)?;
            }
        }
        let policy = self.challenge_policy();
        let thumbprint = account_client
            .client()
            .account_key()
            .thumbprint()
            .map_err(SolveAttemptError::Fatal)?;
        let mut selected_by_url: HashMap<String, ChallengeType> = HashMap::new();

        // Present and initiate one challenge per pending authorization (acmez
        // `presentForNextChallenge` + `initiateCurrentChallenge`; caddy-rs
        // `acknowledge_challenge` performs the initiate request).
        for fetched in &authorizations {
            if fetched.authorization.status == AuthorizationStatus::Valid {
                continue;
            }
            let identifier = identifier_key(&fetched.authorization);
            let failed = failed_challenge_types
                .get(&identifier)
                .cloned()
                .unwrap_or_default();
            let challenge =
                select_remaining_challenge(&policy, &self.solvers, &fetched.authorization, &failed)
                    .map_err(SolveAttemptError::Fatal)?;
            let challenge_type = challenge.kind().ok_or_else(|| {
                SolveAttemptError::Fatal(Error::Issuer(format!(
                    "ACME authorization offered unsupported challenge type `{}`",
                    challenge.challenge_type
                )))
            })?;
            selected_by_url.insert(fetched.url.clone(), challenge_type);
            let solver = self.solvers.get(challenge_type).ok_or_else(|| {
                SolveAttemptError::Fatal(Error::Issuer(format!(
                    "no challenge solver is configured for `{challenge_type}`"
                )))
            })?;
            let domain = fetched
                .authorization
                .identifier
                .as_ref()
                .map(|identifier| identifier.value.clone())
                .ok_or_else(|| {
                    SolveAttemptError::Fatal(Error::Issuer(
                        "ACME authorization is missing its identifier".to_string(),
                    ))
                })?;
            let key_authorization = key_authorization(&challenge.token, &thumbprint);
            let handle = solver
                .present(&domain, challenge, &key_authorization)
                .await
                .map_err(SolveAttemptError::Fatal)?;
            presented.push((solver, handle));
            if let Err(error) = account_client.acknowledge_challenge(challenge).await {
                // acmez treats challenge initiation failures as fatal, but some CAs (and the
                // caddy-rs test CA) report a validation failure directly on the challenge POST;
                // apply the same retryable-problem gate here so the observable order-level
                // behaviour matches.
                self.challenge_selector
                    .record_attempt(challenge_type, false);
                if is_retryable_challenge_problem(&error)
                    && self.remember_failed_challenge_type(
                        &policy,
                        &fetched.authorization,
                        challenge_type,
                        failed_challenge_types,
                    )
                {
                    return Err(SolveAttemptError::Retryable(error));
                }
                return Err(SolveAttemptError::Fatal(error));
            }
        }

        // Poll each authorization (acmez `pollAuthorization`): update the adaptive success
        // statistics and retry the order with a different challenge type when the problem is
        // one acmez considers recoverable.
        for fetched in &authorizations {
            if fetched.authorization.status == AuthorizationStatus::Valid {
                continue;
            }
            let challenge_type = selected_by_url.get(&fetched.url).copied();
            let outcome = account_client
                .poll_authorization(&fetched.url, &self.poll_policy, self.clock.as_ref())
                .await;
            match outcome {
                Ok(_) => {
                    if let Some(challenge_type) = challenge_type {
                        self.challenge_selector.record_attempt(challenge_type, true);
                    }
                }
                Err(error) => {
                    let Some(challenge_type) = challenge_type else {
                        return Err(SolveAttemptError::Fatal(error));
                    };
                    self.challenge_selector
                        .record_attempt(challenge_type, false);
                    if is_retryable_challenge_problem(&error)
                        && self.remember_failed_challenge_type(
                            &policy,
                            &fetched.authorization,
                            challenge_type,
                            failed_challenge_types,
                        )
                    {
                        return Err(SolveAttemptError::Retryable(error));
                    }
                    return Err(SolveAttemptError::Fatal(error));
                }
            }
        }

        Ok(())
    }

    /// Remember `challenge_type` as failed for the authorization's identifier and report whether
    /// another solver-backed challenge type remains (acmez `rememberFailedChallenge` +
    /// `countAvailableChallenges`).
    fn remember_failed_challenge_type(
        &self,
        policy: &ChallengePolicy,
        authorization: &Authorization,
        challenge_type: ChallengeType,
        failed_challenge_types: &mut HashMap<String, Vec<ChallengeType>>,
    ) -> bool {
        let identifier = identifier_key(authorization);
        let mut failed = failed_challenge_types
            .get(&identifier)
            .cloned()
            .unwrap_or_default();
        failed.push(challenge_type);
        if remaining_challenge_types(policy, &self.solvers, authorization, &failed).is_empty() {
            return false;
        }
        failed_challenge_types
            .entry(identifier)
            .or_default()
            .push(challenge_type);
        true
    }

    fn storage_key(&self, domains: &[String]) -> String {
        format!(
            "{}/{}",
            caddy_issuer_key(&self.config.ca),
            caddy_certificate_storage_name(&domains[0])
        )
    }

    fn build_certificate(
        &self,
        issued: &IssuedCertificate,
        csr: &CertificateRequest,
        domains: &[String],
    ) -> Result<Certificate> {
        let leaf = issued.certificates_pem.first().ok_or_else(|| {
            Error::Issuer("ACME certificate download returned no PEM certificates".to_string())
        })?;
        let (not_before, not_after) = certificate_validity_unix(leaf).map_err(|error| {
            Error::Issuer(format!(
                "downloaded ACME certificate has no readable validity period: {error}"
            ))
        })?;
        Ok(Certificate {
            domains: domains.to_vec(),
            cert_chain_der: certificate_chain_der(&issued.certificates_pem)?,
            // Token-held keys stay in the token: there is no DER private key to hand out.
            private_key_der: match self.certificate_key.token_key() {
                Some(_) => Vec::new(),
                None => private_key_der(csr.private_key_pem())?,
            },
            not_before: UNIX_EPOCH + Duration::from_secs(not_before),
            not_after: UNIX_EPOCH + Duration::from_secs(not_after),
            issuer: self.config.ca.clone(),
        })
    }
}

impl AcmeIssuer<HyperTransport> {
    /// Production wiring using Caddy's data-directory `<root>` for account material and
    /// certificate storage.
    ///
    /// The transport trusts the CA's configured `trusted_roots_pem_files` when present (replacing
    /// the platform bundle, matching certmagic) and otherwise uses the platform trust store.
    pub fn from_config(config: AcmeIssuerConfig, root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let transport = if config.has_trusted_roots() {
            HyperTransport::with_root_certificates_pem_files(&config.trusted_roots_pem_files)?
        } else {
            HyperTransport::new()?
        };
        let account_storage: Arc<dyn AcmeStorage> =
            Arc::new(crate::storage::FileStorage::new(&root));
        let certificate_storage: Box<dyn CertificateStorage> =
            Box::new(crate::storage::FileStorage::new(root));
        Ok(Self::new(
            config,
            transport,
            account_storage,
            certificate_storage,
        ))
    }
}

impl<T: AcmeTransport> fmt::Debug for AcmeIssuer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeIssuer")
            .field("config", &self.config)
            .field("solvers", &self.solvers)
            .field("poll_policy", &self.poll_policy)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<T: AcmeTransport> CertificateIssuer for AcmeIssuer<T> {
    fn name(&self) -> &'static str {
        "acme"
    }

    async fn renewal_info(&self, certificate: &Certificate) -> Result<Option<RenewalInfo>> {
        let Some(leaf) = certificate.cert_chain_der.first() else {
            return Ok(None);
        };
        crate::acme::fetch_renewal_info(&self.transport, &self.config.ca, leaf).await
    }

    async fn obtain(&self, request: &IssuanceRequest) -> Result<Certificate> {
        self.issue(request).await
    }
}

/// Build the [`StoredCertificate`] record for a downloaded ACME certificate.
fn stored_certificate(
    issued: &IssuedCertificate,
    csr: &CertificateRequest,
    domains: &[String],
    issuer_data: Option<serde_json::Value>,
    certificate_key: &CertificateKeySource,
) -> Result<StoredCertificate> {
    let leaf = issued.certificates_pem.first().ok_or_else(|| {
        Error::Issuer("ACME certificate download returned no PEM certificates".to_string())
    })?;
    let (_, not_after_unix) = certificate_validity_unix(leaf).map_err(|error| {
        Error::Issuer(format!(
            "downloaded ACME certificate has no readable validity period: {error}"
        ))
    })?;
    Ok(StoredCertificate {
        certificate_pem: issued.certificates_pem.clone(),
        private_key_pem: match certificate_key.token_key() {
            // Token-held keys have no PEM form; storage refuses to write this record.
            Some(_) => String::new(),
            None => csr.private_key_pem().to_string(),
        },
        token_key: certificate_key.token_ref().cloned(),
        domains: domains.to_vec(),
        not_after_unix,
        issuer_data,
        metadata_extra: std::collections::BTreeMap::new(),
    })
}

fn normalize_domains(domains: &[String]) -> Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(domains.len());
    for domain in domains {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return Err(Error::Issuer(
                "certificate request contains an empty domain".to_string(),
            ));
        }
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    if normalized.is_empty() {
        return Err(Error::Issuer(
            "certificate request needs at least one domain".to_string(),
        ));
    }
    Ok(normalized)
}

/// Internal/local CA issuer (`tls internal` / `local_certs`).
///
/// The implementation lives in [`crate::internal_ca`]; this re-export keeps the historical
/// `crate::issuer::InternalIssuer` path working.
pub use crate::internal_ca::InternalIssuer;

/// Expiry/renewal helper used by the scheduler: returns whether `now` is inside the renewal
/// window, where the window is `renewal_window` before expiry (Caddy's default is a fixed
/// fraction of lifetime; see `Certificate::renewal_time`).
pub fn within_renewal_window(
    not_after: SystemTime,
    now: SystemTime,
    renewal_window: Duration,
) -> bool {
    not_after
        .duration_since(now)
        .map(|remaining| remaining <= renewal_window)
        .unwrap_or(true)
}

/// Outcome of solving one order attempt (acmez `solveChallenges`).
enum SolveAttemptError {
    /// acmez `retryableErr`: a challenge failed with a retryable problem type and another
    /// solver-backed challenge type remains, so the order should be recreated.
    Retryable(Error),
    /// Any other failure; propagate it unchanged.
    Fatal(Error),
}

/// acmez `failedChallengeMap.idKey`: identifier type concatenated with its value.
fn identifier_key(authorization: &Authorization) -> String {
    authorization
        .identifier
        .as_ref()
        .map(|identifier| format!("{}{}", identifier.identifier_type, identifier.value))
        .unwrap_or_default()
}

/// Whether an ACME problem is one acmez retries with a different challenge type
/// (`connection`, `dns`, `serverInternal`, `unauthorized`, `tls`; acmez v3.1.7
/// `pollAuthorization`).
fn is_retryable_challenge_problem(error: &Error) -> bool {
    let Error::Acme(error) = error else {
        return false;
    };
    let problem = match error.as_ref() {
        AcmeError::Problem { problem, .. } => problem,
        AcmeError::InvalidAuthorization {
            problem: Some(problem),
            ..
        } => problem,
        AcmeError::InvalidChallenge {
            problem: Some(problem),
            ..
        } => problem,
        _ => return false,
    };
    matches!(
        problem.error_code(),
        Some("connection" | "dns" | "serverInternal" | "unauthorized" | "tls")
    )
}

/// Challenge types that can still be attempted for `authorization`: enabled by `policy`,
/// solver-backed, offered by the CA, and not already failed for this identifier (acmez
/// `remainingChallenges` after `enqueueUnfailedChallenges` and `nextChallenge`).
fn remaining_challenge_types(
    policy: &ChallengePolicy,
    solvers: &SolverRegistry,
    authorization: &Authorization,
    failed: &[ChallengeType],
) -> Vec<ChallengeType> {
    policy
        .ordered_types()
        .into_iter()
        .filter(|challenge_type| !failed.contains(challenge_type))
        .filter(|challenge_type| solvers.contains(*challenge_type))
        .filter(|challenge_type| {
            authorization
                .challenges
                .iter()
                .any(|challenge| challenge.kind() == Some(*challenge_type))
        })
        .collect()
}

/// Select the next challenge to solve for `authorization` (acmez `nextChallenge`): the
/// most-preferred remaining challenge type that also has a configured solver.
fn select_remaining_challenge<'authorization>(
    policy: &ChallengePolicy,
    solvers: &SolverRegistry,
    authorization: &'authorization Authorization,
    failed: &[ChallengeType],
) -> Result<&'authorization Challenge> {
    for challenge_type in remaining_challenge_types(policy, solvers, authorization, failed) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::{
        account_paths, AcmeError, Challenge, ChallengeStatus, HttpMethod, HttpRequest,
        HttpResponse, MemoryAcmeStorage, StoredAccount,
    };
    use crate::dns::{DnsProvider, InMemoryDnsProvider};
    use crate::solver::dns01_txt_value;
    use crate::storage::MemoryStorage;
    use serde_json::{json, Value};
    use std::collections::VecDeque;

    #[test]
    fn acme_config_decodes_renewal_window() {
        let config = AcmeIssuerConfig::from_json(&json!({
            "module": "acme",
            "renewal_window": 3600_000_000_000_i64,
        }))
        .expect("decode integer");
        assert_eq!(
            config.renewal_window,
            Some(std::time::Duration::from_secs(3600))
        );
        let config = AcmeIssuerConfig::from_json(&json!({
            "module": "acme",
            "renewal_window": "1h",
        }))
        .expect("decode string");
        assert_eq!(
            config.renewal_window,
            Some(std::time::Duration::from_secs(3600))
        );
    }
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    const DIRECTORY_URL: &str = "https://acme.test/directory";
    const NEW_ACCOUNT_URL: &str = "https://acme.test/new-account";
    const NEW_ORDER_URL: &str = "https://acme.test/new-order";
    const ACCOUNT_URL: &str = "https://acme.test/account/1";
    const ORDER_URL: &str = "https://acme.test/order/1";
    const AUTHZ_URL: &str = "https://acme.test/authz/1";
    const CHALLENGE_URL: &str = "https://acme.test/challenge/1";
    const FINALIZE_URL: &str = "https://acme.test/finalize/1";
    const CERTIFICATE_URL: &str = "https://acme.test/certificate/1";
    const STORAGE_KEY: &str = "acme.test-directory/example.com";

    /// Certificate chain fixture: leaf (example.com, www.example.com) plus its test CA.
    const CERTIFICATE_CHAIN_PEM: &str = include_str!(
        "../tests/fixtures/caddy-data/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt"
    );
    /// notAfter of the fixture leaf: 2026-04-01T00:00:00Z.
    const NOT_AFTER: u64 = 1_775_001_600;

    // ---- scripted ACME transport ---------------------------------------------------------

    type RequestCheck = Box<dyn Fn(&HttpRequest) + Send + Sync>;

    struct Step {
        method: HttpMethod,
        url: String,
        response: HttpResponse,
        check: Option<RequestCheck>,
    }

    #[derive(Default)]
    struct Inner {
        steps: Mutex<VecDeque<Step>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    #[derive(Clone, Default)]
    struct TestTransport {
        inner: Arc<Inner>,
    }

    impl TestTransport {
        fn new() -> Self {
            Self::default()
        }

        fn expect(
            &self,
            method: HttpMethod,
            url: impl Into<String>,
            response: HttpResponse,
        ) -> &Self {
            self.expect_with(method, url, response, |_| {})
        }

        fn expect_with(
            &self,
            method: HttpMethod,
            url: impl Into<String>,
            response: HttpResponse,
            check: impl Fn(&HttpRequest) + Send + Sync + 'static,
        ) -> &Self {
            self.inner.steps.lock().unwrap().push_back(Step {
                method,
                url: url.into(),
                response,
                check: Some(Box::new(check)),
            });
            self
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.inner.requests.lock().unwrap().clone()
        }

        fn remaining(&self) -> usize {
            self.inner.steps.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl AcmeTransport for TestTransport {
        async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.inner.requests.lock().unwrap().push(request.clone());
            let step = self
                .inner
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    panic!(
                        "scripted transport exhausted at {} {}",
                        request.method, request.url
                    )
                });
            assert_eq!(
                step.method, request.method,
                "unexpected method for {}",
                request.url
            );
            assert_eq!(step.url, request.url, "unexpected request URL");
            if let Some(check) = &step.check {
                check(&request);
            }
            Ok(step.response)
        }
    }

    // ---- ACME wire documents -------------------------------------------------------------

    fn json_response(status: u16, body: Value) -> HttpResponse {
        HttpResponse::with_json(status, &body).expect("JSON response")
    }

    fn with_nonce(mut response: HttpResponse, nonce: &str) -> HttpResponse {
        response
            .headers
            .push(("Replay-Nonce".to_string(), nonce.to_string()));
        response
    }

    fn with_location(mut response: HttpResponse, location: &str) -> HttpResponse {
        response
            .headers
            .push(("Location".to_string(), location.to_string()));
        response
    }

    fn problem_response(status: u16, kind: &str, detail: &str) -> HttpResponse {
        HttpResponse::with_problem(
            status,
            &json!({
                "type": format!("urn:ietf:params:acme:error:{kind}"),
                "detail": detail,
                "status": status
            }),
        )
        .expect("problem response")
    }

    fn pem_response() -> HttpResponse {
        HttpResponse::new(200)
            .with_header("Content-Type", "application/pem-certificate-chain")
            .with_body(CERTIFICATE_CHAIN_PEM)
    }

    fn directory_document() -> Value {
        json!({
            "newNonce": format!("{DIRECTORY_URL}/new-nonce"),
            "newAccount": NEW_ACCOUNT_URL,
            "newOrder": NEW_ORDER_URL,
            "revokeCert": format!("{DIRECTORY_URL}/revoke"),
            "meta": {}
        })
    }

    fn account_document() -> Value {
        json!({
            "status": "valid",
            "contact": ["mailto:ops@example.com"],
            "orders": format!("{ACCOUNT_URL}/orders")
        })
    }

    fn order_document(status: &str) -> Value {
        json!({
            "status": status,
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": [AUTHZ_URL],
            "finalize": FINALIZE_URL
        })
    }

    fn valid_order_document() -> Value {
        let mut order = order_document("valid");
        order["certificate"] = json!(CERTIFICATE_URL);
        order
    }

    fn authorization_document(status: &str, challenge_types: &[&str]) -> Value {
        let challenges: Vec<Value> = challenge_types
            .iter()
            .map(|challenge_type| {
                json!({
                    "type": challenge_type,
                    "url": CHALLENGE_URL,
                    "token": "token-1",
                    "status": if status == "valid" { "valid" } else { "pending" }
                })
            })
            .collect();
        json!({
            "status": status,
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": challenges
        })
    }

    fn challenge_document(challenge_type: &str) -> Value {
        json!({
            "type": challenge_type,
            "url": CHALLENGE_URL,
            "token": "token-1",
            "status": "processing"
        })
    }

    fn script_account_and_order(transport: &TestTransport, challenge_types: &[&str]) {
        transport.expect(
            HttpMethod::Get,
            DIRECTORY_URL,
            with_nonce(json_response(200, directory_document()), "nonce-0"),
        );
        transport.expect(
            HttpMethod::Post,
            NEW_ACCOUNT_URL,
            with_nonce(
                with_location(json_response(201, account_document()), ACCOUNT_URL),
                "nonce-1",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            NEW_ORDER_URL,
            with_nonce(
                with_location(json_response(201, order_document("pending")), ORDER_URL),
                "nonce-2",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            AUTHZ_URL,
            with_nonce(
                json_response(200, authorization_document("pending", challenge_types)),
                "nonce-3",
            ),
        );
    }

    fn script_finalization(transport: &TestTransport, challenge_type: &str) {
        transport.expect(
            HttpMethod::Post,
            CHALLENGE_URL,
            with_nonce(
                json_response(200, challenge_document(challenge_type)),
                "nonce-4",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            AUTHZ_URL,
            with_nonce(
                json_response(200, authorization_document("valid", &[challenge_type])),
                "nonce-5",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            ORDER_URL,
            with_nonce(json_response(200, order_document("ready")), "nonce-6"),
        );
        transport.expect(
            HttpMethod::Post,
            FINALIZE_URL,
            with_nonce(json_response(200, order_document("processing")), "nonce-7"),
        );
        transport.expect(
            HttpMethod::Post,
            ORDER_URL,
            with_nonce(json_response(200, valid_order_document()), "nonce-8"),
        );
        transport.expect(
            HttpMethod::Post,
            CERTIFICATE_URL,
            with_nonce(pem_response(), "nonce-9"),
        );
    }

    // ---- issuer construction helpers -----------------------------------------------------

    fn http_config() -> AcmeIssuerConfig {
        AcmeIssuerConfig {
            ca: DIRECTORY_URL.to_string(),
            email: Some("ops@example.com".to_string()),
            ..AcmeIssuerConfig::default()
        }
    }

    fn tls_alpn01_config() -> AcmeIssuerConfig {
        AcmeIssuerConfig {
            ca: DIRECTORY_URL.to_string(),
            email: Some("ops@example.com".to_string()),
            http_challenge_disabled: true,
            ..AcmeIssuerConfig::default()
        }
    }

    fn issuer_with(
        transport: TestTransport,
        config: AcmeIssuerConfig,
        account_storage: Arc<MemoryAcmeStorage>,
        certificate_storage: &Arc<MemoryStorage>,
    ) -> AcmeIssuer<TestTransport> {
        AcmeIssuer::new(
            config,
            transport,
            account_storage,
            Box::new(Arc::clone(certificate_storage)),
        )
    }

    fn issuance_request() -> IssuanceRequest {
        IssuanceRequest {
            domains: vec!["example.com".to_string()],
            internal: false,
            key_type: CertificateKeyType::P256,
        }
    }

    // ---- configuration unit tests --------------------------------------------------------

    #[test]
    fn parses_acme_json() {
        let config = AcmeIssuerConfig::from_json(&json!({
            "module": "acme",
            "ca": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "email": "ops@example.com",
            "challenges": {"dns": {"provider": {"name": "cloudflare", "api_token": "x"}}}
        }))
        .unwrap();
        assert_eq!(
            config.ca,
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(config.email.as_deref(), Some("ops@example.com"));
        assert_eq!(config.dns_provider.as_deref(), Some("cloudflare"));
        assert!(!config.http_challenge_disabled);
        assert!(!config.tls_alpn_challenge_disabled);
    }

    #[test]
    fn parses_challenge_disabled_flags_and_string_provider() {
        let config = AcmeIssuerConfig::from_json(&json!({
            "module": "acme",
            "challenges": {
                "http": {"disabled": true},
                "tls-alpn": {"disabled": true},
                "dns": {"provider": "route53"}
            }
        }))
        .unwrap();
        assert_eq!(config.dns_provider.as_deref(), Some("route53"));
        assert!(config.http_challenge_disabled);
        assert!(config.tls_alpn_challenge_disabled);
    }

    #[test]
    fn parses_acme_account_and_eab_config() {
        let config = AcmeIssuerConfig::from_json(&json!({
            "module": "acme",
            "ca": "https://acme.example/directory",
            "test_ca": "https://acme.example/test/directory",
            "email": "ops@example.com",
            "account_key": "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
            "external_account": {"key_id": "kid-1", "mac_key": "c2VjcmV0"}
        }))
        .unwrap();
        assert_eq!(
            config.test_ca.as_deref(),
            Some("https://acme.example/test/directory")
        );
        assert_eq!(
            config.account_key_pem.as_deref(),
            Some("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")
        );
        let eab = config.external_account.unwrap();
        assert_eq!(eab.kid, "kid-1");
        assert_eq!(eab.hmac_key, "c2VjcmV0");
    }

    #[test]
    fn rejects_unsupported_challenge_configuration() {
        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "challenges": {"http": {"alternate_port": 8080}}
        }))
        .unwrap_err();
        assert!(
            error.to_string().contains("TLS-ACME-CHALLENGE")
                || error.to_string().contains("alternate"),
            "{error}"
        );

        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "challenges": {"http": {"disabled": "yes"}}
        }))
        .unwrap_err();
        assert!(error.to_string().contains("must be a boolean"), "{error}");

        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "challenges": {"tls-alpn": {"unknown_option": true}}
        }))
        .unwrap_err();
        assert!(
            error.to_string().contains("TLS-ACME-CHALLENGE")
                || error.to_string().contains("unknown_option"),
            "{error}"
        );

        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "challenges": {"device-attest-01": {}}
        }))
        .unwrap_err();
        assert!(
            error.to_string().contains("TLS-ACME-CHALLENGE")
                || error.to_string().contains("device-attest"),
            "{error}"
        );

        // Supported enable/disable flags still parse.
        let config = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "challenges": {"http": {"disabled": true}, "tls-alpn": {"disabled": true}}
        }))
        .unwrap();
        assert!(config.http_challenge_disabled);
        assert!(config.tls_alpn_challenge_disabled);
    }

    #[test]
    fn rejects_malformed_external_account_config() {
        let error = AcmeIssuerConfig::from_json(&json!({
            "module": "acme",
            "external_account": {"key_id": "kid-1"}
        }))
        .unwrap_err();
        assert!(error.to_string().contains("external_account"), "{error}");
    }

    #[test]
    fn renewal_window_boundary() {
        let now = SystemTime::UNIX_EPOCH;
        let not_after = now + Duration::from_secs(30 * 86_400);
        assert!(!within_renewal_window(
            not_after,
            now,
            Duration::from_secs(29 * 86_400)
        ));
        assert!(within_renewal_window(
            not_after,
            now,
            Duration::from_secs(30 * 86_400)
        ));
    }

    #[tokio::test]
    async fn unconfigured_internal_issuer_fails_loudly() {
        let error = InternalIssuer::default()
            .obtain(&issuance_request())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("not configured"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn configured_dns_solver_is_attached_from_configuration_alone() {
        let transport: Arc<dyn AcmeTransport> = Arc::new(TestTransport::new());
        let config = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "ca": DIRECTORY_URL,
            "challenges": {
                "dns": {
                    "provider": {"name": "cloudflare", "api_token": "token"},
                    "propagation_timeout": 5_000_000_000_i64
                }
            }
        }))
        .unwrap();
        let issuer = AcmeIssuer::new(
            config,
            Arc::clone(&transport),
            Arc::new(MemoryAcmeStorage::new()),
            Box::new(MemoryStorage::new()),
        )
        .with_configured_dns_solver(Arc::clone(&transport))
        .expect("configured DNS solver builds");
        assert!(
            issuer.solvers().contains(ChallengeType::Dns01),
            "config alone must attach a DNS-01 solver"
        );
        assert_eq!(issuer.config.dns_provider.as_deref(), Some("cloudflare"));
    }

    #[tokio::test]
    async fn configured_dns_solver_rejects_unknown_provider_loudly() {
        let transport: Arc<dyn AcmeTransport> = Arc::new(TestTransport::new());
        let config = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "challenges": {"dns": {"provider": {"name": "bogus-provider"}}}
        }))
        .unwrap();
        let error = AcmeIssuer::new(
            config,
            Arc::clone(&transport),
            Arc::new(MemoryAcmeStorage::new()),
            Box::new(MemoryStorage::new()),
        )
        .with_configured_dns_solver(transport)
        .expect_err("unknown DNS provider must be rejected");
        let message = error.to_string();
        assert!(message.contains("bogus-provider"), "{message}");
        assert!(message.contains("T-TLS-063"), "{message}");
    }

    // ---- end-to-end HTTP-01 issuance -----------------------------------------------------

    #[tokio::test]
    async fn issuance_uses_configured_csr_key_type_for_p384_and_rsa2048() {
        for key_type in [CertificateKeyType::P384, CertificateKeyType::Rsa2048] {
            let transport = TestTransport::new();
            let account_storage = Arc::new(MemoryAcmeStorage::new());
            let certificate_storage = Arc::new(MemoryStorage::new());
            let issuer = issuer_with(
                transport.clone(),
                http_config(),
                Arc::clone(&account_storage),
                &certificate_storage,
            );
            script_account_and_order(&transport, &["http-01"]);
            script_finalization(&transport, "http-01");

            let mut request = issuance_request();
            request.key_type = key_type;
            let certificate = issuer.obtain(&request).await.unwrap();
            let stored = certificate_storage
                .load(STORAGE_KEY)
                .await
                .unwrap()
                .expect("certificate persisted");
            let key_der = private_key_der(&stored.private_key_pem).unwrap();
            assert_eq!(
                CertificateKeyType::from_private_key_der(&key_der).unwrap(),
                key_type,
                "{key_type:?}: CSR key type must drive the certificate key"
            );
            assert_eq!(certificate.private_key_der, key_der);
        }
    }

    #[tokio::test]
    async fn http01_issuance_succeeds_and_persists_certificate() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            Arc::clone(&account_storage),
            &certificate_storage,
        );
        let tokens = Arc::clone(issuer.http01_token_store());

        script_account_and_order(&transport, &["http-01"]);
        let tokens_for_check = Arc::clone(&tokens);
        let served = Arc::new(AtomicBool::new(false));
        let served_clone = Arc::clone(&served);
        transport.expect_with(
            HttpMethod::Post,
            CHALLENGE_URL,
            with_nonce(json_response(200, challenge_document("http-01")), "nonce-4"),
            move |_request| {
                let key_authorization = tokens_for_check
                    .key_authorization("token-1")
                    .expect("key authorization must be served when the challenge is acknowledged");
                assert!(
                    key_authorization.starts_with("token-1."),
                    "unexpected key authorization `{key_authorization}`"
                );
                served_clone.store(true, Ordering::SeqCst);
            },
        );
        transport.expect(
            HttpMethod::Post,
            AUTHZ_URL,
            with_nonce(
                json_response(200, authorization_document("valid", &["http-01"])),
                "nonce-5",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            ORDER_URL,
            with_nonce(json_response(200, order_document("ready")), "nonce-6"),
        );
        transport.expect(
            HttpMethod::Post,
            FINALIZE_URL,
            with_nonce(json_response(200, order_document("processing")), "nonce-7"),
        );
        transport.expect(
            HttpMethod::Post,
            ORDER_URL,
            with_nonce(json_response(200, valid_order_document()), "nonce-8"),
        );
        transport.expect(
            HttpMethod::Post,
            CERTIFICATE_URL,
            with_nonce(pem_response(), "nonce-9"),
        );

        let certificate = issuer.obtain(&issuance_request()).await.unwrap();

        assert!(served.load(Ordering::SeqCst), "solver was never used");
        assert!(tokens.is_empty(), "HTTP-01 token must be withdrawn");
        assert_eq!(certificate.domains, vec!["example.com".to_string()]);
        assert_eq!(certificate.cert_chain_der.len(), 2, "leaf plus test CA");
        assert!(!certificate.private_key_der.is_empty());
        assert_eq!(certificate.issuer, DIRECTORY_URL);
        assert_eq!(
            certificate.not_after,
            UNIX_EPOCH + Duration::from_secs(NOT_AFTER)
        );

        let stored = certificate_storage
            .load(STORAGE_KEY)
            .await
            .unwrap()
            .expect("certificate must be persisted in the Caddy layout");
        assert_eq!(stored.domains, vec!["example.com".to_string()]);
        assert_eq!(stored.not_after_unix, NOT_AFTER);
        assert_eq!(stored.certificate_pem.len(), 2);
        assert!(stored.private_key_pem.contains("PRIVATE KEY"));
        assert_eq!(
            private_key_der(&stored.private_key_pem).unwrap(),
            certificate.private_key_der
        );
        // CertMagic ACME metadata (`acme.Certificate`) is preserved alongside the certificate so
        // Caddy/ARI tooling can recover the cert URL, CA directory and account URL.
        let issuer_data = stored.issuer_data.expect("ACME issuer_data is stored");
        assert_eq!(issuer_data["url"], CERTIFICATE_URL);
        assert_eq!(issuer_data["ca"], DIRECTORY_URL);
        assert_eq!(issuer_data["account"], ACCOUNT_URL);

        let requests = transport.requests();
        assert_eq!(requests.len(), 10);
        assert_eq!(
            requests
                .iter()
                .map(|request| request.method)
                .collect::<Vec<_>>(),
            vec![
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Post,
                HttpMethod::Post,
                HttpMethod::Post,
                HttpMethod::Post,
                HttpMethod::Post,
                HttpMethod::Post,
                HttpMethod::Post,
                HttpMethod::Post,
            ]
        );
        assert_eq!(requests[4].url, CHALLENGE_URL);
        // Challenge acknowledgement is a signed POST with an empty JWS payload.
        let acknowledged: Value = serde_json::from_slice(&requests[4].body).unwrap();
        assert!(acknowledged.get("protected").is_some());
        assert!(acknowledged.get("signature").is_some());
        assert_eq!(transport.remaining(), 0);
    }

    // ---- end-to-end TLS-ALPN-01 issuance --------------------------------------------------

    #[tokio::test]
    async fn tls_alpn01_issuance_succeeds_when_http01_is_disabled() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let issuer = issuer_with(
            transport.clone(),
            tls_alpn01_config(),
            Arc::clone(&account_storage),
            &certificate_storage,
        );
        let tokens = Arc::clone(issuer.tls_alpn01_token_store());
        assert_eq!(
            issuer.challenge_policy().ordered_types(),
            vec![ChallengeType::TlsAlpn01],
            "HTTP-01 disabled means only TLS-ALPN-01 may be selected"
        );

        script_account_and_order(&transport, &["tls-alpn-01"]);
        let tokens_for_check = Arc::clone(&tokens);
        let served = Arc::new(AtomicBool::new(false));
        let served_clone = Arc::clone(&served);
        transport.expect_with(
            HttpMethod::Post,
            CHALLENGE_URL,
            with_nonce(
                json_response(200, challenge_document("tls-alpn-01")),
                "nonce-4",
            ),
            move |_request| {
                let challenge = tokens_for_check
                    .lookup("example.com")
                    .expect("challenge certificate must exist when the challenge is acknowledged");
                assert!(
                    challenge.key_authorization().starts_with("token-1."),
                    "unexpected key authorization `{}`",
                    challenge.key_authorization()
                );
                served_clone.store(true, Ordering::SeqCst);
            },
        );
        transport.expect(
            HttpMethod::Post,
            AUTHZ_URL,
            with_nonce(
                json_response(200, authorization_document("valid", &["tls-alpn-01"])),
                "nonce-5",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            ORDER_URL,
            with_nonce(json_response(200, order_document("ready")), "nonce-6"),
        );
        transport.expect(
            HttpMethod::Post,
            FINALIZE_URL,
            with_nonce(json_response(200, order_document("processing")), "nonce-7"),
        );
        transport.expect(
            HttpMethod::Post,
            ORDER_URL,
            with_nonce(json_response(200, valid_order_document()), "nonce-8"),
        );
        transport.expect(
            HttpMethod::Post,
            CERTIFICATE_URL,
            with_nonce(pem_response(), "nonce-9"),
        );

        let certificate = issuer.obtain(&issuance_request()).await.unwrap();
        assert!(
            served.load(Ordering::SeqCst),
            "TLS-ALPN solver was never used"
        );
        assert!(
            tokens.is_empty(),
            "challenge certificate must be withdrawn after issuance"
        );
        assert_eq!(certificate.domains, vec!["example.com".to_string()]);
        assert_eq!(transport.remaining(), 0);
    }

    #[tokio::test]
    async fn tls_alpn01_challenge_is_withdrawn_when_validation_fails() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let issuer = issuer_with(
            transport.clone(),
            tls_alpn01_config(),
            Arc::clone(&account_storage),
            &certificate_storage,
        );
        let tokens = Arc::clone(issuer.tls_alpn01_token_store());

        script_account_and_order(&transport, &["tls-alpn-01"]);
        let tokens_for_check = Arc::clone(&tokens);
        transport.expect_with(
            HttpMethod::Post,
            CHALLENGE_URL,
            with_nonce(
                json_response(200, challenge_document("tls-alpn-01")),
                "nonce-4",
            ),
            move |_request| {
                assert!(
                    tokens_for_check.lookup("example.com").is_some(),
                    "challenge certificate must be present before validation"
                );
            },
        );
        // The CA rejects the authorization: issuance fails, evidence must be withdrawn.
        transport.expect(
            HttpMethod::Post,
            AUTHZ_URL,
            with_nonce(
                problem_response(400, "unauthorized", "validation failed"),
                "nonce-5",
            ),
        );

        let error = issuer.obtain(&issuance_request()).await.unwrap_err();
        assert!(
            error.to_string().contains("validation failed")
                || error.to_string().contains("problem"),
            "expected a loud CA error, got: {error}"
        );
        assert!(
            tokens.is_empty(),
            "challenge certificate must be cleaned up when issuance fails"
        );
    }

    #[tokio::test]
    async fn second_issuance_reuses_the_stored_account() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            Arc::clone(&account_storage),
            &certificate_storage,
        );

        script_account_and_order(&transport, &["http-01"]);
        script_finalization(&transport, "http-01");
        issuer.obtain(&issuance_request()).await.unwrap();

        // Second issuance: the directory and the order are fetched, but no new account is created.
        transport.expect(
            HttpMethod::Get,
            DIRECTORY_URL,
            with_nonce(json_response(200, directory_document()), "nonce-a"),
        );
        transport.expect(
            HttpMethod::Post,
            NEW_ORDER_URL,
            with_nonce(
                with_location(json_response(201, order_document("pending")), ORDER_URL),
                "nonce-b",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            AUTHZ_URL,
            with_nonce(
                json_response(200, authorization_document("pending", &["http-01"])),
                "nonce-c",
            ),
        );
        script_finalization(&transport, "http-01");
        issuer.obtain(&issuance_request()).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 19);
        // First request of the second issuance is the directory; the next is the order.
        assert_eq!(requests[10].url, DIRECTORY_URL);
        assert_eq!(requests[11].url, NEW_ORDER_URL);
        assert!(requests[11..]
            .iter()
            .all(|request| request.url != NEW_ACCOUNT_URL));
    }

    #[tokio::test]
    async fn http01_challenge_failure_cleans_up_the_token() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            account_storage,
            &certificate_storage,
        );
        let tokens = Arc::clone(issuer.http01_token_store());

        script_account_and_order(&transport, &["http-01"]);
        transport.expect(
            HttpMethod::Post,
            CHALLENGE_URL,
            with_nonce(
                problem_response(
                    400,
                    "unauthorized",
                    "Invalid response from http://example.com/.well-known/acme-challenge/token-1",
                ),
                "nonce-4",
            ),
        );

        let error = issuer.obtain(&issuance_request()).await.unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("unauthorized") || message.contains("Invalid response"),
            "unexpected error: {message}"
        );
        assert!(
            tokens.is_empty(),
            "failed issuance must withdraw the HTTP-01 token"
        );
        assert!(certificate_storage.list("").await.unwrap().is_empty());
        assert_eq!(transport.requests().len(), 5);
        assert_eq!(transport.remaining(), 0);
    }

    /// Deterministic randomness source: always returns index 0, which reverses the first-fill
    /// Fisher–Yates shuffle (the bound is inclusive), so a selector offered
    /// `[http-01, tls-alpn-01]` prefers TLS-ALPN-01 first.
    struct AlwaysZeroRng;

    impl crate::acme::adaptive_challenge::ChallengeRng for AlwaysZeroRng {
        fn random_index(
            &self,
            _max: usize,
        ) -> std::result::Result<usize, ring::error::Unspecified> {
            Ok(0)
        }
    }

    /// Clock that records sleeps instead of waiting, so the acmez inter-attempt delay is
    /// asserted without slowing the suite.
    #[derive(Default)]
    struct RecordingClock {
        sleeps: Mutex<Vec<Duration>>,
    }

    #[async_trait::async_trait]
    impl AcmeClock for RecordingClock {
        async fn sleep(&self, duration: Duration) {
            self.sleeps.lock().unwrap().push(duration);
        }
    }

    #[tokio::test]
    async fn retryable_tls_alpn_failure_retries_the_order_with_http01() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let mut issuer = issuer_with(
            transport.clone(),
            http_config(),
            account_storage,
            &certificate_storage,
        );
        issuer.challenge_selector = AdaptiveChallengeSelector::with_rng(Box::new(AlwaysZeroRng));
        let clock = Arc::new(RecordingClock::default());
        issuer.clock = clock.clone();
        let tls_alpn_tokens = Arc::clone(issuer.tls_alpn01_token_store());

        // Both challenge types are offered; the deterministic selector tries TLS-ALPN-01 first and
        // the CA rejects it with a retryable `connection` problem.
        script_account_and_order(&transport, &["http-01", "tls-alpn-01"]);
        transport.expect(
            HttpMethod::Post,
            CHALLENGE_URL,
            with_nonce(
                problem_response(400, "connection", "fake CA cannot validate tls-alpn-01"),
                "nonce-4",
            ),
        );
        // acmez `ObtainCertificate` (client.go:123-200) creates a fresh order for the second
        // attempt after a one-second pause, and picks the next solver-backed challenge type.
        transport.expect(
            HttpMethod::Post,
            NEW_ORDER_URL,
            with_nonce(
                with_location(json_response(201, order_document("pending")), ORDER_URL),
                "nonce-5",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            AUTHZ_URL,
            with_nonce(
                json_response(
                    200,
                    authorization_document("pending", &["http-01", "tls-alpn-01"]),
                ),
                "nonce-6",
            ),
        );
        script_finalization(&transport, "http-01");

        let certificate = issuer
            .obtain(&issuance_request())
            .await
            .expect("retryable TLS-ALPN-01 failure must retry with HTTP-01");
        assert_eq!(certificate.domains, vec!["example.com".to_string()]);
        assert!(
            tls_alpn_tokens.lookup("example.com").is_none(),
            "the failed attempt's TLS-ALPN-01 evidence must be withdrawn before retrying"
        );
        assert_eq!(
            *clock.sleeps.lock().unwrap(),
            vec![Duration::from_secs(1)],
            "acmez waits one second between order attempts"
        );
        // First attempt: directory, account, order, authz, challenge. Second attempt: order,
        // authz, challenge, authz, order-ready, finalize, order-valid, certificate.
        assert_eq!(transport.requests().len(), 13);
        assert_eq!(transport.remaining(), 0);
    }

    #[tokio::test]
    async fn tls_alpn_selection_without_http_uses_the_real_solver() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let config = AcmeIssuerConfig {
            ca: DIRECTORY_URL.to_string(),
            http_challenge_disabled: true,
            ..AcmeIssuerConfig::default()
        };
        let issuer = issuer_with(transport, config, account_storage, &certificate_storage);
        assert_eq!(
            issuer.challenge_policy().ordered_types(),
            vec![ChallengeType::TlsAlpn01]
        );
        let tokens = Arc::clone(issuer.tls_alpn01_token_store());
        let solver = issuer
            .solvers()
            .get(ChallengeType::TlsAlpn01)
            .expect("TLS-ALPN-01 solver is registered");
        let challenge: Challenge = serde_json::from_value(json!({
            "type": "tls-alpn-01",
            "url": CHALLENGE_URL,
            "token": "token-1",
            "status": "pending"
        }))
        .unwrap();
        let handle = solver
            .present("example.com", &challenge, "token-1.thumbprint")
            .await
            .unwrap();
        assert!(tokens.lookup("example.com").is_some());
        solver.withdraw(&handle).await.unwrap();
        assert!(tokens.is_empty());
    }

    // ---- end-to-end DNS-01 issuance ------------------------------------------------------

    fn dns_config() -> AcmeIssuerConfig {
        AcmeIssuerConfig {
            ca: DIRECTORY_URL.to_string(),
            email: Some("ops@example.com".to_string()),
            dns_provider: Some("in_memory".to_string()),
            ..AcmeIssuerConfig::default()
        }
    }

    #[tokio::test]
    async fn dns01_issuance_succeeds_with_propagation_and_cleanup() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let provider = Arc::new(InMemoryDnsProvider::with_zones(["example.com"]));
        let issuer = issuer_with(
            transport.clone(),
            dns_config(),
            Arc::clone(&account_storage),
            &certificate_storage,
        )
        .with_dns01_solver_and_propagation(
            provider.clone() as Arc<dyn DnsProvider>,
            Duration::from_secs(1),
            Duration::ZERO,
        );

        script_account_and_order(&transport, &["http-01", "dns-01"]);
        let provider_for_check = Arc::clone(&provider);
        let observed = Arc::new(Mutex::new(None::<String>));
        let observed_clone = Arc::clone(&observed);
        transport.expect_with(
            HttpMethod::Post,
            CHALLENGE_URL,
            with_nonce(json_response(200, challenge_document("dns-01")), "nonce-4"),
            move |_request| {
                let records = provider_for_check.records();
                assert_eq!(records.len(), 1, "DNS-01 TXT record must exist");
                assert_eq!(records[0].fqdn, "_acme-challenge.example.com");
                *observed_clone.lock().unwrap() = Some(records[0].value.clone());
            },
        );
        transport.expect(
            HttpMethod::Post,
            AUTHZ_URL,
            with_nonce(
                json_response(200, authorization_document("valid", &["dns-01"])),
                "nonce-5",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            ORDER_URL,
            with_nonce(json_response(200, order_document("ready")), "nonce-6"),
        );
        transport.expect(
            HttpMethod::Post,
            FINALIZE_URL,
            with_nonce(json_response(200, order_document("processing")), "nonce-7"),
        );
        transport.expect(
            HttpMethod::Post,
            ORDER_URL,
            with_nonce(json_response(200, valid_order_document()), "nonce-8"),
        );
        transport.expect(
            HttpMethod::Post,
            CERTIFICATE_URL,
            with_nonce(pem_response(), "nonce-9"),
        );

        let certificate = issuer.obtain(&issuance_request()).await.unwrap();
        assert_eq!(certificate.domains, vec!["example.com".to_string()]);

        // The TXT value must be base64url(SHA-256(token || '.' || account thumbprint)).
        let paths = account_paths(DIRECTORY_URL, Some("ops@example.com")).expect("account paths");
        let raw = account_storage.load(&paths.account).await.unwrap().unwrap();
        let account: StoredAccount = serde_json::from_slice(&raw).unwrap();
        let expected = dns01_txt_value(&key_authorization("token-1", &account.key_thumbprint));
        assert_eq!(observed.lock().unwrap().as_deref(), Some(expected.as_str()));

        assert!(
            provider.records().is_empty(),
            "DNS-01 TXT record must be cleaned up after issuance"
        );
        assert!(certificate_storage
            .load(STORAGE_KEY)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn dns01_propagation_timeout_cleans_up_the_txt_record() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let provider = Arc::new(InMemoryDnsProvider::with_zones(["example.com"]));
        provider.set_visible(false);
        let issuer = issuer_with(
            transport.clone(),
            dns_config(),
            account_storage,
            &certificate_storage,
        )
        .with_dns01_solver_and_propagation(
            provider.clone() as Arc<dyn DnsProvider>,
            Duration::from_millis(50),
            Duration::ZERO,
        );

        script_account_and_order(&transport, &["dns-01"]);

        let error = issuer.obtain(&issuance_request()).await.unwrap_err();
        assert!(
            error.to_string().contains("timed out"),
            "unexpected error: {error}"
        );
        assert!(
            provider.records().is_empty(),
            "failed propagation must delete the TXT record"
        );
        assert_eq!(transport.requests().len(), 4);
    }

    #[tokio::test]
    async fn dns_provider_without_attached_solver_is_reported() {
        let transport = TestTransport::new();
        let issuer = issuer_with(
            transport.clone(),
            dns_config(),
            Arc::new(MemoryAcmeStorage::new()),
            &Arc::new(MemoryStorage::new()),
        );
        let error = issuer.obtain(&issuance_request()).await.unwrap_err();
        assert!(
            error.to_string().contains("no DnsProvider solver"),
            "unexpected error: {error}"
        );
        assert!(transport.requests().is_empty());
    }

    // ---- account/order error propagation -------------------------------------------------

    #[tokio::test]
    async fn account_registration_error_propagates() {
        let transport = TestTransport::new();
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            Arc::new(MemoryAcmeStorage::new()),
            &Arc::new(MemoryStorage::new()),
        );
        transport.expect(
            HttpMethod::Get,
            DIRECTORY_URL,
            with_nonce(json_response(200, directory_document()), "nonce-0"),
        );
        transport.expect(
            HttpMethod::Post,
            NEW_ACCOUNT_URL,
            with_nonce(
                problem_response(403, "invalidContact", "invalid contact email"),
                "nonce-1",
            ),
        );
        let error = issuer.obtain(&issuance_request()).await.unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("invalidContact") && message.contains("invalid contact email"),
            "unexpected error: {message}"
        );
        assert!(matches!(error, Error::Acme(_)), "{error:?}");
        assert_eq!(transport.requests().len(), 2);
    }

    #[tokio::test]
    async fn new_order_error_propagates() {
        let transport = TestTransport::new();
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            Arc::new(MemoryAcmeStorage::new()),
            &Arc::new(MemoryStorage::new()),
        );
        transport.expect(
            HttpMethod::Get,
            DIRECTORY_URL,
            with_nonce(json_response(200, directory_document()), "nonce-0"),
        );
        transport.expect(
            HttpMethod::Post,
            NEW_ACCOUNT_URL,
            with_nonce(
                with_location(json_response(201, account_document()), ACCOUNT_URL),
                "nonce-1",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            NEW_ORDER_URL,
            with_nonce(
                problem_response(429, "rateLimited", "too many new orders"),
                "nonce-2",
            ),
        );
        let error = issuer.obtain(&issuance_request()).await.unwrap_err();
        assert!(
            error.to_string().contains("too many new orders"),
            "unexpected error: {error}"
        );
        assert!(matches!(error, Error::Acme(_)), "{error:?}");
        assert_eq!(transport.requests().len(), 3);
    }

    #[tokio::test]
    async fn internal_issuance_request_is_rejected_before_any_request() {
        let transport = TestTransport::new();
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            Arc::new(MemoryAcmeStorage::new()),
            &Arc::new(MemoryStorage::new()),
        );
        let error = issuer
            .obtain(&IssuanceRequest {
                domains: vec!["example.com".to_string()],
                internal: true,
                key_type: CertificateKeyType::P256,
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("internal CA"), "{error}");
        assert!(transport.requests().is_empty());
    }

    #[tokio::test]
    async fn empty_domain_list_is_rejected() {
        let transport = TestTransport::new();
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            Arc::new(MemoryAcmeStorage::new()),
            &Arc::new(MemoryStorage::new()),
        );
        let error = issuer
            .obtain(&IssuanceRequest {
                domains: Vec::new(),
                internal: false,
                key_type: CertificateKeyType::P256,
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("at least one domain"), "{error}");
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn challenge_status_enum_is_used_by_the_wire_model() {
        // Keeps the import used and documents the pending status the script emits.
        assert_eq!(ChallengeStatus::default(), ChallengeStatus::Pending);
    }

    #[test]
    fn acme_error_type_is_reachable_for_assertions() {
        // The error-propagations tests above assert `Error::Acme`; this keeps the type referenced.
        let error: Error = AcmeError::AccountKey("test".to_string()).into();
        assert!(matches!(error, Error::Acme(_)));
    }

    #[test]
    fn parses_trusted_roots_pem_files_from_issuer_json() {
        let config = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "ca": "https://ca.test/directory",
            "trusted_roots_pem_files": ["/etc/ssl/private/ca.pem", "relative/ca.pem"]
        }))
        .unwrap();
        assert!(config.has_trusted_roots());
        assert_eq!(
            config.trusted_roots_pem_files,
            vec![
                PathBuf::from("/etc/ssl/private/ca.pem"),
                PathBuf::from("relative/ca.pem")
            ]
        );

        let default = AcmeIssuerConfig::from_json(&serde_json::json!({"module": "acme"})).unwrap();
        assert!(!default.has_trusted_roots());
        assert!(default.read_trusted_roots().unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_trusted_roots_config() {
        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "trusted_roots_pem_files": "/etc/ca.pem"
        }))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("expected an array of PEM file paths"),
            "{error}"
        );

        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "trusted_roots_pem_files": [42]
        }))
        .unwrap_err();
        assert!(
            error.to_string().contains("expected a string path"),
            "{error}"
        );

        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "trusted_roots_pem_files": [""]
        }))
        .unwrap_err();
        assert!(error.to_string().contains("path is empty"), "{error}");
    }

    #[test]
    fn reading_missing_trusted_roots_fails_without_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("does-not-exist.pem");
        let config = AcmeIssuerConfig {
            ca: "https://ca.test/directory".to_string(),
            trusted_roots_pem_files: vec![missing.clone()],
            ..AcmeIssuerConfig::default()
        };
        let error = config.read_trusted_roots().unwrap_err().to_string();
        assert!(
            error.contains(missing.to_string_lossy().as_ref()),
            "error must name the configured path: {error}"
        );
        assert!(error.contains("cannot read"), "{error}");
        assert!(
            error.contains("https://ca.test/directory"),
            "error must name the ACME CA: {error}"
        );
    }

    #[test]
    fn reads_trusted_roots_from_pem_files() {
        let directory = tempfile::tempdir().unwrap();
        let root_file = directory.path().join("root.pem");
        std::fs::write(
            &root_file,
            include_str!("../testdata/acme/localhost-cert.pem"),
        )
        .unwrap();
        let config = AcmeIssuerConfig {
            trusted_roots_pem_files: vec![root_file],
            ..AcmeIssuerConfig::default()
        };
        let roots = config.read_trusted_roots().unwrap();
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn acme_config_decodes_timeout_and_network_proxy() {
        let config = AcmeIssuerConfig::from_json(&serde_json::json!({
            "acme_timeout": "2m",
            "network_proxy": {"from": "url", "url": "http://proxy.example.test:3128"}
        }))
        .unwrap();
        assert_eq!(config.acme_timeout, Some(Duration::from_secs(120)));
        assert_eq!(
            config.network_proxy.as_deref(),
            Some("http://proxy.example.test:3128")
        );

        let none = AcmeIssuerConfig::from_json(&serde_json::json!({
            "network_proxy": {"from": "none"}
        }))
        .unwrap();
        assert_eq!(none.network_proxy, None);
    }

    #[test]
    fn acme_timeout_and_network_proxy_errors_are_located() {
        let error = AcmeIssuerConfig::from_json(&serde_json::json!({"acme_timeout": 0}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("acme_timeout"), "{error}");
        let error = AcmeIssuerConfig::from_json(&serde_json::json!({"acme_timeout": "soon"}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("acme_timeout"), "{error}");
        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "network_proxy": {"from": "url", "url": "https://proxy.example.test:3128"}
        }))
        .unwrap_err()
        .to_string();
        assert!(error.contains("T-TLS-070"), "{error}");
        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "network_proxy": {"from": "url", "url": "http://"}
        }))
        .unwrap_err()
        .to_string();
        assert!(error.contains("network_proxy"), "{error}");
        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
            "network_proxy": {"from": "socks"}
        }))
        .unwrap_err()
        .to_string();
        assert!(error.contains("T-TLS-070"), "{error}");
    }
    // ---- token-held certificate keys (T-TLS-101) -----------------------------------------

    fn token_key_source(
        signer: Arc<crate::acme::csr::test_support::StubCsrSigner>,
    ) -> CertificateKeySource {
        CertificateKeySource::token(
            crate::certificate::TokenKeyRef::new("softHSM", "example.com"),
            signer,
        )
        .expect("P-256 token signer is CSR-compatible")
    }

    #[tokio::test]
    async fn token_signer_signs_the_acme_csr_and_no_pem_key_is_generated() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let signer = crate::acme::csr::test_support::StubCsrSigner::p256("session-1");
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            Arc::clone(&account_storage),
            &certificate_storage,
        )
        .with_certificate_key_source(token_key_source(Arc::clone(&signer)));
        script_account_and_order(&transport, &["http-01"]);
        script_finalization(&transport, "http-01");

        // The CSR is signed through the token signer; storage then refuses to write the
        // token-held key as PKCS#8 PEM, so issuance fails closed instead of persisting a key.
        let error = issuer
            .obtain(&issuance_request())
            .await
            .expect_err("a token-held key must never be written as a PEM key");
        assert_eq!(
            signer.calls(),
            1,
            "the ACME CSR must be signed through the token signer"
        );
        assert!(
            error
                .to_string()
                .contains("token-held keys are never written as PKCS#8 PEM"),
            "{error}"
        );
        assert!(
            error.to_string().contains("pkcs11 token softHSM"),
            "{error}"
        );
        assert!(
            certificate_storage
                .load(STORAGE_KEY)
                .await
                .unwrap()
                .is_none(),
            "no certificate/key record may be persisted for a token-held key"
        );
    }

    #[tokio::test]
    async fn unavailable_token_signer_fails_closed_before_any_csr() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let signer = crate::acme::csr::test_support::StubCsrSigner::failing(
            "session-1",
            "token is not present",
        );
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            Arc::clone(&account_storage),
            &certificate_storage,
        )
        .with_certificate_key_source(token_key_source(Arc::clone(&signer)));
        script_account_and_order(&transport, &["http-01"]);
        script_finalization(&transport, "http-01");

        let error = issuer
            .obtain(&issuance_request())
            .await
            .expect_err("an unavailable token signer must fail closed");
        assert!(
            error.to_string().contains("token is not present"),
            "{error}"
        );
        assert_eq!(signer.calls(), 0);
        assert!(certificate_storage
            .load(STORAGE_KEY)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn renewal_reuses_the_token_key_and_session() {
        let transport = TestTransport::new();
        let account_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let signer = crate::acme::csr::test_support::StubCsrSigner::p256("session-7");
        let issuer = issuer_with(
            transport.clone(),
            http_config(),
            Arc::clone(&account_storage),
            &certificate_storage,
        )
        .with_certificate_key_source(token_key_source(Arc::clone(&signer)));
        script_account_and_order(&transport, &["http-01"]);
        script_finalization(&transport, "http-01");
        // Renewal reuses the stored account, so only the directory and a fresh order are scripted.
        transport.expect(
            HttpMethod::Get,
            DIRECTORY_URL,
            with_nonce(json_response(200, directory_document()), "nonce-0"),
        );
        transport.expect(
            HttpMethod::Post,
            NEW_ORDER_URL,
            with_nonce(
                with_location(json_response(201, order_document("pending")), ORDER_URL),
                "nonce-2",
            ),
        );
        transport.expect(
            HttpMethod::Post,
            AUTHZ_URL,
            with_nonce(
                json_response(200, authorization_document("pending", &["http-01"])),
                "nonce-3",
            ),
        );
        script_finalization(&transport, "http-01");

        use crate::acme::csr::CsrSigner as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        // Token-held keys have no PEM form, so issuance fails closed at storage after the CSR was
        // signed and finalised; the error must be the storage refusal, not an ignored result.
        let first = issuer
            .obtain(&issuance_request())
            .await
            .expect_err("token-held keys are never written as PKCS#8 PEM");
        assert!(
            first
                .to_string()
                .contains("token-held keys are never written as PKCS#8 PEM"),
            "{first}"
        );
        let session = issuer
            .certificate_key_source()
            .token_key()
            .expect("token key")
            .key()
            .clone();
        let renewal = issuer
            .obtain(&issuance_request())
            .await
            .expect_err("token-held keys are never written as PKCS#8 PEM");
        assert!(
            renewal
                .to_string()
                .contains("token-held keys are never written as PKCS#8 PEM"),
            "{renewal}"
        );
        let renewed = issuer
            .certificate_key_source()
            .token_key()
            .expect("token key")
            .key()
            .clone();
        assert_eq!(session, renewed, "renewal must reuse the token key");
        assert_eq!(signer.session(), "session-7");
        assert_eq!(
            signer.calls(),
            2,
            "initial issuance and renewal both sign through the same token session"
        );

        // Both CSRs verify against the stub token key's public key, and the renewal CSR is for the
        // same key: no fresh process-held key was generated for the second issuance.
        let csrs: Vec<Vec<u8>> = transport
            .requests()
            .into_iter()
            .filter(|request| request.url == FINALIZE_URL)
            .map(|request| {
                let jws: Value = serde_json::from_slice(&request.body).expect("JWS body");
                let encoded = jws["payload"].as_str().expect("JWS payload");
                let payload: Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD.decode(encoded).expect("base64url payload"),
                )
                .expect("finalize JSON payload");
                URL_SAFE_NO_PAD
                    .decode(payload["csr"].as_str().expect("csr field"))
                    .expect("base64url CSR")
            })
            .collect();
        assert_eq!(
            csrs.len(),
            2,
            "initial issuance and renewal each finalise one CSR"
        );
        for csr in &csrs {
            let parsed = crate::acme::csr::parse_csr(csr).expect("CSR self-signature verifies");
            assert_eq!(
                parsed.spki_der,
                signer.spki(),
                "the CSR must be signed for the token stub public key"
            );
        }
        assert!(
            certificate_storage
                .load(STORAGE_KEY)
                .await
                .unwrap()
                .is_none(),
            "no process-held key or certificate record may be persisted for a token-held key"
        );
    }
}
