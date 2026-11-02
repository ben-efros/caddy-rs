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
//! * DNS-01 uses the [`DnsProvider`] attached by the caller; provider settings from
//!   `challenges.dns.provider` are parsed but the module registry (provider construction) is not
//!   wired here.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::acme::{
    AccountRegistration, AcmeAccountClient, AcmeClient, AcmeClock, AcmeStorage, AcmeTransport,
    AuthorizationStatus, CertificateRequest, ChallengePolicy, ChallengeType, HyperTransport,
    IssuedCertificate, NewOrderRequest, OrderStatus, PollPolicy, TokioClock,
};
use crate::certificate::Certificate;
use crate::dns::DnsProvider;
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
}

/// Certificate issuer.
#[async_trait]
pub trait CertificateIssuer: Send + Sync {
    /// Module name (`acme`, `internal`).
    fn name(&self) -> &'static str;

    /// Obtain a new certificate.
    async fn obtain(&self, request: &IssuanceRequest) -> Result<Certificate>;

    /// Renew an existing certificate.
    async fn renew(&self, certificate: &Certificate) -> Result<Certificate> {
        self.obtain(&IssuanceRequest {
            domains: certificate.domains.clone(),
            internal: certificate.issuer == "internal",
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
    /// Preferred certificate chains.
    pub preferred_chains: Vec<String>,
    /// DNS challenge provider module name, if any.
    pub dns_provider: Option<String>,
    /// Whether Caddy's `challenges.http.disabled` is set.
    pub http_challenge_disabled: bool,
    /// Whether Caddy's `challenges.tls-alpn.disabled` is set.
    pub tls_alpn_challenge_disabled: bool,
    /// Renewal window override.
    pub renewal_window: Option<Duration>,
}

impl Default for AcmeIssuerConfig {
    fn default() -> Self {
        Self {
            ca: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            test_ca: None,
            email: None,
            account_key_pem: None,
            external_account: None,
            preferred_chains: Vec::new(),
            dns_provider: None,
            http_challenge_disabled: false,
            tls_alpn_challenge_disabled: false,
            renewal_window: None,
        }
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
            if let Some(dns) = challenges.get("dns") {
                // Caddy serialises the provider as an inline module object
                // ({"name":"cloudflare", "api_token": ...}); older configurations use a string.
                config.dns_provider = dns
                    .get("provider")
                    .and_then(|provider| {
                        provider
                            .as_str()
                            .or_else(|| provider.get("name").and_then(serde_json::Value::as_str))
                    })
                    .map(str::to_string);
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
        Ok(config)
    }
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
        let mut policy = ChallengePolicy::default()
            .with_preference(vec![ChallengeType::Http01, ChallengeType::TlsAlpn01]);
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
            .run_order(&account_client, &domains, &mut presented)
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
        presented: &mut Vec<(Arc<dyn ChallengeSolver>, ChallengeHandle)>,
    ) -> Result<Certificate> {
        let order_request = NewOrderRequest::for_domains(domains);
        let order = account_client.new_order(&order_request).await?;

        if order.order.status == OrderStatus::Valid {
            // A valid order has no local CSR/private key, so the certificate cannot be stored.
            return Err(Error::Issuer(
                "ACME order is already valid but no local private key exists; start a new order"
                    .to_string(),
            ));
        }

        if order.order.status == OrderStatus::Pending {
            let authorizations = account_client.fetch_authorizations(&order.order).await?;
            let policy = self.challenge_policy();
            let thumbprint = account_client.client().account_key().thumbprint()?;
            for fetched in &authorizations {
                if fetched.authorization.status == AuthorizationStatus::Valid {
                    continue;
                }
                let challenge = policy.select(&fetched.authorization)?;
                let challenge_type = challenge.kind().ok_or_else(|| {
                    Error::Issuer(format!(
                        "ACME authorization offered unsupported challenge type `{}`",
                        challenge.challenge_type
                    ))
                })?;
                let solver = self.solvers.get(challenge_type).ok_or_else(|| {
                    Error::Issuer(format!(
                        "no challenge solver is configured for `{challenge_type}`"
                    ))
                })?;
                let domain = fetched
                    .authorization
                    .identifier
                    .as_ref()
                    .map(|identifier| identifier.value.clone())
                    .ok_or_else(|| {
                        Error::Issuer("ACME authorization is missing its identifier".to_string())
                    })?;
                let key_authorization = key_authorization(&challenge.token, &thumbprint);
                let handle = solver
                    .present(&domain, challenge, &key_authorization)
                    .await?;
                presented.push((solver, handle));
                account_client.acknowledge_challenge(challenge).await?;
            }
            for fetched in &authorizations {
                if fetched.authorization.status != AuthorizationStatus::Valid {
                    account_client
                        .poll_authorization(&fetched.url, &self.poll_policy, self.clock.as_ref())
                        .await?;
                }
            }
        }

        account_client
            .poll_order_ready(&order.url, &self.poll_policy, self.clock.as_ref())
            .await?;
        let csr = CertificateRequest::generate(domains)?;
        account_client.finalize_order(&order, &csr).await?;
        let issued = account_client
            .wait_for_certificate(&order.url, &self.poll_policy, self.clock.as_ref())
            .await?;

        let stored = stored_certificate(&issued, &csr, domains)?;
        self.certificate_storage
            .store(&self.storage_key(domains), &stored)
            .await?;
        self.build_certificate(&issued, &csr, domains)
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
            private_key_der: private_key_der(csr.private_key_pem())?,
            not_before: UNIX_EPOCH + Duration::from_secs(not_before),
            not_after: UNIX_EPOCH + Duration::from_secs(not_after),
            issuer: self.config.ca.clone(),
        })
    }
}

impl AcmeIssuer<HyperTransport> {
    /// Production wiring: use the platform trust store for the ACME transport and Caddy's
    /// data-directory `<root>` for account material and certificate storage.
    pub fn from_config(config: AcmeIssuerConfig, root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let transport = HyperTransport::new()?;
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

    async fn obtain(&self, request: &IssuanceRequest) -> Result<Certificate> {
        self.issue(request).await
    }
}

/// Build the [`StoredCertificate`] record for a downloaded ACME certificate.
fn stored_certificate(
    issued: &IssuedCertificate,
    csr: &CertificateRequest,
    domains: &[String],
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
        private_key_pem: csr.private_key_pem().to_string(),
        domains: domains.to_vec(),
        not_after_unix,
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

/// Internal CA issuer. Wire implementation is tracked by M5.
#[derive(Debug, Clone, Default)]
pub struct InternalIssuer {
    /// CA name.
    pub name: String,
}

#[async_trait]
impl CertificateIssuer for InternalIssuer {
    fn name(&self) -> &'static str {
        "internal"
    }

    async fn obtain(&self, request: &IssuanceRequest) -> Result<Certificate> {
        let _ = request;
        Err(Error::NotImplemented {
            feature: "internal CA certificate issuance",
            tracking_id: "TLS-INTERNAL-CA",
        })
    }
}

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
    async fn internal_issuer_is_a_tracked_not_implemented() {
        let error = InternalIssuer::default()
            .obtain(&issuance_request())
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                Error::NotImplemented { tracking_id, .. }
                    if *tracking_id == "TLS-INTERNAL-CA"
            ),
            "unexpected error: {error:?}"
        );
    }

    // ---- end-to-end HTTP-01 issuance -----------------------------------------------------

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
}
