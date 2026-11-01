//! ACME challenge solvers: HTTP-01, DNS-01 and the TLS-ALPN-01 placeholder.
//!
//! RFC 8555 requires the ACME client to prove control of each identifier in an order. The issuer
//! (see [`crate::issuer::AcmeIssuer`]) selects a challenge per authorization, asks a
//! [`ChallengeSolver`] to install the evidence, acknowledges the challenge with the CA, and
//! finally withdraws the evidence — including when validation or finalization fails.
//!
//! * [`Http01Solver`] publishes the key authorization in an [`Http01TokenStore`]; the HTTP server
//!   (or a middleware in front of it) can answer `GET /.well-known/acme-challenge/<token>` from
//!   [`Http01TokenStore::response_for_path`].
//! * [`Dns01Solver`] creates `_acme-challenge.<domain>` TXT records through the crate's
//!   [`DnsProvider`] abstraction, waits for propagation via
//!   [`DnsProvider::wait_for_propagation`], and deletes the record on withdrawal (or immediately
//!   if propagation fails).
//! * [`TlsAlpn01Solver`] is a tracked stub: TLS-ALPN-01 needs a live TLS listener carrying a
//!   self-signed certificate with the `acme-tls/1` ALPN protocol, which is the end-to-end TLS
//!   serving work (T-TLS-043). Selecting it returns a located [`Error::NotImplemented`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::digest;

use crate::acme::{Challenge, ChallengeType};
use crate::dns::{DnsError, DnsProvider, TxtRecord};
use crate::{Error, Result};

/// Path prefix the ACME HTTP-01 challenge is served under (RFC 8555 §8.3).
pub const HTTP01_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// Label prefix for the DNS-01 challenge TXT record (RFC 8555 §8.4).
pub const DNS01_RECORD_PREFIX: &str = "_acme-challenge.";

/// Solver evidence for one in-progress challenge, passed back to the solver for withdrawal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeHandle {
    /// An HTTP-01 key authorization registered in the token store.
    Http01 {
        /// Challenge token (the path component below [`HTTP01_PATH_PREFIX`]).
        token: String,
    },
    /// A DNS-01 TXT record created at the provider.
    Dns01 {
        /// The record that was created.
        record: TxtRecord,
    },
    /// TLS-ALPN-01 evidence (not implemented yet).
    TlsAlpn01,
}

/// Installs and removes the evidence for one ACME challenge type.
#[async_trait]
pub trait ChallengeSolver: Send + Sync {
    /// The challenge type this solver handles.
    fn challenge_type(&self) -> ChallengeType;

    /// Present the challenge evidence for `domain`.
    ///
    /// `key_authorization` is `token || '.' || account-key-thumbprint` (RFC 8555 §8.1); DNS-01
    /// solvers derive the TXT value from it with [`dns01_txt_value`].
    async fn present(
        &self,
        domain: &str,
        challenge: &Challenge,
        key_authorization: &str,
    ) -> Result<ChallengeHandle>;

    /// Remove the evidence installed by [`ChallengeSolver::present`].
    ///
    /// Implementations must be idempotent where the backend allows it: withdrawal is also called
    /// when issuance fails, possibly after the evidence was already removed.
    async fn withdraw(&self, handle: &ChallengeHandle) -> Result<()>;
}

/// Compute the ACME key authorization for an account key thumbprint (RFC 8555 §8.1).
pub fn key_authorization(token: &str, account_key_thumbprint: &str) -> String {
    format!("{token}.{account_key_thumbprint}")
}

/// The DNS-01 TXT record value for a key authorization (RFC 8555 §8.4):
/// `base64url(SHA-256(keyAuthorization))` without padding.
pub fn dns01_txt_value(key_authorization: &str) -> String {
    let digest = digest::digest(&digest::SHA256, key_authorization.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// The TXT record name for `domain` (wildcard names use the base domain).
pub fn dns01_record_name(domain: &str) -> String {
    let domain = domain.trim().trim_end_matches('.');
    let domain = domain.strip_prefix("*.").unwrap_or(domain);
    format!("{DNS01_RECORD_PREFIX}{domain}")
}

/// One HTTP-01 token registered for validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http01Token {
    /// Challenge token.
    pub token: String,
    /// Key authorization to return for the token.
    pub key_authorization: String,
    /// Domain/identifier being validated.
    pub domain: String,
}

/// In-memory store of HTTP-01 key authorizations.
///
/// The ACME HTTP-01 validation request arrives as
/// `GET http://<domain>/.well-known/acme-challenge/<token>`; the HTTP server can use
/// [`Http01TokenStore::response_for_path`] to return the matching key authorization.
#[derive(Debug, Default)]
pub struct Http01TokenStore {
    tokens: RwLock<BTreeMap<String, Http01Token>>,
}

impl Http01TokenStore {
    /// An empty token store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `key_authorization` for `token` (replacing an existing entry).
    pub fn insert(&self, token: &str, key_authorization: &str, domain: &str) -> Result<()> {
        validate_http01_token(token)?;
        self.tokens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                token.to_string(),
                Http01Token {
                    token: token.to_string(),
                    key_authorization: key_authorization.to_string(),
                    domain: domain.to_string(),
                },
            );
        Ok(())
    }

    /// The key authorization registered for `token`.
    pub fn key_authorization(&self, token: &str) -> Option<String> {
        self.token(token).map(|token| token.key_authorization)
    }

    /// The full token entry registered for `token`.
    pub fn token(&self, token: &str) -> Option<Http01Token> {
        self.tokens
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(token)
            .cloned()
    }

    /// Remove (and return) the entry for `token`.
    pub fn remove(&self, token: &str) -> Option<Http01Token> {
        self.tokens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(token)
    }

    /// Resolve an HTTP request path to a key authorization.
    ///
    /// Only paths below [`HTTP01_PATH_PREFIX`] with a valid token are answered.
    pub fn response_for_path(&self, request_path: &str) -> Option<String> {
        let token = request_path.strip_prefix(HTTP01_PATH_PREFIX)?;
        let token = token.split(['?', '#']).next()?;
        self.key_authorization(token)
    }

    /// Number of registered tokens.
    pub fn len(&self) -> usize {
        self.tokens
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether no token is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn validate_http01_token(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(Error::Issuer(
            "ACME HTTP-01 challenge token is empty".to_string(),
        ));
    }
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::Issuer(format!(
            "ACME HTTP-01 challenge token `{token}` contains characters outside the base64url \
             alphabet"
        )));
    }
    Ok(())
}

/// HTTP-01 solver: registers key authorizations in an [`Http01TokenStore`].
#[derive(Debug, Clone, Default)]
pub struct Http01Solver {
    tokens: Arc<Http01TokenStore>,
}

impl Http01Solver {
    /// Create a solver writing to `tokens`.
    pub fn new(tokens: Arc<Http01TokenStore>) -> Self {
        Self { tokens }
    }

    /// The token store this solver populates.
    pub fn token_store(&self) -> &Arc<Http01TokenStore> {
        &self.tokens
    }
}

#[async_trait]
impl ChallengeSolver for Http01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::Http01
    }

    async fn present(
        &self,
        domain: &str,
        challenge: &Challenge,
        key_authorization: &str,
    ) -> Result<ChallengeHandle> {
        if challenge.kind() != Some(ChallengeType::Http01) {
            return Err(Error::Issuer(format!(
                "HTTP-01 solver received a `{}` challenge",
                challenge.challenge_type
            )));
        }
        self.tokens
            .insert(&challenge.token, key_authorization, domain)?;
        Ok(ChallengeHandle::Http01 {
            token: challenge.token.clone(),
        })
    }

    async fn withdraw(&self, handle: &ChallengeHandle) -> Result<()> {
        match handle {
            ChallengeHandle::Http01 { token } => {
                self.tokens.remove(token);
                Ok(())
            }
            other => Err(Error::Issuer(format!(
                "HTTP-01 solver cannot withdraw {other:?}"
            ))),
        }
    }
}

/// DNS-01 solver: creates TXT records through a [`DnsProvider`] and waits for propagation.
pub struct Dns01Solver {
    provider: Arc<dyn DnsProvider>,
    propagation_timeout: Duration,
    propagation_delay: Duration,
}

impl Dns01Solver {
    /// Create a solver using Caddy's default propagation timeout (2 minutes) and no delay.
    pub fn new(provider: Arc<dyn DnsProvider>) -> Self {
        Self {
            provider,
            propagation_timeout: crate::dns::DEFAULT_PROPAGATION_TIMEOUT,
            propagation_delay: Duration::ZERO,
        }
    }

    /// Set the propagation wait: delay before the first check and overall timeout.
    pub fn with_propagation(mut self, timeout: Duration, delay: Duration) -> Self {
        self.propagation_timeout = timeout;
        self.propagation_delay = delay;
        self
    }

    /// The DNS provider this solver writes through.
    pub fn provider(&self) -> &Arc<dyn DnsProvider> {
        &self.provider
    }

    /// Propagation timeout.
    pub fn propagation_timeout(&self) -> Duration {
        self.propagation_timeout
    }
}

impl fmt::Debug for Dns01Solver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Dns01Solver")
            .field("provider", &self.provider.name())
            .field("propagation_timeout", &self.propagation_timeout)
            .field("propagation_delay", &self.propagation_delay)
            .finish()
    }
}

#[async_trait]
impl ChallengeSolver for Dns01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::Dns01
    }

    async fn present(
        &self,
        domain: &str,
        challenge: &Challenge,
        key_authorization: &str,
    ) -> Result<ChallengeHandle> {
        if challenge.kind() != Some(ChallengeType::Dns01) {
            return Err(Error::Issuer(format!(
                "DNS-01 solver received a `{}` challenge",
                challenge.challenge_type
            )));
        }
        let fqdn = dns01_record_name(domain);
        let value = dns01_txt_value(key_authorization);
        let record = self.provider.create_txt(&fqdn, &value).await?;
        if !self.propagation_delay.is_zero() {
            tokio::time::sleep(self.propagation_delay).await;
        }
        if let Err(error) = self
            .provider
            .wait_for_propagation(&record, self.propagation_timeout)
            .await
        {
            // Do not leave a stale challenge record behind when propagation fails.
            let _ = self.provider.delete_txt(&record).await;
            return Err(error.into());
        }
        Ok(ChallengeHandle::Dns01 { record })
    }

    async fn withdraw(&self, handle: &ChallengeHandle) -> Result<()> {
        let ChallengeHandle::Dns01 { record } = handle else {
            return Err(Error::Issuer(format!(
                "DNS-01 solver cannot withdraw {handle:?}"
            )));
        };
        match self.provider.delete_txt(record).await {
            Ok(()) => Ok(()),
            // Another solver/cleanup may already have removed it; cleanup is idempotent.
            Err(DnsError::RecordNotFound { .. }) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// TLS-ALPN-01 solver placeholder.
///
/// TLS-ALPN-01 requires a live TLS listener presenting a self-signed certificate with the
/// `acme-tls/1` ALPN protocol; that belongs to the end-to-end TLS serving work (T-TLS-043). The
/// stub keeps challenge selection honest: choosing it fails with a tracked
/// [`Error::NotImplemented`] instead of silently hanging validation.
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsAlpn01Solver;

#[async_trait]
impl ChallengeSolver for TlsAlpn01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::TlsAlpn01
    }

    async fn present(
        &self,
        _domain: &str,
        _challenge: &Challenge,
        _key_authorization: &str,
    ) -> Result<ChallengeHandle> {
        Err(Error::NotImplemented {
            feature: "TLS-ALPN-01 challenge solver (live TLS listener with acme-tls/1 ALPN)",
            tracking_id: "T-TLS-043",
        })
    }

    async fn withdraw(&self, _handle: &ChallengeHandle) -> Result<()> {
        Ok(())
    }
}

/// Solvers available to an issuer, keyed by challenge type.
#[derive(Default)]
pub struct SolverRegistry {
    solvers: Vec<(ChallengeType, Arc<dyn ChallengeSolver>)>,
}

impl SolverRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `solver`, replacing any previous solver for the same challenge type.
    pub fn insert(&mut self, solver: Arc<dyn ChallengeSolver>) {
        let challenge_type = solver.challenge_type();
        self.solvers
            .retain(|(existing, _)| *existing != challenge_type);
        self.solvers.push((challenge_type, solver));
    }

    /// The solver for `challenge_type`, when registered.
    pub fn get(&self, challenge_type: ChallengeType) -> Option<Arc<dyn ChallengeSolver>> {
        self.solvers
            .iter()
            .find(|(existing, _)| *existing == challenge_type)
            .map(|(_, solver)| Arc::clone(solver))
    }

    /// Whether a solver for `challenge_type` is registered.
    pub fn contains(&self, challenge_type: ChallengeType) -> bool {
        self.solvers
            .iter()
            .any(|(existing, _)| *existing == challenge_type)
    }

    /// Registered challenge types.
    pub fn types(&self) -> Vec<ChallengeType> {
        self.solvers.iter().map(|(kind, _)| *kind).collect()
    }

    /// Number of registered solvers.
    pub fn len(&self) -> usize {
        self.solvers.len()
    }

    /// Whether no solver is registered.
    pub fn is_empty(&self) -> bool {
        self.solvers.is_empty()
    }
}

impl fmt::Debug for SolverRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SolverRegistry")
            .field("challenge_types", &self.types())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::ChallengeStatus;
    use crate::dns::InMemoryDnsProvider;

    fn challenge(kind: &str, token: &str) -> Challenge {
        Challenge {
            challenge_type: kind.to_string(),
            url: format!("https://acme.test/challenge/{token}"),
            status: ChallengeStatus::Pending,
            token: token.to_string(),
            validated: None,
            error: None,
        }
    }

    fn dns_provider() -> Arc<InMemoryDnsProvider> {
        Arc::new(InMemoryDnsProvider::with_zones(["example.com"]))
    }

    #[test]
    fn key_authorization_is_token_dot_thumbprint() {
        assert_eq!(
            key_authorization("token-1", "thumbprint-abc"),
            "token-1.thumbprint-abc"
        );
    }

    #[test]
    fn dns01_txt_value_matches_rfc8555_hash() {
        // base64url(SHA-256("token-1.thumbprint-abc")) without padding.
        assert_eq!(
            dns01_txt_value("token-1.thumbprint-abc"),
            "kKuZWTYXWpZUmgitV9JFjLiWmtPMmACIpvVHLdLQDsY"
        );
        assert_eq!(
            dns01_txt_value("token.thumbprint"),
            "61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I"
        );
    }

    #[test]
    fn dns01_record_names_use_wildcard_base_domain() {
        assert_eq!(
            dns01_record_name("example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            dns01_record_name("*.example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            dns01_record_name("api.example.com."),
            "_acme-challenge.api.example.com"
        );
    }

    #[test]
    fn http01_token_store_serves_key_authorization() {
        let store = Http01TokenStore::new();
        store
            .insert("token-1", "token-1.thumbprint", "example.com")
            .unwrap();
        assert_eq!(
            store.key_authorization("token-1").as_deref(),
            Some("token-1.thumbprint")
        );
        assert_eq!(
            store
                .response_for_path("/.well-known/acme-challenge/token-1")
                .as_deref(),
            Some("token-1.thumbprint")
        );
        assert_eq!(
            store.response_for_path("/.well-known/acme-challenge/token-1?x=1"),
            Some("token-1.thumbprint".to_string())
        );
        assert_eq!(
            store.response_for_path("/.well-known/acme-challenge/unknown"),
            None
        );
        assert_eq!(store.response_for_path("/other/token-1"), None);
        assert_eq!(
            store.remove("token-1").map(|token| token.domain),
            Some("example.com".to_string())
        );
        assert!(store.is_empty());
    }

    #[test]
    fn http01_token_store_rejects_invalid_tokens() {
        let store = Http01TokenStore::new();
        for token in ["", "has/slash", "has space", "not+base64"] {
            assert!(
                store
                    .insert(token, "key-authorization", "example.com")
                    .is_err(),
                "token `{token}` should be rejected"
            );
        }
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn http01_solver_presents_and_withdraws() {
        let tokens = Arc::new(Http01TokenStore::new());
        let solver = Http01Solver::new(Arc::clone(&tokens));
        let handle = solver
            .present(
                "example.com",
                &challenge("http-01", "token-1"),
                "token-1.thumbprint",
            )
            .await
            .unwrap();
        assert_eq!(
            handle,
            ChallengeHandle::Http01 {
                token: "token-1".to_string()
            }
        );
        assert_eq!(
            tokens.key_authorization("token-1").as_deref(),
            Some("token-1.thumbprint")
        );
        solver.withdraw(&handle).await.unwrap();
        assert!(tokens.is_empty());
        // Withdrawal is idempotent.
        solver.withdraw(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn dns01_solver_creates_waits_and_withdraws() {
        let provider = dns_provider();
        let solver = Dns01Solver::new(provider.clone() as Arc<dyn DnsProvider>);
        let handle = solver
            .present(
                "example.com",
                &challenge("dns-01", "token-1"),
                "token-1.thumbprint-abc",
            )
            .await
            .unwrap();
        let record = match &handle {
            ChallengeHandle::Dns01 { record } => record.clone(),
            other => panic!("unexpected handle {other:?}"),
        };
        assert_eq!(record.fqdn, "_acme-challenge.example.com");
        assert_eq!(record.value, dns01_txt_value("token-1.thumbprint-abc"));
        assert_eq!(provider.records(), vec![record]);
        solver.withdraw(&handle).await.unwrap();
        assert!(provider.records().is_empty());
    }

    #[tokio::test]
    async fn dns01_solver_cleans_up_when_propagation_times_out() {
        let provider = dns_provider();
        provider.set_visible(false);
        let solver = Dns01Solver::new(provider.clone() as Arc<dyn DnsProvider>)
            .with_propagation(Duration::from_millis(50), Duration::ZERO);
        let error = solver
            .present(
                "example.com",
                &challenge("dns-01", "token-1"),
                "token-1.thumbprint-abc",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Dns(DnsError::PropagationTimeout { .. })
        ));
        assert!(
            provider.records().is_empty(),
            "failed propagation must remove the TXT record"
        );
    }

    #[tokio::test]
    async fn dns01_solver_withdraw_tolerates_missing_record() {
        let provider = dns_provider();
        let solver = Dns01Solver::new(provider.clone() as Arc<dyn DnsProvider>);
        let handle = solver
            .present(
                "example.com",
                &challenge("dns-01", "token-1"),
                "token-1.thumbprint-abc",
            )
            .await
            .unwrap();
        let record = match &handle {
            ChallengeHandle::Dns01 { record } => record.clone(),
            other => panic!("unexpected handle {other:?}"),
        };
        provider.delete_txt(&record).await.unwrap();
        solver.withdraw(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn tls_alpn_solver_is_a_tracked_stub() {
        let solver = TlsAlpn01Solver;
        assert_eq!(solver.challenge_type(), ChallengeType::TlsAlpn01);
        let error = solver
            .present(
                "example.com",
                &challenge("tls-alpn-01", "token-1"),
                "token-1.thumbprint",
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                Error::NotImplemented { tracking_id, .. } if *tracking_id == "T-TLS-043"
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn solver_registry_replaces_solvers_of_the_same_type() {
        let mut registry = SolverRegistry::new();
        assert!(registry.is_empty());
        let tokens = Arc::new(Http01TokenStore::new());
        registry.insert(Arc::new(Http01Solver::new(Arc::clone(&tokens))));
        registry.insert(Arc::new(TlsAlpn01Solver));
        registry.insert(Arc::new(Http01Solver::new(tokens)));
        assert_eq!(registry.len(), 2);
        assert!(registry.contains(ChallengeType::Http01));
        assert!(registry.contains(ChallengeType::TlsAlpn01));
        assert!(!registry.contains(ChallengeType::Dns01));
        assert!(registry.get(ChallengeType::Dns01).is_none());
    }
}
