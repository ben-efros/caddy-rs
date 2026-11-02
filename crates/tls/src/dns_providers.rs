//! Construction of DNS-01 providers and solvers from Caddy configuration.
//!
//! Caddy configures DNS-01 through `apps.tls.automation.policies[].issuers[].challenges.dns`:
//!
//! ```json
//! {
//!   "provider": { "name": "cloudflare", "api_token": "{env.CF_API_TOKEN}" },
//!   "ttl": 120000000000,
//!   "propagation_timeout": 120000000000,
//!   "propagation_delay": 0,
//!   "resolvers": ["1.1.1.1:53"],
//!   "override_domain": "challenges.example.net"
//! }
//! ```
//!
//! [`build_dns_provider`] maps the provider module object to a [`DnsProvider`] implementation
//! (currently `cloudflare`), and [`build_dns01_solver`] pairs it with authoritative propagation
//! checks ([`DohPropagationChecker`], DNS-over-HTTPS). The HTTP transport is injected: production
//! automatic HTTPS passes its hyper/rustls transport, and tests pass a scripted mock, so provider
//! request/response shapes are exercised without network access.
//!
//! Unknown providers and provider options are rejected loudly with tracking id
//! [`DNS_PROVIDER_TRACKING_ID`] instead of being ignored (silently using a different zone/account
//! would be a compatibility and security defect).
//!
//! Deliberate limitations (reported as divergences):
//!
//! * only the `cloudflare` provider module is implemented;
//! * `resolvers` is accepted but not used: propagation is checked via Cloudflare's public DoH
//!   endpoint rather than the configured raw-DNS resolvers;
//! * `override_domain` is applied by the constructed solver (the TXT record is published under
//!   `_acme-challenge.<override_domain>`).

use std::sync::Arc;

use crate::acme::AcmeTransport;
use crate::cloudflare::{CloudflareProvider, CLOUDFLARE_PROVIDER_NAME};
use crate::dns::{
    DnsChallengeConfig, DnsError, DnsProvider, PropagationTimeout,
    DEFAULT_PROPAGATION_POLL_INTERVAL,
};
use crate::propagation::{DohPropagationChecker, PropagationChecker};
use crate::solver::Dns01Solver;
use crate::{Error, Result};

/// Tracking id for DNS provider module construction gaps (plan task T-TLS-063).
pub const DNS_PROVIDER_TRACKING_ID: &str = "T-TLS-063";

/// DNS provider module names this build can construct from configuration.
pub const SUPPORTED_DNS_PROVIDERS: &[&str] = &[CLOUDFLARE_PROVIDER_NAME];

/// Build the [`DnsProvider`] described by Caddy's `challenges.dns` configuration.
///
/// `transport` performs the provider API requests (HTTPS in production; a mock in tests).
pub fn build_dns_provider(
    challenge: &DnsChallengeConfig,
    transport: Arc<dyn AcmeTransport>,
) -> Result<Arc<dyn DnsProvider>> {
    match challenge.provider.as_str() {
        CLOUDFLARE_PROVIDER_NAME => Ok(Arc::new(CloudflareProvider::from_challenge_config(
            transport, challenge,
        )?)),
        other => Err(Error::Dns(DnsError::UnsupportedProvider {
            provider: other.to_string(),
        })),
    }
}

/// Build the full DNS-01 solver described by Caddy's `challenges.dns` configuration.
///
/// The solver creates the TXT record through the configured provider and then waits for
/// authoritative propagation (DNS-over-HTTPS) honoring `propagation_delay`/`propagation_timeout`.
/// `propagation_timeout: -1` disables the wait, matching Caddy. On timeout/error the TXT record is
/// removed before the error is returned.
pub fn build_dns01_solver(
    challenge: &DnsChallengeConfig,
    transport: Arc<dyn AcmeTransport>,
) -> Result<Dns01Solver> {
    let provider = build_dns_provider(challenge, Arc::clone(&transport))?;
    let mut solver = Dns01Solver::new(provider)
        .with_propagation_delay(challenge.propagation_delay.unwrap_or_default());
    if let Some(domain) = &challenge.override_domain {
        solver = solver.with_record_domain_override(domain.clone());
    }
    solver = match challenge.propagation_timeout {
        PropagationTimeout::Disabled => solver.without_propagation_wait(),
        PropagationTimeout::Default => solver.with_checker(
            doh_checker(transport),
            crate::dns::DEFAULT_PROPAGATION_TIMEOUT,
            DEFAULT_PROPAGATION_POLL_INTERVAL,
        ),
        PropagationTimeout::After(timeout) => solver.with_checker(
            doh_checker(transport),
            timeout,
            DEFAULT_PROPAGATION_POLL_INTERVAL,
        ),
    };
    Ok(solver)
}

fn doh_checker(transport: Arc<dyn AcmeTransport>) -> Arc<dyn PropagationChecker> {
    Arc::new(DohPropagationChecker::cloudflare(transport))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::{
        AcmeClock, HttpMethod, HttpRequest, HttpResponse, MemoryAcmeStorage, PollPolicy, TokioClock,
    };
    use crate::dns::{DnsChallengeConfig, DnsError};
    use crate::issuer::{AcmeIssuer, AcmeIssuerConfig, CertificateIssuer, IssuanceRequest};
    use crate::solver::{ChallengeSolver, Http01TokenStore};
    use crate::storage::{CertificateStorage, MemoryStorage};
    use crate::tls_alpn::TlsAlpn01TokenStore;
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use std::sync::Mutex;
    use std::time::Duration;

    const ACME_DIRECTORY: &str = "https://acme.test/directory";
    const CERTIFICATE_PEM: &str = include_str!(
        "../tests/fixtures/caddy-data/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt"
    );

    // ---- mock transport for ACME + Cloudflare API + DoH -----------------------------------

    #[derive(Debug, Clone)]
    struct TxtRecord {
        fqdn: String,
        value: String,
    }

    #[derive(Debug, Default)]
    struct MockState {
        requests: Vec<HttpRequest>,
        records: Vec<TxtRecord>,
        next_id: u64,
        acked: bool,
        finalized: bool,
        deletes: usize,
        doh_queries: usize,
        doh_visible: bool,
    }

    #[derive(Clone, Default)]
    struct DnsMock {
        state: Arc<Mutex<MockState>>,
    }

    impl DnsMock {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(MockState {
                    doh_visible: true,
                    ..MockState::default()
                })),
            }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, MockState> {
            self.state.lock().unwrap()
        }
    }

    fn nonce(response: HttpResponse) -> HttpResponse {
        response.with_header("Replay-Nonce", "nonce")
    }

    fn json_response(status: u16, body: Value) -> HttpResponse {
        nonce(HttpResponse::with_json(status, &body).unwrap())
    }

    fn query_param(url: &str, name: &str) -> Option<String> {
        let query = url.split_once('?')?.1;
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.to_string())
        })
    }

    #[async_trait]
    impl AcmeTransport for DnsMock {
        async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.state().requests.push(request.clone());
            let url = request.url.clone();
            let method = request.method;

            // ---- Cloudflare v4 API ----------------------------------------------------
            if url.starts_with("https://api.cloudflare.com/client/v4/zones?") {
                let name = query_param(&url, "name").unwrap_or_default();
                return Ok(json_response(
                    200,
                    json!({"success": true, "errors": [], "result": [{"id": "zone-1", "name": name}]}),
                ));
            }
            if url.contains("/dns_records") && method == HttpMethod::Post {
                let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
                let fqdn = body["name"].as_str().unwrap_or_default().to_string();
                let value = body["content"].as_str().unwrap_or_default().to_string();
                let mut state = self.state();
                state.next_id += 1;
                let id = format!("rec-{}", state.next_id);
                state.records.push(TxtRecord {
                    fqdn: fqdn.clone(),
                    value: value.clone(),
                });
                return Ok(json_response(
                    200,
                    json!({"success": true, "errors": [], "result": {"id": id, "name": fqdn, "content": value, "type": "TXT"}}),
                ));
            }
            if url.contains("/dns_records/") && method == HttpMethod::Delete {
                let mut state = self.state();
                state.deletes += 1;
                state.records.clear();
                return Ok(json_response(
                    200,
                    json!({"success": true, "errors": [], "result": {"id": "deleted"}}),
                ));
            }

            // ---- DNS-over-HTTPS -------------------------------------------------------
            if url.starts_with("https://cloudflare-dns.com/dns-query") {
                let name = query_param(&url, "name").unwrap_or_default();
                let mut state = self.state();
                state.doh_queries += 1;
                let answers: Vec<Value> = if state.doh_visible {
                    state
                        .records
                        .iter()
                        .filter(|record| record.fqdn == name)
                        .map(|record| {
                            json!({"name": record.fqdn, "type": 16, "TTL": 5,
                                   "data": format!("\"{}\"", record.value)})
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                return Ok(nonce(
                    HttpResponse::with_json(200, &json!({"Status": 0, "Answer": answers})).unwrap(),
                ));
            }

            // ---- ACME server ----------------------------------------------------------
            if method == HttpMethod::Get && url.ends_with("/directory") {
                return Ok(json_response(
                    200,
                    json!({
                        "newNonce": "https://acme.test/new-nonce",
                        "newAccount": "https://acme.test/new-account",
                        "newOrder": "https://acme.test/new-order",
                        "revokeCert": "https://acme.test/revoke"
                    }),
                ));
            }
            if url.ends_with("/new-account") {
                return Ok(json_response(
                    201,
                    json!({"status": "valid", "contact": ["mailto:ops@example.com"]}),
                )
                .with_header("Location", "https://acme.test/account/1"));
            }
            if url.ends_with("/new-order") {
                return Ok(json_response(
                    201,
                    json!({
                        "status": "pending",
                        "identifiers": [{"type": "dns", "value": "example.com"}],
                        "authorizations": ["https://acme.test/authz/1"],
                        "finalize": "https://acme.test/finalize/1"
                    }),
                )
                .with_header("Location", "https://acme.test/order/1"));
            }
            if url.ends_with("/authz/1") {
                let acked = self.state().acked;
                return Ok(json_response(
                    200,
                    if acked {
                        json!({"status": "valid", "identifier": {"type": "dns", "value": "example.com"}, "challenges": []})
                    } else {
                        json!({
                            "status": "pending",
                            "identifier": {"type": "dns", "value": "example.com"},
                            "challenges": [{"type": "dns-01", "url": "https://acme.test/challenge/1",
                                            "token": "token-1", "status": "pending"}]
                        })
                    },
                ));
            }
            if url.ends_with("/challenge/1") {
                self.state().acked = true;
                return Ok(json_response(
                    200,
                    json!({"type": "dns-01", "url": "https://acme.test/challenge/1",
                           "token": "token-1", "status": "processing"}),
                ));
            }
            if url.ends_with("/finalize/1") {
                self.state().finalized = true;
                return Ok(json_response(200, json!({"status": "processing"})));
            }
            if url.ends_with("/order/1") {
                let finalized = self.state().finalized;
                return Ok(json_response(
                    200,
                    if finalized {
                        json!({"status": "valid", "certificate": "https://acme.test/cert/1",
                               "authorizations": ["https://acme.test/authz/1"],
                               "finalize": "https://acme.test/finalize/1"})
                    } else {
                        json!({"status": "ready",
                               "authorizations": ["https://acme.test/authz/1"],
                               "finalize": "https://acme.test/finalize/1"})
                    },
                ));
            }
            if url.ends_with("/cert/1") {
                return Ok(nonce(
                    HttpResponse::new(200)
                        .with_header("Content-Type", "application/pem-certificate-chain")
                        .with_body(CERTIFICATE_PEM),
                ));
            }
            Err(Error::Issuer(format!(
                "unexpected mock DNS/ACME request {method} {url}"
            )))
        }
    }

    fn challenge_config(value: Value) -> DnsChallengeConfig {
        DnsChallengeConfig::from_caddy_json(&value).unwrap()
    }

    // ---- provider/solver construction ----------------------------------------------------

    #[tokio::test]
    async fn builds_cloudflare_provider_from_configuration() {
        let challenge = challenge_config(json!({
            "provider": {"name": "cloudflare", "api_token": "secret-token"},
            "ttl": 120_000_000_000_i64
        }));
        let transport = Arc::new(DnsMock::new());
        let shared: Arc<dyn AcmeTransport> = transport.clone();
        let provider = build_dns_provider(&challenge, shared).unwrap();
        assert_eq!(provider.name(), "cloudflare");
        assert_eq!(
            provider
                .find_zone("_acme-challenge.example.com")
                .await
                .unwrap(),
            "example.com"
        );
        let state = transport.state();
        let zone_request = state
            .requests
            .iter()
            .find(|request| request.url.contains("/zones?"))
            .expect("zone lookup request");
        assert_eq!(
            zone_request.header("Authorization"),
            Some("Bearer secret-token")
        );
        assert!(zone_request.url.contains("name=example.com"));
    }

    #[tokio::test]
    async fn unknown_provider_is_tracked_unsupported() {
        let challenge = challenge_config(json!({"provider": {"name": "route53"}}));
        let transport: Arc<dyn AcmeTransport> = Arc::new(DnsMock::new());
        let error = match build_dns_provider(&challenge, transport) {
            Ok(_) => panic!("unknown provider must be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("route53"), "{message}");
        assert!(
            message.contains("not implemented by this build"),
            "{message}"
        );
        assert!(message.contains(DNS_PROVIDER_TRACKING_ID), "{message}");
        assert!(
            matches!(&error, Error::Dns(DnsError::UnsupportedProvider { .. })),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn unknown_provider_option_is_tracked_unsupported() {
        let challenge = challenge_config(json!({
            "provider": {"name": "cloudflare", "api_token": "token", "zone_id": "zone-1"}
        }));
        let transport: Arc<dyn AcmeTransport> = Arc::new(DnsMock::new());
        let error = match build_dns_provider(&challenge, transport) {
            Ok(_) => panic!("unknown provider must be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("zone_id"), "{message}");
        assert!(message.contains("T-TLS-063"), "{message}");
        assert!(
            matches!(&error, Error::Dns(DnsError::UnsupportedOption { .. })),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn solver_honours_configured_propagation_timeout() {
        let transport: Arc<dyn AcmeTransport> = Arc::new(DnsMock::new());
        let disabled = build_dns01_solver(
            &challenge_config(json!({
                "provider": {"name": "cloudflare", "api_token": "token"},
                "propagation_timeout": -1
            })),
            Arc::clone(&transport),
        )
        .unwrap();
        assert_eq!(disabled.propagation_timeout(), Duration::ZERO);

        let five_seconds = build_dns01_solver(
            &challenge_config(json!({
                "provider": {"name": "cloudflare", "api_token": "token"},
                "propagation_timeout": 5_000_000_000_i64
            })),
            Arc::clone(&transport),
        )
        .unwrap();
        assert_eq!(five_seconds.propagation_timeout(), Duration::from_secs(5));

        let default = build_dns01_solver(
            &challenge_config(json!({
                "provider": {"name": "cloudflare", "api_token": "token"}
            })),
            transport,
        )
        .unwrap();
        assert_eq!(
            default.propagation_timeout(),
            crate::dns::DEFAULT_PROPAGATION_TIMEOUT
        );
    }

    // ---- solver behaviour against the mock DNS stack -------------------------------------

    fn dns_challenge() -> crate::acme::Challenge {
        crate::acme::Challenge {
            challenge_type: "dns-01".to_string(),
            url: "https://acme.test/challenge/1".to_string(),
            status: crate::acme::ChallengeStatus::Pending,
            token: "token-1".to_string(),
            validated: None,
            error: None,
        }
    }

    #[tokio::test]
    async fn propagation_via_doh_succeeds_and_withdraws_record() {
        let transport = Arc::new(DnsMock::new());
        let shared: Arc<dyn AcmeTransport> = transport.clone();
        let solver = build_dns01_solver(
            &challenge_config(json!({
                "provider": {"name": "cloudflare", "api_token": "token"},
                "propagation_timeout": 5_000_000_000_i64
            })),
            shared,
        )
        .unwrap();
        let handle = solver
            .present(
                "example.com",
                &dns_challenge(),
                "token-1.account-thumbprint",
            )
            .await
            .expect("DNS-01 presentation should wait for and observe DoH propagation");
        {
            let state = transport.state();
            assert_eq!(state.records.len(), 1);
            assert_eq!(state.records[0].fqdn, "_acme-challenge.example.com");
            assert!(
                state.doh_queries >= 1,
                "propagation must be checked via DoH"
            );
        }
        solver.withdraw(&handle).await.unwrap();
        let state = transport.state();
        assert!(state.records.is_empty());
        assert_eq!(state.deletes, 1);
    }

    #[tokio::test]
    async fn propagation_timeout_cleans_up_provider_record() {
        let transport = Arc::new(DnsMock::new());
        transport.state().doh_visible = false;
        let shared: Arc<dyn AcmeTransport> = transport.clone();
        let solver = build_dns01_solver(
            &challenge_config(json!({
                "provider": {"name": "cloudflare", "api_token": "token"},
                "propagation_timeout": 50_000_000_i64
            })),
            shared,
        )
        .unwrap();
        let error = solver
            .present(
                "example.com",
                &dns_challenge(),
                "token-1.account-thumbprint",
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error}");
        let state = transport.state();
        assert!(
            state.records.is_empty(),
            "timed-out propagation must delete the TXT record"
        );
        assert!(state.doh_queries >= 1);
    }

    #[tokio::test]
    async fn override_domain_changes_the_txt_record_name() {
        let transport = Arc::new(DnsMock::new());
        let shared: Arc<dyn AcmeTransport> = transport.clone();
        let solver = build_dns01_solver(
            &challenge_config(json!({
                "provider": {"name": "cloudflare", "api_token": "token"},
                "propagation_timeout": 5_000_000_000_i64,
                "override_domain": "challenges.example.net"
            })),
            shared,
        )
        .unwrap();
        let handle = solver
            .present(
                "example.com",
                &dns_challenge(),
                "token-1.account-thumbprint",
            )
            .await
            .unwrap();
        assert_eq!(
            transport.state().records[0].fqdn,
            "_acme-challenge.challenges.example.net"
        );
        solver.withdraw(&handle).await.unwrap();
    }

    #[tokio::test]
    async fn propagation_disabled_skips_doh_queries() {
        let transport = Arc::new(DnsMock::new());
        let shared: Arc<dyn AcmeTransport> = transport.clone();
        let solver = build_dns01_solver(
            &challenge_config(json!({
                "provider": {"name": "cloudflare", "api_token": "token"},
                "propagation_timeout": -1
            })),
            shared,
        )
        .unwrap();
        let handle = solver
            .present(
                "example.com",
                &dns_challenge(),
                "token-1.account-thumbprint",
            )
            .await
            .unwrap();
        assert_eq!(transport.state().doh_queries, 0);
        assert_eq!(transport.state().records.len(), 1);
        solver.withdraw(&handle).await.unwrap();
        assert!(transport.state().records.is_empty());
    }

    // ---- end-to-end issuance with a config-constructed provider --------------------------

    fn dns_issuer_config() -> AcmeIssuerConfig {
        AcmeIssuerConfig::from_json(&json!({
            "module": "acme",
            "ca": ACME_DIRECTORY,
            "email": "ops@example.com",
            "challenges": {
                "dns": {
                    "provider": {"name": "cloudflare", "api_token": "test-token"},
                    "propagation_timeout": 5_000_000_000_i64
                }
            }
        }))
        .unwrap()
    }

    fn issuance_request() -> IssuanceRequest {
        IssuanceRequest {
            domains: vec!["example.com".to_string()],
            internal: false,
        }
    }

    #[tokio::test]
    async fn acme_issuer_uses_config_constructed_dns_solver_end_to_end() {
        let transport = Arc::new(DnsMock::new());
        let shared: Arc<dyn AcmeTransport> = transport.clone();
        let certificate_storage = Arc::new(MemoryStorage::new());
        let issuer = AcmeIssuer::new(
            dns_issuer_config(),
            Arc::clone(&shared),
            Arc::new(MemoryAcmeStorage::new()),
            Box::new(Arc::clone(&certificate_storage)),
        )
        .with_configured_dns_solver(Arc::clone(&shared))
        .expect("configured DNS solver builds");

        let certificate = issuer
            .obtain(&issuance_request())
            .await
            .expect("issuance with a configured DNS provider must succeed");
        assert_eq!(certificate.domains, vec!["example.com".to_string()]);
        assert_eq!(certificate.cert_chain_der.len(), 2, "leaf plus test CA");

        {
            let state = transport.state();
            assert_eq!(state.doh_queries, 1, "propagation checked via DoH once");
            assert_eq!(state.deletes, 1, "TXT record cleaned up after issuance");
            assert!(
                state.records.is_empty(),
                "no challenge records may be left behind"
            );
            assert!(
                state
                    .requests
                    .iter()
                    .any(|request| request.url.contains("/dns_records")
                        && request.method == HttpMethod::Post),
                "Cloudflare record creation must be called"
            );
        }

        let stored = certificate_storage
            .load("acme.test-directory/example.com")
            .await
            .unwrap()
            .expect("issued certificate persisted in the Caddy layout");
        assert_eq!(stored.domains, vec!["example.com".to_string()]);
        assert!(stored.private_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[tokio::test]
    async fn automatic_https_issuer_path_uses_configured_dns_provider() {
        // Exercises the exact construction path automatic HTTPS uses: the ACME issuer is built
        // with `.with_configured_dns_solver(...)` from the issuer configuration alone.
        let directory = tempfile::tempdir().unwrap();
        let transport = Arc::new(DnsMock::new());
        let shared: Arc<dyn AcmeTransport> = transport.clone();
        let certificate = crate::automatic_https::obtain_acme_certificate(
            &dns_issuer_config(),
            &["example.com".to_string()],
            &shared,
            directory.path().to_path_buf(),
            &Arc::new(Http01TokenStore::new()),
            &Arc::new(TlsAlpn01TokenStore::new()),
            &(Arc::new(TokioClock) as Arc<dyn AcmeClock>),
            &PollPolicy::default(),
        )
        .await
        .expect("automatic-HTTPS ACME path issues via the configured DNS provider");

        assert_eq!(certificate.domains, vec!["example.com".to_string()]);
        {
            let state = transport.state();
            assert_eq!(state.doh_queries, 1);
            assert_eq!(state.deletes, 1);
            assert!(state.records.is_empty());
        }

        // The certificate is persisted in the data directory's Caddy layout.
        let storage = crate::storage::FileStorage::new(directory.path());
        let keys = storage.list("").await.unwrap();
        assert_eq!(keys, vec!["acme.test-directory/example.com".to_string()]);
    }
}
