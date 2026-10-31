//! Certificate issuer interface and ACME/internal configuration.
//!
//! The trait is the boundary the rest of the runtime uses. Real ACME wire support (directory
//! discovery, account keys, JWS, challenge servers) is the M5 workstream; this build ships the
//! configuration model and a clear failure for unimplemented issuers, so a configuration using
//! ACME cannot silently appear to work.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::certificate::Certificate;
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
        config.dns_provider = object
            .get("challenges")
            .and_then(|challenges| challenges.get("dns"))
            .and_then(|dns| dns.get("provider"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        Ok(config)
    }
}

/// ACME issuer. Wire implementation is tracked by M5; `obtain` fails loudly.
#[derive(Debug, Clone)]
pub struct AcmeIssuer {
    /// Issuer configuration.
    pub config: AcmeIssuerConfig,
}

#[async_trait]
impl CertificateIssuer for AcmeIssuer {
    fn name(&self) -> &'static str {
        "acme"
    }

    async fn obtain(&self, _request: &IssuanceRequest) -> Result<Certificate> {
        Err(Error::NotImplemented {
            feature: "ACME certificate issuance (directory/account/JWS/challenge client)",
            tracking_id: "TLS-ACME",
        })
    }
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

    #[test]
    fn parses_acme_json() {
        let config = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "ca": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "email": "ops@example.com",
            "challenges": {"dns": {"provider": "cloudflare"}}
        }))
        .unwrap();
        assert_eq!(
            config.ca,
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(config.email.as_deref(), Some("ops@example.com"));
        assert_eq!(config.dns_provider.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn parses_acme_account_and_eab_config() {
        let config = AcmeIssuerConfig::from_json(&serde_json::json!({
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
    fn accepts_alternate_external_account_member_names() {
        let config = AcmeIssuerConfig::from_json(&serde_json::json!({
            "module": "acme",
            "external_account": {"kid": "kid-2", "hmac_key": "bWFj"}
        }))
        .unwrap();
        let eab = config.external_account.unwrap();
        assert_eq!(eab.kid, "kid-2");
        assert_eq!(eab.hmac_key, "bWFj");
        assert_eq!(
            serde_json::to_value(&eab).unwrap(),
            serde_json::json!({"key_id": "kid-2", "mac_key": "bWFj"})
        );
    }

    #[test]
    fn rejects_malformed_external_account_config() {
        let error = AcmeIssuerConfig::from_json(&serde_json::json!({
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
    async fn acme_issuer_fails_loudly_with_tracking_id() {
        let issuer = AcmeIssuer {
            config: AcmeIssuerConfig::default(),
        };
        let error = issuer
            .obtain(&IssuanceRequest {
                domains: vec!["example.com".to_string()],
                internal: false,
            })
            .await
            .err()
            .expect("ACME is not implemented");
        assert!(error.to_string().contains("TLS-ACME"));
    }
}
