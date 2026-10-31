//! Certificate model, SNI cache, and renewal decisions.
//!
//! The TLS build in this repository stops at the compatibility boundary: certificate storage,
//! cache/SNI selection, and renewal policy are implemented and tested; the rustls terminator and
//! ACME wire client are tracked by the TLS workstream (M4/M5). Keeping this layer independent of
//! rustls is deliberate: it is the part that must be unit-testable without network or time.

use std::collections::BTreeMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use crate::Error;

/// A certificate and its private key, in DER form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// Domains this certificate is valid for (first entry is the subject name).
    pub domains: Vec<String>,
    /// DER-encoded X.509 certificate chain, leaf first.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// DER-encoded private key.
    pub private_key_der: Vec<u8>,
    /// Validity start.
    pub not_before: SystemTime,
    /// Validity end.
    pub not_after: SystemTime,
    /// Issuer summary (ACME CA URL, internal CA name, or `"loaded"`).
    pub issuer: String,
}

impl Certificate {
    /// Certificate lifetime.
    pub fn lifetime(&self) -> Duration {
        self.not_after
            .duration_since(self.not_before)
            .unwrap_or_default()
    }

    /// Whether the certificate is valid at `now` (with a small clock-skew allowance).
    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        now + Duration::from_secs(60) >= self.not_before && now <= self.not_after
    }

    /// Renewal time: two thirds through the lifetime, mirroring Caddy's default renewal window
    /// (Caddy renews at 1/3 of remaining lifetime; for a 90-day certificate this is ~30 days
    /// before expiry). Documented as DIV-0012 when the exact policy differs.
    pub fn renewal_time(&self) -> SystemTime {
        let lifetime = self.lifetime();
        self.not_before + lifetime.mul_f64(2.0 / 3.0)
    }

    /// Whether the certificate should be renewed at `now`.
    pub fn needs_renewal(&self, now: SystemTime) -> bool {
        now >= self.renewal_time()
    }
}

/// SNI certificate cache.
#[derive(Debug, Default)]
pub struct CertificateCache {
    certificates: RwLock<BTreeMap<String, Certificate>>,
}

impl CertificateCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a certificate for all of its names.
    pub fn insert(&self, certificate: Certificate) {
        let mut certificates = self.write();
        for domain in &certificate.domains {
            certificates.insert(domain.to_ascii_lowercase(), certificate.clone());
        }
    }

    /// Number of cached names.
    pub fn len(&self) -> usize {
        self.certificates
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Select a certificate for an SNI name.
    ///
    /// Order: exact match, then the closest wildcard (`*.example.com` matches
    /// `api.example.com` but not `example.com` or `a.b.example.com`). This follows RFC 6125
    /// wildcard rules for the one-label wildcard Caddy issues.
    pub fn select(&self, server_name: &str) -> Option<Certificate> {
        let name = server_name.trim_end_matches('.').to_ascii_lowercase();
        let certificates = self
            .certificates
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(certificate) = certificates.get(&name) {
            return Some(certificate.clone());
        }
        // A wildcard certificate covers exactly one label in place of `*`.
        let labels: Vec<&str> = name.split('.').collect();
        if labels.len() >= 3 {
            let wildcard = format!("*.{}", labels[1..].join("."));
            if let Some(certificate) = certificates.get(&wildcard) {
                return Some(certificate.clone());
            }
        }
        None
    }

    /// Remove all names for a certificate.
    pub fn remove(&self, domains: &[String]) {
        let mut certificates = self.write();
        for domain in domains {
            certificates.remove(&domain.to_ascii_lowercase());
        }
    }

    /// Iterate over cached certificates, deduplicated by validity window and names.
    pub fn certificates(&self) -> Vec<Certificate> {
        let certificates = self
            .certificates
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut unique: Vec<Certificate> = Vec::new();
        for certificate in certificates.values() {
            if !unique.iter().any(|existing| {
                existing.domains == certificate.domains
                    && existing.not_after == certificate.not_after
            }) {
                unique.push(certificate.clone());
            }
        }
        unique
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, Certificate>> {
        self.certificates
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A certificate that needs renewal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalItem {
    /// Domains to renew.
    pub domains: Vec<String>,
    /// When renewal becomes due.
    pub due_at: SystemTime,
}

/// Compute the renewal queue for a set of certificates.
pub fn renewal_queue(
    certificates: impl IntoIterator<Item = Certificate>,
    now: SystemTime,
) -> Vec<RenewalItem> {
    let mut items: Vec<RenewalItem> = certificates
        .into_iter()
        .map(|certificate| RenewalItem {
            due_at: certificate.renewal_time(),
            domains: certificate.domains,
        })
        .collect();
    items.sort_by_key(|item| item.due_at);
    items.retain(|item| item.due_at > now);
    items
}

/// Errors surfaced by the certificate layer.
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    /// A certificate has no domains.
    #[error("certificate has no subject domains")]
    NoDomains,
    /// SNI name is empty.
    #[error("server name for certificate selection is empty")]
    EmptyServerName,
}

impl From<CertificateError> for Error {
    fn from(error: CertificateError) -> Self {
        Error::Certificate(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(domains: &[&str], not_before: SystemTime, not_after: SystemTime) -> Certificate {
        Certificate {
            domains: domains.iter().map(|domain| domain.to_string()).collect(),
            cert_chain_der: vec![vec![1, 2, 3]],
            private_key_der: vec![4, 5, 6],
            not_before,
            not_after,
            issuer: "test".to_string(),
        }
    }

    #[test]
    fn cache_selects_exact_then_wildcard() {
        let cache = CertificateCache::new();
        let now = SystemTime::now();
        cache.insert(certificate(
            &["example.com"],
            now,
            now + Duration::from_secs(90 * 86_400),
        ));
        cache.insert(certificate(
            &["*.example.net"],
            now,
            now + Duration::from_secs(90 * 86_400),
        ));
        assert!(cache.select("example.com").is_some());
        assert!(cache.select("EXAMPLE.COM").is_some());
        assert!(cache.select("api.example.net").is_some());
        assert!(cache.select("example.net").is_none());
        assert!(cache.select("deep.api.example.net").is_none());
    }

    #[test]
    fn renewal_is_two_thirds_through_lifetime() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let certificate = certificate(&["example.com"], start, start + Duration::from_secs(90));
        assert_eq!(certificate.renewal_time(), start + Duration::from_secs(60));
        assert!(!certificate.needs_renewal(start + Duration::from_secs(59)));
        assert!(certificate.needs_renewal(start + Duration::from_secs(60)));
    }

    #[test]
    fn renewal_queue_sorts_and_skips_past_due() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let later = certificate(&["b.example"], now, now + Duration::from_secs(300));
        let sooner = certificate(&["a.example"], now, now + Duration::from_secs(150));
        let expired = certificate(
            &["c.example"],
            now - Duration::from_secs(120),
            now - Duration::from_secs(60),
        );
        let queue = renewal_queue(vec![later, sooner, expired], now);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue[0].domains, vec!["a.example"]);
    }
}
