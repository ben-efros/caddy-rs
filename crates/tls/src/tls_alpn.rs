//! ACME TLS-ALPN-01 challenge (RFC 8737).
//!
//! The ACME CA validates TLS-ALPN-01 by connecting to the domain with ALPN protocol `acme-tls/1`
//! and expecting a self-signed certificate that carries:
//!
//! * a `subjectAltName` extension containing the identifier, and
//! * the critical `id-pe-acmeIdentifier` extension (`1.3.6.1.5.5.7.1.31`) whose value is the
//!   SHA-256 digest of the key authorization, DER-encoded as an `OCTET STRING` inside the
//!   extension's `extnValue`.
//!
//! This module generates that short-lived certificate, stores it keyed by (normalised) domain in
//! [`TlsAlpn01TokenStore`], and exposes an SNI resolver overlay ([`AcmeTlsAlpnResolver`]) that a
//! TLS listener uses to answer `acme-tls/1` handshakes. [`TlsAlpn01Solver`] implements the
//! [`ChallengeSolver`] contract so `AcmeIssuer` can present/withdraw the evidence.
//!
//! # Server wiring (follow-up, not done in this crate)
//!
//! A TLS listener must do three things to participate:
//!
//! 1. share the issuer's token store: `issuer.tls_alpn01_token_store()`;
//! 2. advertise `acme-tls/1` in its ALPN list: `TlsServerOptions::with_acme_tls_alpn()`;
//! 3. install [`AcmeTlsAlpnResolver`] as the certificate resolver, wrapping the normal
//!    [`CertificateResolver`] — it prefers a challenge certificate when the ClientHello offers
//!    `acme-tls/1` and falls back to the normal resolver otherwise. Build the rustls config with
//!    [`crate::tls_server::build_server_config_with_cert_resolver`].
//!
//! ```text
//! let tokens = Arc::clone(issuer.tls_alpn01_token_store());
//! let resolver = Arc::new(AcmeTlsAlpnResolver::new(normal_resolver, tokens));
//! let options = TlsServerOptions::default().with_acme_tls_alpn();
//! let config = build_server_config_with_cert_resolver(resolver, &options)?;
//! ```
//!
//! Challenge certificates are keyed by the authorization identifier (a wildcard authorization is
//! validated as its base domain); lookups normalise case and trailing dots.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::acme::{Challenge, ChallengeType};
use crate::solver::{ChallengeHandle, ChallengeSolver};
use crate::tls_server::CertificateResolver;
use crate::{Error, Result};

/// ALPN protocol name used by ACME TLS-ALPN-01 validation (RFC 8737).
pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// `id-pe-acmeIdentifier` object identifier (`1.3.6.1.5.5.7.1.31`).
pub const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// How long a challenge certificate is valid around the moment it is generated.
const CHALLENGE_VALIDITY_SECONDS: u64 = 3600;

/// A generated TLS-ALPN-01 challenge certificate and its private key.
#[derive(Debug)]
pub struct TlsAlpn01Challenge {
    domain: String,
    key_authorization: String,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    public_key: Vec<u8>,
}

impl TlsAlpn01Challenge {
    /// Generate a self-signed `acme-tls/1` certificate for `domain` and `key_authorization`.
    pub fn generate(domain: &str, key_authorization: &str) -> Result<Self> {
        let domain = normalize_domain(domain)?;
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|error| issuer_error(format!("generating challenge key: {error}")))?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .map_err(|error| {
                    issuer_error(format!("loading generated challenge key: {error}"))
                })?;
        let public_key = key_pair.public_key().as_ref().to_vec();
        let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());
        let certificate_der =
            challenge_certificate(&domain, digest.as_ref(), &public_key, &key_pair)?;
        Ok(Self {
            domain,
            key_authorization: key_authorization.to_string(),
            certificate_der,
            private_key_der: pkcs8.as_ref().to_vec(),
            public_key,
        })
    }

    /// The normalised identifier this challenge certificate is for.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The key authorization whose SHA-256 digest is embedded in the certificate.
    pub fn key_authorization(&self) -> &str {
        &self.key_authorization
    }

    /// DER-encoded self-signed challenge certificate.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// DER-encoded PKCS#8 private key.
    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }

    /// The certificate's public key (uncompressed P-256 point), for tests and diagnostics.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Build the rustls signing certificate for this challenge.
    pub fn certified_key(&self) -> Result<CertifiedKey> {
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key_der.clone()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)
            .map_err(|error| issuer_error(format!("challenge private key rejected: {error}")))?;
        Ok(CertifiedKey {
            cert: vec![CertificateDer::from(self.certificate_der.clone())],
            key: signing_key,
            ocsp: None,
        })
    }
}

/// Domain-keyed store of TLS-ALPN-01 challenge certificates.
///
/// The TLS listener performs a lookup per handshake; the store is empty between challenges.
#[derive(Debug, Default)]
pub struct TlsAlpn01TokenStore {
    challenges: RwLock<BTreeMap<String, Arc<TlsAlpn01Challenge>>>,
}

impl TlsAlpn01TokenStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate and register a challenge certificate for `domain`.
    pub fn insert(&self, domain: &str, key_authorization: &str) -> Result<Arc<TlsAlpn01Challenge>> {
        let challenge = Arc::new(TlsAlpn01Challenge::generate(domain, key_authorization)?);
        self.challenges
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(challenge.domain().to_string(), Arc::clone(&challenge));
        Ok(challenge)
    }

    /// Look up the challenge for `server_name` (case-insensitive, trailing dots ignored).
    pub fn lookup(&self, server_name: &str) -> Option<Arc<TlsAlpn01Challenge>> {
        let name = normalize_domain(server_name).ok()?;
        self.challenges
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&name)
            .cloned()
    }

    /// Look up the rustls certificate for `server_name`.
    pub fn certified_key(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let challenge = self.lookup(server_name)?;
        challenge.certified_key().ok().map(Arc::new)
    }

    /// Remove the challenge for `domain`, returning it when present.
    pub fn remove(&self, domain: &str) -> Option<Arc<TlsAlpn01Challenge>> {
        let name = normalize_domain(domain).ok()?;
        self.challenges
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&name)
    }

    /// Remove every registered challenge (used when an issuance is aborted).
    pub fn clear(&self) {
        self.challenges
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// Number of registered challenges.
    pub fn len(&self) -> usize {
        self.challenges
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether no challenge is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Domains with a registered challenge (for diagnostics).
    pub fn domains(&self) -> Vec<String> {
        self.challenges
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .cloned()
            .collect()
    }
}

/// TLS-ALPN-01 challenge solver backed by a [`TlsAlpn01TokenStore`].
#[derive(Debug, Clone)]
pub struct TlsAlpn01Solver {
    tokens: Arc<TlsAlpn01TokenStore>,
}

impl TlsAlpn01Solver {
    /// Create a solver publishing challenge certificates into `tokens`.
    pub fn new(tokens: Arc<TlsAlpn01TokenStore>) -> Self {
        Self { tokens }
    }

    /// The shared challenge-certificate store (also handed to the TLS listener).
    pub fn token_store(&self) -> &Arc<TlsAlpn01TokenStore> {
        &self.tokens
    }

    /// Remove every outstanding challenge; the issuer calls withdraw per challenge, this is a
    /// defensive bulk cleanup for embedders and failure paths.
    pub fn cleanup(&self) {
        self.tokens.clear();
    }
}

#[async_trait]
impl ChallengeSolver for TlsAlpn01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::TlsAlpn01
    }

    async fn present(
        &self,
        domain: &str,
        challenge: &Challenge,
        key_authorization: &str,
    ) -> Result<ChallengeHandle> {
        if challenge.challenge_type != ChallengeType::TlsAlpn01.as_str() {
            return Err(issuer_error(format!(
                "TLS-ALPN-01 solver received a `{}` challenge",
                challenge.challenge_type
            )));
        }
        let challenge = self.tokens.insert(domain, key_authorization)?;
        Ok(ChallengeHandle::TlsAlpn01 {
            domain: challenge.domain().to_string(),
        })
    }

    async fn withdraw(&self, handle: &ChallengeHandle) -> Result<()> {
        if let ChallengeHandle::TlsAlpn01 { domain } = handle {
            self.tokens.remove(domain);
        }
        Ok(())
    }
}

/// Certificate resolver overlay for ACME TLS-ALPN-01.
///
/// When the ClientHello offers the `acme-tls/1` protocol it selects the matching challenge
/// certificate from the token store (and never falls back to a normal certificate — the CA must
/// see the challenge certificate). For every other handshake it delegates to the wrapped
/// [`CertificateResolver`].
#[derive(Debug)]
pub struct AcmeTlsAlpnResolver {
    fallback: Arc<CertificateResolver>,
    tokens: Arc<TlsAlpn01TokenStore>,
}

impl AcmeTlsAlpnResolver {
    /// Wrap `fallback` with `tokens`.
    pub fn new(fallback: Arc<CertificateResolver>, tokens: Arc<TlsAlpn01TokenStore>) -> Self {
        Self { fallback, tokens }
    }

    /// The challenge store consulted for `acme-tls/1` handshakes.
    pub fn token_store(&self) -> &Arc<TlsAlpn01TokenStore> {
        &self.tokens
    }

    /// The normal resolver used for non-`acme-tls/1` handshakes.
    pub fn fallback(&self) -> &Arc<CertificateResolver> {
        &self.fallback
    }

    /// Resolve one ClientHello.
    pub fn resolve_hello(
        &self,
        server_name: Option<&str>,
        offers_acme_tls: bool,
    ) -> Option<Arc<CertifiedKey>> {
        if offers_acme_tls {
            return server_name.and_then(|name| self.tokens.certified_key(name));
        }
        self.fallback.select(server_name)
    }
}

impl crate::tls_server::TlsResolver for AcmeTlsAlpnResolver {
    fn tag_selector(&self) -> Option<&dyn crate::tls_server::TaggedCertificateSelector> {
        crate::tls_server::TlsResolver::tag_selector(&*self.fallback)
    }
}

impl ResolvesServerCert for AcmeTlsAlpnResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let offers_acme_tls = client_hello
            .alpn()
            .map(|protocols| {
                protocols
                    .into_iter()
                    .any(|protocol| protocol == ACME_TLS_ALPN_PROTOCOL)
            })
            .unwrap_or(false);
        self.resolve_hello(client_hello.server_name(), offers_acme_tls)
    }
}

fn issuer_error(message: impl Into<String>) -> Error {
    Error::Issuer(format!("TLS-ALPN-01: {}", message.into()))
}

fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.');
    let domain = domain.strip_prefix("*.").unwrap_or(domain);
    let domain = domain.to_ascii_lowercase();
    if domain.is_empty() {
        return Err(issuer_error("challenge domain is empty"));
    }
    Ok(domain)
}

// ---- challenge certificate generation --------------------------------------------------------

fn challenge_certificate(
    domain: &str,
    digest: &[u8],
    public_key: &[u8],
    key_pair: &EcdsaKeyPair,
) -> Result<Vec<u8>> {
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Err(issuer_error(
            "challenge key is not an uncompressed P-256 point",
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let not_before = now.saturating_sub(CHALLENGE_VALIDITY_SECONDS);
    let not_after = now.saturating_add(CHALLENGE_VALIDITY_SECONDS);
    let signature_algorithm = der_sequence(&[der_oid(&[1, 2, 840, 10045, 4, 3, 2])]);
    let name = der_sequence(&[der_set(&[der_sequence(&[
        der_oid(&[2, 5, 4, 3]),
        der_utf8(domain),
    ])])]);
    let validity = der_sequence(&[der_utc_time(not_before), der_utc_time(not_after)]);
    let spki = der_sequence(&[
        der_sequence(&[
            der_oid(&[1, 2, 840, 10045, 2, 1]),
            der_oid(&[1, 2, 840, 10045, 3, 1, 7]),
        ]),
        der_bit_string(public_key),
    ]);

    // subjectAltName: exactly one dNSName.
    let subject_alt_name = der_sequence(&[
        der_oid(&[2, 5, 29, 17]),
        der_octet_string(&der_sequence(&[der_tlv(0x82, domain.as_bytes())])),
    ]);
    // id-pe-acmeIdentifier: critical, OCTET STRING wrapping the SHA-256 digest (RFC 8737 §3).
    let acme_identifier = der_sequence(&[
        der_oid(ACME_IDENTIFIER_OID),
        der_boolean(true),
        der_octet_string(&der_octet_string(digest)),
    ]);
    // basicConstraints: CA:FALSE.
    let basic_constraints = der_sequence(&[
        der_oid(&[2, 5, 29, 19]),
        der_octet_string(&der_sequence(&[der_boolean(false)])),
    ]);
    let extensions = der_sequence(&[subject_alt_name, acme_identifier, basic_constraints]);
    let tbs = der_sequence(&[
        der_tlv(0xA0, &der_integer(2)), // v3
        der_integer(now.max(1)),
        signature_algorithm.clone(),
        name.clone(),
        validity,
        name,
        spki,
        der_tlv(0xA3, &extensions),
    ]);
    let rng = SystemRandom::new();
    let signature = key_pair
        .sign(&rng, &tbs)
        .map_err(|error| issuer_error(format!("signing challenge certificate: {error}")))?;
    Ok(der_sequence(&[
        tbs,
        signature_algorithm,
        der_bit_string(signature.as_ref()),
    ]))
}

// ---- minimal DER encoding helpers -----------------------------------------------------------

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut bytes = length.to_be_bytes().to_vec();
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    let mut encoded = vec![0x80 | bytes.len() as u8];
    encoded.extend(bytes);
    encoded
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    encoded.extend(der_length(content.len()));
    encoded.extend_from_slice(content);
    encoded
}

fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    der_tlv(0x30, &items.concat())
}

fn der_set(items: &[Vec<u8>]) -> Vec<u8> {
    der_tlv(0x31, &items.concat())
}

fn der_integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = bytes[first..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der_tlv(0x02, &content)
}

fn der_boolean(value: bool) -> Vec<u8> {
    der_tlv(0x01, &[if value { 0xFF } else { 0x00 }])
}

fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut value = *arc;
        let mut stack = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            stack.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        stack.reverse();
        content.extend(stack);
    }
    der_tlv(0x06, &content)
}

fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut inner = vec![0u8];
    inner.extend_from_slice(content);
    der_tlv(0x03, &inner)
}

fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tlv(0x04, content)
}

fn der_utf8(value: &str) -> Vec<u8> {
    der_tlv(0x0C, value.as_bytes())
}

fn der_utc_time(unix: u64) -> Vec<u8> {
    let days = (unix / 86_400) as i64;
    let seconds = unix % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    let value = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year.rem_euclid(100),
        month,
        day,
        hour,
        minute,
        second
    );
    der_tlv(0x17, value.as_bytes())
}

/// Convert days since 1970-01-01 to a civil (year, month, day) date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u32;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year + i64::from(month <= 2), month, day)
}

/// Test-only certificate verifier: accepts the self-signed ACME challenge certificate (whose
/// critical `id-pe-acmeIdentifier` extension a normal WebPKI verifier must reject).
#[cfg(test)]
#[derive(Debug)]
struct AcceptChallengeCertificate(Arc<rustls::crypto::CryptoProvider>);

#[cfg(test)]
impl rustls::client::danger::ServerCertVerifier for AcceptChallengeCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        eprintln!(
            "DEBUG custom verifier called for cert len {}",
            _end_entity.as_ref().len()
        );
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_challenge_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_challenge_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Verify a TLS handshake signature using the challenge certificate's P-256 public key.
///
/// `rustls::crypto::verify_tls13_signature` parses the certificate with webpki, which rejects the
/// challenge certificate's critical `id-pe-acmeIdentifier` extension; the test-only verifier
/// therefore extracts the SubjectPublicKeyInfo itself and verifies the ECDSA signature with ring.
#[cfg(test)]
fn verify_challenge_signature(
    message: &[u8],
    certificate: &CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    if dss.scheme != rustls::SignatureScheme::ECDSA_NISTP256_SHA256 {
        return Err(rustls::Error::General(
            "unsupported challenge certificate signature scheme".to_string(),
        ));
    }
    let public_key = certificate_public_key(certificate.as_ref());
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, dss.signature())
        .map(|()| rustls::client::danger::HandshakeSignatureValid::assertion())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))
}

#[cfg(test)]
fn certificate_public_key(der: &[u8]) -> Vec<u8> {
    fn read(input: &[u8]) -> (u8, &[u8], usize, usize) {
        assert!(input.len() >= 2, "truncated DER");
        let tag = input[0];
        let first = input[1];
        let (length, header) = if first & 0x80 == 0 {
            (first as usize, 2)
        } else {
            let count = (first & 0x7f) as usize;
            let mut length = 0usize;
            for byte in &input[2..2 + count] {
                length = (length << 8) | *byte as usize;
            }
            (length, 2 + count)
        };
        (
            tag,
            &input[header..header + length],
            header + length,
            header,
        )
    }
    fn children(content: &[u8]) -> Vec<(u8, &[u8])> {
        let mut out = Vec::new();
        let mut rest = content;
        while !rest.is_empty() {
            let (tag, value, total, _) = read(rest);
            out.push((tag, value));
            rest = &rest[total..];
        }
        out
    }
    let (tag, certificate, _, _) = read(der);
    assert_eq!(tag, 0x30, "Certificate is a SEQUENCE");
    let parts = children(certificate);
    let (tbs_tag, tbs) = parts[0];
    assert_eq!(tbs_tag, 0x30, "tbsCertificate is a SEQUENCE");
    let mut fields = children(tbs);
    if fields[0].0 == 0xA0 {
        fields.remove(0); // explicit version
    }
    // serial, signature algorithm, issuer, validity, subject, subjectPublicKeyInfo
    let (spki_tag, spki) = fields[5];
    assert_eq!(spki_tag, 0x30, "SubjectPublicKeyInfo is a SEQUENCE");
    let spki_parts = children(spki);
    let (bit_tag, bit_string) = spki_parts[1];
    assert_eq!(bit_tag, 0x03, "public key is a BIT STRING");
    assert_eq!(bit_string[0], 0, "no unused bits");
    bit_string[1..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

    fn challenge() -> TlsAlpn01Challenge {
        TlsAlpn01Challenge::generate("Example.COM.", "token-1.thumbprint").expect("challenge")
    }

    fn expected_extension(key_authorization: &str) -> Vec<u8> {
        let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());
        der_sequence(&[
            der_oid(ACME_IDENTIFIER_OID),
            der_boolean(true),
            der_octet_string(&der_octet_string(digest.as_ref())),
        ])
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn read_tlv(input: &[u8]) -> (u8, &[u8], usize) {
        assert!(input.len() >= 2);
        let tag = input[0];
        let first = input[1];
        let (length, header) = if first & 0x80 == 0 {
            (first as usize, 2)
        } else {
            let count = (first & 0x7f) as usize;
            let mut length = 0usize;
            for byte in &input[2..2 + count] {
                length = (length << 8) | *byte as usize;
            }
            (length, 2 + count)
        };
        (tag, &input[header..header + length], header + length)
    }

    #[test]
    fn challenge_certificate_contains_acme_identifier_extension() {
        let challenge = challenge();
        assert_eq!(challenge.domain(), "example.com");
        let der = challenge.certificate_der();
        let expected = expected_extension("token-1.thumbprint");
        assert!(
            contains(der, &expected),
            "certificate must contain the critical id-pe-acmeIdentifier extension"
        );
        // subjectAltName carries the normalised identifier.
        let san = der_sequence(&[der_tlv(0x82, b"example.com")]);
        assert!(
            contains(der, &san),
            "certificate must contain the SAN dNSName"
        );
        assert!(!contains(der, b"Example.COM."), "identifier is normalised");
    }

    #[test]
    fn challenge_certificate_is_self_signed_and_valid() {
        let challenge = challenge();
        let (tag, body, _) = read_tlv(challenge.certificate_der());
        assert_eq!(tag, 0x30, "Certificate is a SEQUENCE");
        let (info_tag, _info, info_len) = read_tlv(body);
        assert_eq!(info_tag, 0x30, "tbsCertificate is a SEQUENCE");
        let tbs = &body[..info_len];
        let (alg_tag, _alg, alg_len) = read_tlv(&body[info_len..]);
        assert_eq!(alg_tag, 0x30);
        let (sig_tag, sig_content, _) = read_tlv(&body[info_len + alg_len..]);
        assert_eq!(sig_tag, 0x03);
        let signature = &sig_content[1..];
        let public_key =
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, challenge.public_key_bytes());
        public_key
            .verify(tbs, signature)
            .expect("challenge certificate signature verifies with its own key");
        // The extension digest is exactly SHA-256(keyAuthorization).
        let digest = ring::digest::digest(
            &ring::digest::SHA256,
            challenge.key_authorization().as_bytes(),
        );
        assert!(contains(challenge.certificate_der(), digest.as_ref()));
    }

    #[test]
    fn token_store_is_domain_keyed_and_normalises_names() {
        let store = TlsAlpn01TokenStore::new();
        let challenge = store
            .insert("Example.COM.", "token.thumb")
            .expect("challenge inserted");
        assert_eq!(challenge.domain(), "example.com");
        assert_eq!(store.len(), 1);
        assert!(store.lookup("example.com").is_some());
        assert!(store.lookup("EXAMPLE.COM.").is_some());
        assert!(store.lookup("other.example").is_none());
        assert!(store.certified_key("example.com").is_some());
        assert_eq!(store.domains(), vec!["example.com".to_string()]);
        assert!(store.remove("EXAMPLE.com").is_some());
        assert!(store.is_empty());
        assert!(store.remove("example.com").is_none());
    }

    #[test]
    fn token_store_clear_removes_everything() {
        let store = TlsAlpn01TokenStore::new();
        store.insert("a.example", "token.a").unwrap();
        store.insert("b.example", "token.b").unwrap();
        assert_eq!(store.len(), 2);
        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn wildcard_authorization_uses_base_domain() {
        let challenge = TlsAlpn01Challenge::generate("*.example.com", "token.thumb").unwrap();
        assert_eq!(challenge.domain(), "example.com");
    }

    #[test]
    fn rejects_empty_domain_and_mismatched_challenge_type() {
        let store = TlsAlpn01TokenStore::new();
        assert!(store.insert("   ", "token").is_err());
        let solver = TlsAlpn01Solver::new(Arc::new(store));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let http_challenge: Challenge = serde_json::from_value(serde_json::json!({
            "type": "http-01",
            "url": "https://acme.test/challenge/1",
            "token": "token",
            "status": "pending"
        }))
        .unwrap();
        let error = runtime
            .block_on(solver.present("example.com", &http_challenge, "token.thumb"))
            .unwrap_err();
        assert!(error.to_string().contains("TLS-ALPN-01"), "{error}");
    }

    #[test]
    fn solver_present_and_withdraw_manage_the_store() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let tokens = Arc::new(TlsAlpn01TokenStore::new());
        let solver = TlsAlpn01Solver::new(Arc::clone(&tokens));
        let challenge: Challenge = serde_json::from_value(serde_json::json!({
            "type": "tls-alpn-01",
            "url": "https://acme.test/challenge/1",
            "token": "token",
            "status": "pending"
        }))
        .unwrap();
        let handle = runtime
            .block_on(solver.present("example.com", &challenge, "token.thumb"))
            .expect("challenge presented");
        assert!(matches!(handle, ChallengeHandle::TlsAlpn01 { .. }));
        assert!(tokens.lookup("example.com").is_some());
        runtime.block_on(solver.withdraw(&handle)).unwrap();
        assert!(tokens.is_empty());
        // Cleanup is defensive and idempotent.
        solver.cleanup();
        assert!(tokens.is_empty());
    }

    #[test]
    fn resolver_prefers_challenge_certificate_only_for_acme_tls() {
        let tokens = Arc::new(TlsAlpn01TokenStore::new());
        tokens.insert("example.com", "token.thumb").unwrap();
        let fallback = Arc::new(CertificateResolver::new());
        let resolver = AcmeTlsAlpnResolver::new(fallback, tokens);
        // No normal certificate loaded: non-acme handshakes resolve nothing.
        assert!(resolver.resolve_hello(Some("example.com"), false).is_none());
        let challenged = resolver
            .resolve_hello(Some("example.com"), true)
            .expect("challenge certificate selected");
        let expected = resolver
            .token_store()
            .lookup("example.com")
            .unwrap()
            .certified_key()
            .unwrap();
        assert_eq!(challenged.cert, expected.cert);
        // acme-tls/1 for an unknown name never falls back to a normal certificate.
        assert!(resolver
            .resolve_hello(Some("unknown.example"), true)
            .is_none());
    }

    #[tokio::test]
    async fn rustls_handshake_negotiates_acme_tls_with_challenge_certificate() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let tokens = Arc::new(TlsAlpn01TokenStore::new());
        tokens.insert("example.com", "token.thumb").unwrap();
        let challenge_cert = tokens
            .lookup("example.com")
            .unwrap()
            .certificate_der()
            .to_vec();
        let resolver = Arc::new(AcmeTlsAlpnResolver::new(
            Arc::new(CertificateResolver::new()),
            tokens,
        ));
        let options = crate::tls_server::TlsServerOptions::default().with_acme_tls_alpn();
        let server_config =
            crate::tls_server::build_server_config_with_cert_resolver(resolver, &options)
                .expect("server config");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&server_config));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let _ = stream.write_all(b"acme-tls/1 ok").await;
            let _ = stream.shutdown().await;
        });

        // The challenge certificate carries a critical id-pe-acmeIdentifier extension that a
        // normal WebPKI client rejects; the ACME CA parses it specially, so the test client uses
        // a verifier that accepts the self-signed challenge certificate.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptChallengeCertificate(Arc::clone(
                &provider,
            ))))
            .with_no_client_auth();
        client.alpn_protocols = vec![ACME_TLS_ALPN_PROTOCOL.to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let stream = connector
            .connect(server_name, stream)
            .await
            .expect("acme-tls/1 handshake succeeds");
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(ACME_TLS_ALPN_PROTOCOL)
        );
        let peer = stream.get_ref().1.peer_certificates().unwrap();
        assert_eq!(peer[0].as_ref(), challenge_cert.as_slice());
    }

    #[test]
    fn utc_time_encoding_is_correct() {
        // 2026-11-02T00:00:00Z
        let encoded = der_utc_time(1_793_577_600);
        assert_eq!(encoded, {
            let mut value = vec![0x17, 0x0D];
            value.extend_from_slice(b"261102000000Z");
            value
        });
    }
}
