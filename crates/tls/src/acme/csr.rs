//! PKCS#10 certificate signing requests for ACME finalization.
//!
//! RFC 8555 finalization takes a base64url-encoded DER `CertificationRequest`. The workspace's
//! offline registry cache has no CSR-construction crate (rcgen/x509-cert are absent), so this
//! module builds the small, fixed DER structure by hand and signs it with the same `ring` backend
//! used for account keys:
//!
//! * a fresh certificate key per request (the account key is never reused), selected by Caddy's
//!   automation-policy `key_type`: ECDSA P-256 (default), ECDSA P-384, RSA 2048 or RSA 4096;
//! * subject: empty except a `commonName` of the first domain (ACME CAs authorise by SAN);
//! * subjectAltName extension with `dNSName` entries for DNS identifiers and `iPAddress`
//!   entries for IP identifiers, wrapped in the `extensionRequest` attribute;
//! * ECDSA-with-SHA256/384 or SHA-256-with-RSA signatures matching the key type.
//!
//! The private key is returned as PKCS#8 PEM next to the CSR so the caller can store it with the
//! certificate it receives.

use std::net::IpAddr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::rngs::OsRng;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
    ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;

use super::AcmeError;
use crate::Result;

/// ASN.1 DER `OBJECT IDENTIFIER` encodings used by PKCS#10 and X.509.
const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
const OID_SECP384R1: &[u64] = &[1, 3, 132, 0, 34];
const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
const OID_SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
const OID_SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];
const OID_ED25519: &[u64] = &[1, 3, 101, 112];
const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
const OID_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];

/// Certificate key type selected by Caddy's automation policy `key_type`.
///
/// Caddy/certmagic supports `p256` (default), `p384`, `rsa2048`, `rsa4096` and `ed25519`. This
/// build implements the first four; `ed25519` is rejected with a located error because the
/// offline registry cache has no Ed25519 signing path for PKCS#10 (see DIV-0032).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertificateKeyType {
    /// ECDSA P-256 (default).
    #[default]
    P256,
    /// ECDSA P-384.
    P384,
    /// RSA 2048-bit.
    Rsa2048,
    /// RSA 4096-bit.
    Rsa4096,
}

impl CertificateKeyType {
    /// Parse Caddy's `key_type` spelling.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "p256" => Ok(Self::P256),
            "p384" => Ok(Self::P384),
            "rsa2048" => Ok(Self::Rsa2048),
            "rsa4096" => Ok(Self::Rsa4096),
            "ed25519" => Err(AcmeError::CertificateRequest(
                "certificate key type `ed25519` is not implemented (offline build has no Ed25519 PKCS#10 signing path); supported: p256, p384, rsa2048, rsa4096"
                    .to_string(),
            )
            .into()),
            other => Err(AcmeError::CertificateRequest(format!(
                "unknown certificate key type `{other}`; expected p256, p384, rsa2048 or rsa4096"
            ))
            .into()),
        }
    }

    /// Infer the key type of a DER private key produced by this module (PKCS#8, SEC1 or PKCS#1).
    pub fn from_private_key_der(der: &[u8]) -> Result<Self> {
        if let Ok(private_key) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
            use rsa::traits::PublicKeyParts;
            return match private_key.n().bits() {
                2048 => Ok(Self::Rsa2048),
                4096 => Ok(Self::Rsa4096),
                other => Err(AcmeError::CertificateRequest(format!(
                    "unsupported RSA certificate key size {other} bits"
                ))
                .into()),
            };
        }
        if let Ok(private_key) = rsa::RsaPrivateKey::from_pkcs1_der(der) {
            use rsa::traits::PublicKeyParts;
            return match private_key.n().bits() {
                2048 => Ok(Self::Rsa2048),
                4096 => Ok(Self::Rsa4096),
                other => Err(AcmeError::CertificateRequest(format!(
                    "unsupported RSA certificate key size {other} bits"
                ))
                .into()),
            };
        }
        if der.len() > 32 {
            // PKCS#8 EC: detect the named curve OID in the AlgorithmIdentifier.
            let prime256v1 = der_oid(OID_PRIME256V1);
            let secp384r1 = der_oid(OID_SECP384R1);
            if der.windows(prime256v1.len()).any(|w| w == prime256v1) {
                return Ok(Self::P256);
            }
            if der.windows(secp384r1.len()).any(|w| w == secp384r1) {
                return Ok(Self::P384);
            }
        }
        Err(AcmeError::CertificateRequest(
            "could not determine certificate key type from the private key".to_string(),
        )
        .into())
    }

    /// Caddy spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::P256 => "p256",
            Self::P384 => "p384",
            Self::Rsa2048 => "rsa2048",
            Self::Rsa4096 => "rsa4096",
        }
    }
}

/// A generated certificate signing request and its private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    der: Vec<u8>,
    private_key_pem: String,
    public_key: Vec<u8>,
    key_type: CertificateKeyType,
    domains: Vec<String>,
}

impl CertificateRequest {
    /// Generate a CSR for `domains` (DNS names and/or IP addresses) with a fresh P-256 key.
    pub fn generate(domains: &[String]) -> Result<Self> {
        Self::generate_with_key_type(domains, CertificateKeyType::P256)
    }

    /// Generate a CSR for `domains` with a fresh key of `key_type`.
    pub fn generate_with_key_type(
        domains: &[String],
        key_type: CertificateKeyType,
    ) -> Result<Self> {
        let domains = normalize_domains(domains)?;
        match key_type {
            CertificateKeyType::P256 | CertificateKeyType::P384 => {
                Self::generate_ec(&domains, key_type)
            }
            CertificateKeyType::Rsa2048 | CertificateKeyType::Rsa4096 => {
                Self::generate_rsa(&domains, key_type)
            }
        }
    }

    fn generate_ec(domains: &[String], key_type: CertificateKeyType) -> Result<Self> {
        let rng = SystemRandom::new();
        let (pkcs8, key_pair, public_key, spki, signature_algorithm) = match key_type {
            CertificateKeyType::P256 => {
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .map_err(|error| {
                        AcmeError::CertificateRequest(format!("generating P-256 key: {error}"))
                    })?;
                let key_pair =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                        .map_err(|error| {
                            AcmeError::CertificateRequest(format!(
                                "reloading generated P-256 key: {error}"
                            ))
                        })?;
                let public_key = key_pair.public_key().as_ref().to_vec();
                let spki = der_sequence(&[
                    der_sequence(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)]),
                    der_bit_string(&public_key),
                ]);
                (
                    pkcs8.as_ref().to_vec(),
                    EcKeyPair::P256(key_pair),
                    public_key,
                    spki,
                    der_sequence(&[der_oid(OID_ECDSA_WITH_SHA256)]),
                )
            }
            CertificateKeyType::P384 => {
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
                    .map_err(|error| {
                        AcmeError::CertificateRequest(format!("generating P-384 key: {error}"))
                    })?;
                let key_pair =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                        .map_err(|error| {
                            AcmeError::CertificateRequest(format!(
                                "reloading generated P-384 key: {error}"
                            ))
                        })?;
                let public_key = key_pair.public_key().as_ref().to_vec();
                let spki = der_sequence(&[
                    der_sequence(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_SECP384R1)]),
                    der_bit_string(&public_key),
                ]);
                (
                    pkcs8.as_ref().to_vec(),
                    EcKeyPair::P384(key_pair),
                    public_key,
                    spki,
                    der_sequence(&[der_oid(OID_ECDSA_WITH_SHA384)]),
                )
            }
            _ => unreachable!(),
        };
        let certification_request_info = certification_request_info(&domains, spki)?;
        let signature = match &key_pair {
            EcKeyPair::P256(key_pair) => key_pair
                .sign(&rng, &certification_request_info)
                .map_err(|error| {
                    AcmeError::CertificateRequest(format!("signing certification request: {error}"))
                })?
                .as_ref()
                .to_vec(),
            EcKeyPair::P384(key_pair) => key_pair
                .sign(&rng, &certification_request_info)
                .map_err(|error| {
                    AcmeError::CertificateRequest(format!("signing certification request: {error}"))
                })?
                .as_ref()
                .to_vec(),
        };
        let der = der_sequence(&[
            certification_request_info,
            signature_algorithm,
            der_bit_string(&signature),
        ]);
        Ok(Self {
            der,
            private_key_pem: pem_encode("PRIVATE KEY", &pkcs8),
            public_key,
            key_type,
            domains: domains.to_vec(),
        })
    }

    fn generate_rsa(domains: &[String], key_type: CertificateKeyType) -> Result<Self> {
        let bits = match key_type {
            CertificateKeyType::Rsa2048 => 2048,
            CertificateKeyType::Rsa4096 => 4096,
            _ => unreachable!(),
        };
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, bits).map_err(|error| {
            AcmeError::CertificateRequest(format!("generating RSA-{bits} key: {error}"))
        })?;
        Self::csr_from_rsa(domains, key_type, private_key)
    }

    /// Build an RSA CSR from an existing private key (test seam for expensive RSA-4096 keys).
    #[cfg(test)]
    pub(crate) fn generate_rsa_with_key(
        domains: &[String],
        key_type: CertificateKeyType,
        private_key: rsa::RsaPrivateKey,
    ) -> Result<Self> {
        let domains = normalize_domains(domains)?;
        Self::csr_from_rsa(&domains, key_type, private_key)
    }

    fn csr_from_rsa(
        domains: &[String],
        key_type: CertificateKeyType,
        private_key: rsa::RsaPrivateKey,
    ) -> Result<Self> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::traits::PublicKeyParts;
        let public_key = private_key.to_public_key();
        let rsa_public_der = der_sequence(&[
            der_integer_from_bytes(&public_key.n().to_bytes_be()),
            der_integer_from_bytes(&public_key.e().to_bytes_be()),
        ]);
        let spki = der_sequence(&[
            der_sequence(&[der_oid(OID_RSA_ENCRYPTION), der_null()]),
            der_bit_string(&rsa_public_der),
        ]);
        let certification_request_info = certification_request_info(&domains, spki)?;
        let signing_key = SigningKey::<sha2::Sha256>::new(private_key.clone());
        let signature = signing_key.sign(&certification_request_info).to_vec();
        let signature_algorithm = der_sequence(&[der_oid(OID_SHA256_WITH_RSA), der_null()]);
        let der = der_sequence(&[
            certification_request_info,
            signature_algorithm,
            der_bit_string(&signature),
        ]);
        use rsa::pkcs8::EncodePrivateKey;
        let pkcs8 = private_key.to_pkcs8_der().map_err(|error| {
            AcmeError::CertificateRequest(format!("encoding RSA certificate key: {error}"))
        })?;
        Ok(Self {
            der,
            private_key_pem: pem_encode("PRIVATE KEY", pkcs8.as_bytes()),
            public_key: rsa_public_der,
            key_type,
            domains: domains.to_vec(),
        })
    }

    /// The certificate key type.
    pub fn key_type(&self) -> CertificateKeyType {
        self.key_type
    }

    /// DER-encoded `CertificationRequest`.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The CSR's private key in PKCS#8 PEM form.
    ///
    /// Runtime TLS loading expects PKCS#8. This differs from certmagic's certificate-key PEM
    /// (SEC1 `EC PRIVATE KEY` / PKCS#1 `RSA PRIVATE KEY`), which is tracked as a residual
    /// divergence in DIV-0032; account keys do use certmagic's encodings.
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    /// The CSR's public key: an uncompressed EC point (`0x04 || X || Y`) for ECDSA keys or the
    /// PKCS#1 `RSAPublicKey` DER for RSA keys.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Normalised identifiers the CSR covers, in request order.
    pub fn domains(&self) -> &[String] {
        &self.domains
    }
}

fn normalize_domains(domains: &[String]) -> Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(domains.len());
    for domain in domains {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return Err(AcmeError::CertificateRequest(
                "certificate request domains must not be empty".to_string(),
            )
            .into());
        }
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    if normalized.is_empty() {
        return Err(AcmeError::CertificateRequest(
            "certificate request needs at least one domain".to_string(),
        )
        .into());
    }
    Ok(normalized)
}

enum EcKeyPair {
    P256(EcdsaKeyPair),
    P384(EcdsaKeyPair),
}

fn certification_request_info(domains: &[String], spki: Vec<u8>) -> Result<Vec<u8>> {
    let subject = subject_with_common_name(&domains[0]);

    let general_names = general_names(domains);
    let extension = der_sequence(&[
        der_oid(OID_SUBJECT_ALT_NAME),
        der_octet_string(&general_names),
    ]);
    let extensions = der_sequence(&[extension]);
    let attribute = der_sequence(&[der_oid(OID_EXTENSION_REQUEST), der_set(&[extensions])]);
    // attributes [0] IMPLICIT SET OF Attribute: the context tag replaces the SET tag.
    let attributes = der_tlv(0xA0, &attribute);

    Ok(der_sequence(&[der_integer(0), subject, spki, attributes]))
}

fn subject_with_common_name(common_name: &str) -> Vec<u8> {
    // A single CN attribute is sufficient; CAs authorise names via the SAN extension.
    let attribute_type_and_value =
        der_sequence(&[der_oid(OID_COMMON_NAME), der_utf8_string(common_name)]);
    let rdn = der_set(&[attribute_type_and_value]);
    der_sequence(&[rdn])
}

fn general_names(domains: &[String]) -> Vec<u8> {
    let mut names = Vec::with_capacity(domains.len());
    for domain in domains {
        match domain.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => names.push(der_tlv(0x87, &address.octets())),
            Ok(IpAddr::V6(address)) => names.push(der_tlv(0x87, &address.octets())),
            Err(_) => names.push(der_tlv(0x82, domain.as_bytes())),
        }
    }
    der_sequence(&names)
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
    let mut encoded = Vec::with_capacity(bytes.len() + 1);
    encoded.push(0x80 | bytes.len() as u8);
    encoded.extend(bytes);
    encoded
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(content.len() + 4);
    encoded.push(tag);
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
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = bytes[first_non_zero..].to_vec();
    if content.is_empty() {
        content.push(0);
    }
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der_tlv(0x02, &content)
}

fn der_integer_from_bytes(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let mut content = bytes[first..].to_vec();
    if content.is_empty() {
        content.push(0);
    }
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der_tlv(0x02, &content)
}

fn der_null() -> Vec<u8> {
    der_tlv(0x05, &[])
}

fn der_oid(arcs: &[u64]) -> Vec<u8> {
    der_tlv(0x06, &der_oid_content(arcs))
}

/// The content octets of an OBJECT IDENTIFIER (without tag and length).
fn der_oid_content(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    if arcs.len() >= 2 {
        content.push((arcs[0] * 40 + arcs[1]) as u8);
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
    }
    content
}

fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tlv(0x04, content)
}

fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(content.len() + 1);
    inner.push(0); // no unused bits
    inner.extend_from_slice(content);
    der_tlv(0x03, &inner)
}

fn der_utf8_string(value: &str) -> Vec<u8> {
    der_tlv(0x0C, value.as_bytes())
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::with_capacity(encoded.len() + encoded.len() / 64 + 64);
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    pem
}

// ---- server-side CSR parsing (ACME finalize) ------------------------------------------------

/// Largest CSR the ACME finalize endpoint accepts.
pub const MAX_CSR_DER_BYTES: usize = 64 * 1024;

/// A verified PKCS#10 certificate signing request from an ACME finalize request.
///
/// The CSR's self-signature has been checked against the public key it carries, so a caller may
/// safely treat `spki_der` as the certificate key the client proved possession of. Identifiers are
/// only extracted from the subjectAltName extension (RFC 8555 authorises by SAN); a CSR without
/// SANs therefore yields an empty `names` list and a caller comparing against the order
/// identifiers rejects it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCsr {
    /// DER-encoded SubjectPublicKeyInfo exactly as it appears in the CSR.
    pub spki_der: Vec<u8>,
    /// Normalised `dNSName` and `iPAddress` identifiers from the subjectAltName extension.
    pub names: Vec<String>,
    /// Whether the subjectAltName extension carried an entry other than a DNS name or IP address
    /// (email, URI, ...), which RFC 8555 orders cannot authorise.
    pub unsupported_names: bool,
}

/// Parse and verify a DER-encoded PKCS#10 `CertificationRequest`.
///
/// Supported signature algorithms are the ones a real ACME client emits: ECDSA P-256/P-384 with
/// SHA-256/SHA-384, RSA PKCS#1 v1.5 with SHA-256/SHA-384 (2048-8192 bit keys) and Ed25519.
/// Anything else, a malformed structure, or a bad signature is a located
/// [`AcmeError::CertificateRequest`] error.
pub fn parse_csr(der: &[u8]) -> Result<ParsedCsr> {
    if der.is_empty() {
        return Err(csr_error("certificate signing request is empty"));
    }
    if der.len() > MAX_CSR_DER_BYTES {
        return Err(csr_error(format!(
            "certificate signing request is {} bytes, exceeding the {MAX_CSR_DER_BYTES}-byte limit",
            der.len()
        )));
    }

    let (tag, body, consumed) = read_der(der)?;
    if tag != 0x30 || consumed != der.len() {
        return Err(csr_error(
            "certificate signing request must be a single DER SEQUENCE",
        ));
    }

    // CertificationRequestInfo ::= SEQUENCE { version, subject, subjectPKInfo, attributes }
    let (info_tag, info, info_len) = read_der(body)?;
    if info_tag != 0x30 {
        return Err(csr_error("CertificationRequestInfo must be a SEQUENCE"));
    }
    let signature_input = &body[..info_len];

    let (algorithm_tag, algorithm, algorithm_len) = read_der(&body[info_len..])?;
    if algorithm_tag != 0x30 {
        return Err(csr_error("signatureAlgorithm must be a SEQUENCE"));
    }
    let (signature_tag, signature_bits, _) = read_der(&body[info_len + algorithm_len..])?;
    if signature_tag != 0x03 || signature_bits.len() < 2 || signature_bits[0] != 0 {
        return Err(csr_error("CSR signature must be a DER BIT STRING"));
    }
    let signature = &signature_bits[1..];

    let mut offset = 0usize;
    let (version_tag, version, version_len) = read_der(info)?;
    if version_tag != 0x02 || version != [0u8].as_slice() {
        return Err(csr_error("CSR version must be INTEGER 0"));
    }
    offset += version_len;
    let (subject_tag, _subject, subject_len) = read_der(&info[offset..])?;
    if subject_tag != 0x30 {
        return Err(csr_error("CSR subject must be a SEQUENCE"));
    }
    offset += subject_len;
    let (spki_tag, _spki, spki_len) = read_der(&info[offset..])?;
    if spki_tag != 0x30 {
        return Err(csr_error("CSR subjectPKInfo must be a SEQUENCE"));
    }
    let spki_der = info[offset..offset + spki_len].to_vec();
    offset += spki_len;

    let mut names = Vec::new();
    let mut unsupported_names = false;
    if offset < info.len() {
        let (attributes_tag, attributes, _) = read_der(&info[offset..])?;
        if attributes_tag != 0xA0 {
            return Err(csr_error("CSR attributes must be a [0] IMPLICIT SET"));
        }
        parse_csr_attributes(attributes, &mut names, &mut unsupported_names)?;
    }

    verify_csr_signature(algorithm, &spki_der, signature_input, signature)?;

    Ok(ParsedCsr {
        spki_der,
        names,
        unsupported_names,
    })
}

fn csr_error(message: impl Into<String>) -> crate::Error {
    AcmeError::CertificateRequest(message.into()).into()
}

/// Read one DER TLV. Returns `(tag, content, consumed)`; `consumed` includes the header so callers
/// can splice the exact original bytes back out.
fn read_der(input: &[u8]) -> Result<(u8, &[u8], usize)> {
    let tag = *input
        .first()
        .ok_or_else(|| csr_error("truncated DER: missing tag"))?;
    let first = *input
        .get(1)
        .ok_or_else(|| csr_error("truncated DER: missing length"))?;
    let (length, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(csr_error("invalid DER length encoding"));
        }
        if input.len() < 2 + count {
            return Err(csr_error("truncated DER length"));
        }
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    let end = header
        .checked_add(length)
        .ok_or_else(|| csr_error("DER length overflow"))?;
    if input.len() < end {
        return Err(csr_error("truncated DER content"));
    }
    Ok((tag, &input[header..end], end))
}

/// Parse `attributes [0] IMPLICIT SET OF Attribute` looking for the PKCS#9 extensionRequest.
fn parse_csr_attributes(
    attributes: &[u8],
    names: &mut Vec<String>,
    unsupported_names: &mut bool,
) -> Result<()> {
    let mut rest = attributes;
    while !rest.is_empty() {
        let (tag, attribute, consumed) = read_der(rest)?;
        if tag != 0x30 {
            return Err(csr_error("CSR attribute must be a SEQUENCE"));
        }
        let (oid_tag, oid, oid_len) = read_der(attribute)?;
        if oid_tag != 0x06 {
            return Err(csr_error("CSR attribute type must be an OBJECT IDENTIFIER"));
        }
        let (values_tag, values, _) = read_der(&attribute[oid_len..])?;
        if values_tag != 0x31 {
            return Err(csr_error("CSR attribute values must be a SET"));
        }
        if oid == der_oid_content(OID_EXTENSION_REQUEST) {
            let (extensions_tag, extensions, _) = read_der(values)?;
            if extensions_tag != 0x30 {
                return Err(csr_error(
                    "extensionRequest must wrap an Extensions SEQUENCE",
                ));
            }
            parse_csr_extensions(extensions, names, unsupported_names)?;
        }
        rest = &rest[consumed..];
    }
    Ok(())
}

/// Parse `Extensions ::= SEQUENCE OF Extension` and collect subjectAltName entries.
fn parse_csr_extensions(
    mut extensions: &[u8],
    names: &mut Vec<String>,
    unsupported_names: &mut bool,
) -> Result<()> {
    while !extensions.is_empty() {
        let (tag, extension, consumed) = read_der(extensions)?;
        if tag != 0x30 {
            return Err(csr_error("X.509 extension must be a SEQUENCE"));
        }
        let (oid_tag, oid, oid_len) = read_der(extension)?;
        if oid_tag != 0x06 {
            return Err(csr_error("X.509 extension id must be an OBJECT IDENTIFIER"));
        }
        let mut offset = oid_len;
        let (value_tag, _value, value_len) = read_der(&extension[offset..])?;
        if value_tag == 0x01 {
            // critical BOOLEAN DEFAULT FALSE
            offset += value_len;
        }
        let (octets_tag, octets, _) = read_der(&extension[offset..])?;
        if octets_tag != 0x04 {
            return Err(csr_error("X.509 extension value must be an OCTET STRING"));
        }
        if oid == der_oid_content(OID_SUBJECT_ALT_NAME) {
            parse_subject_alt_name(octets, names, unsupported_names)?;
        }
        extensions = &extensions[consumed..];
    }
    Ok(())
}

fn parse_subject_alt_name(
    der: &[u8],
    names: &mut Vec<String>,
    unsupported_names: &mut bool,
) -> Result<()> {
    let (tag, general_names, consumed) = read_der(der)?;
    if tag != 0x30 || consumed != der.len() {
        return Err(csr_error("subjectAltName must be a single SEQUENCE"));
    }
    let mut rest = general_names;
    while !rest.is_empty() {
        let (name_tag, content, consumed) = read_der(rest)?;
        match name_tag {
            // dNSName [2] IA5String
            0x82 => {
                let name = std::str::from_utf8(content)
                    .map_err(|_| csr_error("subjectAltName dNSName is not valid ASCII"))?;
                let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
                if !name.is_empty() && !names.contains(&name) {
                    names.push(name);
                }
            }
            // iPAddress [7] OCTET STRING
            0x87 => {
                let address = match content.len() {
                    4 => std::net::Ipv4Addr::new(content[0], content[1], content[2], content[3])
                        .to_string(),
                    16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(content);
                        std::net::Ipv6Addr::from(octets).to_string()
                    }
                    _ => return Err(csr_error("subjectAltName iPAddress must be 4 or 16 bytes")),
                };
                if !names.contains(&address) {
                    names.push(address);
                }
            }
            // Other GeneralName forms (email, URI, ...) are not ACME identifiers; the caller
            // rejects such a CSR (smallstep's `Order.sans` does the same).
            _ => *unsupported_names = true,
        }
        rest = &rest[consumed..];
    }
    Ok(())
}

/// Verify the CSR self-signature with the public key carried inside the CSR.
fn verify_csr_signature(
    algorithm: &[u8],
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let (oid_tag, oid, oid_len) = read_der(algorithm)?;
    if oid_tag != 0x06 {
        return Err(csr_error(
            "CSR signature algorithm must be an OBJECT IDENTIFIER",
        ));
    }
    if oid_len != algorithm.len() {
        // Parameters are allowed (RSA NULL, ECDSA absent); ignore them only when present.
        let (parameters_tag, _, _) = read_der(&algorithm[oid_len..])?;
        if parameters_tag != 0x05 && parameters_tag != 0x30 {
            return Err(csr_error("unexpected CSR signature algorithm parameters"));
        }
    }

    let public_key = subject_public_key_bytes(spki_der)?;
    let verified = if oid == der_oid_content(OID_ECDSA_WITH_SHA256) {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
            .verify(message, signature)
            .is_ok()
    } else if oid == der_oid_content(OID_ECDSA_WITH_SHA384) {
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_key)
            .verify(message, signature)
            .is_ok()
    } else if oid == der_oid_content(OID_SHA256_WITH_RSA) {
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key)
            .verify(message, signature)
            .is_ok()
    } else if oid == der_oid_content(OID_SHA384_WITH_RSA) {
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, public_key)
            .verify(message, signature)
            .is_ok()
    } else if oid == der_oid_content(OID_ED25519) {
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .is_ok()
    } else {
        return Err(csr_error(
            "unsupported CSR signature algorithm (expected ECDSA-SHA256/SHA384, RSA-SHA256/SHA384 or Ed25519)",
        ));
    };
    if !verified {
        return Err(csr_error("CSR signature verification failed"));
    }
    Ok(())
}

/// Extract the key bit string from a SubjectPublicKeyInfo.
fn subject_public_key_bytes(spki_der: &[u8]) -> Result<&[u8]> {
    let (tag, body, consumed) = read_der(spki_der)?;
    if tag != 0x30 || consumed != spki_der.len() {
        return Err(csr_error("SubjectPublicKeyInfo must be a SEQUENCE"));
    }
    let (algorithm_tag, _algorithm, algorithm_len) = read_der(body)?;
    if algorithm_tag != 0x30 {
        return Err(csr_error(
            "SubjectPublicKeyInfo algorithm must be a SEQUENCE",
        ));
    }
    let (bits_tag, bits, _) = read_der(&body[algorithm_len..])?;
    if bits_tag != 0x03 || bits.len() < 2 || bits[0] != 0 {
        return Err(csr_error(
            "SubjectPublicKeyInfo must carry a BIT STRING key",
        ));
    }
    Ok(&bits[1..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::UnparsedPublicKey;

    const RSA_4096_CERT_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
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
EVdZ8IcAQzAPk1jBxj0YDC0rR5d09Q==
-----END PRIVATE KEY-----
"#;

    /// Verify a CSR signature with the key type's public key.
    fn verify_csr_any(csr: &CertificateRequest) -> bool {
        let (tag, body, _) = read_tlv(csr.der());
        assert_eq!(tag, 0x30);
        let (info_tag, _info, info_len) = read_tlv(body);
        assert_eq!(info_tag, 0x30);
        let tbs = &body[..info_len];
        let mut offset = info_len;
        let (_, _, consumed) = read_tlv(&body[offset..]);
        offset += consumed;
        let (sig_tag, sig_content, _) = read_tlv(&body[offset..]);
        assert_eq!(sig_tag, 0x03);
        let signature = &sig_content[1..];
        match csr.key_type() {
            CertificateKeyType::P256 => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, csr.public_key_bytes())
                    .verify(tbs, signature)
                    .is_ok()
            }
            CertificateKeyType::P384 => {
                UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, csr.public_key_bytes())
                    .verify(tbs, signature)
                    .is_ok()
            }
            CertificateKeyType::Rsa2048 | CertificateKeyType::Rsa4096 => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                use rsa::pkcs1v15::{Signature, VerifyingKey};
                use rsa::signature::Verifier;
                let public_key = rsa::RsaPublicKey::from_pkcs1_der(csr.public_key_bytes())
                    .expect("RSA public key DER");
                let verifying_key = VerifyingKey::<sha2::Sha256>::new(public_key);
                match Signature::try_from(signature) {
                    Ok(signature) => verifying_key.verify(tbs, &signature).is_ok(),
                    Err(_) => false,
                }
            }
        }
    }

    fn assert_csr_contents(csr: &CertificateRequest) {
        assert_eq!(csr.domains()[0], "example.com");
        assert!(lookup(csr.der(), b"www.example.com").is_some());
        let cn = &[0x06, 0x03, 0x55, 0x04, 0x03];
        assert!(lookup(csr.der(), cn).is_some(), "CN attribute present");
        let der = crate::storage::private_key_der(csr.private_key_pem()).unwrap();
        assert_eq!(
            CertificateKeyType::from_private_key_der(&der).unwrap(),
            csr.key_type()
        );
    }

    #[test]
    fn generates_csrs_for_each_supported_key_type() {
        let domains = vec!["example.com".to_string(), "www.example.com".to_string()];
        for key_type in [
            CertificateKeyType::P256,
            CertificateKeyType::P384,
            CertificateKeyType::Rsa2048,
        ] {
            let csr = CertificateRequest::generate_with_key_type(&domains, key_type).unwrap();
            assert_eq!(csr.key_type(), key_type);
            assert!(
                csr.private_key_pem().starts_with(
                    "-----BEGIN PRIVATE KEY-----
"
                ),
                "{key_type:?}: PKCS#8 certificate key"
            );
            assert!(verify_csr_any(&csr), "{key_type:?}");
            assert_csr_contents(&csr);
        }

        // RSA-4096 generation is too slow for the test suite; a pre-generated key exercises the
        // same signing/SPKI path and the configured key type.
        use rsa::pkcs8::DecodePrivateKey;
        let rsa_4096 = rsa::RsaPrivateKey::from_pkcs8_pem(RSA_4096_CERT_KEY_PEM).unwrap();
        let csr = CertificateRequest::generate_rsa_with_key(
            &domains,
            CertificateKeyType::Rsa4096,
            rsa_4096,
        )
        .unwrap();
        assert_eq!(csr.key_type(), CertificateKeyType::Rsa4096);
        assert!(verify_csr_any(&csr));
        assert_csr_contents(&csr);
    }

    #[test]
    fn certificate_key_type_parse_is_located_and_rejects_ed25519() {
        for (value, expected) in [
            ("p256", CertificateKeyType::P256),
            ("P384", CertificateKeyType::P384),
            ("rsa2048", CertificateKeyType::Rsa2048),
            ("rsa4096", CertificateKeyType::Rsa4096),
        ] {
            assert_eq!(CertificateKeyType::parse(value).unwrap(), expected);
        }
        let error = CertificateKeyType::parse("ed25519").unwrap_err();
        assert!(error.to_string().contains("ed25519"), "{error}");
        assert!(
            error.to_string().contains("p256, p384, rsa2048, rsa4096"),
            "{error}"
        );
        let error = CertificateKeyType::parse("bogus").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unknown certificate key type `bogus`"),
            "{error}"
        );
    }

    /// One DER TLV: `(tag, content, total_encoded_len)`.
    fn read_tlv(input: &[u8]) -> (u8, &[u8], usize) {
        assert!(input.len() >= 2, "truncated DER");
        let tag = input[0];
        let first = input[1];
        let (length, header) = if first & 0x80 == 0 {
            (first as usize, 2)
        } else {
            let count = (first & 0x7f) as usize;
            assert!(count > 0 && input.len() >= 2 + count, "bad DER length");
            let mut length = 0usize;
            for byte in &input[2..2 + count] {
                length = (length << 8) | *byte as usize;
            }
            (length, 2 + count)
        };
        assert!(input.len() >= header + length, "truncated DER content");
        (tag, &input[header..header + length], header + length)
    }

    fn lookup<'a>(der: &'a [u8], needle: &[u8]) -> Option<&'a [u8]> {
        der.windows(needle.len())
            .position(|window| window == needle)
            .map(|position| &der[position..position + needle.len()])
    }

    fn verify_csr(csr: &CertificateRequest) -> bool {
        let (tag, body, _) = read_tlv(csr.der());
        assert_eq!(tag, 0x30, "CertificationRequest must be a SEQUENCE");
        let (info_tag, _info, info_len) = read_tlv(body);
        assert_eq!(
            info_tag, 0x30,
            "CertificationRequestInfo must be a SEQUENCE"
        );
        let tbs = &body[..info_len];
        let (alg_tag, _alg, alg_len) = read_tlv(&body[info_len..]);
        assert_eq!(alg_tag, 0x30);
        let (sig_tag, sig_content, _) = read_tlv(&body[info_len + alg_len..]);
        assert_eq!(sig_tag, 0x03);
        let signature = &sig_content[1..]; // strip "unused bits" octet
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, csr.public_key_bytes());
        public_key.verify(tbs, signature).is_ok()
    }

    #[test]
    fn generates_verifiable_csr_with_sans_and_cn() {
        let csr = CertificateRequest::generate(&[
            "Example.COM.".to_string(),
            "www.example.com".to_string(),
            "*.example.com".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        assert_eq!(
            csr.domains(),
            &[
                "example.com".to_string(),
                "www.example.com".to_string(),
                "*.example.com".to_string(),
                "127.0.0.1".to_string()
            ]
        );
        assert!(csr
            .private_key_pem()
            .starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(
            verify_csr(&csr),
            "CSR signature must verify with its public key"
        );

        // SAN general names: DNS names are [2] IA5String, IP addresses are [7] OCTET STRING.
        assert!(lookup(csr.der(), b"example.com").is_some());
        assert!(lookup(csr.der(), b"www.example.com").is_some());
        assert!(lookup(csr.der(), b"*.example.com").is_some());
        assert!(lookup(csr.der(), &[0x87, 0x04, 127, 0, 0, 1]).is_some());

        // Subject commonName attribute is present for the first domain.
        let cn = &[0x06, 0x03, 0x55, 0x04, 0x03];
        assert!(lookup(csr.der(), cn).is_some());
        assert!(
            lookup(csr.der(), &[0x0C, 11]).is_some() || lookup(csr.der(), b"example.com").is_some()
        );

        // The CSR key is a P-256 PKCS#8 key that the account-key loader also understands.
        let key = super::super::AccountKey::from_pkcs8_pem(csr.private_key_pem()).unwrap();
        assert_eq!(key.public_key_bytes(), csr.public_key_bytes());

        // Tampering with the CertificationRequestInfo breaks the signature.
        let mut tampered = csr.clone();
        let position = tampered.der.len() / 2;
        tampered.der[position] ^= 0xff;
        assert!(!verify_csr(&tampered));
    }

    #[test]
    fn includes_ipv6_ip_address_general_name() {
        let csr = CertificateRequest::generate(&["::1".to_string()]).unwrap();
        let ipv6 = std::net::Ipv6Addr::LOCALHOST.octets();
        let mut expected = vec![0x87, 16];
        expected.extend(ipv6);
        assert!(lookup(csr.der(), &expected).is_some());
        assert!(verify_csr(&csr));
    }

    #[test]
    fn parses_and_verifies_generated_csrs() {
        let csr = CertificateRequest::generate(&[
            "Example.COM.".to_string(),
            "www.example.com".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        let parsed = parse_csr(csr.der()).expect("valid CSR parses");
        assert_eq!(
            parsed.names,
            vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
                "127.0.0.1".to_string()
            ]
        );
        assert!(!parsed.spki_der.is_empty());
        // The extracted SPKI is the key the CA signs for, so its BIT STRING wraps the same key.
        assert_eq!(
            subject_public_key_bytes(&parsed.spki_der).unwrap(),
            csr.public_key_bytes()
        );

        let ipv6 = CertificateRequest::generate(&["::1".to_string()]).unwrap();
        let parsed = parse_csr(ipv6.der()).unwrap();
        assert_eq!(parsed.names, vec!["::1".to_string()]);
    }

    #[test]
    fn parses_csrs_for_each_supported_key_type() {
        for key_type in [
            CertificateKeyType::P256,
            CertificateKeyType::P384,
            CertificateKeyType::Rsa2048,
        ] {
            let csr =
                CertificateRequest::generate_with_key_type(&["key.example".to_string()], key_type)
                    .unwrap();
            let parsed = parse_csr(csr.der())
                .unwrap_or_else(|error| panic!("{key_type:?} CSR rejected: {error}"));
            assert_eq!(parsed.names, vec!["key.example".to_string()]);
        }
    }

    #[test]
    fn rejects_csr_with_bad_signature_or_structure() {
        let mut csr = CertificateRequest::generate(&["tampered.example".to_string()]).unwrap();
        let last = csr.der.len() - 1;
        csr.der[last] ^= 0x01;
        let error = parse_csr(csr.der()).expect_err("tampered signature must be rejected");
        assert!(
            error.to_string().contains("signature verification failed"),
            "{error}"
        );

        let mut truncated = CertificateRequest::generate(&["short.example".to_string()]).unwrap();
        truncated.der.truncate(truncated.der.len() / 2);
        assert!(parse_csr(&truncated.der).is_err());

        let error = parse_csr(&[]).expect_err("empty CSR must be rejected");
        assert!(error.to_string().contains("empty"), "{error}");
        let oversized = vec![0x30; MAX_CSR_DER_BYTES + 1];
        let error = parse_csr(&oversized).expect_err("oversized CSR must be rejected");
        assert!(error.to_string().contains("exceeding"), "{error}");
    }

    #[test]
    fn flags_subject_alt_name_entries_that_are_not_dns_or_ip() {
        // GeneralName email [1] is not an ACME identifier; the parser must flag it so finalize
        // rejects the CSR instead of silently issuing without the requested name.
        let san = der_sequence(&[
            der_tlv(0x81, b"user@example.com"),
            der_tlv(0x82, b"example.com"),
        ]);
        let mut names = Vec::new();
        let mut unsupported = false;
        parse_subject_alt_name(&san, &mut names, &mut unsupported).expect("SAN parses");
        assert_eq!(names, vec!["example.com".to_string()]);
        assert!(unsupported, "email SAN must be flagged as unsupported");

        let mut names = Vec::new();
        let mut unsupported = false;
        parse_subject_alt_name(
            &der_sequence(&[der_tlv(0x82, b"example.com")]),
            &mut names,
            &mut unsupported,
        )
        .expect("DNS-only SAN parses");
        assert_eq!(names, vec!["example.com".to_string()]);
        assert!(!unsupported);
    }

    #[test]
    fn rejects_empty_and_duplicate_domains() {
        let error = CertificateRequest::generate(&[]).unwrap_err();
        assert!(error.to_string().contains("at least one domain"), "{error}");
        let error = CertificateRequest::generate(&["   ".to_string()]).unwrap_err();
        assert!(error.to_string().contains("must not be empty"), "{error}");
        let csr = CertificateRequest::generate(&["a.example".to_string(), "A.Example".to_string()])
            .unwrap();
        assert_eq!(csr.domains(), &["a.example".to_string()]);
    }

    #[test]
    fn der_helpers_encode_reference_values() {
        // INTEGER 0 and the RFC 5280 OIDs used above.
        assert_eq!(der_integer(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(der_oid(OID_COMMON_NAME), vec![0x06, 0x03, 0x55, 0x04, 0x03]);
        assert_eq!(
            der_oid(OID_SUBJECT_ALT_NAME),
            vec![0x06, 0x03, 0x55, 0x1D, 0x11]
        );
        assert_eq!(
            der_oid(OID_EC_PUBLIC_KEY),
            vec![0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
        );
        assert_eq!(
            der_oid(OID_PRIME256V1),
            vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        );
        assert_eq!(
            der_oid(OID_ECDSA_WITH_SHA256),
            vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
        );
        assert_eq!(
            der_oid(OID_EXTENSION_REQUEST),
            vec![0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E]
        );
        // Long-form lengths (content > 127 bytes).
        assert_eq!(der_length(127), vec![127]);
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(300), vec![0x82, 0x01, 0x2C]);
    }
}
