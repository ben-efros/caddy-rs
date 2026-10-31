//! PKCS#10 certificate signing requests for ACME finalization.
//!
//! RFC 8555 finalization takes a base64url-encoded DER `CertificationRequest`. The workspace's
//! offline registry cache has no CSR-construction crate (rcgen/x509-cert are absent), so this
//! module builds the small, fixed DER structure by hand and signs it with the same `ring` backend
//! used for account keys:
//!
//! * fresh ECDSA P-256 certificate key per request (the account key is never reused);
//! * subject: empty except a `commonName` of the first domain (ACME CAs authorise by SAN);
//! * subjectAltName extension with `dNSName` entries for DNS identifiers and `iPAddress`
//!   entries for IP identifiers, wrapped in the `extensionRequest` attribute;
//! * ECDSA-with-SHA256 signature (`ECDSA_P256_SHA256_ASN1_SIGNING`).
//!
//! The private key is returned as PKCS#8 PEM next to the CSR so the caller can store it with the
//! certificate it receives.

use std::net::IpAddr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use super::AcmeError;
use crate::Result;

/// ASN.1 DER `OBJECT IDENTIFIER` encodings used by PKCS#10 and X.509.
const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
const OID_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];

/// A generated certificate signing request and its private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    der: Vec<u8>,
    private_key_pem: String,
    public_key: Vec<u8>,
    domains: Vec<String>,
}

impl CertificateRequest {
    /// Generate a CSR for `domains` (DNS names and/or IP addresses) with a fresh P-256 key.
    pub fn generate(domains: &[String]) -> Result<Self> {
        let domains = normalize_domains(domains)?;
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(
            |error| AcmeError::CertificateRequest(format!("generating P-256 key: {error}")),
        )?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .map_err(|error| {
                    AcmeError::CertificateRequest(format!("reloading generated P-256 key: {error}"))
                })?;
        let public_key = key_pair.public_key().as_ref().to_vec();

        let certification_request_info = certification_request_info(&domains, &public_key)?;
        let signature = key_pair
            .sign(&rng, &certification_request_info)
            .map_err(|error| {
                AcmeError::CertificateRequest(format!("signing certification request: {error}"))
            })?;

        let der = der_sequence(&[
            certification_request_info,
            der_sequence(&[der_oid(OID_ECDSA_WITH_SHA256)]),
            der_bit_string(signature.as_ref()),
        ]);

        Ok(Self {
            der,
            private_key_pem: pem_encode("PRIVATE KEY", pkcs8.as_ref()),
            public_key,
            domains,
        })
    }

    /// DER-encoded `CertificationRequest`.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The CSR's private key in PKCS#8 PEM form.
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    /// The CSR's public key (uncompressed P-256 point: `0x04 || X || Y`).
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

fn certification_request_info(domains: &[String], public_key: &[u8]) -> Result<Vec<u8>> {
    let subject = subject_with_common_name(&domains[0]);
    // SubjectPublicKeyInfo for an id-ecPublicKey / prime256v1 key.
    let algorithm = der_sequence(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)]);
    let spki = der_sequence(&[algorithm, der_bit_string(public_key)]);

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

fn der_oid(arcs: &[u64]) -> Vec<u8> {
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
    der_tlv(0x06, &content)
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

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

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
