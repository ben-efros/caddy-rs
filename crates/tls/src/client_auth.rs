//! Verified/unverified client-certificate metadata for Caddy's
//! `{http.request.tls.client.*}` placeholders (T-TLS-072).
//!
//! Caddy v2.11.9 exposes the presented client certificate (its first
//! `PeerCertificates` entry) through the HTTP replacer:
//! `client.fingerprint`, `client.public_key`, `client.public_key_sha256`,
//! `client.certificate_pem`, `client.certificate_der_base64`, `client.issuer`,
//! `client.serial`, `client.subject`, and `client.san.{dns_names,emails,ips,uris}[.N]`
//! (`external/caddy/modules/caddyhttp/replacer.go` client-cert branch and
//! `external/caddy/modules/caddyhttp/app.go` docs). There are no `*In` variants in
//! v2.11.9; the TLS-side API here carries an explicit `verified` flag plus both the
//! presented (unverified) and verified leaf so a server/http hook can expose either.
//!
//! The HTTP placeholder engine still rejects `http.request.tls.*`; wiring this data into the
//! request context is the reported server/http hook (see the task report).

use std::collections::BTreeMap;

use rustls::pki_types::CertificateDer;

/// Client-certificate field extraction errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientCertificateInfoError {
    /// The DER certificate is truncated or not a certificate SEQUENCE.
    #[error("malformed client certificate DER: {0}")]
    Malformed(String),
}

/// Metadata for one presented/verified client certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificateInfo {
    /// DER-encoded leaf certificate.
    pub der: Vec<u8>,
    /// Subject distinguished name, Go `x509.Name.String()` style (`CN=x,O=y`).
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number in decimal (Go's `big.Int.String()`), matching Caddy's placeholder.
    pub serial: String,
    /// Subject alternative DNS names.
    pub dns_names: Vec<String>,
    /// Subject alternative email addresses.
    pub emails: Vec<String>,
    /// Subject alternative IP addresses.
    pub ip_addresses: Vec<String>,
    /// Subject alternative URIs.
    pub uris: Vec<String>,
    /// SHA-256 fingerprint of the DER certificate, lowercase hex.
    pub fingerprint: String,
    /// DER-encoded SubjectPublicKeyInfo.
    pub public_key_der: Vec<u8>,
    /// SHA-256 of `public_key_der`, lowercase hex.
    pub public_key_sha256: String,
    /// Whether the chain was verified by the configured client-auth verifier. Caddy's
    /// `PeerCertificates[0]` is the presented leaf; for verifying modes it was also checked.
    pub verified: bool,
}

impl ClientCertificateInfo {
    /// Parse a DER leaf certificate.
    pub fn parse(der: &[u8], verified: bool) -> Result<Self, ClientCertificateInfoError> {
        parse_certificate(der, verified)
    }

    /// PEM encoding of the leaf certificate (`client.certificate_pem`).
    pub fn certificate_pem(&self) -> String {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    /// Base64 DER encoding (`client.certificate_der_base64`).
    pub fn certificate_der_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&self.der)
    }

    /// Caddy placeholder values for `http.request.tls.client.*` (without the `*In` variants,
    /// which Caddy v2.11.9 does not define).
    ///
    /// SAN list fields are exposed without an index (whole list, comma-joined) and with numeric
    /// indexes (`san.dns_names.0`, ...), matching Caddy's replacer.
    pub fn placeholders(&self) -> BTreeMap<String, String> {
        let mut values = BTreeMap::new();
        values.insert("subject".to_string(), self.subject.clone());
        values.insert("issuer".to_string(), self.issuer.clone());
        values.insert("serial".to_string(), self.serial.clone());
        values.insert("fingerprint".to_string(), self.fingerprint.clone());
        values.insert("certificate_pem".to_string(), self.certificate_pem());
        values.insert(
            "certificate_der_base64".to_string(),
            self.certificate_der_base64(),
        );
        values.insert("public_key".to_string(), hex::encode(&self.public_key_der));
        values.insert(
            "public_key_sha256".to_string(),
            self.public_key_sha256.clone(),
        );
        for (name, list) in [
            ("san.dns_names", &self.dns_names),
            ("san.emails", &self.emails),
            ("san.ips", &self.ip_addresses),
            ("san.uris", &self.uris),
        ] {
            values.insert(name.to_string(), list.join(","));
            for (index, value) in list.iter().enumerate() {
                values.insert(format!("{name}.{index}"), value.clone());
            }
        }
        values
    }
}

/// Parse every presented client certificate in chain order.
pub fn client_certificate_infos(
    peer_certificates: Option<&[CertificateDer<'_>]>,
    verified: bool,
) -> Result<Vec<ClientCertificateInfo>, ClientCertificateInfoError> {
    match peer_certificates {
        Some(certificates) if !certificates.is_empty() => certificates
            .iter()
            .map(|certificate| ClientCertificateInfo::parse(certificate.as_ref(), verified))
            .collect(),
        _ => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------------------------
// Minimal X.509 DER parsing (only what the placeholders need)
// ---------------------------------------------------------------------------------------------

fn malformed(message: impl Into<String>) -> ClientCertificateInfoError {
    ClientCertificateInfoError::Malformed(message.into())
}

fn read_tlv<'a>(
    bytes: &'a [u8],
    position: usize,
) -> Result<(u8, &'a [u8], &'a [u8], usize), ClientCertificateInfoError> {
    let tag = *bytes
        .get(position)
        .ok_or_else(|| malformed("truncated DER tag"))?;
    let mut offset = position + 1;
    let first = *bytes
        .get(offset)
        .ok_or_else(|| malformed("truncated DER length"))?;
    offset += 1;
    let length = if first < 0x80 {
        first as usize
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(malformed("unsupported DER length"));
        }
        let mut length = 0usize;
        for _ in 0..count {
            let byte = *bytes
                .get(offset)
                .ok_or_else(|| malformed("truncated DER length bytes"))?;
            offset += 1;
            length = (length << 8) | byte as usize;
        }
        length
    };
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| malformed("truncated DER value"))?;
    Ok((tag, &bytes[offset..end], &bytes[position..end], end))
}

fn expect_tag<'a>(
    bytes: &'a [u8],
    position: usize,
    expected: u8,
    context: &str,
) -> Result<(&'a [u8], &'a [u8], usize), ClientCertificateInfoError> {
    let (tag, value, full, end) = read_tlv(bytes, position)?;
    if tag != expected {
        return Err(malformed(format!(
            "{context}: expected tag 0x{expected:02x}, got 0x{tag:02x}"
        )));
    }
    Ok((value, full, end))
}

fn parse_certificate(
    der: &[u8],
    verified: bool,
) -> Result<ClientCertificateInfo, ClientCertificateInfoError> {
    let (certificate, _, _) = expect_tag(der, 0, 0x30, "certificate")?;
    let (tbs, _, _) = expect_tag(certificate, 0, 0x30, "tbsCertificate")?;
    let mut position = 0;
    let mut tag = read_tlv(tbs, position)?.0;
    if tag == 0xA0 {
        position = read_tlv(tbs, position)?.3;
        tag = read_tlv(tbs, position)?.0;
    }
    if tag != 0x02 {
        return Err(malformed("serialNumber is not an INTEGER"));
    }
    let (serial_bytes, _, next) = expect_tag(tbs, position, 0x02, "serialNumber")?;
    position = next;
    // signature AlgorithmIdentifier
    position = read_tlv(tbs, position)?.3;
    let (issuer_raw, _, next) = expect_tag(tbs, position, 0x30, "issuer")?;
    let issuer = format_name(issuer_raw)?;
    position = next;
    // validity
    position = read_tlv(tbs, position)?.3;
    let (subject_raw, _, next) = expect_tag(tbs, position, 0x30, "subject")?;
    let subject = format_name(subject_raw)?;
    position = next;
    let (spki, _, next) = expect_tag(tbs, position, 0x30, "subjectPublicKeyInfo")?;
    let public_key_der = collection_full_der(tbs, position).unwrap_or_default();
    let _ = spki;
    position = next;
    let mut dns_names = Vec::new();
    let mut emails = Vec::new();
    let mut ip_addresses = Vec::new();
    let mut uris = Vec::new();
    while position < tbs.len() {
        let (tag, value, _, next) = read_tlv(tbs, position)?;
        if tag == 0xA3 {
            parse_extensions(
                value,
                &mut dns_names,
                &mut emails,
                &mut ip_addresses,
                &mut uris,
            )?;
        }
        position = next;
    }
    let fingerprint = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(der))
    };
    let public_key_sha256 = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&public_key_der))
    };
    Ok(ClientCertificateInfo {
        der: der.to_vec(),
        subject,
        issuer,
        serial: decimal_serial(serial_bytes),
        dns_names,
        emails,
        ip_addresses,
        uris,
        fingerprint,
        public_key_der,
        public_key_sha256,
        verified,
    })
}

fn collection_full_der(bytes: &[u8], position: usize) -> Option<Vec<u8>> {
    read_tlv(bytes, position)
        .ok()
        .map(|(_, _, full, _)| full.to_vec())
}

const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];
const OID_COUNTRY: &[u64] = &[2, 5, 4, 6];
const OID_LOCALITY: &[u64] = &[2, 5, 4, 7];
const OID_STATE: &[u64] = &[2, 5, 4, 8];
const OID_ORGANIZATION: &[u64] = &[2, 5, 4, 10];
const OID_ORGANIZATIONAL_UNIT: &[u64] = &[2, 5, 4, 11];
const OID_EMAIL: &[u64] = &[1, 2, 840, 113549, 1, 9, 1];
const OID_SAN: &[u64] = &[2, 5, 29, 17];

fn parse_oid(value: &[u8]) -> Vec<u64> {
    let Some(first) = value.first() else {
        return Vec::new();
    };
    let mut arcs = vec![(*first / 40) as u64, (*first % 40) as u64];
    let mut current = 0u64;
    for byte in &value[1..] {
        current = (current << 7) | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            arcs.push(current);
            current = 0;
        }
    }
    arcs
}

fn format_name(rdn_sequence: &[u8]) -> Result<String, ClientCertificateInfoError> {
    let mut position = 0;
    let mut parts = Vec::new();
    while position < rdn_sequence.len() {
        let (set_tag, set, _, next) = read_tlv(rdn_sequence, position)?;
        if set_tag != 0x31 {
            return Err(malformed("RDN is not a SET"));
        }
        let mut inner = 0;
        while inner < set.len() {
            let (tag, attribute, _, attribute_end) = read_tlv(set, inner)?;
            if tag != 0x30 {
                return Err(malformed("AttributeTypeAndValue is not a SEQUENCE"));
            }
            let (oid_tag, oid_value, _, value_start) = read_tlv(attribute, 0)?;
            if oid_tag != 0x06 {
                return Err(malformed("attribute OID is not an OBJECT IDENTIFIER"));
            }
            let oid = parse_oid(oid_value);
            let (_, text_value, _, _) = read_tlv(attribute, value_start)?;
            let text = String::from_utf8_lossy(text_value).into_owned();
            let name = match oid.as_slice() {
                OID_COMMON_NAME => "CN",
                OID_COUNTRY => "C",
                OID_LOCALITY => "L",
                OID_STATE => "ST",
                OID_ORGANIZATION => "O",
                OID_ORGANIZATIONAL_UNIT => "OU",
                OID_EMAIL => "emailAddress",
                _ => "",
            };
            if !name.is_empty() {
                parts.push(format!("{name}={text}"));
            }
            inner = attribute_end;
        }
        position = next;
    }
    Ok(parts.join(","))
}

fn parse_extensions(
    extensions: &[u8],
    dns_names: &mut Vec<String>,
    emails: &mut Vec<String>,
    ip_addresses: &mut Vec<String>,
    uris: &mut Vec<String>,
) -> Result<(), ClientCertificateInfoError> {
    let (list, _, _) = expect_tag(extensions, 0, 0x30, "Extensions")?;
    let mut position = 0;
    while position < list.len() {
        let (tag, extension, _, next) = read_tlv(list, position)?;
        if tag != 0x30 {
            position = next;
            continue;
        }
        let (oid_tag, oid_value, _, mut inner) = read_tlv(extension, 0)?;
        if oid_tag != 0x06 {
            position = next;
            continue;
        }
        let oid = parse_oid(oid_value);
        // Optional critical BOOLEAN.
        let (mut value_tag, mut value, _, mut inner_end) = read_tlv(extension, inner)?;
        if value_tag == 0x01 {
            (value_tag, value, _, inner_end) = read_tlv(extension, inner_end)?;
        }
        if oid == OID_SAN && value_tag == 0x04 {
            let (names, _, _) = expect_tag(value, 0, 0x30, "GeneralNames")?;
            let mut name_position = 0;
            while name_position < names.len() {
                let (name_tag, name_value, _, name_end) = read_tlv(names, name_position)?;
                match name_tag {
                    0x82 => dns_names.push(String::from_utf8_lossy(name_value).into_owned()),
                    0x81 => emails.push(String::from_utf8_lossy(name_value).into_owned()),
                    0x86 => uris.push(String::from_utf8_lossy(name_value).into_owned()),
                    0x87 if name_value.len() == 4 => ip_addresses.push(
                        std::net::Ipv4Addr::new(
                            name_value[0],
                            name_value[1],
                            name_value[2],
                            name_value[3],
                        )
                        .to_string(),
                    ),
                    0x87 if name_value.len() == 16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(name_value);
                        ip_addresses.push(std::net::Ipv6Addr::from(octets).to_string())
                    }
                    _ => {}
                }
                name_position = name_end;
            }
        }
        inner = inner_end;
        let _ = (inner, &mut value);
        position = next;
    }
    Ok(())
}

/// Decimal representation of a DER INTEGER value (big-endian, possibly with a leading zero).
fn decimal_serial(bytes: &[u8]) -> String {
    let mut digits = vec![0u8];
    for byte in bytes {
        let mut carry = *byte as u32;
        for digit in digits.iter_mut() {
            let value = (*digit as u32) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    let mut text: String = digits
        .iter()
        .rev()
        .map(|digit| (b'0' + digit) as char)
        .collect();
    let trimmed = text.trim_start_matches('0').to_string();
    if trimmed.is_empty() {
        text = "0".to_string();
    } else {
        text = trimmed;
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_CERT: &str = include_str!("../testdata/client-auth/client.pem");
    const UNTRUSTED_CERT: &str = include_str!("../testdata/client-auth/untrusted-client.pem");

    fn parsed(pem: &str, verified: bool) -> ClientCertificateInfo {
        use base64::Engine as _;
        let chain = crate::acme::parse_pem_certificate_chain(pem).expect("client cert parses");
        let body = chain[0]
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .expect("certificate PEM body decodes");
        ClientCertificateInfo::parse(&der, verified).expect("client cert info")
    }

    #[test]
    fn exposes_caddy_client_certificate_fields() {
        let info = parsed(CLIENT_CERT, true);
        assert!(info.verified);
        assert!(!info.subject.is_empty());
        assert!(info.subject.contains("CN="), "{}", info.subject);
        assert!(!info.issuer.is_empty());
        assert!(!info.serial.is_empty());
        assert!(info
            .serial
            .chars()
            .all(|character| character.is_ascii_digit()));
        assert_eq!(info.fingerprint.len(), 64);
        assert_eq!(info.public_key_sha256.len(), 64);
        assert!(!info.public_key_der.is_empty());
        assert!(!info.dns_names.is_empty(), "fixture has a DNS SAN");
        assert!(info
            .certificate_pem()
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!info.certificate_der_base64().is_empty());

        let placeholders = info.placeholders();
        assert_eq!(placeholders.get("subject"), Some(&info.subject));
        assert_eq!(placeholders.get("issuer"), Some(&info.issuer));
        assert_eq!(placeholders.get("serial"), Some(&info.serial));
        assert_eq!(
            placeholders.get("san.dns_names"),
            Some(&info.dns_names.join(","))
        );
        assert_eq!(placeholders.get("san.dns_names.0"), info.dns_names.first());
    }

    #[test]
    fn verified_flag_distinguishes_presented_and_verified_leaves() {
        let unverified = parsed(UNTRUSTED_CERT, false);
        assert!(!unverified.verified);
        let verified = parsed(UNTRUSTED_CERT, true);
        assert!(verified.verified);
        assert_eq!(unverified.der, verified.der);
        assert_eq!(unverified.subject, verified.subject);
    }

    #[test]
    fn absent_peer_certificates_yield_no_info() {
        assert!(client_certificate_infos(None, false).unwrap().is_empty());
        assert!(client_certificate_infos(Some(&[]), true)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn malformed_der_is_loud() {
        let error = ClientCertificateInfo::parse(&[0x30, 0x01, 0x00], true).unwrap_err();
        assert!(error.to_string().contains("malformed"), "{error}");
    }
}
