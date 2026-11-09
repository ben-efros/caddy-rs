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

// ---------------------------------------------------------------------------------------------
// Client-authentication CA pool sources (`tls.ca_pool.source.*`, T-TLS-079)
// ---------------------------------------------------------------------------------------------

use std::path::PathBuf;
use std::time::Duration;

use crate::Error;

/// External material needed to load a configured CA pool source.
///
/// Caddy's pool source modules are provisioned with the running app context; caddy-rs keeps the
/// loading logic in this module (per the T-TLS-079 scope) and takes the available context
/// explicitly so the `tls_server` connection-policy parser can delegate to it without owning the
/// PKI/storage/http plumbing:
///
/// * `pki_authorities`: configured `apps.pki` CA id → authority directory (the directory holding
///   `root.crt`/`intermediate.crt`, caddy-rs's data-directory layout).
/// * `implicit_authority_root`: data-directory root for Caddy's implicit default `local` CA; when
///   set, `pki_root`/`pki_intermediate` sources naming `local` provision it on first use instead
///   of reporting it as unconfigured.
/// * `storage_root`: root of the configured `file_system` storage (Caddy's default storage), used
///   to resolve `storage.pem_keys`.
/// * `system_roots`: platform roots override for tests/embedders; `None` loads the real platform
///   bundle via the ACME transport's bundle discovery.
/// * `http_timeout`: timeout for each `http` source URL.
#[derive(Debug, Clone, Default)]
pub struct CaPoolContext {
    /// Configured `apps.pki` CA id → authority directory (`pki/authorities/<id>`).
    pub pki_authorities: BTreeMap<String, PathBuf>,
    /// Data-directory root used to provision Caddy's implicit default `local` PKI authority.
    ///
    /// Caddy's PKI app provisions `local` on demand (`ProvisionDefaultCA`/`GetCA`) under
    /// `<data-dir>/pki/authorities/local`, including during `caddy validate`. The runtime sets
    /// this when the configuration does not explicitly declare a `local` authority, so a
    /// `pki_root`/`pki_intermediate` source naming `local` loads (and, on first use, generates)
    /// the material at the same location. `None` keeps the strict "not configured in apps.pki"
    /// error.
    pub implicit_authority_root: Option<PathBuf>,
    /// Root directory of the `file_system` storage backend used for `storage` pool sources.
    pub storage_root: Option<PathBuf>,
    /// Platform roots override; `None` loads the host CA bundle.
    pub system_roots: Option<Vec<CertificateDer<'static>>>,
    /// Per-URL timeout for `http` pool sources.
    pub http_timeout: Duration,
}

impl CaPoolContext {
    /// Default HTTP timeout (10s), matching Caddy's HTTP client timeout.
    pub fn new() -> Self {
        Self {
            http_timeout: Duration::from_secs(10),
            ..Self::default()
        }
    }
}

/// `<data-dir>/pki/authorities/local`, the directory Caddy's PKI app uses for the implicit
/// default `local` authority.
fn default_local_authority_directory(root: &std::path::Path) -> PathBuf {
    root.join("pki")
        .join("authorities")
        .join(crate::internal_ca::DEFAULT_CA_ID)
}

/// Provision — generate on first use, otherwise reuse — Caddy's implicit default `local` CA.
///
/// Caddy's PKI app does this lazily in `ProvisionDefaultCA`/`GetCA`, including during
/// `caddy validate`. The loader here is synchronous, so the async issuer runs on a dedicated
/// current-thread runtime; that also works when the caller is already inside a Tokio runtime.
/// [`InternalIssuer::load_ca`](crate::internal_ca::InternalIssuer::load_ca) loads existing
/// `root.crt`/`intermediate.crt` material instead of replacing it.
fn provision_default_local_authority(root: &std::path::Path, path: &str) -> Result<(), Error> {
    let directory = default_local_authority_directory(root);
    let data_directory = root.to_path_buf();
    let joined = std::thread::Builder::new()
        .name("caddy-rs-default-ca".to_string())
        .spawn(move || -> Result<(), String> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime
                .block_on(
                    crate::internal_ca::InternalIssuer::from_data_directory(data_directory)
                        .with_name(crate::internal_ca::DEFAULT_CA_ID)
                        .load_ca(),
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
        .map_err(|error| Error::TlsConfig {
            path: path.to_string(),
            message: format!(
                "provisioning the implicit default PKI authority `local` under `{}`: {error}",
                directory.display()
            ),
        })?;
    joined
        .join()
        .map_err(|_| Error::TlsConfig {
            path: path.to_string(),
            message: format!(
                "provisioning the implicit default PKI authority `local` under `{}` failed",
                directory.display()
            ),
        })?
        .map_err(|error| Error::TlsConfig {
            path: path.to_string(),
            message: format!(
                "provisioning the implicit default PKI authority `local` under `{}`: {error}",
                directory.display()
            ),
        })
}

/// Load one `tls.ca_pool.source.*` provider value (Caddy `modules/caddytls/capools.go`).
///
/// Supports `inline`, `file`, `system`, `pki_root`, `pki_intermediate`, `storage` (file_system
/// storage), `http` (`http://` endpoints; https needs an HTTP client hook) and `combined`.
/// Unknown providers and missing material are located errors; nothing silently falls back.
pub fn load_ca_pool_source(
    value: &serde_json::Value,
    path: &str,
    context: &CaPoolContext,
) -> Result<Vec<CertificateDer<'static>>, Error> {
    let object = value.as_object().ok_or_else(|| Error::TlsConfig {
        path: path.to_string(),
        message: "CA pool source must be an object".to_string(),
    })?;
    let provider = object
        .get("provider")
        .or_else(|| object.get("module"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::TlsConfig {
            path: path.to_string(),
            message: "CA pool source must name a `provider`".to_string(),
        })?;
    let provider = provider
        .strip_prefix("tls.ca_pool.source.")
        .unwrap_or(provider);
    let field_path = |name: &str| format!("{path}.{name}");
    let strings = |field: &str| -> Result<Vec<String>, Error> {
        match object.get(field) {
            None => Ok(Vec::new()),
            Some(serde_json::Value::Array(items)) => {
                let mut values = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    let value = item.as_str().ok_or_else(|| Error::TlsConfig {
                        path: format!("{}.{field}[{index}]", path),
                        message: "must be a string".to_string(),
                    })?;
                    values.push(value.to_string());
                }
                Ok(values)
            }
            Some(serde_json::Value::String(value)) => Ok(vec![value.clone()]),
            Some(_) => Err(Error::TlsConfig {
                path: field_path(field),
                message: "must be an array of strings".to_string(),
            }),
        }
    };
    match provider {
        "inline" => {
            let mut certificates = Vec::new();
            for key in ["trusted_ca_certs", "trusted_ca_pool"] {
                if let Some(values) = object.get(key) {
                    certificates.extend(parse_base64_der_certificates(
                        values,
                        &field_path(key),
                    )?);
                }
            }
            if certificates.is_empty() {
                return Err(Error::TlsConfig {
                    path: path.to_string(),
                    message: "inline CA pool source requires `trusted_ca_certs`".to_string(),
                });
            }
            Ok(certificates)
        }
        "file" => {
            let mut paths = Vec::new();
            for key in [
                "pem_files",
                "trusted_ca_pem_files",
                "trusted_ca_certs_pem_files",
            ] {
                let values = strings(key)?;
                if !values.is_empty() {
                    paths.extend(values);
                }
            }
            if paths.is_empty() {
                return Err(Error::TlsConfig {
                    path: path.to_string(),
                    message: "file CA pool source requires `pem_files`".to_string(),
                });
            }
            let mut certificates = Vec::new();
            for file in paths {
                let pem = std::fs::read_to_string(&file).map_err(|error| Error::TlsConfig {
                    path: path.to_string(),
                    message: format!("reading CA pool PEM file `{file}`: {error}"),
                })?;
                certificates.extend(crate::tls_server::certificates_from_pem(&pem).map_err(
                    |error| Error::TlsConfig {
                        path: path.to_string(),
                        message: format!("parsing CA pool PEM file `{file}`: {error}"),
                    },
                )?);
            }
            Ok(certificates)
        }
        "system" => match &context.system_roots {
            Some(roots) if !roots.is_empty() => Ok(roots.clone()),
            Some(_) => Err(Error::TlsConfig {
                path: path.to_string(),
                message: "system CA pool has no roots".to_string(),
            }),
            None => crate::acme::transport::load_system_root_certificates().map_err(|error| {
                Error::TlsConfig {
                    path: path.to_string(),
                    message: format!("loading system CA pool: {error}"),
                }
            }),
        },
        "pki_root" | "pki_intermediate" => {
            let authorities = strings("authority")?;
            if authorities.is_empty() {
                return Err(Error::TlsConfig {
                    path: path.to_string(),
                    message: format!("{provider} CA pool source requires `authority`"),
                });
            }
            let file = if provider == "pki_root" {
                "root.crt"
            } else {
                "intermediate.crt"
            };
            let mut certificates = Vec::new();
            for authority in authorities {
                let directory = match context.pki_authorities.get(&authority) {
                    Some(directory) => directory.clone(),
                    // Caddy's `GetCA` provisions the default `local` authority on demand when the
                    // configuration did not declare it. Generate/persist it under the data
                    // directory before reading, so a first `validate` succeeds exactly like
                    // Caddy and later calls reuse the same material.
                    None if authority == crate::internal_ca::DEFAULT_CA_ID => {
                        let root = context.implicit_authority_root.as_ref().ok_or_else(|| {
                            Error::TlsConfig {
                                path: field_path("authority"),
                                message: format!(
                                    "PKI authority `{authority}` is not configured in apps.pki"
                                ),
                            }
                        })?;
                        let directory = default_local_authority_directory(root);
                        // Reuse existing certificates as-is: a trust-anchor loader does not need
                        // the CA signing keys, and a data directory provisioned by real Caddy
                        // stores them in a PEM encoding this crate does not parse for a pool.
                        if !directory.join(file).is_file() {
                            provision_default_local_authority(root, path)?;
                        }
                        directory
                    }
                    None => {
                        return Err(Error::TlsConfig {
                            path: field_path("authority"),
                            message: format!(
                                "PKI authority `{authority}` is not configured in apps.pki"
                            ),
                        })
                    }
                };
                let pem_path = directory.join(file);
                let pem = std::fs::read_to_string(&pem_path).map_err(|error| {
                    Error::TlsConfig {
                        path: path.to_string(),
                        message: format!(
                            "reading {provider} certificate for authority `{authority}` from `{}`: {error}",
                            pem_path.display()
                        ),
                    }
                })?;
                certificates.extend(crate::tls_server::certificates_from_pem(&pem).map_err(
                    |error| Error::TlsConfig {
                        path: path.to_string(),
                        message: format!(
                            "parsing {provider} certificate for authority `{authority}`: {error}"
                        ),
                    },
                )?);
            }
            Ok(certificates)
        }
        "storage" => {
            let keys = strings("pem_keys")?;
            if keys.is_empty() {
                return Err(Error::TlsConfig {
                    path: path.to_string(),
                    message: "storage CA pool source requires `pem_keys`".to_string(),
                });
            }
            let root = context.storage_root.as_ref().ok_or_else(|| Error::Unsupported {
                path: path.to_string(),
                feature: "storage CA pool source without a configured file_system storage root"
                    .to_string(),
                tracking_id: "T-TLS-079",
            })?;
            let mut certificates = Vec::new();
            for key in keys {
                let file = root.join(&key);
                let pem = std::fs::read_to_string(&file).map_err(|error| Error::TlsConfig {
                    path: field_path("pem_keys"),
                    message: format!("reading storage PEM key `{key}` from `{}`: {error}", file.display()),
                })?;
                certificates.extend(crate::tls_server::certificates_from_pem(&pem).map_err(
                    |error| Error::TlsConfig {
                        path: field_path("pem_keys"),
                        message: format!("parsing storage PEM key `{key}`: {error}"),
                    },
                )?);
            }
            Ok(certificates)
        }
        "http" => {
            let endpoints = strings("endpoints")?;
            if endpoints.is_empty() {
                return Err(Error::TlsConfig {
                    path: path.to_string(),
                    message: "http CA pool source requires `endpoints`".to_string(),
                });
            }
            let mut certificates = Vec::new();
            for endpoint in endpoints {
                if !endpoint.starts_with("http://") {
                    return Err(Error::Unsupported {
                        path: field_path("endpoints"),
                        feature: format!(
                            "https CA pool endpoint `{endpoint}` (an HTTP client hook is needed; only http:// endpoints are loaded in-process)"
                        ),
                        tracking_id: "T-TLS-079",
                    });
                }
                let body = http_get(&endpoint, context.http_timeout)?;
                certificates.extend(crate::tls_server::certificates_from_pem(&body).map_err(
                    |error| Error::TlsConfig {
                        path: field_path("endpoints"),
                        message: format!("parsing CA pool PEM from `{endpoint}`: {error}"),
                    },
                )?);
            }
            Ok(certificates)
        }
        "combined" => {
            let sources = object
                .get("sources")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| Error::TlsConfig {
                    path: path.to_string(),
                    message: "combined CA pool source requires a non-empty `sources` array"
                        .to_string(),
                })?;
            if sources.is_empty() {
                return Err(Error::TlsConfig {
                    path: path.to_string(),
                    message: "no sources specified for combined CA pool".to_string(),
                });
            }
            let mut certificates = Vec::new();
            for (index, source) in sources.iter().enumerate() {
                let source_path = format!("{}.sources[{index}]", path);
                // Caddy's SystemCAPool does not implement CertificateProvider, so it cannot be a
                // `combined` source; reject it with a located error instead of silently merging.
                if source
                    .get("provider")
                    .or_else(|| source.get("module"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|provider| provider.trim_end_matches('.').ends_with("system")) {
                    return Err(Error::Unsupported {
                        path: source_path,
                        feature: "system CA pool source inside `combined` (Caddy's SystemCAPool cannot provide its certificate list)"
                            .to_string(),
                        tracking_id: "T-TLS-079",
                    });
                }
                certificates.extend(load_ca_pool_source(source, &source_path, context)?);
            }
            Ok(certificates)
        }
        other => Err(Error::Unsupported {
            path: path.to_string(),
            feature: format!(
                "client authentication CA pool provider `{other}` (supported: inline, file, system, pki_root, pki_intermediate, storage, http, combined)"
            ),
            tracking_id: "T-TLS-079",
        }),
    }
}

fn parse_base64_der_certificates(
    value: &serde_json::Value,
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, Error> {
    use base64::Engine as _;
    let values: Vec<&serde_json::Value> = match value {
        serde_json::Value::Array(items) => items.iter().collect(),
        serde_json::Value::String(_) => vec![value],
        _ => {
            return Err(Error::TlsConfig {
                path: path.to_string(),
                message: "must be an array of base64 DER certificates".to_string(),
            })
        }
    };
    let mut certificates = Vec::with_capacity(values.len());
    for (index, item) in values.iter().enumerate() {
        let encoded = item.as_str().ok_or_else(|| Error::TlsConfig {
            path: format!("{path}[{index}]"),
            message: "certificate must be a base64 DER string".to_string(),
        })?;
        let der = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| Error::TlsConfig {
                path: format!("{path}[{index}]"),
                message: format!("invalid base64 DER certificate: {error}"),
            })?;
        if der.is_empty() {
            return Err(Error::TlsConfig {
                path: format!("{path}[{index}]"),
                message: "certificate is empty".to_string(),
            });
        }
        certificates.push(CertificateDer::from(der));
    }
    Ok(certificates)
}

/// Minimal blocking `http://` GET used for `tls.ca_pool.source.http` (Caddy supports https too;
/// caddy-rs reports the HTTP-client hook for those rather than silently skipping them).
fn http_get(url: &str, timeout: Duration) -> Result<String, Error> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| Error::TlsConfig {
            path: "tls.ca_pool.source.http.endpoints".to_string(),
            message: format!("unsupported CA pool URL `{url}`"),
        })?;
    let (authority, target) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let mut stream = TcpStream::connect(authority).map_err(|error| Error::TlsConfig {
        path: "tls.ca_pool.source.http.endpoints".to_string(),
        message: format!("connecting to CA pool URL `{url}`: {error}"),
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| Error::TlsConfig {
            path: "tls.ca_pool.source.http.endpoints".to_string(),
            message: format!("setting timeout for CA pool URL `{url}`: {error}"),
        })?;
    let request =
        format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| Error::TlsConfig {
            path: "tls.ca_pool.source.http.endpoints".to_string(),
            message: format!("requesting CA pool URL `{url}`: {error}"),
        })?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| Error::TlsConfig {
            path: "tls.ca_pool.source.http.endpoints".to_string(),
            message: format!("reading CA pool URL `{url}`: {error}"),
        })?;
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| Error::TlsConfig {
            path: "tls.ca_pool.source.http.endpoints".to_string(),
            message: format!("malformed HTTP response from CA pool URL `{url}`"),
        })?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        return Err(Error::TlsConfig {
            path: "tls.ca_pool.source.http.endpoints".to_string(),
            message: format!("CA pool URL `{url}` returned HTTP {status}"),
        });
    }
    Ok(body.to_string())
}

#[cfg(test)]
mod ca_pool_tests {
    use super::*;
    use base64::Engine as _;
    use serde_json::json;
    use std::io::{Read, Write};

    const CERT: &str = include_str!("../testdata/https/example.com.pem");
    const OTHER: &str = include_str!("../testdata/https/other.example.pem");

    fn certs(pem: &str) -> Vec<CertificateDer<'static>> {
        crate::tls_server::certificates_from_pem(pem).expect("fixture parses")
    }

    fn default_context() -> CaPoolContext {
        CaPoolContext::new()
    }

    #[test]
    fn loads_inline_and_file_sources() {
        let inline = json!({"provider": "inline", "trusted_ca_certs": [base64::engine::general_purpose::STANDARD.encode(certs(CERT)[0].as_ref())]});
        assert_eq!(
            load_ca_pool_source(&inline, "ca", &default_context())
                .unwrap()
                .len(),
            1
        );

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ca.pem");
        std::fs::write(&file, CERT).unwrap();
        let file_source = json!({"provider": "file", "pem_files": [file]});
        assert_eq!(
            load_ca_pool_source(&file_source, "ca", &default_context())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn loads_system_roots_from_injected_or_platform_bundle() {
        let mut context = default_context();
        context.system_roots = Some(certs(CERT));
        assert_eq!(
            load_ca_pool_source(&json!({"provider": "system"}), "ca", &context)
                .unwrap()
                .len(),
            1
        );
        // The real platform bundle is used when no override is supplied; it must either load
        // roots or produce a located error, never silently return an empty pool.
        match load_ca_pool_source(&json!({"provider": "system"}), "ca", &default_context()) {
            Ok(roots) => assert!(!roots.is_empty()),
            Err(Error::TlsConfig { .. }) => {}
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn loads_pki_root_and_intermediate_from_authority_directories() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("local");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("root.crt"), CERT).unwrap();
        std::fs::write(local.join("intermediate.crt"), OTHER).unwrap();
        let mut context = default_context();
        context.pki_authorities.insert("local".to_string(), local);

        let root = load_ca_pool_source(
            &json!({"provider": "pki_root", "authority": ["local"]}),
            "ca",
            &context,
        )
        .unwrap();
        assert_eq!(root, certs(CERT));
        let intermediate = load_ca_pool_source(
            &json!({"provider": "pki_intermediate", "authority": ["local"]}),
            "ca",
            &context,
        )
        .unwrap();
        assert_eq!(intermediate, certs(OTHER));

        let missing = load_ca_pool_source(
            &json!({"provider": "pki_root", "authority": ["nope"]}),
            "ca",
            &context,
        )
        .unwrap_err();
        assert!(
            missing.to_string().contains("not configured in apps.pki"),
            "{missing}"
        );
    }

    #[test]
    fn provisions_the_implicit_local_authority_once_and_reuses_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = default_context();
        context.implicit_authority_root = Some(dir.path().to_path_buf());
        let root_source = json!({"provider": "pki_root", "authority": ["local"]});
        let intermediate_source = json!({"provider": "pki_intermediate", "authority": ["local"]});

        let root = load_ca_pool_source(&root_source, "ca", &context).unwrap();
        assert_eq!(root.len(), 1, "the generated root loads as a trust anchor");
        let intermediate = load_ca_pool_source(&intermediate_source, "ca", &context).unwrap();
        assert_eq!(intermediate.len(), 1);

        let authority = dir.path().join("pki").join("authorities").join("local");
        for file in [
            "root.crt",
            "root.key",
            "intermediate.crt",
            "intermediate.key",
        ] {
            assert!(
                authority.join(file).is_file(),
                "expected Caddy's `{}` layout at `{}`",
                file,
                authority.display()
            );
        }
        let root_pem = std::fs::read_to_string(authority.join("root.crt")).unwrap();
        let intermediate_pem = std::fs::read_to_string(authority.join("intermediate.crt")).unwrap();

        // A second load must reuse the persisted material, not regenerate it.
        assert_eq!(
            load_ca_pool_source(&root_source, "ca", &context).unwrap(),
            root
        );
        assert_eq!(
            std::fs::read_to_string(authority.join("root.crt")).unwrap(),
            root_pem
        );
        assert_eq!(
            std::fs::read_to_string(authority.join("intermediate.crt")).unwrap(),
            intermediate_pem
        );
    }

    #[test]
    fn implicit_local_without_a_data_root_stays_a_located_error() {
        let error = load_ca_pool_source(
            &json!({"provider": "pki_root", "authority": ["local"]}),
            "ca",
            &default_context(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("not configured in apps.pki"),
            "{error}"
        );
    }

    #[test]
    fn explicitly_configured_local_authority_is_never_generated() {
        // An `apps.pki.certificate_authorities.local` entry is resolved from its configured
        // location; only the implicit default is provisioned on demand.
        let explicit = tempfile::tempdir().unwrap();
        let implicit = tempfile::tempdir().unwrap();
        let mut context = default_context();
        context
            .pki_authorities
            .insert("local".to_string(), explicit.path().to_path_buf());
        context.implicit_authority_root = Some(implicit.path().to_path_buf());

        let error = load_ca_pool_source(
            &json!({"provider": "pki_root", "authority": ["local"]}),
            "ca",
            &context,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("root.crt"),
            "explicit authorities keep the loud missing-material error: {error}"
        );
        assert!(
            !implicit.path().join("pki").exists(),
            "the implicit root must not be touched for an explicitly configured authority"
        );
    }

    #[test]
    fn reuses_certificates_from_a_real_caddy_data_directory_without_its_keys() {
        // The oracle runs real Caddy first against the same data directory. Caddy writes its CA
        // keys as `EC PRIVATE KEY` (SEC1); a trust-anchor pool only needs the certificates, so
        // pre-existing `root.crt`/`intermediate.crt` must be reused without touching the keys.
        let dir = tempfile::tempdir().unwrap();
        let authority = dir.path().join("pki").join("authorities").join("local");
        std::fs::create_dir_all(&authority).unwrap();
        std::fs::write(authority.join("root.crt"), CERT).unwrap();
        std::fs::write(authority.join("intermediate.crt"), OTHER).unwrap();
        let mut context = default_context();
        context.implicit_authority_root = Some(dir.path().to_path_buf());

        let root = load_ca_pool_source(
            &json!({"provider": "pki_root", "authority": ["local"]}),
            "ca",
            &context,
        )
        .unwrap();
        assert_eq!(root, certs(CERT));
        let intermediate = load_ca_pool_source(
            &json!({"provider": "pki_intermediate", "authority": ["local"]}),
            "ca",
            &context,
        )
        .unwrap();
        assert_eq!(intermediate, certs(OTHER));
        assert!(
            !authority.join("root.key").exists() && !authority.join("intermediate.key").exists(),
            "pre-existing certificates must not trigger key loading or generation"
        );
    }

    #[test]
    fn loads_storage_backed_and_combined_sources_and_rejects_system_in_combined() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ca.pem"), CERT).unwrap();
        let mut context = default_context();
        context.storage_root = Some(dir.path().to_path_buf());
        let storage = json!({"provider": "storage", "pem_keys": ["ca.pem"]});
        assert_eq!(
            load_ca_pool_source(&storage, "ca", &context).unwrap().len(),
            1
        );

        let inline = json!({"provider": "inline", "trusted_ca_certs": [base64::engine::general_purpose::STANDARD.encode(certs(OTHER)[0].as_ref())]});
        let combined = json!({"provider": "combined", "sources": [inline, storage]});
        assert_eq!(
            load_ca_pool_source(&combined, "ca", &context)
                .unwrap()
                .len(),
            2
        );

        let system_combined =
            json!({"provider": "combined", "sources": [{"provider": "system"}, inline]});
        let error = load_ca_pool_source(&system_combined, "ca", &context).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot provide its certificate list"),
            "{error}"
        );

        let missing_key = load_ca_pool_source(
            &json!({"provider": "storage", "pem_keys": ["missing.pem"]}),
            "ca",
            &context,
        )
        .unwrap_err();
        assert!(
            missing_key.to_string().contains("missing.pem"),
            "{missing_key}"
        );
    }

    #[test]
    fn loads_http_backed_pem_and_rejects_https_and_unknown_providers() {
        // Local plain-HTTP test server (one request, direct PEM response).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = CERT.as_bytes();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });
        let source = json!({"provider": "http", "endpoints": [format!("http://{address}/ca.pem")]});
        assert_eq!(
            load_ca_pool_source(&source, "ca", &default_context())
                .unwrap()
                .len(),
            1
        );
        server.join().unwrap();

        let https = json!({"provider": "http", "endpoints": ["https://example.com/ca.pem"]});
        let error = load_ca_pool_source(&https, "ca", &default_context()).unwrap_err();
        assert!(error.to_string().contains("HTTP client hook"), "{error}");

        let unknown = json!({"provider": "vault"});
        let error = load_ca_pool_source(&unknown, "ca", &default_context()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("supported: inline, file, system"),
            "{error}"
        );
        assert!(error.to_string().contains("T-TLS-079"), "{error}");
    }
}
