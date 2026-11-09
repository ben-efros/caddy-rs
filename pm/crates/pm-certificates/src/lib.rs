//! Manual certificate validation, metadata and private-key storage for the proxy manager.
//!
//! # What this crate owns
//!
//! [`validate_manual_certificate`] parses a PEM certificate chain and private key, proves the key
//! matches the leaf certificate by signing a fixed challenge, rejects expired/not-yet-valid
//! certificates, checks that every requested domain is covered by the leaf's DNS SAN (or its common
//! name when no SAN exists), and returns bounded metadata plus canonical PEM.
//!
//! [`CertificateRepository`] stores that metadata as `Manual` documents in the namespaced
//! [`StateStore`] and writes the certificate chain and private key to separate files below
//! `<data_dir>/pm/secrets/`:
//!
//! * the directory and every file are created with owner-only permissions (`0700`/`0600`);
//! * file creation uses `O_CREAT | O_EXCL` (`create_new`), so an existing file — including a
//!   symlink — is refused and never overwritten;
//! * the repository refuses a symlinked secrets directory or a symlinked file path;
//! * the private-key bytes never enter the state document, the API response or an error message.
//!
//! # At-rest assumption
//!
//! This slice does **not** encrypt key material. It relies on filesystem permissions: the process
//! UID owns `<data_dir>/pm/secrets`, the directory is `0700`, and each key file is `0600`. Any
//! operator who can read the PM data directory can read the key. Full-disk encryption or an
//! external KMS/secret store is required for at-rest encryption and is tracked separately; this is
//! documented rather than implied. A backup of `<data_dir>` contains the key.
//!
//! # Apply boundary
//!
//! Config **assembly** emits `apps.tls.certificates.load_files` and matching
//! `tls_connection_policies`; this crate never calls the Caddy admin API. A stored certificate is
//! therefore reported with status `pending`, not `issued`, until an apply path exists.

#![forbid(unsafe_code)]

mod key;
mod pem;
mod x509;

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use caddy_rs_pm_core::{
    normalize_domain, normalize_pattern, pattern_covers, CertificateId, CertificateOrigin,
    CertificateStatus, CoreError, ExplicitCertificate, KeyType, TlsMode,
};
use caddy_rs_pm_state::{Document, Revision, StateError, StateStore, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use pem::{encode_block, parse_blocks};
use x509::parse_certificate;

/// Maximum accepted certificate-chain input, including PEM armour.
pub const MAX_CERTIFICATE_PEM_BYTES: usize = 256 * 1024;
/// Maximum accepted private-key input, including PEM armour.
pub const MAX_PRIVATE_KEY_PEM_BYTES: usize = 64 * 1024;
/// Maximum number of certificates in a chain.
pub const MAX_CHAIN_CERTIFICATES: usize = 10;
/// Clock skew allowed for `notBefore`; a certificate further in the future is rejected.
pub const NOT_BEFORE_SKEW_SECONDS: i64 = 24 * 60 * 60;

const CERTIFICATES: &str = "pm.certificates";
const TOMBSTONES: &str = "pm.certificate-tombstones";
const META: &str = "pm.meta";
const NEXT_ID: &str = "next-certificate-id";

/// A failed manual-certificate validation. Messages never contain PEM or key material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CertificateValidationError {
    #[error("{field} is empty")]
    EmptyInput { field: &'static str },
    #[error("{field} exceeds the maximum of {max} bytes")]
    InputTooLarge { field: &'static str, max: usize },
    #[error("{field} is not valid PEM: {reason}")]
    InvalidPem { field: &'static str, reason: String },
    #[error("certificate chain exceeds the maximum of {max} certificates")]
    TooManyCertificates { max: usize },
    #[error("certificate is invalid: {reason}")]
    InvalidCertificate { reason: String },
    #[error("certificate chain entry {index} is invalid: {reason}")]
    InvalidChainEntry { index: usize, reason: String },
    #[error("certificate has no usable DNS subjectAltName or common name")]
    NoUsableNames,
    #[error("certificate is expired (notAfter {not_after_unix})")]
    Expired { not_after_unix: i64 },
    #[error("certificate is not yet valid (notBefore {not_before_unix})")]
    NotYetValid { not_before_unix: i64 },
    #[error("certificate validity is inverted (notAfter is not after notBefore)")]
    InvalidValidity,
    #[error("certificate public key is not supported: {reason}")]
    UnsupportedKeyType { reason: String },
    #[error("private key format is not supported: {reason}")]
    UnsupportedKeyFormat { reason: String },
    #[error("private key is not valid: {reason}")]
    InvalidPrivateKey { reason: String },
    #[error("private key does not match the certificate public key")]
    KeyMismatch,
    #[error("requested domain is invalid: {reason}")]
    InvalidDomain { reason: String },
    #[error("certificate does not cover requested domain `{domain}`")]
    DomainNotCovered { domain: String },
}

impl CertificateValidationError {
    /// Field path used by the API's located error envelope.
    #[must_use]
    pub fn location(&self) -> &'static str {
        match self {
            Self::EmptyInput { field }
            | Self::InputTooLarge { field, .. }
            | Self::InvalidPem { field, .. } => field,
            Self::UnsupportedKeyFormat { .. }
            | Self::InvalidPrivateKey { .. }
            | Self::KeyMismatch => "privateKey",
            Self::InvalidDomain { .. } | Self::DomainNotCovered { .. } => "domains",
            Self::TooManyCertificates { .. }
            | Self::InvalidCertificate { .. }
            | Self::InvalidChainEntry { .. }
            | Self::NoUsableNames
            | Self::Expired { .. }
            | Self::NotYetValid { .. }
            | Self::InvalidValidity
            | Self::UnsupportedKeyType { .. } => "certificate",
        }
    }
}

/// Metadata for a stored manual certificate. This type contains **no** private-key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualCertificate {
    pub id: CertificateId,
    pub origin: CertificateOrigin,
    /// Every DNS name the certificate covers (SANs, or CN when no SAN exists).
    pub domains: Vec<String>,
    pub status: CertificateStatus,
    pub not_before_unix: i64,
    pub expires_at_unix: i64,
    pub fingerprint_sha256: String,
    pub key_type: KeyType,
    /// Path relative to the repository's secrets directory.
    pub certificate_file: String,
    /// Path relative to the repository's secrets directory.
    pub key_file: String,
    pub created_at_unix: i64,
}

impl ManualCertificate {
    /// Validate the persisted document.
    pub fn validate(&self) -> Result<(), CertificateError> {
        if self.id.0 == 0 {
            return Err(CertificateError::InvalidDocument(
                "manual certificate id must be greater than zero".to_string(),
            ));
        }
        if self.origin != CertificateOrigin::Manual {
            return Err(CertificateError::InvalidDocument(format!(
                "manual certificate {} has origin {}",
                self.id.0, self.origin
            )));
        }
        validate_certificate_domains(&self.domains)
            .map_err(|error| CertificateError::InvalidDocument(error.to_string()))?;
        if self.not_before_unix < 0 || self.expires_at_unix <= self.not_before_unix {
            return Err(CertificateError::InvalidDocument(
                "manual certificate validity is invalid".to_string(),
            ));
        }
        if self.fingerprint_sha256.len() != 64
            || !self
                .fingerprint_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CertificateError::InvalidDocument(
                "manual certificate fingerprint is not a SHA-256 hex digest".to_string(),
            ));
        }
        for file in [&self.certificate_file, &self.key_file] {
            if file.is_empty()
                || file.contains('/')
                || file.contains('\\')
                || file == "."
                || file == ".."
            {
                return Err(CertificateError::InvalidDocument(
                    "manual certificate file reference is not a plain file name".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Read-model projection used by host TLS validation and by the API.
    #[must_use]
    pub fn as_explicit(&self) -> ExplicitCertificate {
        ExplicitCertificate {
            id: self.id,
            origin: CertificateOrigin::Manual,
            domains: self.domains.clone(),
            status: self.status,
            expires_at_unix: Some(self.expires_at_unix),
            storage_ref: Some(self.key_file.clone()),
        }
    }
}

/// A manual certificate with the store revision that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCertificate {
    pub certificate: ManualCertificate,
    pub revision: Revision,
}

/// Validated upload material. The private key stays in memory only until [`CertificateRepository::create`]
/// writes it to the secret store.
pub struct ValidatedManualCertificate {
    domains: Vec<String>,
    not_before_unix: i64,
    expires_at_unix: i64,
    fingerprint_sha256: String,
    key_type: KeyType,
    certificate_chain_pem: String,
    private_key_pem: String,
}

impl std::fmt::Debug for ValidatedManualCertificate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedManualCertificate")
            .field("domains", &self.domains)
            .field("not_before_unix", &self.not_before_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("fingerprint_sha256", &self.fingerprint_sha256)
            .field("key_type", &self.key_type)
            .field("certificate_chain_pem", &"<redacted public chain>")
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

impl ValidatedManualCertificate {
    #[must_use]
    pub fn domains(&self) -> &[String] {
        &self.domains
    }
    #[must_use]
    pub fn not_before_unix(&self) -> i64 {
        self.not_before_unix
    }
    #[must_use]
    pub fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }
    #[must_use]
    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint_sha256
    }
    #[must_use]
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
}

/// Parse and validate a PEM certificate chain + matching private key.
///
/// `requested_domains` are concrete host names (`normalize_domain`), not wildcard patterns. Every
/// requested name must be covered by the leaf certificate; a wildcard SAN covers exactly one label.
/// `now_unix` is passed explicitly so tests do not depend on the wall clock.
pub fn validate_manual_certificate(
    certificate_pem: &str,
    private_key_pem: &str,
    requested_domains: &[String],
    now_unix: i64,
) -> Result<ValidatedManualCertificate, CertificateValidationError> {
    let requested_domains = validate_requested_domains(requested_domains)?;

    if certificate_pem.trim().is_empty() {
        return Err(CertificateValidationError::EmptyInput {
            field: "certificate",
        });
    }
    if private_key_pem.trim().is_empty() {
        return Err(CertificateValidationError::EmptyInput {
            field: "privateKey",
        });
    }
    if certificate_pem.len() > MAX_CERTIFICATE_PEM_BYTES {
        return Err(CertificateValidationError::InputTooLarge {
            field: "certificate",
            max: MAX_CERTIFICATE_PEM_BYTES,
        });
    }
    if private_key_pem.len() > MAX_PRIVATE_KEY_PEM_BYTES {
        return Err(CertificateValidationError::InputTooLarge {
            field: "privateKey",
            max: MAX_PRIVATE_KEY_PEM_BYTES,
        });
    }

    let certificate_blocks =
        parse_blocks(certificate_pem).map_err(|reason| CertificateValidationError::InvalidPem {
            field: "certificate",
            reason,
        })?;
    if certificate_blocks
        .iter()
        .any(|block| block.label != "CERTIFICATE")
    {
        return Err(CertificateValidationError::InvalidPem {
            field: "certificate",
            reason: "the certificate field may contain only CERTIFICATE PEM blocks".to_string(),
        });
    }
    if certificate_blocks.len() > MAX_CHAIN_CERTIFICATES {
        return Err(CertificateValidationError::TooManyCertificates {
            max: MAX_CHAIN_CERTIFICATES,
        });
    }
    let mut parsed_chain = Vec::with_capacity(certificate_blocks.len());
    for (index, block) in certificate_blocks.iter().enumerate() {
        let parsed = parse_certificate(&block.der).map_err(|error| {
            if index == 0 {
                CertificateValidationError::InvalidCertificate {
                    reason: error.to_string(),
                }
            } else {
                CertificateValidationError::InvalidChainEntry {
                    index,
                    reason: error.to_string(),
                }
            }
        })?;
        parsed_chain.push(parsed);
    }
    let leaf = parsed_chain
        .first()
        .ok_or(CertificateValidationError::NoUsableNames)?;

    if leaf.not_after_unix <= leaf.not_before_unix {
        return Err(CertificateValidationError::InvalidValidity);
    }
    if leaf.not_after_unix <= now_unix {
        return Err(CertificateValidationError::Expired {
            not_after_unix: leaf.not_after_unix,
        });
    }
    if leaf.not_before_unix > now_unix.saturating_add(NOT_BEFORE_SKEW_SECONDS) {
        return Err(CertificateValidationError::NotYetValid {
            not_before_unix: leaf.not_before_unix,
        });
    }

    let domains = certificate_domains(leaf)?;
    for domain in &requested_domains {
        if !domains
            .iter()
            .any(|covered| pattern_covers(covered, domain))
        {
            return Err(CertificateValidationError::DomainNotCovered {
                domain: domain.clone(),
            });
        }
    }

    let key_blocks =
        parse_blocks(private_key_pem).map_err(|reason| CertificateValidationError::InvalidPem {
            field: "privateKey",
            reason,
        })?;
    if key_blocks.len() != 1 {
        return Err(CertificateValidationError::InvalidPem {
            field: "privateKey",
            reason: "the private key field must contain exactly one PEM block".to_string(),
        });
    }
    let key_block = key_blocks.first().expect("one key block");
    if key_block.label == "EC PRIVATE KEY" {
        return Err(CertificateValidationError::UnsupportedKeyFormat {
            reason: "SEC1 EC PRIVATE KEY is not supported; provide a PKCS#8 PRIVATE KEY"
                .to_string(),
        });
    }
    if key_block.label == "ENCRYPTED PRIVATE KEY" {
        return Err(CertificateValidationError::UnsupportedKeyFormat {
            reason: "encrypted private keys are not supported".to_string(),
        });
    }
    let (parsed_key, key_type) = key::parse_private_key(key_block, &leaf.public_key)?;
    key::verify_key_matches(&parsed_key, &leaf.public_key)?;

    let fingerprint_sha256 = fingerprint(&leaf.der);
    let certificate_chain_pem = parsed_chain
        .iter()
        .map(|certificate| encode_block("CERTIFICATE", &certificate.der))
        .collect::<String>();
    let private_key_pem = encode_block(&key_block.label, &key_block.der);

    Ok(ValidatedManualCertificate {
        domains,
        not_before_unix: leaf.not_before_unix,
        expires_at_unix: leaf.not_after_unix,
        fingerprint_sha256,
        key_type,
        certificate_chain_pem,
        private_key_pem,
    })
}

fn validate_requested_domains(raw: &[String]) -> Result<Vec<String>, CertificateValidationError> {
    if raw.is_empty() {
        return Err(CertificateValidationError::InvalidDomain {
            reason: "at least one domain is required".to_string(),
        });
    }
    if raw.len() > 100 {
        return Err(CertificateValidationError::InvalidDomain {
            reason: "at most 100 domains are supported".to_string(),
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut domains = Vec::with_capacity(raw.len());
    for value in raw {
        let normalized =
            normalize_domain(value).map_err(|error| CertificateValidationError::InvalidDomain {
                reason: error.to_string(),
            })?;
        if !seen.insert(normalized.clone()) {
            return Err(CertificateValidationError::InvalidDomain {
                reason: format!("duplicate domain `{normalized}`"),
            });
        }
        domains.push(normalized);
    }
    Ok(domains)
}

fn validate_certificate_domains(domains: &[String]) -> Result<(), CoreError> {
    if domains.is_empty() {
        return Err(CoreError::Invalid(
            "at least one certificate domain is required".to_string(),
        ));
    }
    if domains.len() > 100 {
        return Err(CoreError::Invalid(
            "at most 100 certificate domains are supported".to_string(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for domain in domains {
        let normalized = normalize_pattern(domain)?;
        if !seen.insert(normalized.clone()) {
            return Err(CoreError::Invalid(format!(
                "duplicate certificate domain `{normalized}`"
            )));
        }
    }
    Ok(())
}

/// The certificate's usable DNS names: valid SANs, or the CN when there is no DNS SAN.
///
/// Invalid SAN entries are skipped rather than reinterpreted: they can never cover a host name,
/// and treating a malformed entry as a literal would be a wildcard/coverage approximation.
fn certificate_domains(
    certificate: &x509::ParsedCertificate,
) -> Result<Vec<String>, CertificateValidationError> {
    let mut names = std::collections::BTreeSet::new();
    for raw in &certificate.dns_names {
        if let Ok(normalized) = normalize_pattern(raw) {
            names.insert(normalized);
        }
    }
    if names.is_empty() {
        if let Some(common_name) = &certificate.common_name {
            if let Ok(normalized) = normalize_pattern(common_name) {
                names.insert(normalized);
            }
        }
    }
    if names.is_empty() {
        return Err(CertificateValidationError::NoUsableNames);
    }
    Ok(names.into_iter().collect())
}

fn fingerprint(der: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut hex = String::with_capacity(64);
    for byte in digest.as_ref() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// A failed certificate repository operation.
#[derive(Debug, Error)]
pub enum CertificateError {
    #[error(transparent)]
    Validation(#[from] CertificateValidationError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("certificate JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("manual certificate {0} was not found")]
    NotFound(u64),
    #[error("manual certificate {0} already exists")]
    AlreadyExists(u64),
    #[error("manual certificate id {0} was retired and cannot be reused")]
    IdRetired(u64),
    #[error("manual certificate ids are exhausted at u64::MAX")]
    IdExhausted,
    #[error("invalid stored manual certificate document: {0}")]
    InvalidDocument(String),
    #[error("certificate secret path {path} is not safe: {reason}")]
    UnsafeSecretPath { path: PathBuf, reason: &'static str },
    #[error("certificate secret file error for {path}: {source}")]
    SecretFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Durable manual-certificate repository with a filesystem secret store.
#[derive(Clone)]
pub struct CertificateRepository {
    store: Arc<dyn StateStore>,
    secrets_dir: PathBuf,
}

impl CertificateRepository {
    pub fn new(store: Arc<dyn StateStore>, secrets_dir: impl Into<PathBuf>) -> Self {
        Self {
            store,
            secrets_dir: secrets_dir.into(),
        }
    }

    /// Directory holding certificate and key files.
    #[must_use]
    pub fn secrets_dir(&self) -> &Path {
        &self.secrets_dir
    }

    /// Absolute path of a metadata file reference.
    ///
    /// The metadata validator only permits plain file names, so this cannot escape the directory.
    #[must_use]
    pub fn secret_path(&self, file: &str) -> PathBuf {
        self.secrets_dir.join(file)
    }

    pub fn get(&self, id: CertificateId) -> Result<Option<StoredCertificate>, CertificateError> {
        let Some(document) = self.store.get(CERTIFICATES, &id.0.to_string())? else {
            return Ok(None);
        };
        Ok(Some(decode_certificate(document)?))
    }

    pub fn list(&self) -> Result<Vec<StoredCertificate>, CertificateError> {
        let mut certificates = self
            .store
            .scan(CERTIFICATES, "")?
            .into_iter()
            .map(decode_certificate)
            .collect::<Result<Vec<_>, _>>()?;
        certificates.sort_by_key(|stored| stored.certificate.id.0);
        Ok(certificates)
    }

    pub fn snapshot_certificates(&self) -> Result<Vec<ManualCertificate>, CertificateError> {
        Ok(self
            .list()?
            .into_iter()
            .map(|stored| stored.certificate)
            .collect())
    }

    /// Mark every unexpired pending manual certificate as issued after a verified config apply.
    ///
    /// The status is local bookkeeping and is only advanced after the caller has loaded and
    /// verified the configuration in caddy-rs. A concurrent edit wins the CAS and is left
    /// untouched; it is retried against its new revision.
    pub fn mark_applied(&self, now_unix: i64) -> Result<Vec<CertificateId>, CertificateError> {
        let mut applied = Vec::new();
        for stored in self.list()? {
            if stored.certificate.status != CertificateStatus::Pending
                || stored.certificate.expires_at_unix <= now_unix
            {
                continue;
            }
            let mut updated = stored.certificate.clone();
            updated.status = CertificateStatus::Issued;
            let key = updated.id.0.to_string();
            let mut revision = stored.revision;
            for attempt in 0..4 {
                let transaction = Transaction::new()
                    .check_revision(CERTIFICATES, key.clone(), revision)
                    .put(CERTIFICATES, key.clone(), serde_json::to_value(&updated)?);
                match self.store.transact(transaction) {
                    Ok(commit) => {
                        let _ = revision_of(&commit, &key)?;
                        applied.push(updated.id);
                        break;
                    }
                    Err(StateError::Conflict { .. }) if attempt < 3 => {
                        let Some(current) = self.get(updated.id)? else {
                            break;
                        };
                        revision = current.revision;
                    }
                    Err(StateError::Conflict { .. }) => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(applied)
    }

    /// Store validated material under a fresh monotonic id.
    ///
    /// Secret files are written first with `create_new` (refusing an existing path) and the metadata
    /// is committed under a compare-and-swap. If the state write fails, the newly created files are
    /// removed. A failed attempt consumes an id; ids are never reused.
    pub fn create(
        &self,
        material: ValidatedManualCertificate,
        now_unix: i64,
    ) -> Result<StoredCertificate, CertificateError> {
        for _ in 0..8 {
            let id = self.next_id()?;
            let certificate_file = format!("manual-{id}.crt.pem");
            let key_file = format!("manual-{id}.key.pem");
            let certificate_path = self.secret_path(&certificate_file);
            let key_path = self.secret_path(&key_file);

            self.ensure_secrets_dir()?;
            write_secret_file(
                &self.secrets_dir,
                &certificate_path,
                material.certificate_chain_pem.as_bytes(),
            )?;
            if let Err(error) = write_secret_file(
                &self.secrets_dir,
                &key_path,
                material.private_key_pem.as_bytes(),
            ) {
                let _ = fs::remove_file(&certificate_path);
                return Err(error);
            }

            let certificate = ManualCertificate {
                id: CertificateId(id),
                origin: CertificateOrigin::Manual,
                domains: material.domains.clone(),
                // No apply path exists in this slice; never report `issued` for an unapplied cert.
                status: CertificateStatus::Pending,
                not_before_unix: material.not_before_unix,
                expires_at_unix: material.expires_at_unix,
                fingerprint_sha256: material.fingerprint_sha256.clone(),
                key_type: material.key_type,
                certificate_file,
                key_file,
                created_at_unix: now_unix,
            };
            if let Err(error) = certificate.validate() {
                let _ = fs::remove_file(&certificate_path);
                let _ = fs::remove_file(&key_path);
                return Err(error);
            }
            let key = id.to_string();
            let transaction = Transaction::new()
                .check_missing(CERTIFICATES, key.clone())
                .check_missing(TOMBSTONES, key.clone())
                .put(
                    CERTIFICATES,
                    key.clone(),
                    serde_json::to_value(&certificate)?,
                );
            match self.store.transact(transaction) {
                Ok(commit) => {
                    let revision = revision_of(&commit, &key)?;
                    return Ok(StoredCertificate {
                        certificate,
                        revision,
                    });
                }
                Err(StateError::Conflict { .. }) => {
                    let _ = fs::remove_file(&certificate_path);
                    let _ = fs::remove_file(&key_path);
                    continue;
                }
                Err(error) => {
                    let _ = fs::remove_file(&certificate_path);
                    let _ = fs::remove_file(&key_path);
                    return Err(error.into());
                }
            }
        }
        Err(CertificateError::State(StateError::Unavailable(
            "manual certificate id allocation is contended".to_string(),
        )))
    }

    /// Delete metadata, tombstone the id and remove the secret files.
    pub fn delete(
        &self,
        id: CertificateId,
        expected_revision: Revision,
    ) -> Result<(), CertificateError> {
        let stored = self.get(id)?.ok_or(CertificateError::NotFound(id.0))?;
        let key = id.0.to_string();
        let transaction = Transaction::new()
            .check_revision(CERTIFICATES, key.clone(), expected_revision)
            .check_missing(TOMBSTONES, key.clone())
            .put(TOMBSTONES, key.clone(), json!({ "certificate_id": id.0 }))
            .delete(CERTIFICATES, key);
        self.store.transact(transaction)?;

        for file in [
            &stored.certificate.certificate_file,
            &stored.certificate.key_file,
        ] {
            let path = self.secret_path(file);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(CertificateError::SecretFile { path, source });
                }
            }
        }
        Ok(())
    }

    /// Reserve the next numeric manual-certificate id.
    pub fn next_id(&self) -> Result<u64, CertificateError> {
        for _ in 0..8 {
            let snapshot = self.store.snapshot()?;
            let document = snapshot.get(META, NEXT_ID);
            let counter = match document {
                Some(document) => document.value.as_u64().ok_or_else(|| {
                    CertificateError::InvalidDocument(
                        "manual certificate id counter is not an unsigned integer".to_string(),
                    )
                })?,
                None => 1,
            };
            let highest = max_numeric_key(&snapshot, CERTIFICATES)
                .max(max_numeric_key(&snapshot, TOMBSTONES))
                .unwrap_or(0);
            let above_highest = highest
                .checked_add(1)
                .ok_or(CertificateError::IdExhausted)?;
            let candidate = counter.max(above_highest).max(1);
            let following = candidate
                .checked_add(1)
                .ok_or(CertificateError::IdExhausted)?;
            let mut transaction = match document {
                Some(document) => {
                    Transaction::new().check_revision(META, NEXT_ID, document.revision)
                }
                None => Transaction::new().check_missing(META, NEXT_ID),
            };
            transaction = transaction
                .check_missing(CERTIFICATES, candidate.to_string())
                .check_missing(TOMBSTONES, candidate.to_string())
                .put(META, NEXT_ID, json!(following));
            match self.store.transact(transaction) {
                Ok(_) => return Ok(candidate),
                Err(StateError::Conflict { .. }) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(CertificateError::State(StateError::Unavailable(
            "manual certificate id counter is contended".to_string(),
        )))
    }

    fn ensure_secrets_dir(&self) -> Result<(), CertificateError> {
        match fs::symlink_metadata(&self.secrets_dir) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(CertificateError::UnsafeSecretPath {
                        path: self.secrets_dir.clone(),
                        reason: "secrets directory is a symlink",
                    });
                }
                if !metadata.is_dir() {
                    return Err(CertificateError::UnsafeSecretPath {
                        path: self.secrets_dir.clone(),
                        reason: "secrets path is not a directory",
                    });
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.mode() & 0o077 != 0 {
                        return Err(CertificateError::UnsafeSecretPath {
                            path: self.secrets_dir.clone(),
                            reason: "secrets directory is accessible by group or others",
                        });
                    }
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder
                    .create(&self.secrets_dir)
                    .map_err(|source| CertificateError::SecretFile {
                        path: self.secrets_dir.clone(),
                        source,
                    })
            }
            Err(source) => Err(CertificateError::SecretFile {
                path: self.secrets_dir.clone(),
                source,
            }),
        }
    }
}

fn write_secret_file(
    secrets_dir: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), CertificateError> {
    if path.parent() != Some(secrets_dir) {
        return Err(CertificateError::UnsafeSecretPath {
            path: path.to_path_buf(),
            reason: "secret file is outside the secrets directory",
        });
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| CertificateError::SecretFile {
            path: path.to_path_buf(),
            source,
        })?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(CertificateError::SecretFile {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

fn revision_of(
    commit: &caddy_rs_pm_state::Commit,
    key: &str,
) -> Result<Revision, CertificateError> {
    commit
        .written
        .iter()
        .find(|document| document.namespace == CERTIFICATES && document.key == key)
        .map(|document| document.revision)
        .ok_or_else(|| {
            CertificateError::InvalidDocument(
                "certificate transaction did not return the certificate".to_string(),
            )
        })
}

fn max_numeric_key(snapshot: &caddy_rs_pm_state::Snapshot, namespace: &str) -> Option<u64> {
    snapshot
        .scan(namespace, "")
        .iter()
        .filter_map(|document| document.key.parse::<u64>().ok())
        .max()
}

fn decode_certificate(document: Document) -> Result<StoredCertificate, CertificateError> {
    let certificate: ManualCertificate = serde_json::from_value(document.value)
        .map_err(|error| CertificateError::InvalidDocument(error.to_string()))?;
    if certificate.id.0.to_string() != document.key {
        return Err(CertificateError::InvalidDocument(format!(
            "certificate document key `{}` does not match certificate id {}",
            document.key, certificate.id.0
        )));
    }
    certificate.validate()?;
    Ok(StoredCertificate {
        certificate,
        revision: document.revision,
    })
}

/// Whether `host_mode` can legally reference a certificate of this origin.
#[must_use]
pub fn explicit_mode_allows_origin(host_mode: TlsMode, origin: CertificateOrigin) -> bool {
    host_mode.origin() == Some(origin)
}

#[cfg(test)]
mod tests;
