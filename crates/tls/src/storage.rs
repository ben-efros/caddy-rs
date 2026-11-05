//! Pluggable certificate storage.
//!
//! Caddy's storage abstraction is one of its most operationally important interfaces: certificates
//! must not be tied to a local filesystem. This module defines the async storage trait, an
//! in-memory backend for tests, and a filesystem backend.
//!
//! # Caddy-compatible file layout
//!
//! The filesystem backend ([`FileStorage`]) uses the same on-disk layout as Caddy/CertMagic, so an
//! existing `$XDG_DATA_HOME/caddy`, `~/.local/share/caddy` (or `/var/lib/caddy/.local/share/caddy`)
//! data directory can be reused without conversion:
//!
//! ```text
//! <root>/certificates/<issuer-key>/<name>/<name>.crt   full PEM chain, leaf first
//! <root>/certificates/<issuer-key>/<name>/<name>.key   PEM private key
//! <root>/certificates/<issuer-key>/<name>/<name>.json  CertMagic metadata
//!                                                  (`{"sans": [...], "issuer_data": {...}}`)
//! ```
//!
//! `<issuer-key>` identifies the issuing CA rather than the issuer module name (Caddy's
//! CertMagic `IssuerKey`): the internal issuer uses the CA ID (`local` by default) and the ACME
//! issuer uses its CA directory URL with the scheme removed and `/` replaced by `-`, e.g.
//! `https://acme-v02.api.letsencrypt.org/directory` becomes
//! `acme-v02.api.letsencrypt.org-directory`. [`caddy_issuer_key`] implements that transform.
//!
//! Wildcard certificate names are stored with `*` replaced by `wildcard_`
//! (`*.example.com` becomes `wildcard_.example.com`), matching CertMagic's filesystem-safe name.
//!
//! A [`CertificateStorage`] key is `<issuer-key>/<certificate-name>` (the part below
//! `certificates/`). Backends are expected to reject keys that would escape the storage root.
//!
//! On load, the domains come from the CertMagic `.json` metadata when present (falling back to the
//! directory name) and `not_after_unix` is recovered from the leaf certificate's validity period.
//! PEM strings returned by [`FileStorage`] are normalised: one block per entry, no trailing
//! newline. CertMagic's opaque `issuer_data` (ACME certificate URL/CA/account and ARI info) and
//! any unknown metadata fields are preserved when a certificate is rewritten, and the metadata is
//! serialised in CertMagic's tab-indented `sans`-then-`issuer_data` shape without a trailing
//! newline.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::{Error, Result};

/// Directory below the storage root that contains certificates (CertMagic's `certificates`).
pub const CERTIFICATES_DIRECTORY: &str = "certificates";

/// A certificate in storage form (PEM, so it can be inspected with standard tooling).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCertificate {
    /// PEM-encoded certificate chain, leaf first.
    pub certificate_pem: Vec<String>,
    /// PEM-encoded private key.
    pub private_key_pem: String,
    /// Domains covered.
    pub domains: Vec<String>,
    /// Unix timestamp (seconds) after which the certificate is not valid.
    pub not_after_unix: u64,
    /// CertMagic's opaque `issuer_data` metadata (for ACME: certificate URL, CA directory and
    /// account URL). Preserved verbatim when a certificate is rewritten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_data: Option<serde_json::Value>,
    /// Any other metadata fields written by Caddy/CertMagic. Preserved verbatim on rewrite so a
    /// newer Caddy metadata field survives a caddy-rs renewal.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata_extra: BTreeMap<String, serde_json::Value>,
}

/// Async certificate storage backend.
#[async_trait]
pub trait CertificateStorage: Send + Sync {
    /// Backend name (for `list-modules` and diagnostics).
    fn name(&self) -> &'static str;

    /// Load a value by key.
    async fn load(&self, key: &str) -> Result<Option<StoredCertificate>>;

    /// Store a value under a key.
    async fn store(&self, key: &str, certificate: &StoredCertificate) -> Result<()>;

    /// Delete a value.
    async fn delete(&self, key: &str) -> Result<()>;

    /// List keys under a prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// In-memory storage, used by tests and ephemeral deployments.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    values: RwLock<BTreeMap<String, StoredCertificate>>,
}

impl MemoryStorage {
    /// Create empty storage.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CertificateStorage for MemoryStorage {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn load(&self, key: &str) -> Result<Option<StoredCertificate>> {
        Ok(self
            .values
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .cloned())
    }

    async fn store(&self, key: &str, certificate: &StoredCertificate) -> Result<()> {
        self.values
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key.to_string(), certificate.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.values
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .values
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }
}

/// Filesystem-backed storage using Caddy's certificate layout.
///
/// `root` is the Caddy data directory (the directory that contains `certificates/`, `acme/`,
/// `pki/`, ...). See the module documentation for the exact layout.
#[derive(Debug, Clone)]
pub struct FileStorage {
    root: PathBuf,
}

/// The on-disk paths for one certificate in the Caddy layout.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CertificatePaths {
    /// `certificates/<issuer>/<name>` directory.
    directory: PathBuf,
    /// `<name>.crt`.
    certificate: PathBuf,
    /// `<name>.key`.
    private_key: PathBuf,
    /// `<name>.json`.
    metadata: PathBuf,
}

impl FileStorage {
    /// Create storage rooted at a Caddy data directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Root directory (the Caddy data directory).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Paths used for a storage key, validating the key first.
    fn certificate_paths(&self, key: &str) -> Result<CertificatePaths> {
        let (issuer, name) = split_storage_key(key)?;
        let stored_name = caddy_certificate_storage_name(&name);
        let directory = self
            .root
            .join(CERTIFICATES_DIRECTORY)
            .join(issuer)
            .join(&stored_name);
        Ok(CertificatePaths {
            certificate: directory.join(format!("{stored_name}.crt")),
            private_key: directory.join(format!("{stored_name}.key")),
            metadata: directory.join(format!("{stored_name}.json")),
            directory,
        })
    }
}

#[async_trait]
impl CertificateStorage for FileStorage {
    fn name(&self) -> &'static str {
        "file_system"
    }

    async fn load(&self, key: &str) -> Result<Option<StoredCertificate>> {
        let paths = self.certificate_paths(key)?;
        let certificate_pem = match fs::read_to_string(&paths.certificate).await {
            Ok(text) => certificate_chain_pem(&text)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::Io(error)),
        };
        let private_key_pem = match fs::read_to_string(&paths.private_key).await {
            Ok(text) => private_key_pem(&text)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Storage(format!(
                    "certificate `{key}` has no private key at `{}`",
                    paths.private_key.display()
                )))
            }
            Err(error) => return Err(Error::Io(error)),
        };

        let (_, name) = split_storage_key(key)?;
        let (domains, issuer_data, metadata_extra) = match fs::read(&paths.metadata).await {
            Ok(data) => {
                let metadata: CaddyCertificateMetadata =
                    serde_json::from_slice(&data).map_err(|error| {
                        Error::Storage(format!(
                            "cannot decode certificate metadata `{}`: {error}",
                            paths.metadata.display()
                        ))
                    })?;
                let domains = match metadata.sans {
                    Some(sans) if !sans.is_empty() => sans,
                    _ => vec![caddy_certificate_name_from_storage(&name)],
                };
                (domains, metadata.issuer_data, metadata.extra)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
                vec![caddy_certificate_name_from_storage(&name)],
                None,
                BTreeMap::new(),
            ),
            Err(error) => return Err(Error::Io(error)),
        };

        let not_after_unix = certificate_not_after_unix(&certificate_pem[0])?;

        Ok(Some(StoredCertificate {
            certificate_pem,
            private_key_pem,
            domains,
            not_after_unix,
            issuer_data,
            metadata_extra,
        }))
    }

    async fn store(&self, key: &str, certificate: &StoredCertificate) -> Result<()> {
        if certificate.certificate_pem.is_empty() {
            return Err(Error::Storage(format!(
                "certificate `{key}` has an empty PEM chain"
            )));
        }
        let paths = self.certificate_paths(key)?;
        fs::create_dir_all(&paths.directory).await?;

        let mut chain = String::new();
        for block in &certificate.certificate_pem {
            chain.push_str(block.trim_end());
            chain.push('\n');
        }
        atomic_write(&paths.certificate, chain.as_bytes()).await?;

        let mut key_pem = certificate.private_key_pem.trim_end().to_string();
        key_pem.push('\n');
        atomic_write(&paths.private_key, key_pem.as_bytes()).await?;
        restrict_private_key_permissions(&paths.private_key).await;

        // CertMagic serialises `CertificateResource` with `json.MarshalIndent(cert, "", "\t")`:
        // tab indentation, struct field order (`sans`, then `issuer_data`), no trailing newline.
        // Preserve any unknown metadata fields after those.
        #[derive(Serialize)]
        struct CertMagicMetadata<'a> {
            sans: &'a [String],
            #[serde(skip_serializing_if = "Option::is_none")]
            issuer_data: Option<&'a serde_json::Value>,
            #[serde(flatten)]
            extra: &'a BTreeMap<String, serde_json::Value>,
        }
        let metadata = CertMagicMetadata {
            sans: &certificate.domains,
            issuer_data: certificate.issuer_data.as_ref(),
            extra: &certificate.metadata_extra,
        };
        let mut data = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"\t");
        let mut serializer = serde_json::Serializer::with_formatter(&mut data, formatter);
        metadata
            .serialize(&mut serializer)
            .map_err(|error| Error::Storage(error.to_string()))?;
        atomic_write(&paths.metadata, &data).await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let paths = self.certificate_paths(key)?;
        for path in [&paths.certificate, &paths.private_key, &paths.metadata] {
            match fs::remove_file(path).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(Error::Io(error)),
            }
        }
        // Remove the now-empty certificate directory; a leftover non-empty directory is fine.
        let _ = fs::remove_dir(&paths.directory).await;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let certificates_root = self.root.join(CERTIFICATES_DIRECTORY);
        let mut keys = Vec::new();
        let mut issuers = match fs::read_dir(&certificates_root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(keys),
            Err(error) => return Err(Error::Io(error)),
        };
        while let Some(issuer_entry) = issuers.next_entry().await? {
            if !issuer_entry.file_type().await?.is_dir() {
                continue;
            }
            let issuer = issuer_entry.file_name().to_string_lossy().into_owned();
            if !is_issuer_component(&issuer) {
                continue;
            }
            let mut certificates = match fs::read_dir(issuer_entry.path()).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(Error::Io(error)),
            };
            while let Some(certificate_entry) = certificates.next_entry().await? {
                if !certificate_entry.file_type().await?.is_dir() {
                    continue;
                }
                let stored_name = certificate_entry.file_name().to_string_lossy().into_owned();
                if !is_certificate_component(&stored_name) {
                    continue;
                }
                let expected = format!("{stored_name}.crt");
                if fs::metadata(certificate_entry.path().join(&expected))
                    .await
                    .map(|metadata| metadata.is_file())
                    .unwrap_or(false)
                {
                    let name = caddy_certificate_name_from_storage(&stored_name);
                    let key = format!("{issuer}/{name}");
                    if key.starts_with(prefix) {
                        keys.push(key);
                    }
                }
            }
        }
        keys.sort();
        Ok(keys)
    }
}

#[async_trait]
impl<T: CertificateStorage + ?Sized> CertificateStorage for Arc<T> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    async fn load(&self, key: &str) -> Result<Option<StoredCertificate>> {
        (**self).load(key).await
    }

    async fn store(&self, key: &str, certificate: &StoredCertificate) -> Result<()> {
        (**self).store(key, certificate).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        (**self).delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        (**self).list(prefix).await
    }
}

/// Metadata file written by CertMagic alongside `<name>.crt` / `<name>.key`.
///
/// CertMagic's JSON has `sans` and an opaque `issuer_data` object (for ACME: certificate URL,
/// CA directory and account URL, optionally ARI renewal info). Unknown fields are preserved on
/// rewrite so a newer Caddy metadata key survives a caddy-rs renewal.
#[derive(Debug, Deserialize)]
struct CaddyCertificateMetadata {
    #[serde(default)]
    sans: Option<Vec<String>>,
    /// CertMagic's issuer-specific metadata (`acme.Certificate` for ACME: url/ca/account/ARI).
    #[serde(default)]
    issuer_data: Option<serde_json::Value>,
    /// Other fields preserved for forward compatibility (for example future CertMagic keys).
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Convert an issuer identity to Caddy's on-disk issuer directory name.
///
/// * ACME issuer: the CA directory URL with its scheme removed and `/` replaced by `-`
///   (`https://acme-v02.api.letsencrypt.org/directory` ->
///   `acme-v02.api.letsencrypt.org-directory`).
/// * Internal issuer: the CA ID unchanged (`local`, `my-ca`, ...).
///
/// This mirrors CertMagic's `ACMEIssuer.IssuerKey` and Caddy's `InternalIssuer.IssuerKey`.
pub fn caddy_issuer_key(ca: &str) -> String {
    match ca.find("://") {
        Some(scheme_end) => {
            let without_scheme = &ca[scheme_end + 3..];
            without_scheme.replace('/', "-")
        }
        None => ca.to_string(),
    }
}

/// Convert a certificate name (possibly a wildcard) to CertMagic's filesystem-safe name.
pub fn caddy_certificate_storage_name(name: &str) -> String {
    name.replace('*', "wildcard_")
}

/// Recover the certificate name from a filesystem-safe directory name.
fn caddy_certificate_name_from_storage(stored_name: &str) -> String {
    match stored_name.strip_prefix("wildcard_") {
        Some(rest) => format!("*{rest}"),
        None => stored_name.to_string(),
    }
}

/// Split and validate a `<issuer-key>/<certificate-name>` storage key.
fn split_storage_key(key: &str) -> Result<(&str, String)> {
    if key.is_empty() || key.contains('\0') || key.contains('\\') || key.starts_with('/') {
        return Err(Error::InvalidKey(key.to_string()));
    }
    let mut parts = key.split('/');
    let issuer = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err(Error::InvalidKey(key.to_string()));
    }
    if !is_issuer_component(issuer) || !is_certificate_component(name) {
        return Err(Error::InvalidKey(key.to_string()));
    }
    Ok((issuer, name.to_string()))
}

/// Issuer directory components: ASCII letters/digits plus `.`, `_`, `-`, `:`. `/` is the key
/// separator and is rejected by construction.
fn is_issuer_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

/// Certificate name components: ASCII letters/digits plus `.`, `_`, `-`, `*`.
fn is_certificate_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'*'))
}

/// Write `data` to `path` atomically: write a temporary sibling, then rename over the target.
async fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Storage(format!("invalid storage path `{}`", path.display())))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_file_name(format!(".{file_name}.{nonce}.{counter}.tmp"));
    if let Err(error) = fs::write(&temporary, data).await {
        let _ = fs::remove_file(&temporary).await;
        return Err(Error::Io(error));
    }
    if let Err(error) = fs::rename(&temporary, path).await {
        let _ = fs::remove_file(&temporary).await;
        return Err(Error::Io(error));
    }
    Ok(())
}

/// Make the private key file readable only by the owner (best effort; Unix only).
async fn restrict_private_key_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Split a PEM document into blocks with the given label.
///
/// Returned blocks keep their `-----BEGIN ...-----` / `-----END ...-----` lines, joined with `\n`,
/// and have no trailing newline.
fn pem_blocks(document: &str, label: &str) -> Result<Vec<String>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut current: Option<Vec<String>> = None;
    for line in document.lines() {
        let line = line.trim_end_matches('\r');
        match &mut current {
            None => {
                if line.trim() == begin {
                    current = Some(vec![begin.clone()]);
                }
            }
            Some(lines) => {
                lines.push(line.to_string());
                if line.trim() == end {
                    blocks.push(lines.join("\n"));
                    current = None;
                }
            }
        }
    }
    if current.is_some() {
        return Err(Error::Storage(format!(
            "unterminated PEM block `{label}` (missing `{end}`)"
        )));
    }
    Ok(blocks)
}

/// PEM certificate chain blocks from a `.crt` document.
fn certificate_chain_pem(document: &str) -> Result<Vec<String>> {
    let blocks = pem_blocks(document, "CERTIFICATE")?;
    if blocks.is_empty() {
        return Err(Error::Storage(
            "certificate file contains no PEM CERTIFICATE block".to_string(),
        ));
    }
    Ok(blocks)
}

/// PEM private key block from a `.key` document.
///
/// Caddy stores PKCS#8 (`PRIVATE KEY`) keys, but imported certificates may use `RSA PRIVATE KEY`
/// or `EC PRIVATE KEY`; all are accepted here.
fn private_key_pem(document: &str) -> Result<String> {
    for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
        let blocks = pem_blocks(document, label)?;
        if let Some(block) = blocks.into_iter().next() {
            return Ok(block);
        }
    }
    Err(Error::Storage(
        "private key file contains no PEM private key block".to_string(),
    ))
}

/// Decode the first PEM block with `label` into DER bytes.
///
/// Used by the ACME issuer to turn downloaded PEM chains and generated PKCS#8 keys into the DER
/// representation held by [`crate::certificate::Certificate`].
pub(crate) fn pem_block_der(pem: &str, label: &str) -> Result<Vec<u8>> {
    let blocks = pem_blocks(pem, label)?;
    let block = blocks
        .first()
        .ok_or_else(|| Error::Storage(format!("PEM document contains no `{label}` block")))?;
    let body: String = block
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|error| Error::Storage(format!("invalid PEM base64: {error}")))
}

/// Convert PEM certificate-chain blocks (leaf first) into DER.
pub(crate) fn certificate_chain_der(chain_pem: &[String]) -> Result<Vec<Vec<u8>>> {
    chain_pem
        .iter()
        .map(|block| pem_block_der(block, "CERTIFICATE"))
        .collect()
}

/// Convert a PEM private key (PKCS#8, PKCS#1 or SEC1) into DER.
pub(crate) fn private_key_der(pem: &str) -> Result<Vec<u8>> {
    for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
        if !pem_blocks(pem, label)?.is_empty() {
            return pem_block_der(pem, label);
        }
    }
    Err(Error::Storage(
        "private key PEM contains no private key block".to_string(),
    ))
}

/// The leaf certificate's `(notBefore, notAfter)` as Unix seconds.
pub(crate) fn certificate_validity_unix(pem: &str) -> Result<(u64, u64)> {
    let der = pem_block_der(pem, "CERTIFICATE")?;
    validity_unix_from_der(&der)
}

/// Decode a PEM certificate block and return its `notAfter` as Unix seconds.
fn certificate_not_after_unix(pem: &str) -> Result<u64> {
    Ok(certificate_validity_unix(pem)?.1)
}

/// Minimal DER reader for the small part of X.509 needed to read validity times.
struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| Error::Storage("truncated DER: missing tag".to_string()))?;
        self.offset += 1;
        if tag & 0x1f == 0x1f {
            return Err(Error::Storage(
                "unsupported DER high-tag-number encoding".to_string(),
            ));
        }
        let first = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| Error::Storage("truncated DER: missing length".to_string()))?;
        self.offset += 1;
        let length = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return Err(Error::Storage(
                    "unsupported DER indefinite or oversized length".to_string(),
                ));
            }
            let mut length = 0usize;
            for _ in 0..count {
                let byte = *self.bytes.get(self.offset).ok_or_else(|| {
                    Error::Storage("truncated DER: missing length byte".to_string())
                })?;
                self.offset += 1;
                length = (length << 8) | byte as usize;
            }
            length
        };
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| Error::Storage("truncated DER: value out of bounds".to_string()))?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok((tag, value))
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<&'a [u8]> {
        let (actual, value) = self.read_tlv()?;
        if actual != tag {
            return Err(Error::Storage(format!(
                "unexpected DER tag 0x{actual:02x} for {what} (expected 0x{tag:02x})"
            )));
        }
        Ok(value)
    }
}

const DER_SEQUENCE: u8 = 0x30;
const DER_INTEGER: u8 = 0x02;
const DER_UTC_TIME: u8 = 0x17;
const DER_GENERALIZED_TIME: u8 = 0x18;
const DER_CONTEXT_0: u8 = 0xa0;

/// Extract `(notBefore, notAfter)` (Unix seconds) from a DER-encoded X.509 certificate.
fn validity_unix_from_der(der: &[u8]) -> Result<(u64, u64)> {
    let mut outer = DerReader::new(der);
    let certificate = outer.expect(DER_SEQUENCE, "Certificate")?;
    let mut certificate_reader = DerReader::new(certificate);
    let tbs_certificate = certificate_reader.expect(DER_SEQUENCE, "TBSCertificate")?;

    let mut tbs = DerReader::new(tbs_certificate);
    let mut field = tbs.read_tlv()?;
    if field.0 == DER_CONTEXT_0 {
        // version [0] EXPLICIT, optional for v1 certificates.
        field = tbs.read_tlv()?;
    }
    if field.0 != DER_INTEGER {
        return Err(Error::Storage(
            "invalid X.509 TBSCertificate: serialNumber is not an INTEGER".to_string(),
        ));
    }
    tbs.expect(DER_SEQUENCE, "signature AlgorithmIdentifier")?;
    tbs.expect(DER_SEQUENCE, "issuer Name")?;
    let validity = tbs.expect(DER_SEQUENCE, "validity")?;

    let mut validity = DerReader::new(validity);
    let not_before = validity.read_tlv()?;
    let not_after = validity.read_tlv()?;
    Ok((
        parse_asn1_time(not_before.0, not_before.1)?,
        parse_asn1_time(not_after.0, not_after.1)?,
    ))
}

/// Parse an ASN.1 `UTCTime` or `GeneralizedTime` value (`YYMMDDHHMMSSZ` / `YYYYMMDDHHMMSSZ`).
fn parse_asn1_time(tag: u8, value: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(value)
        .map_err(|error| Error::Storage(format!("invalid ASN.1 time encoding: {error}")))?;
    if !text.ends_with('Z') {
        return Err(Error::Storage(format!(
            "invalid ASN.1 time `{text}`: only UTC (`Z`) times are supported"
        )));
    }
    let digits = &text[..text.len() - 1];
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Storage(format!(
            "invalid ASN.1 time `{text}`: expected digits"
        )));
    }
    let (year, rest) = match tag {
        DER_UTC_TIME => {
            if digits.len() != 12 {
                return Err(Error::Storage(format!(
                    "invalid UTCTime `{text}`: expected YYMMDDHHMMSSZ"
                )));
            }
            let yy: i64 = digits[0..2].parse().map_err(|_| invalid_time(text))?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &digits[2..])
        }
        DER_GENERALIZED_TIME => {
            if digits.len() != 14 {
                return Err(Error::Storage(format!(
                    "invalid GeneralizedTime `{text}`: expected YYYYMMDDHHMMSSZ"
                )));
            }
            let year: i64 = digits[0..4].parse().map_err(|_| invalid_time(text))?;
            (year, &digits[4..])
        }
        other => {
            return Err(Error::Storage(format!(
                "unsupported ASN.1 time tag 0x{other:02x} (expected UTCTime or GeneralizedTime)"
            )))
        }
    };
    let month: u32 = parse_time_field(&rest[0..2], text)?;
    let day: u32 = parse_time_field(&rest[2..4], text)?;
    let hour: u64 = parse_time_field(&rest[4..6], text)?;
    let minute: u64 = parse_time_field(&rest[6..8], text)?;
    let second: u64 = parse_time_field(&rest[8..10], text)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(Error::Storage(format!(
            "invalid ASN.1 time `{text}`: component out of range"
        )));
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return Err(Error::Storage(format!(
            "invalid ASN.1 time `{text}`: before the Unix epoch"
        )));
    }
    let seconds = (days as u64)
        .checked_mul(86_400)
        .and_then(|base| base.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| Error::Storage(format!("ASN.1 time `{text}` is out of range")))?;
    Ok(seconds)
}

fn parse_time_field<T: std::str::FromStr>(value: &str, whole: &str) -> Result<T> {
    value
        .parse()
        .map_err(|_| Error::Storage(format!("invalid ASN.1 time `{whole}`")))
}

fn invalid_time(value: &str) -> Error {
    Error::Storage(format!("invalid ASN.1 time `{value}`"))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 } as i64;
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Build a certificate storage backend from Caddy storage module JSON.
pub fn from_config(config: &serde_json::Value) -> Result<Box<dyn CertificateStorage>> {
    let object = config
        .as_object()
        .ok_or_else(|| Error::Storage("storage config must be an object".to_string()))?;
    let module = object
        .get("module")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("file_system");
    match module {
        "file_system" => {
            let root = object
                .get("root")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(".caddy-rs");
            Ok(Box::new(FileStorage::new(root)))
        }
        other => Err(Error::Storage(format!(
            "storage module `{other}` is not implemented by this build"
        ))),
    }
}

/// Convenience: staleness check for a stored certificate.
pub fn stored_certificate_expiring(certificate: &StoredCertificate, within: Duration) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    certificate.not_after_unix.saturating_sub(now) <= within.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> StoredCertificate {
        StoredCertificate {
            certificate_pem: vec![
                "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----".to_string(),
            ],
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----"
                .to_string(),
            domains: vec!["example.com".to_string()],
            not_after_unix: 4_000_000_000,
            issuer_data: None,
            metadata_extra: BTreeMap::new(),
        }
    }

    const ACME_ISSUER: &str = "acme-v02.api.letsencrypt.org-directory";

    fn fixture_chain() -> Vec<String> {
        certificate_chain_pem(include_str!("../tests/fixtures/caddy-data/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt"))
            .unwrap()
    }

    fn fixture_key() -> String {
        private_key_pem(include_str!("../tests/fixtures/caddy-data/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.key")).unwrap()
    }

    fn fixture_certificate() -> StoredCertificate {
        StoredCertificate {
            certificate_pem: fixture_chain(),
            private_key_pem: fixture_key(),
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            not_after_unix: 1_775_001_600, // 2026-04-01T00:00:00Z
            issuer_data: None,
            metadata_extra: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn memory_storage_round_trips() {
        let storage = MemoryStorage::new();
        storage
            .store("certs/example.com", &example())
            .await
            .unwrap();
        assert_eq!(
            storage.load("certs/example.com").await.unwrap(),
            Some(example())
        );
        assert_eq!(storage.list("certs/").await.unwrap().len(), 1);
        storage.delete("certs/example.com").await.unwrap();
        assert!(storage.load("certs/example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn file_storage_writes_caddy_layout_and_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let key = format!("{ACME_ISSUER}/example.com");
        let certificate = fixture_certificate();
        storage.store(&key, &certificate).await.unwrap();

        let expected_directory = directory
            .path()
            .join("certificates")
            .join(ACME_ISSUER)
            .join("example.com");
        assert!(expected_directory.join("example.com.crt").is_file());
        assert!(expected_directory.join("example.com.key").is_file());
        assert!(expected_directory.join("example.com.json").is_file());

        // Atomic writes must not leave temporary files behind.
        let mut entries = std::fs::read_dir(&expected_directory).unwrap();
        let mut names: Vec<String> = entries
            .by_ref()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["example.com.crt", "example.com.json", "example.com.key"]
        );

        let loaded = storage.load(&key).await.unwrap().unwrap();
        assert_eq!(loaded.domains, certificate.domains);
        assert_eq!(loaded.certificate_pem, certificate.certificate_pem);
        assert_eq!(
            loaded.private_key_pem.trim_end(),
            certificate.private_key_pem.trim_end()
        );
        assert_eq!(loaded.not_after_unix, certificate.not_after_unix);
        assert_eq!(loaded.certificate_pem.len(), 2, "leaf plus CA chain");
    }

    #[tokio::test]
    async fn file_storage_reads_existing_caddy_data_directory() {
        let directory = tempfile::tempdir().unwrap();
        // Recreate the CertMagic data directory layout in a temp dir.
        let certificate_directory = directory
            .path()
            .join("certificates")
            .join(ACME_ISSUER)
            .join("example.com");
        std::fs::create_dir_all(&certificate_directory).unwrap();
        std::fs::write(
            certificate_directory.join("example.com.crt"),
            include_str!("../tests/fixtures/caddy-data/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt"),
        )
        .unwrap();
        std::fs::write(
            certificate_directory.join("example.com.key"),
            include_str!("../tests/fixtures/caddy-data/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.key"),
        )
        .unwrap();
        std::fs::write(
            certificate_directory.join("example.com.json"),
            r#"{"sans":["example.com","www.example.com"]}"#,
        )
        .unwrap();

        let storage = FileStorage::new(directory.path());
        let loaded = storage
            .load(&format!("{ACME_ISSUER}/example.com"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.domains, vec!["example.com", "www.example.com"]);
        assert_eq!(loaded.not_after_unix, 1_775_001_600);
        assert!(loaded.private_key_pem.contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn file_storage_lists_certificate_keys() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let certificate = fixture_certificate();
        storage
            .store(&format!("{ACME_ISSUER}/example.com"), &certificate)
            .await
            .unwrap();
        storage
            .store("local/example.net", &certificate)
            .await
            .unwrap();
        assert_eq!(
            storage.list("").await.unwrap(),
            vec![
                format!("{ACME_ISSUER}/example.com"),
                "local/example.net".to_string()
            ]
        );
        assert_eq!(
            storage.list("local/").await.unwrap(),
            vec!["local/example.net".to_string()]
        );
        assert!(storage.list("other/").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn file_storage_maps_wildcards_to_wildcard_directories() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let mut certificate = fixture_certificate();
        certificate.domains = vec!["*.example.net".to_string()];
        storage
            .store("local/*.example.net", &certificate)
            .await
            .unwrap();
        let stored = directory
            .path()
            .join("certificates")
            .join("local")
            .join("wildcard_.example.net")
            .join("wildcard_.example.net.crt");
        assert!(stored.is_file(), "expected `{}`", stored.display());
        assert_eq!(
            storage.list("local/").await.unwrap(),
            vec!["local/*.example.net".to_string()]
        );
        let loaded = storage.load("local/*.example.net").await.unwrap().unwrap();
        assert_eq!(loaded.domains, vec!["*.example.net"]);
    }

    #[tokio::test]
    async fn file_storage_delete_removes_every_shipped_file() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let key = format!("{ACME_ISSUER}/example.com");
        storage.store(&key, &fixture_certificate()).await.unwrap();
        storage.delete(&key).await.unwrap();
        assert!(storage.load(&key).await.unwrap().is_none());
        assert!(storage.list("").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn file_storage_refuses_traversal_keys() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        for key in [
            "../escape",
            "a/../../escape",
            "/absolute/path",
            "issuer/name/extra",
            "issuer//name",
            "",
            "issuer/./name",
            "issuer/..",
            "issuer/na\\me",
        ] {
            let error = storage.store(key, &example()).await.unwrap_err();
            assert!(
                matches!(error, Error::InvalidKey(_)),
                "key `{key}` should be rejected, got {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn file_storage_reports_missing_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let key = format!("{ACME_ISSUER}/example.com");
        storage.store(&key, &fixture_certificate()).await.unwrap();
        std::fs::remove_file(
            directory
                .path()
                .join("certificates")
                .join(ACME_ISSUER)
                .join("example.com")
                .join("example.com.key"),
        )
        .unwrap();
        let error = storage.load(&key).await.unwrap_err();
        assert!(error.to_string().contains("no private key"), "{error}");
    }

    #[test]
    fn caddy_issuer_key_matches_certmagic_directory_names() {
        assert_eq!(
            caddy_issuer_key("https://acme-v02.api.letsencrypt.org/directory"),
            "acme-v02.api.letsencrypt.org-directory"
        );
        assert_eq!(
            caddy_issuer_key("https://acme-staging-v02.api.letsencrypt.org/directory"),
            "acme-staging-v02.api.letsencrypt.org-directory"
        );
        assert_eq!(
            caddy_issuer_key("https://acme.zerossl.com/v2/DV90"),
            "acme.zerossl.com-v2-DV90"
        );
        assert_eq!(
            caddy_issuer_key("http://localhost:14000/dir"),
            "localhost:14000-dir"
        );
        // Internal issuers use the CA ID unchanged.
        assert_eq!(caddy_issuer_key("local"), "local");
        assert_eq!(caddy_issuer_key("my-ca"), "my-ca");
    }

    #[test]
    fn wildcard_storage_names_round_trip() {
        assert_eq!(
            caddy_certificate_storage_name("*.example.com"),
            "wildcard_.example.com"
        );
        assert_eq!(
            caddy_certificate_name_from_storage("wildcard_.example.com"),
            "*.example.com"
        );
        assert_eq!(
            caddy_certificate_name_from_storage("example.com"),
            "example.com"
        );
    }

    #[test]
    fn pem_splitting_keeps_chain_order() {
        let pem = include_str!("../tests/fixtures/caddy-data/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt");
        let blocks = certificate_chain_pem(pem).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(blocks[0].ends_with("-----END CERTIFICATE-----"));
        assert!(blocks[1].starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn pem_parsing_rejects_malformed_documents() {
        let error = certificate_chain_pem("not pem at all").unwrap_err();
        assert!(error.to_string().contains("no PEM CERTIFICATE"));
        let error = certificate_chain_pem("-----BEGIN CERTIFICATE-----\nAA==\n").unwrap_err();
        assert!(error.to_string().contains("unterminated"));
        let error = private_key_pem("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----")
            .unwrap_err();
        assert!(error.to_string().contains("no PEM private key"));
    }

    #[test]
    fn der_not_after_matches_certificate_validity() {
        let pem = include_str!("../tests/fixtures/caddy-data/certificates/local/wildcard_.example.net/wildcard_.example.net.crt");
        assert_eq!(
            certificate_not_after_unix(pem).unwrap(),
            1_784_073_600 // 2026-07-15T00:00:00Z
        );
    }

    #[test]
    fn asn1_times_handle_utc_century_boundary() {
        // UTCTime years 50-99 are 19xx, 00-49 are 20xx.
        assert_eq!(
            parse_asn1_time(DER_UTC_TIME, b"491231235959Z").unwrap(),
            days_from_civil(2049, 12, 31) as u64 * 86_400 + 23 * 3_600 + 59 * 60 + 59
        );
        assert_eq!(
            parse_asn1_time(DER_UTC_TIME, b"991231235959Z").unwrap(),
            days_from_civil(1999, 12, 31) as u64 * 86_400 + 23 * 3_600 + 59 * 60 + 59
        );
        // Unix timestamps cannot represent 1950 here, so the parser reports a located error.
        assert!(parse_asn1_time(DER_UTC_TIME, b"500101000000Z").is_err());
        assert_eq!(
            parse_asn1_time(DER_GENERALIZED_TIME, b"20500101000000Z").unwrap(),
            days_from_civil(2050, 1, 1) as u64 * 86_400
        );
        assert!(parse_asn1_time(DER_UTC_TIME, b"49123123595").is_err());
        assert!(parse_asn1_time(DER_UTC_TIME, b"49123123595+Z").is_err());
        assert!(parse_asn1_time(DER_INTEGER, b"49123123595Z").is_err());
    }

    #[test]
    fn days_from_civil_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(days_from_civil(2026, 4, 1), 20_544);
    }

    #[tokio::test]
    async fn writes_certmagic_metadata_with_issuer_data_and_preserves_unknown_fields() {
        let temporary = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(temporary.path());
        let stored = StoredCertificate {
            certificate_pem: fixture_chain(),
            private_key_pem: fixture_key(),
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            not_after_unix: 1_775_001_600,
            issuer_data: Some(serde_json::json!({
                "url": "https://acme.test/certificate/1",
                "ca": "https://acme.test/directory",
                "account": "https://acme.test/account/1"
            })),
            metadata_extra: BTreeMap::from([(
                "future_field".to_string(),
                serde_json::json!("kept"),
            )]),
        };
        let key = "acme-v02.api.letsencrypt.org-directory/example.com";
        storage.store(key, &stored).await.unwrap();
        let metadata_path = temporary
            .path()
            .join("certificates")
            .join("acme-v02.api.letsencrypt.org-directory")
            .join(caddy_certificate_storage_name("example.com"))
            .join("example.com.json");
        let metadata = std::fs::read_to_string(&metadata_path).unwrap();
        // CertMagic uses `json.MarshalIndent(cert, "", "\t")`: tab indentation, `sans` first,
        // then `issuer_data`, no trailing newline. The opaque issuer_data object's keys are sorted
        // by serde_json's map, which is semantically identical JSON.
        let expected = "{\n\t\"sans\": [\n\t\t\"example.com\",\n\t\t\"www.example.com\"\n\t],\n\t\"issuer_data\": {\n\t\t\"account\": \"https://acme.test/account/1\",\n\t\t\"ca\": \"https://acme.test/directory\",\n\t\t\"url\": \"https://acme.test/certificate/1\"\n\t},\n\t\"future_field\": \"kept\"\n}";
        assert_eq!(metadata, expected);

        let loaded = storage
            .load(key)
            .await
            .unwrap()
            .expect("stored certificate");
        assert_eq!(loaded.issuer_data, stored.issuer_data);
        assert_eq!(loaded.metadata_extra, stored.metadata_extra);
        assert_eq!(loaded.domains, stored.domains);
        assert_eq!(loaded.not_after_unix, stored.not_after_unix);

        // Rewriting the loaded record keeps the CertMagic metadata byte-for-byte.
        storage.store(key, &loaded).await.unwrap();
        assert_eq!(std::fs::read_to_string(&metadata_path).unwrap(), expected);
    }

    #[test]
    fn builds_file_storage_from_caddy_json() {
        let storage = from_config(&serde_json::json!({
            "module": "file_system",
            "root": "/tmp/certs"
        }))
        .unwrap();
        assert_eq!(storage.name(), "file_system");
        let error = match from_config(&serde_json::json!({"module": "s3"})) {
            Ok(_) => panic!("unsupported storage modules must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("s3"));
    }
}
