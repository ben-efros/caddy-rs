//! Caddy-compatible internal certificate authority (`tls internal` / `local_certs`).
//!
//! Caddy ships a built-in CA for local HTTPS: it generates an ECDSA P-256 root and intermediate,
//! persists them in the data directory under `pki/authorities/<ca-id>/`, and signs short-lived
//! leaf certificates for the requested names. This module implements that issuer offline with the
//! crates already in the workspace (`ring` for P-256 key generation/signing; no certificate
//! generation crate such as `rcgen`/`x509-cert` is cached, so the small X.509 DER structures are
//! written by hand, mirroring the existing CSR builder in [`crate::acme::csr`]).
//!
//! # Storage layout (Caddy-compatible)
//!
//! ```text
//! <data-dir>/pki/authorities/<ca-id>/root.crt
//! <data-dir>/pki/authorities/<ca-id>/root.key
//! <data-dir>/pki/authorities/<ca-id>/intermediate.crt
//! <data-dir>/pki/authorities/<ca-id>/intermediate.key
//! <data-dir>/certificates/<ca-id>/<name>/<name>.crt / .key / .json   (leaf, via CertificateStorage)
//! ```
//!
//! The default CA ID is `local` (Caddy's `caddypki.DefaultCAID`). Root and intermediate material
//! is read back on startup, so the same root is reused across restarts; the intermediate is
//! rotated automatically when it approaches expiry (Caddy does this with a background maintenance
//! task; caddy-rs checks lazily on the next issuance). Private keys are written with `0600`
//! permissions by the filesystem backend where supported.
//!
//! # Caddy defaults reproduced
//!
//! * ECDSA P-256 keys for root, intermediate and leaves;
//! * root lifetime 10 years (Caddy: 360-day years), intermediate lifetime 7 days;
//! * leaf lifetime 12 hours (Caddy's `defaultInternalCertLifetime`);
//! * CNs `"<CA name> - <year> ECC Root"` and `"<CA name> - ECC Intermediate"` (default CA display
//!   name `Caddy Local Authority`); leaf CN is the first requested name;
//! * SANs for all requested DNS names and IP addresses, `serverAuth` EKU, CA basic constraints and
//!   key usage bits.
//!
//! # Deliberate limitations (reported as divergences)
//!
//! * no background maintenance loop: the intermediate is rotated lazily at the next issuance;
//! * no name constraints, no OCSP responder, no CRL distribution points, no AIA;
//! * no trust-store installation (`install_trust`), no `/pki` admin endpoints;
//! * only ECDSA P-256 key material is accepted; a Caddy data directory whose CA keys use another
//!   algorithm fails loudly instead of being silently ignored;
//! * Caddy stores CA material through CertMagic storage; caddy-rs uses the [`CaStorage`] blob
//!   abstraction (`Auto`/`FileStorage` implement it and map to the same paths);
//! * certificate serial numbers and backdating are not byte-identical to Caddy/smallstep.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{
    EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::acme::AcmeStorage;
use crate::certificate::Certificate;
use crate::issuer::{CertificateIssuer, IssuanceRequest};
use crate::renewal::{RenewalClock, SystemClock};
use crate::storage::{
    caddy_certificate_storage_name, caddy_issuer_key, CertificateStorage, FileStorage,
    StoredCertificate,
};
use crate::{Error, Result};

/// Default CA identifier (Caddy's `caddypki.DefaultCAID`).
pub const DEFAULT_CA_ID: &str = "local";

/// Caddy's default display name for the local CA.
pub const DEFAULT_CA_DISPLAY_NAME: &str = "Caddy Local Authority";

/// Caddy's default root lifetime: 10 years of 12 * 30 days (matching `caddypki`).
pub const DEFAULT_ROOT_LIFETIME: Duration = Duration::from_secs(10 * 12 * 30 * 24 * 60 * 60);

/// Caddy's default intermediate lifetime (7 days).
pub const DEFAULT_INTERMEDIATE_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Caddy's default internal leaf lifetime (`defaultInternalCertLifetime` = 12 hours).
pub const DEFAULT_LEAF_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

/// Clock-skew backdating applied to issued certificates (Caddy/smallstep backdate by ~1 minute).
pub const DEFAULT_BACKDATE: Duration = Duration::from_secs(60);

// ---- storage --------------------------------------------------------------------------------

/// Blob storage for CA material (root/intermediate certificates and keys).
///
/// Caddy persists CA material through its storage abstraction under `pki/authorities/<ca-id>/`;
/// this trait is the same boundary. [`FileStorage`] and [`crate::acme::MemoryAcmeStorage`]
/// implement it, and `FileStorage` writes key material with owner-only permissions.
#[async_trait]
pub trait CaStorage: Send + Sync {
    /// Backend name (for diagnostics).
    fn name(&self) -> &'static str;

    /// Load a value by key.
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Store a value, replacing any existing value.
    async fn store(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Store private key material. Implementations should restrict permissions (0600) where the
    /// backend supports it.
    async fn store_key(&self, key: &str, value: &[u8]) -> Result<()> {
        self.store(key, value).await
    }
}

#[async_trait]
impl<T: CaStorage + ?Sized> CaStorage for Arc<T> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        (**self).load(key).await
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        (**self).store(key, value).await
    }

    async fn store_key(&self, key: &str, value: &[u8]) -> Result<()> {
        (**self).store_key(key, value).await
    }
}

#[async_trait]
impl CaStorage for crate::acme::MemoryAcmeStorage {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        AcmeStorage::load(self, key).await
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        AcmeStorage::store(self, key, value).await
    }
}

#[async_trait]
impl CaStorage for FileStorage {
    fn name(&self) -> &'static str {
        "file_system"
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        AcmeStorage::load(self, key).await
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        AcmeStorage::store(self, key, value).await
    }

    async fn store_key(&self, key: &str, value: &[u8]) -> Result<()> {
        AcmeStorage::store(self, key, value).await?;
        restrict_key_permissions(&self.root().join(key)).await;
        Ok(())
    }
}

/// Best-effort `0600` permissions for key files on Unix.
async fn restrict_key_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Certificate/key storage keys for one CA, matching Caddy's layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaStorageKeys {
    /// `pki/authorities/<ca-id>/root.crt`
    pub root_certificate: String,
    /// `pki/authorities/<ca-id>/root.key`
    pub root_key: String,
    /// `pki/authorities/<ca-id>/intermediate.crt`
    pub intermediate_certificate: String,
    /// `pki/authorities/<ca-id>/intermediate.key`
    pub intermediate_key: String,
}

/// Compute Caddy's CA storage keys for `ca_id`.
///
/// CA identifiers must be filesystem-safe (`[A-Za-z0-9._-]`); Caddy applies a similar
/// `StorageKeys.Safe` transform, and an unsafe identifier fails loudly here.
pub fn ca_storage_keys(ca_id: &str) -> Result<CaStorageKeys> {
    if ca_id.is_empty()
        || !ca_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::Issuer(format!(
            "internal CA id `{ca_id}` is not a safe storage path component"
        )));
    }
    let prefix = format!("pki/authorities/{ca_id}");
    Ok(CaStorageKeys {
        root_certificate: format!("{prefix}/root.crt"),
        root_key: format!("{prefix}/root.key"),
        intermediate_certificate: format!("{prefix}/intermediate.crt"),
        intermediate_key: format!("{prefix}/intermediate.key"),
    })
}

// ---- lifetimes ------------------------------------------------------------------------------

/// Lifetime configuration for the local CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaLifetimes {
    /// Root certificate lifetime (default 10 years).
    pub root: Duration,
    /// Intermediate certificate lifetime (default 7 days).
    pub intermediate: Duration,
    /// Leaf certificate lifetime (default 12 hours).
    pub leaf: Duration,
    /// Backdate applied to `notBefore` (default 1 minute).
    pub backdate: Duration,
}

impl Default for CaLifetimes {
    fn default() -> Self {
        Self {
            root: DEFAULT_ROOT_LIFETIME,
            intermediate: DEFAULT_INTERMEDIATE_LIFETIME,
            leaf: DEFAULT_LEAF_LIFETIME,
            backdate: DEFAULT_BACKDATE,
        }
    }
}

// ---- public CA snapshots --------------------------------------------------------------------

/// PEM/DER views of a loaded local CA, for trust installation and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaCertificates {
    /// Root certificate PEM (never the key).
    pub root_pem: String,
    /// Root certificate DER.
    pub root_der: Vec<u8>,
    /// Intermediate certificate PEM.
    pub intermediate_pem: String,
    /// Intermediate certificate DER.
    pub intermediate_der: Vec<u8>,
    /// Intermediate + root chain, PEM concatenated (suitable for a trust bundle).
    pub chain_pem: String,
}

/// A loaded local CA: persisted root and intermediate certificates plus signing keys.
pub struct LocalCa {
    name: String,
    root_certificate_pem: String,
    root_certificate_der: Vec<u8>,
    intermediate_certificate_pem: String,
    intermediate_certificate_der: Vec<u8>,
    root: ParsedCertificate,
    intermediate: ParsedCertificate,
    intermediate_key: EcdsaKeyPair,
}

impl fmt::Debug for LocalCa {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCa")
            .field("name", &self.name)
            .field("root_not_after", &self.root.not_after)
            .field("intermediate_not_after", &self.intermediate.not_after)
            .finish_non_exhaustive()
    }
}

impl LocalCa {
    /// CA identifier (`local` by default).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Root certificate DER.
    pub fn root_certificate_der(&self) -> &[u8] {
        &self.root_certificate_der
    }

    /// Intermediate certificate DER.
    pub fn intermediate_certificate_der(&self) -> &[u8] {
        &self.intermediate_certificate_der
    }

    /// Root certificate PEM.
    pub fn root_certificate_pem(&self) -> &str {
        &self.root_certificate_pem
    }

    /// Intermediate certificate PEM.
    pub fn intermediate_certificate_pem(&self) -> &str {
        &self.intermediate_certificate_pem
    }

    /// Validity window of the root certificate.
    pub fn root_validity(&self) -> (SystemTime, SystemTime) {
        (self.root.not_before, self.root.not_after)
    }

    /// Validity window of the intermediate certificate.
    pub fn intermediate_validity(&self) -> (SystemTime, SystemTime) {
        (self.intermediate.not_before, self.intermediate.not_after)
    }

    /// Snapshot of the CA certificates for trust installation/diagnostics.
    pub fn certificates(&self) -> CaCertificates {
        let chain_pem = format!(
            "{}{}",
            self.intermediate_certificate_pem, self.root_certificate_pem
        );
        CaCertificates {
            root_pem: self.root_certificate_pem.clone(),
            root_der: self.root_certificate_der.clone(),
            intermediate_pem: self.intermediate_certificate_pem.clone(),
            intermediate_der: self.intermediate_certificate_der.clone(),
            chain_pem,
        }
    }

    fn root_expired(&self, now: SystemTime) -> bool {
        now >= self.root.not_after
    }

    fn intermediate_needs_renewal(&self, now: SystemTime) -> bool {
        needs_intermediate_renewal(&self.intermediate, now)
    }
}

// ---- issuer ---------------------------------------------------------------------------------

/// The internal/local CA issuer used for `tls internal` and `local_certs`.
pub struct InternalIssuer {
    /// CA identifier used in the storage layout (Caddy's `caddypki.DefaultCAID`, `local`).
    pub name: String,
    display_name: String,
    storage: Option<Arc<dyn CaStorage>>,
    certificate_storage: Option<Box<dyn CertificateStorage>>,
    clock: Arc<dyn RenewalClock>,
    lifetimes: CaLifetimes,
    ca: Mutex<Option<Arc<LocalCa>>>,
}

impl Default for InternalIssuer {
    fn default() -> Self {
        Self {
            name: DEFAULT_CA_ID.to_string(),
            display_name: DEFAULT_CA_DISPLAY_NAME.to_string(),
            storage: None,
            certificate_storage: None,
            clock: Arc::new(SystemClock),
            lifetimes: CaLifetimes::default(),
            ca: Mutex::new(None),
        }
    }
}

impl fmt::Debug for InternalIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalIssuer")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("lifetimes", &self.lifetimes)
            .field("configured", &self.storage.is_some())
            .finish_non_exhaustive()
    }
}

impl InternalIssuer {
    /// Create an issuer persisting CA material in `storage` and leaf certificates in
    /// `certificate_storage`.
    pub fn new(
        storage: Arc<dyn CaStorage>,
        certificate_storage: Box<dyn CertificateStorage>,
    ) -> Self {
        Self {
            storage: Some(storage),
            certificate_storage: Some(certificate_storage),
            ..Self::default()
        }
    }

    /// Create an issuer rooted at a Caddy data directory: CA material under
    /// `<data-dir>/pki/authorities/...` and leaves under `<data-dir>/certificates/...`.
    pub fn from_data_directory(data_directory: impl Into<std::path::PathBuf>) -> Self {
        let root = data_directory.into();
        let storage: Arc<dyn CaStorage> = Arc::new(FileStorage::new(&root));
        let certificate_storage: Box<dyn CertificateStorage> = Box::new(FileStorage::new(root));
        Self::new(storage, certificate_storage)
    }

    /// Set the CA identifier (storage path component).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the CA display name used in root/intermediate common names.
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = display_name.into();
        self
    }

    /// Inject the clock used for validity windows (tests use a manual clock).
    pub fn with_clock(mut self, clock: Arc<dyn RenewalClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override root/intermediate/leaf lifetimes.
    pub fn with_lifetimes(mut self, lifetimes: CaLifetimes) -> Self {
        self.lifetimes = lifetimes;
        self
    }

    /// Load the CA certificates, generating/persisting them on first use.
    pub async fn ca_certificates(&self) -> Result<CaCertificates> {
        Ok(self.load_ca().await?.certificates())
    }

    /// Load (or create) the local CA.
    pub async fn load_ca(&self) -> Result<Arc<LocalCa>> {
        let storage = self.storage.clone().ok_or_else(|| {
            Error::Issuer(
                "internal CA issuer is not configured with CA storage; construct it with \
                 InternalIssuer::new or InternalIssuer::from_data_directory"
                    .to_string(),
            )
        })?;
        let now = self.clock.now();
        let mut guard = self.ca.lock().await;
        if let Some(ca) = guard.as_ref() {
            if ca.root_expired(now) {
                return Err(Error::Issuer(format!(
                    "internal CA `{}` root certificate expired at {:?}; remove the CA material \
                     from storage to generate a new local CA",
                    ca.name, ca.root.not_after
                )));
            }
            if !ca.intermediate_needs_renewal(now) {
                return Ok(Arc::clone(ca));
            }
            let renewed = Arc::new(self.load_or_create_ca(&storage, now).await?);
            *guard = Some(Arc::clone(&renewed));
            return Ok(renewed);
        }
        let ca = Arc::new(self.load_or_create_ca(&storage, now).await?);
        *guard = Some(Arc::clone(&ca));
        Ok(ca)
    }

    async fn load_or_create_ca(
        &self,
        storage: &Arc<dyn CaStorage>,
        now: SystemTime,
    ) -> Result<LocalCa> {
        let keys = ca_storage_keys(&self.name)?;
        let root = self.load_or_create_root(storage, &keys, now).await?;
        let intermediate = self
            .load_or_create_intermediate(storage, &keys, &root, now)
            .await?;
        Ok(LocalCa {
            name: self.name.clone(),
            root_certificate_pem: root.0,
            root_certificate_der: root.1,
            root: root.2,
            intermediate_certificate_pem: intermediate.0,
            intermediate_certificate_der: intermediate.1,
            intermediate: intermediate.2,
            intermediate_key: intermediate.3,
        })
    }

    async fn load_or_create_root(
        &self,
        storage: &Arc<dyn CaStorage>,
        keys: &CaStorageKeys,
        now: SystemTime,
    ) -> Result<(String, Vec<u8>, ParsedCertificate, EcdsaKeyPair)> {
        let certificate_pem = storage.load(&keys.root_certificate).await?;
        let key_pem = storage.load(&keys.root_key).await?;
        match (certificate_pem, key_pem) {
            (Some(certificate_pem), Some(key_pem)) => {
                let certificate_pem = String::from_utf8(certificate_pem).map_err(|error| {
                    Error::Issuer(format!(
                        "stored internal CA root certificate `{}` is not UTF-8 PEM: {error}",
                        keys.root_certificate
                    ))
                })?;
                let key_pem = String::from_utf8(key_pem).map_err(|error| {
                    Error::Issuer(format!(
                        "stored internal CA root key `{}` is not UTF-8 PEM: {error}",
                        keys.root_key
                    ))
                })?;
                let der = pem_first_der(&certificate_pem, "CERTIFICATE").map_err(|error| {
                    Error::Issuer(format!(
                        "cannot parse stored internal CA root certificate `{}`: {error}",
                        keys.root_certificate
                    ))
                })?;
                let parsed = parse_certificate(&der).map_err(|error| {
                    Error::Issuer(format!(
                        "cannot parse stored internal CA root certificate `{}`: {error}",
                        keys.root_certificate
                    ))
                })?;
                if parsed.not_after <= now {
                    return Err(Error::Issuer(format!(
                        "stored internal CA root certificate `{}` expired at {:?}; remove the CA \
                         material from storage to generate a new local CA",
                        keys.root_certificate, parsed.not_after
                    )));
                }
                let key = load_ecdsa_key(&key_pem).map_err(|error| {
                    Error::Issuer(format!(
                        "cannot load stored internal CA root key `{}`: {error}",
                        keys.root_key
                    ))
                })?;
                if key.public_key().as_ref() != parsed.public_key.as_slice() {
                    return Err(Error::Issuer(format!(
                        "stored internal CA root key `{}` does not match root certificate `{}`",
                        keys.root_key, keys.root_certificate
                    )));
                }
                Ok((certificate_pem, der, parsed, key))
            }
            (None, None) => {
                let key = generate_key()?;
                let not_before = now - self.lifetimes.backdate;
                let not_after = not_before + self.lifetimes.root;
                let subject = subject_name(&root_common_name(&self.display_name, now)?);
                let spki = subject_public_key_info(&key.public_key);
                let subject_key_id = key_identifier(&key.public_key);
                let der = create_certificate(
                    &CertSpec {
                        serial: &random_serial()?,
                        issuer_subject: &subject,
                        subject: &subject,
                        spki: &spki,
                        not_before,
                        not_after,
                        is_ca: true,
                        path_len: None,
                        key_usage_bits: &[5, 6], // keyCertSign, cRLSign
                        server_auth: false,
                        san: &[],
                        subject_key_id: Some(&subject_key_id),
                        authority_key_id: None,
                    },
                    &key.pair,
                )?;
                let certificate_pem = pem_encode("CERTIFICATE", &der);
                storage
                    .store_key(
                        &keys.root_key,
                        pem_encode("PRIVATE KEY", &key.pkcs8_der).as_bytes(),
                    )
                    .await
                    .map_err(|error| {
                        Error::Issuer(format!(
                            "cannot persist internal CA root key `{}`: {error}",
                            keys.root_key
                        ))
                    })?;
                storage
                    .store(&keys.root_certificate, certificate_pem.as_bytes())
                    .await
                    .map_err(|error| {
                        Error::Issuer(format!(
                            "cannot persist internal CA root certificate `{}`: {error}",
                            keys.root_certificate
                        ))
                    })?;
                let parsed = parse_certificate(&der)?;
                Ok((certificate_pem, der, parsed, key.pair))
            }
            (Some(_), None) => Err(Error::Issuer(format!(
                "internal CA root certificate `{}` exists but its private key `{}` is missing; \
                 refusing to regenerate the CA because that would invalidate existing certificates",
                keys.root_certificate, keys.root_key
            ))),
            (None, Some(_)) => Err(Error::Issuer(format!(
                "internal CA root key `{}` exists but its certificate `{}` is missing; remove the \
                 stray key to generate a new local CA",
                keys.root_key, keys.root_certificate
            ))),
        }
    }

    async fn load_or_create_intermediate(
        &self,
        storage: &Arc<dyn CaStorage>,
        keys: &CaStorageKeys,
        root: &(String, Vec<u8>, ParsedCertificate, EcdsaKeyPair),
        now: SystemTime,
    ) -> Result<(String, Vec<u8>, ParsedCertificate, EcdsaKeyPair)> {
        let certificate_pem = storage.load(&keys.intermediate_certificate).await?;
        let key_pem = storage.load(&keys.intermediate_key).await?;
        match (certificate_pem, key_pem) {
            (Some(certificate_pem), Some(key_pem)) => {
                let certificate_pem = String::from_utf8(certificate_pem).map_err(|error| {
                    Error::Issuer(format!(
                        "stored internal CA intermediate certificate `{}` is not UTF-8 PEM: \
                         {error}",
                        keys.intermediate_certificate
                    ))
                })?;
                let key_pem = String::from_utf8(key_pem).map_err(|error| {
                    Error::Issuer(format!(
                        "stored internal CA intermediate key `{}` is not UTF-8 PEM: {error}",
                        keys.intermediate_key
                    ))
                })?;
                let der = pem_first_der(&certificate_pem, "CERTIFICATE").map_err(|error| {
                    Error::Issuer(format!(
                        "cannot parse stored internal CA intermediate certificate `{}`: {error}",
                        keys.intermediate_certificate
                    ))
                })?;
                let parsed = parse_certificate(&der).map_err(|error| {
                    Error::Issuer(format!(
                        "cannot parse stored internal CA intermediate certificate `{}`: {error}",
                        keys.intermediate_certificate
                    ))
                })?;
                if !needs_intermediate_renewal(&parsed, now) {
                    let key = load_ecdsa_key(&key_pem).map_err(|error| {
                        Error::Issuer(format!(
                            "cannot load stored internal CA intermediate key `{}`: {error}",
                            keys.intermediate_key
                        ))
                    })?;
                    if key.public_key().as_ref() != parsed.public_key.as_slice() {
                        return Err(Error::Issuer(format!(
                            "stored internal CA intermediate key `{}` does not match \
                             intermediate certificate `{}`",
                            keys.intermediate_key, keys.intermediate_certificate
                        )));
                    }
                    return Ok((certificate_pem, der, parsed, key));
                }
                // Expiring/expired: re-sign a new intermediate with the existing root.
                let (certificate_pem, der, parsed, key) =
                    self.generate_intermediate(storage, keys, root, now).await?;
                Ok((certificate_pem, der, parsed, key))
            }
            (None, None) => self.generate_intermediate(storage, keys, root, now).await,
            (Some(_), None) => Err(Error::Issuer(format!(
                "internal CA intermediate certificate `{}` exists but its private key `{}` is \
                 missing; refusing to sign a new intermediate without the existing key",
                keys.intermediate_certificate, keys.intermediate_key
            ))),
            (None, Some(_)) => Err(Error::Issuer(format!(
                "internal CA intermediate key `{}` exists but its certificate `{}` is missing; \
                 remove the stray key to generate a new intermediate",
                keys.intermediate_key, keys.intermediate_certificate
            ))),
        }
    }

    async fn generate_intermediate(
        &self,
        storage: &Arc<dyn CaStorage>,
        keys: &CaStorageKeys,
        root: &(String, Vec<u8>, ParsedCertificate, EcdsaKeyPair),
        now: SystemTime,
    ) -> Result<(String, Vec<u8>, ParsedCertificate, EcdsaKeyPair)> {
        let key = generate_key()?;
        let not_before = now - self.lifetimes.backdate;
        let not_after = not_before + self.lifetimes.intermediate;
        if not_after >= root.2.not_after {
            return Err(Error::Issuer(
                "internal CA intermediate lifetime must be shorter than the remaining root \
                 certificate lifetime; regenerate the root or shorten the intermediate lifetime"
                    .to_string(),
            ));
        }
        let subject = subject_name(&format!("{} - ECC Intermediate", self.display_name));
        let spki = subject_public_key_info(&key.public_key);
        let subject_key_id = key_identifier(&key.public_key);
        let issuer_key_id = issuer_key_identifier(&root.2);
        let der = create_certificate(
            &CertSpec {
                serial: &random_serial()?,
                issuer_subject: &root.2.subject_der,
                subject: &subject,
                spki: &spki,
                not_before,
                not_after,
                is_ca: true,
                path_len: Some(0),
                key_usage_bits: &[5, 6],
                server_auth: false,
                san: &[],
                subject_key_id: Some(&subject_key_id),
                authority_key_id: Some(&issuer_key_id),
            },
            &root.3,
        )?;
        let certificate_pem = pem_encode("CERTIFICATE", &der);
        storage
            .store_key(
                &keys.intermediate_key,
                pem_encode("PRIVATE KEY", &key.pkcs8_der).as_bytes(),
            )
            .await
            .map_err(|error| {
                Error::Issuer(format!(
                    "cannot persist internal CA intermediate key `{}`: {error}",
                    keys.intermediate_key
                ))
            })?;
        storage
            .store(&keys.intermediate_certificate, certificate_pem.as_bytes())
            .await
            .map_err(|error| {
                Error::Issuer(format!(
                    "cannot persist internal CA intermediate certificate `{}`: {error}",
                    keys.intermediate_certificate
                ))
            })?;
        let parsed = parse_certificate(&der)?;
        Ok((certificate_pem, der, parsed, key.pair))
    }

    async fn issue_leaf(
        &self,
        ca: &LocalCa,
        domains: &[String],
        key_type: crate::acme::csr::CertificateKeyType,
        now: SystemTime,
    ) -> Result<Certificate> {
        let certificate_storage = self.certificate_storage.as_ref().ok_or_else(|| {
            Error::Issuer(
                "internal CA issuer is not configured with certificate storage; construct it with \
                 InternalIssuer::new or InternalIssuer::from_data_directory"
                    .to_string(),
            )
        })?;
        let key = generate_leaf_key(key_type)?;
        let not_before = now - self.lifetimes.backdate;
        let not_after = not_before + self.lifetimes.leaf;

        let spki = key.spki.clone();
        let subject_key_id = key.subject_key_id.clone();
        let issuer_key_id = issuer_key_identifier(&ca.intermediate);
        let der = create_certificate(
            &CertSpec {
                serial: &random_serial()?,
                issuer_subject: &ca.intermediate.subject_der,
                subject: &subject_name(&domains[0]),
                spki: &spki,
                not_before,
                not_after,
                is_ca: false,
                path_len: None,
                key_usage_bits: &[0], // digitalSignature
                server_auth: true,
                san: domains,
                subject_key_id: Some(&subject_key_id),
                authority_key_id: Some(&issuer_key_id),
            },
            &ca.intermediate_key,
        )?;

        let leaf_pem = pem_encode("CERTIFICATE", &der);
        let key_pem = pem_encode("PRIVATE KEY", &key.pkcs8_der);
        let stored = StoredCertificate {
            certificate_pem: vec![leaf_pem, ca.intermediate_certificate_pem.clone()],
            private_key_pem: key_pem,
            domains: domains.to_vec(),
            not_after_unix: system_time_to_unix(not_after)?,
            issuer_data: None,
            metadata_extra: std::collections::BTreeMap::new(),
        };
        let storage_key = format!(
            "{}/{}",
            caddy_issuer_key(&self.name),
            caddy_certificate_storage_name(&domains[0])
        );
        certificate_storage
            .store(&storage_key, &stored)
            .await
            .map_err(|error| {
                Error::Issuer(format!(
                    "cannot persist internal certificate for `{}`: {error}",
                    domains[0]
                ))
            })?;

        Ok(Certificate {
            domains: domains.to_vec(),
            cert_chain_der: vec![der, ca.intermediate_certificate_der.clone()],
            private_key_der: key.pkcs8_der,
            not_before,
            not_after,
            issuer: self.name.clone(),
        })
    }
}

#[async_trait]
impl CertificateIssuer for InternalIssuer {
    fn name(&self) -> &'static str {
        "internal"
    }

    async fn obtain(&self, request: &IssuanceRequest) -> Result<Certificate> {
        if request.domains.is_empty() {
            return Err(Error::Issuer(
                "internal CA certificate request has no domains".to_string(),
            ));
        }
        let domains = normalize_domains(&request.domains)?;
        let ca = self.load_ca().await?;
        let now = self.clock.now();
        self.issue_leaf(&ca, &domains, request.key_type, now).await
    }
}

fn normalize_domains(domains: &[String]) -> Result<Vec<String>> {
    let mut normalized: Vec<String> = Vec::new();
    for domain in domains {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return Err(Error::Issuer(
                "internal CA certificate request contains an empty name".to_string(),
            ));
        }
        let is_ip = domain.parse::<IpAddr>().is_ok();
        if !is_ip
            && (domain.contains('/')
                || domain.contains('\0')
                || domain.bytes().any(|byte| byte.is_ascii_whitespace()))
        {
            return Err(Error::Issuer(format!(
                "internal CA certificate request contains an invalid name `{domain}`"
            )));
        }
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    Ok(normalized)
}

fn root_common_name(display_name: &str, now: SystemTime) -> Result<String> {
    let (year, _, _, _, _, _) = civil_from_unix(system_time_to_unix(now)?);
    Ok(format!("{display_name} - {year} ECC Root"))
}

// ---- key handling ---------------------------------------------------------------------------

struct GeneratedKey {
    pair: EcdsaKeyPair,
    pkcs8_der: Vec<u8>,
    public_key: Vec<u8>,
}

fn generate_key() -> Result<GeneratedKey> {
    let rng = SystemRandom::new();
    let pkcs8_der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|error| Error::Issuer(format!("internal CA key generation failed: {error}")))?
        .as_ref()
        .to_vec();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_der, &rng)
        .map_err(|error| Error::Issuer(format!("internal CA key load failed: {error}")))?;
    let public_key = pair.public_key().as_ref().to_vec();
    Ok(GeneratedKey {
        pair,
        pkcs8_der,
        public_key,
    })
}

/// A freshly generated leaf key: PKCS#8 private key, SPKI and SubjectKeyIdentifier input.
struct GeneratedLeafKey {
    pkcs8_der: Vec<u8>,
    spki: Vec<u8>,
    subject_key_id: Vec<u8>,
}

/// Generate a leaf key of the configured automation-policy type.
///
/// P-256/P-384 use ring ECDSA; RSA 2048/4096 use the workspace `rsa` crate. Caddy additionally
/// supports `ed25519`, which this build rejects at configuration parsing (no PKCS#10 Ed25519
/// signing path). The certificate's signature algorithm remains the CA's (P-256) — only the
/// subject key and SPKI vary.
fn generate_leaf_key(key_type: crate::acme::csr::CertificateKeyType) -> Result<GeneratedLeafKey> {
    use crate::acme::csr::CertificateKeyType;
    match key_type {
        CertificateKeyType::P256 | CertificateKeyType::P384 => {
            let (algorithm, curve_oid) = match key_type {
                CertificateKeyType::P256 => (&ECDSA_P256_SHA256_ASN1_SIGNING, OID_PRIME256V1),
                CertificateKeyType::P384 => (&ECDSA_P384_SHA384_ASN1_SIGNING, OID_SECP384R1),
                _ => unreachable!("EC branch only"),
            };
            let rng = SystemRandom::new();
            let pkcs8_der = EcdsaKeyPair::generate_pkcs8(algorithm, &rng)
                .map_err(|error| {
                    Error::Issuer(format!("internal CA leaf key generation failed: {error}"))
                })?
                .as_ref()
                .to_vec();
            let pair = EcdsaKeyPair::from_pkcs8(algorithm, &pkcs8_der, &rng).map_err(|error| {
                Error::Issuer(format!("internal CA leaf key load failed: {error}"))
            })?;
            let public_key = pair.public_key().as_ref().to_vec();
            let spki = der_sequence(&[
                der_sequence(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(curve_oid)]),
                der_bit_string(&public_key),
            ]);
            Ok(GeneratedLeafKey {
                pkcs8_der,
                spki,
                subject_key_id: key_identifier(&public_key),
            })
        }
        CertificateKeyType::Rsa2048 | CertificateKeyType::Rsa4096 => {
            let bits = if matches!(key_type, CertificateKeyType::Rsa2048) {
                2048
            } else {
                4096
            };
            let mut rng = rsa::rand_core::OsRng;
            let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|error| {
                Error::Issuer(format!(
                    "internal CA RSA-{bits} key generation failed: {error}"
                ))
            })?;
            let pkcs8_der = private_key
                .to_pkcs8_der()
                .map_err(|error| {
                    Error::Issuer(format!(
                        "internal CA RSA private key encoding failed: {error}"
                    ))
                })?
                .as_bytes()
                .to_vec();
            let spki = private_key
                .to_public_key()
                .to_public_key_der()
                .map_err(|error| {
                    Error::Issuer(format!(
                        "internal CA RSA public key encoding failed: {error}"
                    ))
                })?
                .as_bytes()
                .to_vec();
            Ok(GeneratedLeafKey {
                pkcs8_der,
                subject_key_id: key_identifier(&spki),
                spki,
            })
        }
    }
}

fn load_ecdsa_key(pem: &str) -> Result<EcdsaKeyPair> {
    let der = pem_first_der(pem, "PRIVATE KEY")?;
    let rng = SystemRandom::new();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der, &rng)
        .map_err(|error| Error::Issuer(format!("not an ECDSA P-256 PKCS#8 key: {error}")))
}

/// Generate a positive 16-byte serial number.
fn random_serial() -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut serial = [0u8; 16];
    rng.fill(&mut serial)
        .map_err(|_| Error::Issuer("internal CA random serial generation failed".to_string()))?;
    serial[0] = (serial[0] & 0x7f) | 0x01;
    Ok(serial.to_vec())
}

// ---- certificate creation -------------------------------------------------------------------

/// Inputs for one X.509 certificate to be signed.
struct CertSpec<'a> {
    serial: &'a [u8],
    issuer_subject: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
    not_before: SystemTime,
    not_after: SystemTime,
    is_ca: bool,
    path_len: Option<u64>,
    key_usage_bits: &'a [u8],
    server_auth: bool,
    san: &'a [String],
    /// SubjectKeyIdentifier to emit (SHA-1 of this certificate's public key).
    subject_key_id: Option<&'a [u8]>,
    /// AuthorityKeyIdentifier keyIdentifier to emit (the issuing CA's subject key identifier).
    authority_key_id: Option<&'a [u8]>,
}

/// RFC 5280 (4.2.1.2) method 1 subject key identifier: SHA-1 over the contents of the
/// subjectPublicKey BIT STRING (the uncompressed EC point, excluding tag/length/unused-bits).
fn key_identifier(public_key: &[u8]) -> Vec<u8> {
    digest(&SHA1_FOR_LEGACY_USE_ONLY, public_key)
        .as_ref()
        .to_vec()
}

/// The key identifier an issuer certificate advertises: its own SKI, or the RFC 5280 method 1
/// value derived from its public key for CA material persisted before SKI support was added.
fn issuer_key_identifier(issuer: &ParsedCertificate) -> Vec<u8> {
    issuer
        .subject_key_identifier
        .clone()
        .unwrap_or_else(|| key_identifier(&issuer.public_key))
}

fn create_certificate(spec: &CertSpec<'_>, signer: &EcdsaKeyPair) -> Result<Vec<u8>> {
    let sig_alg = signature_algorithm();
    let tbs = der_sequence(&[
        // version [0] EXPLICIT v3
        der_tlv(0xA0, &der_integer(2)),
        der_integer_bytes(spec.serial),
        sig_alg.clone(),
        spec.issuer_subject.to_vec(),
        der_sequence(&[
            der_generalized_time(spec.not_before)?,
            der_generalized_time(spec.not_after)?,
        ]),
        spec.subject.to_vec(),
        spec.spki.to_vec(),
        extensions(spec),
    ]);
    let rng = SystemRandom::new();
    let signature = signer
        .sign(&rng, &tbs)
        .map_err(|_| Error::Issuer("internal CA certificate signing failed".to_string()))?;
    Ok(der_sequence(&[
        tbs,
        sig_alg,
        der_bit_string(signature.as_ref()),
    ]))
}

fn extensions(spec: &CertSpec<'_>) -> Vec<u8> {
    let mut extensions = Vec::new();
    // basicConstraints
    let basic_constraints = if spec.is_ca {
        let mut items = vec![der_boolean(true)];
        if let Some(path_len) = spec.path_len {
            items.push(der_integer(path_len));
        }
        der_sequence(&items)
    } else {
        der_sequence(&[])
    };
    extensions.push(extension(
        OID_BASIC_CONSTRAINTS,
        spec.is_ca,
        &basic_constraints,
    ));
    // keyUsage
    extensions.push(extension(
        OID_KEY_USAGE,
        true,
        &key_usage(spec.key_usage_bits),
    ));
    // subjectKeyIdentifier (RFC 5280 4.2.1.2): KeyIdentifier is an OCTET STRING; the extension
    // value wraps that DER. Non-critical, matching Caddy/smallstep and strict verifiers.
    if let Some(subject_key_id) = spec.subject_key_id {
        extensions.push(extension(
            OID_SUBJECT_KEY_IDENTIFIER,
            false,
            &der_tlv(0x04, subject_key_id),
        ));
    }
    // authorityKeyIdentifier (RFC 5280 4.2.1.1): SEQUENCE { keyIdentifier [0] IMPLICIT OCTET
    // STRING }. Non-critical. Emitted for intermediate and leaf certificates so strict clients can
    // link the chain by key id (root is self-signed and has no AKI).
    if let Some(authority_key_id) = spec.authority_key_id {
        extensions.push(extension(
            OID_AUTHORITY_KEY_IDENTIFIER,
            false,
            &der_sequence(&[der_tlv(0x80, authority_key_id)]),
        ));
    }
    // extendedKeyUsage: serverAuth for leaves
    if spec.server_auth {
        extensions.push(extension(
            OID_EXTENDED_KEY_USAGE,
            false,
            &der_sequence(&[der_oid(OID_SERVER_AUTH)]),
        ));
    }
    // subjectAltName for leaves
    if !spec.san.is_empty() {
        extensions.push(extension(
            OID_SUBJECT_ALT_NAME,
            false,
            &general_names(spec.san),
        ));
    }
    if extensions.is_empty() {
        return Vec::new();
    }
    der_tlv(0xA3, &der_sequence(&extensions))
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

fn subject_name(common_name: &str) -> Vec<u8> {
    let attribute = der_sequence(&[der_oid(OID_COMMON_NAME), der_utf8_string(common_name)]);
    der_sequence(&[der_set(&[attribute])])
}

fn signature_algorithm() -> Vec<u8> {
    der_sequence(&[der_oid(OID_ECDSA_WITH_SHA256)])
}

fn key_usage(bits: &[u8]) -> Vec<u8> {
    if bits.is_empty() {
        return der_bit_string(&[]);
    }
    let max_bit = *bits.iter().max().unwrap_or(&0);
    let byte_len = (max_bit as usize / 8) + 1;
    let mut bytes = vec![0u8; byte_len];
    for bit in bits {
        bytes[(*bit as usize) / 8] |= 0x80 >> (*bit % 8);
    }
    let unused_bits = (byte_len * 8) - 1 - max_bit as usize;
    let mut content = vec![unused_bits as u8];
    content.extend(bytes);
    der_tlv(0x03, &content)
}

fn extension(oid: &[u64], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![der_oid(oid)];
    if critical {
        parts.push(der_boolean(true));
    }
    parts.push(der_octet_string(value));
    der_sequence(&parts)
}

const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_SECP384R1: &[u64] = &[1, 3, 132, 0, 34];
const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];
const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
const OID_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37];
const OID_SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];
const OID_AUTHORITY_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 35];
const OID_SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];

fn subject_public_key_info(public_key: &[u8]) -> Vec<u8> {
    let algorithm = der_sequence(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)]);
    der_sequence(&[algorithm, der_bit_string(public_key)])
}

// ---- PEM / DER helpers ----------------------------------------------------------------------

fn pem_first_der(document: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut inside = false;
    let mut body = String::new();
    for line in document.lines() {
        let line = line.trim_end_matches('\r');
        if !inside {
            if line.trim() == begin {
                inside = true;
            }
        } else if line.trim() == end {
            let der = STANDARD
                .decode(body.as_bytes())
                .map_err(|error| Error::Issuer(format!("invalid `{label}` PEM base64: {error}")))?;
            return Ok(der);
        } else {
            body.push_str(line.trim());
        }
    }
    if inside {
        Err(Error::Issuer(format!(
            "unterminated `{label}` PEM block (missing `{end}`)"
        )))
    } else {
        Err(Error::Issuer(format!(
            "PEM document contains no `{label}` block"
        )))
    }
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
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
    der_integer_bytes(&value.to_be_bytes())
}

fn der_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let mut content = bytes[first_non_zero..].to_vec();
    if content.is_empty() {
        content.push(0);
    }
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der_tlv(0x02, &content)
}

fn der_boolean(value: bool) -> Vec<u8> {
    der_tlv(0x01, &[if value { 0xff } else { 0x00 }])
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
    inner.push(0);
    inner.extend_from_slice(content);
    der_tlv(0x03, &inner)
}

fn der_utf8_string(value: &str) -> Vec<u8> {
    der_tlv(0x0C, value.as_bytes())
}

fn der_generalized_time(time: SystemTime) -> Result<Vec<u8>> {
    let (year, month, day, hour, minute, second) = civil_from_unix(system_time_to_unix(time)?);
    let formatted = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
    Ok(der_tlv(0x18, formatted.as_bytes()))
}

fn system_time_to_unix(time: SystemTime) -> Result<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::Issuer("timestamp is before the Unix epoch".to_string()))
}

/// Civil date-time from Unix seconds (proleptic Gregorian; Howard Hinnant's algorithm).
fn civil_from_unix(seconds: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = (remainder / 3_600) as u32;
    let minute = ((remainder % 3_600) / 60) as u32;
    let second = (remainder % 60) as u32;
    (year, month, day, hour, minute, second)
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = (month_prime + if month_prime < 10 { 3 } else { -9 }) as u32;
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

// ---- minimal certificate parsing (for reuse of stored CA material) --------------------------

/// Rotate when 20% of the intermediate's lifetime remains, like Caddy's maintenance task
/// (`renewal_window_ratio` default 0.2).
fn needs_intermediate_renewal(parsed: &ParsedCertificate, now: SystemTime) -> bool {
    let lifetime = parsed
        .not_after
        .duration_since(parsed.not_before)
        .unwrap_or(DEFAULT_INTERMEDIATE_LIFETIME);
    let renew_at = parsed.not_after - lifetime.mul_f64(0.2);
    now >= renew_at
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCertificate {
    subject_der: Vec<u8>,
    /// Uncompressed P-256 point from the certificate's SubjectPublicKeyInfo.
    public_key: Vec<u8>,
    not_before: SystemTime,
    not_after: SystemTime,
    /// `subjectKeyIdentifier` extension value (RFC 5280 method 1: SHA-1 of the public key).
    subject_key_identifier: Option<Vec<u8>>,
    /// `authorityKeyIdentifier.keyIdentifier` extension value, when present.
    authority_key_identifier: Option<Vec<u8>>,
}

struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| Error::Issuer("truncated DER: missing tag".to_string()))?;
        self.offset += 1;
        let first = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| Error::Issuer("truncated DER: missing length".to_string()))?;
        self.offset += 1;
        let length = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return Err(Error::Issuer(
                    "unsupported DER indefinite or oversized length".to_string(),
                ));
            }
            let mut length = 0usize;
            for _ in 0..count {
                let byte = *self
                    .bytes
                    .get(self.offset)
                    .ok_or_else(|| Error::Issuer("truncated DER length".to_string()))?;
                self.offset += 1;
                length = (length << 8) | byte as usize;
            }
            length
        };
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| Error::Issuer("truncated DER value".to_string()))?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok((tag, value))
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<&'a [u8]> {
        let (actual, value) = self.read_tlv()?;
        if actual != tag {
            return Err(Error::Issuer(format!(
                "unexpected DER tag 0x{actual:02x} for {what} (expected 0x{tag:02x})"
            )));
        }
        Ok(value)
    }

    fn slice_from(&self, start: usize) -> &'a [u8] {
        &self.bytes[start..self.offset]
    }
}

fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate> {
    let mut outer = DerReader::new(der);
    let certificate = outer.expect(0x30, "Certificate")?;
    let mut certificate_reader = DerReader::new(certificate);
    let tbs = certificate_reader.expect(0x30, "TBSCertificate")?;
    let mut tbs_reader = DerReader::new(tbs);

    let mut field = tbs_reader.read_tlv()?;
    if field.0 == 0xA0 {
        field = tbs_reader.read_tlv()?;
    }
    if field.0 != 0x02 {
        return Err(Error::Issuer(
            "invalid X.509 certificate: serialNumber is not an INTEGER".to_string(),
        ));
    }
    tbs_reader.expect(0x30, "signature AlgorithmIdentifier")?;
    tbs_reader.expect(0x30, "issuer Name")?;
    let validity = tbs_reader.expect(0x30, "validity")?;
    let subject_start = tbs_reader.position();
    let (subject_tag, _) = tbs_reader.read_tlv()?;
    if subject_tag != 0x30 {
        return Err(Error::Issuer(
            "invalid X.509 certificate: subject is not a Name".to_string(),
        ));
    }
    let subject_der = tbs_reader.slice_from(subject_start).to_vec();
    let spki = tbs_reader.expect(0x30, "subjectPublicKeyInfo")?;
    let public_key = parse_spki_public_key(spki)?;

    // Optional trailing TBSCertificate fields: issuerUniqueID [1], subjectUniqueID [2] and
    // extensions [3]. Only the extensions matter here (SKI/AKI are needed to chain and renew CA
    // certificates and to prove key-id linkage in tests).
    let mut subject_key_identifier = None;
    let mut authority_key_identifier = None;
    while tbs_reader.remaining() > 0 {
        let (tag, value) = tbs_reader.read_tlv()?;
        if tag == 0xA3 {
            let (subject, authority) = parse_key_identifiers(value)?;
            subject_key_identifier = subject;
            authority_key_identifier = authority;
        }
    }

    let mut validity_reader = DerReader::new(validity);
    let not_before = validity_reader.read_tlv()?;
    let not_after = validity_reader.read_tlv()?;
    Ok(ParsedCertificate {
        subject_der,
        public_key,
        not_before: UNIX_EPOCH + Duration::from_secs(parse_asn1_time(not_before.0, not_before.1)?),
        not_after: UNIX_EPOCH + Duration::from_secs(parse_asn1_time(not_after.0, not_after.1)?),
        subject_key_identifier,
        authority_key_identifier,
    })
}

/// Extract the uncompressed EC point from a SubjectPublicKeyInfo.
fn parse_spki_public_key(spki: &[u8]) -> Result<Vec<u8>> {
    let mut reader = DerReader::new(spki);
    reader.expect(0x30, "SubjectPublicKeyInfo.algorithm")?;
    let bit_string = reader.expect(0x03, "SubjectPublicKeyInfo.subjectPublicKey")?;
    if bit_string.first() != Some(&0) {
        return Err(Error::Issuer(
            "invalid EC public key: BIT STRING has unused bits".to_string(),
        ));
    }
    Ok(bit_string[1..].to_vec())
}

/// Extract `subjectKeyIdentifier` and `authorityKeyIdentifier.keyIdentifier` from an
/// `Extensions` [3] EXPLICIT value.
fn parse_key_identifiers(explicit_extensions: &[u8]) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    // DER OID contents: 2.5.29.14 (subjectKeyIdentifier) and 2.5.29.35
    // (authorityKeyIdentifier).
    const SUBJECT_KEY_IDENTIFIER_OID: &[u8] = &[0x55, 0x1d, 0x0e];
    const AUTHORITY_KEY_IDENTIFIER_OID: &[u8] = &[0x55, 0x1d, 0x23];

    let mut reader = DerReader::new(explicit_extensions);
    let extensions = reader.expect(0x30, "Extensions")?;
    let mut extensions = DerReader::new(extensions);
    let mut subject_key_identifier = None;
    let mut authority_key_identifier = None;
    while extensions.remaining() > 0 {
        let extension = extensions.expect(0x30, "Extension")?;
        let mut extension = DerReader::new(extension);
        let (oid_tag, oid) = extension.read_tlv()?;
        if oid_tag != 0x06 {
            return Err(Error::Issuer(
                "invalid X.509 extension: extension ID is not an OBJECT IDENTIFIER".to_string(),
            ));
        }
        let (mut value_tag, mut value) = extension.read_tlv()?;
        if value_tag == 0x01 {
            // critical BOOLEAN
            (value_tag, value) = extension.read_tlv()?;
        }
        if value_tag != 0x04 {
            return Err(Error::Issuer(
                "invalid X.509 extension: extnValue is not an OCTET STRING".to_string(),
            ));
        }
        if oid == SUBJECT_KEY_IDENTIFIER_OID {
            let mut value_reader = DerReader::new(value);
            let (tag, key_identifier) = value_reader.read_tlv()?;
            if tag != 0x04 {
                return Err(Error::Issuer(
                    "invalid subjectKeyIdentifier: value is not an OCTET STRING".to_string(),
                ));
            }
            subject_key_identifier = Some(key_identifier.to_vec());
        } else if oid == AUTHORITY_KEY_IDENTIFIER_OID {
            let mut value_reader = DerReader::new(value);
            let sequence = value_reader.expect(0x30, "AuthorityKeyIdentifier")?;
            let mut sequence_reader = DerReader::new(sequence);
            while sequence_reader.remaining() > 0 {
                let (tag, key_identifier) = sequence_reader.read_tlv()?;
                if tag == 0x80 {
                    authority_key_identifier = Some(key_identifier.to_vec());
                    break;
                }
            }
        }
    }
    Ok((subject_key_identifier, authority_key_identifier))
}

fn parse_asn1_time(tag: u8, value: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(value)
        .map_err(|error| Error::Issuer(format!("invalid ASN.1 time: {error}")))?;
    if !text.ends_with('Z') {
        return Err(Error::Issuer(format!(
            "invalid ASN.1 time `{text}`: only UTC (`Z`) times are supported"
        )));
    }
    let digits = &text[..text.len() - 1];
    let (year, rest) = match tag {
        0x17 => {
            if digits.len() != 12 {
                return Err(Error::Issuer(format!(
                    "invalid UTCTime `{text}`: expected YYMMDDHHMMSSZ"
                )));
            }
            let yy: i64 = digits[0..2]
                .parse()
                .map_err(|_| Error::Issuer(format!("invalid UTCTime `{text}`")))?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
        }
        0x18 => {
            if digits.len() != 14 {
                return Err(Error::Issuer(format!(
                    "invalid GeneralizedTime `{text}`: expected YYYYMMDDHHMMSSZ"
                )));
            }
            let year: i64 = digits[0..4]
                .parse()
                .map_err(|_| Error::Issuer(format!("invalid GeneralizedTime `{text}`")))?;
            (year, &digits[4..])
        }
        other => {
            return Err(Error::Issuer(format!(
                "unsupported ASN.1 time tag 0x{other:02x}"
            )))
        }
    };
    let parse = |slice: &str| -> Result<u64> {
        slice
            .parse()
            .map_err(|_| Error::Issuer(format!("invalid ASN.1 time `{text}`")))
    };
    let month = parse(&rest[0..2])? as u32;
    let day = parse(&rest[2..4])? as u32;
    let hour = parse(&rest[4..6])?;
    let minute = parse(&rest[6..8])?;
    let second = parse(&rest[8..10])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(Error::Issuer(format!(
            "invalid ASN.1 time `{text}`: component out of range"
        )));
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return Err(Error::Issuer(format!(
            "invalid ASN.1 time `{text}`: before the Unix epoch"
        )));
    }
    (days as u64)
        .checked_mul(86_400)
        .and_then(|base| base.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| Error::Issuer(format!("ASN.1 time `{text}` is out of range")))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 } as i64;
    let day_of_year = (153 * month_prime + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::MemoryAcmeStorage;
    use crate::renewal::ManualClock;
    use crate::storage::MemoryStorage;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    /// 2023-11-14T22:13:20Z: a fixed wall clock for deterministic validity assertions.
    const NOW_SECS: u64 = 1_700_000_000;

    fn at(offset: Duration) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW_SECS) + offset
    }

    fn issuance(domains: &[&str]) -> IssuanceRequest {
        IssuanceRequest {
            domains: domains.iter().map(|domain| domain.to_string()).collect(),
            internal: false,
            key_type: crate::acme::csr::CertificateKeyType::P256,
        }
    }

    async fn memory_issuer(
        clock: Arc<ManualClock>,
    ) -> (InternalIssuer, Arc<MemoryAcmeStorage>, Arc<MemoryStorage>) {
        let ca_storage = Arc::new(MemoryAcmeStorage::new());
        let certificate_storage = Arc::new(MemoryStorage::new());
        let ca: Arc<dyn CaStorage> = ca_storage.clone();
        let issuer =
            InternalIssuer::new(ca, Box::new(certificate_storage.clone())).with_clock(clock);
        (issuer, ca_storage, certificate_storage)
    }

    async fn load_blob(storage: &MemoryAcmeStorage, key: &str) -> Vec<u8> {
        AcmeStorage::load(storage, key)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("missing storage key `{key}`"))
    }

    fn dns_name(name: &str) -> ServerName<'static> {
        ServerName::try_from(name)
            .expect("valid DNS name")
            .to_owned()
    }

    fn verify_leaf(
        root_der: &[u8],
        leaf_der: &[u8],
        intermediate_der: &[u8],
        server_name: &ServerName<'_>,
        now: SystemTime,
    ) -> std::result::Result<(), rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(root_der.to_vec()))
            .expect("generated root must parse as a trust anchor");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .expect("server verifier");
        let now = UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH).expect("after epoch"));
        verifier
            .verify_server_cert(
                &CertificateDer::from(leaf_der.to_vec()),
                &[CertificateDer::from(intermediate_der.to_vec())],
                server_name,
                &[],
                now,
            )
            .map(|_| ())
    }

    // ---- creation and persistence --------------------------------------------------------

    #[tokio::test]
    async fn first_issuance_creates_ca_in_caddy_layout_and_signs_leaf() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer, ca_storage, certificate_storage) = memory_issuer(clock).await;

        let certificate = issuer
            .obtain(&issuance(&["example.com", "www.example.com"]))
            .await
            .expect("internal issuance");

        assert_eq!(
            certificate.domains,
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
        assert_eq!(certificate.issuer, DEFAULT_CA_ID);
        assert_eq!(certificate.cert_chain_der.len(), 2, "leaf + intermediate");
        assert!(!certificate.private_key_der.is_empty());
        assert_eq!(
            certificate.not_before,
            at(Duration::ZERO) - DEFAULT_BACKDATE
        );
        assert_eq!(
            certificate.not_after,
            at(Duration::ZERO) - DEFAULT_BACKDATE + DEFAULT_LEAF_LIFETIME
        );

        // Caddy CA layout, keyed by the CA id.
        let keys = ca_storage_keys(DEFAULT_CA_ID).unwrap();
        assert_eq!(keys.root_certificate, "pki/authorities/local/root.crt");
        assert_eq!(keys.root_key, "pki/authorities/local/root.key");
        assert_eq!(
            keys.intermediate_certificate,
            "pki/authorities/local/intermediate.crt"
        );
        assert_eq!(
            keys.intermediate_key,
            "pki/authorities/local/intermediate.key"
        );
        for (key, label) in [
            (&keys.root_certificate, "CERTIFICATE"),
            (&keys.intermediate_certificate, "CERTIFICATE"),
        ] {
            let blob = load_blob(&ca_storage, key).await;
            let pem = String::from_utf8(blob).unwrap();
            assert!(pem.contains(&format!("BEGIN {label}")), "{key}");
        }
        for key in [&keys.root_key, &keys.intermediate_key] {
            let blob = load_blob(&ca_storage, key).await;
            let pem = String::from_utf8(blob).unwrap();
            assert!(pem.contains("BEGIN PRIVATE KEY"), "{key}");
        }

        // Leaf certificate persisted through CertificateStorage in the Caddy cert layout.
        let stored = certificate_storage
            .load("local/example.com")
            .await
            .unwrap()
            .expect("stored leaf certificate");
        assert_eq!(
            stored.domains,
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
        assert_eq!(stored.certificate_pem.len(), 2);
        assert!(stored.private_key_pem.contains("BEGIN PRIVATE KEY"));
        assert_eq!(stored.not_after_unix, utc_seconds(certificate.not_after));
    }

    fn utc_seconds(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    #[tokio::test]
    async fn second_issuance_from_a_new_issuer_reuses_root_and_intermediate() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer, ca_storage, certificate_storage) = memory_issuer(clock.clone()).await;
        let first = issuer.obtain(&issuance(&["reuse.example"])).await.unwrap();
        let keys = ca_storage_keys(DEFAULT_CA_ID).unwrap();
        let root_before = load_blob(&ca_storage, &keys.root_certificate).await;
        let intermediate_before = load_blob(&ca_storage, &keys.intermediate_certificate).await;

        // A fresh issuer (simulating a restart) loads the persisted CA instead of regenerating it.
        let restarted = InternalIssuer::new(
            ca_storage.clone() as Arc<dyn CaStorage>,
            Box::new(certificate_storage.clone()),
        )
        .with_clock(clock);
        let second = restarted
            .obtain(&issuance(&["reuse.example"]))
            .await
            .unwrap();

        assert_eq!(
            load_blob(&ca_storage, &keys.root_certificate).await,
            root_before,
            "root must be reused"
        );
        assert_eq!(
            load_blob(&ca_storage, &keys.intermediate_certificate).await,
            intermediate_before,
            "intermediate must be reused"
        );
        assert_ne!(
            first.cert_chain_der[0], second.cert_chain_der[0],
            "each issuance gets a fresh leaf certificate"
        );
        let ca = restarted.ca_certificates().await.unwrap();
        verify_leaf(
            &ca.root_der,
            &second.cert_chain_der[0],
            &ca.intermediate_der,
            &dns_name("reuse.example"),
            at(Duration::ZERO),
        )
        .expect("reused CA signs a verifiable leaf");
    }

    // ---- verification, SANs and identity ------------------------------------------------

    #[tokio::test]
    async fn issued_leaf_verifies_against_root_with_exact_sans() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer, _ca_storage, _) = memory_issuer(clock).await;
        let certificate = issuer
            .obtain(&issuance(&["example.com", "www.example.com"]))
            .await
            .unwrap();
        let ca = issuer.ca_certificates().await.unwrap();
        let leaf = &certificate.cert_chain_der[0];

        for name in ["example.com", "www.example.com"] {
            verify_leaf(
                &ca.root_der,
                leaf,
                &ca.intermediate_der,
                &dns_name(name),
                at(Duration::ZERO),
            )
            .unwrap_or_else(|error| panic!("`{name}` should verify: {error}"));
        }
        // A name that was not requested must not verify.
        assert!(
            verify_leaf(
                &ca.root_der,
                leaf,
                &ca.intermediate_der,
                &dns_name("other.example"),
                at(Duration::ZERO)
            )
            .is_err(),
            "certificate must not be valid for an unrequested name"
        );
        // Root/intermediate chain is CA material, not an end-entity certificate.
        let root_lifetime = parse_certificate(&ca.root_der)
            .unwrap()
            .not_after
            .duration_since(parse_certificate(&ca.root_der).unwrap().not_before)
            .unwrap();
        assert_eq!(root_lifetime, DEFAULT_ROOT_LIFETIME);
        let intermediate_lifetime = parse_certificate(&ca.intermediate_der)
            .unwrap()
            .not_after
            .duration_since(parse_certificate(&ca.intermediate_der).unwrap().not_before)
            .unwrap();
        assert_eq!(intermediate_lifetime, DEFAULT_INTERMEDIATE_LIFETIME);
        let leaf_lifetime = certificate
            .not_after
            .duration_since(certificate.not_before)
            .unwrap();
        assert_eq!(leaf_lifetime, DEFAULT_LEAF_LIFETIME);
    }

    #[tokio::test]
    async fn ip_sans_are_issued_and_verified() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer, _, _) = memory_issuer(clock).await;
        let certificate = issuer.obtain(&issuance(&["127.0.0.1"])).await.unwrap();
        let ca = issuer.ca_certificates().await.unwrap();
        let server_name =
            ServerName::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into());
        verify_leaf(
            &ca.root_der,
            &certificate.cert_chain_der[0],
            &ca.intermediate_der,
            &server_name,
            at(Duration::ZERO),
        )
        .expect("IP SAN should verify");
        assert!(verify_leaf(
            &ca.root_der,
            &certificate.cert_chain_der[0],
            &ca.intermediate_der,
            &ServerName::IpAddress(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)).into()
            ),
            at(Duration::ZERO),
        )
        .is_err());
    }

    #[tokio::test]
    async fn separate_data_directories_are_isolated() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer_a, _storage_a, _) = memory_issuer(clock.clone()).await;
        let (issuer_b, _storage_b, _) = memory_issuer(clock).await;

        let certificate_a = issuer_a.obtain(&issuance(&["a.example"])).await.unwrap();
        let certificate_b = issuer_b.obtain(&issuance(&["b.example"])).await.unwrap();
        let ca_a = issuer_a.ca_certificates().await.unwrap();
        let ca_b = issuer_b.ca_certificates().await.unwrap();
        assert_ne!(
            ca_a.root_der, ca_b.root_der,
            "each data dir has its own root"
        );
        assert_ne!(
            ca_a.intermediate_der, ca_b.intermediate_der,
            "each data dir has its own intermediate"
        );

        // Leaf from A must not verify against B's root.
        assert!(
            verify_leaf(
                &ca_b.root_der,
                &certificate_a.cert_chain_der[0],
                &certificate_a.cert_chain_der[1],
                &dns_name("a.example"),
                at(Duration::ZERO)
            )
            .is_err(),
            "certificates from one CA must not verify against another CA"
        );
        verify_leaf(
            &ca_b.root_der,
            &certificate_b.cert_chain_der[0],
            &ca_b.intermediate_der,
            &dns_name("b.example"),
            at(Duration::ZERO),
        )
        .expect("B's own leaf verifies against B's root");
    }

    // ---- lifecycle / rotation / failures -------------------------------------------------

    #[tokio::test]
    async fn intermediate_rotates_when_near_expiry_while_root_is_kept() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer, ca_storage, _) = memory_issuer(clock.clone()).await;
        issuer.obtain(&issuance(&["rotate.example"])).await.unwrap();
        let keys = ca_storage_keys(DEFAULT_CA_ID).unwrap();
        let root_before = load_blob(&ca_storage, &keys.root_certificate).await;
        let intermediate_before = load_blob(&ca_storage, &keys.intermediate_certificate).await;

        // Move past the intermediate rotation point (80% of its lifetime).
        clock.advance(DEFAULT_INTERMEDIATE_LIFETIME);
        let certificate = issuer.obtain(&issuance(&["rotate.example"])).await.unwrap();

        assert_eq!(
            load_blob(&ca_storage, &keys.root_certificate).await,
            root_before,
            "root is reused when the intermediate rotates"
        );
        assert_ne!(
            load_blob(&ca_storage, &keys.intermediate_certificate).await,
            intermediate_before,
            "intermediate must be regenerated near expiry"
        );
        let ca = issuer.ca_certificates().await.unwrap();
        assert_ne!(ca.intermediate_der, intermediate_before);
        verify_leaf(
            &ca.root_der,
            &certificate.cert_chain_der[0],
            &ca.intermediate_der,
            &dns_name("rotate.example"),
            clock.now(),
        )
        .expect("rotated intermediate still chains to the root");
    }

    #[tokio::test]
    async fn expired_root_fails_loudly() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer, _, _) = memory_issuer(clock.clone()).await;
        issuer
            .obtain(&issuance(&["expired.example"]))
            .await
            .unwrap();
        clock.advance(DEFAULT_ROOT_LIFETIME + Duration::from_secs(86_400));
        let error = issuer
            .obtain(&issuance(&["expired.example"]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("expired"), "{error}");
        assert!(matches!(error, Error::Issuer(_)), "{error:?}");
    }

    #[tokio::test]
    async fn storage_failures_are_loud() {
        struct FailingCaStorage;
        #[async_trait]
        impl CaStorage for FailingCaStorage {
            fn name(&self) -> &'static str {
                "failing"
            }
            async fn load(&self, _key: &str) -> Result<Option<Vec<u8>>> {
                Ok(None)
            }
            async fn store(&self, key: &str, _value: &[u8]) -> Result<()> {
                Err(Error::Io(std::io::Error::other(format!(
                    "cannot write `{key}`"
                ))))
            }
        }

        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let issuer =
            InternalIssuer::new(Arc::new(FailingCaStorage), Box::new(MemoryStorage::new()))
                .with_clock(clock.clone());
        let error = issuer
            .obtain(&issuance(&["fail.example"]))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("cannot persist internal CA"),
            "{error}"
        );

        // CA material works, but the leaf certificate storage fails.
        struct FailingCertificateStorage;
        #[async_trait]
        impl CertificateStorage for FailingCertificateStorage {
            fn name(&self) -> &'static str {
                "failing"
            }
            async fn load(&self, _key: &str) -> Result<Option<StoredCertificate>> {
                Ok(None)
            }
            async fn store(&self, _key: &str, _certificate: &StoredCertificate) -> Result<()> {
                Err(Error::Storage("disk full".to_string()))
            }
            async fn delete(&self, _key: &str) -> Result<()> {
                Ok(())
            }
            async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
                Ok(Vec::new())
            }
        }
        let issuer = InternalIssuer::new(
            Arc::new(MemoryAcmeStorage::new()) as Arc<dyn CaStorage>,
            Box::new(FailingCertificateStorage),
        )
        .with_clock(clock);
        let error = issuer
            .obtain(&issuance(&["fail.example"]))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot persist internal certificate"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn partial_or_corrupt_ca_material_fails_loudly() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer, source_storage, _) = memory_issuer(clock.clone()).await;
        issuer.obtain(&issuance(&["source.example"])).await.unwrap();
        let keys = ca_storage_keys(DEFAULT_CA_ID).unwrap();
        let root_certificate = load_blob(&source_storage, &keys.root_certificate).await;

        // Certificate present, key missing: must not regenerate (that would invalidate leaves).
        let storage = Arc::new(MemoryAcmeStorage::new());
        AcmeStorage::store(&*storage, &keys.root_certificate, &root_certificate)
            .await
            .unwrap();
        let issuer = InternalIssuer::new(
            storage as Arc<dyn CaStorage>,
            Box::new(MemoryStorage::new()),
        )
        .with_clock(clock.clone());
        let error = issuer
            .obtain(&issuance(&["partial.example"]))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("private key") && error.to_string().contains("missing"),
            "{error}"
        );

        // Corrupt key material is reported against the exact storage key.
        let storage = Arc::new(MemoryAcmeStorage::new());
        AcmeStorage::store(&*storage, &keys.root_certificate, &root_certificate)
            .await
            .unwrap();
        AcmeStorage::store(&*storage, &keys.root_key, b"not a key")
            .await
            .unwrap();
        let issuer = InternalIssuer::new(
            storage as Arc<dyn CaStorage>,
            Box::new(MemoryStorage::new()),
        )
        .with_clock(clock);
        let error = issuer
            .obtain(&issuance(&["corrupt.example"]))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("root key") && error.to_string().contains("root.key"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn mismatched_ca_key_material_fails_loudly() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer_a, storage_a, _) = memory_issuer(clock.clone()).await;
        let (issuer_b, storage_b, _) = memory_issuer(clock.clone()).await;
        issuer_a.obtain(&issuance(&["a.example"])).await.unwrap();
        issuer_b.obtain(&issuance(&["b.example"])).await.unwrap();
        let keys = ca_storage_keys(DEFAULT_CA_ID).unwrap();

        // Root certificate from A with B's root key must be rejected, not silently used.
        let mixed = Arc::new(MemoryAcmeStorage::new());
        AcmeStorage::store(
            &*mixed,
            &keys.root_certificate,
            &load_blob(&storage_a, &keys.root_certificate).await,
        )
        .await
        .unwrap();
        AcmeStorage::store(
            &*mixed,
            &keys.root_key,
            &load_blob(&storage_b, &keys.root_key).await,
        )
        .await
        .unwrap();
        let issuer =
            InternalIssuer::new(mixed as Arc<dyn CaStorage>, Box::new(MemoryStorage::new()))
                .with_clock(clock);
        let error = issuer
            .obtain(&issuance(&["mixed.example"]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");
    }

    #[tokio::test]
    async fn unconfigured_or_unsafe_ca_ids_fail_loudly() {
        let error = InternalIssuer::default()
            .obtain(&issuance(&["example.com"]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not configured"), "{error}");

        assert!(ca_storage_keys("bad/id").is_err());
        assert!(ca_storage_keys("").is_err());
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let issuer = InternalIssuer::new(
            Arc::new(MemoryAcmeStorage::new()) as Arc<dyn CaStorage>,
            Box::new(MemoryStorage::new()),
        )
        .with_clock(clock)
        .with_name("../escape");
        let error = issuer
            .obtain(&issuance(&["example.com"]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("safe storage path"), "{error}");
    }

    #[tokio::test]
    async fn file_storage_ca_keys_are_owner_only() {
        let directory = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let issuer = InternalIssuer::from_data_directory(directory.path()).with_clock(clock);
        issuer.obtain(&issuance(&["perms.example"])).await.unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["root.key", "intermediate.key"] {
                let path = directory.path().join("pki/authorities/local").join(name);
                let mode = std::fs::metadata(&path)
                    .unwrap_or_else(|error| panic!("{path:?}: {error}"))
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "{path:?} must be owner-only");
            }
            assert!(directory
                .path()
                .join("pki/authorities/local/root.crt")
                .is_file());
            assert!(directory
                .path()
                .join("pki/authorities/local/intermediate.crt")
                .is_file());
            assert!(directory
                .path()
                .join("certificates/local/perms.example/perms.example.crt")
                .is_file());
        }
    }

    // ---- SKI / AKI (strict client compatibility; acceptance finding F1) -------------------

    /// Whether the extension `oid` is marked critical (`None` when the extension is absent).
    fn extension_criticality(der: &[u8], oid: &[u64]) -> Option<bool> {
        fn oid_content(oid: &[u64]) -> Vec<u8> {
            let encoded = der_oid(oid);
            let mut reader = DerReader::new(&encoded);
            let (_, content) = reader.read_tlv().expect("encoded OID");
            content.to_vec()
        }
        let expected = oid_content(oid);
        let mut outer = DerReader::new(der);
        let certificate = outer.expect(0x30, "Certificate").ok()?;
        let mut certificate = DerReader::new(certificate);
        let tbs = certificate.expect(0x30, "TBSCertificate").ok()?;
        let mut tbs = DerReader::new(tbs);
        while tbs.remaining() > 0 {
            let (tag, value) = tbs.read_tlv().ok()?;
            if tag != 0xa3 {
                continue;
            }
            let mut explicit = DerReader::new(value);
            let extensions = explicit.expect(0x30, "Extensions").ok()?;
            let mut extensions = DerReader::new(extensions);
            while extensions.remaining() > 0 {
                let extension = extensions.expect(0x30, "Extension").ok()?;
                let mut extension = DerReader::new(extension);
                let (oid_tag, oid_value) = extension.read_tlv().ok()?;
                if oid_tag != 0x06 || oid_value != expected.as_slice() {
                    continue;
                }
                let (tag, value) = extension.read_tlv().ok()?;
                return Some(tag == 0x01 && value != [0x00]);
            }
        }
        None
    }

    #[tokio::test]
    async fn internal_ca_certificates_have_linked_ski_and_aki_extensions() {
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        let (issuer, ca_storage, certificate_storage) = memory_issuer(clock.clone()).await;
        let certificate = issuer
            .obtain(&issuance(&["strict.example"]))
            .await
            .expect("internal issuance");
        let ca = issuer.ca_certificates().await.expect("CA certificates");
        let root = parse_certificate(&ca.root_der).expect("root parses");
        let intermediate = parse_certificate(&ca.intermediate_der).expect("intermediate parses");
        let leaf = parse_certificate(&certificate.cert_chain_der[0]).expect("leaf parses");

        // SKI on all three certificates, RFC 5280 method 1 (SHA-1 over the public key BIT STRING).
        let root_ski = root
            .subject_key_identifier
            .clone()
            .expect("root certificate must carry a subjectKeyIdentifier");
        let intermediate_ski = intermediate
            .subject_key_identifier
            .clone()
            .expect("intermediate certificate must carry a subjectKeyIdentifier");
        let leaf_ski = leaf
            .subject_key_identifier
            .clone()
            .expect("leaf certificate must carry a subjectKeyIdentifier");
        assert_eq!(root_ski.len(), 20);
        assert_eq!(root_ski, key_identifier(&root.public_key));
        assert_eq!(intermediate_ski, key_identifier(&intermediate.public_key));
        assert_eq!(leaf_ski, key_identifier(&leaf.public_key));

        // Key-id linkage: root SKI == intermediate AKI, intermediate SKI == leaf AKI.
        assert_eq!(
            intermediate.authority_key_identifier.as_deref(),
            Some(root_ski.as_slice()),
            "intermediate AKI must equal the root SKI"
        );
        assert_eq!(
            leaf.authority_key_identifier.as_deref(),
            Some(intermediate_ski.as_slice()),
            "leaf AKI must equal the intermediate SKI"
        );
        assert_ne!(root_ski, intermediate_ski);
        assert_ne!(intermediate_ski, leaf_ski);

        // A self-signed root has no AKI; SKI/AKI extensions are non-critical.
        assert!(root.authority_key_identifier.is_none());
        for (der, oid) in [
            (&ca.root_der, OID_SUBJECT_KEY_IDENTIFIER),
            (&ca.intermediate_der, OID_SUBJECT_KEY_IDENTIFIER),
            (&ca.intermediate_der, OID_AUTHORITY_KEY_IDENTIFIER),
            (&certificate.cert_chain_der[0], OID_SUBJECT_KEY_IDENTIFIER),
            (&certificate.cert_chain_der[0], OID_AUTHORITY_KEY_IDENTIFIER),
        ] {
            assert_eq!(
                extension_criticality(der, oid),
                Some(false),
                "extension {oid:?} must be present and non-critical"
            );
        }
        assert_eq!(
            extension_criticality(&ca.root_der, OID_AUTHORITY_KEY_IDENTIFIER),
            None
        );

        // Existing extensions/SANs are preserved and the chain still verifies through webpki.
        verify_leaf(
            &ca.root_der,
            &certificate.cert_chain_der[0],
            &ca.intermediate_der,
            &dns_name("strict.example"),
            at(Duration::ZERO),
        )
        .expect("webpki verifies the SKI/AKI-bearing chain");

        // Reissue/renewal from a restarted issuer (persisted CA loaded, not regenerated) keeps the
        // same key-id linkage: renewals must stay strict-client compatible too.
        let restarted = InternalIssuer::new(
            ca_storage.clone() as Arc<dyn CaStorage>,
            Box::new(certificate_storage.clone()),
        )
        .with_clock(clock);
        let renewed = restarted
            .obtain(&issuance(&["strict.example"]))
            .await
            .expect("renewal issuance");
        let ca_after_restart = restarted.ca_certificates().await.expect("CA certificates");
        let root_after_restart =
            parse_certificate(&ca_after_restart.root_der).expect("root parses");
        let intermediate_after_restart =
            parse_certificate(&ca_after_restart.intermediate_der).expect("intermediate parses");
        let leaf_after_restart =
            parse_certificate(&renewed.cert_chain_der[0]).expect("leaf parses");
        assert_eq!(
            intermediate_after_restart
                .authority_key_identifier
                .as_deref(),
            root_after_restart.subject_key_identifier.as_deref(),
            "reloaded intermediate AKI must still equal the root SKI"
        );
        assert_eq!(
            leaf_after_restart.authority_key_identifier.as_deref(),
            intermediate_after_restart.subject_key_identifier.as_deref(),
            "renewed leaf AKI must equal the intermediate SKI"
        );
        verify_leaf(
            &ca_after_restart.root_der,
            &renewed.cert_chain_der[0],
            &ca_after_restart.intermediate_der,
            &dns_name("strict.example"),
            at(Duration::ZERO),
        )
        .expect("webpki verifies a renewed chain");
    }

    #[tokio::test]
    async fn issued_leaf_uses_configured_key_type() {
        use crate::acme::csr::CertificateKeyType;
        let clock = Arc::new(ManualClock::new(at(Duration::ZERO)));
        for key_type in [
            CertificateKeyType::P256,
            CertificateKeyType::P384,
            CertificateKeyType::Rsa2048,
            CertificateKeyType::Rsa4096,
        ] {
            let (issuer, _, _) = memory_issuer(Arc::clone(&clock)).await;
            let mut request = issuance(&["example.com"]);
            request.key_type = key_type;
            let certificate = issuer.obtain(&request).await.expect("internal issuance");
            assert_eq!(
                CertificateKeyType::from_private_key_der(&certificate.private_key_der)
                    .expect("key type is recognisable"),
                key_type,
                "issued key must match the automation policy key_type"
            );
            let ca = issuer.load_ca().await.expect("local CA");
            verify_leaf(
                ca.root_certificate_der(),
                &certificate.cert_chain_der[0],
                ca.intermediate_certificate_der(),
                &dns_name("example.com"),
                at(Duration::ZERO),
            )
            .unwrap_or_else(|error| {
                panic!("{key_type:?} leaf must verify against the local CA: {error}")
            });
        }
    }
}
