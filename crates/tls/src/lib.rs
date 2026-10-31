//! TLS subsystem foundations: certificate model and cache, Caddy-compatible certificate storage,
//! issuer interface, DNS-01 provider interface, and renewal scheduling.
//!
//! The rustls terminator and ACME wire client are intentionally not wired yet (M4/M5); this crate
//! keeps the parts that do not need a live TLS stack testable and stable.

#![forbid(unsafe_code)]

pub mod acme;
pub mod certificate;
pub mod cloudflare;
pub mod dns;
pub mod issuer;
pub mod storage;

pub use acme::{
    account_paths, Account, AccountKey, AccountPaths, AccountRegistration, AccountStatus,
    AccountStore, AcmeClient, AcmeError, AcmeStorage, AcmeTransport, Directory, DirectoryMeta,
    ExternalAccount, HttpMethod, HttpRequest, HttpResponse, Jwk, MemoryAcmeStorage,
    NewAccountRequest, Problem, StoredAccount,
};
pub use certificate::{renewal_queue, Certificate, CertificateCache, RenewalItem};
pub use cloudflare::{
    resolve_env_placeholders, CloudflareConfig, CloudflareProvider, CLOUDFLARE_API_BASE,
    CLOUDFLARE_MIN_TTL_SECONDS, CLOUDFLARE_PROVIDER_NAME,
};
pub use dns::{
    DnsChallengeConfig, DnsError, DnsProvider, InMemoryDnsProvider, PropagationTimeout, RecordId,
    TxtRecord,
};
pub use issuer::{
    within_renewal_window, AcmeIssuer, AcmeIssuerConfig, CertificateIssuer, InternalIssuer,
    IssuanceRequest,
};
pub use storage::{
    caddy_certificate_storage_name, caddy_issuer_key, from_config, CertificateStorage, FileStorage,
    MemoryStorage, StoredCertificate,
};

/// Errors raised by the TLS layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Certificate model/cache errors.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// Storage errors.
    #[error("certificate storage error: {0}")]
    Storage(String),

    /// Issuer configuration/runtime errors.
    #[error("certificate issuer error: {0}")]
    Issuer(String),

    /// ACME directory/account errors (problem documents, terms of service, account keys).
    ///
    /// Boxed to keep [`Error`] small: ACME problem documents carry several strings and are rare
    /// compared with the success path.
    #[error("ACME error: {0}")]
    Acme(Box<AcmeError>),

    /// A storage key that would escape the storage root.
    #[error("invalid certificate storage key `{0}`")]
    InvalidKey(String),

    /// A capability that this build does not implement yet.
    #[error("not implemented: {feature} ({tracking_id})")]
    NotImplemented {
        /// Capability.
        feature: &'static str,
        /// Tracking task.
        tracking_id: &'static str,
    },

    /// DNS-01 challenge provider errors.
    #[error(transparent)]
    Dns(#[from] dns::DnsError),

    /// I/O errors.
    #[error("certificate I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<AcmeError> for Error {
    fn from(error: AcmeError) -> Self {
        Self::Acme(Box::new(error))
    }
}

/// Result alias for the TLS crate.
pub type Result<T> = std::result::Result<T, Error>;
