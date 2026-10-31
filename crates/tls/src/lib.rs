//! TLS subsystem foundations: certificate model and cache, pluggable storage, issuer interface,
//! and renewal scheduling.
//!
//! The rustls terminator is intentionally not wired yet (M4); this crate keeps the parts that do
//! not need a live TLS stack testable and stable.

#![forbid(unsafe_code)]

pub mod certificate;
pub mod issuer;
pub mod storage;

pub use certificate::{renewal_queue, Certificate, CertificateCache, RenewalItem};
pub use issuer::{
    within_renewal_window, AcmeIssuer, AcmeIssuerConfig, CertificateIssuer, InternalIssuer,
    IssuanceRequest,
};
pub use storage::{from_config, CertificateStorage, FileStorage, MemoryStorage, StoredCertificate};

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

    /// I/O errors.
    #[error("certificate I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias for the TLS crate.
pub type Result<T> = std::result::Result<T, Error>;
