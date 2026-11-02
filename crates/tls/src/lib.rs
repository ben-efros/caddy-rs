//! TLS subsystem foundations: certificate model and cache, Caddy-compatible certificate storage,
//! issuer interface, DNS-01 provider interface, renewal scheduling, the ACME (RFC 8555)
//! account/order client, and the rustls server configuration (SNI resolver, ALPN, client auth).
//!
//! The rustls terminator and the wiring of the ACME issuer into automatic HTTPS are intentionally
//! not wired yet (M4/M5); this crate keeps the parts that do not need a live TLS stack testable
//! and stable.

#![forbid(unsafe_code)]

pub mod acme;
pub mod automatic_https;
pub mod certificate;
pub mod cloudflare;
pub mod dns;
pub mod issuer;
pub mod solver;
pub mod storage;
pub mod tls_server;

pub use acme::{
    account_paths, parse_pem_certificate_chain, parse_retry_after, retry_after, Account,
    AccountKey, AccountPaths, AccountRegistration, AccountStatus, AccountStore, AcmeAccountClient,
    AcmeClient, AcmeClock, AcmeError, AcmeStorage, AcmeTransport, Authorization,
    AuthorizationFetch, AuthorizationStatus, CertificateRequest, Challenge, ChallengeFetch,
    ChallengePolicy, ChallengeStatus, ChallengeType, Directory, DirectoryMeta, ExternalAccount,
    HttpMethod, HttpRequest, HttpResponse, HyperTransport, Identifier, IssuedCertificate, Jwk,
    MemoryAcmeStorage, NewAccountRequest, NewOrderRequest, Order, OrderFetch, OrderHandle,
    OrderStatus, PollPolicy, Problem, StoredAccount, TokioClock,
};
pub use automatic_https::{
    plan as plan_automatic_https, AutomaticHttpsIssuer, AutomaticHttpsPlan, AutomaticHttpsPolicy,
    AutomaticHttpsProvisioner, ProvisionedCertificates, DEFAULT_HTTP_PORT,
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
    IssuanceRequest, ProductionAcmeIssuer,
};
pub use solver::{
    dns01_record_name, dns01_txt_value, key_authorization, ChallengeHandle, ChallengeSolver,
    Dns01Solver, Http01Solver, Http01Token, Http01TokenStore, SolverRegistry, TlsAlpn01Solver,
    DNS01_RECORD_PREFIX, HTTP01_PATH_PREFIX,
};
pub use storage::{
    caddy_certificate_storage_name, caddy_issuer_key, from_config, CertificateStorage, FileStorage,
    MemoryStorage, StoredCertificate,
};
pub use tls_server::{
    build_server_config, certificates_from_pem, certificates_from_tls_app, listener_uses_tls,
    resolver_from_config, CertificateResolver, ClientAuthMode, TlsCertificate, TlsServerOptions,
    TlsVersions, DEFAULT_ALPN, DEFAULT_HTTPS_PORT,
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

    /// Server-side TLS configuration errors (certificate loading, connection policies).
    #[error("TLS configuration at `{path}`: {message}")]
    TlsConfig {
        /// JSON path or component that failed.
        path: String,
        /// Diagnosis.
        message: String,
    },

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
