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
pub mod client_auth;
pub mod cloudflare;
pub mod digitalocean;
pub mod dns;
pub mod dns_providers;
pub mod internal_ca;
pub mod issuer;
pub mod ocsp;
pub mod propagation;
pub mod renewal;
pub mod route53;
pub mod s3;
pub mod sigv4;
pub mod solver;
pub mod storage;
pub mod tls_alpn;
pub mod tls_server;

pub use acme::{
    account_paths, parse_pem_certificate_chain, parse_retry_after,
    read_root_certificates_pem_files, retry_after, Account, AccountKey, AccountPaths,
    AccountRegistration, AccountStatus, AccountStore, AcmeAccountClient, AcmeClient, AcmeClock,
    AcmeError, AcmeStorage, AcmeTransport, Authorization, AuthorizationFetch, AuthorizationStatus,
    CertificateRequest, Challenge, ChallengeFetch, ChallengePolicy, ChallengeStatus, ChallengeType,
    Directory, DirectoryMeta, ExternalAccount, HttpMethod, HttpRequest, HttpResponse,
    HyperTransport, Identifier, IssuedCertificate, Jwk, MemoryAcmeStorage, NewAccountRequest,
    NewOrderRequest, NoAcmeTransport, Order, OrderFetch, OrderHandle, OrderStatus, PollPolicy,
    Problem, StoredAccount, TokioClock,
};
pub use automatic_https::{
    plan as plan_automatic_https, AutomaticHttpsIssuer, AutomaticHttpsPlan, AutomaticHttpsPolicy,
    AutomaticHttpsProvisioner, AutomaticHttpsRenewals, ProvisionedCertificates, DEFAULT_HTTP_PORT,
};
pub use certificate::{renewal_queue, Certificate, CertificateCache, RenewalItem};
pub use client_auth::{
    client_certificate_infos, ClientCertificateInfo, ClientCertificateInfoError,
};
pub use cloudflare::{
    resolve_env_placeholders, CloudflareConfig, CloudflareProvider, CLOUDFLARE_API_BASE,
    CLOUDFLARE_MIN_TTL_SECONDS, CLOUDFLARE_PROVIDER_NAME,
};
pub use dns::{
    DnsChallengeConfig, DnsError, DnsProvider, InMemoryDnsProvider, PropagationTimeout, RecordId,
    TxtRecord,
};
pub use dns_providers::{
    build_dns01_solver, build_dns_provider, DNS_PROVIDER_TRACKING_ID, SUPPORTED_DNS_PROVIDERS,
};
pub use internal_ca::{
    ca_storage_keys, CaCertificates, CaLifetimes, CaStorage, CaStorageKeys, LocalCa,
    DEFAULT_BACKDATE, DEFAULT_CA_DISPLAY_NAME, DEFAULT_CA_ID, DEFAULT_INTERMEDIATE_LIFETIME,
    DEFAULT_LEAF_LIFETIME, DEFAULT_ROOT_LIFETIME,
};
pub use issuer::{
    within_renewal_window, AcmeIssuer, AcmeIssuerConfig, CertificateIssuer, InternalIssuer,
    IssuanceRequest, ProductionAcmeIssuer,
};
pub use ocsp::{
    build_ocsp_request, parse_ocsp_response, staple_for_certificate, DenyOcspTransport,
    OcspCertStatus, OcspError, OcspPolicy, OcspRequest, OcspResponse, OcspStapler, OcspTransport,
    ParsedCertificate, SharedOcspStapler, Staple, StapleOutcome, DEFAULT_OCSP_CHECK_INTERVAL,
    INITIAL_OCSP_RETRY_DELAY, MAX_OCSP_RETRY_DELAY,
};
pub use propagation::{
    txt_data_matches, DohPropagationChecker, PropagationChecker, CLOUDFLARE_DOH_ENDPOINT,
};
pub use renewal::{
    CertificatePublisher, ManualClock, RenewalClock, RenewalOutcome, RenewalPolicy,
    RenewalScheduler, RenewalSchedulerHandle, SharedCertificateStore, SystemClock,
    DEFAULT_BACKOFF_BASE, DEFAULT_BACKOFF_MAX, DEFAULT_RENEWAL_JITTER, RENEWAL_REMAINING_FRACTION,
};
pub use s3::{S3Client, S3Error, S3Settings, S3Storage};
pub use solver::{
    dns01_record_name, dns01_txt_value, key_authorization, ChallengeHandle, ChallengeSolver,
    Dns01Solver, Http01Solver, Http01Token, Http01TokenStore, SolverRegistry, TlsAlpn01Solver,
    DNS01_RECORD_PREFIX, HTTP01_PATH_PREFIX,
};
pub use storage::{
    caddy_certificate_storage_name, caddy_issuer_key, from_config, CertificateStorage, FileStorage,
    MemoryStorage, SelectedStorage, StoredCertificate,
};
pub use tls_alpn::{
    AcmeTlsAlpnResolver, TlsAlpn01Challenge, TlsAlpn01TokenStore, ACME_IDENTIFIER_OID,
    ACME_TLS_ALPN_PROTOCOL,
};
pub use tls_server::{
    build_server_config, build_server_config_with_cert_resolver, certificates_from_pem,
    certificates_from_tls_app, listener_uses_tls, resolver_from_config, CertificatePolicy,
    CertificateResolver, ClientAuthMode, TaggedCertificateSelector, TlsCertificate, TlsResolver,
    TlsServerOptions, TlsVersions, DEFAULT_ALPN, DEFAULT_HTTPS_PORT,
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

    /// A recognised-but-unimplemented capability whose description is built dynamically (for
    /// example a named configuration field). Located so the operator can find the offending JSON.
    #[error("not implemented at `{path}`: {feature} ({tracking_id})")]
    Unsupported {
        /// JSON path of the offending configuration value.
        path: String,
        /// Capability description.
        feature: String,
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
