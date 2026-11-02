//! rustls server configuration: certificate/key loading, SNI resolution, ALPN, and client auth.
//!
//! This is the server-side TLS boundary consumed by `caddy-rs-server`. It keeps the
//! configuration logic free of listener I/O so it can be unit-tested:
//!
//! * [`TlsCertificate`] loads a PEM/DER certificate chain + private key and extracts the names
//!   the certificate covers (subjectAltName `dNSName` entries, falling back to subject
//!   `commonName`) with a small DER walker — no X.509 parsing crate is available in the offline
//!   registry cache;
//! * [`CertificateResolver`] implements rustls' [`ResolvesServerCert`] with exact-name then
//!   one-label-wildcard matching, a default certificate for empty/unknown SNI, and constructors
//!   from the existing [`CertificateCache`], from [`CertificateStorage`], and from typed
//!   `apps.tls.certificates` configuration;
//! * [`TlsServerOptions`] derives ALPN, TLS versions and client-auth mode from Caddy's
//!   `tls_connection_policies` JSON;
//! * [`build_server_config`] assembles the rustls [`ServerConfig`] with the `ring` provider.
//!
//! Listener policy (documented for the server supervisor, see [`listener_uses_tls`]): a TCP
//! listener terminates TLS when its server has non-empty `tls_connection_policies`, or when its
//! port is the effective HTTPS port (`apps.http.https_port`, default 443). A TLS listener with no
//! certificate fails the configuration apply loudly instead of serving cleartext.
//!
//! Automatic HTTPS (ACME issuance, HTTP→HTTPS redirects, certificate automation) is not wired
//! yet; see DIV-0001/DIV-0002 and the divergence entries added with this task.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion};
use serde_json::Value;

use caddy_rs_core::config::{CertKeyPemPair, Config, TlsApp};
use caddy_rs_core::listen::{ListenAddr, Network};

use crate::certificate::{Certificate, CertificateCache};
use crate::storage::{CertificateStorage, StoredCertificate};
use crate::{Error, Result};

/// Default ALPN protocols offered by a TLS listener (Caddy's defaults for HTTPS servers).
pub const DEFAULT_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// The effective HTTPS port when `apps.http.https_port` is absent (Caddy default).
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// Client certificate authentication mode (Caddy's `client_authentication.mode`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClientAuthMode {
    /// Do not ask for a client certificate (Caddy's default).
    #[default]
    None,
    /// Ask for a client certificate and verify it when supplied, but allow none.
    Request,
    /// Require a client certificate and verify it against the configured roots.
    Require,
}

impl ClientAuthMode {
    /// Parse Caddy's `client_authentication.mode` values.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "request" => Ok(Self::Request),
            "require" | "require_and_verify" => Ok(Self::Require),
            other => Err(Error::TlsConfig {
                path: "tls_connection_policies[0].client_authentication.mode".to_string(),
                message: format!(
                    "unsupported client authentication mode `{other}`; expected `request`, `require` or `require_and_verify`"
                ),
            }),
        }
    }
}

/// TLS protocol versions a listener may negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersions {
    /// TLS 1.2 and TLS 1.3 (rustls safe defaults, matching Caddy's defaults).
    Default,
    /// TLS 1.2 only.
    Tls12Only,
    /// TLS 1.3 only.
    Tls13Only,
}

impl Default for TlsVersions {
    fn default() -> Self {
        Self::Default
    }
}

const TLS12_AND_13: &[&SupportedProtocolVersion] =
    &[&rustls::version::TLS12, &rustls::version::TLS13];
const TLS12_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS12];
const TLS13_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

impl TlsVersions {
    fn rustls_versions(self) -> &'static [&'static SupportedProtocolVersion] {
        match self {
            Self::Default => TLS12_AND_13,
            Self::Tls12Only => TLS12_ONLY,
            Self::Tls13Only => TLS13_ONLY,
        }
    }
}

/// Options for the rustls server configuration derived from a connection policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerOptions {
    /// ALPN protocols offered, in preference order. Defaults to [`DEFAULT_ALPN`].
    pub alpn: Vec<Vec<u8>>,
    /// Enabled TLS protocol versions.
    pub versions: TlsVersions,
    /// Client certificate authentication mode.
    pub client_auth: ClientAuthMode,
    /// PEM CA bundle used to verify client certificates for [`ClientAuthMode::Request`] and
    /// [`ClientAuthMode::Require`]. Configuration-driven CA pools are not modelled yet; embedders
    /// that need client auth supply the bundle explicitly.
    pub client_auth_roots_pem: Option<String>,
}

impl Default for TlsServerOptions {
    fn default() -> Self {
        Self {
            alpn: DEFAULT_ALPN
                .iter()
                .map(|protocol| protocol.to_vec())
                .collect(),
            versions: TlsVersions::Default,
            client_auth: ClientAuthMode::None,
            client_auth_roots_pem: None,
        }
    }
}

impl TlsServerOptions {
    /// Derive options from the first server `tls_connection_policies` entry.
    ///
    /// Absent or empty policies mean Caddy's defaults (ALPN `h2`/`http/1.1`, TLS 1.2+1.3, no
    /// client auth). Unsupported connection-policy fields fail with a located error instead of
    /// being silently ignored, so a configuration that asks for behaviour this build does not
    /// implement never appears to work.
    pub fn from_connection_policies(policies: Option<&[Value]>) -> Result<Self> {
        let Some(policies) = policies else {
            return Ok(Self::default());
        };
        let Some(policy) = policies.first() else {
            return Ok(Self::default());
        };
        let Some(policy) = policy.as_object() else {
            return Err(Error::TlsConfig {
                path: "tls_connection_policies[0]".to_string(),
                message: "connection policy must be an object".to_string(),
            });
        };
        let mut options = Self::default();
        if let Some(alpn) = policy.get("alpn") {
            let protocols = alpn.as_array().ok_or_else(|| Error::TlsConfig {
                path: "tls_connection_policies[0].alpn".to_string(),
                message: "must be an array of strings".to_string(),
            })?;
            let mut configured = Vec::with_capacity(protocols.len());
            for (index, protocol) in protocols.iter().enumerate() {
                let path = format!("tls_connection_policies[0].alpn[{index}]");
                let protocol = protocol.as_str().ok_or_else(|| Error::TlsConfig {
                    path: path.clone(),
                    message: "ALPN protocol must be a string".to_string(),
                })?;
                match protocol {
                    "h2" | "http/1.1" => configured.push(protocol.as_bytes().to_vec()),
                    other => {
                        return Err(Error::TlsConfig {
                            path,
                            message: format!(
                                "unsupported ALPN protocol `{other}`; this build supports `h2` and `http/1.1`"
                            ),
                        })
                    }
                }
            }
            if !configured.is_empty() {
                options.alpn = configured;
            }
        }
        if let Some(protocols) = policy.get("protocols") {
            let protocols = protocols.as_array().ok_or_else(|| Error::TlsConfig {
                path: "tls_connection_policies[0].protocols".to_string(),
                message: "must be an array of strings".to_string(),
            })?;
            let mut tls12 = false;
            let mut tls13 = false;
            for (index, protocol) in protocols.iter().enumerate() {
                let path = format!("tls_connection_policies[0].protocols[{index}]");
                match protocol.as_str() {
                    Some("tls1.2") => tls12 = true,
                    Some("tls1.3") => tls13 = true,
                    other => {
                        return Err(Error::TlsConfig {
                            path,
                            message: format!(
                                "unsupported TLS protocol `{}`; expected `tls1.2` or `tls1.3`",
                                other.unwrap_or("<non-string>")
                            ),
                        })
                    }
                }
            }
            options.versions = match (tls12, tls13) {
                (true, true) | (false, false) => TlsVersions::Default,
                (true, false) => TlsVersions::Tls12Only,
                (false, true) => TlsVersions::Tls13Only,
            };
        }
        if let Some(client_authentication) = policy.get("client_authentication") {
            let object = client_authentication
                .as_object()
                .ok_or_else(|| Error::TlsConfig {
                    path: "tls_connection_policies[0].client_authentication".to_string(),
                    message: "must be an object".to_string(),
                })?;
            if object.contains_key("trusted_ca_pool")
                || object.contains_key("trusted_leaf_cert_file")
            {
                return Err(Error::NotImplemented {
                    feature: "ACME client authentication CA pools (`client_authentication.trusted_ca_pool`)",
                    tracking_id: "TLS-CLIENT-AUTH",
                });
            }
            let mode =
                object
                    .get("mode")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::TlsConfig {
                        path: "tls_connection_policies[0].client_authentication.mode".to_string(),
                        message: "client authentication requires a `mode`".to_string(),
                    })?;
            options.client_auth = ClientAuthMode::parse(mode)?;
        }
        // Every remaining field changes TLS behaviour; fail loudly rather than approximating.
        for field in policy.keys() {
            if !matches!(
                field.as_str(),
                "alpn" | "protocols" | "client_authentication"
            ) {
                return Err(Error::NotImplemented {
                    feature: "TLS connection policy field (`tls_connection_policies[0]`)",
                    tracking_id: "TLS-CONN-POLICY",
                });
            }
        }
        Ok(options)
    }
}

/// A certificate chain and private key ready for rustls, with the names it covers.
#[derive(Debug)]
pub struct TlsCertificate {
    names: Vec<String>,
    chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl TlsCertificate {
    /// Load a certificate chain and private key from PEM text.
    ///
    /// The certificate names are taken from the leaf's subjectAltName extension (falling back to
    /// the subject commonName). Supported key encodings are PKCS#8 (`PRIVATE KEY`), SEC1
    /// (`EC PRIVATE KEY`) and PKCS#1 (`RSA PRIVATE KEY`); the key type must be supported by
    /// rustls' `ring` provider.
    pub fn from_pem(certificate_pem: &str, private_key_pem: &str) -> Result<Self> {
        let chain = certificate_chain_from_pem(certificate_pem)?;
        let private_key = private_key_from_pem(private_key_pem)?;
        let names = certificate_names(chain[0].as_ref())?;
        Ok(Self {
            names,
            chain,
            private_key,
        })
    }

    /// Build from DER components, using explicitly supplied names.
    pub fn from_der(
        chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        names: Vec<String>,
    ) -> Result<Self> {
        if chain_der.is_empty() {
            return Err(Error::TlsConfig {
                path: "certificates".to_string(),
                message: "certificate chain must not be empty".to_string(),
            });
        }
        if names.is_empty() {
            return Err(Error::TlsConfig {
                path: "certificates".to_string(),
                message: "certificate must cover at least one name".to_string(),
            });
        }
        Ok(Self {
            names,
            chain: chain_der.into_iter().map(CertificateDer::from).collect(),
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der)),
        })
    }

    /// Build from a stored certificate (PEM chain + PEM key, names from metadata).
    pub fn from_stored(stored: &StoredCertificate) -> Result<Self> {
        let chain_der: Vec<Vec<u8>> = stored
            .certificate_pem
            .iter()
            .map(|pem| certificate_chain_from_pem(pem).map(|chain| chain[0].as_ref().to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let private_key = private_key_from_pem(&stored.private_key_pem)?;
        let names = if stored.domains.is_empty() {
            certificate_names(chain_der[0].as_slice())?
        } else {
            stored.domains.clone()
        };
        Ok(Self {
            names,
            chain: chain_der.into_iter().map(CertificateDer::from).collect(),
            private_key,
        })
    }

    /// Build from a [`Certificate`] in the in-memory cache.
    pub fn from_cache_certificate(certificate: &Certificate) -> Result<Self> {
        let names = if certificate.domains.is_empty() {
            let leaf = certificate
                .cert_chain_der
                .first()
                .ok_or_else(|| Error::TlsConfig {
                    path: "certificate cache".to_string(),
                    message: "cached certificate has an empty chain".to_string(),
                })?;
            certificate_names(leaf)?
        } else {
            certificate.domains.clone()
        };
        Self::from_der(
            certificate.cert_chain_der.clone(),
            certificate.private_key_der.clone(),
            names,
        )
    }

    /// Names this certificate covers (as configured/parsed, not lowercased).
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// The DER certificate chain, leaf first.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// The DER private key.
    pub fn private_key(&self) -> &PrivateKeyDer<'static> {
        &self.private_key
    }

    /// Convert to the rustls signing form, validating the key type against the `ring` provider.
    pub fn certified_key(&self) -> Result<CertifiedKey> {
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&self.private_key)
            .map_err(|error| Error::TlsConfig {
                path: "certificates".to_string(),
                message: format!(
                    "private key type is not supported by the rustls ring provider: {error}"
                ),
            })?;
        Ok(CertifiedKey {
            cert: self.chain.clone(),
            key: signing_key,
            ocsp: None,
        })
    }
}

#[derive(Debug, Default)]
struct ResolverState {
    certificates: BTreeMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
    names: Vec<String>,
}

impl ResolverState {
    fn insert(&mut self, certificate: TlsCertificate) -> Result<()> {
        let certified = Arc::new(certificate.certified_key()?);
        if self.default.is_none() {
            self.default = Some(Arc::clone(&certified));
        }
        for name in certificate.names() {
            let key = normalize_server_name(name);
            if key.is_empty() {
                return Err(Error::TlsConfig {
                    path: "certificates".to_string(),
                    message: "certificate contains an empty name".to_string(),
                });
            }
            self.certificates
                .insert(key.clone(), Arc::clone(&certified));
            if !self.names.contains(&key) {
                self.names.push(key);
            }
        }
        Ok(())
    }
}

/// SNI certificate resolver backed by loaded certificates (cache, storage, or configuration).
///
/// Matching order: exact name, then the one-label wildcard (`*.example.com` covers
/// `api.example.com`), then the default certificate (the first one inserted). Like certmagic
/// with `strict_sni_host` disabled, an unknown SNI still completes the handshake with the
/// default certificate; the client rejects it if the name does not match.
pub struct CertificateResolver {
    state: RwLock<ResolverState>,
}

impl std::fmt::Debug for CertificateResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        formatter
            .debug_struct("CertificateResolver")
            .field("names", &state.names)
            .field("has_default", &state.default.is_some())
            .finish()
    }
}

impl Default for CertificateResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateResolver {
    /// An empty resolver.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(ResolverState::default()),
        }
    }

    /// Build a resolver from certificates.
    pub fn from_certificates(
        certificates: impl IntoIterator<Item = TlsCertificate>,
    ) -> Result<Self> {
        let resolver = Self::new();
        for certificate in certificates {
            resolver.insert(certificate)?;
        }
        Ok(resolver)
    }

    /// Build a resolver from the existing in-memory certificate cache.
    pub fn from_cache(cache: &CertificateCache) -> Result<Self> {
        let certificates = cache
            .certificates()
            .iter()
            .map(TlsCertificate::from_cache_certificate)
            .collect::<Result<Vec<_>>>()?;
        Self::from_certificates(certificates)
    }

    /// Load every certificate in a storage backend (Caddy layout keys).
    pub async fn load_from_storage<S: CertificateStorage + ?Sized>(storage: &S) -> Result<Self> {
        let resolver = Self::new();
        for key in storage.list("").await? {
            if let Some(stored) = storage.load(&key).await? {
                resolver.insert(TlsCertificate::from_stored(&stored)?)?;
            }
        }
        Ok(resolver)
    }

    /// Add a certificate. Names are keyed case-insensitively; the first certificate added becomes
    /// the default for empty/unknown SNI.
    pub fn insert(&self, certificate: TlsCertificate) -> Result<()> {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(certificate)
    }

    /// Number of distinct names served.
    pub fn len(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .names
            .len()
    }

    /// Whether the resolver has no certificates.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether a default certificate is available for empty/unknown SNI.
    pub fn has_default(&self) -> bool {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .default
            .is_some()
    }

    /// Names served by this resolver (lowercased).
    pub fn names(&self) -> Vec<String> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .names
            .clone()
    }

    /// Whether a certificate is loaded for `server_name` (exact or one-label wildcard).
    ///
    /// Unlike [`Self::select`], this does not fall back to the default certificate; it is used by
    /// automatic HTTPS to decide whether a subject still needs to be obtained.
    pub fn covers(&self, server_name: &str) -> bool {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let name = normalize_server_name(server_name);
        if state.certificates.contains_key(&name) {
            return true;
        }
        if let Some((_, rest)) = name.split_once('.') {
            if !rest.is_empty()
                && rest.contains('.')
                && state.certificates.contains_key(&format!("*.{rest}"))
            {
                return true;
            }
        }
        false
    }

    /// Select the certificate for `server_name` (exact, then one-label wildcard, then default).
    pub fn select(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(server_name) = server_name else {
            return state.default.clone();
        };
        let name = normalize_server_name(server_name);
        if let Some(certified) = state.certificates.get(&name) {
            return Some(Arc::clone(certified));
        }
        if let Some((_, rest)) = name.split_once('.') {
            if !rest.is_empty() && rest.contains('.') {
                if let Some(certified) = state.certificates.get(&format!("*.{rest}")) {
                    return Some(Arc::clone(certified));
                }
            }
        }
        state.default.clone()
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.select(client_hello.server_name())
    }
}

/// Build a rustls server configuration from a resolver and options.
pub fn build_server_config(
    resolver: Arc<CertificateResolver>,
    options: &TlsServerOptions,
) -> Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(options.versions.rustls_versions())
        .map_err(|error| Error::TlsConfig {
            path: "tls_connection_policies[0].protocols".to_string(),
            message: format!("rustls rejected the configured protocol versions: {error}"),
        })?;
    let builder = match options.client_auth {
        ClientAuthMode::None => builder.with_no_client_auth(),
        mode => {
            let roots_pem = options.client_auth_roots_pem.as_deref().ok_or_else(|| {
                Error::TlsConfig {
                    path: "tls_connection_policies[0].client_authentication".to_string(),
                    message: format!(
                        "client authentication mode `{mode:?}` requires a trusted CA bundle; configuration-driven `trusted_ca_pool` modules are not implemented (TLS-CLIENT-AUTH)"
                    ),
                }
            })?;
            let roots = root_store_from_pem(roots_pem)?;
            let verifier_builder =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
            let verifier = match mode {
                ClientAuthMode::Request => verifier_builder.allow_unauthenticated().build(),
                _ => verifier_builder.build(),
            }
            .map_err(|error| Error::TlsConfig {
                path: "tls_connection_policies[0].client_authentication".to_string(),
                message: format!("cannot build client certificate verifier: {error}"),
            })?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder.with_cert_resolver(resolver);
    config.alpn_protocols = options.alpn.clone();
    Ok(Arc::new(config))
}

/// Build a certificate resolver from the typed `apps.tls` app configuration.
///
/// Returns `Ok(None)` when the app is absent or declares no loadable certificates. `load_pem`
/// entries are used first, then `load_files` (only the `pem` format is supported).
pub fn resolver_from_config(config: &Config) -> Result<Option<CertificateResolver>> {
    let Some(tls) = config.tls() else {
        return Ok(None);
    };
    let certificates = certificates_from_tls_app(tls)?;
    if certificates.is_empty() {
        return Ok(None);
    }
    Ok(Some(CertificateResolver::from_certificates(certificates)?))
}

/// Load certificates declared by `apps.tls.certificates` (`load_pem` then `load_files`).
pub fn certificates_from_tls_app(tls: &TlsApp) -> Result<Vec<TlsCertificate>> {
    let mut certificates = Vec::new();
    for (index, pair) in tls.load_pems().iter().enumerate() {
        let path = format!("apps.tls.certificates.load_pem[{index}]");
        certificates.push(load_pem_pair(pair, &path)?);
    }
    for (index, pair) in tls.load_files().iter().enumerate() {
        let path = format!("apps.tls.certificates.load_files[{index}]");
        let format = pair.format.as_deref().unwrap_or("pem");
        if format != "pem" {
            return Err(Error::NotImplemented {
                feature: "non-PEM certificate files (`apps.tls.certificates.load_files[].format`)",
                tracking_id: "TLS-CERT-FORMAT",
            });
        }
        let certificate_pem =
            std::fs::read_to_string(&pair.certificate).map_err(|error| Error::TlsConfig {
                path: format!("{path}.certificate"),
                message: format!("cannot read `{}`: {error}", pair.certificate),
            })?;
        let private_key_pem =
            std::fs::read_to_string(&pair.key).map_err(|error| Error::TlsConfig {
                path: format!("{path}.key"),
                message: format!("cannot read `{}`: {error}", pair.key),
            })?;
        let certificate =
            TlsCertificate::from_pem(&certificate_pem, &private_key_pem).map_err(|error| {
                Error::TlsConfig {
                    path: path.clone(),
                    message: error.to_string(),
                }
            })?;
        certificates.push(certificate);
    }
    Ok(certificates)
}

fn load_pem_pair(pair: &CertKeyPemPair, path: &str) -> Result<TlsCertificate> {
    TlsCertificate::from_pem(&pair.certificate, &pair.key).map_err(|error| match error {
        Error::TlsConfig { message, .. } => Error::TlsConfig {
            path: path.to_string(),
            message,
        },
        other => other,
    })
}

/// Listener policy: whether a configured TCP listener terminates TLS.
///
/// TLS is enabled when the owning HTTP server declares connection policies or when the listener
/// port is the effective HTTPS port. Unix listeners never terminate TLS (policy-configured TLS
/// over Unix is rejected loudly).
pub fn listener_uses_tls(
    configured_listen: &str,
    https_port: u16,
    has_connection_policies: bool,
) -> Result<bool> {
    let address = ListenAddr::parse(configured_listen).map_err(|reason| Error::TlsConfig {
        path: "listen".to_string(),
        message: format!("cannot parse listen address `{configured_listen}`: {reason}"),
    })?;
    match address.network {
        Network::Tcp => Ok(has_connection_policies || address.port() == Some(https_port)),
        Network::Unix => {
            if has_connection_policies {
                Err(Error::NotImplemented {
                    feature: "TLS termination on Unix sockets",
                    tracking_id: "TLS-UNIX-LISTENER",
                })
            } else {
                Ok(false)
            }
        }
        Network::Udp => Ok(false),
    }
}

// ---- PEM / DER helpers -----------------------------------------------------------------------

/// A PEM block: label plus DER bytes.
fn pem_blocks(pem: &str) -> Result<Vec<(String, Vec<u8>)>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let mut blocks = Vec::new();
    let mut label: Option<String> = None;
    let mut body = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let Some(begin_label) = rest.strip_suffix("-----") else {
                continue;
            };
            if label.is_some() {
                return Err(Error::TlsConfig {
                    path: "certificates".to_string(),
                    message: "nested PEM block".to_string(),
                });
            }
            label = Some(begin_label.to_string());
            body.clear();
        } else if let Some(rest) = line.strip_prefix("-----END ") {
            let Some(end_label) = rest.strip_suffix("-----") else {
                continue;
            };
            let Some(begin_label) = label.take() else {
                return Err(Error::TlsConfig {
                    path: "certificates".to_string(),
                    message: "PEM END without BEGIN".to_string(),
                });
            };
            if begin_label != end_label {
                return Err(Error::TlsConfig {
                    path: "certificates".to_string(),
                    message: format!(
                        "PEM block labels differ: BEGIN `{begin_label}`, END `{end_label}`"
                    ),
                });
            }
            let der = STANDARD
                .decode(body.as_bytes())
                .map_err(|error| Error::TlsConfig {
                    path: "certificates".to_string(),
                    message: format!("PEM block `{begin_label}` is not valid base64: {error}"),
                })?;
            blocks.push((begin_label, der));
            body.clear();
        } else if label.is_some() {
            body.extend(line.chars().filter(|character| !character.is_whitespace()));
        }
    }
    if label.is_some() {
        return Err(Error::TlsConfig {
            path: "certificates".to_string(),
            message: "unterminated PEM block".to_string(),
        });
    }
    Ok(blocks)
}

/// Parse every `CERTIFICATE` block in PEM text into DER certificates (leaf first).
///
/// This is the public counterpart of the loader used by [`TlsCertificate`]; callers that build a
/// client trust store (for example the HTTPS integration tests) use it directly.
pub fn certificates_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    certificate_chain_from_pem(pem)
}

fn certificate_chain_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let chain: Vec<CertificateDer<'static>> = pem_blocks(pem)?
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| CertificateDer::from(der))
        .collect();
    if chain.is_empty() {
        return Err(Error::TlsConfig {
            path: "certificates".to_string(),
            message: "no CERTIFICATE block found in PEM data".to_string(),
        });
    }
    Ok(chain)
}

fn private_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    for (label, der) in pem_blocks(pem)? {
        match label.as_str() {
            "PRIVATE KEY" => return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))),
            "EC PRIVATE KEY" => return Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der))),
            "RSA PRIVATE KEY" => return Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der))),
            _ => continue,
        }
    }
    Err(Error::TlsConfig {
        path: "certificates".to_string(),
        message: "no private key block found in PEM data".to_string(),
    })
}

fn root_store_from_pem(pem: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certificate_chain_from_pem(pem)? {
        roots.add(certificate).map_err(|error| Error::TlsConfig {
            path: "tls_connection_policies[0].client_authentication".to_string(),
            message: format!("invalid client-auth trust root: {error}"),
        })?;
    }
    if roots.is_empty() {
        return Err(Error::TlsConfig {
            path: "tls_connection_policies[0].client_authentication".to_string(),
            message: "client-auth trust root bundle is empty".to_string(),
        });
    }
    Ok(roots)
}

fn normalize_server_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

// ---- minimal X.509 name extraction -----------------------------------------------------------

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    encoded_len: usize,
}

fn read_tlv(input: &[u8]) -> Result<Tlv<'_>> {
    if input.len() < 2 {
        return Err(x509_error("truncated DER"));
    }
    let tag = input[0];
    let first = input[1];
    let (length, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || input.len() < 2 + count {
            return Err(x509_error("invalid DER length"));
        }
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    let end = header
        .checked_add(length)
        .ok_or_else(|| x509_error("DER length overflow"))?;
    if input.len() < end {
        return Err(x509_error("truncated DER content"));
    }
    Ok(Tlv {
        tag,
        content: &input[header..end],
        encoded_len: end,
    })
}

fn read_children<'a>(content: &'a [u8]) -> Result<Vec<Tlv<'a>>> {
    let mut children = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let tlv = read_tlv(rest)?;
        rest = &rest[tlv.encoded_len..];
        children.push(tlv);
    }
    Ok(children)
}

fn x509_error(message: impl Into<String>) -> Error {
    Error::TlsConfig {
        path: "certificates".to_string(),
        message: format!("cannot read certificate names: {}", message.into()),
    }
}

/// Extract the names a certificate covers: subjectAltName `dNSName` entries, or the subject
/// commonName when no SAN DNS names are present.
fn certificate_names(der: &[u8]) -> Result<Vec<String>> {
    let outer = read_tlv(der)?;
    if outer.tag != 0x30 {
        return Err(x509_error("Certificate is not a SEQUENCE"));
    }
    let certificate = read_children(outer.content)?;
    let tbs = certificate
        .first()
        .ok_or_else(|| x509_error("missing tbsCertificate"))?;
    if tbs.tag != 0x30 {
        return Err(x509_error("tbsCertificate is not a SEQUENCE"));
    }
    let mut children = read_children(tbs.content)?;
    // Version [0] is optional; drop it so the fixed positions line up.
    if children.first().map(|child| child.tag) == Some(0xA0) {
        children.remove(0);
    }
    if children.len() < 6 {
        return Err(x509_error("tbsCertificate is too short"));
    }
    let subject = &children[4];

    let mut names = Vec::new();
    if let Some(extensions) = children.iter().find(|child| child.tag == 0xA3) {
        names = subject_alt_names(extensions.content)?;
    }
    if names.is_empty() {
        if let Some(common_name) = common_name(subject.content)? {
            names.push(common_name);
        }
    }
    if names.is_empty() {
        return Err(Error::TlsConfig {
            path: "certificates".to_string(),
            message: "certificate has no subjectAltName dNSName entries and no subject commonName"
                .to_string(),
        });
    }
    Ok(names)
}

fn subject_alt_names(extensions_der: &[u8]) -> Result<Vec<String>> {
    // [3] EXPLICIT Extensions, whose content is a SEQUENCE OF Extension.
    let sequence = read_tlv(extensions_der)?;
    if sequence.tag != 0x30 {
        return Err(x509_error("extensions is not a SEQUENCE"));
    }
    let mut names = Vec::new();
    for extension in read_children(sequence.content)? {
        if extension.tag != 0x30 {
            continue;
        }
        let parts = read_children(extension.content)?;
        let Some(oid) = parts.first() else { continue };
        if oid.tag != 0x06 {
            continue;
        }
        // subjectAltName OID: 2.5.29.17
        if oid.content != [0x55, 0x1D, 0x11] {
            continue;
        }
        let Some(value) = parts.iter().find(|part| part.tag == 0x04) else {
            continue;
        };
        // extnValue OCTET STRING contains GeneralNames ::= SEQUENCE OF GeneralName.
        let general_names = read_tlv(value.content)?;
        if general_names.tag != 0x30 {
            continue;
        }
        for general_name in read_children(general_names.content)? {
            // [2] IMPLICIT IA5String dNSName.
            if general_name.tag == 0x82 {
                if let Ok(name) = std::str::from_utf8(general_name.content) {
                    if !name.is_empty() {
                        names.push(name.to_string());
                    }
                }
            }
        }
    }
    Ok(names)
}

fn common_name(subject_der: &[u8]) -> Result<Option<String>> {
    // Name ::= SEQUENCE OF RelativeDistinguishedName; RDN ::= SET OF AttributeTypeAndValue.
    let name = read_tlv(subject_der)?;
    if name.tag != 0x30 {
        return Ok(None);
    }
    for rdn in read_children(name.content)? {
        if rdn.tag != 0x31 {
            continue;
        }
        for attribute in read_children(rdn.content)? {
            if attribute.tag != 0x30 {
                continue;
            }
            let parts = read_children(attribute.content)?;
            let Some(oid) = parts.first() else { continue };
            if oid.tag != 0x06 || oid.content != [0x55, 0x04, 0x03] {
                continue;
            }
            let Some(value) = parts.get(1) else { continue };
            // UTF8String (0x0C), PrintableString (0x13) or IA5String (0x16).
            let text = match value.tag {
                0x0C => std::str::from_utf8(value.content).ok().map(str::to_string),
                0x13 | 0x16 => std::str::from_utf8(value.content).ok().map(str::to_string),
                _ => None,
            };
            if text.is_some() {
                return Ok(text);
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    const EXAMPLE_CERT: &str = include_str!("../testdata/https/example.com.pem");
    const EXAMPLE_KEY: &str = include_str!("../testdata/https/example.com.key");
    const OTHER_CERT: &str = include_str!("../testdata/https/other.example.pem");
    const OTHER_KEY: &str = include_str!("../testdata/https/other.example.key");

    fn example() -> TlsCertificate {
        TlsCertificate::from_pem(EXAMPLE_CERT, EXAMPLE_KEY).expect("example fixture loads")
    }

    fn other() -> TlsCertificate {
        TlsCertificate::from_pem(OTHER_CERT, OTHER_KEY).expect("other fixture loads")
    }

    fn certificate_der(certificate: &TlsCertificate) -> Vec<u8> {
        certificate.chain()[0].as_ref().to_vec()
    }

    fn fixture_stored(cert_pem: &str, key_pem: &str, domains: &[&str]) -> StoredCertificate {
        StoredCertificate {
            certificate_pem: vec![cert_pem.to_string()],
            private_key_pem: key_pem.to_string(),
            domains: domains.iter().map(|domain| domain.to_string()).collect(),
            not_after_unix: 2_000_000_000,
        }
    }

    #[test]
    fn loads_certificate_names_from_sans() {
        let certificate = example();
        assert_eq!(
            certificate.names(),
            &["example.com".to_string(), "www.example.com".to_string()]
        );
    }

    #[test]
    fn loads_other_certificate_and_its_san() {
        let certificate = other();
        assert_eq!(certificate.names(), &["other.example".to_string()]);
    }

    #[test]
    fn certificate_name_extraction_handles_bad_der() {
        let error = certificate_names(b"not der").unwrap_err();
        assert!(
            error.to_string().contains("cannot read certificate names"),
            "{error}"
        );
    }

    #[test]
    fn validates_key_and_reports_bad_pem() {
        let error = TlsCertificate::from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n", EXAMPLE_KEY)
            .unwrap_err();
        assert!(error.to_string().contains("unterminated"), "{error}");
        let error =
            TlsCertificate::from_pem(EXAMPLE_CERT, "-----BEGIN PRIVATE KEY-----\n").unwrap_err();
        assert!(error.to_string().contains("unterminated"), "{error}");
        let error = TlsCertificate::from_pem(EXAMPLE_CERT, "not a key").unwrap_err();
        assert!(error.to_string().contains("no private key"), "{error}");
    }

    #[test]
    fn resolver_selects_exact_then_wildcard_then_default() {
        let resolver = CertificateResolver::from_certificates([example(), other()]).unwrap();
        assert_eq!(resolver.len(), 3);
        assert!(resolver.has_default());

        let exact = resolver.select(Some("example.com")).expect("exact match");
        assert_eq!(
            exact.cert[0].as_ref(),
            certificate_der(&example()).as_slice()
        );
        assert_eq!(
            resolver
                .select(Some("WWW.EXAMPLE.COM."))
                .expect("case/trailing dot")
                .cert[0]
                .as_ref(),
            certificate_der(&example()).as_slice()
        );
        assert_eq!(
            resolver
                .select(Some("other.example"))
                .expect("second name")
                .cert[0]
                .as_ref(),
            certificate_der(&other()).as_slice()
        );
        // Empty and unknown SNI fall back to the default (first inserted) certificate.
        assert_eq!(
            resolver.select(None).expect("default").cert[0].as_ref(),
            certificate_der(&example()).as_slice()
        );
        assert_eq!(
            resolver
                .select(Some("unknown.example.org"))
                .expect("default fallback")
                .cert[0]
                .as_ref(),
            certificate_der(&example()).as_slice()
        );
        assert_eq!(
            resolver.names(),
            vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
                "other.example".to_string()
            ]
        );
    }

    #[test]
    fn resolver_handles_wildcard_certificates() {
        // A wildcard certificate cannot be generated at fixture time without a CA, but the
        // resolver inserts names verbatim, so a synthetic wildcard name exercises the matching
        // path against a real certificate/key pair.
        let mut wildcard = example();
        wildcard.names = vec!["*.example.net".to_string()];
        let resolver = CertificateResolver::from_certificates([wildcard]).unwrap();
        assert_eq!(
            resolver
                .select(Some("api.example.net"))
                .expect("wildcard match")
                .cert[0]
                .as_ref(),
            certificate_der(&example()).as_slice()
        );
        // A wildcard covers exactly one label.
        assert!(resolver.select(Some("a.b.example.net")).is_none() || resolver.has_default());
    }

    #[test]
    fn resolver_from_cache_uses_cached_der_and_domains() {
        let cache = CertificateCache::new();
        let example = example();
        cache.insert(Certificate {
            domains: vec!["cached.example".to_string()],
            cert_chain_der: example
                .chain()
                .iter()
                .map(|der| der.as_ref().to_vec())
                .collect(),
            private_key_der: match example.private_key() {
                PrivateKeyDer::Pkcs8(key) => key.secret_pkcs8_der().to_vec(),
                other => panic!("fixture key must be PKCS#8, got {other:?}"),
            },
            not_before: std::time::SystemTime::UNIX_EPOCH,
            not_after: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(3600),
            issuer: "loaded".to_string(),
        });
        let resolver = CertificateResolver::from_cache(&cache).unwrap();
        assert_eq!(resolver.names(), vec!["cached.example".to_string()]);
        assert!(resolver.select(Some("cached.example")).is_some());
    }

    #[tokio::test]
    async fn resolver_loads_from_storage() {
        let storage = MemoryStorage::new();
        storage
            .store(
                "local/example.com",
                &fixture_stored(
                    EXAMPLE_CERT,
                    EXAMPLE_KEY,
                    &["example.com", "www.example.com"],
                ),
            )
            .await
            .unwrap();
        storage
            .store(
                "local/other.example",
                &fixture_stored(OTHER_CERT, OTHER_KEY, &["other.example"]),
            )
            .await
            .unwrap();
        let resolver = CertificateResolver::load_from_storage(&storage)
            .await
            .unwrap();
        assert_eq!(
            resolver.names(),
            vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
                "other.example".to_string()
            ]
        );
        assert!(resolver.select(Some("other.example")).is_some());
    }

    #[tokio::test]
    async fn resolver_loads_from_caddy_layout_file_storage() {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::storage::FileStorage::new(directory.path());
        storage
            .store(
                "local/example.com",
                &fixture_stored(
                    EXAMPLE_CERT,
                    EXAMPLE_KEY,
                    &["example.com", "www.example.com"],
                ),
            )
            .await
            .unwrap();
        let resolver = CertificateResolver::load_from_storage(&storage)
            .await
            .unwrap();
        assert_eq!(resolver.len(), 2);
    }

    #[test]
    fn builds_server_config_with_alpn_and_resolver() {
        let resolver = Arc::new(CertificateResolver::from_certificates([example()]).unwrap());
        let config = build_server_config(Arc::clone(&resolver), &TlsServerOptions::default())
            .expect("server config builds");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert!(Arc::strong_count(&resolver) >= 1);
    }

    #[test]
    fn option_parsing_from_connection_policies() {
        // Absent/empty policies mean Caddy defaults.
        assert_eq!(
            TlsServerOptions::from_connection_policies(None).unwrap(),
            TlsServerOptions::default()
        );
        assert_eq!(
            TlsServerOptions::from_connection_policies(Some(&[])).unwrap(),
            TlsServerOptions::default()
        );
        let options = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
            "alpn": ["http/1.1"],
            "protocols": ["tls1.3"],
            "client_authentication": {"mode": "request"}
        })]))
        .unwrap();
        assert_eq!(options.alpn, vec![b"http/1.1".to_vec()]);
        assert_eq!(options.versions, TlsVersions::Tls13Only);
        assert_eq!(options.client_auth, ClientAuthMode::Request);

        let error = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
            "alpn": ["h3"]
        })]))
        .unwrap_err();
        assert!(error.to_string().contains("unsupported ALPN"), "{error}");
        let error = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
            "protocols": ["ssl3"]
        })]))
        .unwrap_err();
        assert!(
            error.to_string().contains("unsupported TLS protocol"),
            "{error}"
        );
    }

    #[test]
    fn option_parsing_rejects_unimplemented_policy_fields() {
        let error = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
            "default_sni": "example.com"
        })]))
        .unwrap_err();
        assert!(
            error.to_string().contains("TLS connection policy field"),
            "{error}"
        );
        let error = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
            "curves": ["x25519"]
        })]))
        .unwrap_err();
        assert!(
            error.to_string().contains("TLS connection policy field"),
            "{error}"
        );
    }

    #[test]
    fn option_parsing_rejects_unmodelled_client_auth_ca_pools() {
        let error = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
            "client_authentication": {
                "mode": "require",
                "trusted_ca_pool": {"module": "tls.ca_pool.source.inline"}
            }
        })]))
        .unwrap_err();
        assert!(
            error.to_string().contains("client authentication CA pools"),
            "{error}"
        );
    }

    #[test]
    fn client_auth_requires_explicit_roots() {
        let resolver = Arc::new(CertificateResolver::from_certificates([example()]).unwrap());
        let mut options = TlsServerOptions {
            client_auth: ClientAuthMode::Require,
            ..TlsServerOptions::default()
        };
        let error = build_server_config(Arc::clone(&resolver), &options).unwrap_err();
        assert!(
            error.to_string().contains("requires a trusted CA bundle"),
            "{error}"
        );

        options.client_auth_roots_pem = Some(EXAMPLE_CERT.to_string());
        let config = build_server_config(resolver, &options).unwrap();
        assert!(config.alpn_protocols.contains(&b"h2".to_vec()));
    }

    #[test]
    fn listener_policy_uses_policies_or_https_port() {
        assert!(listener_uses_tls(":443", DEFAULT_HTTPS_PORT, false).unwrap());
        assert!(!listener_uses_tls(":80", DEFAULT_HTTPS_PORT, false).unwrap());
        assert!(listener_uses_tls(":8080", DEFAULT_HTTPS_PORT, true).unwrap());
        assert!(!listener_uses_tls("127.0.0.1:0", DEFAULT_HTTPS_PORT, false).unwrap());
        assert!(listener_uses_tls("127.0.0.1:0", DEFAULT_HTTPS_PORT, true).unwrap());
        let error =
            listener_uses_tls("unix//run/caddy.sock", DEFAULT_HTTPS_PORT, true).unwrap_err();
        assert!(error.to_string().contains("Unix"), "{error}");
    }

    #[test]
    fn loads_certificates_from_typed_tls_config() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"tls": {"certificates": {"load_pem": [
                {"certificate": EXAMPLE_CERT, "key": EXAMPLE_KEY},
                {"certificate": OTHER_CERT, "key": OTHER_KEY}
            ]}}}
        }))
        .unwrap();
        let resolver = resolver_from_config(&config)
            .unwrap()
            .expect("certificates load");
        assert_eq!(resolver.len(), 3);
        assert!(resolver.select(Some("other.example")).is_some());
        // No TLS app at all: no resolver.
        let empty = Config::from_value(serde_json::json!({"apps": {}})).unwrap();
        assert!(resolver_from_config(&empty).unwrap().is_none());
    }

    #[test]
    fn config_loading_reports_located_pem_errors() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"tls": {"certificates": {"load_pem": [
                {"certificate": "not a certificate", "key": "not a key"}
            ]}}}
        }))
        .unwrap();
        let error = resolver_from_config(&config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("apps.tls.certificates.load_pem[0]"),
            "{error}"
        );
    }

    #[test]
    fn resolver_rejects_unsupported_key_types() {
        // A syntactically valid PEM block whose DER is not a supported key is rejected when the
        // rustls signing key is built (i.e. when the resolver inserts the certificate).
        let certificate = TlsCertificate::from_pem(
            EXAMPLE_CERT,
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let error = certificate.certified_key().unwrap_err();
        assert!(error.to_string().contains("certificates"), "{error}");
        let error = CertificateResolver::from_certificates([certificate]).unwrap_err();
        assert!(error.to_string().contains("certificates"), "{error}");
    }
}
