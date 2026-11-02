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
//!   `tls_connection_policies` JSON and keeps every policy's `match.sni` /
//!   `certificate_selection.any_tag` for per-connection certificate selection (evaluated by
//!   [`ConnectionPolicyResolver`] after the ClientHello, in policy order, with `{}` as the
//!   catch-all fallback);
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TlsVersions {
    /// TLS 1.2 and TLS 1.3 (rustls safe defaults, matching Caddy's defaults).
    #[default]
    Default,
    /// TLS 1.2 only.
    Tls12Only,
    /// TLS 1.3 only.
    Tls13Only,
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
    /// Per-connection certificate selection policies, in configuration order.
    ///
    /// Caddy evaluates `tls_connection_policies` per ClientHello: the first policy whose
    /// `match` constraints accept the connection applies, including its
    /// `certificate_selection`. The empty catch-all policy (`{}`) matches every connection and
    /// therefore falls back to normal SNI selection.
    pub certificate_policies: Vec<CertificatePolicy>,
}

/// Certificate selection rules from one `tls_connection_policies` entry.
///
/// Only the fields the rustls terminator can honour are represented: SNI matching (`match.sni`)
/// and tag-based selection (`certificate_selection.any_tag`). Other selection criteria are
/// rejected loudly by [`TlsServerOptions::from_connection_policies`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertificatePolicy {
    /// SNI patterns from `match.sni`. Left-most-label wildcards (`*.example.com`) are supported;
    /// `None` matches every SNI (including connections without SNI).
    pub sni: Option<Vec<String>>,
    /// Tags from `certificate_selection.any_tag`; a certificate matches when it carries at least
    /// one of these tags. `None` (or an empty list) means "no tag filtering".
    pub any_tag: Option<Vec<String>>,
}

impl CertificatePolicy {
    /// Whether this policy's `match` constraints accept `server_name`.
    pub fn matches_server_name(&self, server_name: Option<&str>) -> bool {
        let Some(patterns) = &self.sni else {
            return true;
        };
        let Some(server_name) = server_name else {
            return false;
        };
        let server_name = normalize_server_name(server_name);
        patterns
            .iter()
            .any(|pattern| server_name_matches(pattern, &server_name))
    }

    /// The tags this policy filters on, if any.
    pub fn tags(&self) -> Option<&[String]> {
        self.any_tag.as_deref().filter(|tags| !tags.is_empty())
    }
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
            certificate_policies: Vec::new(),
        }
    }
}

impl TlsServerOptions {
    /// Include the ACME TLS-ALPN-01 protocol (`acme-tls/1`) in the server's ALPN list.
    ///
    /// Required when the listener should be able to answer `acme-tls/1` challenge handshakes; the
    /// resolver overlay is [`crate::tls_alpn::AcmeTlsAlpnResolver`].
    pub fn with_acme_tls_alpn(mut self) -> Self {
        if !self.supports_acme_tls_alpn() {
            self.alpn
                .push(crate::tls_alpn::ACME_TLS_ALPN_PROTOCOL.to_vec());
        }
        self
    }

    /// Whether `acme-tls/1` is in the ALPN list.
    pub fn supports_acme_tls_alpn(&self) -> bool {
        self.alpn
            .iter()
            .any(|protocol| protocol.as_slice() == crate::tls_alpn::ACME_TLS_ALPN_PROTOCOL)
    }

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
        // Parse every connection policy: the first one supplied the listener-wide options above,
        // and each policy contributes per-connection certificate selection. Caddy evaluates the
        // policies in order after the ClientHello (SNI is available) and the first matching policy
        // applies, including its certificate selection.
        let mut certificate_policies = Vec::with_capacity(policies.len());
        for (index, value) in policies.iter().enumerate() {
            certificate_policies.push(parse_connection_policy(value, index)?);
        }
        options.certificate_policies = certificate_policies;
        Ok(options)
    }
}

/// Parse one `tls_connection_policies[i]` entry into per-connection certificate selection rules.
///
/// Fields that configure the rustls `ServerConfig` (`alpn`, `protocols`, `client_authentication`)
/// are only honoured on the first policy (rustls has one configuration per listener); seeing them
/// on a later policy fails loudly instead of silently applying the first policy's value.
fn parse_connection_policy(value: &Value, index: usize) -> Result<CertificatePolicy> {
    let path = format!("tls_connection_policies[{index}]");
    let Some(object) = value.as_object() else {
        return Err(Error::TlsConfig {
            path,
            message: "connection policy must be an object".to_string(),
        });
    };
    let mut policy = CertificatePolicy::default();
    for field in object.keys() {
        match field.as_str() {
            "match" => {
                let match_object =
                    object
                        .get("match")
                        .and_then(Value::as_object)
                        .ok_or_else(|| Error::TlsConfig {
                            path: format!("{path}.match"),
                            message: "`match` must be an object".to_string(),
                        })?;
                for key in match_object.keys() {
                    if key != "sni" {
                        return Err(Error::Unsupported {
                            path: format!("{path}.match.{key}"),
                            feature: format!("TLS connection policy match field `{key}`"),
                            tracking_id: "TLS-CONN-MATCH",
                        });
                    }
                }
                if let Some(sni) = match_object.get("sni") {
                    let patterns = sni.as_array().ok_or_else(|| Error::TlsConfig {
                        path: format!("{path}.match.sni"),
                        message: "`match.sni` must be an array of server names".to_string(),
                    })?;
                    if patterns.is_empty() {
                        return Err(Error::TlsConfig {
                            path: format!("{path}.match.sni"),
                            message: "`match.sni` must contain at least one server name"
                                .to_string(),
                        });
                    }
                    let mut sni_patterns = Vec::with_capacity(patterns.len());
                    for (pattern_index, pattern) in patterns.iter().enumerate() {
                        let pattern = pattern.as_str().ok_or_else(|| Error::TlsConfig {
                            path: format!("{path}.match.sni[{pattern_index}]"),
                            message: "SNI pattern must be a string".to_string(),
                        })?;
                        if pattern.trim().is_empty() {
                            return Err(Error::TlsConfig {
                                path: format!("{path}.match.sni[{pattern_index}]"),
                                message: "SNI pattern must not be empty".to_string(),
                            });
                        }
                        if !pattern.trim().is_ascii() {
                            return Err(Error::Unsupported {
                                path: format!("{path}.match.sni[{pattern_index}]"),
                                feature: "internationalized (IDN) `match.sni` patterns; configure the ASCII/punycode form"
                                    .to_string(),
                                tracking_id: "TLS-CONN-MATCH",
                            });
                        }
                        sni_patterns.push(pattern.trim().to_string());
                    }
                    policy.sni = Some(sni_patterns);
                }
            }
            "certificate_selection" => {
                let selection = object
                    .get("certificate_selection")
                    .and_then(Value::as_object)
                    .ok_or_else(|| Error::TlsConfig {
                        path: format!("{path}.certificate_selection"),
                        message: "`certificate_selection` must be an object".to_string(),
                    })?;
                for key in selection.keys() {
                    if key != "any_tag" {
                        return Err(Error::Unsupported {
                            path: format!("{path}.certificate_selection.{key}"),
                            feature: format!("certificate selection criterion `{key}`"),
                            tracking_id: "TLS-CERT-SELECTION",
                        });
                    }
                }
                if let Some(tags) = selection.get("any_tag") {
                    let tags = tags.as_array().ok_or_else(|| Error::TlsConfig {
                        path: format!("{path}.certificate_selection.any_tag"),
                        message: "`any_tag` must be an array of tags".to_string(),
                    })?;
                    let mut any_tags = Vec::with_capacity(tags.len());
                    for (tag_index, tag) in tags.iter().enumerate() {
                        let tag = tag.as_str().ok_or_else(|| Error::TlsConfig {
                            path: format!("{path}.certificate_selection.any_tag[{tag_index}]"),
                            message: "tag must be a string".to_string(),
                        })?;
                        if tag.trim().is_empty() {
                            return Err(Error::TlsConfig {
                                path: format!("{path}.certificate_selection.any_tag[{tag_index}]"),
                                message: "tag must not be empty".to_string(),
                            });
                        }
                        any_tags.push(tag.trim().to_string());
                    }
                    if !any_tags.is_empty() {
                        policy.any_tag = Some(any_tags);
                    }
                }
            }
            "alpn" | "protocols" | "client_authentication" => {
                if index != 0 {
                    return Err(Error::Unsupported {
                        path: format!("{path}.{field}"),
                        feature: format!(
                            "per-connection policy field `{field}` (only the first policy's listener-wide options are applied)"
                        ),
                        tracking_id: "TLS-CONN-POLICY",
                    });
                }
            }
            other => {
                return Err(Error::Unsupported {
                    path: path.clone(),
                    feature: format!("TLS connection policy field `{other}`"),
                    tracking_id: "TLS-CONN-POLICY",
                });
            }
        }
    }
    Ok(policy)
}

/// A certificate chain and private key ready for rustls, with the names it covers.
#[derive(Debug)]
pub struct TlsCertificate {
    names: Vec<String>,
    tags: Vec<String>,
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
            tags: Vec::new(),
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
            tags: Vec::new(),
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
            tags: Vec::new(),
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

    /// Tags carried by this certificate (`apps.tls.certificates.load_*.tags`).
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Attach the configured tags (used by connection-policy `certificate_selection.any_tag`).
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
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
    /// Distinct tagged certificates, in insertion order, for `certificate_selection.any_tag`.
    tagged: Vec<TaggedCertificate>,
}

#[derive(Debug)]
struct TaggedCertificate {
    /// Tags as configured (case-sensitive; compared exactly like Caddy's `HasTag`).
    tags: Vec<String>,
    /// Normalized names the certificate covers (lowercase, no trailing dot).
    names: Vec<String>,
    certified: Arc<CertifiedKey>,
}

impl ResolverState {
    fn insert(&mut self, certificate: TlsCertificate) -> Result<()> {
        let certified = Arc::new(certificate.certified_key()?);
        if self.default.is_none() {
            self.default = Some(Arc::clone(&certified));
        }
        if !certificate.tags().is_empty() {
            self.tagged.push(TaggedCertificate {
                tags: certificate.tags().to_vec(),
                names: certificate
                    .names()
                    .iter()
                    .map(|name| normalize_server_name(name))
                    .collect(),
                certified: Arc::clone(&certified),
            });
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

/// Tag-filtered certificate selection used by connection-policy `certificate_selection.any_tag`.
pub trait TaggedCertificateSelector: Send + Sync {
    /// Select a certificate carrying at least one of `any_tags`.
    ///
    /// Matching order within the tagged subset: exact SNI, one-label wildcard, then the first
    /// tagged certificate as the subset default. `None` means the tagged subset is empty (Caddy
    /// fails the handshake in that case rather than falling back to an untagged certificate).
    fn select_with_tags(
        &self,
        server_name: Option<&str>,
        any_tags: &[String],
    ) -> Option<Arc<CertifiedKey>>;
}

impl TaggedCertificateSelector for CertificateResolver {
    fn select_with_tags(
        &self,
        server_name: Option<&str>,
        any_tags: &[String],
    ) -> Option<Arc<CertifiedKey>> {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let candidates: Vec<&TaggedCertificate> = state
            .tagged
            .iter()
            .filter(|candidate| {
                candidate
                    .tags
                    .iter()
                    .any(|tag| any_tags.iter().any(|wanted| wanted == tag))
            })
            .collect();
        let first = candidates.first()?;
        let Some(server_name) = server_name else {
            return Some(Arc::clone(&first.certified));
        };
        let name = normalize_server_name(server_name);
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.names.iter().any(|candidate| candidate == &name))
        {
            return Some(Arc::clone(&candidate.certified));
        }
        if let Some((_, rest)) = name.split_once('.') {
            if !rest.is_empty() && rest.contains('.') {
                let wildcard = format!("*.{rest}");
                if let Some(candidate) = candidates
                    .iter()
                    .find(|candidate| candidate.names.iter().any(|name| name == &wildcard))
                {
                    return Some(Arc::clone(&candidate.certified));
                }
            }
        }
        // Caddy's certmagic default selector falls back to the first viable candidate.
        Some(Arc::clone(&first.certified))
    }
}

/// A certificate resolver that can expose tag-filtered selection to connection policies.
///
/// `build_server_config_with_cert_resolver` wraps this in a
/// [`ConnectionPolicyResolver`] when the listener has `certificate_selection.any_tag` policies.
/// The two resolvers supplied by this crate implement it: [`CertificateResolver`] exposes its
/// tagged certificates directly, and [`crate::tls_alpn::AcmeTlsAlpnResolver`] forwards to its
/// fallback resolver.
pub trait TlsResolver: ResolvesServerCert {
    /// The tag selector for this resolver, if it can select by certificate tags.
    fn tag_selector(&self) -> Option<&dyn TaggedCertificateSelector>;
}

impl TlsResolver for CertificateResolver {
    fn tag_selector(&self) -> Option<&dyn TaggedCertificateSelector> {
        Some(self)
    }
}

/// Adapter from [`TlsResolver`] to rustls' [`ResolvesServerCert`] for the no-policy path.
#[derive(Debug)]
struct TlsResolverAdapter(Arc<dyn TlsResolver>);

impl ResolvesServerCert for TlsResolverAdapter {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.resolve(client_hello)
    }
}

/// Resolver that applies per-connection `tls_connection_policies` certificate selection.
#[derive(Debug)]
struct ConnectionPolicyResolver {
    fallback: Arc<dyn TlsResolver>,
    policies: Vec<CertificatePolicy>,
}

impl ResolvesServerCert for ConnectionPolicyResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // ACME TLS-ALPN-01 challenge handshakes must never be filtered by connection policies; the
        // fallback resolver's overlay answers them (it advertises `acme-tls/1` itself).
        let offers_acme_tls = client_hello
            .alpn()
            .map(|protocols| {
                protocols
                    .into_iter()
                    .any(|protocol| protocol == crate::tls_alpn::ACME_TLS_ALPN_PROTOCOL)
            })
            .unwrap_or(false);
        if offers_acme_tls {
            return self.fallback.resolve(client_hello);
        }
        let server_name = client_hello.server_name();
        for policy in &self.policies {
            if !policy.matches_server_name(server_name) {
                continue;
            }
            let Some(tags) = policy.tags() else {
                // First matching policy without a tag filter: normal SNI selection.
                return self.fallback.resolve(client_hello);
            };
            // A connection policy matched and requires one of these tags. Caddy's custom selector
            // fails the handshake when no tagged certificate is viable, so do not fall through to
            // later policies here.
            return self
                .fallback
                .tag_selector()
                .and_then(|selector| selector.select_with_tags(server_name, tags));
        }
        // No policy's match constraints accepted the connection (for example an unknown SNI with
        // no catch-all policy): keep the historical permissive default-certificate behaviour.
        self.fallback.resolve(client_hello)
    }
}

/// Build a rustls server configuration from a [`CertificateResolver`] and options.
pub fn build_server_config(
    resolver: Arc<CertificateResolver>,
    options: &TlsServerOptions,
) -> Result<Arc<ServerConfig>> {
    build_server_config_with_cert_resolver(resolver, options)
}

/// Build a rustls server configuration from a certificate resolver.
///
/// Use this with [`crate::tls_alpn::AcmeTlsAlpnResolver`] to combine normal SNI selection with
/// ACME TLS-ALPN-01 challenge certificates.
///
/// When the listener's `tls_connection_policies` contain per-connection certificate selection
/// rules, the supplied resolver is wrapped in a policy resolver that selects the certificate after
/// the ClientHello (SNI is available), matching Caddy's policy order. Tag-based selection requires
/// a resolver that implements [`TlsResolver`]; both resolvers provided by this crate do, including
/// the ACME TLS-ALPN overlay (which forwards to its fallback).
pub fn build_server_config_with_cert_resolver(
    resolver: Arc<dyn TlsResolver>,
    options: &TlsServerOptions,
) -> Result<Arc<ServerConfig>> {
    let resolver: Arc<dyn ResolvesServerCert> = if options.certificate_policies.is_empty() {
        Arc::new(TlsResolverAdapter(resolver))
    } else {
        // Tag filtering needs a tag-aware resolver; fail loudly rather than ignoring the policy.
        let requires_tags = options
            .certificate_policies
            .iter()
            .any(|policy| policy.tags().is_some());
        if requires_tags && resolver.tag_selector().is_none() {
            return Err(Error::NotImplemented {
                feature: "certificate_selection.any_tag with a resolver that cannot select by certificate tag",
                tracking_id: "TLS-CERT-SELECTION",
            });
        }
        Arc::new(ConnectionPolicyResolver {
            fallback: resolver,
            policies: options.certificate_policies.clone(),
        })
    };
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
        let certificate = TlsCertificate::from_pem(&certificate_pem, &private_key_pem)
            .map(|certificate| certificate.with_tags(pair.tags.clone()))
            .map_err(|error| Error::TlsConfig {
                path: path.clone(),
                message: error.to_string(),
            })?;
        certificates.push(certificate);
    }
    Ok(certificates)
}

fn load_pem_pair(pair: &CertKeyPemPair, path: &str) -> Result<TlsCertificate> {
    TlsCertificate::from_pem(&pair.certificate, &pair.key)
        .map(|certificate| certificate.with_tags(pair.tags.clone()))
        .map_err(|error| match error {
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

/// Match one SNI pattern against a normalized server name.
///
/// Exact names compare case-insensitively. Left-most-label wildcards (`*.example.com`) match
/// exactly one additional label, mirroring Caddy's `MatchServerName` semantics.
fn server_name_matches(pattern: &str, normalized_server_name: &str) -> bool {
    let pattern = normalize_server_name(pattern);
    if pattern == "*" || pattern == normalized_server_name {
        return true;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) => normalized_server_name
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
        None => false,
    }
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

    // ---- connection-policy SNI matching and certificate_selection tags -------------------

    /// Test-only verifier that accepts any server certificate. Used to inspect which certificate
    /// the connection policy selected when the name does not match the certificate.
    #[derive(Debug)]
    struct AcceptAnyCertificate(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
        {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            rustls::crypto::verify_tls12_signature(
                message,
                certificate,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            rustls::crypto::verify_tls13_signature(
                message,
                certificate,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Run a real rustls handshake against `server_config` and return the leaf certificate DER the
    /// client received.
    async fn handshake_peer_certificate(
        server_config: Arc<ServerConfig>,
        server_name: &str,
    ) -> Vec<u8> {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.expect("server TLS handshake");
            let _ = tls.write_all(b"ok").await;
            let _ = tls.shutdown().await;
        });

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string()).unwrap();
        let tls = connector
            .connect(server_name, stream)
            .await
            .expect("client TLS handshake");
        let certificate = tls.get_ref().1.peer_certificates().unwrap()[0]
            .as_ref()
            .to_vec();
        server.await.unwrap();
        certificate
    }

    #[test]
    fn parses_adapted_cert_key_connection_policies() {
        // shape emitted by the Caddyfile adapter for `tls <cert> <key>`:
        // a tag-selecting policy matched by SNI plus an empty catch-all fallback.
        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({
                "match": {"sni": ["localhost"]},
                "certificate_selection": {"any_tag": ["cert0"]}
            }),
            serde_json::json!({}),
        ]))
        .expect("adapted cert/key policies parse");

        assert_eq!(options.certificate_policies.len(), 2);
        assert_eq!(
            options.certificate_policies[0].sni,
            Some(vec!["localhost".to_string()])
        );
        assert_eq!(
            options.certificate_policies[0].any_tag,
            Some(vec!["cert0".to_string()])
        );
        assert!(options.certificate_policies[1].sni.is_none());
        assert!(options.certificate_policies[1].any_tag.is_none());
        // Listener-wide options still come from the first policy; absent fields are defaults.
        assert_eq!(options.alpn, TlsServerOptions::default().alpn);

        let any_name = CertificatePolicy {
            sni: Some(vec!["*".to_string()]),
            any_tag: None,
        };
        assert!(any_name.matches_server_name(Some("example.com")));
        assert!(any_name.matches_server_name(Some("a.b.example.com")));

        let wildcard = CertificatePolicy {
            sni: Some(vec!["*.example.com".to_string()]),
            any_tag: None,
        };
        assert!(wildcard.matches_server_name(Some("api.example.com")));
        assert!(!wildcard.matches_server_name(Some("example.com")));
        assert!(!wildcard.matches_server_name(Some("a.b.example.com")));
        assert!(!wildcard.matches_server_name(None));
        let catch_all = CertificatePolicy::default();
        assert!(catch_all.matches_server_name(Some("anything.example")));
        assert!(catch_all.matches_server_name(None));
    }

    #[test]
    fn rejects_unsupported_connection_policy_match_and_selection_fields() {
        let error = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
            "match": {"remote_ip": ["192.0.2.1"]}
        })]))
        .unwrap_err();
        assert!(error.to_string().contains("TLS-CONN-MATCH"), "{error}");
        assert!(error.to_string().contains("remote_ip"), "{error}");

        for criterion in [
            "serial_number",
            "subject_organization",
            "all_tags",
            "public_key_algorithm",
        ] {
            let error = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
                "certificate_selection": {criterion: ["x"]}
            })]))
            .unwrap_err();
            assert!(
                error.to_string().contains("TLS-CERT-SELECTION"),
                "{criterion}: {error}"
            );
        }

        // IDN patterns are not silently ignored: this build does not implement IDNA conversion.
        let error = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
            "match": {"sni": ["bücher.example"]}
        })]))
        .unwrap_err();
        assert!(error.to_string().contains("IDN"), "{error}");

        // Listener-wide fields are only honoured on the first policy; a later policy that tries to
        // change them fails loudly instead of silently using the first policy's values.
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"certificate_selection": {"any_tag": ["a"]}}),
            serde_json::json!({"alpn": ["http/1.1"]}),
        ]))
        .unwrap_err();
        assert!(error.to_string().contains("TLS-CONN-POLICY"), "{error}");
    }

    #[tokio::test]
    async fn certificate_selection_any_tag_filters_by_tag_before_sni() {
        // The default certificate is `other.example`; the example.com certificate is untagged.
        // A policy for SNI example.com requesting tag `cert0` must pick the tagged certificate,
        // proving tag filtering is applied rather than plain SNI selection.
        let resolver = Arc::new(
            CertificateResolver::from_certificates([
                other().with_tags(vec!["cert0".to_string()]),
                example(),
            ])
            .expect("resolver builds"),
        );
        let policies = [
            serde_json::json!({
                "match": {"sni": ["example.com"]},
                "certificate_selection": {"any_tag": ["cert0"]}
            }),
            serde_json::json!({}),
        ];
        let options =
            TlsServerOptions::from_connection_policies(Some(&policies)).expect("policies parse");
        let config = build_server_config(Arc::clone(&resolver), &options).expect("config builds");
        let served = handshake_peer_certificate(config, "example.com").await;
        assert_eq!(
            served,
            certificate_der(&other()),
            "tag policy must select the tagged certificate even when SNI matches another cert"
        );

        // Without policies the same resolver serves the normal SNI-selected certificate.
        let plain = build_server_config(resolver, &TlsServerOptions::default()).expect("config");
        let served = handshake_peer_certificate(plain, "example.com").await;
        assert_eq!(served, certificate_der(&example()));
    }

    #[tokio::test]
    async fn certificate_selection_policies_evaluate_in_order_with_catch_all_fallback() {
        let resolver = Arc::new(
            CertificateResolver::from_certificates([
                example().with_tags(vec!["cert0".to_string()]),
                other().with_tags(vec!["cert1".to_string()]),
            ])
            .expect("resolver builds"),
        );
        let policies = [
            serde_json::json!({
                "match": {"sni": ["example.com", "www.example.com"]},
                "certificate_selection": {"any_tag": ["cert0"]}
            }),
            serde_json::json!({
                "match": {"sni": ["other.example"]},
                "certificate_selection": {"any_tag": ["cert1"]}
            }),
            serde_json::json!({}),
        ];
        let options =
            TlsServerOptions::from_connection_policies(Some(&policies)).expect("policies parse");
        let config = build_server_config(Arc::clone(&resolver), &options).expect("config builds");

        assert_eq!(
            handshake_peer_certificate(Arc::clone(&config), "example.com").await,
            certificate_der(&example())
        );
        assert_eq!(
            handshake_peer_certificate(Arc::clone(&config), "www.example.com").await,
            certificate_der(&example())
        );
        assert_eq!(
            handshake_peer_certificate(Arc::clone(&config), "other.example").await,
            certificate_der(&other())
        );
        // Unknown SNI matches only the empty catch-all policy: normal SNI selection (default
        // certificate, which is the first inserted one).
        assert_eq!(
            handshake_peer_certificate(config, "unknown.example").await,
            certificate_der(&example())
        );
    }

    #[tokio::test]
    async fn no_tagged_candidate_fails_the_handshake() {
        let resolver =
            Arc::new(CertificateResolver::from_certificates([example()]).expect("resolver builds"));
        let policies = [serde_json::json!({
            "match": {"sni": ["example.com"]},
            "certificate_selection": {"any_tag": ["missing-tag"]}
        })];
        let options =
            TlsServerOptions::from_connection_policies(Some(&policies)).expect("policies parse");
        let config = build_server_config(resolver, &options).expect("config builds");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await
        });
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        assert!(
            connector.connect(server_name, stream).await.is_err(),
            "a policy whose tag set matches no certificate must fail the handshake"
        );
        assert!(server.await.unwrap().is_err());
    }

    #[test]
    fn load_files_tags_are_loaded_into_certificates() {
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("example.pem");
        let key_path = directory.path().join("example.key");
        std::fs::write(&certificate_path, EXAMPLE_CERT).unwrap();
        std::fs::write(&key_path, EXAMPLE_KEY).unwrap();
        let config = Config::from_value(serde_json::json!({
            "apps": {"tls": {"certificates": {"load_files": [{
                "certificate": certificate_path.to_string_lossy(),
                "key": key_path.to_string_lossy(),
                "tags": ["cert0", "shared"]
            }]}}}
        }))
        .expect("config decodes");
        let certificates = certificates_from_tls_app(config.tls().unwrap()).unwrap();
        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].tags(), &["cert0", "shared"]);
        let resolver = CertificateResolver::from_certificates(certificates).unwrap();
        assert!(
            resolver
                .select_with_tags(Some("example.com"), &["shared".to_string()])
                .is_some(),
            "tags from load_files must be selectable"
        );
        assert!(resolver
            .select_with_tags(Some("example.com"), &["missing".to_string()])
            .is_none());
    }

    #[test]
    fn build_server_config_with_custom_resolver_supports_tag_policies() {
        // The ACME TLS-ALPN overlay forwards tag selection to its fallback resolver, so the
        // auto-HTTPS listener path supports connection-policy tag selection too.
        let resolver = Arc::new(
            CertificateResolver::from_certificates(
                [example().with_tags(vec!["cert0".to_string()])],
            )
            .expect("resolver builds"),
        );
        let tokens = Arc::new(crate::tls_alpn::TlsAlpn01TokenStore::new());
        let overlay = Arc::new(crate::tls_alpn::AcmeTlsAlpnResolver::new(
            Arc::clone(&resolver),
            tokens,
        ));
        let policies = [serde_json::json!({
            "match": {"sni": ["example.com"]},
            "certificate_selection": {"any_tag": ["cert0"]}
        })];
        let options =
            TlsServerOptions::from_connection_policies(Some(&policies)).expect("policies parse");
        build_server_config_with_cert_resolver(overlay, &options)
            .expect("ACME overlay with tag-aware fallback builds");
    }
}
