//! rustls server configuration: certificate/key loading, SNI resolution, ALPN, and client auth.
//!
//! This is the server-side TLS boundary consumed by `caddy-rs-server`. It keeps the
//! configuration logic free of listener I/O so it can be unit-tested:
//!
//! * [`TlsCertificate`] loads a PEM/DER certificate chain + private key and extracts the names
//!   the certificate covers (subjectAltName `dNSName` entries plus the subject `commonName`, like
//!   Caddy's certmagic) with a small DER walker — no X.509 parsing crate is available in the
//!   offline registry cache;
//! * [`CertificateResolver`] implements rustls' [`ResolvesServerCert`] with exact-name then
//!   one-label-wildcard matching, a default certificate for empty/unknown SNI, and constructors
//!   from the existing [`CertificateCache`], from [`CertificateStorage`], and from typed
//!   `apps.tls.certificates` configuration;
//! * [`TlsServerOptions`] derives ALPN, TLS versions and client-auth mode from Caddy's
//!   `tls_connection_policies` JSON and keeps every policy's `match.sni` /
//!   `certificate_selection.any_tag` for per-connection certificate selection (evaluated by
//!   [`ConnectionPolicyResolver`] after the ClientHello, in policy order, with `{}` as the
//!   catch-all fallback);
//! * [`build_server_config`] assembles the rustls [`ServerConfig`] with the aws-lc-rs provider
//!   and applies `tls_connection_policies[0].curves`/`cipher_suites` to a custom
//!   [`CryptoProvider`] (Caddy/Go curve names x25519mlkem768/x25519/secp256r1/secp384r1 and the
//!   six ECDHE AES-GCM/ChaCha20 TLS 1.2 suites). TLS 1.3 cipher suites are fixed by rustls/Go
//!   and cannot be configured; unsupported curve/cipher names (including secp521r1, RSA
//!   key-exchange suites and TLS 1.3 suites) fail loudly with TLS-POLICY tracking. P-521
//!   certificate keys are supported through the provider's signature schemes; only the P-521
//!   key-exchange group is unavailable.
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

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme, SupportedCipherSuite, SupportedProtocolVersion,
};
use serde_json::Value;

use caddy_rs_core::config::{CertKeyPemPair, Config, TlsApp};
use caddy_rs_core::listen::{ListenAddr, Network};

use crate::certificate::{Certificate, CertificateCache};
use crate::key_type::{self, classify, KeySupport};
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
    /// Ask for a client certificate but allow none and do not verify it (Caddy `request`).
    Request,
    /// Require a client certificate but do not verify it (Caddy `require`).
    Require,
    /// Ask for a client certificate, allow none, and verify it when supplied
    /// (Caddy `verify_if_given`).
    VerifyIfGiven,
    /// Require a valid client certificate that chains to the configured trust pool
    /// (Caddy `require_and_verify`).
    RequireAndVerify,
}

impl ClientAuthMode {
    /// Parse Caddy's `client_authentication.mode` values.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "request" => Ok(Self::Request),
            "require" => Ok(Self::Require),
            "verify_if_given" => Ok(Self::VerifyIfGiven),
            "require_and_verify" => Ok(Self::RequireAndVerify),
            other => Err(Error::TlsConfig {
                path: "tls_connection_policies[0].client_authentication.mode".to_string(),
                message: format!(
                    "unsupported client authentication mode `{other}`; expected `request`, \
                     `require`, `verify_if_given` or `require_and_verify`"
                ),
            }),
        }
    }

    /// Whether this mode verifies the certificate chain (Caddy's `VerifyClientCertIfGiven` and
    /// `RequireAndVerifyClientCert`).
    pub fn verifies(self) -> bool {
        matches!(self, Self::VerifyIfGiven | Self::RequireAndVerify)
    }

    /// Whether a client certificate is mandatory for this mode.
    pub fn requires_certificate(self) -> bool {
        matches!(self, Self::Require | Self::RequireAndVerify)
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

/// TLS key-exchange group / curve selected by `tls_connection_policies[].curves`.
///
/// Caddy v2.11.9 accepts `x25519mlkem768`, `x25519`, `secp256r1`, `secp384r1` and `secp521r1`.
/// rustls' aws-lc-rs provider implements the first four as key-exchange groups; it has no P-521
/// key-exchange group, so `secp521r1` still fails loudly (P-521 *certificate* keys are separate
/// and supported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCurve {
    /// X25519MLKEM768 hybrid (Go `x25519mlkem768`).
    X25519MlKem768,
    /// X25519 (Go `x25519`).
    X25519,
    /// NIST P-256 (Go `secp256r1`).
    P256,
    /// NIST P-384 (Go `secp384r1`).
    P384,
    /// NIST P-521 (Go `secp521r1`), accepted by Caddy but without a rustls key-exchange group.
    Secp521r1,
}

/// Caddy v2.11.9's default curves (`external/caddy/modules/caddytls/values.go`):
/// `X25519MLKEM768, X25519, P-256`.
const DEFAULT_CURVES: &[TlsCurve] = &[TlsCurve::X25519MlKem768, TlsCurve::X25519, TlsCurve::P256];

impl TlsCurve {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "x25519mlkem768" => Ok(Self::X25519MlKem768),
            "x25519" => Ok(Self::X25519),
            "secp256r1" => Ok(Self::P256),
            "secp384r1" => Ok(Self::P384),
            "secp521r1" => Ok(Self::Secp521r1),
            other => Err(Error::TlsConfig {
                path: "tls_connection_policies[0].curves".to_string(),
                message: format!(
                    "unsupported TLS curve `{other}`; expected x25519mlkem768, x25519, secp256r1, secp384r1 or secp521r1"
                ),
            }),
        }
    }

    /// Go/Caddy name (for located errors and documentation).
    fn name(self) -> &'static str {
        match self {
            Self::X25519MlKem768 => "x25519mlkem768",
            Self::X25519 => "x25519",
            Self::P256 => "secp256r1",
            Self::P384 => "secp384r1",
            Self::Secp521r1 => "secp521r1",
        }
    }

    /// The provider's key-exchange group, when it implements one for this curve.
    fn kx_group(self) -> Option<&'static dyn SupportedKxGroup> {
        match self {
            Self::X25519MlKem768 => Some(rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768),
            Self::X25519 => Some(rustls::crypto::aws_lc_rs::kx_group::X25519),
            Self::P256 => Some(rustls::crypto::aws_lc_rs::kx_group::SECP256R1),
            Self::P384 => Some(rustls::crypto::aws_lc_rs::kx_group::SECP384R1),
            Self::Secp521r1 => None,
        }
    }
}

/// TLS 1.2 cipher suite selected by `tls_connection_policies[].cipher_suites`.
///
/// These are the six ECDHE AEAD suites rustls' aws-lc-rs provider implements. TLS 1.3 cipher
/// suites
/// are not configurable in rustls (or Go), so listing them fails loudly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12CipherSuite {
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
    EcdheEcdsaAes128GcmSha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
    EcdheEcdsaAes256GcmSha384,
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
    EcdheEcdsaChacha20Poly1305,
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    EcdheRsaAes128GcmSha256,
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
    EcdheRsaAes256GcmSha384,
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
    EcdheRsaChacha20Poly1305,
}

impl Tls12CipherSuite {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => Ok(Self::EcdheEcdsaAes128GcmSha256),
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => Ok(Self::EcdheEcdsaAes256GcmSha384),
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => Ok(Self::EcdheEcdsaChacha20Poly1305),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => Ok(Self::EcdheRsaAes128GcmSha256),
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => Ok(Self::EcdheRsaAes256GcmSha384),
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => Ok(Self::EcdheRsaChacha20Poly1305),
            name if name.starts_with("TLS_AES_")
                || name.starts_with("TLS_CHACHA20_")
                || name.starts_with("TLS13_") =>
            {
                Err(Error::Unsupported {
                    path: "tls_connection_policies[0].cipher_suites".to_string(),
                    feature: format!(
                        "TLS 1.3 cipher suite `{name}` (TLS 1.3 cipher suites are fixed by rustls and Go; only TLS 1.2 suites are configurable)"
                    ),
                    tracking_id: "TLS-POLICY",
                })
            }
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA" | "TLS_RSA_WITH_AES_128_CBC_SHA"
            | "TLS_RSA_WITH_AES_256_CBC_SHA" | "TLS_RSA_WITH_AES_128_GCM_SHA256"
            | "TLS_RSA_WITH_AES_256_GCM_SHA384" | "TLS_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                Err(Error::Unsupported {
                    path: "tls_connection_policies[0].cipher_suites".to_string(),
                    feature: format!(
                        "RSA key-exchange cipher suite `{value}` (rustls only implements ECDHE suites)"
                    ),
                    tracking_id: "TLS-POLICY",
                })
            }
            other => Err(Error::TlsConfig {
                path: "tls_connection_policies[0].cipher_suites".to_string(),
                message: format!(
                    "unsupported cipher suite `{other}`; expected a TLS 1.2 ECDHE AES-GCM/ChaCha20 suite"
                ),
            }),
        }
    }

    fn supported_suite(self) -> SupportedCipherSuite {
        // The aws-lc-rs provider exposes its suites as `DEFAULT_CIPHER_SUITES` rather than the
        // per-suite `cipher_suite` module the rustls ring provider used. Look each selectable
        // suite up by its wire identifier so the restricted-policy code stays provider-agnostic.
        let suite = match self {
            Self::EcdheEcdsaAes128GcmSha256 => {
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            }
            Self::EcdheEcdsaAes256GcmSha384 => {
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            }
            Self::EcdheEcdsaChacha20Poly1305 => {
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            Self::EcdheRsaAes128GcmSha256 => {
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            }
            Self::EcdheRsaAes256GcmSha384 => {
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            }
            Self::EcdheRsaChacha20Poly1305 => {
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
        };
        *rustls::crypto::aws_lc_rs::DEFAULT_CIPHER_SUITES
            .iter()
            .find(|candidate| candidate.suite() == suite)
            .expect("the aws-lc-rs provider implements every selectable TLS 1.2 cipher suite")
    }
}

/// Options for the rustls server configuration derived from a connection policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerOptions {
    /// ALPN protocols offered, in preference order. Defaults to [`DEFAULT_ALPN`].
    pub alpn: Vec<Vec<u8>>,
    /// Enabled TLS protocol versions.
    pub versions: TlsVersions,
    /// Key-exchange group preference (`tls_connection_policies[0].curves`); empty means Caddy's
    /// defaults (`x25519mlkem768`, `x25519`, `secp256r1`).
    pub curves: Vec<TlsCurve>,
    /// TLS 1.2 cipher-suite preference (`cipher_suites`/`ciphers`); empty means the provider
    /// defaults. TLS 1.3 suites are fixed by rustls and cannot be configured here.
    pub cipher_suites: Vec<Tls12CipherSuite>,
    /// Client certificate authentication mode.
    pub client_auth: ClientAuthMode,
    /// Whether the policy contained a `client_authentication` object at all (Caddy disables
    /// session tickets when `ClientAuthentication != nil`, even if it is empty/inactive).
    pub client_auth_configured: bool,
    /// Trust anchors used to verify client certificates (`client_authentication.ca` /
    /// deprecated PEM fields). Parsed eagerly so invalid pools fail the configuration.
    pub client_auth_roots: Vec<CertificateDer<'static>>,
    /// Client leaf certificates accepted by exact DER equality (`trusted_leaf_certs` /
    /// `trusted_leaf_cert_file`). When non-empty the presented leaf must be in this list in
    /// addition to any chain verification.
    pub client_auth_leaf_certs: Vec<CertificateDer<'static>>,
    /// PEM CA bundle used to verify client certificates (embedder convenience, legacy field).
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
            curves: Vec::new(),
            cipher_suites: Vec::new(),
            client_auth: ClientAuthMode::None,
            client_auth_configured: false,
            client_auth_roots: Vec::new(),
            client_auth_leaf_certs: Vec::new(),
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
        Self::from_connection_policies_with_ca_pool(
            policies,
            &crate::client_auth::CaPoolContext::new(),
        )
    }

    /// Like [`Self::from_connection_policies`], with the runtime context needed to load
    /// client-auth CA pools from `apps.pki` authorities and the configured storage root.
    pub fn from_connection_policies_with_ca_pool(
        policies: Option<&[Value]>,
        ca_pool: &crate::client_auth::CaPoolContext,
    ) -> Result<Self> {
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
        if let Some(curves) = policy.get("curves") {
            let curves = curves.as_array().ok_or_else(|| Error::TlsConfig {
                path: "tls_connection_policies[0].curves".to_string(),
                message: "must be an array of curve names".to_string(),
            })?;
            let mut parsed: Vec<TlsCurve> = Vec::with_capacity(curves.len());
            for (index, curve) in curves.iter().enumerate() {
                let path = format!("tls_connection_policies[0].curves[{index}]");
                let curve = curve.as_str().ok_or_else(|| Error::TlsConfig {
                    path: path.clone(),
                    message: "curve name must be a string".to_string(),
                })?;
                let curve = TlsCurve::parse(curve).map_err(|error| match error {
                    Error::Unsupported {
                        feature,
                        tracking_id,
                        ..
                    } => Error::Unsupported {
                        path: path.clone(),
                        feature,
                        tracking_id,
                    },
                    other => other,
                })?;
                if !parsed.contains(&curve) {
                    parsed.push(curve);
                }
            }
            options.curves = parsed;
        }
        if let Some(cipher_suites) = policy
            .get("cipher_suites")
            .or_else(|| policy.get("ciphers"))
        {
            let cipher_suites = cipher_suites.as_array().ok_or_else(|| Error::TlsConfig {
                path: "tls_connection_policies[0].cipher_suites".to_string(),
                message: "must be an array of cipher suite names".to_string(),
            })?;
            let mut parsed: Vec<Tls12CipherSuite> = Vec::with_capacity(cipher_suites.len());
            for (index, suite) in cipher_suites.iter().enumerate() {
                let path = format!("tls_connection_policies[0].cipher_suites[{index}]");
                let suite = suite.as_str().ok_or_else(|| Error::TlsConfig {
                    path: path.clone(),
                    message: "cipher suite name must be a string".to_string(),
                })?;
                let suite = Tls12CipherSuite::parse(suite).map_err(|error| match error {
                    Error::Unsupported {
                        feature,
                        tracking_id,
                        ..
                    } => Error::Unsupported {
                        path: path.clone(),
                        feature,
                        tracking_id,
                    },
                    other => other,
                })?;
                if !parsed.contains(&suite) {
                    parsed.push(suite);
                }
            }
            options.cipher_suites = parsed;
        }
        if let Some(client_authentication) = policy.get("client_authentication") {
            let parsed = parse_client_authentication(client_authentication, ca_pool)?;
            options.client_auth_configured = true;
            options.client_auth = parsed.mode;
            options.client_auth_roots = parsed.roots;
            options.client_auth_leaf_certs = parsed.leaf_certs;
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
            "alpn"
            | "protocols"
            | "curves"
            | "cipher_suites"
            | "ciphers"
            | "client_authentication" => {
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
    /// DER-encoded OCSP response to staple with this certificate (T-TLS-051).
    ocsp_staple: Option<Vec<u8>>,
    /// Configured source of this certificate, used to locate key errors when several
    /// certificates are configured (`apps.tls.certificates.load_files[i]`, a storage key, ...).
    source: Option<String>,
}

impl Clone for TlsCertificate {
    fn clone(&self) -> Self {
        Self {
            names: self.names.clone(),
            tags: self.tags.clone(),
            chain: self.chain.clone(),
            private_key: self.private_key.clone_key(),
            ocsp_staple: self.ocsp_staple.clone(),
            source: self.source.clone(),
        }
    }
}

impl TlsCertificate {
    /// Load a certificate chain and private key from PEM text.
    ///
    /// The certificate names are taken from the leaf's subjectAltName extension plus the subject
    /// commonName. Caddy's certmagic (`fillCertFromLeaf`) keeps both: a certificate whose only
    /// identity is the deprecated commonName still loads, and when SANs exist the commonName is
    /// retained as an additional name (SAN entries are listed first here).
    /// Supported key encodings are PKCS#8 (`PRIVATE KEY`), SEC1
    /// (`EC PRIVATE KEY`) and PKCS#1 (`RSA PRIVATE KEY`); the key type must be supported by
    /// rustls' aws-lc-rs provider.
    pub fn from_pem(certificate_pem: &str, private_key_pem: &str) -> Result<Self> {
        Self::from_pem_with_source(certificate_pem, private_key_pem, None)
    }

    /// Load a certificate chain and private key, recording the configured source for located
    /// key errors.
    ///
    /// Names are parsed before the private key so a key error can name the certificate that
    /// failed (DNS names plus source) even when several certificates are configured.
    pub(crate) fn from_pem_with_source(
        certificate_pem: &str,
        private_key_pem: &str,
        source: Option<String>,
    ) -> Result<Self> {
        let chain = certificate_chain_from_pem(certificate_pem)?;
        let names = certificate_names(chain[0].as_ref())?;
        let private_key = private_key_from_pem(private_key_pem)
            .map_err(|error| attach_certificate_identity(error, source.as_deref(), &names))?;
        Ok(Self {
            names,
            tags: Vec::new(),
            chain,
            private_key,
            ocsp_staple: None,
            source,
        })
    }

    /// Build from DER components, using explicitly supplied names.
    pub fn from_der(
        chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        names: Vec<String>,
    ) -> Result<Self> {
        Self::from_der_with_source(chain_der, private_key_der, names, None)
    }

    /// Build from DER components, naming the origin and classifying the key.
    pub fn from_der_with_source(
        chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        names: Vec<String>,
        source: Option<String>,
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
        // Label-less DER (the certificate cache, renewal and `from_cache_certificate`) can be any
        // of the three encodings; the structure decides the rustls variant, not an assumption.
        let private_key = match key_type::sniff_der_form(&private_key_der) {
            key_type::DerForm::Pkcs8 => {
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der))
            }
            key_type::DerForm::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(private_key_der)),
            key_type::DerForm::Pkcs1 => {
                PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(private_key_der))
            }
            key_type::DerForm::Unknown => {
                return Err(Error::TlsConfig {
                    path: "certificates".to_string(),
                    message: format!(
                        "private key is {}; expected PKCS#8, SEC1 or PKCS#1. Encrypted keys must be \
                         decrypted (`openssl pkey -in <key> -out <key.plain>`), otherwise re-export \
                         as PKCS#8 (`openssl pkcs8 -topk8 -nocrypt -in <key> -out <key.pk8>`)",
                        key_type::der_form_label(key_type::DerForm::Unknown)
                    ),
                })
            }
        };
        if let Some(message) = classify_private_key_der(&private_key) {
            return Err(attach_certificate_identity(
                Error::TlsConfig {
                    path: "certificates".to_string(),
                    message,
                },
                source.as_deref(),
                &names,
            ));
        }
        Ok(Self {
            names,
            tags: Vec::new(),
            chain: chain_der.into_iter().map(CertificateDer::from).collect(),
            private_key,
            ocsp_staple: None,
            source,
        })
    }

    /// Build from a stored certificate (PEM chain + PEM key, names from metadata).
    pub fn from_stored(stored: &StoredCertificate) -> Result<Self> {
        Self::from_stored_with_source(stored, None)
    }

    /// Build from a stored certificate, recording the storage key for located key errors.
    pub(crate) fn from_stored_with_source(
        stored: &StoredCertificate,
        source: Option<String>,
    ) -> Result<Self> {
        let chain_der: Vec<Vec<u8>> = stored
            .certificate_pem
            .iter()
            .map(|pem| certificate_chain_from_pem(pem).map(|chain| chain[0].as_ref().to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let names = if stored.domains.is_empty() {
            certificate_names(chain_der[0].as_slice())?
        } else {
            stored.domains.clone()
        };
        let private_key = private_key_from_pem(&stored.private_key_pem)
            .map_err(|error| attach_certificate_identity(error, source.as_deref(), &names))?;
        Ok(Self {
            names,
            tags: Vec::new(),
            chain: chain_der.into_iter().map(CertificateDer::from).collect(),
            private_key,
            ocsp_staple: None,
            source,
        })
    }

    /// Build from a [`Certificate`] in the in-memory cache.
    pub fn from_cache_certificate(certificate: &Certificate) -> Result<Self> {
        Self::from_cache_certificate_with_source(certificate, None)
    }

    /// Build from a cached certificate, naming where the loader got it from.
    pub fn from_cache_certificate_with_source(
        certificate: &Certificate,
        source: Option<String>,
    ) -> Result<Self> {
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
        Self::from_der_with_source(
            certificate.cert_chain_der.clone(),
            certificate.private_key_der.clone(),
            names,
            source,
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

    /// Attach the configured source (a file path, `load_pem` entry or storage key) so a later
    /// key error names this certificate instead of only `certificates`.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Attach a DER-encoded OCSP response to staple with this certificate (T-TLS-051).
    ///
    /// The server hook obtains the response through the [`crate::ocsp::OcspStapler`] and rebuilds
    /// the resolver-inserted certificate with the returned staple. `None` clears it.
    pub fn with_ocsp_staple(mut self, staple: Option<Vec<u8>>) -> Self {
        self.ocsp_staple = staple;
        self
    }

    /// The attached OCSP staple, if any.
    pub fn ocsp_staple(&self) -> Option<&[u8]> {
        self.ocsp_staple.as_deref()
    }

    /// The DER certificate chain, leaf first.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// The DER private key.
    pub fn private_key(&self) -> &PrivateKeyDer<'static> {
        &self.private_key
    }

    /// Convert to the rustls signing form, validating the key type against the aws-lc-rs provider.
    ///
    /// A failure names the configured source and the first DNS names of this certificate, so a
    /// configuration with several certificates identifies the offending entry.
    pub fn certified_key(&self) -> Result<CertifiedKey> {
        let signing_key =
            match rustls::crypto::aws_lc_rs::sign::any_supported_type(&self.private_key) {
                Ok(key) => key,
                Err(provider_error) => {
                    let reason = classify_private_key_der(&self.private_key).unwrap_or_else(|| {
                        format!(
                            "private key type is not supported by the rustls aws-lc-rs provider: \
                         {provider_error}"
                        )
                    });
                    return Err(Error::TlsConfig {
                        path: "certificates".to_string(),
                        message: format!(
                            "{}: {reason}",
                            certificate_identity(self.source.as_deref(), &self.names)
                        ),
                    });
                }
            };
        Ok(CertifiedKey {
            cert: self.chain.clone(),
            key: signing_key,
            ocsp: self.ocsp_staple.clone(),
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
    /// Source certificates (with keys) so the server can rebuild entries with OCSP staples.
    sources: Vec<TlsCertificate>,
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
        // Keep the source for OCSP re-stapling; replace entries covering the same leaf rather than
        // growing on each refresh.
        let leaf = certificate.chain()[0].as_ref().to_vec();
        self.sources.retain(|source| {
            source
                .chain()
                .first()
                .map(|der| der.as_ref() != leaf)
                .unwrap_or(false)
        });
        self.sources.push(certificate.clone());
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
                let certificate = TlsCertificate::from_stored_with_source(
                    &stored,
                    Some(format!("storage key {key}")),
                )?;
                resolver.insert(certificate)?;
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

    /// Snapshot of every served source certificate (used by the OCSP refresh scheduler).
    pub fn certificates(&self) -> Vec<TlsCertificate> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sources
            .clone()
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

/// Install the aws-lc-rs crypto provider as the process-wide rustls default.
///
/// caddy-rs builds every rustls client/server configuration with an explicit provider, so this
/// is mainly for dependencies that call [`CryptoProvider::get_default`]. Installing is
/// idempotent: an already-installed provider (another component or a test) is left untouched.
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Build the rustls crypto provider for a listener, applying the configured key-exchange
/// groups and TLS 1.2 cipher suites on top of the aws-lc-rs defaults.
///
/// TLS 1.3 cipher suites are fixed in rustls (and Go's `crypto/tls`), so only TLS 1.2 suites can
/// be restricted; the provider always retains the fixed TLS 1.3 suites.
fn crypto_provider(options: &TlsServerOptions) -> Result<Arc<CryptoProvider>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // Caddy defaults to [x25519mlkem768, x25519, secp256r1]; rustls' aws-lc-rs default differs
    // (no post-quantum preference unless the `prefer-post-quantum` feature is on), so always set
    // the list explicitly. A configured curve the compiled provider lacks fails closed.
    let curves: &[TlsCurve] = if options.curves.is_empty() {
        DEFAULT_CURVES
    } else {
        &options.curves
    };
    let mut groups: Vec<&'static dyn SupportedKxGroup> = Vec::with_capacity(curves.len());
    for &curve in curves {
        let Some(group) = curve.kx_group() else {
            return Err(Error::Unsupported {
                path: "tls_connection_policies[0].curves".to_string(),
                feature: format!(
                    "TLS curve `{}` accepted by Caddy but not implemented by rustls' aws-lc-rs \
                     provider (no P-521 key-exchange group; P-521 certificate keys are supported \
                     separately)",
                    curve.name()
                ),
                tracking_id: "TLS-POLICY",
            });
        };
        groups.push(group);
    }
    provider.kx_groups = groups;
    if !options.cipher_suites.is_empty() {
        let mut suites: Vec<SupportedCipherSuite> = options
            .cipher_suites
            .iter()
            .map(|suite| suite.supported_suite())
            .collect();
        // TLS 1.3 suites cannot be configured; keep every provider default.
        suites.extend(
            provider
                .cipher_suites
                .iter()
                .filter(|suite| suite.version() == &rustls::version::TLS13)
                .copied(),
        );
        provider.cipher_suites = suites;
    }
    Ok(Arc::new(provider))
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
    let provider = crypto_provider(options)?;
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(options.versions.rustls_versions())
        .map_err(|error| Error::TlsConfig {
            path: "tls_connection_policies[0].protocols".to_string(),
            message: format!("rustls rejected the configured protocol versions: {error}"),
        })?;
    let builder = match options.client_auth {
        ClientAuthMode::None => builder.with_no_client_auth(),
        mode => {
            let mut roots = options.client_auth_roots.clone();
            if let Some(pem) = options.client_auth_roots_pem.as_deref() {
                roots.extend(certificate_chain_from_pem(pem).map_err(|error| {
                    Error::TlsConfig {
                        path: CLIENT_AUTH_PATH.to_string(),
                        message: format!("cannot parse client-auth root PEM bundle: {error}"),
                    }
                })?);
            }
            let trusted_leaves: Vec<Vec<u8>> = options
                .client_auth_leaf_certs
                .iter()
                .map(|certificate| certificate.as_ref().to_vec())
                .collect();
            let verifier: Arc<dyn ClientCertVerifier> = if mode.verifies() {
                if !roots.is_empty() {
                    let store = root_store_from_client_auth_roots(roots)?;
                    let verifier_builder = WebPkiClientVerifier::builder_with_provider(
                        Arc::new(store),
                        Arc::clone(&provider),
                    );
                    let webpki = if mode.requires_certificate() {
                        verifier_builder.build()
                    } else {
                        verifier_builder.allow_unauthenticated().build()
                    }
                    .map_err(|error| Error::TlsConfig {
                        path: CLIENT_AUTH_PATH.to_string(),
                        message: format!("cannot build client certificate verifier: {error}"),
                    })?;
                    if trusted_leaves.is_empty() {
                        webpki
                    } else {
                        Arc::new(LeafAllowlistClientCertVerifier {
                            inner: webpki,
                            trusted_leaves,
                        })
                    }
                } else if !trusted_leaves.is_empty() {
                    // Leaf-allowlist-only configurations: exact-leaf authentication without a CA
                    // bundle (Caddy falls back to system roots for chain verification; this build
                    // requires the exact leaf, documented divergence).
                    Arc::new(AcceptAnyClientCertVerifier {
                        provider: Arc::clone(&provider),
                        mandatory: mode.requires_certificate(),
                        trusted_leaves,
                    })
                } else {
                    return Err(Error::TlsConfig {
                        path: CLIENT_AUTH_PATH.to_string(),
                        message: format!(
                            "client authentication mode `{mode:?}` requires a trusted CA bundle (`client_authentication.ca` or `trusted_ca_pem_files`) or `trusted_leaf_cert_file`"
                        ),
                    });
                }
            } else {
                // Caddy's `request`/`require` modes ask for a certificate but do not verify its
                // chain; an optional exact-leaf allowlist is still enforced.
                Arc::new(AcceptAnyClientCertVerifier {
                    provider: Arc::clone(&provider),
                    mandatory: mode.requires_certificate(),
                    trusted_leaves,
                })
            };
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder.with_cert_resolver(resolver);
    config.alpn_protocols = options.alpn.clone();
    // Caddy disables TLS session tickets whenever a client-authentication policy is configured
    // (`external/caddy/modules/caddytls/connpolicy.go:403-424`): a session authenticated in one
    // configuration must not be resumed under another, and client auth on a resumed handshake is
    // not re-run. rustls: no stateful session storage, no TLS 1.3 tickets (the default ticketer
    // never produces tickets, and send_tls13_tickets=0 suppresses issuance entirely).
    if options.client_auth_configured || options.client_auth != ClientAuthMode::None {
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
    }
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
        let source = format!(
            "{path} (certificate file {}, key file {})",
            pair.certificate, pair.key
        );
        let certificate =
            TlsCertificate::from_pem_with_source(&certificate_pem, &private_key_pem, Some(source))
                .map(|certificate| certificate.with_tags(pair.tags.clone()))
                .map_err(|error| Error::TlsConfig {
                    path: path.clone(),
                    message: located_message(error),
                })?;
        certificates.push(certificate);
    }
    Ok(certificates)
}

fn load_pem_pair(pair: &CertKeyPemPair, path: &str) -> Result<TlsCertificate> {
    TlsCertificate::from_pem_with_source(&pair.certificate, &pair.key, Some(path.to_string()))
        .map(|certificate| certificate.with_tags(pair.tags.clone()))
        .map_err(|error| match error {
            Error::TlsConfig { message, .. } => Error::TlsConfig {
                path: path.to_string(),
                message,
            },
            other => other,
        })
}

/// Extract the message of a located error, so wrapping at a more precise path does not nest
/// `TLS configuration at ...` prefixes.
fn located_message(error: Error) -> String {
    match error {
        Error::TlsConfig { message, .. } => message,
        other => other.to_string(),
    }
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

/// Labels whose rejection reason is the label itself, not the DER structure.
fn form_is_label_specific(label: &str) -> bool {
    matches!(
        label,
        "ENCRYPTED PRIVATE KEY" | "DSA PRIVATE KEY" | "OPENSSH PRIVATE KEY"
    )
}

fn private_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let blocks = pem_blocks(pem)?;
    let key_blocks: Vec<usize> = blocks
        .iter()
        .enumerate()
        .filter(|(_, (label, _))| label.ends_with("PRIVATE KEY"))
        .map(|(index, _)| index)
        .collect();
    let Some(&first) = key_blocks.first() else {
        return Err(Error::TlsConfig {
            path: "certificates".to_string(),
            message: "no private key block found in PEM data".to_string(),
        });
    };
    if key_blocks.len() > 1 {
        let (first_label, _) = &blocks[first];
        let (second_label, _) = &blocks[key_blocks[1]];
        eprintln!(
            "caddy-rs: warning: private key PEM data contains multiple private key blocks; \
             using the first (`{first_label}` at block {first}) and ignoring `{second_label}` at \
             block {}",
            key_blocks[1]
        );
    }
    let (label, der) = &blocks[first];
    // The DER structure decides the variant. The label is only a hint: some exporters write a
    // `PRIVATE KEY` label over a SEC1 or PKCS#1 body, and rejecting those would be a parsing gap,
    // not a security property.
    // Labels that are unsupported for reasons of their own keep their specific message
    // (encrypted PEM, DSA, OpenSSH); the structure sniff only decides between the three formats
    // rustls can read.
    if let Some(KeySupport::Unsupported(message)) = classify(label, der) {
        if form_is_label_specific(label) {
            return Err(Error::TlsConfig {
                path: "certificates".to_string(),
                message,
            });
        }
    }
    let form = key_type::sniff_der_form(der);
    if form == key_type::DerForm::Unknown {
        return Err(Error::TlsConfig {
            path: "certificates".to_string(),
            message: format!(
                "`{label}` block is not a recognised PKCS#8, SEC1 or PKCS#1 private key (the \
                 ASN.1 is truncated, has trailing data, or is not a private key). If the key is \
                 encrypted, decrypt it (`openssl pkey -in <key> -out <key.plain>`); otherwise \
                 re-export it as PKCS#8 (`openssl pkcs8 -topk8 -nocrypt -in <key> -out <key.pk8>`)"
            ),
        });
    }
    let canonical = match form {
        key_type::DerForm::Pkcs8 => "PRIVATE KEY",
        key_type::DerForm::Sec1 => "EC PRIVATE KEY",
        key_type::DerForm::Pkcs1 => "RSA PRIVATE KEY",
        key_type::DerForm::Unknown => unreachable!(),
    };
    if canonical != label {
        eprintln!(
            "caddy-rs: warning: private key block labelled `{label}` is {}; using its structure. \
             Re-export it as PKCS#8 to silence this",
            key_type::der_form_label(form)
        );
    }
    if let Some(KeySupport::Unsupported(message)) = classify(canonical, der) {
        return Err(Error::TlsConfig {
            path: "certificates".to_string(),
            message,
        });
    }
    Ok(match form {
        key_type::DerForm::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.clone())),
        key_type::DerForm::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der.clone())),
        key_type::DerForm::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der.clone())),
        key_type::DerForm::Unknown => unreachable!(),
    })
}

/// Label and DER payload of a parsed private key (the DER borrows from `key`).
fn private_key_label_and_der<'a>(key: &'a PrivateKeyDer<'_>) -> (&'static str, &'a [u8]) {
    match key {
        PrivateKeyDer::Pkcs8(key) => ("PRIVATE KEY", key.secret_pkcs8_der()),
        PrivateKeyDer::Sec1(key) => ("EC PRIVATE KEY", key.secret_sec1_der()),
        PrivateKeyDer::Pkcs1(key) => ("RSA PRIVATE KEY", key.secret_pkcs1_der()),
        // `PrivateKeyDer` is non-exhaustive; an unknown future variant stays unclassified and
        // falls back to the provider's own error.
        _ => ("", &[]),
    }
}

/// Classify a parsed private key, returning the unsupported-type reason when known.
fn classify_private_key_der(key: &PrivateKeyDer<'_>) -> Option<String> {
    let (label, der) = private_key_label_and_der(key);
    match classify(label, der) {
        Some(KeySupport::Unsupported(message)) => Some(message),
        _ => None,
    }
}

/// Human-readable certificate identity for located key errors.
fn certificate_identity(source: Option<&str>, names: &[String]) -> String {
    let mut identity = String::from("private key for certificate");
    if let Some(source) = source {
        identity.push_str(&format!(" `{source}`"));
    }
    if !names.is_empty() {
        let mut shown = names.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        if names.len() > 3 {
            shown.push_str(", ...");
        }
        identity.push_str(&format!(" (DNS names: {shown})"));
    }
    identity
}

/// Prefix a certificate-loading error with the certificate identity (source + DNS names).
///
/// Every caller hands in a bare diagnosis (the key classifier's or the PEM parser's), never a
/// message that already carries the `TLS configuration at ...` prefix, so this wraps exactly once.
fn attach_certificate_identity(error: Error, source: Option<&str>, names: &[String]) -> Error {
    match error {
        Error::TlsConfig { path, message } => Error::TlsConfig {
            path,
            message: format!("{}: {message}", certificate_identity(source, names)),
        },
        other => other,
    }
}

/// Located path for client-authentication configuration errors.
const CLIENT_AUTH_PATH: &str = "tls_connection_policies[0].client_authentication";

/// Parsed `client_authentication` configuration.
#[derive(Debug, Default)]
struct ParsedClientAuthentication {
    mode: ClientAuthMode,
    roots: Vec<CertificateDer<'static>>,
    leaf_certs: Vec<CertificateDer<'static>>,
}

/// Parse Caddy's `tls_connection_policies[].client_authentication`.
///
/// Supports the `ca` module (`tls.ca_pool.source.inline` / `tls.ca_pool.source.file`), the
/// deprecated direct trust fields (`trusted_ca_certs`, `trusted_ca_certs_pem_files`,
/// `trusted_leaf_certs`) and the task-facing aliases (`trusted_ca_pool`, `trusted_ca_pem_files`,
/// `trusted_leaf_cert_file`). Unsupported verifier modules and unknown fields fail loudly.
fn parse_client_authentication(
    value: &Value,
    ca_pool: &crate::client_auth::CaPoolContext,
) -> Result<ParsedClientAuthentication> {
    let object = value.as_object().ok_or_else(|| Error::TlsConfig {
        path: CLIENT_AUTH_PATH.to_string(),
        message: "must be an object".to_string(),
    })?;
    let mut parsed = ParsedClientAuthentication::default();
    let mut mode = None;
    let mut saw_ca_module = false;
    let mut saw_direct_roots = false;
    for (key, field) in object {
        let path = format!("{CLIENT_AUTH_PATH}.{key}");
        match key.as_str() {
            "mode" => {
                let mode_value = field.as_str().ok_or_else(|| Error::TlsConfig {
                    path: path.clone(),
                    message: "mode must be a string".to_string(),
                })?;
                mode = Some(ClientAuthMode::parse(mode_value)?);
            }
            "ca" => {
                saw_ca_module = true;
                parse_client_auth_ca_pool(field, &path, &mut parsed.roots, ca_pool)?;
            }
            "trusted_ca_pool" => {
                saw_direct_roots = true;
                parse_client_auth_ca_pool(field, &path, &mut parsed.roots, ca_pool)?;
            }
            "trusted_ca_certs" | "trusted_ca_cert" => {
                saw_direct_roots = true;
                parsed
                    .roots
                    .extend(parse_base64_der_cert_list(field, &path)?);
            }
            "trusted_ca_certs_pem_files" | "trusted_ca_pem_files" | "trusted_ca_cert_file" => {
                saw_direct_roots = true;
                parsed
                    .roots
                    .extend(parse_client_auth_pem_files(field, &path)?);
            }
            "trusted_leaf_certs" | "trusted_leaf_cert" => {
                parsed
                    .leaf_certs
                    .extend(parse_base64_der_cert_list(field, &path)?);
            }
            "trusted_leaf_cert_file" => {
                parsed
                    .leaf_certs
                    .extend(parse_client_auth_pem_files(field, &path)?);
            }
            "verifiers" => {
                parse_client_auth_verifiers(field, &path, &mut parsed.leaf_certs)?;
            }
            other => {
                return Err(Error::Unsupported {
                    path,
                    feature: format!("client authentication field `{other}`"),
                    tracking_id: "TLS-CLIENT-AUTH",
                })
            }
        }
    }
    if saw_ca_module && saw_direct_roots {
        return Err(Error::TlsConfig {
            path: CLIENT_AUTH_PATH.to_string(),
            message: "conflicting client authentication trust configuration: `ca` cannot be combined with trusted CA fields".to_string(),
        });
    }
    let actionable = mode.is_some() || !parsed.roots.is_empty() || !parsed.leaf_certs.is_empty();
    if !actionable {
        parsed.mode = ClientAuthMode::None;
        return Ok(parsed);
    }
    // Caddy's default: require_and_verify when a trust pool/leaf list is provided, otherwise
    // require. Explicit `mode` always wins.
    parsed.mode = mode.unwrap_or(if parsed.roots.is_empty() && parsed.leaf_certs.is_empty() {
        ClientAuthMode::Require
    } else {
        ClientAuthMode::RequireAndVerify
    });
    Ok(parsed)
}

/// Parse Caddy's `client_authentication.verifiers` modules.
///
/// Caddy v2.11.9 registers only `tls.client_auth.verifier.leaf`, which enforces an exact leaf
/// allowlist loaded by `tls.leaf_cert_loader.pem` / `.file` loaders. The allowlist is merged into
/// the same exact-DER leaf list this crate already enforces after chain verification. Other
/// verifier modules (for example custom CRL/OCSP verifiers) fail loudly.
fn parse_client_auth_verifiers(
    value: &Value,
    path: &str,
    leaf_certs: &mut Vec<CertificateDer<'static>>,
) -> Result<()> {
    let verifiers = value.as_array().ok_or_else(|| Error::TlsConfig {
        path: path.to_string(),
        message: "verifiers must be an array".to_string(),
    })?;
    for (index, verifier) in verifiers.iter().enumerate() {
        let verifier_path = format!("{path}[{index}]");
        let object = verifier.as_object().ok_or_else(|| Error::TlsConfig {
            path: verifier_path.clone(),
            message: "verifier must be an object".to_string(),
        })?;
        let name = object
            .get("verifier")
            .or_else(|| object.get("module"))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::TlsConfig {
                path: verifier_path.clone(),
                message: "verifier module is missing its `verifier` field".to_string(),
            })?;
        let name = name
            .strip_prefix("tls.client_auth.verifier.")
            .unwrap_or(name);
        if name != "leaf" {
            return Err(Error::Unsupported {
                path: verifier_path,
                feature: format!("client authentication verifier module `{name}`"),
                tracking_id: "T-TLS-072",
            });
        }
        let loaders = object
            .get("leaf_certs_loaders")
            .ok_or_else(|| Error::TlsConfig {
                path: verifier_path.clone(),
                message: "leaf verifier requires `leaf_certs_loaders`".to_string(),
            })?;
        let loaders = loaders.as_array().ok_or_else(|| Error::TlsConfig {
            path: format!("{verifier_path}.leaf_certs_loaders"),
            message: "leaf_certs_loaders must be an array".to_string(),
        })?;
        if loaders.is_empty() {
            return Err(Error::TlsConfig {
                path: format!("{verifier_path}.leaf_certs_loaders"),
                message: "leaf verifier requires at least one certificate loader".to_string(),
            });
        }
        for (loader_index, loader) in loaders.iter().enumerate() {
            let loader_path = format!("{verifier_path}.leaf_certs_loaders[{loader_index}]");
            let loader_object = loader.as_object().ok_or_else(|| Error::TlsConfig {
                path: loader_path.clone(),
                message: "leaf certificate loader must be an object".to_string(),
            })?;
            let loader_name = loader_object
                .get("loader")
                .or_else(|| loader_object.get("module"))
                .and_then(Value::as_str)
                .ok_or_else(|| Error::TlsConfig {
                    path: loader_path.clone(),
                    message: "leaf certificate loader is missing its `loader` field".to_string(),
                })?;
            let loader_name = loader_name
                .strip_prefix("tls.leaf_cert_loader.")
                .unwrap_or(loader_name);
            match loader_name {
                "pem" => {
                    let certificates = loader_object
                        .get("certificates")
                        .and_then(Value::as_array)
                        .ok_or_else(|| Error::TlsConfig {
                            path: format!("{loader_path}.certificates"),
                            message: "pem loader requires a `certificates` array".to_string(),
                        })?;
                    for (certificate_index, certificate) in certificates.iter().enumerate() {
                        let pem = certificate.as_str().ok_or_else(|| Error::TlsConfig {
                            path: format!("{loader_path}.certificates[{certificate_index}]"),
                            message: "pem loader entries must be PEM strings".to_string(),
                        })?;
                        leaf_certs.extend(certificate_chain_from_pem(pem)?);
                    }
                }
                "file" => {
                    let files = loader_object
                        .get("files")
                        .and_then(Value::as_array)
                        .ok_or_else(|| Error::TlsConfig {
                            path: format!("{loader_path}.files"),
                            message: "file loader requires a `files` array".to_string(),
                        })?;
                    for (file_index, file) in files.iter().enumerate() {
                        let file_path = file.as_str().ok_or_else(|| Error::TlsConfig {
                            path: format!("{loader_path}.files[{file_index}]"),
                            message: "file loader entries must be paths".to_string(),
                        })?;
                        let pem = std::fs::read_to_string(file_path).map_err(|error| {
                            Error::TlsConfig {
                                path: format!("{loader_path}.files[{file_index}]"),
                                message: format!(
                                    "cannot read client leaf certificate file `{file_path}`: {error}"
                                ),
                            }
                        })?;
                        leaf_certs.extend(certificate_chain_from_pem(&pem)?);
                    }
                }
                other => {
                    return Err(Error::Unsupported {
                        path: loader_path,
                        feature: format!("leaf certificate loader module `{other}`"),
                        tracking_id: "T-TLS-072",
                    })
                }
            }
        }
    }
    Ok(())
}

/// Parse one CA pool source (`ca` module or the `trusted_ca_pool` alias).
fn parse_client_auth_ca_pool(
    value: &Value,
    path: &str,
    roots: &mut Vec<CertificateDer<'static>>,
    ca_pool: &crate::client_auth::CaPoolContext,
) -> Result<()> {
    match value {
        // The task-facing alias also accepts a bare array of base64 DER certificates.
        Value::Array(_) => {
            roots.extend(parse_base64_der_cert_list(value, path)?);
            return Ok(());
        }
        Value::Object(object) => {
            let provider = object
                .get("provider")
                .or_else(|| object.get("module"))
                .and_then(Value::as_str);
            let provider = match provider {
                Some(provider) => provider,
                None => {
                    // No explicit provider: accept the inline fields directly.
                    if object.contains_key("trusted_ca_certs")
                        || object.contains_key("trusted_ca_pool")
                    {
                        "inline"
                    } else if object.contains_key("pem_files")
                        || object.contains_key("trusted_ca_pem_files")
                        || object.contains_key("trusted_ca_certs_pem_files")
                    {
                        "file"
                    } else {
                        return Err(Error::TlsConfig {
                            path: path.to_string(),
                            message: "CA pool source must name a `provider` (`inline` or `file`)"
                                .to_string(),
                        });
                    }
                }
            };
            let provider = provider
                .strip_prefix("tls.ca_pool.source.")
                .unwrap_or(provider);
            match provider {
                "inline" => {
                    for (key, value) in object {
                        match key.as_str() {
                            "provider" | "module" => {}
                            "trusted_ca_certs" | "trusted_ca_pool" => roots.extend(
                                parse_base64_der_cert_list(value, &format!("{path}.{key}"))?,
                            ),
                            "pem_files" | "trusted_ca_pem_files" | "trusted_ca_certs_pem_files" => {
                                roots.extend(parse_client_auth_pem_files(
                                    value,
                                    &format!("{path}.{key}"),
                                )?)
                            }
                            other => {
                                return Err(Error::Unsupported {
                                    path: format!("{path}.{other}"),
                                    feature: format!("inline client-auth CA pool field `{other}`"),
                                    tracking_id: "TLS-CLIENT-AUTH",
                                })
                            }
                        }
                    }
                }
                "file" => {
                    let mut saw_files = false;
                    for (key, value) in object {
                        match key.as_str() {
                            "provider" | "module" => {}
                            "pem_files" | "trusted_ca_pem_files" | "trusted_ca_certs_pem_files" => {
                                saw_files = true;
                                roots.extend(parse_client_auth_pem_files(
                                    value,
                                    &format!("{path}.{key}"),
                                )?);
                            }
                            other => {
                                return Err(Error::Unsupported {
                                    path: format!("{path}.{other}"),
                                    feature: format!("file client-auth CA pool field `{other}`"),
                                    tracking_id: "TLS-CLIENT-AUTH",
                                })
                            }
                        }
                    }
                    if !saw_files {
                        return Err(Error::TlsConfig {
                            path: path.to_string(),
                            message: "file client-auth CA pool requires `pem_files`".to_string(),
                        });
                    }
                }
                // Remaining Caddy providers (`system`, `pki_root`, `pki_intermediate`,
                // `storage`, `http`, `combined`) are loaded by the shared client-auth
                // CA-pool loader, which reports located errors for missing authorities,
                // storage roots or unsupported endpoints.
                _ => {
                    roots.extend(crate::client_auth::load_ca_pool_source(
                        value, path, ca_pool,
                    )?);
                }
            }
        }
        _ => {
            return Err(Error::TlsConfig {
                path: path.to_string(),
                message: "CA pool source must be an object or an array of base64 DER certificates"
                    .to_string(),
            })
        }
    }
    Ok(())
}

/// Parse a list (or single string) of base64 DER certificates.
fn parse_base64_der_cert_list(value: &Value, path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let values: Vec<&Value> = match value {
        Value::Array(values) => values.iter().collect(),
        Value::String(_) => vec![value],
        _ => {
            return Err(Error::TlsConfig {
                path: path.to_string(),
                message: "must be an array of base64 DER certificates".to_string(),
            })
        }
    };
    let mut certificates = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let encoded = value.as_str().ok_or_else(|| Error::TlsConfig {
            path: format!("{path}[{index}]"),
            message: "certificate must be a base64 DER string".to_string(),
        })?;
        let der = BASE64.decode(encoded).map_err(|error| Error::TlsConfig {
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

/// Parse a PEM file path (or array of paths) into DER certificates.
fn parse_client_auth_pem_files(value: &Value, path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let paths: Vec<&str> = match value {
        Value::Array(values) => {
            let mut paths = Vec::with_capacity(values.len());
            for (index, value) in values.iter().enumerate() {
                let value = value.as_str().ok_or_else(|| Error::TlsConfig {
                    path: format!("{path}[{index}]"),
                    message: "PEM file path must be a string".to_string(),
                })?;
                if value.trim().is_empty() {
                    return Err(Error::TlsConfig {
                        path: format!("{path}[{index}]"),
                        message: "PEM file path must not be empty".to_string(),
                    });
                }
                paths.push(value);
            }
            paths
        }
        Value::String(path) => vec![path.as_str()],
        _ => {
            return Err(Error::TlsConfig {
                path: path.to_string(),
                message: "must be a PEM file path or array of paths".to_string(),
            })
        }
    };
    if paths.is_empty() {
        return Err(Error::TlsConfig {
            path: path.to_string(),
            message: "at least one PEM file is required".to_string(),
        });
    }
    let mut certificates = Vec::new();
    for (index, file) in paths.iter().enumerate() {
        let pem = std::fs::read_to_string(file).map_err(|error| Error::TlsConfig {
            path: format!("{path}[{index}]"),
            message: format!("cannot read client-auth PEM file `{file}`: {error}"),
        })?;
        let parsed = certificate_chain_from_pem(&pem).map_err(|error| Error::TlsConfig {
            path: format!("{path}[{index}]"),
            message: format!("cannot parse client-auth PEM file `{file}`: {error}"),
        })?;
        certificates.extend(parsed);
    }
    Ok(certificates)
}

/// Client-certificate verifier that asks for a certificate but does not validate its chain
/// (Caddy's `request`/`require` modes) while still enforcing an optional exact-leaf allowlist.
#[derive(Debug)]
struct AcceptAnyClientCertVerifier {
    provider: Arc<CryptoProvider>,
    mandatory: bool,
    trusted_leaves: Vec<Vec<u8>>,
}

impl ClientCertVerifier for AcceptAnyClientCertVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        if !self.trusted_leaves.is_empty()
            && !self
                .trusted_leaves
                .iter()
                .any(|trusted| trusted.as_slice() == end_entity.as_ref())
        {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wrapper that adds exact-leaf allowlist enforcement after a chain verifier accepted the
/// certificate (Caddy's deprecated `trusted_leaf_certs` verifier).
#[derive(Debug)]
struct LeafAllowlistClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    trusted_leaves: Vec<Vec<u8>>,
}

impl ClientCertVerifier for LeafAllowlistClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        if !self
            .trusted_leaves
            .iter()
            .any(|trusted| trusted.as_slice() == end_entity.as_ref())
        {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a rustls client-auth root store from already-parsed DER certificates.
fn root_store_from_client_auth_roots(roots: Vec<CertificateDer<'static>>) -> Result<RootCertStore> {
    if roots.is_empty() {
        return Err(Error::TlsConfig {
            path: CLIENT_AUTH_PATH.to_string(),
            message: "client-auth trust root bundle is empty".to_string(),
        });
    }
    let mut store = RootCertStore::empty();
    for certificate in roots {
        store.add(certificate).map_err(|error| Error::TlsConfig {
            path: CLIENT_AUTH_PATH.to_string(),
            message: format!("invalid client-auth trust root: {error}"),
        })?;
    }
    Ok(store)
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

/// Extract the names a certificate covers: subjectAltName `dNSName` entries plus the subject
/// commonName (SAN entries first; a commonName already covered by a SAN is not duplicated).
///
/// Caddy's certmagic `fillCertFromLeaf` keeps the commonName even when SANs are present, and a
/// certificate whose only identity is the deprecated commonName still loads (Go's `crypto/x509`
/// parses it). A certificate with neither SAN DNS names nor a commonName remains a located error.
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
    if let Some(common_name) = common_name(subject)? {
        if !names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&common_name))
        {
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

/// Extract the subject commonName (OID 2.5.4.3) from the DER `Name` SEQUENCE.
///
/// The walk is `Name ::= SEQUENCE OF RDN` -> `RDN ::= SET OF AttributeTypeAndValue` ->
/// `AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }`, so a CN in any RDN
/// (including a later one) is found. Structural violations and a CN value that is not one of Go's
/// ASN.1 string types are located errors: silently skipping them would turn a malformed
/// certificate into a confusing "no names" rejection. Go's `pkix.Name.FillFromRDNSequence` keeps
/// the last commonName, so a subject with several CN attributes resolves the same way here.
fn common_name(subject: &Tlv<'_>) -> Result<Option<String>> {
    if subject.tag != 0x30 {
        return Err(x509_error("subject is not a SEQUENCE"));
    }
    let mut common_name = None;
    for rdn in read_children(subject.content)? {
        if rdn.tag != 0x31 {
            return Err(x509_error(
                "subject relative distinguished name is not a SET",
            ));
        }
        for attribute in read_children(rdn.content)? {
            if attribute.tag != 0x30 {
                return Err(x509_error("subject attribute is not a SEQUENCE"));
            }
            let parts = read_children(attribute.content)?;
            let Some(oid) = parts.first() else {
                return Err(x509_error("subject attribute has no type"));
            };
            if oid.tag != 0x06 {
                return Err(x509_error(
                    "subject attribute type is not an OBJECT IDENTIFIER",
                ));
            }
            if oid.content != [0x55, 0x04, 0x03] {
                continue;
            }
            let value = parts
                .get(1)
                .ok_or_else(|| x509_error("subject commonName has no value"))?;
            common_name = Some(common_name_string(value)?);
        }
    }
    // Caddy/Go ignores an empty commonName; an earlier non-empty CN does not survive a later
    // empty one because `FillFromRDNSequence` keeps the last attribute.
    Ok(common_name.filter(|name| !name.is_empty()))
}

/// Decode an ASN.1 string value the way Go's `crypto/x509` does for `Name` attributes.
///
/// Go accepts PrintableString (0x13), UTF8String (0x0C), IA5String (0x16), T61String (0x14,
/// treated as Latin-1), BMPString (0x1E, UCS-2/UTF-16BE) and NumericString (0x12); any other tag
/// is an unsupported string type and fails the certificate parse. Matching that set keeps a
/// commonName's encoding from changing whether a certificate loads.
fn common_name_string(value: &Tlv<'_>) -> Result<String> {
    match value.tag {
        0x0C => std::str::from_utf8(value.content)
            .map(str::to_string)
            .map_err(|_| x509_error("subject commonName is not valid UTF-8")),
        0x12 | 0x13 | 0x16 => std::str::from_utf8(value.content)
            .map(str::to_string)
            .map_err(|_| x509_error("subject commonName is not valid ASCII")),
        // T.61 is defunct; Go (like BoringSSL) treats it as ISO-8859-1.
        0x14 => Ok(value.content.iter().map(|byte| char::from(*byte)).collect()),
        0x1E => {
            if value.content.len() % 2 != 0 {
                return Err(x509_error("subject commonName BMPString has an odd length"));
            }
            let units: Vec<u16> = value
                .content
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16(&units)
                .map_err(|_| x509_error("subject commonName BMPString is not valid UTF-16"))
        }
        tag => Err(x509_error(format!(
            "subject commonName has unsupported value tag 0x{tag:02X}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    const EXAMPLE_CERT: &str = include_str!("../testdata/https/example.com.pem");
    const EXAMPLE_KEY: &str = include_str!("../testdata/https/example.com.key");
    const OTHER_CERT: &str = include_str!("../testdata/https/other.example.pem");
    const OTHER_KEY: &str = include_str!("../testdata/https/other.example.key");
    /// Subject CN only, no subjectAltName extension (the deprecated form Caddy still accepts).
    const CN_ONLY_CERT: &str = include_str!("../testdata/https/cn-only.pem");
    const CN_ONLY_KEY: &str = include_str!("../testdata/https/cn-only.key");
    /// Subject CN and a different subjectAltName dNSName.
    const CN_AND_SAN_CERT: &str = include_str!("../testdata/https/cn-and-san.pem");
    const CN_AND_SAN_KEY: &str = include_str!("../testdata/https/cn-and-san.key");

    fn example() -> TlsCertificate {
        TlsCertificate::from_pem(EXAMPLE_CERT, EXAMPLE_KEY).expect("example fixture loads")
    }

    fn other() -> TlsCertificate {
        TlsCertificate::from_pem(OTHER_CERT, OTHER_KEY).expect("other fixture loads")
    }

    fn certificate_der(certificate: &TlsCertificate) -> Vec<u8> {
        certificate.chain()[0].as_ref().to_vec()
    }

    /// Every certificate key algorithm the aws-lc-rs provider accepts must still load and
    /// produce a rustls signing key. P-521 is the regression this task fixes; the rest guard the
    /// matrix Caddy accepts.
    #[test]
    fn supported_private_key_matrix_builds_signing_keys() {
        let keys = [
            (
                "RSA-2048 PKCS#1",
                include_str!("../testdata/key-types/rsa2048-pkcs1.key"),
            ),
            (
                "RSA-2048 PKCS#8",
                include_str!("../testdata/key-types/rsa2048-pkcs8.key"),
            ),
            (
                "RSA-4096",
                include_str!("../testdata/key-types/rsa4096.key"),
            ),
            (
                "ECDSA P-256 SEC1",
                include_str!("../testdata/key-types/p256-sec1.key"),
            ),
            (
                "ECDSA P-256 PKCS#8",
                include_str!("../testdata/key-types/p256-pkcs8.key"),
            ),
            (
                "ECDSA P-384 PKCS#8",
                include_str!("../testdata/key-types/p384.key"),
            ),
            (
                "ECDSA P-521 SEC1",
                include_str!("../testdata/key-types/p521-sec1.key"),
            ),
            (
                "ECDSA P-521 PKCS#8",
                include_str!("../testdata/key-types/p521-pkcs8.key"),
            ),
            ("Ed25519", include_str!("../testdata/key-types/ed25519.key")),
        ];
        for (name, pem) in keys {
            let key = private_key_from_pem(pem).unwrap_or_else(|error| panic!("{name}: {error}"));
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }

    /// A key rejected on the certificate-cache path names where it came from, and the located
    /// prefix and the certificate identity each appear once (an operator saw both doubled).
    #[test]
    fn cache_path_errors_name_the_source_once() {
        let certificate = example();
        let chain: Vec<Vec<u8>> = certificate.chain().iter().map(|der| der.to_vec()).collect();
        let names = vec!["example.com".to_string()];
        let secp256k1 =
            crate::storage::private_key_der(include_str!("../testdata/key-types/secp256k1.key"))
                .expect("fixture DER");
        let error = TlsCertificate::from_der_with_source(
            chain,
            secp256k1,
            names,
            Some("storage key certificates/local/example.com".to_string()),
        )
        .expect_err("secp256k1 must be rejected on the cache path");
        let message = error.to_string();
        assert!(
            message.contains("storage key certificates/local/example.com"),
            "{message}"
        );
        assert!(
            message.contains("x509: unsupported elliptic curve"),
            "{message}"
        );
        assert_eq!(
            message
                .matches("TLS configuration at `certificates`")
                .count(),
            1,
            "{message}"
        );
        assert_eq!(
            message.matches("private key for certificate").count(),
            1,
            "{message}"
        );
    }

    /// A key the classifier accepts can still be refused by the provider: aws-lc-rs rejects an
    /// RSA key whose public exponent is even. That fallback has to keep the located path, the
    /// source and the DNS names rather than surfacing the provider's bare message, and the
    /// resolver has to reject the certificate too (T-TLS-095).
    #[test]
    fn provider_refusal_keeps_the_certificate_identity() {
        let certificate = example();
        let chain: Vec<Vec<u8>> = certificate.chain().iter().map(|der| der.to_vec()).collect();
        let source = "storage key certificates/local/example.com";
        let (_, bad_rsa) = pem_blocks(include_str!(
            "../testdata/key-types/rsa2048-bad-exponent.key"
        ))
        .expect("bad-exponent fixture PEM parses")
        .remove(0);
        let certificate = TlsCertificate::from_der_with_source(
            chain,
            bad_rsa,
            vec!["example.com".to_string()],
            Some(source.to_string()),
        )
        .expect("the classifier accepts RSA-2048; the provider refuses the exponent later");

        let error = certificate
            .certified_key()
            .expect_err("the provider must refuse an even public exponent");
        let message = error.to_string();
        assert!(message.contains(source), "{message}");
        assert!(message.contains("DNS names: example.com"), "{message}");
        assert!(
            message.contains("not supported by the rustls aws-lc-rs provider"),
            "{message}"
        );
        assert_eq!(
            message.matches("private key for certificate").count(),
            1,
            "{message}"
        );

        let error = CertificateResolver::from_certificates([certificate])
            .expect_err("the resolver must refuse a certificate the provider cannot sign with");
        let message = error.to_string();
        assert!(message.contains(source), "{message}");
        assert_eq!(
            message.matches("private key for certificate").count(),
            1,
            "{message}"
        );
    }

    /// Label-less DER (the certificate cache path) must dispatch on structure: a SEC1 body is
    /// not PKCS#8 and wrapping it as such is the reported startup failure.
    #[test]
    fn from_der_dispatches_on_the_der_structure_not_pkcs8() {
        let certificate = example();
        let chain: Vec<Vec<u8>> = certificate.chain().iter().map(|der| der.to_vec()).collect();
        let names = vec!["example.com".to_string()];

        for (name, pem_file) in [
            ("SEC1 P-256", "p256-sec1"),
            ("PKCS#1 RSA-2048", "rsa2048-pkcs1"),
            ("PKCS#8 P-256", "p256-pkcs8"),
        ] {
            let pem = std::fs::read_to_string(format!(
                "{}/testdata/key-types/{pem_file}.key",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
            let der = crate::storage::private_key_der(&pem)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let uto = TlsCertificate::from_der(chain.clone(), der, names.clone())
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            uto.certified_key()
                .unwrap_or_else(|error| panic!("{name} must produce a signing key: {error}"));
        }
    }

    /// A block labelled `PRIVATE KEY` whose body is SEC1 or PKCS#1 is accepted by structure, with
    /// a warning; the label is a hint, not a gate.
    #[test]
    fn private_key_from_pem_accepts_a_mislabelled_structure() {
        let sec1 = include_str!("../testdata/key-types/p256-sec1.key");
        let relabelled = sec1
            .replace("BEGIN EC PRIVATE KEY", "BEGIN PRIVATE KEY")
            .replace("END EC PRIVATE KEY", "END PRIVATE KEY");
        let key = private_key_from_pem(&relabelled).expect("structure wins over the label");
        assert!(
            matches!(key, PrivateKeyDer::Sec1(_)),
            "a SEC1 body under a PKCS#8 label must build the SEC1 variant"
        );

        let pkcs1 = include_str!("../testdata/key-types/rsa2048-pkcs1.key");
        let relabelled = pkcs1
            .replace("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY")
            .replace("END RSA PRIVATE KEY", "END PRIVATE KEY");
        let key = private_key_from_pem(&relabelled).expect("structure wins over the label");
        assert!(
            matches!(key, PrivateKeyDer::Pkcs1(_)),
            "a PKCS#1 body under a PKCS#8 label must build the PKCS#1 variant"
        );
    }

    /// A block that is none of the three structures stays loud, and the message tells the operator
    /// what to do instead of blaming the ASN.1.
    #[test]
    fn unknown_private_key_structure_reports_the_conversion_command() {
        let not_a_key = "-----BEGIN PRIVATE KEY-----\nZGVhZGJlZWY=\n-----END PRIVATE KEY-----\n";
        let error = private_key_from_pem(not_a_key).expect_err("garbage must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("not a recognised PKCS#8, SEC1 or PKCS#1"),
            "{message}"
        );
        assert!(
            message.contains("openssl pkcs8 -topk8 -nocrypt"),
            "the error must carry the conversion command: {message}"
        );
    }

    /// Unsupported key types stay rejected with a located message that names the detected type
    /// (and uses Caddy's wording where Caddy rejects the same key).
    #[test]
    fn unsupported_private_key_types_are_classified() {
        let cases = [
            (
                "secp256k1",
                include_str!("../testdata/key-types/secp256k1.key"),
                ["secp256k1", "x509: unsupported elliptic curve"].as_slice(),
            ),
            (
                "Ed448",
                include_str!("../testdata/key-types/ed448.key"),
                ["Ed448", "1.3.101.113"].as_slice(),
            ),
            (
                "DSA",
                include_str!("../testdata/key-types/dsa.key"),
                ["DSA", "1.2.840.10040.4.1"].as_slice(),
            ),
            (
                "encrypted",
                include_str!("../testdata/key-types/encrypted-p256.key"),
                ["encrypted private keys are not supported"].as_slice(),
            ),
        ];
        for (name, pem, expected) in cases {
            let error = match private_key_from_pem(pem) {
                Ok(_) => panic!("{name} must be rejected"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(
                message.contains("TLS configuration at `certificates`"),
                "{name}: {message}"
            );
            for needle in expected {
                assert!(message.contains(needle), "{name}: {message}");
            }
        }
    }

    #[test]
    fn unsupported_key_error_names_certificate_source_and_dns_names() {
        let error = TlsCertificate::from_pem_with_source(
            include_str!("../testdata/key-types/p256-sec1.pem"),
            include_str!("../testdata/key-types/secp256k1.key"),
            Some("apps.tls.certificates.load_pem[1]".to_string()),
        )
        .expect_err("secp256k1 must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("apps.tls.certificates.load_pem[1]"),
            "{message}"
        );
        assert!(message.contains("localhost"), "{message}");
        assert!(message.contains("secp256k1"), "{message}");
    }

    /// RSA-1024 is accepted by Caddy (Go's minimum RSA size is 1024 bits) but rejected by
    /// aws-lc-rs, which requires 2048..=8192 bits (DIV-0114). The failure must stay loud and
    /// located: a silent accept, a panic, or the provider's generic parse error all fail here.
    #[test]
    fn rsa_1024_keys_are_rejected_with_located_errors() {
        let cert = include_str!("../testdata/key-types/rsa1024.pem");
        let keys = [
            ("PKCS#8", include_str!("../testdata/key-types/rsa1024.key")),
            (
                "PKCS#1",
                include_str!("../testdata/key-types/rsa1024-pkcs1.key"),
            ),
        ];
        for (encoding, key) in keys {
            let error = TlsCertificate::from_pem_with_source(
                cert,
                key,
                Some("apps.tls.certificates.load_files[0]".to_string()),
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains("TLS configuration at `certificates`"),
                "{encoding}: {message}"
            );
            assert!(
                message.contains("apps.tls.certificates.load_files[0]"),
                "{encoding}: {message}"
            );
            assert!(
                message.contains("DNS names: localhost"),
                "{encoding}: {message}"
            );
            assert!(message.contains("RSA-1024"), "{encoding}: {message}");
            assert!(message.contains("2048 and 8192"), "{encoding}: {message}");
            assert!(
                !message.contains("failed to parse private key as RSA, ECDSA, or EdDSA"),
                "{encoding}: the provider's opaque parse error must be replaced by the detected size: {message}"
            );
        }
    }

    /// Caddy/Go reject brainpool curves with `x509: unsupported elliptic curve`; caddy-rs must
    /// reject them at load with the same wording plus the configured entry and DNS names.
    #[test]
    fn brainpool_curve_keys_are_rejected_with_located_errors() {
        let cases = [
            (
                "brainpoolP256r1 SEC1",
                include_str!("../testdata/key-types/brainpool-p256-sec1.pem"),
                include_str!("../testdata/key-types/brainpool-p256-sec1.key"),
                "brainpoolP256r1",
                "1.3.36.3.3.2.8.1.1.7",
            ),
            (
                "brainpoolP384r1 PKCS#8",
                include_str!("../testdata/key-types/brainpool-p384-pkcs8.pem"),
                include_str!("../testdata/key-types/brainpool-p384-pkcs8.key"),
                "brainpoolP384r1",
                "1.3.36.3.3.2.8.1.1.11",
            ),
        ];
        for (name, cert, key, curve, oid) in cases {
            let error = TlsCertificate::from_pem_with_source(
                cert,
                key,
                Some("apps.tls.certificates.load_files[2]".to_string()),
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains("TLS configuration at `certificates`"),
                "{name}: {message}"
            );
            assert!(
                message.contains("apps.tls.certificates.load_files[2]"),
                "{name}: {message}"
            );
            assert!(
                message.contains("DNS names: localhost"),
                "{name}: {message}"
            );
            assert!(message.contains(curve), "{name}: {message}");
            assert!(message.contains(oid), "{name}: {message}");
            assert!(
                message.contains("x509: unsupported elliptic curve"),
                "{name}: {message}"
            );
        }
    }

    #[test]
    fn malformed_private_key_der_names_the_block_label() {
        // DER prefix `30 82 01 00` claims a 256-byte SEQUENCE with no body: truncated.
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIBAA==\n-----END PRIVATE KEY-----\n";
        let error = private_key_from_pem(pem).expect_err("truncated DER must be rejected");
        let message = error.to_string();
        assert!(message.contains("`PRIVATE KEY` block"), "{message}");
        assert!(message.contains("truncated"), "{message}");
    }

    #[test]
    fn multiple_private_key_blocks_use_the_first() {
        let combined = format!(
            "{}{}",
            include_str!("../testdata/key-types/p256-sec1.key"),
            include_str!("../testdata/key-types/p521-sec1.key")
        );
        let used = private_key_from_pem(&combined).expect("the first key is used");
        let first = private_key_from_pem(include_str!("../testdata/key-types/p256-sec1.key"))
            .expect("first key parses alone");
        assert_eq!(
            private_key_label_and_der(&used),
            private_key_label_and_der(&first)
        );
    }

    const CLIENT_CA_CERT: &str = include_str!("../testdata/auto-https/ca.pem");
    const CLIENT_CERT: &str = include_str!("../testdata/client-auth/client.pem");
    const CLIENT_KEY: &str = include_str!("../testdata/client-auth/client.key");
    const OTHER_CLIENT_CERT: &str = include_str!("../testdata/client-auth/other-client.pem");
    const OTHER_CLIENT_KEY: &str = include_str!("../testdata/client-auth/other-client.key");
    const UNTRUSTED_CLIENT_CERT: &str =
        include_str!("../testdata/client-auth/untrusted-client.pem");
    const UNTRUSTED_CLIENT_KEY: &str = include_str!("../testdata/client-auth/untrusted-client.key");
    const EXPIRED_CLIENT_CERT: &str = include_str!("../testdata/client-auth/expired-client.pem");
    const EXPIRED_CLIENT_KEY: &str = include_str!("../testdata/client-auth/expired-client.key");

    fn client_auth_server(
        mode: ClientAuthMode,
        roots_pem: Option<&str>,
        leaf_certs: &[&str],
    ) -> Arc<ServerConfig> {
        let resolver =
            Arc::new(CertificateResolver::from_certificates([example()]).expect("resolver builds"));
        let mut options = TlsServerOptions {
            client_auth: mode,
            ..TlsServerOptions::default()
        };
        if let Some(pem) = roots_pem {
            options.client_auth_roots =
                certificate_chain_from_pem(pem).expect("client CA fixture parses");
        }
        for leaf in leaf_certs {
            options
                .client_auth_leaf_certs
                .extend(certificate_chain_from_pem(leaf).expect("leaf fixture parses"));
        }
        build_server_config(resolver, &options).expect("client-auth server config builds")
    }

    /// Run a real rustls handshake with an optional client certificate.
    async fn handshake_with_client_auth(
        server_config: Arc<ServerConfig>,
        identity: Option<(&str, &str)>,
        versions: &'static [&'static SupportedProtocolVersion],
    ) -> std::result::Result<(), String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
            acceptor
                .accept(stream)
                .await
                .map(|_| ())
                .map_err(|error| format!("server handshake: {error}"))
        });
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(versions)
            .map_err(|error| error.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)));
        let mut client = match identity {
            Some((certificate, key)) => builder
                .with_client_auth_cert(
                    certificate_chain_from_pem(certificate).expect("client cert parses"),
                    private_key_from_pem(key).expect("client key parses"),
                )
                .map_err(|error| error.to_string())?,
            None => builder.with_no_client_auth(),
        };
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .map_err(|error| error.to_string())?;
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let client_result = connector
            .connect(server_name, stream)
            .await
            .map(|_| ())
            .map_err(|error| format!("client handshake: {error}"));
        let server_result = server
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string());
        match (client_result, server_result) {
            (Ok(()), Ok(())) => Ok(()),
            (client, server) => Err(format!("client={client:?} server={server:?}")),
        }
    }

    fn fixture_stored(cert_pem: &str, key_pem: &str, domains: &[&str]) -> StoredCertificate {
        StoredCertificate {
            certificate_pem: vec![cert_pem.to_string()],
            private_key_pem: key_pem.to_string(),
            domains: domains.iter().map(|domain| domain.to_string()).collect(),
            not_after_unix: 2_000_000_000,
            issuer_data: None,
            metadata_extra: std::collections::BTreeMap::new(),
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
    fn cn_only_certificate_loads_and_matches_its_name() {
        // Regression for T-TLS-091: common_name() used to receive the Subject SEQUENCE content
        // and then look for a SEQUENCE inside it, so the first RDN SET made it return None and
        // every CN-only certificate failed with "no subjectAltName ... and no subject commonName".
        let certificate =
            TlsCertificate::from_pem(CN_ONLY_CERT, CN_ONLY_KEY).expect("CN-only certificate loads");
        assert_eq!(certificate.names(), &["cn-only.example".to_string()]);
        let resolver = CertificateResolver::from_certificates([certificate]).expect("resolver");
        assert!(resolver.covers("cn-only.example"));
        assert!(resolver.covers("CN-ONLY.EXAMPLE."));
        assert!(!resolver.covers("other.example"));
        assert!(resolver.select(Some("cn-only.example")).is_some());
    }

    #[test]
    fn cn_and_san_certificate_prefers_san_and_keeps_cn_like_caddy() {
        // The pinned Caddy v2.11.9 oracle serves this certificate for both SNI values: certmagic's
        // fillCertFromLeaf keeps leaf.Subject.CommonName and appends the SANs. SAN entries are
        // listed first here so the SAN stays the preferred identity.
        let certificate = TlsCertificate::from_pem(CN_AND_SAN_CERT, CN_AND_SAN_KEY)
            .expect("CN+SAN certificate loads");
        assert_eq!(
            certificate.names(),
            &[
                "san-name.example".to_string(),
                "cn-name.example".to_string()
            ]
        );
        let resolver = CertificateResolver::from_certificates([certificate]).expect("resolver");
        assert!(resolver.covers("san-name.example"));
        assert!(resolver.covers("cn-name.example"));
    }

    // ---- subject commonName DER walk ------------------------------------------------------

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 0x80, "test DER uses short-form lengths");
        let mut out = Vec::with_capacity(content.len() + 2);
        out.push(tag);
        out.push(content.len() as u8);
        out.extend_from_slice(content);
        out
    }

    fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<u8> = parts.iter().flatten().copied().collect();
        der_tlv(0x30, &content)
    }

    fn der_set(parts: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<u8> = parts.iter().flatten().copied().collect();
        der_tlv(0x31, &content)
    }

    fn common_name_attribute(value: &[u8]) -> Vec<u8> {
        der_sequence(&[der_tlv(0x06, &[0x55, 0x04, 0x03]), value.to_vec()])
    }

    /// `Certificate ::= SEQUENCE { tbsCertificate }` with exactly the fixed tbs fields
    /// `certificate_names` indexes (version omitted): serial, signature, issuer, validity,
    /// subject, subjectPublicKeyInfo. No signature is needed; this tests name extraction only.
    fn certificate_with_subject(subject: &[u8]) -> Vec<u8> {
        der_sequence(&[der_sequence(&[
            der_tlv(0x02, &[0x01]),
            der_sequence(&[]),
            der_sequence(&[]),
            der_sequence(&[]),
            subject.to_vec(),
            der_sequence(&[]),
        ])])
    }

    #[test]
    fn common_name_is_read_from_the_attribute_value_tlv() {
        let subject = der_sequence(&[der_set(&[common_name_attribute(&der_tlv(
            0x0C,
            b"walked.example",
        ))])]);
        let subject = read_tlv(&subject).expect("subject parses");
        assert_eq!(
            common_name(&subject).expect("CN walks"),
            Some("walked.example".to_string())
        );
    }

    #[test]
    fn common_name_is_found_in_a_later_multi_rdn_subject() {
        let organization =
            der_sequence(&[der_tlv(0x06, &[0x55, 0x04, 0x0A]), der_tlv(0x0C, b"Org")]);
        let subject = der_sequence(&[
            der_set(&[organization]),
            der_set(&[common_name_attribute(&der_tlv(0x13, b"later.example"))]),
        ]);
        let subject = read_tlv(&subject).expect("subject parses");
        assert_eq!(
            common_name(&subject).expect("CN walks"),
            Some("later.example".to_string())
        );
    }

    #[test]
    fn common_name_supports_go_string_encodings() {
        let bmp: Vec<u8> = "bmp.example"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        let subject = der_sequence(&[der_set(&[common_name_attribute(&der_tlv(0x1E, &bmp))])]);
        let subject = read_tlv(&subject).expect("subject parses");
        assert_eq!(
            common_name(&subject).expect("BMPString CN walks"),
            Some("bmp.example".to_string())
        );
        let t61 = der_sequence(&[der_set(&[common_name_attribute(&der_tlv(
            0x14,
            b"t61.example",
        ))])]);
        let t61 = read_tlv(&t61).expect("subject parses");
        assert_eq!(
            common_name(&t61).expect("T61String CN walks"),
            Some("t61.example".to_string())
        );
    }

    #[test]
    fn non_string_common_name_value_fails_loudly() {
        let subject = der_sequence(&[der_set(&[common_name_attribute(&der_tlv(
            0x04,
            b"not a string",
        ))])]);
        let subject = read_tlv(&subject).expect("subject parses");
        let error = common_name(&subject).expect_err("OCTET STRING CN is rejected");
        assert!(
            error.to_string().contains("unsupported value tag 0x04"),
            "{error}"
        );
    }

    #[test]
    fn empty_subject_is_a_located_error_not_a_panic() {
        let error =
            certificate_names(&certificate_with_subject(&der_sequence(&[]))).expect_err("no names");
        assert!(
            error
                .to_string()
                .contains("no subjectAltName dNSName entries and no subject commonName"),
            "{error}"
        );
    }

    #[test]
    fn malformed_subject_is_a_located_error_not_a_panic() {
        // RDN SET claims two content bytes but only one follows inside a well-formed outer TLV.
        let malformed = der_tlv(0x30, &[0x31, 0x02, 0x30]);
        let error =
            certificate_names(&certificate_with_subject(&malformed)).expect_err("truncated RDN");
        assert!(
            error.to_string().contains("cannot read certificate names"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn cn_only_certificate_is_selected_over_tls() {
        let cn_only =
            TlsCertificate::from_pem(CN_ONLY_CERT, CN_ONLY_KEY).expect("CN-only certificate loads");
        let expected_leaf = cn_only.chain()[0].as_ref().to_vec();
        let resolver = Arc::new(
            CertificateResolver::from_certificates([example(), cn_only]).expect("resolver builds"),
        );
        let server_config = build_server_config(resolver, &TlsServerOptions::default())
            .expect("server config builds");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("local address");
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            acceptor.accept(stream).await.map(|_| ())
        });

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("safe protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("TCP connect");
        let server_name = rustls::pki_types::ServerName::try_from("cn-only.example".to_string())
            .expect("valid server name");
        let stream = connector
            .connect(server_name, stream)
            .await
            .expect("handshake");
        assert_eq!(
            stream
                .get_ref()
                .1
                .peer_certificates()
                .expect("peer certificate")[0]
                .as_ref(),
            expected_leaf.as_slice(),
            "SNI cn-only.example must select the CN-only certificate"
        );
        server
            .await
            .expect("server task")
            .expect("server handshake");
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
    }

    fn client_ca_der_base64() -> String {
        use base64::Engine as _;
        let der = certificate_chain_from_pem(CLIENT_CA_CERT).unwrap()[0]
            .as_ref()
            .to_vec();
        BASE64.encode(der)
    }

    #[test]
    fn client_auth_mode_parsing_accepts_all_caddy_modes() {
        for (value, mode) in [
            ("request", ClientAuthMode::Request),
            ("require", ClientAuthMode::Require),
            ("verify_if_given", ClientAuthMode::VerifyIfGiven),
            ("require_and_verify", ClientAuthMode::RequireAndVerify),
        ] {
            let options = TlsServerOptions::from_connection_policies(Some(&[
                serde_json::json!({"client_authentication": {"mode": value}}),
            ]))
            .unwrap();
            assert_eq!(options.client_auth, mode, "mode {value}");
        }
        // An empty client_authentication object is inert, like Caddy's inactive config.
        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {}}),
        ]))
        .unwrap();
        assert_eq!(options.client_auth, ClientAuthMode::None);
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {"mode": "bogus"}}),
        ]))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported client authentication mode"),
            "{error}"
        );
    }

    #[test]
    fn parses_client_auth_inline_ca_pool() {
        let encoded = client_ca_der_base64();
        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "ca": {"provider": "inline", "trusted_ca_certs": [encoded]}
            }}),
        ]))
        .expect("inline CA pool parses");
        // Caddy's default mode with a trust pool is require_and_verify.
        assert_eq!(options.client_auth, ClientAuthMode::RequireAndVerify);
        assert_eq!(options.client_auth_roots.len(), 1);
        assert!(options.client_auth_leaf_certs.is_empty());
    }

    #[test]
    fn parses_client_auth_file_ca_pool_and_legacy_fields() {
        let directory = tempfile::tempdir().unwrap();
        let ca_path = directory.path().join("client-ca.pem");
        std::fs::write(&ca_path, CLIENT_CA_CERT).unwrap();
        let ca_path = ca_path.to_string_lossy().to_string();

        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "mode": "verify_if_given",
                "ca": {"provider": "file", "pem_files": [ca_path]}
            }}),
        ]))
        .expect("file CA pool parses");
        assert_eq!(options.client_auth, ClientAuthMode::VerifyIfGiven);
        assert_eq!(options.client_auth_roots.len(), 1);

        // Deprecated/direct Caddy fields plus the task-facing aliases.
        let encoded = client_ca_der_base64();
        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "trusted_ca_pool": [encoded],
                "trusted_leaf_cert_file": ca_path,
            }}),
        ]))
        .expect("direct trusted fields parse");
        assert_eq!(options.client_auth, ClientAuthMode::RequireAndVerify);
        assert_eq!(options.client_auth_roots.len(), 1);
        assert_eq!(options.client_auth_leaf_certs.len(), 1);

        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "trusted_ca_certs_pem_files": [ca_path],
            }}),
        ]))
        .expect("canonical PEM files field parses");
        assert_eq!(options.client_auth, ClientAuthMode::RequireAndVerify);
        assert_eq!(options.client_auth_roots.len(), 1);
    }

    #[test]
    fn client_auth_config_errors_are_loud() {
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "trusted_ca_certs": ["not-base64!"]
            }}),
        ]))
        .unwrap_err();
        assert!(
            error.to_string().contains("invalid base64 DER certificate"),
            "{error}"
        );

        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.pem");
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "trusted_ca_pem_files": [missing.to_string_lossy()]
            }}),
        ]))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot read client-auth PEM file"),
            "{error}"
        );

        // `system` is now supported by the shared CA-pool loader (T-TLS-079), so it either loads
        // the platform bundle or fails with a located error — never silently ignores the source.
        let system = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "ca": {"provider": "system"}
            }}),
        ]));
        match system {
            Ok(options) => assert!(
                !options.client_auth_roots.is_empty(),
                "system CA pool must load platform roots"
            ),
            Err(error) => assert!(
                error.to_string().contains("platform") || error.to_string().contains("root"),
                "system CA pool error must be located: {error}"
            ),
        }

        // An unknown provider is still rejected with the supported-source list.
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "ca": {"provider": "bogus"}
            }}),
        ]))
        .unwrap_err();
        assert!(
            error.to_string().contains("bogus"),
            "unknown provider must be named: {error}"
        );

        // The Caddy leaf verifier module is supported with its loaders; unknown verifier modules
        // and empty loader lists fail loudly.
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "verifiers": [{"verifier": "leaf"}]
            }}),
        ]))
        .unwrap_err();
        assert!(error.to_string().contains("leaf_certs_loaders"), "{error}");
        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "verifiers": [{
                    "verifier": "leaf",
                    "leaf_certs_loaders": [{"loader": "pem", "certificates": [CLIENT_CERT]}]
                }]
            }}),
        ]))
        .expect("leaf verifier with a pem loader is supported");
        assert_eq!(options.client_auth_leaf_certs.len(), 1);
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "verifiers": [{"verifier": "custom-revocation"}]
            }}),
        ]))
        .unwrap_err();
        assert!(error.to_string().contains("T-TLS-072"), "{error}");

        let encoded = client_ca_der_base64();
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {
                "ca": {"provider": "inline", "trusted_ca_certs": [encoded]},
                "trusted_ca_certs": [encoded],
            }}),
        ]))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("conflicting client authentication"),
            "{error}"
        );

        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"client_authentication": {"unknown_field": true}}),
        ]))
        .unwrap_err();
        assert!(
            error.to_string().contains("client authentication field"),
            "{error}"
        );
    }

    #[test]
    fn client_auth_verifying_modes_require_roots() {
        let resolver = Arc::new(CertificateResolver::from_certificates([example()]).unwrap());
        for mode in [
            ClientAuthMode::VerifyIfGiven,
            ClientAuthMode::RequireAndVerify,
        ] {
            let options = TlsServerOptions {
                client_auth: mode,
                ..TlsServerOptions::default()
            };
            let error = build_server_config(Arc::clone(&resolver), &options).unwrap_err();
            assert!(
                error.to_string().contains("requires a trusted CA bundle"),
                "{mode:?}: {error}"
            );
        }

        // `request` and `require` do not verify the chain, so no trust pool is needed.
        for mode in [ClientAuthMode::Request, ClientAuthMode::Require] {
            let options = TlsServerOptions {
                client_auth: mode,
                ..TlsServerOptions::default()
            };
            build_server_config(Arc::clone(&resolver), &options)
                .unwrap_or_else(|error| panic!("{mode:?}: {error}"));
        }

        // The programmatic PEM convenience still works for verifying modes.
        let options = TlsServerOptions {
            client_auth: ClientAuthMode::RequireAndVerify,
            client_auth_roots_pem: Some(CLIENT_CA_CERT.to_string()),
            ..TlsServerOptions::default()
        };
        let config = build_server_config(resolver, &options).unwrap();
        assert!(config.alpn_protocols.contains(&b"h2".to_vec()));
    }

    #[tokio::test]
    async fn client_auth_request_mode_allows_missing_and_unverified_certificates() {
        // Caddy `request`: ask for a certificate but verify nothing.
        let server = client_auth_server(ClientAuthMode::Request, None, &[]);
        handshake_with_client_auth(Arc::clone(&server), None, TLS12_AND_13)
            .await
            .expect("request mode allows no client certificate");
        handshake_with_client_auth(
            Arc::clone(&server),
            Some((CLIENT_CERT, CLIENT_KEY)),
            TLS12_AND_13,
        )
        .await
        .expect("request mode accepts a client certificate");
        handshake_with_client_auth(
            server,
            Some((UNTRUSTED_CLIENT_CERT, UNTRUSTED_CLIENT_KEY)),
            TLS12_AND_13,
        )
        .await
        .expect("request mode does not verify the certificate");
    }

    #[tokio::test]
    async fn client_auth_require_mode_requires_but_does_not_verify() {
        let server = client_auth_server(ClientAuthMode::Require, None, &[]);
        assert!(
            handshake_with_client_auth(Arc::clone(&server), None, TLS12_AND_13)
                .await
                .is_err(),
            "require mode must reject a missing client certificate"
        );
        handshake_with_client_auth(
            Arc::clone(&server),
            Some((CLIENT_CERT, CLIENT_KEY)),
            TLS12_AND_13,
        )
        .await
        .expect("require mode accepts a certificate");
        handshake_with_client_auth(
            server,
            Some((UNTRUSTED_CLIENT_CERT, UNTRUSTED_CLIENT_KEY)),
            TLS12_AND_13,
        )
        .await
        .expect("require mode does not verify the chain (Caddy semantics)");
    }

    #[tokio::test]
    async fn client_auth_verify_if_given_accepts_missing_and_rejects_untrusted() {
        let server = client_auth_server(ClientAuthMode::VerifyIfGiven, Some(CLIENT_CA_CERT), &[]);
        handshake_with_client_auth(Arc::clone(&server), None, TLS12_AND_13)
            .await
            .expect("verify_if_given allows no client certificate");
        handshake_with_client_auth(
            Arc::clone(&server),
            Some((CLIENT_CERT, CLIENT_KEY)),
            TLS12_AND_13,
        )
        .await
        .expect("verify_if_given accepts a trusted certificate");
        assert!(
            handshake_with_client_auth(
                server,
                Some((UNTRUSTED_CLIENT_CERT, UNTRUSTED_CLIENT_KEY)),
                TLS12_AND_13,
            )
            .await
            .is_err(),
            "verify_if_given must reject an untrusted certificate"
        );
    }

    #[tokio::test]
    async fn client_auth_require_and_verify_enforces_both() {
        let server =
            client_auth_server(ClientAuthMode::RequireAndVerify, Some(CLIENT_CA_CERT), &[]);
        assert!(
            handshake_with_client_auth(Arc::clone(&server), None, TLS12_AND_13)
                .await
                .is_err(),
            "require_and_verify must reject a missing certificate"
        );
        handshake_with_client_auth(
            Arc::clone(&server),
            Some((CLIENT_CERT, CLIENT_KEY)),
            TLS12_AND_13,
        )
        .await
        .expect("require_and_verify accepts a trusted certificate");
        assert!(
            handshake_with_client_auth(
                server,
                Some((UNTRUSTED_CLIENT_CERT, UNTRUSTED_CLIENT_KEY)),
                TLS12_AND_13,
            )
            .await
            .is_err(),
            "require_and_verify must reject an untrusted certificate"
        );
    }

    #[tokio::test]
    async fn client_auth_require_and_verify_works_for_tls12_and_tls13() {
        for versions in [TLS12_ONLY, TLS13_ONLY] {
            let server =
                client_auth_server(ClientAuthMode::RequireAndVerify, Some(CLIENT_CA_CERT), &[]);
            handshake_with_client_auth(
                Arc::clone(&server),
                Some((CLIENT_CERT, CLIENT_KEY)),
                versions,
            )
            .await
            .unwrap_or_else(|error| panic!("valid client cert: {error}"));
            assert!(
                handshake_with_client_auth(server, None, versions)
                    .await
                    .is_err(),
                "missing client cert must fail for {versions:?}"
            );
        }
    }

    #[tokio::test]
    async fn client_auth_leaf_allowlist_is_enforced_after_chain_verification() {
        let server = client_auth_server(
            ClientAuthMode::RequireAndVerify,
            Some(CLIENT_CA_CERT),
            &[CLIENT_CERT],
        );
        handshake_with_client_auth(
            Arc::clone(&server),
            Some((CLIENT_CERT, CLIENT_KEY)),
            TLS12_AND_13,
        )
        .await
        .expect("allowlisted leaf is accepted");
        assert!(
            handshake_with_client_auth(
                server,
                Some((OTHER_CLIENT_CERT, OTHER_CLIENT_KEY)),
                TLS12_AND_13,
            )
            .await
            .is_err(),
            "a trusted-CA leaf not in the allowlist must be rejected"
        );
    }

    #[tokio::test]
    async fn client_auth_leaf_only_configuration_accepts_exact_leaf() {
        let server = client_auth_server(ClientAuthMode::RequireAndVerify, None, &[CLIENT_CERT]);
        handshake_with_client_auth(
            Arc::clone(&server),
            Some((CLIENT_CERT, CLIENT_KEY)),
            TLS12_AND_13,
        )
        .await
        .expect("exact allowlisted leaf is accepted without a CA bundle");
        assert!(
            handshake_with_client_auth(
                server,
                Some((UNTRUSTED_CLIENT_CERT, UNTRUSTED_CLIENT_KEY)),
                TLS12_AND_13,
            )
            .await
            .is_err(),
            "non-allowlisted leaf must be rejected"
        );
    }

    #[tokio::test]
    async fn client_auth_require_and_verify_rejects_expired_client_certificate() {
        // The fixture is signed by the trusted client CA but valid 2020-01-01..2021-01-01.
        let server =
            client_auth_server(ClientAuthMode::RequireAndVerify, Some(CLIENT_CA_CERT), &[]);
        assert!(
            handshake_with_client_auth(
                server,
                Some((EXPIRED_CLIENT_CERT, EXPIRED_CLIENT_KEY)),
                TLS12_AND_13,
            )
            .await
            .is_err(),
            "an expired client certificate must be rejected with a TLS alert"
        );
    }

    #[tokio::test]
    async fn client_auth_require_accepts_expired_certificate_without_verification() {
        // Caddy's `require` mode requires a certificate but does not verify the chain/validity;
        // only `verify_if_given`/`require_and_verify` reject the expired fixture.
        let server = client_auth_server(ClientAuthMode::Require, Some(CLIENT_CA_CERT), &[]);
        handshake_with_client_auth(
            server,
            Some((EXPIRED_CLIENT_CERT, EXPIRED_CLIENT_KEY)),
            TLS12_AND_13,
        )
        .await
        .expect("require mode accepts a presented (unverified) expired certificate");
    }

    #[tokio::test]
    async fn client_auth_verify_if_given_rejects_expired_when_present() {
        let server = client_auth_server(ClientAuthMode::VerifyIfGiven, Some(CLIENT_CA_CERT), &[]);
        handshake_with_client_auth(Arc::clone(&server), None, TLS12_AND_13)
            .await
            .expect("verify_if_given allows a missing certificate");
        assert!(
            handshake_with_client_auth(
                server,
                Some((EXPIRED_CLIENT_CERT, EXPIRED_CLIENT_KEY)),
                TLS12_AND_13,
            )
            .await
            .is_err(),
            "an expired presented certificate must be rejected when verifying"
        );
    }

    /// Look up one of the aws-lc-rs provider's cipher suites by its wire identifier.
    fn aws_lc_suite(suite: rustls::CipherSuite) -> SupportedCipherSuite {
        *rustls::crypto::aws_lc_rs::DEFAULT_CIPHER_SUITES
            .iter()
            .find(|candidate| candidate.suite() == suite)
            .expect("aws-lc-rs provides the cipher suite")
    }

    fn provider_with(
        curves: Option<&[&'static dyn SupportedKxGroup]>,
        suites: Option<Vec<SupportedCipherSuite>>,
    ) -> Arc<CryptoProvider> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        if let Some(curves) = curves {
            provider.kx_groups = curves.to_vec();
        }
        if let Some(suites) = suites {
            provider.cipher_suites = suites;
        }
        Arc::new(provider)
    }

    fn policy_server(
        curves: Vec<TlsCurve>,
        cipher_suites: Vec<Tls12CipherSuite>,
        versions: TlsVersions,
    ) -> Arc<ServerConfig> {
        let resolver =
            Arc::new(CertificateResolver::from_certificates([example()]).expect("resolver builds"));
        let options = TlsServerOptions {
            versions,
            curves,
            cipher_suites,
            ..TlsServerOptions::default()
        };
        build_server_config(resolver, &options).expect("restricted TLS policy config builds")
    }

    /// Handshake against a server with a custom client provider and report the negotiated
    /// cipher suite, key-exchange group and protocol version from the client connection.
    async fn handshake_with_provider(
        server_config: Arc<ServerConfig>,
        client_provider: Arc<CryptoProvider>,
        versions: &'static [&'static SupportedProtocolVersion],
    ) -> std::result::Result<
        (
            rustls::CipherSuite,
            rustls::NamedGroup,
            rustls::ProtocolVersion,
        ),
        String,
    > {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
            acceptor
                .accept(stream)
                .await
                .map(|_| ())
                .map_err(|error| format!("server handshake: {error}"))
        });
        let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&client_provider))
            .with_protocol_versions(versions)
            .map_err(|error| error.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(client_provider)))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .map_err(|error| error.to_string())?;
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let client_result = connector.connect(server_name, stream).await;
        let server_result = server
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string());
        let tls = client_result.map_err(|error| format!("client handshake: {error}"))?;
        server_result?;
        let (_, connection) = tls.get_ref();
        let suite = connection
            .negotiated_cipher_suite()
            .ok_or_else(|| "no negotiated cipher suite".to_string())?
            .suite();
        let group = connection
            .negotiated_key_exchange_group()
            .ok_or_else(|| "no negotiated key exchange group".to_string())?
            .name();
        let version = connection
            .protocol_version()
            .ok_or_else(|| "no negotiated protocol version".to_string())?;
        Ok((suite, group, version))
    }

    #[test]
    fn parses_curve_and_cipher_suite_policy_fields() {
        let options = TlsServerOptions::from_connection_policies(Some(&[serde_json::json!({
            "curves": ["x25519mlkem768", "x25519", "secp384r1", "x25519"],
            "cipher_suites": [
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            ]
        })]))
        .expect("curves and cipher suites parse");
        assert_eq!(
            options.curves,
            vec![TlsCurve::X25519MlKem768, TlsCurve::X25519, TlsCurve::P384,]
        );
        assert_eq!(
            options.cipher_suites,
            vec![
                Tls12CipherSuite::EcdheEcdsaAes128GcmSha256,
                Tls12CipherSuite::EcdheRsaAes256GcmSha384,
            ]
        );

        // The task-facing `ciphers` alias also works; empty arrays mean provider defaults.
        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"ciphers": ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]}),
        ]))
        .expect("ciphers alias parses");
        assert_eq!(
            options.cipher_suites,
            vec![Tls12CipherSuite::EcdheEcdsaAes256GcmSha384]
        );
        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"curves": [], "cipher_suites": []}),
        ]))
        .expect("empty policy arrays parse");
        assert!(options.curves.is_empty());
        assert!(options.cipher_suites.is_empty());
    }

    #[test]
    fn secp521r1_curve_fails_closed_and_unknown_names_fail_loudly() {
        // Caddy accepts secp521r1 as a curve; rustls' aws-lc-rs provider has no P-521
        // key-exchange group, so the policy must fail with a located error instead of being
        // silently dropped. P-521 *certificate* keys are supported (see the key-type tests).
        let options = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"curves": ["secp521r1"]}),
        ]))
        .expect("secp521r1 parses like Caddy");
        assert_eq!(options.curves, vec![TlsCurve::Secp521r1]);
        let resolver =
            Arc::new(CertificateResolver::from_certificates([example()]).expect("resolver"));
        let error = build_server_config(resolver, &options).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("secp521r1"), "{message}");
        assert!(message.contains("aws-lc-rs"), "{message}");
        assert!(message.contains("TLS-POLICY"), "{message}");

        // A curve name Caddy does not know still fails at parse time.
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"curves": ["bogus-curve"]}),
        ]))
        .unwrap_err();
        assert!(
            error.to_string().contains("unsupported TLS curve"),
            "{error}"
        );
    }

    #[test]
    fn unsupported_cipher_names_fail_loudly() {
        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"cipher_suites": ["TLS_AES_128_GCM_SHA256"]}),
        ]))
        .unwrap_err();
        assert!(
            error.to_string().contains("TLS 1.3 cipher suite"),
            "{error}"
        );

        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"]}),
        ]))
        .unwrap_err();
        assert!(error.to_string().contains("RSA key-exchange"), "{error}");

        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({"cipher_suites": ["TLS_BOGUS"]}),
        ]))
        .unwrap_err();
        assert!(
            error.to_string().contains("unsupported cipher suite"),
            "{error}"
        );

        let error = TlsServerOptions::from_connection_policies(Some(&[
            serde_json::json!({}),
            serde_json::json!({"curves": ["x25519"]}),
        ]))
        .unwrap_err();
        assert!(
            error.to_string().contains("per-connection policy field"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn restricted_tls12_cipher_suites_are_negotiated() {
        let server = policy_server(
            Vec::new(),
            vec![Tls12CipherSuite::EcdheEcdsaAes128GcmSha256],
            TlsVersions::Tls12Only,
        );
        let client = provider_with(
            None,
            Some(vec![aws_lc_suite(
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            )]),
        );
        let (suite, _group, version) = handshake_with_provider(server, client, TLS12_ONLY)
            .await
            .expect("restricted TLS 1.2 cipher suite negotiates");
        assert_eq!(
            suite,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        );
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);

        let server = policy_server(
            Vec::new(),
            vec![Tls12CipherSuite::EcdheEcdsaAes128GcmSha256],
            TlsVersions::Tls12Only,
        );
        let mismatched_client = provider_with(
            None,
            Some(vec![aws_lc_suite(
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            )]),
        );
        assert!(
            handshake_with_provider(server, mismatched_client, TLS12_ONLY)
                .await
                .is_err(),
            "no common TLS 1.2 cipher suite must fail the handshake"
        );
    }

    #[tokio::test]
    async fn restricted_curves_are_negotiated() {
        use rustls::crypto::aws_lc_rs::kx_group;
        // TLS 1.3 restriction: server offers only P-384, client only supplies P-384.
        let server = policy_server(vec![TlsCurve::P384], Vec::new(), TlsVersions::Default);
        let client = provider_with(Some(&[kx_group::SECP384R1]), None);
        let (_, group, _) = handshake_with_provider(server, client, TLS12_AND_13)
            .await
            .expect("restricted P-384 handshake");
        assert_eq!(group, rustls::NamedGroup::secp384r1);

        // A client that offers only X25519 cannot complete a P-384-only handshake.
        let server = policy_server(vec![TlsCurve::P384], Vec::new(), TlsVersions::Default);
        let client = provider_with(Some(&[kx_group::X25519]), None);
        assert!(
            handshake_with_provider(server, client, TLS12_AND_13)
                .await
                .is_err(),
            "no common key-exchange group must fail the handshake"
        );

        // The restriction also applies to TLS 1.3.
        let server = policy_server(vec![TlsCurve::X25519], Vec::new(), TlsVersions::Tls13Only);
        let client = provider_with(Some(&[kx_group::X25519]), None);
        let (_, group, version) = handshake_with_provider(server, client, TLS13_ONLY)
            .await
            .expect("restricted TLS 1.3 handshake");
        assert_eq!(group, rustls::NamedGroup::X25519);
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
    }

    #[tokio::test]
    async fn each_supported_curve_negotiates_when_configured_alone() {
        use rustls::crypto::aws_lc_rs::kx_group;
        let cases: [(TlsCurve, &'static dyn SupportedKxGroup, rustls::NamedGroup); 4] = [
            (
                TlsCurve::X25519MlKem768,
                kx_group::X25519MLKEM768,
                rustls::NamedGroup::X25519MLKEM768,
            ),
            (
                TlsCurve::X25519,
                kx_group::X25519,
                rustls::NamedGroup::X25519,
            ),
            (
                TlsCurve::P256,
                kx_group::SECP256R1,
                rustls::NamedGroup::secp256r1,
            ),
            (
                TlsCurve::P384,
                kx_group::SECP384R1,
                rustls::NamedGroup::secp384r1,
            ),
        ];
        for (curve, client_group, expected) in cases {
            let server = policy_server(vec![curve], Vec::new(), TlsVersions::Tls13Only);
            let client = provider_with(Some(&[client_group]), None);
            let (_, group, version) = handshake_with_provider(server, client, TLS13_ONLY)
                .await
                .unwrap_or_else(|error| panic!("{}: {error}", curve.name()));
            assert_eq!(
                group,
                expected,
                "{} negotiated the wrong group",
                curve.name()
            );
            assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
        }
    }

    #[tokio::test]
    async fn default_curves_prefer_mlkem_and_fall_back_to_x25519() {
        use rustls::crypto::aws_lc_rs::kx_group;

        // Caddy's default curve list starts with x25519mlkem768. A client that offers a hybrid
        // key share must negotiate it (rustls' own default client order starts with X25519, so
        // pin the client order explicitly here).
        let server = policy_server(Vec::new(), Vec::new(), TlsVersions::Tls13Only);
        let client = provider_with(Some(&[kx_group::X25519MLKEM768, kx_group::X25519]), None);
        let (_, group, _) = handshake_with_provider(server, client, TLS13_ONLY)
            .await
            .expect("default policy handshake");
        assert_eq!(group, rustls::NamedGroup::X25519MLKEM768);

        // A client that offers only X25519 still connects: the server falls back past the
        // hybrid group instead of requiring it.
        let server = policy_server(Vec::new(), Vec::new(), TlsVersions::Tls13Only);
        let client = provider_with(Some(&[kx_group::X25519]), None);
        let (_, group, _) = handshake_with_provider(server, client, TLS13_ONLY)
            .await
            .expect("x25519-only client falls back");
        assert_eq!(group, rustls::NamedGroup::X25519);
    }

    /// The provider's default key-exchange set must be Caddy's exact default curve list
    /// (`external/caddy/modules/caddytls/values.go`): `[x25519mlkem768, x25519, secp256r1]`.
    ///
    /// This guards the explicit `provider.kx_groups = groups` assignment in `crypto_provider`:
    /// rustls' aws-lc-rs default is `[X25519, SECP256R1, SECP384R1, X25519MLKEM768]`, which both
    /// reorders the preference and offers P-384 by default. Removing the assignment, changing
    /// `DEFAULT_CURVES`, or upgrading to a provider with a different default set must fail here
    /// rather than silently changing what a listener negotiates.
    #[test]
    fn default_provider_kx_groups_are_caddys_default_curves() {
        assert_eq!(
            DEFAULT_CURVES
                .iter()
                .map(|curve| curve.name())
                .collect::<Vec<_>>(),
            vec!["x25519mlkem768", "x25519", "secp256r1"],
            "DEFAULT_CURVES must stay Caddy's exact default list"
        );

        let provider = crypto_provider(&TlsServerOptions::default()).expect("default provider");
        assert_eq!(
            provider
                .kx_groups
                .iter()
                .map(|group| group.name())
                .collect::<Vec<_>>(),
            vec![
                rustls::NamedGroup::X25519MLKEM768,
                rustls::NamedGroup::X25519,
                rustls::NamedGroup::secp256r1,
            ],
            "the default provider must install Caddy's exact curve list, in order"
        );
        assert!(
            !provider
                .kx_groups
                .iter()
                .any(|group| group.name() == rustls::NamedGroup::secp384r1),
            "P-384 must not be offered unless the policy configures it"
        );

        // P-384 is implemented and selectable, so its absence above is a policy choice rather
        // than a missing provider group.
        assert_eq!(
            TlsCurve::P384.kx_group().expect("P-384 group").name(),
            rustls::NamedGroup::secp384r1
        );
        let configured = TlsServerOptions {
            curves: vec![TlsCurve::P384],
            ..TlsServerOptions::default()
        };
        let provider = crypto_provider(&configured).expect("configured provider");
        assert_eq!(
            provider
                .kx_groups
                .iter()
                .map(|group| group.name())
                .collect::<Vec<_>>(),
            vec![rustls::NamedGroup::secp384r1],
            "an explicit P-384 policy must install only P-384"
        );
    }

    #[tokio::test]
    async fn default_tls_policy_negotiates_provider_defaults() {
        let server = policy_server(Vec::new(), Vec::new(), TlsVersions::Default);
        let client = provider_with(None, None);
        let (_suite, _group, version) = handshake_with_provider(server, client, TLS12_AND_13)
            .await
            .expect("default policy handshake");
        assert!(matches!(
            version,
            rustls::ProtocolVersion::TLSv1_3 | rustls::ProtocolVersion::TLSv1_2
        ));
    }

    #[tokio::test]
    async fn tls13_cipher_suites_remain_fixed_when_tls12_is_restricted() {
        let server = policy_server(
            Vec::new(),
            vec![Tls12CipherSuite::EcdheEcdsaAes128GcmSha256],
            TlsVersions::Tls13Only,
        );
        let client = provider_with(
            None,
            Some(vec![
                aws_lc_suite(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256),
                aws_lc_suite(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384),
                aws_lc_suite(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
            ]),
        );
        let (suite, _group, version) = handshake_with_provider(server, client, TLS13_ONLY)
            .await
            .expect("TLS 1.3 still negotiates with a TLS 1.2 cipher restriction");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
        assert!(matches!(
            suite,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                | rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        ));
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
        // A syntactically valid PEM block whose DER is not a supported key is rejected while
        // loading the certificate, with a message naming the block and the certificate.
        let error = TlsCertificate::from_pem(
            EXAMPLE_CERT,
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("certificates"), "{message}");
        assert!(message.contains("`PRIVATE KEY` block"), "{message}");

        // A certificate built from DER (the in-memory cache/storage path) is classified too, so the
        // rejection now happens when the certificate is built and still names the key type and
        // certificate rather than surfacing the provider's raw error later.
        let (_, ed448_der) = pem_blocks(include_str!("../testdata/key-types/ed448.key"))
            .expect("Ed448 fixture PEM parses")
            .remove(0);
        let error = TlsCertificate::from_der_with_source(
            vec![certificate_der(&example())],
            ed448_der,
            vec!["example.com".to_string()],
            Some("storage key certificates/local/example.com".to_string()),
        )
        .expect_err("the DER path must reject Ed448");
        let message = error.to_string();
        assert!(message.contains("Ed448"), "{message}");
        assert!(message.contains("DNS names: example.com"), "{message}");
        assert!(
            message.contains("storage key certificates/local/example.com"),
            "{message}"
        );
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

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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

    #[test]
    fn resolver_exposes_stapled_certificates() {
        let certificate = TlsCertificate::from_pem(
            include_str!("../testdata/https/example.com.pem"),
            include_str!("../testdata/https/example.com.key"),
        )
        .expect("fixture certificate");
        let resolver = CertificateResolver::new();
        resolver
            .insert(certificate.with_ocsp_staple(Some(vec![0x30, 0x00])))
            .expect("insert stapled certificate");
        let certified = resolver.select(Some("example.com")).expect("selected");
        assert_eq!(certified.ocsp.as_deref(), Some(&[0x30, 0x00][..]));
        let sources = resolver.certificates();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].ocsp_staple(), Some(&[0x30, 0x00][..]));
        // Re-inserting the same leaf replaces the source snapshot rather than duplicating it.
        resolver
            .insert(sources[0].clone().with_ocsp_staple(Some(vec![0x30, 0x01])))
            .expect("reinsert");
        assert_eq!(resolver.certificates().len(), 1);
    }

    fn resumption_server(mode: ClientAuthMode, roots_pem: Option<&str>) -> Arc<ServerConfig> {
        let resolver =
            Arc::new(CertificateResolver::from_certificates([example()]).expect("resolver builds"));
        let mut options = TlsServerOptions {
            versions: TlsVersions::Tls12Only,
            client_auth: mode,
            ..TlsServerOptions::default()
        };
        if let Some(pem) = roots_pem {
            options.client_auth_roots =
                certificate_chain_from_pem(pem).expect("client CA fixture parses");
        }
        build_server_config(resolver, &options).expect("resumption server config builds")
    }

    /// Run one TLS 1.2 handshake with a reusable client config and return the server-side
    /// handshake kind (Full or Resumed).
    async fn handshake_kind(
        server_config: Arc<ServerConfig>,
        client_config: Arc<rustls::ClientConfig>,
    ) -> std::result::Result<rustls::HandshakeKind, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
            let stream = acceptor
                .accept(stream)
                .await
                .map_err(|error| format!("server handshake: {error}"))?;
            stream
                .get_ref()
                .1
                .handshake_kind()
                .ok_or_else(|| "server handshake kind unavailable".to_string())
        });
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .map_err(|error| error.to_string())?;
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        connector
            .connect(server_name, stream)
            .await
            .map_err(|error| format!("client handshake: {error}"))?;
        server.await.map_err(|error| error.to_string())?
    }

    fn resumption_client(identity: Option<(&str, &str)>) -> Arc<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(TLS12_ONLY)
            .expect("TLS 1.2 client config")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)));
        let mut client = match identity {
            Some((certificate, key)) => builder
                .with_client_auth_cert(
                    certificate_chain_from_pem(certificate).expect("client cert parses"),
                    private_key_from_pem(key).expect("client key parses"),
                )
                .expect("client identity"),
            None => builder.with_no_client_auth(),
        };
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(client)
    }

    #[tokio::test]
    async fn listener_without_client_auth_resumes_sessions() {
        let server = resumption_server(ClientAuthMode::None, None);
        let client = resumption_client(None);
        assert_eq!(
            handshake_kind(Arc::clone(&server), Arc::clone(&client))
                .await
                .expect("first handshake"),
            rustls::HandshakeKind::Full
        );
        assert_eq!(
            handshake_kind(server, client)
                .await
                .expect("resumed handshake"),
            rustls::HandshakeKind::Resumed,
            "a listener without client auth must keep TLS session resumption"
        );
    }

    #[tokio::test]
    async fn client_auth_listener_never_resumes_sessions() {
        let server = resumption_server(ClientAuthMode::RequireAndVerify, Some(CLIENT_CA_CERT));
        let client = resumption_client(Some((CLIENT_CERT, CLIENT_KEY)));
        assert_eq!(
            handshake_kind(Arc::clone(&server), Arc::clone(&client))
                .await
                .expect("first handshake"),
            rustls::HandshakeKind::Full
        );
        assert_eq!(
            handshake_kind(server, client)
                .await
                .expect("second handshake"),
            rustls::HandshakeKind::Full,
            "a client-auth listener must disable ticket issuance/acceptance"
        );
    }
}
