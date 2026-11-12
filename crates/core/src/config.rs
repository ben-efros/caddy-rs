//! The Caddy JSON configuration model.
//!
//! The model is deliberately *incomplete but faithful*: every field this project understands is
//! typed, and every field it does not understand is preserved verbatim in an `extra` map so that
//! [`Config`] round-trips without losing configuration. Compatibility target: Caddy v2.11.9
//! (`external/caddy`, pinned by the program repository). See
//! `docs/compatibility/CONFIGURATION.md` for the coverage matrix and known divergences.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::duration::{CaddyDuration, CaddySignedDuration};
use crate::error::{Error, Result};

/// The root of a Caddy configuration document.
///
/// Unknown top-level keys are preserved in [`Config::extra`] and rejected by validation, because
/// Caddy itself rejects unknown top-level fields when the strict loader is used.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Admin API settings. Absent means "enabled with Caddy defaults".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<AdminConfig>,

    /// Logging configuration (`logging`), including the global sink and named logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<Logging>,

    /// Storage module configuration, for example the file-system storage backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageConfig>,

    /// Applications, keyed by app module name (`http`, `tls`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apps: Option<Apps>,

    /// caddy-rs extension (`stock_compat`, DIV-0130): selects the documented stock-compatibility
    /// profile. Absent means `false`. The file/glob import policy is implemented (DIV-0124); the
    /// remaining profile surfaces (response headers, log redaction, identity) are tracked by
    /// T-CONF-071/T-HTTP-160/T-HTTP-161.
    #[serde(
        default,
        deserialize_with = "deserialize_stock_compat",
        skip_serializing_if = "Option::is_none"
    )]
    pub stock_compat: Option<bool>,

    /// Unknown top-level keys, preserved for round-tripping and rejected by validation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Decode `stock_compat` with a field-named error instead of a bare serde type error.
fn deserialize_stock_compat<'de, D>(deserializer: D) -> std::result::Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Value::deserialize(deserializer)? {
        Value::Bool(value) => Ok(Some(value)),
        Value::Null => Err(serde::de::Error::custom(
            "stock_compat must be a boolean, got null",
        )),
        other => Err(serde::de::Error::custom(format!(
            "stock_compat must be a boolean, got {other}"
        ))),
    }
}

impl Config {
    /// Decode configuration from UTF-8 JSON bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Decode configuration from a JSON value.
    pub fn from_value(value: Value) -> Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Read and decode a JSON configuration file.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|source| Error::ConfigIo {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_slice(&bytes)
    }

    /// Serialize the configuration to compact JSON.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Serialize the configuration to a JSON value.
    pub fn to_value(&self) -> Result<Value> {
        Ok(serde_json::to_value(self)?)
    }

    /// The logging configuration, if present.
    pub fn logging(&self) -> Option<&Logging> {
        self.logging.as_ref()
    }

    /// The effective `stock_compat` flag (an absent field means `false`).
    ///
    /// This is the caddy-rs stock-compatibility switch (DIV-0130). The import-path policy is the
    /// first surface it gates (DIV-0124); the remaining profile rows are tracked by
    /// T-CONF-071/T-HTTP-160/T-HTTP-161.
    pub fn stock_compat(&self) -> bool {
        self.stock_compat.unwrap_or(false)
    }

    /// The global storage configuration, if present.
    pub fn storage(&self) -> Option<&StorageConfig> {
        self.storage.as_ref()
    }

    /// The HTTP app, if configured.
    pub fn http(&self) -> Option<&HttpApp> {
        self.apps.as_ref().and_then(|apps| apps.http.as_ref())
    }

    /// The TLS app, if configured.
    pub fn tls(&self) -> Option<&TlsApp> {
        self.apps.as_ref().and_then(|apps| apps.tls.as_ref())
    }

    /// The PKI app, if configured.
    pub fn pki(&self) -> Option<&PkiApp> {
        self.apps.as_ref().and_then(|apps| apps.pki.as_ref())
    }
}

/// Admin API configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminConfig {
    /// When true, the admin endpoint is not started.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,

    /// Listen address of the admin API. Caddy's default is `localhost:2019`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,

    /// Whether the `Origin` header of requests must be in [`AdminConfig::origins`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub enforce_origin: bool,

    /// Allowed admin API origins.  `None` means "not configured" (derive defaults).
    /// `Some([])` means explicitly empty (block all origins).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<Vec<String>>,

    /// Unknown admin fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            listen: None,
            enforce_origin: false,
            origins: None,
            extra: BTreeMap::new(),
        }
    }
}

impl AdminConfig {
    /// Admin listen address, applying Caddy's default.
    pub fn listen_addr(&self) -> &str {
        self.listen.as_deref().unwrap_or("localhost:2019")
    }

    /// Whether configuration changes should be autosaved (`admin.config.persist`).
    ///
    /// Caddy's default is `true`; an explicit `false` disables autosave. The nested `config`
    /// object is preserved in [`AdminConfig::extra`] so it round-trips without a typed field; this
    /// accessor is the single place the persistence gate is interpreted. A malformed `persist`
    /// value is treated as the default (`true`), matching the conservative "do not silently drop
    /// persistence" choice.
    pub fn persist_config(&self) -> bool {
        self.extra
            .get("config")
            .and_then(Value::as_object)
            .and_then(|config| config.get("persist"))
            .and_then(Value::as_bool)
            .unwrap_or(true)
    }
}

/// The applications section of a configuration document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Apps {
    /// HTTP app (`apps.http`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpApp>,

    /// TLS app (`apps.tls`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsApp>,

    /// PKI app (`apps.pki`): certificate authorities used by internal issuers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pki: Option<PkiApp>,

    /// Apps this build does not model; preserved and rejected by validation unless registered.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// PKI app configuration (`apps.pki`, Caddy module `pki`).
///
/// Caddy's PKI app manages certificate authorities that internal issuers use. The default CA ID
/// is `local`; when the app is absent (or defines no CAs) Caddy provisions that default CA
/// implicitly, which is why `tls internal` works without any `apps.pki` configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PkiApp {
    /// Certificate authorities keyed by their config-facing ID (`certificate_authorities`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_authorities: Option<BTreeMap<String, CertificateAuthority>>,

    /// Unknown PKI-app fields, preserved for round-tripping and rejected by validation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Default for PkiApp {
    fn default() -> Self {
        Self {
            certificate_authorities: None,
            extra: BTreeMap::new(),
        }
    }
}

/// One certificate authority in `apps.pki.certificate_authorities`.
///
/// Field names follow Caddy's `caddypki.CA` JSON encoding. The config-facing ID is the map key;
/// Caddy ignores an `id` field in JSON, but it is accepted here for configuration generators and
/// must match the key when present.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CertificateAuthority {
    /// Unique config-facing ID. Duplicated map key, accepted for generators that emit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// User-facing name of the certificate authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Common Name of the root certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_common_name: Option<String>,

    /// Common Name of the intermediate certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate_common_name: Option<String>,

    /// Lifetime of the intermediate certificates, in nanoseconds (Caddy `Duration`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate_lifetime: Option<i64>,

    /// How often to check whether CA certificates need renewal, in nanoseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance_interval: Option<i64>,

    /// Fraction of a certificate's lifetime after which renewal is attempted (0.0–1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_window_ratio: Option<f64>,

    /// Whether Caddy installs the root certificate into system trust stores (`install_trust`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_trust: Option<bool>,

    /// Root certificate/key to use; generated when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PkiKeyPair>,

    /// Intermediate certificate/key to use; generated when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate: Option<PkiKeyPair>,

    /// Storage backend for this CA, overriding the global storage configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageConfig>,

    /// Unknown CA fields, preserved for round-tripping and rejected by validation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A certificate/key pair (`root` / `intermediate` in a PKI CA).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PkiKeyPair {
    /// Path to (or inline value of) the certificate PEM; format-dependent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,

    /// Path to (or inline value of) the private key; format-dependent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    /// Format of the certificate and key. Caddy supports `pem_file` (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Unknown key-pair fields, preserved for round-tripping and rejected by validation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// HTTP app configuration (`apps.http`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpApp {
    /// Port used for automatic HTTP listeners (Caddy default 80).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_port: Option<u16>,

    /// Port used for automatic HTTPS listeners (Caddy default 443).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_port: Option<u16>,

    /// Grace period for graceful shutdown. Caddy serializes `caddy.Duration` as integer
    /// nanoseconds and accepts Go duration strings (`"5s"`) on input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_period: Option<CaddySignedDuration>,

    /// How long to keep serving after a shutdown is scheduled, before initiating the grace period
    /// (`apps.http.shutdown_delay`, Caddy's `caddy.Duration`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shutdown_delay: Option<CaddySignedDuration>,

    /// Experimental HTTP metrics configuration (`apps.http.metrics`).
    ///
    /// Caddy v2.11.9 gates the `caddy_http_*` metric families behind this object; caddy-rs records
    /// them unconditionally but validates the shape so a configuration that Caddy accepts is not
    /// rejected as an unknown app field, and so the unsupported behaviours (`per_host`, `otlp`) are
    /// named loudly instead of silently ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsApp>,

    /// HTTP servers keyed by server name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub servers: BTreeMap<String, HttpServer>,

    /// Unknown HTTP-app fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Caddy's experimental HTTP metrics configuration (`apps.http.metrics`).
///
/// Mirrors `modules/caddyhttp/metrics.go` `Metrics`: three omitempty booleans. Unknown fields are
/// preserved so validation can reject them by name rather than dropping them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MetricsApp {
    /// Per-host metric labels (`per_host`). Requires host labelling, which caddy-rs does not
    /// implement yet; validation rejects `true` loudly.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub per_host: bool,

    /// Allow individual labels for catch-all hosts (`observe_catchall_hosts`); only meaningful with
    /// `per_host`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub observe_catchall_hosts: bool,

    /// Push metrics over OTLP in addition to scraping (`otlp`); not implemented.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub otlp: bool,

    /// Unknown `apps.http.metrics` fields, preserved for a located validation error.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl MetricsApp {
    /// Whether this object asks for behaviour caddy-rs cannot provide.
    ///
    /// Returns the offending field name and its tracking task, or `None` when the configuration is
    /// representable (metrics are always recorded, so the plain object is a no-op).
    pub fn unsupported_field(&self) -> Option<(&'static str, &'static str)> {
        if self.otlp {
            Some(("otlp", "T-ADMIN-031"))
        } else if self.per_host {
            Some(("per_host", "T-ADMIN-031"))
        } else {
            None
        }
    }
}

impl Default for HttpApp {
    fn default() -> Self {
        Self {
            http_port: None,
            https_port: None,
            grace_period: None,
            shutdown_delay: None,
            metrics: None,
            servers: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }
}

/// One HTTP server (`apps.http.servers.<name>`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HttpServer {
    /// Listen addresses, for example `":443"` or `"unix//run/caddy.sock"`.
    #[serde(default)]
    pub listen: Vec<String>,

    /// HTTP protocols offered on this server (Caddy's `protocols`).
    ///
    /// Supported values are `h1`, `h2` and `h2c`; `h3` and unknown tokens are rejected loudly
    /// (HTTP/3 is not implemented). Absent means Caddy's defaults: HTTP/1.1 everywhere plus
    /// HTTP/2 over TLS, with **no** cleartext h2c Upgrade (matching Caddy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,

    /// Routes, evaluated in order.
    #[serde(default)]
    pub routes: Vec<Route>,

    /// Automatic HTTPS policy overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automatic_https: Option<AutoHttps>,

    /// TLS connection policies for this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_connection_policies: Option<Vec<Value>>,

    /// Error handling routes (`handle_errors`): evaluated after a handler fails or produces an
    /// error status. Absent means Caddy's nil error config (no error routes); a present object
    /// with an empty `routes` array still enables error-route handling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<HttpErrorConfig>,

    /// `strict_sni_host` may be a bool or an object in Caddy; preserved opaquely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_sni_host: Option<Value>,

    /// Read timeout (duration string or nanoseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_timeout: Option<Value>,

    /// Write timeout (duration string or nanoseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_timeout: Option<Value>,

    /// Idle timeout (duration string or nanoseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<Value>,

    /// Per-server access-log association (`logs`), Caddy's `ServerLogConfig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<ServerLogConfig>,

    /// Listener wrappers (`listener_wrappers`), applied in order to accepted connections.
    ///
    /// caddy-rs implements `proxy_protocol` (PROXY protocol v1/v2 header parsing before TLS) and
    /// accepts the Caddy `tls` marker as an ordering no-op; other wrappers are rejected loudly at
    /// validation time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listener_wrappers: Vec<ListenerWrapperConfig>,

    /// Unknown server fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One server's error handling configuration (`apps.http.servers.*.errors`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HttpErrorConfig {
    /// Routes evaluated after the primary handler chain returns an error.
    #[serde(default)]
    pub routes: Vec<Route>,

    /// Unknown error-config fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One listener wrapper (`apps.http.servers.*.listener_wrappers[i]`).
///
/// Caddy's JSON shape is a module object with the wrapper name in `wrapper` and the module's
/// options flattened alongside it (for example `{"wrapper":"proxy_protocol","timeout":"5s"}`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ListenerWrapperConfig {
    /// Listener wrapper module name (`caddy.listeners.*` short key, for example `proxy_protocol`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapper: Option<String>,

    /// Wrapper-specific options, preserved and validated per wrapper.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Options of the `proxy_protocol` listener wrapper (`caddy.listeners.proxy_protocol`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProxyProtocolConfig {
    /// Maximum time to read the PROXY header; absent/zero disables the timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<CaddyDuration>,

    /// CIDR ranges from which a PROXY header is required/used (policy `USE`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,

    /// CIDR ranges from which a PROXY header is rejected (policy `REJECT`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,

    /// Policy for peers that are neither allowed nor denied. Default `IGNORE`.
    #[serde(default, skip_serializing_if = "is_default_proxy_policy")]
    pub fallback_policy: ProxyProtocolPolicy,

    /// Unknown wrapper options, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Connection policy of the `proxy_protocol` listener wrapper, matching go-proxyproto's `Policy`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum ProxyProtocolPolicy {
    /// Use PROXY header addresses when present, accept without header otherwise (default).
    #[default]
    Ignore,
    /// Require and use the PROXY header addresses; reject connections without one.
    Use,
    /// Reject connections that send a PROXY header; accept connections without one.
    Reject,
    /// Require a PROXY header and use its addresses (same acceptance as `Use`).
    Require,
    /// Do not read a PROXY header; always use the real connection addresses.
    Skip,
}

impl ProxyProtocolPolicy {
    /// The Caddy/go-proxyproto spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ignore => "IGNORE",
            Self::Use => "USE",
            Self::Reject => "REJECT",
            Self::Require => "REQUIRE",
            Self::Skip => "SKIP",
        }
    }

    /// Parse a policy name (case-insensitive, like Caddy's `Policy.UnmarshalText`).
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        match value.to_ascii_uppercase().as_str() {
            "IGNORE" => Ok(Self::Ignore),
            "USE" => Ok(Self::Use),
            "REJECT" => Ok(Self::Reject),
            "REQUIRE" => Ok(Self::Require),
            "SKIP" => Ok(Self::Skip),
            other => Err(format!(
                "invalid proxy_protocol fallback_policy `{other}` (expected IGNORE, USE, REJECT, REQUIRE or SKIP)"
            )),
        }
    }
}

impl TryFrom<String> for ProxyProtocolPolicy {
    type Error = String;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ProxyProtocolPolicy> for String {
    fn from(value: ProxyProtocolPolicy) -> Self {
        value.as_str().to_string()
    }
}

fn is_default_proxy_policy(policy: &ProxyProtocolPolicy) -> bool {
    *policy == ProxyProtocolPolicy::Ignore
}

/// Per-server access-log association (`apps.http.servers.*.logs`).
///
/// Mirrors Caddy's `modules/caddyhttp.ServerLogConfig`: which logger name(s) a request host maps
/// to, and which hosts are skipped. The runtime applies this when emitting access entries; the
/// global `logging.logs[]` configuration still decides where those named loggers are written.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerLogConfig {
    /// Logger name for hosts that do not match [`ServerLogConfig::logger_names`].
    ///
    /// An empty/absent name means Caddy's base access logger (`http.log.access`); a name `foo`
    /// means `http.log.access.foo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_logger_name: Option<String>,

    /// Host pattern to logger name(s) mapping. Keys are hostnames without ports and may contain
    /// `*` labels (`*.example.com`); a single string is also accepted in place of an array.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub logger_names: BTreeMap<String, StringList>,

    /// Request hosts whose access entries are dropped (unless mapped by `logger_names`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip_hosts: Vec<String>,

    /// Drop entries for hosts that do not appear in `logger_names`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub skip_unmapped_hosts: bool,

    /// Log credential header values instead of redacting them (modeled for round-tripping; the
    /// runtime currently applies the global encoder redaction policy — see DIV for T-CONF-030).
    #[serde(default, skip_serializing_if = "is_false")]
    pub should_log_credentials: bool,

    /// Log each invoked handler at DEBUG level (modeled for round-tripping; handler tracing is not
    /// emitted yet).
    #[serde(default, skip_serializing_if = "is_false")]
    pub trace: bool,

    /// Unknown per-server log fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A list of strings that also accepts a single JSON string (Caddy's `StringArray`).
///
/// Caddy accepts `"logger_names": {"example.com": "name"}` for backwards compatibility and always
/// serializes an array; this type does the same.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StringList(pub Vec<String>);

impl StringList {
    /// The contained strings.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<String>> for StringList {
    fn from(values: Vec<String>) -> Self {
        Self(values)
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            One(String),
            Many(Vec<String>),
        }
        Ok(Self(match Repr::deserialize(deserializer)? {
            Repr::One(value) => vec![value],
            Repr::Many(values) => values,
        }))
    }
}

/// Automatic HTTPS policy (`automatic_https`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AutoHttps {
    /// Disable automatic HTTPS entirely for this server.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable: bool,

    /// Keep automatic HTTPS but disable HTTP-to-HTTPS redirects.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_redirects: bool,

    /// Keep automatic HTTPS and redirects but disable automatic certificate management.
    ///
    /// Caddy JSON spells this `disable_certificates`; the shorter alias is accepted for
    /// compatibility with earlier caddy-rs test fixtures.
    #[serde(
        rename = "disable_certificates",
        alias = "disable_certs",
        default,
        skip_serializing_if = "is_false"
    )]
    pub disable_certs: bool,

    /// Ignore certificates already loaded from storage when deciding what to automate.
    #[serde(
        rename = "ignore_loaded_certificates",
        default,
        skip_serializing_if = "is_false"
    )]
    pub ignore_loaded_certs: bool,

    /// Hosts to skip automating.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip: Vec<String>,

    /// Hosts whose certificates are skipped (Caddy's `skip_certificates`; the short alias is
    /// accepted for compatibility with earlier caddy-rs fixtures).
    #[serde(
        rename = "skip_certificates",
        alias = "skip_certs",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub skip_certs: Vec<String>,

    /// Prefer wildcard certificates when possible.
    #[serde(default, skip_serializing_if = "is_false")]
    pub prefer_wildcard: bool,

    /// Unknown automatic-HTTPS fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One route (`routes[i]`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Route {
    /// Stable route id (`@id` in JSON), unique within a configuration.
    #[serde(rename = "@id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Handler chain. Each object names its module with a `handler` key.
    #[serde(default)]
    pub handle: Vec<Value>,

    /// Matcher sets. Each object names its matcher module by key; all matchers in a set must match.
    #[serde(rename = "match", default, skip_serializing_if = "Vec::is_empty")]
    pub matcher_sets: Vec<Value>,

    /// If true, no later route is evaluated after this one matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,

    /// Mutual-exclusion group; at most one matching route per group runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Unknown route fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Logging configuration (`logging`).
///
/// Mirrors Caddy's `caddy.Logging`: the global unstructured-log sink plus named structured logs.
/// Every nested struct flattens unknown fields into an `extra` map so a configuration this build
/// does not model still round-trips byte-for-byte (as JSON values) without losing data.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Logging {
    /// Destination for unstructured logs from Go's standard library logger (Caddy's `sink`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink: Option<SinkLog>,

    /// Named structured logs; the `"default"` key customizes Caddy's default logger.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub logs: BTreeMap<String, CustomLog>,

    /// Unknown logging fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Logging {
    /// The named log, if configured.
    pub fn log(&self, name: &str) -> Option<&CustomLog> {
        self.logs.get(name)
    }

    /// The log Caddy calls `default`, if configured.
    pub fn default_log(&self) -> Option<&CustomLog> {
        self.log("default")
    }
}

/// The global unstructured-log sink (`logging.sink`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SinkLog {
    /// Shared log fields (writer, encoder, level, sampling, ...).
    pub base: BaseLog,
}

/// Structured log (`logging.logs.<name>`), which adds include/exclude filters to [`BaseLog`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CustomLog {
    /// Shared log fields (writer, encoder, level, sampling, ...).
    #[serde(flatten)]
    pub base: BaseLog,

    /// Logger-name prefixes to include. Empty means include everything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,

    /// Logger-name prefixes to exclude.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

/// Fields shared by [`SinkLog`] and [`CustomLog`] (Caddy's `BaseLog`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BaseLog {
    /// Writer module (`caddy.logging.writers.*`); JSON inline key is `output`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer: Option<LogWriter>,

    /// Encoder module (`caddy.logging.encoders.*`); JSON inline key is `format`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoder: Option<LogEncoder>,

    /// Optional zap core module (`caddy.logging.cores.*`); JSON inline key is `module`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core: Option<ModuleRef>,

    /// Minimum level to emit (`DEBUG`, `INFO`, `WARN`, `ERROR`, `PANIC`, `FATAL`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,

    /// Sampling configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<LogSampling>,

    /// Include the caller's file name and line number.
    #[serde(default, skip_serializing_if = "is_false")]
    pub with_caller: bool,

    /// Number of stack frames to skip when reporting the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub with_caller_skip: Option<u32>,

    /// Include a stack trace at or above this level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub with_stacktrace: Option<String>,

    /// Unknown log fields, preserved (encoder options, writer options, future fields).
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A log writer module reference plus its writer-specific fields.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LogWriter {
    /// Module short name for `caddy.logging.writers.*` (JSON inline key `output`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,

    /// Writer-specific fields (for example `filename`, `address`, `roll`), preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A log encoder module reference plus its encoder-specific fields.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LogEncoder {
    /// Module short name for `caddy.logging.encoders.*` (JSON inline key `format`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Encoder-specific fields (for example `time_format`, `message_key`, `wrap`), preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Log entry sampling (`logging.*.sampling`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LogSampling {
    /// Sampling window; Caddy marshals durations as integer nanoseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<Value>,

    /// Entries to log per level and message in each interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first: Option<i64>,

    /// After `first`, log one in this many entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thereafter: Option<i64>,

    /// Unknown sampling fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Global storage module configuration (`storage`).
///
/// Caddy's storage object is a module object with the module short name in `module` and the rest of
/// the backend's fields alongside it (for example `{"module":"file_system","root":"/data"}`).
/// Backend fields this build does not model are preserved in [`StorageConfig::extra`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage module short name (`caddy.storage.*`), required by Caddy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,

    /// Backend-specific fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl StorageConfig {
    /// The module short name, when present.
    pub fn module_name(&self) -> Option<&str> {
        self.module.as_deref()
    }

    /// The `file_system` backend root, when configured.
    pub fn root(&self) -> Option<&str> {
        self.extra.get("root").and_then(Value::as_str)
    }
}

/// A module object whose JSON inline key is `module` (issuers, TLS on-demand permission, log core).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ModuleRef {
    /// Module short name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,

    /// Module-specific fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A module object whose JSON inline key is `name` (the TLS app's default DNS provider).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NamedModuleRef {
    /// Module short name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Module-specific fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A module object whose JSON inline key is `provider` (session-ticket key source).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProviderModuleRef {
    /// Module short name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Module-specific fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// TLS app configuration (`apps.tls`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TlsApp {
    /// Certificates to load into memory (`certificates`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<CertificatesConfig>,

    /// Certificate automation policies (`automation`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automation: Option<TlsAutomation>,

    /// TLS session ticket (STEK) configuration (`session_tickets`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_tickets: Option<SessionTicketService>,

    /// In-memory certificate cache configuration; opaque but preserved exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<Value>,

    /// Disable OCSP stapling for manually-managed certificates.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_ocsp_stapling: bool,

    /// Disable certmagic's storage readiness checks.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_storage_check: bool,

    /// Disable automatic cleanup of the storage backend.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_storage_clean: bool,

    /// Default DNS provider module for TLS-related DNS operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<NamedModuleRef>,

    /// DNS resolvers used for TLS-related DNS operations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,

    /// Encrypted ClientHello configuration; opaque but preserved exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_client_hello: Option<Value>,

    /// Unknown TLS-app fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl TlsApp {
    /// Automation policies in evaluation order (empty when no automation is configured).
    pub fn automation_policies(&self) -> &[AutomationPolicy] {
        self.automation
            .as_ref()
            .map(|automation| automation.policies.as_slice())
            .unwrap_or(&[])
    }

    /// Manually loaded certificate/key file pairs (`certificates.load_files`).
    pub fn load_files(&self) -> &[CertKeyFilePair] {
        self.certificates
            .as_ref()
            .and_then(|certificates| certificates.load_files.as_deref())
            .unwrap_or(&[])
    }

    /// Manually loaded PEM pairs (`certificates.load_pem`; Caddy's canonical JSON key).
    pub fn load_pems(&self) -> &[CertKeyPemPair] {
        self.certificates
            .as_ref()
            .and_then(|certificates| certificates.load_pem.as_deref())
            .unwrap_or(&[])
    }
}

/// Certificate loaders configured on the TLS app (`apps.tls.certificates`).
///
/// Caddy models this as a module map keyed by loader short name. The loaders with a stable,
/// simple shape are typed here; other loader keys (for example `load_folders`, `load_storage`) are
/// preserved in [`CertificatesConfig::extra`] and their module names are still validated.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CertificatesConfig {
    /// `tls.certificates.load_files`: certificates and keys loaded from disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_files: Option<Vec<CertKeyFilePair>>,

    /// `tls.certificates.load_pem`: certificates and keys decoded from PEM blocks.
    ///
    /// Caddy's JSON key is `load_pem`; `load_pems` is accepted as an alias for readability but
    /// serializes back to the canonical `load_pem` key.
    #[serde(
        rename = "load_pem",
        alias = "load_pems",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub load_pem: Option<Vec<CertKeyPemPair>>,

    /// `tls.certificates.automate`: subjects whose certificates should be managed automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automate: Option<Vec<String>>,

    /// `tls.certificates.pkcs11`: certificate chains and token-held private keys loaded through
    /// PKCS#11 (TPM, SoftHSM, YubiKey PIV, network HSM).
    ///
    /// JSON-only: there is no Caddyfile syntax for this loader. Each entry loads a certificate
    /// chain from PEM and pairs it with a non-extractable private key that stays inside a
    /// PKCS#11 token. The key itself never enters process memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkcs11: Option<Vec<Pkcs11CertConfig>>,

    /// Other loader module keys, preserved verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One PKCS#11 certificate-key entry (`tls.certificates.pkcs11[i]`).
///
/// Loads a certificate chain from PEM and a private key from a PKCS#11 token. The token holds
/// the key non-extractably; caddy-rs only ever holds an object handle and the public key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pkcs11CertConfig {
    /// Path to the PKCS#11 module (shared library), for example
    /// `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`, `/usr/lib/libtpm2_pkcs11.so.1`,
    /// or `ykcs11.dll`. Loaded at runtime via `dlopen`; caddy-rs does not link any vendor
    /// library at build time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,

    /// Token label used to select the PKCS#11 token. Mutually exclusive with `slot`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Slot ID used to select the PKCS#11 token. Mutually exclusive with `token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,

    /// Object label of the private key on the token. Mutually exclusive with `key_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_label: Option<String>,

    /// DER-encoded object ID of the private key on the token, hex-encoded. Mutually exclusive
    /// with `key_label`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// Path to a PEM file containing the certificate chain (leaf first). Mutually exclusive
    /// with `certificate_pem`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,

    /// Inline PEM certificate chain (leaf first). Mutually exclusive with `certificate`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,

    /// PIN source: `"env"` reads from an environment variable named by `pin`, `"file"` reads
    /// from the path named by `pin_file`.
    #[serde(default, skip_serializing_if = "PinSource::is_default")]
    pub pin_source: PinSource,

    /// Name of the environment variable holding the PIN (used when `pin_source` is `env`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,

    /// Path to a file containing the PIN (used when `pin_source` is `file`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_file: Option<String>,

    /// Optional per-token session reuse window in seconds. When set, sessions are held open
    /// across handshakes up to this window; otherwise each handshake opens and closes a session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_timeout: Option<u64>,

    /// Unknown fields, preserved verbatim for forward compatibility.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Source of the PKCS#11 PIN.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum PinSource {
    #[default]
    #[serde(rename = "env")]
    Env,
    #[serde(rename = "file")]
    File,
}

impl PinSource {
    /// Returns true when this is the default (`env`), so serde can omit it on serialisation.
    pub fn is_default(&self) -> bool {
        matches!(self, PinSource::Env)
    }
}

/// One certificate/key file pair (`load_files` entry).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CertKeyFilePair {
    /// Path to the certificate (public key) file.
    pub certificate: String,

    /// Path to the private key file.
    pub key: String,

    /// Certificate/key encoding format; Caddy defaults to `pem`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Arbitrary tags associated with this certificate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Unknown pair fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One certificate/key PEM pair (`load_pem` entry).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CertKeyPemPair {
    /// Certificate (public key) in PEM format.
    pub certificate: String,

    /// Private key in PEM format.
    pub key: String,

    /// Arbitrary tags associated with this certificate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Unknown pair fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// TLS certificate automation configuration (`apps.tls.automation`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TlsAutomation {
    /// Automation policies; the first matching policy applies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<AutomationPolicy>,

    /// On-Demand TLS configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_demand: Option<OnDemandConfig>,

    /// OCSP response freshness scan interval (duration as Caddy JSON number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_interval: Option<Value>,

    /// Managed-certificate expiration scan interval (duration as Caddy JSON number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renew_interval: Option<Value>,

    /// Storage cleanup scan interval (duration as Caddy JSON number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_clean_interval: Option<Value>,

    /// Unknown automation fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One TLS automation policy (`apps.tls.automation.policies[i]`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AutomationPolicy {
    /// Subjects (hostnames or IP addresses) this policy applies to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<String>,

    /// Certificate issuer modules (`tls.issuance.*`, JSON inline key `module`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<ModuleRef>,

    /// Certificate manager modules (`tls.get_certificate.*`, JSON inline key `via`); preserved.
    #[serde(
        rename = "get_certificate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub get_certificate: Option<Vec<Value>>,

    /// Request certificates with Must-Staple.
    #[serde(default, skip_serializing_if = "is_false")]
    pub must_staple: bool,

    /// Renew when this fraction of the certificate lifetime remains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_window_ratio: Option<f64>,

    /// Certificate key type (`ed25519`, `p256`, `p384`, `rsa2048`, `rsa4096`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,

    /// Policy-specific storage backend; falls back to the global storage when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageConfig>,

    /// Enable On-Demand TLS for this policy.
    #[serde(default, skip_serializing_if = "is_false")]
    pub on_demand: bool,

    /// Reuse private keys already present in storage.
    #[serde(default, skip_serializing_if = "is_false")]
    pub reuse_private_keys: bool,

    /// Disable OCSP stapling for certificates managed by this policy.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_ocsp_stapling: bool,

    /// Override OCSP responder URLs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ocsp_overrides: BTreeMap<String, String>,

    /// Unknown policy fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// On-Demand TLS configuration (`apps.tls.automation.on_demand`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OnDemandConfig {
    /// Deprecated ask endpoint (Caddy's legacy permission mechanism).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<String>,

    /// Permission module (`tls.permission.*`, JSON inline key `module`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<ModuleRef>,

    /// Unknown on-demand fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// TLS session ticket (STEK) configuration (`apps.tls.session_tickets`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionTicketService {
    /// Key source module (`tls.stek.*`, JSON inline key `provider`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<ProviderModuleRef>,

    /// STEK rotation interval (duration as Caddy JSON number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_interval: Option<Value>,

    /// Maximum number of keys to keep in rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_keys: Option<i64>,

    /// Disable STEK rotation.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_rotation: bool,

    /// Disable TLS session resumption by tickets entirely.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,

    /// Unknown session-ticket fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_caddy_example_without_losing_unknown_fields() {
        let json = serde_json::json!({
            "admin": {"listen": "localhost:2019", "unknown_admin_field": true},
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":443"],
                            "routes": [{
                                "@id": "proxy",
                                "match": [{"host": ["example.com"]}],
                                "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "localhost:8096"}]}],
                                "terminal": true
                            }]
                        }
                    }
                }
            },
            "future_top_level": {"x": 1}
        });
        let config = Config::from_value(json.clone()).expect("valid model");
        let round_tripped = config.to_value().expect("serializes");
        assert_eq!(round_tripped, json);
        assert_eq!(config.extra.len(), 1);
        assert_eq!(
            config.http().unwrap().servers["srv0"].routes[0]
                .id
                .as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn round_trips_listener_wrappers() {
        let json = serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "routes": [],
                "listener_wrappers": [
                    {
                        "wrapper": "proxy_protocol",
                        "timeout": "5s",
                        "allow": ["10.0.0.0/8"],
                        "deny": ["192.0.2.0/24"],
                        "fallback_policy": "REQUIRE",
                        "future_option": {"kept": true}
                    },
                    {"wrapper": "tls"}
                ]
            }}}}
        });
        let config = Config::from_value(json).expect("typed wrappers decode");
        let server = &config.http().expect("http app").servers["srv0"];
        assert_eq!(server.listener_wrappers.len(), 2);
        let proxy = &server.listener_wrappers[0];
        assert_eq!(proxy.wrapper.as_deref(), Some("proxy_protocol"));
        let options: crate::ProxyProtocolConfig = serde_json::from_value(
            serde_json::Value::Object(proxy.extra.clone().into_iter().collect()),
        )
        .expect("options decode");
        assert_eq!(
            options.timeout.map(|timeout| timeout.as_nanos()),
            Some(5_000_000_000)
        );
        assert_eq!(options.allow, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(options.deny, vec!["192.0.2.0/24".to_string()]);
        assert_eq!(options.fallback_policy, crate::ProxyProtocolPolicy::Require);
        assert!(options.extra.contains_key("future_option"));
        assert_eq!(server.listener_wrappers[1].wrapper.as_deref(), Some("tls"));

        // Wrapper options are preserved verbatim in the flattened extra map, so the original JSON
        // (including the Go duration string spelling) round-trips losslessly.
        let value = config.to_value().expect("serializes");
        assert_eq!(
            value["apps"]["http"]["servers"]["srv0"]["listener_wrappers"][0]["timeout"],
            serde_json::json!("5s")
        );
        assert_eq!(
            value["apps"]["http"]["servers"]["srv0"]["listener_wrappers"][0]["fallback_policy"],
            serde_json::json!("REQUIRE")
        );
        assert_eq!(
            value["apps"]["http"]["servers"]["srv0"]["listener_wrappers"][0]["future_option"]
                ["kept"],
            serde_json::json!(true)
        );

        // Caddy's canonical integer-nanosecond representation also decodes, and policy names are
        // case-insensitive.
        let options: crate::ProxyProtocolConfig = serde_json::from_value(serde_json::json!({
            "timeout": 5_000_000_000_u64,
            "fallback_policy": "ignore"
        }))
        .expect("canonical options decode");
        assert_eq!(
            options.timeout.map(|timeout| timeout.as_nanos()),
            Some(5_000_000_000)
        );
        assert_eq!(options.fallback_policy, crate::ProxyProtocolPolicy::Ignore);
    }

    #[test]
    fn proxy_protocol_policy_parses_case_insensitively() {
        for (input, expected) in [
            ("ignore", crate::ProxyProtocolPolicy::Ignore),
            ("Use", crate::ProxyProtocolPolicy::Use),
            ("REJECT", crate::ProxyProtocolPolicy::Reject),
            ("require", crate::ProxyProtocolPolicy::Require),
            ("SKIP", crate::ProxyProtocolPolicy::Skip),
        ] {
            assert_eq!(
                crate::ProxyProtocolPolicy::parse(input).expect("valid policy"),
                expected
            );
        }
        assert!(crate::ProxyProtocolPolicy::parse("sometimes").is_err());
    }

    #[test]
    fn round_trips_per_server_access_log_association() {
        let json = serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "routes": [],
                "logs": {
                    "default_logger_name": "fallback",
                    "logger_names": {
                        "example.com": ["one", "two"],
                        "*.internal.example.com": ["internal"]
                    },
                    "skip_hosts": ["skip.example.com"],
                    "skip_unmapped_hosts": true,
                    "should_log_credentials": true,
                    "trace": true,
                    "future_logs_field": {"kept": true}
                }
            }}}}
        });
        let config = Config::from_value(json.clone()).expect("typed model decodes");
        let server = &config.http().expect("http app").servers["srv0"];
        let logs = server.logs.as_ref().expect("logs typed");
        assert_eq!(logs.default_logger_name.as_deref(), Some("fallback"));
        assert_eq!(
            logs.logger_names["example.com"].as_slice(),
            ["one".to_string(), "two".to_string()]
        );
        assert_eq!(logs.skip_hosts, vec!["skip.example.com".to_string()]);
        assert!(logs.skip_unmapped_hosts);
        assert!(logs.should_log_credentials);
        assert!(logs.trace);
        assert!(logs.extra.contains_key("future_logs_field"));
        // Canonical Caddy JSON round-trips exactly (unknown fields preserved).
        assert_eq!(config.to_value().expect("serializes"), json);
    }

    #[test]
    fn logger_names_accepts_a_single_string_like_caddy_string_array() {
        // Caddy's `StringArray` accepts a bare string for backwards compatibility and always
        // serializes an array.
        let config = Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "routes": [],
                "logs": {"logger_names": {"example.com": "only"}}
            }}}}
        }))
        .expect("string form decodes");
        let logs = config.http().unwrap().servers["srv0"]
            .logs
            .clone()
            .expect("logs");
        assert_eq!(
            logs.logger_names["example.com"].as_slice(),
            ["only".to_string()]
        );
        let value = config.to_value().expect("serializes");
        assert_eq!(
            value["apps"]["http"]["servers"]["srv0"]["logs"]["logger_names"]["example.com"],
            serde_json::json!(["only"])
        );
    }

    #[test]
    fn admin_default_listen_matches_caddy() {
        assert_eq!(AdminConfig::default().listen_addr(), "localhost:2019");
        let custom = AdminConfig {
            listen: Some("127.0.0.1:2999".into()),
            ..Default::default()
        };
        assert_eq!(custom.listen_addr(), "127.0.0.1:2999");
    }

    #[test]
    fn admin_persist_config_defaults_true_and_honours_false() {
        let default = Config::from_value(serde_json::json!({"admin": {}})).expect("decodes");
        assert!(default.admin.as_ref().expect("admin").persist_config());

        let disabled =
            Config::from_value(serde_json::json!({"admin": {"config": {"persist": false}}}))
                .expect("decodes");
        assert!(!disabled.admin.as_ref().expect("admin").persist_config());
        // The nested object round-trips unchanged (no typed field was added).
        assert_eq!(
            disabled.to_value().expect("serializes")["admin"]["config"]["persist"],
            serde_json::json!(false)
        );

        let enabled =
            Config::from_value(serde_json::json!({"admin": {"config": {"persist": true}}}))
                .expect("decodes");
        assert!(enabled.admin.as_ref().expect("admin").persist_config());
    }

    /// Representative upstream-shaped JSON: every object below is either copied from a Caddy
    /// struct (`caddy.Logging`, `caddytls.TLS`, `filestorage.FileStorage`, ...) or includes an
    /// extra field to prove unknown fields at every nesting level survive the round-trip.
    pub(crate) fn representative_settings_json() -> Value {
        serde_json::json!({
            "logging": {
                "sink": {
                    "writer": {"output": "stdout"},
                    "encoder": {"format": "console"},
                    "level": "INFO",
                    "future_sink_field": {"kept": true}
                },
                "logs": {
                    "default": {
                        "level": "DEBUG",
                        "writer": {
                            "output": "file",
                            "filename": "/var/log/caddy/access.log",
                            "roll_size_mb": 100,
                            "roll_interval": 86400000000000_i64,
                            "future_writer_field": "kept"
                        },
                        "encoder": {
                            "format": "json",
                            "time_format": "wall_milli",
                            "message_key": "msg",
                            "future_encoder_field": 7
                        },
                        "sampling": {
                            "interval": 1000000000_i64,
                            "first": 100,
                            "thereafter": 100,
                            "future_sampling_field": true
                        },
                        "include": ["http.log.access"],
                        "exclude": ["http.log.access.health"],
                        "with_caller": true,
                        "with_caller_skip": 2,
                        "future_log_field": null
                    },
                    "runtime": {
                        "writer": {"output": "net", "address": "localhost:9999"},
                        "encoder": {"format": "filter", "wrap": {"format": "console"}},
                        "core": {"module": "mock"}
                    }
                },
                "future_logging_field": ["kept"]
            },
            "storage": {
                "module": "file_system",
                "root": "/data",
                "future_backend_field": {"kept": true}
            },
            "apps": {
                "tls": {
                    "certificates": {
                        "load_files": [{
                            "certificate": "/etc/ssl/site.crt",
                            "key": "/etc/ssl/site.key",
                            "format": "pem",
                            "tags": ["site"],
                            "future_pair_field": "kept"
                        }],
                        "load_pem": [{
                            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                            "key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
                            "tags": ["inline"]
                        }],
                        "automate": ["example.com", "*.example.com"],
                        "load_storage": {"pairs": [{"certificate": "example.com", "key": "example.com"}]}
                    },
                    "automation": {
                        "policies": [{
                            "subjects": ["example.com"],
                            "issuers": [
                                {
                                    "module": "acme",
                                    "ca": "https://acme-staging-v02.api.letsencrypt.org/directory",
                                    "email": "admin@example.com",
                                    "challenges": {"dns": {"provider": "cloudflare", "api_token": "secret"}},
                                    "future_issuer_field": "kept"
                                },
                                {"module": "internal"}
                            ],
                            "must_staple": true,
                            "renewal_window_ratio": 0.3333,
                            "key_type": "p256",
                            "storage": {"module": "file_system", "root": "/tls"},
                            "on_demand": true,
                            "reuse_private_keys": true,
                            "disable_ocsp_stapling": true,
                            "ocsp_overrides": {"http://ocsp.example.com": "http://ocsp2.example.com"},
                            "future_policy_field": {"kept": true}
                        }],
                        "on_demand": {
                            "ask": "https://example.com/ask",
                            "permission": {"module": "http", "endpoint": "https://example.com/ask"}
                        },
                        "ocsp_interval": 3600000000000_i64,
                        "renew_interval": 600000000000_i64,
                        "storage_clean_interval": 86400000000000_i64,
                        "future_automation_field": "kept"
                    },
                    "session_tickets": {
                        "key_source": {"provider": "standard"},
                        "rotation_interval": 43200000000000_i64,
                        "max_keys": 4,
                        // Caddy's own JSON marshalling drops explicit false booleans (omitempty),
                        // so absence is the canonical representation of the default.
                        "disabled": true,
                        "future_ticket_field": "kept"
                    },
                    "cache": {"capacity": 10000},
                    "disable_ocsp_stapling": true,
                    "disable_storage_check": true,
                    "disable_storage_clean": true,
                    "dns": {"name": "cloudflare", "api_token": "secret"},
                    "resolvers": ["1.1.1.1", "8.8.8.8"],
                    "encrypted_client_hello": {"config": "opaque"},
                    "future_tls_field": {"kept": true}
                }
            }
        })
    }

    #[test]
    fn round_trips_typed_logging_storage_and_tls_without_losing_fields() {
        let json = representative_settings_json();
        let config = Config::from_value(json.clone()).expect("typed models decode");
        let round_tripped = config.to_value().expect("serializes");
        assert_eq!(round_tripped, json);
    }

    #[test]
    fn typed_logging_accessors_expose_sink_and_logs() {
        let config = Config::from_value(representative_settings_json()).unwrap();
        let logging = config.logging().expect("logging present");
        let sink = logging.sink.as_ref().expect("sink present");
        assert_eq!(
            sink.base.writer.as_ref().and_then(|w| w.output.as_deref()),
            Some("stdout")
        );
        let default = logging.default_log().expect("default log");
        assert_eq!(default.base.level.as_deref(), Some("DEBUG"));
        assert_eq!(default.include, vec!["http.log.access".to_string()]);
        assert_eq!(default.exclude, vec!["http.log.access.health".to_string()]);
        let sampling = default.base.sampling.as_ref().expect("sampling");
        assert_eq!(sampling.first, Some(100));
        assert_eq!(
            default
                .base
                .writer
                .as_ref()
                .and_then(|writer| writer.extra.get("filename"))
                .and_then(Value::as_str),
            Some("/var/log/caddy/access.log")
        );
        let runtime = logging.log("runtime").expect("runtime log");
        assert_eq!(
            runtime
                .base
                .encoder
                .as_ref()
                .and_then(|encoder| encoder.format.as_deref()),
            Some("filter")
        );
        assert!(logging.extra.contains_key("future_logging_field"));
    }

    #[test]
    fn typed_storage_accessors_expose_module_and_root() {
        let config = Config::from_value(representative_settings_json()).unwrap();
        let storage = config.storage().expect("storage present");
        assert_eq!(storage.module_name(), Some("file_system"));
        assert_eq!(storage.root(), Some("/data"));
        assert!(storage.extra.contains_key("future_backend_field"));
    }

    #[test]
    fn typed_tls_accessors_expose_certificates_policies_and_tickets() {
        let config = Config::from_value(representative_settings_json()).unwrap();
        let tls = config.tls().expect("tls present");
        assert_eq!(tls.load_files().len(), 1);
        assert_eq!(tls.load_files()[0].certificate, "/etc/ssl/site.crt");
        assert_eq!(tls.load_files()[0].tags, vec!["site".to_string()]);
        assert_eq!(tls.load_pems().len(), 1);
        assert_eq!(tls.automation_policies().len(), 1);

        let policy = &tls.automation_policies()[0];
        assert_eq!(policy.subjects, vec!["example.com".to_string()]);
        assert_eq!(policy.issuers[0].module.as_deref(), Some("acme"));
        assert_eq!(
            policy.storage.as_ref().and_then(StorageConfig::module_name),
            Some("file_system")
        );

        let automation = tls.automation.as_ref().unwrap();
        assert_eq!(
            automation
                .on_demand
                .as_ref()
                .and_then(|on_demand| on_demand.permission.as_ref())
                .and_then(|permission| permission.module.as_deref()),
            Some("http")
        );

        let tickets = tls.session_tickets.as_ref().expect("tickets");
        assert_eq!(
            tickets
                .key_source
                .as_ref()
                .and_then(|source| source.provider.as_deref()),
            Some("standard")
        );
        assert_eq!(tickets.max_keys, Some(4));
        assert!(tickets.disabled);
        assert_eq!(
            tls.dns.as_ref().and_then(|dns| dns.name.as_deref()),
            Some("cloudflare")
        );
        assert!(tls.extra.contains_key("future_tls_field"));
    }

    #[test]
    fn logging_and_tls_sections_may_be_absent() {
        let config = Config::from_value(serde_json::json!({"admin": {"disabled": true}})).unwrap();
        assert!(config.logging().is_none());
        assert!(config.storage().is_none());
        assert!(config.tls().is_none());
        assert_eq!(
            config.to_value().unwrap(),
            serde_json::json!({"admin": {"disabled": true}})
        );
    }

    #[test]
    fn round_trips_typed_pki_app_without_losing_fields() {
        let json = serde_json::json!({
            "apps": {
                "pki": {
                    "certificate_authorities": {
                        "local": {
                            "name": "Local",
                            "root_common_name": "Root CN",
                            "intermediate_common_name": "Intermediate CN",
                            "intermediate_lifetime": 86_400_000_000_000_i64,
                            "maintenance_interval": 600_000_000_000_i64,
                            "renewal_window_ratio": 0.2,
                            "install_trust": false,
                            "root": {
                                "certificate": "/path/cert.pem",
                                "private_key": "/path/key.pem",
                                "format": "pem_file"
                            },
                            "intermediate": {"certificate": "/path/inter.pem"},
                            "storage": {"module": "file_system", "root": "/data"}
                        }
                    }
                }
            }
        });
        let config = Config::from_value(json.clone()).expect("typed pki model decodes");
        let pki = config.pki().expect("pki app present");
        let authorities = pki
            .certificate_authorities
            .as_ref()
            .expect("certificate authorities");
        let local = authorities.get("local").expect("local CA");
        assert_eq!(local.name.as_deref(), Some("Local"));
        assert_eq!(local.intermediate_lifetime, Some(86_400_000_000_000));
        assert_eq!(local.renewal_window_ratio, Some(0.2));
        assert_eq!(local.install_trust, Some(false));
        assert_eq!(
            local.root.as_ref().and_then(|root| root.format.as_deref()),
            Some("pem_file")
        );
        assert_eq!(config.to_value().expect("serializes"), json);
    }
    #[test]
    fn http_app_grace_period_and_shutdown_delay_are_typed() {
        let config = Config::from_value(serde_json::json!({
            "apps": {"http": {
                "grace_period": "5s",
                "shutdown_delay": 1_500_000_000_u64,
                "servers": {}
            }}
        }))
        .expect("typed shutdown timing decodes");
        let http = config.http().expect("http app");
        assert_eq!(
            http.grace_period.map(|d| d.as_nanos()),
            Some(5_000_000_000_i64)
        );
        assert_eq!(
            http.shutdown_delay.map(|d| d.as_nanos()),
            Some(1_500_000_000_i64)
        );
        // Caddy marshals caddy.Duration as integer nanoseconds.
        let value = config.to_value().expect("serializes");
        assert_eq!(
            value["apps"]["http"]["grace_period"],
            serde_json::json!(5_000_000_000_u64)
        );
        assert_eq!(
            value["apps"]["http"]["shutdown_delay"],
            serde_json::json!(1_500_000_000_u64)
        );

        // Caddy accepts negative durations (its runtime treats any value <= 0 as "no limit").
        let negative = Config::from_value(serde_json::json!({
            "apps": {"http": {"grace_period": -1, "servers": {}}}
        }))
        .expect("negative grace period decodes like Caddy");
        assert_eq!(
            negative
                .http()
                .and_then(|http| http.grace_period)
                .map(|d| d.as_nanos()),
            Some(-1)
        );

        // Malformed durations still fail decoding instead of being preserved as opaque JSON.
        for bad in [
            serde_json::json!({"apps": {"http": {"grace_period": "soon"}}}),
            serde_json::json!({"apps": {"http": {"grace_period": "5"}}}),
        ] {
            assert!(
                Config::from_value(bad.clone()).is_err(),
                "invalid shutdown timing must be rejected: {bad}"
            );
        }
    }

    #[test]
    fn pkcs11_config_decodes_and_round_trips() {
        let json = serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "module": "/usr/lib/libsofthsm2.so",
                            "token": "softhsm-token",
                            "key_label": "server-key",
                            "certificate": "/etc/certs/chain.pem",
                            "pin_source": "env",
                            "pin": "PKCS11_PIN",
                            "session_timeout": 300
                        }]
                    }
                }
            }
        });
        let config = Config::from_value(json.clone()).expect("valid pkcs11 config");
        let tls = config.tls().expect("tls app");
        let certs = tls.certificates.as_ref().expect("certificates configured");
        let entries = certs.pkcs11.as_ref().expect("pkcs11 entries");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.module.as_deref(), Some("/usr/lib/libsofthsm2.so"));
        assert_eq!(entry.token.as_deref(), Some("softhsm-token"));
        assert_eq!(entry.key_label.as_deref(), Some("server-key"));
        assert_eq!(entry.certificate.as_deref(), Some("/etc/certs/chain.pem"));
        assert_eq!(entry.pin_source, PinSource::Env);
        assert_eq!(entry.pin.as_deref(), Some("PKCS11_PIN"));
        assert_eq!(entry.session_timeout, Some(300));
        assert_eq!(entry.key_id, None);
        assert_eq!(entry.certificate_pem, None);
        assert_eq!(entry.pin_file, None);

        // Round-trips losslessly (flattened extra preserves unknown fields).
        let value = config.to_value().expect("serializes");
        assert_eq!(
            value["apps"]["tls"]["certificates"]["pkcs11"][0]["module"],
            serde_json::json!("/usr/lib/libsofthsm2.so")
        );
        assert_eq!(
            value["apps"]["tls"]["certificates"]["pkcs11"][0]["token"],
            serde_json::json!("softhsm-token")
        );
    }

    #[test]
    fn pkcs11_config_certificate_pem_and_pin_file() {
        let json = serde_json::json!({
            "apps": {
                "tls": {
                    "certificates": {
                        "pkcs11": [{
                            "module": "/usr/lib/ykcs11.dll",
                            "slot": 3,
                            "key_id": "deadbeef",
                            "certificate_pem": "-----BEGIN CERTIFICATE-----\\nMIIB...\\n-----END CERTIFICATE-----\\n",
                            "pin_source": "file",
                            "pin_file": "/run/secrets/pin"
                        }]
                    }
                }
            }
        });
        let config = Config::from_value(json).expect("valid pkcs11 pem config");
        let entry = &config
            .tls()
            .expect("tls app")
            .certificates
            .as_ref()
            .expect("certificates")
            .pkcs11
            .as_ref()
            .expect("pkcs11 entries")[0];
        assert_eq!(entry.slot, Some(3));
        assert_eq!(entry.key_id.as_deref(), Some("deadbeef"));
        assert!(entry.certificate_pem.is_some());
        assert_eq!(entry.pin_source, PinSource::File);
        assert_eq!(entry.pin_file.as_deref(), Some("/run/secrets/pin"));
        assert!(entry.token.is_none());
        assert!(entry.key_label.is_none());
        assert!(entry.certificate.is_none());
        assert!(entry.pin.is_none());
    }
}
