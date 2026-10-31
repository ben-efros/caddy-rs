//! The Caddy JSON configuration model.
//!
//! The model is deliberately *incomplete but faithful*: every field this project understands is
//! typed, and every field it does not understand is preserved verbatim in an `extra` map so that
//! [`Config`] round-trips without losing configuration. Compatibility target: Caddy v2.11.7
//! (`external/caddy`, pinned by the program repository). See
//! `docs/compatibility/CONFIGURATION.md` for the coverage matrix and known divergences.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

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

    /// Unknown top-level keys, preserved for round-tripping and rejected by validation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
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

    /// Allowed admin API origins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<String>,

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
            origins: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

impl AdminConfig {
    /// Admin listen address, applying Caddy's default.
    pub fn listen_addr(&self) -> &str {
        self.listen.as_deref().unwrap_or("localhost:2019")
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

    /// Apps this build does not model; preserved and rejected by validation unless registered.
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

    /// Grace period for graceful shutdown; a duration string such as `"5s"` in Caddy JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_period: Option<Value>,

    /// HTTP servers keyed by server name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub servers: BTreeMap<String, HttpServer>,

    /// Unknown HTTP-app fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Default for HttpApp {
    fn default() -> Self {
        Self {
            http_port: None,
            https_port: None,
            grace_period: None,
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

    /// Routes, evaluated in order.
    #[serde(default)]
    pub routes: Vec<Route>,

    /// Automatic HTTPS policy overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automatic_https: Option<AutoHttps>,

    /// TLS connection policies for this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_connection_policies: Option<Vec<Value>>,

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

    /// Unknown server fields, preserved.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
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

    /// Hosts whose certificates are skipped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
/// Caddy models this as a module map keyed by loader short name. The two loaders with a stable,
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

    /// Other loader module keys, preserved verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
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
    fn admin_default_listen_matches_caddy() {
        assert_eq!(AdminConfig::default().listen_addr(), "localhost:2019");
        let custom = AdminConfig {
            listen: Some("127.0.0.1:2999".into()),
            ..Default::default()
        };
        assert_eq!(custom.listen_addr(), "127.0.0.1:2999");
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
}
