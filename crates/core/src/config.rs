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

    /// Logging configuration. Kept opaque until the logging workstream lands (WS-07/T-LOG).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,

    /// Storage module configuration, for example the file-system storage backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<Value>,

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

/// TLS app configuration (`apps.tls`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TlsApp {
    /// Loaded certificate configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Value>,

    /// Automation policies and ACME issuers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automation: Option<Value>,

    /// Session ticket configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_tickets: Option<Value>,

    /// Unknown TLS-app fields, preserved.
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
}
