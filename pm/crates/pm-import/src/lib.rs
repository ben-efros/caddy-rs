//! Native-first import mapping for NPM v2.16 HTTP host payloads.
//!
//! The importer maps NPM proxy, redirection and dead host API payloads onto [`caddy_rs_pm_core`]
//! hosts. It intentionally refuses to approximate settings that the native host model cannot
//! represent: `advanced_config`, `locations`, access lists and stream hosts fail with a located
//! error instead of being dropped. Features that are only metadata today (caching, exploit
//! blocking, HTTP/2 support and the WebSocket flag) are reported as warnings so the caller can see
//! exactly what the native compiler did not apply.
//!
//! The importer never chooses a certificate origin. A non-zero `certificate_id` requires the caller
//! to supply the origin map, and TLS flags without a certificate are rejected rather than cleared
//! the way NPM does. Full [`Host::validate`](caddy_rs_pm_core::Host::validate) coverage checks remain
//! the caller's responsibility, just as in `pm-hosts`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use caddy_rs_pm_core::{
    normalize_pattern, CertificateId, CertificateOrigin, CoreError, DeadSpec, Host, HostId,
    HostSpec, HostTls, ProxySpec, RedirectScheme, RedirectSpec, Upstream, UpstreamScheme,
};
use serde::Deserialize;
use thiserror::Error;

/// An imported native host plus the non-fatal differences the caller must know about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    pub host: Host,
    pub warnings: Vec<String>,
}

/// Why an NPM payload could not be mapped without approximating.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("host payload id 0 must be greater than zero")]
    ZeroHostId,
    #[error("host {host_id}: invalid domain `{domain}`: {source}")]
    InvalidDomain {
        host_id: u64,
        domain: String,
        source: CoreError,
    },
    #[error("host {host_id}: invalid host: {source}")]
    InvalidHost { host_id: u64, source: CoreError },
    #[error("host {host_id}: unsupported forward_scheme `{scheme}`; expected {expected}")]
    UnsupportedScheme {
        host_id: u64,
        scheme: String,
        expected: &'static str,
    },
    #[error("host {host_id}: advanced_config is not supported by the native host model")]
    UnsupportedAdvancedConfig { host_id: u64 },
    #[error("host {host_id}: {count} location(s) are not supported by the native host model")]
    UnsupportedLocations { host_id: u64, count: usize },
    #[error(
        "host {host_id}: access_list_id {access_list_id} is not supported by the native host model"
    )]
    UnsupportedAccessList { host_id: u64, access_list_id: u64 },
    #[error("host {host_id}: certificate_id {certificate_id} has no supplied certificate origin")]
    MissingCertificateOrigin { host_id: u64, certificate_id: u64 },
    #[error(
        "host {host_id}: certificate_id {certificate_id} maps to origin `{origin}`, which cannot be selected by id"
    )]
    UnbindableCertificateOrigin {
        host_id: u64,
        certificate_id: u64,
        origin: CertificateOrigin,
    },
    #[error("host {host_id}: {flag} is set but certificate_id is 0; refusing to clear it")]
    TlsFlagWithoutCertificate { host_id: u64, flag: &'static str },
    #[error("NPM stream payloads are not supported by the native host model")]
    Unsupported,
}

/// NPM v2.16 proxy host payload. Only the fields needed for the native host mapping are declared;
/// unknown payload fields are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NpmProxyHost {
    pub id: u64,
    pub domain_names: Vec<String>,
    #[serde(deserialize_with = "serde_flag")]
    pub enabled: bool,
    pub forward_scheme: String,
    pub forward_host: String,
    pub forward_port: u16,
    pub access_list_id: u64,
    pub certificate_id: u64,
    #[serde(deserialize_with = "serde_flag")]
    pub ssl_forced: bool,
    #[serde(deserialize_with = "serde_flag")]
    pub hsts_enabled: bool,
    #[serde(deserialize_with = "serde_flag")]
    pub hsts_subdomains: bool,
    pub advanced_config: String,
    #[serde(deserialize_with = "deserialize_locations")]
    pub locations: Vec<serde_json::Value>,
    #[serde(deserialize_with = "serde_flag")]
    pub caching_enabled: bool,
    #[serde(deserialize_with = "serde_flag")]
    pub block_exploits: bool,
    #[serde(deserialize_with = "serde_flag")]
    pub allow_websocket_upgrade: bool,
    #[serde(deserialize_with = "serde_flag")]
    pub http2_support: bool,
}

/// NPM v2.16 redirection host payload. Only the fields needed for the native host mapping are
/// declared; unknown payload fields are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NpmRedirectionHost {
    pub id: u64,
    pub domain_names: Vec<String>,
    #[serde(deserialize_with = "serde_flag")]
    pub enabled: bool,
    pub forward_scheme: String,
    pub forward_domain_name: String,
    pub forward_http_code: u16,
    #[serde(deserialize_with = "serde_flag")]
    pub preserve_path: bool,
    pub certificate_id: u64,
    #[serde(deserialize_with = "serde_flag")]
    pub ssl_forced: bool,
    #[serde(deserialize_with = "serde_flag")]
    pub hsts_enabled: bool,
    #[serde(deserialize_with = "serde_flag")]
    pub hsts_subdomains: bool,
    pub advanced_config: String,
}

/// NPM v2.16 dead host payload. Only the fields needed for the native host mapping are declared;
/// unknown payload fields are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NpmDeadHost {
    pub id: u64,
    pub domain_names: Vec<String>,
    #[serde(deserialize_with = "serde_flag")]
    pub enabled: bool,
    pub certificate_id: u64,
    #[serde(deserialize_with = "serde_flag")]
    pub ssl_forced: bool,
    #[serde(deserialize_with = "serde_flag")]
    pub hsts_enabled: bool,
    #[serde(deserialize_with = "serde_flag")]
    pub hsts_subdomains: bool,
    pub advanced_config: String,
}

/// Map an NPM proxy host payload to a native proxy host.
///
/// `certificate_origins` supplies the origin for every non-zero `certificate_id` in the payload.
pub fn import_proxy(
    payload: &NpmProxyHost,
    certificate_origins: &BTreeMap<u64, CertificateOrigin>,
) -> Result<ImportOutcome, ImportError> {
    let id = map_host_id(payload.id)?;
    let domains = map_domains(payload.id, &payload.domain_names)?;
    reject_advanced_config(payload.id, &payload.advanced_config)?;
    reject_locations(payload.id, &payload.locations)?;
    if payload.access_list_id != 0 {
        return Err(ImportError::UnsupportedAccessList {
            host_id: payload.id,
            access_list_id: payload.access_list_id,
        });
    }
    let tls = map_tls(
        payload.id,
        payload.certificate_id,
        payload.ssl_forced,
        payload.hsts_enabled,
        payload.hsts_subdomains,
        certificate_origins,
    )?;
    let upstream = Upstream::new(
        proxy_scheme(payload.id, &payload.forward_scheme)?,
        payload.forward_host.clone(),
        payload.forward_port,
    );
    let mut proxy = ProxySpec::new(upstream);
    proxy.websocket = payload.allow_websocket_upgrade;
    proxy.preserve_host = true;

    finish(
        Host {
            id,
            domains,
            tls,
            enabled: payload.enabled,
            spec: HostSpec::Proxy(proxy),
        },
        proxy_warnings(payload),
    )
}

/// Map an NPM redirection host payload to a native redirect host.
pub fn import_redirection(
    payload: &NpmRedirectionHost,
    certificate_origins: &BTreeMap<u64, CertificateOrigin>,
) -> Result<ImportOutcome, ImportError> {
    let id = map_host_id(payload.id)?;
    let domains = map_domains(payload.id, &payload.domain_names)?;
    reject_advanced_config(payload.id, &payload.advanced_config)?;
    let tls = map_tls(
        payload.id,
        payload.certificate_id,
        payload.ssl_forced,
        payload.hsts_enabled,
        payload.hsts_subdomains,
        certificate_origins,
    )?;
    let spec = RedirectSpec {
        scheme: redirect_scheme(payload.id, &payload.forward_scheme)?,
        target: payload.forward_domain_name.clone(),
        status: payload.forward_http_code,
        preserve_path: payload.preserve_path,
    };

    finish(
        Host {
            id,
            domains,
            tls,
            enabled: payload.enabled,
            spec: HostSpec::Redirect(spec),
        },
        Vec::new(),
    )
}

/// Map an NPM dead host payload to a native dead host.
pub fn import_dead(
    payload: &NpmDeadHost,
    certificate_origins: &BTreeMap<u64, CertificateOrigin>,
) -> Result<ImportOutcome, ImportError> {
    let id = map_host_id(payload.id)?;
    let domains = map_domains(payload.id, &payload.domain_names)?;
    reject_advanced_config(payload.id, &payload.advanced_config)?;
    let tls = map_tls(
        payload.id,
        payload.certificate_id,
        payload.ssl_forced,
        payload.hsts_enabled,
        payload.hsts_subdomains,
        certificate_origins,
    )?;

    finish(
        Host {
            id,
            domains,
            tls,
            enabled: payload.enabled,
            spec: HostSpec::Dead(DeadSpec),
        },
        Vec::new(),
    )
}

/// NPM stream hosts have no representation in the native host model; this always fails.
pub fn import_stream(_payload: &serde_json::Value) -> Result<ImportOutcome, ImportError> {
    Err(ImportError::Unsupported)
}

fn map_host_id(id: u64) -> Result<HostId, ImportError> {
    HostId::new(id).map_err(|_| ImportError::ZeroHostId)
}

fn map_domains(host_id: u64, domain_names: &[String]) -> Result<Vec<String>, ImportError> {
    domain_names
        .iter()
        .map(|domain| {
            normalize_pattern(domain).map_err(|source| ImportError::InvalidDomain {
                host_id,
                domain: domain.clone(),
                source,
            })
        })
        .collect()
}

fn reject_advanced_config(host_id: u64, advanced_config: &str) -> Result<(), ImportError> {
    if advanced_config.trim().is_empty() {
        Ok(())
    } else {
        Err(ImportError::UnsupportedAdvancedConfig { host_id })
    }
}

fn reject_locations(host_id: u64, locations: &[serde_json::Value]) -> Result<(), ImportError> {
    if locations.is_empty() {
        Ok(())
    } else {
        Err(ImportError::UnsupportedLocations {
            host_id,
            count: locations.len(),
        })
    }
}

fn map_tls(
    host_id: u64,
    certificate_id: u64,
    ssl_forced: bool,
    hsts_enabled: bool,
    hsts_subdomains: bool,
    certificate_origins: &BTreeMap<u64, CertificateOrigin>,
) -> Result<HostTls, ImportError> {
    if certificate_id == 0 {
        for (flag, set) in [
            ("ssl_forced", ssl_forced),
            ("hsts_enabled", hsts_enabled),
            ("hsts_subdomains", hsts_subdomains),
        ] {
            if set {
                return Err(ImportError::TlsFlagWithoutCertificate { host_id, flag });
            }
        }
        return Ok(HostTls::disabled());
    }

    let origin = certificate_origins.get(&certificate_id).copied().ok_or(
        ImportError::MissingCertificateOrigin {
            host_id,
            certificate_id,
        },
    )?;
    if !origin.bindable_by_id() {
        return Err(ImportError::UnbindableCertificateOrigin {
            host_id,
            certificate_id,
            origin,
        });
    }

    let mut tls = HostTls::for_explicit(CertificateId(certificate_id), origin);
    tls.ssl_forced = ssl_forced;
    tls.hsts_enabled = hsts_enabled;
    tls.hsts_subdomains = hsts_subdomains;
    Ok(tls)
}

fn proxy_scheme(host_id: u64, scheme: &str) -> Result<UpstreamScheme, ImportError> {
    match scheme.trim().to_ascii_lowercase().as_str() {
        "http" => Ok(UpstreamScheme::Http),
        "https" => Ok(UpstreamScheme::Https),
        _ => Err(ImportError::UnsupportedScheme {
            host_id,
            scheme: scheme.to_string(),
            expected: "http or https",
        }),
    }
}

fn redirect_scheme(host_id: u64, scheme: &str) -> Result<RedirectScheme, ImportError> {
    match scheme.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(RedirectScheme::Auto),
        "http" => Ok(RedirectScheme::Http),
        "https" => Ok(RedirectScheme::Https),
        _ => Err(ImportError::UnsupportedScheme {
            host_id,
            scheme: scheme.to_string(),
            expected: "auto, http or https",
        }),
    }
}

fn proxy_warnings(payload: &NpmProxyHost) -> Vec<String> {
    let mut warnings = Vec::new();
    if payload.caching_enabled {
        warnings.push(format!(
            "host {}: caching_enabled is not implemented by the native compiler; the flag is not applied",
            payload.id
        ));
    }
    if payload.block_exploits {
        warnings.push(format!(
            "host {}: block_exploits is not implemented by the native compiler; the flag is not applied",
            payload.id
        ));
    }
    if payload.http2_support {
        warnings.push(format!(
            "host {}: http2_support is a listener-level setting; the host route compiler does not apply it",
            payload.id
        ));
    }
    if payload.allow_websocket_upgrade {
        warnings.push(format!(
            "host {}: allow_websocket_upgrade is declared; Caddy proxies WebSocket upgrades natively so route output is unchanged",
            payload.id
        ));
    }
    warnings
}

fn finish(host: Host, warnings: Vec<String>) -> Result<ImportOutcome, ImportError> {
    let host_id = host.id.0;
    host.validate_structure()
        .map_err(|source| ImportError::InvalidHost { host_id, source })?;
    Ok(ImportOutcome { host, warnings })
}

/// NPM serializes tinyint flags as `0`/`1` in API payloads; accept real booleans as well.
fn serde_flag<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WireFlag {
        Bool(bool),
        Integer(i64),
    }

    match WireFlag::deserialize(deserializer)? {
        WireFlag::Bool(value) => Ok(value),
        WireFlag::Integer(0) => Ok(false),
        WireFlag::Integer(1) => Ok(true),
        WireFlag::Integer(value) => Err(serde::de::Error::custom(format!(
            "expected a boolean or a 0/1 flag, got {value}"
        ))),
    }
}

/// NPM's API returns `locations` as an array, while a database snapshot can carry it as a JSON
/// text column. Both forms are accepted; anything non-empty is rejected by the importer.
fn deserialize_locations<'de, D>(deserializer: D) -> Result<Vec<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(values)) => Ok(values),
        Some(serde_json::Value::String(raw)) if raw.trim().is_empty() => Ok(Vec::new()),
        Some(serde_json::Value::String(raw)) => match serde_json::from_str(raw.trim()) {
            Ok(serde_json::Value::Array(values)) => Ok(values),
            _ => Ok(vec![serde_json::Value::String(raw)]),
        },
        Some(other) => Ok(vec![other]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn origins(entries: &[(u64, CertificateOrigin)]) -> BTreeMap<u64, CertificateOrigin> {
        entries.iter().copied().collect()
    }

    fn proxy(payload: &str) -> NpmProxyHost {
        serde_json::from_str(payload).expect("valid proxy fixture")
    }

    fn redirection(payload: &str) -> NpmRedirectionHost {
        serde_json::from_str(payload).expect("valid redirection fixture")
    }

    fn dead(payload: &str) -> NpmDeadHost {
        serde_json::from_str(payload).expect("valid dead fixture")
    }

    #[test]
    fn imports_basic_proxy_host() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["Example.COM.", "*.Wild.Example.com"],
                "enabled": 1,
                "forward_scheme": "http",
                "forward_host": "10.0.0.5",
                "forward_port": 8080,
                "access_list_id": 0,
                "certificate_id": 0,
                "ssl_forced": 0,
                "hsts_enabled": 0,
                "hsts_subdomains": 0,
                "advanced_config": "",
                "locations": [],
                "caching_enabled": 0,
                "block_exploits": 0,
                "allow_websocket_upgrade": 0,
                "http2_support": 0,
                "meta": {"notes": "ignored"},
                "owner_user_id": 1
            }"#,
        );

        let outcome = import_proxy(&payload, &BTreeMap::new()).expect("proxy imports");

        assert_eq!(outcome.host.id, HostId(7));
        assert_eq!(
            outcome.host.domains,
            vec!["example.com".to_string(), "*.wild.example.com".to_string()]
        );
        assert!(outcome.host.enabled);
        assert_eq!(outcome.host.tls, HostTls::disabled());
        assert_eq!(
            outcome.host.spec,
            HostSpec::Proxy(ProxySpec {
                upstream: Upstream::new(UpstreamScheme::Http, "10.0.0.5", 8080),
                websocket: false,
                preserve_host: true,
            })
        );
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn imports_proxy_with_certificate_origin_and_flags() {
        let payload = proxy(
            r#"{
                "id": 12,
                "domain_names": ["secure.example.com"],
                "enabled": 1,
                "forward_scheme": "https",
                "forward_host": "backend.internal",
                "forward_port": 8443,
                "certificate_id": 42,
                "ssl_forced": 1,
                "hsts_enabled": 1,
                "hsts_subdomains": 0,
                "advanced_config": "",
                "locations": []
            }"#,
        );
        let origins = origins(&[(42, CertificateOrigin::Manual)]);

        let outcome = import_proxy(&payload, &origins).expect("proxy imports");

        assert_eq!(
            outcome.host.tls,
            HostTls {
                mode: caddy_rs_pm_core::TlsMode::Manual,
                certificate_id: Some(CertificateId(42)),
                auto_policy_id: None,
                ssl_forced: true,
                hsts_enabled: true,
                hsts_subdomains: false,
            }
        );
        assert_eq!(
            outcome.host.spec,
            HostSpec::Proxy(ProxySpec {
                upstream: Upstream::new(UpstreamScheme::Https, "backend.internal", 8443),
                websocket: false,
                preserve_host: true,
            })
        );
    }

    #[test]
    fn preserves_disabled_ssl_and_hsts_flags_with_a_certificate() {
        let payload = proxy(
            r#"{
                "id": 13,
                "domain_names": ["plain.example.com"],
                "enabled": 1,
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 80,
                "certificate_id": 42,
                "ssl_forced": 0,
                "hsts_enabled": 0,
                "hsts_subdomains": 0,
                "advanced_config": "",
                "locations": []
            }"#,
        );
        let origins = origins(&[(42, CertificateOrigin::AcmeConfigured)]);

        let outcome = import_proxy(&payload, &origins).expect("proxy imports");

        assert_eq!(
            outcome.host.tls.mode,
            caddy_rs_pm_core::TlsMode::AcmeConfigured
        );
        assert_eq!(outcome.host.tls.certificate_id, Some(CertificateId(42)));
        assert!(!outcome.host.tls.ssl_forced);
        assert!(!outcome.host.tls.hsts_enabled);
        assert!(!outcome.host.tls.hsts_subdomains);
    }

    #[test]
    fn missing_certificate_origin_is_a_located_error() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["secure.example.com"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 80,
                "certificate_id": 99
            }"#,
        );

        let error = import_proxy(&payload, &BTreeMap::new()).unwrap_err();

        assert_eq!(
            error,
            ImportError::MissingCertificateOrigin {
                host_id: 7,
                certificate_id: 99
            }
        );
        assert!(error.to_string().contains("host 7"));
        assert!(error.to_string().contains("certificate_id 99"));
    }

    #[test]
    fn auto_generated_origin_cannot_be_bound_by_id() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["secure.example.com"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 80,
                "certificate_id": 3,
                "ssl_forced": 1
            }"#,
        );
        let origins = origins(&[(3, CertificateOrigin::AutoGenerated)]);

        let error = import_proxy(&payload, &origins).unwrap_err();

        assert_eq!(
            error,
            ImportError::UnbindableCertificateOrigin {
                host_id: 7,
                certificate_id: 3,
                origin: CertificateOrigin::AutoGenerated,
            }
        );
    }

    #[test]
    fn rejects_advanced_config() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["advanced.example.com"],
                "advanced_config": "{\"headers\": {\"X-Test\": [\"1\"]}}"
            }"#,
        );

        let error = import_proxy(&payload, &BTreeMap::new()).unwrap_err();

        assert_eq!(error, ImportError::UnsupportedAdvancedConfig { host_id: 7 });
        assert!(error.to_string().contains("advanced_config"));
    }

    #[test]
    fn rejects_locations() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["locations.example.com"],
                "locations": [
                    {"path": "/api", "forward_scheme": "http", "forward_host": "api", "forward_port": 8080},
                    {"path": "/static", "forward_scheme": "http", "forward_host": "static", "forward_port": 8081}
                ]
            }"#,
        );

        let error = import_proxy(&payload, &BTreeMap::new()).unwrap_err();

        assert_eq!(
            error,
            ImportError::UnsupportedLocations {
                host_id: 7,
                count: 2
            }
        );
        assert!(error.to_string().contains("2 location(s)"));
    }

    #[test]
    fn accepts_empty_json_text_locations() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["locations.example.com"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 80,
                "locations": "[]"
            }"#,
        );

        let outcome = import_proxy(&payload, &BTreeMap::new()).expect("proxy imports");

        assert!(!outcome.host.domains.is_empty());
    }

    #[test]
    fn rejects_access_list() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["acl.example.com"],
                "access_list_id": 4
            }"#,
        );

        let error = import_proxy(&payload, &BTreeMap::new()).unwrap_err();

        assert_eq!(
            error,
            ImportError::UnsupportedAccessList {
                host_id: 7,
                access_list_id: 4
            }
        );
        assert!(error.to_string().contains("access_list_id 4"));
    }

    #[test]
    fn ssl_forced_without_a_certificate_is_rejected() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["nossl.example.com"],
                "certificate_id": 0,
                "ssl_forced": 1
            }"#,
        );

        let error = import_proxy(&payload, &BTreeMap::new()).unwrap_err();

        assert_eq!(
            error,
            ImportError::TlsFlagWithoutCertificate {
                host_id: 7,
                flag: "ssl_forced"
            }
        );
        assert!(error.to_string().contains("refusing to clear"));
    }

    #[test]
    fn hsts_without_a_certificate_is_rejected() {
        for (field, flag) in [
            ("hsts_enabled", "hsts_enabled"),
            ("hsts_subdomains", "hsts_subdomains"),
        ] {
            let payload = proxy(&format!(
                r#"{{
                    "id": 7,
                    "domain_names": ["nossl.example.com"],
                    "certificate_id": 0,
                    "ssl_forced": 0,
                    "{field}": 1
                }}"#
            ));

            assert_eq!(
                import_proxy(&payload, &BTreeMap::new()).unwrap_err(),
                ImportError::TlsFlagWithoutCertificate { host_id: 7, flag }
            );
        }
    }

    #[test]
    fn imports_redirection_host() {
        let payload = redirection(
            r#"{
                "id": 8,
                "domain_names": ["Old.Example.COM."],
                "enabled": 1,
                "forward_scheme": "auto",
                "forward_domain_name": "new.example.com",
                "forward_http_code": 301,
                "preserve_path": 1,
                "certificate_id": 0,
                "ssl_forced": 0,
                "hsts_enabled": 0,
                "hsts_subdomains": 0,
                "advanced_config": "",
                "meta": {"ignored": true}
            }"#,
        );

        let outcome = import_redirection(&payload, &BTreeMap::new()).expect("redirect imports");

        assert_eq!(outcome.host.id, HostId(8));
        assert_eq!(outcome.host.domains, vec!["old.example.com".to_string()]);
        assert!(outcome.host.enabled);
        assert_eq!(outcome.host.tls, HostTls::disabled());
        assert_eq!(
            outcome.host.spec,
            HostSpec::Redirect(RedirectSpec {
                scheme: RedirectScheme::Auto,
                target: "new.example.com".to_string(),
                status: 301,
                preserve_path: true,
            })
        );
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn maps_redirection_schemes() {
        for (wire, expected) in [
            ("auto", RedirectScheme::Auto),
            ("http", RedirectScheme::Http),
            ("https", RedirectScheme::Https),
        ] {
            let payload: NpmRedirectionHost = serde_json::from_value(json!({
                "id": 8,
                "domain_names": ["old.example.com"],
                "enabled": 1,
                "forward_scheme": wire,
                "forward_domain_name": "new.example.com",
                "forward_http_code": 308,
                "preserve_path": 0
            }))
            .expect("valid redirection fixture");

            let spec = import_redirection(&payload, &BTreeMap::new())
                .expect("redirect imports")
                .host
                .spec;
            let HostSpec::Redirect(spec) = spec else {
                panic!("expected a redirect spec");
            };
            assert_eq!(spec.scheme, expected);
            assert_eq!(spec.status, 308);
            assert!(!spec.preserve_path);
        }
    }

    #[test]
    fn invalid_redirection_status_is_validated_by_core() {
        let payload = redirection(
            r#"{
                "id": 8,
                "domain_names": ["old.example.com"],
                "forward_scheme": "http",
                "forward_domain_name": "new.example.com",
                "forward_http_code": 418
            }"#,
        );

        let error = import_redirection(&payload, &BTreeMap::new()).unwrap_err();

        assert!(matches!(error, ImportError::InvalidHost { host_id: 8, .. }));
        assert!(error.to_string().contains("redirect status 418"));
    }

    #[test]
    fn imports_dead_host() {
        let payload = dead(
            r#"{
                "id": 9,
                "domain_names": ["dead.example.com"],
                "enabled": 0,
                "certificate_id": 0,
                "ssl_forced": 0,
                "hsts_enabled": 0,
                "hsts_subdomains": 0,
                "advanced_config": "",
                "meta": {"ignored": true}
            }"#,
        );

        let outcome = import_dead(&payload, &BTreeMap::new()).expect("dead imports");

        assert_eq!(outcome.host.id, HostId(9));
        assert_eq!(outcome.host.domains, vec!["dead.example.com".to_string()]);
        assert!(!outcome.host.enabled);
        assert_eq!(outcome.host.tls, HostTls::disabled());
        assert_eq!(outcome.host.spec, HostSpec::Dead(DeadSpec));
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn rejects_stream_payloads() {
        let error = import_stream(&json!({
            "id": 10,
            "domain_names": ["stream.example.com"],
            "forward_host": "127.0.0.1",
            "forward_port": 5432
        }))
        .unwrap_err();

        assert_eq!(error, ImportError::Unsupported);
        assert!(error.to_string().contains("stream"));
    }

    #[test]
    fn warns_for_flags_without_native_implementation() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["flags.example.com"],
                "enabled": 1,
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 80,
                "certificate_id": 0,
                "ssl_forced": 0,
                "hsts_enabled": 0,
                "hsts_subdomains": 0,
                "advanced_config": "",
                "locations": [],
                "caching_enabled": 1,
                "block_exploits": 1,
                "allow_websocket_upgrade": 1,
                "http2_support": 1
            }"#,
        );

        let outcome = import_proxy(&payload, &BTreeMap::new()).expect("proxy imports");

        assert_eq!(
            outcome.warnings,
            vec![
                "host 7: caching_enabled is not implemented by the native compiler; the flag is not applied".to_string(),
                "host 7: block_exploits is not implemented by the native compiler; the flag is not applied".to_string(),
                "host 7: http2_support is a listener-level setting; the host route compiler does not apply it".to_string(),
                "host 7: allow_websocket_upgrade is declared; Caddy proxies WebSocket upgrades natively so route output is unchanged".to_string(),
            ]
        );
        assert!(
            outcome.host.spec
                == HostSpec::Proxy(ProxySpec {
                    upstream: Upstream::new(UpstreamScheme::Http, "backend", 80),
                    websocket: true,
                    preserve_host: true,
                })
        );
    }

    #[test]
    fn rejects_host_id_zero() {
        let payload = proxy(
            r#"{
                "id": 0,
                "domain_names": ["zero.example.com"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 80
            }"#,
        );

        let error = import_proxy(&payload, &BTreeMap::new()).unwrap_err();

        assert_eq!(error, ImportError::ZeroHostId);
        assert_eq!(
            error.to_string(),
            "host payload id 0 must be greater than zero"
        );
    }

    #[test]
    fn rejects_invalid_proxy_scheme() {
        let payload = proxy(
            r#"{
                "id": 7,
                "domain_names": ["scheme.example.com"],
                "forward_scheme": "ftp",
                "forward_host": "backend",
                "forward_port": 21
            }"#,
        );

        let error = import_proxy(&payload, &BTreeMap::new()).unwrap_err();

        assert_eq!(
            error,
            ImportError::UnsupportedScheme {
                host_id: 7,
                scheme: "ftp".to_string(),
                expected: "http or https"
            }
        );
    }
}
