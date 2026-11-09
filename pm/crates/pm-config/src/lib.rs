//! Deterministic Caddy JSON assembly for the proxy-manager route layer.
//!
//! [`assemble`] takes the ordered route lists produced by
//! [`compile_routes`](caddy_rs_pm_compiler::compile_routes) and wraps them in a complete
//! `apps.http` configuration with one HTTP server (`pm_http`) and one HTTPS server (`pm_https`).
//! [`assemble_from_hosts`] is the convenience entry point that compiles a host list first.
//!
//! The assembler is deliberately narrow for this slice. It does not emit:
//!
//! * certificate deployment/apply calls (the output is config, not an applied config);
//! * logging, access lists or request authentication;
//! * an admin apply step.
//!
//! [`assemble_with_tls_and_certificates`] additionally emits
//! `apps.tls.certificates.load_files` for stored manual certificates and matching
//! `apps.http.servers.pm_https.tls_connection_policies` entries. It only writes file paths; the
//! output never contains private-key bytes. Manual keys stay in the proxy manager's secret store,
//! and auto/ACME keys never enter it.
//!
//! The route layer stays separate so listeners and TLS policy can be added without changing host
//! compilation semantics.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use caddy_rs_pm_compiler::{compile_routes, CompileError, CompiledRoutes};
use caddy_rs_pm_core::{
    normalize_pattern, AcmeChallenge, AutoCertificatePolicy, AutoMode, CoreError, Host, TlsMode,
};
use serde_json::{json, Map, Value};
use thiserror::Error;

/// Default plaintext HTTP listener port.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// Default HTTPS listener port.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// Listener ports used by the assembled Caddy configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigSettings {
    /// Port for the `pm_http` server; also written to `apps.http.http_port`.
    pub http_port: u16,
    /// Port for the `pm_https` server; also written to `apps.http.https_port`.
    pub https_port: u16,
}

impl Default for ConfigSettings {
    fn default() -> Self {
        Self {
            http_port: DEFAULT_HTTP_PORT,
            https_port: DEFAULT_HTTPS_PORT,
        }
    }
}

impl ConfigSettings {
    pub fn new(http_port: u16, https_port: u16) -> Self {
        Self {
            http_port,
            https_port,
        }
    }
}

/// Files and names for one stored manual certificate, as seen by the config assembler.
///
/// Paths are absolute paths to files in the PM secret store. The type carries no key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateFiles {
    /// Numeric manual certificate id; used for the Caddy tag `pm-cert-<id>`.
    pub id: u64,
    /// Every DNS name the certificate covers.
    pub domains: Vec<String>,
    /// Absolute path to the PEM certificate chain.
    pub certificate: PathBuf,
    /// Absolute path to the PEM private key.
    pub key: PathBuf,
}

/// A failed configuration assembly.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The host list could not be compiled into routes.
    #[error(transparent)]
    Compile(#[from] CompileError),
    /// An enabled policy selected DNS-01, which needs DNS provider credentials this slice does
    /// not store. No partial policy is emitted.
    #[error(
        "auto-certificate policy {policy_id} selects the dns01 challenge for subjects {subjects:?}, \
         but no DNS provider credentials are stored in this slice"
    )]
    UnsupportedDnsChallenge {
        policy_id: u64,
        subjects: Vec<String>,
    },
    /// An enabled policy named an issuer that has no deterministic core module mapping.
    #[error(
        "auto-certificate policy {policy_id} uses unsupported issuer `{issuer}`; expected \
         letsencrypt, zerossl or internal"
    )]
    UnsupportedIssuer { policy_id: u64, issuer: String },
    /// A stored policy contains a subject that is not a valid DNS pattern.
    #[error("auto-certificate policy {policy_id} has an invalid subject `{subject}`: {reason}")]
    InvalidPolicySubject {
        policy_id: u64,
        subject: String,
        reason: String,
    },
    /// A stored policy is structurally invalid (for example a wildcard subject with HTTP-01).
    #[error("auto-certificate policy {policy_id} is invalid: {source}")]
    InvalidPolicy {
        policy_id: u64,
        #[source]
        source: CoreError,
    },
    /// Core on-demand issuance is not implemented; silently emitting an eager policy would change
    /// the stored intent, so only `Eager` is accepted.
    #[error(
        "auto-certificate policy {policy_id} uses the on-demand mode, which this assembler does \
         not implement; store an eager policy instead"
    )]
    UnsupportedMode { policy_id: u64 },
    /// A stored manual certificate has an unusable id, domain or file path.
    #[error("manual certificate {certificate_id} cannot be assembled: {reason}")]
    InvalidCertificate { certificate_id: u64, reason: String },
}

/// Assemble compiled routes into a complete Caddy configuration value.
///
/// HTTP routes are placed on `pm_http` and HTTPS routes on `pm_https` in the input order.
/// `pm_http` disables Caddy's automatic HTTPS redirects so host-level redirects stay authoritative.
/// The configured ports are written both to `http_port`/`https_port` and to the server `listen`
/// addresses. Object key ordering is deterministic for `serde_json`'s default map, and route order
/// is never rewritten.
pub fn assemble(compiled: &CompiledRoutes, settings: &ConfigSettings) -> Value {
    json!({
        "apps": {
            "http": {
                "http_port": settings.http_port,
                "https_port": settings.https_port,
                "servers": {
                    "pm_http": {
                        "listen": [format!(":{}", settings.http_port)],
                        "automatic_https": { "disable_redirects": true },
                        "routes": &compiled.http
                    },
                    "pm_https": {
                        "listen": [format!(":{}", settings.https_port)],
                        "routes": &compiled.https
                    }
                }
            }
        }
    })
}

/// Compile a host list and assemble the resulting configuration.
///
/// Invalid hosts are rejected by the compiler before any configuration is produced; the error is
/// reported as [`ConfigError::Compile`].
pub fn assemble_from_hosts(
    hosts: &[Host],
    settings: &ConfigSettings,
) -> Result<Value, ConfigError> {
    let compiled = compile_routes(hosts)?;
    Ok(assemble(&compiled, settings))
}

/// Compile hosts and assemble routes **and** `apps.tls` certificate automation.
///
/// This is the policy-aware entry point. [`assemble`] and [`assemble_from_hosts`] keep emitting
/// the route-only configuration they always have; only callers that pass policies get a TLS app.
///
/// Enabled policies are compiled in id order:
///
/// * `apps.tls.certificates.automate` is the sorted union of their subjects;
/// * `apps.tls.automation.policies[i]` carries the subjects, optional `key_type` and
///   `renewal_window_ratio`, and one issuer module;
/// * `apps.http.servers.*.automatic_https.skip` lists the domains of hosts whose TLS mode is not
///   `Auto` (Disabled, Manual, ACME-configured or Internal-CA) and that no enabled policy
///   automates, so an explicit certificate is never silently duplicated by automatic issuance.
///
/// Issuer mapping is deterministic: `letsencrypt` and `zerossl` become ACME issuers with their
/// public directory URLs, and `internal` becomes Caddy's internal issuer. A missing issuer means
/// the PM default, Let's Encrypt.
///
/// DNS-01 is rejected with [`ConfigError::UnsupportedDnsChallenge`] because this slice stores no
/// DNS provider credentials; the assembler never emits a half-configured DNS policy.
pub fn assemble_with_tls(
    hosts: &[Host],
    policies: &[AutoCertificatePolicy],
    settings: &ConfigSettings,
) -> Result<Value, ConfigError> {
    let compiled = compile_routes(hosts)?;
    assemble_routes_with_tls(&compiled, hosts, policies, settings)
}

/// Compile hosts and assemble routes, certificate automation **and** manual certificate loaders.
///
/// This is the full config entry point for the manual-certificate slice. It calls
/// [`assemble_with_tls`] first, then adds:
///
/// * `apps.tls.certificates.load_files`, one `{certificate, key, tags}` object per stored manual
///   certificate in numeric id order;
/// * `apps.http.servers.pm_https.tls_connection_policies`, one SNI/tag policy per certificate plus
///   a final empty default policy.
///
/// No Caddy admin API is called. `load_files` references the files written by
/// [`caddy_rs_pm_certificates::CertificateRepository`]; the config itself is deterministic and
/// contains no private-key material.
pub fn assemble_with_tls_and_certificates(
    hosts: &[Host],
    policies: &[AutoCertificatePolicy],
    certificates: &[CertificateFiles],
    settings: &ConfigSettings,
) -> Result<Value, ConfigError> {
    let compiled = compile_routes(hosts)?;
    assemble_routes_with_tls_and_certificates(&compiled, hosts, policies, certificates, settings)
}

/// Assemble already-compiled routes plus certificate automation.
///
/// See [`assemble_with_tls`] for the emitted shape. A caller that has compiled routes for a
/// different host list is responsible for passing the matching `hosts`.
pub fn assemble_routes_with_tls(
    compiled: &CompiledRoutes,
    hosts: &[Host],
    policies: &[AutoCertificatePolicy],
    settings: &ConfigSettings,
) -> Result<Value, ConfigError> {
    let mut config = assemble(compiled, settings);

    let mut enabled: Vec<&AutoCertificatePolicy> =
        policies.iter().filter(|policy| policy.enabled).collect();
    enabled.sort_by_key(|policy| policy.id.0);

    apply_automatic_https_skip(&mut config, hosts, &enabled);

    if !enabled.is_empty() {
        let mut automate = BTreeSet::new();
        let mut compiled_policies = Vec::with_capacity(enabled.len());
        for policy in &enabled {
            for subject in &policy.subjects {
                automate.insert(normalize_subject(policy.id.0, subject)?);
            }
            compiled_policies.push(automation_policy(policy)?);
        }

        config["apps"]["tls"] = json!({
            "certificates": {
                "automate": automate.into_iter().collect::<Vec<_>>()
            },
            "automation": {
                "policies": compiled_policies
            }
        });
    }

    Ok(config)
}

/// Assemble compiled routes, automation and manual certificate loaders.
///
/// See [`assemble_with_tls_and_certificates`]. Entries are sorted by certificate id and their SNI
/// lists are sorted and deduplicated, so equal inputs always produce byte-identical JSON.
pub fn assemble_routes_with_tls_and_certificates(
    compiled: &CompiledRoutes,
    hosts: &[Host],
    policies: &[AutoCertificatePolicy],
    certificates: &[CertificateFiles],
    settings: &ConfigSettings,
) -> Result<Value, ConfigError> {
    let mut config = assemble_routes_with_tls(compiled, hosts, policies, settings)?;
    if certificates.is_empty() {
        return Ok(config);
    }

    let mut sorted: Vec<&CertificateFiles> = certificates.iter().collect();
    sorted.sort_by_key(|certificate| certificate.id);

    let mut load_files = Vec::with_capacity(sorted.len());
    let mut connection_policies = Vec::with_capacity(sorted.len() + 1);
    for certificate in sorted {
        if certificate.id == 0 {
            return Err(ConfigError::InvalidCertificate {
                certificate_id: 0,
                reason: "certificate id must be greater than zero".to_string(),
            });
        }
        let certificate_path =
            certificate
                .certificate
                .to_str()
                .ok_or_else(|| ConfigError::InvalidCertificate {
                    certificate_id: certificate.id,
                    reason: "certificate path is not valid UTF-8".to_string(),
                })?;
        let key_path = certificate
            .key
            .to_str()
            .ok_or_else(|| ConfigError::InvalidCertificate {
                certificate_id: certificate.id,
                reason: "private-key path is not valid UTF-8".to_string(),
            })?;
        let mut domains = BTreeSet::new();
        for domain in &certificate.domains {
            let normalized =
                normalize_pattern(domain).map_err(|error| ConfigError::InvalidCertificate {
                    certificate_id: certificate.id,
                    reason: format!("invalid domain `{domain}`: {error}"),
                })?;
            domains.insert(normalized);
        }
        if domains.is_empty() {
            return Err(ConfigError::InvalidCertificate {
                certificate_id: certificate.id,
                reason: "certificate has no DNS names".to_string(),
            });
        }
        let tag = format!("pm-cert-{}", certificate.id);
        load_files.push(json!({
            "certificate": certificate_path,
            "key": key_path,
            "tags": [tag]
        }));
        connection_policies.push(json!({
            "match": { "sni": domains.into_iter().collect::<Vec<_>>() },
            "certificate_selection": { "any_tag": [tag] }
        }));
    }
    // Keep a default policy for SNI that is served by automation rather than a manual cert.
    connection_policies.push(json!({}));

    let tls = config["apps"]
        .as_object_mut()
        .ok_or_else(|| ConfigError::InvalidCertificate {
            certificate_id: 0,
            reason: "assembled config has no apps object".to_string(),
        })?
        .entry("tls")
        .or_insert_with(|| json!({}));
    tls["certificates"]["load_files"] = Value::Array(load_files);
    config["apps"]["http"]["servers"]["pm_https"]["tls_connection_policies"] =
        Value::Array(connection_policies);
    Ok(config)
}

fn apply_automatic_https_skip(
    config: &mut Value,
    hosts: &[Host],
    enabled: &[&AutoCertificatePolicy],
) {
    let mut skip = BTreeSet::new();
    for host in hosts {
        // `Disabled` is the documented case. Explicit modes are skipped unless a policy covers
        // them: a manual certificate may be loaded, and Caddy must not auto-issue a second
        // certificate for the same name. `Auto` hosts are left alone: their policy is the
        // issuance authority.
        if host.tls.mode == TlsMode::Auto {
            continue;
        }
        for domain in &host.domains {
            if enabled.iter().any(|policy| policy.matches(domain)) {
                continue;
            }
            skip.insert(domain.clone());
        }
    }
    if skip.is_empty() {
        return;
    }
    let skip: Vec<String> = skip.into_iter().collect();
    for server in ["pm_http", "pm_https"] {
        let Some(server) = config["apps"]["http"]["servers"]
            .get_mut(server)
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let automatic_https = server.entry("automatic_https").or_insert_with(|| json!({}));
        automatic_https["skip"] = json!(skip);
    }
}

fn automation_policy(policy: &AutoCertificatePolicy) -> Result<Value, ConfigError> {
    // The assembler is public and can be called with policies that were never stored through
    // `PolicyRepository`, so it must enforce the same structural rules as the repository rather
    // than emitting an invalid wildcard/HTTP-01 combination.
    policy
        .validate()
        .map_err(|source| ConfigError::InvalidPolicy {
            policy_id: policy.id.0,
            source,
        })?;
    if policy.mode != AutoMode::Eager {
        return Err(ConfigError::UnsupportedMode {
            policy_id: policy.id.0,
        });
    }
    let subjects: Vec<String> = policy
        .subjects
        .iter()
        .map(|subject| normalize_subject(policy.id.0, subject))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect();

    if policy.challenge == AcmeChallenge::Dns01 {
        return Err(ConfigError::UnsupportedDnsChallenge {
            policy_id: policy.id.0,
            subjects,
        });
    }

    let issuer = issuer_module(policy)?;

    let mut object = Map::new();
    object.insert("subjects".to_string(), json!(subjects));
    if let Some(key_type) = policy.key_type {
        object.insert("key_type".to_string(), json!(key_type.as_str()));
    }
    if let Some(ratio) = policy.renewal_window_ratio {
        object.insert("renewal_window_ratio".to_string(), json!(ratio));
    }
    object.insert("issuers".to_string(), json!([issuer]));
    Ok(Value::Object(object))
}

fn normalize_subject(policy_id: u64, subject: &str) -> Result<String, ConfigError> {
    caddy_rs_pm_core::normalize_pattern(subject).map_err(|error| {
        ConfigError::InvalidPolicySubject {
            policy_id,
            subject: subject.to_string(),
            reason: error.to_string(),
        }
    })
}

const LETSENCRYPT_CA: &str = "https://acme-v02.api.letsencrypt.org/directory";
const ZEROSSL_CA: &str = "https://acme.zerossl.com/v2/DV90";

fn issuer_module(policy: &AutoCertificatePolicy) -> Result<Value, ConfigError> {
    let name = policy
        .issuer
        .as_deref()
        .unwrap_or("letsencrypt")
        .trim()
        .to_ascii_lowercase();
    match name.as_str() {
        "letsencrypt" => Ok(acme_issuer(LETSENCRYPT_CA, policy.challenge)),
        "zerossl" => Ok(acme_issuer(ZEROSSL_CA, policy.challenge)),
        "internal" => Ok(json!({ "module": "internal" })),
        _ => Err(ConfigError::UnsupportedIssuer {
            policy_id: policy.id.0,
            issuer: name,
        }),
    }
}

fn acme_issuer(ca: &str, challenge: AcmeChallenge) -> Value {
    let (http, tls_alpn, dns) = match challenge {
        AcmeChallenge::Http01 => (false, true, true),
        AcmeChallenge::TlsAlpn01 => (true, false, true),
        // Rejected by `automation_policy` before an issuer is built.
        AcmeChallenge::Dns01 => (true, true, false),
    };
    json!({
        "module": "acme",
        "ca": ca,
        "challenges": {
            "http": { "disabled": http },
            "tls-alpn": { "disabled": tls_alpn },
            "dns": { "disabled": dns }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_pm_compiler::CompiledRoutes;
    use caddy_rs_pm_core::{
        AcmeChallenge, AutoCertificatePolicy, AutoMode, CertificateId, CertificateOrigin, Host,
        HostId, HostSpec, HostTls, KeyType, PolicyId, ProxySpec, Upstream, UpstreamScheme,
    };
    use serde_json::json;

    fn proxy_host(id: u64, domains: &[&str], tls: HostTls) -> Host {
        Host::new(
            HostId(id),
            domains.iter().map(|value| value.to_string()).collect(),
            tls,
            HostSpec::Proxy(ProxySpec::new(Upstream::new(
                UpstreamScheme::Http,
                "10.0.0.5",
                8080,
            ))),
        )
    }

    fn tls_policy(
        id: u64,
        subjects: &[&str],
        issuer: &str,
        challenge: AcmeChallenge,
    ) -> AutoCertificatePolicy {
        AutoCertificatePolicy {
            id: PolicyId(id),
            name: format!("policy-{id}"),
            subjects: subjects.iter().map(|value| (*value).to_string()).collect(),
            mode: AutoMode::Eager,
            issuer: Some(issuer.to_string()),
            key_type: None,
            renewal_window_ratio: None,
            challenge,
            enabled: true,
        }
    }

    fn http01_challenges() -> Value {
        json!({
            "http": { "disabled": false },
            "tls-alpn": { "disabled": true },
            "dns": { "disabled": true }
        })
    }

    fn golden_proxy_route(id: u64, domain: &str) -> Value {
        json!({
            "@id": format!("pm-host-{id}-http"),
            "match": [{ "host": [domain] }],
            "handle": [{
                "handler": "reverse_proxy",
                "upstreams": [{ "dial": "10.0.0.5:8080" }]
            }]
        })
    }

    #[test]
    fn simple_proxy_matches_golden_json() {
        let hosts = vec![proxy_host(1, &["example.com"], HostTls::disabled())];
        let config = assemble_from_hosts(&hosts, &ConfigSettings::default()).expect("assemble");

        assert_eq!(
            config,
            json!({
                "apps": {
                    "http": {
                        "http_port": 80,
                        "https_port": 443,
                        "servers": {
                            "pm_http": {
                                "listen": [":80"],
                                "automatic_https": { "disable_redirects": true },
                                "routes": [golden_proxy_route(1, "example.com")]
                            },
                            "pm_https": {
                                "listen": [":443"],
                                "routes": []
                            }
                        }
                    }
                }
            })
        );
    }

    #[test]
    fn empty_routes_keep_both_servers_with_empty_arrays() {
        let config = assemble_from_hosts(&[], &ConfigSettings::default()).expect("assemble");

        assert_eq!(
            config,
            json!({
                "apps": {
                    "http": {
                        "http_port": 80,
                        "https_port": 443,
                        "servers": {
                            "pm_http": {
                                "listen": [":80"],
                                "automatic_https": { "disable_redirects": true },
                                "routes": []
                            },
                            "pm_https": {
                                "listen": [":443"],
                                "routes": []
                            }
                        }
                    }
                }
            })
        );
    }

    #[test]
    fn custom_ports_are_reflected_in_listen_and_port_fields() {
        let settings = ConfigSettings::new(8080, 8443);
        let config = assemble(
            &CompiledRoutes {
                http: Vec::new(),
                https: Vec::new(),
            },
            &settings,
        );

        assert_eq!(config["apps"]["http"]["http_port"], 8080);
        assert_eq!(config["apps"]["http"]["https_port"], 8443);
        assert_eq!(
            config["apps"]["http"]["servers"]["pm_http"]["listen"],
            json!([":8080"])
        );
        assert_eq!(
            config["apps"]["http"]["servers"]["pm_https"]["listen"],
            json!([":8443"])
        );
    }

    #[test]
    fn default_settings_are_80_and_443() {
        let settings = ConfigSettings::default();
        assert_eq!(settings.http_port, 80);
        assert_eq!(settings.https_port, 443);
    }

    #[test]
    fn tls_hosts_keep_http_and_https_routes_on_their_servers() {
        let host = proxy_host(2, &["secure.example.com"], HostTls::for_auto(PolicyId(4)));
        let config = assemble_from_hosts(&[host], &ConfigSettings::default()).expect("assemble");

        let pm_http = &config["apps"]["http"]["servers"]["pm_http"];
        let pm_https = &config["apps"]["http"]["servers"]["pm_https"];
        assert_eq!(pm_http["routes"][0]["handle"][0]["status_code"], 301);
        assert_eq!(
            pm_http["routes"][0]["handle"][0]["headers"]["Location"][0],
            "https://{http.request.host}{http.request.uri}"
        );
        assert_eq!(
            pm_https["routes"][0]["handle"][0]["handler"],
            "reverse_proxy"
        );
        assert_eq!(
            pm_https["routes"][0]["handle"][0]["upstreams"][0]["dial"],
            "10.0.0.5:8080"
        );
        assert!(config["apps"].get("tls").is_none());
    }

    #[test]
    fn routes_are_preserved_in_compiler_order() {
        let http_routes = vec![
            json!({ "@id": "first", "handle": [{ "handler": "static_response", "status_code": 404 }] }),
            json!({ "@id": "second", "handle": [{ "handler": "static_response", "status_code": 410 }] }),
        ];
        let https_routes = vec![json!({ "@id": "https-first" })];
        let compiled = CompiledRoutes {
            http: http_routes.clone(),
            https: https_routes.clone(),
        };

        let config = assemble(&compiled, &ConfigSettings::default());

        assert_eq!(
            config["apps"]["http"]["servers"]["pm_http"]["routes"],
            json!(http_routes)
        );
        assert_eq!(
            config["apps"]["http"]["servers"]["pm_https"]["routes"],
            json!(https_routes)
        );
    }

    #[test]
    fn compiler_order_is_kept_for_multiple_hosts() {
        let hosts = vec![
            proxy_host(11, &["b.example.com"], HostTls::disabled()),
            proxy_host(10, &["a.example.com"], HostTls::disabled()),
        ];
        let config = assemble_from_hosts(&hosts, &ConfigSettings::default()).expect("assemble");
        let routes = &config["apps"]["http"]["servers"]["pm_http"]["routes"];

        assert_eq!(routes[0]["@id"], "pm-host-10-http");
        assert_eq!(routes[1]["@id"], "pm-host-11-http");
        assert_eq!(routes[0]["match"][0]["host"][0], "a.example.com");
        assert_eq!(routes[1]["match"][0]["host"][0], "b.example.com");
    }

    #[test]
    fn assemble_from_hosts_propagates_compile_errors() {
        let first = proxy_host(1, &["same.example.com"], HostTls::disabled());
        let second = proxy_host(2, &["same.example.com"], HostTls::disabled());

        let error = assemble_from_hosts(&[first, second], &ConfigSettings::default())
            .expect_err("duplicate domains must fail");

        assert!(matches!(error, ConfigError::Compile(_)));
        assert!(error.to_string().contains("same.example.com"));
    }

    #[test]
    fn assembled_json_has_no_private_key_markers() {
        let host = Host::new(
            HostId(9),
            vec!["manual.example.com".to_string()],
            HostTls::for_explicit(CertificateId(7), CertificateOrigin::Manual),
            HostSpec::Proxy(ProxySpec::new(Upstream::new(
                UpstreamScheme::Https,
                "backend.internal",
                8443,
            ))),
        );
        let config = assemble_from_hosts(&[host], &ConfigSettings::default()).expect("assemble");
        let rendered = config.to_string();

        assert!(!rendered.contains("PRIVATE KEY"));
        assert!(!rendered.contains("BEGIN PRIVATE"));
        assert!(!rendered.to_ascii_lowercase().contains("private_key"));
    }

    #[test]
    fn letsencrypt_http01_emits_deterministic_tls_automation() {
        let policies = vec![tls_policy(
            3,
            &["example.com", "api.example.com"],
            "letsencrypt",
            AcmeChallenge::Http01,
        )];
        let config = assemble_with_tls(&[], &policies, &ConfigSettings::default())
            .expect("assemble TLS config");

        assert_eq!(
            config["apps"]["tls"],
            json!({
                "certificates": {
                    "automate": ["api.example.com", "example.com"]
                },
                "automation": {
                    "policies": [{
                        "subjects": ["api.example.com", "example.com"],
                        "issuers": [{
                            "module": "acme",
                            "ca": "https://acme-v02.api.letsencrypt.org/directory",
                            "challenges": http01_challenges()
                        }]
                    }]
                }
            })
        );
        assert_eq!(
            serde_json::to_string(&config).expect("serialize"),
            serde_json::to_string(
                &assemble_with_tls(&[], &policies, &ConfigSettings::default()).expect("assemble")
            )
            .expect("serialize")
        );
    }

    #[test]
    fn zerossl_issuer_uses_the_pm_adapter_ca() {
        let policies = vec![tls_policy(
            1,
            &["shop.example.com"],
            "zerossl",
            AcmeChallenge::Http01,
        )];
        let config = assemble_with_tls(&[], &policies, &ConfigSettings::default())
            .expect("assemble TLS config");

        assert_eq!(
            config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["ca"],
            "https://acme.zerossl.com/v2/DV90"
        );
    }

    #[test]
    fn internal_issuer_has_no_acme_challenge_object() {
        let policies = vec![tls_policy(
            1,
            &["internal.example.com"],
            "internal",
            AcmeChallenge::Http01,
        )];
        let config = assemble_with_tls(&[], &policies, &ConfigSettings::default())
            .expect("assemble TLS config");

        assert_eq!(
            config["apps"]["tls"]["automation"]["policies"][0]["issuers"],
            json!([{ "module": "internal" }])
        );
    }

    #[test]
    fn tls_alpn01_inverts_the_challenge_flags() {
        let policies = vec![tls_policy(
            1,
            &["alpn.example.com"],
            "letsencrypt",
            AcmeChallenge::TlsAlpn01,
        )];
        let config = assemble_with_tls(&[], &policies, &ConfigSettings::default())
            .expect("assemble TLS config");

        assert_eq!(
            config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["challenges"],
            json!({
                "http": { "disabled": true },
                "tls-alpn": { "disabled": false },
                "dns": { "disabled": true }
            })
        );
    }

    #[test]
    fn dns01_is_rejected_with_a_located_error_and_no_partial_config() {
        let policies = vec![tls_policy(
            9,
            &["*.example.com", "example.com"],
            "letsencrypt",
            AcmeChallenge::Dns01,
        )];
        let error = assemble_with_tls(&[], &policies, &ConfigSettings::default())
            .expect_err("dns01 has no provider credentials");

        match &error {
            ConfigError::UnsupportedDnsChallenge {
                policy_id,
                subjects,
            } => {
                assert_eq!(*policy_id, 9);
                assert_eq!(
                    subjects,
                    &vec!["*.example.com".to_string(), "example.com".to_string()]
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let rendered = error.to_string();
        assert!(rendered.contains("policy 9"), "{rendered}");
        assert!(rendered.contains("dns01"), "{rendered}");
    }

    #[test]
    fn unknown_issuer_is_a_located_error() {
        let policies = vec![tls_policy(
            4,
            &["example.com"],
            "corporate-acme",
            AcmeChallenge::Http01,
        )];
        let error = assemble_with_tls(&[], &policies, &ConfigSettings::default())
            .expect_err("unknown issuer");
        assert!(matches!(
            error,
            ConfigError::UnsupportedIssuer { policy_id: 4, .. }
        ));
        assert!(error.to_string().contains("corporate-acme"));
    }

    #[test]
    fn disabled_hosts_are_skipped_unless_an_enabled_policy_covers_them() {
        let host = proxy_host(1, &["plain.example.com"], HostTls::disabled());
        let config =
            assemble_with_tls(std::slice::from_ref(&host), &[], &ConfigSettings::default())
                .expect("assemble HTTP-only host");
        assert_eq!(
            config["apps"]["http"]["servers"]["pm_https"]["automatic_https"]["skip"],
            json!(["plain.example.com"])
        );
        assert_eq!(
            config["apps"]["http"]["servers"]["pm_http"]["automatic_https"]["skip"],
            json!(["plain.example.com"])
        );
        assert!(config["apps"].get("tls").is_none());

        let policies = vec![tls_policy(
            2,
            &["plain.example.com"],
            "letsencrypt",
            AcmeChallenge::Http01,
        )];
        let config = assemble_with_tls(&[host], &policies, &ConfigSettings::default())
            .expect("assemble covered HTTP-only host");
        assert!(
            config["apps"]["http"]["servers"]["pm_https"]["automatic_https"]
                .get("skip")
                .is_none()
        );
    }

    #[test]
    fn manual_and_acme_hosts_are_skipped_too_unless_a_policy_covers_them() {
        let manual = proxy_host(
            3,
            &["manual.example.com"],
            HostTls::for_explicit(CertificateId(7), CertificateOrigin::Manual),
        );
        let acme = proxy_host(
            4,
            &["acme.example.com"],
            HostTls::for_explicit(CertificateId(8), CertificateOrigin::AcmeConfigured),
        );
        let config = assemble_with_tls(&[manual, acme], &[], &ConfigSettings::default())
            .expect("assemble explicit-certificate hosts");
        assert_eq!(
            config["apps"]["http"]["servers"]["pm_https"]["automatic_https"]["skip"],
            json!(["acme.example.com", "manual.example.com"])
        );
    }

    #[test]
    fn tls_policies_follow_id_order_and_ignore_disabled_ones() {
        let mut disabled = tls_policy(
            1,
            &["disabled.example.com"],
            "letsencrypt",
            AcmeChallenge::Http01,
        );
        disabled.enabled = false;
        let policies = vec![
            tls_policy(9, &["nine.example.com"], "internal", AcmeChallenge::Http01),
            disabled,
            tls_policy(3, &["three.example.com"], "internal", AcmeChallenge::Http01),
        ];
        let config = assemble_with_tls(&[], &policies, &ConfigSettings::default())
            .expect("assemble TLS config");

        let entries = config["apps"]["tls"]["automation"]["policies"]
            .as_array()
            .expect("policies array");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["subjects"], json!(["three.example.com"]));
        assert_eq!(entries[1]["subjects"], json!(["nine.example.com"]));
        assert_eq!(
            config["apps"]["tls"]["certificates"]["automate"],
            json!(["nine.example.com", "three.example.com"])
        );
    }

    #[test]
    fn key_type_and_renewal_ratio_are_copied_when_present() {
        let mut policy = tls_policy(
            5,
            &["typed.example.com"],
            "letsencrypt",
            AcmeChallenge::Http01,
        );
        policy.key_type = Some(KeyType::P384);
        policy.renewal_window_ratio = Some(0.25);
        let config = assemble_with_tls(&[], &[policy], &ConfigSettings::default())
            .expect("assemble TLS config");

        let entry = &config["apps"]["tls"]["automation"]["policies"][0];
        assert_eq!(entry["key_type"], "p384");
        assert_eq!(entry["renewal_window_ratio"], 0.25);
    }

    #[test]
    fn direct_assembly_rejects_a_wildcard_with_http01() {
        // The repository rejects this combination, but the public assembler must not rely on
        // callers having validated first.
        let policy = tls_policy(
            7,
            &["*.wild.example.com"],
            "letsencrypt",
            AcmeChallenge::Http01,
        );
        let error = assemble_with_tls(&[], &[policy], &ConfigSettings::default())
            .expect_err("wildcard http01 must be rejected");
        assert!(matches!(
            error,
            ConfigError::InvalidPolicy { policy_id: 7, .. }
        ));
    }

    #[test]
    fn direct_assembly_rejects_on_demand_mode_instead_of_emitting_eager() {
        let mut policy = tls_policy(
            8,
            &["ondemand.example.com"],
            "letsencrypt",
            AcmeChallenge::Http01,
        );
        policy.mode = AutoMode::OnDemand;
        let error = assemble_with_tls(&[], &[policy], &ConfigSettings::default())
            .expect_err("on-demand is not implemented");
        assert!(matches!(
            error,
            ConfigError::UnsupportedMode { policy_id: 8 }
        ));
    }

    #[test]
    fn serialization_is_deterministic() {
        let hosts = vec![
            proxy_host(1, &["one.example.com"], HostTls::disabled()),
            proxy_host(2, &["two.example.com"], HostTls::disabled()),
        ];
        let settings = ConfigSettings::new(8080, 8443);

        let first = assemble_from_hosts(&hosts, &settings).expect("assemble");
        let second = assemble_from_hosts(&hosts, &settings).expect("assemble");

        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string(&first).expect("serialize"),
            serde_json::to_string(&second).expect("serialize")
        );
    }
}
