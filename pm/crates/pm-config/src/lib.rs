//! Deterministic Caddy JSON assembly for the proxy-manager route layer.
//!
//! [`assemble`] takes the ordered route lists produced by
//! [`compile_routes`](caddy_rs_pm_compiler::compile_routes) and wraps them in a complete
//! `apps.http` configuration with one HTTP server (`pm_http`) and one HTTPS server (`pm_https`).
//! [`assemble_from_hosts`] is the convenience entry point that compiles a host list first.
//!
//! The assembler is deliberately narrow for this slice. It does not emit:
//!
//! * `tls_connection_policies` or any `apps.tls` certificate automation/loader/storage;
//! * certificate deployment or management endpoints;
//! * logging, access lists or request authentication;
//! * an admin apply step.
//!
//! Those are later slices. Keeping the route layer separate means listeners and TLS policy can be
//! added without changing host compilation semantics.
//!
//! The output contains no private-key material; manual keys stay in the proxy manager's secret
//! store, and auto/ACME keys never enter it.

#![forbid(unsafe_code)]

use caddy_rs_pm_compiler::{compile_routes, CompileError, CompiledRoutes};
use caddy_rs_pm_core::Host;
use serde_json::{json, Value};
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

/// A failed configuration assembly.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The host list could not be compiled into routes.
    #[error(transparent)]
    Compile(#[from] CompileError),
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

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_pm_compiler::CompiledRoutes;
    use caddy_rs_pm_core::{
        CertificateId, CertificateOrigin, Host, HostId, HostSpec, HostTls, PolicyId, ProxySpec,
        Upstream, UpstreamScheme,
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
