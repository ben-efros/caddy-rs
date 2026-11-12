//! Deterministic Caddy JSON route compilation for proxy-manager hosts.
//!
//! This is the route layer only. It deliberately does not emit listeners, TLS automation,
//! certificate storage or access lists yet; those are separate slices. The output is a pair of
//! ordered route lists for an HTTP and an HTTPS server, so a later compiler stage can attach them
//! to `apps.http.servers` without changing host semantics.
//!
//! The compiler never emits private-key material. Manual certificate keys belong in the secret
//! store, and auto/ACME keys never enter the proxy manager.

#![forbid(unsafe_code)]

use caddy_rs_pm_core::{
    validate_host_domain_uniqueness, validate_host_id_uniqueness, Host, HostKind, HostSpec,
    RedirectScheme, SecurityHeadersConfig, TlsMode,
};
use serde_json::{json, Value};
use thiserror::Error;

/// A compiled pair of route lists.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledRoutes {
    /// Routes for the HTTP (`:80`) server, in evaluation order.
    pub http: Vec<Value>,
    /// Routes for the HTTPS (`:443`) server, in evaluation order.
    pub https: Vec<Value>,
}

impl CompiledRoutes {
    pub fn is_empty(&self) -> bool {
        self.http.is_empty() && self.https.is_empty()
    }

    /// Serialize as a stable JSON object for golden tests and review.
    pub fn to_json(&self) -> Value {
        json!({ "http": self.http, "https": self.https })
    }
}

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Core(#[from] caddy_rs_pm_core::CoreError),
}

/// Compile all enabled hosts into deterministic HTTP/HTTPS route lists.
///
/// Disabled hosts are omitted. Duplicate domains across hosts are rejected before any route is
/// produced. Hosts are ordered by their first normalized domain and then by id, so the same input
/// always produces the same JSON.
pub fn compile_routes(hosts: &[Host]) -> Result<CompiledRoutes, CompileError> {
    validate_host_domain_uniqueness(hosts)?;
    validate_host_id_uniqueness(hosts)?;

    let mut prepared: Vec<PreparedHost> = Vec::new();
    for host in hosts {
        if !host.enabled {
            continue;
        }
        host.validate_structure()?;
        let domains = host.normalized_domains()?;
        let first = domains
            .first()
            .cloned()
            .ok_or_else(|| CompileError::Invalid("host has no domains".to_string()))?;
        prepared.push(PreparedHost {
            id: host.id.0,
            domains,
            first,
            host,
        });
    }
    prepared.sort_by(|a, b| (a.first.as_str(), a.id).cmp(&(b.first.as_str(), b.id)));

    let mut compiled = CompiledRoutes {
        http: Vec::new(),
        https: Vec::new(),
    };
    for entry in prepared {
        compile_one(entry, &mut compiled)?;
    }
    Ok(compiled)
}

struct PreparedHost<'a> {
    id: u64,
    domains: Vec<String>,
    first: String,
    host: &'a Host,
}

fn compile_one(entry: PreparedHost<'_>, out: &mut CompiledRoutes) -> Result<(), CompileError> {
    let tls_enabled = entry.host.tls.mode != TlsMode::Disabled;

    if tls_enabled {
        let handle = host_handle(entry.host, true)?;
        out.https.push(route(
            format!("pm-host-{}-https", entry.id),
            &entry.domains,
            handle,
        ));
    }

    let http_handle = if tls_enabled && entry.host.tls.ssl_forced {
        vec![json!({
            "handler": "static_response",
            "status_code": 301,
            "headers": {
                "Location": ["https://{http.request.host}{http.request.uri}"]
            }
        })]
    } else {
        host_handle(entry.host, false)?
    };
    out.http.push(route(
        format!("pm-host-{}-http", entry.id),
        &entry.domains,
        http_handle,
    ));
    Ok(())
}

fn host_handle(host: &Host, on_https: bool) -> Result<Vec<Value>, CompileError> {
    let mut handle = Vec::new();

    // Security headers are staged as defaults first, so any explicit `headers` handler
    // emitted later in the chain can override them.
    if let Some(security) = &host.security_headers {
        handle.push(security_headers_handler(security)?);
    }

    if on_https && host.tls.hsts_enabled {
        let value = if host.tls.hsts_subdomains {
            "max-age=63072000; includeSubDomains; preload"
        } else {
            "max-age=63072000; preload"
        };
        handle.push(json!({
            "handler": "headers",
            "response": {
                "set": { "Strict-Transport-Security": [value] }
            }
        }));
    }

    match &host.spec {
        HostSpec::Proxy(spec) => {
            if !spec.preserve_host {
                handle.push(json!({
                    "handler": "headers",
                    "request": {
                        "set": { "Host": [spec.upstream.host] }
                    }
                }));
            }
            let mut proxy = json!({
                "handler": "reverse_proxy",
                "upstreams": [{ "dial": spec.upstream.dial() }]
            });
            if spec.upstream.scheme == caddy_rs_pm_core::UpstreamScheme::Https {
                proxy["transport"] = json!({
                    "protocol": "http",
                    "tls": {}
                });
            }
            handle.push(proxy);
        }
        HostSpec::Redirect(spec) => {
            let scheme = spec.scheme.as_caddy_placeholder();
            let suffix = if spec.preserve_path {
                "{http.request.uri}"
            } else {
                ""
            };
            let target = spec.normalized_target()?;
            let location = format!("{scheme}://{}{suffix}", target);
            handle.push(json!({
                "handler": "static_response",
                "status_code": spec.status,
                "headers": { "Location": [location] }
            }));
        }
        HostSpec::Dead(_) => {
            handle.push(json!({
                "handler": "static_response",
                "status_code": 404
            }));
        }
    }

    // Defensive: the compiler must never emit key material even if a future host spec grows.
    let rendered = serde_json::to_string(&handle)
        .map_err(|error| CompileError::Invalid(format!("cannot serialize route: {error}")))?;
    if rendered.contains("PRIVATE KEY") {
        return Err(CompileError::Invalid(
            "compiled route unexpectedly contains private-key material".to_string(),
        ));
    }
    Ok(handle)
}

/// Render a [`SecurityHeadersConfig`] as a Caddy `headers` handler with a `security_headers`
/// block. The block is emitted as a fill-if-absent default stage: explicit `headers` handlers
/// later in the chain override these values.
fn security_headers_handler(security: &SecurityHeadersConfig) -> Result<Value, CompileError> {
    let mut block = serde_json::Map::new();

    if let Some(csp) = &security.content_security_policy {
        block.insert("content_security_policy".to_string(), json!(csp));
    }
    if let Some(hsts) = &security.strict_transport_security {
        let mut hsts_obj = serde_json::Map::new();
        hsts_obj.insert("max_age".to_string(), json!(hsts.max_age));
        hsts_obj.insert(
            "include_subdomains".to_string(),
            json!(hsts.include_subdomains),
        );
        hsts_obj.insert("preload".to_string(), json!(hsts.preload));
        block.insert("strict_transport_security".to_string(), json!(hsts_obj));
    }
    if let Some(pp) = &security.permissions_policy {
        block.insert("permissions_policy".to_string(), json!(pp));
    }
    if let Some(xfo) = &security.x_frame_options {
        block.insert("x_frame_options".to_string(), json!(xfo));
    }
    if let Some(xcto) = &security.x_content_type_options {
        block.insert("x_content_type_options".to_string(), json!(xcto));
    }
    if let Some(rp) = &security.referrer_policy {
        block.insert("referrer_policy".to_string(), json!(rp));
    }

    Ok(json!({
        "handler": "headers",
        "security_headers": json!(block)
    }))
}

fn route(id: String, domains: &[String], handle: Vec<Value>) -> Value {
    json!({
        "@id": id,
        "match": [{ "host": domains }],
        "handle": handle
    })
}

/// Human-readable kind used by diagnostics and tests.
pub fn kind_name(kind: HostKind) -> &'static str {
    kind.as_str()
}

/// The redirect scheme placeholder used by the compiler, exposed for API/UI previews.
pub fn redirect_scheme_placeholder(scheme: RedirectScheme) -> &'static str {
    scheme.as_caddy_placeholder()
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_pm_core::{
        CertificateId, CertificateOrigin, HostId, HostTls, PolicyId, ProxySpec, RedirectSpec,
        Upstream, UpstreamScheme,
    };

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

    fn redirect_host(id: u64, domains: &[&str], tls: HostTls) -> Host {
        Host::new(
            HostId(id),
            domains.iter().map(|value| value.to_string()).collect(),
            tls,
            HostSpec::Redirect(RedirectSpec {
                scheme: RedirectScheme::Auto,
                target: "new.example.com".to_string(),
                status: 301,
                preserve_path: true,
            }),
        )
    }

    #[test]
    fn compiles_http_proxy_route() {
        let host = proxy_host(1, &["example.com"], HostTls::disabled());
        let compiled = compile_routes(&[host]).expect("compile");
        assert!(compiled.https.is_empty());
        assert_eq!(compiled.http.len(), 1);
        assert_eq!(
            compiled.http[0],
            json!({
                "@id": "pm-host-1-http",
                "match": [{ "host": ["example.com"] }],
                "handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{ "dial": "10.0.0.5:8080" }]
                }]
            })
        );
    }

    #[test]
    fn tls_forced_host_gets_https_route_and_http_redirect() {
        let host = proxy_host(2, &["secure.example.com"], HostTls::for_auto(PolicyId(4)));
        let compiled = compile_routes(&[host]).expect("compile");
        assert_eq!(compiled.https.len(), 1);
        assert_eq!(compiled.http.len(), 1);
        assert_eq!(compiled.http[0]["handle"][0]["status_code"], 301);
        assert_eq!(
            compiled.http[0]["handle"][0]["headers"]["Location"][0],
            "https://{http.request.host}{http.request.uri}"
        );
        assert_eq!(
            compiled.https[0]["handle"][0]["upstreams"][0]["dial"],
            "10.0.0.5:8080"
        );
    }

    #[test]
    fn non_forced_tls_host_keeps_both_routes() {
        let mut tls = HostTls::for_auto(PolicyId(4));
        tls.ssl_forced = false;
        let host = proxy_host(3, &["secure.example.com"], tls);
        let compiled = compile_routes(&[host]).expect("compile");
        assert_eq!(compiled.https.len(), 1);
        assert_eq!(compiled.http.len(), 1);
        assert_eq!(compiled.http[0]["handle"][0]["handler"], "reverse_proxy");
    }

    #[test]
    fn hsts_is_attached_only_to_https() {
        let mut tls = HostTls::for_explicit(CertificateId(7), CertificateOrigin::Manual);
        tls.hsts_enabled = true;
        tls.hsts_subdomains = true;
        let host = proxy_host(4, &["secure.example.com"], tls);
        let compiled = compile_routes(&[host]).expect("compile");
        assert_eq!(compiled.https[0]["handle"][0]["handler"], "headers");
        assert_eq!(
            compiled.https[0]["handle"][0]["response"]["set"]["Strict-Transport-Security"][0],
            "max-age=63072000; includeSubDomains; preload"
        );
        assert_eq!(compiled.http[0]["handle"][0]["status_code"], 301);
    }

    #[test]
    fn redirect_preserves_path_and_uses_auto_scheme() {
        let host = redirect_host(5, &["old.example.com"], HostTls::disabled());
        let compiled = compile_routes(&[host]).expect("compile");
        assert_eq!(
            compiled.http[0]["handle"][0]["headers"]["Location"][0],
            "{http.request.scheme}://new.example.com{http.request.uri}"
        );
    }

    #[test]
    fn redirect_target_is_normalized_in_location() {
        let host = Host::new(
            HostId(19),
            vec!["old.example.com".to_string()],
            HostTls::disabled(),
            HostSpec::Redirect(RedirectSpec {
                scheme: RedirectScheme::Https,
                target: " New.Example.COM. ".to_string(),
                status: 302,
                preserve_path: false,
            }),
        );
        let compiled = compile_routes(&[host]).expect("compile");
        assert_eq!(
            compiled.http[0]["handle"][0]["headers"]["Location"][0],
            "https://new.example.com"
        );
    }

    #[test]
    fn dead_host_returns_404() {
        let host = Host::new(
            HostId(6),
            vec!["gone.example.com".to_string()],
            HostTls::disabled(),
            HostSpec::Dead(Default::default()),
        );
        let compiled = compile_routes(&[host]).expect("compile");
        assert_eq!(compiled.http[0]["handle"][0]["status_code"], 404);
    }

    #[test]
    fn https_upstream_gets_tls_transport_without_a_scheme_in_dial() {
        let mut host = proxy_host(17, &["example.com"], HostTls::disabled());
        if let HostSpec::Proxy(spec) = &mut host.spec {
            spec.upstream = caddy_rs_pm_core::Upstream::new(
                caddy_rs_pm_core::UpstreamScheme::Https,
                "backend.internal",
                8443,
            );
        }
        let compiled = compile_routes(&[host]).expect("compile");
        let proxy = &compiled.http[0]["handle"][0];
        assert_eq!(proxy["upstreams"][0]["dial"], "backend.internal:8443");
        assert_eq!(proxy["transport"]["protocol"], "http");
        assert_eq!(proxy["transport"]["tls"], json!({}));
    }

    #[test]
    fn preserve_host_false_rewrites_the_upstream_host_header() {
        let mut host = proxy_host(16, &["example.com"], HostTls::disabled());
        if let HostSpec::Proxy(spec) = &mut host.spec {
            spec.preserve_host = false;
        }
        let compiled = compile_routes(&[host]).expect("compile");
        let handle = &compiled.http[0]["handle"];
        assert_eq!(handle[0]["handler"], "headers");
        assert_eq!(handle[0]["request"]["set"]["Host"][0], "10.0.0.5");
        assert_eq!(handle[1]["handler"], "reverse_proxy");
    }

    #[test]
    fn disabled_hosts_are_omitted() {
        let mut host = proxy_host(7, &["disabled.example.com"], HostTls::disabled());
        host.enabled = false;
        let compiled = compile_routes(&[host]).expect("compile");
        assert!(compiled.is_empty());
    }

    #[test]
    fn duplicate_host_ids_are_rejected() {
        let first = proxy_host(18, &["one.example.com"], HostTls::disabled());
        let second = proxy_host(18, &["two.example.com"], HostTls::disabled());
        assert!(compile_routes(&[first, second]).is_err());
    }

    #[test]
    fn duplicate_domains_are_rejected_before_routes() {
        let first = proxy_host(8, &["same.example.com"], HostTls::disabled());
        let second = proxy_host(9, &["same.example.com"], HostTls::disabled());
        assert!(matches!(
            compile_routes(&[first, second]),
            Err(CompileError::Core(_))
        ));
    }

    #[test]
    fn output_is_deterministic_for_input_order() {
        let a = proxy_host(10, &["b.example.com"], HostTls::disabled());
        let b = proxy_host(11, &["a.example.com"], HostTls::disabled());
        let one = compile_routes(&[a.clone(), b.clone()]).expect("compile");
        let two = compile_routes(&[b, a]).expect("compile");
        assert_eq!(one, two);
        assert_eq!(one.http[0]["match"][0]["host"][0], "a.example.com");
    }

    #[test]
    fn upstream_validation_rejects_scheme_and_zero_port() {
        let mut host = proxy_host(12, &["example.com"], HostTls::disabled());
        if let HostSpec::Proxy(spec) = &mut host.spec {
            spec.upstream.host = "http://bad".to_string();
        }
        assert!(compile_routes(&[host]).is_err());

        let mut host = proxy_host(13, &["example.com"], HostTls::disabled());
        if let HostSpec::Proxy(spec) = &mut host.spec {
            spec.upstream.port = 0;
        }
        assert!(compile_routes(&[host]).is_err());
    }

    #[test]
    fn compiled_json_never_contains_private_key_markers() {
        let hosts = vec![
            proxy_host(14, &["one.example.com"], HostTls::disabled()),
            redirect_host(15, &["two.example.com"], HostTls::disabled()),
        ];
        let rendered = compile_routes(&hosts)
            .expect("compile")
            .to_json()
            .to_string();
        assert!(!rendered.contains("PRIVATE KEY"));
    }
}
