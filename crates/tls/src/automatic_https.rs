//! Automatic HTTPS: derive certificate subjects, provision certificates with the ACME issuer,
//! and describe the HTTP→HTTPS redirect/challenge listener requirements.
//!
//! This module is the policy/provisioning layer between Caddy's typed configuration and the
//! rustls server boundary in [`crate::tls_server`]. It deliberately stops at *plans* and
//! *certificates*: the server supervisor owns listener binding and HTTP request handling.
//!
//! # Opt-in policy (divergence from Caddy)
//!
//! Caddy enables automatic HTTPS by default for every site address. caddy-rs enables it only
//! when the configuration explicitly declares automation — `apps.tls.automation.policies` or
//! `apps.tls.certificates.automate`. This keeps offline/embedding runs deterministic: a TLS
//! listener without certificates still fails loudly at apply time instead of starting a network
//! ACME transaction. See the divergence register (DIV-0034).
//!
//! # What is derived
//!
//! * **subjects**: host matchers of HTTP servers that terminate TLS (`tls_connection_policies`
//!   or the effective HTTPS port) plus `apps.tls.certificates.automate`, minus
//!   `automatic_https.skip`/`skip_certs`; servers with `automatic_https.disable` are manual.
//! * **policies**: `apps.tls.automation.policies` in order, matched by subject (empty subjects =
//!   catch-all, `*` wildcards supported). The first `acme` issuer in a policy becomes an
//!   [`crate::issuer::AcmeIssuerConfig`]; `internal` issuers are a tracked stub.
//! * **redirects**: HTTPS subjects of servers that do not disable redirects, plus a catch-all
//!   marker when an HTTPS server has a route without a host matcher.
//! * **HTTP listener requirement**: when redirects or managed subjects exist and the configuration
//!   has no cleartext listener on the HTTP port, the supervisor derives one (`:<http_port>`).
//!
//! # Provisioning
//!
//! [`AutomaticHttpsProvisioner`] loads already-valid certificates from [`CertificateStorage`],
//! then obtains every missing subject through the existing [`AcmeIssuer`] (HTTP-01 via the shared
//! [`Http01TokenStore`], or the configured DNS-01 provider), adding the results to a
//! [`CertificateResolver`]. The transport is injectable, so tests (and embedders) drive the whole
//! path against a local fake ACME CA without network access.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use caddy_rs_core::config::{AutomationPolicy, Config, TlsApp};
use caddy_rs_core::listen::{ListenAddr, Network};

use crate::acme::{AcmeClock, AcmeStorage, AcmeTransport, PollPolicy, TokioClock};
use crate::certificate::Certificate;
use crate::issuer::{AcmeIssuer, AcmeIssuerConfig, CertificateIssuer, IssuanceRequest};
use crate::solver::Http01Solver;
use crate::solver::Http01TokenStore;
use crate::storage::{CertificateStorage, FileStorage, StoredCertificate};
use crate::tls_server::{CertificateResolver, TlsCertificate};
use crate::{Error, Result};

/// Caddy's default HTTP port for automatic HTTPS redirects/challenges.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// One automation policy that applies to the planned subjects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomaticHttpsPolicy {
    /// Caddy subject patterns (empty = catch-all; `*` wildcards supported).
    pub subjects: Vec<String>,
    /// Issuer that should obtain certificates for these subjects.
    pub issuer: AutomaticHttpsIssuer,
    /// Whether the matching policy uses on-demand TLS (not supported by this build).
    pub on_demand: bool,
}

/// The issuer selected by an automation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomaticHttpsIssuer {
    /// Use an ACME issuer with this configuration.
    Acme(Box<AcmeIssuerConfig>),
    /// Caddy's internal CA (`tls internal`); tracked by T-TLS-050 and not implemented yet.
    Internal,
}

/// The automatic-HTTPS plan for one configuration generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomaticHttpsPlan {
    /// Effective HTTP port (`apps.http.http_port`, default 80).
    pub http_port: u16,
    /// Effective HTTPS port (`apps.http.https_port`, default 443).
    pub https_port: u16,
    /// Certificate subjects to manage, lowercased and deduplicated.
    pub subjects: Vec<String>,
    /// Hosts that HTTP requests should be redirected to HTTPS for.
    pub redirect_hosts: Vec<String>,
    /// Whether a hostless HTTPS site exists, so every HTTP host should be redirected.
    pub redirect_all: bool,
    /// Whether HTTP→HTTPS redirects are enabled by this configuration.
    pub redirects_enabled: bool,
    /// Whether the supervisor must derive an HTTP listener on `http_port` (challenge/redirect
    /// serving) because the configuration does not already have one.
    pub needs_http_listener: bool,
    /// Automation policies in evaluation order.
    pub policies: Vec<AutomaticHttpsPolicy>,
}

impl AutomaticHttpsPlan {
    /// The policy that applies to `subject` (first match, catch-all last by declaration order).
    pub fn policy_for(&self, subject: &str) -> Option<&AutomaticHttpsPolicy> {
        self.policies
            .iter()
            .find(|policy| policy_matches(&policy.subjects, subject))
    }

    /// Whether `host` should be redirected from HTTP to HTTPS.
    pub fn redirects_host(&self, host: &str) -> bool {
        if !self.redirects_enabled {
            return false;
        }
        if self.redirect_all {
            return true;
        }
        let host = normalize_host(host);
        self.redirect_hosts
            .iter()
            .any(|candidate| candidate == &host)
    }

    /// The supervisor's derived HTTP listener key, when one is required.
    pub fn http_listener(&self) -> Option<String> {
        self.needs_http_listener
            .then(|| format!(":{}", self.http_port))
    }
}

/// Derive the automatic-HTTPS plan for `config`.
///
/// Returns `Ok(None)` when automatic HTTPS is not explicitly configured (see the module-level
/// opt-in policy) or when there are no HTTP servers.
pub fn plan(config: &Config) -> Result<Option<AutomaticHttpsPlan>> {
    let Some(http) = config.http() else {
        return Ok(None);
    };
    let tls = config.tls();
    let explicitly_enabled = tls
        .map(|tls| {
            !tls.automation_policies().is_empty()
                || tls_automate(tls).is_some_and(|subjects| !subjects.is_empty())
        })
        .unwrap_or(false);
    if !explicitly_enabled {
        return Ok(None);
    }
    let http_port = http.http_port.unwrap_or(DEFAULT_HTTP_PORT);
    let https_port = http
        .https_port
        .unwrap_or(crate::tls_server::DEFAULT_HTTPS_PORT);

    let mut policies = tls.map(parse_policies).transpose()?.unwrap_or_default();
    // Caddy applies a default automation policy (ACME issuers) to subjects that no configured
    // policy matches; model that as a catch-all policy appended after the configured ones.
    if !policies.iter().any(|policy| policy.subjects.is_empty()) {
        policies.push(AutomaticHttpsPolicy {
            subjects: Vec::new(),
            issuer: AutomaticHttpsIssuer::Acme(Box::new(AcmeIssuerConfig::default())),
            on_demand: false,
        });
    }

    let mut subjects: Vec<String> = Vec::new();
    let mut redirect_hosts: Vec<String> = Vec::new();
    let mut redirect_all = false;
    let mut has_manual_disable = false;
    for (_server_name, server) in &http.servers {
        let auto_https = server.automatic_https.clone().unwrap_or_default();
        let policies_present = server
            .tls_connection_policies
            .as_ref()
            .is_some_and(|policies| !policies.is_empty());
        let terminates_tls = policies_present
            || server.listen.iter().any(|listen| {
                ListenAddr::parse(listen)
                    .ok()
                    .and_then(|address| address.port())
                    == Some(https_port)
            });
        if !terminates_tls {
            continue;
        }
        if auto_https.disable {
            has_manual_disable = true;
            continue;
        }
        let routes = serde_json::to_value(&server.routes).map_err(|error| {
            Error::Issuer(format!(
                "cannot inspect routes for automatic HTTPS: {error}"
            ))
        })?;
        let mut hosts = Vec::new();
        let mut catch_all = false;
        if let Some(routes) = routes.as_array() {
            collect_route_hosts(routes, &mut hosts, &mut catch_all);
        }
        let skipped = |host: &str| {
            auto_https
                .skip
                .iter()
                .any(|pattern| host_matches(pattern, host))
                || auto_https
                    .skip_certs
                    .iter()
                    .any(|pattern| host_matches(pattern, host))
        };
        for host in hosts {
            let host = normalize_host(&host);
            if host.is_empty() || skipped(&host) {
                continue;
            }
            if !subjects.contains(&host) {
                subjects.push(host.clone());
            }
            if !auto_https.disable_redirects {
                if !redirect_hosts.contains(&host) {
                    redirect_hosts.push(host);
                }
            }
        }
        if catch_all && !auto_https.disable_redirects {
            redirect_all = true;
        }
    }
    let skip_patterns: Vec<String> = http
        .servers
        .values()
        .filter_map(|server| server.automatic_https.as_ref())
        .flat_map(|auto| auto.skip.iter().cloned())
        .collect();
    // Explicitly automated subjects (`apps.tls.certificates.automate`) are managed even when no
    // host matcher covers them (Caddy uses this for hosts sharing a server block with a hostless
    // address).
    if let Some(tls) = tls {
        for subject in tls_automate(tls).map(Vec::as_slice).unwrap_or(&[]) {
            let subject = normalize_host(&subject);
            if subject.is_empty()
                || skip_patterns
                    .iter()
                    .any(|pattern| host_matches(pattern, &subject))
            {
                continue;
            }
            if !subjects.contains(&subject) {
                subjects.push(subject.clone());
            }
            if !redirect_hosts.contains(&subject) {
                redirect_hosts.push(subject);
            }
        }
    }
    subjects.sort();
    redirect_hosts.sort();
    let redirects_enabled = !redirect_hosts.is_empty() || redirect_all;

    // Does an existing cleartext listener already serve the HTTP port (and thus challenges)?
    let has_http_listener = http.servers.values().any(|server| {
        let policies_present = server
            .tls_connection_policies
            .as_ref()
            .is_some_and(|policies| !policies.is_empty());
        server.listen.iter().any(|listen| {
            let Ok(address) = ListenAddr::parse(listen) else {
                return false;
            };
            address.network == Network::Tcp
                && address.port() == Some(http_port)
                && !policies_present
        })
    });
    let needs_http_listener = (redirects_enabled || !subjects.is_empty())
        && !has_http_listener
        && http_port != https_port;

    if policies.is_empty() && subjects.is_empty() && !has_manual_disable {
        return Ok(None);
    }
    Ok(Some(AutomaticHttpsPlan {
        http_port,
        https_port,
        subjects,
        redirect_hosts,
        redirect_all,
        redirects_enabled,
        needs_http_listener,
        policies,
    }))
}

fn tls_automate(tls: &TlsApp) -> Option<&Vec<String>> {
    tls.certificates
        .as_ref()
        .and_then(|certificates| certificates.automate.as_ref())
}

fn parse_policies(tls: &TlsApp) -> Result<Vec<AutomaticHttpsPolicy>> {
    let mut policies = Vec::new();
    for (index, policy) in tls.automation_policies().iter().enumerate() {
        policies.push(parse_policy(policy, index)?);
    }
    Ok(policies)
}

fn parse_policy(policy: &AutomationPolicy, index: usize) -> Result<AutomaticHttpsPolicy> {
    let path = format!("apps.tls.automation.policies[{index}]");
    if policy.get_certificate.is_some() {
        return Err(Error::Issuer(format!(
            "{path}.get_certificate module certificates are not implemented (AUTO-HTTPS-GET-CERT)"
        )));
    }
    if policy.on_demand {
        return Err(Error::Issuer(format!(
            "{path}.on_demand: on-demand TLS is not implemented (T-TLS-028)"
        )));
    }
    let mut issuer = None;
    for (issuer_index, module) in policy.issuers.iter().enumerate() {
        let issuer_path = format!("{path}.issuers[{issuer_index}]");
        match module.module.as_deref() {
            Some("acme") => {
                let value = serde_json::to_value(module).map_err(|error| {
                    Error::Issuer(format!("{issuer_path}: cannot read issuer config: {error}"))
                })?;
                let config = AcmeIssuerConfig::from_json(&value)?;
                issuer = Some(AutomaticHttpsIssuer::Acme(Box::new(config)));
                break;
            }
            Some("internal") => {
                return Err(Error::Issuer(format!(
                    "{issuer_path}: the internal CA issuer is not implemented (T-TLS-050)"
                )))
            }
            Some(other) => {
                return Err(Error::Issuer(format!(
                    "{issuer_path}: issuer module `{other}` is not implemented for automatic HTTPS"
                )))
            }
            None => {
                return Err(Error::Issuer(format!(
                    "{issuer_path}: issuer module is missing its `module` field"
                )))
            }
        }
    }
    let issuer = issuer.unwrap_or_else(|| {
        // Caddy's default issuers are the ACME issuers; this build defaults to Let's Encrypt.
        AutomaticHttpsIssuer::Acme(Box::new(AcmeIssuerConfig::default()))
    });
    Ok(AutomaticHttpsPolicy {
        subjects: policy.subjects.clone(),
        issuer,
        on_demand: policy.on_demand,
    })
}

fn collect_route_hosts(routes: &[Value], hosts: &mut Vec<String>, catch_all: &mut bool) {
    for route in routes {
        let mut route_has_host = false;
        if let Some(matcher_sets) = route.get("match").and_then(Value::as_array) {
            for matcher_set in matcher_sets {
                if let Some(host_list) = matcher_set.get("host").and_then(Value::as_array) {
                    for host in host_list.iter().filter_map(Value::as_str) {
                        route_has_host = true;
                        hosts.push(host.to_string());
                    }
                }
            }
        }
        if let Some(handlers) = route.get("handle").and_then(Value::as_array) {
            for handler in handlers {
                if handler.get("handler").and_then(Value::as_str) == Some("subroute") {
                    if let Some(nested) = handler.get("routes").and_then(Value::as_array) {
                        collect_route_hosts(nested, hosts, catch_all);
                    }
                }
            }
        }
        if !route_has_host {
            *catch_all = true;
        }
    }
}

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host.rsplit_once(':').map(|(host, _)| host).unwrap_or(host)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = normalize_host(pattern);
    let host = normalize_host(host);
    if pattern == host {
        return true;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(&format!(".{suffix}"))
            .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.')),
        None => false,
    }
}

fn policy_matches(patterns: &[String], subject: &str) -> bool {
    patterns.is_empty()
        || patterns
            .iter()
            .any(|pattern| host_matches(pattern, subject))
}

// ---- provisioning ----------------------------------------------------------------------------

/// A resolver plus the certificates obtained during this provisioning pass.
#[derive(Debug)]
pub struct ProvisionedCertificates {
    /// Certificate resolver to install into the rustls server configuration.
    pub resolver: Arc<CertificateResolver>,
    /// Certificates obtained through the issuer during this pass.
    pub issued: Vec<Certificate>,
}

/// Obtains missing certificates through the ACME issuer and loads persisted ones from storage.
pub struct AutomaticHttpsProvisioner {
    transport: Arc<dyn AcmeTransport>,
    root: PathBuf,
    challenge_tokens: Arc<Http01TokenStore>,
    clock: Arc<dyn AcmeClock>,
    poll_policy: PollPolicy,
}

impl std::fmt::Debug for AutomaticHttpsProvisioner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AutomaticHttpsProvisioner")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl AutomaticHttpsProvisioner {
    /// Create a provisioner.
    ///
    /// `root` is Caddy's data directory (certificate and account storage); `challenge_tokens` is
    /// shared with the HTTP server so HTTP-01 validations can be answered.
    pub fn new(
        transport: Arc<dyn AcmeTransport>,
        root: impl Into<PathBuf>,
        challenge_tokens: Arc<Http01TokenStore>,
    ) -> Self {
        Self {
            transport,
            root: root.into(),
            challenge_tokens,
            clock: Arc::new(TokioClock),
            poll_policy: PollPolicy::default(),
        }
    }

    /// Override the polling clock (tests use a no-sleep clock).
    pub fn with_clock(mut self, clock: Arc<dyn AcmeClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override the order/authorization polling policy.
    pub fn with_poll_policy(mut self, poll_policy: PollPolicy) -> Self {
        self.poll_policy = poll_policy;
        self
    }

    /// The data directory used for account and certificate storage.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// Load persisted, still-valid certificates and obtain every missing planned subject.
    pub async fn provision(
        &self,
        plan: &AutomaticHttpsPlan,
        base_resolver: Option<CertificateResolver>,
    ) -> Result<ProvisionedCertificates> {
        let storage = FileStorage::new(&self.root);
        let resolver = base_resolver.unwrap_or_default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for key in storage.list("").await? {
            let Some(stored) = CertificateStorage::load(&storage, &key).await? else {
                continue;
            };
            if stored.not_after_unix <= now {
                continue;
            }
            resolver.insert(TlsCertificate::from_stored(&stored)?)?;
        }

        let account_storage: Arc<dyn AcmeStorage> = Arc::new(FileStorage::new(&self.root));
        let mut issued = Vec::new();
        for subject in &plan.subjects {
            if resolver.covers(subject) {
                continue;
            }
            let policy = plan.policy_for(subject).ok_or_else(|| {
                Error::Issuer(format!(
                    "automatic HTTPS: no automation policy matches subject `{subject}`"
                ))
            })?;
            if policy.on_demand {
                return Err(Error::Issuer(format!(
                    "automatic HTTPS: on-demand TLS for `{subject}` is not implemented (T-TLS-028)"
                )));
            }
            let config = match &policy.issuer {
                AutomaticHttpsIssuer::Internal => {
                    return Err(Error::Issuer(format!(
                    "automatic HTTPS: subject `{subject}` uses Caddy's internal CA, which is not \
                         implemented (T-TLS-050)"
                )))
                }
                AutomaticHttpsIssuer::Acme(config) => config.as_ref().clone(),
            };
            let issuer = AcmeIssuer::new(
                config,
                Arc::clone(&self.transport),
                Arc::clone(&account_storage),
                Box::new(FileStorage::new(&self.root)),
            )
            .with_solver(Arc::new(Http01Solver::new(Arc::clone(
                &self.challenge_tokens,
            ))))
            .with_clock(Arc::clone(&self.clock))
            .with_poll_policy(self.poll_policy.clone());
            let certificate = issuer
                .obtain(&IssuanceRequest {
                    domains: vec![subject.clone()],
                    internal: false,
                })
                .await
                .map_err(|error| {
                    Error::Issuer(format!(
                        "automatic HTTPS: cannot obtain a certificate for `{subject}`: {error}"
                    ))
                })?;
            resolver.insert(TlsCertificate::from_cache_certificate(&certificate)?)?;
            issued.push(certificate);
        }
        Ok(ProvisionedCertificates {
            resolver: Arc::new(resolver),
            issued,
        })
    }
}

/// Convert a stored certificate into the in-memory model (used by callers that load storage
/// certificates directly).
pub fn stored_to_certificate(stored: &StoredCertificate, issuer: &str) -> Result<Certificate> {
    let (not_before, not_after) =
        crate::storage::certificate_validity_unix(&stored.certificate_pem[0])?;
    Ok(Certificate {
        domains: stored.domains.clone(),
        cert_chain_der: crate::storage::certificate_chain_der(&stored.certificate_pem)?,
        private_key_der: crate::storage::private_key_der(&stored.private_key_pem)?,
        not_before: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(not_before),
        not_after: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(not_after),
        issuer: issuer.to_string(),
    })
}

/// Subject → policy mapping helper used by diagnostics and tests.
pub fn subjects_by_policy(plan: &AutomaticHttpsPlan) -> BTreeMap<String, Option<String>> {
    plan.subjects
        .iter()
        .map(|subject| {
            (
                subject.clone(),
                plan.policy_for(subject).map(|policy| match &policy.issuer {
                    AutomaticHttpsIssuer::Acme(config) => config.ca.clone(),
                    AutomaticHttpsIssuer::Internal => "internal".to_string(),
                }),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::{HttpMethod, HttpRequest, HttpResponse};
    use crate::solver::Http01TokenStore;
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Mutex;

    fn config(value: Value) -> Config {
        Config::from_value(value).expect("config decodes")
    }

    fn https_config() -> Config {
        config(json!({
            "apps": {
                "tls": {"automation": {"policies": [
                    {"subjects": ["*.example.com"], "issuers": [
                        {"module": "acme", "ca": "https://acme.test/directory", "email": "ops@example.com"}
                    ]}
                ]}},
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": ["127.0.0.1:0"],
                            "tls_connection_policies": [{}],
                            "routes": [{"match": [{"host": ["example.com", "www.example.com"]}],
                                        "handle": [{"handler": "static_response", "body": "ok"}]}]
                        }
                    }
                }
            }
        }))
    }

    #[test]
    fn plan_requires_explicit_automation() {
        let plain = config(json!({
            "apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": []}}}}
        }));
        assert!(plan(&plain).unwrap().is_none());
    }

    #[test]
    fn plan_derives_subjects_policies_and_http_listener() {
        let plan = plan(&https_config()).unwrap().expect("plan exists");
        assert_eq!(plan.http_port, 80);
        assert_eq!(plan.https_port, 443);
        assert_eq!(
            plan.subjects,
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
        assert_eq!(plan.redirect_hosts, plan.subjects);
        assert!(plan.redirects_enabled);
        assert!(plan.needs_http_listener, "no cleartext listener configured");
        assert_eq!(plan.http_listener().as_deref(), Some(":80"));
        let policy = plan.policy_for("www.example.com").expect("policy");
        match &policy.issuer {
            AutomaticHttpsIssuer::Acme(config) => {
                assert_eq!(config.ca, "https://acme.test/directory");
                assert_eq!(config.email.as_deref(), Some("ops@example.com"));
            }
            other => panic!("unexpected issuer: {other:?}"),
        }
    }

    #[test]
    fn plan_respects_disable_redirects_and_skip() {
        let mut value = serde_json::to_value(https_config()).unwrap();
        value["apps"]["http"]["servers"]["srv0"]["automatic_https"] =
            json!({"disable_redirects": true, "skip": ["www.example.com"]});
        let plan = plan(&Config::from_value(value).unwrap()).unwrap().unwrap();
        assert!(plan.subjects.contains(&"example.com".to_string()));
        assert!(!plan.subjects.contains(&"www.example.com".to_string()));
        assert!(!plan.redirects_enabled);
        assert!(
            plan.needs_http_listener,
            "subjects still need challenge serving"
        );
    }

    #[test]
    fn plan_respects_auto_https_disable() {
        let mut value = serde_json::to_value(https_config()).unwrap();
        value["apps"]["http"]["servers"]["srv0"]["automatic_https"] = json!({"disable": true});
        let plan = plan(&Config::from_value(value).unwrap()).unwrap().unwrap();
        assert!(plan.subjects.is_empty());
        assert!(!plan.redirects_enabled);
        assert!(!plan.needs_http_listener);
    }

    #[test]
    fn plan_reads_explicit_automate_subjects() {
        let mut value = serde_json::to_value(https_config()).unwrap();
        value["apps"]["tls"]["certificates"] = json!({"automate": ["extra.example.com"]});
        let plan = plan(&Config::from_value(value).unwrap()).unwrap().unwrap();
        assert!(plan.subjects.contains(&"extra.example.com".to_string()));
        assert!(plan
            .redirect_hosts
            .contains(&"extra.example.com".to_string()));
    }

    #[test]
    fn plan_rejects_unimplemented_issuers_and_on_demand() {
        let mut value = serde_json::to_value(https_config()).unwrap();
        value["apps"]["tls"]["automation"]["policies"][0]["issuers"] =
            json!([{"module": "internal"}]);
        let error = plan(&Config::from_value(value.clone()).unwrap()).unwrap_err();
        assert!(error.to_string().contains("internal CA"), "{error}");
        value["apps"]["tls"]["automation"]["policies"][0]["issuers"] = json!([]);
        value["apps"]["tls"]["automation"]["policies"][0]["on_demand"] = json!(true);
        let error = plan(&Config::from_value(value).unwrap()).unwrap_err();
        assert!(error.to_string().contains("on-demand"), "{error}");
    }

    #[test]
    fn host_matching_supports_wildcards() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(!host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(host_matches("example.com", "EXAMPLE.COM."));
    }

    // ---- provisioning with a fake ACME transport -----------------------------------------

    #[derive(Debug, Default)]
    struct FakeInner {
        requests: Mutex<Vec<HttpRequest>>,
        challenge_acked: Mutex<bool>,
        finalize_seen: Mutex<bool>,
    }

    #[derive(Clone, Default, Debug)]
    struct FakeAcme {
        inner: Arc<FakeInner>,
    }

    const CERT_PEM: &str = include_str!("../testdata/https/example.com.pem");
    const CERT_KEY_PEM: &str = include_str!("../testdata/https/example.com.key");

    fn response(status: u16, body: Value) -> HttpResponse {
        HttpResponse::with_json(status, &body)
            .unwrap()
            .with_header("Replay-Nonce", "nonce")
    }

    #[async_trait]
    impl AcmeTransport for FakeAcme {
        async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.inner.requests.lock().unwrap().push(request.clone());
            let url = request.url.clone();
            let body = if request.method == HttpMethod::Get && url.ends_with("/directory") {
                json!({
                    "newNonce": "https://acme.test/new-nonce",
                    "newAccount": "https://acme.test/new-account",
                    "newOrder": "https://acme.test/new-order",
                    "revokeCert": "https://acme.test/revoke"
                })
            } else if url.ends_with("/new-account") {
                json!({"status": "valid", "contact": ["mailto:ops@example.com"]})
            } else if url.ends_with("/new-order") {
                json!({"status": "pending",
                       "authorizations": ["https://acme.test/authz/1"],
                       "finalize": "https://acme.test/finalize/1"})
            } else if url.ends_with("/authz/1") {
                let acked = *self.inner.challenge_acked.lock().unwrap();
                if acked {
                    json!({"status": "valid", "identifier": {"type": "dns", "value": "example.com"}, "challenges": []})
                } else {
                    json!({"status": "pending", "identifier": {"type": "dns", "value": "example.com"},
                           "challenges": [{"type": "http-01", "url": "https://acme.test/challenge/1", "token": "tok", "status": "pending"}]})
                }
            } else if url.ends_with("/challenge/1") {
                *self.inner.challenge_acked.lock().unwrap() = true;
                json!({"type": "http-01", "url": "https://acme.test/challenge/1", "token": "tok", "status": "processing"})
            } else if url.ends_with("/finalize/1") {
                *self.inner.finalize_seen.lock().unwrap() = true;
                json!({"status": "processing"})
            } else if url.ends_with("/order/1") {
                if *self.inner.finalize_seen.lock().unwrap() {
                    json!({"status": "valid", "certificate": "https://acme.test/cert/1",
                           "authorizations": ["https://acme.test/authz/1"],
                           "finalize": "https://acme.test/finalize/1"})
                } else {
                    json!({"status": "ready",
                           "authorizations": ["https://acme.test/authz/1"],
                           "finalize": "https://acme.test/finalize/1"})
                }
            } else if url.ends_with("/cert/1") {
                return Ok(HttpResponse::new(200)
                    .with_header("Content-Type", "application/pem-certificate-chain")
                    .with_header("Replay-Nonce", "nonce")
                    .with_body(CERT_PEM));
            } else {
                return Err(Error::Issuer(format!("unexpected fake ACME request {url}")));
            };
            let mut response = response(200, body);
            response.status = if url.ends_with("/new-account") || url.ends_with("/new-order") {
                201
            } else {
                200
            };
            if url.ends_with("/new-account") {
                response = response.with_header("Location", "https://acme.test/account/1");
            }
            if url.ends_with("/new-order") {
                response = response.with_header("Location", "https://acme.test/order/1");
            }
            Ok(response)
        }
    }

    #[tokio::test]
    async fn provisioner_obtains_missing_certificate_and_persists_it() {
        let directory = tempfile::tempdir().unwrap();
        let tokens = Arc::new(Http01TokenStore::new());
        let transport = Arc::new(FakeAcme::default());
        let provisioner =
            AutomaticHttpsProvisioner::new(transport.clone(), directory.path(), tokens.clone());
        let plan = plan(&https_config()).unwrap().unwrap();
        // Only manage example.com for this test (www.example.com would need a second
        // certificate; single-subject plans are what the driver issues).
        let mut plan = plan;
        plan.subjects = vec!["example.com".to_string()];
        let result = provisioner
            .provision(&plan, None)
            .await
            .expect("provisioning succeeds");
        assert_eq!(result.issued.len(), 1);
        assert_eq!(result.issued[0].domains, vec!["example.com".to_string()]);
        assert!(result.resolver.covers("example.com"));
        assert!(!transport.inner.requests.lock().unwrap().is_empty());
        // The certificate is persisted in the Caddy storage layout.
        let storage = FileStorage::new(directory.path());
        let keys = storage.list("").await.unwrap();
        assert_eq!(keys.len(), 1, "one stored certificate, got {keys:?}");

        // A second provisioner loads the persisted certificate without issuing again.
        let transport = Arc::new(FakeAcme::default());
        let second = AutomaticHttpsProvisioner::new(
            transport.clone(),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        );
        let result = second.provision(&plan, None).await.unwrap();
        assert!(result.issued.is_empty());
        assert!(result.resolver.covers("example.com"));
        assert!(transport.inner.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn provisioner_defensively_reports_internal_issuer_as_not_implemented() {
        let directory = tempfile::tempdir().unwrap();
        let plan = AutomaticHttpsPlan {
            http_port: 80,
            https_port: 443,
            subjects: vec!["example.com".to_string()],
            redirect_hosts: Vec::new(),
            redirect_all: false,
            redirects_enabled: false,
            needs_http_listener: false,
            policies: vec![AutomaticHttpsPolicy {
                subjects: vec!["example.com".to_string()],
                issuer: AutomaticHttpsIssuer::Internal,
                on_demand: false,
            }],
        };
        let provisioner = AutomaticHttpsProvisioner::new(
            Arc::new(FakeAcme::default()),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        );
        let error = provisioner.provision(&plan, None).await.unwrap_err();
        assert!(error.to_string().contains("internal CA"), "{error}");
        assert!(error.to_string().contains("T-TLS-050"), "{error}");
    }

    #[tokio::test]
    async fn provisioner_loads_persisted_certificates_into_resolver() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let stored = crate::storage::StoredCertificate {
            certificate_pem: vec![CERT_PEM.to_string()],
            private_key_pem: CERT_KEY_PEM.to_string(),
            domains: vec!["example.com".to_string()],
            not_after_unix: u64::MAX,
        };
        CertificateStorage::store(&storage, "local/example.com", &stored)
            .await
            .unwrap();
        let plan = AutomaticHttpsPlan {
            http_port: 80,
            https_port: 443,
            subjects: vec!["example.com".to_string()],
            redirect_hosts: vec!["example.com".to_string()],
            redirect_all: false,
            redirects_enabled: true,
            needs_http_listener: false,
            policies: Vec::new(),
        };
        let provisioner = AutomaticHttpsProvisioner::new(
            Arc::new(FakeAcme::default()),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        );
        let result = provisioner.provision(&plan, None).await.unwrap();
        assert!(result.issued.is_empty());
        assert!(result.resolver.covers("example.com"));
    }
}
