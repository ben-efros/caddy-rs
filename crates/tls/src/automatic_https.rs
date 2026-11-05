//! Automatic HTTPS: derive certificate subjects, provision certificates with the ACME issuer,
//! and describe the HTTP→HTTPS redirect/challenge listener requirements.
//!
//! This module is the policy/provisioning layer between Caddy's typed configuration and the
//! rustls server boundary in [`crate::tls_server`]. It deliberately stops at *plans* and
//! *certificates*: the server supervisor owns listener binding and HTTP request handling.
//!
//! # Default-on policy
//!
//! Like Caddy, automatic HTTPS is **on by default**: host matchers on a server that terminates
//! TLS are managed automatically, and HTTP requests for those hosts are redirected to HTTPS,
//! without requiring `apps.tls.automation` or `tls_connection_policies`. A server signals TLS by
//! listening on the effective HTTPS port (`apps.http.https_port`, default 443), by declaring
//! `tls_connection_policies`, or implicitly by listening on any non-HTTP port (Caddy treats a
//! host matcher on a non-HTTP listener port as HTTPS on that port; the redirect destination uses
//! the listener's own port, e.g. `https://example.com:8443`). Multiple non-standard HTTPS ports in
//! one server block and mixed cleartext/TLS listener ports fail loudly as ambiguous.
//!
//! Opt-outs mirror Caddy and are read from the typed server-level `automatic_https` before any
//! inference: `disable` (also emitted by the Caddyfile `auto_https off` global option),
//! `disable_redirects`, `disable_certificates`, `ignore_loaded_certificates`, `skip`, and
//! `skip_certificates`. `skip` is applied first, so a host listed there is neither certificate
//! subject nor redirect host and does not demand TLS; this is how adapted
//! `http://host:port` sites stay plaintext. The Caddyfile adapter/parser still lacks the global
//! `auto_https disable_certs` spelling, and the typed JSON field is `disable_certificates`.
//!
//! **No-CA policy:** ordinary public names use the default ACME issuer (Let's Encrypt). Local
//! names (localhost/*.local/*.internal/private IPs and other non-public subjects) use the
//! built-in internal CA automatically, so they work offline; `localhost`-style certificates are
//! self-signed by that CA. A public-name configuration with no reachable CA fails the apply
//! loudly and rolls back to the previous generation (Caddy instead keeps retrying in the
//! background). Tests inject a fake ACME transport through the server runtime's
//! `with_acme_transport` seam (or the provisioner seam) and never touch the network.
//!
//! # What is derived
//!
//! * **subjects**: host matchers of HTTP servers that terminate TLS (`tls_connection_policies`,
//!   the effective HTTPS port, or a non-HTTP listener port) plus
//!   `apps.tls.certificates.automate`, minus `automatic_https.skip`/`skip_certificates`;
//!   manually loaded certificates suppress automatic management unless
//!   `automatic_https.ignore_loaded_certificates` is set. Servers with `automatic_https.disable`
//!   are manual.
//! * **TLS ports**: listener ports the plan terminates TLS on, including implicitly-HTTPS
//!   non-standard ports, so the server supervisor can derive TLS without mutating the config.
//! * **policies**: `apps.tls.automation.policies` in order, matched by subject (empty subjects =
//!   catch-all, `*` wildcards supported). The first issuer in a policy becomes either an ACME
//!   issuer ([`crate::issuer::AcmeIssuerConfig`]) or Caddy's local internal CA
//!   ([`crate::internal_ca::InternalIssuer`]).
//! * **redirects**: HTTPS subjects of servers that do not disable redirects, plus a catch-all
//!   marker when an HTTPS server has a route without a host matcher.
//! * **HTTP listener requirement**: when redirects or managed subjects exist and the configuration
//!   has no cleartext listener on the HTTP port, the supervisor derives one (`:<http_port>`).
//!
//! # Provisioning
//!
//! Issuers configured with `trusted_roots_pem_files` (emitted from Caddy's `acme_ca_root`) get a
//! transport that trusts exactly those PEM roots for the CA HTTPS connection; unreadable/empty
//! files fail the generation loudly and explicit roots never fall back to the platform bundle.
//!
//! [`AutomaticHttpsProvisioner`] loads already-valid certificates from [`CertificateStorage`],
//! then obtains every missing subject through the policy's issuer: ACME ([`AcmeIssuer`], HTTP-01
//! via the shared [`Http01TokenStore`], or the configured DNS-01 provider) or the local internal
//! CA ([`InternalIssuer`], material persisted under Caddy's `pki/authorities/<ca-id>/` layout and
//! leaves under `certificates/<ca-id>/`). Results are added to a [`CertificateResolver`].
//!
//! For `tls internal` sites the provisioner exposes the local CA certificates through
//! [`AutomaticHttpsProvisioner::ca_certificates`] so a server can serve or install trust later;
//! trust installation itself is not done here (see the divergence register). The transport is
//! injectable, so tests (and embedders) drive the ACME path against a local fake CA without
//! network access.
//!
//! # Renewal
//!
//! After provisioning, [`AutomaticHttpsProvisioner::provision`] starts a generation-scoped
//! [`RenewalScheduler`] for the managed certificates (issuer-issued *and* reused from storage)
//! unless disabled with [`AutomaticHttpsProvisioner::with_renewal_scheduler`]. The scheduler is
//! wired to the returned [`CertificateResolver`] through a [`SharedCertificateStore`] publisher:
//!
//! * each due certificate is renewed through the automation policy's ACME or internal issuer
//!   (see the private renewal issuer router), persisted with [`CertificateStorage`] and only then
//!   swapped in;
//! * the publisher replaces the resolver's `Arc<CertifiedKey>` atomically, so a handshake already
//!   in flight keeps the certificate it resolved and new handshakes see the renewed one;
//! * failed renewals keep the old certificate serving and retry with exponential backoff;
//! * the scheduler lives in [`ProvisionedCertificates::renewals`]. It is owned by the generation:
//!   stop it with [`AutomaticHttpsRenewals::stop`]/[`AutomaticHttpsRenewals::abort`] (or simply
//!   drop it) when the generation is retired. Dropping aborts the background task so reloads cannot
//!   leak schedulers.
//!
//! Server adoption of this lifecycle (keeping `ProvisionedCertificates::renewals` alongside the
//! generation's listeners and stopping it on drain) is a follow-up wiring step. ARI-driven renewal
//! and on-demand TLS are not implemented.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::Value;

use caddy_rs_core::config::{AutomationPolicy, Config, TlsApp};
use caddy_rs_core::listen::{ListenAddr, Network};

use crate::acme::{AcmeClock, AcmeStorage, AcmeTransport, PollPolicy, TokioClock};
use crate::certificate::{Certificate, RenewalItem};
use crate::internal_ca::{CaCertificates, CaStorage, InternalIssuer, DEFAULT_CA_ID};
use crate::issuer::{AcmeIssuer, AcmeIssuerConfig, CertificateIssuer, IssuanceRequest};
use crate::renewal::{
    CertificatePublisher, RenewalClock, RenewalOutcome, RenewalPolicy, RenewalScheduler,
    RenewalSchedulerHandle, SharedCertificateStore, SystemClock,
};
use crate::solver::Http01TokenStore;
use crate::solver::{Http01Solver, TlsAlpn01Solver};
use crate::storage::{CertificateStorage, FileStorage, StoredCertificate};
use crate::tls_alpn::TlsAlpn01TokenStore;
use crate::tls_server::{CertificateResolver, TlsCertificate};
use crate::{Error, Result};
use tokio::sync::Mutex as AsyncMutex;

/// Caddy's default HTTP port for automatic HTTPS redirects/challenges.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// One automation policy that applies to the planned subjects.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
    /// Caddy's internal/local CA (`tls internal`, `local_certs`).
    Internal,
}

impl Default for AutomaticHttpsIssuer {
    fn default() -> Self {
        AutomaticHttpsIssuer::Acme(Box::default())
    }
}

/// The automatic-HTTPS plan for one configuration generation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
    /// Listener ports that this plan terminates TLS on.
    ///
    /// Includes the configured HTTPS port and any implicitly-HTTPS non-standard listener port
    /// (Caddy treats a host matcher on a non-HTTP listener port as HTTPS on that port).
    pub tls_ports: Vec<u16>,
    /// HTTPS destination port per redirect host.
    ///
    /// Implicit HTTPS on a non-standard port redirects to that same port; ordinary sites redirect
    /// to [`Self::https_port`].
    pub redirect_ports: BTreeMap<String, u16>,
    /// HTTPS destination port for hostless/catch-all redirects.
    pub redirect_all_port: u16,
    /// Subjects whose loaded certificates must be ignored: renewals/issuance are forced even when
    /// a matching certificate is already loaded (`automatic_https.ignore_loaded_certificates`).
    pub force_reissue: Vec<String>,
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
/// Returns `Ok(None)` when there are no HTTP servers, every server disables automatic HTTPS, or
/// nothing qualifies (for example plain HTTP-only sites or fully skipped hosts).
pub fn plan(config: &Config) -> Result<Option<AutomaticHttpsPlan>> {
    let Some(http) = config.http() else {
        return Ok(None);
    };
    let tls = config.tls();
    let http_port = http.http_port.unwrap_or(DEFAULT_HTTP_PORT);
    let https_port = http
        .https_port
        .unwrap_or(crate::tls_server::DEFAULT_HTTPS_PORT);

    let mut policies = tls.map(parse_policies).transpose()?.unwrap_or_default();
    let explicit_policies = !policies.is_empty();
    let explicit_automate: Vec<String> = tls
        .and_then(tls_automate)
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .to_vec();

    // Manually configured certificates suppress automatic management unless the server opts out
    // with `ignore_loaded_certificates` (Caddy checks its loaded-certificate cache; storage-loaded
    // certificates are additionally consulted during provisioning).
    let loaded_resolver = crate::tls_server::resolver_from_config(config)?;

    let mut subjects: Vec<String> = Vec::new();
    let mut redirect_hosts: Vec<String> = Vec::new();
    let mut redirect_all = false;
    let mut redirect_all_port = https_port;
    let mut redirect_ports: BTreeMap<String, u16> = BTreeMap::new();
    let mut tls_ports: Vec<u16> = Vec::new();
    let mut force_reissue: Vec<String> = Vec::new();
    let mut internal_subjects: Vec<String> = Vec::new();
    let mut public_subjects: Vec<String> = Vec::new();
    let mut enabled_servers = 0usize;
    let mut explicit_skip_patterns: Vec<String> = Vec::new();

    for (server_name, server) in &http.servers {
        let auto = server.automatic_https.clone().unwrap_or_default();
        if auto.disable {
            continue;
        }
        enabled_servers += 1;
        explicit_skip_patterns.extend(auto.skip.iter().cloned());

        let mut ports: Vec<u16> = Vec::new();
        for listen in &server.listen {
            let Ok(address) = ListenAddr::parse(listen) else {
                continue;
            };
            if address.network == Network::Tcp {
                if let Some(port) = address.port() {
                    if !ports.contains(&port) {
                        ports.push(port);
                    }
                }
            }
        }
        let policies_present = server
            .tls_connection_policies
            .as_ref()
            .is_some_and(|policies| !policies.is_empty());
        if !ports.is_empty() && ports.iter().all(|port| *port == http_port) && !policies_present {
            // Caddy warns and disables automatic HTTPS for a server listening only on the HTTP
            // port; there is no TLS to manage. Explicit TLS connection policies preserve the
            // pre-default-on behaviour (tests/embedders may use an ephemeral HTTP port for TLS).
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

        // Server-level `automatic_https` is authoritative before any inference: hosts listed in
        // `skip` are not certificate subjects, not redirect hosts, and do not demand TLS. The
        // Caddyfile adapter emits this for explicit `http://host:port` site addresses.
        let unskipped: Vec<String> = hosts
            .iter()
            .filter_map(|host| {
                let host = normalize_host(host);
                if host.is_empty() || auto.skip.iter().any(|pattern| host_matches(pattern, &host)) {
                    None
                } else {
                    Some(host)
                }
            })
            .collect();

        if unskipped.is_empty() {
            // Nothing on this server is managed. Preserve explicit-policy catch-all redirects
            // (on-demand style) when automation was configured explicitly.
            if policies_present && (explicit_policies || !explicit_automate.is_empty()) {
                tls_ports.extend(ports.iter().copied());
                if catch_all && !auto.disable_redirects {
                    redirect_all = true;
                    redirect_all_port = https_port;
                }
            }
            continue;
        }

        let path = format!("apps.http.servers.{server_name}.listen");
        let non_http_ports: Vec<u16> = ports
            .iter()
            .copied()
            .filter(|port| *port != http_port)
            .collect();
        let has_https_port = non_http_ports.contains(&https_port);
        let uses_tls = policies_present || !non_http_ports.is_empty();
        if !uses_tls {
            // All listeners are on the HTTP port (already handled above), or the server has no
            // TCP listeners; automatic HTTPS does not apply.
            continue;
        }

        // `redirect_port` is the HTTPS destination for this server's hosts, when redirects are
        // enabled. Explicit TLS policy servers keep the legacy redirect target
        // (`apps.http.https_port`) so explicit configurations behave as before; implicit HTTPS on
        // a non-standard port redirects to that same port, matching Caddy's site addresses.
        let (redirect_port, redirects_for_server) = if policies_present {
            tls_ports.extend(ports.iter().copied());
            let redirects = !auto.disable_redirects && (has_https_port || explicit_policies);
            (https_port, redirects)
        } else {
            if ports.contains(&http_port) {
                return Err(Error::TlsConfig {
                    path,
                    message: format!(
                        "a server cannot mix cleartext (port {http_port}) and HTTPS listeners in \
                         one block; split the HTTP and HTTPS sites into separate server blocks"
                    ),
                });
            }
            if non_http_ports.len() > 1 {
                return Err(Error::TlsConfig {
                    path,
                    message: format!(
                        "implicit HTTPS on multiple non-standard listener ports {non_http_ports:?} \
                         is ambiguous; use one HTTPS port per server block or declare \
                         `tls_connection_policies`"
                    ),
                });
            }
            let tls_port = non_http_ports[0];
            tls_ports.push(tls_port);
            if auto.disable_redirects {
                (tls_port, false)
            } else {
                (tls_port, true)
            }
        };

        let disable_certs = auto.disable_certs;
        for host in unskipped {
            let skip_certs = auto
                .skip_certs
                .iter()
                .any(|pattern| host_matches(pattern, &host));
            if !disable_certs && !skip_certs && subject_qualifies_for_cert(&host) {
                let already_planned = subjects.iter().any(|subject| subject == &host);
                let loaded = loaded_resolver
                    .as_ref()
                    .is_some_and(|resolver| resolver.covers(&host));
                if loaded && !auto.ignore_loaded_certs {
                    // A manually loaded certificate already covers this name; Caddy keeps it and
                    // only redirects. The name is not added to automatic management.
                } else if !already_planned {
                    subjects.push(host.clone());
                    if auto.ignore_loaded_certs {
                        force_reissue.push(host.clone());
                    }
                    if subject_uses_internal_issuer(&host, explicit_policies) {
                        internal_subjects.push(host.clone());
                    } else {
                        public_subjects.push(host.clone());
                    }
                }
            }
            if redirects_for_server {
                match redirect_ports.get(&host) {
                    Some(existing) if *existing != redirect_port => {
                        return Err(Error::TlsConfig {
                            path: format!("apps.http.servers.{server_name}.routes"),
                            message: format!(
                                "host `{host}` is served on HTTPS ports {existing} and \
                                 {redirect_port}; one redirect destination is required per host"
                            ),
                        });
                    }
                    Some(_) => {}
                    None => {
                        redirect_ports.insert(host.clone(), redirect_port);
                    }
                }
                if !redirect_hosts.contains(&host) {
                    redirect_hosts.push(host.clone());
                }
            }
        }
        if catch_all && redirects_for_server {
            redirect_all = true;
            redirect_all_port = redirect_port;
        }
    }

    // Explicitly automated subjects (`apps.tls.certificates.automate`) are managed even when no
    // host matcher covers them (Caddy uses this for hosts sharing a server block with a hostless
    // address).
    for subject in &explicit_automate {
        let subject = normalize_host(subject);
        if subject.is_empty()
            || explicit_skip_patterns
                .iter()
                .any(|pattern| host_matches(pattern, &subject))
        {
            continue;
        }
        if !subjects.contains(&subject) {
            subjects.push(subject.clone());
            if subject_uses_internal_issuer(&subject, explicit_policies) {
                internal_subjects.push(subject.clone());
            } else {
                public_subjects.push(subject.clone());
            }
        }
        if !redirect_hosts.contains(&subject) {
            redirect_hosts.push(subject.clone());
            redirect_ports.entry(subject).or_insert(https_port);
        }
    }

    subjects.sort();
    subjects.dedup();
    redirect_hosts.sort();
    redirect_hosts.dedup();
    tls_ports.sort_unstable();
    tls_ports.dedup();
    force_reissue.sort();
    force_reissue.dedup();

    // Derive implicit automation policies for managed subjects that no configured policy matches.
    let unmatched = |subjects: &[String]| -> Vec<String> {
        subjects
            .iter()
            .filter(|subject| {
                !policies
                    .iter()
                    .any(|policy| policy_matches(&policy.subjects, subject))
            })
            .cloned()
            .collect()
    };
    let unmatched_internal = unmatched(&internal_subjects);
    let unmatched_public = unmatched(&public_subjects);
    if !unmatched_internal.is_empty() {
        policies.push(AutomaticHttpsPolicy {
            subjects: unmatched_internal,
            issuer: AutomaticHttpsIssuer::Internal,
            on_demand: false,
        });
    }
    let needs_default_acme = !policies.iter().any(|policy| policy.subjects.is_empty())
        && (!unmatched_public.is_empty() || explicit_policies || !explicit_automate.is_empty());
    if needs_default_acme {
        // Caddy's default automation policy: public names use the default ACME issuers.
        policies.push(AutomaticHttpsPolicy {
            subjects: Vec::new(),
            issuer: AutomaticHttpsIssuer::Acme(Box::default()),
            on_demand: false,
        });
    }

    if enabled_servers == 0 {
        // Every server opted out with `automatic_https.disable` (for example Caddyfile
        // `auto_https off`): automatic HTTPS is inert.
        return Ok(None);
    }
    if subjects.is_empty()
        && redirect_hosts.is_empty()
        && !redirect_all
        && policies.is_empty()
        && explicit_automate.is_empty()
    {
        return Ok(None);
    }

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

    Ok(Some(AutomaticHttpsPlan {
        http_port,
        https_port,
        subjects,
        redirect_hosts,
        redirect_all,
        redirects_enabled,
        needs_http_listener,
        tls_ports,
        redirect_ports,
        redirect_all_port,
        force_reissue,
        policies,
    }))
}

/// Whether `subject` can be issued by a CA (certmagic's `SubjectQualifiesForCert`).
fn subject_qualifies_for_cert(subject: &str) -> bool {
    let subject = subject.trim();
    !subject.is_empty()
        && !subject.starts_with('.')
        && !subject.ends_with('.')
        && (!subject.contains('*') || subject.starts_with("*.") || subject == "*")
        && !subject.contains([
            '(', ')', '[', ']', '{', '}', '<', '>', ' ', '\t', '\n', '"', '\\', '!', '@', '#', '$',
            '%', '^', '&', '|', ';', '\'', '+', '=',
        ])
}

/// Whether `subject` is internal (certmagic's `SubjectIsInternal`): localhost-style names,
/// `.local`/`.internal`/`.home.arpa` and private/link-local/loopback IPs. These get an internal
/// CA certificate by default so local sites work without any public CA.
fn subject_is_internal(subject: &str) -> bool {
    let subject = normalize_host(subject);
    subject == "localhost"
        || subject.ends_with(".localhost")
        || subject.ends_with(".local")
        || subject.ends_with(".internal")
        || subject.ends_with(".home.arpa")
        || subject_is_internal_ip(&subject)
}

/// Caddy assigns self-signed/internal certificates to IP addresses when no explicit automation
/// policies exist (public CAs do not issue for IPs through the default issuers); with explicit
/// policies an IP would go to whatever the policy says, so it is treated as public here.
fn subject_uses_internal_issuer(subject: &str, explicit_policies: bool) -> bool {
    subject_is_internal(subject) || (subject_is_ip(subject) && !explicit_policies)
}

fn subject_is_ip(subject: &str) -> bool {
    normalize_host(subject).parse::<IpAddr>().is_ok()
}

fn subject_is_internal_ip(subject: &str) -> bool {
    let Ok(address) = subject.parse::<IpAddr>() else {
        return false;
    };
    match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            address.is_loopback()
                || address.is_unspecified()
                || (segments[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (segments[0] & 0xffc0) == 0xfe80 // link local fe80::/10
        }
    }
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
    // Only the first issuer of a policy is honoured: Caddy tries the configured issuers in
    // order as a fallback chain, while this build supports one per policy. Choosing the first
    // issuer keeps the common single-issuer configuration exact and never silently skips a
    // configured issuer.
    let mut issuer = None;
    if let Some((issuer_index, module)) = policy.issuers.iter().enumerate().next() {
        let issuer_path = format!("{path}.issuers[{issuer_index}]");
        match module.module.as_deref() {
            Some("acme") => {
                let value = serde_json::to_value(module).map_err(|error| {
                    Error::Issuer(format!("{issuer_path}: cannot read issuer config: {error}"))
                })?;
                let config = AcmeIssuerConfig::from_json(&value)?;
                issuer = Some(AutomaticHttpsIssuer::Acme(Box::new(config)));
            }
            Some("internal") => {
                if !module.extra.is_empty() {
                    return Err(Error::NotImplemented {
                        feature: "internal CA issuer options in automation policies (T-TLS-031)",
                        tracking_id: "T-TLS-031",
                    });
                }
                issuer = Some(AutomaticHttpsIssuer::Internal);
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
        AutomaticHttpsIssuer::Acme(Box::default())
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
    /// Generation-scoped renewal scheduler for the managed certificates.
    ///
    /// `None` when no managed certificates exist. The scheduler is started by default; dropping
    /// this value stops it, so the owning generation must keep it alive for renewals to run (see
    /// the server-wiring notes in the module docs).
    pub renewals: Option<AutomaticHttpsRenewals>,
}

/// A started (or startable) renewal scheduler plus the shared store it renews into.
///
/// The scheduler publishes renewed certificates through a [`CertificatePublisher`] attached to the
/// [`CertificateResolver`] returned by [`AutomaticHttpsProvisioner::provision`], so a renewal
/// hot-swaps the rustls configuration atomically: in-flight handshakes keep the `Arc` they already
/// resolved and new handshakes use the renewed certificate.
///
/// Lifecycle: [`AutomaticHttpsRenewals::stop`]/[`AutomaticHttpsRenewals::abort`] stop the
/// background task explicitly; dropping the value also aborts it, which prevents leaked scheduler
/// tasks when a generation is retired without an explicit stop.
pub struct AutomaticHttpsRenewals {
    scheduler: Arc<RenewalScheduler>,
    store: Arc<SharedCertificateStore>,
    handle: StdMutex<Option<RenewalSchedulerHandle>>,
}

impl std::fmt::Debug for AutomaticHttpsRenewals {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AutomaticHttpsRenewals")
            .field("running", &self.is_running())
            .field("certificates", &self.store.len())
            .finish()
    }
}

impl AutomaticHttpsRenewals {
    fn new(scheduler: Arc<RenewalScheduler>, store: Arc<SharedCertificateStore>) -> Self {
        Self {
            scheduler,
            store,
            handle: StdMutex::new(None),
        }
    }

    /// The underlying scheduler (also usable via [`Self::run_once`] for deterministic tests).
    pub fn scheduler(&self) -> &Arc<RenewalScheduler> {
        &self.scheduler
    }

    /// The shared certificate store updated after each renewal.
    pub fn store(&self) -> &Arc<SharedCertificateStore> {
        &self.store
    }

    /// Whether the background renewal task is currently running.
    pub fn is_running(&self) -> bool {
        self.handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    /// Whether the background renewal task has finished (never started or stopped/aborted).
    pub fn is_finished(&self) -> bool {
        self.handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|handle| handle.is_finished())
            .unwrap_or(true)
    }

    /// Start the background task if it is not already running.
    ///
    /// Returns whether the task was started by this call.
    pub fn start(&self) -> bool {
        let mut handle = self
            .handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if handle.is_some() || self.scheduler.is_stopped() {
            return false;
        }
        *handle = Some(self.scheduler.start());
        true
    }

    /// Stop the background task and wait for it to finish (idempotent).
    pub async fn stop(&self) {
        let handle = self
            .handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.stop().await;
        }
    }

    /// Ask the background task to stop without waiting (idempotent).
    pub fn abort(&self) {
        let handle = self
            .handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.abort();
        }
    }

    /// Renew every certificate that is due at `now` (deterministic tests and embedders with their
    /// own timer loop).
    pub async fn run_once(&self, now: SystemTime) -> Vec<RenewalOutcome> {
        self.scheduler.run_once(now).await
    }

    /// Earliest time the scheduler has work, taking failed-renewal backoff into account.
    pub fn next_renewal(&self, now: SystemTime) -> Option<RenewalItem> {
        self.scheduler.next_renewal(now)
    }

    /// Recent renewal outcomes (most recent last).
    pub fn history(&self) -> Vec<RenewalOutcome> {
        self.scheduler.history()
    }

    /// Certificates currently tracked for renewal.
    pub fn managed_certificates(&self) -> Vec<Arc<Certificate>> {
        self.store.certificates()
    }
}

impl Drop for AutomaticHttpsRenewals {
    fn drop(&mut self) {
        // Generation-scoped lifecycle: a generation that goes away without an explicit stop must
        // not leave its renewal task running.
        self.abort();
    }
}

/// Obtains missing certificates through the ACME issuer and loads persisted ones from storage.
pub struct AutomaticHttpsProvisioner {
    transport: Arc<dyn AcmeTransport>,
    root: PathBuf,
    challenge_tokens: Arc<Http01TokenStore>,
    tls_alpn01_tokens: Arc<TlsAlpn01TokenStore>,
    clock: Arc<dyn AcmeClock>,
    poll_policy: PollPolicy,
    /// Optional injected CA blob storage; when absent the internal CA is rooted at `root`
    /// (`InternalIssuer::from_data_directory`).
    internal_ca_storage: Option<Arc<dyn CaStorage>>,
    /// CA identifier used by the internal issuer (`local`, matching Caddy's default).
    internal_ca_name: String,
    /// Whether this provisioner has provisioned subjects from the internal CA.
    internal_ca_used: AtomicBool,
    /// Lazily constructed internal CA issuer (CA material loaded once per provisioner); shared
    /// with the renewal issuers so CA state and clock stay consistent.
    internal_issuer: Arc<AsyncMutex<Option<Arc<InternalIssuer>>>>,
    /// Snapshots of local CA certificates for trust installation/diagnostics.
    ca_certificates: StdMutex<BTreeMap<String, CaCertificates>>,
    /// Clock used by the renewal scheduler (system clock in production, manual in tests).
    renewal_clock: Arc<dyn RenewalClock>,
    /// Renewal policy (window, jitter, backoff) used by generation schedulers.
    renewal_policy: RenewalPolicy,
    /// Whether provisioning starts the generation's renewal scheduler by default.
    renewal_scheduler_enabled: bool,
    /// Clock used for internal CA validity windows (tests share a manual clock with renewals).
    internal_ca_clock: Arc<dyn RenewalClock>,
}

impl std::fmt::Debug for AutomaticHttpsProvisioner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AutomaticHttpsProvisioner")
            .field("root", &self.root)
            .field("internal_ca_name", &self.internal_ca_name)
            .field("internal_ca_storage", &self.internal_ca_storage.is_some())
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
            tls_alpn01_tokens: Arc::new(TlsAlpn01TokenStore::new()),
            clock: Arc::new(TokioClock),
            poll_policy: PollPolicy::default(),
            internal_ca_storage: None,
            internal_ca_name: DEFAULT_CA_ID.to_string(),
            internal_ca_used: AtomicBool::new(false),
            internal_issuer: Arc::new(AsyncMutex::new(None)),
            ca_certificates: StdMutex::new(BTreeMap::new()),
            renewal_clock: Arc::new(SystemClock),
            renewal_policy: RenewalPolicy::default(),
            renewal_scheduler_enabled: true,
            internal_ca_clock: Arc::new(SystemClock),
        }
    }

    /// Inject the blob storage used for internal CA material.
    ///
    /// Without this, the internal CA persists under `<data-dir>/pki/authorities/<ca-id>/` via
    /// [`InternalIssuer::from_data_directory`]. Leaf certificates always use the provisioner's
    /// data directory (`CertificateStorage`), matching the ACME path.
    pub fn with_internal_ca_storage(mut self, storage: Arc<dyn CaStorage>) -> Self {
        self.internal_ca_storage = Some(storage);
        self
    }

    /// Set the internal CA identifier used in the Caddy storage layout (default `local`).
    pub fn with_internal_ca_name(mut self, name: impl Into<String>) -> Self {
        self.internal_ca_name = name.into();
        self
    }

    /// Override the clock used for certificate validity of internal-CA leaves.
    ///
    /// Tests share a [`ManualClock`](crate::renewal::ManualClock) between this and
    /// [`Self::with_renewal_clock`] so internal leaf renewal is deterministic.
    pub fn with_internal_ca_clock(mut self, clock: Arc<dyn RenewalClock>) -> Self {
        self.internal_ca_clock = clock;
        self
    }

    /// Override the renewal scheduler clock (production uses [`SystemClock`]; tests use
    /// [`ManualClock`](crate::renewal::ManualClock)).
    pub fn with_renewal_clock(mut self, clock: Arc<dyn RenewalClock>) -> Self {
        self.renewal_clock = clock;
        self
    }

    /// Override the renewal policy (renewal window, jitter, exponential backoff).
    pub fn with_renewal_policy(mut self, policy: RenewalPolicy) -> Self {
        self.renewal_policy = policy;
        self
    }

    /// Enable/disable automatically starting the renewal scheduler after provisioning.
    ///
    /// Disabling is intended for embedders that drive [`AutomaticHttpsRenewals::run_once`] with
    /// their own timer loop and for deterministic tests; a scheduler is still returned so those
    /// callers can start it later with [`AutomaticHttpsRenewals::start`].
    pub fn with_renewal_scheduler(mut self, enabled: bool) -> Self {
        self.renewal_scheduler_enabled = enabled;
        self
    }

    /// Local CA certificates recorded during this provisioner's lifetime.
    ///
    /// Empty until a generation with an internal-CA policy has been provisioned (or
    /// [`Self::ca_certificates`] was called after such a provision). The entries are root +
    /// intermediate chains suitable for trust installation by a server/CLI layer.
    pub fn recorded_ca_certificates(&self) -> Vec<CaCertificates> {
        self.ca_certificates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Local CA certificates for trust installation, loading/recording them on first use.
    ///
    /// Returns an empty vector when no internal-CA policy has been provisioned. This is the
    /// accessor a server/CLI uses to install the local root (`root_pem`/`root_der`); trust
    /// installation and `/pki` endpoints are follow-up work.
    pub async fn ca_certificates(&self) -> Result<Vec<CaCertificates>> {
        if self.internal_ca_used.load(Ordering::Acquire)
            && self
                .ca_certificates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        {
            let issuer = self.internal_issuer().await?;
            self.record_ca_certificates(&issuer).await?;
        }
        Ok(self.recorded_ca_certificates())
    }

    async fn internal_issuer(&self) -> Result<Arc<InternalIssuer>> {
        cached_internal_issuer(
            &self.internal_issuer,
            &self.internal_ca_storage,
            &self.root,
            &self.internal_ca_name,
            &self.internal_ca_clock,
        )
        .await
    }

    async fn record_ca_certificates(&self, issuer: &InternalIssuer) -> Result<()> {
        let certificates = issuer.ca_certificates().await.map_err(|error| {
            Error::Issuer(format!(
                "automatic HTTPS: cannot initialize the internal CA `{}`: {error}",
                issuer.name
            ))
        })?;
        self.ca_certificates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(issuer.name.clone(), certificates);
        Ok(())
    }

    /// The TLS-ALPN-01 challenge-certificate store shared with every issuer this provisioner
    /// builds.
    ///
    /// The server's TLS listeners must use it (with [`crate::tls_alpn::AcmeTlsAlpnResolver`] and
    /// [`crate::tls_server::TlsServerOptions::with_acme_tls_alpn`]) so `acme-tls/1` handshakes are
    /// answered while an order is validated.
    pub fn tls_alpn01_token_store(&self) -> &Arc<TlsAlpn01TokenStore> {
        &self.tls_alpn01_tokens
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
    ///
    /// After provisioning, a generation-scoped [`RenewalScheduler`] is started (unless disabled
    /// with [`Self::with_renewal_scheduler`]) for every managed certificate; it renews due
    /// certificates through the policy's ACME or internal issuer and hot-swaps them into the
    /// returned resolver. Drop/stop [`ProvisionedCertificates::renewals`] when the generation is
    /// retired.
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
        let mut managed: Vec<Certificate> = Vec::new();
        for key in storage.list("").await? {
            let Some(stored) = CertificateStorage::load(&storage, &key).await? else {
                continue;
            };
            if stored.not_after_unix <= now {
                continue;
            }
            let issuer_label = key.split('/').next().unwrap_or("loaded").to_string();
            if let Ok(certificate) = stored_to_certificate(&stored, &issuer_label) {
                if plan.subjects.iter().any(|subject| {
                    certificate
                        .domains
                        .iter()
                        .any(|domain| host_matches(domain, subject))
                }) {
                    managed.push(certificate);
                }
            }
            resolver.insert(TlsCertificate::from_stored(&stored)?)?;
        }

        // Internal-CA policies load (or generate) the local CA before any subject is examined, so
        // a restart that reuses persisted leaves still exposes the CA certificates for trust
        // installation and CA errors surface before partial provisioning.
        if plan
            .policies
            .iter()
            .any(|policy| matches!(policy.issuer, AutomaticHttpsIssuer::Internal))
        {
            self.internal_ca_used.store(true, Ordering::Release);
            let issuer = self.internal_issuer().await?;
            self.record_ca_certificates(&issuer).await?;
        }

        let mut issued = Vec::new();
        for subject in &plan.subjects {
            if resolver.covers(subject)
                && !plan.force_reissue.iter().any(|forced| forced == subject)
            {
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
            let certificate = self.obtain_subject(plan, subject).await?;
            resolver.insert(TlsCertificate::from_cache_certificate(&certificate)?)?;
            managed.push(certificate.clone());
            issued.push(certificate);
        }

        let resolver = Arc::new(resolver);
        let renewals = self.start_renewals(plan, Arc::clone(&resolver), managed)?;
        Ok(ProvisionedCertificates {
            resolver,
            issued,
            renewals,
        })
    }

    async fn obtain_subject(
        &self,
        plan: &AutomaticHttpsPlan,
        subject: &str,
    ) -> Result<Certificate> {
        let policy = plan.policy_for(subject).ok_or_else(|| {
            Error::Issuer(format!(
                "automatic HTTPS: no automation policy matches subject `{subject}`"
            ))
        })?;
        match &policy.issuer {
            AutomaticHttpsIssuer::Internal => {
                let issuer = self.internal_issuer().await?;
                issuer
                    .obtain(&IssuanceRequest {
                        domains: vec![subject.to_string()],
                        internal: true,
                    })
                    .await
                    .map_err(|error| {
                        Error::Issuer(format!(
                            "automatic HTTPS: cannot obtain a local-CA certificate for \
                             `{subject}`: {error}"
                        ))
                    })
            }
            AutomaticHttpsIssuer::Acme(config) => obtain_acme_certificate(
                config,
                &[subject.to_string()],
                &self.transport,
                self.root.clone(),
                &self.challenge_tokens,
                &self.tls_alpn01_tokens,
                &self.clock,
                &self.poll_policy,
            )
            .await
            .map_err(|error| {
                Error::Issuer(format!(
                    "automatic HTTPS: cannot obtain a certificate for `{subject}`: {error}"
                ))
            }),
        }
    }

    fn start_renewals(
        &self,
        plan: &AutomaticHttpsPlan,
        resolver: Arc<CertificateResolver>,
        managed: Vec<Certificate>,
    ) -> Result<Option<AutomaticHttpsRenewals>> {
        if managed.is_empty() {
            return Ok(None);
        }
        let mut unique: Vec<Certificate> = Vec::new();
        for certificate in managed {
            if !unique.iter().any(|existing| {
                existing.domains == certificate.domains
                    && existing.not_before == certificate.not_before
                    && existing.not_after == certificate.not_after
            }) {
                unique.push(certificate);
            }
        }
        if unique.is_empty() {
            return Ok(None);
        }
        let publisher: Arc<dyn CertificatePublisher> = resolver;
        let store = Arc::new(SharedCertificateStore::with_publisher(publisher));
        for certificate in &unique {
            store.insert(certificate.clone())?;
        }
        let issuer: Arc<dyn CertificateIssuer> = Arc::new(RenewalIssuer {
            plan: plan.clone(),
            transport: Arc::clone(&self.transport),
            root: self.root.clone(),
            challenge_tokens: Arc::clone(&self.challenge_tokens),
            tls_alpn01_tokens: Arc::clone(&self.tls_alpn01_tokens),
            acme_clock: Arc::clone(&self.clock),
            poll_policy: self.poll_policy.clone(),
            internal_ca_storage: self.internal_ca_storage.clone(),
            internal_ca_name: self.internal_ca_name.clone(),
            internal_ca_clock: Arc::clone(&self.internal_ca_clock),
            internal_issuer: Arc::clone(&self.internal_issuer),
        });
        let storage: Arc<dyn CertificateStorage> = Arc::new(FileStorage::new(&self.root));
        let scheduler = Arc::new(
            RenewalScheduler::new(
                issuer,
                storage,
                Arc::clone(&store),
                Arc::clone(&self.renewal_clock),
            )
            .with_policy(renewal_policy_for(plan, self.renewal_policy.clone())),
        );
        let renewals = AutomaticHttpsRenewals::new(scheduler, store);
        if self.renewal_scheduler_enabled {
            renewals.start();
        }
        Ok(Some(renewals))
    }
}

/// Choose the renewal policy for a generation's scheduler.
///
/// An explicit ACME `renewal_window` (renew this long before `not_after`) overrides the default
/// one-third-of-lifetime rule. A window at least the certificate's remaining lifetime makes a
/// freshly issued certificate immediately due. When no ACME policy sets a window the provisioner
/// default is used unchanged.
fn renewal_policy_for(plan: &AutomaticHttpsPlan, default: RenewalPolicy) -> RenewalPolicy {
    let window = plan
        .policies
        .iter()
        .find_map(|policy| match &policy.issuer {
            AutomaticHttpsIssuer::Acme(config) => config.renewal_window,
            AutomaticHttpsIssuer::Internal => None,
        });
    match window {
        Some(window) => default.with_renewal_window(Some(window)),
        None => default,
    }
}

/// Construct (once) and cache the internal CA issuer shared by provisioning and renewal.
async fn cached_internal_issuer(
    cache: &Arc<AsyncMutex<Option<Arc<InternalIssuer>>>>,
    storage: &Option<Arc<dyn CaStorage>>,
    root: &std::path::Path,
    name: &str,
    clock: &Arc<dyn RenewalClock>,
) -> Result<Arc<InternalIssuer>> {
    let mut guard = cache.lock().await;
    if let Some(issuer) = guard.as_ref() {
        return Ok(Arc::clone(issuer));
    }
    let issuer = match storage {
        Some(storage) => InternalIssuer::new(Arc::clone(storage), Box::new(FileStorage::new(root))),
        None => InternalIssuer::from_data_directory(root),
    }
    .with_name(name.to_string())
    .with_clock(Arc::clone(clock));
    let issuer = Arc::new(issuer);
    *guard = Some(Arc::clone(&issuer));
    Ok(issuer)
}

/// Build the transport for one ACME issuer configuration.
///
/// Caddy's `trusted_roots_pem_files` (emitted from `acme_ca_root`) replaces the platform trust
/// store for the ACME CA connection; the roots are read eagerly so a bad path fails the
/// generation instead of silently falling back to platform roots. Without explicit roots the
/// provisioner's transport is used unchanged (production: the platform bundle).
fn acme_transport_for_config(
    config: &AcmeIssuerConfig,
    transport: &Arc<dyn AcmeTransport>,
) -> Result<Arc<dyn AcmeTransport>> {
    if !config.has_trusted_roots() {
        return Ok(Arc::clone(transport));
    }
    let roots = config.read_trusted_roots()?;
    transport.with_trusted_roots(roots).map_err(|error| {
        Error::Issuer(format!(
            "automatic HTTPS: cannot apply trusted roots for ACME CA `{}`: {error}",
            config.ca
        ))
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn obtain_acme_certificate(
    config: &AcmeIssuerConfig,
    domains: &[String],
    transport: &Arc<dyn AcmeTransport>,
    root: PathBuf,
    challenge_tokens: &Arc<Http01TokenStore>,
    tls_alpn01_tokens: &Arc<TlsAlpn01TokenStore>,
    clock: &Arc<dyn AcmeClock>,
    poll_policy: &PollPolicy,
) -> Result<Certificate> {
    let transport = acme_transport_for_config(config, transport)?;
    let account_storage: Arc<dyn AcmeStorage> = Arc::new(FileStorage::new(&root));
    let issuer = AcmeIssuer::new(
        config.clone(),
        Arc::clone(&transport),
        account_storage,
        Box::new(FileStorage::new(&root)),
    )
    .with_solver(Arc::new(Http01Solver::new(Arc::clone(challenge_tokens))))
    .with_solver(Arc::new(TlsAlpn01Solver::new(Arc::clone(
        tls_alpn01_tokens,
    ))))
    // Configuration alone selects DNS-01 when `challenges.dns` names a provider.
    .with_configured_dns_solver(Arc::clone(&transport))?
    .with_clock(Arc::clone(clock))
    .with_poll_policy(poll_policy.clone());
    issuer
        .obtain(&IssuanceRequest {
            domains: domains.to_vec(),
            internal: false,
        })
        .await
}

/// Renewal issuer router: picks the ACME or internal issuer per certificate policy.
struct RenewalIssuer {
    plan: AutomaticHttpsPlan,
    transport: Arc<dyn AcmeTransport>,
    root: PathBuf,
    challenge_tokens: Arc<Http01TokenStore>,
    tls_alpn01_tokens: Arc<TlsAlpn01TokenStore>,
    acme_clock: Arc<dyn AcmeClock>,
    poll_policy: PollPolicy,
    internal_ca_storage: Option<Arc<dyn CaStorage>>,
    internal_ca_name: String,
    internal_ca_clock: Arc<dyn RenewalClock>,
    internal_issuer: Arc<AsyncMutex<Option<Arc<InternalIssuer>>>>,
}

impl RenewalIssuer {
    async fn internal_issuer(&self) -> Result<Arc<InternalIssuer>> {
        cached_internal_issuer(
            &self.internal_issuer,
            &self.internal_ca_storage,
            &self.root,
            &self.internal_ca_name,
            &self.internal_ca_clock,
        )
        .await
    }
}

#[async_trait]
impl CertificateIssuer for RenewalIssuer {
    fn name(&self) -> &'static str {
        "automatic_https"
    }

    async fn obtain(&self, request: &IssuanceRequest) -> Result<Certificate> {
        let subject = request.domains.first().ok_or_else(|| {
            Error::Issuer("automatic HTTPS renewal request has no domains".to_string())
        })?;
        let policy = self.plan.policy_for(subject).ok_or_else(|| {
            Error::Issuer(format!(
                "automatic HTTPS: no automation policy matches subject `{subject}`"
            ))
        })?;
        if policy.on_demand {
            return Err(Error::Issuer(format!(
                "automatic HTTPS: on-demand TLS for `{subject}` is not implemented (T-TLS-028)"
            )));
        }
        match &policy.issuer {
            AutomaticHttpsIssuer::Internal => {
                let issuer = self.internal_issuer().await?;
                issuer
                    .obtain(&IssuanceRequest {
                        domains: request.domains.clone(),
                        internal: true,
                    })
                    .await
            }
            AutomaticHttpsIssuer::Acme(config) => {
                obtain_acme_certificate(
                    config,
                    &request.domains,
                    &self.transport,
                    self.root.clone(),
                    &self.challenge_tokens,
                    &self.tls_alpn01_tokens,
                    &self.acme_clock,
                    &self.poll_policy,
                )
                .await
            }
        }
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
    use crate::acme::transport::parse_pem_certificates;
    use crate::acme::{
        AcmeTransport, HttpMethod, HttpRequest, HttpResponse, HyperTransport, MemoryAcmeStorage,
    };
    use crate::renewal::ManualClock;
    use crate::solver::Http01TokenStore;
    use async_trait::async_trait;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::service::service_fn;
    use hyper::{Response as HyperResponse, StatusCode};
    use hyper_util::rt::TokioIo;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn renewal_policy_for_applies_acme_renewal_window() {
        let mut plan = AutomaticHttpsPlan::default();
        let mut acme = AcmeIssuerConfig::default();
        acme.renewal_window = Some(Duration::from_secs(3600));
        plan.policies.push(AutomaticHttpsPolicy {
            issuer: AutomaticHttpsIssuer::Acme(Box::new(acme)),
            ..Default::default()
        });
        let policy = renewal_policy_for(&plan, RenewalPolicy::default());
        assert_eq!(policy.renewal_window, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn renewal_policy_for_keeps_default_without_key_window() {
        let plan = AutomaticHttpsPlan::default(); // no ACME window
        let policy = renewal_policy_for(&plan, RenewalPolicy::default());
        assert_eq!(policy.renewal_window, None);
    }

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

    fn internal_config() -> Config {
        config(json!({
            "apps": {
                "tls": {"automation": {"policies": [
                    {"subjects": ["*.internal.example"], "issuers": [{"module": "internal"}]}
                ]}},
                "http": {"servers": {"srv0": {
                    "listen": ["127.0.0.1:0"],
                    "tls_connection_policies": [{}],
                    "routes": [{"match": [{"host": ["app.internal.example"]}],
                                "handle": [{"handler": "static_response", "body": "ok"}]}]
                }}}
            }
        }))
    }

    fn acme_and_internal_config() -> Config {
        config(json!({
            "apps": {
                "tls": {"automation": {"policies": [
                    {"subjects": ["acme.example"], "issuers": [
                        {"module": "acme", "ca": "https://acme.test/directory"}
                    ]},
                    {"subjects": ["*.internal.example"], "issuers": [{"module": "internal"}]}
                ]}},
                "http": {"servers": {"srv0": {
                    "listen": ["127.0.0.1:0"],
                    "tls_connection_policies": [{}],
                    "routes": [{"match": [{"host": ["acme.example", "app.internal.example"]}],
                                "handle": [{"handler": "static_response", "body": "ok"}]}]
                }}}
            }
        }))
    }

    /// A transport that fails the test if the ACME path is used at all.
    #[derive(Clone, Default, Debug)]
    struct NoopTransport {
        calls: Arc<Mutex<usize>>,
    }

    #[async_trait]
    impl AcmeTransport for NoopTransport {
        async fn request(&self, _request: HttpRequest) -> Result<HttpResponse> {
            *self.calls.lock().unwrap() += 1;
            Err(Error::Issuer(
                "ACME transport must not be used for internal-CA policies".to_string(),
            ))
        }
    }

    /// CA storage that always fails, for loud-failure tests.
    struct FailingCaStorage;

    #[async_trait]
    impl CaStorage for FailingCaStorage {
        fn name(&self) -> &'static str {
            "failing"
        }

        async fn load(&self, _key: &str) -> Result<Option<Vec<u8>>> {
            Err(Error::Issuer("ca storage exploded".to_string()))
        }

        async fn store(&self, _key: &str, _value: &[u8]) -> Result<()> {
            Err(Error::Issuer("ca storage exploded".to_string()))
        }
    }

    /// Perform a real rustls handshake trusting only `root_der`, proving the leaf chains to the
    /// exposed local root (with the intermediate in the served chain).
    async fn assert_serves_verified_chain(
        resolver: Arc<CertificateResolver>,
        root_der: Vec<u8>,
        server_name: &str,
    ) {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let server_config = crate::tls_server::build_server_config(
            resolver,
            &crate::tls_server::TlsServerOptions::default(),
        )
        .expect("server config builds");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if let Ok(mut stream) = acceptor.accept(stream).await {
                let _ = stream.write_all(b"ok").await;
                let _ = stream.shutdown().await;
            }
        });
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(root_der))
            .expect("exposed local root is a valid trust anchor");
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string()).unwrap();
        let stream = connector
            .connect(name, tcp)
            .await
            .expect("chain verifies against the exposed internal CA root");
        assert_eq!(
            stream.get_ref().1.peer_certificates().unwrap().len(),
            2,
            "served chain is leaf + intermediate"
        );
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
    fn plan_retains_trusted_roots_for_acme_issuer() {
        let mut value = serde_json::to_value(https_config()).unwrap();
        value["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]
            ["trusted_roots_pem_files"] = json!(["/etc/ssl/private/test-ca.pem"]);
        let plan = plan(&Config::from_value(value).unwrap()).unwrap().unwrap();
        match &plan.policy_for("www.example.com").unwrap().issuer {
            AutomaticHttpsIssuer::Acme(config) => {
                assert!(config.has_trusted_roots());
                assert_eq!(
                    config.trusted_roots_pem_files,
                    vec![PathBuf::from("/etc/ssl/private/test-ca.pem")]
                );
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
        // `automatic_https.disable` (Caddyfile `auto_https off`) makes automatic HTTPS inert,
        // even when automation policies are present; manual TLS still uses configured certs.
        assert!(plan(&Config::from_value(value).unwrap()).unwrap().is_none());
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

    fn implicit_https_config(hosts: &[&str]) -> Config {
        config(json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "routes": [{"match": [{"host": hosts}],
                            "handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}}
        }))
    }

    #[test]
    fn plan_defaults_on_for_implicit_https_hosts() {
        let plan = plan(&implicit_https_config(&["example.com"]))
            .unwrap()
            .expect("default-on plan");
        assert_eq!(plan.subjects, vec!["example.com".to_string()]);
        assert_eq!(plan.redirect_hosts, vec!["example.com".to_string()]);
        assert!(plan.redirects_enabled);
        assert!(plan.needs_http_listener);
        assert_eq!(plan.https_port, 443);
        match &plan.policy_for("example.com").unwrap().issuer {
            AutomaticHttpsIssuer::Acme(config) => {
                assert!(config.ca.contains("letsencrypt.org"), "{}", config.ca)
            }
            other => panic!("public host must use the default ACME policy: {other:?}"),
        }
    }

    #[test]
    fn plan_defaults_off_for_http_only_sites() {
        let plain = config(json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":80"],
                "routes": [{"match": [{"host": ["example.com"]}],
                            "handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}}
        }));
        assert!(plan(&plain).unwrap().is_none());
    }

    #[test]
    fn plan_default_on_honours_disable_redirects() {
        let mut value = serde_json::to_value(implicit_https_config(&["example.com"])).unwrap();
        value["apps"]["http"]["servers"]["srv0"]["automatic_https"] =
            json!({"disable_redirects": true});
        let plan = plan(&Config::from_value(value).unwrap()).unwrap().unwrap();
        assert_eq!(plan.subjects, vec!["example.com".to_string()]);
        assert!(!plan.redirects_enabled);
        assert!(
            plan.needs_http_listener,
            "challenge serving still needs the HTTP listener"
        );
    }

    #[test]
    fn plan_default_on_honours_disable_certs() {
        let mut value = serde_json::to_value(implicit_https_config(&["example.com"])).unwrap();
        // `disable_certs` is preserved in the untyped automatic_https object until the typed
        // model/adapter expose it.
        value["apps"]["http"]["servers"]["srv0"]["automatic_https"] =
            json!({"disable_certificates": true});
        let plan = plan(&Config::from_value(value).unwrap()).unwrap().unwrap();
        assert!(
            plan.subjects.is_empty(),
            "certificate management is disabled"
        );
        assert_eq!(plan.redirect_hosts, vec!["example.com".to_string()]);
        assert!(plan.redirects_enabled);
    }

    #[test]
    fn plan_default_on_honours_skip_and_skip_certs() {
        let mut value = serde_json::to_value(implicit_https_config(&[
            "example.com",
            "skip.example.com",
            "certs.example.com",
        ]))
        .unwrap();
        value["apps"]["http"]["servers"]["srv0"]["automatic_https"] = json!({
            "skip": ["skip.example.com"],
            "skip_certificates": ["certs.example.com"]
        });
        let plan = plan(&Config::from_value(value).unwrap()).unwrap().unwrap();
        assert!(plan.subjects.contains(&"example.com".to_string()));
        assert!(!plan.subjects.contains(&"skip.example.com".to_string()));
        assert!(!plan.subjects.contains(&"certs.example.com".to_string()));
        assert!(!plan
            .redirect_hosts
            .contains(&"skip.example.com".to_string()));
        assert!(
            plan.redirect_hosts
                .contains(&"certs.example.com".to_string()),
            "skip_certs only disables certificate management, not redirects"
        );
    }

    #[test]
    fn plan_default_on_routes_internal_names_to_the_internal_issuer() {
        let internal_plan = plan(&implicit_https_config(&["localhost", "app.internal"]))
            .unwrap()
            .expect("internal default-on plan");
        assert!(internal_plan.subjects.contains(&"localhost".to_string()));
        assert!(internal_plan.subjects.contains(&"app.internal".to_string()));
        assert!(matches!(
            internal_plan.policy_for("localhost").unwrap().issuer,
            AutomaticHttpsIssuer::Internal
        ));
        assert!(matches!(
            internal_plan.policy_for("app.internal").unwrap().issuer,
            AutomaticHttpsIssuer::Internal
        ));

        // With no explicit policies, IP addresses are self-signed by the internal CA as well.
        let plan = plan(&implicit_https_config(&["203.0.113.7"]))
            .unwrap()
            .expect("public IP default-on plan");
        assert!(matches!(
            plan.policy_for("203.0.113.7").unwrap().issuer,
            AutomaticHttpsIssuer::Internal
        ));
    }

    #[test]
    fn plan_ignores_loaded_manual_certificates_unless_forced() {
        let mut value = serde_json::to_value(implicit_https_config(&["example.com"])).unwrap();
        value["apps"]["tls"] = json!({"certificates": {"load_pem": [{
            "certificate": include_str!("../testdata/https/example.com.pem"),
            "key": include_str!("../testdata/https/example.com.key")
        }]}});
        let loaded_plan = plan(&Config::from_value(value.clone()).unwrap())
            .unwrap()
            .unwrap();
        assert!(
            loaded_plan.subjects.is_empty(),
            "a loaded certificate suppresses automatic management"
        );
        assert!(loaded_plan.redirects_enabled, "redirects still apply");

        value["apps"]["http"]["servers"]["srv0"]["automatic_https"] =
            json!({"ignore_loaded_certificates": true});
        let forced_plan = plan(&Config::from_value(value).unwrap()).unwrap().unwrap();
        assert_eq!(forced_plan.subjects, vec!["example.com".to_string()]);
        assert_eq!(forced_plan.force_reissue, vec!["example.com".to_string()]);
    }

    #[test]
    fn plan_derives_implicit_https_on_non_standard_port() {
        // Caddy treats a host matcher on a non-HTTP listener port as implicit HTTPS on that port.
        let value = json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8443"],
                "routes": [{"match": [{"host": ["example.com"]}],
                            "handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}}
        });
        let plan = plan(&Config::from_value(value).unwrap()).unwrap().unwrap();
        assert_eq!(plan.subjects, vec!["example.com".to_string()]);
        assert_eq!(plan.tls_ports, vec![8443]);
        assert_eq!(plan.redirect_ports.get("example.com"), Some(&8443));
        assert_eq!(plan.redirect_hosts, vec!["example.com".to_string()]);
        assert!(plan.redirects_enabled);
        assert!(
            plan.needs_http_listener,
            "redirects/challenges need a derived HTTP listener"
        );
    }

    #[test]
    fn plan_honours_server_level_skip_for_plain_http_site() {
        // Caddyfile `http://127.0.0.1:<port>` adapts to a host matcher plus
        // `automatic_https.skip`; the skipped host must not be managed or demand TLS.
        let value = json!({
            "apps": {"http": {"http_port": 80, "servers": {"srv0": {
                "listen": [":12345"],
                "automatic_https": {"skip": ["127.0.0.1"]},
                "routes": [{"match": [{"host": ["127.0.0.1"]}],
                            "handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}}
        });
        assert!(plan(&Config::from_value(value).unwrap()).unwrap().is_none());
    }

    #[test]
    fn plan_rejects_mixed_cleartext_and_tls_listeners() {
        let value = json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":80", ":443"],
                "routes": [{"match": [{"host": ["example.com"]}],
                            "handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}}
        });
        let error = plan(&Config::from_value(value).unwrap()).unwrap_err();
        assert!(
            error.to_string().contains("cannot mix cleartext"),
            "{error}"
        );
    }

    #[test]
    fn plan_preserves_dns_challenge_configuration_for_the_issuer() {
        let mut value = serde_json::to_value(https_config()).unwrap();
        value["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["challenges"] = json!({"dns": {
            "provider": {"name": "cloudflare", "api_token": "config-token"},
            "propagation_timeout": 5_000_000_000_i64
        }});
        let plan = plan(&Config::from_value(value).unwrap())
            .unwrap()
            .expect("DNS challenge policy yields a plan");
        match &plan.policy_for("www.example.com").unwrap().issuer {
            AutomaticHttpsIssuer::Acme(config) => {
                assert_eq!(config.dns_provider.as_deref(), Some("cloudflare"));
                let challenge = config
                    .dns_challenge
                    .as_ref()
                    .expect("challenges.dns configuration retained in the plan");
                assert_eq!(challenge.provider, "cloudflare");
                assert_eq!(
                    challenge
                        .settings
                        .get("api_token")
                        .and_then(serde_json::Value::as_str),
                    Some("config-token")
                );
                assert_eq!(
                    challenge.propagation_timeout_duration(),
                    Some(std::time::Duration::from_secs(5))
                );
            }
            other => panic!("unexpected issuer: {other:?}"),
        }
    }

    #[test]
    fn plan_accepts_internal_issuers_and_rejects_unknown_or_on_demand() {
        let mut value = serde_json::to_value(https_config()).unwrap();
        value["apps"]["tls"]["automation"]["policies"][0]["issuers"] =
            json!([{"module": "internal"}]);
        let selected = plan(&Config::from_value(value.clone()).unwrap())
            .unwrap()
            .expect("internal policy yields a plan");
        assert!(matches!(
            selected.policy_for("www.example.com").unwrap().issuer,
            AutomaticHttpsIssuer::Internal
        ));

        value["apps"]["tls"]["automation"]["policies"][0]["issuers"] = json!([{"module": "bogus"}]);
        let error = plan(&Config::from_value(value.clone()).unwrap()).unwrap_err();
        assert!(error.to_string().contains("not implemented"), "{error}");

        value["apps"]["tls"]["automation"]["policies"][0]["issuers"] =
            json!([{"module": "internal", "name": "custom"}]);
        let error = plan(&Config::from_value(value.clone()).unwrap()).unwrap_err();
        assert!(
            error.to_string().contains("internal CA issuer options"),
            "{error}"
        );

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
        fail_new_order: Mutex<bool>,
        renewed_certificate: Mutex<bool>,
        base_url: Mutex<String>,
    }

    #[derive(Clone, Default, Debug)]
    struct FakeAcme {
        inner: Arc<FakeInner>,
    }

    const CERT_PEM: &str = include_str!("../testdata/https/example.com.pem");
    const CERT_KEY_PEM: &str = include_str!("../testdata/https/example.com.key");
    /// Later-validity certificate returned for renewals.
    const RENEWED_CERT_PEM: &str = include_str!("../testdata/renewal/renewed-example.com.pem");

    impl FakeAcme {
        fn set_fail_new_order(&self, fail: bool) {
            *self.inner.fail_new_order.lock().unwrap() = fail;
        }

        fn set_renewed_certificate(&self, renewed: bool) {
            *self.inner.renewed_certificate.lock().unwrap() = renewed;
        }

        /// Point the fake CA's advertised URLs at a local server (used by the real-TLS test).
        fn set_base_url(&self, base_url: impl Into<String>) {
            *self.inner.base_url.lock().unwrap() = base_url.into();
        }
    }

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
            let base = {
                let configured = self.inner.base_url.lock().unwrap().clone();
                if configured.is_empty() {
                    "https://acme.test".to_string()
                } else {
                    configured
                }
            };
            let body = if request.method == HttpMethod::Get && url.ends_with("/directory") {
                json!({
                    "newNonce": format!("{base}/new-nonce"),
                    "newAccount": format!("{base}/new-account"),
                    "newOrder": format!("{base}/new-order"),
                    "revokeCert": format!("{base}/revoke")
                })
            } else if url.ends_with("/new-account") {
                json!({"status": "valid", "contact": ["mailto:ops@example.com"]})
            } else if url.ends_with("/new-order") {
                if *self.inner.fail_new_order.lock().unwrap() {
                    return Ok(HttpResponse::with_problem(
                        400,
                        &json!({
                            "type": "urn:ietf:params:acme:error:serverInternal",
                            "detail": "fake CA is configured to fail newOrder",
                            "status": 400
                        }),
                    )
                    .unwrap()
                    .with_header("Replay-Nonce", "nonce"));
                }
                json!({"status": "pending",
                       "authorizations": [format!("{base}/authz/1")],
                       "finalize": format!("{base}/finalize/1")})
            } else if url.ends_with("/authz/1") {
                let acked = *self.inner.challenge_acked.lock().unwrap();
                if acked {
                    json!({"status": "valid", "identifier": {"type": "dns", "value": "example.com"}, "challenges": []})
                } else {
                    json!({"status": "pending", "identifier": {"type": "dns", "value": "example.com"},
                           "challenges": [{"type": "http-01", "url": format!("{base}/challenge/1"), "token": "tok", "status": "pending"}]})
                }
            } else if url.ends_with("/challenge/1") {
                *self.inner.challenge_acked.lock().unwrap() = true;
                json!({"type": "http-01", "url": format!("{base}/challenge/1"), "token": "tok", "status": "processing"})
            } else if url.ends_with("/finalize/1") {
                *self.inner.finalize_seen.lock().unwrap() = true;
                json!({"status": "processing"})
            } else if url.ends_with("/order/1") {
                if *self.inner.finalize_seen.lock().unwrap() {
                    json!({"status": "valid", "certificate": format!("{base}/cert/1"),
                           "authorizations": [format!("{base}/authz/1")],
                           "finalize": format!("{base}/finalize/1")})
                } else {
                    json!({"status": "ready",
                           "authorizations": [format!("{base}/authz/1")],
                           "finalize": format!("{base}/finalize/1")})
                }
            } else if url.ends_with("/cert/1") {
                let renewed = *self.inner.renewed_certificate.lock().unwrap();
                let pem = if renewed { RENEWED_CERT_PEM } else { CERT_PEM };
                return Ok(HttpResponse::new(200)
                    .with_header("Content-Type", "application/pem-certificate-chain")
                    .with_header("Replay-Nonce", "nonce")
                    .with_body(pem));
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
                response = response.with_header("Location", format!("{base}/account/1"));
            }
            if url.ends_with("/new-order") {
                response = response.with_header("Location", format!("{base}/order/1"));
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
    async fn internal_policy_provisions_local_leaf_and_exposes_trust_root() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&internal_config()).unwrap().unwrap();
        let transport = NoopTransport::default();
        let provisioner = AutomaticHttpsProvisioner::new(
            Arc::new(transport.clone()),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        );
        let result = provisioner.provision(&plan, None).await.unwrap();

        assert_eq!(result.issued.len(), 1);
        assert_eq!(result.issued[0].issuer, "local");
        assert_eq!(
            result.issued[0].cert_chain_der.len(),
            2,
            "leaf plus intermediate"
        );
        assert!(result.resolver.covers("app.internal.example"));
        assert_eq!(
            *transport.calls.lock().unwrap(),
            0,
            "internal policies must not touch the ACME transport"
        );

        let ca = provisioner.ca_certificates().await.unwrap();
        assert_eq!(ca.len(), 1);
        assert!(!ca[0].root_der.is_empty());
        assert!(ca[0].root_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(ca[0].chain_pem.contains("-----END CERTIFICATE-----"));
        assert_serves_verified_chain(
            Arc::clone(&result.resolver),
            ca[0].root_der.clone(),
            "app.internal.example",
        )
        .await;

        let keys = FileStorage::new(directory.path()).list("").await.unwrap();
        assert_eq!(keys.len(), 1, "one persisted internal leaf: {keys:?}");
        assert!(keys[0].starts_with("local/"), "{keys:?}");
    }

    #[tokio::test]
    async fn restart_reuses_the_internal_ca_and_persisted_leaf() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&internal_config()).unwrap().unwrap();
        let first = AutomaticHttpsProvisioner::new(
            Arc::new(NoopTransport::default()),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        );
        let first_result = first.provision(&plan, None).await.unwrap();
        assert_eq!(first_result.issued.len(), 1);
        let first_ca = first.ca_certificates().await.unwrap();
        let first_keys = FileStorage::new(directory.path()).list("").await.unwrap();
        assert_eq!(first_ca.len(), 1);

        // A fresh provisioner over the same data directory behaves like a process restart.
        let second = AutomaticHttpsProvisioner::new(
            Arc::new(NoopTransport::default()),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        );
        let second_result = second.provision(&plan, None).await.unwrap();
        assert!(
            second_result.issued.is_empty(),
            "persisted leaf must be reused instead of reissued"
        );
        assert!(second_result.resolver.covers("app.internal.example"));
        let second_ca = second.ca_certificates().await.unwrap();
        assert_eq!(second_ca.len(), 1);
        assert_eq!(
            second_ca[0].root_der, first_ca[0].root_der,
            "the persisted CA root must be reused"
        );
        assert_eq!(
            FileStorage::new(directory.path()).list("").await.unwrap(),
            first_keys,
            "no additional certificate files after restart"
        );
        assert_serves_verified_chain(
            Arc::clone(&second_result.resolver),
            second_ca[0].root_der.clone(),
            "app.internal.example",
        )
        .await;
    }

    #[tokio::test]
    async fn injectable_ca_storage_and_ca_name_are_used() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&internal_config()).unwrap().unwrap();
        let ca_storage = Arc::new(MemoryAcmeStorage::new());
        let provisioner = AutomaticHttpsProvisioner::new(
            Arc::new(NoopTransport::default()),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_internal_ca_storage(ca_storage.clone())
        .with_internal_ca_name("custom");
        let result = provisioner.provision(&plan, None).await.unwrap();
        assert_eq!(result.issued.len(), 1);
        assert!(result.resolver.covers("app.internal.example"));

        let keys = FileStorage::new(directory.path()).list("").await.unwrap();
        assert!(
            keys.iter().any(|key| key.starts_with("custom/")),
            "leaves use the configured CA id: {keys:?}"
        );
        let root = CaStorage::load(ca_storage.as_ref(), "pki/authorities/custom/root.crt")
            .await
            .unwrap()
            .expect("root certificate persisted in the injected CA storage");
        assert!(String::from_utf8_lossy(&root).contains("BEGIN CERTIFICATE"));
        let ca = provisioner.ca_certificates().await.unwrap();
        assert_eq!(ca.len(), 1);
    }

    #[tokio::test]
    async fn internal_and_acme_policies_coexist() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&acme_and_internal_config()).unwrap().unwrap();
        let transport = Arc::new(FakeAcme::default());
        let provisioner = AutomaticHttpsProvisioner::new(
            transport.clone(),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        );
        let result = provisioner.provision(&plan, None).await.unwrap();
        assert_eq!(result.issued.len(), 2, "one ACME and one internal leaf");
        assert!(result.resolver.covers("acme.example"));
        assert!(result.resolver.covers("app.internal.example"));
        assert!(
            !transport.inner.requests.lock().unwrap().is_empty(),
            "ACME policy uses the ACME transport"
        );
        let ca = provisioner.ca_certificates().await.unwrap();
        assert_eq!(
            ca.len(),
            1,
            "only the internal policy records CA certificates"
        );
        let keys = FileStorage::new(directory.path()).list("").await.unwrap();
        assert!(
            keys.iter().any(|key| key.starts_with("local/")),
            "internal leaf stored under the local CA id: {keys:?}"
        );
        assert!(
            keys.iter().any(|key| key.contains("acme.test")),
            "ACME leaf stored under the ACME issuer key: {keys:?}"
        );
    }

    #[tokio::test]
    async fn internal_ca_failures_are_loud() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&internal_config()).unwrap().unwrap();
        let provisioner = AutomaticHttpsProvisioner::new(
            Arc::new(NoopTransport::default()),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_internal_ca_storage(Arc::new(FailingCaStorage));
        let error = provisioner.provision(&plan, None).await.unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("cannot initialize the internal CA"),
            "{message}"
        );
        assert!(message.contains("ca storage exploded"), "{message}");
        assert!(
            provisioner.ca_certificates().await.is_err()
                || provisioner.recorded_ca_certificates().is_empty()
        );
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
            tls_ports: Vec::new(),
            redirect_ports: BTreeMap::new(),
            redirect_all_port: 443,
            force_reissue: Vec::new(),
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
    // ---- renewal wiring ------------------------------------------------------------------

    fn acme_renewal_config() -> Config {
        config(json!({
            "apps": {
                "tls": {"automation": {"policies": [
                    {"subjects": ["example.com"], "issuers": [
                        {"module": "acme", "ca": "https://acme.test/directory"}
                    ]}
                ]}},
                "http": {"servers": {"srv0": {
                    "listen": ["127.0.0.1:0"],
                    "tls_connection_policies": [{}],
                    "routes": [{"match": [{"host": ["example.com"]}],
                                "handle": [{"handler": "static_response", "body": "ok"}]}]
                }}}
            }
        }))
    }

    fn renewal_start() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn renewal_test_policy() -> RenewalPolicy {
        RenewalPolicy::new()
            .with_jitter(Duration::ZERO)
            .with_backoff(Duration::from_secs(10), Duration::from_secs(300))
    }

    /// The policy's default due time: two thirds through the certificate's lifetime.
    fn renewal_due(certificate: &Certificate) -> SystemTime {
        let lifetime = certificate
            .not_after
            .duration_since(certificate.not_before)
            .unwrap_or_default();
        certificate.not_before + lifetime.mul_f64(2.0 / 3.0)
    }

    fn leaf_der(pem: &str) -> Vec<u8> {
        crate::tls_server::certificates_from_pem(pem).expect("fixture PEM parses")[0]
            .as_ref()
            .to_vec()
    }

    #[tokio::test]
    async fn renewal_renews_due_acme_certificate_and_hot_swaps_resolver() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&acme_renewal_config()).unwrap().unwrap();
        let clock = Arc::new(ManualClock::new(renewal_start()));
        let fake = Arc::new(FakeAcme::default());
        let provisioner = AutomaticHttpsProvisioner::new(
            fake.clone(),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_renewal_clock(clock.clone())
        .with_renewal_policy(renewal_test_policy())
        .with_renewal_scheduler(false);
        let result = provisioner.provision(&plan, None).await.unwrap();
        assert_eq!(result.issued.len(), 1);
        let renewals = result.renewals.expect("renewal scheduler returned");
        assert!(
            !renewals.is_running(),
            "background task is disabled for deterministic tests"
        );
        assert_eq!(renewals.managed_certificates().len(), 1);

        let old_certificate = result.issued[0].clone();
        let old_leaf = leaf_der(CERT_PEM);
        let new_leaf = leaf_der(RENEWED_CERT_PEM);
        let before = result
            .resolver
            .select(Some("example.com"))
            .expect("certificate resolved");
        assert_eq!(before.cert[0].as_ref(), old_leaf.as_slice());

        clock.set(renewal_due(&old_certificate) + Duration::from_secs(1));
        fake.set_renewed_certificate(true);
        let outcomes = renewals.run_once(clock.now()).await;
        assert_eq!(outcomes.len(), 1);
        assert!(
            outcomes[0].is_renewed(),
            "expected a successful renewal: {outcomes:?}"
        );

        let after = result
            .resolver
            .select(Some("example.com"))
            .expect("renewed certificate resolved");
        assert!(
            !Arc::ptr_eq(&before, &after),
            "resolver must hot-swap to a new CertifiedKey"
        );
        assert_eq!(
            before.cert[0].as_ref(),
            old_leaf.as_slice(),
            "an in-flight handshake keeps the certificate it resolved"
        );
        assert_eq!(
            after.cert[0].as_ref(),
            new_leaf.as_slice(),
            "new handshakes see the renewed certificate"
        );
        let managed = renewals.managed_certificates();
        assert_eq!(managed.len(), 1);
        assert!(managed[0].not_after > old_certificate.not_after);
        assert!(
            renewals.next_renewal(clock.now()).unwrap().due_at > clock.now(),
            "the renewed certificate is not due immediately"
        );
        assert!(renewals.history().iter().any(RenewalOutcome::is_renewed));
    }

    #[tokio::test]
    async fn failed_renewal_keeps_certificate_and_backs_off() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&acme_renewal_config()).unwrap().unwrap();
        let clock = Arc::new(ManualClock::new(renewal_start()));
        let fake = Arc::new(FakeAcme::default());
        let provisioner = AutomaticHttpsProvisioner::new(
            fake.clone(),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_renewal_clock(clock.clone())
        .with_renewal_policy(renewal_test_policy())
        .with_renewal_scheduler(false);
        let result = provisioner.provision(&plan, None).await.unwrap();
        let renewals = result.renewals.expect("renewal scheduler");
        let old_certificate = result.issued[0].clone();
        let old_not_after = old_certificate.not_after;
        let before = result.resolver.select(Some("example.com")).unwrap();

        clock.set(renewal_due(&old_certificate) + Duration::from_secs(1));
        let now = clock.now();
        fake.set_fail_new_order(true);
        let outcomes = renewals.run_once(now).await;
        let RenewalOutcome::Failed { retry_at, .. } = &outcomes[0] else {
            panic!("expected a failed renewal: {outcomes:?}");
        };
        let retry_at = *retry_at;
        assert!(retry_at > now, "failure schedules a backoff retry");
        let after_failure = result.resolver.select(Some("example.com")).unwrap();
        assert!(
            Arc::ptr_eq(&before, &after_failure),
            "a failed renewal keeps the old certificate installed"
        );
        assert_eq!(renewals.managed_certificates()[0].not_after, old_not_after);

        // Before the retry time, the certificate is not due again.
        let outcomes = renewals.run_once(now + Duration::from_secs(1)).await;
        assert!(
            outcomes.is_empty(),
            "backoff suppresses retries until retry_at: {outcomes:?}"
        );
        assert_eq!(
            renewals
                .next_renewal(now + Duration::from_secs(1))
                .unwrap()
                .due_at,
            retry_at,
            "the scheduler reports the backoff retry time"
        );

        // The next attempt at the retry time fails again and backs off further.
        clock.set(retry_at);
        let outcomes = renewals.run_once(retry_at).await;
        let RenewalOutcome::Failed {
            retry_at: retry_again_at,
            ..
        } = &outcomes[0]
        else {
            panic!("expected a second failed renewal: {outcomes:?}");
        };
        let first_delay = retry_at.duration_since(now).unwrap();
        let second_delay = retry_again_at.duration_since(retry_at).unwrap();
        assert!(
            second_delay > first_delay,
            "exponential backoff: {first_delay:?} then {second_delay:?}"
        );
    }

    #[tokio::test]
    async fn scheduler_lifecycle_starts_stops_and_does_not_leak_across_generations() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&acme_renewal_config()).unwrap().unwrap();
        let fake = Arc::new(FakeAcme::default());
        let provisioner = AutomaticHttpsProvisioner::new(
            fake,
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        );
        let first = provisioner.provision(&plan, None).await.unwrap();
        let first_renewals = first.renewals.expect("first generation scheduler");
        assert!(first_renewals.is_running());
        assert_eq!(first_renewals.store().len(), 1);

        // A new generation over the same provisioner gets its own scheduler and reuses certs.
        let second = provisioner.provision(&plan, None).await.unwrap();
        assert!(second.issued.is_empty(), "certificate is reused");
        let second_renewals = second.renewals.expect("second generation scheduler");
        assert!(second_renewals.is_running());

        first_renewals.stop().await;
        assert!(!first_renewals.is_running());
        assert!(first_renewals.is_finished());
        assert!(first_renewals.scheduler().is_stopped());
        second_renewals.stop().await;
        assert!(!second_renewals.is_running());
        assert!(second_renewals.scheduler().is_stopped());

        // Dropping a generation without an explicit stop aborts its scheduler (no leak).
        let third = provisioner.provision(&plan, None).await.unwrap();
        let third_renewals = third.renewals.expect("third generation scheduler");
        assert!(third_renewals.is_running());
        let scheduler = Arc::clone(third_renewals.scheduler());
        drop(third_renewals);
        assert!(scheduler.is_stopped(), "drop aborts the scheduler task");
    }

    #[tokio::test]
    async fn scheduler_can_be_started_explicitly_when_disabled() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&acme_renewal_config()).unwrap().unwrap();
        let provisioner = AutomaticHttpsProvisioner::new(
            Arc::new(FakeAcme::default()),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_renewal_scheduler(false);
        let result = provisioner.provision(&plan, None).await.unwrap();
        let renewals = result.renewals.expect("scheduler returned");
        assert!(!renewals.is_running());
        assert!(renewals.start());
        assert!(renewals.is_running());
        assert!(!renewals.start(), "starting twice is a no-op");
        renewals.stop().await;
        assert!(!renewals.is_running());
    }

    #[tokio::test]
    async fn internal_leaf_renews_with_manual_clock() {
        let directory = tempfile::tempdir().unwrap();
        let plan = plan(&internal_config()).unwrap().unwrap();
        let clock = Arc::new(ManualClock::new(renewal_start()));
        let provisioner = AutomaticHttpsProvisioner::new(
            Arc::new(NoopTransport::default()),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_renewal_clock(clock.clone())
        .with_internal_ca_clock(clock.clone())
        .with_renewal_policy(renewal_test_policy())
        .with_renewal_scheduler(false);
        let result = provisioner.provision(&plan, None).await.unwrap();
        let old_certificate = result.issued[0].clone();
        assert_eq!(old_certificate.issuer, "local");
        let renewals = result.renewals.expect("renewal scheduler");
        let ca_before = provisioner.ca_certificates().await.unwrap();

        clock.set(renewal_due(&old_certificate) + Duration::from_secs(1));
        let before = result
            .resolver
            .select(Some("app.internal.example"))
            .expect("internal leaf resolves");
        let outcomes = renewals.run_once(clock.now()).await;
        assert!(
            outcomes[0].is_renewed(),
            "expected internal leaf renewal: {outcomes:?}"
        );
        let after = result
            .resolver
            .select(Some("app.internal.example"))
            .expect("renewed internal leaf resolves");
        assert!(!Arc::ptr_eq(&before, &after));
        let managed = renewals.managed_certificates();
        assert_eq!(managed.len(), 1);
        assert_eq!(managed[0].issuer, "local");
        assert!(
            managed[0].not_after > old_certificate.not_after,
            "renewed internal leaf has a later expiry"
        );
        let ca_after = provisioner.ca_certificates().await.unwrap();
        assert_eq!(
            ca_after[0].root_der, ca_before[0].root_der,
            "internal leaf renewal reuses the local CA"
        );
    }

    // ---- native trusted roots over real TLS ------------------------------------------------

    const ACME_TLS_CERT_PEM: &str = include_str!("../testdata/acme/localhost-cert.pem");
    const ACME_TLS_KEY_PEM: &str = include_str!("../testdata/acme/localhost-key.pem");
    const UNRELATED_ACME_ROOT_PEM: &str = include_str!("../testdata/acme/unrelated-cert.pem");

    fn pem_block_der(pem: &str, label: &str) -> Vec<u8> {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let mut inside = false;
        let mut base64 = String::new();
        for line in pem.lines() {
            let line = line.trim();
            if line == begin {
                inside = true;
            } else if line == end {
                inside = false;
            } else if inside {
                base64.push_str(line);
            }
        }
        STANDARD.decode(base64.as_bytes()).unwrap()
    }

    /// Serve the scripted fake ACME CA over real HTTPS on 127.0.0.1, with its advertised URLs
    /// pointing back at the local server. Returns the bound port.
    fn spawn_tls_acme_server(fake: FakeAcme) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        fake.set_base_url(format!("https://127.0.0.1:{port}"));
        let listener = TcpListener::from_std(listener).unwrap();
        let certificates = parse_pem_certificates(ACME_TLS_CERT_PEM.as_bytes()).unwrap();
        let key = pem_block_der(ACME_TLS_KEY_PEM, "PRIVATE KEY");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                certificates,
                rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let fake = fake.clone();
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service =
                        service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            let fake = fake.clone();
                            async move {
                                let (parts, body) = request.into_parts();
                                let body = body
                                    .collect()
                                    .await
                                    .map(|collected| collected.to_bytes().to_vec())
                                    .unwrap_or_default();
                                let path = parts
                                    .uri
                                    .path_and_query()
                                    .map(|path| path.as_str())
                                    .unwrap_or("/");
                                let url = format!("https://127.0.0.1:{port}{path}");
                                let method = match parts.method {
                                    hyper::Method::GET => HttpMethod::Get,
                                    hyper::Method::HEAD => HttpMethod::Head,
                                    hyper::Method::POST => HttpMethod::Post,
                                    hyper::Method::DELETE => HttpMethod::Delete,
                                    _ => HttpMethod::Post,
                                };
                                let headers = parts
                                    .headers
                                    .iter()
                                    .map(|(name, value)| {
                                        (
                                            name.to_string(),
                                            value.to_str().unwrap_or_default().to_string(),
                                        )
                                    })
                                    .collect();
                                let request = HttpRequest {
                                    method,
                                    url,
                                    headers,
                                    body,
                                };
                                let response = match fake.request(request).await {
                                    Ok(response) => response,
                                    Err(error) => {
                                        return Ok::<_, std::convert::Infallible>(
                                            HyperResponse::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(Full::new(Bytes::from(error.to_string())))
                                                .unwrap(),
                                        );
                                    }
                                };
                                let mut builder = HyperResponse::builder().status(
                                    StatusCode::from_u16(response.status)
                                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                                );
                                for (name, value) in &response.headers {
                                    builder = builder.header(name.as_str(), value.as_str());
                                }
                                Ok::<_, std::convert::Infallible>(
                                    builder.body(Full::new(Bytes::from(response.body))).unwrap(),
                                )
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        port
    }

    fn local_acme_config(port: u16, trusted_roots: Option<PathBuf>) -> Config {
        let mut value = serde_json::to_value(https_config()).unwrap();
        value["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["ca"] =
            json!(format!("https://127.0.0.1:{port}/directory"));
        if let Some(root) = trusted_roots {
            value["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]
                ["trusted_roots_pem_files"] = json!([root]);
        }
        Config::from_value(value).unwrap()
    }

    #[tokio::test]
    async fn provisioner_honors_configured_trusted_roots_over_real_tls() {
        let fake = FakeAcme::default();
        let port = spawn_tls_acme_server(fake.clone());
        let directory = tempfile::tempdir().unwrap();
        let root_file = directory.path().join("acme-ca.pem");
        std::fs::write(&root_file, ACME_TLS_CERT_PEM).unwrap();
        let mut plan = plan(&local_acme_config(port, Some(root_file)))
            .unwrap()
            .expect("plan exists");
        plan.subjects = vec!["www.example.com".to_string()];
        // Start from a transport that trusts only an unrelated root: success is only possible if
        // the configured trusted_roots_pem_files replace that store.
        let base: Arc<dyn AcmeTransport> = Arc::new(
            HyperTransport::with_root_certificates(
                parse_pem_certificates(UNRELATED_ACME_ROOT_PEM.as_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let provisioner = AutomaticHttpsProvisioner::new(
            base,
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_renewal_scheduler(false);
        let result = provisioner
            .provision(&plan, None)
            .await
            .expect("real-TLS ACME issuance with configured trusted roots");
        assert_eq!(result.issued.len(), 1);
        assert!(result.resolver.covers("www.example.com"));
        let requests = fake.inner.requests.lock().unwrap();
        assert!(
            requests
                .iter()
                .any(|request| request.url.ends_with("/directory")),
            "the ACME client must have fetched the directory over real TLS"
        );
        assert!(
            requests
                .iter()
                .any(|request| request.url.contains("/new-order")),
            "the ACME order flow must have run over real TLS"
        );
    }

    #[tokio::test]
    async fn renewal_uses_configured_trusted_roots_over_real_tls() {
        let fake = FakeAcme::default();
        let port = spawn_tls_acme_server(fake.clone());
        let directory = tempfile::tempdir().unwrap();
        let root_file = directory.path().join("acme-ca.pem");
        std::fs::write(&root_file, ACME_TLS_CERT_PEM).unwrap();
        let mut plan = plan(&local_acme_config(port, Some(root_file)))
            .unwrap()
            .expect("plan exists");
        plan.subjects = vec!["www.example.com".to_string()];
        let clock = Arc::new(ManualClock::new(renewal_start()));
        let base: Arc<dyn AcmeTransport> = Arc::new(
            HyperTransport::with_root_certificates(
                parse_pem_certificates(UNRELATED_ACME_ROOT_PEM.as_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let provisioner = AutomaticHttpsProvisioner::new(
            base,
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_renewal_clock(clock.clone())
        .with_renewal_policy(renewal_test_policy())
        .with_renewal_scheduler(false);
        let result = provisioner
            .provision(&plan, None)
            .await
            .expect("initial issuance with configured trusted roots");
        let issued = result.issued[0].clone();
        let renewals = result.renewals.expect("renewal scheduler");
        fake.set_renewed_certificate(true);
        clock.set(renewal_due(&issued) + Duration::from_secs(1));
        let outcomes = renewals.run_once(clock.now()).await;
        assert!(
            outcomes[0].is_renewed(),
            "renewal must use the configured roots: {outcomes:?}"
        );
        let managed = renewals.managed_certificates();
        assert_eq!(managed.len(), 1);
        assert!(managed[0].not_after > issued.not_after);
    }

    #[tokio::test]
    async fn provisioner_rejects_acme_tls_without_configured_trusted_roots() {
        let fake = FakeAcme::default();
        let port = spawn_tls_acme_server(fake.clone());
        let directory = tempfile::tempdir().unwrap();
        let mut plan = plan(&local_acme_config(port, None)).unwrap().unwrap();
        plan.subjects = vec!["www.example.com".to_string()];
        let base: Arc<dyn AcmeTransport> = Arc::new(
            HyperTransport::with_root_certificates(
                parse_pem_certificates(UNRELATED_ACME_ROOT_PEM.as_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let provisioner = AutomaticHttpsProvisioner::new(
            base,
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_renewal_scheduler(false);
        let error = provisioner.provision(&plan, None).await.unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("invalid peer certificate") || message.contains("UnknownIssuer"),
            "expected a TLS trust failure without configured roots, got: {message}"
        );
        assert!(
            fake.inner.requests.lock().unwrap().is_empty(),
            "no ACME request may reach an untrusted CA"
        );
    }

    #[tokio::test]
    async fn provisioner_fails_loudly_when_transport_cannot_reconfigure_trust() {
        let directory = tempfile::tempdir().unwrap();
        let root_file = directory.path().join("ca.pem");
        std::fs::write(&root_file, ACME_TLS_CERT_PEM).unwrap();
        let mut plan = plan(&local_acme_config(18443, Some(root_file)))
            .unwrap()
            .unwrap();
        plan.subjects = vec!["www.example.com".to_string()];
        // A scripted test transport has no TLS stack to reconfigure; it must error rather than
        // silently keep trusting the platform store.
        let fake = Arc::new(FakeAcme::default());
        let provisioner = AutomaticHttpsProvisioner::new(
            fake.clone(),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_renewal_scheduler(false);
        let error = provisioner.provision(&plan, None).await.unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("does not support explicit trusted roots"),
            "expected a loud transport error, got: {message}"
        );
        assert!(fake.inner.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn provisioner_fails_loudly_for_missing_trusted_root_file() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing-ca.pem");
        let mut plan = plan(&local_acme_config(18443, Some(missing.clone())))
            .unwrap()
            .unwrap();
        plan.subjects = vec!["www.example.com".to_string()];
        let fake = Arc::new(FakeAcme::default());
        let provisioner = AutomaticHttpsProvisioner::new(
            fake.clone(),
            directory.path(),
            Arc::new(Http01TokenStore::new()),
        )
        .with_renewal_scheduler(false);
        let error = provisioner.provision(&plan, None).await.unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains(missing.to_string_lossy().as_ref()),
            "error must name the bad trusted-roots path: {message}"
        );
        assert!(message.contains("cannot read"), "{message}");
        assert!(
            fake.inner.requests.lock().unwrap().is_empty(),
            "no ACME request may be attempted when explicit roots cannot be loaded"
        );
    }
}
