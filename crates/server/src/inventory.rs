//! Live runtime-inventory snapshot for the caddy-rs `GET /runtime/inventory` admin extension
//! (T-ADMIN-023).
//!
//! Caddy v2.11.7 has no general runtime-inventory endpoint (see `external/caddy/admin.go` route
//! registrations: config/id/stop/debug plus module-owned `/pki`, `/metrics`,
//! `/reverse_proxy/upstreams`). This module implements the server half of caddy-rs's documented
//! extension: the runtime refreshes a complete [`RuntimeInventorySnapshot`] after every successful
//! apply and clears it on shutdown, and the admin API only copies the last completed snapshot.
//! That keeps the extension read-only and non-blocking during reloads; the admin endpoint marks a
//! snapshot whose generation no longer matches the active one as `stale` instead of presenting it
//! as current.

use std::sync::{Arc, RwLock};

use caddy_rs_admin::inventory::{
    InventoryAdminListener, InventoryCertificate, InventoryHealthChecks, InventoryListener,
    RuntimeIntrospectionSource, RuntimeInventorySnapshot,
};

/// Shared, replaceable runtime-inventory snapshot.
#[derive(Debug, Default)]
pub struct RuntimeInventorySource {
    snapshot: RwLock<RuntimeInventorySnapshot>,
}

impl RuntimeInventorySource {
    /// Create an empty source (the admin endpoint reports `snapshot.available = false`).
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Install the snapshot of a successfully applied generation.
    pub fn install(&self, snapshot: RuntimeInventorySnapshot) {
        *self
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = snapshot;
    }

    /// Clear the snapshot on shutdown.
    pub fn clear(&self) {
        self.install(RuntimeInventorySnapshot::default());
    }
}

impl RuntimeIntrospectionSource for RuntimeInventorySource {
    fn snapshot(&self) -> RuntimeInventorySnapshot {
        self.snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// Build the listener inventory for one decoded configuration plus the runtime's bound status.
pub fn listener_inventory(
    config: &caddy_rs_core::Config,
    bound: &std::collections::BTreeMap<String, String>,
) -> Vec<InventoryListener> {
    let Some(http) = config.http() else {
        return Vec::new();
    };
    let https_port = http.https_port.unwrap_or(443);
    let mut listeners = Vec::new();
    for (server_name, server) in &http.servers {
        let policies = server
            .tls_connection_policies
            .as_ref()
            .is_some_and(|policies| !policies.is_empty());
        for configured in &server.listen {
            let (network, http3) = caddy_rs_core::ListenAddr::parse(configured)
                .map(|address| match address.network {
                    caddy_rs_core::Network::Tcp => ("tcp".to_string(), false),
                    caddy_rs_core::Network::Udp => ("udp".to_string(), cfg!(feature = "http3")),
                    caddy_rs_core::Network::Unix => ("unix".to_string(), false),
                })
                .unwrap_or_else(|_| ("unknown".to_string(), false));
            let tls = if network == "tcp" {
                caddy_rs_tls::listener_uses_tls(configured, https_port, policies).unwrap_or(false)
            } else {
                false
            };
            #[cfg(feature = "http3")]
            let protocols = server
                .protocols
                .clone()
                .unwrap_or_else(|| vec!["h1".to_string(), "h2".to_string(), "h3".to_string()]);
            #[cfg(not(feature = "http3"))]
            let protocols = server
                .protocols
                .clone()
                .unwrap_or_else(|| vec!["h1".to_string(), "h2".to_string()]);
            listeners.push(InventoryListener {
                server: server_name.clone(),
                configured: configured.clone(),
                bound: bound.get(configured).cloned(),
                network,
                tls,
                protocols,
                http3,
            });
        }
    }
    listeners.sort_by(|left, right| {
        (&left.server, &left.configured).cmp(&(&right.server, &right.configured))
    });
    listeners
}

/// Build the certificate inventory: managed certificates from the automatic-HTTPS renewal store
/// plus manually loaded `apps.tls.certificates`.
pub fn certificate_inventory(
    config: &caddy_rs_core::Config,
    managed: &[Arc<caddy_rs_tls::Certificate>],
) -> Vec<InventoryCertificate> {
    let mut certificates = Vec::new();
    for certificate in managed {
        let subject = certificate.domains.first().cloned().unwrap_or_default();
        certificates.push(InventoryCertificate {
            subject,
            sans: certificate.domains.clone(),
            issuer: Some(certificate.issuer.clone()),
            not_after: caddy_rs_admin::inventory::unix_seconds(certificate.not_after),
            source: "managed".to_string(),
        });
    }
    if let Some(tls) = config.tls() {
        match caddy_rs_tls::certificates_from_tls_app(tls) {
            Ok(loaded) => {
                for certificate in loaded {
                    let leaf = certificate.chain().first().map(|der| der.as_ref());
                    let info = leaf.and_then(caddy_rs_admin::pki::certificate_info_from_der);
                    let subject = info
                        .as_ref()
                        .and_then(|info| info.common_name.clone())
                        .or_else(|| certificate.names().first().cloned())
                        .unwrap_or_default();
                    let sans = info
                        .as_ref()
                        .map(|info| info.dns_names.clone())
                        .filter(|names| !names.is_empty())
                        .unwrap_or_else(|| certificate.names().to_vec());
                    certificates.push(InventoryCertificate {
                        subject,
                        sans,
                        issuer: info
                            .as_ref()
                            .and_then(|info| info.issuer_common_name.clone()),
                        not_after: info
                            .as_ref()
                            .and_then(|info| info.not_after_unix)
                            .map(|seconds| seconds as f64),
                        source: "loaded".to_string(),
                    });
                }
            }
            Err(error) => {
                tracing::warn!(%error, "runtime inventory: cannot list loaded certificates");
            }
        }
    }
    certificates
        .sort_by(|left, right| (&left.source, &left.subject).cmp(&(&right.subject, &right.source)));
    certificates
}

/// Build the admin-listener inventory entry.
pub fn admin_inventory(
    configured: Option<String>,
    bound: Option<String>,
) -> Option<InventoryAdminListener> {
    if configured.is_none() && bound.is_none() {
        return None;
    }
    Some(InventoryAdminListener { configured, bound })
}

/// Build the health-check scheduler inventory entries.
pub fn health_check_inventory<'a>(
    schedulers: impl Iterator<Item = (&'a u64, &'a Vec<caddy_rs_proxy::HealthCheckScheduler>)>,
) -> Vec<InventoryHealthChecks> {
    let mut entries: Vec<InventoryHealthChecks> = schedulers
        .map(|(generation, schedulers)| InventoryHealthChecks {
            generation: *generation,
            checkers: schedulers.len(),
        })
        .collect();
    entries.sort_by_key(|entry| entry.generation);
    entries
}
