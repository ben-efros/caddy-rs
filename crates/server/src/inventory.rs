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
    InventoryAdminListener, InventoryAutomaticHttps, InventoryCertificate, InventoryHealthChecks,
    InventoryListener, RuntimeIntrospectionSource, RuntimeInventorySnapshot,
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

/// Maximum length, in bytes, of the recorded automatic-HTTPS error text.
const AUTOMATIC_HTTPS_ERROR_LIMIT: usize = 2048;

/// Record a failed automatic-HTTPS provisioning attempt for the runtime inventory.
///
/// `domains` are the subject hostnames the attempt tried to obtain (the pending plan's
/// `subjects`), and `error` is the provisioning error's `Display` text: it carries the ACME/CA
/// failure (problem type, detail) or the internal-CA error and never contains private key
/// material. The text is bounded to [`AUTOMATIC_HTTPS_ERROR_LIMIT`] bytes on a char boundary so a
/// pathological CA response cannot bloat the admin response.
pub fn automatic_https_failure(
    generation_id: u64,
    domains: Vec<String>,
    error: &str,
) -> InventoryAutomaticHttps {
    let mut text = error.to_string();
    if text.len() > AUTOMATIC_HTTPS_ERROR_LIMIT {
        let mut end = AUTOMATIC_HTTPS_ERROR_LIMIT;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
    InventoryAutomaticHttps {
        generation_id,
        failed_at: caddy_rs_admin::inventory::unix_seconds(std::time::SystemTime::now())
            .unwrap_or(0.0),
        domains,
        error: text,
    }
}

/// Attach the last failed automatic-HTTPS attempt to a snapshot.
///
/// The rest of the snapshot stays the last *completed* apply, so the admin endpoint keeps
/// `snapshot.available`/`stale` honest: after a failed apply the serving generation and its
/// listener/certificate data are the previous generation's, and `stale` reports the mismatch
/// between the store's generation and that snapshot.
pub(crate) fn with_automatic_https_failure(
    snapshot: RuntimeInventorySnapshot,
    failure: Option<InventoryAutomaticHttps>,
) -> RuntimeInventorySnapshot {
    RuntimeInventorySnapshot {
        automatic_https: failure,
        ..snapshot
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_https_failure_bounds_the_error_text_on_a_char_boundary() {
        let failure = automatic_https_failure(7, vec!["example.com".to_string()], "acme: boom");
        assert_eq!(failure.generation_id, 7);
        assert_eq!(failure.domains, vec!["example.com".to_string()]);
        assert_eq!(failure.error, "acme: boom");
        assert!(failure.failed_at > 0.0);

        // Multi-byte text at the limit is truncated without splitting a character.
        let long = "é".repeat(AUTOMATIC_HTTPS_ERROR_LIMIT);
        let failure = automatic_https_failure(8, Vec::new(), &long);
        assert!(failure.error.len() <= AUTOMATIC_HTTPS_ERROR_LIMIT + '…'.len_utf8());
        assert!(failure.error.ends_with('…'));
        assert!(failure.error.is_char_boundary(failure.error.len()));
    }
}
