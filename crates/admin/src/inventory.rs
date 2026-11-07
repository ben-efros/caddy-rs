//! Runtime inventory snapshot types for the caddy-rs `GET /runtime/inventory` extension
//! (T-ADMIN-023).
//!
//! Caddy v2.11.7 has **no** general runtime-inventory endpoint: its admin API exposes
//! `/config/`, `/id/`, `/stop`, `/debug/*`, plus module-owned routes such as `/pki/`,
//! `/metrics`, `/reverse_proxy/upstreams` (`admin.go` route registrations and the `admin.api`
//! modules). The server runtime's listeners, health-check schedulers and managed-certificate
//! inventory are therefore not available from Caddy in one place. caddy-rs adds a read-only
//! extension endpoint (like `/healthz`, DIV-0018) whose JSON shape is defined here and documented
//! in ADMIN.md; it is not a Caddy-parity feature.
//!
//! The server runtime owns the live data and installs a [`RuntimeIntrospectionSource`] on the
//! [`AdminApi`](crate::AdminApi). Snapshots are copied under a lock and installed after a
//! successful apply (and cleared after shutdown), so the admin endpoint never reaches into runtime
//! internals and never blocks a reload: it reports the last completed snapshot and marks it
//! `stale` when the active generation has moved on.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// One bound (or configured-but-unbound) listener in the inventory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryListener {
    /// HTTP server name (`apps.http.servers.<name>`).
    pub server: String,
    /// Configured listen address (`apps.http.servers.<name>.listen`).
    pub configured: String,
    /// Actual bound address, when the runtime has bound it (`:0` resolves here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<String>,
    /// Listener network: `tcp`, `udp` or `unix`.
    pub network: String,
    /// Whether this listener terminates TLS.
    pub tls: bool,
    /// Configured/default protocols offered on this listener (`h1`, `h2`, `h3`).
    pub protocols: Vec<String>,
    /// Whether the listener is the HTTP/3 (QUIC/UDP) listener.
    pub http3: bool,
}

/// The admin listener's bound address, when enabled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryAdminListener {
    /// Configured admin listen address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured: Option<String>,
    /// Actual bound address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<String>,
}

/// One certificate known to the runtime (managed by automatic HTTPS or loaded from `apps.tls`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryCertificate {
    /// Subject name (first domain/SAN, matching Caddy's certificate naming).
    pub subject: String,
    /// Subject alternative names / covered domains.
    pub sans: Vec<String>,
    /// Issuer description (ACME URL, internal CA name, or `loaded`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Expiry as Unix seconds (fractional), matching the access-log `ts` representation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<f64>,
    /// `managed` (automatic HTTPS renewal store) or `loaded` (`apps.tls.certificates`).
    pub source: String,
}

/// One active health-check scheduler group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryHealthChecks {
    /// Generation that owns the schedulers.
    pub generation: u64,
    /// Number of scheduler tasks (one per configured upstream pool).
    pub checkers: usize,
}

/// A complete snapshot of the server runtime's inventory as of the last completed apply.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuntimeInventorySnapshot {
    /// Generation id the snapshot was taken for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation_id: Option<u64>,
    /// Admin listener state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<InventoryAdminListener>,
    /// Configured listeners and their bound state.
    #[serde(default)]
    pub listeners: Vec<InventoryListener>,
    /// Managed and manually loaded certificates.
    #[serde(default)]
    pub certificates: Vec<InventoryCertificate>,
    /// Active health-check scheduler groups.
    #[serde(default)]
    pub health_checks: Vec<InventoryHealthChecks>,
}

impl RuntimeInventorySnapshot {
    /// Unix seconds of the snapshot's generation load time, supplied by the caller.
    pub fn empty_for_generation(generation_id: Option<u64>) -> Self {
        Self {
            generation_id,
            ..Self::default()
        }
    }
}

/// Source of live runtime-inventory snapshots (implemented by the server runtime).
pub trait RuntimeIntrospectionSource: Send + Sync + std::fmt::Debug {
    /// Copy the most recent completed snapshot. Must be cheap and never block on a reload: callers
    /// are on the admin request path.
    fn snapshot(&self) -> RuntimeInventorySnapshot;
}

/// Convert a `SystemTime` to Unix seconds (fractional), `None` before the epoch.
pub fn unix_seconds(time: SystemTime) -> Option<f64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_serde_omits_absent_optional_fields_repr() {
        let snapshot = RuntimeInventorySnapshot::empty_for_generation(None);
        let value = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(value["listeners"], serde_json::json!([]));
        assert_eq!(value["certificates"], serde_json::json!([]));
        assert_eq!(value["health_checks"], serde_json::json!([]));
        assert!(value.get("generation_id").is_none());
        assert!(value.get("admin").is_none());
    }

    #[test]
    fn unix_seconds_handles_epoch_and_pre_epoch() {
        assert_eq!(unix_seconds(SystemTime::UNIX_EPOCH), Some(0.0));
        assert_eq!(
            unix_seconds(SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(1500)),
            Some(1.5)
        );
        assert_eq!(
            unix_seconds(SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1)),
            None
        );
    }
}
