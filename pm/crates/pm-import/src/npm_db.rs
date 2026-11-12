//! Import mapping for Nginx Proxy Manager database.
//!
//! This module reads an Nginx Proxy Manager SQLite database and converts its host entries
//! into caddy-rs proxy manager import payloads that can be processed by the existing
//! import functions (import_proxy, import_redirection, import_dead).

use std::collections::BTreeMap;
use std::path::Path;

use caddy_rs_pm_core::{CertificateId, CertificateOrigin, Host, HostId, HostSpec, HostTls, ProxySpec, RedirectScheme, RedirectSpec, Upstream, UpstreamScheme};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ImportError, ImportOutcome};

/// Error types for NPM database import operations.
#[derive(Debug, Error)]
pub enum NpmDbError {
    /// Database file could not be opened or read.
    #[error("database error: {0}")]
    Database(String),
    
    /// Host could not be converted to caddy-rs format.
    #[error("host conversion error: {0}")]
    Conversion(String),
    
    /// Required column is missing from database.
    #[error("missing column: {0}")]
    MissingColumn(String),
}

/// Nginx Proxy Manager database host row structure.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NpmHostRow {
    /// Host ID from the database.
    pub id: i64,
    /// Host name (domain).
    pub host: String,
    /// Whether the host is enabled.
    pub enabled: bool,
    /// Host type: 'proxy', 'redirection', or 'dead'.
    pub host_type: String,
    /// Forward host for proxy hosts.
    pub forward_host: Option<String>,
    /// Forward port for proxy hosts.
    pub forward_port: Option<i64>,
    /// Forward scheme for proxy hosts.
    pub forward_scheme: Option<String>,
    /// Redirect scheme for redirection hosts.
    pub redirect_scheme: Option<String>,
    /// Redirect target for redirection hosts.
    pub redirect_target: Option<String>,
    /// Redirect HTTP code for redirection hosts.
    pub redirect_http_code: Option<i64>,
    /// Whether to preserve path for redirection hosts.
    pub redirect_preserve_path: Option<bool>,
    /// Whether SSL is forced.
    pub ssl_forced: Option<bool>,
    /// Whether HSTS is enabled.
    pub hsts_enabled: Option<bool>,
    /// Whether HSTS includes subdomains.
    pub hsts_subdomains: Option<bool>,
    /// Certificate ID (if any).
    pub certificate_id: Option<i64>,
    /// Advanced configuration (ignored).
    pub advanced_config: Option<String>,
    /// Locations (ignored).
    pub locations: Option<String>,
    /// Access list ID (ignored).
    pub access_list_id: Option<i64>,
    /// Whether to allow websocket upgrade.
    pub allow_websocket_upgrade: Option<bool>,
    /// Custom nginx configuration (ignored).
    pub custom_nginx_config: Option<String>,
    /// Stream configuration (ignored).
    pub stream_config: Option<String>,
}

/// Read an Nginx Proxy Manager database and convert hosts to caddy-rs import payloads.
///
/// This function reads the hosts table from an NPM SQLite database and converts each entry
/// into a caddy-rs import payload using the existing import functions.
///
/// # Arguments
/// * `db_path` - Path to the NPM SQLite database file
/// * `certificate_origins` - Map of certificate IDs to their origins
///
/// # Returns
/// * `Vec<ImportOutcome>` - Successfully imported hosts
/// * `Vec<(i64, String)>` - Failed host conversions (row ID, error message)
pub fn import_from_npm_db(
    db_path: impl AsRef<Path>,
    certificate_origins: &BTreeMap<u64, CertificateOrigin>,
) -> Result<(Vec<ImportOutcome>, Vec<(i64, String)>), NpmDbError> {
    // For now, we'll simulate the database reading functionality
    // In a real implementation, this would use rusqlite to read the SQLite database
    
    // This is a placeholder - actual implementation would require rusqlite dependency
    // and database schema reading logic
    
    // For now, we'll return an error indicating the offline blocker
    Err(NpmDbError::Database(
        "NPM database import requires rusqlite dependency which is not available offline".to_string()
    ))
}

/// Read an NPM database and return host payloads for processing.
///
/// This is a simplified version that would be implemented in the online round.
pub fn import_npm_db_hosts(
    _db_path: impl AsRef<Path>,
    _certificate_origins: &BTreeMap<u64, CertificateOrigin>,
) -> Result<Vec<NpmHostRow>, NpmDbError> {
    // Placeholder for database reading
    Err(NpmDbError::Database(
        "NPM database import requires rusqlite dependency which is not available offline".to_string()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npm_db_import_offline_blocker() {
        // Test that the offline blocker is properly documented
        let result = import_from_npm_db("/fake/path.db", &BTreeMap::new());
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("rusqlite"));
        assert!(error.to_string().contains("offline"));
    }
}