//! Configuration transaction engine for atomic config changes with staging, diff, apply, rollback, and history.
//!
//! This crate provides a transactional interface for managing Caddy configuration changes.
//! It supports staging configurations, computing diffs, atomic application with optimistic
//! concurrency control, rollback to previous revisions, and a full revision history.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use xxhash_rust::xxh3::xxh3_64;

mod diff;
mod revision_store;
mod validation;

pub use diff::{Diff, DiffKind};
pub use revision_store::{
    InMemoryRevisionStore, PersistentRevisionStore, RevisionRecord, RevisionStore, RevisionStoreExt,
};
pub use validation::{validate_config_structure, ConfigStructureError};

/// Unique identifier for a host route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostId(pub String);

impl HostId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for HostId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a configuration generation with its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Generation {
    /// The configuration JSON value.
    pub config: Value,
    /// The xxHash64 hash of the configuration (used as ETag).
    pub hash: String,
    /// Monotonically increasing revision number.
    pub revision: u64,
    /// Timestamp when this generation was created.
    pub timestamp: DateTime<Utc>,
}

impl Generation {
    /// Create a new generation from a config value.
    pub fn new(config: Value, revision: u64) -> Self {
        let hash = compute_hash(&config);
        let timestamp = Utc::now();
        Self {
            config,
            hash,
            revision,
            timestamp,
        }
    }

    /// Get the ETag for this generation (format: `W/"<revision>"`).
    pub fn etag(&self) -> String {
        format!("W/\"{}\"", self.revision)
    }
}

/// A staged configuration ready for application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedConfig {
    /// The configuration JSON value.
    pub config: Value,
    /// The xxHash64 hash of the configuration.
    pub hash: String,
    /// Timestamp when this config was staged.
    pub timestamp: DateTime<Utc>,
}

impl StagedConfig {
    /// Create a new staged config from a config value.
    pub fn new(config: Value) -> Self {
        let hash = compute_hash(&config);
        let timestamp = Utc::now();
        Self {
            config,
            hash,
            timestamp,
        }
    }
}

/// Errors that can occur during config transactions.
#[derive(Debug, Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TxError {
    /// Precondition failed (e.g., If-Match header mismatch).
    #[error("precondition failed: {message}")]
    PreconditionFailed { message: String },

    /// Configuration validation error with JSON path.
    #[error("validation error at {path}: {message}")]
    Validation { path: String, message: String },

    /// Requested resource not found.
    #[error("not found: {resource}")]
    NotFound { resource: String },

    /// Internal error.
    #[error("internal error: {message}")]
    Internal { message: String },

    /// Quarantine operation error.
    #[error("quarantine error for host {host_id}: {message}")]
    Quarantine { host_id: String, message: String },
}

impl TxError {
    pub fn precondition_failed(message: impl Into<String>) -> Self {
        Self::PreconditionFailed {
            message: message.into(),
        }
    }

    pub fn validation(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            path: path.into(),
            message: message.into(),
        }
    }

    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    pub fn quarantine(host_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Quarantine {
            host_id: host_id.into(),
            message: message.into(),
        }
    }
}

/// Status of a revision in history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RevisionStatus {
    /// Revision was successfully applied.
    Applied,
    /// Revision was rolled back to.
    RolledBack,
    /// Revision application failed.
    Failed,
}

/// The main configuration transaction manager.
pub struct ConfigTx<S: RevisionStore> {
    /// The currently active generation.
    active_generation: Arc<RwLock<Option<Generation>>>,
    /// The currently staged configuration.
    staged: Mutex<Option<StagedConfig>>,
    /// Revision store for persistence.
    revisions: S,
}

impl<S: RevisionStore + RevisionStoreExt> ConfigTx<S> {
    /// Create a new ConfigTx with the given revision store.
    pub fn new(revisions: S) -> Self {
        Self {
            active_generation: Arc::new(RwLock::new(None)),
            staged: Mutex::new(None),
            revisions,
        }
    }

    /// Get the currently active generation.
    pub fn active_generation(&self) -> Option<Generation> {
        self.active_generation.read().unwrap().clone()
    }

    /// Get the currently staged configuration.
    pub fn staged_config(&self) -> Option<StagedConfig> {
        self.staged.lock().unwrap().clone()
    }

    /// Stage a new configuration.
    ///
    /// Validates that the JSON is a valid Caddy config structure (apps.http, apps.tls, etc.),
    /// computes the xxHash64 hash, and returns the staged configuration.
    pub fn stage(&self, config: Value) -> Result<StagedConfig, TxError> {
        // Validate config structure
        validate_config_structure(&config).map_err(|e| TxError::validation(e.path, e.message))?;

        let staged = StagedConfig::new(config);
        *self.staged.lock().unwrap() = Some(staged.clone());
        Ok(staged)
    }

    /// Compute the diff between staged and active configuration.
    ///
    /// Returns None if there is no staged config or no active generation.
    /// Compares routes by @id to determine added/removed/modified routes.
    pub fn diff(&self) -> Option<Diff> {
        let staged = self.staged.lock().unwrap().clone()?;
        let active = self.active_generation.read().unwrap().clone()?;
        Some(diff::compute_diff(&active.config, &staged.config))
    }

    /// Apply the staged configuration atomically.
    ///
    /// If `if_match` is provided, it must match the active generation's ETag (`W/"<revision>"`).
    /// Atomically swaps active = staged, increments revision, records revision in store,
    /// clears staged, and returns the new generation.
    /// On failure (precondition mismatch, validation error), active is unchanged.
    pub fn apply(&self, if_match: Option<String>) -> Result<Generation, TxError> {
        // Take the staged config
        let staged = self
            .staged
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| TxError::precondition_failed("no staged configuration"))?;

        // Validate the staged config again before applying
        validate_config_structure(&staged.config)
            .map_err(|e| TxError::validation(e.path, e.message))?;

        // Check precondition
        let mut active_guard = self.active_generation.write().unwrap();
        if let Some(if_match) = if_match {
            let active = active_guard.as_ref().ok_or_else(|| {
                TxError::precondition_failed("precondition failed: no active generation")
            })?;
            if active.etag() != if_match {
                return Err(TxError::precondition_failed(format!(
                    "ETag mismatch: expected {}, got {}",
                    active.etag(),
                    if_match
                )));
            }
        }

        // Create new generation with incremented revision
        let new_revision = active_guard.as_ref().map(|g| g.revision).unwrap_or(0) + 1;
        let new_generation = Generation::new(staged.config, new_revision);

        // Record in revision store
        let record = RevisionRecord {
            revision: new_generation.revision,
            hash: new_generation.hash.clone(),
            timestamp: new_generation.timestamp,
            status: RevisionStatus::Applied,
            error: None,
        };
        self.revisions
            .record_generation(record, new_generation.clone())
            .map_err(|e| TxError::internal(format!("failed to record revision: {}", e)))?;

        // Atomically swap
        *active_guard = Some(new_generation.clone());

        Ok(new_generation)
    }

    /// Quarantine specific host routes in the staged configuration.
    ///
    /// Marks specific host routes as quarantined by adding a `@id` filter or removing them.
    /// Used when a host has invalid upstream.
    pub fn quarantine(&self, host_ids: &[HostId]) -> Result<(), TxError> {
        let mut staged_guard = self.staged.lock().unwrap();
        let staged = staged_guard
            .as_mut()
            .ok_or_else(|| TxError::precondition_failed("no staged configuration"))?;

        // Modify the staged config to quarantine the specified hosts
        let config = &mut staged.config;

        // Navigate to apps.http.servers.*.routes
        if let Some(apps) = config.get_mut("apps").and_then(|a| a.as_object_mut()) {
            if let Some(http) = apps.get_mut("http").and_then(|h| h.as_object_mut()) {
                if let Some(servers) = http.get_mut("servers").and_then(|s| s.as_object_mut()) {
                    for (_, server) in servers.iter_mut() {
                        if let Some(routes) =
                            server.get_mut("routes").and_then(|r| r.as_array_mut())
                        {
                            // Filter out routes that match the quarantined host_ids
                            routes.retain(|route| {
                                if let Some(route_obj) = route.as_object() {
                                    if let Some(route_id) =
                                        route_obj.get("@id").and_then(|v| v.as_str())
                                    {
                                        let host_id = HostId::new(route_id);
                                        return !host_ids.contains(&host_id);
                                    }
                                }
                                true
                            });
                        }
                    }
                }
            }
        }

        // Recompute hash after modification
        staged.hash = compute_hash(&staged.config);
        staged.timestamp = Utc::now();

        Ok(())
    }

    /// Rollback to a previous revision.
    ///
    /// Restores a previous generation as the active configuration.
    pub fn rollback(&self, revision: u64) -> Result<Generation, TxError> {
        // Retrieve the revision from the store
        let record = self
            .revisions
            .get(revision)
            .ok_or_else(|| TxError::not_found(format!("revision {}", revision)))?;

        // Get the config for this revision (we need to store full config in revision store)
        // For now, we'll need the revision store to also store the config
        // This is a limitation - we'll handle it by having the revision store return the generation
        let generation = self
            .revisions
            .get_generation(revision)
            .ok_or_else(|| TxError::not_found(format!("generation for revision {}", revision)))?;

        // Validate before applying
        validate_config_structure(&generation.config)
            .map_err(|e| TxError::validation(e.path, e.message))?;

        // Atomically swap
        let mut active_guard = self.active_generation.write().unwrap();
        let new_revision = active_guard.as_ref().map(|g| g.revision).unwrap_or(0) + 1;
        let mut new_generation = generation.clone();
        new_generation.revision = new_revision;
        new_generation.timestamp = Utc::now();
        new_generation.hash = compute_hash(&new_generation.config);

        // Record rollback in revision store
        let rollback_record = RevisionRecord {
            revision: new_generation.revision,
            hash: new_generation.hash.clone(),
            timestamp: new_generation.timestamp,
            status: RevisionStatus::RolledBack,
            error: None,
        };
        self.revisions
            .record_generation(rollback_record, new_generation.clone())
            .map_err(|e| TxError::internal(format!("failed to record rollback: {}", e)))?;

        *active_guard = Some(new_generation.clone());

        Ok(new_generation)
    }

    /// Get revision history.
    pub fn history(&self, limit: usize, offset: usize) -> Vec<RevisionRecord> {
        self.revisions.history(limit, offset)
    }
}

/// Compute xxHash64 hash of a JSON value (similar to Caddy's ETag computation).
fn compute_hash(value: &Value) -> String {
    let serialized = serde_json::to_vec(value).unwrap_or_default();
    let hash = xxh3_64(&serialized);
    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn valid_config() -> Value {
        serde_json::json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":80"],
                            "routes": [
                                {
                                    "@id": "host1",
                                    "match": [{"host": ["example.com"]}],
                                    "handle": [{"handler": "static_response", "body": "Hello"}]
                                }
                            ]
                        }
                    }
                }
            }
        })
    }

    fn invalid_config() -> Value {
        serde_json::json!({
            "apps": {
                "unknown_app": {}
            }
        })
    }

    #[test]
    fn test_stage_valid_config() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config = valid_config();

        let staged = tx.stage(config.clone()).unwrap();
        assert_eq!(staged.config, config);
        assert!(!staged.hash.is_empty());
    }

    #[test]
    fn test_stage_invalid_config() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config = invalid_config();

        let result = tx.stage(config);
        assert!(matches!(result, Err(TxError::Validation { .. })));
    }

    #[test]
    fn test_apply_valid_config() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config = valid_config();

        let staged = tx.stage(config).unwrap();
        let generation = tx.apply(None).unwrap();

        assert_eq!(generation.revision, 1);
        assert_eq!(generation.config, staged.config);
        assert_eq!(generation.hash, staged.hash);

        // Verify active generation
        let active = tx.active_generation().unwrap();
        assert_eq!(active.revision, 1);
        assert_eq!(active.config, generation.config);
    }

    #[test]
    fn test_apply_with_if_match_success() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config = valid_config();

        tx.stage(config.clone()).unwrap();
        let gen1 = tx.apply(None).unwrap();

        // Stage a new config
        let config2 = serde_json::json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":8080"],
                            "routes": [
                                {
                                    "@id": "host2",
                                    "match": [{"host": ["example.org"]}],
                                    "handle": [{"handler": "static_response", "body": "World"}]
                                }
                            ]
                        }
                    }
                }
            }
        });
        tx.stage(config2).unwrap();

        // Apply with correct if_match
        let gen2 = tx.apply(Some(gen1.etag())).unwrap();
        assert_eq!(gen2.revision, 2);
    }

    #[test]
    fn test_apply_with_if_match_failure() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config = valid_config();

        tx.stage(config.clone()).unwrap();
        let gen1 = tx.apply(None).unwrap();

        // Stage a new config
        let config2 = serde_json::json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":8080"],
                            "routes": [
                                {
                                    "@id": "host2",
                                    "match": [{"host": ["example.org"]}],
                                    "handle": [{"handler": "static_response", "body": "World"}]
                                }
                            ]
                        }
                    }
                }
            }
        });
        tx.stage(config2).unwrap();

        // Apply with wrong if_match
        let result = tx.apply(Some("W/\"999\"".to_string()));
        assert!(matches!(result, Err(TxError::PreconditionFailed { .. })));

        // Active generation should be unchanged
        let active = tx.active_generation().unwrap();
        assert_eq!(active.revision, 1);
        assert_eq!(active.config, gen1.config);
    }

    #[test]
    fn test_apply_invalid_config_fails() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config = valid_config();

        tx.stage(config).unwrap();
        tx.apply(None).unwrap();

        // Stage invalid config
        let invalid = invalid_config();
        tx.stage(invalid).unwrap();

        // Apply should fail with validation error
        let result = tx.apply(None);
        assert!(matches!(result, Err(TxError::Validation { .. })));

        // Active generation should be unchanged (still revision 1)
        let active = tx.active_generation().unwrap();
        assert_eq!(active.revision, 1);
    }

    #[test]
    fn test_diff() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config1 = valid_config();

        tx.stage(config1).unwrap();
        tx.apply(None).unwrap();

        let config2 = serde_json::json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":80"],
                            "routes": [
                                {
                                    "@id": "host1",
                                    "match": [{"host": ["example.com"]}],
                                    "handle": [{"handler": "static_response", "body": "Hello"}]
                                },
                                {
                                    "@id": "host2",
                                    "match": [{"host": ["example.org"]}],
                                    "handle": [{"handler": "static_response", "body": "World"}]
                                }
                            ]
                        }
                    }
                }
            }
        });

        tx.stage(config2).unwrap();
        let diff = tx.diff().unwrap();

        // Should have one added route
        let added: Vec<_> = diff
            .changes
            .iter()
            .filter(|c| c.kind == DiffKind::Added)
            .collect();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].route_id, Some("host2".to_string()));
    }

    #[test]
    fn test_quarantine() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config = valid_config();

        tx.stage(config).unwrap();
        tx.quarantine(&[HostId::new("host1")]).unwrap();

        let staged = tx.staged_config().unwrap();
        let routes = staged.config["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array()
            .unwrap();
        assert_eq!(routes.len(), 0); // host1 should be removed
    }

    #[test]
    fn test_rollback() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config1 = valid_config();

        tx.stage(config1).unwrap();
        let gen1 = tx.apply(None).unwrap();

        let config2 = serde_json::json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":8080"],
                            "routes": [
                                {
                                    "@id": "host2",
                                    "match": [{"host": ["example.org"]}],
                                    "handle": [{"handler": "static_response", "body": "World"}]
                                }
                            ]
                        }
                    }
                }
            }
        });
        tx.stage(config2).unwrap();
        let _gen2 = tx.apply(None).unwrap();

        // Rollback to revision 1
        let rolled_back = tx.rollback(1).unwrap();
        assert_eq!(rolled_back.revision, 3); // New revision
        assert_eq!(rolled_back.config, gen1.config);

        // Active should now be the rolled back config
        let active = tx.active_generation().unwrap();
        assert_eq!(active.config, gen1.config);
        assert_eq!(active.revision, 3);
    }

    #[test]
    fn test_history() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        let config = valid_config();

        tx.stage(config.clone()).unwrap();
        tx.apply(None).unwrap();

        let config2 = serde_json::json!({
            "apps": {
                "http": {
                    "servers": {
                        "srv0": {
                            "listen": [":8080"],
                            "routes": [
                                {
                                    "@id": "host2",
                                    "match": [{"host": ["example.org"]}],
                                    "handle": [{"handler": "static_response", "body": "World"}]
                                }
                            ]
                        }
                    }
                }
            }
        });
        tx.stage(config2).unwrap();
        tx.apply(None).unwrap();

        let history = tx.history(10, 0);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].status, RevisionStatus::Applied);
        assert_eq!(history[1].status, RevisionStatus::Applied);
        assert_eq!(history[0].revision, 1);
        assert_eq!(history[1].revision, 2);
    }

    #[test]
    fn test_full_workflow_valid_then_invalid() {
        // This is the non-PM test harness test:
        // stages a valid config, applies, verifies active,
        // then stages invalid config, apply fails, active unchanged,
        // history shows both attempts
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);

        // Stage and apply valid config
        let config = valid_config();
        tx.stage(config.clone()).unwrap();
        let gen1 = tx.apply(None).unwrap();
        assert_eq!(gen1.revision, 1);

        // Verify active
        let active = tx.active_generation().unwrap();
        assert_eq!(active.revision, 1);
        assert_eq!(active.config, config);

        // Stage invalid config
        let invalid = invalid_config();
        tx.stage(invalid).unwrap();

        // Apply should fail with Validation error
        let result = tx.apply(None);
        assert!(matches!(result, Err(TxError::Validation { .. })));

        // Active should be unchanged
        let active = tx.active_generation().unwrap();
        assert_eq!(active.revision, 1);
        assert_eq!(active.config, config);

        // History should show both attempts
        let history = tx.history(10, 0);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].status, RevisionStatus::Applied);
        assert_eq!(history[0].revision, 1);
        assert_eq!(history[1].status, RevisionStatus::Failed);
        assert_eq!(history[1].revision, 2); // Revision still increments on failed attempt
        assert!(history[1].error.is_some());
    }

    #[test]
    fn test_persistent_revision_store() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("revisions.json");
        let store = PersistentRevisionStore::new(store_path).unwrap();

        let tx = ConfigTx::new(store);
        let config = valid_config();

        tx.stage(config).unwrap();
        let gen = tx.apply(None).unwrap();
        assert_eq!(gen.revision, 1);

        // Create new ConfigTx with same store
        let store2 = PersistentRevisionStore::new(temp_dir.path().join("revisions.json")).unwrap();
        let tx2 = ConfigTx::new(store2);

        // History should persist
        let history = tx2.history(10, 0);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].revision, 1);
        assert_eq!(history[0].status, RevisionStatus::Applied);
    }
}
