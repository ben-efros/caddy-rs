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

mod apply;
mod diff;
mod revision_store;
mod validation;

pub use apply::{
    configs_match_ignoring_admin, ApplyFailure, ApplyFailureKind, ApplyOutcome,
    ConfigApplyPipeline, ConfigTarget,
};
pub use diff::{Diff, DiffKind};
pub use revision_store::{
    InMemoryRevisionStore, PersistentRevisionStore, RevisionRecord, RevisionStore,
    RevisionStoreError, RevisionStoreExt,
};
pub use validation::{validate_config_structure, ConfigStructureError};

/// Lock a mutex without treating a poisoned lock as fatal.
///
/// L9: `.lock().unwrap()` panics once *any* thread panicked while holding the lock, so a single
/// bug turned every later configuration transaction (and therefore the admin API) into a panic.
/// The guarded data here is only ever replaced wholesale (`*guard = ...`) or mutated through a
/// `BTreeMap` insert, so recovering the inner value cannot expose a half-written configuration.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Read-lock an `RwLock` with the same poison tolerance as [`lock`].
pub(crate) fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Write-lock an `RwLock` with the same poison tolerance as [`lock`].
pub(crate) fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
    ///
    /// The active generation is restored from the store's newest applied or rolled-back
    /// generation. A restart therefore continues from the durable revision instead of starting at
    /// `None` and reusing revision 1.
    pub fn new(revisions: S) -> Self {
        let active = revisions.latest_generation();
        Self {
            active_generation: Arc::new(RwLock::new(active)),
            staged: Mutex::new(None),
            revisions,
        }
    }

    /// Get the currently active generation.
    pub fn active_generation(&self) -> Option<Generation> {
        read(&self.active_generation).clone()
    }

    /// Get the currently staged configuration.
    pub fn staged_config(&self) -> Option<StagedConfig> {
        lock(&self.staged).clone()
    }

    /// Stage a new configuration.
    ///
    /// Validates the Caddy JSON structure and computes the xxHash64 hash. Structural validation is
    /// deliberately done here so an invalid document never becomes the active configuration and a
    /// caller gets the error at the point of the mistake. Semantic validation (routes, upstreams,
    /// TLS coverage) belongs to the compiler and is re-checked on apply.
    pub fn stage(&self, config: Value) -> Result<StagedConfig, TxError> {
        validate_config_structure(&config)
            .map_err(|error| TxError::validation(error.path, error.message))?;
        let staged = StagedConfig::new(config);
        *lock(&self.staged) = Some(staged.clone());
        Ok(staged)
    }

    /// Compute the diff between staged and active configuration.
    ///
    /// Returns None if there is no staged config or no active generation.
    /// Compares routes by @id to determine added/removed/modified routes.
    pub fn diff(&self) -> Option<Diff> {
        let staged = lock(&self.staged).clone()?;
        let active = read(&self.active_generation).clone()?;
        Some(diff::compute_diff(&active.config, &staged.config))
    }

    /// Apply the staged configuration atomically.
    ///
    /// If `if_match` is provided, it must match the active generation's ETag
    /// (`W/"<revision>"`). The active generation is swapped only after validation, the
    /// precondition and the revision record have all succeeded. A failed attempt leaves the active
    /// generation and the staged configuration untouched, and records a `Failed` revision so the
    /// audit trail shows the attempt.
    pub fn apply(&self, if_match: Option<String>) -> Result<Generation, TxError> {
        let staged = lock(&self.staged)
            .clone()
            .ok_or_else(|| TxError::precondition_failed("no staged configuration"))?;

        // Re-check structure on apply: stage is the normal validation point, but `StagedConfig` is
        // public and a caller can construct one directly.
        if let Err(error) = validate_config_structure(&staged.config) {
            // Hold the write lock through recording: revision allocation and the audit write must
            // be one critical section, otherwise two failed attempts can pick the same number and
            // the BTreeMap record store silently overwrites one.
            let active = write(&self.active_generation);
            let revision = self.next_revision(active.as_ref());
            self.record_failure(
                revision,
                &staged,
                format!("Validation: {} at {}", error.message, error.path),
            )?;
            drop(active);
            return Err(TxError::validation(error.path, error.message));
        }

        // One write lock makes "check If-Match then swap" atomic against other applies.
        let mut active_guard = write(&self.active_generation);
        let revision = self.next_revision(active_guard.as_ref());

        if let Some(expected) = if_match {
            let active = match active_guard.as_ref() {
                Some(active) => active,
                None => {
                    return Err(TxError::precondition_failed(
                        "precondition failed: no active generation",
                    ))
                }
            };
            if active.etag() != expected {
                let actual = active.etag();
                // Keep `active_guard` held until the failed record is durable: releasing it here
                // lets a concurrent apply allocate the same revision and overwrite this record.
                self.record_failure(
                    revision,
                    &staged,
                    format!(
                        "PreconditionFailed: ETag mismatch (expected {actual}, got {expected})"
                    ),
                )?;
                return Err(TxError::precondition_failed(format!(
                    "ETag mismatch: expected {actual}, got {expected}"
                )));
            }
        }

        let generation = Generation::new(staged.config, revision);
        let record = RevisionRecord {
            revision: generation.revision,
            hash: generation.hash.clone(),
            timestamp: generation.timestamp,
            status: RevisionStatus::Applied,
            error: None,
        };
        self.revisions
            .record_generation(record, generation.clone())
            .map_err(|error| TxError::internal(format!("failed to record revision: {error}")))?;

        *active_guard = Some(generation.clone());
        drop(active_guard);
        *lock(&self.staged) = None;
        Ok(generation)
    }

    /// Record a failed apply attempt in the revision store without changing the active or staged
    /// configuration. Used by [`crate::ConfigApplyPipeline`] for target and verification failures
    /// that occur after the structural stage succeeded.
    pub fn record_failed_attempt(
        &self,
        config: Value,
        error: impl Into<String>,
    ) -> Result<u64, TxError> {
        // Serialize revision allocation and the durable audit write against concurrent applies.
        let active = write(&self.active_generation);
        let revision = self.next_revision(active.as_ref());
        let staged = StagedConfig::new(config);
        self.record_failure(revision, &staged, error.into())?;
        Ok(revision)
    }

    /// Next revision number, accounting for failed attempts and a restored store.
    fn next_revision(&self, active: Option<&Generation>) -> u64 {
        let active = active.map_or(0, |generation| generation.revision);
        let recorded = self.revisions.latest_revision().unwrap_or(0);
        active.max(recorded) + 1
    }

    /// Record a failed attempt without changing the active generation or the staged configuration.
    fn record_failure(
        &self,
        revision: u64,
        staged: &StagedConfig,
        error: String,
    ) -> Result<(), TxError> {
        let generation = Generation::new(staged.config.clone(), revision);
        let record = RevisionRecord {
            revision,
            hash: generation.hash.clone(),
            timestamp: generation.timestamp,
            status: RevisionStatus::Failed,
            error: Some(error),
        };
        self.revisions
            .record_generation(record, generation)
            .map_err(|error| TxError::internal(format!("failed to record revision: {error}")))
    }

    /// Quarantine specific host routes in the staged configuration.
    ///
    /// Marks specific host routes as quarantined by adding a `@id` filter or removing them.
    /// Used when a host has invalid upstream.
    pub fn quarantine(&self, host_ids: &[HostId]) -> Result<(), TxError> {
        let mut staged_guard = lock(&self.staged);
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
        let record = self
            .revisions
            .get(revision)
            .ok_or_else(|| TxError::not_found(format!("revision {}", revision)))?;
        // A failed attempt is audit evidence, not a restorable configuration. Rolling back to it
        // would publish the exact document that was rejected.
        if !matches!(
            record.status,
            RevisionStatus::Applied | RevisionStatus::RolledBack
        ) {
            return Err(TxError::not_found(format!(
                "revision {revision} is not a successful generation"
            )));
        }
        let generation = self
            .revisions
            .get_generation(revision)
            .ok_or_else(|| TxError::not_found(format!("generation for revision {}", revision)))?;

        // Validate before applying
        validate_config_structure(&generation.config)
            .map_err(|e| TxError::validation(e.path, e.message))?;

        // Atomically swap
        let mut active_guard = write(&self.active_generation);
        let new_revision = self.next_revision(active_guard.as_ref());
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
        drop(active_guard);
        *lock(&self.staged) = None;

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

    /// L9: a panic in another thread poisons the transaction locks. Staging, diffing and applying
    /// used to panic as well, taking the admin API down with a single unrelated bug.
    #[test]
    fn poisoned_locks_do_not_panic() {
        let tx = ConfigTx::new(InMemoryRevisionStore::new());
        let staged_poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.staged.lock().unwrap();
            panic!("poison the staged mutex");
        }));
        assert!(staged_poison.is_err(), "the staged mutex must be poisoned");
        let active_poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.active_generation.write().unwrap();
            panic!("poison the active generation lock");
        }));
        assert!(
            active_poison.is_err(),
            "the active generation lock must be poisoned"
        );

        assert!(tx.active_generation().is_none());
        tx.stage(valid_config()).expect("stage after poisoning");
        assert!(tx.staged_config().is_some());
        // No active generation yet, so there is nothing to diff against.
        assert!(tx.diff().is_none());
        let generation = tx.apply(None).expect("apply after poisoning");
        assert_eq!(generation.revision, 1);
        assert!(tx.active_generation().is_some());
        assert!(tx.staged_config().is_none());
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
    fn test_apply_without_a_staged_config_fails() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);

        let result = tx.apply(None);
        assert!(matches!(result, Err(TxError::PreconditionFailed { .. })));
        assert!(tx.active_generation().is_none());
        assert!(tx.history(10, 0).is_empty());
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
    fn rollback_refuses_a_failed_attempt() {
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);
        tx.stage(valid_config()).unwrap();
        let first = tx.apply(None).unwrap();

        let mut second = valid_config();
        second["apps"]["http"]["servers"]["srv0"]["listen"] = serde_json::json!([":8080"]);
        tx.stage(second).unwrap();
        let error = tx
            .apply(Some("W/\"999\"".to_string()))
            .expect_err("stale precondition");
        assert!(matches!(error, TxError::PreconditionFailed { .. }));

        let error = tx
            .rollback(2)
            .expect_err("failed revision is not restorable");
        assert!(matches!(error, TxError::NotFound { .. }));
        assert_eq!(tx.active_generation().unwrap().revision, first.revision);
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

        // Newest first.
        let history = tx.history(10, 0);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].revision, 2);
        assert_eq!(history[0].status, RevisionStatus::Applied);
        assert_eq!(history[1].revision, 1);
        assert_eq!(history[1].status, RevisionStatus::Applied);
    }

    #[test]
    fn test_full_workflow_valid_then_stale_precondition() {
        // Non-PM harness: stage+apply a valid config, then stage another valid config and fail the
        // apply on a stale precondition. The active generation must not move, the staged config
        // must survive for a corrected retry, and both attempts must be in history.
        let store = InMemoryRevisionStore::new();
        let tx = ConfigTx::new(store);

        let config = valid_config();
        tx.stage(config.clone()).unwrap();
        let gen1 = tx.apply(None).unwrap();
        assert_eq!(gen1.revision, 1);
        assert_eq!(tx.active_generation().unwrap().config, config);

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

        let result = tx.apply(Some("W/\"999\"".to_string()));
        assert!(matches!(result, Err(TxError::PreconditionFailed { .. })));

        // Active is unchanged and the staged document is still available.
        let active = tx.active_generation().unwrap();
        assert_eq!(active.revision, 1);
        assert_eq!(active.config, config);
        assert!(tx.staged_config().is_some());

        // History: failed attempt 2, applied attempt 1 (newest first).
        let history = tx.history(10, 0);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].revision, 2);
        assert_eq!(history[0].status, RevisionStatus::Failed);
        assert!(history[0].error.is_some());
        assert_eq!(history[1].revision, 1);
        assert_eq!(history[1].status, RevisionStatus::Applied);

        // A corrected retry succeeds at the next revision and consumes the staged config.
        let gen3 = tx.apply(Some(gen1.etag())).unwrap();
        assert_eq!(gen3.revision, 3);
        assert!(tx.staged_config().is_none());
        assert_eq!(tx.history(10, 0)[0].status, RevisionStatus::Applied);
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

        // Reopen: the applied generation is restored as active and the next apply continues the
        // durable revision instead of reusing revision 1.
        let store2 = PersistentRevisionStore::new(temp_dir.path().join("revisions.json")).unwrap();
        let tx2 = ConfigTx::new(store2);

        let history = tx2.history(10, 0);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].revision, 1);
        assert_eq!(history[0].status, RevisionStatus::Applied);
        assert_eq!(tx2.active_generation().unwrap().revision, 1);

        tx2.stage(valid_config()).unwrap();
        let next = tx2.apply(None).unwrap();
        assert_eq!(next.revision, 2);
    }

    #[test]
    fn concurrent_failed_applies_hold_unique_revisions() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let tx = Arc::new(ConfigTx::new(InMemoryRevisionStore::new()));
        tx.stage(valid_config()).unwrap();
        tx.apply(None).unwrap();
        // A successful apply consumes the staged document; stage again for the failing attempts.
        tx.stage(valid_config()).unwrap();

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let tx = Arc::clone(&tx);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..25 {
                    let error = tx
                        .apply(Some("W/\"999\"".to_string()))
                        .expect_err("stale precondition");
                    assert!(matches!(error, TxError::PreconditionFailed { .. }));
                }
            }));
        }
        for handle in handles {
            handle.join().expect("worker");
        }

        let history = tx.history(1000, 0);
        assert_eq!(history.len(), 201, "one applied + 200 failed records");
        let mut revisions: Vec<u64> = history.iter().map(|record| record.revision).collect();
        revisions.sort_unstable();
        assert_eq!(revisions, (1..=201).collect::<Vec<_>>());
        assert_eq!(
            history
                .iter()
                .filter(|record| record.status == RevisionStatus::Failed)
                .count(),
            200
        );
    }
}
