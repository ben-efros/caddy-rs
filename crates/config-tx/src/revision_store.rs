//! Revision store trait and implementations.
//!
//! A revision store is the durable audit trail for configuration generations. It holds one record
//! per attempt (applied, rolled back or failed) and, for attempts that produced a configuration, the
//! full generation so a rollback can restore it.
//!
//! The persistent implementation writes atomically (temporary file, `sync_all`, rename) and keeps a
//! bounded number of records so an audit file cannot grow without limit. Bounding drops the oldest
//! records *and* their generations together, so a retained record always has its generation.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Generation, RevisionStatus};

/// Default bound on retained revisions for a persistent store.
pub const DEFAULT_MAX_RECORDS: usize = 1024;

/// Errors from revision store operations.
#[derive(Debug, Error)]
pub enum RevisionStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Revision not found: {0}")]
    NotFound(u64),
}

/// Record of a revision in history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionRecord {
    /// Revision number.
    pub revision: u64,
    /// Hash of the configuration.
    pub hash: String,
    /// Timestamp of the revision.
    pub timestamp: DateTime<Utc>,
    /// Status of the revision.
    pub status: RevisionStatus,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Trait for revision storage.
pub trait RevisionStore: Send + Sync + 'static {
    /// Record a revision without a generation (metadata only).
    fn record(&self, record: RevisionRecord) -> Result<(), RevisionStoreError>;

    /// Get a revision record by revision number.
    fn get(&self, revision: u64) -> Option<RevisionRecord>;

    /// Get the full generation for a revision (config + metadata).
    fn get_generation(&self, revision: u64) -> Option<Generation>;

    /// Get revision history, newest first, with pagination.
    fn history(&self, limit: usize, offset: usize) -> Vec<RevisionRecord>;

    /// Get the latest revision number, including failed attempts.
    fn latest_revision(&self) -> Option<u64>;

    /// The newest generation that was actually applied or rolled back.
    ///
    /// Failed attempts are recorded but are not a valid active configuration, so they are skipped.
    fn latest_generation(&self) -> Option<Generation> {
        self.history(usize::MAX, 0)
            .into_iter()
            .find(|record| {
                matches!(
                    record.status,
                    RevisionStatus::Applied | RevisionStatus::RolledBack
                )
            })
            .and_then(|record| self.get_generation(record.revision))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredData {
    records: BTreeMap<u64, RevisionRecord>,
    generations: BTreeMap<u64, Generation>,
}

impl StoredData {
    fn insert(&mut self, record: RevisionRecord, generation: Option<Generation>) {
        let revision = record.revision;
        self.records.insert(revision, record);
        if let Some(generation) = generation {
            self.generations.insert(revision, generation);
        }
    }

    fn prune(&mut self, max_records: usize) {
        while self.records.len() > max_records {
            let Some(oldest) = self.records.keys().next().copied() else {
                break;
            };
            self.records.remove(&oldest);
            self.generations.remove(&oldest);
        }
    }

    fn history(&self, limit: usize, offset: usize) -> Vec<RevisionRecord> {
        self.records
            .values()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }
}

/// In-memory revision store implementation.
#[derive(Debug, Default)]
pub struct InMemoryRevisionStore {
    data: Arc<Mutex<StoredData>>,
}

impl InMemoryRevisionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RevisionStore for InMemoryRevisionStore {
    fn record(&self, record: RevisionRecord) -> Result<(), RevisionStoreError> {
        crate::lock(&self.data).insert(record, None);
        Ok(())
    }

    fn get(&self, revision: u64) -> Option<RevisionRecord> {
        crate::lock(&self.data).records.get(&revision).cloned()
    }

    fn get_generation(&self, revision: u64) -> Option<Generation> {
        crate::lock(&self.data).generations.get(&revision).cloned()
    }

    fn history(&self, limit: usize, offset: usize) -> Vec<RevisionRecord> {
        crate::lock(&self.data).history(limit, offset)
    }

    fn latest_revision(&self) -> Option<u64> {
        crate::lock(&self.data).records.keys().next_back().copied()
    }
}

/// Persistent revision store implementation using a JSON file.
#[derive(Debug)]
pub struct PersistentRevisionStore {
    path: std::path::PathBuf,
    data: Arc<Mutex<StoredData>>,
    max_records: usize,
}

impl PersistentRevisionStore {
    /// Create a persistent store with the default retention bound.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, RevisionStoreError> {
        Self::with_limit(path, DEFAULT_MAX_RECORDS)
    }

    /// Create a persistent store retaining at most `max_records` revisions.
    pub fn with_limit<P: AsRef<Path>>(
        path: P,
        max_records: usize,
    ) -> Result<Self, RevisionStoreError> {
        if max_records == 0 {
            return Err(RevisionStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "max_records must be greater than zero",
            )));
        }
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            serde_json::from_str(&raw)?
        } else {
            StoredData::default()
        };
        Ok(Self {
            path,
            data: Arc::new(Mutex::new(data)),
            max_records,
        })
    }

    /// Rewrite the store file atomically.
    ///
    /// The caller holds the data lock, so a concurrent writer cannot interleave. The rename is the
    /// commit point: a crash before it leaves the previous file intact, and a crash after it leaves
    /// the complete new file.
    fn persist(&self, data: &StoredData) -> Result<(), RevisionStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(data)?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&json)?;
            file.sync_all()?;
        }
        if let Err(error) = fs::rename(&tmp, &self.path) {
            let _ = fs::remove_file(&tmp);
            return Err(error.into());
        }
        Ok(())
    }

    fn insert_and_persist(
        &self,
        record: RevisionRecord,
        generation: Option<Generation>,
    ) -> Result<(), RevisionStoreError> {
        let mut data = crate::lock(&self.data);
        data.insert(record, generation);
        data.prune(self.max_records);
        self.persist(&data)
    }
}

impl RevisionStore for PersistentRevisionStore {
    fn record(&self, record: RevisionRecord) -> Result<(), RevisionStoreError> {
        self.insert_and_persist(record, None)
    }

    fn get(&self, revision: u64) -> Option<RevisionRecord> {
        crate::lock(&self.data).records.get(&revision).cloned()
    }

    fn get_generation(&self, revision: u64) -> Option<Generation> {
        crate::lock(&self.data).generations.get(&revision).cloned()
    }

    fn history(&self, limit: usize, offset: usize) -> Vec<RevisionRecord> {
        crate::lock(&self.data).history(limit, offset)
    }

    fn latest_revision(&self) -> Option<u64> {
        crate::lock(&self.data).records.keys().next_back().copied()
    }
}

/// Extension trait to record a generation together with its revision.
pub trait RevisionStoreExt: RevisionStore {
    /// Record a revision along with its generation.
    fn record_generation(
        &self,
        record: RevisionRecord,
        generation: Generation,
    ) -> Result<(), RevisionStoreError>;
}

impl RevisionStoreExt for InMemoryRevisionStore {
    fn record_generation(
        &self,
        record: RevisionRecord,
        generation: Generation,
    ) -> Result<(), RevisionStoreError> {
        crate::lock(&self.data).insert(record, Some(generation));
        Ok(())
    }
}

impl RevisionStoreExt for PersistentRevisionStore {
    fn record_generation(
        &self,
        record: RevisionRecord,
        generation: Generation,
    ) -> Result<(), RevisionStoreError> {
        self.insert_and_persist(record, Some(generation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn record(revision: u64) -> RevisionRecord {
        RevisionRecord {
            revision,
            hash: format!("hash{revision}"),
            timestamp: Utc::now(),
            status: RevisionStatus::Applied,
            error: None,
        }
    }

    /// L9: a panic in another thread poisons the store mutex. Every later revision lookup and
    /// record used to panic with it; the store must keep working instead.
    #[test]
    fn poisoned_store_mutex_does_not_panic() {
        let store = InMemoryRevisionStore::new();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.data.lock().unwrap();
            panic!("poison the revision store mutex");
        }));
        assert!(poisoned.is_err(), "the guard must have been poisoned");

        store.record(record(1)).expect("record after poisoning");
        store
            .record_generation(
                record(2),
                Generation {
                    config: serde_json::json!({}),
                    hash: "hash2".to_string(),
                    revision: 2,
                    timestamp: Utc::now(),
                },
            )
            .expect("record_generation after poisoning");

        assert_eq!(store.get(1).map(|r| r.revision), Some(1));
        assert!(store.get_generation(2).is_some());
        assert_eq!(store.latest_revision(), Some(2));
        assert_eq!(store.history(2, 0).len(), 2);
    }

    #[test]
    fn in_memory_history_is_newest_first() {
        let store = InMemoryRevisionStore::new();
        for revision in 1..=5 {
            store.record(record(revision)).unwrap();
        }

        let history = store.history(3, 0);
        assert_eq!(
            history.iter().map(|r| r.revision).collect::<Vec<_>>(),
            vec![5, 4, 3]
        );

        let history = store.history(3, 3);
        assert_eq!(
            history.iter().map(|r| r.revision).collect::<Vec<_>>(),
            vec![2, 1]
        );
    }

    #[test]
    fn persistent_store_survives_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("revisions.json");
        let store = PersistentRevisionStore::new(&path).unwrap();
        store.record(record(1)).unwrap();

        let reopened = PersistentRevisionStore::new(&path).unwrap();
        assert_eq!(reopened.get(1).unwrap().hash, "hash1");
        assert_eq!(reopened.latest_revision(), Some(1));
    }

    #[test]
    fn persistent_store_is_bounded_and_drops_generations_with_records() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("revisions.json");
        let store = PersistentRevisionStore::with_limit(&path, 3).unwrap();
        for revision in 1..=5 {
            let generation = Generation::new(serde_json::json!({"revision": revision}), revision);
            store
                .record_generation(record(revision), generation)
                .unwrap();
        }

        let reopened = PersistentRevisionStore::with_limit(&path, 3).unwrap();
        assert_eq!(reopened.history(10, 0).len(), 3);
        assert_eq!(reopened.latest_revision(), Some(5));
        assert!(reopened.get(1).is_none());
        assert!(reopened.get_generation(1).is_none());
        assert!(reopened.get_generation(5).is_some());
    }

    #[test]
    fn latest_generation_skips_failed_attempts() {
        let store = InMemoryRevisionStore::new();
        let applied = Generation::new(serde_json::json!({"ok": true}), 1);
        store.record_generation(record(1), applied).unwrap();
        let failed = Generation::new(serde_json::json!({"ok": false}), 2);
        store
            .record_generation(
                RevisionRecord {
                    revision: 2,
                    hash: failed.hash.clone(),
                    timestamp: Utc::now(),
                    status: RevisionStatus::Failed,
                    error: Some("stale precondition".to_owned()),
                },
                failed,
            )
            .unwrap();

        assert_eq!(store.latest_revision(), Some(2));
        assert_eq!(store.latest_generation().unwrap().revision, 1);
    }

    #[test]
    fn rejects_a_zero_limit() {
        let temp_dir = TempDir::new().unwrap();
        let error = PersistentRevisionStore::with_limit(temp_dir.path().join("r.json"), 0)
            .expect_err("zero is invalid");
        assert!(matches!(error, RevisionStoreError::Io(_)));
    }
}
