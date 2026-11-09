//! Revision store trait and implementations.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Generation, RevisionStatus};

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
    /// Record a revision.
    fn record(&self, record: RevisionRecord) -> Result<(), RevisionStoreError>;

    /// Get a revision record by revision number.
    fn get(&self, revision: u64) -> Option<RevisionRecord>;

    /// Get the full generation for a revision (config + metadata).
    fn get_generation(&self, revision: u64) -> Option<Generation>;

    /// Get revision history with pagination.
    fn history(&self, limit: usize, offset: usize) -> Vec<RevisionRecord>;

    /// Get the latest revision number.
    fn latest_revision(&self) -> Option<u64>;
}

/// In-memory revision store implementation.
#[derive(Debug, Default)]
pub struct InMemoryRevisionStore {
    records: Arc<Mutex<HashMap<u64, RevisionRecord>>>,
    generations: Arc<Mutex<HashMap<u64, Generation>>>,
}

impl InMemoryRevisionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RevisionStore for InMemoryRevisionStore {
    fn record(&self, record: RevisionRecord) -> Result<(), RevisionStoreError> {
        let mut records = self.records.lock().unwrap();
        records.insert(record.revision, record);
        Ok(())
    }

    fn get(&self, revision: u64) -> Option<RevisionRecord> {
        let records = self.records.lock().unwrap();
        records.get(&revision).cloned()
    }

    fn get_generation(&self, revision: u64) -> Option<Generation> {
        let generations = self.generations.lock().unwrap();
        generations.get(&revision).cloned()
    }

    fn history(&self, limit: usize, offset: usize) -> Vec<RevisionRecord> {
        let records = self.records.lock().unwrap();
        let mut sorted: Vec<_> = records.values().cloned().collect();
        sorted.sort_by_key(|r| r.revision);
        sorted.into_iter().rev().skip(offset).take(limit).collect()
    }

    fn latest_revision(&self) -> Option<u64> {
        let records = self.records.lock().unwrap();
        records.keys().max().copied()
    }
}

/// Persistent revision store implementation using JSON file.
#[derive(Debug)]
pub struct PersistentRevisionStore {
    path: std::path::PathBuf,
    records: Arc<Mutex<HashMap<u64, RevisionRecord>>>,
    generations: Arc<Mutex<HashMap<u64, Generation>>>,
}

impl PersistentRevisionStore {
    /// Create a new persistent revision store at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, RevisionStoreError> {
        let path = path.as_ref().to_path_buf();
        let (records, generations) = if path.exists() {
            let data = fs::read_to_string(&path)?;
            let stored: StoredData = serde_json::from_str(&data)?;
            (stored.records, stored.generations)
        } else {
            (HashMap::new(), HashMap::new())
        };

        Ok(Self {
            path,
            records: Arc::new(Mutex::new(records)),
            generations: Arc::new(Mutex::new(generations)),
        })
    }

    fn persist(&self) -> Result<(), RevisionStoreError> {
        let records = self.records.lock().unwrap();
        let generations = self.generations.lock().unwrap();
        let data = StoredData {
            records: records.clone(),
            generations: generations.clone(),
        };
        let json = serde_json::to_string_pretty(&data)?;
        fs::write(&self.path, json)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct StoredData {
    records: HashMap<u64, RevisionRecord>,
    generations: HashMap<u64, Generation>,
}

impl RevisionStore for PersistentRevisionStore {
    fn record(&self, record: RevisionRecord) -> Result<(), RevisionStoreError> {
        // If this is an Applied or RolledBack record, also store the generation
        // Note: We need the generation to be passed separately or reconstructed
        // For now, we just store the record; the ConfigTx will call a separate method
        // Actually, let's add a method to record with generation
        let mut records = self.records.lock().unwrap();
        records.insert(record.revision, record);
        drop(records);
        self.persist()
    }

    fn get(&self, revision: u64) -> Option<RevisionRecord> {
        let records = self.records.lock().unwrap();
        records.get(&revision).cloned()
    }

    fn get_generation(&self, revision: u64) -> Option<Generation> {
        let generations = self.generations.lock().unwrap();
        generations.get(&revision).cloned()
    }

    fn history(&self, limit: usize, offset: usize) -> Vec<RevisionRecord> {
        let records = self.records.lock().unwrap();
        let mut sorted: Vec<_> = records.values().cloned().collect();
        sorted.sort_by_key(|r| r.revision);
        sorted.into_iter().rev().skip(offset).take(limit).collect()
    }

    fn latest_revision(&self) -> Option<u64> {
        let records = self.records.lock().unwrap();
        records.keys().max().copied()
    }
}

/// Extension trait to record generation along with revision.
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
        let mut records = self.records.lock().unwrap();
        records.insert(record.revision, record);
        let mut generations = self.generations.lock().unwrap();
        generations.insert(generation.revision, generation);
        Ok(())
    }
}

impl RevisionStoreExt for PersistentRevisionStore {
    fn record_generation(
        &self,
        record: RevisionRecord,
        generation: Generation,
    ) -> Result<(), RevisionStoreError> {
        let mut records = self.records.lock().unwrap();
        records.insert(record.revision, record);
        let mut generations = self.generations.lock().unwrap();
        generations.insert(generation.revision, generation);
        drop(records);
        drop(generations);
        self.persist()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_in_memory_store() {
        let store = InMemoryRevisionStore::new();
        let record = RevisionRecord {
            revision: 1,
            hash: "abc123".to_string(),
            timestamp: Utc::now(),
            status: RevisionStatus::Applied,
            error: None,
        };

        store.record(record.clone()).unwrap();
        let retrieved = store.get(1).unwrap();
        assert_eq!(retrieved.revision, 1);
        assert_eq!(retrieved.hash, "abc123");
    }

    #[test]
    fn test_in_memory_store_history() {
        let store = InMemoryRevisionStore::new();

        for i in 1..=5 {
            let record = RevisionRecord {
                revision: i,
                hash: format!("hash{}", i),
                timestamp: Utc::now(),
                status: RevisionStatus::Applied,
                error: None,
            };
            store.record(record).unwrap();
        }

        let history = store.history(3, 0);
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].revision, 5);
        assert_eq!(history[1].revision, 4);
        assert_eq!(history[2].revision, 3);

        let history = store.history(3, 3);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].revision, 2);
        assert_eq!(history[1].revision, 1);
    }

    #[test]
    fn test_persistent_store() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("revisions.json");
        let store = PersistentRevisionStore::new(&store_path).unwrap();

        let record = RevisionRecord {
            revision: 1,
            hash: "abc123".to_string(),
            timestamp: Utc::now(),
            status: RevisionStatus::Applied,
            error: None,
        };

        store.record(record.clone()).unwrap();
        let retrieved = store.get(1).unwrap();
        assert_eq!(retrieved.revision, 1);
        assert_eq!(retrieved.hash, "abc123");

        // Create new store instance with same file
        let store2 = PersistentRevisionStore::new(&store_path).unwrap();
        let retrieved2 = store2.get(1).unwrap();
        assert_eq!(retrieved2.revision, 1);
        assert_eq!(retrieved2.hash, "abc123");
    }

    #[test]
    fn test_persistent_store_history() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("revisions.json");
        let store = PersistentRevisionStore::new(&store_path).unwrap();

        for i in 1..=5 {
            let record = RevisionRecord {
                revision: i,
                hash: format!("hash{}", i),
                timestamp: Utc::now(),
                status: RevisionStatus::Applied,
                error: None,
            };
            store.record(record).unwrap();
        }

        let history = store.history(3, 0);
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].revision, 5);
    }
}
