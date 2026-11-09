//! Backend-agnostic durable state for the caddy-rs proxy manager.
//!
//! This crate deliberately knows nothing about hosts, certificates, users or NPM. It provides a
//! small namespaced document store with:
//!
//! * immutable [`Snapshot`] reads — readers never take a lock that a writer holds;
//! * compare-and-swap preconditions on writes;
//! * one serialized writer per store, so callers cannot contend on a database lock;
//! * a memory backend for tests and a snapshot-file backend for small single-node deployments.
//!
//! The snapshot-file backend is intentionally simple: the full state is serialized, written to a
//! temporary file, fsynced and atomically renamed. It is suitable for control-plane state at modest
//! scale and gives a clean backend boundary for a future `redb`/SQL backend without changing the
//! API. It is **not** a replacement for a multi-writer database.
//!
//! Backends are selected at compile time by the embedding binary. This crate has no SQL, network or
//! C dependency.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Monotonic document revision.
pub type Revision = u64;
/// Monotonic store generation. A generation changes on every committed transaction that changes
/// at least one document.
pub type Generation = u64;

/// A namespaced key. Namespaces are application-defined (`hosts`, `certificates`, ...).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub namespace: String,
    pub key: String,
}

impl Key {
    pub fn new(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
        }
    }
}

/// A stored document with its revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Document {
    pub namespace: String,
    pub key: String,
    pub revision: Revision,
    pub value: Value,
}

impl Document {
    pub fn new(
        namespace: impl Into<String>,
        key: impl Into<String>,
        revision: Revision,
        value: Value,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
            revision,
            value,
        }
    }
}

/// An immutable view of the store. Cloning a snapshot never blocks a writer; it is an `Arc` clone.
#[derive(Debug, Clone)]
pub struct Snapshot {
    generation: Generation,
    documents: Arc<BTreeMap<Key, Document>>,
}

impl Snapshot {
    fn from_inner(inner: &Inner) -> Self {
        Self {
            generation: inner.generation,
            documents: Arc::new(inner.documents.clone()),
        }
    }

    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub fn get(&self, namespace: &str, key: &str) -> Option<&Document> {
        self.documents
            .get(&Key::new(namespace.to_string(), key.to_string()))
    }

    /// Return every document in `namespace` whose key starts with `prefix`, ordered by key.
    pub fn scan(&self, namespace: &str, prefix: &str) -> Vec<Document> {
        let start = Key::new(namespace.to_string(), prefix.to_string());
        self.documents
            .range(start..)
            .take_while(|(candidate, _)| candidate.namespace == namespace)
            .filter(|(candidate, _)| candidate.key.starts_with(prefix))
            .map(|(_, document)| document.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.documents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// All documents in key order. Used by backup/export paths; not for request-path reads.
    pub fn documents(&self) -> impl Iterator<Item = &Document> {
        self.documents.values()
    }
}

/// A precondition checked against the current state before a transaction commits.
#[derive(Debug, Clone)]
pub enum Check {
    /// The key must exist at exactly this revision.
    Revision { key: Key, revision: Revision },
    /// The key must not exist.
    Missing { key: Key },
}

/// A write in a transaction. The new revision is assigned by the store.
#[derive(Debug, Clone)]
pub struct WriteRecord {
    pub key: Key,
    pub value: Value,
}

/// A set of reads-with-preconditions and writes applied atomically by one writer.
#[derive(Debug, Clone, Default)]
pub struct Transaction {
    checks: Vec<Check>,
    writes: Vec<WriteRecord>,
    deletes: Vec<Key>,
}

impl Transaction {
    pub fn new() -> Self {
        Self::default()
    }

    /// Require an existing document at exactly `revision`.
    pub fn check_revision(
        mut self,
        namespace: impl Into<String>,
        key: impl Into<String>,
        revision: Revision,
    ) -> Self {
        self.checks.push(Check::Revision {
            key: Key::new(namespace, key),
            revision,
        });
        self
    }

    /// Require that the document does not exist.
    pub fn check_missing(mut self, namespace: impl Into<String>, key: impl Into<String>) -> Self {
        self.checks.push(Check::Missing {
            key: Key::new(namespace, key),
        });
        self
    }

    pub fn put(
        mut self,
        namespace: impl Into<String>,
        key: impl Into<String>,
        value: Value,
    ) -> Self {
        self.writes.push(WriteRecord {
            key: Key::new(namespace, key),
            value,
        });
        self
    }

    pub fn delete(mut self, namespace: impl Into<String>, key: impl Into<String>) -> Self {
        self.deletes.push(Key::new(namespace, key));
        self
    }
}

/// The result of a committed transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct Commit {
    pub generation: Generation,
    pub written: Vec<Document>,
    pub deleted: Vec<Key>,
}

/// Backend error. A failed transaction leaves the store unchanged.
#[derive(Debug, Error)]
pub enum StateError {
    #[error("state I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("state serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("state file is corrupt: {0}")]
    Corrupt(String),
    #[error(
        "state conflict for {namespace}/{key}: expected revision {expected:?}, found {actual:?}"
    )]
    Conflict {
        namespace: String,
        key: String,
        expected: Option<Revision>,
        actual: Option<Revision>,
    },
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("state backend unavailable: {0}")]
    Unavailable(String),
}

/// The backend contract. Implementations must be `Send + Sync`; reads use snapshots.
pub trait StateStore: Send + Sync {
    fn get(&self, namespace: &str, key: &str) -> Result<Option<Document>, StateError>;
    fn scan(&self, namespace: &str, prefix: &str) -> Result<Vec<Document>, StateError>;
    fn snapshot(&self) -> Result<Snapshot, StateError>;
    fn transact(&self, transaction: Transaction) -> Result<Commit, StateError>;
    /// Write a consistent JSON export of the current snapshot to `path`.
    fn backup(&self, path: &Path) -> Result<(), StateError>;
}

#[derive(Debug, Clone, Default)]
struct Inner {
    generation: Generation,
    documents: BTreeMap<Key, Document>,
}

impl Inner {
    fn apply(&mut self, transaction: Transaction) -> Result<Commit, StateError> {
        let mut keys = std::collections::BTreeSet::new();
        for check in &transaction.checks {
            let key = match check {
                Check::Revision { key, .. } | Check::Missing { key } => key,
            };
            if !keys.insert(key.clone()) {
                return Err(StateError::InvalidTransaction(format!(
                    "duplicate check for {}/{}",
                    key.namespace, key.key
                )));
            }
        }

        for check in &transaction.checks {
            match check {
                Check::Revision { key, revision } => {
                    let actual = self.documents.get(key).map(|document| document.revision);
                    if actual != Some(*revision) {
                        return Err(StateError::Conflict {
                            namespace: key.namespace.clone(),
                            key: key.key.clone(),
                            expected: Some(*revision),
                            actual,
                        });
                    }
                }
                Check::Missing { key } => {
                    if let Some(document) = self.documents.get(key) {
                        return Err(StateError::Conflict {
                            namespace: key.namespace.clone(),
                            key: key.key.clone(),
                            expected: None,
                            actual: Some(document.revision),
                        });
                    }
                }
            }
        }

        let mut written = Vec::with_capacity(transaction.writes.len());
        let mut touched = std::collections::BTreeSet::new();
        for write in &transaction.writes {
            if !touched.insert(write.key.clone()) {
                return Err(StateError::InvalidTransaction(format!(
                    "duplicate write for {}/{}",
                    write.key.namespace, write.key.key
                )));
            }
            let revision = self
                .documents
                .get(&write.key)
                .map(|document| document.revision)
                .unwrap_or(0)
                + 1;
            let document = Document::new(
                write.key.namespace.clone(),
                write.key.key.clone(),
                revision,
                write.value.clone(),
            );
            self.documents.insert(write.key.clone(), document.clone());
            written.push(document);
        }

        let mut deleted = Vec::with_capacity(transaction.deletes.len());
        for key in &transaction.deletes {
            if !touched.insert(key.clone()) {
                return Err(StateError::InvalidTransaction(format!(
                    "key is both written and deleted: {}/{}",
                    key.namespace, key.key
                )));
            }
            if self.documents.remove(key).is_some() {
                deleted.push(key.clone());
            }
        }

        if !written.is_empty() || !deleted.is_empty() {
            self.generation += 1;
        }

        Ok(Commit {
            generation: self.generation,
            written,
            deleted,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    generation: Generation,
    documents: Vec<Document>,
}

impl PersistedState {
    fn from_inner(inner: &Inner) -> Self {
        Self {
            generation: inner.generation,
            documents: inner.documents.values().cloned().collect(),
        }
    }

    fn into_inner(self, source: &Path) -> Result<Inner, StateError> {
        let mut documents = BTreeMap::new();
        for document in self.documents {
            let key = Key::new(document.namespace.clone(), document.key.clone());
            if documents.insert(key.clone(), document).is_some() {
                return Err(StateError::Corrupt(format!(
                    "{}: duplicate document {}/{}",
                    source.display(),
                    key.namespace,
                    key.key
                )));
            }
        }
        Ok(Inner {
            generation: self.generation,
            documents,
        })
    }
}

#[derive(Debug)]
struct Shared {
    writer: Mutex<Inner>,
    snapshot: RwLock<Arc<Snapshot>>,
    persistence: Option<PathBuf>,
}

impl Shared {
    fn new(inner: Inner, persistence: Option<PathBuf>) -> Self {
        let snapshot = Arc::new(Snapshot::from_inner(&inner));
        Self {
            writer: Mutex::new(inner),
            snapshot: RwLock::new(snapshot),
            persistence,
        }
    }

    fn get(&self, namespace: &str, key: &str) -> Result<Option<Document>, StateError> {
        Ok(self
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(namespace, key)
            .cloned())
    }

    fn scan(&self, namespace: &str, prefix: &str) -> Result<Vec<Document>, StateError> {
        Ok(self
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .scan(namespace, prefix))
    }

    fn snapshot(&self) -> Result<Snapshot, StateError> {
        Ok(self
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .clone())
    }

    fn transact(&self, transaction: Transaction) -> Result<Commit, StateError> {
        let mut guard = self
            .writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Apply to a clone first. A backend write failure must leave both the in-memory state and
        // the published snapshot at the previous generation.
        let mut next = guard.clone();
        let commit = next.apply(transaction)?;

        if let Some(path) = &self.persistence {
            let bytes = serde_json::to_vec(&PersistedState::from_inner(&next))?;
            write_atomic(path, &bytes)?;
        }

        *guard = next;
        *self
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Arc::new(Snapshot::from_inner(&guard));
        Ok(commit)
    }

    fn backup(&self, path: &Path) -> Result<(), StateError> {
        let snapshot = self.snapshot()?;
        let bytes = serde_json::to_vec(&PersistedState {
            generation: snapshot.generation,
            documents: snapshot.documents().cloned().collect(),
        })?;
        write_atomic(path, &bytes)
    }
}

/// In-memory backend. Useful for tests and for an embedded PM process that has an external backup.
#[derive(Clone)]
pub struct MemoryStore {
    shared: Arc<Shared>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared::new(Inner::default(), None)),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StateStore for MemoryStore {
    fn get(&self, namespace: &str, key: &str) -> Result<Option<Document>, StateError> {
        self.shared.get(namespace, key)
    }

    fn scan(&self, namespace: &str, prefix: &str) -> Result<Vec<Document>, StateError> {
        self.shared.scan(namespace, prefix)
    }

    fn snapshot(&self) -> Result<Snapshot, StateError> {
        self.shared.snapshot()
    }

    fn transact(&self, transaction: Transaction) -> Result<Commit, StateError> {
        self.shared.transact(transaction)
    }

    fn backup(&self, path: &Path) -> Result<(), StateError> {
        self.shared.backup(path)
    }
}

/// Snapshot-file backend: one JSON file, atomic replace on every committed transaction.
///
/// This is a single-node backend. It intentionally does not implement locking across processes;
/// opening the same path in two writers is unsupported and must be prevented by the deployment
/// (one state service per data directory).
#[derive(Debug, Clone)]
pub struct SnapshotStore {
    shared: Arc<Shared>,
    path: PathBuf,
}

impl SnapshotStore {
    /// Open (or create) a snapshot file. A missing file starts empty; a malformed file fails closed.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StateError> {
        let path = path.into();
        let inner = if path.exists() {
            let bytes = fs::read(&path)?;
            if bytes.is_empty() {
                return Err(StateError::Corrupt(format!(
                    "{}: state file is empty",
                    path.display()
                )));
            }
            let persisted: PersistedState = serde_json::from_slice(&bytes)?;
            persisted.into_inner(&path)?
        } else {
            let inner = Inner::default();
            let bytes = serde_json::to_vec(&PersistedState::from_inner(&inner))?;
            write_atomic(&path, &bytes)?;
            inner
        };

        Ok(Self {
            shared: Arc::new(Shared::new(inner, Some(path.clone()))),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl StateStore for SnapshotStore {
    fn get(&self, namespace: &str, key: &str) -> Result<Option<Document>, StateError> {
        self.shared.get(namespace, key)
    }

    fn scan(&self, namespace: &str, prefix: &str) -> Result<Vec<Document>, StateError> {
        self.shared.scan(namespace, prefix)
    }

    fn snapshot(&self) -> Result<Snapshot, StateError> {
        self.shared.snapshot()
    }

    fn transact(&self, transaction: Transaction) -> Result<Commit, StateError> {
        self.shared.transact(transaction)
    }

    fn backup(&self, path: &Path) -> Result<(), StateError> {
        self.shared.backup(path)
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state.json");
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;

    match fs::rename(&temporary, path) {
        Ok(()) => {}
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(StateError::Io(error));
        }
    }

    // Persist the directory entry where the platform exposes a directory handle.
    #[cfg(unix)]
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn put(store: &dyn StateStore, key: &str, value: Value) -> Document {
        store
            .transact(Transaction::new().put("hosts", key, value))
            .expect("transaction")
            .written
            .into_iter()
            .next()
            .expect("one document")
    }

    #[test]
    fn put_get_and_scan_are_namespaced_and_prefix_ordered() {
        let store = MemoryStore::new();
        put(&store, "a/one", json!({"name": "one"}));
        put(&store, "a/two", json!({"name": "two"}));
        put(&store, "b/one", json!({"name": "other"}));

        assert_eq!(store.get("hosts", "a/one").unwrap().unwrap().revision, 1);
        assert!(store.get("other", "a/one").unwrap().is_none());
        let scanned = store.scan("hosts", "a/").unwrap();
        assert_eq!(scanned.len(), 2);
        assert_eq!(scanned[0].key, "a/one");
        assert_eq!(scanned[1].key, "a/two");
        assert_eq!(store.scan("hosts", "a/o").unwrap().len(), 1);
    }

    #[test]
    fn revisions_are_monotonic_and_cas_conflicts_do_not_mutate() {
        let store = MemoryStore::new();
        let first = put(&store, "one", json!({"v": 1}));
        assert_eq!(first.revision, 1);

        let second = store
            .transact(Transaction::new().check_revision("hosts", "one", 1).put(
                "hosts",
                "one",
                json!({"v": 2}),
            ))
            .expect("matching cas");
        assert_eq!(second.written[0].revision, 2);
        assert_eq!(second.generation, 2);

        let error = store
            .transact(Transaction::new().check_revision("hosts", "one", 1).put(
                "hosts",
                "one",
                json!({"v": 3}),
            ))
            .expect_err("stale cas");
        match error {
            StateError::Conflict {
                expected, actual, ..
            } => {
                assert_eq!(expected, Some(1));
                assert_eq!(actual, Some(2));
            }
            other => panic!("expected conflict, got {other:?}"),
        }

        assert_eq!(
            store.get("hosts", "one").unwrap().unwrap().value,
            json!({"v": 2})
        );
    }

    #[test]
    fn missing_precondition_blocks_upsert() {
        let store = MemoryStore::new();
        put(&store, "one", json!({"v": 1}));
        let error = store
            .transact(Transaction::new().check_missing("hosts", "one").put(
                "hosts",
                "one",
                json!({"v": 2}),
            ))
            .expect_err("must conflict");
        assert!(matches!(error, StateError::Conflict { .. }));
        assert_eq!(
            store.get("hosts", "one").unwrap().unwrap().value,
            json!({"v": 1})
        );
    }

    #[test]
    fn duplicate_write_and_delete_are_rejected_without_mutation() {
        let store = MemoryStore::new();
        let error = store
            .transact(Transaction::new().put("hosts", "one", json!({"v": 1})).put(
                "hosts",
                "one",
                json!({"v": 2}),
            ))
            .expect_err("duplicate write");
        assert!(matches!(error, StateError::InvalidTransaction(_)));

        let error = store
            .transact(
                Transaction::new()
                    .put("hosts", "one", json!({"v": 1}))
                    .delete("hosts", "one"),
            )
            .expect_err("write+delete");
        assert!(matches!(error, StateError::InvalidTransaction(_)));
        assert!(store.get("hosts", "one").unwrap().is_none());
    }

    #[test]
    fn snapshots_are_isolated_from_later_writes() {
        let store = MemoryStore::new();
        put(&store, "one", json!({"v": 1}));
        let before = store.snapshot().unwrap();
        put(&store, "two", json!({"v": 2}));

        assert!(before.get("hosts", "one").is_some());
        assert!(before.get("hosts", "two").is_none());
        assert_eq!(before.generation(), 1);
        assert_eq!(store.snapshot().unwrap().generation(), 2);
    }

    #[test]
    fn snapshot_file_round_trips_and_backs_up() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("state.json");
        {
            let store = SnapshotStore::open(&path).expect("open");
            put(&store, "one", json!({"v": 1}));
            store
                .transact(
                    Transaction::new()
                        .put("hosts", "two", json!({"v": 2}))
                        .delete("hosts", "missing"),
                )
                .expect("transaction");
            store
                .backup(&directory.path().join("backup.json"))
                .expect("backup");
        }

        let reopened = SnapshotStore::open(&path).expect("reopen");
        assert_eq!(
            reopened.get("hosts", "one").unwrap().unwrap().value,
            json!({"v": 1})
        );
        assert_eq!(reopened.scan("hosts", "").unwrap().len(), 2);

        let backup = fs::read(directory.path().join("backup.json")).expect("backup bytes");
        let value: Value = serde_json::from_slice(&backup).expect("backup json");
        assert_eq!(value["documents"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn persistence_failure_leaves_memory_and_snapshot_unchanged() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("state.json");
        let store = SnapshotStore::open(&path).expect("open");
        put(&store, "one", json!({"v": 1}));
        let generation = store.snapshot().expect("snapshot").generation();

        // Make the atomic replace fail: the destination becomes a directory.
        fs::remove_file(&path).expect("remove state");
        fs::create_dir(&path).expect("replace with directory");

        let error = store
            .transact(Transaction::new().put("hosts", "two", json!({"v": 2})))
            .expect_err("persistence must fail");
        assert!(matches!(error, StateError::Io(_)));
        assert_eq!(store.snapshot().expect("snapshot").generation(), generation);
        assert!(store.get("hosts", "one").expect("read").is_some());
        assert!(store.get("hosts", "two").expect("read").is_none());
    }

    #[test]
    fn corrupt_snapshot_fails_closed() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("state.json");
        fs::write(&path, b"{not json").expect("write");
        let error = SnapshotStore::open(&path).expect_err("must reject");
        assert!(matches!(
            error,
            StateError::Corrupt(_) | StateError::Serialization(_)
        ));
    }

    #[test]
    fn empty_snapshot_is_corrupt_not_silently_reset() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("state.json");
        fs::write(&path, b"").expect("write");
        let error = SnapshotStore::open(&path).expect_err("must reject");
        assert!(matches!(error, StateError::Corrupt(_)));
    }

    #[test]
    fn delete_is_idempotent_and_generation_does_not_move_for_a_noop() {
        let store = MemoryStore::new();
        put(&store, "one", json!({"v": 1}));
        let before = store.snapshot().unwrap().generation();
        let commit = store
            .transact(Transaction::new().delete("hosts", "missing"))
            .expect("delete missing");
        assert_eq!(commit.generation, before);
        assert!(commit.deleted.is_empty());

        let commit = store
            .transact(Transaction::new().delete("hosts", "one"))
            .expect("delete");
        assert_eq!(commit.deleted.len(), 1);
        assert!(store.get("hosts", "one").unwrap().is_none());
    }

    #[test]
    fn concurrent_readers_see_a_stable_snapshot() {
        let store = Arc::new(MemoryStore::new());
        put(store.as_ref(), "seed", json!({"v": 1}));

        let reader_store = Arc::clone(&store);
        let reader = std::thread::spawn(move || {
            let snapshot = reader_store.snapshot().expect("snapshot");
            for _ in 0..100 {
                let _ = snapshot.get("hosts", "seed");
                let _ = snapshot.scan("hosts", "");
            }
            snapshot.generation()
        });

        for index in 0..20 {
            store
                .transact(Transaction::new().put("hosts", format!("k{index}"), json!(index)))
                .expect("write");
        }

        assert!(reader.join().expect("reader") <= store.snapshot().unwrap().generation());
    }
}
