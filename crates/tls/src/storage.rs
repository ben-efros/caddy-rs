//! Pluggable certificate storage.
//!
//! Caddy's storage abstraction is one of its most operationally important interfaces: certificates
//! must not be tied to a local filesystem. This module defines the async storage trait, an
//! in-memory backend for tests, and a filesystem backend. The filesystem layout is
//! `certificates/<safe-key>/<name>.crt` + `.key`, storing PEM; it is intentionally simple and is
//! **not** claimed to be byte-compatible with Caddy's storage layout (DIV-0013).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::{Error, Result};

/// A certificate in storage form (PEM, so it can be inspected with standard tooling).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCertificate {
    /// PEM-encoded certificate chain, leaf first.
    pub certificate_pem: Vec<String>,
    /// PEM-encoded private key.
    pub private_key_pem: String,
    /// Domains covered.
    pub domains: Vec<String>,
    /// Unix timestamp (seconds) after which the certificate is not valid.
    pub not_after_unix: u64,
}

/// Async certificate storage backend.
#[async_trait]
pub trait CertificateStorage: Send + Sync {
    /// Backend name (for `list-modules` and diagnostics).
    fn name(&self) -> &'static str;

    /// Load a value by key.
    async fn load(&self, key: &str) -> Result<Option<StoredCertificate>>;

    /// Store a value under a key.
    async fn store(&self, key: &str, certificate: &StoredCertificate) -> Result<()>;

    /// Delete a value.
    async fn delete(&self, key: &str) -> Result<()>;

    /// List keys under a prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// In-memory storage, used by tests and ephemeral deployments.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    values: RwLock<BTreeMap<String, StoredCertificate>>,
}

impl MemoryStorage {
    /// Create empty storage.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CertificateStorage for MemoryStorage {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn load(&self, key: &str) -> Result<Option<StoredCertificate>> {
        Ok(self
            .values
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .cloned())
    }

    async fn store(&self, key: &str, certificate: &StoredCertificate) -> Result<()> {
        self.values
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key.to_string(), certificate.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.values
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .values
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }
}

/// Filesystem-backed storage.
#[derive(Debug, Clone)]
pub struct FileStorage {
    root: PathBuf,
}

impl FileStorage {
    /// Create storage rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn key_path(&self, key: &str) -> Result<PathBuf> {
        if key.is_empty() || key.contains("..") || key.starts_with('/') || key.contains('\0') {
            return Err(Error::InvalidKey(key.to_string()));
        }
        Ok(self.root.join(key))
    }
}

#[async_trait]
impl CertificateStorage for FileStorage {
    fn name(&self) -> &'static str {
        "file_system"
    }

    async fn load(&self, key: &str) -> Result<Option<StoredCertificate>> {
        let path = self.key_path(key)?;
        let data = match fs::read(&path).await {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::Io(error)),
        };
        let stored: StoredCertificate = serde_json::from_slice(&data).map_err(|error| {
            Error::Storage(format!("cannot decode `{}`: {error}", path.display()))
        })?;
        Ok(Some(stored))
    }

    async fn store(&self, key: &str, certificate: &StoredCertificate) -> Result<()> {
        let path = self.key_path(key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let data = serde_json::to_vec_pretty(certificate)
            .map_err(|error| Error::Storage(error.to_string()))?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, data).await?;
        fs::rename(&temporary, &path).await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_path(key)?;
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Io(error)),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let root = self.root.clone();
        let prefix = prefix.to_string();
        let mut keys = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(directory) = stack.pop() {
            let mut entries = match fs::read_dir(&directory).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(Error::Io(error)),
            };
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let file_type = entry.file_type().await?;
                if file_type.is_dir() {
                    stack.push(path);
                } else if let Ok(relative) = path.strip_prefix(&root) {
                    let key = relative.to_string_lossy().replace('\\', "/");
                    if key.starts_with(&prefix) {
                        keys.push(key);
                    }
                }
            }
        }
        keys.sort();
        Ok(keys)
    }
}

/// Build a certificate storage backend from Caddy storage module JSON.
pub fn from_config(config: &serde_json::Value) -> Result<Box<dyn CertificateStorage>> {
    let object = config
        .as_object()
        .ok_or_else(|| Error::Storage("storage config must be an object".to_string()))?;
    let module = object
        .get("module")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("file_system");
    match module {
        "file_system" => {
            let root = object
                .get("root")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(".caddy-rs");
            Ok(Box::new(FileStorage::new(root)))
        }
        other => Err(Error::Storage(format!(
            "storage module `{other}` is not implemented by this build"
        ))),
    }
}

/// Convenience: staleness check for a stored certificate.
pub fn stored_certificate_expiring(certificate: &StoredCertificate, within: Duration) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    certificate.not_after_unix.saturating_sub(now) <= within.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> StoredCertificate {
        StoredCertificate {
            certificate_pem: vec![
                "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----".to_string(),
            ],
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----"
                .to_string(),
            domains: vec!["example.com".to_string()],
            not_after_unix: 4_000_000_000,
        }
    }

    #[tokio::test]
    async fn memory_storage_round_trips() {
        let storage = MemoryStorage::new();
        storage
            .store("certs/example.com", &example())
            .await
            .unwrap();
        assert_eq!(
            storage.load("certs/example.com").await.unwrap(),
            Some(example())
        );
        assert_eq!(storage.list("certs/").await.unwrap().len(), 1);
        storage.delete("certs/example.com").await.unwrap();
        assert!(storage.load("certs/example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn file_storage_round_trips_and_lists() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        storage
            .store("certs/example.com", &example())
            .await
            .unwrap();
        assert_eq!(
            storage.load("certs/example.com").await.unwrap(),
            Some(example())
        );
        assert_eq!(
            storage.list("certs/").await.unwrap(),
            vec!["certs/example.com".to_string()]
        );
        storage.delete("certs/example.com").await.unwrap();
        assert!(storage.load("certs/example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn file_storage_refuses_traversal_keys() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let error = storage.store("../escape", &example()).await.unwrap_err();
        assert!(error.to_string().contains("../escape"));
    }

    #[test]
    fn builds_file_storage_from_caddy_json() {
        let storage = from_config(&serde_json::json!({
            "module": "file_system",
            "root": "/tmp/certs"
        }))
        .unwrap();
        assert_eq!(storage.name(), "file_system");
    }
}
