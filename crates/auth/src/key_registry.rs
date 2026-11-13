//! Static passkey registry: load validated COSE keys plus display metadata.
//!
//! Two sources are supported, both read-only:
//!
//! * JSON configuration under `apps.auth.passkeys` (array of objects, see [`KeyRegistry::from_config`]).
//! * A flat `authorized_passkeys` file, one key per line
//!   (`key_id user cose_key transports [name]`, see [`KeyRegistry::from_file`]).
//!
//! The registry is an immutable snapshot: it is built once when configuration loads and shared by
//! the request path. A bad key never degrades into a weaker check — it fails with a located error
//! naming the JSON path or the `file:line`.

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use thiserror::Error;

use crate::cose::{CoseError, CosePublicKey, KeyAlgorithm};

/// One authorized passkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyEntry {
    /// Operator-chosen stable identifier (for example `yubikey-5-nfc`).
    pub key_id: String,
    /// User the key authenticates; defaults to `admin` when the source omits it.
    pub user: String,
    /// Human-readable label shown in the enrollment UI.
    pub name: Option<String>,
    /// Free-form tags for grouping keys (for example `["admin", "prod"]`).
    pub tags: Vec<String>,
    /// Declared authenticator transports (`usb`, `nfc`, `internal`, ...).
    pub transports: Vec<String>,
    /// Algorithm the key is registered for.
    pub algorithm: KeyAlgorithm,
    /// Validated public key.
    pub key: CosePublicKey,
    /// Unix timestamp (seconds) when the entry was added.
    pub added_at: u64,
}

/// Why a registry could not be built.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// A key entry is invalid; `location` is a JSON path or `file:line`.
    #[error("{location}: {reason}")]
    InvalidKey {
        /// JSON path (`apps.auth.passkeys[2].cose_key`) or `file:line`.
        location: String,
        /// Concrete reason.
        reason: String,
    },
    /// Two entries share a `key_id`.
    #[error("{location}: duplicate key_id `{key_id}`")]
    DuplicateKey {
        /// Location of the duplicate.
        location: String,
        /// The repeated identifier.
        key_id: String,
    },
    /// The source could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File that failed.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl RegistryError {
    fn invalid(location: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidKey {
            location: location.into(),
            reason: reason.into(),
        }
    }
}

/// An immutable set of authorized passkeys, indexed by `key_id`.
#[derive(Debug, Clone, Default)]
pub struct KeyRegistry {
    entries: Vec<PasskeyEntry>,
    index: HashMap<String, usize>,
}

impl KeyRegistry {
    /// Build a registry from a parsed JSON configuration value.
    ///
    /// The array is looked up at `apps.auth.passkeys`, then `auth.passkeys`, then a top-level
    /// `passkeys`; a value that is itself an array is used directly. A configuration without a
    /// passkey array yields an empty registry (passkey auth is then simply unavailable).
    ///
    /// Each entry must be an object with a `key_id` and exactly one key field: `cose_key`
    /// (base64url-encoded `COSE_Key`), `pem` (SPKI block) or `key` (either form, sniffed).
    /// Optional fields: `user` (default `admin`), `name`, `tags` (array of strings),
    /// `transports` (array of strings or comma-separated string), `added_at` (unix seconds).
    pub fn from_config(config: &Value) -> Result<Self, RegistryError> {
        let (array, base) = match locate_passkeys(config) {
            Some(found) => found,
            None => return Ok(Self::default()),
        };
        let mut entries = Vec::with_capacity(array.len());
        for (i, item) in array.iter().enumerate() {
            let location = format!("{base}[{i}]");
            entries.push(entry_from_json(item, &location)?);
        }
        Self::from_entries(entries)
    }

    /// Build a registry from a flat `authorized_passkeys` file.
    ///
    /// Format (whitespace separated, `#` starts a comment line, blank lines ignored):
    ///
    /// ```text
    /// # key_id          user   cose_key(base64url)   transports   [name]
    /// yubikey-5-nfc      admin  pQECAyYgASFYIB...     usb,nfc
    /// ```
    ///
    /// `name` is optional and may not contain whitespace.
    pub fn from_file(path: &Path) -> Result<Self, RegistryError> {
        let text = std::fs::read_to_string(path).map_err(|source| RegistryError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_file_text(path.display().to_string().as_str(), &text)
    }

    /// Build a registry from the text of an `authorized_passkeys` file (`label` prefixes errors).
    pub fn from_file_text(label: &str, text: &str) -> Result<Self, RegistryError> {
        let mut entries = Vec::new();
        for (line_index, line) in text.lines().enumerate() {
            let location = format!("{label}:{}", line_index + 1);
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() < 3 {
                return Err(RegistryError::invalid(
                    location,
                    format!(
                        "expected `key_id user cose_key [transports] [name]`, found {} field(s)",
                        fields.len()
                    ),
                ));
            }
            let key_id = fields[0];
            let user = fields[1];
            let key_text = fields[2];
            let transports = fields
                .get(3)
                .map(|value| split_list(value))
                .unwrap_or_default();
            let name = fields.get(4).map(|value| (*value).to_string());

            let key = CosePublicKey::parse(key_text).map_err(|error| {
                RegistryError::invalid(format!("{location}.cose_key"), key_error(&error))
            })?;
            let algorithm = key.algorithm;
            entries.push(PasskeyEntry {
                key_id: key_id.to_string(),
                user: user.to_string(),
                name,
                tags: Vec::new(),
                transports,
                algorithm,
                key,
                added_at: now_secs(),
            });
        }
        Self::from_entries(entries)
    }

    fn from_entries(entries: Vec<PasskeyEntry>) -> Result<Self, RegistryError> {
        let mut index = HashMap::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            if index.insert(entry.key_id.clone(), i).is_some() {
                return Err(RegistryError::DuplicateKey {
                    location: format!("apps.auth.passkeys[{i}].key_id"),
                    key_id: entry.key_id.clone(),
                });
            }
        }
        Ok(Self { entries, index })
    }

    /// Look up an entry by `key_id`.
    pub fn get(&self, key_id: &str) -> Option<&PasskeyEntry> {
        self.index.get(key_id).map(|i| &self.entries[*i])
    }

    /// Entries for one user, in declaration order.
    pub fn keys_for_user(&self, user: &str) -> Vec<&PasskeyEntry> {
        self.entries.iter().filter(|e| e.user == user).collect()
    }

    /// All entries, in declaration order.
    pub fn entries(&self) -> &[PasskeyEntry] {
        &self.entries
    }

    /// Number of registered keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no key is registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Algorithms present in the registry (for capability reporting).
    pub fn algorithms(&self) -> Vec<KeyAlgorithm> {
        let mut out = Vec::new();
        for entry in &self.entries {
            if !out.contains(&entry.algorithm) {
                out.push(entry.algorithm);
            }
        }
        out
    }
}

fn locate_passkeys(config: &Value) -> Option<(&Vec<Value>, String)> {
    if let Some(array) = config.as_array() {
        return Some((array, "passkeys".to_string()));
    }
    let paths: [&[&str]; 3] = [
        &["apps", "auth", "passkeys"],
        &["auth", "passkeys"],
        &["passkeys"],
    ];
    for path in paths {
        let mut cursor = config;
        let mut resolved = true;
        for segment in path {
            match cursor.get(*segment) {
                Some(next) => cursor = next,
                None => {
                    resolved = false;
                    break;
                }
            }
        }
        if !resolved {
            continue;
        }
        if let Some(array) = cursor.as_array() {
            return Some((array, path.join(".")));
        }
    }
    None
}

fn entry_from_json(item: &Value, location: &str) -> Result<PasskeyEntry, RegistryError> {
    let object = item
        .as_object()
        .ok_or_else(|| RegistryError::invalid(location, "entry must be a JSON object"))?;

    let key_id = object
        .get("key_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            RegistryError::invalid(
                location,
                "`key_id` is required and must be a non-empty string",
            )
        })?
        .to_string();

    let key_text = ["cose_key", "pem", "key"]
        .iter()
        .find_map(|field| object.get(*field).and_then(Value::as_str))
        .ok_or_else(|| {
            RegistryError::invalid(
                location,
                "one of `cose_key`, `pem` or `key` is required (string)",
            )
        })?;

    let key = CosePublicKey::parse(key_text).map_err(|error| {
        RegistryError::invalid(format!("{location}.cose_key"), key_error(&error))
    })?;

    let user = object
        .get("user")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| "admin".to_string());
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string);
    let tags = string_list(object.get("tags"), location, "tags")?;
    let transports = match object.get("transports") {
        Some(Value::String(value)) => split_list(value),
        other => string_list(other, location, "transports")?,
    };
    let added_at = match object.get("added_at") {
        Some(value) => value.as_u64().ok_or_else(|| {
            RegistryError::invalid(
                format!("{location}.added_at"),
                "must be a unix timestamp (integer)",
            )
        })?,
        None => now_secs(),
    };

    Ok(PasskeyEntry {
        key_id,
        user,
        name,
        tags,
        transports,
        algorithm: key.algorithm,
        key,
        added_at,
    })
}

fn string_list(
    value: Option<&Value>,
    location: &str,
    field: &str,
) -> Result<Vec<String>, RegistryError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let array = value.as_array().ok_or_else(|| {
        RegistryError::invalid(format!("{location}.{field}"), "must be an array of strings")
    })?;
    array
        .iter()
        .enumerate()
        .map(|(i, item)| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                RegistryError::invalid(format!("{location}.{field}[{i}]"), "must be a string")
            })
        })
        .collect()
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn key_error(error: &CoseError) -> String {
    format!("invalid public key: {error}")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
