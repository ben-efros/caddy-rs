//! Composition root for the caddy-rs proxy manager.
//!
//! This crate wires the durable repositories, the host service and the Caddy configuration
//! compiler/assembler around one data directory, and performs the data-directory preflight before
//! any state is opened. It is deliberately the only PM crate that knows about filesystem layout;
//! the repositories still accept any [`StateStore`](caddy_rs_pm_state::StateStore).
//!
//! # Layout
//!
//! ```text
//! <data_dir>/
//!   pm/
//!     state.json   # PM host/policy documents (SnapshotStore, mode 0600)
//! ```
//!
//! PM state never lives directly in `<data_dir>`. The data directory itself is owned by the
//! deployment and may contain unrelated files, including legacy Caddy data.
//!
//! # Preflight
//!
//! [`PmRuntime::open`] refuses an empty or non-directory data directory with a path-aware error.
//! A missing data directory and `<data_dir>/pm` are created with mode `0700` on Unix. Existing
//! directories are used as given: the runtime never changes ownership (`chown`) and never changes
//! the mode of an existing data directory or `pm` directory.
//!
//! Writability is proven, not assumed: the runtime creates a unique `.pm-write-probe-*` file inside
//! `<data_dir>/pm`, writes it, fsyncs it and removes it. Any failure is
//! [`RuntimeError::DataDirNotWritable`] naming `<data_dir>/pm` and the underlying I/O error. There
//! is no fallback to the current directory or a temporary directory.
//!
//! # Symlinks
//!
//! Both `<data_dir>` and `<data_dir>/pm` are inspected with `symlink_metadata`, never with a
//! following `stat`. A symlink at either position is refused by default with a located
//! [`RuntimeError::SymlinkNotAllowed`] naming the link and its target. The opt-in
//! [`RuntimeConfig::allow_symlink_data_dir`] canonicalises the link and requires its target to be a
//! directory before the normal checks run; the resolved target becomes the effective
//! [`PmRuntime::data_dir`] or state directory. A dangling symlink is always a located error, with or
//! without the override, and is never followed or created through.
//!
//! # Legacy Caddy data
//!
//! A data directory that previously belonged to Caddy may still contain Caddy's certificate
//! storage. The runtime detects the following direct children and records a warning in
//! [`RuntimeStatus::warnings`]:
//!
//! * directories named `certificates`, `acme` or `pki`;
//! * a regular file named `instance.uuid`;
//! * regular files named `caddy.db` or starting with `caddy.db-`/`caddy.db.` (the SQLite database
//!   and its lock/journal/backup sidecars).
//!
//! Detection only reads directory entries and file types. Legacy paths are never opened, read,
//! adopted, migrated or modified, and symlinks are not followed. PM state remains under
//! `<data_dir>/pm` even when legacy Caddy data is present.
//!
//! # Errors and secrets
//!
//! Every error carries the path it applies to where a path is relevant, and errors never include
//! secret material. This crate has no secret store and does not read certificate or key files.
//!
//! [`RuntimeStatus`]: crate::RuntimeStatus
//! [`RuntimeStatus::warnings`]: crate::RuntimeStatus::warnings

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use caddy_rs_pm_compiler::{compile_routes, CompileError, CompiledRoutes};
use caddy_rs_pm_config::{assemble_from_hosts, ConfigError, ConfigSettings};
use caddy_rs_pm_hosts::HostRepository;
use caddy_rs_pm_policies::PolicyRepository;
use caddy_rs_pm_service::{HostService, ServiceError};
use caddy_rs_pm_state::{SnapshotStore, StateError, StateStore};
use serde_json::Value;
use thiserror::Error;

/// Name of the PM-owned directory below the data directory.
pub const PM_DIRECTORY: &str = "pm";

/// Name of the PM state file below [`PM_DIRECTORY`].
pub const STATE_FILE: &str = "state.json";

/// Direct children of the data directory that are detected as legacy Caddy storage directories.
pub const LEGACY_CADDY_DIRECTORY_MARKERS: &[&str] = &["certificates", "acme", "pki"];

/// Direct children of the data directory that are detected as legacy Caddy storage files.
pub const LEGACY_CADDY_FILE_MARKERS: &[&str] = &["instance.uuid"];

/// Prefix of legacy Caddy database files (`caddy.db`, `caddy.db-wal`, `caddy.db.backup`, ...).
pub const LEGACY_CADDY_DATABASE_PREFIX: &str = "caddy.db";

/// Inputs for the PM runtime composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Deployment-owned data directory. The runtime only creates and uses its `pm/` child.
    ///
    /// When [`RuntimeConfig::allow_symlink_data_dir`] is set and this path is a symlink, the
    /// runtime replaces it with the canonical target while opening.
    pub data_dir: PathBuf,
    symlink_data_dir_allowed: bool,
}

impl RuntimeConfig {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            symlink_data_dir_allowed: false,
        }
    }

    /// Allow a symlinked data directory or `<data_dir>/pm` directory.
    ///
    /// The default is `false`: both paths are inspected with `symlink_metadata` and a symlink is
    /// refused with [`RuntimeError::SymlinkNotAllowed`]. When allowed, each link is canonicalised
    /// and its target must be a directory; a dangling or non-directory target is a located error.
    /// The override never follows a symlink during legacy detection or the write probe.
    #[must_use]
    pub fn allow_symlink_data_dir(mut self, allow: bool) -> Self {
        self.symlink_data_dir_allowed = allow;
        self
    }

    /// Whether symlinked data and `pm` directories are allowed.
    pub fn symlink_data_dir_allowed(&self) -> bool {
        self.symlink_data_dir_allowed
    }
}

/// A snapshot of the runtime's current observable state.
///
/// Host and policy counts are read from the store on every call; they are not cached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub data_dir: PathBuf,
    pub state_path: PathBuf,
    pub host_count: usize,
    pub policy_count: usize,
    pub legacy_caddy_detected: bool,
    /// Operator-facing diagnostics. Warnings never contain secret material.
    pub warnings: Vec<String>,
}

/// A failed runtime open, read or compile.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The configured data-directory path is empty.
    #[error("invalid PM data directory {path}: {reason}")]
    InvalidDataDir { path: PathBuf, reason: &'static str },
    /// The configured path exists but is not a directory.
    #[error("PM data directory {path} exists but is not a directory")]
    NotADirectory { path: PathBuf },
    /// A symlinked data or `pm` directory was refused because symlinks are not allowed.
    #[error(
        "PM data path {path} is a symlink to {target}; symlinked data directories are refused \
         unless RuntimeConfig::allow_symlink_data_dir(true) is set"
    )]
    SymlinkNotAllowed { path: PathBuf, target: PathBuf },
    /// A symlink's target could not be resolved.
    #[error("PM data path {path} is a symlink to {target}, which cannot be resolved: {source}")]
    SymlinkUnresolvable {
        path: PathBuf,
        target: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A symlink's resolved target is not a directory.
    #[error("PM data path {path} is a symlink to {target}, which is not a directory")]
    SymlinkTargetNotDirectory { path: PathBuf, target: PathBuf },
    /// A data-directory or `pm` directory could not be inspected.
    #[error("PM data path {path} could not be inspected: {source}")]
    DataDirUnreadable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A missing data-directory or `pm` directory could not be created or secured.
    #[error("failed to create PM directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The write probe in `<data_dir>/pm` failed.
    #[error(
        "PM data directory {path} is not writable ({source}); fix the ownership and permissions of \
         {path}"
    )]
    DataDirNotWritable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The state file could not be opened or read.
    #[error("PM state error for {path}: {source}")]
    State {
        path: PathBuf,
        #[source]
        source: StateError,
    },
    /// A host or policy read failed.
    #[error("PM service error for {path}: {source}")]
    Service {
        path: PathBuf,
        #[source]
        source: ServiceError,
    },
    /// Stored hosts could not be compiled into routes.
    #[error("cannot compile routes for hosts stored in {path}: {source}")]
    Compile {
        path: PathBuf,
        #[source]
        source: CompileError,
    },
    /// The assembled Caddy configuration was rejected.
    #[error("cannot assemble a Caddy configuration for hosts stored in {path}: {source}")]
    Config {
        path: PathBuf,
        #[source]
        source: ConfigError,
    },
}

/// The composed proxy-manager runtime over one data directory.
///
/// Cloning shares the underlying store, repositories and service.
#[derive(Clone)]
pub struct PmRuntime {
    config: RuntimeConfig,
    state_path: PathBuf,
    legacy_markers: Vec<String>,
    hosts: HostRepository,
    policies: PolicyRepository,
    service: HostService,
}

impl PmRuntime {
    /// Perform the data-directory preflight and open the PM state.
    pub fn open(config: RuntimeConfig) -> Result<Self, RuntimeError> {
        Self::open_inner(config, probe_writable)
    }

    fn open_inner(
        mut config: RuntimeConfig,
        probe: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<Self, RuntimeError> {
        let configured = config.data_dir.clone();
        if configured.as_os_str().is_empty() {
            return Err(RuntimeError::InvalidDataDir {
                path: configured,
                reason: "the data directory path is empty",
            });
        }

        let allow_symlinks = config.symlink_data_dir_allowed();
        let data_dir = resolve_or_create_directory(&configured, allow_symlinks)?;
        let pm_dir = resolve_or_create_directory(&data_dir.join(PM_DIRECTORY), allow_symlinks)?;
        probe(&pm_dir).map_err(|source| RuntimeError::DataDirNotWritable {
            path: pm_dir.clone(),
            source,
        })?;

        let legacy_markers = detect_legacy_caddy_data(&data_dir)?;
        let state_path = pm_dir.join(STATE_FILE);
        let store: Arc<dyn StateStore> = Arc::new(SnapshotStore::open(&state_path).map_err(
            |source| RuntimeError::State {
                path: state_path.clone(),
                source,
            },
        )?);
        let hosts = HostRepository::new(Arc::clone(&store));
        let policies = PolicyRepository::new(Arc::clone(&store));
        let service = HostService::with_policies(Arc::clone(&store), policies.clone());

        // Keep the effective (canonical, when a symlink override was used) data directory so
        // `data_dir()` and `status()` describe where state actually lives.
        config.data_dir = data_dir;

        Ok(Self {
            config,
            state_path,
            legacy_markers,
            hosts,
            policies,
            service,
        })
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    pub fn data_dir(&self) -> &Path {
        &self.config.data_dir
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub fn hosts(&self) -> &HostRepository {
        &self.hosts
    }

    pub fn policies(&self) -> &PolicyRepository {
        &self.policies
    }

    pub fn service(&self) -> &HostService {
        &self.service
    }

    /// Legacy Caddy markers found during [`PmRuntime::open`], sorted. Informational only.
    pub fn legacy_markers(&self) -> &[String] {
        &self.legacy_markers
    }

    /// Read current counts and diagnostics.
    ///
    /// Both counts are fresh store reads on every call.
    pub fn status(&self) -> Result<RuntimeStatus, RuntimeError> {
        let hosts = self
            .hosts
            .list()
            .map_err(|source| self.service_error(ServiceError::Host(source)))?;
        let policies = self
            .policies
            .list()
            .map_err(|source| self.service_error(ServiceError::Policy(source)))?;
        let legacy_caddy_detected = !self.legacy_markers.is_empty();
        let mut warnings = Vec::new();
        if legacy_caddy_detected {
            warnings.push(format!(
                "legacy Caddy data detected in {} ({}); the proxy manager never reads, adopts, \
                 migrates or modifies those paths, and PM state is stored separately in {}",
                self.data_dir().display(),
                self.legacy_markers.join(", "),
                self.state_path.display()
            ));
        }
        Ok(RuntimeStatus {
            data_dir: self.config.data_dir.clone(),
            state_path: self.state_path.clone(),
            host_count: hosts.len(),
            policy_count: policies.len(),
            legacy_caddy_detected,
            warnings,
        })
    }

    /// Compile the stored hosts into deterministic HTTP/HTTPS route lists.
    pub fn compile(&self) -> Result<CompiledRoutes, RuntimeError> {
        let hosts = self
            .hosts
            .snapshot_hosts()
            .map_err(|source| self.service_error(ServiceError::Host(source)))?;
        compile_routes(&hosts).map_err(|source| RuntimeError::Compile {
            path: self.state_path.clone(),
            source,
        })
    }

    /// Compile the stored hosts and assemble a complete Caddy configuration.
    pub fn assemble(&self, settings: ConfigSettings) -> Result<Value, RuntimeError> {
        let hosts = self
            .hosts
            .snapshot_hosts()
            .map_err(|source| self.service_error(ServiceError::Host(source)))?;
        assemble_from_hosts(&hosts, &settings).map_err(|source| RuntimeError::Config {
            path: self.state_path.clone(),
            source,
        })
    }

    fn service_error(&self, source: ServiceError) -> RuntimeError {
        RuntimeError::Service {
            path: self.state_path.clone(),
            source,
        }
    }
}

fn resolve_or_create_directory(path: &Path, allow_symlinks: bool) -> Result<PathBuf, RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => resolve_existing_directory(path, &metadata, allow_symlinks),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            create_directory(path, allow_symlinks)
        }
        Err(source) => Err(RuntimeError::DataDirUnreadable {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Resolve an existing directory without ever following a symlink implicitly.
///
/// `metadata` must come from `symlink_metadata`. The returned path is the canonical symlink target
/// only when the caller opted in to symlinks; otherwise it is the input path.
fn resolve_existing_directory(
    path: &Path,
    metadata: &fs::Metadata,
    allow_symlinks: bool,
) -> Result<PathBuf, RuntimeError> {
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(|source| RuntimeError::DataDirUnreadable {
            path: path.to_path_buf(),
            source,
        })?;
        if !allow_symlinks {
            return Err(RuntimeError::SymlinkNotAllowed {
                path: path.to_path_buf(),
                target,
            });
        }
        let canonical =
            fs::canonicalize(path).map_err(|source| RuntimeError::SymlinkUnresolvable {
                path: path.to_path_buf(),
                target: target.clone(),
                source,
            })?;
        let resolved =
            fs::metadata(&canonical).map_err(|source| RuntimeError::DataDirUnreadable {
                path: canonical.clone(),
                source,
            })?;
        if !resolved.is_dir() {
            return Err(RuntimeError::SymlinkTargetNotDirectory {
                path: path.to_path_buf(),
                target: canonical,
            });
        }
        return Ok(canonical);
    }
    if metadata.is_dir() {
        Ok(path.to_path_buf())
    } else {
        Err(RuntimeError::NotADirectory {
            path: path.to_path_buf(),
        })
    }
}

/// Create a missing directory once and re-inspect on `AlreadyExists`.
///
/// The `AlreadyExists` path deliberately does not call this function again: a symlink or a racing
/// creator is resolved by inspection only, so a dangling link can never cause unbounded recursion.
fn create_directory(path: &Path, allow_symlinks: bool) -> Result<PathBuf, RuntimeError> {
    match create_single_directory(path) {
        Ok(()) => {
            secure_directory(path)?;
            Ok(path.to_path_buf())
        }
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            match fs::symlink_metadata(path) {
                Ok(metadata) => resolve_existing_directory(path, &metadata, allow_symlinks),
                Err(source) => Err(RuntimeError::DataDirUnreadable {
                    path: path.to_path_buf(),
                    source,
                }),
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|source| RuntimeError::CreateDirectory {
                path: path.to_path_buf(),
                source,
            })?;
            match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    resolve_existing_directory(path, &metadata, allow_symlinks)
                }
                Ok(metadata) if metadata.is_dir() => {
                    secure_directory(path)?;
                    Ok(path.to_path_buf())
                }
                Ok(_) => Err(RuntimeError::NotADirectory {
                    path: path.to_path_buf(),
                }),
                Err(source) => Err(RuntimeError::DataDirUnreadable {
                    path: path.to_path_buf(),
                    source,
                }),
            }
        }
        Err(source) => Err(RuntimeError::CreateDirectory {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn create_single_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        RuntimeError::CreateDirectory {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), RuntimeError> {
    Ok(())
}

/// Create, write, fsync and remove a unique probe file in `directory`.
///
/// This is the production writability check. It intentionally does not fall back anywhere.
fn probe_writable(directory: &Path) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let path = directory.join(format!(
            ".pm-write-probe-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                let result = file
                    .write_all(b"pm-runtime write probe\n")
                    .and_then(|()| file.sync_all());
                drop(file);
                return match result {
                    Ok(()) => fs::remove_file(&path),
                    Err(source) => {
                        let _ = fs::remove_file(&path);
                        Err(source)
                    }
                };
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(source),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique write-probe file",
    ))
}

fn detect_legacy_caddy_data(data_dir: &Path) -> Result<Vec<String>, RuntimeError> {
    let entries = fs::read_dir(data_dir).map_err(|source| RuntimeError::DataDirUnreadable {
        path: data_dir.to_path_buf(),
        source,
    })?;
    let mut markers = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| RuntimeError::DataDirUnreadable {
            path: data_dir.to_path_buf(),
            source,
        })?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let file_type = entry
            .file_type()
            .map_err(|source| RuntimeError::DataDirUnreadable {
                path: data_dir.join(&file_name),
                source,
            })?;
        let marker = if file_type.is_dir() && LEGACY_CADDY_DIRECTORY_MARKERS.contains(&name) {
            Some(format!("{name}/"))
        } else if file_type.is_file()
            && (LEGACY_CADDY_FILE_MARKERS.contains(&name) || is_legacy_caddy_database(name))
        {
            Some(name.to_owned())
        } else {
            None
        };
        if let Some(marker) = marker {
            markers.push(marker);
        }
    }
    markers.sort_unstable();
    markers.dedup();
    Ok(markers)
}

fn is_legacy_caddy_database(name: &str) -> bool {
    name.strip_prefix(LEGACY_CADDY_DATABASE_PREFIX)
        .is_some_and(|suffix| {
            suffix.is_empty() || suffix.starts_with('-') || suffix.starts_with('.')
        })
}

#[cfg(test)]
mod tests;
