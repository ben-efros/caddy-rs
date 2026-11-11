//! Caddy-compatible data-directory resolution and early permission preflight.
//!
//! The server must not begin automatic-HTTPS work (or consume an ACME order) before it knows that
//! the certificate/account storage root can actually be created and written. The old failure mode
//! was an unlocated `certificate I/O error: Permission denied` after the listeners had already been
//! started.
//!
//! This module is intentionally small and side-effect-free until [`preflight`] is called. It has no
//! dependency on the HTTP, TLS or manager layers, so the CLI, `pki`/`trust`, tests and future
//! embedders can share the same resolution and diagnostics.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Environment override for the data directory (caddy-rs-specific).
pub const DATA_DIR_ENV: &str = "CADDY_RS_DATA_DIR";
/// XDG base directory for application data.
pub const XDG_DATA_HOME_ENV: &str = "XDG_DATA_HOME";
/// Home directory fallback.
pub const HOME_ENV: &str = "HOME";
/// Caddy's application data subdirectory.
pub const CADDY_DATA_SUBDIR: &str = "caddy";
/// Legacy caddy-rs working-directory data directory.
pub const LEGACY_DATA_DIR: &str = ".caddy-rs";

/// Why a data directory was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirSource {
    /// Explicit `--data-dir`.
    Explicit,
    /// `CADDY_RS_DATA_DIR`.
    Environment,
    /// `storage.root` from the configuration.
    StorageRoot,
    /// Caddy's XDG/HOME path (the drop-in default).
    CaddyDefault,
    /// Legacy `.caddy-rs` in the working directory.
    Legacy,
}

impl DataDirSource {
    /// Stable label for diagnostics and `data status`.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Explicit => "--data-dir",
            Self::Environment => "CADDY_RS_DATA_DIR",
            Self::StorageRoot => "storage.root",
            Self::CaddyDefault => "Caddy XDG data directory",
            Self::Legacy => "legacy .caddy-rs",
        }
    }
}

/// Resolution result with any operator-facing warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDataDir {
    /// Chosen path (possibly relative to the working directory).
    pub path: PathBuf,
    /// Why this path was chosen.
    pub source: DataDirSource,
    /// Warnings to log once at startup.
    pub warnings: Vec<String>,
}

/// Resolve the effective server data directory from the environment and working directory.
pub fn resolve_server_data_dir(
    explicit: Option<PathBuf>,
    storage_root: Option<PathBuf>,
) -> ResolvedDataDir {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    resolve_server_data_dir_with(
        explicit,
        std::env::var_os(DATA_DIR_ENV).map(PathBuf::from),
        storage_root,
        &cwd,
        std::env::var_os(XDG_DATA_HOME_ENV),
        std::env::var_os(HOME_ENV),
    )
}

/// Testable resolution with explicit environment and working directory.
pub fn resolve_server_data_dir_with(
    explicit: Option<PathBuf>,
    environment: Option<PathBuf>,
    storage_root: Option<PathBuf>,
    cwd: &Path,
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> ResolvedDataDir {
    // A configured `storage.root` is the effective certificate/account root: the TLS storage
    // selector gives it precedence over the CLI data-directory fallback (proved by
    // `configured_storage_root_wins_over_the_data_directory` in the server tests). Resolve the
    // same way here so diagnostics/preflight check the root that will actually be written.
    if let Some(path) = storage_root {
        return ResolvedDataDir {
            path,
            source: DataDirSource::StorageRoot,
            warnings: Vec::new(),
        };
    }
    if let Some(path) = explicit {
        return ResolvedDataDir {
            path,
            source: DataDirSource::Explicit,
            warnings: Vec::new(),
        };
    }
    if let Some(path) = environment.filter(|path| !path.as_os_str().is_empty()) {
        return ResolvedDataDir {
            path,
            source: DataDirSource::Environment,
            warnings: Vec::new(),
        };
    }

    let caddy = caddy_data_dir_with(cwd, xdg_data_home, home);
    let legacy = cwd.join(LEGACY_DATA_DIR);
    if caddy.is_dir() {
        let mut warnings = Vec::new();
        if legacy.is_dir() {
            warnings.push(format!(
                "found both Caddy data `{}` and legacy caddy-rs data `{}`; using the Caddy path \
                 and leaving the legacy directory untouched",
                caddy.display(),
                legacy.display()
            ));
        }
        ResolvedDataDir {
            path: caddy,
            source: DataDirSource::CaddyDefault,
            warnings,
        }
    } else if legacy.is_dir() {
        ResolvedDataDir {
            path: legacy.clone(),
            source: DataDirSource::Legacy,
            warnings: vec![format!(
                "legacy caddy-rs data directory `{}` is in use; Caddy's data path would be `{}`. \
                 Run `caddy-rs data status` before migrating",
                legacy.display(),
                caddy.display()
            )],
        }
    } else {
        ResolvedDataDir {
            path: caddy,
            source: DataDirSource::CaddyDefault,
            warnings: Vec::new(),
        }
    }
}

/// Caddy's `AppDataDir()`-equivalent path: `$XDG_DATA_HOME/caddy`, then
/// `$HOME/.local/share/caddy`, then `./caddy`.
pub fn caddy_data_dir() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    caddy_data_dir_with(
        &cwd,
        std::env::var_os(XDG_DATA_HOME_ENV),
        std::env::var_os(HOME_ENV),
    )
}

/// Testable form of [`caddy_data_dir`].
pub fn caddy_data_dir_with(
    cwd: &Path,
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> PathBuf {
    if let Some(base) = xdg_data_home.filter(|value| !value.is_empty()) {
        PathBuf::from(base).join(CADDY_DATA_SUBDIR)
    } else if let Some(home) = home.filter(|value| !value.is_empty()) {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join(CADDY_DATA_SUBDIR)
    } else {
        cwd.join(CADDY_DATA_SUBDIR)
    }
}

/// Failure to prepare the data directory. Every field is safe to print (paths, modes, uids and an
/// errno; never certificate or account contents).
#[derive(Debug)]
pub struct DataDirError {
    /// Directory involved.
    pub path: PathBuf,
    /// Operation that failed.
    pub operation: &'static str,
    /// Underlying I/O error, when the failure came from the OS.
    pub source: Option<io::Error>,
    /// Classification.
    pub kind: DataDirErrorKind,
    /// Nearest existing ancestor, when known.
    pub parent: Option<PathBuf>,
    /// Parent mode (Unix), when known.
    pub parent_mode: Option<u32>,
    /// Process uid (Unix), when known.
    pub process_uid: Option<u32>,
    /// Suggested operator action.
    pub hint: Option<String>,
}

/// Classification for [`DataDirError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirErrorKind {
    /// The path exists but is not a directory.
    NotDirectory,
    /// The path is a symlink; refused unless explicitly allowed.
    Symlink,
    /// The directory or a parent is world-writable.
    WorldWritable,
    /// The directory is owned by another user and this process is not root.
    NotOwned,
    /// The create/write/probe operation failed.
    Io,
}

impl fmt::Display for DataDirError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot prepare data directory `{}` ({}): ",
            self.path.display(),
            self.operation
        )?;
        match &self.source {
            Some(error) => write!(formatter, "{error}")?,
            None => write!(formatter, "{:?}", self.kind)?,
        }
        if let Some(parent) = &self.parent {
            write!(formatter, "; parent `{}`", parent.display())?;
            if let Some(mode) = self.parent_mode {
                write!(formatter, " mode {mode:04o}")?;
            }
        }
        if let Some(uid) = self.process_uid {
            write!(formatter, "; process uid {uid}")?;
        }
        if let Some(hint) = &self.hint {
            write!(formatter, "; hint: {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DataDirError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

/// Result of a successful preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirReport {
    /// Absolute root that was checked.
    pub root: PathBuf,
    /// Whether the final directory was created by this call.
    pub created: bool,
    /// Directory mode (Unix; 0 elsewhere).
    pub mode: u32,
    /// Owner uid (Unix; None elsewhere).
    pub owner: Option<u32>,
    /// Non-fatal warnings (group-writable, root-owned directory used by a non-root future service).
    pub warnings: Vec<String>,
}

/// Number of times a preflight is retried when the data directory itself is created or removed by
/// another thread/process while it is being checked.
const CONCURRENT_RETRIES: usize = 3;

/// Create/check the data directory before any certificate work.
///
/// This is intentionally conservative:
/// * symlinked roots are refused (a symlink can redirect credential storage);
/// * world-writable roots are refused; group-writable roots warn;
/// * a root owned by another uid is refused unless this process is root;
/// * a random `0600` probe file is created and removed with `create_new` (no symlink following);
/// * failures carry the path, operation, parent mode/owner and a fix hint.
///
/// A data directory can legitimately be created or removed concurrently: two runtimes (or two
/// parallel tests) may resolve the same path, and one may clean it up while the other checks it.
/// That is not a permission failure, so [`preflight_once`] is retried a bounded number of times
/// before the losing side of the race is reported.
pub fn preflight(root: &Path) -> Result<DataDirReport, DataDirError> {
    let mut attempt = 0;
    loop {
        match preflight_once(root) {
            Err(error) if attempt < CONCURRENT_RETRIES && is_concurrent_race(&error) => {
                attempt += 1;
                std::thread::yield_now();
            }
            result => return result,
        }
    }
}

/// Whether `error` looks like the data directory changed under us rather than a permission problem.
///
/// `NotFound` covers a directory (or probe file) removed by another actor between our stat and our
/// use; `AlreadyExists` covers a directory created by another actor after we saw it missing. Both
/// are retried, and a real permission failure still surfaces with its original location.
fn is_concurrent_race(error: &DataDirError) -> bool {
    error.kind == DataDirErrorKind::Io
        && matches!(
            error.source.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::NotFound | io::ErrorKind::AlreadyExists)
        )
}

fn preflight_once(root: &Path) -> Result<DataDirReport, DataDirError> {
    let root = absolute_path(root)?;
    let mut warnings = Vec::new();

    let existing = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(DataDirError {
                path: root,
                operation: "stat data directory",
                source: Some(error),
                kind: DataDirErrorKind::Io,
                parent: None,
                parent_mode: None,
                process_uid: process_uid(),
                hint: None,
            })
        }
    };

    let created;
    if let Some(metadata) = &existing {
        if metadata.file_type().is_symlink() {
            return Err(DataDirError {
                path: root.clone(),
                operation: "reject symlinked data directory",
                source: None,
                kind: DataDirErrorKind::Symlink,
                parent: root.parent().map(Path::to_path_buf),
                parent_mode: root.parent().and_then(mode_of),
                process_uid: process_uid(),
                hint: Some(
                    "point --data-dir/storage.root at the real directory, not a symlink"
                        .to_string(),
                ),
            });
        }
        if !metadata.is_dir() {
            return Err(DataDirError {
                path: root.clone(),
                operation: "check data directory",
                source: None,
                kind: DataDirErrorKind::NotDirectory,
                parent: root.parent().map(Path::to_path_buf),
                parent_mode: root.parent().and_then(mode_of),
                process_uid: process_uid(),
                hint: Some("remove the file or choose another --data-dir".to_string()),
            });
        }
        created = false;
    } else {
        let parent = root.parent().map(Path::to_path_buf);
        let nearest = parent.as_deref().and_then(nearest_existing_ancestor);
        if let Some(ancestor) = &nearest {
            check_ancestor(ancestor, &root)?;
        }
        created = match create_root(&root) {
            Ok(()) => true,
            // Another thread/process created the directory between our stat and our create. That
            // is success: the directory exists, and the mode/owner/write checks below still run.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                return Err(DataDirError {
                    path: root.clone(),
                    operation: "create data directory",
                    source: Some(error),
                    kind: DataDirErrorKind::Io,
                    parent,
                    parent_mode: nearest.as_deref().and_then(mode_of),
                    process_uid: process_uid(),
                    hint: Some(format!(
                        "create it as the service user: install -d -o {} -g {} -m 0750 {}",
                        user_name(),
                        group_name(),
                        root.display()
                    )),
                })
            }
        };
    }

    let metadata = std::fs::metadata(&root).map_err(|error| DataDirError {
        path: root.clone(),
        operation: "stat created data directory",
        source: Some(error),
        kind: DataDirErrorKind::Io,
        parent: root.parent().map(Path::to_path_buf),
        parent_mode: root.parent().and_then(mode_of),
        process_uid: process_uid(),
        hint: None,
    })?;
    let mode = mode_of_metadata(&metadata);
    if mode & 0o002 != 0 {
        return Err(DataDirError {
            path: root.clone(),
            operation: "reject world-writable data directory",
            source: None,
            kind: DataDirErrorKind::WorldWritable,
            parent: root.parent().map(Path::to_path_buf),
            parent_mode: root.parent().and_then(mode_of),
            process_uid: process_uid(),
            hint: Some(
                "chmod o-w on the data directory; certificate keys must not be replaceable"
                    .to_string(),
            ),
        });
    }
    if mode & 0o020 != 0 {
        warnings.push(format!(
            "data directory `{}` is group-writable (mode {mode:04o}); ensure the group is trusted",
            root.display()
        ));
    }
    if let (Some(owner), Some(uid)) = (owner_of_metadata(&metadata), process_uid()) {
        if owner != uid && uid != 0 {
            return Err(DataDirError {
                path: root.clone(),
                operation: "check data-directory owner",
                source: None,
                kind: DataDirErrorKind::NotOwned,
                parent: root.parent().map(Path::to_path_buf),
                parent_mode: root.parent().and_then(mode_of),
                process_uid: Some(uid),
                hint: Some(format!(
                    "chown -R {uid}:{gid} {}",
                    root.display(),
                    gid = process_gid().unwrap_or(uid)
                )),
            });
        }
        if uid == 0 && owner != 0 {
            warnings.push(format!(
                "running as root but data directory `{}` is owned by uid {owner}; files created \
                 here will be root-owned and may block a later non-root service",
                root.display()
            ));
        }
    }

    probe_write(&root)?;

    Ok(DataDirReport {
        root,
        created,
        mode,
        owner: owner_of_metadata(&metadata),
        warnings,
    })
}

fn create_root(root: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o750);
        builder.create(root)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(root)
    }
}

/// Distinguishes probes created in the same clock tick by different threads of this process.
///
/// `SystemTime` has nanosecond *resolution*, not nanosecond *granularity*: two threads (or two
/// virtualized hosts) can read the same tick, and before this counter existed both computed the
/// same probe filename. The first `create_new` then won and the second failed with `AlreadyExists`,
/// while the winner's `remove_file` failed with `NotFound` after the loser cleaned up — a flaky
/// "data directory is not writable" panic from a directory that was perfectly writable.
static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// How many probe names to try before accepting a persistent collision as proof of writability.
const PROBE_ATTEMPTS: usize = 3;

fn probe_name(nonce: u128) -> String {
    let sequence = PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!(
        ".caddy-rs-write-test.{}.{nonce}.{sequence}",
        std::process::id()
    )
}

fn probe_write(root: &Path) -> Result<(), DataDirError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    probe_write_with_nonce(root, nonce)
}

/// Write and remove one `0600` probe file. `nonce` is a parameter so tests can force two probes
/// into the same clock tick and prove that they still do not collide.
fn probe_write_with_nonce(root: &Path, nonce: u128) -> Result<(), DataDirError> {
    probe_write_with_names(root, || probe_name(nonce))
}

/// The retry loop, with the probe filename supplied by `next_name` so tests can force an
/// `AlreadyExists` collision deterministically instead of relying on a timing race.
fn probe_write_with_names(
    root: &Path,
    mut next_name: impl FnMut() -> String,
) -> Result<(), DataDirError> {
    for _ in 0..PROBE_ATTEMPTS {
        let probe = root.join(next_name());
        match try_probe(&probe) {
            Ok(()) => return Ok(()),
            // The name exists already. Another actor is demonstrably able to create files here,
            // which is what the probe checks, so retry with a fresh name and then accept success.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                let _ = std::fs::remove_file(&probe);
                return Err(DataDirError {
                    path: root.to_path_buf(),
                    operation: "write-probe data directory",
                    source: Some(error),
                    kind: DataDirErrorKind::Io,
                    parent: root.parent().map(Path::to_path_buf),
                    parent_mode: root.parent().and_then(mode_of),
                    process_uid: process_uid(),
                    hint: Some(format!(
                        "ensure the service user can create files in `{}`",
                        root.display()
                    )),
                });
            }
        }
    }
    Ok(())
}

fn try_probe(probe: &Path) -> io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(probe)?;
    file.write_all(b"caddy-rs data-directory preflight\n")?;
    file.sync_all()?;
    drop(file);
    match std::fs::remove_file(probe) {
        Ok(()) => Ok(()),
        // Another actor removed our probe first (a colliding probe name, or a cleanup). The write
        // itself succeeded, so this is not a data-directory failure.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn check_ancestor(ancestor: &Path, root: &Path) -> Result<(), DataDirError> {
    let metadata = std::fs::metadata(ancestor).map_err(|error| DataDirError {
        path: root.to_path_buf(),
        operation: "stat data-directory ancestor",
        source: Some(error),
        kind: DataDirErrorKind::Io,
        parent: ancestor.parent().map(Path::to_path_buf),
        parent_mode: ancestor.parent().and_then(mode_of),
        process_uid: process_uid(),
        hint: None,
    })?;
    if !metadata.is_dir() {
        return Err(DataDirError {
            path: root.to_path_buf(),
            operation: "check data-directory ancestor",
            source: None,
            kind: DataDirErrorKind::NotDirectory,
            parent: Some(ancestor.to_path_buf()),
            parent_mode: mode_of(ancestor),
            process_uid: process_uid(),
            hint: Some("a parent component is not a directory".to_string()),
        });
    }
    let mode = mode_of_metadata(&metadata);
    if mode & 0o002 != 0 {
        return Err(DataDirError {
            path: root.to_path_buf(),
            operation: "reject world-writable data-directory ancestor",
            source: None,
            kind: DataDirErrorKind::WorldWritable,
            parent: Some(ancestor.to_path_buf()),
            parent_mode: Some(mode),
            process_uid: process_uid(),
            hint: Some(format!("chmod o-w `{}`", ancestor.display())),
        });
    }
    if let (Some(owner), Some(uid)) = (owner_of_metadata(&metadata), process_uid()) {
        if owner != uid && uid != 0 {
            return Err(DataDirError {
                path: root.to_path_buf(),
                operation: "check data-directory ancestor owner",
                source: None,
                kind: DataDirErrorKind::NotOwned,
                parent: Some(ancestor.to_path_buf()),
                parent_mode: Some(mode),
                process_uid: Some(uid),
                hint: Some(format!(
                    "choose a path below a directory owned by uid {uid}, or chown `{}`",
                    ancestor.display()
                )),
            });
        }
    }
    Ok(())
}

fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut candidate = path;
    loop {
        if candidate.exists() {
            return Some(candidate.to_path_buf());
        }
        candidate = candidate.parent()?;
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, DataDirError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().map_err(|error| DataDirError {
        path: path.to_path_buf(),
        operation: "resolve data-directory working directory",
        source: Some(error),
        kind: DataDirErrorKind::Io,
        parent: None,
        parent_mode: None,
        process_uid: process_uid(),
        hint: None,
    })?;
    Ok(cwd.join(path))
}

fn mode_of(path: &Path) -> Option<u32> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| mode_of_metadata(&metadata))
}

#[cfg(unix)]
fn mode_of_metadata(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of_metadata(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn owner_of_metadata(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.uid())
}

#[cfg(not(unix))]
fn owner_of_metadata(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

#[cfg(target_os = "linux")]
fn process_uid() -> Option<u32> {
    process_status_field("Uid:")
}

#[cfg(target_os = "linux")]
fn process_gid() -> Option<u32> {
    process_status_field("Gid:")
}

#[cfg(target_os = "linux")]
fn process_status_field(prefix: &str) -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with(prefix))?;
    // Format: `Uid:	<real>	<effective>	<saved>	<fs>` (same shape for Gid).
    line.split_whitespace().nth(2)?.parse().ok()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_uid() -> Option<u32> {
    None
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_gid() -> Option<u32> {
    None
}

#[cfg(not(unix))]
fn process_uid() -> Option<u32> {
    None
}

#[cfg(not(unix))]
fn process_gid() -> Option<u32> {
    None
}

fn user_name() -> String {
    std::env::var("USER").unwrap_or_else(|_| "caddy".to_string())
}

fn group_name() -> String {
    std::env::var("GROUP").unwrap_or_else(|_| "caddy".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "caddy-rs-data-{label}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn caddy_path_prefers_xdg_then_home_then_cwd() {
        let cwd = Path::new("/work");
        assert_eq!(
            caddy_data_dir_with(
                cwd,
                Some(OsString::from("/xdg")),
                Some(OsString::from("/home/u"))
            ),
            PathBuf::from("/xdg/caddy")
        );
        assert_eq!(
            caddy_data_dir_with(cwd, None, Some(OsString::from("/home/u"))),
            PathBuf::from("/home/u/.local/share/caddy")
        );
        assert_eq!(
            caddy_data_dir_with(cwd, None, None),
            PathBuf::from("/work/caddy")
        );
    }

    #[test]
    fn existing_caddy_data_is_preferred_over_legacy() {
        let cwd = temp_dir("caddy");
        let caddy = cwd.join("caddy");
        let legacy = cwd.join(LEGACY_DATA_DIR);
        std::fs::create_dir_all(&caddy).unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        let resolved = resolve_server_data_dir_with(None, None, None, &cwd, None, None);
        assert_eq!(resolved.path, caddy);
        assert_eq!(resolved.source, DataDirSource::CaddyDefault);
        assert!(resolved
            .warnings
            .iter()
            .any(|warning| warning.contains("both")));
        let _ = std::fs::remove_dir_all(cwd);
    }

    #[test]
    fn legacy_data_is_used_when_caddy_data_is_absent() {
        let cwd = temp_dir("legacy");
        let legacy = cwd.join(LEGACY_DATA_DIR);
        std::fs::create_dir_all(&legacy).unwrap();
        let resolved = resolve_server_data_dir_with(
            None,
            None,
            None,
            &cwd,
            None,
            Some(OsString::from(cwd.to_string_lossy().to_string())),
        );
        assert_eq!(resolved.path, legacy);
        assert_eq!(resolved.source, DataDirSource::Legacy);
        assert!(!resolved.warnings.is_empty());
        let _ = std::fs::remove_dir_all(cwd);
    }

    #[test]
    fn configured_storage_root_wins_over_explicit_and_environment() {
        let resolved = resolve_server_data_dir_with(
            Some(PathBuf::from("/explicit")),
            Some(PathBuf::from("/env")),
            Some(PathBuf::from("/storage")),
            Path::new("/work"),
            None,
            None,
        );
        assert_eq!(resolved.path, PathBuf::from("/storage"));
        assert_eq!(resolved.source, DataDirSource::StorageRoot);
    }

    #[test]
    fn explicit_then_environment_apply_when_no_storage_root_is_configured() {
        let resolved = resolve_server_data_dir_with(
            Some(PathBuf::from("/explicit")),
            Some(PathBuf::from("/env")),
            None,
            Path::new("/work"),
            None,
            None,
        );
        assert_eq!(resolved.path, PathBuf::from("/explicit"));
        assert_eq!(resolved.source, DataDirSource::Explicit);

        let resolved = resolve_server_data_dir_with(
            None,
            Some(PathBuf::from("/env")),
            None,
            Path::new("/work"),
            None,
            None,
        );
        assert_eq!(resolved.path, PathBuf::from("/env"));
        assert_eq!(resolved.source, DataDirSource::Environment);
    }

    #[test]
    fn preflight_creates_a_private_directory_and_removes_the_probe() {
        let parent = temp_dir("preflight");
        let root = parent.join("data");
        let report = preflight(&root).expect("preflight");
        assert!(report.created);
        assert!(root.is_dir());
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            0,
            "probe must be removed"
        );
        let _ = std::fs::remove_dir_all(parent);
    }

    /// The probe filename must stay unique even when parallel threads read the same clock tick:
    /// before the atomic sequence existed, both threads used `pid.nonce` and one lost with
    /// `AlreadyExists` (the other's `remove_file` then failed with `NotFound`).
    #[test]
    fn probe_names_are_unique_within_one_clock_tick() {
        const THREADS: usize = 64;
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                probe_name(7)
            }));
        }
        let names: HashSet<String> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(names.len(), THREADS, "probe names must not collide");
    }

    /// Two probes that were handed the *same* nonce (the exact race) must both succeed, leave no
    /// file behind, and must not report the other's file as a data-directory failure.
    #[test]
    fn concurrent_probes_in_the_same_clock_tick_succeed() {
        const THREADS: usize = 16;
        let parent = temp_dir("probe-concurrent");
        let root = parent.join("data");
        std::fs::create_dir_all(&root).unwrap();
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                probe_write_with_nonce(&root, 42)
            }));
        }
        for handle in handles {
            handle
                .join()
                .unwrap()
                .expect("concurrent probe must succeed");
        }
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            0,
            "probes must remove their own files"
        );
        let _ = std::fs::remove_dir_all(parent);
    }

    /// The `AlreadyExists` retry branch, forced deterministically instead of by a timing race: the
    /// first two generated names are a pre-existing file, so `create_new` must fail with
    /// `AlreadyExists`, the loop must retry with the next name, and the third name must succeed.
    #[test]
    fn probe_retries_a_name_that_already_exists() {
        let parent = temp_dir("probe-retry");
        let root = parent.join("data");
        std::fs::create_dir_all(&root).unwrap();
        let occupied = ".caddy-rs-write-test.occupied";
        std::fs::write(root.join(occupied), b"pre-existing").unwrap();

        let mut generated = 0usize;
        let result = probe_write_with_names(&root, || {
            generated += 1;
            if generated < PROBE_ATTEMPTS {
                occupied.to_string()
            } else {
                format!(".caddy-rs-write-test.retry-{generated}")
            }
        });

        result.expect("a colliding probe name must be retried, not reported as a write failure");
        assert_eq!(
            generated, PROBE_ATTEMPTS,
            "every collision must consume one bounded attempt"
        );
        let entries: Vec<OsString> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            vec![OsString::from(occupied)],
            "the pre-existing file must be left alone and the probe removed"
        );
        assert_eq!(
            std::fs::read_to_string(root.join(occupied)).unwrap(),
            "pre-existing"
        );
        let _ = std::fs::remove_dir_all(parent);
    }

    /// A shared data directory is not an error when several threads preflight it at once: the
    /// directory appears and the probe files come and go concurrently.
    #[test]
    fn concurrent_preflight_of_one_fresh_root_succeeds() {
        const THREADS: usize = 32;
        const ROUNDS: usize = 25;
        for round in 0..ROUNDS {
            let parent = temp_dir(&format!("preflight-concurrent-{round}"));
            let root = parent.join("data");
            let barrier = Arc::new(Barrier::new(THREADS));
            let mut handles = Vec::new();
            for _ in 0..THREADS {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    preflight(&root)
                }));
            }
            for handle in handles {
                handle
                    .join()
                    .unwrap()
                    .expect("concurrent preflight must succeed");
            }
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn preflight_rejects_world_writable_directory() {
        let root = temp_dir("world");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o702)).unwrap();
        }
        let error = preflight(&root).expect_err("world-writable must fail");
        assert_eq!(error.kind, DataDirErrorKind::WorldWritable);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_symlink_root() {
        let parent = temp_dir("symlink");
        let target = parent.join("target");
        let link = parent.join("link");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = preflight(&link).expect_err("symlink must fail");
        assert_eq!(error.kind, DataDirErrorKind::Symlink);
        let _ = std::fs::remove_dir_all(parent);
    }

    #[test]
    fn preflight_rejects_regular_file_root() {
        let parent = temp_dir("file");
        let root = parent.join("data");
        std::fs::write(&root, b"not a directory").unwrap();
        let error = preflight(&root).expect_err("file must fail");
        assert_eq!(error.kind, DataDirErrorKind::NotDirectory);
        let _ = std::fs::remove_dir_all(parent);
    }
}
