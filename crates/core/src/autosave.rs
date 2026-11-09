//! Configuration autosave and resume, mirroring Caddy's autosave behavior.
//!
//! Caddy persists the last *successfully loaded* configuration to an `autosave.json` file after
//! every config transition (CLI `run` and admin-driven loads alike) unless `admin.config.persist`
//! is `false` ([`caddy.go`](https://github.com/caddyserver/caddy/blob/v2.11.9/caddy.go) ~line 377,
//! `unsyncedDecodeAndRun`). The `--resume` startup flag then loads that file in preference to
//! `--config` (`cmd/commandfuncs.go`, run command).
//!
//! The autosave path follows Caddy's `AppConfigDir()` resolution: a per-call override (the CLI's
//! `--autosave-path` flag) wins, then `$XDG_CONFIG_HOME/caddy/autosave.json`, then
//! `$HOME/.config/caddy/autosave.json`, then `./caddy/autosave.json` when neither environment
//! variable is set. A legacy caddy-rs autosave under `caddy-rs` or `.caddy-rs` is used only when
//! the Caddy path does not exist, so an upgrade does not silently lose `--resume` state.
//!
//! Unlike Caddy (which writes the file in place with `os.WriteFile`), the write here is atomic:
//! the JSON is written to a uniquely-named temporary file in the same directory, `fsync`ed, and
//! `rename`d over the target, so a crash or concurrent observer never sees a partially-written
//! autosave. The file mode is `0600` and the parent directory chain is created with `0700`, as in
//! Caddy (`MkdirAll(dir, 0o700)` + `WriteFile(path, cfgJSON, 0o600)`).
//!
//! This module is `std`-only.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Upper bound for an autosave document read by `--resume`.
///
/// The autosave is a complete Caddy config; 16 MiB is far above any realistic document while
/// keeping a corrupted or attacker-grown file from exhausting memory before JSON parsing rejects
/// it. Caddy's `os.ReadFile` has no such cap.
const MAX_AUTOSAVE_BYTES: u64 = 16 * 1024 * 1024;

/// `O_NOFOLLOW | O_CLOEXEC` for the platforms this project ships on. `O_NOFOLLOW` closes the
/// symlink race between the `symlink_metadata` check and the `open`; `O_CLOEXEC` keeps the
/// descriptor out of child processes.
#[cfg(target_os = "linux")]
const OPEN_NOFOLLOW_CLOEXEC: i32 = 0o400000 | 0o2000000;
#[cfg(target_os = "macos")]
const OPEN_NOFOLLOW_CLOEXEC: i32 = 0x0100 | 0x1000000;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const OPEN_NOFOLLOW_CLOEXEC: i32 = 0;

/// The autosave file name, matching Caddy's `autosave.json` under the config directory.
pub const AUTOSAVE_FILE_NAME: &str = "autosave.json";

/// The subdirectory appended to the XDG/HOME config base: Caddy's `caddy`, for drop-in
/// compatibility.
pub const CONFIG_DIR_SUBDIR: &str = "caddy";

/// Legacy caddy-rs config subdirectory, consulted only when the Caddy path is absent.
pub const LEGACY_CONFIG_DIR_SUBDIR: &str = "caddy-rs";

/// Environment variable consulted first for the config base directory (Unix convention).
pub const XDG_CONFIG_HOME_ENV: &str = "XDG_CONFIG_HOME";

/// Environment variable consulted when `XDG_CONFIG_HOME` is unset.
pub const HOME_ENV: &str = "HOME";

/// Fallback config base when neither `XDG_CONFIG_HOME` nor `HOME` is set; Caddy's `./caddy`
/// fallback (`AppConfigDir`).
pub const FALLBACK_CONFIG_DIR: &str = "caddy";

/// Legacy fallback config base used by older caddy-rs versions.
pub const LEGACY_FALLBACK_CONFIG_DIR: &str = ".caddy-rs";

/// The application config directory: `$XDG_CONFIG_HOME/caddy` when `XDG_CONFIG_HOME` is set,
/// `$HOME/.config/caddy` otherwise, and `./caddy` when `HOME` is also unavailable. This is Caddy's
/// `AppConfigDir()` layout.
pub fn config_dir() -> PathBuf {
    config_dir_with(
        std::env::var_os(XDG_CONFIG_HOME_ENV),
        std::env::var_os(HOME_ENV),
    )
}

/// Testable form of [`config_dir`] with the environment values supplied explicitly.
///
/// An empty `XDG_CONFIG_HOME` is treated as unset, matching Caddy's `if basedir != ""` check.
pub fn config_dir_with(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> PathBuf {
    if let Some(base) = xdg_config_home.filter(|value| !value.is_empty()) {
        PathBuf::from(base).join(CONFIG_DIR_SUBDIR)
    } else if let Some(home) = home.filter(|value| !value.is_empty()) {
        PathBuf::from(home).join(".config").join(CONFIG_DIR_SUBDIR)
    } else {
        PathBuf::from(FALLBACK_CONFIG_DIR)
    }
}

/// Result of resolving the autosave path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutosavePath {
    /// Path to use.
    pub path: PathBuf,
    /// Whether a legacy caddy-rs autosave was selected.
    pub legacy: bool,
}

/// The default autosave path: the Caddy config directory when it exists, otherwise a legacy
/// caddy-rs autosave when that exists, otherwise the Caddy path for a new installation.
pub fn default_autosave_path() -> PathBuf {
    resolve_autosave_path().path
}

/// Resolve the default autosave path and report whether a legacy path was used.
pub fn resolve_autosave_path() -> AutosavePath {
    resolve_autosave_path_with(
        std::env::var_os(XDG_CONFIG_HOME_ENV),
        std::env::var_os(HOME_ENV),
    )
}

/// Testable form of [`resolve_autosave_path`].
pub fn resolve_autosave_path_with(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> AutosavePath {
    let caddy = config_dir_with(xdg_config_home.clone(), home.clone()).join(AUTOSAVE_FILE_NAME);
    if caddy.exists() {
        return AutosavePath {
            path: caddy,
            legacy: false,
        };
    }
    let legacy = legacy_config_dir_with(xdg_config_home, home).join(AUTOSAVE_FILE_NAME);
    if legacy.exists() {
        AutosavePath {
            path: legacy,
            legacy: true,
        }
    } else {
        AutosavePath {
            path: caddy,
            legacy: false,
        }
    }
}

/// Legacy caddy-rs config directory (`caddy-rs` under the XDG/HOME base, or `.caddy-rs`).
pub fn legacy_config_dir() -> PathBuf {
    legacy_config_dir_with(
        std::env::var_os(XDG_CONFIG_HOME_ENV),
        std::env::var_os(HOME_ENV),
    )
}

/// Testable form of [`legacy_config_dir`].
pub fn legacy_config_dir_with(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> PathBuf {
    if let Some(base) = xdg_config_home.filter(|value| !value.is_empty()) {
        PathBuf::from(base).join(LEGACY_CONFIG_DIR_SUBDIR)
    } else if let Some(home) = home.filter(|value| !value.is_empty()) {
        PathBuf::from(home)
            .join(".config")
            .join(LEGACY_CONFIG_DIR_SUBDIR)
    } else {
        PathBuf::from(LEGACY_FALLBACK_CONFIG_DIR)
    }
}

/// Atomically persist `config_json` to `path`.
///
/// The parent directory chain is created with mode `0700` (only missing directories are created,
/// matching `MkdirAll(dir, 0o700)`), the bytes are written to a unique temporary file in the same
/// directory with mode `0600`, the temporary file is `fsync`ed, and it is `rename`d over `path`,
/// so the target either keeps its previous content or contains the complete new document — never a
/// partial write. Errors leave any previously-autosaved file intact.
pub fn autosave(config_json: &[u8], path: &Path) -> io::Result<()> {
    let directory = parent_directory(path);

    create_dir_private(&directory)?;
    check_private_directory(&directory)?;

    let temp_path = temporary_path(path);
    let result = write_temp(&temp_path, config_json)
        .and_then(|()| std::fs::rename(&temp_path, path))
        .and_then(|()| sync_directory(&directory));
    if result.is_err() {
        // Best effort: never leave a half-written temp file behind.
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

/// Read the autosave file at `path`.
///
/// Returns `Ok(None)` when the file does not exist (the `--resume` fall-through case) and
/// `Ok(Some(bytes))` when it does. Any other I/O failure is returned as `Err`, which callers treat
/// as fatal, exactly like Caddy's run command.
///
/// Security: the final path component must be a regular file, not a symlink, and must not be
/// group/world-writable; the open uses `O_NOFOLLOW` so a symlink swapped in after the check is
/// still refused. The read is capped at [`MAX_AUTOSAVE_BYTES`].
pub fn load_autosave(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "autosave path is a symbolic link; refusing to follow it",
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "autosave path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "autosave file is group/world-writable; refusing to load it",
            ));
        }
    }
    if metadata.len() > MAX_AUTOSAVE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("autosave file is larger than {MAX_AUTOSAVE_BYTES} bytes"),
        ));
    }
    check_owner(&metadata, "autosave file")?;
    // A file in a group/world-writable directory can be replaced by another local user between
    // runs even when the file itself is 0600, so refuse to load from such a directory.
    check_private_directory(&parent_directory(path))?;

    let file = open_nofollow(path)?;
    // Re-check the opened descriptor: the path could have been replaced between the metadata
    // check and the open (the O_NOFOLLOW flag only covers symlinks, not a regular-file swap).
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "autosave path is not a regular file",
        ));
    }
    if opened.len() > MAX_AUTOSAVE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("autosave file is larger than {MAX_AUTOSAVE_BYTES} bytes"),
        ));
    }

    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_AUTOSAVE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_AUTOSAVE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("autosave file is larger than {MAX_AUTOSAVE_BYTES} bytes"),
        ));
    }
    Ok(Some(bytes))
}

/// Open `path` read-only with `O_NOFOLLOW` (where available) and `O_CLOEXEC`.
fn open_nofollow(path: &Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(OPEN_NOFOLLOW_CLOEXEC);
    }
    options.open(path)
}

/// The directory holding `path`, with `..` elements resolved against the current directory so
/// relative autosave paths (for example `./.caddy-rs/autosave.json`) are handled correctly.
fn parent_directory(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Create a directory chain with mode `0700`; directories that already exist are left untouched
/// (`MkdirAll` semantics — an existing config dir keeps its mode). Std-only implementation of
/// `os.MkdirAll(dir, 0o700)`.
fn create_dir_private(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.recursive(true).create(directory)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(directory)
    }
}

/// Refuse to write secrets into a directory that another local user can replace entries in.
///
/// `create_dir_all` follows an existing symlink; checking the leaf after creation closes that
/// hole. An existing directory is accepted when it is a real directory and not group/world-
/// writable (a common `0755` personal config directory is fine).
fn check_private_directory(directory: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "autosave directory is a symbolic link; refusing to write through it",
        ));
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "autosave parent is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "autosave directory is group/world-writable; refusing to write secrets into it",
            ));
        }
    }
    check_owner(&metadata, "autosave directory")?;
    Ok(())
}

/// `fsync` the directory entry after `rename` so the replacement survives a crash.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

/// Require the autosave artifact to be owned by the current process.
///
/// On Linux `/proc/self` is owned by the process's UID, which gives the effective-UID check
/// without a libc dependency. On platforms without that probe the ownership check is skipped
/// rather than guessed; the symlink/regular-file/mode checks still apply.
#[cfg(target_os = "linux")]
fn check_owner(metadata: &std::fs::Metadata, what: &str) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if let Ok(process) = std::fs::metadata("/proc/self") {
        if metadata.uid() != process.uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{what} is owned by another user; refusing to use it"),
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn check_owner(_metadata: &std::fs::Metadata, _what: &str) -> io::Result<()> {
    Ok(())
}

/// A unique temporary-file path in the same directory as `path`, named after it but clearly
/// temporary (`<name>.tmp.<pid>.<counter>`). `create_new` in [`write_temp`] guarantees no other
/// writer can collide with it.
fn temporary_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("autosave"));
    name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    parent_directory(path).join(name)
}

/// Write `bytes` to a fresh file at `temp_path` with mode `0600` and `fsync` it.
fn write_temp(temp_path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(OPEN_NOFOLLOW_CLOEXEC);
    }
    let mut file = options.open(temp_path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "autosave temporary path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode(0o600)` at open is still subject to the process umask; pin the mode explicitly so
        // the autosave is always 0600 regardless of the caller's umask.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Std-only temporary directory for tests (the core crate deliberately has no dev-dependencies).
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "caddy-rs-autosave-test-{name}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("create test dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn config_dir_follows_xdg_then_home_then_fallback() {
        assert_eq!(
            config_dir_with(Some("/xdg".into()), Some("/home/user".into())),
            PathBuf::from("/xdg/caddy")
        );
        assert_eq!(
            config_dir_with(None, Some("/home/user".into())),
            PathBuf::from("/home/user/.config/caddy")
        );
        assert_eq!(config_dir_with(None, None), PathBuf::from("caddy"));
        // An empty XDG_CONFIG_HOME means "unset", matching Caddy's `!= ""` check.
        assert_eq!(
            config_dir_with(Some("".into()), Some("/home/user".into())),
            PathBuf::from("/home/user/.config/caddy")
        );
    }

    #[test]
    fn default_autosave_path_is_autosave_json_under_the_config_dir() {
        assert_eq!(
            config_dir_with(Some("/xdg".into()), None).join(AUTOSAVE_FILE_NAME),
            PathBuf::from("/xdg/caddy/autosave.json")
        );
        let resolved = resolve_autosave_path_with(Some("/xdg".into()), None);
        assert_eq!(resolved.path, PathBuf::from("/xdg/caddy/autosave.json"));
        assert!(!resolved.legacy);
    }

    #[test]
    fn legacy_autosave_is_used_only_when_the_caddy_path_is_absent() {
        let base = TestDir::new("autosave-legacy");
        let legacy_dir = base.path().join("caddy-rs");
        std::fs::create_dir_all(&legacy_dir).unwrap();
        let legacy = legacy_dir.join(AUTOSAVE_FILE_NAME);
        std::fs::write(&legacy, b"{}").unwrap();
        let resolved =
            resolve_autosave_path_with(Some(base.path().as_os_str().to_os_string()), None);
        assert_eq!(resolved.path, legacy);
        assert!(resolved.legacy);

        let caddy_dir = base.path().join("caddy");
        std::fs::create_dir_all(&caddy_dir).unwrap();
        let caddy = caddy_dir.join(AUTOSAVE_FILE_NAME);
        std::fs::write(&caddy, b"{}").unwrap();
        let resolved =
            resolve_autosave_path_with(Some(base.path().as_os_str().to_os_string()), None);
        assert_eq!(resolved.path, caddy);
        assert!(!resolved.legacy);
    }

    #[cfg(unix)]
    #[test]
    fn autosave_writes_exact_bytes_with_0600_mode_and_cleans_up_temps() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("write");
        let target = dir.path().join("nested/deeper/autosave.json");
        autosave(b"{\"config\":true}", &target).expect("autosave succeeds");

        let contents = std::fs::read(&target).expect("file exists");
        assert_eq!(contents, b"{\"config\":true}");

        let mode = std::fs::metadata(&target)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "autosave file must be 0600");

        // The created directory chain uses 0700 like Caddy's MkdirAll(dir, 0700).
        let leaf_mode = std::fs::metadata(dir.path().join("nested/deeper"))
            .expect("leaf metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(leaf_mode, 0o700, "created config dir must be 0700");

        // No temporary files are left behind after a successful write.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn autosave_replaces_an_existing_file_and_keeps_reading_atomic() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use std::sync::Arc;
        use std::thread;

        let dir = TestDir::new("atomic");
        let target = dir.path().join("autosave.json");
        autosave(b"{\"generation\":0}", &target).expect("initial autosave");

        // A previously-autosaved file is replaced atomically: concurrent readers must always
        // observe either the old or the new complete document, never a mix or a truncation.
        let payloads: Vec<Vec<u8>> = (0..64)
            .map(|index| {
                format!(
                    "{{ \"generation\": {index}, \"padding\": \"{}\" }}",
                    "x".repeat(4096)
                )
                .into_bytes()
            })
            .collect();
        let keep_reading = Arc::new(AtomicBool::new(true));
        // Barrier: each reader signals after its first loop iteration starts, and the writer
        // waits for all readers before writing. Without it a reader thread can be scheduled so
        // late that `keep_reading` already flipped false and it never observes a document.
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut readers = Vec::new();
        for _ in 0..4 {
            let target = target.clone();
            let keep_reading = Arc::clone(&keep_reading);
            let started = Arc::clone(&started);
            readers.push(thread::spawn(move || {
                let mut seen = std::collections::BTreeSet::new();
                // Announce this reader exactly once, from inside its first loop iteration: the
                // writer waits for one announcement per reader, so a single reader spinning many
                // iterations can never satisfy the barrier on behalf of a reader that has not
                // started yet.
                let mut announced = false;
                while keep_reading.load(AtomicOrdering::Relaxed) {
                    if !announced {
                        started.fetch_add(1, AtomicOrdering::SeqCst);
                        announced = true;
                    }
                    match std::fs::read(&target) {
                        Ok(bytes) => {
                            let parsed: Result<serde_json::Value, _> =
                                serde_json::from_slice(&bytes);
                            assert!(
                                parsed.is_ok(),
                                "reader observed a partially-written autosave ({} bytes)",
                                bytes.len()
                            );
                            let generation =
                                parsed.unwrap()["generation"].as_u64().expect("generation");
                            seen.insert(generation);
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            // Only possible before the first rename lands; acceptable.
                        }
                        Err(error) => panic!("read failed: {error}"),
                    }
                }
                assert!(!seen.is_empty());
            }));
        }
        // Wait until every reader has announced itself so the writes below race with active
        // reads.
        while started.load(std::sync::atomic::Ordering::SeqCst) < readers.len() {
            std::thread::yield_now();
        }

        let mut writer_round = 0u64;
        for payload in &payloads {
            autosave(payload, &target).expect("autosave round");
            writer_round += 1;
        }
        keep_reading.store(false, AtomicOrdering::Relaxed);
        for reader in readers {
            reader.join().expect("reader joins");
        }
        assert_eq!(writer_round, payloads.len() as u64);

        let final_bytes = std::fs::read(&target).expect("final read");
        assert_eq!(final_bytes, *payloads.last().expect("last payload"));
    }

    #[test]
    fn load_autosave_distinguishes_missing_from_present_and_errors() {
        let dir = TestDir::new("load");
        let missing = dir.path().join("does-not-exist.json");
        assert_eq!(load_autosave(&missing).expect("no error"), None);

        let present = dir.path().join("present.json");
        std::fs::write(&present, b"payload").expect("write");
        assert_eq!(
            load_autosave(&present).expect("no error"),
            Some(b"payload".to_vec())
        );

        // Reading a directory is not "not found" and must surface as an error (fatal for --resume).
        let is_dir = dir.path();
        let error = load_autosave(is_dir).expect_err("directory read must fail");
        assert_ne!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn autosave_failure_is_clean_and_leaves_no_partial_state() {
        let dir = TestDir::new("failure");
        // A path whose parent is a regular file cannot be created: the write must fail and never
        // leave a partial target or a stray temporary file behind.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").expect("write blocker");
        let target = blocker.join("autosave.json");

        let error = autosave(b"new", &target).expect_err("must fail");
        assert!(
            error.kind() == io::ErrorKind::AlreadyExists
                || error.kind() == io::ErrorKind::NotADirectory,
            "unexpected error kind: {error:?}"
        );
        assert!(!target.exists(), "target must not exist after failed write");
        let stray: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(stray.is_empty(), "temp files left behind: {stray:?}");
    }

    #[cfg(unix)]
    #[test]
    fn load_autosave_refuses_symlinks() {
        let dir = TestDir::new("symlink");
        let target = dir.path().join("target.json");
        std::fs::write(&target, b"{}").expect("write target");
        let link = dir.path().join("autosave.json");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let error = load_autosave(&link).expect_err("symlink must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(error.to_string().contains("symbolic link"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn load_autosave_refuses_group_or_world_writable_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("writable");
        let path = dir.path().join("autosave.json");
        std::fs::write(&path, b"{}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");

        let error = load_autosave(&path).expect_err("writable file must be refused");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    }

    #[test]
    fn load_autosave_refuses_oversized_files() {
        let dir = TestDir::new("oversized");
        let path = dir.path().join("autosave.json");
        let file = std::fs::File::create(&path).expect("create");
        file.set_len(MAX_AUTOSAVE_BYTES + 1).expect("set_len");

        let error = load_autosave(&path).expect_err("oversized file must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(error.to_string().contains("larger than"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn autosave_refuses_group_or_world_writable_directories() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("insecure-dir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))
            .expect("chmod");

        let error = autosave(b"{}", &dir.path().join("autosave.json"))
            .expect_err("insecure directory must be refused");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(
            !dir.path().join("autosave.json").exists(),
            "no autosave may be written into an insecure directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn autosave_refuses_a_symlinked_directory() {
        let dir = TestDir::new("symlink-dir");
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("create real");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let error = autosave(b"{}", &link.join("autosave.json"))
            .expect_err("symlinked directory must be refused");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn load_autosave_refuses_a_file_owned_by_another_user() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("foreign-owner");
        let path = dir.path().join("autosave.json");
        std::fs::write(&path, b"{}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        // The ownership boundary only exists when running as root; unprivileged CI skips it.
        if std::os::unix::fs::chown(&path, Some(65534), Some(65534)).is_err() {
            return;
        }

        let error = load_autosave(&path).expect_err("foreign-owned file must be refused");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    }
}
