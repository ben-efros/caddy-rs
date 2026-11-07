//! Configuration autosave and resume, mirroring Caddy's autosave behavior.
//!
//! Caddy persists the last *successfully loaded* configuration to an `autosave.json` file after
//! every config transition (CLI `run` and admin-driven loads alike) unless `admin.config.persist`
//! is `false` ([`caddy.go`](https://github.com/caddyserver/caddy/blob/v2.11.9/caddy.go) ~line 377,
//! `unsyncedDecodeAndRun`). The `--resume` startup flag then loads that file in preference to
//! `--config` (`cmd/commandfuncs.go`, run command).
//!
//! The autosave path is configurable, matching Caddy's `AppConfigDir()` resolution
//! (`storage.go`): a per-call override (the CLI's `--autosave-path` flag) wins, then
//! `$XDG_CONFIG_HOME/caddy-rs/autosave.json`, then `$HOME/.config/caddy-rs/autosave.json`, then
//! `./.caddy-rs/autosave.json` (the same `.caddy-rs` default name the data directory uses) when
//! neither environment variable is set.
//!
//! Unlike Caddy (which writes the file in place with `os.WriteFile`), the write here is atomic:
//! the JSON is written to a uniquely-named temporary file in the same directory, `fsync`ed, and
//! `rename`d over the target, so a crash or concurrent observer never sees a partially-written
//! autosave. The file mode is `0600` and the parent directory chain is created with `0700`, as in
//! Caddy (`MkdirAll(dir, 0o700)` + `WriteFile(path, cfgJSON, 0o600)`).
//!
//! This module is `std`-only.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The autosave file name, matching Caddy's `autosave.json` under the config directory.
pub const AUTOSAVE_FILE_NAME: &str = "autosave.json";

/// The subdirectory appended to the XDG/HOME config base, mirroring Caddy's `caddy` subdir but
/// using this project's name (`caddy-rs`), consistent with the `.caddy-rs` data-directory default.
pub const CONFIG_DIR_SUBDIR: &str = "caddy-rs";

/// Environment variable consulted first for the config base directory (Unix convention).
pub const XDG_CONFIG_HOME_ENV: &str = "XDG_CONFIG_HOME";

/// Environment variable consulted when `XDG_CONFIG_HOME` is unset.
pub const HOME_ENV: &str = "HOME";

/// Fallback config base when neither `XDG_CONFIG_HOME` nor `HOME` is set; the `.caddy-rs` file
/// appears in the working directory, like Caddy's `./caddy` fallback (`AppConfigDir`).
pub const FALLBACK_CONFIG_DIR: &str = ".caddy-rs";

/// The application config directory: `$XDG_CONFIG_HOME/caddy-rs` when `XDG_CONFIG_HOME` is set,
/// `$HOME/.config/caddy-rs` otherwise, and `./.caddy-rs` when `HOME` is also unavailable. This is
/// the caddy-rs analogue of Caddy's `AppConfigDir()`.
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

/// The default autosave path: [`AUTOSAVE_FILE_NAME`] under [`config_dir`].
pub fn default_autosave_path() -> PathBuf {
    config_dir().join(AUTOSAVE_FILE_NAME)
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

    let temp_path = temporary_path(path);
    let result =
        write_temp(&temp_path, config_json).and_then(|()| std::fs::rename(&temp_path, path));
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
pub fn load_autosave(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
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
    }
    let mut file = options.open(temp_path)?;
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
            PathBuf::from("/xdg/caddy-rs")
        );
        assert_eq!(
            config_dir_with(None, Some("/home/user".into())),
            PathBuf::from("/home/user/.config/caddy-rs")
        );
        assert_eq!(config_dir_with(None, None), PathBuf::from(".caddy-rs"));
        // An empty XDG_CONFIG_HOME means "unset", matching Caddy's `!= ""` check.
        assert_eq!(
            config_dir_with(Some("".into()), Some("/home/user".into())),
            PathBuf::from("/home/user/.config/caddy-rs")
        );
    }

    #[test]
    fn default_autosave_path_is_autosave_json_under_the_config_dir() {
        assert_eq!(
            config_dir_with(Some("/xdg".into()), None).join(AUTOSAVE_FILE_NAME),
            PathBuf::from("/xdg/caddy-rs/autosave.json")
        );
        assert_eq!(
            default_autosave_path(),
            config_dir().join(AUTOSAVE_FILE_NAME)
        );
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
}
