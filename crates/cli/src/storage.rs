//! `caddy storage export` and `caddy storage import` parity.
//!
//! Upstream (`cmd/storagefuncs.go`, pinned Caddy v2.11.9) exports the terminal keys of the
//! configured `caddy.storage` module as a tar archive and imports a tar archive back into it with
//! `Store`. This build implements the `file_system` storage module — the only backend it has — and
//! there a storage key *is* the slash-separated path of a file below the storage root: `storage.root`
//! from `--config` when set, else Caddy's data directory. Certmagic's file storage has no directory
//! keys, so directories are archived implicitly (their files are) and created implicitly on import.
//!
//! Ordering and error mapping follow upstream: keys are listed before the output file is opened (a
//! listing failure must not truncate an existing archive), a key that disappears mid-export is a
//! warning, and every failure after startup is `ExitCodeFailedQuit` (3) like Caddy's.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{bail, Context};
use caddy_rs_config::AdaptOptions;
use caddy_rs_core::Config;

use crate::CliExit;

/// Caddy's `ExitCodeFailedQuit`: the command started, then failed while operating.
const FAILED_QUIT: u8 = 3;

/// One terminal storage key: certmagic's key and the file that holds its value.
struct StoredKey {
    /// Slash-separated path relative to the storage root.
    key: String,
    /// Filesystem path to read the value from.
    path: PathBuf,
}

/// `caddy storage export --config <path> --output <path>`.
pub(crate) fn export(config: Option<&Path>, output: Option<&Path>) -> anyhow::Result<()> {
    let Some(config) = config else {
        bail!("--config is required")
    };
    let Some(output) = output else {
        bail!("--output is required")
    };

    let root = storage_root(config)?;
    let keys = list_keys(&root)?;

    // Caddy lists the keys before it opens the output file, so a listing failure cannot truncate an
    // existing archive; `-` writes the archive to standard output.
    let sink: Box<dyn Write> = if output == Path::new("-") {
        Box::new(io::stdout())
    } else {
        Box::new(
            File::create(output)
                .with_context(|| format!("opening output file `{}`", output.display()))?,
        )
    };
    let mut builder = tar::Builder::new(sink);
    for key in keys {
        let value = match fs::read(&key.path) {
            Ok(value) => value,
            // Caddy warns and continues when a key is removed while the export is in progress.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!(
                    "warning: key: {} removed while export is in-progress",
                    key.key
                );
                continue;
            }
            Err(error) => {
                return Err(failed_quit(format!(
                    "writing archive: cannot read `{}`: {error}",
                    key.path.display()
                )))
            }
        };
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(value.len() as u64);
        // Caddy archives every asset as owner-read/write, whatever the file mode is.
        header.set_mode(0o600);
        header.set_mtime(modified_seconds(&key.path));
        if let Err(error) = builder.append_data(&mut header, &key.key, value.as_slice()) {
            return Err(failed_quit(format!("writing archive: {error}")));
        }
    }
    if let Err(error) = builder.finish() {
        return Err(failed_quit(format!("writing archive: {error}")));
    }
    let mut sink = match builder.into_inner() {
        Ok(sink) => sink,
        Err(error) => return Err(failed_quit(format!("writing archive: {error}"))),
    };
    if let Err(error) = sink.flush() {
        return Err(failed_quit(format!("writing archive: {error}")));
    }
    Ok(())
}

/// `caddy storage import --config <path> --input <path>`.
pub(crate) fn import(config: Option<&Path>, input: Option<&Path>) -> anyhow::Result<()> {
    let Some(config) = config else {
        bail!("--config is required")
    };
    let Some(input) = input else {
        bail!("--input is required")
    };

    let root = storage_root(config)?;

    // `-` reads the archive from standard input.
    let source: Box<dyn Read> = if input == Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(
            File::open(input)
                .with_context(|| format!("opening input file `{}`", input.display()))?,
        )
    };

    let mut archive = tar::Archive::new(source);
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(error) => return Err(failed_quit(format!("reading archive: {error}"))),
    };
    for entry in entries {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(error) => return Err(failed_quit(format!("reading archive: {error}"))),
        };
        let path = match entry.path() {
            Ok(path) => path.into_owned(),
            Err(error) => return Err(failed_quit(format!("reading archive: {error}"))),
        };
        let key = stored_key(&path)?;
        let mut value = Vec::new();
        if let Err(error) = entry.read_to_end(&mut value) {
            return Err(failed_quit(format!("reading archive: {error}")));
        }
        if let Err(error) = store_key(&root, &key, &value) {
            // Caddy reports a failed `Store` as `reading archive: ...`; keep that message, but name
            // the key it was storing so the failure is locatable.
            return Err(failed_quit(format!(
                "reading archive: cannot store key `{key}`: {error}"
            )));
        }
    }
    println!("Successfully imported storage");
    Ok(())
}

/// Resolve the storage root the server would use for the configuration in `config`.
///
/// The configuration is adapted (Caddyfile or JSON, inferred like `caddy-rs adapt`), decoded, and
/// its `storage` object inspected. Only `file_system` is implemented, so any other module is a
/// located error rather than a silent fallback to the default storage. Like Caddy's
/// `determineStorage`, the configuration is *not* fully provisioned here: `storage` commands must
/// work against a configuration whose HTTP/TLS apps the operator is not asking about.
fn storage_root(config: &Path) -> anyhow::Result<PathBuf> {
    let (document, warnings) = crate::adapt(
        config,
        Some(config_adapter(config)),
        AdaptOptions::default(),
    )?;
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    let model = Config::from_slice(&document).with_context(|| {
        format!(
            "config `{}` does not match the configuration model",
            config.display()
        )
    })?;

    let mut configured_root = None;
    if let Some(storage) = model.storage() {
        match storage.module_name() {
            None | Some("file_system" | "caddy.storage.file_system") => {}
            Some(module) => bail!(
                "unsupported storage module `{module}`; this build implements only `file_system`"
            ),
        }
        configured_root = storage.root().map(PathBuf::from);
    }

    // A configured `storage.root` wins; otherwise Caddy's default storage is `file_system` rooted at
    // the data directory, resolved exactly as the server resolves it.
    let resolved = caddy_rs_core::data_dir::resolve_server_data_dir(None, configured_root);
    for warning in &resolved.warnings {
        eprintln!("caddy-rs: warning: {warning}");
    }
    Ok(resolved.path)
}

/// The config adapter Caddy's `LoadConfig` would pick for `config` when no adapter is given.
///
/// This is `cmd/main.go::isCaddyfile`: a `.json` extension always means JSON; otherwise a base name
/// that starts with `caddyfile` (case-insensitive) or ends with `.caddyfile` means the Caddyfile
/// adapter, and anything else is JSON. The `storage` commands expose no `--adapter` flag, matching
/// Caddy, so this inference is the only way the format is chosen.
fn config_adapter(config: &Path) -> &'static str {
    let name = config
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_lowercase();
    let extension = Path::new(&name)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    if extension == "json" {
        return "json";
    }
    if name.starts_with("caddyfile") || name.ends_with(".caddyfile") {
        return "caddyfile";
    }
    "json"
}

/// Every regular file below `root`, as a sorted list of terminal storage keys.
fn list_keys(root: &Path) -> anyhow::Result<Vec<StoredKey>> {
    let mut keys = Vec::new();
    walk(root, root, &mut keys)
        .with_context(|| format!("cannot list storage `{}`", root.display()))?;
    // Certmagic's `List` walks the directory tree in lexical order.
    keys.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(keys)
}

fn walk(root: &Path, directory: &Path, keys: &mut Vec<StoredKey>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        // `file_type` does not follow symlinks, matching `filepath.Walk`: a symlinked directory is
        // a terminal key, not a subtree.
        if entry.file_type()?.is_dir() {
            walk(root, &path, keys)?;
        } else {
            keys.push(StoredKey {
                key: storage_key(root, &path)?,
                path,
            });
        }
    }
    Ok(())
}

/// The slash-separated storage key for `path`, which must be below `root`.
fn storage_key(root: &Path, path: &Path) -> io::Result<String> {
    let relative = path.strip_prefix(root).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("`{}` is outside the storage root: {error}", path.display()),
        )
    })?;
    let key = relative.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("storage key `{}` is not valid UTF-8", relative.display()),
        )
    })?;
    Ok(key.replace(std::path::MAIN_SEPARATOR, "/"))
}

/// Validate and normalize an archive entry name into a storage key.
///
/// Upstream passes the entry name straight to `Store`; a name containing `..` or starting at the
/// filesystem root would therefore be written outside the storage root. This build refuses those
/// names instead of writing outside the configured storage (see `docs/compatibility/T-CLI-010.md`).
fn stored_key(path: &Path) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            // `./key` names the same file as `key`; Go's `filepath.Join` would clean it away.
            Component::CurDir => {}
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(|| {
                    failed_quit(format!(
                        "reading archive: key `{}` is not valid UTF-8",
                        path.display()
                    ))
                })?;
                parts.push(part);
            }
            _ => {
                return Err(failed_quit(format!(
                    "reading archive: refusing key `{}`: it is not a relative path below the \
                     storage root",
                    path.display()
                )))
            }
        }
    }
    if parts.is_empty() {
        return Err(failed_quit(format!(
            "reading archive: refusing key `{}`: it names no file",
            path.display()
        )));
    }
    Ok(parts.join("/"))
}

/// Write one archive element below `root`, like certmagic's file storage `Store`.
fn store_key(root: &Path, key: &str, value: &[u8]) -> io::Result<()> {
    let target = root.join(key);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&target)?;
    file.write_all(value)?;
    drop(file);
    // certmagic replaces the target through a 0600 temporary file, so an existing key always ends up
    // owner-read/write whatever its previous mode was.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// The file's modification time in whole seconds since the Unix epoch, or 0 when unavailable.
fn modified_seconds(path: &Path) -> u64 {
    fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// An error that exits with Caddy's `ExitCodeFailedQuit`.
fn failed_quit(message: String) -> anyhow::Error {
    CliExit {
        code: FAILED_QUIT,
        message,
    }
    .into()
}
