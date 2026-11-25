//! Owner-only files and directories, portable across Unix and Windows.
//!
//! caddy-rs keeps secrets on disk: ACME account keys, certificate private keys, the internal CA,
//! the proxy manager's JWT signing key, autosaved configuration. On Unix "owner-only" is mode
//! `0600` for files and `0700` for directories. Windows has no mode bits: a file inherits the
//! DACL of its parent directory, and under `%ProgramData%` or a drive root that DACL grants read
//! access to `BUILTIN\Users`. Calling `chmod` there would silently do nothing, which is how a port
//! ends up with world-readable private keys. This crate gives every call site one API with the
//! same meaning on both platforms:
//!
//! * [`create_dir_all_private`] / [`create_new_file_private`] create with the restrictive
//!   permissions **at creation**, so a secret is never readable between `create` and a later
//!   `chmod`/ACL call (no race window);
//! * [`restrict_file`] / [`restrict_dir`] tighten something that already exists (for example a key
//!   written by an older version);
//! * [`exposure`] reports whether anyone besides the owner (and the platform's administrators) can
//!   read or write a path, which the data-directory preflight and the Caddyfile import rule use to
//!   refuse unsafe locations.
//!
//! # Windows model
//!
//! The DACL grants `FILE_ALL_ACCESS` to exactly three principals — the current token user,
//! `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` — and is *protected*, so nothing is inherited
//! from the parent. Directories carry the grant as inheritable (`OICI`) so files created inside
//! them are private from their first byte. Administrators are included because they can take
//! ownership of any file anyway; excluding them would only break backup and service management.
//!
//! # Unsafe code
//!
//! The Win32 security API is `unsafe`. The crate denies unsafe code everywhere except the
//! `windows` module, whose every block is annotated with its invariant.

#![deny(unsafe_code)]

use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as imp;

/// Who, besides the owner and the platform's administrators, can reach a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Exposure {
    /// Another principal can read the contents (or list the directory).
    pub readable_by_others: bool,
    /// Another principal can modify the contents, replace or delete the path, delete entries from a
    /// directory, or change its permissions.
    pub writable_by_others: bool,
    /// Another principal can create new entries in a directory (add files or subdirectories) but
    /// not replace or delete existing ones. `C:\` and `ProgramData` allow this for every user, as
    /// does a sticky `/tmp`; it is harmless for an ancestor but not for a directory that holds
    /// secrets. Always `false` for a file.
    pub creatable_by_others: bool,
    /// Windows only: the path is owned by a principal other than the current user, SYSTEM or
    /// Administrators. An owner keeps the implicit right to read and rewrite the access list, so
    /// the list alone cannot show that such a path is safe. Always `false` on Unix, where callers
    /// compare the owning uid themselves.
    pub owned_by_others: bool,
}

impl Exposure {
    /// Whether the path is private: nobody else can read it, write it or add entries to it.
    #[must_use]
    pub fn is_private(self) -> bool {
        !self.readable_by_others
            && !self.writable_by_others
            && !self.creatable_by_others
            && !self.owned_by_others
    }

    /// Whether another principal can change what the path contains or means: modify or replace it
    /// or add entries to it. This is the test for a directory that will hold secrets.
    #[must_use]
    pub fn tamperable_by_others(self) -> bool {
        self.writable_by_others || self.creatable_by_others || self.owned_by_others
    }
}

/// Create exactly one owner-only directory (no parents), failing with
/// [`io::ErrorKind::AlreadyExists`] if it exists.
///
/// For callers that create-then-inspect (a racing creator or a symlink at that name must be
/// noticed rather than silently accepted, which `create_dir_all_private` would do).
///
/// # Errors
/// [`io::ErrorKind::AlreadyExists`] when the path exists; otherwise any I/O error.
pub fn create_dir_private(path: &Path) -> io::Result<()> {
    imp::create_dir_private(path)
}

/// Create `path` and any missing parents as owner-only directories.
///
/// Directories that already exist are left untouched (use [`restrict_dir`] to tighten one).
///
/// # Errors
/// Any I/O error from creating a directory.
pub fn create_dir_all_private(path: &Path) -> io::Result<()> {
    imp::create_dir_all_private(path)
}

/// Create a new file that only its owner can access, failing if it already exists.
///
/// The returned handle is open for reading and writing. The restrictive permissions are applied
/// by the create call itself, so the contents are never exposed.
///
/// # Errors
/// [`io::ErrorKind::AlreadyExists`] when the file exists; otherwise any I/O error.
pub fn create_new_file_private(path: &Path) -> io::Result<File> {
    imp::create_new_file_private(path)
}

/// Make an existing file owner-only.
///
/// # Errors
/// Any I/O error from changing the permissions.
pub fn restrict_file(path: &Path) -> io::Result<()> {
    imp::restrict(path, false)
}

/// Make an existing directory (and, on Windows, everything that inherits from it) owner-only.
///
/// # Errors
/// Any I/O error from changing the permissions.
pub fn restrict_dir(path: &Path) -> io::Result<()> {
    imp::restrict(path, true)
}

/// Report who besides the owner can reach `path`.
///
/// Conservative: on Windows any allow entry for a principal other than the current user, SYSTEM,
/// Administrators, TrustedInstaller or the owner placeholders counts, even if that principal is
/// not a person (a service account is reported so the caller can decide).
///
/// # Errors
/// Any I/O error reading the permissions.
pub fn exposure(path: &Path) -> io::Result<Exposure> {
    imp::exposure(path)
}

/// The real, symlink-free path of an *open* file, as the operating system sees it right now.
///
/// This is what makes a "stay inside this directory" rule safe against a race: checking a path and
/// then opening it leaves a window in which a component can be swapped for a symlink, but the path
/// of a file that is *already open* cannot change what was opened. Open first, ask for the final
/// path of the handle, compare that, and read from the same handle.
///
/// Linux reads `/proc/self/fd/N`, macOS asks `F_GETPATH`, Windows calls `GetFinalPathNameByHandleW`
/// (and returns the verbatim `\\?\` form, like `std::fs::canonicalize`). Elsewhere it returns
/// [`io::ErrorKind::Unsupported`], and callers must then fall back to the path-based check.
///
/// # Errors
/// [`io::ErrorKind::Unsupported`] on other platforms, or the OS error.
pub fn final_path(file: &File) -> io::Result<std::path::PathBuf> {
    imp::final_path(file)
}

/// Open a regular file for reading, never blocking and never opening anything else.
///
/// On Unix the open uses `O_NONBLOCK`, so a FIFO or device placed where a file is expected cannot
/// hang the caller waiting for a writer; the opened handle is then required to be a regular file.
/// Everywhere the check is made on the *handle*, not on the path, so it cannot be raced.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] when the handle is not a regular file; otherwise the OS error.
pub fn open_regular_file(path: &Path) -> io::Result<File> {
    imp::open_regular_file(path)
}

/// The real path of an open file, with a fallback where the platform cannot report it.
///
/// Like [`final_path`], but on Unix, when the handle's path is unavailable (no `/proc`, an OS without
/// `F_GETPATH`), it resolves `path` and requires that it names the very file that is open (same
/// device and inode), failing with [`io::ErrorKind::PermissionDenied`] when it does not. On Windows
/// it is `final_path`; a failure there means the caller must rely on its own path check.
///
/// # Errors
/// The OS error, or [`io::ErrorKind::PermissionDenied`] when the open file is not the file `path`
/// resolves to.
pub fn verified_real_path(file: &File, path: &Path) -> io::Result<std::path::PathBuf> {
    imp::verified_real_path(file, path)
}

/// Whether `path` is owned by the user this process runs as.
///
/// On Unix that is the effective uid. On Windows the owner must be the current token user, `SYSTEM`
/// or `BUILTIN\Administrators` (files created by an elevated process are owned by the
/// Administrators group, and a service running as `LocalSystem` creates files owned by `SYSTEM`).
///
/// # Errors
/// Any I/O error reading the owner.
pub fn owned_by_current_user(path: &Path) -> io::Result<bool> {
    imp::owned_by_current_user(path)
}

#[cfg(test)]
mod tests;
