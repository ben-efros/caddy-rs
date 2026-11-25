//! Unix implementation: mode bits.

#![allow(unsafe_code)]

use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::Exposure;

pub(crate) fn create_dir_all_private(path: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)
}

pub(crate) fn create_new_file_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

pub(crate) fn restrict(path: &Path, directory: bool) -> io::Result<()> {
    let mode = if directory { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

pub(crate) fn exposure(path: &Path) -> io::Result<Exposure> {
    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    let others_can_write = mode & 0o022 != 0;
    // A sticky directory (`/tmp`, mode 1777) lets everyone create entries but only an entry's owner
    // delete or rename it: creatable, not replaceable.
    let sticky = metadata.is_dir() && mode & 0o1000 != 0;
    Ok(Exposure {
        readable_by_others: mode & 0o044 != 0,
        writable_by_others: others_can_write && !sticky,
        creatable_by_others: others_can_write && metadata.is_dir(),
    })
}

pub(crate) fn owned_by_current_user(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::metadata(path)?.uid();
    // SAFETY: `geteuid` takes no arguments, cannot fail and touches no memory.
    let effective = unsafe { libc::geteuid() };
    Ok(owner == effective)
}

/// Real path of an open file. See [`crate::final_path`].
pub(crate) fn final_path(file: &File) -> io::Result<std::path::PathBuf> {
    use std::os::unix::io::AsRawFd;
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut buffer = [0u8; libc::PATH_MAX as usize];
        // SAFETY: `F_GETPATH` writes a NUL-terminated path into a buffer of at least `PATH_MAX`
        // bytes, which is exactly what `buffer` is; the descriptor is open for the call.
        let status = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) };
        if status == -1 {
            return Err(io::Error::last_os_error());
        }
        let length = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        Ok(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
            &buffer[..length],
        )))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Create exactly one directory, owner-only, failing if it exists. See [`crate::create_dir_private`].
pub(crate) fn create_dir_private(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(0o700).create(path)
}

/// Open a regular file for reading without ever blocking. See [`crate::open_regular_file`].
pub(crate) fn open_regular_file(path: &Path) -> io::Result<File> {
    // `O_NONBLOCK` makes opening a FIFO (or a device) return immediately instead of waiting for a
    // writer forever; it has no effect on a regular file. The handle is then checked to be one.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// Real path of an open file, with a fallback when the platform cannot report it. See
/// [`crate::verified_real_path`].
pub(crate) fn verified_real_path(file: &File, path: &Path) -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    match final_path(file) {
        Ok(real) => Ok(real),
        // No `/proc` (a minimal chroot, some sandboxes) or an OS without a handle-to-path call:
        // resolve the path now and require that it names the very file that is open (same device
        // and inode). A component swapped before or after the open makes the two differ.
        Err(_) => {
            let real = std::fs::canonicalize(path)?;
            let opened = file.metadata()?;
            let resolved = std::fs::metadata(&real)?;
            if opened.dev() == resolved.dev() && opened.ino() == resolved.ino() {
                Ok(real)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the opened file is not the file its path resolves to",
                ))
            }
        }
    }
}
