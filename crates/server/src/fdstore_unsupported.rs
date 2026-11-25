//! systemd fd-store uploads on platforms without systemd (Windows).
//!
//! The real implementation (`fdstore.rs`) attaches a descriptor to a datagram sent to systemd's
//! `NOTIFY_SOCKET` as an `SCM_RIGHTS` control message. Neither descriptors nor that socket exist
//! on Windows, so this keeps the public API (the CLI's `bind-fds` helper compiles against it) and
//! reports a clear, located error instead of silently doing nothing.

use std::ffi::OsStr;
use std::io;

/// Why an fd-store operation failed.
#[derive(Debug)]
pub enum FdStoreError {
    /// `NOTIFY_SOCKET` is unset or empty: there is no fd store to upload to.
    NotifySocketUnset,
    /// The notification socket could not be used.
    Socket(io::Error),
}

impl std::fmt::Display for FdStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotifySocketUnset => write!(
                f,
                "there is no systemd fd store on this platform; fdstore mode requires systemd"
            ),
            Self::Socket(error) => write!(f, "cannot upload to the systemd fd store: {error}"),
        }
    }
}

impl std::error::Error for FdStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotifySocketUnset => None,
            Self::Socket(error) => Some(error),
        }
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "systemd fd-store uploads are not supported on this platform",
    )
}

/// Always fails on this platform: there is no fd store.
pub fn send_fd_to_store(_fd: i32, _fd_name: &str) -> Result<(), FdStoreError> {
    Err(FdStoreError::Socket(unsupported()))
}

/// Always fails on this platform: there is no fd store.
pub fn remove_fd_from_store(_fd_name: &str) -> Result<(), FdStoreError> {
    Err(FdStoreError::Socket(unsupported()))
}

/// Always fails on this platform: there is no fd store.
pub fn remove_fd_from_store_at(_socket_name: &OsStr, _fd_name: &str) -> io::Result<()> {
    Err(unsupported())
}

/// Always fails on this platform: there is no fd store.
pub fn send_fd_to_store_at(_socket_name: &OsStr, _fd: i32, _fd_name: &str) -> io::Result<()> {
    Err(unsupported())
}
