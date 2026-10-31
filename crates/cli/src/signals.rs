//! Minimal SIGINT/SIGTERM handling.
//!
//! Tokio's `signal` feature needs a crate that is unavailable in this sandbox's read-only cargo
//! cache, so the CLI installs a C signal handler and polls an atomic flag. The handler only stores
//! to an atomic — the only async-signal-safe operation used — and the runtime task turns it into a
//! graceful shutdown.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Install handlers and return a channel that becomes `true` on SIGINT/SIGTERM.
pub fn shutdown_channel() -> anyhow::Result<watch::Receiver<bool>> {
    // SAFETY: the handler only performs an atomic store, which is async-signal-safe. The signal
    // numbers and `sighandler_t` ABI are the standard Linux/POSIX ones provided by `libc`.
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        );
    }

    let (sender, receiver) = watch::channel(false);
    let sender = Arc::new(sender);
    tokio::spawn(async move {
        loop {
            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                let _ = sender.send(true);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    Ok(receiver)
}
