//! Minimal SIGINT/SIGTERM handling.
//!
//! Tokio's `signal` feature needs a crate that is unavailable in this sandbox's read-only cargo
//! cache, so the CLI installs a C signal handler and polls an atomic counter. The handler only
//! increments an atomic — the only async-signal-safe operation used — and a runtime task turns
//! signal counts into graceful/forced shutdown notifications.
//!
//! The first SIGINT/SIGTERM starts a graceful shutdown; a second signal (Caddy's "force quit")
//! skips the configured `/`grace period and closes connections immediately.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

static SIGNAL_COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn handle_signal(_signal: libc::c_int) {
    SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Signal channels consumed by [`caddy_rs_server::ServerRuntime::run_with_force`].
pub struct SignalChannels {
    /// Becomes `true` on the first SIGINT/SIGTERM (graceful shutdown).
    pub shutdown: watch::Receiver<bool>,
    /// Becomes `true` on the second SIGINT/SIGTERM (immediate shutdown, skipping the grace period).
    pub force: watch::Receiver<bool>,
}

/// Install handlers and return shutdown/force channels for SIGINT/SIGTERM.
pub fn shutdown_channels() -> anyhow::Result<SignalChannels> {
    // SAFETY: the handler only performs an atomic increment, which is async-signal-safe. The
    // signal numbers and `sighandler_t` ABI are the standard Linux/POSIX ones provided by
    // `libc`.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_signal as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_RESTART;
        if libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut()) == -1 {
            return Err(anyhow::anyhow!("failed to install SIGINT handler"));
        }
        if libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut()) == -1 {
            return Err(anyhow::anyhow!("failed to install SIGTERM handler"));
        }
    }

    let (shutdown_sender, shutdown) = watch::channel(false);
    let (force_sender, force) = watch::channel(false);
    let shutdown_sender = Arc::new(shutdown_sender);
    let force_sender = Arc::new(force_sender);
    tokio::spawn(async move {
        let mut last_seen = 0usize;
        loop {
            let count = SIGNAL_COUNT.load(Ordering::SeqCst);
            if count > last_seen {
                last_seen = count;
                if count == 1 {
                    let _ = shutdown_sender.send(true);
                } else {
                    let _ = force_sender.send(true);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    Ok(SignalChannels { shutdown, force })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// First SIGTERM asks for graceful shutdown; a second one forces it.
    #[tokio::test]
    async fn first_signal_is_graceful_and_second_signal_forces() {
        let channels = shutdown_channels().expect("install handlers");
        assert!(!*channels.shutdown.borrow());
        assert!(!*channels.force.borrow());

        // SAFETY: the installed handler only performs an atomic increment.
        unsafe { libc::raise(libc::SIGTERM) };
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*channels.shutdown.borrow() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("first signal must request graceful shutdown");
        assert!(!*channels.force.borrow());

        unsafe { libc::raise(libc::SIGTERM) };
        tokio::time::timeout(Duration::from_secs(2), async {
            while !*channels.force.borrow() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second signal must request forced shutdown");
    }
}
