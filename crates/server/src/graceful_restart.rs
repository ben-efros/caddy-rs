//! Graceful process restart (binary upgrade), behind the default-off `graceful-restart` feature.
//!
//! This module wires `ecdysis` into the server so a running process can replace its binary while
//! keeping its listening sockets. The design and its constraints are decided in
//! `docs/adr/0044-process-graceful-restart.md`; this file implements the parts of §1, §2 and §5
//! that can be expressed without binding listeners into the runtime (that is `T-CORE-102`).
//!
//! # Why this is feature-gated
//!
//! ADR-0044 OQ-2 accepted `ecdysis` as an optional dependency so that a default build's dependency
//! set, binary and reproducible-build result are unchanged. Nothing in this module is reachable
//! unless the `graceful-restart` feature is enabled, and when it is disabled `ecdysis` is not
//! compiled at all.
//!
//! # Unix-only
//!
//! Fork/exec and file-descriptor inheritance do not exist on Windows. Per ADR-0044 §5 the refusal
//! must be **loud**: on a non-Unix target enabling the feature is a compile error with a named
//! message, never a silent fallback to stop-then-start. That is enforced below rather than at
//! runtime, so an operator cannot ship a build that quietly stops accepting connections.
//!
//! # What this module deliberately does NOT claim
//!
//! ADR-0044 §2 states that a gap-free upgrade is a *design constraint, not a demonstrated result*.
//! `T-CORE-104` is the task that measures it under live load. Nothing here may be read as evidence
//! of zero dropped or zero refused connections.

#![cfg(feature = "graceful-restart")]

#[cfg(not(unix))]
compile_error!(
    "the `graceful-restart` feature requires a Unix target: graceful binary upgrade passes socket \
     file descriptors across fork/exec, which is unavailable on this platform. ADR-0044 section 5 \
     requires this to fail loudly rather than silently fall back to stopping the process. Build \
     without `--features graceful-restart` to get the existing stop-then-start behaviour."
);

use std::fmt;
use std::io;

/// Errors raised while configuring or performing a graceful restart.
///
/// Every variant names the operation and its cause, matching the crate's located-error convention
/// so the CLI's `{error:#}` chain prints the reason once.
#[derive(Debug)]
pub enum GracefulRestartError {
    /// The single-upgrade invariant (ADR-0044 §2.6) refused a second concurrent upgrade.
    ///
    /// A second request is refused rather than queued: queueing would turn repeated requests into
    /// a fork storm, which §5 calls out as a denial-of-service primitive.
    UpgradeInFlight,

    /// The child binary failed to reach `ready()`.
    ///
    /// The parent must keep serving after this error; it is reported so the upgrade attempt is
    /// loud rather than silently abandoned (ADR-0044 §2.4).
    ChildNotReady {
        /// The error the child reported, or the reason the parent stopped waiting.
        cause: String,
    },

    /// The platform refused the underlying socket or process operation.
    Io(io::Error),
}

impl fmt::Display for GracefulRestartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpgradeInFlight => write!(
                f,
                "graceful restart refused: an upgrade is already in flight (only one upgrade may \
                 run at a time)"
            ),
            Self::ChildNotReady { cause } => write!(
                f,
                "graceful restart failed: the new process did not become ready ({cause}); the \
                 current process is still serving"
            ),
            Self::Io(e) => write!(f, "graceful restart I/O error: {e}"),
        }
    }
}

impl std::error::Error for GracefulRestartError {}

impl From<io::Error> for GracefulRestartError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The restart trigger decided in ADR-0044 OQ-1.
///
/// `SIGUSR2` is the primary documented trigger because upstream Caddy reserves it and never
/// implements it (`external/caddy/sigtrap_posix.go:38-84`), so a Caddy-compatible deployment that
/// sends it today gets nothing and gets a graceful restart here. `SIGUSR1` is Caddy's reload and
/// `SIGHUP` is deliberately ignored upstream, so neither is overloaded. The admin API is an
/// additional trigger authorized exactly like `POST /load`.
///
/// This type exists so the choice is expressed once and cannot drift between the CLI and the
/// server; the signal is installed by `T-CORE-102`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartTrigger {
    /// `SIGUSR2` — the primary, documented trigger.
    SignalUsr2,
    /// The admin API, authorized identically to `POST /load`.
    AdminApi,
}

impl fmt::Display for RestartTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignalUsr2 => f.write_str("SIGUSR2"),
            Self::AdminApi => f.write_str("admin API"),
        }
    }
}

/// Whether a graceful restart is compiled into this build.
///
/// Always `true` when this module is reachable (the module is feature-gated), but exposed so the
/// CLI can report the capability rather than infer it from a `cfg!`.
pub const fn is_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_feature_reports_itself_enabled() {
        assert!(is_enabled());
    }

    #[test]
    fn the_in_flight_refusal_is_located_and_names_the_invariant() {
        let msg = GracefulRestartError::UpgradeInFlight.to_string();
        assert!(msg.contains("already in flight"), "got: {msg}");
        assert!(msg.contains("only one upgrade"), "got: {msg}");
    }

    #[test]
    fn a_child_that_never_becomes_ready_says_the_old_process_still_serves() {
        // ADR-0044 section 2.4: a failed upgrade must leave the old generation serving and must
        // say so loudly. The message has to carry both facts, not just the error.
        let e = GracefulRestartError::ChildNotReady {
            cause: "invalid configuration".to_string(),
        };
        let msg = e.to_string();
        assert!(msg.contains("invalid configuration"), "got: {msg}");
        assert!(
            msg.contains("still serving"),
            "a failed upgrade must state the old process is still serving; got: {msg}"
        );
    }

    #[test]
    fn io_errors_keep_their_cause_and_are_convertible() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "fd inheritance refused");
        let e: GracefulRestartError = io_err.into();
        let msg = e.to_string();
        assert!(msg.contains("I/O error"), "got: {msg}");
        assert!(msg.contains("fd inheritance refused"), "got: {msg}");
    }

    #[test]
    fn the_trigger_displays_as_the_documented_signal() {
        // OQ-1: the signal is SIGUSR2, and it must be named exactly that wherever it is reported.
        assert_eq!(RestartTrigger::SignalUsr2.to_string(), "SIGUSR2");
        assert_eq!(RestartTrigger::AdminApi.to_string(), "admin API");
    }
}
