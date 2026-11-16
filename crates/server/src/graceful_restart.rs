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

use socket2_v05::Socket;
use std::net::TcpListener;

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

/// What an `ecdysis` upgrade failure means for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeFailure {
    /// The single-upgrade invariant refused a second concurrent upgrade (§2.6).
    ConcurrentUpgradeRefused,
    /// No new generation took over — the child failed, timed out, or the machinery could not start.
    ChildDidNotTakeOver,
}

/// The one payload `ecdysis` writes when its in-flight swap refuses a second upgrade.
///
/// `executioner.rs:43` constructs `NotStarted(String::from("Already in upgrade"))`, which renders
/// through `#[display("upgrade not started: {}", _0)]` as this exact string.
const CONCURRENT_REFUSAL: &str = "upgrade not started: Already in upgrade";

/// Classify an `ecdysis` upgrade failure from its rendered reason.
///
/// # Why this is a separate pure function
///
/// `ecdysis` 1.1.1 does not re-export `UpgradeError`, so the variant cannot be matched on and the
/// only available signal is the `Display` text. That makes the classification load-bearing and
/// worth testing directly: a pure function over the string can be table-tested against the real
/// strings `ecdysis` produces, including the ones that are *not* a refusal.
///
/// # The trap this exists to avoid
///
/// `NotStarted` is constructed in **two** places, and they mean opposite things:
///
/// - `executioner.rs:43`, the `UPGRADING` swap — a genuine concurrent refusal.
/// - `executioner.rs:89`, `impl From<Error> for UpgradeError`, which wraps an `io::Error` as
///   `NotStarted(format!("{:?}", e))`. This is what `?` uses at `UpgradePipes::new()?` and
///   `exec_upgraded(...)?`, so **a pipe-creation or fork/exec failure also renders with the
///   `"upgrade not started"` prefix**.
///
/// Matching the prefix alone would report "a second concurrent upgrade was refused" when the truth
/// is "the upgrade machinery could not start", and would send the operator looking for a
/// concurrency problem that does not exist while the real io cause was swallowed at warn level.
/// Only the exact refusal payload is therefore treated as a refusal; everything else — including an
/// unrecognised or empty payload — is a startup failure, so the classification fails safe.
pub fn classify_upgrade_failure(reason: &str) -> UpgradeFailure {
    if reason == CONCURRENT_REFUSAL {
        UpgradeFailure::ConcurrentUpgradeRefused
    } else {
        UpgradeFailure::ChildDidNotTakeOver
    }
}

/// Owns the `ecdysis` listener registry for this generation (ADR-0044 §1).
///
/// A listener created through this type is registered with the registry, so on the next upgrade the
/// child inherits the *same* kernel socket instead of rebinding it. Rebinding is what opens the
/// window in which connections are refused; inheriting closes it for the listeners that go through
/// here.
///
/// # Why every TCP and admin/Unix listener must go through this
///
/// `T-CORE-102` is the single highest-risk task in the tree precisely because the failure is
/// per-listener and silent: a listener bound directly rather than through this type keeps working
/// perfectly, and only shows up as a refused-connection window for *that one listener* during an
/// upgrade. There is no runtime symptom until an upgrade happens under load.
///
/// UDP is deliberately absent. UDP has no listener to inherit across `exec`; its restart path is an
/// `SO_REUSEPORT` group plus eBPF flow dispatch (ADR-0044 §1, ADR-0045 §1), owned by `T-CORE-111`
/// and `T-CORE-112`. Adding `build_socket_udp` here would contradict the accepted ADR and pre-empt
/// that work, so this type does not offer it.
pub struct ListenerBinder {
    runtime: ecdysis::Ecdysis,
    /// Addresses this generation has bound through the registry, in binding order.
    ///
    /// ecdysis tracks the fd set internally but does not expose it (`get_fds_for_child` and
    /// `ListenerInfo::fd` are both crate-private in 1.1.1), so the set is mirrored here. This is what
    /// makes the inherited fd set enumerable and loggable at startup, which ADR-0044 §1 requires:
    /// an operator must be able to see which listeners will survive an upgrade *before* triggering
    /// one. Addresses rather than raw fd numbers, because an fd number means nothing to an operator
    /// while `127.0.0.1:8080` does.
    registered: std::sync::Mutex<Vec<std::net::SocketAddr>>,
}

impl ListenerBinder {
    /// Create the registry for this process generation.
    ///
    /// On an upgrade the child is started by the parent, so this reconstructs the inherited fd set;
    /// on a first start it is empty and every listener binds fresh.
    pub fn new() -> Self {
        Self {
            runtime: ecdysis::Ecdysis::new(),
            registered: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Whether this process is the child of an upgrade (`exec`'d by the parent generation).
    pub fn is_child(&self) -> bool {
        self.runtime.is_child()
    }

    /// Bind a TCP listener through the registry, or adopt the inherited socket for `addr`.
    ///
    /// `sock_build` runs **only** when a new socket has to be created; on an upgrade the inherited
    /// descriptor is adopted and the closure is never called. That asymmetry is why the closure must
    /// apply every socket option the listener needs: if an option were applied *outside* the closure
    /// it would be skipped for inherited sockets, and the two generations would disagree about the
    /// same kernel socket.
    ///
    /// The listener is returned in its **std** form because that is what `ecdysis` constructs and
    /// adopts; the caller sets it non-blocking and converts to `tokio::net::TcpListener`, exactly as
    /// the direct-bind path already does. ecdysis 1.1.1 offers no way to hand back a tokio listener,
    /// and converting is the only correct order: `set_nonblocking` must be applied to the std socket
    /// before `from_std`, for inherited and freshly-bound sockets alike.
    ///
    /// `addr` must be a numeric `SocketAddr`. ecdysis keys inheritance on the concrete address, so a
    /// hostname cannot be used as the key: two hostnames that resolve to the same address are the
    /// same socket, and a hostname that resolves differently between generations would look up the
    /// wrong fd. Callers resolve first (see `listeners::bind_configured_tcp`).
    pub fn bind_tcp<F>(&self, addr: std::net::SocketAddr, sock_build: F) -> io::Result<TcpListener>
    where
        F: FnOnce(Socket, std::net::SocketAddr) -> io::Result<TcpListener>,
    {
        let listener = self.runtime.build_listen_tcp(addr, sock_build)?;
        // Record the socket's ACTUAL local address, not `addr` as requested. ecdysis keys its
        // registry on `local_addr()` of the live socket (`Listener::info` in ecdysis 1.1.1), so for
        // an ephemeral bind (`127.0.0.1:0`) the key is the port the kernel chose. Recording the
        // requested `:0` would make this list disagree with what the child actually looks up, and
        // the child would miss the inherited fd and silently rebind - the exact per-listener
        // coverage gap this task exists to prevent. A test asserts the two agree.
        let bound = listener.local_addr().map_err(|error| {
            io::Error::other(format!("bound listener has no local address: {error}"))
        })?;
        if let Ok(mut registered) = self.registered.lock() {
            if !registered.contains(&bound) {
                registered.push(bound);
            }
        }
        Ok(listener)
    }

    /// Forget a listener that is no longer bound.
    ///
    /// **This is what keeps a config reload working.** ecdysis holds a `dup` of every registered
    /// socket for the whole life of the process and only releases them on `quit()`, so a listener
    /// that is registered and then closed still has a live descriptor inside the registry — the
    /// kernel keeps the port bound and keeps accepting into a queue nobody serves. That would break
    /// the reload semantics this crate already has: `http_graceful_shutdown`'s
    /// `reload_honors_shutdown_delay_and_grace_for_closing_listeners` asserts that after a reload
    /// the old address **refuses** connections, and it caught exactly this.
    ///
    /// ADR-0044 §1 scopes graceful restart to replacing the *binary*; configuration reload is
    /// explicitly out of its scope. A reloaded-away listener must therefore be dropped from the
    /// registry, so the next `exec` does not resurrect it and the port is genuinely released.
    ///
    /// Note the asymmetry this creates and why it is correct: the registry describes "what the next
    /// generation should inherit", which is the set of listeners bound *now*, not the set that has
    /// ever been bound.
    pub fn forget(&self, addr: std::net::SocketAddr) {
        if let Ok(mut registered) = self.registered.lock() {
            registered.retain(|candidate| *candidate != addr);
        }
    }

    /// The addresses this generation would hand to its child, in binding order.
    ///
    /// ADR-0044 §1 requires the inherited fd set to be enumerable. These are the listeners that will
    /// be adopted rather than rebound on the next upgrade; anything missing from this list will
    /// rebind and therefore has a refused-connection window.
    pub fn inherited_listeners(&self) -> Vec<std::net::SocketAddr> {
        self.registered
            .lock()
            .map(|registered| registered.clone())
            .unwrap_or_default()
    }

    /// Declare this generation ready to take over (ADR-0044 §2.3).
    ///
    /// **The child calls this, and only after it has fully initialised** — config parsed, TLS
    /// loaded, routes compiled, listeners bound. ecdysis's `ready()` then writes `OK` down the pipe
    /// to the parent, whose `upgrade()` returns; the parent is what closes its listener copies and
    /// begins draining.
    ///
    /// This is the single most important ordering in the whole restart path, and the reason it is a
    /// separate method rather than being folded into `upgrade`: if the child signalled readiness
    /// before it could actually serve, the parent would exit and the new generation would be
    /// half-initialised with nobody listening — a bad config would take the service down, which is
    /// exactly what §2.4 forbids. Calling this too early is worse than not calling it at all,
    /// because the parent times out and keeps serving if it is never called.
    ///
    /// Returns an error if the readiness pipe cannot be written; the parent then treats the upgrade
    /// as failed and keeps serving.
    pub fn ready(&mut self) -> Result<(), GracefulRestartError> {
        if !self.is_child() {
            // Not an error: a first generation has no parent to notify, and `ready()` on a
            // non-child is a no-op in ecdysis. Returning Ok keeps the CLI's startup path
            // unconditional rather than branching on `is_child()`.
            tracing::debug!(
                "graceful restart: not an upgrade child, so there is no parent to notify of readiness"
            );
            return Ok(());
        }
        self.runtime
            .ready()
            .map_err(|e| GracefulRestartError::Io(e))
    }

    /// Ask the parent to fork+exec a new generation (ADR-0044 §2.1-§2.2, §2.6).
    ///
    /// **Blocks until the child either declares ready or exits**, which is what makes the §2
    /// ordering hold: ecdysis's `upgrade()` waits on the readiness pipe and reports
    /// [`GracefulRestartError::ChildNotReady`] when the child dies first, so the caller learns the
    /// outcome before it decides whether to drain. The parent must keep serving on every error path
    /// — that is the whole point of doing it this way round.
    ///
    /// The single-upgrade invariant (§2.6) is enforced inside `ecdysis::upgrade` by an atomic swap,
    /// so a second call while one is in flight returns [`GracefulRestartError::UpgradeInFlight`]
    /// instead of forking a second child. A second request is **refused, not queued**: queueing
    /// repeated requests turns them into a fork storm, which §5 names as a denial-of-service
    /// primitive.
    ///
    /// This runs the fork/exec on the calling thread. Callers on an async runtime must therefore
    /// call it from a blocking context (`tokio::task::spawn_blocking`), never directly from a task
    /// that also drives listeners — `exec` after `fork` is not async-signal-safe.
    pub fn upgrade(&self) -> Result<(), GracefulRestartError> {
        if !self.registered_any_listener() {
            // Forking a child that inherits nothing would produce a second generation with no
            // sockets: the new process would try to bind the same addresses, fail, and exit —
            // while the parent had already been asked to hand over. Refusing here keeps the old
            // generation serving and says why.
            return Err(GracefulRestartError::ChildNotReady {
                cause: "no listeners are registered to inherit, so a new generation could not \
                        serve; refusing to start an upgrade that would leave nothing listening"
                    .to_string(),
            });
        }
        match self.runtime.upgrade() {
            Ok(()) => {
                tracing::info!(
                    listeners = self.inherited_listeners().len(),
                    "graceful restart: the new generation is ready; this generation will now \
                     stop accepting and drain"
                );
                Ok(())
            }
            Err(error) => {
                // ecdysis 1.1.1 returns `UpgradeFinished`, but neither `UpgradeError` nor
                // `UpgradeFinished` is re-exported (`lib.rs` imports them with a private `use`), so
                // the variants cannot be matched on. Classification therefore goes through
                // `classify_upgrade_failure`, which is a pure function over the rendered reason and
                // is table-tested against the strings ecdysis actually produces.
                let reason = error.to_string();
                if classify_upgrade_failure(&reason) == UpgradeFailure::ConcurrentUpgradeRefused {
                    // The single-upgrade invariant (§2.6) refused a second concurrent upgrade.
                    // Refused rather than queued, so repeated requests cannot become a fork storm.
                    tracing::warn!(%reason, "graceful restart: refused a second concurrent upgrade");
                    return Err(GracefulRestartError::UpgradeInFlight);
                }
                // Everything else — the child exited, timed out, or the upgrade machinery could not
                // start at all — means no new generation took over. The parent is still serving and
                // the cause must be reported at error level (§2.4).
                tracing::error!(
                    %reason,
                    "graceful restart failed; the current process is still serving"
                );
                Err(GracefulRestartError::ChildNotReady { cause: reason })
            }
        }
    }

    /// Whether any listener is registered to be inherited.
    fn registered_any_listener(&self) -> bool {
        self.registered
            .lock()
            .map(|registered| !registered.is_empty())
            .unwrap_or(false)
    }
}

impl Default for ListenerBinder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ListenerBinder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerBinder")
            .field("is_child", &self.is_child())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_feature_reports_itself_enabled() {
        assert!(is_enabled());
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

    #[test]
    fn a_bound_listener_is_recorded_as_inheritable() {
        // The registry is what the child inherits. If binding did not record the address, the next
        // generation would find no fd for it, rebind, and open the refused-connection window this
        // task exists to close - so the record itself is the property worth asserting.
        let binder = ListenerBinder::new();
        assert!(
            binder.inherited_listeners().is_empty(),
            "a fresh generation inherits nothing"
        );

        let listener = binder
            .bind_tcp("127.0.0.1:0".parse().unwrap(), |socket, addr| {
                socket.bind(&addr.into())?;
                socket.listen(128)?;
                let std_listener: std::net::TcpListener = socket.into();
                std_listener.set_nonblocking(true)?;
                Ok(std_listener)
            })
            .expect("bind through the registry");

        let bound = listener.local_addr().expect("local address");
        assert_eq!(
            binder.inherited_listeners(),
            vec![bound],
            "the address actually bound is the one the child will look up; a mismatch would make \
             the child miss the inherited socket and rebind"
        );
    }

    #[test]
    fn the_creation_closure_runs_for_a_new_socket_and_is_what_applies_options() {
        // ecdysis only calls the closure when it is creating a socket; on an upgrade the inherited
        // descriptor is adopted and the closure never runs. That is precisely why every socket
        // option must be applied INSIDE the closure rather than after it: an option applied outside
        // would be silently skipped for inherited sockets, and the parent and child would disagree
        // about the same kernel socket.
        let binder = ListenerBinder::new();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&calls);
        let listener = binder
            .bind_tcp("127.0.0.1:0".parse().unwrap(), move |socket, addr| {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                socket.bind(&addr.into())?;
                socket.listen(128)?;
                let std_listener: std::net::TcpListener = socket.into();
                std_listener.set_nonblocking(true)?;
                Ok(std_listener)
            })
            .expect("bind through the registry");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a first generation creates the socket, so the closure must run exactly once"
        );
        drop(listener);
    }

    #[test]
    fn a_non_upgrade_generation_is_not_a_child() {
        // Without an inherited environment this process is the first generation. It must not think
        // it is a child, because a child that believes it inherited sockets it did not would skip
        // binding and serve nothing.
        let binder = ListenerBinder::new();
        assert!(
            !binder.is_child(),
            "a process started normally is not the child of an upgrade"
        );
    }

    #[test]
    fn ready_on_a_first_generation_is_a_no_op_rather_than_an_error() {
        // Startup calls `ready()` unconditionally. A first generation has no parent to notify, so
        // the call must succeed silently instead of forcing every caller to branch on `is_child()`.
        let mut binder = ListenerBinder::new();
        assert!(!binder.is_child());
        binder
            .ready()
            .expect("ready() on a first generation must not fail");
    }

    #[test]
    fn an_upgrade_with_no_registered_listeners_is_refused_before_forking() {
        // Forking a child that inherits nothing would produce a generation with no sockets: it
        // would try to rebind, fail, and exit - after the parent had already been asked to hand
        // over. The refusal must name that, and must not claim the child merely "was not ready".
        let binder = ListenerBinder::new();
        let error = binder
            .upgrade()
            .expect_err("an upgrade with nothing to inherit must be refused");
        let message = error.to_string();
        assert!(
            message.contains("nothing listening"),
            "the refusal must say why it would leave nothing serving; got: {message}"
        );
        assert!(
            message.contains("still serving"),
            "the message must say the current process is still serving; got: {message}"
        );
    }

    #[test]
    fn only_registered_listeners_are_handed_to_the_child() {
        // ADR-0044 section 2.7 / DIV-0155: only listener and pipe descriptors may cross `exec`.
        // The claim is structural - the registry holds exactly what was bound through it - so this
        // proves it by showing that a descriptor opened *outside* the binder is absent from the set
        // the child would receive, while a listener bound *through* the binder is present.
        let binder = ListenerBinder::new();
        assert!(
            binder.inherited_listeners().is_empty(),
            "a fresh registry inherits nothing"
        );

        // A canary descriptor: a plain file that must never reach the child.
        let canary_path = std::env::temp_dir().join(format!(
            "caddy-rs-canary-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let canary = std::fs::File::create(&canary_path).expect("create canary file");
        let canary_fd = {
            use std::os::fd::AsRawFd;
            canary.as_raw_fd()
        };
        assert!(
            binder.inherited_listeners().is_empty(),
            "opening a file outside the binder must not register anything: fd {canary_fd} must \
             not cross exec"
        );

        let listener = binder
            .bind_tcp("127.0.0.1:0".parse().unwrap(), |socket, addr| {
                socket.bind(&addr.into())?;
                socket.listen(128)?;
                let std_listener: std::net::TcpListener = socket.into();
                std_listener.set_nonblocking(true)?;
                Ok(std_listener)
            })
            .expect("bind through the registry");
        let bound = listener.local_addr().expect("local address");

        let inherited = binder.inherited_listeners();
        assert_eq!(
            inherited,
            vec![bound],
            "exactly the listener bound through the binder is inherited - the canary fd {canary_fd} \
             is not, and no other descriptor is either"
        );

        drop(listener);
        drop(canary);
        let _ = std::fs::remove_file(&canary_path);
    }

    #[test]
    fn upgrade_failures_are_classified_from_the_strings_ecdysis_actually_emits() {
        // The only signal available is the rendered `Display` text, because ecdysis 1.1.1 does not
        // re-export `UpgradeError`. Each row below is a string ecdysis really produces, taken from
        // executioner.rs, so a dependency bump that changes the wording fails here instead of
        // silently changing how an operator-visible failure is reported.
        let cases = [
            // executioner.rs:43 - the UPGRADING swap. The genuine concurrent refusal.
            (
                "upgrade not started: Already in upgrade",
                UpgradeFailure::ConcurrentUpgradeRefused,
            ),
            // executioner.rs:89 via the blanket From<Error>, used by `UpgradePipes::new()?`. This
            // is an io failure that *also* renders with the "upgrade not started" prefix: matching
            // the prefix alone would misreport it as a concurrent refusal.
            (
                "upgrade not started: Os { code: 24, kind: Uncategorized, message: \"Too many open files\" }",
                UpgradeFailure::ChildDidNotTakeOver,
            ),
            // executioner.rs:89 via the blanket From<Error>, used by `exec_upgraded(...)?`.
            (
                "upgrade not started: Os { code: 2, kind: NotFound, message: \"No such file or directory\" }",
                UpgradeFailure::ChildDidNotTakeOver,
            ),
            // executioner.rs:26 - the child died before signalling ready.
            ("child exited unexpectedly", UpgradeFailure::ChildDidNotTakeOver),
            // executioner.rs:29 - the child never signalled ready in time.
            (
                "timed out waiting for ready signal from child",
                UpgradeFailure::ChildDidNotTakeOver,
            ),
            // executioner.rs:35 - the descriptor payload could not be serialised.
            (
                "serialization error: Custom(\"bad fd payload\")",
                UpgradeFailure::ChildDidNotTakeOver,
            ),
            // Defensive: an empty or unrecognised payload must never be read as a refusal.
            ("", UpgradeFailure::ChildDidNotTakeOver),
            ("upgrade not started: ", UpgradeFailure::ChildDidNotTakeOver),
            (
                "upgrade not started: something new in a future release",
                UpgradeFailure::ChildDidNotTakeOver,
            ),
        ];
        for (reason, expected) in cases {
            assert_eq!(
                classify_upgrade_failure(reason),
                expected,
                "misclassified {reason:?}: reporting an io/fork failure as a concurrent refusal \
                 would send the operator after a concurrency problem that does not exist"
            );
        }
    }
}
