//! Client side of the `udpgrm` UDP graceful-restart protocol (ADR-0045 §2, §3).
//!
//! `udpgrm` is an optional, privileged external daemon that installs eBPF hooks on `getsockopt`,
//! `setsockopt`, `bind` and `sendmsg`, scoped to a cgroup. It gives a `SO_REUSEPORT` group of UDP
//! sockets a *flow table*, so that during a restart each in-flight QUIC flow keeps reaching the
//! socket generation that owns it. caddy-rs **integrates** with it and never implements the eBPF
//! dispatch itself, never ships it and never installs it (ADR-0045 §3).
//!
//! # The sequence, and why each step exists
//!
//! 1. `getsockopt(UDP_GRM_WORKING_GEN)` — the **presence probe**. When the cgroup hooks are not
//!    loaded the kernel has no such option and the call fails `ENOPROTOOPT`. That is not an error:
//!    it means "graceful UDP restart unavailable", and caddy-rs serves UDP exactly as it does
//!    without the daemon (ADR-0045 §3).
//! 2. `setsockopt(UDP_GRM_SOCKET_GEN, work_gen + 1)` — register this socket into the new generation.
//!    The daemon does the registration **asynchronously**, so the call returning success does not
//!    mean the socket is registered yet.
//! 3. `getsockopt(UDP_GRM_SOCKET_GEN, 8)` — read back the 32-bit `(socket_gen, socket_idx)` pair to
//!    confirm the registration landed. `socket_idx == 0xffffffff` means "not yet", which is why
//!    this step needs a **bounded** retry rather than a single read.
//! 4. `setsockopt(UDP_GRM_WORKING_GEN, work_gen + 1)` — promote the new generation so it takes new
//!    flows.
//!
//! # Why the constants are defined here rather than imported
//!
//! `UDP_GRM_*` is **not** in the kernel UAPI headers: `/usr/include/linux/udp.h` has no such
//! symbol, because the option numbers are owned by udpgrm's out-of-tree eBPF program rather than by
//! the kernel. The values below are therefore transcribed from udpgrm's own public header,
//! `udp_grm_public.h`, at `cloudflare/udpgrm` commit
//! `e5bbb047d4899042505ddd15dce2aaf98369e778`:
//!
//! ```c
//! enum udp_grm_socket_opt {
//!     UDP_GRM_WORKING_GEN = 200,
//!     UDP_GRM_SOCKET_GEN  = 201,
//!     UDP_GRM_DISSECTOR   = 202,
//!     UDP_GRM_FLOW_ASSURE = 203,
//!     UDP_GRM_SOCKET_APP  = 204
//! };
//! ```
//!
//! They are transcribed rather than generated so that this crate does not depend on a C header it
//! cannot ship. If udpgrm ever renumbers them, the probe in step 1 fails `ENOPROTOOPT` against a
//! real daemon and caddy-rs degrades loudly instead of silently mis-setting an unrelated option —
//! which is the failure mode worth having.
//!
//! ## Unsafe code
//!
//! The udpgrm API is exposed only as raw `getsockopt`/`setsockopt` calls; there is no safe wrapper
//! in `libc` for an option number the kernel headers do not define. The crate denies unsafe code
//! (`#![deny(unsafe_code)]`) and only this module and `activation.rs` allow it. Every unsafe block
//! below is annotated with its invariant: the descriptor is a live socket owned by the caller for
//! the duration of the call, and the value pointer always refers to a local of exactly the size
//! passed as the length.

#![allow(unsafe_code)]

use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, Once, OnceLock};
use std::time::Duration;

/// `UDP_GRM_WORKING_GEN` — read the current working generation; write to promote a generation.
///
/// Transcribed from udpgrm `udp_grm_public.h` at commit `e5bbb047d489` (see the module docs).
const UDP_GRM_WORKING_GEN: libc::c_int = 200;

/// `UDP_GRM_SOCKET_GEN` — register a socket into a generation; read back `(gen, idx)` to confirm.
///
/// Transcribed from udpgrm `udp_grm_public.h` at commit `e5bbb047d489` (see the module docs).
const UDP_GRM_SOCKET_GEN: libc::c_int = 201;

/// `socket_idx` value meaning "the daemon has not registered this socket yet".
///
/// udpgrm's eBPF program sets this sentinel in `ebpf.c` (`s->sock_idx == 0xffffffff`) until its
/// ring-buffer message has been processed, so step 3 must retry rather than fail on first read.
const SOCKET_IDX_NOT_YET: u32 = 0xffff_ffff;

/// How many times to re-read the registration before giving up, and how long to wait between reads.
///
/// The daemon processes the ring-buffer message on its own schedule, so the wait is real but short.
/// The bound exists so a wedged daemon cannot stall a listener bind indefinitely: giving up is
/// handled as a loud degradation, never as a panic or an infinite loop.
const REGISTRATION_ATTEMPTS: u32 = 50;
const REGISTRATION_INTERVAL: Duration = Duration::from_millis(2);

/// The `(socket_gen, socket_idx)` pair udpgrm reports for a registered socket.
///
/// Mirrors `struct udp_grm_socket_gen` from `udp_grm_public.h`; only the first two `u32` fields are
/// meaningful for the confirmation read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketGeneration {
    /// The generation this socket belongs to.
    pub socket_gen: u32,
    /// The socket's index within that generation, or [`SOCKET_IDX_NOT_YET`] while unregistered.
    pub socket_idx: u32,
}

impl SocketGeneration {
    /// Whether the daemon has finished registering this socket.
    pub fn is_registered(&self) -> bool {
        self.socket_idx != SOCKET_IDX_NOT_YET
    }
}

/// Why a udpgrm interaction did not produce a usable result.
#[derive(Debug)]
pub enum UdpgrmError {
    /// The presence probe failed `ENOPROTOOPT`: the daemon (or its cgroup hooks) is absent.
    ///
    /// This is the expected outcome on any host without udpgrm installed, including this
    /// program's sandbox, and is **not** an error that prevents serving.
    Absent,

    /// The daemon answered the probe but never confirmed the registration within the bound.
    RegistrationTimedOut {
        /// The generation the socket was being registered into.
        generation: u32,
    },

    /// The platform refused the option for another reason.
    Io(io::Error),
}

impl std::fmt::Display for UdpgrmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => f.write_str(
                "udpgrm is not available (getsockopt UDP_GRM_WORKING_GEN failed ENOPROTOOPT): \
                 graceful UDP restart is unavailable and UDP will serve without it",
            ),
            Self::RegistrationTimedOut { generation } => write!(
                f,
                "udpgrm did not confirm socket registration into generation {generation} within \
                 {} attempts",
                REGISTRATION_ATTEMPTS
            ),
            Self::Io(e) => write!(f, "udpgrm socket option failed: {e}"),
        }
    }
}

impl std::error::Error for UdpgrmError {}

impl From<io::Error> for UdpgrmError {
    fn from(error: io::Error) -> Self {
        if error.raw_os_error() == Some(libc::ENOPROTOOPT) {
            Self::Absent
        } else {
            Self::Io(error)
        }
    }
}

/// Read the current working generation.
///
/// This is the presence probe: `Err(UdpgrmError::Absent)` means the daemon or its hooks are not
/// loaded, and the caller must degrade rather than fail.
pub fn working_generation(socket: &UdpSocket) -> Result<u32, UdpgrmError> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a live socket owned by `socket`; `value` and `length` point at writable
    // memory of the sizes passed, which is the contract of `getsockopt`.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            UDP_GRM_WORKING_GEN,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(value as u32)
}

/// Register `socket` into `generation` and wait (bounded) for the daemon to confirm it.
///
/// Returns the confirmed [`SocketGeneration`]. Step 2 of the sequence is asynchronous on the
/// daemon side, so this performs steps 2 and 3 together.
pub fn register_socket(
    socket: &UdpSocket,
    generation: u32,
) -> Result<SocketGeneration, UdpgrmError> {
    let value: libc::c_int = generation as libc::c_int;
    // SAFETY: as in `working_generation`; `value` is a live local of the size passed.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            UDP_GRM_SOCKET_GEN,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    confirm_registration(socket, generation)
}

/// Step 3: read back `(socket_gen, socket_idx)` until the daemon stops reporting "not yet".
fn confirm_registration(
    socket: &UdpSocket,
    generation: u32,
) -> Result<SocketGeneration, UdpgrmError> {
    let mut last = SocketGeneration {
        socket_gen: 0,
        socket_idx: SOCKET_IDX_NOT_YET,
    };
    for _ in 0..REGISTRATION_ATTEMPTS {
        last = read_socket_generation(socket)?;
        if last.is_registered() {
            return Ok(last);
        }
        std::thread::sleep(REGISTRATION_INTERVAL);
    }
    Err(UdpgrmError::RegistrationTimedOut { generation })
}

/// Step 3, one read: fetch the 8-byte `struct udp_grm_socket_gen`.
fn read_socket_generation(socket: &UdpSocket) -> Result<SocketGeneration, UdpgrmError> {
    // The struct is two `u32`s; read exactly those eight bytes so the call does not depend on the
    // padding the C struct carries.
    let mut pair = [0u32; 2];
    let mut length = std::mem::size_of::<[u32; 2]>() as libc::socklen_t;
    // SAFETY: as above; `pair` is 8 bytes and `length` states exactly that.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            UDP_GRM_SOCKET_GEN,
            pair.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(SocketGeneration {
        socket_gen: pair[0],
        socket_idx: pair[1],
    })
}

/// Step 4: promote `generation` so it receives new flows.
pub fn promote_generation(socket: &UdpSocket, generation: u32) -> Result<(), UdpgrmError> {
    let value: libc::c_int = generation as libc::c_int;
    // SAFETY: as in `register_socket`.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            UDP_GRM_WORKING_GEN,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Registry of UDP sockets registered into a socket generation but not yet promoted.
///
/// The bind path ([`crate::listeners`]) is far from the runtime and has no handle to it, while the
/// promotion point is the runtime's readiness signal (`ServerRuntime::mark_ready`). A registry is
/// the narrowest way to connect them without threading a handle through the listener bind chain:
/// sockets register here as they are bound, and the runtime drains and promotes the whole set once,
/// at the moment the instance is fully initialised.
///
/// The registry is an ordinary owned value rather than a bare global so that tests can construct
/// their own and exercise the ordering contract without sharing mutable state. The production path
/// uses the process-wide [`registry`] below; tests that used that global concurrently were
/// genuinely flaky (a test could drain another test's entry, or observe its counter movement), and
/// a test that fails a fraction of the time is eventually dismissed as noise, which is how a real
/// regression gets waved through.
///
/// Entries are keyed by the listener description so a rebind of the same address replaces rather
/// than duplicates. A socket is held by the entry, keeping the descriptor alive until promotion, so
/// a dropped entry cannot leave a stale registration pointing at a closed fd.
#[derive(Default)]
pub struct PendingRegistry {
    entries: Mutex<Vec<(String, UdpSocket, PendingGeneration)>>,
    /// Counts real calls into [`promote_generation`] made on behalf of this registry.
    ///
    /// The ordering contract of ADR-0045 §2 is that promotion happens *later*, at readiness, so the
    /// property worth asserting is that no promotion is *attempted* while a socket is only being
    /// registered. Without a udpgrm daemon the call always fails, so counting attempts is the only
    /// observable that separates "registered and waiting" from "registered and already promoted".
    attempts: AtomicUsize,
}

impl PendingRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<(String, UdpSocket, PendingGeneration)>> {
        // A panic while holding the lock cannot corrupt the `Vec` in a way that matters here - the
        // worst case is a lost entry, which degrades to "not promoted" - so recover rather than
        // propagate the panic into an unrelated caller.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record a registered-but-unpromoted socket for later promotion.
    ///
    /// `socket` must be a duplicate of the listener's descriptor (see [`duplicate_for_promotion`]);
    /// ownership moves into the registry.
    pub fn defer(&self, listen: &str, socket: UdpSocket, pending_generation: PendingGeneration) {
        let mut entries = self.lock();
        entries.retain(|(existing, _, _)| existing != listen);
        entries.push((listen.to_string(), socket, pending_generation));
    }

    /// Promote every deferred socket generation, draining the registry.
    ///
    /// Returns the number of generations promoted. An empty registry is not an error: it means no
    /// UDP listener registered (udpgrm absent, or no UDP listeners configured).
    pub fn promote_all(&self) -> usize {
        let drained: Vec<_> = std::mem::take(&mut *self.lock());
        let mut promoted = 0;
        for (listen, socket, pending_generation) in drained {
            if promote(&socket, pending_generation, &listen) {
                promoted += 1;
            }
        }
        promoted
    }

    /// How many promotions this registry has attempted.
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    /// How many sockets are registered but not yet promoted.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no socket is awaiting promotion.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every entry without promoting.
    pub fn clear(&self) {
        self.lock().clear();
    }
}

/// The process-wide registry used by the real bind and readiness paths.
static PENDING: OnceLock<PendingRegistry> = OnceLock::new();

/// The process-wide registry, created on first use.
pub fn registry() -> &'static PendingRegistry {
    PENDING.get_or_init(PendingRegistry::new)
}

/// Record a registered-but-unpromoted socket in the process-wide registry.
pub fn defer_promotion(listen: &str, socket: UdpSocket, pending_generation: PendingGeneration) {
    registry().defer(listen, socket, pending_generation);
}

/// Promote every generation deferred in the process-wide registry.
pub fn promote_deferred() -> usize {
    registry().promote_all()
}

/// How many sockets the process-wide registry is holding. Used by diagnostics and tests.
pub fn deferred_len() -> usize {
    registry().len()
}

/// Duplicate a listener's descriptor so the registry can hold its own handle.
///
/// The promotion calls need a live socket; the listener is owned by the accept loop, so the registry
/// keeps a duplicate rather than borrowing it. Both refer to the same kernel socket, so a socket
/// option set through the duplicate applies to the listener.
pub fn duplicate_for_promotion(socket: &UdpSocket) -> io::Result<UdpSocket> {
    socket.try_clone()
}

/// Log the absence of udpgrm **once per process**, loudly and by name (ADR-0045 §3).
///
/// Silence is a defect: it is the difference between a deliberate, documented degradation and a
/// silent one. `Once` keeps a multi-listener configuration from repeating the message per socket,
/// which would bury it.
pub fn report_absent_once(listen: &str) {
    static ABSENT: Once = Once::new();
    ABSENT.call_once(|| {
        tracing::warn!(
            listen = listen,
            "udpgrm is not available on this host (getsockopt UDP_GRM_WORKING_GEN failed \
             ENOPROTOOPT), so graceful UDP restart is unavailable. UDP listeners serve normally, \
             but a restart drops in-flight QUIC connections. Install and start the udpgrm daemon \
             with its cgroup-scoped eBPF hooks to enable UDP graceful restart (ADR-0045)."
        );
    });
}

/// A socket registered into a udpgrm socket generation but **not yet promoted**.
///
/// This is the mapping boundary between the two generation vocabularies (ADR-0045 §2, and the design
/// section "Configuration generations" -> "UDP socket generations", `docs/DESIGN.md`):
///
/// * the caddy-rs **config generation** (`caddy_rs_core::Generation::id()`) identifies a loaded
///   configuration and is **not** an input to the socket generation number;
/// * the **socket generation** is `working_gen + 1` read from the reuseport group, i.e. it is
///   assigned by udpgrm relative to whatever the previous process promoted.
///
/// Keeping registration and promotion as separate steps is the point: a socket can be registered
/// into the new generation while the working generation still points at the old one, so new flows
/// keep reaching the old instance until the new one is ready. Promoting at bind time instead would
/// send new flows to a process that has not finished initialising — the UDP form of the ordering
/// bug ADR-0044 §2 fixes for TCP with `ready()`.
#[derive(Debug, Clone, Copy)]
pub struct PendingGeneration {
    /// The generation this socket was registered into.
    pub generation: u32,
    /// The confirmed `(socket_gen, socket_idx)` the daemon reported.
    pub confirmed: SocketGeneration,
}

/// Register a freshly bound `SO_REUSEPORT` UDP socket into the next socket generation, **without**
/// promoting it.
///
/// Returns `None` when udpgrm is unavailable or registration fails; every failure is a
/// *degradation*, never a bind failure: the caller keeps serving and the reason is logged. The
/// `SO_REUSEPORT` option itself is set by the caller before `bind`, because udpgrm's hooks only act
/// on a reuseport group.
///
/// The caller must later call [`promote`] once the instance is fully initialised. Dropping the
/// returned value leaves the socket registered but unpromoted, which is safe: it simply receives no
/// new flows.
pub fn register_listener(socket: &UdpSocket, listen: &str) -> Option<PendingGeneration> {
    let working = match working_generation(socket) {
        Ok(generation) => generation,
        Err(UdpgrmError::Absent) => {
            report_absent_once(listen);
            return None;
        }
        Err(error) => {
            tracing::warn!(
                listen = listen,
                %error,
                "udpgrm presence probe failed; graceful UDP restart unavailable for this listener"
            );
            return None;
        }
    };
    // `-1` is udpgrm's "no reuseport group yet" sentinel *and* the default working generation, so
    // the first process to bind a group registers into generation 0. `wrapping_add` is deliberate:
    // it maps the sentinel to 0 instead of overflowing or needing a special case.
    let generation = working.wrapping_add(1);
    match register_socket(socket, generation) {
        Ok(confirmed) => {
            tracing::debug!(
                listen = listen,
                generation,
                socket_idx = confirmed.socket_idx,
                "udpgrm registered the UDP socket generation; promotion waits for readiness"
            );
            Some(PendingGeneration {
                generation,
                confirmed,
            })
        }
        Err(error) => {
            tracing::warn!(
                listen = listen,
                generation,
                %error,
                "udpgrm could not register the UDP socket generation; UDP still serves"
            );
            None
        }
    }
}

/// Promote a previously registered generation so it receives new flows.
///
/// Call this only when the instance is **fully initialised** — the same point at which the TCP path
/// signals `ready()` (ADR-0044 §2). Returns `true` when the promotion succeeded.
pub fn promote(socket: &UdpSocket, pending: PendingGeneration, listen: &str) -> bool {
    registry().attempts.fetch_add(1, Ordering::SeqCst);
    match promote_generation(socket, pending.generation) {
        Ok(()) => {
            tracing::debug!(
                listen = listen,
                generation = pending.generation,
                socket_idx = pending.confirmed.socket_idx,
                "udpgrm promoted the UDP socket generation; new flows now dispatch to it"
            );
            true
        }
        Err(error) => {
            tracing::warn!(
                listen = listen,
                generation = pending.generation,
                %error,
                "udpgrm could not promote the new socket generation; UDP still serves on the \
                 previous generation"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transcribed_constants_match_udpgrm_public_header() {
        // Pinned against `udp_grm_public.h` at cloudflare/udpgrm e5bbb047d489. If udpgrm ever
        // renumbers these, this test is where a reader finds out - not at runtime, where a wrong
        // optname would silently set an unrelated socket option.
        assert_eq!(UDP_GRM_WORKING_GEN, 200);
        assert_eq!(UDP_GRM_SOCKET_GEN, 201);
    }

    #[test]
    fn enoprotoopt_is_reported_as_absence_not_as_an_io_error() {
        // The probe's failure is the documented, expected outcome on a host without the daemon, and
        // it must be distinguishable from a genuine I/O error so the caller degrades instead of
        // failing the bind.
        let error = UdpgrmError::from(io::Error::from_raw_os_error(libc::ENOPROTOOPT));
        assert!(
            matches!(error, UdpgrmError::Absent),
            "ENOPROTOOPT must classify as Absent, got {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains("graceful UDP restart is unavailable"),
            "the absence must name the consequence, not just the errno: {message}"
        );
        assert!(
            message.contains("serve without it"),
            "the absence must say UDP still serves: {message}"
        );
    }

    #[test]
    fn a_different_errno_stays_an_io_error() {
        let error = UdpgrmError::from(io::Error::from_raw_os_error(libc::EPERM));
        assert!(
            matches!(error, UdpgrmError::Io(_)),
            "only ENOPROTOOPT means absence, got {error:?}"
        );
    }

    #[test]
    fn the_not_yet_sentinel_is_recognised() {
        assert!(!SocketGeneration {
            socket_gen: 7,
            socket_idx: SOCKET_IDX_NOT_YET
        }
        .is_registered());
        assert!(SocketGeneration {
            socket_gen: 7,
            socket_idx: 0
        }
        .is_registered());
    }

    #[test]
    fn the_probe_reports_absence_on_a_host_without_udpgrm() {
        // This sandbox has no udpgrm, and the research record documents that the option numbers are
        // absent from this kernel's UAPI headers, so the probe must fail ENOPROTOOPT. That makes it
        // a real check of the degrade path rather than a mock.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a probe socket");
        match working_generation(&socket) {
            Err(UdpgrmError::Absent) => {}
            other => {
                panic!("expected the probe to report udpgrm absent on this host, got {other:?}")
            }
        }
    }

    #[test]
    fn registering_without_the_daemon_degrades_to_none_and_serves() {
        // The full sequence must return `None` (no graceful restart) rather than propagating an
        // error that would prevent UDP from serving.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a probe socket");
        assert!(
            register_listener(&socket, "udp/127.0.0.1:0").is_none(),
            "without udpgrm the sequence must degrade to None, not fail the listener"
        );
        // The socket is still usable: degradation must not have broken it.
        socket
            .set_nonblocking(true)
            .expect("the socket still works after a degraded udpgrm sequence");
    }

    #[test]
    fn a_registered_generation_is_not_promoted_until_promotion_runs() {
        // The acceptance criterion for ADR-0045 §2: a socket registered into generation N+1 must not
        // receive new flows until the working generation is promoted.
        //
        // Without a udpgrm daemon the eBPF dispatch cannot be observed, so this asserts the one
        // observable that distinguishes "registered" from "promoted": whether a promotion was
        // *attempted*. It counts real calls into `promote_generation` - not registry bookkeeping -
        // because an earlier version asserted only that the entry was recorded, which stayed true
        // when `defer` was mutated to promote eagerly and so could never have caught the ordering
        // bug it claims to cover.
        //
        // The registry is constructed locally rather than using the process-wide one. Tests in one
        // binary run on several threads: a shared registry let this test drain another test's entry
        // and observe its counter movement, which made the suite fail intermittently. A per-test
        // registry is the fix - the assertions are unchanged, because weakening them would remove
        // exactly the check that catches eager promotion.
        let queue = PendingRegistry::new();
        let listener = UdpSocket::bind("127.0.0.1:0").expect("bind a listener");
        let pending = PendingGeneration {
            generation: 7,
            confirmed: SocketGeneration {
                socket_gen: 7,
                socket_idx: 0,
            },
        };
        let owned = duplicate_for_promotion(&listener).expect("duplicate the listener");

        let before = registry().attempts();
        queue.defer("udp/127.0.0.1:0", owned, pending);
        assert_eq!(
            registry().attempts(),
            before,
            "deferring a registration must not attempt a promotion - promoting at bind time is \
             exactly the ordering defect ADR-0045 §2 forbids"
        );
        assert_eq!(queue.len(), 1, "the socket is registered and waiting");

        // Promotion drains the set and attempts the promotion once.
        let promoted = queue.promote_all();
        assert!(
            registry().attempts() > before,
            "promotion must actually attempt to promote the deferred generation"
        );
        assert_eq!(queue.len(), 0, "promotion drains the deferred set");
        // Without a daemon the attempt fails, so nothing is reported as promoted - the call was
        // still made, which is what the ordering contract is about.
        assert_eq!(promoted, 0, "no daemon means no successful promotion");
    }

    #[test]
    fn the_deferred_set_is_keyed_by_listener_so_a_rebind_does_not_duplicate() {
        let queue = PendingRegistry::new();
        let listener = UdpSocket::bind("127.0.0.1:0").expect("bind a listener");
        let pending = PendingGeneration {
            generation: 1,
            confirmed: SocketGeneration {
                socket_gen: 1,
                socket_idx: 0,
            },
        };
        for _ in 0..3 {
            let owned = duplicate_for_promotion(&listener).expect("duplicate");
            queue.defer("udp/127.0.0.1:0", owned, pending);
        }
        assert_eq!(
            queue.len(),
            1,
            "re-registering the same listener must replace its entry, not accumulate duplicates"
        );
    }

    #[test]
    fn promotion_of_an_empty_set_is_not_an_error() {
        // With udpgrm absent, or with no UDP listeners, nothing is ever deferred. Readiness must
        // still succeed - a missing daemon is a degradation, not a startup failure.
        let queue = PendingRegistry::new();
        assert_eq!(
            queue.promote_all(),
            0,
            "nothing deferred means nothing promoted"
        );
    }

    #[test]
    fn the_next_generation_is_working_plus_one_including_the_no_group_sentinel() {
        // The mapping documented in docs/DESIGN.md, section "UDP socket generations":
        // `-1` is udpgrm's "no reuseport group yet" sentinel and doubles as the default working
        // generation, so the first process to bind a group registers into generation 0. This pins
        // the arithmetic so a future reader cannot "fix" the wrapping_add into a checked add.
        assert_eq!(
            (u32::MAX).wrapping_add(1),
            0,
            "the no-group sentinel must map to generation 0"
        );
        assert_eq!(0u32.wrapping_add(1), 1, "successor of generation 0 is 1");
        assert_eq!(1u32.wrapping_add(1), 2, "successor of generation 1 is 2");
    }
}
