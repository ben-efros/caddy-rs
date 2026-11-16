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
use std::sync::Once;
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

/// Apply the whole udpgrm sequence to a freshly bound `SO_REUSEPORT` UDP socket.
///
/// Returns the confirmed generation on success. Every failure is a *degradation*, never a bind
/// failure: the caller keeps serving, and the reason is logged. The `SO_REUSEPORT` option itself is
/// set by the caller before `bind`, because udpgrm's hooks only act on a reuseport group.
pub fn register_listener(socket: &UdpSocket, listen: &str) -> Option<SocketGeneration> {
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
    let generation = working.wrapping_add(1);
    match register_socket(socket, generation) {
        Ok(confirmed) => {
            if let Err(error) = promote_generation(socket, generation) {
                tracing::warn!(
                    listen = listen,
                    generation,
                    %error,
                    "udpgrm could not promote the new socket generation; UDP still serves"
                );
                return None;
            }
            tracing::debug!(
                listen = listen,
                generation,
                socket_idx = confirmed.socket_idx,
                "udpgrm registered and promoted the UDP socket generation"
            );
            Some(confirmed)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transcribed_constants_are_the_values_recorded_in_the_module_docs() {
        // Guards against a *local* edit drifting from the values recorded above - nothing more.
        //
        // It deliberately does NOT read udpgrm's header, so it CANNOT detect upstream renumbering:
        // this assertion would pass unchanged against a udpgrm that had changed 200/201. Do not
        // read a green run as "our constants still match upstream". The defence against upstream
        // drift is the runtime one - a renumbered option makes the presence probe fail
        // `ENOPROTOOPT`, so caddy-rs degrades loudly instead of silently setting an unrelated
        // socket option - plus a human re-checking `udp_grm_public.h` when udpgrm is upgraded.
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
}
