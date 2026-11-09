//! Test-only helpers shared by the real-socket integration tests.
//!
//! The helpers exist because `bind("127.0.0.1:0")`, reading the port and dropping the listener is
//! a time-of-check/time-of-use race: the kernel may hand the same number to a parallel test (or,
//! less likely, an unrelated process) before the server binds it. Two mechanisms make that safe:
//!
//! * [`free_port`] records every port it hands out for the rest of the process and retries a probe
//!   the kernel assigns an already-issued port. Two tests running in parallel threads therefore
//!   never receive the same number from this helper.
//! * [`retry_addr_in_use`] re-runs a test's *server start* with freshly allocated ports when a
//!   fixed address is nevertheless claimed between the probe and the bind. A server that can
//!   listen on port 0 should do that instead: the kernel then assigns the port exactly once and
//!   there is no window at all.
//!
//! The crate is a dev-dependency of the test crates; it is never part of a shipped binary.

#![deny(unsafe_code)]

use std::collections::HashSet;
use std::future::Future;
use std::net::{TcpListener, UdpSocket};
use std::sync::{Mutex, OnceLock};

/// How many times a start is retried when its fixed port was claimed before it could bind.
///
/// The window is a few microseconds wide; losing it more than once in a row is implausible, but
/// the bound keeps a pathological port squatter from hanging the suite forever.
pub const START_ATTEMPTS: usize = 8;

/// Hand out an ephemeral IPv4 loopback port that this process has not issued before.
///
/// The probe socket is closed before returning, so the caller's server can bind the address. The
/// number stays in the process-wide registry: a later probe that the kernel hands the same number
/// is rejected and re-probed, which is what stops parallel tests from reusing each other's ports.
///
/// A candidate that is already bound on UDP loopback is rejected as well: HTTP/3 servers bind the
/// same number for TCP *and* QUIC/UDP, so a port that only looks free on TCP can still collide with
/// another process's UDP socket (a parallel test binary, or a QUIC endpoint left by an earlier run).
pub fn free_port() -> u16 {
    static ISSUED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let issued = ISSUED.get_or_init(|| Mutex::new(HashSet::new()));
    loop {
        let port = TcpListener::bind(("127.0.0.1", 0))
            .expect("bind an ephemeral loopback port")
            .local_addr()
            .expect("read the probe socket address")
            .port();
        // Probe the UDP space too; the socket is closed immediately, but this removes the case
        // where a UDP port was never checked at all.
        let udp_free = UdpSocket::bind(("127.0.0.1", port)).is_ok();
        let mut guard = issued.lock().expect("port registry");
        if udp_free && guard.insert(port) {
            return port;
        }
    }
}

/// Whether an error or child-process log reports that a bind lost the port race.
pub fn is_address_in_use(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    text.contains("address already in use") || text.contains("addrinuse")
}

/// Run `attempt` until it succeeds or fails for a reason other than a lost port race.
///
/// The closure must allocate fresh ports (through [`free_port`]) on every call, so a retry starts
/// the server on a number the kernel has not already assigned.
pub async fn retry_addr_in_use<T, E, F, Fut>(mut attempt: F) -> Result<T, E>
where
    E: std::fmt::Display,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut last = None;
    for _ in 0..START_ATTEMPTS {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(error) if is_address_in_use(&error.to_string()) => last = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last.expect("START_ATTEMPTS is at least one"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_port_never_reissues_in_one_process() {
        let ports: HashSet<u16> = (0..64).map(|_| free_port()).collect();
        assert_eq!(ports.len(), 64);
    }

    #[test]
    fn recognises_bind_conflicts_case_insensitively() {
        assert!(is_address_in_use(
            "cannot bind listener 127.0.0.1:1234: Address already in use (os error 98)"
        ));
        assert!(is_address_in_use("AddrInUse"));
        assert!(!is_address_in_use("permission denied"));
    }
}
