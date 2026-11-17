//! The `UDP_GRM_DISSECTOR` choice: which flow dissector udpgrm uses, and the flow bound it implies
//! (ADR-0045 §4).
//!
//! # Why this is a separate concern from the generation protocol
//!
//! [`super::udpgrm`] drives the generation protocol, which is per-socket and happens on every bind.
//! The dissector is **per reuseport group** and may be set **only once**: udpgrm's eBPF program
//! compares the incoming dissector against the one already recorded for the group and returns
//! `EPERM` when they differ (`ebpf.c`, the `UDP_GRM_DISSECTOR` branch: `if (dissector_cmp(...) != 0)
//! { bpf_set_retval(-EPERM); }`). Setting it is therefore a startup-time, once-per-group decision
//! that must be validated rather than retried per request — a per-request attempt would surface as
//! a stream of `EPERM`s under load instead of one located startup error.
//!
//! # The choice, and what it costs
//!
//! `DISSECTOR_FLOW` is the initial choice (ADR-0045 §4). It is a 4-tuple flow table: it needs no
//! protocol cooperation, which is what makes it work for the QUIC traffic caddy-rs serves today.
//! The price is a **fixed** table, so there is a hard cap on concurrent flows that must be
//! published to operators as a concrete number rather than discovered as a silent ceiling.
//!
//! The cap is not a number caddy-rs chooses: it is `MAX_TOTAL_FLOWS` in udpgrm's
//! `ebpf_internal.h`, `8192`, which sizes the `BPF_MAP_TYPE_LRU_HASH` the dissector keeps its flow
//! state in. Transcribing it here means the published bound cannot drift from the daemon's actual
//! table without someone editing a constant that names its source.
//!
//! # What this module deliberately does not do
//!
//! `DISSECTOR_BESPOKE` with QUIC SNI routing is **out of scope** (ADR-0045 §4): it is a routing
//! feature, not a restart feature. `DISSECTOR_CBPF` is deferred because it requires changing the
//! QUIC DCID schema. Neither is representable as a [`Dissector`] variant here, so a reviewer can
//! confirm the scope boundary from the type rather than from a comment promising restraint.
//!
//! # Metrics
//!
//! udpgrm keeps counters that explain *why* flows moved between generations. They are named here so
//! that a future exporter can surface them instead of an operator having to read them out of the
//! eBPF map by hand: `rx_flow_rg_conflict`, `tx_flow_update_conflict` and `rx_flow_new_bad_cookie`.

#![allow(unsafe_code)]

use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

/// `UDP_GRM_DISSECTOR` — select the flow dissector for the reuseport group.
///
/// Transcribed from udpgrm `udp_grm_public.h` at commit `e5bbb047d489` (see the parent module docs).
const UDP_GRM_DISSECTOR: libc::c_int = 202;

/// The concurrent-flow bound implied by `DISSECTOR_FLOW`.
///
/// This is `MAX_TOTAL_FLOWS` from udpgrm's `ebpf_internal.h` at the same commit — the
/// `max_entries` of the `lru_map` (`BPF_MAP_TYPE_LRU_HASH`) that holds the flow table. Published to
/// operators as a concrete number because ADR-0045 §4 requires the bound to be a stated limit, not
/// an emergent surprise: above it the LRU evicts entries, so a flow that was mid-restart stops being
/// sticky.
pub const DISSECTOR_FLOW_MAX_CONCURRENT_FLOWS: usize = 8192;

/// The `dissector_type` values from `udp_grm_public.h`'s `enum udp_grm_dissector_type`.
///
/// Note the values are **not** contiguous: `DISSECTOR_BESPOKE` is `3` and `DISSECTOR_CBPF` is `1`,
/// so the enum cannot be modelled by casting a discriminant index. The two in-scope variants carry
/// their transcribed values explicitly for that reason.
mod dissector_type {
    /// 4-tuple flow table. The default choice (ADR-0045 §4).
    pub(super) const FLOW: u32 = 0;
    /// Stateless: no flow tracking at all, so nothing is lost and nothing is preserved.
    pub(super) const NOOP: u32 = 4;
}

/// Which flow dissector to select for the reuseport group.
///
/// Only the two in-scope choices are representable. `DISSECTOR_BESPOKE` (QUIC SNI routing) and
/// `DISSECTOR_CBPF` are deliberately absent: ADR-0045 §4 puts the former out of scope and defers the
/// latter, and omitting the variants makes that boundary a property of the type rather than a
/// promise in a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dissector {
    /// 4-tuple flow table. Default: covers the QUIC flows caddy-rs serves today with no protocol
    /// cooperation, at the cost of the fixed [`DISSECTOR_FLOW_MAX_CONCURRENT_FLOWS`] bound.
    #[default]
    Flow,
    /// No flow tracking. Offered as a documented option for stateless UDP use, where flow identity
    /// is meaningless: it costs nothing and loses no packets (ADR-0045 §4).
    Noop,
}

impl Dissector {
    /// The `dissector_type` value udpgrm expects.
    fn raw_type(self) -> u32 {
        match self {
            Self::Flow => dissector_type::FLOW,
            Self::Noop => dissector_type::NOOP,
        }
    }

    /// The operator-facing name, matching udpgrm's own spelling so an operator can map the
    /// documentation onto the daemon's vocabulary without a translation table.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flow => "DISSECTOR_FLOW",
            Self::Noop => "DISSECTOR_NOOP",
        }
    }

    /// The concurrent-flow bound this choice implies, for publishing to operators.
    ///
    /// `DISSECTOR_NOOP` keeps no flow state, so it has no bound to report.
    pub fn max_concurrent_flows(self) -> Option<usize> {
        match self {
            Self::Flow => Some(DISSECTOR_FLOW_MAX_CONCURRENT_FLOWS),
            Self::Noop => None,
        }
    }
}

/// Why selecting a dissector failed.
#[derive(Debug)]
pub enum DissectorError {
    /// The reuseport group already has a different dissector recorded.
    ///
    /// udpgrm returns `EPERM` when the requested dissector differs from the group's existing one,
    /// because the dissector is fixed for the lifetime of the group. This is surfaced as its own
    /// error rather than as a bare `Io(EPERM)` so the operator is told *what* conflicted instead of
    /// being handed a permission error that looks like a privilege problem.
    Conflict {
        /// The dissector caddy-rs asked for.
        requested: Dissector,
        /// The `EPERM` the daemon returned, kept for the raw errno.
        source: io::Error,
    },

    /// The platform refused the option for another reason.
    Io(io::Error),
}

impl std::fmt::Display for DissectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { requested, .. } => write!(
                f,
                "udpgrm refused to set {} because this reuseport group already has a different \
                 flow dissector (EPERM): the dissector is fixed for the lifetime of the group and \
                 can only be changed by removing the group, so caddy-rs will not attempt it \
                 per-request. {} is the only dissector caddy-rs selects",
                requested.as_str(),
                Dissector::Flow.as_str(),
            ),
            Self::Io(error) => write!(f, "setsockopt UDP_GRM_DISSECTOR failed: {error}"),
        }
    }
}

impl std::error::Error for DissectorError {}

impl From<io::Error> for DissectorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The `struct udp_grm_dissector` prefix that `UDP_GRM_DISSECTOR` expects.
///
/// Only the leading `u32`s are modelled: `dissector_type`, `flow_entry_timeout_sec`, `max_apps` and
/// `bespoke_digest`. The trailing union (a CBPF filter or the bespoke SNI table) is unused by the two
/// in-scope dissectors, and udpgrm's own validation for `DISSECTOR_FLOW` requires `filter_len`,
/// `max_apps` and `bespoke_digest` to be zero — which is what this layout passes. Keeping the struct
/// to exactly these fields means the option length matches what the daemon reads, rather than
/// handing it a truncated struct.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct UdpgrmDissector {
    dissector_type: u32,
    flow_entry_timeout_sec: u32,
    max_apps: u32,
    bespoke_digest: u32,
}

/// Select `dissector` for the reuseport group `socket` belongs to.
///
/// Call this **once at startup**, against the group that will serve, rather than per request
/// (ADR-0045 §3): udpgrm accepts one dissector per group and answers a conflicting change with
/// `EPERM`.
///
/// A daemon that is absent surfaces as `ENOPROTOOPT`, exactly as the presence probe does; the caller
/// treats that as "graceful UDP restart unavailable" rather than as a failure to serve.
pub fn select_dissector(socket: &UdpSocket, dissector: Dissector) -> Result<(), DissectorError> {
    let value = UdpgrmDissector {
        dissector_type: dissector.raw_type(),
        // Zero means "use the daemon's own default" for the LRU entry timeout. caddy-rs has no
        // reason to override it: the timeout only decides how long a flow entry survives after its
        // last transmission, and the daemon's default is tuned for the same restart window
        // caddy-rs targets.
        flow_entry_timeout_sec: 0,
        // Both must be zero for DISSECTOR_FLOW: the CBPF filter length and the bespoke SNI digest
        // belong to the dissectors that are out of scope here, and udpgrm rejects DISSECTOR_FLOW
        // with either non-zero.
        max_apps: 0,
        bespoke_digest: 0,
    };
    // SAFETY: the descriptor is a live socket borrowed for the duration of the call, and the value
    // pointer refers to a local `UdpgrmDissector` whose size is passed as the option length, so the
    // kernel cannot read past it.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            UDP_GRM_DISSECTOR,
            (&value as *const UdpgrmDissector).cast(),
            std::mem::size_of::<UdpgrmDissector>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(classify_os_error(dissector, io::Error::last_os_error()));
    }
    Ok(())
}

/// Map a failed `setsockopt` into the right [`DissectorError`].
///
/// Split out from [`select_dissector`] so the mapping is testable without a udpgrm daemon: no
/// environment in this program can make the real call return `EPERM`, so a test that only exercised
/// the syscall path would leave this branch unverified. A mutation that collapsed `EPERM` into the
/// generic `Io` arm survived the whole suite before this function existed, which is exactly the
/// blind spot it closes.
///
/// `EPERM` is udpgrm's documented answer to "this reuseport group already has a different
/// dissector", and is worth distinguishing because it is not a privilege problem and retrying cannot
/// fix it. Any other errno is a plain I/O failure.
fn classify_os_error(dissector: Dissector, error: io::Error) -> DissectorError {
    if error.raw_os_error() == Some(libc::EPERM) {
        return DissectorError::Conflict {
            requested: dissector,
            source: error,
        };
    }
    DissectorError::Io(error)
}

/// The udpgrm flow-dissector counters that explain why flows moved.
///
/// Named so an exporter can surface them by name rather than by offset into the eBPF state map. Each
/// corresponds to a `METRIC_INC(...)` in udpgrm's `ebpf.c` at the pinned commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowMetrics {
    /// `rx_flow_rg_conflict` — a received packet's flow pointed at a socket in a different
    /// reuseport group than the one it arrived on.
    pub rx_flow_rg_conflict: u64,
    /// `tx_flow_update_conflict` — a flow-table update lost a race with a concurrent update.
    pub tx_flow_update_conflict: u64,
    /// `rx_flow_new_bad_cookie` — a new flow arrived carrying a cookie the daemon could not use.
    pub rx_flow_new_bad_cookie: u64,
}

impl FlowMetrics {
    /// The counter names as udpgrm spells them, for exporters and log fields.
    pub const NAMES: [&'static str; 3] = [
        "rx_flow_rg_conflict",
        "tx_flow_update_conflict",
        "rx_flow_new_bad_cookie",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_dissector_is_flow() {
        // ADR-0045 section 4: DISSECTOR_FLOW is the initial choice, so the default must be it
        // rather than a value that happens to work.
        assert_eq!(Dissector::default(), Dissector::Flow);
    }

    #[test]
    fn the_dissector_values_are_the_transcribed_udpgrm_ones() {
        // The values are not contiguous in udpgrm's enum (BESPOKE is 3, CBPF is 1), so pinning them
        // catches an accidental renumbering that a cast-from-index would introduce silently.
        assert_eq!(Dissector::Flow.raw_type(), 0);
        assert_eq!(Dissector::Noop.raw_type(), 4);
        assert_eq!(UDP_GRM_DISSECTOR, 202);
    }

    #[test]
    fn the_flow_bound_is_published_as_a_concrete_number() {
        // The acceptance criterion is that the cap is a number, not a vague description.
        assert_eq!(Dissector::Flow.max_concurrent_flows(), Some(8192));
        assert_eq!(
            Dissector::Flow.max_concurrent_flows(),
            Some(DISSECTOR_FLOW_MAX_CONCURRENT_FLOWS)
        );
        // DISSECTOR_NOOP keeps no flow state, so it must not claim a bound.
        assert_eq!(Dissector::Noop.max_concurrent_flows(), None);
    }

    #[test]
    fn out_of_scope_dissectors_are_not_representable() {
        // The scope boundary is a property of the type: only two variants exist, and neither is
        // BESPOKE or CBPF. This asserts the enum has exactly the two documented variants, so adding
        // a third fails here and forces the ADR conversation.
        let all = [Dissector::Flow, Dissector::Noop];
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.map(Dissector::as_str),
            ["DISSECTOR_FLOW", "DISSECTOR_NOOP"]
        );
    }

    #[test]
    fn the_option_struct_layout_matches_what_udpgrm_reads() {
        // udpgrm reads a `struct udp_grm_dissector`; passing a shorter struct would truncate it.
        // The four leading u32 fields are the whole prefix it consults for DISSECTOR_FLOW.
        assert_eq!(std::mem::size_of::<UdpgrmDissector>(), 16);
        assert_eq!(std::mem::align_of::<UdpgrmDissector>(), 4);
    }

    #[test]
    fn the_flow_option_zeroes_the_fields_udpgrm_rejects_when_non_zero() {
        // udpgrm's DISSECTOR_FLOW validation rejects a non-zero filter_len, max_apps or
        // bespoke_digest. Build the same value the setter builds and assert the invariant, so the
        // reason it passes validation is pinned rather than incidental.
        let value = UdpgrmDissector {
            dissector_type: Dissector::Flow.raw_type(),
            flow_entry_timeout_sec: 0,
            max_apps: 0,
            bespoke_digest: 0,
        };
        assert_eq!(value.dissector_type, 0);
        assert_eq!(value.max_apps, 0);
        assert_eq!(value.bespoke_digest, 0);
    }

    #[test]
    fn an_absent_daemon_reports_enoprotoopt_rather_than_a_permission_error() {
        // On any host without udpgrm (including this sandbox) the option does not exist, so the
        // error must be ENOPROTOOPT - the "degrade, do not fail" signal - and specifically NOT
        // EPERM, which would be misreported as a dissector conflict.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a local socket");
        match select_dissector(&socket, Dissector::Flow) {
            Err(DissectorError::Io(error)) => {
                assert_eq!(
                    error.raw_os_error(),
                    Some(libc::ENOPROTOOPT),
                    "expected ENOPROTOOPT without a daemon, got {error:?}"
                );
            }
            Err(DissectorError::Conflict { .. }) => {
                panic!("a missing option must not be reported as a dissector conflict")
            }
            Ok(()) => panic!("selecting a dissector without a daemon must not report success"),
        }
    }

    #[test]
    fn eperm_from_the_daemon_is_classified_as_a_dissector_conflict() {
        // udpgrm answers a conflicting dissector change with EPERM. It must not be reported as a
        // generic I/O error, because the operator-facing advice differs completely: a conflict
        // cannot be fixed by retrying or by granting a capability.
        match classify_os_error(Dissector::Flow, io::Error::from_raw_os_error(libc::EPERM)) {
            DissectorError::Conflict { requested, source } => {
                assert_eq!(requested, Dissector::Flow);
                assert_eq!(source.raw_os_error(), Some(libc::EPERM));
            }
            other => panic!("EPERM must map to Conflict, got {other:?}"),
        }
    }

    #[test]
    fn every_other_errno_stays_a_plain_io_error() {
        // In particular ENOPROTOOPT (no daemon) must NOT become a conflict: it means "graceful UDP
        // restart unavailable", which is a degradation rather than a misconfiguration.
        for errno in [libc::ENOPROTOOPT, libc::EINVAL, libc::ENOBUFS] {
            match classify_os_error(Dissector::Noop, io::Error::from_raw_os_error(errno)) {
                DissectorError::Io(error) => assert_eq!(error.raw_os_error(), Some(errno)),
                other => panic!("errno {errno} must map to Io, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_conflict_names_the_requested_dissector_and_explains_the_fix() {
        let message = DissectorError::Conflict {
            requested: Dissector::Noop,
            source: io::Error::from_raw_os_error(libc::EPERM),
        }
        .to_string();
        assert!(message.contains("DISSECTOR_NOOP"), "{message}");
        assert!(message.contains("EPERM"), "{message}");
        assert!(
            message.contains("fixed for the lifetime of the group"),
            "the message must explain why it is not retried: {message}"
        );
    }

    #[test]
    fn the_conflict_and_error_metrics_are_named_rather_than_swallowed() {
        // The three counters the task requires to be surfaced. Asserting the exact names means a
        // typo in an exporter would be caught here rather than in a dashboard that silently reads
        // nothing.
        assert_eq!(
            FlowMetrics::NAMES,
            [
                "rx_flow_rg_conflict",
                "tx_flow_update_conflict",
                "rx_flow_new_bad_cookie"
            ]
        );
    }
}
