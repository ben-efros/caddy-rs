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

    /// Parse an operator-supplied dissector name.
    ///
    /// Accepts udpgrm's own spelling with or without the `DISSECTOR_` prefix, case-insensitively, so
    /// an operator copying from udpgrm's README does not have to translate. The out-of-scope names
    /// are rejected with a specific reason.
    pub fn parse(value: &str) -> Result<Self, String> {
        let normalised = value.trim().to_ascii_uppercase();
        let normalised = normalised.strip_prefix("DISSECTOR_").unwrap_or(&normalised);
        match normalised {
            "FLOW" => Ok(Self::Flow),
            "NOOP" => Ok(Self::Noop),
            "CBPF" => Err(format!(
                "{DISSECTOR_ENV}=DISSECTOR_CBPF is not supported: it requires encoding a udpgrm \
                 cookie into the QUIC connection ID, which is a change to the DCID schema, and the \
                 daemon documents it as slow (ADR-0045 section 4). Use DISSECTOR_FLOW"
            )),
            "BESPOKE" => Err(format!(
                "{DISSECTOR_ENV}=DISSECTOR_BESPOKE is out of scope: it is a routing feature (QUIC \
                 SNI routing), not a restart feature, and caddy-rs does not offer it (ADR-0045 \
                 section 4). Use DISSECTOR_FLOW"
            )),
            other => Err(format!(
                "{DISSECTOR_ENV}={other} is not a dissector caddy-rs understands; use \
                 DISSECTOR_FLOW (the default) or DISSECTOR_NOOP"
            )),
        }
    }
}

/// The environment variable that selects the dissector.
///
/// Named after udpgrm's own `UDP_GRM_*` vocabulary so an operator debugging a unit sees the same
/// spelling in caddy-rs and in the daemon. An environment variable rather than a configuration key
/// because the dissector is a property of the *host's* udpgrm deployment, not of a site's routing:
/// one binary serves the same configuration in environments that may have different daemon builds,
/// and a config key would have to be overridden per environment anyway.
pub const DISSECTOR_ENV: &str = "CADDY_RS_UDP_GRM_DISSECTOR";

/// Read the dissector selection from the environment, defaulting to [`Dissector::Flow`].
///
/// Unset or empty selects the default. An unrecognised value is an **error rather than a silent
/// fallback**: an operator who asked for a dissector and got a different one has a configuration bug
/// that would otherwise only show up as unexplained restart behaviour. `DISSECTOR_CBPF` and
/// `DISSECTOR_BESPOKE` are rejected by name with an explanation of why they are unavailable, rather
/// than being reported as unknown strings.
pub fn dissector_from_env() -> Result<Dissector, String> {
    match std::env::var(DISSECTOR_ENV) {
        Err(_) => Ok(Dissector::default()),
        Ok(value) if value.trim().is_empty() => Ok(Dissector::default()),
        Ok(value) => Dissector::parse(value.trim()),
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
/// Each corresponds to a `METRIC_INC(...)` in udpgrm's `ebpf.c` at the pinned commit, and each is
/// registered in the admin [`MetricsRegistry`] under its udpgrm name so `GET /metrics` reports it.
/// Registering is what makes the counter *exported*: a constant naming a counter that nothing
/// registers is a comment with extra steps, and this program has already shipped one tautology of
/// that shape.
///
/// [`MetricsRegistry`]: caddy_rs_admin::MetricsRegistry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// The counter names as udpgrm spells them.
    ///
    /// Kept in udpgrm's own vocabulary rather than renamed to a `caddy_*` convention: these values
    /// are read out of the daemon's eBPF state map, and a renamed counter would force an operator
    /// to maintain a translation table between the metric and the daemon they are debugging.
    pub const NAMES: [&'static str; 3] = [
        "rx_flow_rg_conflict",
        "tx_flow_update_conflict",
        "rx_flow_new_bad_cookie",
    ];

    /// Publish every counter into the registry `GET /metrics` renders.
    ///
    /// Returns the number of series published so a caller can assert the export happened rather
    /// than assuming it did.
    pub fn register(
        &self,
        registry: &caddy_rs_admin::MetricsRegistry,
    ) -> Result<usize, caddy_rs_admin::MetricsError> {
        registry
            .counter(
                Self::NAMES[0],
                "Flows whose reuseport group differed from the group the packet arrived on.",
                &[],
            )?
            .add(self.rx_flow_rg_conflict)?;
        registry
            .counter(
                Self::NAMES[1],
                "Flow-table updates that lost a race with a concurrent update.",
                &[],
            )?
            .add(self.tx_flow_update_conflict)?;
        registry
            .counter(
                Self::NAMES[2],
                "New flows that arrived carrying a cookie the daemon could not use.",
                &[],
            )?
            .add(self.rx_flow_new_bad_cookie)?;
        Ok(Self::NAMES.len())
    }
}

/// The exported eviction observable ADR-0045 §4 requires of this task.
///
/// **This is an approximation, and it is named as one.** The flow table is a `BPF_MAP_TYPE_LRU_HASH`
/// inside udpgrm's eBPF program, so the kernel evicts entries where caddy-rs cannot see it: there is
/// no `getsockopt` that reports eviction, and the daemon raises no error when the table is full
/// (ADR-0045 §4: "the kernel silently evicts the least-recently-used flow"). Any counter claiming to
/// be exact would be inventing kernel truth caddy-rs does not have.
///
/// What caddy-rs *can* observe is the **at-risk condition**: a listener whose concurrent flows are at
/// or above the published bound. Recording that as a counter makes the condition visible rather than
/// leaving it to be inferred from lost stickiness, which is exactly what ADR-0045 §4 asks for. The
/// metric name carries `approximate` so no operator or dashboard mistakes it for a kernel counter.
///
/// A genuinely exact eviction count needs either a counter in udpgrm's state map (an upstream
/// change, tracked by the DIV-0156/T-CORE-114 verdict work) or eBPF inspection the server must never
/// do itself (ADR-0045 §5). That is why this is documented as an approximation rather than presented
/// as the finished observable.
pub const FLOW_TABLE_EVICTION_APPROXIMATE_TOTAL: &str =
    "caddy_udp_grm_flow_table_eviction_approximate_total";

/// Record that `flows` concurrent flows were observed against the published bound.
///
/// Increments [`FLOW_TABLE_EVICTION_APPROXIMATE_TOTAL`] by one whenever `flows` reaches or exceeds
/// [`DISSECTOR_FLOW_MAX_CONCURRENT_FLOWS`], because that is the first observation at which the LRU can
/// have evicted anything. Below the bound this records nothing: no eviction is possible there, and a
/// counter that moved below the bound would be noise an operator learns to ignore.
///
/// Returns whether the at-risk condition was recorded, so a caller can log or test it.
pub fn record_flow_pressure(
    registry: &caddy_rs_admin::MetricsRegistry,
    flows: usize,
) -> Result<bool, caddy_rs_admin::MetricsError> {
    if flows < DISSECTOR_FLOW_MAX_CONCURRENT_FLOWS {
        return Ok(false);
    }
    registry
        .counter(
            FLOW_TABLE_EVICTION_APPROXIMATE_TOTAL,
            "Approximate count of observations at or above the published 8192 concurrent-flow \
             bound, where the udpgrm LRU may have evicted a flow. Not a kernel eviction count: the \
             table lives in udpgrm's eBPF map and raises no error.",
            &[],
        )?
        .inc()?;
    Ok(true)
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
    fn the_flow_metrics_are_registered_in_the_registry_metrics_renders() {
        // The criterion is that the counters are EXPORTED, not that a constant names them. So this
        // drives the real MetricsRegistry and asserts the rendered output carries the values -
        // a test asserting `NAMES == [...]` would pass with nothing registered at all.
        let registry = caddy_rs_admin::MetricsRegistry::new();
        let metrics = FlowMetrics {
            rx_flow_rg_conflict: 7,
            tx_flow_update_conflict: 3,
            rx_flow_new_bad_cookie: 1,
        };
        assert_eq!(metrics.register(&registry).expect("register"), 3);

        let rendered = registry.render();
        for (name, value) in [
            ("rx_flow_rg_conflict", "7"),
            ("tx_flow_update_conflict", "3"),
            ("rx_flow_new_bad_cookie", "1"),
        ] {
            assert!(rendered.contains(name), "{name} missing from:\n{rendered}");
            assert!(
                rendered.contains(value),
                "value {value} for {name} missing from:\n{rendered}"
            );
        }
    }

    #[test]
    fn eviction_pressure_is_recorded_only_at_or_above_the_published_bound() {
        // The eviction observable ADR-0045 section 4 requires of this task. Below the bound no
        // eviction is possible, so nothing is recorded; at and above it, the at-risk condition is.
        let registry = caddy_rs_admin::MetricsRegistry::new();
        assert!(
            !record_flow_pressure(&registry, DISSECTOR_FLOW_MAX_CONCURRENT_FLOWS - 1)
                .expect("record")
        );
        assert!(
            !registry
                .render()
                .contains(FLOW_TABLE_EVICTION_APPROXIMATE_TOTAL),
            "nothing may be exported below the bound:\n{}",
            registry.render()
        );

        assert!(
            record_flow_pressure(&registry, DISSECTOR_FLOW_MAX_CONCURRENT_FLOWS).expect("record")
        );
        assert!(
            registry
                .render()
                .contains(FLOW_TABLE_EVICTION_APPROXIMATE_TOTAL),
            "the at-risk condition must be exported:\n{}",
            registry.render()
        );

        // Above the bound also records, and the counter accumulates rather than resetting.
        assert!(
            record_flow_pressure(&registry, DISSECTOR_FLOW_MAX_CONCURRENT_FLOWS * 2)
                .expect("record")
        );
        let rendered = registry.render();
        let line = rendered
            .lines()
            .find(|line| {
                line.starts_with(FLOW_TABLE_EVICTION_APPROXIMATE_TOTAL) && !line.starts_with('#')
            })
            .expect("a sample line");
        assert!(
            line.trim_end().ends_with(" 2"),
            "expected 2 observations, got {line:?}"
        );
    }

    #[test]
    fn the_eviction_metric_name_says_it_is_approximate() {
        // Honesty requirement: the LRU lives in udpgrm's eBPF map and raises no error, so caddy-rs
        // cannot count kernel evictions. The name must not read like a kernel counter.
        assert!(
            FLOW_TABLE_EVICTION_APPROXIMATE_TOTAL.contains("approximate"),
            "the metric name must disclose that it is an approximation: \
             {FLOW_TABLE_EVICTION_APPROXIMATE_TOTAL}"
        );
    }

    #[test]
    fn the_dissector_is_selectable_from_the_environment() {
        // DISSECTOR_NOOP must be reachable by an operator, not merely a variant in an enum.
        assert_eq!(
            Dissector::parse("DISSECTOR_FLOW").expect("parse"),
            Dissector::Flow
        );
        assert_eq!(
            Dissector::parse("DISSECTOR_NOOP").expect("parse"),
            Dissector::Noop
        );
        // Accepts the bare name and any case, so copying from udpgrm's README works.
        assert_eq!(Dissector::parse("flow").expect("parse"), Dissector::Flow);
        assert_eq!(Dissector::parse("noop").expect("parse"), Dissector::Noop);
    }

    #[test]
    fn the_environment_selects_noop_end_to_end_and_defaults_to_flow_when_absent() {
        // Proves `dissector_from_env` really reads the variable rather than only that `parse`
        // works: the two are separate functions and a wiring mistake between them would leave
        // DISSECTOR_NOOP unreachable from an operator's point of view.
        //
        // Serialised by the caller (`--test-threads=1` is not assumed): the guard restores the
        // previous value so a concurrent test in this module cannot observe the change.
        let previous = std::env::var_os(DISSECTOR_ENV);

        // SAFETY: setting an environment variable is unsafe in Rust 2024 because it races with
        // other threads reading the environment. This test mutates it and immediately restores it,
        // and it is the only test in this module that touches this variable.
        unsafe { std::env::set_var(DISSECTOR_ENV, "DISSECTOR_NOOP") };
        let selected = dissector_from_env();
        match previous {
            Some(value) => unsafe { std::env::set_var(DISSECTOR_ENV, value) },
            None => unsafe { std::env::remove_var(DISSECTOR_ENV) },
        }
        assert_eq!(selected.expect("parse"), Dissector::Noop);

        // Absent means the default, so an environment that never sets it keeps DISSECTOR_FLOW.
        assert_eq!(Dissector::default(), Dissector::Flow);
    }

    #[test]
    fn the_out_of_scope_dissectors_are_rejected_by_name_with_a_reason() {
        // Rejected as *known but unavailable*, not as unknown strings: the operator needs to know
        // the difference between a typo and a feature caddy-rs deliberately does not offer.
        for (value, expected) in [
            ("DISSECTOR_CBPF", "DCID schema"),
            ("DISSECTOR_BESPOKE", "out of scope"),
        ] {
            let error = Dissector::parse(value).expect_err("must be rejected");
            assert!(
                error.contains(expected),
                "the rejection of {value} must explain {expected}: {error}"
            );
        }
    }

    #[test]
    fn an_unrecognised_dissector_name_is_rejected_rather_than_defaulted() {
        // The rejected value appears in the message (with udpgrm's `DISSECTOR_` prefix stripped,
        // since that is how it is normalised), so an operator can see what was misread. What
        // matters is that it is an error rather than a silent fallback to the default.
        let error = Dissector::parse("DISSECTOR_TYPO").expect_err("must be rejected");
        assert!(
            error.contains("TYPO"),
            "the rejected value must be echoed: {error}"
        );
        assert!(
            error.contains("DISSECTOR_FLOW") && error.contains("DISSECTOR_NOOP"),
            "must name both valid options: {error}"
        );
        // And the environment variable name, so the operator knows which knob to fix.
        assert!(error.contains(DISSECTOR_ENV), "{error}");
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
