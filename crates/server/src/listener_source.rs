//! Where `run` gets its listeners from (ADR-0047 §4, §7; DIV-0158).
//!
//! With fdstore mode enabled, `run` does not bind: the `bind-fds` helper already bound the sockets
//! and stored them in `systemd`'s fd store, and `run` adopts them through the existing
//! [`crate::activation`] machinery. Only the *provenance* changes — the descriptors arrive from the
//! fd store rather than from a `.socket` unit — so adoption, validation and matching are the same
//! code path in both cases.
//!
//! # No silent fallback
//!
//! A planned listener with no matching stored descriptor is a **loud failure** that names what was
//! planned and what was found. Falling back to binding would re-introduce the privilege
//! requirement this mode exists to remove, and would mask a misconfiguration: the unit would look
//! healthy while the server had quietly regained the ability to bind privileged ports.
//!
//! # TCP only
//!
//! UDP listeners under fdstore mode fail loudly naming the missing prerequisite. caddy-rs has no
//! UDP socket activation at all (`DIV-0040`), and ADR-0045 explains why UDP restart needs
//! `SO_REUSEPORT` plus eBPF rather than an inherited listener. Uploading a bound UDP socket would
//! let packets queue on the stored socket while the service is stopped, but that is **not** QUIC
//! flow preservation and must never be described as such.

use std::collections::BTreeSet;
use std::fmt;

use caddy_rs_core::Network;

/// Where `run` obtains its listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ListenerSource {
    /// Bind the configured listeners directly. The default, and unchanged behaviour.
    #[default]
    Bind,
    /// Adopt the descriptors the `bind-fds` helper stored in `systemd`'s fd store.
    Fdstore,
}

impl ListenerSource {
    /// Parse the `--listener-source` value.
    pub fn parse(value: &str) -> Result<Self, ListenerSourceError> {
        match value {
            "bind" => Ok(Self::Bind),
            "fdstore" => Ok(Self::Fdstore),
            other => Err(ListenerSourceError::UnknownValue {
                value: other.to_string(),
            }),
        }
    }

    /// The value as it appears on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Fdstore => "fdstore",
        }
    }

    /// Whether this source needs the fd store.
    pub fn is_fdstore(self) -> bool {
        matches!(self, Self::Fdstore)
    }
}

impl fmt::Display for ListenerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A planned listener that cannot be served from the fd store, or an inconsistency in the source.
#[derive(Debug)]
pub enum ListenerSourceError {
    /// `--listener-source` was given a value that is not `bind` or `fdstore`.
    UnknownValue { value: String },
    /// A UDP listener is planned but fdstore mode cannot serve it (ADR-0047 §7, DIV-0040).
    UdpUnsupported { addresses: Vec<String> },
    /// A planned listener has no matching stored descriptor. The message names both sides.
    PlannedWithoutDescriptor {
        missing: Vec<String>,
        found: Vec<String>,
    },
}

impl fmt::Display for ListenerSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownValue { value } => write!(
                f,
                "unknown listener source {value:?}: expected \"bind\" or \"fdstore\""
            ),
            Self::UdpUnsupported { addresses } => write!(
                f,
                "fdstore mode cannot serve UDP listeners ({}): caddy-rs has no UDP socket \
                 activation, so a UDP listener cannot be pre-bound and adopted. UDP socket \
                 activation is a prerequisite that does not exist yet (DIV-0040, ADR-0045). \
                 Remove the UDP listener, or use the default bind mode",
                addresses.join(", ")
            ),
            Self::PlannedWithoutDescriptor { missing, found } => write!(
                f,
                "fdstore mode is enabled but no stored descriptor matches the planned \
                 listeners. Planned: [{}]. Found in the fd store: [{}]. Refusing to fall back to \
                 binding: that would silently re-introduce the CAP_NET_BIND_SERVICE requirement \
                 this mode exists to remove. Check that bind-fds ran as this unit's \
                 ExecStartPre=+ and stored these names (ADR-0047 §4)",
                missing.join(", "),
                if found.is_empty() {
                    "nothing".to_string()
                } else {
                    found.join(", ")
                }
            ),
        }
    }
}

impl std::error::Error for ListenerSourceError {}

/// A listener the plan expects the fd store to provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedListenerRef {
    /// The `FDNAME` the helper stored this listener under.
    pub fd_name: String,
    /// The transport network, so UDP can be rejected before any descriptor is consulted.
    pub network: Network,
}

/// Check that fdstore mode can serve `planned`, given the FD names actually `found` in the store.
///
/// This is the gate that makes "no silent fallback" real: it runs before any descriptor is adopted,
/// and returns an error naming both what was planned and what was found. `found` is the set of
/// `FDNAME`s the store reported; anything outside the plan is ignored here (ADR-0047 §4: stored FDs
/// outside the plan are logged at debug and ignored).
pub fn check_fdstore_coverage(
    planned: &[PlannedListenerRef],
    found: &BTreeSet<String>,
) -> Result<(), ListenerSourceError> {
    // UDP first: it is a configuration error independent of what happens to be stored, and its
    // message must name the missing prerequisite rather than a missing descriptor.
    let udp: Vec<String> = planned
        .iter()
        .filter(|entry| entry.network == Network::Udp)
        .map(|entry| entry.fd_name.clone())
        .collect();
    if !udp.is_empty() {
        return Err(ListenerSourceError::UdpUnsupported { addresses: udp });
    }

    let missing: Vec<String> = planned
        .iter()
        .filter(|entry| !found.contains(&entry.fd_name))
        .map(|entry| entry.fd_name.clone())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    // Report what was found, restricted to planned names that ARE present, so the operator can see
    // which half of the plan made it. Listing every stored name would bury the useful signal.
    let found_and_planned: Vec<String> = planned
        .iter()
        .filter(|entry| found.contains(&entry.fd_name))
        .map(|entry| entry.fd_name.clone())
        .collect();
    Err(ListenerSourceError::PlannedWithoutDescriptor {
        missing,
        found: found_and_planned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planned(names: &[(&str, Network)]) -> Vec<PlannedListenerRef> {
        names
            .iter()
            .map(|(name, network)| PlannedListenerRef {
                fd_name: (*name).to_string(),
                network: *network,
            })
            .collect()
    }

    fn found(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn parses_both_values_and_rejects_anything_else() {
        assert_eq!(ListenerSource::parse("bind").unwrap(), ListenerSource::Bind);
        assert_eq!(
            ListenerSource::parse("fdstore").unwrap(),
            ListenerSource::Fdstore
        );
        assert!(
            ListenerSource::parse("Fdstore").is_err(),
            "the value is case-sensitive"
        );
        assert!(ListenerSource::parse("socket").is_err());
        assert_eq!(ListenerSource::default(), ListenerSource::Bind);
    }

    #[test]
    fn a_fully_covered_plan_passes() {
        let plan = planned(&[("a", Network::Tcp), ("b", Network::Tcp)]);
        assert!(check_fdstore_coverage(&plan, &found(&["a", "b"])).is_ok());
    }

    #[test]
    fn stored_descriptors_outside_the_plan_are_ignored() {
        // ADR-0047 §4: stored FDs outside the plan are ignored, not an error.
        let plan = planned(&[("a", Network::Tcp)]);
        assert!(check_fdstore_coverage(&plan, &found(&["a", "stale-old-site"])).is_ok());
    }

    #[test]
    fn a_planned_listener_without_a_descriptor_names_both_sides() {
        let plan = planned(&[
            ("a", Network::Tcp),
            ("b", Network::Tcp),
            ("c", Network::Tcp),
        ]);
        let error = check_fdstore_coverage(&plan, &found(&["a"])).unwrap_err();
        let message = error.to_string();

        // The message must name what was planned and what was found - the acceptance criterion.
        assert!(
            message.contains("Planned:"),
            "must name the planned side: {message}"
        );
        assert!(
            message.contains('b') && message.contains('c'),
            "must name the missing entries"
        );
        assert!(
            message.contains("Found in the fd store: [a]"),
            "must name the found side"
        );
        // And it must say why falling back is refused, so the operator understands the stakes.
        assert!(message.contains("CAP_NET_BIND_SERVICE"));
        assert!(message.contains("Refusing to fall back"));
    }

    #[test]
    fn an_empty_store_reports_nothing_found_rather_than_an_empty_list() {
        let plan = planned(&[("a", Network::Tcp)]);
        let error = check_fdstore_coverage(&plan, &found(&[])).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("Found in the fd store: [nothing]"),
            "an empty store must read as 'nothing', not '[]': {message}"
        );
    }

    #[test]
    fn a_udp_listener_fails_naming_the_missing_prerequisite() {
        let plan = planned(&[("tcp-a", Network::Tcp), ("udp-b", Network::Udp)]);
        // Even with every descriptor present, UDP must fail: the problem is the prerequisite, not
        // the store contents.
        let error = check_fdstore_coverage(&plan, &found(&["tcp-a", "udp-b"])).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("UDP"), "must name UDP: {message}");
        assert!(
            message.contains("udp-b"),
            "must name the offending listener"
        );
        assert!(
            message.contains("socket activation") && message.contains("prerequisite"),
            "must name the missing prerequisite: {message}"
        );
        assert!(message.contains("DIV-0040"));
        // It must NOT be reported as a missing descriptor: that would send the operator to look for
        // a stored socket instead of at the missing feature.
        assert!(!message.contains("no stored descriptor"));
    }

    #[test]
    fn udp_is_reported_before_missing_descriptors() {
        // Both problems present: the configuration error is the one worth surfacing, because it
        // cannot be fixed by running the helper again.
        let plan = planned(&[("udp-b", Network::Udp), ("tcp-a", Network::Tcp)]);
        let error = check_fdstore_coverage(&plan, &found(&[])).unwrap_err();
        assert!(matches!(error, ListenerSourceError::UdpUnsupported { .. }));
    }

    #[test]
    fn an_empty_plan_is_vacuously_covered() {
        assert!(check_fdstore_coverage(&[], &found(&[])).is_ok());
    }
}
