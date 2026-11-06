//! Capability grants.
//!
//! The plugin host has **no ambient authority**: a WASM plugin cannot touch the filesystem,
//! network, clock or randomness unless the host operator explicitly grants a capability and the
//! plugin asks for it while negotiating its descriptor. Two gates exist:
//!
//! 1. [`CapabilityPolicy`] is the host-side allow-list (operator policy). A capability that is not
//!    in the policy is never granted, even if the plugin requests it.
//! 2. The plugin descriptor lists the raw capability codes it requests. Codes unknown to this ABI
//!    version are rejected (not ignored), because ignoring them would let a plugin compiled for a
//!    newer minor version run with silently missing functionality.
//!
//! Capability codes and their required host calls are stable ABI. This module defines the
//! vocabulary and the grant algorithm; the host runtime (T-PLUG-011) enforces it.

use serde::{Deserialize, Serialize};

use crate::error::CapabilityError;

/// Maximum number of capabilities a single plugin descriptor may request.
pub const MAX_REQUESTED_CAPABILITIES: usize = 16;

/// A capability a plugin can be granted.
///
/// Numeric codes are part of the ABI and must never be renumbered. Capabilities are deliberately
/// coarse: they grant a class of host calls, not individual operations. There is no filesystem or
/// raw-socket capability in ABI v1 — those host calls do not exist yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum Capability {
    /// Emit structured log records through the host (host call 1).
    Log = 1,
    /// Read the host's monotonic/wall clock (host call 2).
    Clock = 2,
    /// Obtain host-provided random bytes (host call 3).
    Random = 3,
    /// Perform generation-scoped outbound HTTP requests through the host (host call 4). This is
    /// the only network access a plugin can obtain; it is proxied and governed by the host.
    HttpClient = 4,
    /// Read a snapshot of the configuration that loaded the plugin (host call 5), never the live
    /// mutable configuration.
    ConfigRead = 5,
}

impl Capability {
    /// Every capability defined by this ABI version, in numeric order.
    pub const ALL: [Capability; 5] = [
        Capability::Log,
        Capability::Clock,
        Capability::Random,
        Capability::HttpClient,
        Capability::ConfigRead,
    ];

    /// Stable numeric code used on the wire and in descriptors.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Decode a wire code, returning `None` for codes this ABI version does not define.
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Capability::Log),
            2 => Some(Capability::Clock),
            3 => Some(Capability::Random),
            4 => Some(Capability::HttpClient),
            5 => Some(Capability::ConfigRead),
            _ => None,
        }
    }

    /// Stable human-readable name (for diagnostics and documentation; not used for matching).
    pub const fn name(self) -> &'static str {
        match self {
            Capability::Log => "log",
            Capability::Clock => "clock",
            Capability::Random => "random",
            Capability::HttpClient => "http_client",
            Capability::ConfigRead => "config_read",
        }
    }

    /// Bit used in [`CapabilitySet`].
    pub const fn bit(self) -> u64 {
        1 << (self.code() - 1)
    }
}

/// A compact set of granted capabilities.
///
/// The representation is a `u64` bitmask with bit `N-1` for capability code `N`; only bits for
/// capabilities defined by this ABI version are ever set by this crate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    /// No capabilities (the secure default).
    pub const EMPTY: Self = Self(0);

    /// Every capability defined by ABI v1.
    pub const ALL_V1: Self = Self(
        Capability::Log.bit()
            | Capability::Clock.bit()
            | Capability::Random.bit()
            | Capability::HttpClient.bit()
            | Capability::ConfigRead.bit(),
    );

    /// Build a set from an iterator of capabilities.
    pub fn from_capabilities(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        let mut set = Self::EMPTY;
        for capability in capabilities {
            set = set.with(capability);
        }
        set
    }

    /// Whether `capability` is contained.
    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// Add a capability, returning the new set.
    pub const fn with(self, capability: Capability) -> Self {
        Self(self.0 | capability.bit())
    }

    /// Union of two sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Raw bitmask (stable representation; only ABI-defined bits are used).
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Iterate over the capabilities in this set, in numeric order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |capability| self.contains(*capability))
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Host-side capability allow-list. Defaults to denying everything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapabilityPolicy {
    allowed: CapabilitySet,
}

impl CapabilityPolicy {
    /// Policy that grants nothing (secure default).
    pub const fn deny_all() -> Self {
        Self {
            allowed: CapabilitySet::EMPTY,
        }
    }

    /// Policy that grants every capability defined by ABI v1.
    pub const fn grant_all_v1() -> Self {
        Self {
            allowed: CapabilitySet::ALL_V1,
        }
    }

    /// Policy that grants exactly the given set.
    pub const fn new(allowed: CapabilitySet) -> Self {
        Self { allowed }
    }

    /// Build a policy from an iterator of capabilities.
    pub fn with_capabilities(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self::new(CapabilitySet::from_capabilities(capabilities))
    }

    /// The allow-list.
    pub const fn allowed(self) -> CapabilitySet {
        self.allowed
    }
}

/// Grant requested capability codes against an operator policy.
///
/// Order of checks (all failures are located and typed):
///
/// 1. `requested` may not exceed [`MAX_REQUESTED_CAPABILITIES`];
/// 2. every code must be defined by this ABI version, otherwise the plugin fails with
///    [`CapabilityError::Unsupported`] (forward-compatible rejection, never a silent drop);
/// 3. duplicated codes are rejected with [`CapabilityError::Duplicate`];
/// 4. a known code outside the host policy is rejected with [`CapabilityError::NotGranted`].
///
/// The returned set is exactly the requested-and-granted capabilities; the order of `requested` is
/// irrelevant to the result.
pub fn grant_capabilities(
    requested: &[u32],
    policy: &CapabilityPolicy,
) -> Result<CapabilitySet, CapabilityError> {
    if requested.len() > MAX_REQUESTED_CAPABILITIES {
        return Err(CapabilityError::TooMany {
            count: requested.len(),
            max: MAX_REQUESTED_CAPABILITIES,
        });
    }
    let mut granted = CapabilitySet::EMPTY;
    let mut seen = CapabilitySet::EMPTY;
    for code in requested {
        let Some(capability) = Capability::from_code(*code) else {
            return Err(CapabilityError::Unsupported { code: *code });
        };
        if seen.contains(capability) {
            return Err(CapabilityError::Duplicate { code: *code });
        }
        seen = seen.with(capability);
        if !policy.allowed().contains(capability) {
            return Err(CapabilityError::NotGranted { capability });
        }
        granted = granted.with(capability);
    }
    Ok(granted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_codes_are_stable() {
        assert_eq!(Capability::Log.code(), 1);
        assert_eq!(Capability::Clock.code(), 2);
        assert_eq!(Capability::Random.code(), 3);
        assert_eq!(Capability::HttpClient.code(), 4);
        assert_eq!(Capability::ConfigRead.code(), 5);
        for capability in Capability::ALL {
            assert_eq!(
                Capability::from_code(capability.code()),
                Some(capability),
                "code {} must round-trip",
                capability.code()
            );
        }
        assert_eq!(Capability::from_code(0), None);
        assert_eq!(Capability::from_code(6), None);
        assert_eq!(Capability::from_code(u32::MAX), None);
    }

    #[test]
    fn capability_sets_round_trip_bits() {
        let set = CapabilitySet::from_capabilities([Capability::Log, Capability::HttpClient]);
        assert_eq!(set.bits(), 1 | (1 << 3));
        assert!(set.contains(Capability::Log));
        assert!(!set.contains(Capability::Clock));
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![Capability::Log, Capability::HttpClient]
        );
        assert_eq!(CapabilitySet::ALL_V1.iter().count(), Capability::ALL.len());
        assert_eq!(CapabilitySet::ALL_V1.bits(), 0b1_1111);
        assert!(CapabilitySet::EMPTY.is_empty());
        assert!(!CapabilitySet::EMPTY.contains(Capability::Log));
    }

    #[test]
    fn grants_intersect_request_and_policy() {
        let policy = CapabilityPolicy::with_capabilities([Capability::Log, Capability::Clock]);
        let granted = grant_capabilities(&[1, 2], &policy).expect("granted");
        assert_eq!(
            granted,
            CapabilitySet::from_capabilities([Capability::Log, Capability::Clock])
        );
        // Requesting only a subset is fine.
        assert_eq!(
            grant_capabilities(&[2], &policy).expect("subset"),
            CapabilitySet::from_capabilities([Capability::Clock])
        );
        // An empty request is fine.
        assert_eq!(
            grant_capabilities(&[], &policy).expect("empty"),
            CapabilitySet::EMPTY
        );
    }

    #[test]
    fn unsupported_and_ungranted_capabilities_are_rejected() {
        let policy = CapabilityPolicy::grant_all_v1();
        assert_eq!(
            grant_capabilities(&[99], &policy),
            Err(CapabilityError::Unsupported { code: 99 })
        );
        assert_eq!(
            grant_capabilities(&[1, 2, 1], &policy),
            Err(CapabilityError::Duplicate { code: 1 })
        );
        let denied = CapabilityPolicy::deny_all();
        assert_eq!(
            grant_capabilities(&[1], &denied),
            Err(CapabilityError::NotGranted {
                capability: Capability::Log
            })
        );
        let too_many: Vec<u32> = std::iter::repeat_n(1, MAX_REQUESTED_CAPABILITIES + 1).collect();
        assert!(matches!(
            grant_capabilities(&too_many, &policy),
            Err(CapabilityError::TooMany { .. })
        ));
    }

    #[test]
    fn policies_have_secure_defaults() {
        assert_eq!(CapabilityPolicy::default(), CapabilityPolicy::deny_all());
        assert_eq!(
            CapabilityPolicy::grant_all_v1().allowed(),
            CapabilitySet::ALL_V1
        );
        assert!(CapabilityPolicy::deny_all().allowed().is_empty());
    }
}
