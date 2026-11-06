//! Adaptive ACME challenge-type selection (T-TLS-076, DIV-0097).
//!
//! Mirrors acmez v3.1.7's randomized preferred-challenge ordering ([`client.go`]): every
//! challenge type the CA offers is added to a preference pool, the pool is shuffled **once** at
//! the first fill, each attempted challenge updates per-type success statistics, and the pool is
//! then re-sorted **stably** by descending success ratio so higher-ratio types are preferred on
//! later issuances. A challenge type that has never been attempted has ratio 1.0, exactly like
//! acmez's `challengeHistory.successRatio`; ties keep their previous (randomized) order, exactly
//! like Go's `sort.Stable`.
//!
//! [`client.go`]: https://github.com/caddyserver/caddy/blob/v2.11.7/go.mod (acmez/v3 v3.1.7)
//!
//! Randomness comes from `ring::rand::SystemRandom` through an injectable [`ChallengeRng`]; acmez
//! deliberately uses weak `math/rand` (seeded once per process, mutex-guarded), and this
//! strengthening is documented in DIV-0097.
//!
//! Divergence from Caddy v2.11.7 — `docs/compatibility/BEHAVIOR-DIVERGENCES.md` DIV-0097:
//!
//! * Status: mitigated
//! * Behaviour: challenge **order** now matches acmez's adaptive randomized selection.
//!   Alternate challenge **ports** (`challenges.http.alternate_port`,
//!   `challenges.tls-alpn.alternate_port`) remain unsupported and are rejected with a located
//!   error by [`crate::issuer::AcmeIssuerConfig`].
//! * Rationale: order parity is implemented here; alternate ports need HTTP/TLS listener wiring
//!   outside the ACME crate and stay documented as unsupported (tracked by T-TLS-064).
//! * Tracking: T-TLS-076 T-TLS-064
//! * Test: this module's tests plus `AcmeIssuerConfig` alternate-port rejection tests.
//!
//! The canonical challenge type is [`ChallengeType`] ([`crate::acme::order`]); this module only
//! depends on that shared definition, it never re-declares it.

use std::sync::{Mutex, OnceLock};

use ring::rand::{SecureRandom, SystemRandom};

use crate::acme::order::ChallengeType;
use crate::acme::AcmeError;
use crate::{Error, Result};

/// Challenge universe used when a standalone caller ([`generate_random_challenge_type`]) reaches
/// [`AdaptiveChallengeSelector::pick_random`] before any offers were recorded. The issuance path
/// always records real offers first, so this never affects [`crate::issuer::AcmeIssuer`].
const DEFAULT_UNIVERSE: [ChallengeType; 3] = [
    ChallengeType::Dns01,
    ChallengeType::Http01,
    ChallengeType::TlsAlpn01,
];

/// Randomness source for the initial challenge-pool shuffle (injectable for tests).
pub trait ChallengeRng: Send + Sync {
    /// Uniformly random index in `0..=max`.
    fn random_index(&self, max: usize) -> std::result::Result<usize, ring::error::Unspecified>;
}

/// [`ChallengeRng`] backed by `ring::rand::SystemRandom`.
///
/// Stronger than acmez's per-process `math/rand` source; documented as an intentional
/// strengthening in DIV-0097.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemChallengeRng;

impl ChallengeRng for SystemChallengeRng {
    fn random_index(&self, max: usize) -> std::result::Result<usize, ring::error::Unspecified> {
        if max == 0 {
            return Ok(0);
        }
        let mut buffer = [0u8; 8];
        SystemRandom::new().fill(&mut buffer)?;
        let value = u64::from_le_bytes(buffer);
        // Modulo bias is negligible for the tiny pools involved; acmez's rand.Shuffle uses
        // Intn (rejection-free) too.
        Ok((value % (max as u64 + 1)) as usize)
    }
}

/// Per-type statistics, mirroring acmez's `challengeHistory` (client.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChallengeHistory {
    challenge_type: ChallengeType,
    successes: u64,
    total: u64,
}

impl ChallengeHistory {
    fn new(challenge_type: ChallengeType) -> Self {
        Self {
            challenge_type,
            successes: 0,
            total: 0,
        }
    }

    /// acmez `successRatio` — 1.0 while the type has never been attempted.
    fn success_ratio(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.successes as f64 / self.total as f64
        }
    }
}

struct SelectorState {
    preferred: Vec<ChallengeHistory>,
    rng: Box<dyn ChallengeRng>,
}

impl std::fmt::Debug for SelectorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The RNG is opaque (`dyn ChallengeRng`); only the preference pool matters for debugging.
        f.debug_struct("SelectorState")
            .field("preferred", &self.preferred)
            .finish_non_exhaustive()
    }
}

impl SelectorState {
    /// acmez `challengeTypes.addUnique`.
    fn add_unique(&mut self, challenge_type: ChallengeType) {
        if !self
            .preferred
            .iter()
            .any(|history| history.challenge_type == challenge_type)
        {
            self.preferred.push(ChallengeHistory::new(challenge_type));
        }
    }

    /// Fisher–Yates shuffle over the whole pool (acmez shuffles on the first fill only).
    fn shuffle(&mut self) -> Result<()> {
        for i in (1..self.preferred.len()).rev() {
            let j = self.rng.random_index(i).map_err(|_| {
                Error::Acme(Box::new(AcmeError::ChallengeSelection {
                    reason: "randomness source failed while shuffling the challenge pool"
                        .to_string(),
                }))
            })?;
            self.preferred.swap(i, j);
        }
        Ok(())
    }

    /// acmez `challengeTypes.increment` + `sort.Stable` — descending success ratio, ties in
    /// current (randomized/offered) order. `sort_by` is stable, matching Go's `sort.Stable`.
    fn resort(&mut self) {
        self.preferred
            .sort_by(|a, b| b.success_ratio().total_cmp(&a.success_ratio()));
    }
}

/// Instance-scoped adaptive challenge selector — acmez's package-global `preferredChallenges` +
/// `randomSource`, but per-issuer so tests and issuers stay isolated.
pub struct AdaptiveChallengeSelector {
    state: Mutex<SelectorState>,
}

impl std::fmt::Debug for AdaptiveChallengeSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AdaptiveChallengeSelector")
            .finish_non_exhaustive()
    }
}

impl Default for AdaptiveChallengeSelector {
    fn default() -> Self {
        Self::with_rng(Box::new(SystemChallengeRng))
    }
}

impl AdaptiveChallengeSelector {
    /// Create a selector with an explicit randomness source (tests use a deterministic one).
    pub fn with_rng(rng: Box<dyn ChallengeRng>) -> Self {
        Self {
            state: Mutex::new(SelectorState {
                preferred: Vec::new(),
                rng,
            }),
        }
    }

    /// Record every challenge type a CA authorization offered, mirroring acmez's
    /// `getAuthzObjects` initial fill: types are added uniquely and the pool is shuffled
    /// once, on the first fill only. Later offers append in their offered order.
    pub fn record_offered(&self, offered: &[ChallengeType]) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .expect("adaptive challenge selector mutex poisoned");
        let was_empty = state.preferred.is_empty();
        for challenge_type in offered {
            state.add_unique(*challenge_type);
        }
        if was_empty && !state.preferred.is_empty() {
            state.shuffle()?;
        }
        Ok(())
    }

    /// Record the outcome of a challenge attempt (acmez `pollAuthorization` →
    /// `preferredChallenges.increment`) and re-sort the pool stably by descending success ratio.
    pub fn record_attempt(&self, challenge_type: ChallengeType, successful: bool) {
        let mut state = self
            .state
            .lock()
            .expect("adaptive challenge selector mutex poisoned");
        if let Some(history) = state
            .preferred
            .iter_mut()
            .find(|history| history.challenge_type == challenge_type)
        {
            history.total += 1;
            if successful {
                history.successes += 1;
            }
        }
        state.resort();
    }

    /// The current adaptive preference order (descending success ratio, ties stable). Empty
    /// when no offers have been recorded yet.
    pub fn ordered(&self) -> Vec<ChallengeType> {
        self.state
            .lock()
            .expect("adaptive challenge selector mutex poisoned")
            .preferred
            .iter()
            .map(|history| history.challenge_type)
            .collect()
    }

    /// A uniformly random member of the current adaptive pool. When the pool is empty
    /// (standalone use) it is seeded from [`DEFAULT_UNIVERSE`] first. Falls back to the first
    /// (highest-ratio) entry if the randomness source fails.
    pub fn pick_random(&self) -> ChallengeType {
        let mut state = self
            .state
            .lock()
            .expect("adaptive challenge selector mutex poisoned");
        if state.preferred.is_empty() {
            for challenge_type in DEFAULT_UNIVERSE {
                state.add_unique(challenge_type);
            }
            let _ = state.shuffle(); // keep (partially shuffled) order when randomness fails
        }
        match state.rng.random_index(state.preferred.len() - 1) {
            Ok(index) => state.preferred[index].challenge_type,
            Err(_) => state.preferred[0].challenge_type,
        }
    }
}

/// The module-global selector behind [`generate_random_challenge_type`], mirroring acmez's
/// package-level `preferredChallenges`/`randomSource` globals for standalone callers. The
/// issuance path uses a per-issuer [`AdaptiveChallengeSelector`] instead ([`crate::issuer`]).
pub fn global_selector() -> &'static AdaptiveChallengeSelector {
    static GLOBAL: OnceLock<AdaptiveChallengeSelector> = OnceLock::new();
    GLOBAL.get_or_init(AdaptiveChallengeSelector::default)
}

/// Generate a challenge type from the adaptive pool (T-TLS-076 / DIV-0097).
///
/// Not hard-coded: the pool is the set of challenge types this selector has seen — seeded from
/// [`DEFAULT_UNIVERSE`] on first standalone use — ordered by recorded success, and the return
/// value is drawn uniformly from it, so repeated calls yield different types and the pool
/// adapts to `record_offered`/`record_attempt` history. The ACME issuance path drives
/// [`AdaptiveChallengeSelector`] directly.
pub fn generate_random_challenge_type() -> ChallengeType {
    global_selector().pick_random()
}

/// Parse a comma-separated challenge order (e.g. `"dns-01,http-01,tls-alpn-01"`) into the typed
/// list, preserving the given order. Unknown or empty entries produce
/// [`AcmeError::InvalidChallengeOrder`] carrying the original string.
pub fn parse_challenge_order(order: &str) -> Result<Vec<ChallengeType>> {
    let mut parsed = Vec::new();
    for entry in order.split(',') {
        match ChallengeType::from_wire(entry.trim()) {
            Some(challenge_type) => parsed.push(challenge_type),
            None => {
                return Err(Error::Acme(Box::new(AcmeError::InvalidChallengeOrder {
                    order: order.to_string(),
                })));
            }
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic RNG that always returns index 0 — so every shuffle swap moves the
    /// `i`-th slot (with `i` descending from `len-1`) into position 0, i.e. `[a,b,c]` →
    /// `[c,b,a]` then `[b,c,a]`. Values are drawn from `0..=max` (inclusive, Go-parity).
    #[derive(Debug)]
    struct ZeroRng;

    impl ChallengeRng for ZeroRng {
        fn random_index(
            &self,
            _max: usize,
        ) -> std::result::Result<usize, ring::error::Unspecified> {
            Ok(0)
        }
    }

    /// Deterministic RNG that always returns `max` — a self-swap on every step, so `shuffle`
    /// preserves the offered order exactly (identity permutation, possible only because the
    /// bound is inclusive `0..=max`, mirroring Go's `rand.Shuffle`).
    #[derive(Debug)]
    struct IdentityRng;

    impl ChallengeRng for IdentityRng {
        fn random_index(&self, max: usize) -> std::result::Result<usize, ring::error::Unspecified> {
            Ok(max)
        }
    }

    #[test]
    fn record_offered_shuffles_once_with_add_unique() {
        let selector = AdaptiveChallengeSelector::with_rng(Box::new(ZeroRng));
        // Offered stream contains duplicates; add_unique collapses while keeping first-seen
        // insertion order: [Http01, Dns01, TlsAlpn01]. ZeroRng then shuffles once:
        //   len 3, i=2 j=0 -> [TlsAlpn01, Dns01, Http01]
        //   len 3, i=1 j=0 -> [Dns01, TlsAlpn01, Http01]
        selector
            .record_offered(&[
                ChallengeType::Http01,
                ChallengeType::Dns01,
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01,
                ChallengeType::Http01,
            ])
            .unwrap();
        assert_eq!(
            selector.ordered(),
            vec![
                ChallengeType::Dns01,
                ChallengeType::TlsAlpn01,
                ChallengeType::Http01
            ]
        );

        // Recording the same set again must NOT re-shuffle (was_empty == false).
        selector
            .record_offered(&[
                ChallengeType::Dns01,
                ChallengeType::TlsAlpn01,
                ChallengeType::Http01,
            ])
            .unwrap();
        assert_eq!(
            selector.ordered(),
            vec![
                ChallengeType::Dns01,
                ChallengeType::TlsAlpn01,
                ChallengeType::Http01
            ]
        );
    }

    #[test]
    fn record_offered_does_not_reshuffle_later_offers() {
        let selector = AdaptiveChallengeSelector::with_rng(Box::new(ZeroRng));
        // First fill shuffles once: [Http01, Dns01] -- i=1 j=0 -> [Dns01, Http01].
        selector
            .record_offered(&[ChallengeType::Http01, ChallengeType::Dns01])
            .unwrap();
        assert_eq!(
            selector.ordered(),
            vec![ChallengeType::Dns01, ChallengeType::Http01]
        );

        // A later offer of a brand-new type appends, but must NOT re-shuffle the pool.
        selector
            .record_offered(&[ChallengeType::TlsAlpn01])
            .unwrap();
        assert_eq!(
            selector.ordered(),
            vec![
                ChallengeType::Dns01,
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01
            ]
        );
    }

    #[test]
    fn record_attempt_reorders_by_descending_success_ratio() {
        // IdentityRng preserves the offered order through the one-time shuffle.
        let selector = AdaptiveChallengeSelector::with_rng(Box::new(IdentityRng));
        selector
            .record_offered(&[
                ChallengeType::Dns01,
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01,
            ])
            .unwrap();
        assert_eq!(
            selector.ordered(),
            vec![
                ChallengeType::Dns01,
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01
            ]
        );

        // Never-attempted types all have ratio 1.0 (stable ties keep offered order).
        // Fail Dns01 -> 0/1 = 0.0; the two 1.0 types stay ahead, Dns01 falls to the back.
        selector.record_attempt(ChallengeType::Dns01, false);
        assert_eq!(
            selector.ordered(),
            vec![
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01,
                ChallengeType::Dns01
            ]
        );

        // Fail TlsAlpn01 too -> 0.0; now only Http01 keeps 1.0 and rises to the front.
        selector.record_attempt(ChallengeType::TlsAlpn01, false);
        assert_eq!(
            selector.ordered(),
            vec![
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01,
                ChallengeType::Dns01
            ]
        );

        // Fail Dns01 again -> 0/2 = 0.0 (unchanged ratio). Order is stable.
        selector.record_attempt(ChallengeType::Dns01, false);
        assert_eq!(
            selector.ordered(),
            vec![
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01,
                ChallengeType::Dns01
            ]
        );

        // Succeed Http01 -> 1/1 = 1.0: still first, no other ratio changes.
        selector.record_attempt(ChallengeType::Http01, true);
        assert_eq!(
            selector.ordered(),
            vec![
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01,
                ChallengeType::Dns01
            ]
        );
    }

    #[test]
    fn never_attempted_ratio_keeps_a_type_first() {
        // A fresh, never-attempted type must outrank a repeatedly-failed one.
        let selector = AdaptiveChallengeSelector::with_rng(Box::new(IdentityRng));
        selector
            .record_offered(&[ChallengeType::Http01, ChallengeType::Dns01])
            .unwrap();
        selector.record_attempt(ChallengeType::Http01, false);
        selector.record_attempt(ChallengeType::Http01, false);
        // Http01 = 0/2 = 0.0, Dns01 never attempted = 1.0 -> Dns01 ahead.
        assert_eq!(
            selector.ordered(),
            vec![ChallengeType::Dns01, ChallengeType::Http01]
        );
    }

    #[test]
    fn parse_challenge_order_round_trips() {
        let parsed = parse_challenge_order("dns-01,http-01,tls-alpn-01").unwrap();
        assert_eq!(
            parsed,
            vec![
                ChallengeType::Dns01,
                ChallengeType::Http01,
                ChallengeType::TlsAlpn01
            ]
        );
        assert_eq!(
            parse_challenge_order("http-01").unwrap(),
            vec![ChallengeType::Http01]
        );
    }

    #[test]
    fn parse_challenge_order_rejects_unknown() {
        let err = parse_challenge_order("http-01,bogus-01").unwrap_err();
        match err {
            Error::Acme(acme) => match acme.as_ref() {
                AcmeError::InvalidChallengeOrder { order } => {
                    assert_eq!(order, "http-01,bogus-01");
                }
                other => panic!("unexpected ACME error: {other}"),
            },
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn pick_random_returns_a_member_of_the_pool() {
        let selector = AdaptiveChallengeSelector::with_rng(Box::new(IdentityRng));
        // Standalone use: pool seeded from DEFAULT_UNIVERSE, order preserved (identity shuffle).
        let value = selector.pick_random();
        assert!([
            ChallengeType::Dns01,
            ChallengeType::Http01,
            ChallengeType::TlsAlpn01
        ]
        .contains(&value));
    }
}
