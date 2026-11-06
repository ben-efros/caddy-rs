//! Renewal scheduling and atomic certificate hot-swapping.
//!
//! This module owns the runtime lifecycle of long-lived certificates:
//!
//! * [`SharedCertificateStore`] is a hot-swappable, name-indexed certificate store. Replacing a
//!   certificate swaps an [`Arc<Certificate>`](Certificate) atomically; a TLS handshake already
//!   in flight keeps the old `Arc` it resolved, while new handshakes see the new certificate.
//!   When a [`CertificatePublisher`] is attached (for example a rustls
//!   [`CertificateResolver`](crate::tls_server::CertificateResolver)), the new certificate is
//!   published into the live resolver at the same time.
//! * [`RenewalPolicy`] decides when a certificate is due: by default one third of its lifetime
//!   before expiry (two thirds through), plus deterministic jitter (default: up to 10 minutes),
//!   with exponential backoff for failed renewals. An explicit `renewal_window` can instead
//!   renew a fixed duration before expiry.
//! * [`RenewalScheduler`] renews due certificates through a [`CertificateIssuer`], persists the
//!   result through [`CertificateStorage`], and only then swaps it into the store. A failed
//!   issuance or storage write keeps the previous certificate serving and schedules a retry with
//!   exponential backoff. Renewals are deduplicated per certificate, and the scheduler supports
//!   `start`/`stop` cancellation.
//! * [`RenewalClock`] abstracts time; [`SystemClock`] is used in production and [`ManualClock`]
//!   lets tests advance time without sleeping.
//!
//! Caddy renews certificates within the last third of their lifetime with random jitter and
//! retries with backoff; caddy-rs uses a deterministic per-name jitter instead so that tests (and
//! restarts) schedule identically. TLS-ALPN/ARI-driven renewal is not implemented (see the
//! divergence notes reported with this module).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tokio::sync::watch;
use tokio::sync::{Mutex as AsyncMutex, Notify};

use crate::acme::ari::RenewalInfo;
use crate::certificate::{Certificate, RenewalItem};
use crate::issuer::{CertificateIssuer, IssuanceRequest};
use crate::storage::{
    caddy_certificate_storage_name, caddy_issuer_key, CertificateStorage, StoredCertificate,
};
use crate::{Error, Result};

/// Default jitter added to renewal times (Caddy uses up to 10 minutes of random jitter).
pub const DEFAULT_RENEWAL_JITTER: Duration = Duration::from_secs(10 * 60);

/// Default first-retry delay after a failed renewal.
pub const DEFAULT_BACKOFF_BASE: Duration = Duration::from_secs(30);

/// Default cap for exponentially increasing renewal backoff.
pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);

/// Fraction of the certificate lifetime that remains when renewal becomes due (one third).
pub const RENEWAL_REMAINING_FRACTION: f64 = 1.0 / 3.0;

/// Caddy/certmagic's default renewal check interval (also the ARI "renew just before the selected
/// time" cutoff and the emergency-window divisor).
pub const DEFAULT_RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How long to wait before retrying an ARI fetch that failed (certmagic uses a retry/backoff; the
/// scheduler keeps its local heuristic in the meantime).
const ARI_RETRY_FALLBACK: Duration = Duration::from_secs(10 * 60);

/// Maximum number of renewal outcomes remembered for diagnostics/tests.
const HISTORY_LIMIT: usize = 64;

// ---- clock ----------------------------------------------------------------------------------

/// Clock abstraction used by the renewal scheduler.
///
/// Implementations provide the current time and a cancellable sleep; tests use [`ManualClock`]
/// so no real time passes.
#[async_trait]
pub trait RenewalClock: Send + Sync {
    /// Current wall-clock time as seen by the scheduler.
    fn now(&self) -> SystemTime;

    /// Complete once `self.now() >= deadline`. Must return immediately when the deadline is in the
    /// past, and should be cancellable by dropping the future.
    async fn sleep_until(&self, deadline: SystemTime);
}

/// Production clock backed by `SystemTime::now` and tokio timers.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[async_trait]
impl RenewalClock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    async fn sleep_until(&self, deadline: SystemTime) {
        if let Ok(remaining) = deadline.duration_since(SystemTime::now()) {
            if !remaining.is_zero() {
                tokio::time::sleep(remaining).await;
            }
        }
    }
}

/// Manually advanced clock for deterministic tests.
#[derive(Debug, Clone)]
pub struct ManualClock {
    now: watch::Sender<SystemTime>,
}

impl ManualClock {
    /// Create a clock set to `start`.
    pub fn new(start: SystemTime) -> Self {
        let (now, _receiver) = watch::channel(start);
        Self { now }
    }

    /// Current time.
    pub fn now(&self) -> SystemTime {
        *self.now.borrow()
    }

    /// Advance the clock by `duration`, waking every [`RenewalClock::sleep_until`] waiter whose
    /// deadline is now reached.
    pub fn advance(&self, duration: Duration) {
        self.set(self.now() + duration);
    }

    /// Set the clock to an absolute time, waking sleepers whose deadlines are reached.
    pub fn set(&self, now: SystemTime) {
        self.now.send_replace(now);
    }
}

#[async_trait]
impl RenewalClock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.now.borrow()
    }

    async fn sleep_until(&self, deadline: SystemTime) {
        let mut receiver = self.now.subscribe();
        loop {
            if *receiver.borrow_and_update() >= deadline {
                return;
            }
            if receiver.changed().await.is_err() {
                // The clock was dropped; returning avoids leaving the scheduler hung forever.
                return;
            }
        }
    }
}

// ---- policy ---------------------------------------------------------------------------------

fn fnv1a(value: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in value {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Deterministic renewal timing and retry policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalPolicy {
    /// Renew this long before `not_after` (Caddy's `renewal_window`); `None` uses one third of the
    /// lifetime remaining (two thirds through the lifetime).
    pub renewal_window: Option<Duration>,
    /// Maximum jitter added to each renewal time; jitter is deterministic per certificate name so
    /// schedules are stable across restarts. Defaults to [`DEFAULT_RENEWAL_JITTER`].
    pub jitter: Duration,
    /// First retry delay after a failed renewal. Defaults to [`DEFAULT_BACKOFF_BASE`].
    pub backoff_base: Duration,
    /// Upper bound for the exponential retry delay. Defaults to [`DEFAULT_BACKOFF_MAX`].
    pub backoff_max: Duration,
    /// How often the scheduler checks certificates and, when ARI is present, how far before the
    /// ARI-selected time renewal becomes due. Defaults to [`DEFAULT_RENEW_CHECK_INTERVAL`].
    pub check_interval: Duration,
}

impl Default for RenewalPolicy {
    fn default() -> Self {
        Self {
            renewal_window: None,
            jitter: DEFAULT_RENEWAL_JITTER,
            backoff_base: DEFAULT_BACKOFF_BASE,
            backoff_max: DEFAULT_BACKOFF_MAX,
            check_interval: DEFAULT_RENEW_CHECK_INTERVAL,
        }
    }
}

impl RenewalPolicy {
    /// The default policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use an explicit renewal window before expiry instead of the one-third-remaining rule.
    pub fn with_renewal_window(mut self, renewal_window: Option<Duration>) -> Self {
        self.renewal_window = renewal_window;
        self
    }

    /// Set the maximum jitter (use [`Duration::ZERO`] for deterministic tests).
    pub fn with_jitter(mut self, jitter: Duration) -> Self {
        self.jitter = jitter;
        self
    }

    /// Set the retry backoff base and cap.
    pub fn with_backoff(mut self, backoff_base: Duration, backoff_max: Duration) -> Self {
        self.backoff_base = backoff_base;
        self.backoff_max = backoff_max;
        self
    }

    /// Set the maintenance check interval (also the ARI selected-time cutoff).
    pub fn with_check_interval(mut self, check_interval: Duration) -> Self {
        self.check_interval = check_interval;
        self
    }

    /// When `certificate` becomes due for renewal (with deterministic jitter applied).
    pub fn renewal_time(&self, certificate: &Certificate) -> SystemTime {
        let nominal = match self.renewal_window {
            Some(window) => certificate
                .not_after
                .checked_sub(window)
                .unwrap_or(certificate.not_before),
            None => {
                // Integer arithmetic avoids `Duration::mul_f64`'s nanosecond rounding.
                let remaining = certificate.lifetime() / 3;
                certificate
                    .not_after
                    .checked_sub(remaining)
                    .unwrap_or(certificate.not_before)
            }
        };
        nominal + self.jitter_for(&certificate.domains)
    }

    /// Deterministic jitter for a certificate: a stable function of its names.
    pub fn jitter_for(&self, domains: &[String]) -> Duration {
        if self.jitter.is_zero() {
            return Duration::ZERO;
        }
        let millis = u64::try_from(self.jitter.as_millis()).unwrap_or(u64::MAX);
        let mut names: Vec<String> = domains
            .iter()
            .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        names.sort();
        names.dedup();
        let hash = fnv1a(names.join("\0").as_bytes());
        Duration::from_millis(hash % millis.saturating_add(1))
    }

    /// Retry delay after the `attempts`-th consecutive failure (1-based): exponential from
    /// `backoff_base`, capped at `backoff_max`.
    pub fn backoff(&self, attempts: u32) -> Duration {
        let exponent = attempts.saturating_sub(1).min(31);
        let factor = 1u32 << exponent;
        self.backoff_base
            .saturating_mul(factor)
            .min(self.backoff_max)
    }
}

// ---- shared hot-swappable store -------------------------------------------------------------

/// Receives certificates after they are persisted and before they become visible in a
/// [`SharedCertificateStore`]; used to keep the live rustls resolver in sync.
pub trait CertificatePublisher: Send + Sync {
    /// Publish (install or replace) `certificate` in the live TLS stack.
    fn publish(&self, certificate: &Certificate) -> Result<()>;
}

/// Publish renewed certificates into the rustls
/// [`CertificateResolver`](crate::tls_server::CertificateResolver).
///
/// [`CertificateResolver::insert`](crate::tls_server::CertificateResolver::insert) validates the
/// chain/private key and swaps a new
/// `Arc<CertifiedKey>` into its state under a write lock, so in-flight handshakes keep the old
/// `Arc` and new handshakes use the new certificate.
impl CertificatePublisher for crate::tls_server::CertificateResolver {
    fn publish(&self, certificate: &Certificate) -> Result<()> {
        let tls_certificate =
            crate::tls_server::TlsCertificate::from_cache_certificate(certificate)?;
        self.insert(tls_certificate)
    }
}

#[derive(Debug, Default)]
struct StoreState {
    by_name: BTreeMap<String, Arc<Certificate>>,
    default: Option<Arc<Certificate>>,
}

/// Hot-swappable certificate store indexed by name.
///
/// All reads hand out `Arc<Certificate>` clones, so a reader that already obtained a certificate
/// keeps it even if the store is updated concurrently. Writes replace the mapping atomically
/// under a write lock; the attached [`CertificatePublisher`] (if any) is updated first so the TLS
/// resolver observes the new certificate at the same time.
pub struct SharedCertificateStore {
    state: RwLock<StoreState>,
    publisher: RwLock<Option<Arc<dyn CertificatePublisher>>>,
    changed: Notify,
}

impl Default for SharedCertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SharedCertificateStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedCertificateStore")
            .field("names", &self.names())
            .finish_non_exhaustive()
    }
}

impl SharedCertificateStore {
    /// An empty store with no publisher.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(StoreState::default()),
            publisher: RwLock::new(None),
            changed: Notify::new(),
        }
    }

    /// An empty store that publishes to `publisher` (for example a rustls resolver).
    pub fn with_publisher(publisher: Arc<dyn CertificatePublisher>) -> Self {
        let store = Self::new();
        store.set_publisher(Some(publisher));
        store
    }

    /// Replace the publisher callback.
    pub fn set_publisher(&self, publisher: Option<Arc<dyn CertificatePublisher>>) {
        *self
            .publisher
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = publisher;
    }

    /// Install or replace a certificate for all of its names.
    ///
    /// The previous certificate is retained by any reader that already resolved it (including an
    /// in-flight TLS handshake). Returns an error for a certificate with no usable names.
    pub fn insert(&self, certificate: Certificate) -> Result<()> {
        let certificate = Arc::new(certificate);
        let domains = normalized_domains(&certificate.domains);
        if domains.is_empty() {
            return Err(Error::Certificate(
                "cannot store a certificate with no names".to_string(),
            ));
        }

        // Publish first so the live TLS resolver serves the new certificate before the store's
        // bookkeeping is updated; publish failures leave the store untouched.
        let publisher = self
            .publisher
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(publisher) = publisher {
            publisher.publish(&certificate)?;
        }

        {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let domain_set: Vec<String> = domains.clone();
            for domain in &domains {
                if let Some(previous) = state.by_name.get(domain).cloned() {
                    if !Arc::ptr_eq(&previous, &certificate) {
                        // Drop names that only the replaced certificate covered.
                        let stale: Vec<String> = state
                            .by_name
                            .iter()
                            .filter(|(name, existing)| {
                                Arc::ptr_eq(existing, &previous) && !domain_set.contains(name)
                            })
                            .map(|(name, _)| name.clone())
                            .collect();
                        for name in stale {
                            state.by_name.remove(&name);
                        }
                    }
                }
                state
                    .by_name
                    .insert(domain.clone(), Arc::clone(&certificate));
            }
            if state.default.is_none() {
                state.default = Some(Arc::clone(&certificate));
            }
        }
        self.changed.notify_waiters();
        Ok(())
    }

    /// Exact-name lookup.
    pub fn get(&self, server_name: &str) -> Option<Arc<Certificate>> {
        let name = normalize_name(server_name);
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .by_name
            .get(&name)
            .cloned()
    }

    /// Select a certificate like the TLS resolver: exact name, one-label wildcard, then default.
    pub fn select(&self, server_name: Option<&str>) -> Option<Arc<Certificate>> {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(server_name) = server_name else {
            return state.default.clone();
        };
        let name = normalize_name(server_name);
        if let Some(certificate) = state.by_name.get(&name) {
            return Some(Arc::clone(certificate));
        }
        if let Some((_, rest)) = name.split_once('.') {
            if rest.contains('.') {
                if let Some(certificate) = state.by_name.get(&format!("*.{rest}")) {
                    return Some(Arc::clone(certificate));
                }
            }
        }
        state.default.clone()
    }

    /// The default certificate (first installed), used for empty or unknown SNI.
    pub fn default_certificate(&self) -> Option<Arc<Certificate>> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .default
            .clone()
    }

    /// Names currently served (lowercased).
    pub fn names(&self) -> Vec<String> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .by_name
            .keys()
            .cloned()
            .collect()
    }

    /// Number of names served.
    pub fn len(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .by_name
            .len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove every name covered by `domains`. Returns whether any name was removed.
    pub fn remove(&self, domains: &[String]) -> bool {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut removed = false;
        for domain in normalized_domains(domains) {
            removed |= state.by_name.remove(&domain).is_some();
        }
        if let Some(default) = state.default.clone() {
            if !state
                .by_name
                .values()
                .any(|cert| Arc::ptr_eq(cert, &default))
            {
                state.default = None;
            }
        }
        removed
    }

    /// Distinct certificates in the store (deduplicated by `Arc` identity), sorted by primary
    /// name. Readers receive immutable snapshots: replacing a certificate never mutates an
    /// already-returned `Arc`.
    pub fn certificates(&self) -> Vec<Arc<Certificate>> {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut certificates: Vec<Arc<Certificate>> = Vec::new();
        for certificate in state.by_name.values() {
            if !certificates
                .iter()
                .any(|existing| Arc::ptr_eq(existing, certificate))
            {
                certificates.push(Arc::clone(certificate));
            }
        }
        certificates.sort_by_key(|certificate| {
            certificate
                .domains
                .first()
                .map(|domain| domain.to_ascii_lowercase())
                .unwrap_or_default()
        });
        certificates
    }

    /// Earliest renewal time of any stored certificate according to `policy`.
    ///
    /// The value may be in the past (certificates are then due immediately); it is `None` only
    /// when the store is empty. Failed-renewal backoff is applied by [`RenewalScheduler`], not
    /// here.
    pub fn next_renewal(&self, now: SystemTime, policy: &RenewalPolicy) -> Option<RenewalItem> {
        let _ = now;
        self.certificates()
            .into_iter()
            .map(|certificate| RenewalItem {
                domains: certificate.domains.clone(),
                due_at: policy.renewal_time(&certificate),
            })
            .min_by_key(|item| item.due_at)
    }
}

fn normalize_name(server_name: &str) -> String {
    server_name
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn normalized_domains(domains: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = Vec::new();
    for domain in domains {
        let domain = normalize_name(domain);
        if !domain.is_empty() && !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    normalized
}

// ---- scheduler ------------------------------------------------------------------------------

/// Result of one renewal attempt, surfaced in [`RenewalScheduler::run_once`] and history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// A new certificate was issued, persisted and swapped in.
    Renewed {
        /// Names covered by the new certificate.
        domains: Vec<String>,
        /// Validity start of the new certificate.
        not_before: SystemTime,
        /// Expiry of the new certificate.
        not_after: SystemTime,
    },
    /// The certificate is not due yet; no issuance was attempted.
    NotDue {
        /// Names covered by the certificate.
        domains: Vec<String>,
        /// When it becomes due.
        due_at: SystemTime,
    },
    /// A concurrent renewal already replaced this certificate, so this attempt did nothing.
    Skipped {
        /// Names covered by the certificate.
        domains: Vec<String>,
        /// Why the attempt was skipped.
        reason: String,
    },
    /// The renewal failed; the previous certificate is still installed and a retry is scheduled.
    Failed {
        /// Names covered by the certificate.
        domains: Vec<String>,
        /// Failure description.
        error: String,
        /// When the scheduler will retry.
        retry_at: SystemTime,
    },
}

impl RenewalOutcome {
    /// Names the outcome refers to.
    pub fn domains(&self) -> &[String] {
        match self {
            Self::Renewed { domains, .. }
            | Self::NotDue { domains, .. }
            | Self::Skipped { domains, .. }
            | Self::Failed { domains, .. } => domains,
        }
    }

    /// Whether the attempt succeeded.
    pub fn is_renewed(&self) -> bool {
        matches!(self, Self::Renewed { .. })
    }

    /// Whether the attempt failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

#[derive(Debug, Clone)]
struct FailureState {
    attempts: u32,
    retry_at: SystemTime,
    not_after: SystemTime,
}

#[derive(Debug, Clone)]
struct AriState {
    info: Option<RenewalInfo>,
    retry_at: Option<SystemTime>,
}

#[derive(Debug, Default)]
struct SchedulerState {
    failures: BTreeMap<String, FailureState>,
    history: VecDeque<RenewalOutcome>,
}

/// Renewal scheduler: watches the [`SharedCertificateStore`], renews due certificates through a
/// [`CertificateIssuer`], persists them with [`CertificateStorage`] and hot-swaps them in.
///
/// Create it with [`RenewalScheduler::new`], optionally adjust the [`RenewalPolicy`], then either
/// drive it with [`RenewalScheduler::run_once`] (deterministic tests, callers that have their own
/// timer loop) or spawn it with [`RenewalScheduler::start`].
pub struct RenewalScheduler {
    issuer: Arc<dyn CertificateIssuer>,
    storage: Arc<dyn CertificateStorage>,
    store: Arc<SharedCertificateStore>,
    clock: Arc<dyn RenewalClock>,
    policy: RenewalPolicy,
    state: Mutex<SchedulerState>,
    /// Latest ARI per certificate key (in-memory; fetched by [`Self::refresh_renewal_info`]).
    ari: Mutex<BTreeMap<String, AriState>>,
    locks: Mutex<BTreeMap<String, Arc<AsyncMutex<()>>>>,
    stopped: AtomicBool,
    stop_notify: Notify,
}

impl fmt::Debug for RenewalScheduler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenewalScheduler")
            .field("policy", &self.policy)
            .field("certificates", &self.store.certificates().len())
            .field("stopped", &self.is_stopped())
            .finish_non_exhaustive()
    }
}

impl RenewalScheduler {
    /// Create a scheduler.
    pub fn new(
        issuer: Arc<dyn CertificateIssuer>,
        storage: Arc<dyn CertificateStorage>,
        store: Arc<SharedCertificateStore>,
        clock: Arc<dyn RenewalClock>,
    ) -> Self {
        Self {
            issuer,
            storage,
            store,
            clock,
            policy: RenewalPolicy::default(),
            state: Mutex::new(SchedulerState::default()),
            ari: Mutex::new(BTreeMap::new()),
            locks: Mutex::new(BTreeMap::new()),
            stopped: AtomicBool::new(false),
            stop_notify: Notify::new(),
        }
    }

    /// Replace the renewal/retry policy.
    pub fn with_policy(mut self, policy: RenewalPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The shared certificate store.
    pub fn store(&self) -> &Arc<SharedCertificateStore> {
        &self.store
    }

    /// The active policy.
    pub fn policy(&self) -> &RenewalPolicy {
        &self.policy
    }

    /// The latest ARI cached for `certificate`, if any.
    pub fn renewal_info_for(&self, certificate: &Certificate) -> Option<RenewalInfo> {
        self.ari
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&certificate_key(certificate))
            .and_then(|state| state.info.clone())
    }

    /// The clock used for scheduling.
    pub fn clock(&self) -> &Arc<dyn RenewalClock> {
        &self.clock
    }

    /// Recent renewal outcomes (most recent last, bounded).
    pub fn history(&self) -> Vec<RenewalOutcome> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .history
            .iter()
            .cloned()
            .collect()
    }

    /// Refresh cached ARI for stored certificates whose document is missing or whose
    /// `Retry-After` elapsed.
    ///
    /// Failures fall back to the local renewal heuristic: a previous ARI is retained and a retry
    /// is scheduled; a certificate with no ARI is not queried again until its retry time. This
    /// mirrors certmagic's "log and continue with the local schedule" behaviour without blocking
    /// renewals on ARI availability.
    pub async fn refresh_renewal_info(&self, now: SystemTime) {
        let certificates = self.store.certificates();
        {
            let mut ari = self
                .ari
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let current: BTreeMap<String, SystemTime> = certificates
                .iter()
                .map(|certificate| (certificate_key(certificate), certificate.not_after))
                .collect();
            ari.retain(|key, _| current.contains_key(key));
        }
        for certificate in certificates {
            let key = certificate_key(&certificate);
            let state = self
                .ari
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&key)
                .cloned();
            let needs_refresh = match &state {
                None => true,
                Some(state) => match &state.info {
                    Some(info) => info.needs_refresh(now),
                    None => state.retry_at.is_some_and(|retry_at| now >= retry_at),
                },
            };
            if !needs_refresh {
                continue;
            }
            let new_state = match self.issuer.renewal_info(&certificate).await {
                Ok(Some(info)) => AriState {
                    retry_at: info.retry_after,
                    info: Some(info),
                },
                Ok(None) => AriState {
                    info: None,
                    retry_at: None,
                },
                Err(_) => AriState {
                    info: state.as_ref().and_then(|state| state.info.clone()),
                    retry_at: Some(
                        state
                            .as_ref()
                            .and_then(|state| state.retry_at)
                            .unwrap_or(now + ARI_RETRY_FALLBACK),
                    ),
                },
            };
            self.ari
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(key, new_state);
        }
    }

    /// The next time the scheduler has work, taking failed-renewal backoff into account.
    ///
    /// Returns `None` when the store is empty. The returned time may be in the past, meaning work
    /// is already due.
    pub fn next_renewal(&self, now: SystemTime) -> Option<RenewalItem> {
        let _ = now;
        self.prune_failures();
        let failures = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .failures
            .clone();
        self.store
            .certificates()
            .into_iter()
            .map(|certificate| {
                let due_at = self.effective_due(&certificate, &failures);
                let (_, wake) = self.ari_times(&certificate);
                RenewalItem {
                    domains: certificate.domains.clone(),
                    due_at: wake.map_or(due_at, |wake| due_at.min(wake)),
                }
            })
            .min_by_key(|item| item.due_at)
    }

    /// Renew every certificate that is due at `now`.
    ///
    /// Failures are captured per certificate in the returned outcomes; the old certificate stays
    /// installed and a backoff retry is scheduled.
    pub async fn run_once(&self, now: SystemTime) -> Vec<RenewalOutcome> {
        self.refresh_renewal_info(now).await;
        self.prune_failures();
        let failures = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .failures
            .clone();
        let mut due: Vec<Arc<Certificate>> = self
            .store
            .certificates()
            .into_iter()
            .filter(|certificate| now >= self.effective_due(certificate, &failures))
            .collect();
        due.sort_by_key(|certificate| self.effective_due(certificate, &failures));

        let mut outcomes = Vec::with_capacity(due.len());
        for certificate in due {
            let outcome = self.renew_certificate(certificate).await;
            self.record_history(outcome.clone());
            outcomes.push(outcome);
        }
        outcomes
    }

    /// Attempt to renew one certificate.
    ///
    /// Deduplicated per certificate: concurrent calls for the same certificate serialise on a
    /// per-name lock and the second call observes the already-replaced certificate and returns
    /// [`RenewalOutcome::Skipped`].
    pub async fn renew_certificate(&self, certificate: Arc<Certificate>) -> RenewalOutcome {
        let domains = certificate.domains.clone();
        let key = certificate_key(&certificate);
        let lock = {
            let mut locks = self
                .locks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(
                locks
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
            )
        };
        let _guard = lock.lock().await;

        // Re-read the store: another attempt may have replaced the certificate while we waited.
        let Some(current) = self
            .store
            .certificates()
            .into_iter()
            .find(|candidate| certificate_key(candidate) == key)
        else {
            return RenewalOutcome::Skipped {
                domains,
                reason: "certificate is no longer in the store".to_string(),
            };
        };
        if current.not_after != certificate.not_after
            || current.not_before != certificate.not_before
        {
            return RenewalOutcome::Skipped {
                domains,
                reason: "certificate was renewed concurrently".to_string(),
            };
        }

        let now = self.clock.now();
        self.refresh_renewal_info(now).await;
        let failures = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .failures
            .clone();
        let due_at = self.effective_due(&current, &failures);
        if now < due_at {
            return RenewalOutcome::NotDue { domains, due_at };
        }

        let key_type =
            crate::acme::csr::CertificateKeyType::from_private_key_der(&current.private_key_der)
                .unwrap_or(crate::acme::csr::CertificateKeyType::P256);
        let request = IssuanceRequest {
            domains: current.domains.clone(),
            internal: current.issuer == "internal",
            key_type,
        };
        let issued = match self.issuer.obtain(&request).await {
            Ok(certificate) => certificate,
            Err(error) => {
                let retry_at = self.record_failure(&current, now);
                return RenewalOutcome::Failed {
                    domains,
                    error: error.to_string(),
                    retry_at,
                };
            }
        };

        if let Err(error) = self.persist(&issued).await {
            let message = format!("certificate storage: {error}");
            let retry_at = self.record_failure(&current, now);
            return RenewalOutcome::Failed {
                domains,
                error: message,
                retry_at,
            };
        }

        if let Err(error) = self.store.insert(issued.clone()) {
            let message = format!("certificate swap: {error}");
            let retry_at = self.record_failure(&current, now);
            return RenewalOutcome::Failed {
                domains,
                error: message,
                retry_at,
            };
        }
        self.clear_failure(&key);
        self.ari
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
        RenewalOutcome::Renewed {
            domains: issued.domains,
            not_before: issued.not_before,
            not_after: issued.not_after,
        }
    }

    /// Start the background scheduler. The returned handle stops it.
    pub fn start(self: &Arc<Self>) -> RenewalSchedulerHandle {
        let scheduler = Arc::clone(self);
        let task = tokio::spawn(async move {
            scheduler.run().await;
        });
        RenewalSchedulerHandle {
            scheduler: Arc::clone(self),
            task,
        }
    }

    /// Ask a started scheduler to stop. Waiters are woken immediately.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.stop_notify.notify_waiters();
    }

    /// Whether [`RenewalScheduler::stop`] has been called.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    async fn run(self: Arc<Self>) {
        loop {
            if self.is_stopped() {
                return;
            }
            let _outcomes = self.run_once(self.clock.now()).await;
            if self.is_stopped() {
                return;
            }
            self.wait_for_work().await;
        }
    }

    async fn wait_for_work(&self) {
        if self.is_stopped() {
            return;
        }
        // Register wake sources before observing state to avoid lost wakeups.
        let store_changed = self.store.changed.notified();
        tokio::pin!(store_changed);
        store_changed.as_mut().enable();
        let stop = self.stop_notify.notified();
        tokio::pin!(stop);
        stop.as_mut().enable();

        let now = self.clock.now();
        match self.next_renewal(now) {
            Some(item) if item.due_at <= now => {}
            Some(item) => {
                tokio::select! {
                    _ = self.clock.sleep_until(item.due_at) => {}
                    _ = &mut store_changed => {}
                    _ = &mut stop => {}
                }
            }
            None => {
                tokio::select! {
                    _ = &mut store_changed => {}
                    _ = &mut stop => {}
                }
            }
        }
    }

    /// ARI-derived renewal time and next refresh wake-up.
    ///
    /// Certmagic renews at `selected_time - renew_check_interval`, but always honors the emergency
    /// window (last 1/20 of the lifetime) even if ARI suggests something later. When no usable ARI
    /// is cached the local heuristic remains authoritative; `Retry-After` is only an extra wake-up
    /// so a changed CA window is noticed.
    fn ari_times(&self, certificate: &Certificate) -> (Option<SystemTime>, Option<SystemTime>) {
        let Some(state) = self
            .ari
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&certificate_key(certificate))
            .cloned()
        else {
            return (None, None);
        };
        let renewal = state.info.as_ref().and_then(|info| {
            info.selected_time.map(|selected| {
                let cutoff = selected
                    .checked_sub(self.policy.check_interval)
                    .unwrap_or(certificate.not_before);
                let emergency = certificate
                    .not_after
                    .checked_sub(certificate.lifetime() / 20)
                    .unwrap_or(certificate.not_before);
                cutoff.min(emergency)
            })
        });
        (renewal, state.retry_at)
    }

    fn effective_due(
        &self,
        certificate: &Certificate,
        failures: &BTreeMap<String, FailureState>,
    ) -> SystemTime {
        let (ari_renewal, _) = self.ari_times(certificate);
        let nominal = ari_renewal.unwrap_or_else(|| self.policy.renewal_time(certificate));
        match failures.get(&certificate_key(certificate)) {
            Some(failure) if failure.not_after == certificate.not_after => {
                nominal.max(failure.retry_at)
            }
            _ => nominal,
        }
    }

    fn record_failure(&self, certificate: &Certificate, now: SystemTime) -> SystemTime {
        let key = certificate_key(certificate);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let attempts = state
            .failures
            .get(&key)
            .map(|failure| failure.attempts.saturating_add(1))
            .unwrap_or(1);
        let retry_at = now + self.policy.backoff(attempts);
        state.failures.insert(
            key.clone(),
            FailureState {
                attempts,
                retry_at,
                not_after: certificate.not_after,
            },
        );
        retry_at
    }

    fn clear_failure(&self, key: &str) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .failures
            .remove(key);
    }

    /// Drop backoff state for certificates that were replaced (for example by auto-HTTPS) while
    /// they were failing.
    fn prune_failures(&self) {
        let current: BTreeMap<String, SystemTime> = self
            .store
            .certificates()
            .into_iter()
            .map(|certificate| (certificate_key(&certificate), certificate.not_after))
            .collect();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .failures
            .retain(|key, failure| current.get(key) == Some(&failure.not_after));
    }

    fn record_history(&self, outcome: RenewalOutcome) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.history.push_back(outcome);
        while state.history.len() > HISTORY_LIMIT {
            state.history.pop_front();
        }
    }

    async fn persist(&self, certificate: &Certificate) -> Result<()> {
        let mut stored = stored_certificate(certificate)?;
        let primary = certificate.domains.first().ok_or_else(|| {
            Error::Certificate("certificate to persist has no domains".to_string())
        })?;
        let key = format!(
            "{}/{}",
            caddy_issuer_key(&certificate.issuer),
            caddy_certificate_storage_name(primary)
        );
        // Issuers persist their own metadata (for ACME: url/ca/account) before the scheduler
        // stores the certificate. Preserve that CertMagic metadata, plus any unknown fields a
        // newer Caddy may have written, instead of overwriting the `.json` with just `sans`.
        if let Some(existing) = self.storage.load(&key).await? {
            stored.issuer_data = existing.issuer_data;
            stored.metadata_extra = existing.metadata_extra;
        }
        self.storage.store(&key, &stored).await
    }
}

/// Handle returned by [`RenewalScheduler::start`].
pub struct RenewalSchedulerHandle {
    scheduler: Arc<RenewalScheduler>,
    task: tokio::task::JoinHandle<()>,
}

impl fmt::Debug for RenewalSchedulerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenewalSchedulerHandle")
            .field("finished", &self.task.is_finished())
            .finish()
    }
}

impl RenewalSchedulerHandle {
    /// Stop the scheduler and wait for the background task to finish.
    pub async fn stop(self) {
        self.scheduler.stop();
        let _ = self.task.await;
    }

    /// Whether the background task has finished.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// The scheduler this handle controls.
    pub fn scheduler(&self) -> &Arc<RenewalScheduler> {
        &self.scheduler
    }

    /// Abort the background task without waiting.
    pub fn abort(self) {
        self.scheduler.stop();
        self.task.abort();
    }
}

fn certificate_key(certificate: &Certificate) -> String {
    let mut domains = normalized_domains(&certificate.domains);
    domains.sort();
    domains.join("\0")
}

fn unix_seconds(time: SystemTime) -> Result<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            Error::Certificate("certificate validity starts before the Unix epoch".to_string())
        })
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        // The base64 alphabet is ASCII, so from_utf8 cannot fail here.
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn stored_certificate(certificate: &Certificate) -> Result<StoredCertificate> {
    if certificate.cert_chain_der.is_empty() {
        return Err(Error::Certificate(
            "cannot persist a certificate with an empty chain".to_string(),
        ));
    }
    Ok(StoredCertificate {
        certificate_pem: certificate
            .cert_chain_der
            .iter()
            .map(|der| pem_encode("CERTIFICATE", der))
            .collect(),
        private_key_pem: pem_encode("PRIVATE KEY", &certificate.private_key_der),
        domains: certificate.domains.clone(),
        not_after_unix: unix_seconds(certificate.not_after)?,
        issuer_data: None,
        metadata_extra: std::collections::BTreeMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::parse_pem_certificate_chain;
    use crate::storage::MemoryStorage;
    use std::sync::atomic::AtomicUsize;

    const FIXTURE_CERTIFICATE_PEM: &str = include_str!(
        "../tests/fixtures/caddy-data/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt"
    );
    const FIXTURE_PRIVATE_KEY_PEM: &str = include_str!(
        "../tests/fixtures/caddy-data/certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.key"
    );

    fn fixture_chain_der() -> Vec<Vec<u8>> {
        crate::storage::certificate_chain_der(
            &parse_pem_certificate_chain(FIXTURE_CERTIFICATE_PEM).expect("fixture chain"),
        )
        .expect("fixture chain DER")
    }

    fn fixture_private_key_der() -> Vec<u8> {
        crate::storage::private_key_der(FIXTURE_PRIVATE_KEY_PEM).expect("fixture key DER")
    }

    fn certificate(domains: &[&str], not_before: SystemTime, not_after: SystemTime) -> Certificate {
        Certificate {
            domains: domains.iter().map(|domain| domain.to_string()).collect(),
            cert_chain_der: fixture_chain_der(),
            private_key_der: fixture_private_key_der(),
            not_before,
            not_after,
            issuer: "fake-ca".to_string(),
        }
    }

    fn ninety_day_certificate(domains: &[&str], not_before: SystemTime) -> Certificate {
        certificate(
            domains,
            not_before,
            not_before + Duration::from_secs(90 * 86_400),
        )
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    // ---- policy --------------------------------------------------------------------------

    #[test]
    fn renewal_time_is_one_third_remaining_without_jitter() {
        let policy = RenewalPolicy::new().with_jitter(Duration::ZERO);
        let start = at(1_000);
        let certificate = ninety_day_certificate(&["example.com"], start);
        // Two thirds through a 90-day lifetime.
        assert_eq!(
            policy.renewal_time(&certificate),
            start + Duration::from_secs(60 * 86_400)
        );
        // `Certificate::renewal_time` still uses floating point and may round a nanosecond later.
        let model = certificate.renewal_time();
        let policy_due = policy.renewal_time(&certificate);
        assert!(model >= policy_due);
        assert!(model.duration_since(policy_due).unwrap_or_default() <= Duration::from_secs(1));
    }

    #[test]
    fn jitter_is_deterministic_and_bounded() {
        let policy = RenewalPolicy::new();
        let start = at(1_000);
        let first = ninety_day_certificate(&["example.com"], start);
        let second = ninety_day_certificate(&["example.com"], start);
        let other = ninety_day_certificate(&["other.example"], start);
        let nominal = RenewalPolicy::new()
            .with_jitter(Duration::ZERO)
            .renewal_time(&first);
        let jittered = policy.renewal_time(&first);
        assert_eq!(
            jittered,
            policy.renewal_time(&second),
            "jitter must be stable"
        );
        assert!(jittered >= nominal);
        assert!(jittered <= nominal + DEFAULT_RENEWAL_JITTER);
        // Different names almost certainly hash to a different jitter; the important property is
        // that each stays within the bound.
        let other_due = policy.renewal_time(&other);
        assert!(other_due >= nominal && other_due <= nominal + DEFAULT_RENEWAL_JITTER);
    }

    #[test]
    fn explicit_renewal_window_overrides_fraction() {
        let start = at(1_000);
        let certificate = ninety_day_certificate(&["example.com"], start);
        let policy = RenewalPolicy::new()
            .with_jitter(Duration::ZERO)
            .with_renewal_window(Some(Duration::from_secs(30 * 86_400)));
        assert_eq!(
            policy.renewal_time(&certificate),
            certificate.not_after - Duration::from_secs(30 * 86_400)
        );
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let policy =
            RenewalPolicy::new().with_backoff(Duration::from_secs(10), Duration::from_secs(40));
        assert_eq!(policy.backoff(1), Duration::from_secs(10));
        assert_eq!(policy.backoff(2), Duration::from_secs(20));
        assert_eq!(policy.backoff(3), Duration::from_secs(40));
        assert_eq!(policy.backoff(10), Duration::from_secs(40));
    }

    // ---- shared store --------------------------------------------------------------------

    #[test]
    fn hot_swap_keeps_old_snapshot_and_updates_new_readers() {
        let store = SharedCertificateStore::new();
        let start = at(1_000);
        let old = ninety_day_certificate(&["example.com"], start);
        store.insert(old.clone()).unwrap();
        let snapshot = store.get("example.com").expect("old certificate");
        assert_eq!(snapshot.not_after, old.not_after);

        let renewed = certificate(
            &["example.com"],
            start + Duration::from_secs(80 * 86_400),
            start + Duration::from_secs(170 * 86_400),
        );
        store.insert(renewed.clone()).unwrap();

        let current = store.get("EXAMPLE.COM").expect("new certificate");
        assert!(!Arc::ptr_eq(&snapshot, &current));
        assert_eq!(current.not_after, renewed.not_after);
        // The snapshot an in-flight handshake already holds is untouched.
        assert_eq!(snapshot.not_after, old.not_after);
        assert_eq!(store.certificates().len(), 1);
    }

    #[test]
    fn store_selects_wildcards_and_next_renewal() {
        let store = SharedCertificateStore::new();
        let start = at(1_000);
        store
            .insert(ninety_day_certificate(&["*.example.net"], start))
            .unwrap();
        store
            .insert(certificate(
                &["example.com"],
                start,
                start + Duration::from_secs(30 * 86_400),
            ))
            .unwrap();
        assert!(store.select(Some("api.example.net")).is_some());
        assert!(store.select(Some("example.net")).is_some()); // default certificate
        assert!(store.select(Some("example.com")).is_some());

        let policy = RenewalPolicy::new().with_jitter(Duration::ZERO);
        let next = store.next_renewal(start, &policy).expect("next renewal");
        assert_eq!(next.domains, vec!["example.com".to_string()]);
    }

    #[test]
    fn removing_names_clears_default_when_store_becomes_empty() {
        let store = SharedCertificateStore::new();
        store
            .insert(ninety_day_certificate(&["example.com"], at(1_000)))
            .unwrap();
        assert!(store.remove(&["example.com".to_string()]));
        assert!(store.is_empty());
        assert!(store.default_certificate().is_none());
    }

    // ---- test doubles --------------------------------------------------------------------

    struct FakeIssuer {
        calls: AtomicUsize,
        fail: AtomicBool,
        failure: String,
        delay: Duration,
        not_before: SystemTime,
        not_after: SystemTime,
        ari: Mutex<Option<RenewalInfo>>,
        ari_fails: AtomicBool,
    }

    impl FakeIssuer {
        fn new(not_before: SystemTime, not_after: SystemTime) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail: AtomicBool::new(false),
                failure: "fake issuer failure".to_string(),
                delay: Duration::ZERO,
                not_before,
                not_after,
                ari: Mutex::new(None),
                ari_fails: AtomicBool::new(false),
            }
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn with_ari(self, info: RenewalInfo) -> Self {
            *self
                .ari
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(info);
            self
        }

        fn with_ari_failure(self) -> Self {
            self.ari_fails.store(true, Ordering::SeqCst);
            self
        }
    }

    #[async_trait]
    impl CertificateIssuer for FakeIssuer {
        fn name(&self) -> &'static str {
            "fake"
        }

        async fn renewal_info(&self, _certificate: &Certificate) -> Result<Option<RenewalInfo>> {
            if self.ari_fails.load(Ordering::SeqCst) {
                return Err(Error::Issuer("mock ARI endpoint failed".to_string()));
            }
            Ok(self
                .ari
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone())
        }

        async fn obtain(&self, request: &IssuanceRequest) -> Result<Certificate> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.fail.load(Ordering::SeqCst) {
                return Err(Error::Issuer(self.failure.clone()));
            }
            let domains: Vec<&str> = request.domains.iter().map(String::as_str).collect();
            Ok(certificate(&domains, self.not_before, self.not_after))
        }
    }

    struct FailingStorage;

    #[async_trait]
    impl CertificateStorage for FailingStorage {
        fn name(&self) -> &'static str {
            "failing"
        }

        async fn load(&self, _key: &str) -> Result<Option<StoredCertificate>> {
            Ok(None)
        }

        async fn store(&self, _key: &str, _certificate: &StoredCertificate) -> Result<()> {
            Err(Error::Storage("disk full".to_string()))
        }

        async fn delete(&self, _key: &str) -> Result<()> {
            Ok(())
        }

        async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    fn scheduler<C: RenewalClock + 'static>(
        issuer: Arc<dyn CertificateIssuer>,
        storage: Arc<dyn CertificateStorage>,
        store: Arc<SharedCertificateStore>,
        clock: Arc<C>,
    ) -> Arc<RenewalScheduler> {
        Arc::new(
            RenewalScheduler::new(issuer, storage, store, clock).with_policy(
                RenewalPolicy::new()
                    .with_jitter(Duration::ZERO)
                    .with_backoff(Duration::from_secs(30), Duration::from_secs(300)),
            ),
        )
    }

    fn ari_window(start: SystemTime, selected: SystemTime) -> RenewalInfo {
        RenewalInfo {
            suggested_window: crate::acme::ari::SuggestedWindow {
                start,
                end: start + Duration::from_secs(2 * 86_400),
            },
            explanation_url: Some("https://ca.test/ari".to_string()),
            unique_identifier: "test-cert-id".to_string(),
            retry_after: None,
            selected_time: Some(selected),
        }
    }

    #[tokio::test]
    async fn ari_selected_time_overrides_the_local_renewal_heuristic() {
        let start = at(1_000);
        let certificate = ninety_day_certificate(&["ari.example"], start);
        let store = Arc::new(SharedCertificateStore::new());
        store.insert(certificate).unwrap();
        let clock = Arc::new(ManualClock::new(start + Duration::from_secs(61 * 86_400)));
        let selected = start + Duration::from_secs(81 * 86_400);
        // Local heuristic would renew at ~day 60, but ARI suggests day 81.
        let issuer = Arc::new(
            FakeIssuer::new(selected, selected + Duration::from_secs(90 * 86_400))
                .with_ari(ari_window(selected - Duration::from_secs(86_400), selected)),
        );
        let scheduler = scheduler(
            issuer.clone(),
            Arc::new(MemoryStorage::new()),
            Arc::clone(&store),
            Arc::clone(&clock),
        );
        let outcomes = scheduler.run_once(clock.now()).await;
        assert!(outcomes.is_empty(), "ARI window is still in the future");
        assert_eq!(issuer.calls(), 0);
        let info = scheduler
            .renewal_info_for(&store.certificates()[0])
            .expect("ARI cached");
        assert_eq!(info.selected_time, Some(selected));
        let due = scheduler.next_renewal(clock.now()).unwrap().due_at;
        assert_eq!(
            due,
            selected - scheduler.policy().check_interval,
            "renewal wakes the check interval before the ARI-selected time"
        );

        clock.set(selected);
        let outcomes = scheduler.run_once(clock.now()).await;
        assert!(
            outcomes.iter().any(RenewalOutcome::is_renewed),
            "{outcomes:?}"
        );
        assert_eq!(issuer.calls(), 1);
    }

    #[tokio::test]
    async fn ari_can_renew_earlier_than_the_local_heuristic() {
        let start = at(1_000);
        let certificate = ninety_day_certificate(&["early.example"], start);
        let store = Arc::new(SharedCertificateStore::new());
        store.insert(certificate).unwrap();
        let selected = start + Duration::from_secs(21 * 86_400);
        let clock = Arc::new(ManualClock::new(selected));
        let issuer = Arc::new(
            FakeIssuer::new(selected, selected + Duration::from_secs(90 * 86_400)).with_ari(
                ari_window(start + Duration::from_secs(20 * 86_400), selected),
            ),
        );
        let scheduler = scheduler(
            issuer.clone(),
            Arc::new(MemoryStorage::new()),
            Arc::clone(&store),
            clock,
        );
        let outcomes = scheduler.run_once(selected).await;
        assert!(
            outcomes.iter().any(RenewalOutcome::is_renewed),
            "{outcomes:?}"
        );
        assert_eq!(issuer.calls(), 1);
    }

    #[tokio::test]
    async fn ari_failure_or_absence_falls_back_to_the_local_heuristic() {
        for with_failure in [false, true] {
            let start = at(1_000);
            let certificate = ninety_day_certificate(&["fallback.example"], start);
            let store = Arc::new(SharedCertificateStore::new());
            store.insert(certificate).unwrap();
            // Local renewal is at day 60; before that nothing is due even if ARI fetching fails.
            let clock = Arc::new(ManualClock::new(start + Duration::from_secs(50 * 86_400)));
            let mut issuer = FakeIssuer::new(
                start + Duration::from_secs(60 * 86_400),
                start + Duration::from_secs(150 * 86_400),
            );
            if with_failure {
                issuer = issuer.with_ari_failure();
            }
            let issuer = Arc::new(issuer);
            let scheduler = scheduler(
                issuer.clone(),
                Arc::new(MemoryStorage::new()),
                Arc::clone(&store),
                Arc::clone(&clock),
            );
            assert!(scheduler.run_once(clock.now()).await.is_empty());
            let due = scheduler.next_renewal(clock.now()).unwrap().due_at;
            assert!(
                due <= start + Duration::from_secs(60 * 86_400),
                "local one-third-lifetime heuristic remains the renewal fallback; an ARI retry may wake earlier: {due:?}"
            );
            clock.advance(Duration::from_secs(11 * 86_400));
            let outcomes = scheduler.run_once(clock.now()).await;
            assert!(
                outcomes.iter().any(RenewalOutcome::is_renewed),
                "{outcomes:?}"
            );
            assert_eq!(issuer.calls(), 1);
        }
    }

    // ---- scheduler -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_once_renews_only_due_certificates() {
        let start = at(1_000);
        let store = Arc::new(SharedCertificateStore::new());
        let due = ninety_day_certificate(&["due.example"], start);
        // Longer lifetime: its renewal point is day 120, so it is not due at day 61.
        let not_due = certificate(
            &["later.example"],
            start,
            start + Duration::from_secs(180 * 86_400),
        );
        store.insert(due.clone()).unwrap();
        store.insert(not_due.clone()).unwrap();

        let clock = Arc::new(ManualClock::new(start));
        let issuer = Arc::new(FakeIssuer::new(
            start + Duration::from_secs(30 * 86_400),
            start + Duration::from_secs(120 * 86_400),
        ));
        let storage = Arc::new(MemoryStorage::new());
        let scheduler = scheduler(
            issuer.clone(),
            storage.clone(),
            Arc::clone(&store),
            Arc::clone(&clock),
        );

        // Not due at all.
        let outcomes = scheduler.run_once(start).await;
        assert!(outcomes.is_empty());
        assert_eq!(issuer.calls(), 0);

        // Advance past the renewal point of every certificate (90 days * 2/3 = 60 days).
        clock.advance(Duration::from_secs(61 * 86_400));
        let outcomes = scheduler.run_once(clock.now()).await;
        assert_eq!(outcomes.len(), 1, "only the due certificate renews");
        assert!(outcomes[0].is_renewed(), "{outcomes:?}");
        assert_eq!(issuer.calls(), 1);

        let renewed = store.get("due.example").expect("renewed certificate");
        assert_eq!(renewed.not_after, start + Duration::from_secs(120 * 86_400));
        // The certificate that is not due yet was not touched.
        assert_eq!(
            store.get("later.example").unwrap().not_after,
            not_due.not_after
        );
        // Persisted through CertificateStorage.
        assert_eq!(
            storage.list("").await.unwrap(),
            vec!["fake-ca/due.example".to_string()]
        );
    }

    #[tokio::test]
    async fn failed_renewal_retains_old_certificate_and_backs_off() {
        let start = at(1_000);
        let store = Arc::new(SharedCertificateStore::new());
        let old = ninety_day_certificate(&["example.com"], start);
        store.insert(old.clone()).unwrap();

        let clock = Arc::new(ManualClock::new(start));
        let issuer = Arc::new(FakeIssuer::new(
            start + Duration::from_secs(30 * 86_400),
            start + Duration::from_secs(120 * 86_400),
        ));
        issuer.fail.store(true, Ordering::SeqCst);
        let scheduler = scheduler(
            issuer.clone(),
            Arc::new(MemoryStorage::new()),
            Arc::clone(&store),
            Arc::clone(&clock),
        );

        // Due at two thirds of the lifetime: 60 days.
        let due = start + Duration::from_secs(60 * 86_400);
        clock.set(due);
        let outcomes = scheduler.run_once(clock.now()).await;
        assert_eq!(outcomes.len(), 1);
        let RenewalOutcome::Failed {
            error, retry_at, ..
        } = &outcomes[0]
        else {
            panic!("expected failure, got {outcomes:?}");
        };
        assert!(error.contains("fake issuer failure"), "{error}");
        assert_eq!(*retry_at, due + Duration::from_secs(30));
        assert_eq!(issuer.calls(), 1);
        // Old certificate still installed.
        assert_eq!(store.get("example.com").unwrap().not_after, old.not_after);

        // Before the retry time: no new attempt.
        clock.set(due + Duration::from_secs(15));
        assert!(scheduler.run_once(clock.now()).await.is_empty());
        assert_eq!(issuer.calls(), 1);

        // At the retry time: a second attempt happens and the backoff doubles.
        clock.set(*retry_at);
        let outcomes = scheduler.run_once(clock.now()).await;
        let RenewalOutcome::Failed { retry_at, .. } = &outcomes[0] else {
            panic!("expected failure, got {outcomes:?}");
        };
        assert_eq!(*retry_at, due + Duration::from_secs(30 + 60));
        assert_eq!(issuer.calls(), 2);
        assert_eq!(store.get("example.com").unwrap().not_after, old.not_after);

        // Recovering: the old certificate is replaced and stored.
        issuer.fail.store(false, Ordering::SeqCst);
        clock.set(*retry_at + Duration::from_secs(120));
        let outcomes = scheduler.run_once(clock.now()).await;
        assert!(outcomes[0].is_renewed(), "{outcomes:?}");
        assert_ne!(store.get("example.com").unwrap().not_after, old.not_after);

        // Failure history was cleared after success.
        let failures = scheduler.state.lock().unwrap().failures.len();
        assert_eq!(failures, 0);
    }

    #[tokio::test]
    async fn storage_failure_keeps_old_certificate_and_surfaces() {
        let start = at(1_000);
        let store = Arc::new(SharedCertificateStore::new());
        let old = ninety_day_certificate(&["example.com"], start);
        store.insert(old.clone()).unwrap();

        let clock = Arc::new(ManualClock::new(start + Duration::from_secs(60 * 86_400)));
        let issuer = Arc::new(FakeIssuer::new(
            start + Duration::from_secs(30 * 86_400),
            start + Duration::from_secs(120 * 86_400),
        ));
        let now = clock.now();
        let scheduler = scheduler(
            issuer.clone(),
            Arc::new(FailingStorage),
            Arc::clone(&store),
            clock,
        );

        let outcomes = scheduler.run_once(now).await;
        let RenewalOutcome::Failed { error, .. } = &outcomes[0] else {
            panic!("expected storage failure, got {outcomes:?}");
        };
        assert!(error.contains("disk full"), "{error}");
        assert!(error.contains("certificate storage"), "{error}");
        assert_eq!(issuer.calls(), 1);
        assert_eq!(
            store.get("example.com").unwrap().not_after,
            old.not_after,
            "storage failure must not swap the certificate"
        );
    }

    #[tokio::test]
    async fn concurrent_renewals_are_deduplicated() {
        let start = at(1_000);
        let store = Arc::new(SharedCertificateStore::new());
        let old = ninety_day_certificate(&["example.com"], start);
        store.insert(old.clone()).unwrap();

        let clock = Arc::new(ManualClock::new(start + Duration::from_secs(60 * 86_400)));
        let issuer = Arc::new(
            FakeIssuer::new(
                start + Duration::from_secs(30 * 86_400),
                start + Duration::from_secs(120 * 86_400),
            )
            .with_delay(Duration::from_millis(20)),
        );
        let scheduler = scheduler(
            issuer.clone(),
            Arc::new(MemoryStorage::new()),
            Arc::clone(&store),
            clock,
        );

        let certificate = store.get("example.com").unwrap();
        let (first, second) = tokio::join!(
            scheduler.renew_certificate(Arc::clone(&certificate)),
            scheduler.renew_certificate(Arc::clone(&certificate)),
        );
        let outcomes = [&first, &second];
        let renewed = outcomes
            .iter()
            .filter(|outcome| outcome.is_renewed())
            .count();
        let skipped = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RenewalOutcome::Skipped { .. }))
            .count();
        assert_eq!(renewed, 1, "exactly one renewal: {first:?} / {second:?}");
        assert_eq!(skipped, 1, "the second attempt must be skipped");
        assert_eq!(issuer.calls(), 1, "issuer must be called exactly once");
    }

    #[tokio::test]
    async fn not_due_certificate_reports_not_due() {
        let start = at(1_000);
        let store = Arc::new(SharedCertificateStore::new());
        store
            .insert(ninety_day_certificate(&["example.com"], start))
            .unwrap();
        let clock = Arc::new(ManualClock::new(start));
        let issuer = Arc::new(FakeIssuer::new(start, start + Duration::from_secs(86_400)));
        let scheduler = scheduler(
            issuer.clone(),
            Arc::new(MemoryStorage::new()),
            Arc::clone(&store),
            clock,
        );
        let outcome = scheduler
            .renew_certificate(store.get("example.com").unwrap())
            .await;
        assert!(
            matches!(outcome, RenewalOutcome::NotDue { .. }),
            "{outcome:?}"
        );
        assert_eq!(issuer.calls(), 0);
    }

    #[tokio::test]
    async fn background_scheduler_renews_when_the_clock_advances_and_stops_cleanly() {
        let start = at(1_000);
        let store = Arc::new(SharedCertificateStore::new());
        store
            .insert(ninety_day_certificate(&["example.com"], start))
            .unwrap();
        let clock = Arc::new(ManualClock::new(start));
        let issuer = Arc::new(FakeIssuer::new(
            start + Duration::from_secs(30 * 86_400),
            start + Duration::from_secs(120 * 86_400),
        ));
        let scheduler = scheduler(
            issuer.clone(),
            Arc::new(MemoryStorage::new()),
            Arc::clone(&store),
            Arc::clone(&clock),
        );
        let handle = scheduler.start();
        // Let the background task reach its wait state.
        tokio::task::yield_now().await;
        assert_eq!(issuer.calls(), 0);

        clock.advance(Duration::from_secs(61 * 86_400));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if issuer.calls() > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("scheduler did not renew after the clock advanced");

        tokio::time::timeout(Duration::from_secs(5), handle.stop())
            .await
            .expect("scheduler did not stop");
        assert_eq!(
            store.get("example.com").unwrap().not_after,
            start + Duration::from_secs(120 * 86_400)
        );
    }

    #[tokio::test]
    async fn stop_cancels_a_scheduler_waiting_for_a_far_future_renewal() {
        let start = at(1_000);
        let store = Arc::new(SharedCertificateStore::new());
        store
            .insert(ninety_day_certificate(&["example.com"], start))
            .unwrap();
        let clock = Arc::new(ManualClock::new(start));
        let issuer = Arc::new(FakeIssuer::new(start, start + Duration::from_secs(86_400)));
        let scheduler = scheduler(
            issuer.clone(),
            Arc::new(MemoryStorage::new()),
            Arc::clone(&store),
            clock,
        );
        let handle = scheduler.start();
        tokio::task::yield_now().await;
        tokio::time::timeout(Duration::from_secs(2), handle.stop())
            .await
            .expect("stopping a waiting scheduler must not hang");
        assert!(scheduler.is_stopped());
        assert_eq!(issuer.calls(), 0);
    }

    // ---- resolver hot-swap ---------------------------------------------------------------

    #[tokio::test]
    async fn renewal_is_visible_to_new_resolutions_while_in_flight_handshakes_keep_old_cert() {
        use crate::tls_server::CertificateResolver;

        let start = at(1_000);
        let resolver = Arc::new(CertificateResolver::new());
        let publisher: Arc<dyn CertificatePublisher> = resolver.clone();
        let store = Arc::new(SharedCertificateStore::with_publisher(publisher));

        let old = ninety_day_certificate(&["example.com"], start);
        store.insert(old.clone()).unwrap();
        let in_flight = resolver
            .select(Some("example.com"))
            .expect("old certificate in resolver");

        let clock = Arc::new(ManualClock::new(start + Duration::from_secs(60 * 86_400)));
        let issuer = Arc::new(FakeIssuer::new(
            start + Duration::from_secs(30 * 86_400),
            start + Duration::from_secs(120 * 86_400),
        ));
        let scheduler = scheduler(
            issuer,
            Arc::new(MemoryStorage::new()),
            Arc::clone(&store),
            clock,
        );
        let outcomes = scheduler.run_once(scheduler.clock().now()).await;
        assert!(outcomes[0].is_renewed(), "{outcomes:?}");

        let current = resolver
            .select(Some("example.com"))
            .expect("new certificate in resolver");
        assert!(
            !Arc::ptr_eq(&in_flight, &current),
            "resolver must serve the renewed certificate"
        );
        // The old `Arc` an in-flight handshake already resolved is still alive and usable.
        assert_eq!(in_flight.cert.len(), 2, "old chain is still usable");
        assert_eq!(
            store.get("example.com").unwrap().not_after,
            start + Duration::from_secs(120 * 86_400)
        );
    }

    #[tokio::test]
    async fn new_certificate_wakes_a_scheduler_with_an_empty_store() {
        let start = at(1_000);
        let store = Arc::new(SharedCertificateStore::new());
        let clock = Arc::new(ManualClock::new(start));
        let issuer = Arc::new(FakeIssuer::new(
            start + Duration::from_secs(30 * 86_400),
            start + Duration::from_secs(120 * 86_400),
        ));
        let renewal_clock: Arc<dyn RenewalClock> = clock.clone();
        let scheduler = Arc::new(
            RenewalScheduler::new(
                issuer.clone(),
                Arc::new(MemoryStorage::new()),
                Arc::clone(&store),
                renewal_clock,
            )
            .with_policy(RenewalPolicy::new().with_jitter(Duration::ZERO)),
        );
        let handle = scheduler.start();
        tokio::task::yield_now().await;
        assert!(scheduler.next_renewal(clock.now()).is_none());

        // A certificate that is already due when added wakes the scheduler immediately.
        store
            .insert(certificate(
                &["example.com"],
                start - Duration::from_secs(90 * 86_400),
                start + Duration::from_secs(86_400),
            ))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if issuer.calls() > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("adding a due certificate must wake the scheduler");
        handle.stop().await;
    }
}
