//! The UDP session table: one session per `(source, destination)` pair, expired on idle.
//!
//! A datagram socket has no connections, so an L4 proxy has to invent them: a session is the
//! association between one peer and the upstream it was routed to, and it is what lets a reply be
//! relayed back to the right peer. [`UdpSessionTable`] keys those sessions by the
//! `(source, destination)` pair the task specifies and expires each one after its route's idle
//! timeout.
//!
//! Two properties matter more than throughput here:
//!
//! * **Bounded memory.** The table never grows without limit. When a new session would exceed the
//!   configured capacity, the least-recently-used session is evicted first, and every eviction is
//!   reported through a [`EvictionLog`] callback so an operator can see a flood rather than only its
//!   aftermath.
//! * **Idleness is time-driven, not traffic-driven.** [`UdpSessionTable::sweep`] is the only thing
//!   that expires sessions, and it is passed the current instant explicitly. Nothing reads the wall
//!   clock internally, so tests are deterministic and a caller can expire on its own timer tick.
//!
//! Two deliberate departures from ADR-031's §4.4 sketch, both recorded here because the ADR is a
//! design sketch and this is what was actually built:
//!
//! * ADR-031 draws the table as a `DashMap` with a `cleanup_interval` and "a background task evicts
//!   idle sessions". This table is an ordinary `HashMap` whose `sweep` the owner drives, because a
//!   background evictor makes expiry non-deterministic to test and hides a whole class of bug behind
//!   a sleep — the expiry rule is verified here by passing `Instant`s, not by waiting. A caller that
//!   wants a background tick can spawn one that calls [`UdpSessionTable::sweep`]; nothing in this
//!   module spawns a task or reads a clock.
//! * ADR-031 keys sessions by `(SocketAddr, SocketAddr)` and keeps the matched route on the session.
//!   [`SessionKey`] is that same pair as a named type, and the session records the matched upstream
//!   and idle timeout rather than an `Arc<L4Route>`, so a live session is not invalidated when the
//!   configuration is reloaded underneath it.
//!
//! `udp`/`asn`/payload matcher selection and the handler pipeline that ADR-031's datagram flow puts
//! on top of this table belong to T-L4-011, which adapts configuration onto these tables.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The default idle timeout, in seconds.
///
/// The task specifies 30s, which is long enough that a quiet but live flow survives sporadic
/// datagrams and short enough that a dead peer's session is reclaimed promptly.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The default cap on live sessions.
///
/// A flood of spoofed sources would otherwise allocate one session per source until the process
/// dies; a fixed default keeps memory bounded even when the operator configures nothing.
pub const DEFAULT_MAX_SESSIONS: usize = 8192;

/// The `(source, destination)` pair that identifies one UDP session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionKey {
    source: SocketAddr,
    destination: SocketAddr,
}

impl SessionKey {
    /// Builds a key from the peer's source address and the socket's destination address.
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            source,
            destination,
        }
    }

    /// The peer address.
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// The local (destination) address the datagram arrived on.
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }
}

impl fmt::Display for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}->{}", self.source, self.destination)
    }
}

/// A live UDP session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpSession {
    key: SessionKey,
    upstream: String,
    packets: u64,
    bytes: u64,
    last_seen: Instant,
    idle_timeout: Duration,
}

impl UdpSession {
    /// The session's key.
    pub fn key(&self) -> SessionKey {
        self.key
    }

    /// The upstream this session proxies to, empty when the matched action drops datagrams.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// Datagrams seen on this session so far.
    pub fn packets(&self) -> u64 {
        self.packets
    }

    /// Bytes seen on this session so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The instant the session last carried a datagram.
    pub fn last_seen(&self) -> Instant {
        self.last_seen
    }

    /// The idle timeout this session expires after.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Whether the session has been idle for at least its timeout at `now`.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_seen) >= self.idle_timeout
    }
}

/// Why a session left the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictionCause {
    /// It sat idle past its timeout.
    Expired,
    /// It was the least-recently-used session when the table was full.
    Capacity,
}

impl EvictionCause {
    /// Short, stable name for logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Capacity => "capacity",
        }
    }
}

/// A record of one session leaving the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvictionEvent {
    /// The session that was removed, as it was at removal.
    pub session: UdpSession,
    /// Why it was removed.
    pub cause: EvictionCause,
    /// The table's size after the removal.
    pub remaining: usize,
}

/// Where evictions are reported.
///
/// Implementations must not block: this runs on the datagram path.
pub trait EvictionLog: Send + Sync {
    /// Called once per removed session.
    fn record(&self, event: &EvictionEvent);
}

/// An [`EvictionLog`] that discards events, for callers that do not care.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardEvictions;

impl EvictionLog for DiscardEvictions {
    fn record(&self, _event: &EvictionEvent) {}
}

/// Counters describing the table as a whole, kept so a flood is visible even when eviction events
/// are discarded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionTableStats {
    /// Sessions created (one per `(source, destination)` pair first seen or re-created after expiry).
    pub created: u64,
    /// Sessions reused for a later datagram.
    pub reused: u64,
    /// Sessions removed because they idled past their timeout.
    pub expired: u64,
    /// Sessions removed to stay within capacity.
    pub evicted_for_capacity: u64,
}

/// The UDP session table.
pub struct UdpSessionTable {
    sessions: HashMap<SessionKey, UdpSession>,
    max_sessions: usize,
    default_idle_timeout: Duration,
    evictions: Arc<dyn EvictionLog>,
    stats: SessionTableStats,
}

impl fmt::Debug for UdpSessionTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSessionTable")
            .field("sessions", &self.sessions.len())
            .field("max_sessions", &self.max_sessions)
            .field("default_idle_timeout", &self.default_idle_timeout)
            .field("stats", &self.stats)
            .finish()
    }
}

impl UdpSessionTable {
    /// A table with the default capacity and idle timeout.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_SESSIONS, DEFAULT_IDLE_TIMEOUT)
    }

    /// A table with an explicit capacity and default idle timeout.
    ///
    /// A capacity of zero is clamped to one: a table that can hold nothing could not carry a single
    /// datagram, and quietly dropping every packet is worse than keeping one session.
    pub fn with_limits(max_sessions: usize, default_idle_timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions: max_sessions.max(1),
            default_idle_timeout,
            evictions: Arc::new(DiscardEvictions),
            stats: SessionTableStats::default(),
        }
    }

    /// Installs the eviction log.
    pub fn with_eviction_log(mut self, log: Arc<dyn EvictionLog>) -> Self {
        self.evictions = log;
        self
    }

    /// The capacity.
    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// The default idle timeout.
    pub fn default_idle_timeout(&self) -> Duration {
        self.default_idle_timeout
    }

    /// The number of live sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the table holds no sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// The table's lifetime counters.
    pub fn stats(&self) -> SessionTableStats {
        self.stats
    }

    /// Looks up a live session without changing it.
    pub fn get(&self, key: &SessionKey) -> Option<&UdpSession> {
        self.sessions.get(key)
    }

    /// Records one datagram for `key` and returns the session it belongs to.
    ///
    /// On the first datagram for a pair the session is created with `upstream` and `idle_timeout`
    /// (the matched route's values). Later datagrams reuse the existing session, refresh its idle
    /// clock and accumulate the packet and byte counts — the upstream and timeout of an established
    /// session are not re-evaluated, so a route change does not migrate a live flow mid-stream.
    ///
    /// When creating a session would exceed capacity, the least-recently-used session is evicted
    /// first, so the table never grows past [`Self::max_sessions`]. An expired session for the same
    /// key is replaced rather than reused, so a session can never outlive its idle timeout.
    pub fn observe(
        &mut self,
        key: SessionKey,
        now: Instant,
        packets: u64,
        bytes: u64,
        upstream: impl Into<String>,
        idle_timeout: Option<Duration>,
    ) -> &UdpSession {
        let timeout = idle_timeout.unwrap_or(self.default_idle_timeout);

        // An entry for this key that has already expired must not be resurrected: expire it first so
        // the create path below starts a fresh session with the current route's upstream.
        if self
            .sessions
            .get(&key)
            .is_some_and(|session| session.is_expired(now))
        {
            if let Some(old) = self.sessions.remove(&key) {
                self.record_eviction(old, EvictionCause::Expired, now);
            }
        }

        if self.sessions.contains_key(&key) {
            let session = self
                .sessions
                .get_mut(&key)
                .expect("presence was just checked");
            session.packets = session.packets.saturating_add(packets);
            session.bytes = session.bytes.saturating_add(bytes);
            session.last_seen = now;
            self.stats.reused += 1;
            return self
                .sessions
                .get(&key)
                .expect("the session was just updated");
        }

        if self.sessions.len() >= self.max_sessions {
            self.evict_least_recently_used(now);
        }

        let session = UdpSession {
            key,
            upstream: upstream.into(),
            packets,
            bytes,
            last_seen: now,
            idle_timeout: timeout,
        };
        self.stats.created += 1;
        self.sessions.insert(key, session);
        self.sessions.get(&key).expect("just inserted")
    }

    /// Expires every session idle for at least its timeout at `now`.
    ///
    /// Returns the number of sessions removed. Callers drive this on their own timer rather than
    /// relying on a background task, so expiry is deterministic in tests and observable in logs.
    pub fn sweep(&mut self, now: Instant) -> usize {
        let expired: Vec<SessionKey> = self
            .sessions
            .values()
            .filter(|session| session.is_expired(now))
            .map(|session| session.key)
            .collect();
        for key in &expired {
            if let Some(session) = self.sessions.remove(key) {
                self.record_eviction(session, EvictionCause::Expired, now);
            }
        }
        expired.len()
    }

    /// Removes every session, reporting each as capacity eviction.
    pub fn clear(&mut self, now: Instant) {
        let keys: Vec<SessionKey> = self.sessions.keys().copied().collect();
        for key in keys {
            if let Some(session) = self.sessions.remove(&key) {
                self.record_eviction(session, EvictionCause::Capacity, now);
            }
        }
    }

    /// Evicts the session with the oldest `last_seen`.
    fn evict_least_recently_used(&mut self, now: Instant) {
        let victim = self
            .sessions
            .values()
            .min_by_key(|session| session.last_seen)
            .map(|session| session.key);
        if let Some(key) = victim {
            if let Some(session) = self.sessions.remove(&key) {
                self.record_eviction(session, EvictionCause::Capacity, now);
            }
        }
    }

    fn record_eviction(&mut self, session: UdpSession, cause: EvictionCause, _now: Instant) {
        match cause {
            EvictionCause::Expired => self.stats.expired += 1,
            EvictionCause::Capacity => self.stats.evicted_for_capacity += 1,
        }
        let event = EvictionEvent {
            session,
            cause,
            remaining: self.sessions.len(),
        };
        self.evictions.record(&event);
    }
}

impl Default for UdpSessionTable {
    fn default() -> Self {
        Self::new()
    }
}
