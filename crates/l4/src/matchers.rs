//! Connection matchers and their composition.
//!
//! A [`ConnMatcher`] decides whether a buffered L4 connection belongs to a route. Matchers are
//! **pure over the peeked prefix**: they may look at [`StreamContext::buffered`] and at connection
//! metadata (peer address, ASN) but they must never read from the socket or consume the buffered
//! bytes, which is what guarantees a connection can be matched by several routes and then handed to
//! a handler with every byte intact. [`StreamContext::evaluate`] enforces this at runtime: a matcher
//! that reads from the socket or takes the prefix is reported as
//! [`MatcherError::ConsumedStream`] instead of silently corrupting the connection.
//!
//! Matchers are composed exactly like the L7 (HTTP) matchers:
//!
//! - [`MatcherSet::All`] — every member must match (an empty set matches everything);
//! - [`MatcherSet::Any`] — at least one member must match;
//! - a matcher can be negated, and negation applies to the whole match result.

use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use crate::client_hello::Protocol;
use crate::context::{sniff, Sniffed, StreamContext};

/// Connection metadata a matcher may consult without touching the stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionMeta {
    /// The remote address of the connection.
    pub peer: Option<IpAddr>,
    /// The autonomous system number resolved for the peer, if the deployment has ASN data.
    pub asn: Option<u32>,
}

/// The verdict of one matcher, plus the reason when it did not match (kept for diagnostics).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchOutcome {
    matched: bool,
    reason: MatcherError,
}

impl MatchOutcome {
    /// Whether the matcher matched.
    pub fn is_match(&self) -> bool {
        self.matched
    }

    /// Why the matcher did not match (or [`MatcherError::NoMatch`] semantics when it did).
    pub fn reason(&self) -> &MatcherError {
        &self.reason
    }
}

/// A matcher that did not match, could not run, or misbehaved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatcherError {
    /// The connection did not match this matcher (the normal negative case).
    NoMatch,
    /// The connection does not look like TLS, so a TLS matcher cannot decide.
    NotTls,
    /// No SNI / no ALPN was present where the matcher required one.
    Missing(&'static str),
    /// The ASN data was not available for the peer.
    NoAsnData,
    /// A matcher tried to read from or consume the buffered stream; matching must be side-effect
    /// free.
    ConsumedStream,
    /// The peeked prefix was insufficient for this matcher.
    NeedMoreBytes,
}

impl fmt::Display for MatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMatch => f.write_str("connection does not match"),
            Self::NotTls => f.write_str("connection is not TLS"),
            Self::Missing(what) => write!(f, "connection does not carry {what}"),
            Self::NoAsnData => f.write_str("no ASN data for the peer address"),
            Self::ConsumedStream => {
                f.write_str("matcher consumed the stream; matchers must not read or take bytes")
            }
            Self::NeedMoreBytes => f.write_str("peeked prefix is not enough to decide"),
        }
    }
}

impl std::error::Error for MatcherError {}

/// Builds a successful match.
pub fn matched() -> MatchOutcome {
    MatchOutcome {
        matched: true,
        reason: MatcherError::NoMatch,
    }
}

/// Builds a negative outcome carrying the reason.
pub fn unmatched(reason: MatcherError) -> MatchOutcome {
    MatchOutcome {
        matched: false,
        reason,
    }
}

/// A connection-level matcher.
///
/// Implementations receive a [`MatchContext`], which carries the peeked prefix and the connection
/// metadata and nothing else: a matcher physically cannot read from the socket or take the
/// buffered prefix, so "a matcher never consumes bytes" is enforced by the signature. The cost is
/// that the method cannot be `async fn` in the trait; matchers are pure functions of the prefix, so
/// they do not need to be.
pub trait ConnMatcher: Send + Sync {
    /// Short name used in diagnostics and route descriptions.
    fn name(&self) -> &'static str;

    /// Decides the match against the buffered prefix and metadata.
    fn matches(&self, ctx: &MatchContext<'_>) -> MatchOutcome;
}

/// The context a matcher sees: the buffered prefix and the connection metadata, and nothing else.
///
/// Matchers receive `&mut MatchContext` rather than the [`StreamContext`] itself, so they cannot
/// reach the socket or take the prefix at all — the "a matcher never consumes bytes" rule is
/// enforced by the type, not by discipline.
pub struct MatchContext<'a> {
    buffer: &'a [u8],
    meta: &'a ConnectionMeta,
}

impl<'a> MatchContext<'a> {
    /// The buffered prefix the router is deciding on.
    pub fn buffered(&self) -> &[u8] {
        self.buffer
    }

    /// The connection metadata (peer address, ASN).
    pub fn meta(&self) -> &ConnectionMeta {
        self.meta
    }
}

/// Convenience: a boxed matcher.
pub type BoxedMatcher = Arc<dyn ConnMatcherErased>;

/// Object-safe form of [`ConnMatcher`], used by matcher sets.
#[async_trait]
pub trait ConnMatcherErased: Send + Sync {
    /// Short name used in diagnostics and route descriptions.
    fn name(&self) -> &'static str;
    /// Decides the match against the buffered prefix and metadata.
    async fn matches_erased(&self, ctx: &mut MatchContext<'_>) -> MatchOutcome;
}

/// Adapts any [`StreamMatcher`] into the object-safe form matcher sets store.
pub struct StreamMatcherAdapter<T>(pub T);

#[async_trait]
impl<T: ConnMatcher> ConnMatcherErased for StreamMatcherAdapter<T> {
    fn name(&self) -> &'static str {
        ConnMatcher::name(&self.0)
    }

    async fn matches_erased(&self, ctx: &mut MatchContext<'_>) -> MatchOutcome {
        ConnMatcher::matches(&self.0, ctx)
    }
}

/// Boxes a [`ConnMatcher`] for use inside a [`MatcherSet`].
pub fn matcher<T: ConnMatcher + 'static>(inner: T) -> Arc<dyn ConnMatcherErased> {
    Arc::new(StreamMatcherAdapter(inner))
}

/// A matcher over a buffered prefix. The socket is not reachable from here by construction, and
/// every type implementing this trait is also a [`ConnMatcher`] (blanket impl below).
pub trait StreamMatcher<'a>: Send + Sync {
    /// Short name used in diagnostics and route descriptions.
    fn name(&self) -> &'static str;
    /// Decides the match against `buffer` and metadata.
    fn matches_buffer(&self, buffer: &[u8], meta: &ConnectionMeta) -> MatchOutcome;
}

impl<T: StreamMatcher<'static> + Send + Sync> ConnMatcher for T {
    fn name(&self) -> &'static str {
        StreamMatcher::name(self)
    }

    fn matches(&self, ctx: &MatchContext<'_>) -> MatchOutcome {
        self.matches_buffer(ctx.buffered(), ctx.meta())
    }
}

/// A matcher set: `all`/`any`/`not` composition of matchers.
#[derive(Default)]
pub struct MatcherSet {
    root: Option<Node>,
    stats: Option<MatcherStats>,
}

enum Node {
    All(Vec<Node>),
    Any(Vec<Node>),
    Not(Box<Node>),
    Leaf(Arc<dyn ConnMatcherErased>),
}

impl MatcherSet {
    /// A set with diagnostics counters attached: every evaluation updates them.
    pub fn with_stats(self, stats: MatcherStats) -> Self {
        Self {
            stats: Some(stats),
            ..self
        }
    }

    /// The diagnostics counters, if this set has any.
    pub fn stats(&self) -> Option<&MatcherStats> {
        self.stats.as_ref()
    }

    /// An empty set, which matches everything (matching the L7 semantics).
    pub fn new() -> Self {
        Self::default()
    }

    /// Requires every member to match.
    pub fn all<I>(matchers: I) -> Self
    where
        I: IntoIterator<Item = Arc<dyn ConnMatcherErased>>,
    {
        Self {
            root: Some(Node::All(matchers.into_iter().map(Node::Leaf).collect())),
            stats: None,
        }
    }

    /// Requires at least one member to match.
    pub fn any<I>(matchers: I) -> Self
    where
        I: IntoIterator<Item = Arc<dyn ConnMatcherErased>>,
    {
        Self {
            root: Some(Node::Any(matchers.into_iter().map(Node::Leaf).collect())),
            stats: None,
        }
    }

    /// Negates a matcher.
    pub fn not(matcher: Arc<dyn ConnMatcherErased>) -> Self {
        Self {
            root: Some(Node::Not(Box::new(Node::Leaf(matcher)))),
            stats: None,
        }
    }

    /// Composes two sets conjunctively (the Caddy `all` wrapper). Diagnostics counters are not
    /// merged: the composed set starts without them.
    pub fn and(self, other: Self) -> Self {
        let left = self.root.into_iter();
        let right = other.root.into_iter();
        let members: Vec<Node> = left.chain(right).collect();
        if members.is_empty() {
            return Self::new();
        }
        Self {
            root: Some(Node::All(members)),
            stats: None,
        }
    }

    /// Composes two sets disjunctively (the Caddy `any` wrapper).
    pub fn or(self, other: Self) -> Self {
        let left = self.root.into_iter();
        let right = other.root.into_iter();
        let members: Vec<Node> = left.chain(right).collect();
        if members.is_empty() {
            return Self::new();
        }
        Self {
            root: Some(Node::Any(members)),
            stats: None,
        }
    }

    /// Wraps this set in a negation.
    pub fn negate(self) -> Self {
        match self.root {
            None => Self::new(),
            Some(node) => Self {
                root: Some(Node::Not(Box::new(node))),
                stats: None,
            },
        }
    }

    /// Whether the set is empty (matches everything).
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Evaluates the set against a buffered prefix, updating this set's [`MatcherStats`].
    pub async fn evaluate(&self, buffer: &[u8], meta: &ConnectionMeta) -> MatchOutcome {
        if let Some(stats) = &self.stats {
            stats.evaluated.fetch_add(1, Ordering::Relaxed);
        }
        let outcome = Self::eval(self.root.as_ref(), buffer, meta).await;
        if let Some(stats) = &self.stats {
            if outcome.reason() == &MatcherError::NeedMoreBytes {
                stats.need_more_bytes.fetch_add(1, Ordering::Relaxed);
            }
        }
        outcome
    }

    async fn eval(node: Option<&Node>, buffer: &[u8], meta: &ConnectionMeta) -> MatchOutcome {
        let mut ctx = MatchContext { buffer, meta };
        Self::eval_node(node, &mut ctx).await
    }

    async fn eval_node(node: Option<&Node>, ctx: &mut MatchContext<'_>) -> MatchOutcome {
        match node {
            // An empty set (or an empty `all`) matches everything, like the L7 matchers.
            None => matched(),
            Some(Node::All(members)) => {
                for member in members {
                    let outcome = Box::pin(Self::eval_node(Some(member), ctx)).await;
                    if !outcome.matched {
                        return outcome;
                    }
                }
                matched()
            }
            Some(Node::Any(members)) => {
                if members.is_empty() {
                    return unmatched(MatcherError::NoMatch);
                }
                let mut last = unmatched(MatcherError::NoMatch);
                for member in members {
                    let outcome = Box::pin(Self::eval_node(Some(member), ctx)).await;
                    if outcome.matched {
                        return outcome;
                    }
                    last = outcome;
                }
                last
            }
            Some(Node::Not(inner)) => {
                let outcome = Box::pin(Self::eval_node(Some(inner), ctx)).await;
                if outcome.matched {
                    unmatched(MatcherError::NoMatch)
                } else {
                    matched()
                }
            }
            Some(Node::Leaf(matcher)) => matcher.matches_erased(ctx).await,
        }
    }
}

impl fmt::Debug for MatcherSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn describe(node: &Node, out: &mut Vec<&'static str>) {
            match node {
                Node::All(members) => {
                    out.push("all(");
                    for member in members {
                        describe(member, out);
                    }
                    out.push(")");
                }
                Node::Any(members) => {
                    out.push("any(");
                    for member in members {
                        describe(member, out);
                    }
                    out.push(")");
                }
                Node::Not(inner) => {
                    out.push("not(");
                    describe(inner, out);
                    out.push(")");
                }
                Node::Leaf(matcher) => out.push(matcher.name()),
            }
        }
        match &self.root {
            None => f.write_str("MatcherSet<all>"),
            Some(node) => {
                let mut out = Vec::new();
                describe(node, &mut out);
                write!(f, "MatcherSet<{}>", out.join(" "))
            }
        }
    }
}

/// Matcher statistics, so a deployment can see how often a matcher could not decide.
#[derive(Clone, Debug, Default)]
pub struct MatcherStats {
    evaluated: Arc<AtomicU64>,
    need_more_bytes: Arc<AtomicU64>,
}

impl MatcherStats {
    /// How many connections were evaluated.
    pub fn evaluated(&self) -> u64 {
        self.evaluated.load(Ordering::Relaxed)
    }

    /// How often a matcher needed more bytes than were peeked.
    pub fn need_more_bytes(&self) -> u64 {
        self.need_more_bytes.load(Ordering::Relaxed)
    }
}

/// Evaluation of [`StreamContext`] against matcher sets, with the safety check that a matcher did
/// not consume the stream.
pub trait EvaluateContext {
    /// Evaluates `set`, verifying the matcher left the stream untouched.
    fn evaluate_set<'a>(
        &'a mut self,
        set: &'a MatcherSet,
        meta: &'a ConnectionMeta,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<MatchOutcome, MatchError>> + 'a>>;
}

/// A matcher evaluation failure (not a negative match).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchError {
    /// The matcher read from the socket or took the buffered prefix.
    ConsumedStream,
}

impl fmt::Display for MatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConsumedStream => MatcherError::ConsumedStream.fmt(f),
        }
    }
}

impl std::error::Error for MatchError {}

impl<S: tokio::io::AsyncRead + Unpin + Send> EvaluateContext for StreamContext<S> {
    fn evaluate_set<'a>(
        &'a mut self,
        set: &'a MatcherSet,
        meta: &'a ConnectionMeta,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<MatchOutcome, MatchError>> + 'a>>
    {
        Box::pin(async move {
            let before = self.buffered_len();
            let snapshot = self.buffered().to_vec();
            let outcome = set.evaluate(&snapshot, meta).await;
            if self.buffered_len() != before || self.buffered() != snapshot.as_slice() {
                return Err(MatchError::ConsumedStream);
            }
            Ok(outcome)
        })
    }
}

/// Matches on the sniffed protocol family of the buffered prefix.
pub struct ProtocolMatcher {
    protocol: Protocol,
}

impl ProtocolMatcher {
    /// Matches connections whose first bytes are `protocol`.
    pub fn new(protocol: Protocol) -> Self {
        Self { protocol }
    }
}

impl StreamMatcher<'_> for ProtocolMatcher {
    fn name(&self) -> &'static str {
        "protocol"
    }

    fn matches_buffer(&self, buffer: &[u8], _meta: &ConnectionMeta) -> MatchOutcome {
        match sniff(buffer) {
            Sniffed::NonTls { protocol } if protocol == self.protocol => matched(),
            Sniffed::Tls { info } if self.protocol.is_tls() && info.is_tls => matched(),
            Sniffed::Unknown if buffer.is_empty() => unmatched(MatcherError::NeedMoreBytes),
            _ => unmatched(MatcherError::NoMatch),
        }
    }
}

/// Matches on the SNI and/or ALPN of a TLS ClientHello.
#[derive(Default)]
pub struct TlsMatcher {
    sni: Vec<SniPattern>,
    alpn: Vec<String>,
}

/// An SNI pattern: exact hostname or a `*.suffix` wildcard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SniPattern {
    /// An exact, lowercased hostname.
    Exact(String),
    /// A wildcard matching any well-formed name ending in `.suffix`.
    Wildcard(String),
}

impl SniPattern {
    /// Parses an SNI pattern, validating it like a route hostname.
    pub fn parse(pattern: &str) -> Result<Self, SniPatternError> {
        let pattern = pattern.trim().to_ascii_lowercase();
        if pattern.is_empty() {
            return Err(SniPatternError("SNI pattern must not be empty".to_string()));
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') {
                return Err(SniPatternError(format!(
                    "invalid wildcard SNI pattern {pattern:?}"
                )));
            }
            return Ok(Self::Wildcard(format!(".{suffix}")));
        }
        if pattern.contains('*') {
            return Err(SniPatternError(format!(
                "invalid SNI pattern {pattern:?}: '*' is only allowed as a leading '*.'"
            )));
        }
        Ok(Self::Exact(pattern))
    }

    /// Whether `sni` (already lowercased) matches this pattern.
    pub fn matches(&self, sni: &str) -> bool {
        match self {
            Self::Exact(expected) => sni == expected,
            Self::Wildcard(suffix) => match sni.strip_suffix(suffix.as_str()) {
                Some(prefix) => {
                    !prefix.is_empty()
                        && !prefix.ends_with('.')
                        && !prefix.split('.').any(|label| label.is_empty())
                }
                None => false,
            },
        }
    }
}

/// An invalid SNI pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SniPatternError(pub String);

impl fmt::Display for SniPatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SniPatternError {}

impl TlsMatcher {
    /// Matches any TLS ClientHello.
    pub fn any() -> Self {
        Self::default()
    }

    /// Adds an exact or wildcard SNI pattern (any of the SNI patterns may match).
    pub fn with_sni(mut self, pattern: SniPattern) -> Self {
        self.sni.push(pattern);
        self
    }

    /// Requires one of the given ALPN protocols.
    pub fn with_alpn(mut self, protocols: impl IntoIterator<Item = String>) -> Self {
        self.alpn.extend(protocols);
        self
    }

    /// The configured SNI patterns.
    pub fn sni_patterns(&self) -> &[SniPattern] {
        &self.sni
    }

    /// The configured ALPN protocols.
    pub fn alpn_required(&self) -> &[String] {
        &self.alpn
    }
}

impl StreamMatcher<'_> for TlsMatcher {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn matches_buffer(&self, buffer: &[u8], _meta: &ConnectionMeta) -> MatchOutcome {
        let Sniffed::Tls { info } = sniff(buffer) else {
            return unmatched(MatcherError::NotTls);
        };
        if !info.is_tls {
            return unmatched(MatcherError::NotTls);
        }
        if !self.sni.is_empty() {
            let Some(sni) = info.sni.as_deref() else {
                return unmatched(MatcherError::Missing("SNI"));
            };
            if !self.sni.iter().any(|pattern| pattern.matches(sni)) {
                return unmatched(MatcherError::NoMatch);
            }
        }
        if !self.alpn.is_empty() {
            if info.alpn.is_empty() {
                return unmatched(MatcherError::Missing("ALPN"));
            }
            if !info.alpn.iter().any(|offered| self.alpn.contains(offered)) {
                return unmatched(MatcherError::NoMatch);
            }
        }
        matched()
    }
}

/// Matches the peer IP against an allowlist of addresses and CIDR prefixes.
#[derive(Clone, Debug, Default)]
pub struct IpMatcher {
    ranges: Vec<IpRange>,
}

/// An IP address range (`a.b.c.d/n`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRange {
    network: IpAddr,
    prefix: u8,
}

impl IpRange {
    /// Parses `10.0.0.0/8`, `::1/128`, or a bare address (host route).
    pub fn parse(spec: &str) -> Result<Self, IpRangeError> {
        let spec = spec.trim();
        let (addr, prefix) = match spec.split_once('/') {
            Some((addr, prefix)) => {
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|_| IpRangeError(format!("invalid prefix length in {spec:?}")))?;
                (addr, Some(prefix))
            }
            None => (spec, None),
        };
        let network: IpAddr = addr
            .parse()
            .map_err(|_| IpRangeError(format!("invalid IP address {addr:?}")))?;
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return Err(IpRangeError(format!(
                "prefix length {prefix} exceeds {max} for {spec:?}"
            )));
        }
        // A range spelled as an IPv4-mapped IPv6 block (`::ffff:a.b.c.d/n`, n >= 96) is the same set
        // of clients as the IPv4 range, which is how `contains` compares them (SEC-MEDIUM-PROXY C2).
        if let (IpAddr::V6(v6), true) = (network, prefix >= 96) {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return Ok(Self {
                    network: IpAddr::V4(v4),
                    prefix: prefix - 96,
                });
            }
        }
        Ok(Self { network, prefix })
    }

    /// Whether `addr` falls inside this range (families must match).
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, what a dual-stack `[::]` listener reports for
    /// an IPv4 client) is also compared as the IPv4 address it stands for, like Caddy's
    /// `netip.Addr.Unmap()` (SEC-MEDIUM-PROXY C2). The raw spelling is still compared first, so a
    /// range that genuinely covers the mapped block (`::/0`) keeps matching.
    pub fn contains(&self, addr: IpAddr) -> bool {
        caddy_rs_core::net::ip_in_net(self.network, self.prefix, addr)
    }
}

/// An invalid IP range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpRangeError(pub String);

impl fmt::Display for IpRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IpRangeError {}

impl IpMatcher {
    /// An empty matcher (nothing matches until a range is added).
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a range; the connection matches if any range contains its peer address.
    pub fn with_range(mut self, range: IpRange) -> Self {
        self.ranges.push(range);
        self
    }

    /// The configured ranges.
    pub fn ranges(&self) -> &[IpRange] {
        &self.ranges
    }
}

impl StreamMatcher<'_> for IpMatcher {
    fn name(&self) -> &'static str {
        "ip"
    }

    fn matches_buffer(&self, _buffer: &[u8], meta: &ConnectionMeta) -> MatchOutcome {
        let Some(peer) = meta.peer else {
            return unmatched(MatcherError::Missing("a peer address"));
        };
        if self.ranges.iter().any(|range| range.contains(peer)) {
            matched()
        } else {
            unmatched(MatcherError::NoMatch)
        }
    }
}

/// Matches the peer's autonomous system number against an allowlist.
#[derive(Clone, Debug, Default)]
pub struct AsnMatcher {
    asns: Vec<u32>,
}

impl AsnMatcher {
    /// An empty matcher (nothing matches until an ASN is added).
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an ASN; the connection matches if any listed ASN equals the peer's ASN.
    pub fn with_asn(mut self, asn: u32) -> Self {
        self.asns.push(asn);
        self
    }

    /// The configured ASNs.
    pub fn asns(&self) -> &[u32] {
        &self.asns
    }
}

impl StreamMatcher<'_> for AsnMatcher {
    fn name(&self) -> &'static str {
        "asn"
    }

    fn matches_buffer(&self, _buffer: &[u8], meta: &ConnectionMeta) -> MatchOutcome {
        let Some(asn) = meta.asn else {
            return unmatched(MatcherError::NoAsnData);
        };
        if self.asns.contains(&asn) {
            matched()
        } else {
            unmatched(MatcherError::NoMatch)
        }
    }
}

/// Matches the L7 protocol a connection carries, reusing the protocol sniffers.
pub struct L7Matcher {
    protocol: L7Protocol,
}

/// The non-TLS protocol families L4 can route on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L7Protocol {
    /// HTTP/1.x request line.
    Http,
    /// HTTP/2 connection preface.
    Http2,
    /// SSH identification banner.
    Ssh,
}

impl L7Matcher {
    /// Matches `protocol`.
    pub fn new(protocol: L7Protocol) -> Self {
        Self { protocol }
    }
}

impl StreamMatcher<'_> for L7Matcher {
    fn name(&self) -> &'static str {
        match self.protocol {
            L7Protocol::Http => "http",
            L7Protocol::Http2 => "http2",
            L7Protocol::Ssh => "ssh",
        }
    }

    fn matches_buffer(&self, buffer: &[u8], _meta: &ConnectionMeta) -> MatchOutcome {
        let family = match self.protocol {
            L7Protocol::Http => {
                if buffer.first() == Some(&b'P') && b"PRI * HTTP/2.0".starts_with(buffer) {
                    return unmatched(MatcherError::NeedMoreBytes);
                }
                Protocol::Http1
            }
            L7Protocol::Http2 => Protocol::Http2,
            L7Protocol::Ssh => Protocol::Ssh,
        };
        match sniff(buffer) {
            Sniffed::NonTls { protocol } if protocol == family => matched(),
            Sniffed::Tls { .. } => unmatched(MatcherError::NoMatch),
            _ => unmatched(MatcherError::NoMatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        matched, matcher, unmatched, AsnMatcher, ConnectionMeta, IpMatcher, IpRange, L7Matcher,
        L7Protocol, MatchError, MatcherError, MatcherSet, SniPattern, StreamMatcher, TlsMatcher,
    };
    use crate::context::StreamContext;
    use crate::matchers::EvaluateContext;
    use std::net::{IpAddr, Ipv4Addr};

    /// Builds a minimal ClientHello. The SNI extension carries `data = list_len(2) |
    /// name_type(1) | name_len(2) | name` and the ALPN extension `data = list_len(2) |
    /// [len(1) | name]*`; each extension header's own length prefix covers its whole `data`.
    fn hello(sni: &str, alpn: &[&str]) -> Vec<u8> {
        let mut extensions = Vec::new();
        if !sni.is_empty() {
            let host = sni.as_bytes();
            let mut names = vec![0_u8]; // host_name
            names.extend_from_slice(&(host.len() as u16).to_be_bytes());
            names.extend_from_slice(host);
            let mut ext = Vec::new();
            ext.extend_from_slice(&(names.len() as u16).to_be_bytes());
            ext.extend_from_slice(&names);
            extensions.extend_from_slice(&0x0000_u16.to_be_bytes());
            extensions.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&ext);
        }
        if !alpn.is_empty() {
            let mut protocols = Vec::new();
            for name in alpn {
                protocols.push(name.len() as u8);
                protocols.extend_from_slice(name.as_bytes());
            }
            let mut ext = Vec::new();
            ext.extend_from_slice(&(protocols.len() as u16).to_be_bytes());
            ext.extend_from_slice(&protocols);
            extensions.extend_from_slice(&0x0010_u16.to_be_bytes());
            extensions.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&ext);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // empty session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.push(1); // one compression method
        body.push(0); // null compression
        if !extensions.is_empty() {
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
        }

        let mut handshake = vec![1_u8]; // client_hello
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // u24
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16_u8]; // handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
    fn sample(action: &dyn StreamMatcher<'_>, buffer: &[u8], meta: &ConnectionMeta) -> bool {
        action.matches_buffer(buffer, meta).is_match()
    }

    #[test]
    fn tls_matcher_checks_sni_and_alpn() {
        let buffer = hello("api.example.com", &["h2", "http/1.1"]);
        let parsed = crate::client_hello::parse_client_hello(&buffer);
        assert!(parsed.is_ok(), "fixture ClientHello must parse: {parsed:?}");
        let meta = ConnectionMeta::default();
        assert!(sample(&TlsMatcher::any(), &buffer, &meta));
        assert!(sample(
            &TlsMatcher::any().with_sni(SniPattern::parse("api.example.com").unwrap()),
            &buffer,
            &meta
        ));
        assert!(sample(
            &TlsMatcher::any().with_sni(SniPattern::parse("*.example.com").unwrap()),
            &buffer,
            &meta
        ));
        assert!(!sample(
            &TlsMatcher::any().with_sni(SniPattern::parse("*.other.com").unwrap()),
            &buffer,
            &meta
        ));
        assert!(sample(
            &TlsMatcher::any().with_alpn([String::from("h2")]),
            &buffer,
            &meta
        ));
        assert!(!sample(
            &TlsMatcher::any().with_alpn([String::from("h3")]),
            &buffer,
            &meta
        ));
        assert!(!sample(&TlsMatcher::any(), b"SSH-2.0-x\r\n", &meta));
    }

    #[test]
    fn sni_patterns_validate_and_match_at_label_boundaries() {
        assert!(SniPattern::parse("Example.COM")
            .unwrap()
            .matches("example.com"));
        assert!(SniPattern::parse("*.example.com")
            .unwrap()
            .matches("a.example.com"));
        assert!(!SniPattern::parse("*.example.com")
            .unwrap()
            .matches("example.com"));
        assert!(!SniPattern::parse("*.example.com")
            .unwrap()
            .matches("..example.com"));
        assert!(SniPattern::parse("a*b.com").is_err());
        assert!(SniPattern::parse("").is_err());
    }

    #[test]
    fn ip_and_asn_matchers_use_connection_metadata() {
        let ip = IpMatcher::new()
            .with_range(IpRange::parse("10.0.0.0/8").unwrap())
            .with_range(IpRange::parse("::1").unwrap());
        assert!(sample(
            &ip,
            b"",
            &ConnectionMeta {
                peer: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
                asn: None
            }
        ));
        assert!(!sample(
            &ip,
            b"",
            &ConnectionMeta {
                peer: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                asn: None
            }
        ));
        let asn = AsnMatcher::new().with_asn(64512);
        assert_eq!(
            asn.matches_buffer(
                b"",
                &ConnectionMeta {
                    peer: None,
                    asn: None
                }
            )
            .reason(),
            &MatcherError::NoAsnData
        );
        assert!(sample(
            &asn,
            b"",
            &ConnectionMeta {
                peer: None,
                asn: Some(64512)
            }
        ));
        assert!(IpRange::parse("10.0.0.0/33").is_err());
        assert!(IpRange::parse("not-an-ip").is_err());
    }

    /// SEC-MEDIUM-PROXY C2: on a dual-stack `[::]` listener an IPv4 client appears as
    /// `::ffff:a.b.c.d`. It must be matched as the IPv4 address, otherwise a negated/deny-style
    /// `ip` matcher never sees the client in its range.
    #[test]
    fn ipv4_mapped_ipv6_peers_match_ipv4_ranges() {
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        let v4_range = IpRange::parse("203.0.113.0/24").unwrap();
        assert!(
            v4_range.contains(mapped),
            "mapped peer is inside the v4 range"
        );
        assert!(!v4_range.contains("::ffff:203.0.114.7".parse().unwrap()));
        assert!(IpRange::parse("0.0.0.0/0").unwrap().contains(mapped));
        assert!(IpRange::parse("203.0.113.7").unwrap().contains(mapped));
        // Plain v4 and native v6 behaviour is unchanged; families still do not cross.
        assert!(v4_range.contains("203.0.113.7".parse().unwrap()));
        let v6_range = IpRange::parse("2001:db8::/32").unwrap();
        assert!(v6_range.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6_range.contains(mapped));
        assert!(!v4_range.contains("2001:db8::1".parse().unwrap()));
        // A range spelled in the mapped form is the same set of clients as its v4 spelling.
        let mapped_range = IpRange::parse("::ffff:203.0.113.0/120").unwrap();
        assert!(mapped_range.contains("203.0.113.9".parse().unwrap()));
        assert!(mapped_range.contains(mapped));
        assert!(!mapped_range.contains("203.0.114.9".parse().unwrap()));
        // A genuine IPv6 range that covers the mapped block keeps matching mapped peers (the raw
        // spelling is still compared), so allow-lists written as `::/0` do not shrink.
        let wide = IpRange::parse("::/0").unwrap();
        assert!(wide.contains("2001:db8::1".parse().unwrap()));
        assert!(wide.contains(mapped));

        // The matcher itself, on the mapped peer an `[::]` listener reports.
        let matcher = IpMatcher::new().with_range(v4_range);
        assert!(sample(
            &matcher,
            b"",
            &ConnectionMeta {
                peer: Some(mapped),
                asn: None
            }
        ));
        let other = ConnectionMeta {
            peer: Some("::ffff:192.0.2.1".parse().unwrap()),
            asn: None,
        };
        assert!(!sample(&matcher, b"", &other));
    }

    #[test]
    fn l7_matchers_classify_banners() {
        let meta = ConnectionMeta::default();
        assert!(sample(
            &L7Matcher::new(L7Protocol::Ssh),
            b"SSH-2.0-x\r\n",
            &meta
        ));
        assert!(sample(
            &L7Matcher::new(L7Protocol::Http),
            b"GET / HTTP/1.1\r\n",
            &meta
        ));
        assert!(sample(
            &L7Matcher::new(L7Protocol::Http2),
            b"PRI * HTTP/2.0\r\n",
            &meta
        ));
        assert!(!sample(
            &L7Matcher::new(L7Protocol::Http),
            b"SSH-2.0-x\r\n",
            &meta
        ));
    }

    #[tokio::test]
    async fn matcher_sets_compose_all_any_and_not() {
        let buffer = hello("api.example.com", &["h2"]);
        let meta = ConnectionMeta::default();
        let sni =
            matcher(TlsMatcher::any().with_sni(SniPattern::parse("api.example.com").unwrap()));
        let alpn = matcher(TlsMatcher::any().with_alpn([String::from("h2")]));
        let ssh = matcher(L7Matcher::new(L7Protocol::Ssh));
        let all = MatcherSet::all(vec![sni.clone(), alpn.clone()]);
        assert!(all.evaluate(&buffer, &meta).await.is_match());
        let any = MatcherSet::any(vec![ssh.clone(), alpn.clone()]);
        assert!(any.evaluate(&buffer, &meta).await.is_match());
        let none = MatcherSet::any(vec![ssh.clone()]);
        assert!(!none.evaluate(&buffer, &meta).await.is_match());
        let negated = MatcherSet::not(ssh);
        assert!(negated.evaluate(&buffer, &meta).await.is_match());
        assert!(MatcherSet::new().evaluate(b"", &meta).await.is_match());
        assert!(MatcherSet::all(Vec::new())
            .evaluate(b"", &meta)
            .await
            .is_match());
    }

    #[test]
    fn a_custom_conn_matcher_sees_only_the_prefix_and_metadata() {
        struct HeaderByte(u8);

        impl super::ConnMatcher for HeaderByte {
            fn name(&self) -> &'static str {
                "header-byte"
            }

            fn matches(&self, ctx: &super::MatchContext<'_>) -> super::MatchOutcome {
                // Only `buffered()`/`meta()` are available: there is no way to reach the socket.
                if ctx.buffered().first() == Some(&self.0) {
                    matched()
                } else {
                    unmatched(MatcherError::NoMatch)
                }
            }
        }

        let ctx = super::MatchContext {
            buffer: &[0x16, 0x03],
            meta: &ConnectionMeta::default(),
        };
        assert!(super::ConnMatcher::matches(&HeaderByte(0x16), &ctx).is_match());
        assert!(!super::ConnMatcher::matches(&HeaderByte(0x47), &ctx).is_match());
        // The blanket impl makes every StreamMatcher usable as a ConnMatcher too.
        let tls = TlsMatcher::any();
        let mut meta = ConnectionMeta::default();
        let empty = super::MatchContext {
            buffer: b"",
            meta: &mut meta,
        };
        assert_eq!(super::ConnMatcher::name(&tls), "tls");
        assert!(!super::ConnMatcher::matches(&tls, &empty).is_match());
    }

    #[tokio::test]
    async fn matcher_stats_count_evaluations_and_undecided_peeks() {
        let stats = super::MatcherStats::default();
        let set = MatcherSet::new().with_stats(stats.clone());
        assert!(set
            .evaluate(b"", &ConnectionMeta::default())
            .await
            .is_match());
        assert!(set
            .evaluate(b"", &ConnectionMeta::default())
            .await
            .is_match());
        assert_eq!(stats.evaluated(), 2);
        assert_eq!(stats.need_more_bytes(), 0);

        let stats = super::MatcherStats::default();
        let undecided = MatcherSet::all(vec![matcher(super::ProtocolMatcher::new(
            crate::client_hello::Protocol::Ssh,
        ))])
        .with_stats(stats.clone());
        assert!(!undecided
            .evaluate(b"", &ConnectionMeta::default())
            .await
            .is_match());
        assert_eq!(stats.evaluated(), 1);
        assert_eq!(stats.need_more_bytes(), 1);
        assert!(undecided.stats().is_some());
    }

    #[tokio::test]
    async fn evaluation_leaves_the_peek_buffer_untouched() {
        let buffer = hello("api.example.com", &["h2"]);
        let (mut client, server) = tokio::io::duplex(4096);
        tokio::io::AsyncWriteExt::write_all(&mut client, &buffer)
            .await
            .unwrap();
        let mut ctx = StreamContext::new(server);
        ctx.peek_tls_record().await.expect("peek");
        // The guard is a hard invariant: matching must never change the buffered prefix.
        assert_eq!(ctx.buffered(), buffer.as_slice());
        let meta = ConnectionMeta::default();
        let set = MatcherSet::all(vec![matcher(TlsMatcher::any())]);
        let outcome = ctx.evaluate_set(&set, &meta).await.expect("no consumption");
        assert!(outcome.is_match());
        assert_eq!(ctx.buffered(), buffer.as_slice());
        let error = MatchError::ConsumedStream;
        assert!(error.to_string().contains("must not read"));
        assert_eq!(matched().reason(), &MatcherError::NoMatch);
    }
}
