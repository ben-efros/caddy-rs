//! Layer-4 (TCP) stream primitives shared by the caddy-rs L4 router.
//!
//! The L4 router must peek the first bytes of a TCP connection (a TLS ClientHello) to decide
//! whether a connection is terminated locally, passed through, or routed. The bytes consumed
//! during peeking cannot be recovered from the socket, so the router replays them:
//!
//! - [`PrefixedStream`] wraps an upstream stream and yields a buffered prefix first, then
//!   delegates every read and write to the upstream without copying the prefix back into the
//!   socket.
//! - [`BufferPool`] owns fixed-size 16 KiB [`BytesMut`](bytes::BytesMut) buffers so peeking does
//!   not allocate per connection; buffers are returned to the pool once replayed and reused by
//!   the next connection.
//!
//! Both are transport-agnostic (anything implementing [`tokio::io::AsyncRead`] /
//! [`tokio::io::AsyncWrite`] works), so the L4 router and its tests can use in-memory duplex
//! streams.

#![forbid(unsafe_code)]

pub mod actions;
pub mod client_hello;
pub mod context;
pub mod handler;
pub mod handlers;
pub mod matchers;
pub mod metered_copy;
pub mod metrics;
pub mod prefixed_stream;
pub mod router;

pub use actions::{
    ActionConfigError, FallbackConfig, FallbackReason, HttpConfig, PassthroughConfig, SniAction,
    TerminateConfig,
};
pub use client_hello::{
    detect_protocol, parse_client_hello, ClientHelloInfo, ParseError, Protocol,
};
pub use handler::{
    BoxedStream, HandlerContext, HandlerError, HandlerPipeline, L4Handler, L4Stream,
};
pub use handlers::{
    proxy_connection, proxy_route, render_proxy_header, validate_stage_order, ProxyError,
    ProxyHeaderAddresses, ProxyHeaderError, ProxyOptions, ProxyProtocolVersion, RateLimit,
    RateLimitError, StageOrderError, TerminateError, ThrottledStream, TlsTerminator,
    DEFAULT_IDLE_TIMEOUT, STAGE_ORDER, THROTTLE_BURST_BYTES, V2_SIGNATURE,
};
pub use metered_copy::{
    metered_copy_bidirectional, AtomicByteMeter, ByteMeter, CopyTotals, NullMeter, SharedMeter,
};
pub use metrics::{
    route_label, L4Connection, L4Metrics, SharedL4Metrics, CONNECTIONS_ACTIVE,
    HANDSHAKE_DURATION_SECONDS, OTHER_LABEL, READ_BYTES_TOTAL, SNI_LABEL, WRITE_BYTES_TOTAL,
};
pub use prefixed_stream::{BufferPool, PrefixedStream, POOL_BUFFER_SIZE};
pub use router::{Route, RouteDefinition, RouteError, SniRouter, SniTable};

pub use context::{sniff, PeekError, PeekLimits, PeekStats, ProtocolInfo, Sniffed, StreamContext};
pub use matchers::{
    matched, unmatched, AsnMatcher, BoxedMatcher, ConnMatcher, ConnMatcherErased, ConnectionMeta,
    EvaluateContext, IpMatcher, IpRange, IpRangeError, L7Matcher, L7Protocol, MatchContext,
    MatchError, MatchOutcome, MatcherError, MatcherSet, MatcherStats, SniPattern, SniPatternError,
    StreamMatcher, TlsMatcher,
};
