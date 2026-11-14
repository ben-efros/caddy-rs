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

pub mod client_hello;
pub mod prefixed_stream;

pub use client_hello::{
    detect_protocol, parse_client_hello, ClientHelloInfo, ParseError, Protocol,
};
pub use prefixed_stream::{BufferPool, PrefixedStream, POOL_BUFFER_SIZE};
