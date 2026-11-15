//! The per-connection stream context and the L4 matcher trait.
//!
//! A connection is matched by peeking at its first bytes. Peeking consumes bytes from the socket,
//! and those bytes may never come back, so the context owns the buffer once and hands it to the
//! handlers afterwards:
//!
//! - [`StreamContext::peek`] reads into an internal buffer without consuming anything from the
//!   router's point of view; every [`ConnMatcher`](crate::matchers::ConnMatcher) sees the same
//!   bytes.
//! - [`StreamContext::take_prefix`] removes the buffered prefix and returns it as [`Bytes`], and
//!   [`StreamContext::into_prefixed_stream`] wraps the connection in a
//!   [`PrefixedStream`](crate::prefixed_stream::PrefixedStream) that replays those bytes to the
//!   handler exactly once, byte for byte.
//!
//! The pipelined context is [`StreamContext`] itself:
//!
//! ```text
//! accept -> StreamContext::new(stream, pool, limits)
//!        -> peek()                (as many times as the matchers need)
//!        -> add_match_set(matcher) / evaluate
//!        -> take_prefix() or into_prefixed_stream()   (handlers see every byte)
//! ```

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::client_hello::{detect_protocol, parse_client_hello, ClientHelloInfo, ParseError};
use crate::prefixed_stream::{PrefixedStream, POOL_BUFFER_SIZE};

/// Default bound for how many bytes the router may buffer while peeking.
pub const DEFAULT_MAX_PEEK_BYTES: usize = POOL_BUFFER_SIZE;
/// Default deadline for the peek loop.
pub const DEFAULT_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// How long and how far the router may peek at a connection before handing it to a handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeekLimits {
    /// Maximum buffered bytes; peeking stops with [`PeekError::LimitExceeded`] past it.
    pub max_peek_bytes: usize,
    /// Deadline for the whole peek loop (`None` disables it); exceeding it yields
    /// [`PeekError::Timeout`].
    pub timeout: Option<Duration>,
}

impl Default for PeekLimits {
    fn default() -> Self {
        Self {
            max_peek_bytes: DEFAULT_MAX_PEEK_BYTES,
            timeout: Some(DEFAULT_PEEK_TIMEOUT),
        }
    }
}

impl PeekLimits {
    /// Limits with an explicit byte bound and no timeout.
    pub fn bytes(max_peek_bytes: usize) -> Self {
        Self {
            max_peek_bytes,
            timeout: None,
        }
    }
}

/// Peek diagnostics shared by every connection of a listener.
#[derive(Clone, Debug, Default)]
pub struct PeekStats {
    bytes_read: Arc<AtomicU64>,
    buffers_acquired: Arc<AtomicU64>,
}

impl PeekStats {
    /// Returns the total bytes the peek loop has read across connections.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    /// Returns how many buffers the peek loop has taken from the pool.
    pub fn buffers_acquired(&self) -> u64 {
        self.buffers_acquired.load(Ordering::Relaxed)
    }
}

/// A failure of the peek loop or of the context itself.
#[derive(Debug)]
pub enum PeekError {
    /// The connection closed before `target` bytes were buffered.
    UnexpectedEof {
        /// How many bytes were requested.
        target: usize,
        /// How many were buffered before the peer closed.
        buffered: usize,
    },
    /// The connection would need more than [`PeekLimits::max_peek_bytes`] buffered.
    LimitExceeded {
        /// The configured bound.
        limit: usize,
        /// How many bytes are already buffered.
        buffered: usize,
    },
    /// The peek loop exceeded [`PeekLimits::timeout`].
    Timeout {
        /// The configured deadline.
        limit: Duration,
        /// How many bytes were buffered when the deadline hit.
        buffered: usize,
    },
    /// The read failed.
    Io(std::io::Error),
}

impl fmt::Display for PeekError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { target, buffered } => write!(
                f,
                "connection closed after {buffered} byte(s) while {target} were required"
            ),
            Self::LimitExceeded { limit, buffered } => write!(
                f,
                "peek limit exceeded: {buffered} byte(s) buffered, limit {limit}"
            ),
            Self::Timeout { limit, buffered } => write!(
                f,
                "peek timed out after {limit:?} with {buffered} byte(s) buffered"
            ),
            Self::Io(error) => write!(f, "peek read failed: {error}"),
        }
    }
}

impl std::error::Error for PeekError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// The connection the router is deciding about.
///
/// The context borrows nothing: it owns one growable buffer containing exactly the bytes it has
/// read ahead of the socket, plus the connection itself. Dropping the context without calling
/// [`StreamContext::take_prefix`] or [`StreamContext::into_prefixed_stream`] closes the connection
/// and discards the peeked bytes, so callers must take the prefix before handing off.
#[derive(Debug)]
pub struct StreamContext<S> {
    stream: Option<S>,
    buffer: BytesMut,
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    limits: PeekLimits,
    stats: Option<PeekStats>,
}

impl<S> StreamContext<S> {
    /// Wraps an accepted connection with default [`PeekLimits`].
    pub fn new(stream: S) -> Self {
        Self::with_limits(stream, PeekLimits::default())
    }

    /// Wraps an accepted connection with explicit limits.
    pub fn with_limits(stream: S, limits: PeekLimits) -> Self {
        Self {
            stream: Some(stream),
            buffer: BytesMut::with_capacity(limits.max_peek_bytes.min(POOL_BUFFER_SIZE)),
            peer: None,
            local: None,
            limits,
            stats: None,
        }
    }

    /// Records the remote address of the connection.
    pub fn with_peer(mut self, peer: SocketAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Records the local address the connection arrived on.
    pub fn with_local(mut self, local: SocketAddr) -> Self {
        self.local = Some(local);
        self
    }

    /// Attaches peek diagnostics counters.
    pub fn with_stats(mut self, stats: PeekStats) -> Self {
        self.stats = Some(stats);
        self
    }

    /// The remote address, when the caller supplied it.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// The local address, when the caller supplied it.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local
    }

    /// The bytes buffered so far (the prefix handlers will see first).
    pub fn buffered(&self) -> &[u8] {
        &self.buffer
    }

    /// How many bytes are buffered.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// The limits in force.
    pub fn limits(&self) -> PeekLimits {
        self.limits
    }

    /// A handle to the connection for reading, if it has not been handed off yet.
    pub fn stream_mut(&mut self) -> Option<&mut S> {
        self.stream.as_mut()
    }

    /// Takes the buffered prefix. Bytes read from the connection afterwards no longer include it,
    /// so this may be called exactly once per context.
    pub fn take_prefix(&mut self) -> Bytes {
        std::mem::take(&mut self.buffer).freeze()
    }

    /// Consumes the context and returns the buffered prefix plus the connection.
    pub fn into_parts(mut self) -> (Bytes, S) {
        let prefix = self.take_prefix();
        let stream = self
            .stream
            .take()
            .expect("StreamContext always owns its stream until into_parts");
        (prefix, stream)
    }
}

impl<S: AsyncRead + Unpin> StreamContext<S> {
    /// Buffers exactly `target` bytes, one read per missing byte chunk.
    ///
    /// Returns the buffered bytes (exactly `target` of them) or a typed [`PeekError`]. Reads stop as
    /// soon as `target` is reached, so a route that needs only a few bytes never waits for the
    /// deadline.
    pub async fn peek_to(&mut self, target: usize) -> Result<&[u8], PeekError> {
        self.peek_inner(target, false).await?;
        Ok(&self.buffer)
    }

    /// Like [`StreamContext::peek_to`], but returns as soon as *either* `target` bytes are
    /// buffered, the peer closes the connection, or the peek deadline expires, so callers can match
    /// on a short connection (an SSH banner) without waiting for a full ClientHello.
    pub async fn peek_available(&mut self, target: usize) -> Result<&[u8], PeekError> {
        self.peek_inner(target, true).await?;
        Ok(&self.buffer)
    }

    /// Buffers enough bytes to contain the first TLS record when the connection starts with TLS,
    /// and returns the buffered prefix in either case.
    ///
    /// Non-TLS connections are not delayed: they return as soon as enough bytes classify them.
    pub async fn peek_tls_record(&mut self) -> Result<&[u8], PeekError> {
        // Record header (5) + handshake header (4) is the shortest meaningful ClientHello prefix.
        self.peek_to(5).await?;
        let Some(header) = self.buffer.get(..5) else {
            return Ok(&self.buffer);
        };
        // The record length bounds the handshake message; a ClientHello must fit the first record.
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if detect_protocol(&self.buffer) == crate::client_hello::Protocol::Tls {
            self.peek_to(5 + record_len).await?;
        }
        Ok(&self.buffer)
    }

    async fn peek_inner(&mut self, target: usize, allow_short: bool) -> Result<(), PeekError> {
        let limit = self.limits.max_peek_bytes;
        if target > limit {
            return Err(PeekError::LimitExceeded {
                limit,
                buffered: self.buffer.len(),
            });
        }
        if self.buffer.len() >= target {
            return Ok(());
        }
        if let Some(stats) = &self.stats {
            stats.buffers_acquired.fetch_add(1, Ordering::Relaxed);
        }
        let deadline = self.limits.timeout.map(|limit| {
            let at = tokio::time::Instant::now() + limit;
            (at, limit)
        });
        // Read at most `target - buffered` bytes per read so the buffer never overshoots `target`.
        let mut chunk = [0_u8; 512];
        loop {
            let missing = target - self.buffer.len();
            if missing == 0 {
                return Ok(());
            }
            let want = missing.min(chunk.len()).min(limit - self.buffer.len());
            let read_fut = self
                .stream
                .as_mut()
                .expect("StreamContext owns its stream until into_parts")
                .read(&mut chunk[..want]);
            let read = match deadline {
                Some((at, limit)) => {
                    let remaining = at.saturating_duration_since(tokio::time::Instant::now());
                    match tokio::time::timeout(remaining, read_fut).await {
                        Ok(result) => result.map_err(PeekError::Io)?,
                        Err(_) if allow_short && !self.buffer.is_empty() => return Ok(()),
                        Err(_) => {
                            return Err(PeekError::Timeout {
                                limit,
                                buffered: self.buffer.len(),
                            })
                        }
                    }
                }
                None => read_fut.await.map_err(PeekError::Io)?,
            };
            if read == 0 {
                return if allow_short && !self.buffer.is_empty() {
                    Ok(())
                } else {
                    Err(PeekError::UnexpectedEof {
                        target,
                        buffered: self.buffer.len(),
                    })
                };
            }
            self.buffer.extend_from_slice(&chunk[..read]);
            if let Some(stats) = &self.stats {
                stats.bytes_read.fetch_add(read as u64, Ordering::Relaxed);
            }
        }
    }
}

/// A parsed view of the buffered prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sniffed {
    /// A complete TLS record holding a ClientHello (or a TLS record that is not one).
    Tls {
        /// The TLS classification (SNI/ALPN when the record is a ClientHello).
        info: Box<ProtocolInfo>,
    },
    /// Recognisably another protocol (HTTP/1, HTTP/2, SSH).
    NonTls {
        /// The detected protocol family.
        protocol: crate::client_hello::Protocol,
    },
    /// The prefix does not identify a protocol.
    Unknown,
}

/// The routing-relevant fields of a ClientHello, owned so they can outlive the peek buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolInfo {
    /// `true` when a valid ClientHello was parsed.
    pub is_tls: bool,
    /// Lowercased SNI, when the client sent one.
    pub sni: Option<String>,
    /// ALPN protocol names in preference order.
    pub alpn: Vec<String>,
}

impl ProtocolInfo {
    /// Owns a borrowed [`ClientHelloInfo`].
    pub fn from_client_hello(info: &ClientHelloInfo<'_>) -> Self {
        Self {
            is_tls: info.is_tls,
            sni: info.sni.as_ref().map(|sni| sni.as_ref().to_owned()),
            alpn: info.alpn.iter().map(|proto| (*proto).to_owned()).collect(),
        }
    }
}

/// Parses the buffered prefix, tolerating short non-TLS prefixes.
///
/// [`parse_client_hello`] rejects a short unknown prefix with a permanent content-type error; this
/// helper classifies what it can and reports [`Sniffed::Unknown`] for a prefix that is simply too
/// short to tell (the caller can peek more or treat it as unknown).
pub fn sniff(buffer: &[u8]) -> Sniffed {
    match parse_client_hello(buffer) {
        Ok(info) => match info.protocol {
            // A complete TLS record, whether or not it carries a valid ClientHello.
            crate::client_hello::Protocol::Tls => Sniffed::Tls {
                info: Box::new(ProtocolInfo::from_client_hello(&info)),
            },
            protocol => Sniffed::NonTls { protocol },
        },
        Err(ParseError::Incomplete) => Sniffed::Unknown,
        Err(_) => match detect_protocol(buffer) {
            crate::client_hello::Protocol::Unknown => Sniffed::Unknown,
            protocol => Sniffed::NonTls { protocol },
        },
    }
}

impl<S: AsyncRead + Unpin + Send + 'static> StreamContext<S> {
    /// Consumes the context and returns a [`PrefixedStream`] that replays the peeked bytes before
    /// the socket, so the handler sees the connection from its first byte.
    pub fn into_prefixed_stream(self) -> PrefixedStream<S> {
        let (prefix, stream) = self.into_parts();
        PrefixedStream::new(prefix, stream)
    }
}

#[cfg(test)]
mod tests {
    use super::{sniff, PeekError, PeekLimits, Sniffed, StreamContext};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    #[tokio::test]
    async fn peek_buffers_the_requested_bytes_without_consuming_them() {
        let (client, server) = tokio::io::duplex(4096);
        let payload = hello("example.com", &["h2"]);
        // The writer runs as its own task: a linear test that writes before reading would deadlock
        // on the bounded duplex buffer once the payload grows past the ring size.
        let mut client = client;
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&expected).await.unwrap();
            client.write_all(b"tail").await.unwrap();
            client
        });
        let mut ctx = StreamContext::new(server);
        let seen = ctx.peek_to(5).await.expect("peek header");
        assert_eq!(seen.len(), 5);
        let all = ctx.peek_tls_record().await.expect("peek record");
        assert_eq!(all, payload.as_slice());
        let (prefix, mut stream) = ctx.into_parts();
        assert_eq!(prefix.as_ref(), payload.as_slice());
        // `read_to_end` keeps reading until EOF, and the client stays open so it can be reused; read
        // exactly the four trailing bytes the writer sends after the ClientHello instead.
        let mut tail = [0_u8; 4];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"tail");
        drop(stream);
        let client = writer.await.expect("writer task");
        drop(client);
    }

    #[tokio::test]
    async fn into_prefixed_stream_replays_every_byte_once() {
        let (mut client, server) = tokio::io::duplex(4096);
        let payload = b"SSH-2.0-OpenSSH_9.6\r\nrest".to_vec();
        client.write_all(&payload).await.unwrap();
        drop(client);
        let mut ctx = StreamContext::new(server);
        ctx.peek_tls_record().await.expect("peek banner");
        let mut prefixed = ctx.into_prefixed_stream();
        let mut seen = Vec::new();
        prefixed.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, payload);
    }

    #[tokio::test]
    async fn peek_reports_eof_and_limits() {
        let (client, server) = tokio::io::duplex(4096);
        drop(client);
        let mut ctx = StreamContext::new(server);
        let error = ctx.peek_to(10).await.expect_err("closed peer");
        assert!(matches!(
            error,
            PeekError::UnexpectedEof {
                target: 10,
                buffered: 0
            }
        ));

        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(&[0x16, 0x03]).await.unwrap();
        let mut ctx = StreamContext::with_limits(server, PeekLimits::bytes(4));
        let error = ctx.peek_to(8).await.expect_err("limit");
        assert!(matches!(error, PeekError::LimitExceeded { limit: 4, .. }));
    }

    #[tokio::test]
    async fn peek_available_returns_short_banners_without_waiting_for_the_deadline() {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        drop(client);
        let mut ctx = StreamContext::with_limits(
            server,
            PeekLimits {
                max_peek_bytes: 1024,
                timeout: Some(Duration::from_secs(30)),
            },
        );
        let started = std::time::Instant::now();
        let seen = ctx.peek_available(1024).await.expect("short peek");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(seen, b"SSH-2.0-test\r\n");
    }

    #[tokio::test]
    async fn peek_timeout_is_typed() {
        let (_client, server) = tokio::io::duplex(4096);
        let mut ctx = StreamContext::with_limits(
            server,
            PeekLimits {
                max_peek_bytes: 1024,
                timeout: Some(Duration::from_millis(50)),
            },
        );
        let error = ctx.peek_to(10).await.expect_err("timeout");
        assert!(matches!(error, PeekError::Timeout { .. }));
    }

    #[test]
    fn sniff_classifies_tls_non_tls_and_unknown_prefixes() {
        let record = hello("example.com", &["h2"]);
        let parsed = crate::client_hello::parse_client_hello(&record);
        assert!(parsed.is_ok(), "fixture ClientHello must parse: {parsed:?}");
        match sniff(&record) {
            Sniffed::Tls { info } => {
                assert!(info.is_tls);
                assert_eq!(info.sni.as_deref(), Some("example.com"));
                assert_eq!(info.alpn, ["h2"]);
            }
            other => panic!("expected TLS, got {other:?}"),
        }
        assert!(matches!(
            sniff(b"SSH-2.0-OpenSSH_9.6\r\n"),
            Sniffed::NonTls { .. }
        ));
        assert_eq!(sniff(b"GE"), Sniffed::Unknown);
        assert_eq!(sniff(b""), Sniffed::Unknown);
    }
}
