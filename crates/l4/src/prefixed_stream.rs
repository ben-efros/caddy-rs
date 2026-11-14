//! Replayable prefixed streams and the fixed-size buffer pool used when peeking TCP prefixes.
//!
//! A TCP listener that peeks the first bytes of a connection (for example the TLS ClientHello to
//! implement SNI routing) consumes bytes that no longer exist in the socket. [`PrefixedStream`]
//! keeps them in a [`Bytes`] buffer and serves them before the upstream stream, so the handler
//! pipeline sees a byte-identical stream. [`BufferPool`] provides the 16 KiB [`BytesMut`] buffers
//! used for peeking and recycles them across connections instead of allocating per connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Size of a pool buffer: one TLS ClientHello fits comfortably in 16 KiB, and keeping the size
/// fixed is what lets a released buffer be reused by the next connection (a buffer with a
/// different capacity would pin the pool to the largest connection).
pub const POOL_BUFFER_SIZE: usize = 16 * 1024;

/// A stream that serves a buffered prefix before delegating to an upstream stream.
///
/// The prefix is replayed exactly once, in order, and never copied back to the socket. Reads
/// return the prefix first (as much as the caller's buffer fits, so a large prefix can be served
/// over several reads) and only poll the upstream once the prefix is fully consumed. Writes,
/// flushes and shutdowns go straight to the upstream.
///
/// Reads polled before the upstream has data never mix buffered and upstream bytes in one
/// `Poll::Ready`, which keeps [`AsyncRead`]'s contract (a `Poll::Pending` never carries appended
/// bytes) trivially true.
#[derive(Debug)]
pub struct PrefixedStream<S> {
    prefix: Bytes,
    upstream: S,
}

impl<S> PrefixedStream<S> {
    /// Wraps `upstream`, replaying `prefix` before any upstream byte.
    pub fn new(prefix: impl Into<Bytes>, upstream: S) -> Self {
        Self {
            prefix: prefix.into(),
            upstream,
        }
    }

    /// Bytes still waiting to be replayed (empty once the prefix has been consumed).
    pub fn remaining_prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Whether the buffered prefix has been fully replayed.
    pub fn prefix_consumed(&self) -> bool {
        self.prefix.is_empty()
    }

    /// Shared reference to the upstream stream.
    pub fn get_ref(&self) -> &S {
        &self.upstream
    }

    /// Mutable reference to the upstream stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.upstream
    }

    /// Consumes the wrapper, returning the upstream stream and the unreplayed prefix.
    pub fn into_parts(self) -> (Bytes, S) {
        (self.prefix, self.upstream)
    }

    /// Consumes the wrapper, returning the upstream stream (discarding any unreplayed prefix).
    pub fn into_inner(self) -> S {
        self.upstream
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = std::cmp::min(this.prefix.len(), buf.remaining());
            buf.put_slice(&this.prefix[..n]);
            this.prefix.advance(n);
            // Return as soon as any prefix byte is copied: the caller gets the buffered bytes
            // without waiting for the upstream, and a later poll reads the socket only after the
            // prefix is drained. This also means `Poll::Pending` from the upstream can never
            // follow bytes appended to `buf` in the same poll.
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.upstream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().upstream).poll_write(cx, data)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().upstream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.upstream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().upstream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().upstream).poll_shutdown(cx)
    }
}

/// A bounded pool of fixed-size [`BytesMut`] buffers.
///
/// `acquire` returns a cleared buffer with at least [`POOL_BUFFER_SIZE`] capacity, reusing a
/// released one when available; `release` returns a buffer to the pool when it is large enough
/// and the pool is below its limit. A released buffer keeps its capacity (only its length is
/// reset), so under steady load the pool reaches a fixed set of allocations: connections borrow
/// and return buffers instead of growing the heap or the connection's own buffer.
///
/// The pool is not internally synchronised: callers either own one pool per runtime task or wrap
/// it in their own lock when it is shared (see the concurrency tests).
#[derive(Debug)]
pub struct BufferPool {
    free: Vec<BytesMut>,
    max_free: usize,
    created: u64,
    reused: u64,
}

impl BufferPool {
    /// Creates a pool holding at most `max_free` released buffers.
    pub fn new(max_free: usize) -> Self {
        Self {
            free: Vec::new(),
            max_free,
            created: 0,
            reused: 0,
        }
    }

    /// Creates a pool with `max_free` slots and `initial` already allocated buffers.
    pub fn with_capacity(max_free: usize, initial: usize) -> Self {
        let initial = std::cmp::min(initial, max_free);
        Self {
            free: (0..initial)
                .map(|_| BytesMut::with_capacity(POOL_BUFFER_SIZE))
                .collect(),
            max_free,
            created: initial as u64,
            reused: 0,
        }
    }

    /// Borrows a cleared buffer of at least [`POOL_BUFFER_SIZE`] capacity.
    pub fn acquire(&mut self) -> BytesMut {
        if let Some(mut buffer) = self.free.pop() {
            debug_assert!(buffer.capacity() >= POOL_BUFFER_SIZE);
            buffer.clear();
            self.reused += 1;
            return buffer;
        }
        self.created += 1;
        BytesMut::with_capacity(POOL_BUFFER_SIZE)
    }

    /// Returns a buffer to the pool. Returns `false` (and drops the buffer) when it is too small
    /// to be reused at the pool's fixed size or the pool is full.
    pub fn release(&mut self, buffer: BytesMut) -> bool {
        if buffer.capacity() < POOL_BUFFER_SIZE || self.free.len() >= self.max_free {
            return false;
        }
        let mut buffer = buffer;
        buffer.clear();
        self.free.push(buffer);
        true
    }

    /// Number of released buffers currently available for reuse.
    pub fn available(&self) -> usize {
        self.free.len()
    }

    /// Buffers allocated by this pool (the steady-state allocation count under load).
    pub fn created(&self) -> u64 {
        self.created
    }

    /// Buffers served from the pool instead of being allocated.
    pub fn reused(&self) -> u64 {
        self.reused
    }

    /// Whether every buffer was returned to the pool.
    pub fn is_full(&self) -> bool {
        self.free.len() >= self.max_free
    }

    /// Drops the pooled buffers and returns how many were discarded.
    pub fn discard(&mut self) -> usize {
        let count = self.free.len();
        self.free.clear();
        count
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(32)
    }
}
