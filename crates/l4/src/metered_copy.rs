//! Metered bidirectional copy for L4 proxy connections (T-L4-005).
//!
//! `tokio::io::copy_bidirectional` moves bytes but reports nothing until both directions finish,
//! so a long-lived proxied connection is invisible to metrics. [`metered_copy_bidirectional`]
//! copies the same way — concurrently in both directions, half-closing the opposite direction
//! when one side reaches EOF, returning both totals — but charges every completed chunk to the
//! caller-supplied [`ByteMeter`] *as it is copied*, so a counter tracks live traffic and a gauge
//! tracks live connections.
//!
//! The copy never allocates per chunk: each direction reuses one fixed-size buffer from the
//! caller (`POOL_BUFFER_SIZE`, the same 16 KiB the peeking pool uses).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::prefixed_stream::POOL_BUFFER_SIZE;

/// Receives the bytes copied in each direction as they are copied.
///
/// Implementations must be cheap and allocation-free: every completed chunk calls
/// [`ByteMeter::record`] once per direction, from the connection's task.
pub trait ByteMeter: Send + Sync {
    /// Records `bytes` read from the client and written to the upstream.
    fn record_read(&self, bytes: u64);

    /// Records `bytes` read from the upstream and written back to the client.
    fn record_write(&self, bytes: u64);
}

/// A [`ByteMeter`] that counts bytes in two atomics and nothing else.
///
/// This is the meter a proxy installs when no metric registry is wired: it keeps the per-route
/// totals available to the caller without touching the registry on the hot path.
#[derive(Debug, Default)]
pub struct AtomicByteMeter {
    read: AtomicU64,
    write: AtomicU64,
}

impl AtomicByteMeter {
    /// Creates a meter that has not copied anything yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total bytes read from clients.
    pub fn read_bytes(&self) -> u64 {
        self.read.load(Ordering::Relaxed)
    }

    /// Total bytes written to clients.
    pub fn write_bytes(&self) -> u64 {
        self.write.load(Ordering::Relaxed)
    }
}

impl ByteMeter for AtomicByteMeter {
    fn record_read(&self, bytes: u64) {
        self.read.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_write(&self, bytes: u64) {
        self.write.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// A meter shared by a connection and its counters.
pub type SharedMeter = Arc<dyn ByteMeter>;

/// A meter that charges nothing. Used when a caller only wants the returned totals.
#[derive(Debug, Default)]
pub struct NullMeter;

impl ByteMeter for NullMeter {
    fn record_read(&self, _bytes: u64) {}
    fn record_write(&self, _bytes: u64) {}
}

/// The bytes copied in each direction, in the same shape `copy_bidirectional` returns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CopyTotals {
    /// Bytes read from `a` and written to `b`.
    pub a_to_b: u64,
    /// Bytes read from `b` and written to `a`.
    pub b_to_a: u64,
}

impl CopyTotals {
    /// Both directions combined.
    pub fn total(&self) -> u64 {
        self.a_to_b.saturating_add(self.b_to_a)
    }
}

/// Copies bytes in both directions until both reach EOF, charging `meter` as it goes.
///
/// Semantics match [`tokio::io::copy_bidirectional`]: both directions run concurrently, a
/// direction that reaches EOF shuts down the write half of its peer, and the call returns once
/// both directions have finished. `a_to_b` is read from `a`/written to `b`, so the meter's
/// [`ByteMeter::record_read`] charges the client-to-upstream direction and
/// [`ByteMeter::record_write`] charges upstream-to-client.
///
/// Errors are returned as the underlying I/O error, after both directions have stopped: a failure
/// in one direction aborts the other, exactly like `copy_bidirectional`.
pub async fn metered_copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    meter: &SharedMeter,
) -> std::io::Result<CopyTotals>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    // `try_join!` needs both futures at once; the disjoint halves of each stream are taken by
    // splitting the borrow, so the two directions can run concurrently.
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    let a_to_b = copy_one_way(a_read, b_write, true, meter);
    let b_to_a = copy_one_way(b_read, a_write, false, meter);
    let (a_to_b, b_to_a) = tokio::try_join!(a_to_b, b_to_a)?;
    Ok(CopyTotals { a_to_b, b_to_a })
}

/// Copies `reader` -> `writer` until EOF, then half-closes `writer`.
async fn copy_one_way<R, W>(
    mut reader: R,
    mut writer: W,
    client_to_upstream: bool,
    meter: &SharedMeter,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; POOL_BUFFER_SIZE];
    let mut copied = 0u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).await?;
        let read = read as u64;
        copied = copied.saturating_add(read);
        if client_to_upstream {
            meter.record_read(read);
        } else {
            meter.record_write(read);
        }
    }
    writer.shutdown().await?;
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn counts_match_the_bytes_actually_proxied() {
        let meter: SharedMeter = Arc::new(AtomicByteMeter::new());
        let (mut client_side, mut client_peer) = duplex(64);
        let (mut upstream_side, mut upstream_peer) = duplex(64);

        let copy = tokio::spawn(async move {
            metered_copy_bidirectional(&mut client_side, &mut upstream_side, &meter).await
        });

        // Client sends a request; upstream answers; both close.
        client_peer.write_all(b"hello upstream").await.unwrap();
        upstream_peer.read_exact(&mut [0u8; 14]).await.unwrap();
        upstream_peer.write_all(b"and back").await.unwrap();
        let mut answer = [0u8; 8];
        client_peer.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"and back");
        client_peer.shutdown().await.unwrap();
        upstream_peer.shutdown().await.unwrap();

        let totals = copy.await.unwrap().unwrap();
        assert_eq!(totals.a_to_b, 14);
        assert_eq!(totals.b_to_a, 8);
        assert_eq!(totals.total(), 22);
    }
}
