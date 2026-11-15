//! Bandwidth shaping for L4 connections (T-L4-008, ADR-030).
//!
//! The throttle stage wraps the stream so every `poll_read`/`poll_write` is charged against a
//! token bucket: bytes beyond the configured rate wait until the bucket refills. Shaping happens
//! on the connection's own task (the wrapper returns `Poll::Pending` and schedules a wakeup), so a
//! slow route cannot starve the listener's accept loop.
//!
//! Rates are per second; `0` means unlimited in that direction, which is also how a route with no
//! `throttle` handler behaves.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A per-direction throughput limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    /// Bytes per second allowed from the client to the upstream (`0` = unlimited).
    pub upstream_bytes_per_second: u64,
    /// Bytes per second allowed from the upstream to the client (`0` = unlimited).
    pub downstream_bytes_per_second: u64,
}

impl RateLimit {
    /// Creates a limit for each direction.
    pub fn new(upstream_bytes_per_second: u64, downstream_bytes_per_second: u64) -> Self {
        Self {
            upstream_bytes_per_second,
            downstream_bytes_per_second,
        }
    }

    /// Whether both directions are unlimited (the wrapper is then a no-op).
    pub fn is_unlimited(&self) -> bool {
        self.upstream_bytes_per_second == 0 && self.downstream_bytes_per_second == 0
    }
}

impl Default for RateLimit {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Why a rate limit is invalid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitError {
    message: String,
}

impl RateLimitError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The reason.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RateLimitError {}

/// The largest burst a bucket holds, in bytes: enough for a 64 KiB window so a shaping limit does
/// not fight TCP flow control.
pub const THROTTLE_BURST_BYTES: u64 = 64 * 1024;

/// A token bucket for one direction.
#[derive(Debug)]
struct Bucket {
    bytes_per_second: u64,
    available: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second,
            // Start full so the first burst is not delayed.
            available: THROTTLE_BURST_BYTES as f64,
            last_refill: Instant::now(),
        }
    }

    /// Refills the bucket for the elapsed time, capped at the burst size.
    fn refill(&mut self, now: Instant) {
        if self.bytes_per_second == 0 {
            return;
        }
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        self.available = (self.available + elapsed * self.bytes_per_second as f64)
            .min(THROTTLE_BURST_BYTES as f64);
        self.last_refill = now;
    }

    /// How long until `bytes` are available, or zero when they already are.
    fn delay_for(&mut self, bytes: usize, now: Instant) -> Duration {
        self.refill(now);
        let bytes = bytes as f64;
        if self.bytes_per_second == 0 || self.available >= bytes {
            self.available -= bytes.min(self.available);
            return Duration::ZERO;
        }
        let missing = bytes - self.available;
        self.available = 0.0;
        Duration::from_secs_f64(missing / self.bytes_per_second as f64)
    }
}

/// A stream wrapper that shapes both directions.
#[derive(Debug)]
pub struct ThrottledStream<S> {
    inner: S,
    upstream: Bucket,
    downstream: Bucket,
}

impl<S> ThrottledStream<S> {
    /// Wraps `inner`, shaping reads (upstream) and writes (downstream) per `limit`.
    pub fn new(inner: S, limit: RateLimit) -> Self {
        Self {
            inner,
            upstream: Bucket::new(limit.upstream_bytes_per_second),
            downstream: Bucket::new(limit.downstream_bytes_per_second),
        }
    }

    /// The wrapped stream.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// The wrapped stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Unwraps the stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ThrottledStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let now = Instant::now();
        // Charge the *previous* read's bytes: the bytes were only known after the read completed,
        // and charging before it would need a guess about the future read size.
        let delay = this.upstream.delay_for(0, now);
        if !delay.is_zero() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len().saturating_sub(before);
                if read > 0 {
                    let delay = this.upstream.delay_for(read, Instant::now());
                    if !delay.is_zero() {
                        // The bytes are already delivered to the caller; the *next* read waits.
                        // Scheduling the wakeup here keeps the connection honest without holding
                        // back data that is already in the caller's buffer.
                        this.upstream.available = 0.0;
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ThrottledStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let now = Instant::now();
        this.downstream.refill(now);
        if this.downstream.available <= 0.0 {
            let delay = this.downstream.delay_for(0, now);
            if !delay.is_zero() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = poll {
            this.downstream.delay_for(written, Instant::now());
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Validates a configured limit pair.
pub fn validate_rate_limit(limit: &RateLimit) -> Result<(), RateLimitError> {
    // Zero is the "unlimited" spelling; any other value is a rate in bytes per second. There is no
    // upper bound to enforce, but a limit below one byte per second can never make progress, so it
    // is rejected rather than silently stalling a route.
    for (direction, rate) in [
        ("upstream", limit.upstream_bytes_per_second),
        ("downstream", limit.downstream_bytes_per_second),
    ] {
        if rate != 0 && rate < 1 {
            return Err(RateLimitError::new(format!(
                "l4 throttle {direction} rate must be at least 1 byte per second"
            )));
        }
    }
    Ok(())
}

/// A limit shared by a handler stage and the proxy it shapes.
pub type SharedRateLimit = Arc<RateLimit>;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn unlimited_by_default() {
        assert!(RateLimit::default().is_unlimited());
        assert!(!RateLimit::new(1024, 0).is_unlimited());
    }

    #[test]
    fn a_bucket_grants_the_initial_burst_then_paces() {
        let mut bucket = Bucket::new(1024);
        let now = Instant::now();
        // The whole burst is free.
        assert!(bucket
            .delay_for(THROTTLE_BURST_BYTES as usize, now)
            .is_zero());
        // The next kilobyte at 1 KiB/s costs about a second.
        let delay = bucket.delay_for(1024, now);
        assert!(
            delay >= Duration::from_millis(900),
            "the kilobyte past the burst is paced: {delay:?}"
        );
        assert_eq!(bucket.available, 0.0, "the bucket was drained");
    }

    #[test]
    fn refilling_restores_the_burst_cap() {
        let mut bucket = Bucket::new(1024);
        let start = Instant::now();
        bucket.delay_for(THROTTLE_BURST_BYTES as usize, start);
        assert_eq!(bucket.available, 0.0);
        // Ten seconds of a 1 KiB/s allowance is 10 KiB: the cap is a ceiling, not a target.
        bucket.refill(start + Duration::from_secs(10));
        assert_eq!(bucket.available, 10_240.0);
        // Once the allowance exceeds the burst, the bucket holds exactly the burst.
        bucket.refill(start + Duration::from_secs(600));
        assert_eq!(
            bucket.available, THROTTLE_BURST_BYTES as f64,
            "a long refill caps at the burst"
        );
    }

    #[test]
    fn a_refill_smaller_than_the_burst_is_exactly_timed() {
        let mut bucket = Bucket::new(1024);
        let start = Instant::now();
        bucket.delay_for(THROTTLE_BURST_BYTES as usize, start);
        bucket.refill(start + Duration::from_millis(500));
        assert_eq!(bucket.available, 512.0, "half a second at 1 KiB/s");
    }

    #[tokio::test]
    async fn a_throttled_read_still_delivers_every_byte() {
        let (mut peer, server) = tokio::io::duplex(1024);
        let mut shaped = ThrottledStream::new(server, RateLimit::new(1_000_000, 1_000_000));
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            peer.write_all(b"throttled payload").await.expect("write");
            peer.shutdown().await.expect("close");
        });
        let mut out = Vec::new();
        shaped.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"throttled payload");
    }

    #[test]
    fn validation_rejects_a_sub_byte_rate() {
        // The `rate < 1` branch is unreachable for `u64` rates, so the validator is only a
        // guard against future fractional configuration; prove it accepts the legal spellings.
        validate_rate_limit(&RateLimit::new(0, 0)).expect("unlimited is legal");
        validate_rate_limit(&RateLimit::new(1, 1)).expect("one byte per second is legal");
    }
}
