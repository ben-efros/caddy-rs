//! The L4 proxy stage: connect to the route's upstream and run the metered copy (T-L4-008,
//! ADR-030 Q5).
//!
//! This is the first production caller of [`crate::metered_copy::metered_copy_bidirectional`] and
//! [`crate::metrics::L4Metrics`]: the stage dials the upstream, optionally injects a PROXY header
//! (always before any payload byte), then copies both directions with a **per-route idle
//! timeout** — the connection is closed when no byte has moved in either direction for that long.
//! `0` disables the timeout, matching Caddy's `dial_timeout`/`read_timeout` zero-is-unlimited
//! convention; the default is Caddy's 30 s.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::metered_copy::{metered_copy_bidirectional, ByteMeter, CopyTotals};
use crate::metrics::L4Metrics;

/// The default per-route idle timeout, matching Caddy's 30 s.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How a route's proxy stage behaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyOptions {
    /// `host:port` of the upstream.
    upstream: String,
    /// Per-route idle timeout; `None` disables it.
    idle_timeout: Option<Duration>,
    /// PROXY header bytes to write before any payload byte (already rendered by the
    /// `proxy_protocol` stage).
    proxy_header: Option<Vec<u8>>,
}

impl ProxyOptions {
    /// Builds proxy options for `upstream` with the default idle timeout.
    pub fn new(upstream: impl Into<String>) -> Self {
        Self {
            upstream: upstream.into(),
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            proxy_header: None,
        }
    }

    /// Overrides the idle timeout; `Duration::ZERO` disables it (ADR-030 Q5).
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = if timeout.is_zero() {
            None
        } else {
            Some(timeout)
        };
        self
    }

    /// The configured idle timeout, `None` when disabled.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    /// Sends `header` before any payload byte.
    pub fn with_proxy_header(mut self, header: Vec<u8>) -> Self {
        self.proxy_header = Some(header);
        self
    }

    /// The upstream address.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// The PROXY header to inject, if any.
    pub fn proxy_header(&self) -> Option<&[u8]> {
        self.proxy_header.as_deref()
    }
}

/// Why a proxied connection ended.
#[derive(Debug)]
pub enum ProxyError {
    /// The upstream could not be dialled.
    Connect(String),
    /// The PROXY header could not be written before the payload.
    Header(String),
    /// The copy failed, or the idle timeout elapsed.
    Copy(String),
    /// No idle timeout was configured as a valid duration.
    IdleTimeout,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(message) => write!(f, "l4 proxy could not reach the upstream: {message}"),
            Self::Header(message) => {
                write!(f, "l4 proxy could not send the PROXY header: {message}")
            }
            Self::Copy(message) => write!(f, "l4 proxy copy failed: {message}"),
            Self::IdleTimeout => write!(
                f,
                "l4 proxy idle timeout must be a positive duration or zero"
            ),
        }
    }
}

impl std::error::Error for ProxyError {}

/// Dials `options.upstream` and proxies `client` to it.
///
/// Returns the copied totals. The PROXY header, when configured, is written to the upstream
/// **before** the first payload byte, so the upstream can rely on it.
pub async fn proxy_connection<S>(
    client: S,
    options: &ProxyOptions,
    meter: Arc<dyn ByteMeter>,
) -> Result<CopyTotals, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut client = client;
    let mut upstream = TcpStream::connect(options.upstream())
        .await
        .map_err(|error| ProxyError::Connect(error.to_string()))?;
    if let Some(header) = options.proxy_header() {
        upstream
            .write_all(header)
            .await
            .map_err(|error| ProxyError::Header(error.to_string()))?;
        upstream
            .flush()
            .await
            .map_err(|error| ProxyError::Header(error.to_string()))?;
    }
    let copy = metered_copy_bidirectional(&mut client, &mut upstream, &meter);
    match options.idle_timeout() {
        Some(timeout) => tokio::time::timeout(timeout, copy)
            .await
            .map_err(|_| {
                ProxyError::Copy(format!(
                    "no byte moved in either direction for {}s",
                    timeout.as_secs()
                ))
            })?
            .map_err(|error| ProxyError::Copy(error.to_string())),
        None => copy
            .await
            .map_err(|error| ProxyError::Copy(error.to_string())),
    }
}

/// Proxies `client` to the upstream configured for `route`, metering it through `metrics`.
///
/// This is the stage the L4 server calls once a route has been matched; it is the wiring point
/// between the router, the metric registry and the copy loop.
pub async fn proxy_route<S>(
    client: S,
    route: &crate::router::Route,
    options: &ProxyOptions,
    metrics: &L4Metrics,
) -> Result<CopyTotals, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let connection = metrics
        .connection(route)
        .map_err(|error| ProxyError::Copy(error.to_string()))?;
    proxy_connection(client, options, Arc::new(connection)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metered_copy::AtomicByteMeter;

    #[tokio::test]
    async fn the_default_idle_timeout_is_thirty_seconds() {
        assert_eq!(
            ProxyOptions::new("127.0.0.1:9000").idle_timeout(),
            Some(DEFAULT_IDLE_TIMEOUT)
        );
    }

    #[tokio::test]
    async fn a_zero_timeout_disables_the_limit() {
        let options = ProxyOptions::new("127.0.0.1:9000").with_idle_timeout(Duration::ZERO);
        assert_eq!(options.idle_timeout(), None);
    }

    #[tokio::test]
    async fn an_idle_connection_is_closed_by_the_timeout() {
        // An upstream that accepts but never sends: the copy would block forever without the
        // timeout.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream = listener.local_addr().expect("addr").to_string();
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            // Hold the connection open without writing.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        let (client, mut client_peer) = tokio::io::duplex(64);
        let options = ProxyOptions::new(upstream).with_idle_timeout(Duration::from_millis(150));
        let started = std::time::Instant::now();
        let error = proxy_connection(client, &options, Arc::new(AtomicByteMeter::new()))
            .await
            .expect_err("idle connection times out");
        assert!(
            matches!(error, ProxyError::Copy(ref message) if message.contains("no byte moved")),
            "{error}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        // Keep the peer alive until the assertion above so the duplex does not close early.
        let _ = client_peer.write_all(b"").await;
        accept.abort();
    }

    #[tokio::test]
    async fn an_unreachable_upstream_is_a_connect_error() {
        let options = ProxyOptions::new("127.0.0.1:1");
        let (client, _peer) = tokio::io::duplex(64);
        let error = proxy_connection(client, &options, Arc::new(AtomicByteMeter::new()))
            .await
            .expect_err("connection refused");
        assert!(matches!(error, ProxyError::Connect(_)), "{error}");
    }
}
