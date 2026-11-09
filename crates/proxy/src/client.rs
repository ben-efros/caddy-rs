//! Shared outbound HTTP client for proxying and health checks.
//!
//! The connector routes URIs by scheme:
//!
//! * `http://host:port/...` is dialed over TCP by hyper-util's [`HttpConnector`].
//! * `https://host:port/...` is dialed over TCP and wrapped in TLS (when the handler configures
//!   `transport.tls`); the server name comes from [`crate::tls::UpstreamTls`]. ALPN selects
//!   HTTP/2 or HTTP/1.1 (see [`UpstreamConnector::with_transport`]).
//! * Cleartext upstreams configured with `transport.versions: ["h2c", ...]` use HTTP/2 prior
//!   knowledge on the plain TCP/Unix connection (`h2c`): the connector reports an
//!   already-negotiated HTTP/2 connection so hyper's legacy client speaks h2 without an upgrade.
//! * `unix://<hex-encoded-socket-path>/...` is dialed over a Unix domain socket. The socket path
//!   is carried in the URI authority (hex-encoded, because an authority cannot contain `/`) so
//!   that hyper's connection pool keys each socket separately and the connector itself stays
//!   stateless and `Clone`.
//! * `unixs://<hex-encoded-socket-path>/...` is the same socket wrapped in TLS.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(test)]
use bytes::Bytes;
use caddy_rs_http::body::RequestBody;
use http::Uri;
#[cfg(test)]
use http_body_util::Full;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::client::TlsStream;
use tower_service::Service;

use crate::dns::{DnsResolver, IpVersion, ResolverAddress, SystemDnsResolver};
use crate::tls::UpstreamTls;
use crate::upstream::{Transport, Upstream};

/// Hyper client body type used for outbound requests.
///
/// [`RequestBody`] supports both buffered bytes and streamed chunks, so the proxy can forward a
/// request body without buffering it (see `T-PROXY-040`).
pub type ClientBody = RequestBody;

/// The generic outbound client type (URI-scheme-directed connector; used by tests/health helpers).
pub type HttpClient = Client<UpstreamConnector, ClientBody>;

/// A per-upstream client: the connector always dials one configured upstream regardless of the
/// request URI authority, so the URI authority can carry the client's Host for HTTP/2
/// `:authority` parity (see `crate::client::FixedUpstreamConnector`).
pub type UpstreamClient = Client<FixedUpstreamConnector, ClientBody>;

/// Which PROXY protocol header version to send to upstreams (`transport.proxy_protocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    /// Text header (`PROXY TCP4/TCP6 ...`).
    V1,
    /// Binary header (v2 signature + address block, no TLVs).
    V2,
}

impl ProxyProtocolVersion {
    /// Parse Caddy's JSON values (`"v1"` / `"v2"`).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "v1" => Some(Self::V1),
            "v2" => Some(Self::V2),
            _ => None,
        }
    }
}

/// Encode the per-request client address into a URI authority so the connector can write the
/// PROXY header for exactly this client.
///
/// Caddy encodes `proxyProtocolInfo.AddrPort.String() + "->" + reqHost` with `url.QueryEscape`
/// (`httptransport.go`/`reverseproxy.go`) so an HTTP/2 connection is never reused for a different
/// client (Caddy issue #7529). Rust's `http::Uri` rejects percent-encoded authorities, so the same
/// information is encoded in a plain reg-name token: `pp-<hex client ip>-p<port>.<host>`. The host
/// part keeps the per-client pool key; the token is what the connector decodes.
pub(crate) fn proxy_protocol_authority(source: IpAddr, host: &str) -> String {
    let token = match source {
        IpAddr::V4(address) => format!("pp-{:08x}-p0", u32::from(address)),
        IpAddr::V6(address) => format!("pp-{:032x}-p0", u128::from(address)),
    };
    format!("{token}.{host}")
}

/// Recover the PROXY-protocol source address from a request URI authority.
///
/// Returns `None` when the authority carries no marker (for example active health-check requests,
/// which use Caddy's plain default HTTP client and therefore send no PROXY header, like Caddy).
pub(crate) fn proxy_protocol_source(authority: &str) -> Option<IpAddr> {
    let marker = authority.strip_prefix("pp-")?;
    let (hex, rest) = marker.split_once("-p")?;
    let port_end = rest.find('.').unwrap_or(rest.len());
    rest[..port_end].parse::<u16>().ok()?;
    match hex.len() {
        8 => {
            let value = u32::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V4(std::net::Ipv4Addr::from(value)))
        }
        32 => {
            let value = u128::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(value)))
        }
        _ => None,
    }
}

/// Build the PROXY protocol header bytes Caddy's `go-proxyproto` writes for these addresses.
///
/// Caddy sets the source to the resolved client address (port 0, because `client_ip` has no port)
/// and the destination to the all-zero address of the same family, since the original destination
/// is not knowable (`httptransport.go`, `ProxyProtocolInfo`).
pub(crate) fn proxy_protocol_header(version: ProxyProtocolVersion, source: IpAddr) -> Vec<u8> {
    match version {
        ProxyProtocolVersion::V1 => match source {
            IpAddr::V4(address) => format!("PROXY TCP4 {address} 0.0.0.0 0 0\r\n").into_bytes(),
            IpAddr::V6(address) => format!("PROXY TCP6 {address} :: 0 0\r\n").into_bytes(),
        },
        ProxyProtocolVersion::V2 => {
            let mut header = Vec::with_capacity(28);
            header.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
            header.push(0x21); // version 2, command PROXY
            match source {
                IpAddr::V4(address) => {
                    header.push(0x11); // AF_INET, STREAM
                    header.extend_from_slice(&12u16.to_be_bytes());
                    header.extend_from_slice(&address.octets());
                    header.extend_from_slice(&[0, 0, 0, 0]);
                }
                IpAddr::V6(address) => {
                    header.push(0x21); // AF_INET6, STREAM
                    header.extend_from_slice(&36u16.to_be_bytes());
                    header.extend_from_slice(&address.octets());
                    header.extend_from_slice(&[0u8; 16]);
                }
            }
            header.extend_from_slice(&0u16.to_be_bytes()); // source port (Caddy: port 0)
            header.extend_from_slice(&0u16.to_be_bytes()); // destination port
            header
        }
    }
}

/// Caddy's `transport.keep_alive` settings, in the form the connector consumes.
///
/// Caddy's defaults (`httptransport.go` `NewTransport`) are applied even when the JSON object is
/// absent: HTTP keep-alive enabled, a 30 s TCP keep-alive probe interval, at most 32 idle
/// connections per host and a 2 min idle connection timeout. This type stores the *effective*
/// values, so `Default` is Caddy's default transport.
#[derive(Debug, Clone)]
pub struct KeepAliveConfig {
    /// Whether HTTP connections may be reused (`keep_alive.enabled`).
    pub enabled: bool,
    /// TCP keep-alive idle/interval; `None` disables TCP keep-alive (negative
    /// `keep_alive.probe_interval` in Caddy).
    pub probe_interval: Option<Duration>,
    /// Global idle-connection cap (`keep_alive.max_idle_conns`); `None` means no limit.
    pub max_idle_conns: Option<usize>,
    /// Per-host idle-connection cap (`keep_alive.max_idle_conns_per_host`).
    pub max_idle_conns_per_host: usize,
    /// How long an idle pooled connection is kept (`keep_alive.idle_timeout`); `None` keeps it
    /// until the upstream closes it.
    pub idle_timeout: Option<Duration>,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            probe_interval: Some(Duration::from_secs(30)),
            max_idle_conns: None,
            max_idle_conns_per_host: 32,
            idle_timeout: Some(Duration::from_secs(120)),
        }
    }
}

impl KeepAliveConfig {
    /// The idle-connection cap hyper's pool should enforce for one upstream client.
    ///
    /// caddy-rs builds one client per upstream (see [`FixedUpstreamConnector`]), so Caddy's
    /// *global* `max_idle_conns` and its per-host cap both constrain the same pool: the tighter
    /// of the two applies (DIV-0112 documents this).
    pub fn pool_max_idle_per_host(&self) -> usize {
        if !self.enabled {
            return 0;
        }
        match self.max_idle_conns {
            Some(total) => total.min(self.max_idle_conns_per_host),
            None => self.max_idle_conns_per_host,
        }
    }
}

/// A DNS resolver configured for the upstream transport (`transport.resolver`).
///
/// Caddy's transport uses the configured resolvers only for hostnames; an IP-literal upstream
/// dial is never resolved. Queries reuse the transport's `dial_timeout` as their bound, like
/// Caddy's resolver dialer.
#[derive(Debug, Clone)]
pub struct TransportResolver {
    addresses: Vec<ResolverAddress>,
    timeout: Duration,
}

impl TransportResolver {
    /// Build a resolver from already-parsed `transport.resolver.addresses` entries.
    pub fn new(addresses: Vec<ResolverAddress>, timeout: Duration) -> Self {
        Self { addresses, timeout }
    }

    /// Resolve `host` with the configured resolvers, returning socket addresses on `port`.
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let addresses = SystemDnsResolver
            .lookup_ip(host, IpVersion::Both, &self.addresses, self.timeout)
            .await
            .map_err(io::Error::other)?;
        Ok(addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect())
    }
}

/// Connection-tuning subset of Caddy's HTTP transport (`keep_alive`, `max_conns_per_host`,
/// `dial_fallback_delay`, `local_address`, `resolver`, `read_buffer_size`).
///
/// `Default` is Caddy's default transport. The handler parses the JSON form into this type and
/// hands it to the per-upstream client builders.
#[derive(Debug, Clone)]
pub struct TransportTuning {
    /// Caddy `keep_alive`.
    pub keep_alive: KeepAliveConfig,
    /// Caddy `max_conns_per_host`; `None` means no limit.
    pub max_conns_per_host: Option<usize>,
    /// Caddy `dial_fallback_delay`: `Some(delay)` races resolved addresses, `None` (a negative
    /// value in Caddy) dials them serially. Caddy's default is 300 ms.
    pub fallback_delay: Option<Duration>,
    /// Caddy `local_address`, resolved to a socket address at config load.
    pub local_address: Option<SocketAddr>,
    /// Caddy `resolver`.
    pub resolver: Option<Arc<TransportResolver>>,
    /// Caddy `read_buffer_size` (HTTP/1 read buffer; Caddy's minimum is 4 KiB).
    pub read_buffer_size: Option<usize>,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            keep_alive: KeepAliveConfig::default(),
            max_conns_per_host: None,
            fallback_delay: Some(Duration::from_millis(300)),
            local_address: None,
            resolver: None,
            read_buffer_size: None,
        }
    }
}

/// Connector supporting TCP, Unix-socket, TLS, HTTP/2-ALPN and cleartext-h2c upstreams.
#[derive(Clone, Debug)]
pub struct UpstreamConnector {
    tcp: HttpConnector,
    tls: Option<Arc<UpstreamTls>>,
    /// Speak HTTP/2 with prior knowledge (no upgrade) on cleartext connections (`h2c`).
    h2c: bool,
}

impl UpstreamConnector {
    /// Create a plaintext-only HTTP/1.1 connector with tokio-backed TCP dialing.
    pub fn new() -> Self {
        Self {
            tcp: tcp_connector(),
            tls: None,
            h2c: false,
        }
    }

    /// Create a connector that enables TLS for `https://`/`unixs://` URIs.
    pub fn with_tls(tls: Option<Arc<UpstreamTls>>) -> Self {
        Self::with_transport(tls, false)
    }

    /// Create a connector for a configured `transport`.
    ///
    /// * `tls` — client configuration for `https://`/`unixs://` URIs; ALPN protocols are taken
    ///   from the [`UpstreamTls`] value itself.
    /// * `h2c` — use HTTP/2 prior knowledge on cleartext `http://`/`unix://` connections.
    pub fn with_transport(tls: Option<Arc<UpstreamTls>>, h2c: bool) -> Self {
        Self {
            tcp: tcp_connector(),
            tls,
            h2c,
        }
    }
}

/// hyper-util's [`HttpConnector`] enforces the `http` scheme by default (it was designed to be
/// wrapped by a TLS connector that passes `https`). This connector handles TLS itself, so the
/// plain TCP dialer must accept `https`/`unixs` URIs too.
fn tcp_connector() -> HttpConnector {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    connector
}

impl Default for UpstreamConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl Service<Uri> for UpstreamConnector {
    type Response = TokioIo<UpstreamStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut tcp = self.tcp.clone();
        let tls = self.tls.clone();
        let h2c = self.h2c;
        Box::pin(async move {
            match uri.scheme_str() {
                Some("unix") => {
                    #[cfg(unix)]
                    {
                        let path = unix_socket_path(&uri)?;
                        let stream = tokio::net::UnixStream::connect(&path).await?;
                        Ok(TokioIo::new(UpstreamStream::plain(stream, h2c)))
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = &mut tcp;
                        Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "unix sockets are not supported on this platform",
                        ))
                    }
                }
                Some("unixs") => {
                    #[cfg(unix)]
                    {
                        let tls = require_tls(tls)?;
                        let path = unix_socket_path(&uri)?;
                        let server_name = tls.server_name_for(None).map_err(|message| {
                            io::Error::new(io::ErrorKind::InvalidInput, message)
                        })?;
                        let stream = tokio::net::UnixStream::connect(&path).await?;
                        let stream = connect_tls(&tls, server_name, stream).await?;
                        Ok(TokioIo::new(UpstreamStream::tls(stream)))
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = &mut tcp;
                        Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "unix sockets are not supported on this platform",
                        ))
                    }
                }
                Some("https") => {
                    let tls = require_tls(tls)?;
                    let server_name = tls
                        .server_name_for(uri.host())
                        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
                    let stream = tcp.call(uri).await.map_err(io::Error::other)?.into_inner();
                    let stream = connect_tls(&tls, server_name, stream).await?;
                    Ok(TokioIo::new(UpstreamStream::tls(stream)))
                }
                _ => {
                    let stream = tcp.call(uri).await.map_err(io::Error::other)?.into_inner();
                    Ok(TokioIo::new(UpstreamStream::plain(stream, h2c)))
                }
            }
        })
    }
}

fn require_tls(tls: Option<Arc<UpstreamTls>>) -> io::Result<Arc<UpstreamTls>> {
    tls.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS upstream URI used with a client that has no transport.tls configuration",
        )
    })
}

#[cfg(unix)]
fn unix_socket_path(uri: &Uri) -> io::Result<std::path::PathBuf> {
    let authority = uri.host().unwrap_or_default();
    crate::upstream::decode_unix_authority(authority)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))
}

/// Perform the TLS handshake, optionally bounded by `transport.tls.handshake_timeout`.
async fn connect_tls<S>(
    tls: &UpstreamTls,
    server_name: ServerName<'static>,
    stream: S,
) -> io::Result<TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connector = tokio_rustls::TlsConnector::from(tls.client_config());
    match tls.handshake_timeout() {
        Some(timeout) => {
            match tokio::time::timeout(timeout, connector.connect(server_name, stream)).await {
                Ok(result) => result.map_err(io::Error::other),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS handshake to upstream timed out",
                )),
            }
        }
        None => connector
            .connect(server_name, stream)
            .await
            .map_err(io::Error::other),
    }
}

/// Transport hyper may drive for an upstream connection.
///
/// The connection reports HTTP/2 as already negotiated when ALPN selected `h2` (TLS) or when the
/// transport is configured for h2c prior knowledge. hyper-util's legacy client then speaks HTTP/2
/// on this connection instead of HTTP/1.1.
#[derive(Debug)]
pub struct UpstreamStream {
    io: StreamIo,
    /// Cleartext HTTP/2 prior knowledge (h2c): no ALPN to inspect.
    prior_knowledge_h2: bool,
    /// `transport.max_conns_per_host` slot, released when the connection is dropped.
    conn_permit: Option<OwnedSemaphorePermit>,
}

#[derive(Debug)]
enum StreamIo {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Tls(Box<TlsStream<tokio::net::TcpStream>>),
    #[cfg(unix)]
    UnixTls(Box<TlsStream<tokio::net::UnixStream>>),
}

impl UpstreamStream {
    fn plain<S>(stream: S, prior_knowledge_h2: bool) -> Self
    where
        S: Into<PlainIo>,
    {
        Self {
            io: stream.into().into(),
            prior_knowledge_h2,
            conn_permit: None,
        }
    }

    fn tls<S>(stream: TlsStream<S>) -> Self
    where
        TlsStream<S>: Into<TlsIo>,
    {
        Self {
            io: stream.into().into(),
            prior_knowledge_h2: false,
            conn_permit: None,
        }
    }

    /// Hold a `transport.max_conns_per_host` slot for as long as this connection lives.
    fn with_permit(mut self, permit: Option<OwnedSemaphorePermit>) -> Self {
        self.conn_permit = permit;
        self
    }

    /// Whether HTTP/2 was negotiated (ALPN `h2` or h2c prior knowledge).
    fn is_http2(&self) -> bool {
        if self.prior_knowledge_h2 {
            return true;
        }
        match &self.io {
            StreamIo::Tls(stream) => stream.get_ref().1.alpn_protocol() == Some(b"h2"),
            #[cfg(unix)]
            StreamIo::UnixTls(stream) => stream.get_ref().1.alpn_protocol() == Some(b"h2"),
            StreamIo::Tcp(_) => false,
            #[cfg(unix)]
            StreamIo::Unix(_) => false,
        }
    }
}

/// Helper so [`UpstreamStream::plain`] works for TCP and Unix streams.
enum PlainIo {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl From<tokio::net::TcpStream> for PlainIo {
    fn from(stream: tokio::net::TcpStream) -> Self {
        Self::Tcp(stream)
    }
}

#[cfg(unix)]
impl From<tokio::net::UnixStream> for PlainIo {
    fn from(stream: tokio::net::UnixStream) -> Self {
        Self::Unix(stream)
    }
}

impl From<PlainIo> for StreamIo {
    fn from(io: PlainIo) -> Self {
        match io {
            PlainIo::Tcp(stream) => Self::Tcp(stream),
            #[cfg(unix)]
            PlainIo::Unix(stream) => Self::Unix(stream),
        }
    }
}

/// Helper so [`UpstreamStream::tls`] works for TCP and Unix TLS streams.
enum TlsIo {
    Tcp(Box<TlsStream<tokio::net::TcpStream>>),
    #[cfg(unix)]
    Unix(Box<TlsStream<tokio::net::UnixStream>>),
}

impl From<TlsStream<tokio::net::TcpStream>> for TlsIo {
    fn from(stream: TlsStream<tokio::net::TcpStream>) -> Self {
        Self::Tcp(Box::new(stream))
    }
}

#[cfg(unix)]
impl From<TlsStream<tokio::net::UnixStream>> for TlsIo {
    fn from(stream: TlsStream<tokio::net::UnixStream>) -> Self {
        Self::Unix(Box::new(stream))
    }
}

impl From<TlsIo> for StreamIo {
    fn from(io: TlsIo) -> Self {
        match io {
            TlsIo::Tcp(stream) => Self::Tls(stream),
            #[cfg(unix)]
            TlsIo::Unix(stream) => Self::UnixTls(stream),
        }
    }
}

impl Connection for UpstreamStream {
    fn connected(&self) -> Connected {
        if self.is_http2() {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}

impl tokio::io::AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            StreamIo::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            StreamIo::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            StreamIo::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
            #[cfg(unix)]
            StreamIo::UnixTls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().io {
            StreamIo::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            StreamIo::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            StreamIo::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
            #[cfg(unix)]
            StreamIo::UnixTls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            StreamIo::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            StreamIo::Unix(stream) => Pin::new(stream).poll_flush(cx),
            StreamIo::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            #[cfg(unix)]
            StreamIo::UnixTls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().io {
            StreamIo::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            StreamIo::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            StreamIo::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            #[cfg(unix)]
            StreamIo::UnixTls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Build the plaintext HTTP/1.1 client used by tests and health checks.
pub fn build_client() -> HttpClient {
    build_client_with_tls(None)
}

/// Build the outbound client, enabling TLS when `transport.tls` is configured.
pub fn build_client_with_tls(tls: Option<Arc<UpstreamTls>>) -> HttpClient {
    build_client_with_transport(tls, false)
}

/// Build the outbound client for a configured `transport` (TLS and/or h2c).
///
/// The connector's ALPN/HTTP/2 decision is per connection, so the same client serves all
/// upstreams and active health checks of the handler.
pub fn build_client_with_transport(tls: Option<Arc<UpstreamTls>>, h2c: bool) -> HttpClient {
    Client::builder(TokioExecutor::new()).build(UpstreamConnector::with_transport(tls, h2c))
}

/// How a per-upstream client reaches its upstream.
#[derive(Clone, Debug)]
enum DialTarget {
    /// `host:port` TCP target.
    Tcp(String),
    /// Unix domain socket path.
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

/// Connector bound to one upstream target.
///
/// hyper's client derives the HTTP/2 `:authority` pseudo-header (and HTTP/1.1 `Host`, when the
/// header is absent) from the request URI, not from the connector. To match Caddy/Go — where the
/// client's `Host` becomes `:authority` while the configured upstream is still what gets dialed —
/// the proxy gives each upstream a client whose connector ignores the URI authority and always
/// connects to its configured target. TLS SNI is likewise derived from the *dial* target (or the
/// explicit `transport.tls.server_name`), never from the URI authority.
#[derive(Clone, Debug)]
pub struct FixedUpstreamConnector {
    target: DialTarget,
    tls: Option<Arc<UpstreamTls>>,
    server_name: Option<ServerName<'static>>,
    h2c: bool,
    /// Send a PROXY protocol header on every new connection (`transport.proxy_protocol`).
    proxy_protocol: Option<ProxyProtocolVersion>,
    /// `transport.dial_timeout`: cap on establishing the upstream connection.
    dial_timeout: Option<Duration>,
    /// Connection tuning parsed from `transport` (T-PROXY-054).
    tuning: Arc<TransportTuning>,
    /// `transport.max_conns_per_host` slots; held by live connections.
    max_conns: Option<Arc<Semaphore>>,
}

impl Service<Uri> for FixedUpstreamConnector {
    type Response = TokioIo<UpstreamStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let target = self.target.clone();
        let tls = self.tls.clone();
        let server_name = self.server_name.clone();
        let h2c = self.h2c;
        let proxy_protocol = self.proxy_protocol;
        let dial_timeout = self.dial_timeout;
        let tuning = Arc::clone(&self.tuning);
        let max_conns = self.max_conns.clone();
        Box::pin(async move {
            // The authority marker carries the PROXY-protocol source address. Health checks build
            // plain upstream URLs (no marker) and therefore send no header, matching Caddy's
            // active checker, which uses the default HTTP client instead of the configured
            // transport.
            let proxy_source = uri
                .authority()
                .and_then(|authority| proxy_protocol_source(authority.as_str()));
            match target {
                DialTarget::Tcp(address) => {
                    // One semaphore permit is held by each live connection (idle or in use), which
                    // is Go's `MaxConnsPerHost` accounting.
                    let permit = match &max_conns {
                        Some(semaphore) => {
                            Some(semaphore.clone().acquire_owned().await.map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "upstream connection limiter closed",
                                )
                            })?)
                        }
                        None => None,
                    };
                    let dial = dial_tcp(&address, &tuning);
                    let mut stream = match dial_timeout {
                        Some(limit) => match tokio::time::timeout(limit, dial).await {
                            Ok(result) => result?,
                            Err(_) => return Err(dial_timed_out(&address, limit)),
                        },
                        None => dial.await?,
                    };
                    apply_tcp_keepalive(&stream, tuning.keep_alive.probe_interval)?;
                    // The header is written before the TLS handshake, so a TLS upstream sees the
                    // PROXY header ahead of the ClientHello (Caddy writes it before wrapping the
                    // connection in the TLS client).
                    if let (Some(version), Some(source)) = (proxy_protocol, proxy_source) {
                        stream
                            .write_all(&proxy_protocol_header(version, source))
                            .await?;
                    }
                    match tls {
                        Some(tls) => {
                            let server_name = server_name.ok_or_else(no_server_name)?;
                            let stream = connect_tls(&tls, server_name, stream).await?;
                            Ok(TokioIo::new(
                                UpstreamStream::tls(stream).with_permit(permit),
                            ))
                        }
                        None => Ok(TokioIo::new(
                            UpstreamStream::plain(stream, h2c).with_permit(permit),
                        )),
                    }
                }
                #[cfg(unix)]
                DialTarget::Unix(path) => {
                    if proxy_protocol.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "PROXY protocol is not supported for Unix-socket upstreams",
                        ));
                    }
                    if tuning.local_address.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "transport.local_address is not supported for Unix-socket upstreams",
                        ));
                    }
                    let connect = tokio::net::UnixStream::connect(&path);
                    let stream = match dial_timeout {
                        Some(limit) => match tokio::time::timeout(limit, connect).await {
                            Ok(result) => result?,
                            Err(_) => {
                                return Err(dial_timed_out(&path.display().to_string(), limit))
                            }
                        },
                        None => connect.await?,
                    };
                    match tls {
                        Some(tls) => {
                            let server_name = server_name.ok_or_else(no_server_name)?;
                            let stream = connect_tls(&tls, server_name, stream).await?;
                            Ok(TokioIo::new(UpstreamStream::tls(stream)))
                        }
                        None => Ok(TokioIo::new(UpstreamStream::plain(stream, h2c))),
                    }
                }
            }
        })
    }
}

/// Resolve and connect to an upstream `host:port`, honouring `dial_fallback_delay`,
/// `local_address` and `resolver`.
///
/// Name resolution happens here (rather than in hyper-util's `HttpConnector`) so the transport's
/// resolver, local bind address and RFC 6555 Fast Fallback apply to the actual dial.
async fn dial_tcp(address: &str, tuning: &TransportTuning) -> io::Result<TcpStream> {
    let (host, port) = split_host_port(address)?;
    let mut addresses = resolve_upstream(host, port, tuning).await?;
    if let Some(local) = tuning.local_address {
        addresses.retain(|address| address.is_ipv4() == local.is_ipv4());
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "transport.local_address {local} has a different address family than upstream `{address}`"
                ),
            ));
        }
    }
    let local = tuning.local_address;
    match tuning.fallback_delay {
        Some(delay) if addresses.len() > 1 => {
            race_connect(addresses, delay, move |address| {
                connect_address(address, local)
            })
            .await
        }
        _ => {
            let mut last_error = None;
            for address in addresses {
                match connect_address(address, local).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("upstream `{address}` resolved to no addresses"),
                )
            }))
        }
    }
}

/// Split a `host:port` or `[v6]:port` dial address.
fn split_host_port(address: &str) -> io::Result<(&str, u16)> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("upstream dial `{address}` is not a host:port address"),
        )
    };
    if let Some(rest) = address.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(invalid)?;
        let port = after
            .strip_prefix(':')
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("upstream dial `{address}` has an invalid port"),
                )
            })?;
        return Ok((host, port));
    }
    let (host, port) = address.rsplit_once(':').ok_or_else(invalid)?;
    let port = port.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("upstream dial `{address}` has an invalid port"),
        )
    })?;
    Ok((host, port))
}

/// Resolve an upstream host: IP literals pass through, hostnames use the configured
/// `transport.resolver` or the system resolver.
async fn resolve_upstream(
    host: &str,
    port: u16,
    tuning: &TransportTuning,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    match &tuning.resolver {
        Some(resolver) => resolver.resolve(host, port).await,
        None => {
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("upstream host `{host}` resolved to no addresses"),
                ));
            }
            Ok(addresses)
        }
    }
}

/// Connect to one resolved address, binding `local_address` first when configured.
async fn connect_address(address: SocketAddr, local: Option<SocketAddr>) -> io::Result<TcpStream> {
    let stream = match local {
        None => TcpStream::connect(address).await?,
        Some(local) => {
            let socket = match local {
                SocketAddr::V4(_) => TcpSocket::new_v4()?,
                SocketAddr::V6(_) => TcpSocket::new_v6()?,
            };
            socket.bind(local)?;
            socket.connect(address).await?
        }
    };
    Ok(stream)
}

/// Race resolved addresses: start the next attempt after `delay` (or immediately after a
/// failure), and keep the first connection that succeeds.
///
/// This is the RFC 6555 Fast Fallback behaviour of Go's `net.Dialer.FallbackDelay`, which Caddy
/// exposes as `transport.dial_fallback_delay`.
async fn race_connect<T, F, Fut>(
    addresses: Vec<SocketAddr>,
    delay: Duration,
    connect: F,
) -> io::Result<T>
where
    T: Send + 'static,
    F: Fn(SocketAddr) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = io::Result<T>> + Send + 'static,
{
    let mut pending = addresses.into_iter();
    let mut tasks = tokio::task::JoinSet::new();
    let mut last_error: Option<io::Error> = None;
    let mut next = pending.next();
    if let Some(address) = next.take() {
        tasks.spawn(connect(address));
        next = pending.next();
    }
    loop {
        if tasks.is_empty() && next.is_none() {
            return Err(last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no upstream addresses to dial")
            }));
        }
        tokio::select! {
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(Ok(value))) => {
                        tasks.abort_all();
                        return Ok(value);
                    }
                    Some(Ok(Err(error))) => last_error = Some(error),
                    Some(Err(error)) => last_error = Some(io::Error::other(error)),
                    None => {}
                }
                // A failed attempt frees the lane immediately; do not wait out the fallback delay.
                if let Some(address) = next.take() {
                    tasks.spawn(connect(address));
                    next = pending.next();
                }
            }
            _ = tokio::time::sleep(delay), if next.is_some() => {
                if let Some(address) = next.take() {
                    tasks.spawn(connect(address));
                    next = pending.next();
                }
            }
        }
    }
}

/// Apply Caddy's TCP keep-alive settings (`keep_alive.probe_interval`) to a connected socket.
///
/// Caddy sets `SO_KEEPALIVE` and uses the probe interval for both the idle time and the interval;
/// a negative interval disables TCP keep-alive.
fn apply_tcp_keepalive(stream: &TcpStream, probe_interval: Option<Duration>) -> io::Result<()> {
    let socket = socket2::SockRef::from(stream);
    match probe_interval {
        Some(interval) => {
            socket.set_keepalive(true)?;
            socket.set_tcp_keepalive(
                &socket2::TcpKeepalive::new()
                    .with_time(interval)
                    .with_interval(interval),
            )
        }
        None => socket.set_keepalive(false),
    }
}

/// Error surfaced when `transport.dial_timeout` elapses before the upstream accepts.
fn dial_timed_out(target: &str, limit: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("upstream dial `{target}` did not complete within {limit:?}"),
    )
}

fn no_server_name() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "TLS upstream has no server name (this is validated at config load)",
    )
}

/// Strip the port from a `host:port` (or `[v6]:port`) dial address.
fn host_without_port(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    address
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(address)
}

/// Build a client bound to `upstream`.
///
/// * `tls` / `h2c` come from the handler's parsed `transport`; `http1_only` builds the companion
///   used for protocol upgrades (ALPN/h2c disabled).
/// * TLS server name: explicit `transport.tls.server_name`, else the dial host (Caddy default).
pub fn build_upstream_client(
    upstream: &Upstream,
    tls: Option<Arc<UpstreamTls>>,
    h2c: bool,
    http1_only: bool,
) -> Result<UpstreamClient, String> {
    let transport = upstream.transport().ok_or_else(|| {
        format!(
            "upstream `{}` has a dynamic dial; build its client from the expanded transport",
            upstream.dial
        )
    })?;
    build_upstream_client_for(transport, tls, h2c, http1_only, None, None)
}

/// Like [`build_upstream_client`] but with a configured PROXY protocol version and dial timeout.
pub fn build_upstream_client_with_proxy_protocol(
    upstream: &Upstream,
    tls: Option<Arc<UpstreamTls>>,
    h2c: bool,
    http1_only: bool,
    proxy_protocol: Option<ProxyProtocolVersion>,
    dial_timeout: Option<Duration>,
) -> Result<UpstreamClient, String> {
    let transport = upstream.transport().ok_or_else(|| {
        format!(
            "upstream `{}` has a dynamic dial; build its client from the expanded transport",
            upstream.dial
        )
    })?;
    build_upstream_client_for(
        transport,
        tls,
        h2c,
        http1_only,
        proxy_protocol,
        dial_timeout,
    )
}

/// Like [`build_upstream_client_with_proxy_protocol`] with the handler's connection tuning.
pub fn build_upstream_client_with_proxy_protocol_tuned(
    upstream: &Upstream,
    tls: Option<Arc<UpstreamTls>>,
    h2c: bool,
    http1_only: bool,
    proxy_protocol: Option<ProxyProtocolVersion>,
    dial_timeout: Option<Duration>,
    tuning: &TransportTuning,
) -> Result<UpstreamClient, String> {
    let transport = upstream.transport().ok_or_else(|| {
        format!(
            "upstream `{}` has a dynamic dial; build its client from the expanded transport",
            upstream.dial
        )
    })?;
    build_upstream_client_for_tuned(
        transport,
        tls,
        h2c,
        http1_only,
        proxy_protocol,
        dial_timeout,
        tuning,
    )
}

/// Build a client bound to one already-resolved dial transport with Caddy's default tuning.
///
/// Used by tests and health-check helpers; the handler uses
/// [`build_upstream_client_for_tuned`] with the parsed `transport` knobs.
pub fn build_upstream_client_for(
    transport: &Transport,
    tls: Option<Arc<UpstreamTls>>,
    h2c: bool,
    http1_only: bool,
    proxy_protocol: Option<ProxyProtocolVersion>,
    dial_timeout: Option<Duration>,
) -> Result<UpstreamClient, String> {
    build_upstream_client_for_tuned(
        transport,
        tls,
        h2c,
        http1_only,
        proxy_protocol,
        dial_timeout,
        &TransportTuning::default(),
    )
}

/// Build a client bound to one already-resolved dial transport.
///
/// Used for fixed upstreams and for dynamic (placeholder) upstreams after per-request expansion.
/// TLS server name: explicit `transport.tls.server_name`, else the dial host (Caddy default).
pub fn build_upstream_client_for_tuned(
    transport: &Transport,
    tls: Option<Arc<UpstreamTls>>,
    h2c: bool,
    http1_only: bool,
    proxy_protocol: Option<ProxyProtocolVersion>,
    dial_timeout: Option<Duration>,
    tuning: &TransportTuning,
) -> Result<UpstreamClient, String> {
    let tls = if http1_only {
        tls.map(|tls| Arc::new(tls.h1_only()))
    } else {
        tls
    };
    let h2c = h2c && !http1_only;
    let server_name = match &tls {
        Some(tls) => Some(match transport {
            Transport::Tcp { address } => tls.server_name_for(Some(host_without_port(address)))?,
            #[cfg(unix)]
            Transport::Unix { .. } => tls.server_name_for(None)?,
        }),
        None => None,
    };
    let target = match transport {
        Transport::Tcp { address } => DialTarget::Tcp(address.clone()),
        #[cfg(unix)]
        Transport::Unix { path } => DialTarget::Unix(path.clone()),
    };
    let mut builder = Client::builder(TokioExecutor::new());
    // Caddy's pool: `keep_alive.idle_timeout` and the effective idle cap (per-host, since each
    // client serves exactly one upstream target).
    builder.pool_max_idle_per_host(tuning.keep_alive.pool_max_idle_per_host());
    builder.pool_idle_timeout(tuning.keep_alive.idle_timeout);
    if let Some(size) = tuning.read_buffer_size {
        builder.http1_read_buf_exact_size(size);
    }
    let max_conns = tuning
        .max_conns_per_host
        .map(|limit| Arc::new(Semaphore::new(limit)));
    Ok(builder.build(FixedUpstreamConnector {
        target,
        tls,
        server_name,
        h2c,
        proxy_protocol,
        dial_timeout,
        tuning: Arc::new(tuning.clone()),
        max_conns,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use std::convert::Infallible;

    #[test]
    fn uri_scheme_selects_transport() {
        // The connector is stateless; the URI scheme decides TCP/Unix/TLS, and ALPN/h2c decides
        // HTTP/1.1 vs HTTP/2.
        let unix = Uri::from_static("unix://2f72756e2f6170702e736f636b/health");
        assert_eq!(unix.scheme_str(), Some("unix"));
        let unix_tls = Uri::from_static("unixs://2f72756e2f6170702e736f636b/health");
        assert_eq!(unix_tls.scheme_str(), Some("unixs"));
        let tcp = Uri::from_static("http://127.0.0.1:8080/health");
        assert_eq!(tcp.scheme_str(), Some("http"));
        let https = Uri::from_static("https://127.0.0.1:8443/health");
        assert_eq!(https.scheme_str(), Some("https"));
    }

    #[tokio::test]
    async fn dial_timeout_bounds_the_upstream_dial() {
        // TEST-NET-1 is not routed, so the dial only ends when the configured cap fires (or the
        // host rejects the route immediately, in which case it still must not hang).
        let upstream = crate::upstream::Upstream::parse_dial("192.0.2.1:81", false).unwrap();
        let client = build_upstream_client_for(
            upstream.transport().unwrap(),
            None,
            false,
            false,
            None,
            Some(Duration::from_millis(150)),
        )
        .expect("client with dial_timeout");
        let request = hyper::Request::builder()
            .uri(upstream.url("/"))
            .body(RequestBody::empty())
            .unwrap();
        let started = std::time::Instant::now();
        let error = client.request(request).await.expect_err("dial must fail");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "dial_timeout must bound the wait, took {:?}",
            started.elapsed()
        );
        // hyper wraps connector errors, so check the whole chain for the cause.
        let mut message = error.to_string();
        let mut source = std::error::Error::source(&error);
        while let Some(current) = source {
            message.push_str(&format!(": {current}"));
            source = current.source();
        }
        assert!(
            message.contains("did not complete within")
                || message.contains("unreachable")
                || message.contains("Connection refused")
                || message.contains("timed out"),
            "unexpected dial error: {message}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn client_serves_request_over_unix_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("upstream.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let service = service_fn(
                |request: hyper::Request<hyper::body::Incoming>| async move {
                    let body = format!("unix path={}", request.uri().path());
                    Ok::<_, Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                },
            );
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let upstream =
            crate::upstream::Upstream::parse_dial(&format!("unix/{}", socket.display()), false)
                .unwrap();
        let client = build_client();
        let request = hyper::Request::builder()
            .uri(upstream.url("/over-unix"))
            .body(RequestBody::empty())
            .unwrap();
        let response = client.request(request).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            crate::health::drain(response.into_body()).await.unwrap(),
            Bytes::from_static(b"unix path=/over-unix")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn client_reports_missing_unix_socket_as_connect_error() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("missing.sock");
        let upstream =
            crate::upstream::Upstream::parse_dial(&format!("unix/{}", socket.display()), false)
                .unwrap();
        let client = build_client();
        let request = hyper::Request::builder()
            .uri(upstream.url("/"))
            .body(RequestBody::empty())
            .unwrap();
        let error = client
            .request(request)
            .await
            .expect_err("missing unix socket must fail");
        assert!(error.is_connect(), "expected a dial error, got {error}");
    }

    #[tokio::test]
    async fn tls_uri_without_transport_tls_config_fails() {
        let client = build_client();
        let request = hyper::Request::builder()
            .uri("https://127.0.0.1:9/")
            .body(RequestBody::empty())
            .unwrap();
        let error = client
            .request(request)
            .await
            .expect_err("https without TLS config must fail");
        assert!(error.is_connect(), "expected a connect error, got {error}");
    }

    #[test]
    fn proxy_protocol_authority_round_trips_the_source_address() {
        for source in [
            "192.0.2.10".parse::<IpAddr>().unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap(),
        ] {
            let authority = proxy_protocol_authority(source, "example.com:8080");
            assert!(
                authority.parse::<Uri>().is_ok(),
                "marker authority must be URI-valid: {authority}"
            );
            assert_eq!(proxy_protocol_source(&authority), Some(source));
        }
        // No marker (health-check request URLs) -> no header.
        assert_eq!(proxy_protocol_source("127.0.0.1:8080"), None);
        assert_eq!(proxy_protocol_source("not-a-marker.example"), None);
    }

    #[test]
    fn proxy_protocol_headers_match_caddy_address_semantics() {
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(
            proxy_protocol_header(ProxyProtocolVersion::V1, v4),
            b"PROXY TCP4 192.0.2.10 0.0.0.0 0 0\r\n".to_vec()
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            proxy_protocol_header(ProxyProtocolVersion::V1, v6),
            b"PROXY TCP6 2001:db8::1 :: 0 0\r\n".to_vec()
        );

        let v2 = proxy_protocol_header(ProxyProtocolVersion::V2, v4);
        assert_eq!(v2.len(), 28, "16-byte prefix + 12-byte IPv4 block");
        assert_eq!(&v2[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(&v2[12..14], &[0x21, 0x11]);
        assert_eq!(u16::from_be_bytes([v2[14], v2[15]]), 12);
        assert_eq!(&v2[16..20], &[192, 0, 2, 10]);
        assert_eq!(&v2[20..24], &[0, 0, 0, 0]);
        assert_eq!(&v2[24..28], &[0, 0, 0, 0]);

        let v2 = proxy_protocol_header(ProxyProtocolVersion::V2, v6);
        assert_eq!(v2.len(), 52, "16-byte prefix + 36-byte IPv6 block");
        assert_eq!(&v2[12..14], &[0x21, 0x21]);
        assert_eq!(u16::from_be_bytes([v2[14], v2[15]]), 36);
        assert_eq!(
            &v2[16..32],
            &v6.to_string()
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
    }
}
