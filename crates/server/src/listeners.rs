//! Listener binding and accept loops.
//!
//! Each configured listen address gets one accept task. The task reads its router (and the
//! server's limits) from the shared generation map at connection time, so a reload that keeps
//! the same listen address does not need to rebind (no listener gap, no `EADDRINUSE`).
//!
//! TLS listeners (decided by the runtime: server `tls_connection_policies` or the effective HTTPS
//! port) terminate TLS with the rustls configuration prepared by `caddy_rs_tls`; the negotiated
//! ALPN protocol is passed to the request context as the `tls.alpn` variable. Cleartext
//! listeners are unchanged (HTTP/1.1 and h2c).
//!
//! The connection boundary applies the per-server limits from [`crate::limits`]:
//!
//! * `read_timeout`/`write_timeout` wrap the transport in a per-operation I/O timer,
//! * `idle_timeout` closes connections that stay idle between requests (Caddy closes after
//!   5 minutes by default),
//! * `read_header_timeout`, `max_header_bytes` configure hyper's HTTP/1 parser,
//! * `max_connections` caps concurrent connections per listener,
//! * `max_request_body_size` is enforced per request in [`crate::http`].

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
#[cfg(feature = "http3")]
use bytes::{Buf, BytesMut};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(feature = "http3")]
use tokio::net::UdpSocket;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use caddy_rs_admin::access_log::AccessLogContext;
use caddy_rs_admin::{common_name_from_subject, AdminApi, AdminRequest, SharedRequestRecorder};
use caddy_rs_core::{Generation, GenerationStore, ListenAddr, Network};
use caddy_rs_http::{Body, Router};
use caddy_rs_proxy::trusted_proxies::ServerTrustedProxies;

use crate::activation::{adopt_tcp, adopt_unix, InheritedSocket, LocalSocket};
use crate::auto_https::AutomaticHttpsServing;
use crate::error::Error;
use crate::http::{serve_request_with_automatic_upgradable, ServedResponse};
use crate::limits::ServerLimits;
use crate::observability::{
    approximate_request_size, body_len, observe_request, request_host, request_started,
    AccessLogRuntime, PendingObservation, RequestSnapshot, ServerAccessLogPolicy, TlsLogInfo,
};
use crate::proxy_protocol::{ListenerWrappers, PrefixedStream};

/// Router map shared with accept loops, keyed by configured listen address.
///
/// Kept for API compatibility; the runtime now shares [`ListenerState`] instead because a
/// listener also needs its server's limits.
pub type SharedRouters = Arc<RwLock<HashMap<String, Arc<Router>>>>;

/// Per-listener serving state: the router for the configured listen address plus the limits of
/// the HTTP server that owns it.
pub(crate) struct ListenerState {
    pub(crate) router: Arc<Router>,
    pub(crate) limits: Arc<ServerLimits>,
    /// Server-level `trusted_proxies`/`client_ip_headers` policy for this server.
    pub(crate) trusted_proxies: Arc<ServerTrustedProxies>,
    /// TLS configuration when this listener terminates TLS; `None` for cleartext listeners.
    pub(crate) tls: Option<Arc<rustls::ServerConfig>>,
    /// PKCS#11 token pool backing this listener's token-held certificate keys, when any
    /// configured certificate uses one (`apps.tls.certificates.pkcs11`, T-TLS-097). The TLS
    /// branch of `serve_accepted` bounds such handshakes with the pool's budget.
    pub(crate) external_key: Option<Arc<caddy_rs_tls::pkcs11::TokenPool>>,
    /// Whether the listener's client-auth mode verifies client certificates (Caddy
    /// `require_and_verify`/`verify_if_given`); used for `{http.request.tls.client.*}`.
    pub(crate) client_auth_verified: bool,
    /// Whether the QUIC listener accepts 0-RTT early data (Caddy `allow_0rtt`). Caddy's default
    /// when the field is absent is "allowed"; only an explicit `false` disables it.
    ///
    /// Only the QUIC listener reads this, and that code is behind the `http3` feature; in a
    /// TCP-only build the field is carried but inert, so it must not be reported as dead.
    #[cfg_attr(not(feature = "http3"), allow(dead_code))]
    pub(crate) allow_0rtt: bool,
    /// Automatic-HTTPS pre-routing (challenge responses, HTTP→HTTPS redirects) for cleartext
    /// listeners; `None` when automatic HTTPS is not active for this generation.
    pub(crate) automatic: Option<Arc<AutomaticHttpsServing>>,
    /// Name of the configured HTTP server (`apps.http.servers.<name>`), used as the metrics
    /// `server` label and in access-log diagnostics. Empty for the derived challenge listener.
    pub(crate) server_name: String,
    /// Shared request recorder (metrics) — the same handle the admin `/metrics` endpoint renders.
    pub(crate) recorder: SharedRequestRecorder,
    /// Access-log sinks for this generation.
    pub(crate) access_log: Arc<AccessLogRuntime>,
    /// Per-server access-log association (`apps.http.servers.<name>.logs`).
    pub(crate) access_log_policy: Arc<ServerAccessLogPolicy>,
    /// Listener wrappers (PROXY protocol) applied to accepted connections.
    pub(crate) wrappers: Arc<ListenerWrappers>,
    /// Whether this listener may switch HTTP/1.1 to HTTP/2 via the cleartext `Upgrade: h2c`
    /// handshake (Caddy `protocols` includes `h2c`; the default offers no h2c Upgrade).
    pub(crate) h2c_upgrade: bool,
    /// `Alt-Svc` value advertising HTTP/3 on this server's UDP listener, when the server's
    /// `protocols` include `h3` and a UDP listener has a concrete port (Caddy's
    /// `http3.Server.SetQUICHeaders`: `h3=":<port>"; ma=2592000`). `None` when HTTP/3 is not
    /// offered (or the UDP listener port is ephemeral and therefore unknown at plan time).
    pub(crate) alt_svc: Option<String>,
}

/// Listener state shared with accept loops, keyed by configured listen address.
pub(crate) type SharedListeners = Arc<RwLock<HashMap<String, Arc<ListenerState>>>>;

/// Tracks connections accepted by one listener so shutdown can wait for in-flight work.
#[derive(Debug, Default)]
pub(crate) struct ConnectionTracker {
    active: AtomicUsize,
    /// Subset of `active` that are hijacked/upgraded tunnels (WebSocket, extended CONNECT).
    ///
    /// Go's `http.Server.Shutdown` neither closes nor waits for hijacked connections, so Caddy's
    /// grace-period drain only waits for ordinary connections; hijacked tunnels die when the
    /// process exits. caddy-rs keeps them alive through an explicit grace period (the runtime
    /// force-closes them when the grace expires or, without a grace period, as shutdown finishes),
    /// but must not let an eternal grace period wait for them forever.
    upgraded: AtomicUsize,
    notify: tokio::sync::Notify,
}

impl ConnectionTracker {
    /// Register one active connection. The returned guard decrements the count when dropped.
    pub(crate) fn guard(self: &Arc<Self>) -> TrackedConnection {
        self.active.fetch_add(1, Ordering::AcqRel);
        TrackedConnection {
            tracker: Arc::clone(self),
        }
    }

    /// Number of active connections.
    pub(crate) fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Number of active connections that are hijacked/upgraded tunnels.
    pub(crate) fn active_upgraded(&self) -> usize {
        self.upgraded.load(Ordering::Acquire)
    }

    /// Number of active ordinary (non-hijacked) connections.
    pub(crate) fn active_ordinary(&self) -> usize {
        self.active().saturating_sub(self.active_upgraded())
    }

    /// Wait until every ordinary connection has finished.
    ///
    /// Hijacked/upgraded tunnels are excluded, mirroring Go's `http.Server.Shutdown` (which
    /// ignores hijacked connections), so an eternal grace period cannot hang on a WebSocket.
    pub(crate) async fn wait_ordinary_drained(&self) {
        loop {
            if self.active_ordinary() == 0 {
                return;
            }
            let notified = self.notify.notified();
            if self.active_ordinary() == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Wait until no connections are active, or the timeout expires.
    ///
    /// Returns `true` when the tracker drained, `false` when the timeout expired first. `None`
    /// waits indefinitely.
    pub(crate) async fn wait_drained(&self, timeout: Option<Duration>) -> bool {
        let deadline = timeout.map(|timeout| tokio::time::Instant::now() + timeout);
        loop {
            if self.active() == 0 {
                return true;
            }
            let notified = self.notify.notified();
            if self.active() == 0 {
                return true;
            }
            match deadline {
                None => notified.await,
                Some(deadline) => {
                    let now = tokio::time::Instant::now();
                    if now >= deadline {
                        return self.active() == 0;
                    }
                    tokio::select! {
                        _ = notified => {}
                        _ = tokio::time::sleep_until(deadline) => {
                            return self.active() == 0;
                        }
                    }
                }
            }
        }
    }
}

/// Guards one registered active connection; dropped when the connection task ends (or when the
/// last upgraded-tunnel reference is dropped).
pub(crate) struct TrackedConnection {
    tracker: Arc<ConnectionTracker>,
}

impl TrackedConnection {
    /// Mark this connection as an upgraded/hijacked tunnel for the tunnel task's lifetime.
    ///
    /// The ordinary connection count stays unchanged (the tunnel still owns its socket); the
    /// separate upgraded counter lets the shutdown drain exclude hijacked connections.
    pub(crate) fn upgrade_guard(self: &Arc<Self>) -> TrackedUpgrade {
        self.tracker.upgraded.fetch_add(1, Ordering::AcqRel);
        TrackedUpgrade {
            tracker: Arc::clone(&self.tracker),
        }
    }
}

impl Drop for TrackedConnection {
    fn drop(&mut self) {
        self.tracker.active.fetch_sub(1, Ordering::AcqRel);
        self.tracker.notify.notify_waiters();
    }
}

/// Guards the "hijacked/upgraded tunnel" subset of a tracked connection; dropped when the tunnel
/// task ends.
pub(crate) struct TrackedUpgrade {
    tracker: Arc<ConnectionTracker>,
}

impl Drop for TrackedUpgrade {
    fn drop(&mut self) {
        self.tracker.upgraded.fetch_sub(1, Ordering::AcqRel);
        self.tracker.notify.notify_waiters();
    }
}

/// A running listener task.
pub(crate) struct ListenerHandle {
    pub(crate) shutdown: watch::Sender<bool>,
    pub(crate) force: watch::Sender<bool>,
    pub(crate) tracker: Arc<ConnectionTracker>,
    pub(crate) task: JoinHandle<()>,
    pub(crate) bound: String,
    pub(crate) socket_addr: Option<SocketAddr>,
}

impl ListenerHandle {
    /// Stop accepting new connections and ask existing connections to finish gracefully.
    pub(crate) fn begin_graceful(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Drop existing connections immediately (used after the grace period or on a second signal).
    pub(crate) fn begin_force(&self) {
        let _ = self.force.send(true);
    }

    /// The tracker for this listener's connections.
    pub(crate) fn tracker(&self) -> Arc<ConnectionTracker> {
        Arc::clone(&self.tracker)
    }

    /// Number of active connections accepted by this listener.
    pub(crate) fn active_connections(&self) -> usize {
        self.tracker.active()
    }

    /// Gracefully stop the listener (accept loop ends; in-flight connections finish on their own).
    pub(crate) async fn stop(self) {
        self.begin_graceful();
        let _ = self.task.await;
    }

    /// Stop the listener and force-close its connections immediately.
    pub(crate) async fn stop_forcibly(self) {
        self.begin_graceful();
        self.begin_force();
        let _ = self.task.await;
    }
}

/// Bind the listener for a Caddy listen address, or adopt an inherited systemd socket.
///
/// When `inherited` is `Some`, the descriptor passed by systemd is adopted instead of binding a
/// new socket. The caller must only pass a socket whose local address was matched against this
/// configured listener by [`crate::activation::plan_activation`].
pub(crate) async fn bind(
    configured: &str,
    listeners: SharedListeners,
    store: Arc<GenerationStore>,
    inherited: Option<InheritedSocket>,
) -> Result<ListenerHandle, Error> {
    let address = ListenAddr::parse(configured).map_err(|reason| Error::Listen {
        listen: configured.to_string(),
        reason,
    })?;
    match address.network {
        Network::Tcp => {
            let listener = match inherited {
                Some(socket) => {
                    if !matches!(socket.local(), LocalSocket::Tcp(_)) {
                        return Err(Error::SocketActivation {
                            path: format!("LISTEN_FDS[{}]", socket.index()),
                            message: format!(
                                "inherited {} cannot serve configured TCP listener `{configured}`",
                                socket.local()
                            ),
                        });
                    }
                    tracing::info!(
                        listen = configured,
                        fd = socket.fd(),
                        socket = %socket.local(),
                        "adopting inherited systemd TCP socket"
                    );
                    adopt_tcp(socket, configured)?
                }
                None => bind_configured_tcp(configured, &address).await?,
            };
            let socket_addr = listener
                .local_addr()
                .map_err(|error| Error::bind(configured, error))?;
            let (shutdown, receiver) = watch::channel(false);
            let (force, force_receiver) = watch::channel(false);
            let tracker = Arc::new(ConnectionTracker::default());
            let task = spawn_tcp_accept_loop(
                listener,
                configured.to_string(),
                listeners,
                store,
                receiver,
                force_receiver,
                Arc::clone(&tracker),
            );
            Ok(ListenerHandle {
                shutdown,
                force,
                tracker,
                task,
                bound: socket_addr.to_string(),
                socket_addr: Some(socket_addr),
            })
        }
        Network::Unix => {
            let path = address.address.clone();
            let listener = match inherited {
                Some(socket) => {
                    if !matches!(socket.local(), LocalSocket::Unix(_)) {
                        return Err(Error::SocketActivation {
                            path: format!("LISTEN_FDS[{}]", socket.index()),
                            message: format!(
                                "inherited {} cannot serve configured Unix listener `{configured}`",
                                socket.local()
                            ),
                        });
                    }
                    tracing::info!(
                        listen = configured,
                        fd = socket.fd(),
                        socket = %socket.local(),
                        "adopting inherited systemd Unix socket"
                    );
                    adopt_unix(socket, configured)?
                }
                None => {
                    // Only a socket we bind ourselves may have a stale path to remove: an
                    // inherited Unix socket is already bound and must not be unlinked.
                    if std::path::Path::new(&path).exists() {
                        std::fs::remove_file(&path)
                            .map_err(|error| Error::bind(configured, error))?;
                    }
                    UnixListener::bind(&path).map_err(|error| Error::bind(configured, error))?
                }
            };
            let (shutdown, receiver) = watch::channel(false);
            let (force, force_receiver) = watch::channel(false);
            let tracker = Arc::new(ConnectionTracker::default());
            let task = spawn_unix_accept_loop(
                listener,
                configured.to_string(),
                listeners,
                store,
                receiver,
                force_receiver,
                Arc::clone(&tracker),
            );
            Ok(ListenerHandle {
                shutdown,
                force,
                tracker,
                task,
                bound: path,
                socket_addr: None,
            })
        }
        #[cfg(feature = "http3")]
        Network::Udp => {
            if inherited.is_some() {
                return Err(Error::Listen {
                    listen: configured.to_string(),
                    reason: "UDP listeners cannot adopt inherited stream sockets".to_string(),
                });
            }
            let state = listeners
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(configured)
                .cloned()
                .ok_or_else(|| Error::Listen {
                    listen: configured.to_string(),
                    reason: "UDP listener state is missing".to_string(),
                })?;
            let Some(tls) = state.tls.clone() else {
                return Err(Error::Config(caddy_rs_core::Error::invalid(
                    "listen",
                    format!(
                        "UDP listener `{configured}` requires TLS (HTTP/3 is never served cleartext)"
                    ),
                )));
            };
            let socket = bind_configured_udp(configured, &address).await?;
            let socket_addr = socket
                .local_addr()
                .map_err(|error| Error::bind(configured, error))?;
            let std_socket = socket
                .into_std()
                .map_err(|error| Error::bind(configured, error))?;
            let server_config =
                quic_server_config(configured, tls, state.allow_0rtt).map_err(|reason| {
                    Error::Listen {
                        listen: configured.to_string(),
                        reason,
                    }
                })?;
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                std_socket,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|error| Error::bind(configured, error))?;
            let local_addr = endpoint
                .local_addr()
                .map_err(|error| Error::bind(configured, error))?;
            let (shutdown, receiver) = watch::channel(false);
            let (force, force_receiver) = watch::channel(false);
            let tracker = Arc::new(ConnectionTracker::default());
            let task = spawn_udp_accept_loop(
                endpoint,
                configured.to_string(),
                listeners,
                store,
                local_addr,
                receiver,
                force_receiver,
                Arc::clone(&tracker),
            );
            Ok(ListenerHandle {
                shutdown,
                force,
                tracker,
                task,
                bound: socket_addr.to_string(),
                socket_addr: Some(socket_addr),
            })
        }
        #[cfg(not(feature = "http3"))]
        Network::Udp => Err(Error::Listen {
            listen: configured.to_string(),
            reason: "HTTP/3 support is not compiled in; this build cannot serve a UDP listener"
                .to_string(),
        }),
    }
}

/// Bind a TCP listener for a configured Caddy listen address.
///
/// Hostless Caddy addresses (`:443`, `:80`, `:0`) mean "all interfaces, both address families":
/// Go's `net.Listen("tcp", ":port")` creates a dual-stack IPv6 wildcard when the platform
/// supports IPv6. Binding `0.0.0.0` would silently serve IPv4 only, so hostless addresses
/// explicitly request a dual-stack wildcard (ignoring the OS `bindv6only` default; Caddy does the
/// same) and fall back to an IPv4 wildcard only when IPv6 sockets are unavailable.
///
/// Explicit wildcard literals (`0.0.0.0:port`, `[::]:port`) keep their family; IP literals and
/// hostnames behave exactly as Caddy's resolved bind.
async fn bind_configured_tcp(configured: &str, address: &ListenAddr) -> Result<TcpListener, Error> {
    if address.host().is_empty() {
        let port = address.port().ok_or_else(|| Error::Listen {
            listen: configured.to_string(),
            reason: "expected `host:port`; a hostless address needs a numeric port".to_string(),
        })?;
        match wildcard_dual_stack_listener(port) {
            Ok(listener) => return Ok(listener),
            Err(error) if ipv6_wildcard_unavailable(&error) => {
                tracing::debug!(
                    listen = configured,
                    %error,
                    "IPv6 wildcard listener unavailable; binding the IPv4 wildcard"
                );
            }
            Err(error) => return Err(Error::bind(configured, error)),
        }
        let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .map_err(|error| Error::bind(configured, error))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| Error::bind(configured, error))?;
        return TcpListener::from_std(listener).map_err(|error| Error::bind(configured, error));
    }
    match address.socket_addr() {
        // IP literal: bind exactly that address/family.
        Some(socket_addr) => TcpListener::bind(socket_addr)
            .await
            .map_err(|error| Error::bind(configured, error)),
        // Hostname: resolve and bind like Caddy's `net.Listen("tcp", "host:port")`. Bind the
        // address without a `tcp/`/`udp/` network prefix (the prefix is already parsed above).
        None => TcpListener::bind(&address.address)
            .await
            .map_err(|error| Error::bind(configured, error)),
    }
}

/// A dual-stack (`IPv6` wildcard with `IPV6_V6ONLY=0`) listening socket for a hostless address.
fn wildcard_dual_stack_listener(port: u16) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    // Caddy (Go) forces IPV6_V6ONLY=0 for `:port`; do not depend on the host's bindv6only default.
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    // Caddy (Go) uses the system `somaxconn` backlog for `:port` wildcard listeners.
    socket.listen(libc::SOMAXCONN)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Whether a failed wildcard bind means the platform has no usable IPv6 sockets (fall back to
/// IPv4 rather than failing the configuration).
fn ipv6_wildcard_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput
    ) || matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EAFNOSUPPORT || code == libc::EPROTONOSUPPORT
    )
}

/// Bind a UDP socket for a configured Caddy listen address (`udp/...`, HTTP/3).
///
/// Hostless addresses (`udp/:443`) request the dual-stack IPv6 wildcard like Caddy's
/// `net.ListenPacket("udp", ":port")`; IP literals and hostnames bind/resolve like the TCP path.
#[cfg(feature = "http3")]
async fn bind_configured_udp(configured: &str, address: &ListenAddr) -> Result<UdpSocket, Error> {
    if address.host().is_empty() {
        let port = address.port().ok_or_else(|| Error::Listen {
            listen: configured.to_string(),
            reason: "expected `host:port`; a hostless address needs a numeric port".to_string(),
        })?;
        match wildcard_dual_stack_udp(port) {
            Ok(socket) => return Ok(socket),
            Err(error) if ipv6_wildcard_unavailable(&error) => {
                tracing::debug!(
                    listen = configured,
                    %error,
                    "IPv6 wildcard UDP socket unavailable; binding the IPv4 wildcard"
                );
            }
            Err(error) => return Err(Error::bind(configured, error)),
        }
        let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .map_err(|error| Error::bind(configured, error))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| Error::bind(configured, error))?;
        return UdpSocket::from_std(socket).map_err(|error| Error::bind(configured, error));
    }
    match address.socket_addr() {
        Some(socket_addr) => UdpSocket::bind(socket_addr)
            .await
            .map_err(|error| Error::bind(configured, error)),
        None => UdpSocket::bind(&address.address)
            .await
            .map_err(|error| Error::bind(configured, error)),
    }
}

/// A dual-stack (`IPv6` wildcard with `IPV6_V6ONLY=0`) UDP socket for a hostless address.
#[cfg(feature = "http3")]
fn wildcard_dual_stack_udp(port: u16) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Build a QUIC server configuration from the listener's rustls configuration (Caddy's
/// `http3.Server` shares the TLS connection policy but negotiates only `h3` over QUIC).
///
/// `allow_0rtt` mirrors Caddy's `apps.http.servers.*.allow_0rtt`: quinn/rustls accept early data
/// only when the TLS configuration advertises a non-zero `max_early_data_size` (QUIC permits only
/// `u32::MAX`), so an explicit `false` leaves it at zero and the TLS stack rejects 0-RTT. Caddy
/// passes the same flag to `quic-go`'s `ListenEarly`; the default (field absent) is "allowed".
#[cfg(feature = "http3")]
fn quic_server_config(
    configured: &str,
    tls: Arc<rustls::ServerConfig>,
    allow_0rtt: bool,
) -> std::result::Result<quinn::ServerConfig, String> {
    let mut tls = (*tls).clone();
    // QUIC requires TLS 1.3 and the HTTP/3 ALPN token. Caddy's `http3.Server` configures its own
    // TLS config for QUIC, so the TCP listener keeps its h2/http1 ALPN list.
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = if allow_0rtt { u32::MAX } else { 0 };
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|error| {
        format!("listener `{configured}` cannot be used for QUIC: {error} (TLS 1.3 required)")
    })?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Accept QUIC connections on one UDP listener and serve HTTP/3 through the shared routers.
#[cfg(feature = "http3")]
fn spawn_udp_accept_loop(
    endpoint: quinn::Endpoint,
    listen_key: String,
    listeners: SharedListeners,
    store: Arc<GenerationStore>,
    local_addr: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
    tracker: Arc<ConnectionTracker>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                changed = force.changed() => {
                    if changed.is_err() || *force.borrow() {
                        break;
                    }
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let Some((context, permit)) = admit_connection(&listeners, &listen_key, &active) else {
                        tracing::debug!(listen = %listen_key, "QUIC connection refused: max_connections reached");
                        incoming.refuse();
                        continue;
                    };
                    // The generation guard, connection permit and tracker are held by the
                    // connection task for its lifetime.
                    let generation = store.acquire();
                    let Ok(connection) = incoming.await else {
                        drop(permit);
                        continue;
                    };
                    let remote_addr = connection.remote_address();
                    let shutdown = shutdown.clone();
                    let force = force.clone();
                    let tracked = tracker.guard();
                    tokio::spawn(serve_h3_connection(
                        connection,
                        context,
                        permit,
                        generation,
                        remote_addr,
                        local_addr,
                        shutdown,
                        force,
                        tracked,
                    ));
                }
            }
        }
        // Close the endpoint and all its connections (removal/reload); the per-connection tasks
        // observe the closed connections and end, releasing their permits and trackers.
        endpoint.close(0u32.into(), b"listener closed");
        let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    })
}

/// Serve HTTP/3 on one QUIC connection through the same router pipeline as HTTP/1.1/2.
#[cfg(feature = "http3")]
#[allow(clippy::too_many_arguments)]
async fn serve_h3_connection(
    connection: quinn::Connection,
    context: ConnectionContext,
    permit: ConnectionPermit,
    generation: Option<Arc<Generation>>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
    tracked: TrackedConnection,
) {
    let _permit = permit;
    let _generation = generation;
    let _tracked = tracked;
    let tls_info = h3_tls_info(&connection, context.client_auth_verified);
    let mut h3_connection =
        match h3::server::Connection::new(h3_quinn::Connection::new(connection.clone())).await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::debug!(%error, "HTTP/3 connection setup failed");
                connection.close(0u32.into(), b"");
                return;
            }
        };
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    connection.close(0u32.into(), b"");
                    break;
                }
            }
            changed = force.changed() => {
                if changed.is_err() || *force.borrow() {
                    connection.close(0u32.into(), b"");
                    break;
                }
            }
            accepted = h3_connection.accept() => {
                match accepted {
                    Ok(Some(resolver)) => {
                        let (mut request, mut stream) = match resolver.resolve_request().await {
                            Ok(pair) => pair,
                            Err(error) => {
                                tracing::debug!(%error, "HTTP/3 request resolution failed");
                                continue;
                            }
                        };
                        let started = std::time::Instant::now();
                        let method = request.method().as_str().to_string();
                        // Caddy's metrics labels and request-size histogram are computed before
                        // the request is consumed (`modules/caddyhttp/metrics.go:314-368`).
                        let host = request_host(request.headers(), request.uri());
                        let is_https = true;
                        let request_size = approximate_request_size(
                            request.method(),
                            request.version(),
                            request.uri(),
                            request.headers(),
                        );
                        let mut snapshot = context.access_log.is_enabled().then(|| {
                            RequestSnapshot::capture_http3(
                                &request,
                                Some(remote_addr),
                                Some(&tls_info),
                            )
                        });
                        if let Some(snapshot) = snapshot.as_mut() {
                            snapshot.resolve_client_ip(&context.trusted_proxies);
                        }
                        // One shared observation context per request: the access logger and the
                        // metrics recorder both read the handler/error fields the router publishes,
                        // and the access-log half stays a no-op when no sink is active.
                        let access_log_context = Some({
                            let access_log = Arc::new(AccessLogContext::new());
                            access_log.start(started);
                            access_log
                        });
                        let _request_guard = request_started(
                            &context.recorder,
                            &context.server_name,
                            &host,
                            is_https,
                        );
                        // RFC 9114 has no HTTP/1.1-style `Upgrade`, and caddy-rs has no HTTP/3
                        // request-stream tunnel for RFC 8441 extended CONNECT. Reject every
                        // upgrade-style request before routing so a WebSocket/extended-CONNECT
                        // request can never be silently served as an ordinary request. Caddy
                        // v2.11.9: quic-go rejects a plain `Upgrade` header with H3_MESSAGE_ERROR
                        // (no HTTP response) and its reverse_proxy tunnels extended CONNECT; this
                        // build's loud 501 is the documented divergence (DIV-0004).
                        if h3_upgrade_request(&request) {
                            let mut headers = http::HeaderMap::new();
                            headers.insert(
                                http::header::CONTENT_TYPE,
                                http::HeaderValue::from_static("text/plain; charset=utf-8"),
                            );
                            let response = http::Response::builder()
                                .status(http::StatusCode::NOT_IMPLEMENTED)
                                .header(
                                    http::header::CONTENT_TYPE,
                                    "text/plain; charset=utf-8",
                                )
                                .body(())
                                .unwrap_or_else(|_| http::Response::new(()));
                            let _ = stream.send_response(response).await;
                            let body = H3_UPGRADE_UNSUPPORTED_BODY;
                            let _ = stream.send_data(Bytes::from_static(body.as_bytes())).await;
                            let _ = stream.finish().await;
                            observe_request(
                                &context.recorder,
                                &context.access_log,
                                &context.access_log_policy,
                                &context.server_name,
                                &method,
                                snapshot.as_ref(),
                                started,
                                501,
                                body.len() as u64,
                                &headers,
                                // Rejected before the request pipeline exists, so there is no
                                // per-request access-log context and no body write to report.
                                None,
                                None,
                                &host,
                                is_https,
                                request_size,
                                std::time::Instant::now(),
                            );
                            continue;
                        }
                        let limit = context.limits.max_request_body_size;
                        let mut body = BytesMut::new();
                        let mut too_large = false;
                        loop {
                            match stream.recv_data().await {
                                Ok(Some(mut chunk)) => {
                                    let chunk = chunk.copy_to_bytes(chunk.remaining());
                                    if let Some(limit) = limit {
                                        if body.len() as u64 + chunk.len() as u64 > limit {
                                            too_large = true;
                                            break;
                                        }
                                    }
                                    body.extend_from_slice(&chunk);
                                }
                                Ok(None) => break,
                                Err(error) => {
                                    tracing::debug!(%error, "HTTP/3 request body read failed");
                                    break;
                                }
                            }
                        }
                        if let Some(access_log_context) = &access_log_context {
                            // The HTTP/3 path buffers the request body here; report the bytes
                            // actually read from the transport (Caddy's `bytes_read`).
                            access_log_context.request_bytes().set(body.len() as u64);
                        }
                        if too_large {
                            let response = http::Response::builder()
                                .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                                .body(())
                                .unwrap_or_else(|_| http::Response::new(()));
                            let _ = stream.send_response(response).await;
                            let _ = stream
                                .send_data(Bytes::from_static(b"413 Request Entity Too Large"))
                                .await;
                            let _ = stream.finish().await;
                            observe_request(
                                &context.recorder,
                                &context.access_log,
                                &context.access_log_policy,
                                &context.server_name,
                                &method,
                                snapshot.as_ref(),
                                started,
                                413,
                                0,
                                &http::HeaderMap::new(),
                                access_log_context.as_ref(),
                                None,
                                &host,
                                is_https,
                                request_size,
                                std::time::Instant::now(),
                            );
                            continue;
                        }
                        // HTTP/3 carries `:authority` in the request URI; synthesize the Host
                        // header so Caddy host matching/placeholders behave like h1/h2.
                        if !request.headers().contains_key(http::header::HOST) {
                            if let Some(authority) = request.uri().authority() {
                                if let Ok(value) = http::HeaderValue::from_str(authority.as_str()) {
                                    request
                                        .headers_mut()
                                        .insert(http::header::HOST, value);
                                }
                            }
                        }
                        let (mut parts, ()) = request.into_parts();
                        parts.version = http::Version::HTTP_3;
                        let Some(router) = context.router.clone() else {
                            let headers = http::HeaderMap::new();
                            observe_request(
                                &context.recorder,
                                &context.access_log,
                                &context.access_log_policy,
                                &context.server_name,
                                &method,
                                snapshot.as_ref(),
                                started,
                                503,
                                0,
                                &headers,
                                access_log_context.as_ref(),
                                None,
                                &host,
                                is_https,
                                request_size,
                                std::time::Instant::now(),
                            );
                            let response = http::Response::builder()
                                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                                .body(())
                                .unwrap_or_else(|_| http::Response::new(()));
                            let _ = stream.send_response(response).await;
                            let _ = stream.finish().await;
                            continue;
                        };
                        let served = crate::http::serve_internal_buffered(
                            &context.limits,
                            router,
                            parts,
                            body.freeze(),
                            Some(remote_addr),
                            Some(local_addr),
                            true,
                            Some("h3"),
                            Arc::clone(&context.trusted_proxies),
                            h3_client_certificate(&connection, context.client_auth_verified),
                            request_tls_connection(Some(&tls_info)),
                            access_log_context.clone(),
                        )
                        .await;
                        let hyper_response = match served {
                            ServedResponse::Response(response) => response,
                            ServedResponse::Upgraded { response, .. } => response,
                        };
                        let (response_parts, response_body) = hyper_response.into_parts();
                        let mut response_headers = response_parts.headers;
                        // A buffered body has a known length, so keep the Caddy-compatible
                        // `Content-Length`; a streamed body is sent chunk by chunk without one and
                        // is never collected, so a large file does not have to fit in memory.
                        let known_size = response_body.exact_size();
                        if let Some(size) = known_size {
                            if !response_headers.contains_key(http::header::CONTENT_LENGTH)
                                && response_parts.status != http::StatusCode::NO_CONTENT
                                && response_parts.status != http::StatusCode::NOT_MODIFIED
                            {
                                if let Ok(value) = http::HeaderValue::from_str(&size.to_string()) {
                                    response_headers.insert(http::header::CONTENT_LENGTH, value);
                                }
                            }
                        }
                        let mut response = http::Response::builder()
                            .status(response_parts.status)
                            .body(())
                            .unwrap_or_else(|_| http::Response::new(()));
                        for (name, value) in &response_headers {
                            response.headers_mut().append(name.clone(), value.clone());
                        }
                        if let Err(error) = stream.send_response(response).await {
                            tracing::debug!(%error, "HTTP/3 response headers failed");
                            continue;
                        }
                        // Caddy's `response_duration_seconds` is time to response headers.
                        let response_started = std::time::Instant::now();
                        let mut body = std::pin::pin!(response_body);
                        let mut sent = 0_u64;
                        let mut failed = false;
                        while let Some(frame) = body.frame().await {
                            let Ok(frame) = frame else {
                                failed = true;
                                break;
                            };
                            let Ok(data) = frame.into_data() else {
                                continue;
                            };
                            sent += data.len() as u64;
                            if method == "HEAD" || data.is_empty() {
                                continue;
                            }
                            if let Err(error) = stream.send_data(data).await {
                                tracing::debug!(%error, "HTTP/3 response body failed");
                                failed = true;
                                break;
                            }
                        }
                        let _ = stream.finish().await;
                        let write_error = failed
                            .then(|| format!("response body write failed after {sent} bytes"));
                        observe_request(
                            &context.recorder,
                            &context.access_log,
                            &context.access_log_policy,
                            &context.server_name,
                            &method,
                            snapshot.as_ref(),
                            started,
                            response_parts.status.as_u16(),
                            sent,
                            &response_headers,
                            access_log_context.as_ref(),
                            write_error.as_deref(),
                            &host,
                            is_https,
                            request_size,
                            response_started,
                        );
                        if failed {
                            continue;
                        }
                        continue;
                    }
                    Ok(None) => break,
                    Err(error) => {
                        tracing::debug!(%error, "HTTP/3 connection closed");
                        break;
                    }
                }
            }
        }
    }
}

/// Body returned for an HTTP/3 protocol-upgrade attempt.
///
/// Shared with the buffered router path so a handler that reports an upgrade (for example a
/// `reverse_proxy` upstream switching protocols) produces exactly the same response.
#[cfg(feature = "http3")]
pub(crate) const H3_UPGRADE_UNSUPPORTED_BODY: &str =
    "501 Not Implemented: protocol upgrades are not supported over HTTP/3";

/// Whether an HTTP/3 request asks for a protocol upgrade this build cannot serve.
///
/// HTTP/3 (RFC 9114) has no HTTP/1.1 `Upgrade` mechanism: a request that carries `Upgrade` is a
/// WebSocket/other-upgrade attempt that quic-go would reject as malformed. RFC 8441 extended
/// CONNECT is a `CONNECT` request with a `:protocol` pseudo-header, which `h3` surfaces as an
/// extension. caddy-rs buffers HTTP/3 requests and has no request-stream tunnel, so both forms are
/// rejected loudly instead of being handed to the router as ordinary requests. A plain `CONNECT`
/// without `:protocol` is not an upgrade and keeps the existing routing behaviour.
#[cfg(feature = "http3")]
fn h3_upgrade_request(request: &http::Request<()>) -> bool {
    request.headers().contains_key(http::header::UPGRADE)
        || request.extensions().get::<h3::ext::Protocol>().is_some()
}

/// Map the first presented client certificate to Caddy's HTTP placeholder representation.
///
/// `verified` comes from the listener's client-auth mode: Caddy's `require_and_verify` and
/// `verify_if_given` verify the chain; `require`/`request` only require/request a certificate.
fn client_certificate_for_request(
    connection: &rustls::ServerConnection,
    verified: bool,
) -> Option<caddy_rs_http::ClientCertificate> {
    let der = connection.peer_certificates()?.first()?;
    client_certificate_from_der(der.as_ref(), verified)
}

/// Build the placeholder representation from a DER-encoded leaf certificate.
///
/// Shared by the TCP and QUIC paths: rustls exposes the chain for a TCP listener and quinn's
/// `peer_identity` exposes it for a QUIC connection; both end up here.
fn client_certificate_from_der(
    der: &[u8],
    verified: bool,
) -> Option<caddy_rs_http::ClientCertificate> {
    let info = caddy_rs_tls::ClientCertificateInfo::parse(der, verified).ok()?;
    let certificate_pem = info.certificate_pem();
    let certificate_der_base64 = info.certificate_der_base64();
    Some(caddy_rs_http::ClientCertificate {
        subject: info.subject,
        issuer: info.issuer,
        serial: info.serial,
        fingerprint: info.fingerprint,
        public_key_der: info.public_key_der,
        public_key_sha256: info.public_key_sha256,
        certificate_pem,
        certificate_der_base64,
        dns_names: info.dns_names,
        emails: info.emails,
        ips: info.ip_addresses,
        uris: info.uris,
        verified: info.verified,
    })
}

/// Client certificate presented on an HTTP/3 connection.
///
/// quinn exposes the verified peer chain through `peer_identity` as rustls `CertificateDer`
/// values, so HTTP/3 client authentication reaches the same placeholders as a TCP listener
/// (Caddy reads the certificate from TLS state regardless of transport).
#[cfg(feature = "http3")]
fn h3_client_certificate(
    connection: &quinn::Connection,
    verified: bool,
) -> Option<caddy_rs_http::ClientCertificate> {
    let identity = connection.peer_identity()?;
    let chain = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    client_certificate_from_der(chain.first()?.as_ref(), verified)
}

/// Best-effort TLS metadata for access logs on an HTTP/3 connection.
///
/// quinn exposes the rustls handshake data (ALPN, SNI, resumption) but not the negotiated cipher
/// suite; HTTP/3 is always TLS 1.3. See the compatibility divergence note.
#[cfg(feature = "http3")]
fn h3_tls_info(connection: &quinn::Connection, client_auth_verified: bool) -> TlsLogInfo {
    let handshake = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok());
    let (server_name, proto) = match handshake {
        Some(data) => (
            data.server_name.clone().unwrap_or_default(),
            data.protocol
                .as_ref()
                .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
                .unwrap_or_else(|| "h3".to_string()),
        ),
        None => (String::new(), "h3".to_string()),
    };
    // Caddy logs the presented leaf certificate's common name and serial for every TLS request
    // with `PeerCertificates` (`modules/caddyhttp/marshalers.go:81-84`).
    let client_certificate = h3_client_certificate(connection, client_auth_verified);
    let client_common_name = client_certificate
        .as_ref()
        .and_then(|certificate| caddy_rs_admin::common_name_from_subject(&certificate.subject));
    let client_serial = client_certificate
        .as_ref()
        .map(|certificate| certificate.serial.clone());
    TlsLogInfo {
        // quinn-proto's rustls HandshakeData does not expose the resumption flag; HTTP/3 access
        // log TLS metadata is therefore approximate (DIV note).
        resumed: false,
        version: u16::from(rustls::ProtocolVersion::TLSv1_3),
        cipher_suite: 0,
        proto,
        server_name,
        ech: false,
        client_common_name,
        client_serial,
    }
}

/// Typed TLS session metadata for the internal request (Caddy's `r.TLS` version/cipher fields).
fn request_tls_connection(tls_info: Option<&TlsLogInfo>) -> Option<caddy_rs_http::TlsConnection> {
    let info = tls_info?;
    caddy_rs_http::TlsConnection::from_iana(info.version, info.cipher_suite)
}

/// State captured for one accepted connection.
#[derive(Clone)]
struct ConnectionContext {
    /// Router to serve, or `None` while the listener is being retired (responds 503).
    router: Option<Arc<Router>>,
    limits: Arc<ServerLimits>,
    /// Server-level trusted-proxy policy (empty/default when not configured).
    trusted_proxies: Arc<ServerTrustedProxies>,
    /// TLS configuration for this accepted connection, when the listener terminates TLS.
    tls: Option<Arc<rustls::ServerConfig>>,
    /// Token pool backing this listener's token-held certificate keys, if any.
    external_key: Option<Arc<caddy_rs_tls::pkcs11::TokenPool>>,
    /// Whether the listener's client-auth mode verifies client certificates.
    client_auth_verified: bool,
    /// Automatic-HTTPS pre-routing for cleartext connections.
    automatic: Option<Arc<AutomaticHttpsServing>>,
    /// Configured HTTP server name for metrics/access-log labels.
    server_name: String,
    /// Shared metrics recorder.
    recorder: SharedRequestRecorder,
    /// Access-log sinks for the connection's generation.
    access_log: Arc<AccessLogRuntime>,
    /// Per-server access-log association.
    access_log_policy: Arc<ServerAccessLogPolicy>,
    /// Listener wrappers for accepted connections.
    wrappers: Arc<ListenerWrappers>,
    /// Whether cleartext h2c Upgrade is enabled for this listener (`protocols` includes h2c).
    h2c_upgrade: bool,
    /// `Alt-Svc` value advertising HTTP/3 on the h1/h2 response for this listener.
    alt_svc: Option<String>,
}

/// Look up the state of an accepted connection and acquire a connection slot.
///
/// Returns `None` when the listener's `max_connections` cap is reached; the caller closes the
/// accepted stream immediately.
fn admit_connection(
    listeners: &SharedListeners,
    listen_key: &str,
    active: &Arc<AtomicUsize>,
) -> Option<(ConnectionContext, ConnectionPermit)> {
    let state = listeners
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(listen_key)
        .cloned();
    let context = match state {
        Some(state) => ConnectionContext {
            router: Some(Arc::clone(&state.router)),
            limits: Arc::clone(&state.limits),
            trusted_proxies: Arc::clone(&state.trusted_proxies),
            tls: state.tls.clone(),
            external_key: state.external_key.clone(),
            client_auth_verified: state.client_auth_verified,
            automatic: state.automatic.clone(),
            server_name: state.server_name.clone(),
            recorder: Arc::clone(&state.recorder),
            access_log: Arc::clone(&state.access_log),
            access_log_policy: Arc::clone(&state.access_log_policy),
            wrappers: Arc::clone(&state.wrappers),
            h2c_upgrade: state.h2c_upgrade,
            alt_svc: state.alt_svc.clone(),
        },
        None => ConnectionContext {
            router: None,
            limits: Arc::new(ServerLimits::default()),
            trusted_proxies: Arc::new(ServerTrustedProxies::default()),
            tls: None,
            external_key: None,
            client_auth_verified: false,
            automatic: None,
            server_name: String::new(),
            recorder: caddy_rs_admin::noop_recorder(),
            access_log: AccessLogRuntime::disabled(),
            access_log_policy: Arc::new(ServerAccessLogPolicy::default()),
            wrappers: Arc::new(ListenerWrappers::default()),
            h2c_upgrade: false,
            alt_svc: None,
        },
    };
    let permit = ConnectionPermit::try_acquire(Arc::clone(active), context.limits.max_connections)?;
    Some((context, permit))
}

/// RAII permit for one concurrent connection slot.
struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn try_acquire(active: Arc<AtomicUsize>, limit: Option<usize>) -> Option<Self> {
        if let Some(limit) = limit {
            let mut current = active.load(Ordering::Relaxed);
            loop {
                if current >= limit {
                    return None;
                }
                match active.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
        } else {
            active.fetch_add(1, Ordering::Relaxed);
        }
        Some(Self { active })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn spawn_tcp_accept_loop(
    listener: TcpListener,
    listen_key: String,
    listeners: SharedListeners,
    store: Arc<GenerationStore>,
    mut shutdown: watch::Receiver<bool>,
    force: watch::Receiver<bool>,
    tracker: Arc<ConnectionTracker>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { continue };
                    let Some((context, permit)) = admit_connection(&listeners, &listen_key, &active) else {
                        tracing::debug!(listen = %listen_key, "connection refused: max_connections reached");
                        drop(stream);
                        continue;
                    };
                    let generation = store.acquire();
                    let connection_shutdown = shutdown.clone();
                    let connection_force = force.clone();
                    let tracked = tracker.guard();
                    let local = stream.local_addr().ok();
                    tokio::spawn(serve_wrapped(
                        stream,
                        Some(peer),
                        local,
                        context,
                        permit,
                        generation,
                        connection_shutdown,
                        connection_force,
                        tracked,
                    ));
                }
            }
        }
    })
}

fn spawn_unix_accept_loop(
    listener: UnixListener,
    listen_key: String,
    listeners: SharedListeners,
    store: Arc<GenerationStore>,
    mut shutdown: watch::Receiver<bool>,
    force: watch::Receiver<bool>,
    tracker: Arc<ConnectionTracker>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((stream, _peer)) = accepted else { continue };
                    let Some((context, permit)) = admit_connection(&listeners, &listen_key, &active) else {
                        tracing::debug!(listen = %listen_key, "connection refused: max_connections reached");
                        drop(stream);
                        continue;
                    };
                    let generation = store.acquire();
                    let connection_shutdown = shutdown.clone();
                    let connection_force = force.clone();
                    let tracked = tracker.guard();
                    tokio::spawn(serve_wrapped(
                        stream,
                        None,
                        None,
                        context,
                        permit,
                        generation,
                        connection_shutdown,
                        connection_force,
                        tracked,
                    ));
                }
            }
        }
    })
}

/// Apply the configured listener wrappers (PROXY protocol) to an accepted connection, then serve.
///
/// The wrapper reads the PROXY header from the transport *before* TLS termination and replaces the
/// remote/local addresses for the rest of the connection.
#[allow(clippy::too_many_arguments)]
async fn serve_wrapped<I>(
    stream: I,
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    context: ConnectionContext,
    permit: ConnectionPermit,
    generation: Option<Arc<Generation>>,
    shutdown: watch::Receiver<bool>,
    force: watch::Receiver<bool>,
    tracked: TrackedConnection,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (stream, remote_override, local_override, proxy_vars) = match context
        .wrappers
        .proxy_protocol()
    {
        Some(settings) => match crate::proxy_protocol::wrap(stream, peer, local, settings).await {
            Ok(wrapped) => wrapped,
            Err(error) => {
                tracing::warn!(
                    peer = ?peer,
                    %error,
                    "rejecting connection: PROXY protocol wrapper failed"
                );
                return;
            }
        },
        None => (
            PrefixedStream::new(stream, Vec::new()),
            None,
            None,
            Vec::new(),
        ),
    };
    serve_accepted(
        stream,
        remote_override.or(peer),
        local_override.or(local),
        Arc::new(proxy_vars),
        context,
        permit,
        generation,
        shutdown,
        force,
        tracked,
    )
    .await;
}

/// Terminate TLS when the listener is a TLS listener, then serve the connection.
#[allow(clippy::too_many_arguments)]
async fn serve_accepted<I>(
    stream: I,
    peer: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    proxy_vars: Arc<Vec<(String, String)>>,
    context: ConnectionContext,
    permit: ConnectionPermit,
    generation: Option<Arc<Generation>>,
    shutdown: watch::Receiver<bool>,
    force: watch::Receiver<bool>,
    tracked: TrackedConnection,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The permit and generation guard are held by the connection service so an HTTP Upgrade tunnel
    // can take ownership of them once the connection is handed off. For normal connections the
    // service is dropped when the connection ends, releasing both.
    let permit = Arc::new(permit);
    let generation = generation;
    // One tracked-connection guard per accepted connection; cloned into the upgrade tunnel when
    // the socket is handed off, so it survives until the tunnel ends.
    let tracked = Arc::new(tracked);
    let limits = Arc::clone(&context.limits);
    let trusted_proxies = Arc::clone(&context.trusted_proxies);
    let activity = Arc::new(ConnectionActivity::default());
    let router = context.router;
    let automatic = context.automatic;
    let external_key = context.external_key;
    let server_name = context.server_name;
    let recorder = context.recorder;
    let access_log = context.access_log;
    let access_log_policy = context.access_log_policy;
    if let Some(tls) = context.tls {
        let acceptor = TlsAcceptor::from(tls);
        let tls_stream = match external_key {
            // A token-held key signs inside the PKCS#11 token: hold a token handshake permit and
            // bound the whole handshake by the token budget (T-TLS-097).
            Some(pool) => {
                match caddy_rs_tls::tls_server::accept_external_key_handshake(
                    acceptor, stream, pool,
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        // Budget exhaustion and token failures are per-connection errors: log at
                        // debug and drop the connection, like the handshake failure below.
                        tracing::debug!(%error, "TLS handshake failed");
                        return;
                    }
                }
            }
            None => match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    // TLS handshake failures are client-side errors (wrong SNI, protocol
                    // mismatch); log at debug and drop the connection like Caddy does.
                    tracing::debug!(%error, "TLS handshake failed");
                    return;
                }
            },
        };
        let connection = tls_stream.get_ref().1;
        let alpn = connection
            .alpn_protocol()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
        let client_certificate =
            client_certificate_for_request(connection, context.client_auth_verified);
        let tls_info = TlsLogInfo {
            resumed: matches!(
                connection.handshake_kind(),
                Some(rustls::HandshakeKind::Resumed)
            ),
            version: connection.protocol_version().map(u16::from).unwrap_or(0),
            cipher_suite: connection
                .negotiated_cipher_suite()
                .map(|suite| u16::from(suite.suite()))
                .unwrap_or(0),
            proto: alpn.clone().unwrap_or_default(),
            server_name: connection.server_name().unwrap_or("").to_string(),
            ech: false,
            // Caddy's `request.tls.client_common_name`/`client_serial`
            // (`modules/caddyhttp/marshalers.go:81-84`).
            client_common_name: client_certificate
                .as_ref()
                .and_then(|certificate| common_name_from_subject(&certificate.subject)),
            client_serial: client_certificate
                .as_ref()
                .map(|certificate| certificate.serial.clone()),
        };
        let service = connection_service(
            router,
            Arc::clone(&limits),
            Arc::clone(&trusted_proxies),
            Arc::clone(&proxy_vars),
            peer,
            local_addr,
            true,
            alpn,
            Some(tls_info),
            server_name,
            recorder,
            access_log,
            access_log_policy,
            automatic,
            Arc::clone(&activity),
            Arc::clone(&permit),
            generation.clone(),
            force.clone(),
            Arc::clone(&tracked),
            false,
            context.alt_svc.clone(),
            client_certificate,
        );
        serve_connection(tls_stream, service, shutdown, force, limits, activity).await;
    } else {
        let service = connection_service(
            router,
            Arc::clone(&limits),
            Arc::clone(&trusted_proxies),
            Arc::clone(&proxy_vars),
            peer,
            local_addr,
            false,
            None,
            None,
            server_name,
            recorder,
            access_log,
            access_log_policy,
            automatic,
            Arc::clone(&activity),
            Arc::clone(&permit),
            generation.clone(),
            force.clone(),
            Arc::clone(&tracked),
            context.h2c_upgrade,
            context.alt_svc.clone(),
            None,
        );
        serve_connection(stream, service, shutdown, force, limits, activity).await;
    }
}

/// Everything the per-request service needs, cloned for the h2c upgrade service.
#[derive(Clone)]
struct RequestContext {
    router: Option<Arc<Router>>,
    limits: Arc<ServerLimits>,
    trusted_proxies: Arc<ServerTrustedProxies>,
    /// PROXY-protocol TLV/Unix variables (empty when no wrapper/header).
    proxy_vars: Arc<Vec<(String, String)>>,
    remote_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    tls: bool,
    alpn: Option<String>,
    tls_info: Option<TlsLogInfo>,
    /// Presented client certificate mapped to the HTTP placeholder representation.
    client_certificate: Option<caddy_rs_http::ClientCertificate>,
    server_name: String,
    recorder: SharedRequestRecorder,
    access_log: Arc<AccessLogRuntime>,
    access_log_policy: Arc<ServerAccessLogPolicy>,
    automatic: Option<Arc<AutomaticHttpsServing>>,
    activity: Arc<ConnectionActivity>,
    permit: Arc<ConnectionPermit>,
    generation: Option<Arc<Generation>>,
    force: watch::Receiver<bool>,
    tracked: Arc<TrackedConnection>,
    /// Cleartext h2c Upgrade enabled (`protocols` includes h2c).
    h2c_upgrade: bool,
    /// `Alt-Svc` value advertising HTTP/3 on h1/h2 responses.
    alt_svc: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn connection_service(
    router: Option<Arc<Router>>,
    limits: Arc<ServerLimits>,
    trusted_proxies: Arc<ServerTrustedProxies>,
    proxy_vars: Arc<Vec<(String, String)>>,
    remote_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    tls: bool,
    alpn: Option<String>,
    tls_info: Option<TlsLogInfo>,
    server_name: String,
    recorder: SharedRequestRecorder,
    access_log: Arc<AccessLogRuntime>,
    access_log_policy: Arc<ServerAccessLogPolicy>,
    automatic: Option<Arc<AutomaticHttpsServing>>,
    activity: Arc<ConnectionActivity>,
    permit: Arc<ConnectionPermit>,
    generation: Option<Arc<Generation>>,
    force: watch::Receiver<bool>,
    tracked: Arc<TrackedConnection>,
    h2c_upgrade: bool,
    alt_svc: Option<String>,
    client_certificate: Option<caddy_rs_http::ClientCertificate>,
) -> impl hyper::service::Service<
    hyper::Request<Incoming>,
    Response = hyper::Response<Body>,
    Error = std::convert::Infallible,
    Future: Send,
> + Send
       + 'static {
    request_service(RequestContext {
        router,
        limits,
        trusted_proxies,
        proxy_vars,
        remote_addr,
        local_addr,
        tls,
        alpn,
        tls_info,
        client_certificate,
        server_name,
        recorder,
        access_log,
        access_log_policy,
        automatic,
        activity,
        permit,
        generation,
        force,
        tracked,
        h2c_upgrade,
        alt_svc,
    })
}

fn request_service(
    context: RequestContext,
) -> impl hyper::service::Service<
    hyper::Request<Incoming>,
    Response = hyper::Response<Body>,
    Error = std::convert::Infallible,
    Future: Send,
> + Send
       + 'static {
    service_fn(move |request: hyper::Request<Incoming>| {
        let context = context.clone();
        async move { serve_one_request(context, request).await }
    })
}

/// Serve one hyper request (also used for requests arriving on an h2c-upgraded connection).
async fn serve_one_request(
    context: RequestContext,
    mut request: hyper::Request<Incoming>,
) -> Result<hyper::Response<Body>, std::convert::Infallible> {
    let _in_flight = context.activity.begin();
    let started = std::time::Instant::now();
    let method = request.method().as_str().to_string();
    // Caddy computes the metrics labels and the approximate request size before the handler chain
    // consumes the request (`modules/caddyhttp/metrics.go:314-368`).
    let host = request_host(request.headers(), request.uri());
    let is_https = context.tls;
    let request_size = approximate_request_size(
        request.method(),
        request.version(),
        request.uri(),
        request.headers(),
    );
    // Capture the access-log fields before the request is consumed. Only done when a sink is
    // configured, so the common no-logging path pays nothing.
    let mut snapshot = context.access_log.is_enabled().then(|| {
        RequestSnapshot::capture(&request, context.remote_addr, context.tls_info.as_ref())
    });
    if let Some(snapshot) = snapshot.as_mut() {
        snapshot.resolve_client_ip(&context.trusted_proxies);
    }
    // One shared observation context per request: the access logger and the metrics recorder both
    // read the handler/error fields the router publishes, and the access-log half stays inert when
    // no sink is active.
    let access_log_context = Some({
        let access_log = Arc::new(AccessLogContext::new());
        access_log.start(started);
        access_log
    });
    let _request_guard = request_started(&context.recorder, &context.server_name, &host, is_https);
    // Decide once, before the request is consumed, whether this is a real WebSocket handshake
    // offer. The response side (Sec-WebSocket-Accept) is checked when the 101 is returned; only a
    // complete handshake gets close-frame synthesis.
    let websocket_request = caddy_rs_proxy::websocket::request_is_websocket(request.headers());

    let Some(router) = context.router.clone() else {
        let response = with_alt_svc(error_response(), context.alt_svc.as_ref());
        observe_request(
            &context.recorder,
            &context.access_log,
            &context.access_log_policy,
            &context.server_name,
            &method,
            snapshot.as_ref(),
            started,
            503,
            body_len(response.body()),
            response.headers(),
            access_log_context.as_ref(),
            None,
            &host,
            is_https,
            request_size,
            std::time::Instant::now(),
        );
        return Ok(response);
    };

    // Cleartext HTTP/2 upgrade (RFC 7540 §3.2): answer with 101 + Upgrade headers and serve
    // hyper's HTTP/2 connection on the upgraded stream. Only HTTP/1.1, non-TLS, bodyless requests
    // are eligible; prior-knowledge h2c is handled by the auto connection builder already.
    if !context.tls && context.h2c_upgrade && h2c_upgrade_allowed(&request) {
        let on_upgrade = hyper::upgrade::on(&mut request);
        let h2c_service = request_service(context.clone());
        let mut force = context.force.clone();
        let permit = Arc::clone(&context.permit);
        let generation = context.generation.clone();
        let tracked = Arc::clone(&context.tracked);
        spawn_h2c_connection(
            on_upgrade,
            h2c_service,
            &mut force,
            Arc::clone(&context.limits),
            permit,
            generation,
            tracked,
        );
        let mut response = hyper::Response::builder()
            .status(http::StatusCode::SWITCHING_PROTOCOLS)
            .body(Body::empty())
            .unwrap_or_else(|error| {
                tracing::error!(%error, "cannot build h2c upgrade response");
                error_response()
            });
        *response.headers_mut() = caddy_rs_http::h2c_upgrade_headers();
        let response = with_alt_svc(response, context.alt_svc.as_ref());
        observe_request(
            &context.recorder,
            &context.access_log,
            &context.access_log_policy,
            &context.server_name,
            &method,
            snapshot.as_ref(),
            started,
            101,
            body_len(response.body()),
            response.headers(),
            access_log_context.as_ref(),
            None,
            &host,
            is_https,
            request_size,
            std::time::Instant::now(),
        );
        return Ok(response);
    }

    // Take the client-side upgrade future before the request is consumed. HTTP/1.1 upgrades use
    // `Upgrade`/`Connection`; HTTP/2 extended CONNECT (RFC 8441) is a `CONNECT` stream whose
    // duplex stream hyper fulfils through the same `OnUpgrade` mechanism after a 2xx response.
    let wants_upgrade = caddy_rs_http::requested_upgrade_type(request.headers()).is_some()
        || (request.version() == http::Version::HTTP_2
            && request.method() == http::Method::CONNECT);
    let on_upgrade = wants_upgrade.then(|| hyper::upgrade::on(&mut request));
    let served = serve_request_with_automatic_upgradable(
        &context.limits,
        router,
        request,
        context.remote_addr,
        context.local_addr,
        context.tls,
        context.alpn.as_deref(),
        context.automatic.clone(),
        on_upgrade,
        Arc::clone(&context.trusted_proxies),
        context.client_certificate.clone(),
        request_tls_connection(context.tls_info.as_ref()),
        &context.proxy_vars,
        access_log_context.clone(),
    )
    .await;

    // Caddy advertises HTTP/3 on HTTP/1.1 and HTTP/2 responses (`http3.Server.SetQUICHeaders`)
    // only when the server offers HTTP/3; h3 responses never advertise Alt-Svc themselves.
    let mut served = served;
    if let Some(alt_svc) = &context.alt_svc {
        if let Ok(value) = http::HeaderValue::from_str(alt_svc) {
            match &mut served {
                ServedResponse::Response(response) => {
                    response.headers_mut().insert(http::header::ALT_SVC, value);
                }
                ServedResponse::Upgraded { response, .. } => {
                    response.headers_mut().insert(http::header::ALT_SVC, value);
                }
            }
        }
    }
    let (status, response_headers) = match &served {
        ServedResponse::Response(response) => {
            (response.status().as_u16(), response.headers().clone())
        }
        ServedResponse::Upgraded { response, .. } => {
            (response.status().as_u16(), response.headers().clone())
        }
    };
    let observation = PendingObservation::new(
        &context.recorder,
        &context.access_log,
        &context.access_log_policy,
        &context.server_name,
        &method,
        snapshot,
        started,
        status,
        response_headers,
        access_log_context,
        &host,
        is_https,
        request_size,
        std::time::Instant::now(),
    );

    match served {
        ServedResponse::Response(mut response) => {
            // Defer the access entry (and the finished-request metrics) to body completion: hyper
            // owns the body after this return, and Caddy's `duration`/`size` describe the last
            // byte, not the headers.
            let body = std::mem::replace(response.body_mut(), Body::empty());
            *response.body_mut() = body.observe(Arc::new(observation));
            Ok::<_, std::convert::Infallible>(response)
        }
        ServedResponse::Upgraded {
            response,
            tunnel,
            on_upgrade,
            extended_connect,
        } => {
            // A protocol switch has no response body: the access entry is rendered here (Caddy
            // renders an upgraded request when the handler returns, not when the tunnel closes).
            observation.finish_now(0, None);
            // An h2 extended CONNECT is a WebSocket-over-HTTP/2 tunnel even though the original
            // request has no `Upgrade` header: treat it as a WebSocket connection so the existing
            // close-frame handshake applies to the h2 stream too.
            let websocket = extended_connect
                || (websocket_request
                    && caddy_rs_proxy::websocket::response_negotiated_websocket(
                        response.headers(),
                    ));
            spawn_upgraded_tunnel(
                on_upgrade,
                tunnel,
                context.force.clone(),
                websocket,
                context.permit,
                context.generation,
                context.tracked,
            );
            Ok::<_, std::convert::Infallible>(response)
        }
    }
}

/// Whether an HTTP/1.1 request is an eligible h2c Upgrade offer.
///
/// RFC 7540 §3.2.1 requires the upgrade request to have no body and a valid `HTTP2-Settings`
/// header; a request with a non-zero declared length, a transfer-encoding, or a missing or
/// unparseable `HTTP2-Settings` is served as a normal HTTP/1.1 request instead (the server MUST
/// ignore the `Upgrade: h2c` offer in that case).
fn h2c_upgrade_allowed(request: &hyper::Request<Incoming>) -> bool {
    if request.version() != http::Version::HTTP_11
        || !caddy_rs_http::is_h2c_upgrade(request.headers())
        || caddy_rs_http::h2c_upgrade_settings(request.headers()).is_err()
    {
        return false;
    }
    if request
        .headers()
        .contains_key(http::header::TRANSFER_ENCODING)
    {
        return false;
    }
    match request.headers().get(http::header::CONTENT_LENGTH) {
        None => true,
        Some(value) => {
            value
                .to_str()
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                == Some(0)
        }
    }
}

/// Serve hyper HTTP/2 on the client stream of a completed h2c Upgrade.
fn spawn_h2c_connection<S>(
    on_upgrade: hyper::upgrade::OnUpgrade,
    service: S,
    force: &mut watch::Receiver<bool>,
    limits: Arc<ServerLimits>,
    permit: Arc<ConnectionPermit>,
    generation: Option<Arc<Generation>>,
    tracked: Arc<TrackedConnection>,
) where
    S: hyper::service::Service<
            hyper::Request<Incoming>,
            Response = hyper::Response<Body>,
            Error = std::convert::Infallible,
        > + Send
        + 'static,
    S::Future: Send + 'static,
{
    let mut force = force.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let _generation = generation;
        let _tracked = tracked;
        if *force.borrow() {
            return;
        }
        let upgraded = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(error) => {
                tracing::debug!(%error, "client h2c upgrade did not complete");
                return;
            }
        };
        let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        // An h2c-upgraded connection is an HTTP/2 server connection too: apply the same
        // Caddy/Go-compatible SETTINGS as the prior-knowledge h2 path.
        configure_h2_raw_server(&mut builder, &limits);
        // `hyper::upgrade::Upgraded` already implements hyper's IO traits; only the tokio
        // copy path needs the `TokioIo` adapter.
        let connection = builder.serve_connection(upgraded, service);
        tokio::pin!(connection);
        tokio::select! {
            result = connection.as_mut() => {
                if let Err(error) = result {
                    tracing::debug!(%error, "h2c connection ended with error");
                }
            }
            _ = force.changed() => {
                tracing::debug!("closing h2c connection on forced shutdown");
                connection.as_mut().graceful_shutdown();
                let _ = tokio::time::timeout(Duration::from_secs(1), connection.as_mut()).await;
            }
        }
    });
}

/// Tunnel an upgraded client connection to the upgraded upstream connection.
///
/// The task owns the connection permit and the generation guard for the lifetime of the tunnel, so
/// connection limits and generation draining stay correct after hyper hands the socket off. A
/// shutdown signal, EOF from either side, or a copy error ends the task and drops both streams,
/// which closes the corresponding sockets.
#[allow(clippy::too_many_arguments)]
fn spawn_upgraded_tunnel(
    on_upgrade: hyper::upgrade::OnUpgrade,
    tunnel: caddy_rs_http::Tunnel,
    force: watch::Receiver<bool>,
    websocket: bool,
    permit: Arc<ConnectionPermit>,
    generation: Option<Arc<Generation>>,
    tracked: Arc<TrackedConnection>,
) {
    tokio::spawn(async move {
        let _permit = permit;
        let _generation = generation;
        let _upgraded = tracked.upgrade_guard();
        let _tracked = tracked;
        if *force.borrow() {
            return;
        }
        let client = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(error) => {
                tracing::debug!(%error, "client upgrade did not complete");
                return;
            }
        };
        // `TokioIo` adapts hyper's upgraded I/O to tokio's AsyncRead/AsyncWrite traits. The proxy
        // crate owns the tunnel pump so WebSocket peers see a close control frame instead of an
        // abnormal 1006: 1000 (normal) on upstream EOF, 1001 (going away) when the connection is
        // actually closed (graceful-shutdown grace expiry or a forced shutdown).
        let client = TokioIo::new(client);
        let upstream = tunnel.into_inner();
        // Only the forced/immediate close cancels the pump. Graceful shutdown leaves upgraded
        // tunnels alive through the grace period (Caddy's hijacked connections are closed by
        // `cleanupConnections` at close time); the runtime's grace-expiry force-all signal is what
        // ends them, and the pump writes the going-away frame at that point.
        let result = caddy_rs_proxy::websocket::tunnel(client, upstream, websocket, force).await;
        match result {
            Ok(()) => tracing::debug!("upgraded connection closed"),
            Err(error) => tracing::debug!(%error, "upgraded connection tunnel failed"),
        }
        // Dropping the tunnel halves closes both sides of the connection.
    });
}

/// Caddy applies a 16 KiB default `MaxHeaderBytes` when the server field is absent or <= 0
/// (`external/caddy/modules/caddyhttp/app.go`, `Server.Start`).
const CADDY_DEFAULT_MAX_HEADER_BYTES: usize = 16 * 1024;

/// Go's `http2adjustHTTP1MaxHeaderSize`: HTTP/2 counts 32 bytes of per-field overhead per pair and
/// assumes 10 typical headers, so the advertised `SETTINGS_MAX_HEADER_LIST_SIZE` is the HTTP/1
/// `MaxHeaderBytes` plus 320 (`net/http/h2_bundle.go`).
const GO_H2_HEADER_LIST_PADDING: u32 = 10 * 32;

/// Go `x/net/http2` server default for `SETTINGS_MAX_CONCURRENT_STREAMS`
/// (`http2defaultMaxStreams = 250`, `net/http/h2_bundle.go`).
const GO_H2_DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 250;

/// Go `x/net/http2` server default for the maximum frame it accepts, which is what the server
/// advertises as `SETTINGS_MAX_FRAME_SIZE` (`http2defaultMaxReadFrameSize = 1 << 20` in
/// `net/http/h2_bundle.go`; `ConfigureServer(new(http2.Server))` applies that default). Caddy
/// constructs `new(http2.Server)`, so Caddy advertises 1 MiB. The protocol's initial maximum frame
/// size (16384) is a different constant and is not what Go advertises.
const GO_H2_DEFAULT_MAX_READ_FRAME_SIZE: u32 = 1024 * 1024;

/// Go `x/net/http2` server default receive window per stream and per connection
/// (`MaxUploadBufferPerStream`/`MaxUploadBufferPerConnection` = 1 MiB).
const GO_H2_DEFAULT_INITIAL_WINDOW_SIZE: u32 = 1024 * 1024;

/// Apply Caddy/Go-compatible HTTP/2 server tuning explicitly.
///
/// Caddy v2.11.7 exposes **no JSON fields** for h2 stream/frame/window tuning: it passes
/// `new(http2.Server)` to `http2.ConfigureServer`, so Go's defaults apply. Hyper's defaults differ
/// for `MAX_CONCURRENT_STREAMS` (200 vs Go's 250), so the values are set explicitly here. Header
/// size comes from the existing per-server `max_header_bytes` field, converted the way Go's
/// HTTP/2 server converts `http.MaxHeaderBytes`.
///
/// Kept deliberately unset: `enable_connect_protocol` (extended CONNECT is not implemented and is
/// rejected loudly by the request layer), h2 keepalive/PING tuning and `keepalive_*` socket options
/// (documented gaps: Caddy's `keepalive_*` fields are TCP keepalive, not h2 PING).
fn configure_h2_raw_server(
    builder: &mut hyper::server::conn::http2::Builder<TokioExecutor>,
    limits: &ServerLimits,
) {
    let max_header_bytes = limits
        .max_header_bytes
        .unwrap_or(CADDY_DEFAULT_MAX_HEADER_BYTES);
    let max_header_list_size = u32::try_from(max_header_bytes)
        .unwrap_or(u32::MAX)
        .saturating_add(GO_H2_HEADER_LIST_PADDING);
    let _ = builder
        .timer(TokioTimer::new())
        .max_concurrent_streams(GO_H2_DEFAULT_MAX_CONCURRENT_STREAMS)
        .max_frame_size(GO_H2_DEFAULT_MAX_READ_FRAME_SIZE)
        .initial_stream_window_size(GO_H2_DEFAULT_INITIAL_WINDOW_SIZE)
        .initial_connection_window_size(GO_H2_DEFAULT_INITIAL_WINDOW_SIZE)
        .max_header_list_size(max_header_list_size);
    // RFC 8441 / Caddy v2.11.7 parity: Go's net/http HTTP/2 server leaves
    // SETTINGS_ENABLE_CONNECT_PROTOCOL unadvertised unless the process runs with
    // `GODEBUG=http2xconnect=1` (Go issue #71128), so caddy-rs mirrors that gate.
    if crate::http::http2_extended_connect_enabled() {
        builder.enable_connect_protocol();
    }
}

/// The same tuning applied through hyper-util's auto-builder `Http2Builder` wrapper (used for
/// connections served by the automatic HTTP/1-or-HTTP/2 detector).
fn configure_h2_auto_server(
    builder: &mut hyper_util::server::conn::auto::Http2Builder<'_, TokioExecutor>,
    limits: &ServerLimits,
) {
    let max_header_bytes = limits
        .max_header_bytes
        .unwrap_or(CADDY_DEFAULT_MAX_HEADER_BYTES);
    let max_header_list_size = u32::try_from(max_header_bytes)
        .unwrap_or(u32::MAX)
        .saturating_add(GO_H2_HEADER_LIST_PADDING);
    let _ = builder
        .timer(TokioTimer::new())
        .max_concurrent_streams(GO_H2_DEFAULT_MAX_CONCURRENT_STREAMS)
        .max_frame_size(GO_H2_DEFAULT_MAX_READ_FRAME_SIZE)
        .initial_stream_window_size(GO_H2_DEFAULT_INITIAL_WINDOW_SIZE)
        .initial_connection_window_size(GO_H2_DEFAULT_INITIAL_WINDOW_SIZE)
        .max_header_list_size(max_header_list_size);
    // Same gate as the raw h2c-upgrade builder (Go issue #71128 / Caddy v2.11.7): only advertise
    // HTTP/2 extended CONNECT when GODEBUG=http2xconnect=1 is set.
    if crate::http::http2_extended_connect_enabled() {
        builder.enable_connect_protocol();
    }
}

/// Serve one connection with the server's limits and graceful-shutdown/idle handling.
async fn serve_connection<I, S>(
    io: I,
    service: S,
    mut shutdown: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
    limits: Arc<ServerLimits>,
    activity: Arc<ConnectionActivity>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: hyper::service::Service<
            hyper::Request<Incoming>,
            Response = hyper::Response<Body>,
            Error = std::convert::Infallible,
        > + Send
        + 'static,
    S::Future: Send + 'static,
{
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    // Caddy defaults `MaxHeaderBytes` to 16 KiB when the server field is absent/zero.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(limits.read_header_timeout))
        .max_buf_size(
            limits
                .max_header_bytes
                .unwrap_or(CADDY_DEFAULT_MAX_HEADER_BYTES),
        );
    let mut http2 = builder.http2();
    configure_h2_auto_server(&mut http2, &limits);

    let io = TimedIo::new(io, limits.read_timeout, limits.write_timeout);
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(connection);
    let idle = idle_after(activity, limits.idle_timeout);
    tokio::pin!(idle);

    tokio::select! {
        result = connection.as_mut() => {
            if let Err(error) = result {
                tracing::debug!(%error, "connection ended with error");
            }
        }
        _ = force.changed() => {
            // A forced shutdown (grace period expired or second signal) drops the connection
            // without waiting for in-flight work.
            tracing::debug!("force-closing connection");
        }
        _ = shutdown.changed() => {
            connection.as_mut().graceful_shutdown();
            // Finish in-flight work, but a forced shutdown must not wait for it.
            tokio::select! {
                _ = connection.as_mut() => {}
                _ = force.changed() => {
                    tracing::debug!("force-closing connection during graceful shutdown");
                }
            }
        }
        _ = idle.as_mut() => {
            tracing::debug!(
                idle_timeout_ms = limits.idle_timeout.as_millis() as u64,
                "closing idle connection"
            );
            connection.as_mut().graceful_shutdown();
            // Bound the grace period: an idle peer may never read the close, and the accept task
            // must not leak tasks. This is deliberately short and independent of Caddy's
            // (unimplemented) connection grace period (DIV-0020).
            let _ = tokio::time::timeout(Duration::from_secs(1), connection.as_mut()).await;
        }
    }
}

/// Tracks whether a connection has a request in flight, for idle-timeout accounting.
#[derive(Debug, Default)]
struct ConnectionActivity {
    in_flight: AtomicUsize,
    notify: tokio::sync::Notify,
}

impl ConnectionActivity {
    /// Mark the start of one request. The returned guard marks the end when dropped.
    fn begin(self: &Arc<Self>) -> InFlightGuard {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        self.notify.notify_one();
        InFlightGuard(Arc::clone(self))
    }
}

struct InFlightGuard(Arc<ConnectionActivity>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
        self.0.notify.notify_one();
    }
}

/// Resolve when the connection has been idle (no request in flight) for `idle`.
///
/// The timer restarts whenever a request starts or finishes, so a slow request never trips the
/// idle timeout; only a connection waiting for its next request does.
async fn idle_after(activity: Arc<ConnectionActivity>, idle: Duration) {
    loop {
        let notified = activity.notify.notified();
        tokio::pin!(notified);
        if activity.in_flight.load(Ordering::Acquire) != 0 {
            notified.await;
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(idle) => {
                if activity.in_flight.load(Ordering::Acquire) == 0 {
                    return;
                }
            }
            _ = &mut notified => {}
        }
    }
}

/// Apply an optional per-operation timeout to an I/O poll result.
fn apply_io_timeout<T>(
    timer: &mut Option<Pin<Box<tokio::time::Sleep>>>,
    timeout: Option<Duration>,
    cx: &mut Context<'_>,
    result: Poll<io::Result<T>>,
) -> Poll<io::Result<T>> {
    match result {
        Poll::Ready(value) => {
            *timer = None;
            Poll::Ready(value)
        }
        Poll::Pending => match timeout {
            None => Poll::Pending,
            Some(timeout) => {
                let sleep = timer.get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        *timer = None;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("I/O timed out after {timeout:?}"),
                        )))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        },
    }
}

/// A transport wrapper that enforces a per-read and per-write timeout.
///
/// Caddy's `read_timeout`/`write_timeout` are deadlines over the whole transfer; hyper 1.x does
/// not expose that hook, so caddy-rs applies the configured value to each stalled read/write
/// operation instead. A client that makes progress is never disconnected; one that stalls for
/// longer than the limit is. See DIV-0029.
struct TimedIo<I> {
    inner: I,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    read_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    write_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<I> TimedIo<I> {
    fn new(inner: I, read_timeout: Option<Duration>, write_timeout: Option<Duration>) -> Self {
        Self {
            inner,
            read_timeout,
            write_timeout,
            read_timer: None,
            write_timer: None,
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for TimedIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        apply_io_timeout(&mut this.read_timer, this.read_timeout, cx, result)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for TimedIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        apply_io_timeout(&mut this.write_timer, this.write_timeout, cx, result)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        apply_io_timeout(&mut this.write_timer, this.write_timeout, cx, result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        apply_io_timeout(&mut this.write_timer, this.write_timeout, cx, result)
    }
}

/// Add the server's HTTP/3 advertisement to a response, like Caddy inserting Alt-Svc at the top of
/// `ServeHTTP` so *every* HTTP/1.1/HTTP/2 response carries it — including the h2c upgrade `101`
/// and the missing-router `503` that never reach the normal response path.
fn with_alt_svc(
    mut response: hyper::Response<Body>,
    alt_svc: Option<&String>,
) -> hyper::Response<Body> {
    if let Some(alt_svc) = alt_svc {
        if let Ok(value) = http::HeaderValue::from_str(alt_svc) {
            if !response.headers().contains_key(http::header::ALT_SVC) {
                response.headers_mut().insert(http::header::ALT_SVC, value);
            }
        }
    }
    response
}

fn error_response() -> hyper::Response<Body> {
    hyper::Response::builder()
        .status(503)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from_bytes(Bytes::from_static(
            b"503 Service Unavailable",
        )))
        .expect("static response is valid")
}

/// Bind the admin API listener.
pub(crate) async fn bind_admin(configured: &str, api: AdminApi) -> Result<ListenerHandle, Error> {
    let address = ListenAddr::parse(configured).map_err(|reason| Error::Listen {
        listen: configured.to_string(),
        reason,
    })?;
    if address.network != Network::Tcp {
        return Err(Error::NotImplemented {
            feature: "admin API on non-TCP listeners",
            tracking_id: "ADMIN-LISTEN",
        });
    }
    let listener = bind_configured_tcp(configured, &address).await?;
    let socket_addr = listener
        .local_addr()
        .map_err(|error| Error::bind(configured, error))?;
    let (shutdown, mut receiver) = watch::channel(false);
    let (force, mut force_receiver) = watch::channel(false);
    let tracker = Arc::new(ConnectionTracker::default());
    let loop_tracker = Arc::clone(&tracker);
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = receiver.changed() => {
                    if changed.is_err() || *receiver.borrow() {
                        break;
                    }
                }
                changed = force_receiver.changed() => {
                    if changed.is_err() || *force_receiver.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((stream, _peer)) = accepted else { continue };
                    let api = api.clone();
                    let connection_shutdown = receiver.clone();
                    let connection_force = force_receiver.clone();
                    let tracked = loop_tracker.guard();
                    tokio::spawn(async move {
                        let _tracked = tracked;
                        let service = service_fn(move |request: hyper::Request<Incoming>| {
                            let api = api.clone();
                            async move {
                                let (parts, body) = request.into_parts();
                                let body = match body.collect().await {
                                    Ok(collected) => collected.to_bytes(),
                                    Err(_) => Bytes::new(),
                                };
                                let path = parts
                                    .uri
                                    .path_and_query()
                                    .map(|value| value.as_str().to_string())
                                    .unwrap_or_else(|| "/".to_string());
                                let response = api
                                    .handle(AdminRequest {
                                        method: parts.method,
                                        path,
                                        headers: parts.headers,
                                        body,
                                    })
                                    .await;
                                let mut builder = hyper::Response::builder().status(response.status);
                                for (name, value) in &response.headers {
                                    builder = builder.header(name, value);
                                }
                                Ok::<_, std::convert::Infallible>(
                                    builder
                                        .body(Body::from_bytes(response.body))
                                        .expect("admin response is valid"),
                                )
                            }
                        });
                        let limits = Arc::new(ServerLimits::default());
                        let activity = Arc::new(ConnectionActivity::default());
                        serve_connection(
                            stream,
                            service,
                            connection_shutdown,
                            connection_force,
                            limits,
                            activity,
                        )
                        .await;
                    });
                }
            }
        }
    });
    Ok(ListenerHandle {
        shutdown,
        force,
        tracker,
        task,
        bound: socket_addr.to_string(),
        socket_addr: Some(socket_addr),
    })
}

#[cfg(test)]
mod client_certificate_tests {
    use super::client_certificate_from_der;

    const CLIENT_PEM: &str = include_str!("../../tls/testdata/client-auth/client.pem");

    /// The QUIC path shares this conversion with the TCP path, so proving it here proves the
    /// HTTP/3 placeholders carry the same data (DIV-0004 residual, T-HTTP-048).
    #[test]
    fn derives_placeholders_from_a_presented_leaf_certificate() {
        let chain =
            caddy_rs_tls::tls_server::certificates_from_pem(CLIENT_PEM).expect("client PEM");
        let leaf = chain.first().expect("leaf certificate");
        let certificate = client_certificate_from_der(leaf, true).expect("derived certificate");
        assert!(!certificate.subject.is_empty(), "subject must be populated");
        assert!(certificate.verified, "verification flag must be carried");
        assert!(!certificate.certificate_pem.is_empty());
        assert!(!certificate.fingerprint.is_empty());

        let unverified = client_certificate_from_der(leaf, false).expect("derived certificate");
        assert!(
            !unverified.verified,
            "an unverified listener must not claim verification"
        );
    }
}
