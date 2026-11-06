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
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use caddy_rs_admin::{AdminApi, AdminRequest, SharedRequestRecorder};
use caddy_rs_core::{Generation, GenerationStore, ListenAddr, Network};
use caddy_rs_http::{Body, Router};

use crate::activation::{adopt_tcp, adopt_unix, InheritedSocket, LocalSocket};
use crate::auto_https::AutomaticHttpsServing;
use crate::error::Error;
use crate::http::{serve_request_with_automatic_upgradable, ServedResponse};
use crate::limits::ServerLimits;
use crate::observability::{
    body_len, observe_request, request_started, AccessLogRuntime, RequestSnapshot,
    ServerAccessLogPolicy, TlsLogInfo,
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
    /// TLS configuration when this listener terminates TLS; `None` for cleartext listeners.
    pub(crate) tls: Option<Arc<rustls::ServerConfig>>,
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
}

/// Listener state shared with accept loops, keyed by configured listen address.
pub(crate) type SharedListeners = Arc<RwLock<HashMap<String, Arc<ListenerState>>>>;

/// Tracks connections accepted by one listener so shutdown can wait for in-flight work.
#[derive(Debug, Default)]
pub(crate) struct ConnectionTracker {
    active: AtomicUsize,
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

impl Drop for TrackedConnection {
    fn drop(&mut self) {
        self.tracker.active.fetch_sub(1, Ordering::AcqRel);
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
        Network::Udp => Err(Error::NotImplemented {
            feature: "UDP listeners (HTTP/3)",
            tracking_id: "HTTP3-UDP",
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

/// State captured for one accepted connection.
struct ConnectionContext {
    /// Router to serve, or `None` while the listener is being retired (responds 503).
    router: Option<Arc<Router>>,
    limits: Arc<ServerLimits>,
    /// TLS configuration for this accepted connection, when the listener terminates TLS.
    tls: Option<Arc<rustls::ServerConfig>>,
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
            tls: state.tls.clone(),
            automatic: state.automatic.clone(),
            server_name: state.server_name.clone(),
            recorder: Arc::clone(&state.recorder),
            access_log: Arc::clone(&state.access_log),
            access_log_policy: Arc::clone(&state.access_log_policy),
            wrappers: Arc::clone(&state.wrappers),
            h2c_upgrade: state.h2c_upgrade,
        },
        None => ConnectionContext {
            router: None,
            limits: Arc::new(ServerLimits::default()),
            tls: None,
            automatic: None,
            server_name: String::new(),
            recorder: caddy_rs_admin::noop_recorder(),
            access_log: AccessLogRuntime::disabled(),
            access_log_policy: Arc::new(ServerAccessLogPolicy::default()),
            wrappers: Arc::new(ListenerWrappers::default()),
            h2c_upgrade: false,
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
    let (stream, remote_override, local_override) = match context.wrappers.proxy_protocol() {
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
        None => (PrefixedStream::new(stream, Vec::new()), None, None),
    };
    serve_accepted(
        stream,
        remote_override.or(peer),
        local_override.or(local),
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
    let activity = Arc::new(ConnectionActivity::default());
    let router = context.router;
    let automatic = context.automatic;
    let server_name = context.server_name;
    let recorder = context.recorder;
    let access_log = context.access_log;
    let access_log_policy = context.access_log_policy;
    if let Some(tls) = context.tls {
        let acceptor = TlsAcceptor::from(tls);
        let tls_stream = match acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(error) => {
                // TLS handshake failures are client-side errors (wrong SNI, protocol mismatch);
                // log at debug and drop the connection like Caddy does.
                tracing::debug!(%error, "TLS handshake failed");
                return;
            }
        };
        let connection = tls_stream.get_ref().1;
        let alpn = connection
            .alpn_protocol()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
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
        };
        let service = connection_service(
            router,
            Arc::clone(&limits),
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
            shutdown.clone(),
            Arc::clone(&tracked),
            false,
        );
        serve_connection(tls_stream, service, shutdown, force, limits, activity).await;
    } else {
        let service = connection_service(
            router,
            Arc::clone(&limits),
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
            shutdown.clone(),
            Arc::clone(&tracked),
            context.h2c_upgrade,
        );
        serve_connection(stream, service, shutdown, force, limits, activity).await;
    }
}

/// Everything the per-request service needs, cloned for the h2c upgrade service.
#[derive(Clone)]
struct RequestContext {
    router: Option<Arc<Router>>,
    limits: Arc<ServerLimits>,
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
    /// Graceful shutdown signal: upgraded WebSocket tunnels send a going-away close frame.
    shutdown: watch::Receiver<bool>,
    tracked: Arc<TrackedConnection>,
    /// Cleartext h2c Upgrade enabled (`protocols` includes h2c).
    h2c_upgrade: bool,
}

#[allow(clippy::too_many_arguments)]
fn connection_service(
    router: Option<Arc<Router>>,
    limits: Arc<ServerLimits>,
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
    shutdown: watch::Receiver<bool>,
    tracked: Arc<TrackedConnection>,
    h2c_upgrade: bool,
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
        remote_addr,
        local_addr,
        tls,
        alpn,
        tls_info,
        server_name,
        recorder,
        access_log,
        access_log_policy,
        automatic,
        activity,
        permit,
        generation,
        force,
        shutdown,
        tracked,
        h2c_upgrade,
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
    // Capture the access-log fields before the request is consumed. Only done when a sink is
    // configured, so the common no-logging path pays nothing.
    let snapshot = context.access_log.is_enabled().then(|| {
        RequestSnapshot::capture(&request, context.remote_addr, context.tls_info.as_ref())
    });
    let _request_guard = request_started(&context.recorder, &context.server_name);
    // Decide once, before the request is consumed, whether this is a real WebSocket handshake
    // offer. The response side (Sec-WebSocket-Accept) is checked when the 101 is returned; only a
    // complete handshake gets close-frame synthesis.
    let websocket_request = caddy_rs_proxy::websocket::request_is_websocket(request.headers());

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
        );
        return Ok(error_response());
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
        observe_request(
            &context.recorder,
            &context.access_log,
            &context.access_log_policy,
            &context.server_name,
            &method,
            snapshot.as_ref(),
            started,
            101,
            0,
            response.headers(),
        );
        return Ok(response);
    }

    // Take the client-side upgrade future before the request is consumed. Only requests
    // that actually negotiate an upgrade get one; the router decides whether to switch.
    let on_upgrade = caddy_rs_http::requested_upgrade_type(request.headers())
        .map(|_| hyper::upgrade::on(&mut request));
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
    )
    .await;

    let (status, response_size, response_headers) = match &served {
        ServedResponse::Response(response) => (
            response.status().as_u16(),
            body_len(response.body()),
            response.headers().clone(),
        ),
        ServedResponse::Upgraded { response, .. } => {
            (response.status().as_u16(), 0, response.headers().clone())
        }
    };
    observe_request(
        &context.recorder,
        &context.access_log,
        &context.access_log_policy,
        &context.server_name,
        &method,
        snapshot.as_ref(),
        started,
        status,
        response_size,
        &response_headers,
    );

    match served {
        ServedResponse::Response(response) => Ok::<_, std::convert::Infallible>(response),
        ServedResponse::Upgraded {
            response,
            tunnel,
            on_upgrade,
        } => {
            let websocket = websocket_request
                && caddy_rs_proxy::websocket::response_negotiated_websocket(response.headers());
            spawn_upgraded_tunnel(
                on_upgrade,
                tunnel,
                context.force.clone(),
                context.shutdown.clone(),
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
        let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
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

/// Combine the graceful-shutdown and forced-shutdown signals into one cancellation receiver.
///
/// An upgraded tunnel cares about "the listener is stopping", not which phase signalled it: both
/// paths write the best-effort WebSocket going-away close frame before closing.
fn merge_shutdown_signals(
    mut shutdown: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
) -> (watch::Receiver<bool>, Option<tokio::task::JoinHandle<()>>) {
    let (sender, receiver) = watch::channel(false);
    if *shutdown.borrow() || *force.borrow() {
        let _ = sender.send(true);
        return (receiver, None);
    }
    let watcher = tokio::spawn(async move {
        tokio::select! {
            result = shutdown.changed() => {
                let _ = result;
            }
            result = force.changed() => {
                let _ = result;
            }
        }
        let _ = sender.send(true);
    });
    (receiver, Some(watcher))
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
    shutdown: watch::Receiver<bool>,
    websocket: bool,
    permit: Arc<ConnectionPermit>,
    generation: Option<Arc<Generation>>,
    tracked: Arc<TrackedConnection>,
) {
    tokio::spawn(async move {
        let _permit = permit;
        let _generation = generation;
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
        // abnormal 1006: 1000 (normal) on upstream EOF, 1001 (going away) on graceful shutdown.
        let client = TokioIo::new(client);
        let upstream = tunnel.into_inner();
        // Treat graceful shutdown and forced shutdown alike: the tunnel sends a going-away close
        // frame (best effort) before it closes, so a shutdown never looks like abnormal closure to
        // a WebSocket client.
        let (cancellation, watcher) = merge_shutdown_signals(shutdown, force);
        let result =
            caddy_rs_proxy::websocket::tunnel(client, upstream, websocket, cancellation).await;
        // The watcher normally exits when a shutdown signal fires; a tunnel that closed on its own
        // must not leave it behind until the listener stops.
        if let Some(watcher) = watcher {
            watcher.abort();
        }
        match result {
            Ok(()) => tracing::debug!("upgraded connection closed"),
            Err(error) => tracing::debug!(%error, "upgraded connection tunnel failed"),
        }
        // Dropping the tunnel halves closes both sides of the connection.
    });
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
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(limits.read_header_timeout));
    if let Some(max_header_bytes) = limits.max_header_bytes {
        builder.http1().max_buf_size(max_header_bytes);
        builder
            .http2()
            .max_header_list_size(u32::try_from(max_header_bytes).unwrap_or(u32::MAX));
    }

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
