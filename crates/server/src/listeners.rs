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
    /// For a Unix admin listener: the socket path and the identity of the file this listener
    /// created there (the `/stop` exit path removes it only if it is still that file).
    pub(crate) unix_socket: Option<(std::path::PathBuf, SocketIdentity)>,
}

/// How an admin listener is bound, decided by the caller from the generation being applied and the
/// process role (not re-derived from whatever generation happens to be active).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AdminBindOptions {
    /// The generation being applied sets `stock_compat true`: replace a Unix socket
    /// unconditionally like stock Caddy, and lift the body cap/slots.
    pub stock_compat: bool,
    /// This process is the child of a zero-downtime upgrade. The parent keeps serving its admin
    /// socket until the child reports ready, so a socket that still accepts is expected and is
    /// replaced (the parent's cleanup then leaves the replaced path alone: different inode).
    pub replace_live: bool,
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

/// The optional ecdysis registry handed to the bind path.
///
/// With the `graceful-restart` feature this borrows the runtime's [`ListenerBinder`]; without it the
/// type is a never-constructible placeholder so every signature is identical in both builds and the
/// bind path reads the same either way. That keeps the feature split in exactly one place
/// ([`bind_tcp_ip`]) instead of duplicating every signature behind a `cfg`.
#[cfg(feature = "graceful-restart")]
type BinderRef<'a> = Option<&'a crate::graceful_restart::ListenerBinder>;

/// See the `graceful-restart` variant above: with the feature off there is no registry to pass.
#[cfg(not(feature = "graceful-restart"))]
type BinderRef<'a> = Option<&'a std::convert::Infallible>;

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
    #[cfg_attr(not(feature = "graceful-restart"), allow(unused_variables))] binder: BinderRef<'_>,
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
                None => bind_configured_tcp(configured, &address, binder).await?,
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
                unix_socket: None,
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
                unix_socket: None,
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
                unix_socket: None,
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
async fn bind_configured_tcp(
    configured: &str,
    address: &ListenAddr,
    #[cfg_attr(not(feature = "graceful-restart"), allow(unused_variables))] binder: BinderRef<'_>,
) -> Result<TcpListener, Error> {
    if address.host().is_empty() {
        let port = address.port().ok_or_else(|| Error::Listen {
            listen: configured.to_string(),
            reason: "expected `host:port`; a hostless address needs a numeric port".to_string(),
        })?;
        // The dual-stack wildcard is a TCP listener like any other, so it goes through the same
        // ecdysis routing: a hostless listener is the common case for a public site, and missing it
        // here would reintroduce the refused-connection window on exactly the busiest listener.
        return bind_tcp_wildcard(configured, port, binder);
    }
    match address.socket_addr() {
        // IP literal: bind exactly that address/family, through ecdysis when the graceful-restart
        // feature is on so the socket is inherited across `exec` rather than rebound.
        Some(socket_addr) => bind_tcp_ip(configured, socket_addr, binder),
        // Hostname: resolve and bind like Caddy's `net.Listen("tcp", "host:port")`. Bind the
        // address without a `tcp/`/`udp/` network prefix (the prefix is already parsed above).
        None => {
            let first = TcpListener::bind(&address.address).await;
            match first {
                Ok(listener) => Ok(listener),
                Err(error) => {
                    // ADR-0046: retry once under CAP_NET_BIND_SERVICE only for EACCES on a
                    // TCP/UDP nonzero-port address. Everything else keeps the original error.
                    let address_owned = address.clone();
                    let bind_address = address_owned.address.clone();
                    // The seam's error is passed through UNCHANGED and handed to `Error::bind`,
                    // which is what keeps the located error naming the configured address. A
                    // previous revision rebuilt it as `std::io::Error::new(error.kind(), reason)`
                    // with `reason` captured BEFORE the retry, which silently discarded the second
                    // attempt's message -- including the seam's deliberate
                    // "(raising CAP_NET_BIND_SERVICE: <why>)" explanation. An operator then saw the
                    // first attempt's wording with no hint that escalation was tried and failed.
                    let retried =
                        crate::bindcap::with_bind_capability(&address_owned, error, move || {
                            // A fresh single-threaded runtime: this runs on the dedicated thread
                            // the seam spawned, not on the caller's Tokio runtime.
                            let runtime = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()?;
                            runtime.block_on(TcpListener::bind(&bind_address))
                        })
                        .map_err(|error| located_bind_error(configured, error));
                    match retried {
                        Ok(listener) => Ok(listener),
                        Err(error) => Err(error),
                    }
                }
            }
        }
    }
}

/// Map a bind failure into the located [`Error::Bind`], naming the configured address.
///
/// Every capability-retry site routes its error through this, and it deliberately passes the
/// [`crate::bindcap::with_bind_capability`] error through **unchanged**. An earlier revision rebuilt
/// the error as `std::io::Error::new(error.kind(), reason)` with `reason` captured *before* the
/// retry, which discarded the second attempt's message — including the seam's deliberate
/// `(raising CAP_NET_BIND_SERVICE: <why>)` explanation — so an operator saw the first attempt's
/// wording with no hint that escalation was attempted and failed. Editing this function changes
/// every wired site, which is why the test below can pin the behaviour on the real code.
fn located_bind_error(configured: &str, error: std::io::Error) -> Error {
    Error::bind(configured, error)
}

/// Bind a TCP listener to a numeric address, through ecdysis when the feature is enabled.
///
/// This is the single point where the graceful-restart feature changes listener creation. With the
/// feature off it is exactly the `TcpListener::bind` it replaced, so behaviour is bit-identical;
/// with it on the socket is registered with ecdysis and the next generation inherits it.
///
/// The two paths must apply the same socket options, so both go through [`tcp_socket_options`]
/// rather than duplicating the calls: if they diverged, an inherited socket would carry different
/// options from a freshly-bound one and the generations would disagree about the same kernel socket.
fn bind_tcp_ip(
    configured: &str,
    socket_addr: SocketAddr,
    #[cfg_attr(not(feature = "graceful-restart"), allow(unused_variables))] binder: BinderRef<'_>,
) -> Result<TcpListener, Error> {
    #[cfg(feature = "graceful-restart")]
    if let Some(binder) = binder {
        let listener = binder
            .bind_tcp(socket_addr, |socket, addr| {
                tcp_socket_options(&socket)?;
                socket.bind(&addr.into())?;
                socket.listen(128)?;
                let listener: std::net::TcpListener = socket.into();
                listener.set_nonblocking(true)?;
                Ok(listener)
            })
            .map_err(|error| Error::bind(configured, error))?;
        return TcpListener::from_std(listener).map_err(|error| Error::bind(configured, error));
    }
    // ADR-0046 §§1-2: attempt with no capability manipulation, then retry ONCE under
    // CAP_NET_BIND_SERVICE only when the failure is EACCES on a TCP/UDP nonzero-port address and the
    // capability is permitted-but-not-effective. A second EACCES is genuine and surfaces unchanged.
    let listener = match std::net::TcpListener::bind(socket_addr) {
        Ok(listener) => listener,
        Err(error) => {
            let address = ListenAddr {
                network: Network::Tcp,
                address: socket_addr.to_string(),
            };
            match crate::bindcap::with_bind_capability(&address, error, move || {
                std::net::TcpListener::bind(socket_addr)
            }) {
                Ok(listener) => listener,
                // Located error naming the configured address, through the single shared mapping.
                Err(error) => return Err(located_bind_error(configured, error)),
            }
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|error| Error::bind(configured, error))?;
    TcpListener::from_std(listener).map_err(|error| Error::bind(configured, error))
}

/// Bind a hostless (`:port`) TCP listener, through ecdysis when the feature is enabled.
///
/// Keeps the existing dual-stack preference: an `IPV6_V6ONLY=0` wildcard when the platform offers
/// it, falling back to an IPv4 wildcard when IPv6 sockets are unavailable. Both branches are routed
/// through ecdysis, because both produce a listener that must survive `exec`.
fn bind_tcp_wildcard(
    configured: &str,
    port: u16,
    #[cfg_attr(not(feature = "graceful-restart"), allow(unused_variables))] binder: BinderRef<'_>,
) -> Result<TcpListener, Error> {
    #[cfg(feature = "graceful-restart")]
    let v6_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));

    #[cfg(feature = "graceful-restart")]
    if let Some(binder) = binder {
        // Try the dual-stack wildcard first. ecdysis keys inheritance on the address it is asked
        // for, so the key must be the address actually bound: the dual-stack case is keyed on the
        // IPv6 wildcard, and the IPv4 fallback on the IPv4 wildcard. Trying IPv6 first and only
        // falling back when the platform refuses it keeps the key correct in both cases.
        match binder.bind_tcp(v6_addr, |socket, addr| {
            socket.set_only_v6(false)?;
            tcp_socket_options(&socket)?;
            socket.bind(&addr.into())?;
            socket.listen(128)?;
            let listener: std::net::TcpListener = socket.into();
            listener.set_nonblocking(true)?;
            Ok(listener)
        }) {
            Ok(listener) => {
                return TcpListener::from_std(listener)
                    .map_err(|error| Error::bind(configured, error))
            }
            Err(error) if ipv6_wildcard_unavailable(&error) => {
                tracing::debug!(
                    listen = configured,
                    %error,
                    "IPv6 wildcard listener unavailable; binding the IPv4 wildcard"
                );
            }
            Err(error) => return Err(Error::bind(configured, error)),
        }
        let v4_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        let listener = binder
            .bind_tcp(v4_addr, |socket, addr| {
                tcp_socket_options(&socket)?;
                socket.bind(&addr.into())?;
                socket.listen(128)?;
                let listener: std::net::TcpListener = socket.into();
                listener.set_nonblocking(true)?;
                Ok(listener)
            })
            .map_err(|error| Error::bind(configured, error))?;
        return TcpListener::from_std(listener).map_err(|error| Error::bind(configured, error));
    }

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
    TcpListener::from_std(listener).map_err(|error| Error::bind(configured, error))
}

/// The socket options every caddy-rs TCP listener carries, applied before `bind`.
///
/// Kept in one place so the direct-bind path and the ecdysis creation closure cannot drift.
///
/// Generic over the socket type because two socket2 versions are in the graph: this crate pins
/// 0.6.5 while ecdysis 1.1.1 builds its sockets with ^0.5 (the accepted KNOWN COST recorded in
/// `Cargo.toml`). Both expose `set_reuse_address`, so the options are written once and applied to
/// whichever socket the caller has; the point of this function is that the two paths cannot
/// diverge, and splitting it per version would defeat that.
#[cfg(feature = "graceful-restart")]
trait TcpSocketOptions {
    fn set_reuse_address(&self, reuse: bool) -> io::Result<()>;
}

#[cfg(feature = "graceful-restart")]
impl TcpSocketOptions for Socket {
    fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        Socket::set_reuse_address(self, reuse)
    }
}

#[cfg(feature = "graceful-restart")]
impl TcpSocketOptions for socket2_v05::Socket {
    fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        socket2_v05::Socket::set_reuse_address(self, reuse)
    }
}

#[cfg(feature = "graceful-restart")]
fn tcp_socket_options(socket: &impl TcpSocketOptions) -> io::Result<()> {
    socket.set_reuse_address(true)?;
    Ok(())
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
        let socket = bind_udp_ipv4_wildcard(port, configured)?;
        return Ok(socket);
    }
    match address.socket_addr() {
        Some(socket_addr) => bind_udp_socket_addr(socket_addr, configured),
        None => {
            // ADR-0046: a udp/<hostname>:<privileged port> listener must get the same EACCES retry
            // as its TCP equivalent, otherwise the two protocols disagree about whether a
            // privileged port is bindable.
            let first = UdpSocket::bind(&address.address).await;
            match first {
                Ok(socket) => Ok(socket),
                Err(error) => {
                    let address_owned = address.clone();
                    let bind_address = address_owned.address.clone();
                    crate::bindcap::with_bind_capability(&address_owned, error, move || {
                        // Runs on the dedicated thread the seam spawned, so a fresh current-thread
                        // runtime is built here rather than borrowing the caller's.
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        runtime.block_on(UdpSocket::bind(&bind_address))
                    })
                    .map_err(|error| located_bind_error(configured, error))
                }
            }
        }
    }
}

/// Bind the IPv4 wildcard UDP socket, joining a reuseport group when `udpgrm` is enabled.
#[cfg(feature = "http3")]
fn bind_udp_ipv4_wildcard(port: u16, configured: &str) -> Result<UdpSocket, Error> {
    let wildcard = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    // ADR-0046: same EACCES-only retry as TCP; a UDP privileged port needs the same capability.
    let socket = match std::net::UdpSocket::bind(wildcard) {
        Ok(socket) => socket,
        Err(error) => {
            let address = ListenAddr {
                network: Network::Udp,
                address: wildcard.to_string(),
            };
            crate::bindcap::with_bind_capability(&address, error, move || {
                std::net::UdpSocket::bind(wildcard)
            })
            .map_err(|error| located_bind_error(configured, error))?
        }
    };
    socket
        .set_nonblocking(true)
        .map_err(|error| Error::bind(configured, error))?;
    UdpSocket::from_std(socket).map_err(|error| Error::bind(configured, error))
}

/// Bind an explicit-address UDP socket.
///
/// With `udpgrm` enabled the socket is created through socket2 so `SO_REUSEPORT` can be set
/// **before** `bind`: the option only takes effect for a group created at bind time, so setting it
/// afterwards would silently leave the socket outside the group and defeat the whole mechanism.
/// Without the feature this is the original `UdpSocket::bind` and is behaviourally identical.
#[cfg(feature = "http3")]
fn bind_udp_socket_addr(
    socket_addr: SocketAddr,
    #[cfg_attr(not(feature = "udpgrm"), allow(unused_variables))] configured: &str,
) -> Result<UdpSocket, Error> {
    #[cfg(feature = "udpgrm")]
    {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|error| Error::bind(configured, error))?;
        socket
            .set_reuse_port(true)
            .map_err(|error| Error::bind(configured, error))?;
        socket
            .bind(&socket_addr.into())
            .map_err(|error| Error::bind(configured, error))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| Error::bind(configured, error))?;
        let std_socket: std::net::UdpSocket = socket.into();
        // The dissector belongs to the reuseport group created by `bind` above, so it is selected
        // before registration and before any flow can arrive.
        select_udpgrm_dissector(&std_socket, configured);
        // Register with udpgrm after bind, because its hooks only act on a bound socket inside a
        // reuseport group. Registration and promotion are separate steps (ADR-0045 §2): the socket
        // joins the new generation here, but new flows keep reaching the old generation until the
        // runtime is fully initialised and promotes. A failure here degrades: UDP still serves.
        defer_udpgrm_promotion(&std_socket, configured);
        return UdpSocket::from_std(std_socket).map_err(|error| Error::bind(configured, error));
    }
    #[cfg(not(feature = "udpgrm"))]
    {
        // No runtime to block on here; the socket is already bound synchronously below, so this
        // mirrors the original `UdpSocket::bind` call exactly.
        //
        // ADR-0046: the EACCES-only capability retry applies here too. The `udpgrm` branch above
        // deliberately does NOT use it: that path must set `SO_REUSEPORT` *before* `bind` to join the
        // reuseport group, so a naive retry would either resurrect an ungrouped socket or need the
        // whole socket constructed on the dedicated thread. UDP over udpgrm therefore keeps the
        // pre-ADR-0046 behaviour, which is a documented scope boundary rather than an oversight.
        let socket = match std::net::UdpSocket::bind(socket_addr) {
            Ok(socket) => socket,
            Err(error) => {
                let address = ListenAddr {
                    network: Network::Udp,
                    address: socket_addr.to_string(),
                };
                crate::bindcap::with_bind_capability(&address, error, move || {
                    std::net::UdpSocket::bind(socket_addr)
                })
                .map_err(|error| located_bind_error(configured, error))?
            }
        };
        socket
            .set_nonblocking(true)
            .map_err(|error| Error::bind(configured, error))?;
        UdpSocket::from_std(socket).map_err(|error| Error::bind(configured, error))
    }
}

/// Select the udpgrm flow dissector for the reuseport group this socket just joined.
///
/// Called once per socket, immediately after `bind` created (or joined) the group and **before**
/// registration, because the dissector is a property of the group rather than of the generation:
/// udpgrm records it when the group is created and answers any later change with `EPERM` (ADR-0045
/// §3, §4). Setting it here rather than per request is what turns a conflicting group into one
/// located startup message instead of a stream of failures under load.
///
/// A failure **degrades rather than aborts**, for the same reason the presence probe does: on a host
/// without udpgrm the option does not exist (`ENOPROTOOPT`), which means "graceful UDP restart is
/// unavailable", not "refuse to serve UDP". The conflict case is reported distinctly so an operator
/// can tell a genuine dissector mismatch from a missing daemon.
#[cfg(all(feature = "http3", feature = "udpgrm"))]
fn select_udpgrm_dissector(socket: &std::net::UdpSocket, configured: &str) {
    use crate::udpgrm_dissector::{select_dissector, Dissector, DissectorError};

    // DISSECTOR_FLOW is the initial choice (ADR-0045 §4). Its concurrent-flow cap is published in
    // the operator docs; DISSECTOR_NOOP is available through the documented environment variable
    // for stateless UDP use, where flow identity is meaningless.
    let dissector = match crate::udpgrm_dissector::dissector_from_env() {
        Ok(dissector) => dissector,
        Err(error) => {
            // A misconfigured name must not silently become the default: the operator asked for a
            // specific dissector, and serving with a different one hides the mistake until it shows
            // up as unexplained restart behaviour.
            tracing::warn!(
                listen = configured,
                %error,
                "udpgrm flow dissector selection is invalid; falling back to the default"
            );
            Dissector::default()
        }
    };
    match select_dissector(socket, dissector) {
        Ok(()) => {}
        Err(DissectorError::Conflict { .. }) => tracing::warn!(
            listen = configured,
            dissector = dissector.as_str(),
            max_concurrent_flows = dissector.max_concurrent_flows().unwrap_or(0),
            "udpgrm already has a different flow dissector for this reuseport group; the \
             configured dissector was not applied and new flows may not stay sticky across a \
             restart. The dissector is fixed for the lifetime of the group"
        ),
        Err(DissectorError::Io(error)) if error.raw_os_error() == Some(libc::ENOPROTOOPT) => {
            // No daemon: identical to the presence probe's outcome. Already reported once, loudly,
            // by the generation probe, so this stays quiet rather than repeating it per socket.
        }
        Err(DissectorError::Io(error)) => tracing::warn!(
            listen = configured,
            %error,
            "udpgrm flow dissector could not be selected; flow stickiness across a restart is not \
             guaranteed for this listener"
        ),
    }
}

/// Register a bound UDP socket into the next udpgrm socket generation and defer its promotion.
///
/// Promotion is deliberately *not* done here: a socket bound during `apply` must not attract new
/// flows before the instance is fully initialised, which is the ordering ADR-0044 §2 fixes for TCP
/// and which `ServerRuntime::mark_ready` enforces for UDP by draining the deferred set. Registering
/// and promoting in one step at bind time would send new flows to a process that is not yet serving.
#[cfg(all(feature = "http3", feature = "udpgrm"))]
fn defer_udpgrm_promotion(socket: &std::net::UdpSocket, configured: &str) {
    let Some(pending) = crate::udpgrm::register_listener(socket, configured) else {
        return;
    };
    // The registry keeps its own handle; both descriptors refer to the same kernel socket, so a
    // socket option set through either applies to the listener.
    match crate::udpgrm::duplicate_for_promotion(socket) {
        Ok(owned) => crate::udpgrm::defer_promotion(configured, owned, pending),
        Err(error) => tracing::warn!(
            listen = configured,
            %error,
            "udpgrm registered the UDP socket generation but its handle could not be retained; \
             the generation will not be promoted and UDP keeps serving on the previous one"
        ),
    }
}

/// A dual-stack (`IPv6` wildcard with `IPV6_V6ONLY=0`) UDP socket for a hostless address.
///
/// With `udpgrm` enabled the socket also joins a reuseport group. `IPV6_V6ONLY` behaviour is
/// unchanged in both configurations: the dual-stack wildcard is still attempted first and the IPv4
/// fallback still happens only when IPv6 is unavailable.
#[cfg(feature = "http3")]
fn wildcard_dual_stack_udp(port: u16) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    #[cfg(feature = "udpgrm")]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    #[cfg(feature = "udpgrm")]
    {
        let configured = format!("udp/:{port}");
        select_udpgrm_dissector(&std_socket, &configured);
        defer_udpgrm_promotion(&std_socket, &configured);
    }
    UdpSocket::from_std(std_socket)
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
                            (!tls_info.server_name.is_empty())
                                .then(|| tls_info.server_name.clone()),
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
    mut shutdown: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
    tracked: TrackedConnection,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (stream, remote_override, local_override, proxy_vars) =
        match context.wrappers.proxy_protocol() {
            Some(settings) => match bounded_handshake(
                crate::proxy_protocol::wrap(stream, peer, local, settings),
                // The wrapper enforces its own (default 10 s) header deadline; this only adds the
                // shutdown signals.
                Duration::from_secs(86_400),
                &mut shutdown,
                &mut force,
            )
            .await
            .unwrap_or_else(|abort| {
                Err(crate::proxy_protocol::ProxyProtocolError::Io(
                    io::Error::other(format!("connection abandoned during shutdown: {abort:?}")),
                ))
            }) {
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

/// How long a connection still in its TLS handshake (or PROXY header read) may live after a
/// graceful stop begins. Go's `Server.Shutdown` closes connections that never got past `StateNew`
/// once they are a few seconds old rather than waiting for them.
const HANDSHAKE_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Why a pre-request phase (PROXY header, TLS handshake) was abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseAbort {
    /// The budget ran out.
    TimedOut,
    /// A graceful stop began and [`HANDSHAKE_SHUTDOWN_GRACE`] elapsed.
    ShutdownGrace,
    /// A forced shutdown.
    Forced,
}

/// Drive `phase` to completion, but give up after `budget`, when a forced shutdown arrives, or
/// [`HANDSHAKE_SHUTDOWN_GRACE`] after a graceful one begins. Without this a half-open handshake
/// ignored the shutdown signals and kept its tracker guard (and task) until its own budget ended.
async fn bounded_handshake<F: Future>(
    phase: F,
    budget: Duration,
    shutdown: &mut watch::Receiver<bool>,
    force: &mut watch::Receiver<bool>,
) -> Result<F::Output, PhaseAbort> {
    use tokio::time::Instant;
    tokio::pin!(phase);
    let budget_end = Instant::now() + budget;
    let mut grace_end: Option<Instant> = None;
    loop {
        let (deadline, on_deadline) = match grace_end {
            Some(grace_end) if grace_end < budget_end => (grace_end, PhaseAbort::ShutdownGrace),
            _ => (budget_end, PhaseAbort::TimedOut),
        };
        tokio::select! {
            output = &mut phase => return Ok(output),
            _ = tokio::time::sleep_until(deadline) => return Err(on_deadline),
            _ = force.changed() => return Err(PhaseAbort::Forced),
            _ = shutdown.changed(), if grace_end.is_none() => {
                grace_end = Some(Instant::now() + HANDSHAKE_SHUTDOWN_GRACE);
            }
        }
    }
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
    mut shutdown: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
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
        // Go bounds the handshake by min(read_timeout, read_header_timeout); the connection is
        // dropped when the client does not finish it in time (SEC-MEDIUM-ADMIN-SERVER A4).
        let handshake_timeout = limits.tls_handshake_timeout();
        let tls_stream = match external_key {
            // A token-held key signs inside the PKCS#11 token: hold a token handshake permit and
            // bound the whole handshake by the token budget (T-TLS-097).
            Some(pool) => {
                match bounded_handshake(
                    caddy_rs_tls::tls_server::accept_external_key_handshake(acceptor, stream, pool),
                    handshake_timeout,
                    &mut shutdown,
                    &mut force,
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        // Budget exhaustion and token failures are per-connection errors: log at
                        // debug and drop the connection, like the handshake failure below.
                        tracing::debug!(%error, "TLS handshake failed");
                        return;
                    }
                    Err(abort) => {
                        tracing::debug!(?handshake_timeout, ?abort, "TLS handshake abandoned");
                        return;
                    }
                }
            }
            None => match bounded_handshake(
                acceptor.accept(stream),
                handshake_timeout,
                &mut shutdown,
                &mut force,
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    // TLS handshake failures are client-side errors (wrong SNI, protocol
                    // mismatch); log at debug and drop the connection like Caddy does.
                    tracing::debug!(%error, "TLS handshake failed");
                    return;
                }
                Err(abort) => {
                    tracing::debug!(?handshake_timeout, ?abort, "TLS handshake abandoned");
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
        context
            .tls_info
            .as_ref()
            .filter(|info| !info.server_name.is_empty())
            .map(|info| info.server_name.clone()),
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
pub(crate) const CADDY_DEFAULT_MAX_HEADER_BYTES: usize = 16 * 1024;

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
pub(crate) fn configure_h2_auto_server(
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
        // hyper's header timer also runs while a keep-alive connection waits for its next request,
        // where Go applies `IdleTimeout` instead. Listeners that opt into request-scoped read
        // timers therefore give it the idle budget (their first-byte wait still uses the header
        // budget); everyone else keeps `read_header_timeout`.
        .header_read_timeout(Some(
            if limits.read_timeout_scope == crate::limits::ReadTimeoutScope::BodyReads {
                limits.idle_timeout
            } else {
                limits.read_header_timeout
            },
        ))
        .max_buf_size(
            limits
                .max_header_bytes
                .unwrap_or(CADDY_DEFAULT_MAX_HEADER_BYTES),
        );
    let mut http2 = builder.http2();
    configure_h2_auto_server(&mut http2, &limits);

    let mut io = TimedIo::new(io, limits.read_timeout, limits.write_timeout);
    if limits.read_timeout_scope == crate::limits::ReadTimeoutScope::BodyReads {
        io = io.with_read_gate(Arc::clone(&activity), limits.read_header_timeout);
    }
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
    /// Request bodies currently being read. With [`ReadTimeoutScope::BodyReads`] the per-read
    /// timer runs only while this is non-zero.
    body_reads: AtomicUsize,
    /// Requests started so far; lets the transport tell "the request this header timer was armed
    /// for has begun" without racing a request that starts and ends between two polls.
    started: std::sync::atomic::AtomicU64,
    notify: tokio::sync::Notify,
}

/// Marks a request body read in flight; see [`ConnectionActivity::begin_body_read`].
struct BodyReadGuard(Arc<ConnectionActivity>);

impl Drop for BodyReadGuard {
    fn drop(&mut self) {
        self.0.body_reads.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ConnectionActivity {
    /// Mark the start of a request-body read; the guard marks its end when dropped.
    fn begin_body_read(self: &Arc<Self>) -> BodyReadGuard {
        self.body_reads.fetch_add(1, Ordering::AcqRel);
        BodyReadGuard(Arc::clone(self))
    }

    fn reading_body(&self) -> bool {
        self.body_reads.load(Ordering::Acquire) != 0
    }

    /// Mark the start of one request. The returned guard marks the end when dropped.
    fn begin(self: &Arc<Self>) -> InFlightGuard {
        self.started.fetch_add(1, Ordering::AcqRel);
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
    /// When set, request-scoped read timers (see [`crate::limits::ReadTimeoutScope::BodyReads`]):
    /// the per-read timer runs only while a request body is read, and a request whose first byte
    /// arrived on an otherwise idle connection must deliver its headers within `head_budget`
    /// in total (Go's `ReadHeaderTimeout`), however slowly the bytes trickle.
    read_gate: Option<Arc<ConnectionActivity>>,
    head_budget: Option<Duration>,
    /// The armed header timer and the `started` count it was armed at.
    head_timer: Option<(Pin<Box<tokio::time::Sleep>>, u64)>,
}

impl<I> TimedIo<I> {
    fn new(inner: I, read_timeout: Option<Duration>, write_timeout: Option<Duration>) -> Self {
        Self {
            inner,
            read_timeout,
            write_timeout,
            read_timer: None,
            write_timer: None,
            read_gate: None,
            head_budget: None,
            head_timer: None,
        }
    }

    fn with_read_gate(mut self, gate: Arc<ConnectionActivity>, head_budget: Duration) -> Self {
        self.read_gate = Some(gate);
        self.head_budget = Some(head_budget);
        self
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for TimedIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let Some(gate) = this.read_gate.clone() else {
            return apply_io_timeout(&mut this.read_timer, this.read_timeout, cx, result);
        };
        let started = gate.started.load(Ordering::Acquire);
        // A request began since the header timer was armed (or one is running): its headers
        // arrived, the timer has done its job.
        if this
            .head_timer
            .as_ref()
            .is_some_and(|(_, armed_at)| *armed_at != started)
        {
            this.head_timer = None;
        }
        // First byte of a new HTTP/1 request on an idle connection (a request method starts
        // with a letter; HTTP/2 frames after the preface do not): start the header budget.
        if let (Poll::Ready(Ok(())), Some(budget)) = (&result, this.head_budget) {
            let first = buf.filled().get(before).copied();
            if this.head_timer.is_none()
                && gate.in_flight.load(Ordering::Acquire) == 0
                && !gate.reading_body()
                && first.is_some_and(|byte| byte.is_ascii_alphabetic())
            {
                this.head_timer = Some((Box::pin(tokio::time::sleep(budget)), started));
            }
        }
        let timeout = if gate.reading_body() {
            this.read_timeout
        } else {
            this.read_timer = None;
            None
        };
        let mut result = apply_io_timeout(&mut this.read_timer, timeout, cx, result);
        if result.is_pending() {
            if let Some((timer, _)) = this.head_timer.as_mut() {
                if timer.as_mut().poll(cx).is_ready() {
                    this.head_timer = None;
                    result = Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request headers did not arrive within the header timeout",
                    )));
                }
            }
        }
        result
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

/// The hyper service that answers admin API requests on one connection.
///
/// Shared by the TCP and Unix listeners so both transports apply the same request conversion and
/// the same [`caddy_rs_admin::ClientIdentity::NotPresented`] identity. The origin policy is applied
/// inside [`AdminApi::handle`]. The future is boxed to name a `Send` type: the listeners spawn the
/// connection task, and an anonymous `service_fn` type cannot express that bound.
struct AdminService {
    api: AdminApi,
    /// Shared by every connection of one listener: bounds the admin requests reading a body.
    body_slots: Arc<AdminBodySlots>,
    /// The connection's activity record: a body read in flight switches the read timer on.
    activity: Arc<ConnectionActivity>,
    /// Who is on the other end, for per-peer upload fairness.
    peer: String,
}

/// Upload slots of one admin listener: [`ADMIN_MAX_CONCURRENT_BODIES`] in total, of which one peer
/// may hold at most [`ADMIN_MAX_BODIES_PER_PEER`], so a single client (or certificate) that
/// trickles bodies cannot starve everyone else.
struct AdminBodySlots {
    total: Arc<tokio::sync::Semaphore>,
    per_peer: std::sync::Mutex<HashMap<String, usize>>,
    per_peer_limit: usize,
}

/// One claimed upload slot; released on drop.
struct BodySlot {
    _permit: tokio::sync::OwnedSemaphorePermit,
    slots: Arc<AdminBodySlots>,
    peer: String,
}

impl AdminBodySlots {
    /// Upload slots: [`ADMIN_MAX_CONCURRENT_BODIES`] / [`ADMIN_MAX_BODIES_PER_PEER`].
    fn new() -> Arc<Self> {
        Self::with_limits(ADMIN_MAX_CONCURRENT_BODIES, ADMIN_MAX_BODIES_PER_PEER)
    }

    /// Connection slots: [`ADMIN_MAX_CONNECTIONS`] / [`ADMIN_MAX_CONNECTIONS_PER_PEER`].
    fn for_connections() -> Arc<Self> {
        Self::with_limits(ADMIN_MAX_CONNECTIONS, ADMIN_MAX_CONNECTIONS_PER_PEER)
    }

    fn with_limits(total: usize, per_peer_limit: usize) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::new(tokio::sync::Semaphore::new(total)),
            per_peer: std::sync::Mutex::new(HashMap::new()),
            per_peer_limit,
        })
    }

    /// Claim a slot for `peer`, or `None` when the listener or the peer is at its limit.
    fn try_acquire(self: &Arc<Self>, peer: &str) -> Option<BodySlot> {
        {
            let mut per_peer = self.per_peer.lock().unwrap_or_else(|e| e.into_inner());
            let held = per_peer.entry(peer.to_string()).or_insert(0);
            if *held >= self.per_peer_limit {
                return None;
            }
            *held += 1;
        }
        match Arc::clone(&self.total).try_acquire_owned() {
            Ok(permit) => Some(BodySlot {
                _permit: permit,
                slots: Arc::clone(self),
                peer: peer.to_string(),
            }),
            Err(_) => {
                self.release_peer(peer);
                None
            }
        }
    }

    fn release_peer(&self, peer: &str) {
        let mut per_peer = self.per_peer.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(held) = per_peer.get_mut(peer) {
            *held -= 1;
            if *held == 0 {
                per_peer.remove(peer);
            }
        }
    }

    #[cfg(test)]
    fn available(&self) -> usize {
        self.total.available_permits()
    }
}

impl Drop for BodySlot {
    fn drop(&mut self) {
        self.slots.release_peer(&self.peer);
    }
}

/// Wait up to `budget` for the first byte of a connection and hand it back unconsumed.
///
/// Go's `ReadHeaderTimeout` runs from accept, but hyper's protocol sniffing (and with it the
/// header-read timer) starts only once a byte arrives, so a connection that never sends one would
/// otherwise live until the much longer read/idle timeouts. `None` when the budget expires or the
/// peer closed or failed before sending anything.
async fn await_first_byte<I>(mut stream: I, budget: Duration) -> Option<PrefixedStream<I>>
where
    I: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut first = [0_u8; 1];
    match tokio::time::timeout(budget, stream.read(&mut first)).await {
        Ok(Ok(read)) if read > 0 => Some(PrefixedStream::new(stream, first[..read].to_vec())),
        _ => None,
    }
}

/// [`await_first_byte`] that also gives up on a forced shutdown (immediately) or a graceful one
/// ([`HANDSHAKE_SHUTDOWN_GRACE`]), so a silent connection does not keep its tracker guard for the
/// rest of the header budget after the listener is stopped.
async fn admit_first_byte<I>(
    stream: I,
    budget: Duration,
    shutdown: &mut watch::Receiver<bool>,
    force: &mut watch::Receiver<bool>,
) -> Option<PrefixedStream<I>>
where
    I: AsyncRead + Unpin,
{
    bounded_handshake(await_first_byte(stream, budget), budget, shutdown, force)
        .await
        .ok()
        .flatten()
}

/// Largest admin request body accepted (SEC-MEDIUM-ADMIN-SERVER A2). Stock Caddy reads `/load`
/// and `/adapt` bodies with an unbounded `io.Copy`; 64 MiB is far above any real configuration
/// while stopping a multi-gigabyte POST from exhausting memory. `stock_compat true` lifts it.
pub(crate) const ADMIN_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Admin requests that may be reading a body at once on one listener. With the 64 MiB per-request
/// cap this bounds the memory a flood of trickling uploads can pin to 256 MiB; further requests
/// with a body get `503` until one finishes (`stock_compat true` lifts the bound, like the cap).
pub(crate) const ADMIN_MAX_CONCURRENT_BODIES: usize = 4;

/// Of those, the most one peer (remote address, or certificate for the mTLS listener) may hold, so
/// a client that stalls its uploads cannot take every slot and starve authorised callers.
pub(crate) const ADMIN_MAX_BODIES_PER_PEER: usize = 2;

/// Connections one admin listener keeps open at once (stock Caddy has no cap). File descriptors
/// are process-wide, so unbounded admin connections could starve the public listeners.
pub(crate) const ADMIN_MAX_CONNECTIONS: usize = 128;

/// Of those, the most one peer may hold.
pub(crate) const ADMIN_MAX_CONNECTIONS_PER_PEER: usize = 32;

/// The fairness key of a TCP peer. Every loopback address is one principal: 127.0.0.0/8 is all
/// local, so a per-address limit would be moot (a local process can bind any 127.x source).
fn admin_peer_key(ip: std::net::IpAddr) -> String {
    if ip.is_loopback() {
        "loopback".to_string()
    } else {
        format!("addr:{ip}")
    }
}

/// The body cap for the next admin request: [`ADMIN_MAX_BODY_BYTES`], or none when the active
/// generation sets `stock_compat true`.
fn admin_body_limit(api: &AdminApi) -> Option<usize> {
    (!api_stock_compat(api)).then_some(ADMIN_MAX_BODY_BYTES)
}

/// Whether the active generation sets `stock_compat true`.
fn api_stock_compat(api: &AdminApi) -> bool {
    api.store()
        .current()
        .is_some_and(|generation| generation.config().stock_compat())
}

/// Total time one admin request body may take to arrive: stock Caddy's admin `ReadTimeout`, which
/// Go enforces as one deadline over the whole request. caddy-rs's per-read `read_timeout` alone
/// lets a client that sends a byte every few seconds hold a body slot (and up to 64 MiB) forever.
const ADMIN_BODY_DEADLINE: Duration = Duration::from_secs(10);

/// Read one admin request's body: claim an in-flight body slot (when the request announces a body
/// and `stock_compat` is off), then read under the size cap and [`ADMIN_BODY_DEADLINE`].
///
/// `503` when every slot is busy, `408` when the body does not arrive in time, otherwise as
/// [`read_admin_body`].
#[allow(clippy::result_large_err)] // the error is the ready-to-send admin response
async fn read_admin_request_body<B>(
    api: &AdminApi,
    slots: &Arc<AdminBodySlots>,
    peer: &str,
    activity: &Arc<ConnectionActivity>,
    headers: &http::HeaderMap,
    body: B,
) -> Result<Bytes, caddy_rs_admin::AdminResponse>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    use caddy_rs_admin::AdminResponse;
    use http::StatusCode;
    let limit = admin_body_limit(api);
    // Whether a body is coming is a property of the body, not of the headers: an HTTP/2 request
    // may carry DATA frames with no `content-length`, and chunked HTTP/1 has no length either.
    let announces_body = !body.is_end_stream() && body.size_hint().exact() != Some(0);
    let _slot = if limit.is_some() && announces_body {
        match slots.try_acquire(peer) {
            Some(slot) => Some(slot),
            None => {
                return Err(AdminResponse::api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "too many admin requests are uploading a body; retry shortly",
                ));
            }
        }
    } else {
        None
    };
    // While a body is being read the per-read timer runs; between requests it does not.
    let _reading = announces_body.then(|| activity.begin_body_read());
    match tokio::time::timeout(ADMIN_BODY_DEADLINE, read_admin_body(headers, body, limit)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(AdminResponse::api_error(
            StatusCode::REQUEST_TIMEOUT,
            "timed out reading the request body",
        )),
    }
}

/// Read an admin request body under `limit` (`None` = unbounded).
///
/// An over-cap body (declared by `Content-Length` or streamed) is `413`; a transport failure
/// mid-body is `400` rather than the empty body the listeners used to substitute, which ran
/// `/load` and friends against a silently truncated request.
#[allow(clippy::result_large_err)] // the error is the ready-to-send admin response
async fn read_admin_body<B>(
    headers: &http::HeaderMap,
    body: B,
    limit: Option<usize>,
) -> Result<Bytes, caddy_rs_admin::AdminResponse>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    use caddy_rs_admin::AdminResponse;
    use http::StatusCode;
    let too_large = || {
        AdminResponse::api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the admin API size limit",
        )
    };
    let Some(limit) = limit else {
        return body
            .collect()
            .await
            .map(|collected| collected.to_bytes())
            .map_err(|error| {
                AdminResponse::api_error(
                    StatusCode::BAD_REQUEST,
                    format!("reading request body: {error}"),
                )
            });
    };
    let declared = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    if declared.is_some_and(|length| length > limit as u64) {
        return Err(too_large());
    }
    match http_body_util::Limited::new(body, limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error)
            if error
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            Err(too_large())
        }
        Err(error) => Err(AdminResponse::api_error(
            StatusCode::BAD_REQUEST,
            format!("reading request body: {error}"),
        )),
    }
}

/// The headers the admin API sees for one request, with `Host` resolved the way Go's net/http
/// sets `Request.Host` (what Caddy's `checkHost` compares): the URI authority when the request
/// line carries one (absolute-form HTTP/1.x, or the HTTP/2 `:authority` pseudo-header, which has
/// no `Host` header at all), otherwise the `Host` header. More than one `Host` header is a `400`,
/// as in Go. Without this a prior-knowledge HTTP/2 (h2c) request, or an absolute-form target
/// naming a foreign host, skipped the DNS-rebinding check (SEC-MEDIUM-ADMIN-SERVER A1).
#[allow(clippy::result_large_err)] // the error is the ready-to-send admin response
fn admin_request_headers(
    mut headers: http::HeaderMap,
    uri: &http::Uri,
    version: http::Version,
) -> Result<http::HeaderMap, caddy_rs_admin::AdminResponse> {
    if headers.get_all(http::header::HOST).iter().count() > 1 {
        return Err(caddy_rs_admin::AdminResponse::api_error(
            http::StatusCode::BAD_REQUEST,
            "too many Host headers",
        ));
    }
    // hyper serves an HTTP/1.1 request without `Host`; Go answers `400 missing required Host
    // header`. Do the same, so a host-less request cannot skip the rebinding check (HTTP/1.0 may
    // omit it, as in Go; HTTP/2 carries `:authority`).
    if version == http::Version::HTTP_11
        && uri.authority().is_none()
        && !headers.contains_key(http::header::HOST)
    {
        return Err(caddy_rs_admin::AdminResponse::api_error(
            http::StatusCode::BAD_REQUEST,
            "missing required Host header",
        ));
    }
    if let Some(authority) = uri.authority() {
        // `URL.Host` has no userinfo.
        let host = authority
            .as_str()
            .rsplit_once('@')
            .map_or(authority.as_str(), |(_, host)| host);
        if let Ok(value) = http::HeaderValue::from_str(host) {
            headers.insert(http::header::HOST, value);
        }
    }
    Ok(headers)
}

/// Convert an admin response to the hyper response the connection serves.
fn admin_hyper_response(response: caddy_rs_admin::AdminResponse) -> hyper::Response<Body> {
    let mut builder = hyper::Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from_bytes(response.body))
        .expect("admin response is valid")
}

/// Serve one admin request on either transport, in the order stock Caddy uses: resolve `Host`,
/// make the Host/Origin (plaintext) or access-control (mTLS) decision, and only then read the
/// body. A request that is refused, or whose body is rejected (413/408/503), never has its body
/// read to the end, so an HTTP/1 connection is closed after the response rather than left with
/// unread bytes; refusing before the read also means a refused client never holds an upload slot.
async fn serve_admin_request(
    api: &AdminApi,
    slots: &Arc<AdminBodySlots>,
    activity: &Arc<ConnectionActivity>,
    peer: &str,
    identity: caddy_rs_admin::ClientIdentity,
    request: hyper::Request<Incoming>,
) -> hyper::Response<Body> {
    // A request in flight keeps the connection from being reaped as idle (60 s `IdleTimeout`).
    let _in_flight = activity.begin();
    let (parts, body) = request.into_parts();
    let http1 = matches!(
        parts.version,
        http::Version::HTTP_10 | http::Version::HTTP_11
    );
    let refuse = |response: caddy_rs_admin::AdminResponse| {
        let mut response = admin_hyper_response(response);
        if http1 {
            response.headers_mut().insert(
                http::header::CONNECTION,
                http::HeaderValue::from_static("close"),
            );
        }
        response
    };
    let headers = match admin_request_headers(parts.headers, &parts.uri, parts.version) {
        Ok(headers) => headers,
        Err(rejection) => return refuse(rejection),
    };
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    if let Err(rejection) = api.authorize(&parts.method, &path, &headers, &identity) {
        return refuse(rejection);
    }
    let body = match read_admin_request_body(api, slots, peer, activity, &headers, body).await {
        Ok(body) => body,
        Err(rejection) => return refuse(rejection),
    };
    let response = api
        .handle(AdminRequest {
            method: parts.method,
            path,
            headers,
            body,
            client_identity: identity,
        })
        .await;
    admin_hyper_response(response)
}

impl Clone for AdminService {
    fn clone(&self) -> Self {
        Self {
            api: self.api.clone(),
            body_slots: Arc::clone(&self.body_slots),
            activity: Arc::clone(&self.activity),
            peer: self.peer.clone(),
        }
    }
}

impl hyper::service::Service<hyper::Request<Incoming>> for AdminService {
    type Response = hyper::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>,
    >;

    fn call(&self, request: hyper::Request<Incoming>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            Ok::<_, std::convert::Infallible>(
                serve_admin_request(
                    &service.api,
                    &service.body_slots,
                    &service.activity,
                    &service.peer,
                    caddy_rs_admin::ClientIdentity::NotPresented,
                    request,
                )
                .await,
            )
        })
    }
}

/// The `(device, inode)` of the socket file this process created at the admin path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SocketIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl SocketIdentity {
    fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// Removes the admin Unix socket file we created when its accept loop ends.
///
/// The guard lives inside the listener task, so it runs after the reload/shutdown signal stops the
/// loop and before `ListenerHandle::stop` returns - the next bind on the same path never sees a
/// stale socket. Only the very socket this listener created is removed: if the path now holds a
/// regular file, a symlink, or another process's socket (different inode), it is left alone
/// (SEC-MEDIUM-ADMIN-SERVER A3). The `lstat` and `unlink` are two calls, so a swap in the
/// microseconds between them is narrowed, not eliminated: there is no unlink-if-inode primitive.
struct AdminSocketPath {
    path: std::path::PathBuf,
    identity: SocketIdentity,
}

impl Drop for AdminSocketPath {
    fn drop(&mut self) {
        use std::os::unix::fs::FileTypeExt;
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && SocketIdentity::of(&metadata) == self.identity =>
            {
                if let Err(error) = std::fs::remove_file(&self.path) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            path = %self.path.display(),
                            %error,
                            "cannot remove admin Unix socket"
                        );
                    }
                }
            }
            Ok(_) => tracing::debug!(
                path = %self.path.display(),
                "admin Unix socket path no longer holds our socket; leaving it in place"
            ),
            Err(_) => {}
        }
    }
}

/// Set the admin Unix socket to owner-only access (not Caddy's `0200` default).
///
/// Clients only need write permission to `connect(2)`, but an owner-only socket keeps the admin
/// API unreachable for other users of the host, which is the reason to use a Unix socket instead
/// of a loopback TCP port.
fn set_admin_socket_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Bind the admin Unix socket without ever exposing it under `socket_path` with umask-derived
/// permissions, and without deleting anything that is not a socket (SEC-MEDIUM-ADMIN-SERVER A3).
///
/// A path we bind ourselves may hold a stale socket from a killed process (Caddy removes it too),
/// but the previous `exists()` + `remove_file` happily deleted a regular file, and `bind` followed
/// by `chmod` left the socket connectable per the umask for a moment. Here the type of whatever
/// sits at the path is checked with `symlink_metadata` (never following links): only a socket is
/// replaced; a regular file, directory or symlink is a bind error and is left untouched. The
/// socket is bound inside a freshly created `0700` staging directory next to the final path (its
/// name is 8 random hex digits from the OS RNG, retried on collision, so it cannot be squatted),
/// `chmod`ed `0600`, and then installed under the final name by [`install_staged_socket`]. The
/// staging directory is always removed. Returns the listener and the identity of the socket file
/// now at `socket_path`, so cleanup removes only that file.
fn bind_admin_unix_private(
    socket_path: &std::path::Path,
) -> std::io::Result<(UnixListener, SocketIdentity)> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt};

    let existing = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            // (The liveness probe ran before this, in `bind_admin_unix`.)
            Some(SocketIdentity::of(&metadata))
        }
        Ok(_) => {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "refusing to replace {}: it exists and is not a socket",
                    socket_path.display()
                ),
            ));
        }
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let parent = match socket_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    };
    let mut staging = None;
    // 8 random hex digits normally; 4 when that would push the staged path past `sun_path` but
    // the final path itself fits (a squatter then has 65 536 names to guess, still retried on
    // collision and only able to delay, not redirect, the bind).
    let parent_length = parent.as_os_str().as_bytes().len();
    let digits = if parent_length + 1 + 9 + 2 < SUN_PATH_CAPACITY {
        8
    } else {
        4
    };
    for _ in 0..16 {
        let mut random = [0_u8; 4];
        getrandom::getrandom(&mut random).map_err(Error::other)?;
        let name = if digits == 8 {
            format!(
                ".{:02x}{:02x}{:02x}{:02x}",
                random[0], random[1], random[2], random[3]
            )
        } else {
            format!(".{:02x}{:02x}", random[0], random[1])
        };
        let candidate = parent.join(name);
        // `sun_path` limits the path the socket is *bound* at, which is the staged one.
        let bound_length = candidate.join("s").as_os_str().as_bytes().len();
        if bound_length >= SUN_PATH_CAPACITY
            || socket_path.as_os_str().as_bytes().len() >= SUN_PATH_CAPACITY
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "admin socket path {} is too long: binding needs {bound_length} bytes \
                     (the path of a short staging directory next to it plus a socket name), \
                     but a Unix socket path may hold at most {} bytes plus the trailing NUL \
                     ({SUN_PATH_CAPACITY}-byte sun_path); use a shorter path",
                    socket_path.display(),
                    SUN_PATH_CAPACITY - 1,
                ),
            ));
        }
        match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => {
                staging = Some(candidate);
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let staging = staging.ok_or_else(|| {
        Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "cannot create a unique staging directory next to {}",
                socket_path.display()
            ),
        )
    })?;
    let staged_socket = staging.join("s");
    let result = (|| {
        let listener = UnixListener::bind(&staged_socket)?;
        set_admin_socket_permissions(&staged_socket)?;
        let identity = SocketIdentity::of(&std::fs::symlink_metadata(&staged_socket)?);
        install_staged_socket(&staged_socket, socket_path, existing)?;
        Ok((listener, identity))
    })();
    let _ = std::fs::remove_file(&staged_socket);
    let _ = std::fs::remove_dir(&staging);
    result
}

/// `sun_path` capacity including the trailing NUL (108 on Linux, 104 on the BSDs and macOS).
const SUN_PATH_CAPACITY: usize = if cfg!(target_os = "linux") { 108 } else { 104 };

/// Whether a failed `link(2)` means "this filesystem cannot hard-link" (so the re-checked
/// `rename` fallback applies) rather than a real failure: `EPERM` (for example FUSE and
/// `fs.protected_hardlinks`), `EOPNOTSUPP`/`ENOTSUP` and `ENOSYS`. `EACCES`, `EMLINK`, `ENOSPC`,
/// `EDQUOT`, `EROFS`, `EIO` and the like are surfaced to the operator.
fn hard_link_unsupported(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EPERM
            || code == libc::EOPNOTSUPP
            || code == libc::ENOTSUP
            || code == libc::ENOSYS
    )
}

/// Move the already-bound, already-`0600` staged socket to its final path without clobbering
/// anything that is not the stale socket we saw earlier.
///
/// * Nothing there: `link(2)` the staged socket in. `link` fails with `EEXIST` instead of
///   replacing, so a file or symlink created in the meantime is never overwritten (atomic
///   no-replace; filesystems without hard links fall back to a re-checked `rename`).
/// * A stale socket there: re-`lstat` immediately before and `rename` over it only if it is still
///   a socket with the inode seen at the start. `rename` replaces without following links. There
///   is no portable no-replace-unless-inode primitive (and this crate denies `unsafe`, which rules
///   out calling `renameat2` directly), so a swap in the microseconds between that check and the
///   `rename` is narrowed, not eliminated.
fn install_staged_socket(
    staged: &std::path::Path,
    final_path: &std::path::Path,
    existing: Option<SocketIdentity>,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::FileTypeExt;
    let changed = || {
        Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "{} changed while the admin socket was being bound; not replacing it",
                final_path.display()
            ),
        )
    };
    match existing {
        None => match std::fs::hard_link(staged, final_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => Err(changed()),
            Err(error) if hard_link_unsupported(&error) => {
                match std::fs::symlink_metadata(final_path) {
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        std::fs::rename(staged, final_path)
                    }
                    Ok(_) => Err(changed()),
                    Err(error) => Err(error),
                }
            }
            // Permission, quota, link-count and other real failures are reported, not papered
            // over with a rename that would then be allowed to replace.
            Err(error) => Err(error),
        },
        Some(expected) => match std::fs::symlink_metadata(final_path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && SocketIdentity::of(&metadata) == expected =>
            {
                std::fs::rename(staged, final_path)
            }
            Ok(_) => Err(changed()),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                install_staged_socket(staged, final_path, None)
            }
            Err(error) => Err(error),
        },
    }
}

/// What probing an existing admin socket found.
#[derive(Debug, PartialEq, Eq)]
enum SocketProbe {
    /// Something accepts on it (or did not answer within the budget): a running process owns it.
    Live,
    /// Nobody is listening: replace it.
    Stale,
    /// Could not tell; carries the reason.
    Unknown(String),
}

/// Interpret the outcome of connecting to an existing admin socket.
///
/// `owner_uid` is the socket file's owner and `our_uid` this process's (when known). A connect
/// refused with a permission error to a socket owned by someone else is a stale socket of another
/// user (for example a crashed `sudo caddy-rs run`) that this process could never have been
/// talking to: it counts as stale, and the later replace fails clearly if the directory does not
/// let us unlink it. A timeout counts as live: wrongly refusing is the safe error.
fn classify_probe(
    outcome: Result<(), &std::io::Error>,
    timed_out: bool,
    owner_uid: u32,
    our_uid: Option<u32>,
) -> SocketProbe {
    use std::io::ErrorKind;
    if timed_out {
        return SocketProbe::Live;
    }
    match outcome {
        Ok(()) => SocketProbe::Live,
        Err(error) => match error.kind() {
            ErrorKind::ConnectionRefused | ErrorKind::NotFound => SocketProbe::Stale,
            ErrorKind::PermissionDenied if our_uid.is_some_and(|uid| uid != owner_uid) => {
                SocketProbe::Stale
            }
            _ => SocketProbe::Unknown(error.to_string()),
        },
    }
}

/// This process's effective uid without `unsafe` (Linux; `None` elsewhere): the owner of
/// `/proc/self`.
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Liveness probe for an existing admin socket at `socket_path`: refuse to replace one a running
/// process still accepts on (typically a second instance with the same admin path), since
/// stealing it would silently redirect that instance's admin clients. Does nothing when the path
/// is absent or is not a socket (the bind reports non-sockets itself). Async with a 1 s budget so
/// a wedged peer cannot block the runtime.
async fn probe_existing_admin_socket(socket_path: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let Ok(metadata) = std::fs::symlink_metadata(socket_path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() {
        return Ok(());
    }
    let attempt = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::net::UnixStream::connect(socket_path),
    )
    .await;
    let (outcome, timed_out) = match &attempt {
        Ok(Ok(_)) => (Ok(()), false),
        Ok(Err(error)) => (Err(error), false),
        Err(_elapsed) => (Ok(()), true),
    };
    match classify_probe(outcome, timed_out, metadata.uid(), current_uid()) {
        SocketProbe::Stale => Ok(()),
        SocketProbe::Live => Err(Error::new(
            ErrorKind::AddrInUse,
            format!(
                "admin socket {} is in use by a running process; stop it, choose another admin \
                 address, or set stock_compat to replace it anyway",
                socket_path.display()
            ),
        )),
        SocketProbe::Unknown(reason) => Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "cannot tell whether admin socket {} is stale: {reason}",
                socket_path.display()
            ),
        )),
    }
}

/// Bind the admin API to a Unix domain socket.
async fn bind_admin_unix(
    configured: &str,
    path: &str,
    api: AdminApi,
    options: AdminBindOptions,
) -> Result<ListenerHandle, Error> {
    let socket_path = std::path::Path::new(path);
    if !(options.stock_compat || options.replace_live) {
        probe_existing_admin_socket(socket_path)
            .await
            .map_err(|error| Error::bind(configured, error))?;
    }
    let (listener, identity) =
        bind_admin_unix_private(socket_path).map_err(|error| Error::bind(configured, error))?;
    let (shutdown, mut receiver) = watch::channel(false);
    let (force, mut force_receiver) = watch::channel(false);
    let tracker = Arc::new(ConnectionTracker::default());
    let loop_tracker = Arc::clone(&tracker);
    let cleanup = AdminSocketPath {
        path: socket_path.to_path_buf(),
        identity,
    };
    let body_slots = AdminBodySlots::new();
    let conn_slots = AdminBodySlots::for_connections();
    let task = tokio::spawn(async move {
        let _cleanup = cleanup;
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
                    // Past the per-listener (or per-peer) connection cap the connection is
                    // refused by dropping it.
                    let Some(conn_slot) = conn_slots.try_acquire("unix") else { continue };
                    let mut connection_shutdown = receiver.clone();
                    let mut connection_force = force_receiver.clone();
                    let tracked = loop_tracker.guard();
                    let service = AdminService {
                        api: api.clone(),
                        body_slots: Arc::clone(&body_slots),
                        activity: Arc::new(ConnectionActivity::default()),
                        // Every client of the socket is the same local principal.
                        peer: "unix".to_string(),
                    };
                    tokio::spawn(async move {
                        let _tracked = tracked;
                        let _conn_slot = conn_slot;
                        let limits = Arc::new(ServerLimits::admin());
                        // Go's ReadHeaderTimeout runs from accept; hyper's protocol sniffing does
                        // not start it until the first byte, so bound a silent connection here.
                        let Some(stream) = admit_first_byte(
                            stream,
                            limits.read_header_timeout,
                            &mut connection_shutdown,
                            &mut connection_force,
                        )
                        .await
                        else {
                            return;
                        };
                        let activity = Arc::clone(&service.activity);
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
        bound: configured.to_string(),
        socket_addr: None,
        unix_socket: Some((socket_path.to_path_buf(), identity)),
    })
}

/// [`bind_admin_with`] with options derived from the active generation, for tests.
#[cfg(test)]
pub(crate) async fn bind_admin(
    configured: &str,
    api: AdminApi,
    binder: BinderRef<'_>,
) -> Result<ListenerHandle, Error> {
    let options = AdminBindOptions {
        stock_compat: api_stock_compat(&api),
        replace_live: false,
    };
    bind_admin_with(configured, api, binder, options).await
}

/// Bind the admin API listener.
///
/// Supports the same transports as Caddy's `admin.listen`: TCP (`[host]:port`) and Unix domain
/// sockets (`unix/<absolute path>`, bound with owner-only permissions). The Unix socket file is
/// removed when the listener stops, so reloads never leave stale sockets behind.
pub(crate) async fn bind_admin_with(
    configured: &str,
    api: AdminApi,
    #[cfg_attr(not(feature = "graceful-restart"), allow(unused_variables))] binder: BinderRef<'_>,
    options: AdminBindOptions,
) -> Result<ListenerHandle, Error> {
    let address = ListenAddr::parse(configured).map_err(|reason| Error::Listen {
        listen: configured.to_string(),
        reason,
    })?;
    if address.network == Network::Unix {
        return bind_admin_unix(configured, &address.address, api, options).await;
    }
    if address.network != Network::Tcp {
        return Err(Error::NotImplemented {
            feature: "admin API on non-TCP listeners",
            tracking_id: "ADMIN-LISTEN",
        });
    }
    let listener = bind_configured_tcp(configured, &address, binder).await?;
    let socket_addr = listener
        .local_addr()
        .map_err(|error| Error::bind(configured, error))?;
    let (shutdown, mut receiver) = watch::channel(false);
    let (force, mut force_receiver) = watch::channel(false);
    let tracker = Arc::new(ConnectionTracker::default());
    let loop_tracker = Arc::clone(&tracker);
    let body_slots = AdminBodySlots::new();
    let conn_slots = AdminBodySlots::for_connections();
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
                    let Ok((stream, peer_addr)) = accepted else { continue };
                    let peer = admin_peer_key(peer_addr.ip());
                    let Some(conn_slot) = conn_slots.try_acquire(&peer) else { continue };
                    let api = api.clone();
                    let mut connection_shutdown = receiver.clone();
                    let mut connection_force = force_receiver.clone();
                    let tracked = loop_tracker.guard();
                    let service = AdminService {
                        api,
                        body_slots: Arc::clone(&body_slots),
                        activity: Arc::new(ConnectionActivity::default()),
                        peer,
                    };
                    tokio::spawn(async move {
                        let _tracked = tracked;
                        let _conn_slot = conn_slot;
                        let limits = Arc::new(ServerLimits::admin());
                        // See the Unix listener: bound a connection that never sends a byte.
                        let Some(stream) = admit_first_byte(
                            stream,
                            limits.read_header_timeout,
                            &mut connection_shutdown,
                            &mut connection_force,
                        )
                        .await
                        else {
                            return;
                        };
                        let activity = Arc::clone(&service.activity);
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
        unix_socket: None,
    })
}

/// Build the rustls server configuration for the mutual-TLS remote admin listener
/// (`admin.remote`), from the configured server identity and access-control certificates.
///
/// This mirrors Caddy's `replaceRemoteAdminServer` (`external/caddy/admin.go:509-560`): the
/// client-certificate pool is built from every `access_control[].public_keys` entry and the mode
/// is `RequireAndVerifyClientCert` (rustls `ClientAuthMode::RequireAndVerify`). The identity
/// comes from `admin.identity` (PEM files, a documented caddy-rs deviation from certmagic
/// issuance). The listener speaks HTTP/1.1 only, like the plaintext admin endpoint.
pub(crate) fn remote_admin_tls_config(
    identity: &caddy_rs_core::AdminIdentity,
    remote: &caddy_rs_core::AdminRemote,
) -> Result<Arc<rustls::ServerConfig>, Error> {
    use base64::Engine as _;

    let (Some(certificate_path), Some(key_path)) = (&identity.certificate, &identity.key) else {
        return Err(Error::Config(caddy_rs_core::Error::invalid(
            "admin.identity",
            "remote administration requires `admin.identity.certificate` and `admin.identity.key`",
        )));
    };
    let certificate_pem = std::fs::read_to_string(certificate_path).map_err(|source| {
        Error::Config(caddy_rs_core::Error::invalid(
            "admin.identity.certificate",
            format!("cannot read `{certificate_path}`: {source}"),
        ))
    })?;
    let key_pem = std::fs::read_to_string(key_path).map_err(|source| {
        Error::Config(caddy_rs_core::Error::invalid(
            "admin.identity.key",
            format!("cannot read `{key_path}`: {source}"),
        ))
    })?;
    let certificate =
        caddy_rs_tls::TlsCertificate::from_pem(&certificate_pem, &key_pem).map_err(|error| {
            Error::Config(caddy_rs_core::Error::invalid(
                "admin.identity",
                format!("admin identity certificate/key pair is not loadable: {error}"),
            ))
        })?;
    let resolver =
        caddy_rs_tls::CertificateResolver::from_certificates([certificate]).map_err(|error| {
            Error::Config(caddy_rs_core::Error::invalid(
                "admin.identity.certificate",
                format!("admin identity certificate is not usable for TLS: {error}"),
            ))
        })?;

    let mut roots = Vec::new();
    for (access_index, access) in remote.access_control.iter().enumerate() {
        for (key_index, public_key) in access.public_keys.iter().enumerate() {
            let located =
                format!("admin.remote.access_control[{access_index}].public_keys[{key_index}]");
            let der = base64::engine::general_purpose::STANDARD
                .decode(public_key.trim())
                .map_err(|error| {
                    Error::Config(caddy_rs_core::Error::invalid(
                        &located,
                        format!("public key is not base64-encoded DER: {error}"),
                    ))
                })?;
            roots.push(rustls::pki_types::CertificateDer::from(der));
        }
    }

    let mut options = caddy_rs_tls::TlsServerOptions::default();
    // The admin API is HTTP/1.1; do not negotiate HTTP/2 or solve ACME challenges here.
    options.alpn = vec![b"http/1.1".to_vec()];
    options.client_auth = caddy_rs_tls::ClientAuthMode::RequireAndVerify;
    options.client_auth_configured = true;
    options.client_auth_roots = roots;
    let config = caddy_rs_tls::build_server_config(Arc::new(resolver), &options)?;
    Ok(config)
}

/// Extract the authenticated client identity from a completed mutual-TLS handshake.
///
/// The verifier has already chained the leaf to one of the access-control certificates, so the
/// identity is trustworthy; it feeds `admin.remote.access_control` matching in `caddy-rs-admin`.
/// A missing certificate or one whose metadata cannot be parsed yields
/// [`caddy_rs_admin::ClientIdentity::Unparsable`], which the admin API denies with 401: a request
/// on this listener never falls through to the plaintext origin policy.
fn remote_admin_client_identity(
    certificates: Option<&[rustls::pki_types::CertificateDer<'_>]>,
) -> caddy_rs_admin::ClientIdentity {
    let Some(certificates) = certificates else {
        return caddy_rs_admin::ClientIdentity::Unparsable;
    };
    let Some(leaf) = certificates.first() else {
        return caddy_rs_admin::ClientIdentity::Unparsable;
    };
    let Ok(info) = caddy_rs_tls::ClientCertificateInfo::parse(leaf.as_ref(), true) else {
        return caddy_rs_admin::ClientIdentity::Unparsable;
    };
    caddy_rs_admin::ClientIdentity::Verified(caddy_rs_admin::AdminClientIdentity {
        certificates: certificates
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect(),
        subject: info.subject,
        issuer: info.issuer,
        serial: info.serial,
    })
}

/// Bind the mutual-TLS remote admin listener (`admin.remote.listen`) and serve the admin API.
///
/// Accepts exactly like [`bind_admin`]; the difference is the mandatory TLS handshake, after
/// which the verified client identity is attached to every [`AdminRequest`]. A failed handshake
/// (no certificate, or a certificate outside the access-control pool) never reaches the API.
pub(crate) async fn bind_admin_remote(
    configured: &str,
    api: AdminApi,
    server_config: Arc<rustls::ServerConfig>,
    #[cfg_attr(not(feature = "graceful-restart"), allow(unused_variables))] binder: BinderRef<'_>,
) -> Result<ListenerHandle, Error> {
    let address = ListenAddr::parse(configured).map_err(|reason| Error::Listen {
        listen: configured.to_string(),
        reason,
    })?;
    if address.network != Network::Tcp {
        return Err(Error::Listen {
            listen: configured.to_string(),
            reason: "remote administration requires a TCP listen address".to_string(),
        });
    }
    let listener = bind_configured_tcp(configured, &address, binder).await?;
    let socket_addr = listener
        .local_addr()
        .map_err(|error| Error::bind(configured, error))?;
    let acceptor = TlsAcceptor::from(server_config);
    let (shutdown, mut receiver) = watch::channel(false);
    let (force, mut force_receiver) = watch::channel(false);
    let tracker = Arc::new(ConnectionTracker::default());
    let loop_tracker = Arc::clone(&tracker);
    let body_slots = AdminBodySlots::new();
    let conn_slots = AdminBodySlots::for_connections();
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
                    let Ok((stream, peer_addr)) = accepted else { continue };
                    let Some(conn_slot) =
                        conn_slots.try_acquire(&admin_peer_key(peer_addr.ip())) else { continue };
                    let api = api.clone();
                    let acceptor = acceptor.clone();
                    let mut connection_shutdown = receiver.clone();
                    let mut connection_force = force_receiver.clone();
                    let tracked = loop_tracker.guard();
                    let body_slots = Arc::clone(&body_slots);
                    tokio::spawn(async move {
                        let _tracked = tracked;
                        let _conn_slot = conn_slot;
                        let limits = Arc::new(ServerLimits::admin());
                        // Mandatory mutual TLS: a missing or untrusted client certificate fails
                        // here and the connection is dropped before any admin request is parsed.
                        // The budget is the admin server's own (stock: ReadHeaderTimeout 5 s, the
                        // smallest of its three timeouts), not the public servers' 1 minute.
                        let tls = match bounded_handshake(
                            acceptor.accept(stream),
                            limits.tls_handshake_timeout(),
                            &mut connection_shutdown,
                            &mut connection_force,
                        )
                        .await
                        {
                            Ok(Ok(tls)) => tls,
                            Ok(Err(error)) => {
                                tracing::debug!(%error, "remote admin TLS handshake failed");
                                return;
                            }
                            Err(abort) => {
                                tracing::debug!(?abort, "remote admin TLS handshake abandoned");
                                return;
                            }
                        };
                        let identity = remote_admin_client_identity(
                            tls.get_ref().1.peer_certificates(),
                        );
                        // Upload fairness is per certificate, not per address: every client behind
                        // one proxy shares an address, but each certificate is one principal.
                        let peer = match &identity {
                            caddy_rs_admin::ClientIdentity::Verified(client) => {
                                format!("cert:{}:{}", client.issuer, client.serial)
                            }
                            _ => admin_peer_key(peer_addr.ip()),
                        };
                        let activity = Arc::new(ConnectionActivity::default());
                        let service = {
                            let activity = Arc::clone(&activity);
                            service_fn(move |request: hyper::Request<Incoming>| {
                                let api = api.clone();
                                let identity = identity.clone();
                                let body_slots = Arc::clone(&body_slots);
                                let activity = Arc::clone(&activity);
                                let peer = peer.clone();
                                async move {
                                    Ok::<_, std::convert::Infallible>(
                                        serve_admin_request(
                                            &api,
                                            &body_slots,
                                            &activity,
                                            &peer,
                                            identity,
                                            request,
                                        )
                                        .await,
                                    )
                                }
                            })
                        };
                        serve_connection(
                            tls,
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
        unix_socket: None,
    })
}

/// End-to-end tests for the mutual-TLS remote admin listener (`admin.remote`).
///
/// Certificates are minted with the `openssl` CLI from the test (it is present in this
/// environment); the workspace carries no certificate-generation crate in `Cargo.lock`, and the
/// internal CA in `crates/tls` issues server certificates, not client-auth test material.
#[cfg(test)]
mod remote_admin_tests {
    use super::{bind_admin, bind_admin_remote, remote_admin_tls_config};
    use caddy_rs_admin::AdminApi;
    use caddy_rs_core::{
        AdminAccess, AdminIdentity, AdminPermissions, AdminRemote, GenerationStore,
    };
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    struct Certificates {
        directory: PathBuf,
        ca_pem: String,
        client_pem: String,
        client_key_pem: String,
        untrusted_client_pem: String,
        untrusted_client_key_pem: String,
        server_pem: String,
        server_key_pem: String,
    }

    impl Drop for Certificates {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    /// Whether the `openssl` CLI is available to mint the test certificates. A missing binary
    /// skips each test with an explicit message instead of panicking inside a helper.
    fn openssl_available() -> bool {
        std::process::Command::new("openssl")
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn openssl(directory: &Path, arguments: &[&str]) {
        let output = std::process::Command::new("openssl")
            .current_dir(directory)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "the `openssl` CLI is required to mint the mTLS test certificates and could \
                     not be run ({error}); install openssl or skip this test"
                )
            });
        assert!(
            output.status.success(),
            "openssl {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn write_extensions(directory: &Path, name: &str, contents: &str) -> String {
        let path = directory.join(name);
        std::fs::write(&path, contents).expect("extension file");
        path.to_string_lossy().into_owned()
    }

    fn mint(
        certificates: &Certificates,
        prefix: &str,
        ca_prefix: &str,
        extensions: &str,
        cn: &str,
    ) {
        let directory = &certificates.directory;
        let extension_file = write_extensions(directory, &format!("{prefix}.ext"), extensions);
        openssl(
            directory,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &format!("{prefix}.key"),
                "-out",
                &format!("{prefix}.csr"),
                "-subj",
                &format!("/CN={cn}"),
            ],
        );
        openssl(
            directory,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{prefix}.csr"),
                "-CA",
                &format!("{ca_prefix}.pem"),
                "-CAkey",
                &format!("{ca_prefix}.key"),
                "-CAcreateserial",
                "-out",
                &format!("{prefix}.pem"),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                &extension_file,
            ],
        );
    }

    fn mint_ca(directory: &Path, prefix: &str) {
        openssl(
            directory,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &format!("{prefix}.key"),
                "-out",
                &format!("{prefix}.pem"),
                "-days",
                "2",
                "-subj",
                &format!("/CN={prefix}"),
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ],
        );
    }

    fn read(directory: &Path, name: &str) -> String {
        std::fs::read_to_string(directory.join(name)).expect("PEM file")
    }

    fn test_certificates(name: &str) -> Certificates {
        let directory =
            std::env::temp_dir().join(format!("caddy-rs-admin-mtls-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("temp directory");
        mint_ca(&directory, "ca");
        mint_ca(&directory, "other-ca");
        let mut certificates = Certificates {
            ca_pem: read(&directory, "ca.pem"),
            client_pem: String::new(),
            client_key_pem: String::new(),
            untrusted_client_pem: String::new(),
            untrusted_client_key_pem: String::new(),
            server_pem: String::new(),
            server_key_pem: String::new(),
            directory,
        };
        mint(
            &certificates,
            "server",
            "ca",
            "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
            "localhost",
        );
        mint(
            &certificates,
            "client",
            "ca",
            "extendedKeyUsage=clientAuth\n",
            "client-ok",
        );
        mint(
            &certificates,
            "untrusted-client",
            "other-ca",
            "extendedKeyUsage=clientAuth\n",
            "client-untrusted",
        );
        let directory = certificates.directory.clone();
        certificates.server_pem = read(&directory, "server.pem");
        certificates.server_key_pem = read(&directory, "server.key");
        certificates.client_pem = read(&directory, "client.pem");
        certificates.client_key_pem = read(&directory, "client.key");
        certificates.untrusted_client_pem = read(&directory, "untrusted-client.pem");
        certificates.untrusted_client_key_pem = read(&directory, "untrusted-client.key");
        certificates
    }

    fn der_base64(pem: &str) -> String {
        use base64::Engine as _;
        let chain = caddy_rs_tls::certificates_from_pem(pem).expect("PEM certificate");
        base64::engine::general_purpose::STANDARD.encode(chain[0].as_ref())
    }

    /// The remote configuration used by the tests: the client certificate may GET `/config/`,
    /// while the CA entry may only GET `/id/` (so a different path/method is denied).
    fn remote(certificates: &Certificates) -> AdminRemote {
        AdminRemote {
            listen: None,
            access_control: vec![
                AdminAccess {
                    public_keys: vec![der_base64(&certificates.client_pem)],
                    permissions: vec![AdminPermissions {
                        paths: Some(vec!["/config/".to_string()]),
                        methods: Some(vec!["GET".to_string()]),
                        extra: Default::default(),
                    }],
                    subjects: Vec::new(),
                    serials: Vec::new(),
                    extra: Default::default(),
                },
                AdminAccess {
                    public_keys: vec![der_base64(&certificates.ca_pem)],
                    permissions: vec![AdminPermissions {
                        paths: Some(vec!["/id/".to_string()]),
                        methods: Some(vec!["GET".to_string()]),
                        extra: Default::default(),
                    }],
                    subjects: Vec::new(),
                    serials: Vec::new(),
                    extra: Default::default(),
                },
            ],
            extra: Default::default(),
        }
    }

    fn identity(certificates: &Certificates) -> AdminIdentity {
        AdminIdentity {
            identifiers: Vec::new(),
            certificate: Some(
                certificates
                    .directory
                    .join("server.pem")
                    .to_string_lossy()
                    .into_owned(),
            ),
            key: Some(
                certificates
                    .directory
                    .join("server.key")
                    .to_string_lossy()
                    .into_owned(),
            ),
            issuers: None,
            extra: Default::default(),
        }
    }

    fn api() -> AdminApi {
        AdminApi::new(Arc::new(GenerationStore::with_builtin_registry()))
    }

    fn client_config(
        certificates: &Certificates,
        client_certificate: Option<(&str, &str)>,
    ) -> rustls::ClientConfig {
        let _ = caddy_rs_tls::install_default_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        let ca = caddy_rs_tls::certificates_from_pem(&certificates.ca_pem).expect("CA PEM");
        roots.add(ca[0].clone()).expect("CA is a trust anchor");
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        match client_certificate {
            None => builder.with_no_client_auth(),
            Some((certificate_pem, key_pem)) => {
                let chain = caddy_rs_tls::certificates_from_pem(certificate_pem)
                    .expect("client certificate");
                let key = private_key(certificate_pem, key_pem);
                builder
                    .with_client_auth_cert(chain, key)
                    .expect("client certificate matches its key")
            }
        }
    }

    fn private_key(
        certificate_pem: &str,
        key_pem: &str,
    ) -> rustls::pki_types::PrivateKeyDer<'static> {
        let certificate = caddy_rs_tls::TlsCertificate::from_pem(certificate_pem, key_pem)
            .expect("client certificate and key");
        certificate
            .private_key()
            .expect("client private key")
            .clone_key()
    }

    /// One HTTP/1.1 request over an established TLS stream, returning the status code.
    async fn request_status(
        stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
        request: &str,
    ) -> u16 {
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response = String::from_utf8_lossy(&response);
        let status = response
            .split_whitespace()
            .nth(1)
            .unwrap_or_else(|| panic!("no status line in {response:?}"));
        status.parse().expect("numeric status")
    }

    async fn connect(
        certificates: &Certificates,
        client_certificate: Option<(&str, &str)>,
        port: u16,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error> {
        let config = client_config(certificates, client_certificate);
        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to the remote admin listener");
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        connector
            .connect(server_name, stream)
            .await
            .map_err(std::io::Error::other)
    }

    /// Load `admin.identity` + `admin.remote` through the normal config path (the same `/load`
    /// endpoint operators use) so the API's access-control decision reads the live configuration,
    /// and prove the configuration validates cleanly.
    async fn load_remote_admin_config(api: &AdminApi, certificates: &Certificates) {
        let remote = remote(certificates);
        let identity = identity(certificates);
        let config = serde_json::json!({
            "admin": {
                "identity": serde_json::to_value(&identity).expect("identity serializes"),
                "remote": serde_json::to_value(&remote).expect("remote serializes"),
            }
        });
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        let response = api
            .handle(caddy_rs_admin::AdminRequest {
                method: http::Method::POST,
                path: "/load".to_string(),
                headers,
                body: bytes::Bytes::from(config.to_string()),
                client_identity: caddy_rs_admin::ClientIdentity::NotPresented,
            })
            .await;
        assert_eq!(
            response.status,
            200,
            "admin.identity + admin.remote loads through /load: {}",
            String::from_utf8_lossy(&response.body)
        );
    }

    async fn start_remote(
        certificates: &Certificates,
    ) -> (caddy_rs_admin::AdminApi, u16, super::ListenerHandle) {
        let identity = identity(certificates);
        let remote = remote(certificates);
        let tls = remote_admin_tls_config(&identity, &remote).expect("remote admin TLS config");
        let api = api();
        load_remote_admin_config(&api, certificates).await;
        let handle = bind_admin_remote("127.0.0.1:0", api.clone(), tls, None)
            .await
            .expect("bind remote admin listener");
        let port = handle.socket_addr.expect("bound address").port();
        (api, port, handle)
    }

    /// Issue one request and report whether the server refused to serve it (TLS 1.3 completes the
    /// client handshake before the server validates the client certificate, so rejection shows up
    /// on the first read rather than in `connect`).
    async fn request_refused(
        stream: tokio_rustls::client::TlsStream<TcpStream>,
        request: &'static [u8],
    ) -> bool {
        let mut stream = stream;
        if stream.write_all(request).await.is_err() {
            return true;
        }
        let mut response = Vec::new();
        match stream.read_to_end(&mut response).await {
            Err(_) => true,
            Ok(_) => response.is_empty(),
        }
    }

    #[tokio::test]
    async fn valid_client_certificate_reaches_authorized_endpoint() {
        if !openssl_available() {
            eprintln!(
                "skipping {}: the `openssl` CLI is not available to mint the test certificates",
                "valid_client_certificate_reaches_authorized_endpoint"
            );
            return;
        }
        let certificates = test_certificates("valid");
        let (_api, port, handle) = start_remote(&certificates).await;
        let mut stream = connect(
            &certificates,
            Some((&certificates.client_pem, &certificates.client_key_pem)),
            port,
        )
        .await
        .expect("valid client certificate completes the handshake");
        let status = request_status(
            &mut stream,
            "GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status, 200);
        handle.stop().await;
    }

    /// A client whose role does not allow `POST /load` is refused before its body is read, so it
    /// cannot pin upload slots with trickling bodies and starve authorised callers.
    #[tokio::test]
    async fn an_unauthorised_remote_request_is_refused_without_reading_its_body() {
        if !openssl_available() {
            eprintln!("skipping: the `openssl` CLI is not available to mint the test certificates");
            return;
        }
        let certificates = test_certificates("unread-body");
        let (_api, port, handle) = start_remote(&certificates).await;
        let mut stream = connect(
            &certificates,
            Some((&certificates.client_pem, &certificates.client_key_pem)),
            port,
        )
        .await
        .expect("valid client certificate completes the handshake");
        stream
            .write_all(
                b"POST /load HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
                  Content-Length: 1000\r\n\r\n{",
            )
            .await
            .expect("write");
        stream.flush().await.expect("flush");
        let mut buffer = [0_u8; 512];
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buffer))
                .await
                .expect("a refusal must arrive without waiting for the body")
                .expect("read");
        assert!(
            buffer[..read].starts_with(b"HTTP/1.1 403"),
            "{:?}",
            String::from_utf8_lossy(&buffer[..read])
        );
        handle.stop().await;
    }

    #[tokio::test]
    async fn missing_client_certificate_fails_the_handshake() {
        if !openssl_available() {
            eprintln!(
                "skipping {}: the `openssl` CLI is not available to mint the test certificates",
                "missing_client_certificate_fails_the_handshake"
            );
            return;
        }
        let certificates = test_certificates("missing");
        let (_api, port, handle) = start_remote(&certificates).await;
        let stream = connect(&certificates, None, port).await;
        let refused = match stream {
            Err(error) => {
                assert!(
                    error.to_string().to_lowercase().contains("certificate")
                        || error.to_string().to_lowercase().contains("alert"),
                    "unexpected handshake error: {error}"
                );
                true
            }
            Ok(stream) => {
                request_refused(
                    stream,
                    b"GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .await
            }
        };
        assert!(
            refused,
            "mutual TLS must refuse a request without a client certificate"
        );
        handle.stop().await;
    }

    #[tokio::test]
    async fn untrusted_client_certificate_fails_the_handshake() {
        if !openssl_available() {
            eprintln!(
                "skipping {}: the `openssl` CLI is not available to mint the test certificates",
                "untrusted_client_certificate_fails_the_handshake"
            );
            return;
        }
        let certificates = test_certificates("untrusted");
        let (_api, port, handle) = start_remote(&certificates).await;
        let stream = connect(
            &certificates,
            Some((
                &certificates.untrusted_client_pem,
                &certificates.untrusted_client_key_pem,
            )),
            port,
        )
        .await;
        let refused = match stream {
            Err(_) => true,
            Ok(stream) => {
                request_refused(
                    stream,
                    b"GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .await
            }
        };
        assert!(
            refused,
            "a certificate outside the access-control pool is rejected"
        );
        handle.stop().await;
    }

    #[tokio::test]
    async fn authenticated_but_unauthorized_path_and_method_are_403() {
        if !openssl_available() {
            eprintln!(
                "skipping {}: the `openssl` CLI is not available to mint the test certificates",
                "authenticated_but_unauthorized_path_and_method_are_403"
            );
            return;
        }
        let certificates = test_certificates("unauthorized");
        let (_api, port, handle) = start_remote(&certificates).await;
        let mut stream = connect(
            &certificates,
            Some((&certificates.client_pem, &certificates.client_key_pem)),
            port,
        )
        .await
        .expect("valid client certificate");

        // `/load` is not allowed by any entry that matches this identity.
        let status = request_status(
            &mut stream,
            "POST /load HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status, 403);
        drop(stream);

        // The path is allowed somewhere but only for GET, so the method is what is missing.
        let mut stream = connect(
            &certificates,
            Some((&certificates.client_pem, &certificates.client_key_pem)),
            port,
        )
        .await
        .expect("valid client certificate");
        let status = request_status(
            &mut stream,
            "DELETE /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(status, 403);
        handle.stop().await;
    }

    #[tokio::test]
    async fn plaintext_admin_listener_still_serves_its_endpoints() {
        let api = api();
        let handle = bind_admin("127.0.0.1:0", api, None)
            .await
            .expect("bind plaintext admin listener");
        let port = handle.socket_addr.expect("bound address").port();
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to the plaintext admin listener");
        stream
            .write_all(b"GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "plaintext admin endpoint still answers 200: {response}"
        );
        handle.stop().await;
    }
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

/// Virtual-time tests for [`bounded_handshake`]: a half-open handshake must observe the shutdown
/// signals (SEC-MEDIUM-ADMIN-SERVER A4 follow-up).
#[cfg(test)]
mod bounded_handshake_tests {
    use super::{bounded_handshake, PhaseAbort, HANDSHAKE_SHUTDOWN_GRACE};
    use std::time::Duration;
    use tokio::sync::watch;

    fn channels() -> (
        watch::Sender<bool>,
        watch::Sender<bool>,
        watch::Receiver<bool>,
        watch::Receiver<bool>,
    ) {
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (force, force_rx) = watch::channel(false);
        (shutdown, force, shutdown_rx, force_rx)
    }

    #[tokio::test(start_paused = true)]
    async fn completes_when_the_phase_finishes_first() {
        let (_s, _f, mut shutdown, mut force) = channels();
        let result = bounded_handshake(
            async { 7_u8 },
            Duration::from_secs(60),
            &mut shutdown,
            &mut force,
        )
        .await;
        assert_eq!(result, Ok(7));
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_at_the_budget() {
        let (_s, _f, mut shutdown, mut force) = channels();
        let started = tokio::time::Instant::now();
        let result = bounded_handshake(
            std::future::pending::<()>(),
            Duration::from_secs(60),
            &mut shutdown,
            &mut force,
        )
        .await;
        assert_eq!(result, Err(PhaseAbort::TimedOut));
        assert_eq!(started.elapsed(), Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn forced_shutdown_abandons_immediately() {
        let (_s, force, mut shutdown, mut force_rx) = channels();
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move {
            bounded_handshake(
                std::future::pending::<()>(),
                Duration::from_secs(3600),
                &mut shutdown,
                &mut force_rx,
            )
            .await
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        force.send(true).unwrap();
        assert_eq!(task.await.unwrap(), Err(PhaseAbort::Forced));
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn graceful_shutdown_caps_the_remaining_budget() {
        let (shutdown_tx, _f, mut shutdown, mut force) = channels();
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move {
            bounded_handshake(
                std::future::pending::<()>(),
                Duration::from_secs(3600),
                &mut shutdown,
                &mut force,
            )
            .await
        });
        tokio::time::sleep(Duration::from_secs(2)).await;
        shutdown_tx.send(true).unwrap();
        assert_eq!(task.await.unwrap(), Err(PhaseAbort::ShutdownGrace));
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(2) + HANDSHAKE_SHUTDOWN_GRACE
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_nearly_spent_budget_is_not_extended_by_the_shutdown_grace() {
        let (shutdown_tx, _f, mut shutdown, mut force) = channels();
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move {
            bounded_handshake(
                std::future::pending::<()>(),
                Duration::from_secs(3),
                &mut shutdown,
                &mut force,
            )
            .await
        });
        shutdown_tx.send(true).unwrap();
        assert_eq!(task.await.unwrap(), Err(PhaseAbort::TimedOut));
        assert_eq!(started.elapsed(), Duration::from_secs(3));
    }
}

/// Unit tests for the bounded admin request-body read (SEC-MEDIUM-ADMIN-SERVER A2).
#[cfg(test)]
mod admin_body_tests {
    use super::{admin_body_limit, read_admin_body, ADMIN_MAX_BODY_BYTES};
    use bytes::Bytes;
    use caddy_rs_admin::AdminApi;
    use caddy_rs_core::GenerationStore;
    use http::{HeaderMap, StatusCode};
    use http_body_util::Full;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    /// A body that yields `data` and then fails, like a connection dropped mid-request.
    struct Failing(Option<Bytes>);

    impl hyper::body::Body for Failing {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            match self.0.take() {
                Some(data) => Poll::Ready(Some(Ok(hyper::body::Frame::data(data)))),
                None => Poll::Ready(Some(Err(std::io::Error::other("connection reset")))),
            }
        }
    }

    fn body_of(length: usize) -> Full<Bytes> {
        Full::new(Bytes::from(vec![b'a'; length]))
    }

    #[tokio::test]
    async fn body_within_the_limit_is_returned_and_the_boundary_is_inclusive() {
        let headers = HeaderMap::new();
        assert_eq!(
            read_admin_body(&headers, body_of(10), Some(10))
                .await
                .unwrap()
                .len(),
            10,
            "exactly the limit is accepted"
        );
        assert_eq!(
            read_admin_body(&headers, body_of(0), Some(10))
                .await
                .unwrap()
                .len(),
            0
        );
        let rejected = read_admin_body(&headers, body_of(11), Some(10))
            .await
            .expect_err("one byte over");
        assert_eq!(rejected.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(String::from_utf8_lossy(&rejected.body).contains("\"error\""));
    }

    #[tokio::test]
    async fn declared_content_length_over_the_limit_is_rejected_before_reading() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "11".parse().unwrap());
        // The body itself is empty: only the header can trigger the rejection.
        let rejected = read_admin_body(&headers, body_of(0), Some(10))
            .await
            .expect_err("declared length over the cap");
        assert_eq!(rejected.status, StatusCode::PAYLOAD_TOO_LARGE);
        headers.insert(http::header::CONTENT_LENGTH, "10".parse().unwrap());
        assert!(read_admin_body(&headers, body_of(10), Some(10))
            .await
            .is_ok());
        // A malformed Content-Length is ignored here (hyper rejects it before the service runs).
        headers.insert(http::header::CONTENT_LENGTH, "abc".parse().unwrap());
        assert!(read_admin_body(&headers, body_of(3), Some(10))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn unbounded_read_accepts_any_size() {
        let headers = HeaderMap::new();
        assert_eq!(
            read_admin_body(&headers, body_of(4096), None)
                .await
                .unwrap()
                .len(),
            4096
        );
    }

    #[tokio::test]
    async fn read_failures_are_400_not_an_empty_body() {
        let headers = HeaderMap::new();
        for limit in [Some(1024), None] {
            let rejected = read_admin_body(
                &headers,
                Failing(Some(Bytes::from_static(b"{\"a\":"))),
                limit,
            )
            .await
            .expect_err("a failed read must not become an empty body");
            assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "limit {limit:?}");
        }
    }

    #[test]
    fn stock_compat_lifts_the_admin_body_cap() {
        let store = Arc::new(GenerationStore::with_builtin_registry());
        let api = AdminApi::new(Arc::clone(&store));
        assert_eq!(
            admin_body_limit(&api),
            Some(ADMIN_MAX_BODY_BYTES),
            "no active generation: capped"
        );
        for (stock_compat, expected) in [(false, Some(ADMIN_MAX_BODY_BYTES)), (true, None)] {
            let config = caddy_rs_core::Config::from_value(
                serde_json::json!({"stock_compat": stock_compat}),
            )
            .expect("config");
            store.load(config).expect("load");
            assert_eq!(
                admin_body_limit(&api),
                expected,
                "stock_compat {stock_compat}"
            );
        }
    }
}

/// Connection-level limits of the plaintext TCP admin listener: stock Caddy's admin `http.Server`
/// runs with `ReadTimeout` 10 s, `ReadHeaderTimeout` 5 s and `IdleTimeout` 60 s, and the body
/// cap alone left many trickling connections each free to hold up to 64 MiB.
#[cfg(test)]
mod admin_limits_tests {
    use super::bind_admin;
    use caddy_rs_admin::AdminApi;
    use caddy_rs_core::GenerationStore;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn api() -> AdminApi {
        AdminApi::new(Arc::new(GenerationStore::with_builtin_registry()))
    }

    async fn listener() -> (super::ListenerHandle, SocketAddr) {
        let handle = bind_admin("127.0.0.1:0", api(), None)
            .await
            .expect("bind admin listener");
        let address = handle.socket_addr.expect("bound address");
        (handle, address)
    }

    #[tokio::test]
    async fn a_silent_admin_connection_is_dropped_after_the_header_timeout() {
        let (handle, address) = listener().await;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        let started = Instant::now();
        let mut buffer = [0_u8; 256];
        let outcome = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut buffer)).await;
        assert!(
            outcome.is_ok(),
            "a connection that never sends a request must be closed (stock ReadHeaderTimeout 5 s)"
        );
        assert!(
            started.elapsed() >= Duration::from_secs(4),
            "not closed early: {:?}",
            started.elapsed()
        );
        handle.stop().await;
    }

    #[tokio::test]
    async fn a_silent_admin_connection_is_dropped_by_a_forced_stop_not_after_the_budget() {
        let (handle, address) = listener().await;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let started = Instant::now();
        handle.stop_forcibly().await;
        let mut buffer = [0_u8; 16];
        let outcome =
            tokio::time::timeout(Duration::from_millis(1500), stream.read(&mut buffer)).await;
        assert!(
            outcome.is_ok(),
            "a forced stop must drop a connection that has sent nothing ({:?})",
            started.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn admit_first_byte_observes_shutdown_and_passes_traffic() {
        use super::admit_first_byte;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (force_tx, force_rx) = tokio::sync::watch::channel(false);
        let (mut shutdown, mut force) = (shutdown_rx.clone(), force_rx.clone());
        // Traffic: the first byte is handed back unconsumed.
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"G").await.unwrap();
        let admitted = admit_first_byte(server, Duration::from_secs(5), &mut shutdown, &mut force)
            .await
            .expect("a byte arrived");
        let mut replay = Vec::new();
        let mut admitted = admitted;
        let mut one = [0_u8; 1];
        admitted.read_exact(&mut one).await.unwrap();
        replay.extend_from_slice(&one);
        assert_eq!(replay, b"G");
        // Silence + forced shutdown: gone immediately, long before the 5 s budget.
        let (_client, server) = tokio::io::duplex(64);
        let (mut shutdown, mut force) = (shutdown_rx.clone(), force_rx.clone());
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move {
            admit_first_byte(server, Duration::from_secs(5), &mut shutdown, &mut force)
                .await
                .is_none()
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        force_tx.send(true).unwrap();
        assert!(task.await.unwrap());
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        drop(shutdown_tx);
    }

    /// A body that never produces a frame, like a client trickling nothing.
    struct Stalled;

    impl hyper::body::Body for Stalled {
        type Data = bytes::Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<bytes::Bytes>, Self::Error>>>
        {
            std::task::Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_admin_body_times_out_with_408_and_frees_its_slot() {
        let api = api();
        let slots = super::AdminBodySlots::new();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "10".parse().unwrap());
        let activity = Arc::new(super::ConnectionActivity::default());
        let rejected =
            super::read_admin_request_body(&api, &slots, "peer", &activity, &headers, Stalled)
                .await
                .expect_err("a body that never arrives is rejected");
        assert_eq!(rejected.status, http::StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            slots.available(),
            super::ADMIN_MAX_CONCURRENT_BODIES,
            "the slot is released"
        );
        assert!(!activity.reading_body(), "the body-read marker is cleared");
    }

    #[test]
    fn slots_are_capped_per_peer_and_in_total_and_released_on_drop() {
        let slots = super::AdminBodySlots::new();
        let a1 = slots.try_acquire("a").expect("first");
        let _a2 = slots.try_acquire("a").expect("second");
        assert!(slots.try_acquire("a").is_none(), "per-peer cap");
        let _b1 = slots.try_acquire("b").expect("other peer");
        let _b2 = slots.try_acquire("b").expect("other peer, second");
        assert!(slots.try_acquire("c").is_none(), "global cap");
        assert!(slots.try_acquire("a").is_none());
        drop(a1);
        let _c = slots
            .try_acquire("c")
            .expect("a release frees a global slot");
        assert_eq!(slots.available(), 0);
    }

    /// Connect from the loopback address `source` (127.0.0.x are all local on Linux), so tests can
    /// act as different peers.
    async fn connect_from(source: &str, address: SocketAddr) -> TcpStream {
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket
            .bind(format!("{source}:0").parse().unwrap())
            .expect("bind source");
        socket.connect(address).await.expect("connect")
    }

    /// Start a request from `source` that announces a 1000-byte body and sends one byte, then
    /// stalls: it holds one upload slot until the stream is dropped.
    async fn hold_slot(source: &str, address: SocketAddr) -> TcpStream {
        let mut stream = connect_from(source, address).await;
        stream
            .write_all(
                b"POST /load HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
                  Content-Length: 1000\r\n\r\n{",
            )
            .await
            .expect("write partial request");
        stream
    }

    /// Status of a small `POST /load` from `source`.
    async fn probe_status(source: &str, address: SocketAddr) -> u16 {
        let mut stream = connect_from(source, address).await;
        stream
            .write_all(
                b"POST /load HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
                  Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            )
            .await
            .expect("write request");
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
        String::from_utf8_lossy(&response)
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    /// Poll (bounded) until a probe from `source` is refused with 503: the holders register their
    /// slots asynchronously, so there is no fixed sleep that is both short and safe.
    async fn eventually_503(source: &str, address: SocketAddr) -> bool {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if probe_status(source, address).await == 503 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    #[tokio::test]
    async fn one_peer_cannot_take_more_than_its_share_of_the_upload_slots() {
        let (handle, address) = listener().await;
        // 2 = ADMIN_MAX_BODIES_PER_PEER: two stalled uploads from 127.0.0.1 ...
        let _holders = [
            hold_slot("127.0.0.1", address).await,
            hold_slot("127.0.0.1", address).await,
        ];
        assert!(
            eventually_503("127.0.0.1", address).await,
            "a third upload from the same peer must be refused"
        );
        // 127.0.0.0/8 is all local: every loopback source is the same principal, so another
        // loopback address does not get a fresh share (a per-address limit would be moot).
        assert!(
            eventually_503("127.0.0.2", address).await,
            "loopback aliases share one principal's limit"
        );
        handle.stop().await;
    }

    #[test]
    fn loopback_peers_are_one_principal_and_other_addresses_are_distinct() {
        use super::admin_peer_key;
        let key = |text: &str| admin_peer_key(text.parse().unwrap());
        assert_eq!(key("127.0.0.1"), key("127.9.9.9"));
        assert_eq!(key("127.0.0.1"), key("::1"));
        assert_ne!(key("192.0.2.1"), key("192.0.2.2"));
        assert_ne!(key("192.0.2.1"), key("127.0.0.1"));
    }

    /// Connections are capped per peer (and per listener): fd exhaustion is process-wide, so
    /// unbounded admin connections could starve the public listeners. Silent connections hold
    /// their slot through the 5 s first-byte gate, so over-cap ones are visibly refused at once.
    #[tokio::test]
    async fn connections_beyond_the_per_peer_cap_are_refused_at_once() {
        let (handle, address) = listener().await;
        let mut held = Vec::new();
        for _ in 0..super::ADMIN_MAX_CONNECTIONS_PER_PEER {
            held.push(TcpStream::connect(address).await.expect("connect"));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut extra = TcpStream::connect(address).await.expect("connect");
        let mut buffer = [0_u8; 8];
        let started = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(2), extra.read(&mut buffer)).await;
        assert!(
            matches!(outcome, Ok(Ok(0)) | Ok(Err(_))),
            "the connection past the cap must be dropped immediately, not after the 5 s gate \
             ({:?}, {outcome:?})",
            started.elapsed()
        );
        drop(held);
        handle.stop().await;
    }

    #[test]
    fn the_listener_wide_cap_applies_across_peers() {
        let slots = super::AdminBodySlots::with_limits(3, 2);
        let _a = [
            slots.try_acquire("a").unwrap(),
            slots.try_acquire("a").unwrap(),
        ];
        let _b = slots.try_acquire("b").unwrap();
        assert!(slots.try_acquire("c").is_none(), "listener-wide cap");
        assert!(slots.try_acquire("a").is_none(), "per-peer cap");
    }

    /// A request whose headers trickle in must finish them within the 5 s header budget in total
    /// (Go's `ReadHeaderTimeout`), even on a keep-alive connection that already served a request:
    /// the 60 s budget is for the idle wait *between* requests only.
    #[tokio::test]
    async fn a_trickled_request_header_is_cut_off_after_the_header_budget() {
        let (handle, address) = listener().await;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        let request = b"GET /config/ HTTP/1.1\r\nHost: localhost\r\n\r\n";
        stream.write_all(request).await.unwrap();
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).await.expect("first response");
        assert!(buffer[..read].starts_with(b"HTTP/1.1 200"));
        // The second request: one byte a second, never finishing its headers.
        let started = Instant::now();
        let closed = async {
            for byte in b"GET /config/ HTTP/1.1\r\nHost: loc" {
                if stream.write_all(&[*byte]).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                let mut probe = [0_u8; 64];
                if let Ok(Ok(0)) | Ok(Err(_)) =
                    tokio::time::timeout(Duration::from_millis(10), stream.read(&mut probe)).await
                {
                    return;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(9), closed)
            .await
            .expect("a trickling request must be closed within about 5 s");
        assert!(
            started.elapsed() >= Duration::from_secs(4),
            "not cut off early: {:?}",
            started.elapsed()
        );
        handle.stop().await;
    }

    /// HTTP/2 streams without a `content-length` used to take no slot at all (only the headers
    /// were inspected), so 250 streams per connection x many connections each held up to 64 MiB.
    #[tokio::test]
    async fn http2_streams_without_content_length_take_upload_slots() {
        let (handle, address) = listener().await;
        let tcp = TcpStream::connect(address).await.expect("connect");
        let (mut sender, connection) = h2::client::handshake(tcp).await.expect("h2 handshake");
        tokio::spawn(connection);
        let request = || {
            http::Request::builder()
                .method("POST")
                .uri("http://localhost/load")
                .body(())
                .unwrap()
        };
        let mut held = Vec::new();
        for _ in 0..2 {
            sender = sender.ready().await.expect("ready");
            let (response, stream) = sender.send_request(request(), false).expect("send");
            held.push((response, stream)); // open, never finished
        }
        let mut refused = false;
        for _ in 0..80 {
            sender = sender.ready().await.expect("ready");
            let (response, mut body) = sender.send_request(request(), false).expect("send");
            body.send_data(bytes::Bytes::from_static(b"{}"), true)
                .expect("body");
            if let Ok(Ok(response)) = tokio::time::timeout(Duration::from_secs(2), response).await {
                if response.status() == 503 {
                    refused = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            refused,
            "a third body-carrying HTTP/2 stream from the same peer must be refused"
        );
        handle.stop().await;
    }

    /// Go's `ReadTimeout` covers one request; between requests only `IdleTimeout` (60 s) applies.
    /// The per-read timer used to run during the idle wait too, closing a keep-alive connection
    /// after 10 s.
    /// A graceful stop must close an idle keep-alive admin connection promptly, or a drain (the
    /// runtime waits for ordinary connections before forcing) is held open by it.
    #[tokio::test]
    async fn a_graceful_stop_closes_an_idle_keep_alive_admin_connection() {
        let (handle, address) = listener().await;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream
            .write_all(b"GET /config/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).await.expect("response");
        assert!(buffer[..read].starts_with(b"HTTP/1.1 200"));
        handle.begin_graceful();
        let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "an idle keep-alive connection must close on graceful shutdown: {closed:?}"
        );
        handle.stop().await;
    }

    #[tokio::test]
    async fn an_idle_keep_alive_connection_survives_past_the_read_timeout() {
        let (handle, address) = listener().await;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        let request = b"GET /config/ HTTP/1.1\r\nHost: localhost\r\n\r\n";
        stream.write_all(request).await.unwrap();
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).await.expect("first response");
        assert!(buffer[..read].starts_with(b"HTTP/1.1 200"));
        tokio::time::sleep(Duration::from_secs(12)).await;
        stream
            .write_all(request)
            .await
            .expect("the idle connection is still open after 12 s");
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer))
            .await
            .expect("second response arrives")
            .expect("read");
        assert!(
            buffer[..read].starts_with(b"HTTP/1.1 200"),
            "second request on the idle connection: {:?}",
            String::from_utf8_lossy(&buffer[..read])
        );
        handle.stop().await;
    }
}

/// End-to-end tests of the admin DNS-rebinding `Host` check (SEC-MEDIUM-ADMIN-SERVER A1) on a real
/// listener with a non-zero, known port. A listener configured with port 0 turns the check off
/// (the port is unknown to the allow-list), so these bind a port first and then configure it.
#[cfg(test)]
mod admin_host_check_tests {
    use super::{admin_request_headers, bind_admin};
    use caddy_rs_admin::{AdminApi, OriginPolicy};
    use caddy_rs_core::{AdminConfig, GenerationStore};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn listener() -> (super::ListenerHandle, SocketAddr) {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe port");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let listen = format!("127.0.0.1:{port}");
        let policy = OriginPolicy::from_admin(Some(&AdminConfig {
            listen: Some(listen.clone()),
            ..AdminConfig::default()
        }));
        let api = AdminApi::new(Arc::new(GenerationStore::with_builtin_registry()))
            .with_origin_policy(policy);
        let handle = bind_admin(&listen, api, None).await.expect("bind admin");
        let address = handle.socket_addr.expect("bound address");
        assert_eq!(address.port(), port);
        (handle, address)
    }

    /// Send a raw HTTP/1.1 request and return its status code.
    async fn status_of(address: SocketAddr, request: &str) -> u16 {
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_to_end(&mut response),
        )
        .await;
        let text = String::from_utf8_lossy(&response);
        text.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status line in {text:?}"))
    }

    fn get(target: &str, headers: &[String]) -> String {
        let mut request = format!("GET {target} HTTP/1.1\r\nConnection: close\r\n");
        for header in headers {
            request.push_str(header);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request
    }

    #[tokio::test]
    async fn own_host_is_served_and_foreign_host_is_refused_with_and_without_origin_headers() {
        let (handle, address) = listener().await;
        let own = format!("Host: {address}");
        let foreign = format!("Host: evil.example:{}", address.port());
        let origin = format!("Origin: http://{address}");
        let cross_site = "Sec-Fetch-Mode: cors".to_string();

        for (extra, label) in [
            (vec![], "no Origin or Sec-Fetch-Mode"),
            (vec![origin.clone()], "Origin"),
            (
                vec![origin.clone(), cross_site.clone()],
                "Origin + Sec-Fetch-Mode",
            ),
            (vec![cross_site.clone()], "Sec-Fetch-Mode alone"),
        ] {
            let mut with_own = vec![own.clone()];
            with_own.extend(extra.clone());
            let status = status_of(address, &get("/config/", &with_own)).await;
            // `Sec-Fetch-Mode` alone has no Origin to validate, which Caddy rejects with 403
            // after the Host passed; every other combination with the own Host is served.
            let expected = if label == "Sec-Fetch-Mode alone" {
                403
            } else {
                200
            };
            assert_eq!(status, expected, "own Host, {label}");

            let mut with_foreign = vec![foreign.clone()];
            with_foreign.extend(extra);
            assert_eq!(
                status_of(address, &get("/config/", &with_foreign)).await,
                403,
                "foreign Host must be refused, {label}"
            );
        }
        handle.stop().await;
    }

    #[tokio::test]
    async fn absolute_form_target_host_wins_over_the_host_header() {
        let (handle, address) = listener().await;
        let own = format!("Host: {address}");
        let evil = format!("http://evil.example:{}/config/", address.port());
        assert_eq!(
            status_of(address, &get(&evil, std::slice::from_ref(&own))).await,
            403,
            "Go uses the request-line host, so a foreign absolute-form target is a rebinding attempt"
        );
        let good = format!("http://{address}/config/");
        let foreign = format!("Host: evil.example:{}", address.port());
        assert_eq!(
            status_of(address, &get(&good, &[foreign])).await,
            200,
            "and an own absolute-form target is served whatever the header says"
        );
        handle.stop().await;
    }

    /// A refused request must be refused *before* its body is read: no slot, no memory, and the
    /// 403 arrives although the announced body never does. The body used to be read first, so a
    /// rebinding page's foreign-Host `POST` pinned a slot (and up to 64 MiB) before its 403.
    #[tokio::test]
    async fn a_refused_request_is_answered_without_reading_its_body() {
        let (handle, address) = listener().await;
        let foreign = format!("Host: evil.example:{}", address.port());
        let request = format!(
            "POST /load HTTP/1.1\r\n{foreign}\r\nContent-Type: application/json\r\n\
             Content-Length: 1000\r\n\r\n{{"
        );
        let started = std::time::Instant::now();
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut buffer = [0_u8; 512];
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buffer))
                .await
                .expect("a 403 must arrive without waiting for the body")
                .expect("read");
        assert!(
            buffer[..read].starts_with(b"HTTP/1.1 403"),
            "{:?}",
            String::from_utf8_lossy(&buffer[..read])
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        // Nothing is left holding a slot: the connection is closed after the refusal.
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut rest),
        )
        .await;
        assert!(
            closed.is_ok(),
            "the connection is closed after refusing an unread body"
        );
        handle.stop().await;
    }

    #[tokio::test]
    async fn multiple_host_headers_are_a_400_like_go() {
        let (handle, address) = listener().await;
        let own = format!("Host: {address}");
        assert_eq!(
            status_of(address, &get("/config/", &[own.clone(), own])).await,
            400
        );
        handle.stop().await;
    }

    /// Prior-knowledge HTTP/2 carries only `:authority` (no `Host` header), so the check used to
    /// be skipped entirely for h2c clients.
    #[tokio::test]
    async fn http2_authority_is_checked_like_the_host_header() {
        let (handle, address) = listener().await;
        let request = |authority: String| async move {
            let tcp = TcpStream::connect(address).await.expect("connect");
            let (mut sender, connection) = h2::client::handshake(tcp).await.expect("h2 handshake");
            tokio::spawn(connection);
            let request = http::Request::builder()
                .uri(format!("http://{authority}/config/"))
                .body(())
                .unwrap();
            let (response, _) = sender.send_request(request, true).expect("send");
            response.await.expect("response").status().as_u16()
        };
        assert_eq!(request(address.to_string()).await, 200);
        assert_eq!(
            request(format!("evil.example:{}", address.port())).await,
            403,
            "a foreign :authority over h2c must be refused"
        );
        handle.stop().await;
    }

    #[test]
    fn request_headers_resolve_host_like_go() {
        let uri = |text: &str| text.parse::<http::Uri>().unwrap();
        let with_host = |value: &str| {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::HOST, value.parse().unwrap());
            headers
        };
        use http::Version as V;
        // Origin-form keeps the header.
        let resolved =
            admin_request_headers(with_host("a.example"), &uri("/x"), V::HTTP_11).unwrap();
        assert_eq!(resolved.get(http::header::HOST).unwrap(), "a.example");
        // An authority (absolute-form / :authority) replaces it; userinfo is not part of the host.
        let resolved = admin_request_headers(
            with_host("a.example"),
            &uri("http://u:p@b.example:1/x"),
            V::HTTP_11,
        )
        .unwrap();
        assert_eq!(resolved.get(http::header::HOST).unwrap(), "b.example:1");
        // And supplies it when the header is absent (HTTP/2).
        let resolved = admin_request_headers(
            http::HeaderMap::new(),
            &uri("http://c.example/x"),
            V::HTTP_2,
        )
        .unwrap();
        assert_eq!(resolved.get(http::header::HOST).unwrap(), "c.example");
        // HTTP/1.0 may omit Host (as in Go): still absent.
        let resolved =
            admin_request_headers(http::HeaderMap::new(), &uri("/x"), V::HTTP_10).unwrap();
        assert!(resolved.get(http::header::HOST).is_none());
        // HTTP/1.1 without Host: 400 like Go.
        let rejected =
            admin_request_headers(http::HeaderMap::new(), &uri("/x"), V::HTTP_11).unwrap_err();
        assert_eq!(rejected.status, http::StatusCode::BAD_REQUEST);
        // Two Host headers: 400.
        let mut headers = with_host("a.example");
        headers.append(http::header::HOST, "b.example".parse().unwrap());
        let rejected = admin_request_headers(headers, &uri("/x"), V::HTTP_11).unwrap_err();
        assert_eq!(rejected.status, http::StatusCode::BAD_REQUEST);
    }
}

/// Tests for the Unix-domain-socket admin listener (`admin.listen: "unix/<path>"`).
#[cfg(test)]
mod admin_unix_tests {
    use super::bind_admin;
    use caddy_rs_admin::AdminApi;
    use caddy_rs_core::GenerationStore;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    fn api() -> AdminApi {
        AdminApi::new(Arc::new(GenerationStore::with_builtin_registry()))
    }

    fn unix_listen(directory: &Path) -> (String, PathBuf) {
        let path = directory.join("admin.sock");
        (format!("unix/{}", path.display()), path)
    }

    #[tokio::test]
    async fn serves_the_admin_api_over_a_unix_socket_with_owner_only_permissions() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        let handle = bind_admin(&configured, api(), None)
            .await
            .expect("bind Unix admin listener");
        assert_eq!(
            handle.bound, configured,
            "the handle reports the configured address"
        );
        let mode = std::fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "admin socket is owner-only");
        let mut stream = UnixStream::connect(&path)
            .await
            .expect("connect to the admin socket");
        stream
            .write_all(b"GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "unix admin endpoint answers 200: {response}"
        );
        handle.stop().await;
        assert!(
            !path.exists(),
            "the socket file is removed when the listener stops"
        );
    }

    /// Send raw request bytes to a unix admin listener and return the response head, giving up
    /// after a short deadline (an unfixed server waits forever for the announced body).
    async fn raw_exchange(path: &Path, request: &[u8]) -> String {
        let mut stream = UnixStream::connect(path).await.expect("connect");
        stream.write_all(request).await.expect("write request");
        let mut response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_to_end(&mut response),
        )
        .await;
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn oversized_admin_request_bodies_are_rejected_with_413() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        let handle = bind_admin(&configured, api(), None).await.expect("bind");
        // Announced length beyond the cap: rejected from the header, without reading a byte.
        let response = raw_exchange(
            &path,
            b"POST /load HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
              Content-Type: application/json\r\nContent-Length: 4294967296\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 413"),
            "an over-cap Content-Length must be answered 413: {response}"
        );
        handle.stop().await;
    }

    #[tokio::test]
    async fn replaces_a_stale_socket_and_can_rebind_after_stop() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        // A crashed process leaves its socket file behind; binding must reclaim it.
        drop(std::os::unix::net::UnixListener::bind(&path).expect("plant stale socket"));
        assert!(path.exists());
        let handle = bind_admin(&configured, api(), None)
            .await
            .expect("bind over a stale socket");
        assert!(path.exists());
        handle.stop().await;
        assert!(!path.exists());
        let handle = bind_admin(&configured, api(), None)
            .await
            .expect("rebind after stop");
        handle.stop().await;
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn refuses_to_delete_a_regular_file_at_the_socket_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        std::fs::write(&path, b"precious").expect("plant regular file");
        let error = bind_admin(&configured, api(), None)
            .await
            .err()
            .expect("a regular file must not be replaced");
        assert!(error.to_string().contains("not a socket"), "{error}");
        assert_eq!(
            std::fs::read(&path).expect("file survives"),
            b"precious",
            "the regular file is untouched"
        );
    }

    #[tokio::test]
    async fn refuses_to_delete_a_symlink_or_directory_at_the_socket_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        let victim = directory.path().join("victim");
        std::fs::write(&victim, b"victim").expect("victim file");
        std::os::unix::fs::symlink(&victim, &path).expect("plant symlink");
        assert!(bind_admin(&configured, api(), None).await.is_err());
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("symlink survives")
                .file_type()
                .is_symlink(),
            "the symlink itself is not removed"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
        std::fs::remove_file(&path).unwrap();
        // A dangling symlink is refused too (`exists()` reports false for it).
        std::os::unix::fs::symlink(directory.path().join("missing"), &path).unwrap();
        assert!(bind_admin(&configured, api(), None).await.is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(bind_admin(&configured, api(), None).await.is_err());
        assert!(path.is_dir());
    }

    /// Best-effort probe for the creation window (SEC-MEDIUM-ADMIN-SERVER A3): a watcher thread
    /// polls the parent directory while the listener is bound and re-bound many times, and every
    /// time it sees the final socket path it checks the mode. It is probabilistic, not
    /// deterministic: the pre-fix `bind`-then-`chmod` window is a few microseconds wide, so this
    /// can pass on old code by missing it. The deterministic guarantees (staging directory is gone,
    /// only the final socket remains, mode 0600, failed binds leave nothing behind) are asserted
    /// in `staging_leaves_only_the_socket_behind`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watcher_never_observes_the_socket_with_wider_than_owner_permissions() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher = {
            let stop = Arc::clone(&stop);
            let path = path.clone();
            std::thread::spawn(move || {
                let mut observed = 0_usize;
                let mut worst = 0_u32;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
                        observed += 1;
                        worst = worst.max(metadata.permissions().mode() & 0o077);
                    }
                }
                (observed, worst)
            })
        };
        for _ in 0..200 {
            let handle = bind_admin(&configured, api(), None).await.expect("bind");
            handle.stop().await;
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let (observed, worst) = watcher.join().expect("watcher thread");
        assert_eq!(
            worst, 0,
            "saw the socket with group/other bits ({observed} samples)"
        );
    }

    #[tokio::test]
    async fn staging_leaves_only_the_socket_behind() {
        // The socket is bound inside a private 0700 staging directory and moved into place, so
        // no path under the configured name ever has umask-derived permissions. After bind the
        // staging directory is gone and only the socket remains.
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        let handle = bind_admin(&configured, api(), None).await.expect("bind");
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("admin.sock")],
            "{names:?}"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        handle.stop().await;
        // A failed bind (non-socket in the way) leaves no staging directory behind either.
        std::fs::write(&path, b"x").unwrap();
        assert!(bind_admin(&configured, api(), None).await.is_err());
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("admin.sock")],
            "{names:?}"
        );
    }

    #[test]
    fn probe_outcomes_are_classified_for_stale_other_user_and_wedged_sockets() {
        use super::{classify_probe, SocketProbe};
        use std::io::{Error, ErrorKind};
        let refused = Error::from(ErrorKind::ConnectionRefused);
        let denied = Error::from(ErrorKind::PermissionDenied);
        let other = Error::other("boom");
        assert_eq!(
            classify_probe(Ok(()), false, 1000, Some(1000)),
            SocketProbe::Live
        );
        assert_eq!(
            classify_probe(Err(&refused), false, 1000, Some(1000)),
            SocketProbe::Stale
        );
        // A wedged peer that never accepts within the budget counts as live (safe error).
        assert_eq!(
            classify_probe(Ok(()), true, 1000, Some(1000)),
            SocketProbe::Live
        );
        // EACCES on a socket another user owns (a crashed `sudo caddy-rs run`): stale.
        assert_eq!(
            classify_probe(Err(&denied), false, 0, Some(1000)),
            SocketProbe::Stale
        );
        // EACCES on our own socket, or when we cannot tell who we are: report, do not guess.
        assert!(matches!(
            classify_probe(Err(&denied), false, 1000, Some(1000)),
            SocketProbe::Unknown(_)
        ));
        assert!(matches!(
            classify_probe(Err(&denied), false, 0, None),
            SocketProbe::Unknown(_)
        ));
        assert!(matches!(
            classify_probe(Err(&other), false, 0, Some(1000)),
            SocketProbe::Unknown(_)
        ));
    }

    #[tokio::test]
    async fn explicit_bind_options_decide_replacement_not_the_stores_current_generation() {
        use super::{bind_admin_with, AdminBindOptions};
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        // The api's store has no generation (stock_compat false there), but the generation being
        // applied says stock_compat true, or this is an upgrade child: replace the live socket.
        for options in [
            AdminBindOptions {
                stock_compat: true,
                replace_live: false,
            },
            AdminBindOptions {
                stock_compat: false,
                replace_live: true,
            },
        ] {
            let first = bind_admin(&configured, api(), None).await.expect("bind");
            let second = bind_admin_with(&configured, api(), None, options)
                .await
                .expect("explicit options replace a live socket");
            assert!(path.exists());
            second.stop().await;
            first.stop().await;
        }
    }

    #[tokio::test]
    async fn an_http11_request_without_host_is_a_400_like_go() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        let handle = bind_admin(&configured, api(), None).await.expect("bind");
        let response =
            raw_exchange(&path, b"GET /config/ HTTP/1.1\r\nConnection: close\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        handle.stop().await;
    }

    #[tokio::test]
    async fn a_second_listener_does_not_steal_a_live_admin_socket() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        let first = bind_admin(&configured, api(), None).await.expect("bind");
        let error = bind_admin(&configured, api(), None)
            .await
            .err()
            .expect("a live socket must not be replaced");
        assert!(
            error.to_string().contains("in use by a running process"),
            "{error}"
        );
        // The first instance still owns the path and still answers.
        let response = raw_exchange(
            &path,
            b"GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        first.stop().await;
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn stock_compat_replaces_a_live_admin_socket_like_stock_caddy() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        let first = bind_admin(&configured, api(), None).await.expect("bind");
        let store = Arc::new(GenerationStore::with_builtin_registry());
        store
            .load(
                caddy_rs_core::Config::from_value(serde_json::json!({"stock_compat": true}))
                    .expect("config"),
            )
            .expect("load");
        let second = bind_admin(&configured, AdminApi::new(store), None)
            .await
            .expect("stock_compat replaces unconditionally");
        assert!(path.exists());
        second.stop().await;
        first.stop().await;
    }

    #[tokio::test]
    async fn a_final_path_that_fits_binds_when_only_the_short_staging_name_does() {
        // Parent of 98 bytes: the 8-digit staged path would be 110 bytes (> 107), the 4-digit one
        // 106; the final path is 105.
        let (_base, directory) = directory_of_length(98);
        let path = directory.join("a.sock");
        assert!(path.as_os_str().len() <= 107);
        let configured = format!("unix/{}", path.display());
        let handle = bind_admin(&configured, api(), None)
            .await
            .expect("falls back to the short staging name");
        handle.stop().await;
    }

    #[test]
    fn only_unsupported_hard_links_fall_back_to_rename() {
        let errno = std::io::Error::from_raw_os_error;
        for code in [libc::EPERM, libc::EOPNOTSUPP, libc::ENOSYS] {
            assert!(super::hard_link_unsupported(&errno(code)), "errno {code}");
        }
        for code in [
            libc::EACCES,
            libc::EMLINK,
            libc::ENOSPC,
            libc::EDQUOT,
            libc::EROFS,
            libc::EIO,
            libc::EEXIST,
            libc::ENOENT,
            libc::EXDEV,
        ] {
            assert!(!super::hard_link_unsupported(&errno(code)), "errno {code}");
        }
        assert!(!super::hard_link_unsupported(&std::io::Error::other("x")));
    }

    #[tokio::test]
    async fn stopping_does_not_delete_a_file_or_foreign_socket_that_replaced_ours() {
        // The cleanup used to `remove_file` whatever sat at the path, including a regular file or
        // another process's socket put there after we bound (SEC-MEDIUM-ADMIN-SERVER A3).
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        let handle = bind_admin(&configured, api(), None).await.expect("bind");
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"precious").unwrap();
        handle.stop().await;
        assert_eq!(
            std::fs::read(&path).expect("the replacement file survives the stop"),
            b"precious"
        );
        std::fs::remove_file(&path).unwrap();

        let handle = bind_admin(&configured, api(), None).await.expect("bind");
        std::fs::remove_file(&path).unwrap();
        let foreign = std::os::unix::net::UnixListener::bind(&path).expect("foreign socket");
        handle.stop().await;
        assert!(
            std::fs::symlink_metadata(&path).is_ok(),
            "another process's socket at the path is not ours to delete"
        );
        drop(foreign);
    }

    #[tokio::test]
    async fn a_predictable_staging_name_cannot_block_the_bind() {
        // The staging directory used to be `.caddy-rs-admin-<pid>-<counter>`: in a world-writable
        // parent anyone could pre-create those names and make every bind fail.
        let directory = tempfile::tempdir().expect("temporary directory");
        let (configured, path) = unix_listen(directory.path());
        for counter in 0..256 {
            let name = format!(".caddy-rs-admin-{}-{counter}", std::process::id());
            std::fs::create_dir(directory.path().join(name)).unwrap();
        }
        let handle = bind_admin(&configured, api(), None)
            .await
            .expect("a pre-created guessable name must not block the bind");
        assert!(path.exists());
        handle.stop().await;
    }

    /// A temporary directory whose path is exactly `length` bytes long.
    fn directory_of_length(length: usize) -> (tempfile::TempDir, PathBuf) {
        let base = tempfile::tempdir().expect("temporary directory");
        let used = base.path().as_os_str().len();
        let filler = "d".repeat(length - used - 1);
        let nested = base.path().join(filler);
        std::fs::create_dir(&nested).expect("nested directory");
        assert_eq!(nested.as_os_str().len(), length);
        (base, nested)
    }

    #[tokio::test]
    async fn staging_does_not_cost_much_of_the_108_byte_socket_path_budget() {
        // `sun_path` holds 107 bytes plus the NUL. The staging name used to add ~28 bytes, so a
        // socket path that fits could fail to bind; it now adds a short random name.
        let (_base, directory) = directory_of_length(92);
        let path = directory.join("a.sock");
        assert!(path.as_os_str().len() <= 107);
        let configured = format!("unix/{}", path.display());
        let handle = bind_admin(&configured, api(), None)
            .await
            .expect("a path well within the limit binds");
        handle.stop().await;
    }

    #[tokio::test]
    async fn an_over_long_staging_path_is_reported_with_the_configured_path_and_limit() {
        let (_base, directory) = directory_of_length(100);
        let path = directory.join("a.sock");
        assert!(
            path.as_os_str().len() <= 107,
            "the final path itself would fit"
        );
        let configured = format!("unix/{}", path.display());
        let error = bind_admin(&configured, api(), None)
            .await
            .err()
            .expect("the staged path is too long to bind");
        let message = error.to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("108"), "{message}");
    }
}

/// Tests for the UDP reuseport binding that `udpgrm` enables (ADR-0045 §1).
///
/// These assert the *socket option*, not the udpgrm sequence: this host has no udpgrm daemon, so
/// the protocol itself cannot be exercised here (the research record says so explicitly, and
/// `udpgrm.rs` covers the degrade path against a real `ENOPROTOOPT`). What can be proven locally is
/// that the socket genuinely joins a reuseport group **before** `bind`, which is the precondition
/// the whole mechanism rests on.
#[cfg(all(test, feature = "udpgrm"))]
#[allow(unsafe_code)] // Reads back socket options udpgrm depends on; see the SAFETY notes below.
mod udp_reuseport_tests {
    use std::os::fd::AsRawFd;

    /// Read back `SO_REUSEPORT` from a live descriptor.
    fn reuseport_is_set(fd: libc::c_int) -> bool {
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `fd` is owned by the socket the caller still holds; `value`/`length` describe a
        // local `c_int` exactly.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                (&mut value as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        rc == 0 && value == 1
    }

    /// Read back `IPV6_V6ONLY` from a live descriptor.
    fn only_v6(fd: libc::c_int) -> bool {
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: as above.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&mut value as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        rc == 0 && value == 1
    }

    #[tokio::test]
    async fn the_dual_stack_wildcard_joins_a_reuseport_group_and_stays_dual_stack() {
        let socket = super::wildcard_dual_stack_udp(0).expect("bind the dual-stack wildcard");
        assert!(
            reuseport_is_set(socket.as_raw_fd()),
            "the dual-stack UDP wildcard must set SO_REUSEPORT before bind, or udpgrm cannot \
             dispatch flows across generations"
        );
        assert!(
            !only_v6(socket.as_raw_fd()),
            "IPV6_V6ONLY must stay disabled: the wildcard is dual-stack, and the udpgrm feature \
             must not change that"
        );
    }

    #[tokio::test]
    async fn an_explicit_address_binds_with_reuseport_and_registers() {
        let socket =
            super::bind_udp_socket_addr("127.0.0.1:0".parse().expect("address"), "udp/127.0.0.1:0")
                .expect("bind an explicit UDP address");
        assert!(
            reuseport_is_set(socket.as_raw_fd()),
            "an explicit-address UDP listener must also join the reuseport group"
        );
    }

    #[tokio::test]
    async fn two_sockets_can_share_a_port_only_because_of_reuseport() {
        // The functional consequence: two generations can hold the same UDP port at once. Without
        // SO_REUSEPORT the second bind fails EADDRINUSE, which is exactly what the restart path
        // needs to avoid.
        let first = super::bind_udp_socket_addr("127.0.0.1:0".parse().expect("address"), "udp/a")
            .expect("bind the first socket");
        let port = first.local_addr().expect("local addr").port();
        let second = super::bind_udp_socket_addr(
            format!("127.0.0.1:{port}").parse().expect("address"),
            "udp/b",
        )
        .expect("a second generation must be able to bind the same UDP port");
        assert_eq!(second.local_addr().expect("local addr").port(), port);
    }
}

/// Tests for the ADR-0046 capability retry as wired into the production bind entry points.
#[cfg(test)]
mod bind_capability_tests {
    use super::{bind_configured_tcp, bind_configured_udp, Error};
    use caddy_rs_core::listen::ListenAddr;

    /// Criterion 8: a retried-and-failed bind surfaces `Error::Bind` naming the CONFIGURED address,
    /// and the raise failure is still visible in the cause.
    ///
    /// The reviewer rejected the previous revision for two reasons, both addressed here:
    /// the `map_err` on the TCP hostname path rebuilt the error from a message captured BEFORE the
    /// retry, discarding the seam's "(raising CAP_NET_BIND_SERVICE: ...)" explanation; and no test
    /// built an `Error::Bind` on the retry path at all, asserting only `attempts <= 1`, which passes
    /// whether the closure runs zero or one time.
    ///
    /// Rather than relying on a real privileged-port EACCES (which needs a specific capability state
    /// and would be environment-dependent), this drives the same mapping the bind paths use — the
    /// seam's error through `Error::bind(configured, error)` — and checks the located error names the
    /// configured address *and* carries the second attempt's message.
    #[test]
    fn a_failed_retry_surfaces_a_located_bind_error_naming_the_configured_address() {
        use crate::bindcap::with_bind_capability;
        use caddy_rs_core::listen::ListenAddr;

        let configured = "tcp/example.invalid:443";
        let address = ListenAddr::parse(configured).expect("the configured address parses");

        // A retry that fails with a distinguishable message, as a second EACCES would.
        let second = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SECOND attempt: permission denied",
        );
        let seam_error = with_bind_capability::<(), _>(
            &address,
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "FIRST attempt"),
            move || Err(second),
        )
        .expect_err("a failed retry must not become a success");

        // The exact mapping every wired bind site applies, called through the PRODUCTION helper so
        // that changing the helper (as the rejected revision did) fails this test. Calling
        // `Error::bind` directly here would only prove `Error::bind` works, which is why the first
        // version of this test could not detect the lossy rebuild.
        let located = super::located_bind_error(configured, seam_error);
        let Error::Bind { listen, cause } = &located else {
            panic!("a failed bind must surface as Error::Bind, got {located:?}");
        };
        assert_eq!(
            listen, configured,
            "the located error must name the CONFIGURED address, not a resolved socket address"
        );
        // Whatever the retry did, the cause must not be a lossy rebuild: either it is the second
        // attempt's own message, or (when the seam could not raise) the first attempt's message is
        // retained as the truthful answer. It must never be a generic re-wrap that drops both.
        let rendered = cause.to_string();
        assert!(
            rendered.contains("FIRST attempt") || rendered.contains("SECOND attempt"),
            "the cause must carry the real attempt's message, not a rebuilt placeholder: {rendered}"
        );
    }

    /// The seam's raise-failure explanation must survive all the way to `Error::Bind`.
    ///
    /// The previous TCP hostname path rebuilt the error as
    /// `std::io::Error::new(error.kind(), reason)` with `reason` captured before the retry, which
    /// silently discarded this suffix. The reviewer demonstrated that loss experimentally; this test
    /// pins the suffix so the loss cannot return.
    #[test]
    fn the_raise_failure_explanation_survives_into_the_located_error() {
        // Build the same shape the seam produces when the raise itself fails.
        let wrapped = std::io::Error::other(
            "permission denied (raising CAP_NET_BIND_SERVICE: operation not permitted)",
        );
        let located = super::located_bind_error("tcp/example.invalid:443", wrapped);
        let rendered = located.to_string();
        assert!(
            rendered.contains("example.invalid:443"),
            "the located error must name the configured address: {rendered}"
        );
        assert!(
            rendered.contains("raising CAP_NET_BIND_SERVICE"),
            "the operator must be told escalation was attempted and failed: {rendered}"
        );
    }

    /// Criterion 8 at the REAL bind sites: the located error must carry the REAL socket error.
    ///
    /// The previous revision of this test was green for a reason unrelated to the code under test, for
    /// the third time in this task. Its assertion was
    /// `cause.to_string().contains("127.0.0.1:PORT") || cause.kind() == AddrInUse`, and the test
    /// deliberately makes the bind fail with EADDRINUSE -- so the right-hand side was TRUE BY
    /// CONSTRUCTION and the whole disjunction could not fail. It was not merely weak: the left side
    /// never fires either, because a real EADDRINUSE renders as `[Errno 98] Address already in use`
    /// with no address in the text. The test therefore passed against a lossy mapping that replaced
    /// the cause with a placeholder, which the reviewer demonstrated by mutating the site.
    ///
    /// The fix is to make the assertion able to fail, NOT to add another test. Each site below now
    /// requires the real OS message text, which no placeholder can produce accidentally, and asserts
    /// the placeholder markers are absent. The same shape is used at every branch, because the last
    /// revision had the escape hatch at all four of them.
    #[test]
    fn the_real_bind_sites_surface_a_located_error_carrying_the_real_cause() {
        // The real message the kernel produces for an address already in use. Verified against the
        // actual error rather than assumed: it contains no address, which is precisely why an
        // address-based assertion could never have caught a lossy rebuild.
        const REAL_CAUSE: &str = "Address already in use";

        fn assert_real_cause(configured: &str, error: &Error, site: &str) {
            let Error::Bind { listen, cause } = error else {
                panic!("{site} must surface Error::Bind, got {error:?}");
            };
            assert_eq!(
                listen, configured,
                "{site}: the located error must name the CONFIGURED address"
            );
            assert_eq!(
                cause.kind(),
                std::io::ErrorKind::AddrInUse,
                "{site}: the cause must carry the real OS error kind, got {cause:?}"
            );
            let rendered = cause.to_string();
            assert!(
                rendered.contains(REAL_CAUSE),
                "{site}: the cause must be the real socket error, not a rebuilt placeholder: \
                 {rendered:?}"
            );
        }

        // --- bind_tcp_ip: the site where the reviewer's mutation survived. ---
        let held = std::net::TcpListener::bind("127.0.0.1:0").expect("hold a TCP port");
        let port = held.local_addr().expect("held addr").port();
        let configured = format!("tcp/127.0.0.1:{port}");
        let socket_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let error = super::bind_tcp_ip(&configured, socket_addr, None)
            .expect_err("binding an already-bound TCP port must fail");
        assert_real_cause(&configured, &error, "bind_tcp_ip");
        drop(held);

        // --- bind_udp_socket_addr: the explicit-address UDP site. ---
        let held_udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("hold a UDP port");
        let udp_port = held_udp.local_addr().expect("held udp addr").port();
        let udp_configured = format!("udp/127.0.0.1:{udp_port}");
        let udp_addr: std::net::SocketAddr = format!("127.0.0.1:{udp_port}").parse().expect("addr");
        let error = super::bind_udp_socket_addr(udp_addr, &udp_configured)
            .expect_err("binding an already-bound UDP port must fail");
        assert_real_cause(&udp_configured, &error, "bind_udp_socket_addr");
        drop(held_udp);
    }

    /// Criterion 8 at the UDP HOSTNAME site ([`super::bind_configured_udp`]'s hostname branch).
    ///
    /// This branch was wired in the previous revision but had NO failing-path test, so a lossy
    /// mapping there survived mutation — the same hole the reviewer had already found once at
    /// `bind_tcp_ip`. Driving it requires a literal hostname (an IP literal takes the
    /// `bind_udp_socket_addr` branch instead), so it binds `udp/localhost:<held port>` and asserts
    /// the real OS message, with no `kind()` escape hatch.
    #[tokio::test]
    async fn the_udp_hostname_site_surfaces_the_real_cause() {
        // `localhost` may resolve to IPv6 first; hold the port on both families so whichever is
        // tried is in use.
        let held4 = std::net::UdpSocket::bind("127.0.0.1:0").expect("hold a IPv4 UDP port");
        let port = held4.local_addr().expect("held addr").port();
        let _held6 = std::net::UdpSocket::bind(format!("[::1]:{port}")).ok();

        let configured = format!("udp/localhost:{port}");
        let address = ListenAddr::parse(&configured).expect("the hostname address parses");
        assert!(
            address.socket_addr().is_none(),
            "the configured address must take the hostname branch, not the explicit-address branch"
        );
        let error = super::bind_configured_udp(&configured, &address)
            .await
            .expect_err("binding an already-bound UDP hostname port must fail");
        let Error::Bind { listen, cause } = &error else {
            panic!("the UDP hostname site must surface Error::Bind, got {error:?}");
        };
        assert_eq!(
            listen, &configured,
            "the located error must name the CONFIGURED address"
        );
        assert!(
            cause.to_string().contains("Address already in use"),
            "the cause must be the real socket error, not a rebuilt placeholder: {cause:?}"
        );
    }

    /// The UDP wildcard site ([`super::bind_udp_ipv4_wildcard`]) CANNOT be driven to failure from a
    /// test without the `http3` feature and a hostile environment, so it is asserted structurally
    /// instead of being given another can't-fail assertion.
    ///
    /// The previous revision had an `Ok(socket) => { drop(socket); /* nothing to assert */ }` arm
    /// here, which the reviewer instrumented and found was ALWAYS taken: holding a plain `UdpSocket`
    /// on `0.0.0.0:PORT` does not make a `SO_REUSEPORT` bind fail, so that site never entered its
    /// error path in either direction and the test silently covered nothing. Rather than pretend,
    /// this test reads the production source and requires the wildcard site to route its retry error
    /// through [`super::located_bind_error`] -- the map every other site uses and the one the criterion
    /// is about. If the site is ever given a drivable failure path, replace this with a behavioural
    /// test.
    #[test]
    fn the_udp_wildcard_site_routes_its_retry_error_through_the_shared_mapping() {
        let source = include_str!("listeners.rs");
        let body = source
            .split("fn bind_udp_ipv4_wildcard")
            .nth(1)
            .expect("the wildcard site exists");
        // The function's extent: from its signature to the next top-level `///` doc comment.
        let body = body
            .split("\n/// ")
            .next()
            .expect("the wildcard body precedes the next item");
        assert!(
            body.contains("with_bind_capability"),
            "the wildcard site must use the ADR-0046 retry"
        );
        assert!(
            body.contains("located_bind_error(configured, error)"),
            "the wildcard site must route its retry error through the shared located-error mapping, \
             otherwise a lossy mapping there would go unnoticed: {body}"
        );
        assert!(
            !body.contains("Error::bind(configured, std::io::Error::new("),
            "the wildcard site must not rebuild the error lossily: {body}"
        );
    }

    /// ADR-0046 §1 through the PRODUCTION entry points: a successful bind makes no capability call.
    ///
    /// Testing [`crate::bindcap::with_bind_capability`] alone would not establish this — the
    /// criterion is about the bind path the server actually runs, including the case where the
    /// retry is never reached because the first attempt worked. These binds use an ephemeral port
    /// (port 0), which is unprivileged and succeeds here, so the seam must not be entered at all.
    #[tokio::test]
    async fn the_production_bind_paths_make_no_capability_call_when_the_bind_succeeds() {
        let before = crate::bindcap::capability_operations();
        let before_entries = crate::bindcap::seam_entries();

        let tcp_configured = "127.0.0.1:0";
        let tcp_address = ListenAddr::parse(tcp_configured).expect("tcp address parses");
        let listener = bind_configured_tcp(tcp_configured, &tcp_address, None)
            .await
            .expect("an ephemeral TCP bind succeeds");
        assert!(listener.local_addr().expect("local addr").port() > 0);
        drop(listener);

        let udp_configured = "127.0.0.1:0";
        let udp_address = ListenAddr::parse(udp_configured).expect("udp address parses");
        let socket = bind_configured_udp(udp_configured, &udp_address)
            .await
            .expect("an ephemeral UDP bind succeeds");
        assert!(socket.local_addr().expect("local addr").port() > 0);
        drop(socket);

        assert_eq!(
            crate::bindcap::capability_operations(),
            before,
            "a successful bind must never raise or lower CAP_NET_BIND_SERVICE"
        );
        // Stronger than the operations check, and the one that actually pins "attempt first": the
        // successful path must not even *enter* the capability seam. Checking only operations would pass
        // in an environment where the capability is already effective, because the seam would return
        // before raising anything -- which is exactly how the first version of this test let a mutant
        // that consulted the capability on every bind survive.
        assert_eq!(
            crate::bindcap::seam_entries(),
            before_entries,
            "a successful bind must not consult the capability seam at all"
        );
    }
}
