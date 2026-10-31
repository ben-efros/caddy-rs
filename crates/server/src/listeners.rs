//! Listener binding and accept loops.
//!
//! Each configured listen address gets one accept task. The task reads its router (and the
//! server's limits) from the shared generation map at connection time, so a reload that keeps
//! the same listen address does not need to rebind (no listener gap, no `EADDRINUSE`).
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
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use caddy_rs_admin::{AdminApi, AdminRequest};
use caddy_rs_core::{GenerationStore, ListenAddr, Network};
use caddy_rs_http::Router;

use crate::error::Error;
use crate::http::serve_request_with_limits;
use crate::limits::ServerLimits;

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
}

/// Listener state shared with accept loops, keyed by configured listen address.
pub(crate) type SharedListeners = Arc<RwLock<HashMap<String, Arc<ListenerState>>>>;

/// A running listener task.
pub(crate) struct ListenerHandle {
    pub(crate) shutdown: watch::Sender<bool>,
    pub(crate) task: JoinHandle<()>,
    pub(crate) bound: String,
    pub(crate) socket_addr: Option<SocketAddr>,
}

impl ListenerHandle {
    pub(crate) async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

/// Bind the listener for a Caddy listen address.
pub(crate) async fn bind(
    configured: &str,
    listeners: SharedListeners,
    store: Arc<GenerationStore>,
) -> Result<ListenerHandle, Error> {
    let address = ListenAddr::parse(configured).map_err(|reason| Error::Listen {
        listen: configured.to_string(),
        reason,
    })?;
    match address.network {
        Network::Tcp => {
            let listener = TcpListener::bind(&address.address)
                .await
                .map_err(|error| Error::bind(configured, error))?;
            let socket_addr = listener
                .local_addr()
                .map_err(|error| Error::bind(configured, error))?;
            let (shutdown, receiver) = watch::channel(false);
            let task =
                spawn_tcp_accept_loop(listener, configured.to_string(), listeners, store, receiver);
            Ok(ListenerHandle {
                shutdown,
                task,
                bound: socket_addr.to_string(),
                socket_addr: Some(socket_addr),
            })
        }
        Network::Unix => {
            let path = address.address.clone();
            if std::path::Path::new(&path).exists() {
                std::fs::remove_file(&path).map_err(|error| Error::bind(configured, error))?;
            }
            let listener =
                UnixListener::bind(&path).map_err(|error| Error::bind(configured, error))?;
            let (shutdown, receiver) = watch::channel(false);
            let task = spawn_unix_accept_loop(
                listener,
                configured.to_string(),
                listeners,
                store,
                receiver,
            );
            Ok(ListenerHandle {
                shutdown,
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

/// State captured for one accepted connection.
struct ConnectionContext {
    /// Router to serve, or `None` while the listener is being retired (responds 503).
    router: Option<Arc<Router>>,
    limits: Arc<ServerLimits>,
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
        },
        None => ConnectionContext {
            router: None,
            limits: Arc::new(ServerLimits::default()),
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
                    tokio::spawn(async move {
                        let _generation = generation;
                        let _permit = permit;
                        let limits = Arc::clone(&context.limits);
                        let service_limits = Arc::clone(&limits);
                        let router = context.router;
                        let activity = Arc::new(ConnectionActivity::default());
                        let service_activity = Arc::clone(&activity);
                        let service = service_fn(move |request: hyper::Request<Incoming>| {
                            let router = router.clone();
                            let limits = Arc::clone(&service_limits);
                            let activity = Arc::clone(&service_activity);
                            async move {
                                let _in_flight = activity.begin();
                                let response = match router {
                                    Some(router) => {
                                        serve_request_with_limits(&limits, router, request, Some(peer), false).await
                                    }
                                    None => error_response(),
                                };
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });
                        serve_connection(stream, service, connection_shutdown, limits, activity).await;
                    });
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
                    tokio::spawn(async move {
                        let _generation = generation;
                        let _permit = permit;
                        let limits = Arc::clone(&context.limits);
                        let service_limits = Arc::clone(&limits);
                        let router = context.router;
                        let activity = Arc::new(ConnectionActivity::default());
                        let service_activity = Arc::clone(&activity);
                        let service = service_fn(move |request: hyper::Request<Incoming>| {
                            let router = router.clone();
                            let limits = Arc::clone(&service_limits);
                            let activity = Arc::clone(&service_activity);
                            async move {
                                let _in_flight = activity.begin();
                                let response = match router {
                                    Some(router) => {
                                        serve_request_with_limits(&limits, router, request, None, false).await
                                    }
                                    None => error_response(),
                                };
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });
                        serve_connection(stream, service, connection_shutdown, limits, activity).await;
                    });
                }
            }
        }
    })
}

/// Serve one connection with the server's limits and graceful-shutdown/idle handling.
async fn serve_connection<I, S>(
    io: I,
    service: S,
    mut shutdown: watch::Receiver<bool>,
    limits: Arc<ServerLimits>,
    activity: Arc<ConnectionActivity>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: hyper::service::Service<
            hyper::Request<Incoming>,
            Response = hyper::Response<Full<Bytes>>,
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
    let connection = builder.serve_connection(TokioIo::new(io), service);
    tokio::pin!(connection);
    let idle = idle_after(activity, limits.idle_timeout);
    tokio::pin!(idle);

    tokio::select! {
        result = connection.as_mut() => {
            if let Err(error) = result {
                tracing::debug!(%error, "connection ended with error");
            }
        }
        _ = shutdown.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.as_mut().await;
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

fn error_response() -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(503)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(b"503 Service Unavailable")))
        .expect("static response is valid")
}

/// Bind the admin API listener.
pub(crate) async fn bind_admin(configured: &str, api: AdminApi) -> Result<ListenerHandle, Error> {
    let listener = TcpListener::bind(configured)
        .await
        .map_err(|error| Error::bind(configured, error))?;
    let socket_addr = listener
        .local_addr()
        .map_err(|error| Error::bind(configured, error))?;
    let (shutdown, mut receiver) = watch::channel(false);
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = receiver.changed() => {
                    if changed.is_err() || *receiver.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((stream, _peer)) = accepted else { continue };
                    let api = api.clone();
                    let connection_shutdown = receiver.clone();
                    tokio::spawn(async move {
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
                                        .body(Full::new(response.body))
                                        .expect("admin response is valid"),
                                )
                            }
                        });
                        let limits = Arc::new(ServerLimits::default());
                        let activity = Arc::new(ConnectionActivity::default());
                        serve_connection(stream, service, connection_shutdown, limits, activity).await;
                    });
                }
            }
        }
    });
    Ok(ListenerHandle {
        shutdown,
        task,
        bound: socket_addr.to_string(),
        socket_addr: Some(socket_addr),
    })
}
