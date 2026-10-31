//! Listener binding and accept loops.
//!
//! Each configured listen address gets one accept task. The task reads its router from the shared
//! generation map at connection time, so a reload that keeps the same listen address does not need
//! to rebind (no listener gap, no `EADDRINUSE`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use caddy_rs_admin::{AdminApi, AdminRequest};
use caddy_rs_core::{GenerationStore, ListenAddr, Network};
use caddy_rs_http::Router;

use crate::error::Error;
use crate::http::serve_request;

/// Router map shared with accept loops, keyed by configured listen address.
pub type SharedRouters = Arc<RwLock<HashMap<String, Arc<Router>>>>;

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
    routers: SharedRouters,
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
                spawn_tcp_accept_loop(listener, configured.to_string(), routers, store, receiver);
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
            let task =
                spawn_unix_accept_loop(listener, configured.to_string(), routers, store, receiver);
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

fn spawn_tcp_accept_loop(
    listener: TcpListener,
    listen_key: String,
    routers: SharedRouters,
    store: Arc<GenerationStore>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { continue };
                    let router = routers
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get(&listen_key)
                        .cloned();
                    let generation = store.acquire();
                    let connection_shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        let _generation = generation;
                        let service = service_fn(move |request: hyper::Request<Incoming>| {
                            let router = router.clone();
                            async move {
                                let response = match router {
                                    Some(router) => serve_request(router, request, Some(peer), false).await,
                                    None => error_response(),
                                };
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });
                        serve_connection(stream, service, connection_shutdown).await;
                    });
                }
            }
        }
    })
}

fn spawn_unix_accept_loop(
    listener: UnixListener,
    listen_key: String,
    routers: SharedRouters,
    store: Arc<GenerationStore>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((stream, _peer)) = accepted else { continue };
                    let router = routers
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get(&listen_key)
                        .cloned();
                    let generation = store.acquire();
                    let connection_shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        let _generation = generation;
                        let service = service_fn(move |request: hyper::Request<Incoming>| {
                            let router = router.clone();
                            async move {
                                let response = match router {
                                    Some(router) => serve_request(router, request, None, false).await,
                                    None => error_response(),
                                };
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });
                        serve_connection(stream, service, connection_shutdown).await;
                    });
                }
            }
        }
    })
}

async fn serve_connection<I, S>(io: I, service: S, mut shutdown: watch::Receiver<bool>)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: hyper::service::Service<
            hyper::Request<Incoming>,
            Response = hyper::Response<Full<Bytes>>,
            Error = std::convert::Infallible,
        > + Send
        + 'static,
    S::Future: Send + 'static,
{
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let connection = builder.serve_connection(TokioIo::new(io), service);
    tokio::pin!(connection);
    tokio::select! {
        result = connection.as_mut() => {
            if let Err(error) = result {
                tracing::debug!(%error, "connection ended with error");
            }
        }
        _ = shutdown.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
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
                        serve_connection(stream, service, connection_shutdown).await;
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
