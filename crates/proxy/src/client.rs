//! Shared outbound HTTP client for proxying and health checks.
//!
//! The connector routes URIs by scheme:
//!
//! * `http://host:port/...` is dialed over TCP by hyper-util's [`HttpConnector`].
//! * `https://host:port/...` is dialed over TCP and wrapped in TLS (when the handler configures
//!   `transport.tls`); the server name comes from [`crate::tls::UpstreamTls`].
//! * `unix://<hex-encoded-socket-path>/...` is dialed over a Unix domain socket. The socket path
//!   is carried in the URI authority (hex-encoded, because an authority cannot contain `/`) so
//!   that hyper's connection pool keys each socket separately and the connector itself stays
//!   stateless and `Clone`.
//! * `unixs://<hex-encoded-socket-path>/...` is the same socket wrapped in TLS.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::Uri;
use http_body_util::Full;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio_rustls::client::TlsStream;
use tower_service::Service;

use crate::tls::UpstreamTls;

/// Hyper client body type used for outbound requests.
pub type ClientBody = Full<Bytes>;

/// The outbound client type.
pub type HttpClient = Client<UpstreamConnector, ClientBody>;

/// Connector supporting TCP, Unix-socket, and TLS upstreams.
#[derive(Clone, Debug)]
pub struct UpstreamConnector {
    tcp: HttpConnector,
    tls: Option<Arc<UpstreamTls>>,
}

impl UpstreamConnector {
    /// Create a plaintext-only connector with tokio-backed TCP dialing.
    pub fn new() -> Self {
        Self {
            tcp: tcp_connector(),
            tls: None,
        }
    }

    /// Create a connector that enables TLS for `https://`/`unixs://` URIs.
    pub fn with_tls(tls: Option<Arc<UpstreamTls>>) -> Self {
        Self {
            tcp: tcp_connector(),
            tls,
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
        Box::pin(async move {
            match uri.scheme_str() {
                Some("unix") => {
                    #[cfg(unix)]
                    {
                        let path = unix_socket_path(&uri)?;
                        let stream = tokio::net::UnixStream::connect(&path).await?;
                        Ok(TokioIo::new(UpstreamStream::Unix(stream)))
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
                        Ok(TokioIo::new(UpstreamStream::UnixTls(Box::new(stream))))
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
                    Ok(TokioIo::new(UpstreamStream::Tls(Box::new(stream))))
                }
                _ => {
                    let stream = tcp.call(uri).await.map_err(io::Error::other)?.into_inner();
                    Ok(TokioIo::new(UpstreamStream::Tcp(stream)))
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

/// Either transport hyper may drive for an upstream connection.
#[derive(Debug)]
pub enum UpstreamStream {
    /// TCP connection to a `host:port` upstream.
    Tcp(tokio::net::TcpStream),
    /// Unix domain socket connection.
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    /// TLS connection over TCP.
    Tls(Box<TlsStream<tokio::net::TcpStream>>),
    /// TLS connection over a Unix domain socket.
    #[cfg(unix)]
    UnixTls(Box<TlsStream<tokio::net::UnixStream>>),
}

impl Connection for UpstreamStream {
    fn connected(&self) -> Connected {
        match self {
            UpstreamStream::Tcp(stream) => stream.connected(),
            #[cfg(unix)]
            UpstreamStream::Unix(stream) => stream.connected(),
            // TLS connections are HTTP/1.1-only (ALPN advertises only http/1.1), so the default
            // empty connection metadata is correct.
            UpstreamStream::Tls(_) => Connected::new(),
            #[cfg(unix)]
            UpstreamStream::UnixTls(_) => Connected::new(),
        }
    }
}

impl tokio::io::AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            UpstreamStream::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            UpstreamStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
            #[cfg(unix)]
            UpstreamStream::UnixTls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            UpstreamStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            UpstreamStream::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            UpstreamStream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
            #[cfg(unix)]
            UpstreamStream::UnixTls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            UpstreamStream::Unix(stream) => Pin::new(stream).poll_flush(cx),
            UpstreamStream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            #[cfg(unix)]
            UpstreamStream::UnixTls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            UpstreamStream::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            UpstreamStream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            #[cfg(unix)]
            UpstreamStream::UnixTls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Build the plaintext client used by the reverse proxy and active health checks.
pub fn build_client() -> HttpClient {
    build_client_with_tls(None)
}

/// Build the outbound client, enabling TLS when `transport.tls` is configured.
pub fn build_client_with_tls(tls: Option<Arc<UpstreamTls>>) -> HttpClient {
    Client::builder(TokioExecutor::new()).build(UpstreamConnector::with_tls(tls))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use std::convert::Infallible;

    #[test]
    fn uri_scheme_selects_transport() {
        // The connector is stateless; only the URI scheme decides between TCP, Unix and TLS.
        let unix = Uri::from_static("unix://2f72756e2f6170702e736f636b/health");
        assert_eq!(unix.scheme_str(), Some("unix"));
        let unix_tls = Uri::from_static("unixs://2f72756e2f6170702e736f636b/health");
        assert_eq!(unix_tls.scheme_str(), Some("unixs"));
        let tcp = Uri::from_static("http://127.0.0.1:8080/health");
        assert_eq!(tcp.scheme_str(), Some("http"));
        let https = Uri::from_static("https://127.0.0.1:8443/health");
        assert_eq!(https.scheme_str(), Some("https"));
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
            .body(Full::new(Bytes::new()))
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
            .body(Full::new(Bytes::new()))
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
            .body(Full::new(Bytes::new()))
            .unwrap();
        let error = client
            .request(request)
            .await
            .expect_err("https without TLS config must fail");
        assert!(error.is_connect(), "expected a connect error, got {error}");
    }
}
