//! Shared outbound HTTP client for proxying and health checks.
//!
//! The connector routes URIs by scheme:
//!
//! * `http://host:port/...` is dialed over TCP by hyper-util's [`HttpConnector`].
//! * `unix://<hex-encoded-socket-path>/...` is dialed over a Unix domain socket. The socket path
//!   is carried in the URI authority (hex-encoded, because an authority cannot contain `/`) so
//!   that hyper's connection pool keys each socket separately and the connector itself stays
//!   stateless and `Clone`.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::Uri;
use http_body_util::Full;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tower_service::Service;

/// Hyper client body type used for outbound requests.
pub type ClientBody = Full<Bytes>;

/// The outbound client type.
pub type HttpClient = Client<UpstreamConnector, ClientBody>;

/// Connector supporting both TCP and Unix-socket upstreams.
#[derive(Clone, Debug)]
pub struct UpstreamConnector {
    tcp: HttpConnector,
}

impl UpstreamConnector {
    /// Create a connector with tokio-backed TCP dialing.
    pub fn new() -> Self {
        Self {
            tcp: HttpConnector::new(),
        }
    }
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
        Box::pin(async move {
            if uri.scheme_str() == Some("unix") {
                #[cfg(unix)]
                {
                    let authority = uri.host().unwrap_or_default();
                    let path = crate::upstream::decode_unix_authority(authority)
                        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
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
            } else {
                let stream = tcp.call(uri).await.map_err(io::Error::other)?.into_inner();
                Ok(TokioIo::new(UpstreamStream::Tcp(stream)))
            }
        })
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
}

impl Connection for UpstreamStream {
    fn connected(&self) -> Connected {
        match self {
            UpstreamStream::Tcp(stream) => stream.connected(),
            #[cfg(unix)]
            UpstreamStream::Unix(stream) => stream.connected(),
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
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            UpstreamStream::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            UpstreamStream::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Build the client used by the reverse proxy and active health checks.
pub fn build_client() -> HttpClient {
    Client::builder(TokioExecutor::new()).build(UpstreamConnector::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use std::convert::Infallible;

    #[test]
    fn uri_scheme_selects_transport() {
        // The connector is stateless; only the URI scheme decides between TCP and Unix dialing.
        let unix = Uri::from_static("unix://2f72756e2f6170702e736f636b/health");
        assert_eq!(unix.scheme_str(), Some("unix"));
        let tcp = Uri::from_static("http://127.0.0.1:8080/health");
        assert_eq!(tcp.scheme_str(), Some("http"));
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
}
