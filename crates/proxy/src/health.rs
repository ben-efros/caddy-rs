//! Upstream health checks.
//!
//! Active checks periodically request `health_uri` on each upstream and mark it healthy/unhealthy.
//! Passive checks happen in the proxy request path: a connection failure marks the upstream down.
//! The scheduler is a plain Tokio task; the handler's retry loop consumes the resulting state.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;

use crate::client::HttpClient;
use crate::upstream::Upstream;

/// Active health-check configuration.
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// URI path requested on each upstream.
    pub uri: String,
    /// Delay between rounds.
    pub interval: Duration,
    /// Per-request timeout.
    pub timeout: Duration,
    /// HTTP method.
    pub method: http::Method,
    /// Expected status code; `None` accepts any 2xx.
    pub expected_status: Option<u16>,
    /// Extra request headers.
    pub headers: Vec<(String, String)>,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            uri: "/".to_string(),
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            method: http::Method::GET,
            expected_status: None,
            headers: Vec::new(),
        }
    }
}

impl HealthCheck {
    /// Perform one check. Returns whether the upstream is healthy.
    ///
    /// The check uses the same [`HttpClient`] transport as proxying, so TCP and Unix-socket
    /// upstreams are both supported. Unix-socket checks use `localhost` as the Host, matching
    /// Caddy's active health checker.
    pub async fn check_once(&self, client: &HttpClient, upstream: &Upstream) -> bool {
        let mut builder = hyper::Request::builder()
            .method(self.method.clone())
            .uri(upstream.url(&self.uri))
            .header(http::header::HOST, upstream.fallback_host());
        for (name, value) in &self.headers {
            builder = builder.header(name, value);
        }
        let Ok(request) = builder.body(Full::new(Bytes::new())) else {
            return false;
        };
        let result = tokio::time::timeout(self.timeout, client.request(request)).await;
        let Ok(Ok(response)) = result else {
            return false;
        };
        match self.expected_status {
            Some(expected) => response.status().as_u16() == expected,
            None => response.status().is_success(),
        }
    }

    /// Spawn the periodic checker. The task runs until the returned handle is aborted or the
    /// process exits.
    pub fn spawn(
        self: Arc<Self>,
        upstreams: Vec<Arc<Upstream>>,
        client: HttpClient,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                for upstream in &upstreams {
                    let healthy = self.check_once(&client, upstream).await;
                    upstream.set_healthy(healthy);
                }
            }
        })
    }
}

/// Quick request-body drain helper used by tests and the proxy path.
pub async fn drain(body: hyper::body::Incoming) -> Result<Bytes, hyper::Error> {
    body.collect().await.map(|collected| collected.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    async fn spawn_health_upstream(status: u16) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let service = service_fn(move |_request| async move {
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        address.to_string()
    }

    #[tokio::test]
    async fn active_check_marks_healthy_upstream() {
        let dial = spawn_health_upstream(200).await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck::default();
        let client = crate::client::build_client();
        assert!(check.check_once(&client, &upstream).await);
    }

    #[tokio::test]
    async fn active_check_marks_unhealthy_on_error_status() {
        let dial = spawn_health_upstream(500).await;
        let upstream = Arc::new(Upstream::new(dial, false));
        let check = HealthCheck::default();
        let client = crate::client::build_client();
        assert!(!check.check_once(&client, &upstream).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn active_check_works_over_unix_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("health.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let service = service_fn(move |_request| async move {
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        let upstream =
            Arc::new(Upstream::parse_dial(&format!("unix/{}", socket.display()), false).unwrap());
        let check = HealthCheck::default();
        let client = crate::client::build_client();
        assert!(check.check_once(&client, &upstream).await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn active_check_fails_when_unix_socket_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("missing.sock");
        let upstream =
            Arc::new(Upstream::parse_dial(&format!("unix/{}", socket.display()), false).unwrap());
        let check = HealthCheck::default();
        let client = crate::client::build_client();
        assert!(!check.check_once(&client, &upstream).await);
    }
}
