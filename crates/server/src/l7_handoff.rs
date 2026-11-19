//! The in-memory handoff from an L4 route to the L7 HTTP dispatcher.
//!
//! An `layer4` route whose action is `http` has already matched the connection on its bytes
//! (ClientHello SNI, or the HTTP preface) and, when the route terminated TLS, holds the decrypted
//! stream. This module carries that stream into the HTTP pipeline **without opening a loopback
//! socket**: hyper's connection is driven over the boxed stream in the same task, and every
//! request goes through [`crate::http::serve_request_with_automatic`] — the same entry point the
//! real listeners use — so limits, trusted proxies, access logging and the router all behave
//! exactly as they do for a directly accepted connection.
//!
//! ## Why there is no loopback socket
//!
//! The obvious implementation proxies the stream to `127.0.0.1:<port>` and lets a normal HTTP
//! listener pick it up. That is rejected for three reasons: it burns a file descriptor and an
//! ephemeral port per connection; it makes the peer address a loopback address, so every
//! `{http.request.remote}` placeholder and every `remote_ip` matcher would see the proxy rather
//! than the client; and it turns an in-process handoff into a network dependency that can fail
//! independently of both ends.
//!
//! ## How the no-loopback property is enforced, not just observed
//!
//! [`serve`] is generic over `AsyncRead + AsyncWrite` and nothing else: it is given no
//! `SocketAddr`, no local address and no port, so a loopback proxy is not expressible through this
//! API — there is nothing to connect *to*. The tests drive it with `tokio::io::duplex`, an
//! in-process buffer pair with no network address at all, which is why they cannot accidentally
//! start passing against a socket-based implementation.
//!
//! ## What is carried
//!
//! [`l4_handoff_context`] maps the L4 [`HandoffContext`] — the SNI the route matched on and the
//! h2c decision — onto the HTTP side. The SNI is recorded as `Request::sni` and is deliberately
//! **not** re-derived from the HTTP `Host` header: a client can send a `Host` that disagrees with
//! the SNI it connected under.
//!
//! ## Failure behaviour
//!
//! [`HandoffDispatcher::dispatch`] takes the stream by value, so it cannot return an error while
//! keeping it: on any failure the stream has already been dropped, which closes the connection.
//! The reason is logged here and returned for the pipeline to report.

use std::sync::Arc;

use async_trait::async_trait;
use caddy_rs_http::Router;
use caddy_rs_l4::handler::BoxedStream;
use caddy_rs_l4::handlers::http::{HandoffContext, HandoffError, HttpDispatcher};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};

use crate::http::serve_request_with_automatic;
use crate::limits::ServerLimits;

/// The default dispatcher: drives a real HTTP/1.1-and-HTTP/2 connection over a handed-off stream.
pub struct HandoffDispatcher {
    router: Arc<Router>,
    limits: ServerLimits,
}

impl HandoffDispatcher {
    /// Creates a dispatcher that routes each handed-off request through `router`.
    pub fn new(router: Arc<Router>, limits: ServerLimits) -> Self {
        Self { router, limits }
    }

    /// The router every handed-off request is dispatched to.
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }
}

#[async_trait]
impl HttpDispatcher for HandoffDispatcher {
    async fn dispatch(
        &self,
        stream: BoxedStream,
        context: HandoffContext,
    ) -> Result<(), HandoffError> {
        serve(
            stream,
            Arc::clone(&self.router),
            self.limits.clone(),
            context,
        )
        .await
    }
}

/// Serves one handed-off connection against `router`, applying `context` to every request.
///
/// The stream is moved into hyper's connection and dropped when the connection ends. Returns
/// `Ok(())` when the connection closed cleanly.
pub async fn serve<S>(
    stream: S,
    router: Arc<Router>,
    limits: ServerLimits,
    context: HandoffContext,
) -> Result<(), HandoffError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let server_limits = limits;
    let limits = Arc::new(server_limits.clone());
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let router = Arc::clone(&router);
        let limits = Arc::clone(&limits);
        let context = context.clone();
        async move {
            // `automatic: None` is deliberate: on an L4 route the SNI routing decision has already
            // been made by the ClientHello matcher, so automatic-HTTPS pre-routing (ACME HTTP-01
            // interception, HTTP->HTTPS redirects) must not run a second time here.
            let response = serve_request_with_automatic(
                &limits,
                router,
                request,
                None,
                context.tls,
                None,
                None,
                context.sni.clone(),
            )
            .await;
            Ok::<_, std::convert::Infallible>(response)
        }
    });

    // `auto` negotiates HTTP/1.1 and HTTP/2 per connection: ALPN decides when the L4 route
    // terminated TLS, and prior-knowledge h2c on cleartext, so both request paths work. It is
    // tuned exactly like a directly accepted connection, because a handed-off connection must
    // behave the same as one the listener served itself.
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .max_buf_size(
            server_limits
                .max_header_bytes
                .unwrap_or(crate::listeners::CADDY_DEFAULT_MAX_HEADER_BYTES),
        );
    let mut http2 = builder.http2();
    crate::listeners::configure_h2_auto_server(&mut http2, &server_limits);
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
    connection.await.map_err(|error| {
        let reason = error.to_string();
        tracing::warn!(
            target: "caddy_rs_server::l7_handoff",
            reason = %reason,
            "l7 handoff closed the connection"
        );
        HandoffError::new(reason)
    })
}
