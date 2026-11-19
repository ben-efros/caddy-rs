//! The L4 `http` handler: hand a matched connection to the L7 HTTP dispatcher in memory.
//!
//! This is the terminal action of an `http` route (ADR-030). The route has already matched the
//! connection on its bytes — ClientHello SNI for TLS routes, or the HTTP preface for cleartext —
//! and may have terminated TLS. Rather than proxying the stream to a loopback port, this hands
//! ownership to an [`HttpDispatcher`], which drives a real HTTP/1.1-and-HTTP/2 connection over the
//! same stream in the same process.
//!
//! ## Why the dispatcher is a trait
//!
//! The HTTP pipeline lives in `caddy-rs-server`, which sits *above* this crate: it depends on
//! `caddy-rs-l4` to reach these handler types. Whatever drives the connection therefore cannot be
//! named here without inverting the crate graph, so this module defines the smallest trait the
//! call needs and the server supplies the implementation. That also keeps the call testable with an
//! in-memory fake, and it matches how every other stage in this crate is shaped — a free async
//! function taking the stream by value, not a trait object held in the route.
//!
//! ## What the handoff carries
//!
//! [`HandoffContext`] is the state the HTTP layer cannot recover from the bytes: the client's
//! address, the SNI the route matched on, and whether TLS was terminated here.
//!
//! The peer address is a property of the accepted socket rather than of the route, so it is a
//! parameter of [`http_route`] and must come from whoever accepted the connection. It is
//! deliberately not derived from the route, and `None` is reserved for streams that genuinely have
//! no address (an in-memory duplex in a test) — the L7 side reads it for
//! `{http.request.remote.*}` and for the `remote_ip`/`client_ip` matchers, so dropping it on an
//! L4-routed connection would make every one of those silently see nothing.
//!
//! ## Failure behaviour
//!
//! The stream is moved into the dispatcher, so a failure returns an error with the stream already
//! gone: the connection is closed and the caller logs the reason. There is deliberately no path
//! that reports failure while keeping the stream alive.

use std::fmt;

use crate::handler::BoxedStream;
use crate::router::Route;

/// The connection state an L4 route carries into the L7 request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandoffContext {
    /// The client's address as accepted by the listener.
    ///
    /// Carried because the L7 request's `{http.request.remote.*}` placeholders and the
    /// `remote_ip`/`client_ip` matchers read it, and an in-memory handoff has no socket for the
    /// HTTP layer to ask. `None` only when the acceptor genuinely had no address (a `duplex`
    /// stream in a test), never as a substitute for looking it up.
    pub peer: Option<std::net::SocketAddr>,
    /// The SNI the route matched on, when the connection presented one.
    ///
    /// Taken from the `Route` the connection was matched against, which is the name the route was
    /// selected by. It is deliberately not re-derived from the HTTP `Host` header: a client can
    /// send a `Host` that disagrees with the SNI it connected under.
    pub sni: Option<String>,
    /// Whether the route terminated TLS before handing the stream off.
    ///
    /// The `http` action hands over a **plaintext** stream by contract, so this is true only when
    /// an earlier `terminate` stage in the same pipeline owned the certificate.
    pub tls: bool,
    /// Whether this route enables HTTP/2 cleartext (h2c) on the handed-off stream.
    pub h2c: bool,
}

/// Why a handoff did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffError {
    reason: String,
}

impl HandoffError {
    /// Creates a handoff failure with the given reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// The failure reason, as logged by the caller.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http handoff failed: {}", self.reason)
    }
}

impl std::error::Error for HandoffError {}

/// Serves one handed-off connection as HTTP.
///
/// Implemented by `caddy-rs-server`, which drives hyper over the stream and routes each request
/// through the same pipeline as its own listeners. Owns the stream: on error it must already have
/// dropped it.
#[async_trait::async_trait]
pub trait HttpDispatcher: Send + Sync {
    /// Serves `stream` as HTTP, applying `context` to every request dispatched.
    async fn dispatch(
        &self,
        stream: BoxedStream,
        context: HandoffContext,
    ) -> Result<(), HandoffError>;
}

/// Hands a matched connection to `dispatcher`.
///
/// Mirrors [`crate::handlers::proxy::proxy_route`]: the stream is taken by value, so ownership
/// transfer is the whole API and nothing can be used after the handoff starts. The context is read
/// from the route's [`crate::actions::HttpConfig`], which is where the adapter stores the server
/// name and the h2c decision.
pub async fn http_route<S>(
    client: S,
    peer: Option<std::net::SocketAddr>,
    route: &Route,
    dispatcher: &dyn HttpDispatcher,
) -> Result<(), HandoffError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let crate::actions::SniAction::Http(config) = route.action() else {
        return Err(HandoffError::new(format!(
            "route {} has action `{}`, not `http`",
            route.host(),
            route.action().kind()
        )));
    };
    let context = HandoffContext {
        peer,
        // The config's server name is the one the adapter validated for this route; fall back to
        // the route's own host so a wildcard route still records what it matched.
        sni: config
            .server_name()
            .map(str::to_owned)
            .or_else(|| Some(route.host().to_owned()).filter(|host| !host.is_empty())),
        // The `http` action hands over plaintext by contract; TLS termination is a separate
        // preceding stage and is not this handler's business to claim.
        tls: false,
        h2c: config.h2c(),
    };
    dispatcher.dispatch(Box::new(client), context).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{
        FallbackConfig, FallbackReason, HttpConfig, PassthroughConfig, SniAction,
    };
    use crate::router::{RouteDefinition, SniRouter};
    use std::sync::{Arc, Mutex};

    /// A dispatcher that records what it was handed and can be made to fail.
    struct Recorder {
        seen: Mutex<Vec<HandoffContext>>,
        fail: bool,
    }

    impl Recorder {
        fn new(fail: bool) -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                fail,
            }
        }
    }

    #[async_trait::async_trait]
    impl HttpDispatcher for Recorder {
        async fn dispatch(
            &self,
            _stream: BoxedStream,
            context: HandoffContext,
        ) -> Result<(), HandoffError> {
            self.seen.lock().expect("lock").push(context);
            if self.fail {
                return Err(HandoffError::new("dispatcher refused"));
            }
            Ok(())
        }
    }

    /// The route the router produces for `host` with `action`, exercising the same construction the
    /// adapter uses rather than building a `Route` directly.
    fn route_for(host: &str, action: SniAction) -> Arc<Route> {
        let fallback = SniAction::Passthrough(
            PassthroughConfig::new("127.0.0.1:9001").expect("valid fallback"),
        );
        let router = SniRouter::new(
            vec![RouteDefinition::new(host, action).expect("valid route")],
            fallback,
        )
        .expect("valid router");
        router.lookup(Some(host))
    }

    fn http_route_for(host: &str, server_name: Option<&str>) -> Arc<Route> {
        route_for(
            host,
            SniAction::Http(HttpConfig::new(server_name.map(str::to_owned)).expect("valid config")),
        )
    }

    #[tokio::test]
    async fn the_handoff_carries_the_configured_server_name() {
        let recorder = Recorder::new(false);
        let (client, _server) = tokio::io::duplex(64);
        http_route(
            client,
            None,
            &http_route_for("web.example.com", Some("web.example.com")),
            &recorder,
        )
        .await
        .expect("handoff");
        let seen = recorder.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].sni.as_deref(), Some("web.example.com"));
    }

    #[tokio::test]
    async fn a_route_without_a_configured_name_falls_back_to_its_host() {
        let recorder = Recorder::new(false);
        let (client, _server) = tokio::io::duplex(64);
        http_route(
            client,
            None,
            &http_route_for("*.example.com", None),
            &recorder,
        )
        .await
        .expect("handoff");
        let seen = recorder.seen.lock().expect("lock");
        assert_eq!(seen[0].sni.as_deref(), Some("*.example.com"));
    }

    #[tokio::test]
    async fn a_dispatch_failure_is_reported_not_swallowed() {
        let recorder = Recorder::new(true);
        let (client, _server) = tokio::io::duplex(64);
        let error = http_route(
            client,
            None,
            &http_route_for("web.example.com", Some("web.example.com")),
            &recorder,
        )
        .await
        .expect_err("must fail");
        assert!(error.reason().contains("dispatcher refused"));
    }

    /// A route whose action is not `http` must be refused by name, not silently handed off: this
    /// stage would otherwise serve a passthrough stream as HTTP.
    #[tokio::test]
    async fn a_non_http_route_is_refused_with_its_action_named() {
        let recorder = Recorder::new(false);
        let (client, _server) = tokio::io::duplex(64);
        let route = route_for(
            "ssh.example.com",
            SniAction::Fallback(FallbackConfig::new(FallbackReason::NoRoute)),
        );
        let error = http_route(client, None, &route, &recorder)
            .await
            .expect_err("must be refused");
        assert!(
            error.reason().contains("fallback"),
            "reason names the action: {}",
            error.reason()
        );
        assert!(recorder.seen.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn h2c_is_carried_from_the_route_config() {
        let recorder = Recorder::new(false);
        let (client, _server) = tokio::io::duplex(64);
        let route = route_for(
            "web.example.com",
            SniAction::Http(
                HttpConfig::new(Some("web.example.com".to_owned()))
                    .expect("valid config")
                    .with_h2c(true),
            ),
        );
        http_route(client, None, &route, &recorder)
            .await
            .expect("handoff");
        assert!(recorder.seen.lock().expect("lock")[0].h2c);
    }
}
