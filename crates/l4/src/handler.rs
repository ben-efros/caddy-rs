//! L4 handler pipeline: composable connection handlers and their ordered execution.
//!
//! A route's action is executed by a [`HandlerPipeline`]: an ordered list of [`L4Handler`] stages
//! (for example `tls -> proxy_protocol -> proxy`). Each stage receives the same
//! [`HandlerContext`], which owns the connection stream and the route generation the connection was
//! matched against; a stage can wrap or replace the stream (TLS termination), write to it (PROXY
//! protocol), or consume it (the proxy/DNS stage).
//!
//! When a stage fails, the pipeline logs the handler and reason at error level, drops the stream
//! (closing the TCP connection) and returns the typed [`HandlerError`]. Dropping the stream is the
//! close: there is no half-processed connection left for a later stage.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::router::Route;

/// A bidirectional byte stream an L4 handler can operate on.
pub trait L4Stream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> L4Stream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A boxed connection stream handed through the pipeline.
pub type BoxedStream = Box<dyn L4Stream>;

/// A handler stage failure, naming the stage and the reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerError {
    handler: &'static str,
    message: String,
}

impl HandlerError {
    /// Creates an error raised by the named handler.
    pub fn new(handler: &'static str, message: impl Into<String>) -> Self {
        Self {
            handler,
            message: message.into(),
        }
    }

    /// The handler that failed.
    pub fn handler(&self) -> &'static str {
        self.handler
    }

    /// The failure reason.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "l4 handler {} failed: {}", self.handler, self.message)
    }
}

impl std::error::Error for HandlerError {}

/// The per-connection state handed through the pipeline.
pub struct HandlerContext {
    stream: Option<BoxedStream>,
    route: Arc<Route>,
}

impl HandlerContext {
    /// Creates a context for a connection matched to `route`.
    pub fn new(stream: BoxedStream, route: Arc<Route>) -> Self {
        Self {
            stream: Some(stream),
            route,
        }
    }

    /// The route (and therefore the generation) this connection is served by.
    pub fn route(&self) -> &Arc<Route> {
        &self.route
    }

    /// Mutable access to the stream, if a previous stage has not consumed it.
    pub fn stream(&mut self) -> Option<&mut BoxedStream> {
        self.stream.as_mut()
    }

    /// Takes the stream out of the pipeline (a terminal handler does this).
    pub fn take_stream(&mut self) -> Option<BoxedStream> {
        self.stream.take()
    }

    /// Replaces the stream (for example after TLS termination) and returns the previous one.
    pub fn replace_stream(&mut self, stream: BoxedStream) -> Option<BoxedStream> {
        self.stream.replace(stream)
    }

    /// Whether a stream is still available for a later stage.
    pub fn has_stream(&self) -> bool {
        self.stream.is_some()
    }

    /// Drops the stream, closing the connection. Returns whether there was a stream to close.
    pub fn close(&mut self) -> bool {
        self.stream.take().is_some()
    }
}

/// One stage of an L4 pipeline.
#[async_trait]
pub trait L4Handler: Send + Sync {
    /// Stable stage name, used in the pipeline order and in error logs.
    fn name(&self) -> &'static str;

    /// Runs this stage. The stage may read/write/replace/take the context's stream.
    async fn handle(&self, ctx: &mut HandlerContext) -> Result<(), HandlerError>;
}

/// An ordered list of L4 handlers.
#[derive(Default)]
pub struct HandlerPipeline {
    handlers: Vec<Arc<dyn L4Handler>>,
}

impl HandlerPipeline {
    /// Creates a pipeline that runs `handlers` in the given order.
    pub fn new(handlers: Vec<Arc<dyn L4Handler>>) -> Self {
        Self { handlers }
    }

    /// The stage names, in execution order (for example `["tls", "proxy_protocol", "proxy"]`).
    pub fn names(&self) -> Vec<&'static str> {
        self.handlers.iter().map(|handler| handler.name()).collect()
    }

    /// The number of stages.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether the pipeline has no stages.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Runs every stage in order. On the first failure the connection is closed (the stream is
    /// dropped) and the error is returned; a successful pipeline leaves the terminal stage to
    /// consume the stream.
    ///
    /// The stage order is validated before any stage runs, so a route that would inject a PROXY
    /// header after the payload it must precede, or terminate TLS after proxying started, fails
    /// loudly instead of serving traffic in an order ADR-030 forbids.
    pub async fn run(&self, mut ctx: HandlerContext) -> Result<(), HandlerError> {
        let names = self.names();
        if let Err(error) = crate::handlers::tls::validate_stage_order(&names) {
            tracing::error!(
                route = ctx.route().host(),
                error = %error,
                "l4 handler order is invalid; closing the connection"
            );
            ctx.close();
            return Err(HandlerError::new(
                names.first().copied().unwrap_or("pipeline"),
                error.to_string(),
            ));
        }
        for handler in &self.handlers {
            if let Err(error) = handler.handle(&mut ctx).await {
                tracing::error!(
                    handler = handler.name(),
                    route = ctx.route().host(),
                    error = %error,
                    "l4 handler failed; closing the connection"
                );
                ctx.close();
                return Err(error);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for HandlerPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandlerPipeline")
            .field("handlers", &self.names())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{HandlerContext, HandlerError, HandlerPipeline, L4Handler};
    use crate::actions::{FallbackConfig, FallbackReason, SniAction};
    use crate::router::Route;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    struct Recorder {
        name: &'static str,
        calls: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    #[async_trait]
    impl L4Handler for Recorder {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn handle(&self, _ctx: &mut HandlerContext) -> Result<(), HandlerError> {
            self.calls.lock().unwrap().push(self.name);
            if self.fail {
                Err(HandlerError::new(self.name, "stage failed"))
            } else {
                Ok(())
            }
        }
    }

    fn route() -> Arc<Route> {
        Arc::new(Route::fallback(SniAction::Fallback(FallbackConfig::new(
            FallbackReason::NoRoute,
        ))))
    }

    fn context() -> HandlerContext {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        HandlerContext::new(Box::new(server), route())
    }

    #[tokio::test]
    async fn stages_run_in_order() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let pipeline = HandlerPipeline::new(vec![
            Arc::new(Recorder {
                name: "tls",
                calls: Arc::clone(&calls),
                fail: false,
            }),
            Arc::new(Recorder {
                name: "proxy_protocol",
                calls: Arc::clone(&calls),
                fail: false,
            }),
            Arc::new(Recorder {
                name: "proxy",
                calls: Arc::clone(&calls),
                fail: false,
            }),
        ]);
        assert_eq!(pipeline.names(), ["tls", "proxy_protocol", "proxy"]);
        pipeline.run(context()).await.expect("pipeline succeeds");
        assert_eq!(*calls.lock().unwrap(), ["tls", "proxy_protocol", "proxy"]);
    }

    #[tokio::test]
    async fn error_stops_the_pipeline_and_closes_the_connection() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let pipeline = HandlerPipeline::new(vec![
            Arc::new(Recorder {
                name: "tls",
                calls: Arc::clone(&calls),
                fail: false,
            }),
            Arc::new(Recorder {
                name: "proxy_protocol",
                calls: Arc::clone(&calls),
                fail: true,
            }),
            Arc::new(Recorder {
                name: "proxy",
                calls: Arc::clone(&calls),
                fail: false,
            }),
        ]);
        let error = pipeline.run(context()).await.expect_err("stage failure");
        assert_eq!(error.handler(), "proxy_protocol");
        assert!(error.to_string().contains("proxy_protocol"));
        // The failing stage ran, the later stage did not.
        assert_eq!(*calls.lock().unwrap(), ["tls", "proxy_protocol"]);
    }

    #[test]
    fn context_can_replace_take_and_close_the_stream() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let mut ctx = HandlerContext::new(Box::new(server), route());
        assert!(ctx.has_stream());
        assert!(ctx.stream().is_some());

        let (replacement, _peer) = tokio::io::duplex(16);
        let previous = ctx.replace_stream(Box::new(replacement));
        assert!(previous.is_some());
        let taken = ctx.take_stream();
        assert!(taken.is_some());
        assert!(!ctx.has_stream());
        assert!(!ctx.close());
    }

    #[test]
    fn empty_pipeline_is_a_noop() {
        let pipeline = HandlerPipeline::default();
        assert_eq!(pipeline.len(), 0);
        assert!(pipeline.is_empty());
        assert_eq!(pipeline.names(), Vec::<&'static str>::new());
    }

    #[test]
    fn handler_error_is_displayable() {
        let error = HandlerError::new("tls", "certificate unavailable");
        assert_eq!(error.handler(), "tls");
        assert_eq!(error.message(), "certificate unavailable");
        assert!(error.to_string().contains("certificate unavailable"));
    }

    #[allow(dead_code)]
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn pipeline_is_send_and_sync() {
        assert_send_sync::<HandlerPipeline>();
    }
}
