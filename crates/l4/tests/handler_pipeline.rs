//! Behavioural tests for the L4 handler pipeline and route-generation reloads.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use caddy_rs_l4::{
    BoxedStream, FallbackConfig, FallbackReason, HandlerContext, HandlerError, HandlerPipeline,
    L4Handler, PassthroughConfig, RouteDefinition, SniAction, SniRouter, TerminateConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A stage that records its name and optionally fails.
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

/// A stage that writes a marker to the stream (like PROXY protocol would).
///
/// It reports the real stage name `proxy_protocol`, so a pipeline that places it where the
/// canonical order puts the PROXY header still validates.
struct WriteMarker {
    marker: &'static [u8],
}

#[async_trait]
impl L4Handler for WriteMarker {
    fn name(&self) -> &'static str {
        "proxy_protocol"
    }

    async fn handle(&self, ctx: &mut HandlerContext) -> Result<(), HandlerError> {
        let Some(stream) = ctx.stream() else {
            return Err(HandlerError::new(
                "proxy_protocol",
                "stream already consumed",
            ));
        };
        stream
            .write_all(self.marker)
            .await
            .map_err(|error| HandlerError::new("proxy_protocol", error.to_string()))
    }
}

/// A terminal stage that copies the stream payload and counts it.
struct Drain {
    bytes: Arc<AtomicUsize>,
}

#[async_trait]
impl L4Handler for Drain {
    fn name(&self) -> &'static str {
        "proxy"
    }

    async fn handle(&self, ctx: &mut HandlerContext) -> Result<(), HandlerError> {
        let Some(mut stream) = ctx.take_stream() else {
            return Err(HandlerError::new("proxy", "stream already consumed"));
        };
        let mut buffer = [0_u8; 256];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => {
                    self.bytes.fetch_add(read, Ordering::SeqCst);
                }
                Err(error) => return Err(HandlerError::new("proxy", error.to_string())),
            }
        }
        Ok(())
    }
}

fn route(host: &str, action: SniAction) -> RouteDefinition {
    RouteDefinition::new(host, action).expect("valid route")
}

fn terminate(host: &str) -> SniAction {
    SniAction::Terminate(TerminateConfig::new(host).unwrap())
}

fn fallback() -> SniAction {
    SniAction::Fallback(FallbackConfig::new(FallbackReason::NoRoute))
}

fn context(stream: BoxedStream, router: &SniRouter, sni: &str) -> HandlerContext {
    HandlerContext::new(stream, router.lookup(Some(sni)))
}

#[tokio::test]
async fn components_compose_in_tls_proxy_protocol_proxy_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = SniRouter::new(
        vec![route("example.com", terminate("example.com"))],
        fallback(),
    )
    .unwrap();
    let (mut client, server) = tokio::io::duplex(64);
    let pipeline = HandlerPipeline::new(vec![
        Arc::new(Recorder {
            name: "tls",
            calls: Arc::clone(&calls),
            fail: false,
        }),
        Arc::new(WriteMarker { marker: b"PROXY" }),
        Arc::new(Recorder {
            name: "proxy",
            calls: Arc::clone(&calls),
            fail: false,
        }),
    ]);
    assert_eq!(pipeline.names(), ["tls", "proxy_protocol", "proxy"]);

    pipeline
        .run(context(Box::new(server), &router, "example.com"))
        .await
        .expect("pipeline succeeds");
    assert_eq!(*calls.lock().unwrap(), ["tls", "proxy"]);

    // The marker written by the middle stage reached the peer.
    let mut seen = [0_u8; 5];
    client.read_exact(&mut seen).await.unwrap();
    assert_eq!(&seen, b"PROXY");
}

#[tokio::test]
async fn failing_stage_closes_the_stream_with_a_logged_reason() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = SniRouter::new(
        vec![route("example.com", terminate("example.com"))],
        fallback(),
    )
    .unwrap();
    let (mut client, server) = tokio::io::duplex(64);
    let pipeline = HandlerPipeline::new(vec![
        Arc::new(WriteMarker { marker: b"partial" }),
        Arc::new(Recorder {
            name: "proxy",
            calls: Arc::clone(&calls),
            fail: true,
        }),
    ]);

    let error = pipeline
        .run(context(Box::new(server), &router, "example.com"))
        .await
        .expect_err("stage failure");
    assert_eq!(error.handler(), "proxy");
    assert!(error.to_string().contains("proxy"));

    // The connection was closed after the error: partial bytes then EOF, no later-stage output.
    let mut seen = Vec::new();
    client.read_to_end(&mut seen).await.unwrap();
    assert_eq!(seen, b"partial");
    assert_eq!(*calls.lock().unwrap(), ["proxy"]);
}

#[tokio::test]
async fn terminal_stage_drains_the_whole_stream() {
    let router = SniRouter::new(
        vec![route("example.com", terminate("example.com"))],
        fallback(),
    )
    .unwrap();
    let (mut client, server) = tokio::io::duplex(256);
    client.write_all(b"hello l4").await.unwrap();
    client.shutdown().await.unwrap();
    let bytes = Arc::new(AtomicUsize::new(0));
    let pipeline = HandlerPipeline::new(vec![Arc::new(Drain {
        bytes: Arc::clone(&bytes),
    })]);
    pipeline
        .run(context(Box::new(server), &router, "example.com"))
        .await
        .expect("pipeline succeeds");
    assert_eq!(bytes.load(Ordering::SeqCst), b"hello l4".len());
}

#[tokio::test]
async fn in_flight_connection_keeps_its_route_across_a_reload() {
    let router = Arc::new(
        SniRouter::new(
            vec![route("example.com", terminate("example.com"))],
            fallback(),
        )
        .unwrap(),
    );
    let (mut client, server) = tokio::io::duplex(256);

    // The connection matched the old generation and keeps that Arc<Route>.
    let route = router.lookup(Some("example.com"));
    assert_eq!(route.action_kind(), "terminate");
    let bytes = Arc::new(AtomicUsize::new(0));
    let drain = Arc::new(Drain {
        bytes: Arc::clone(&bytes),
    });
    let pipeline = HandlerPipeline::new(vec![drain]);
    let old_connection = tokio::spawn(async move {
        let ctx = HandlerContext::new(Box::new(server), route);
        pipeline.run(ctx).await
    });

    // Reload while the old connection is draining.
    router
        .load(vec![route_definition(
            "example.com",
            passthrough("127.0.0.1:9443"),
        )])
        .expect("valid reload");
    assert_eq!(
        router.lookup(Some("example.com")).action_kind(),
        "passthrough"
    );

    client.write_all(b"old generation bytes").await.unwrap();
    client.shutdown().await.unwrap();
    old_connection
        .await
        .expect("old connection task")
        .expect("old connection drains without error");
    assert_eq!(bytes.load(Ordering::SeqCst), b"old generation bytes".len());

    // A new connection is served by the new generation.
    assert_eq!(
        router.lookup(Some("example.com")).action_kind(),
        "passthrough"
    );
}

#[tokio::test]
async fn empty_pipeline_is_a_noop_returning_ok() {
    let router = SniRouter::new(
        vec![route("example.com", terminate("example.com"))],
        fallback(),
    )
    .unwrap();
    let (_client, server) = tokio::io::duplex(16);
    let pipeline = HandlerPipeline::default();
    pipeline
        .run(context(Box::new(server), &router, "example.com"))
        .await
        .expect("no stages succeed");
}

fn route_definition(host: &str, action: SniAction) -> RouteDefinition {
    RouteDefinition::new(host, action).expect("valid route")
}

fn passthrough(upstream: &str) -> SniAction {
    SniAction::Passthrough(PassthroughConfig::new(upstream).unwrap())
}
