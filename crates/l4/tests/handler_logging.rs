//! Proves the pipeline's error path logs the failing handler and its reason.
//!
//! This lives in its own test binary: `tracing` caches per-callsite interest globally, so a test
//! that asserts on captured events must not race with other tests hitting the same callsite (here,
//! the pipeline's `tracing::error!`) under a different (or absent) subscriber.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use caddy_rs_l4::{
    FallbackConfig, FallbackReason, HandlerContext, HandlerError, HandlerPipeline, L4Handler,
    RouteDefinition, SniAction, SniRouter, TerminateConfig,
};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

struct FailingHandler;

#[async_trait]
impl L4Handler for FailingHandler {
    fn name(&self) -> &'static str {
        "proxy_protocol"
    }

    async fn handle(&self, _ctx: &mut HandlerContext) -> Result<(), HandlerError> {
        Err(HandlerError::new(self.name(), "stage failed"))
    }
}

/// Minimal `tracing` subscriber that records every formatted event.
#[derive(Clone)]
struct CaptureSubscriber {
    events: Arc<Mutex<Vec<String>>>,
}

struct FieldVisitor {
    fields: Vec<String>,
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.push(format!("{}={:?}", field.name(), value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.push(format!("{}={}", field.name(), value));
    }
}

impl Subscriber for CaptureSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = FieldVisitor { fields: Vec::new() };
        event.record(&mut visitor);
        self.events.lock().unwrap().push(format!(
            "{} {}",
            event.metadata().level(),
            visitor.fields.join(" ")
        ));
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[test]
fn handler_error_is_logged_with_handler_and_reason() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let subscriber = CaptureSubscriber {
        events: Arc::clone(&events),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    tracing::subscriber::with_default(subscriber, || {
        // Make sure the pipeline's callsite is (re)evaluated with this subscriber active.
        tracing::callsite::rebuild_interest_cache();
        runtime.block_on(async {
            let router = SniRouter::new(
                vec![RouteDefinition::new(
                    "example.com",
                    SniAction::Terminate(TerminateConfig::new("example.com").unwrap()),
                )
                .unwrap()],
                SniAction::Fallback(FallbackConfig::new(FallbackReason::NoRoute)),
            )
            .unwrap();
            let (_client, server) = tokio::io::duplex(16);
            let pipeline = HandlerPipeline::new(vec![Arc::new(FailingHandler)]);
            let ctx = HandlerContext::new(Box::new(server), router.lookup(Some("example.com")));
            let error = pipeline
                .run(ctx)
                .await
                .expect_err("the failing handler must abort the pipeline");
            assert_eq!(error.handler(), "proxy_protocol");
        });
    });

    let logged = events.lock().unwrap().join("\n");
    assert!(
        logged.contains("ERROR"),
        "expected an error-level event, got {logged:?}"
    );
    assert!(
        logged.contains("proxy_protocol"),
        "expected the handler name in the log, got {logged:?}"
    );
    assert!(
        logged.contains("stage failed"),
        "expected the failure reason in the log, got {logged:?}"
    );
}
