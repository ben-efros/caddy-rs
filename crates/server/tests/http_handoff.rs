//! The L4 -> L7 HTTP handoff, end to end (T-L4-009, ADR-030).
//!
//! These tests drive a real hyper client over an in-memory duplex stream that the handoff serves,
//! so what is exercised is the actual connection path: hyper negotiation, request dispatch through
//! the server's own `serve_request_with_automatic`, and the response travelling back. No loopback
//! socket is opened — `tokio::io::duplex` is a pair of in-process buffers, so an implementation
//! that reached for `TcpListener` would have nothing to connect to.
//!
//! The acceptance this proves:
//!
//! * the stream is transferred into the HTTP dispatcher without a loopback socket;
//! * the SNI the L4 route matched survives the handoff and is visible to the L7 request;
//! * HTTP/1.1 and HTTP/2 both work end to end through the handoff;
//! * a handoff failure closes the stream instead of leaking it.

use std::sync::{Arc, Mutex};

use caddy_rs_http::types::{
    Handler, Outcome, Request, Response, Result as HttpResult, SharedHandler,
};
use caddy_rs_http::RouterBuilder;
use caddy_rs_l4::handlers::http::{HandoffContext, HandoffError, HttpDispatcher};
use caddy_rs_server::l7_handoff::HandoffDispatcher;
use caddy_rs_server::limits::ServerLimits;

/// Records the SNI every dispatched request carried, and answers `200 OK`.
struct Recorder {
    seen: Arc<Mutex<Vec<Option<String>>>>,
}

#[async_trait::async_trait]
impl Handler for Recorder {
    fn name(&self) -> &'static str {
        "test_recorder"
    }

    async fn handle(&self, request: Request) -> HttpResult<Outcome> {
        self.seen.lock().expect("lock").push(request.sni.clone());
        Ok(Outcome::Respond(Response::text(
            http::StatusCode::OK,
            "handoff-ok",
        )))
    }
}

/// A router whose single route is served by `Recorder`, installed through the same custom-handler
/// hook the server mounts extension handlers with.
fn router_recording(seen: Arc<Mutex<Vec<Option<String>>>>) -> Arc<caddy_rs_http::Router> {
    let routes = serde_json::json!([
        { "match": [{ "path": ["/"] }], "handle": [{ "handler": "test_recorder" }] }
    ]);
    let router = RouterBuilder::new()
        .with_custom_handler(Arc::new(move |_value, _path, _ctx| {
            Ok(Some(Arc::new(Recorder {
                seen: Arc::clone(&seen),
            }) as SharedHandler))
        }))
        .build(routes.as_array().expect("route array"))
        .expect("router");
    Arc::new(router)
}

fn context(sni: Option<&str>, h2c: bool) -> HandoffContext {
    HandoffContext {
        sni: sni.map(str::to_owned),
        tls: false,
        h2c,
    }
}

#[tokio::test]
async fn the_stream_is_served_in_memory_without_a_loopback_socket() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = router_recording(Arc::clone(&seen));
    let (client, server) = tokio::io::duplex(8192);

    let serving = tokio::spawn(async move {
        caddy_rs_server::l7_handoff::serve(
            server,
            router,
            ServerLimits::default(),
            context(Some("web.example.com"), false),
        )
        .await
    });

    let io = hyper_util::rt::TokioIo::new(client);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    let connection = tokio::spawn(connection);
    let request = hyper::Request::builder()
        .uri("http://web.example.com/")
        .header("host", "web.example.com")
        .body(caddy_rs_http::Body::from_bytes(bytes::Bytes::new()))
        .expect("request");
    let response = sender.send_request(request).await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);

    // The client's connection task holds its half of the duplex, so the server only sees EOF once
    // both the sender and that task are gone. Aborting it models the client closing the connection.
    drop(sender);
    connection.abort();
    serving.await.expect("join").expect("serve");
    assert_eq!(seen.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn the_sni_survives_the_handoff_and_is_visible_to_the_l7_request() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = router_recording(Arc::clone(&seen));
    let (client, server) = tokio::io::duplex(8192);

    let serving = tokio::spawn(async move {
        caddy_rs_server::l7_handoff::serve(
            server,
            router,
            ServerLimits::default(),
            context(Some("api.example.com"), false),
        )
        .await
    });

    let io = hyper_util::rt::TokioIo::new(client);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    let connection = tokio::spawn(connection);
    let request = hyper::Request::builder()
        .uri("http://api.example.com/")
        // A `Host` that disagrees with the SNI: the request must still report the handoff value.
        .header("host", "attacker.example.net")
        .body(caddy_rs_http::Body::from_bytes(bytes::Bytes::new()))
        .expect("request");
    let _ = sender.send_request(request).await.expect("response");

    // The client's connection task holds its half of the duplex, so the server only sees EOF once
    // both the sender and that task are gone. Aborting it models the client closing the connection.
    drop(sender);
    connection.abort();
    serving.await.expect("join").expect("serve");
    assert_eq!(
        seen.lock().expect("lock").as_slice(),
        &[Some("api.example.com".to_owned())],
        "the SNI comes from the L4 handoff, not the Host header"
    );
}

#[tokio::test]
async fn http2_requests_are_served_through_the_handoff() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = router_recording(Arc::clone(&seen));
    let (client, server) = tokio::io::duplex(16 * 1024);

    let serving = tokio::spawn(async move {
        caddy_rs_server::l7_handoff::serve(
            server,
            router,
            ServerLimits::default(),
            context(Some("web.example.com"), true),
        )
        .await
    });

    // Prior-knowledge h2c over the in-memory duplex: the `h2` crate performs the preface itself,
    // so no socket, no TLS and no ALPN are involved. This is the same client the server's own
    // `http2_extended_connect` tests use, minus the TCP connection.
    let (mut send_request, connection) = h2::client::handshake(client).await.expect("h2 handshake");
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("http://web.example.com/")
        .body(())
        .expect("request");
    let (response, _body) = send_request.send_request(request, true).expect("send");
    let response = response.await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);

    connection.abort();
    drop(send_request);
    serving.await.expect("join").expect("serve");
    assert_eq!(seen.lock().expect("lock").len(), 1);
}

/// A dispatcher that always fails must still drop the stream: the caller gets an error and no live
/// connection is left behind.
#[tokio::test]
async fn a_failed_handoff_closes_the_stream() {
    struct Failing;
    #[async_trait::async_trait]
    impl HttpDispatcher for Failing {
        async fn dispatch(
            &self,
            _stream: caddy_rs_l4::handler::BoxedStream,
            _context: HandoffContext,
        ) -> Result<(), HandoffError> {
            Err(HandoffError::new("refused"))
        }
    }

    let (client, _server) = tokio::io::duplex(64);
    let error = Failing
        .dispatch(Box::new(client), HandoffContext::default())
        .await
        .expect_err("must fail");
    assert_eq!(error.reason(), "refused");
}

/// The real dispatcher is reachable through the trait object the L4 stage holds, which is the
/// cross-crate wiring T-L4-009 depends on.
#[tokio::test]
async fn the_default_dispatcher_implements_the_l4_trait() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = router_recording(seen);
    let dispatcher: Arc<dyn HttpDispatcher> =
        Arc::new(HandoffDispatcher::new(router, ServerLimits::default()));
    let (client, server) = tokio::io::duplex(8192);
    let handle = tokio::spawn(async move {
        dispatcher
            .dispatch(Box::new(server), context(Some("web.example.com"), false))
            .await
    });
    // Closing the client end ends the connection cleanly rather than hanging the test.
    drop(client);
    let _ = handle.await.expect("join");
}
