//! `forward_auth` with a user `handle_response` block over real listeners (T-CONF-057).
//!
//! Caddy's `forward_auth` expansion seeds the reverse_proxy `handle_response` list with its
//! canonical 2xx handler and only then appends the user's own entries
//! (`modules/caddyhttp/reverseproxy/forwardauth/caddyfile.go`: `rpHandler.HandleResponse =
//! [goodResponseHandler]` before `UnmarshalCaddyfile`; `FinalizeUnmarshalCaddyfile` appends and
//! moves matcher-less entries last). The canonical entry is therefore first: on a 2xx auth
//! response it copies `copy_headers` and lets handling continue, while a non-2xx auth response
//! reaches the user's handler. These tests drive the adapted Caddyfile through a real listener.

use std::convert::Infallible;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};

fn free_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

async fn request(address: SocketAddr, path: &str) -> (u16, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://{address}{path}"))
        .body(Full::new(Bytes::new()))
        .expect("valid request");
    let response = client.request(request).await.expect("request completes");
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    (status, body)
}

/// Start the given Caddyfile through the adapter on a real listener.
async fn start_caddyfile(caddyfile: &str) -> ServerRuntime {
    let adapted = caddy_rs_config::adapt(caddyfile).expect("Caddyfile adapts");
    let config = Config::from_value(adapted.config).expect("adapted config decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("adapted config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    runtime
}

/// Upstream that answers every request with a fixed status, body and headers.
async fn spawn_upstream(
    status: u16,
    body: &'static str,
    headers: Vec<(&'static str, &'static str)>,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let address = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let headers = headers.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_request| {
                    let headers = headers.clone();
                    async move {
                        let mut builder = hyper::Response::builder().status(status);
                        for (name, value) in headers {
                            builder = builder.header(name, value);
                        }
                        Ok::<_, Infallible>(
                            builder
                                .body(Full::new(Bytes::from_static(body.as_bytes())))
                                .expect("response"),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    address
}

#[tokio::test]
async fn user_handle_response_runs_for_a_non_2xx_auth_response() {
    // The auth service rejects the request. The canonical 2xx handler does not match, so the
    // user's matcher-less `handle_response` (appended after it) must answer instead of the
    // upstream response being proxied through unchanged.
    let auth = spawn_upstream(401, "auth-service-body", vec![]).await;
    let port = free_loopback_port();
    let caddyfile = format!(
        r#"{{
	admin 127.0.0.1:0
	auto_https off
}}

http://127.0.0.1:{port} {{
	forward_auth 127.0.0.1:{auth_port} {{
		uri /auth
		handle_response {{
			respond "denied" 401
		}}
	}}

	respond "should-not-run"
}}
"#,
        auth_port = auth.port()
    );
    let runtime = start_caddyfile(&caddyfile).await;
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (status, body) = request(address, "/private").await;
    assert_eq!(status, 401, "user handle_response status");
    assert_eq!(
        body,
        Bytes::from_static(b"denied"),
        "the user's respond handler must run; upstream body must not leak"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn canonical_header_copy_runs_before_the_user_handler_for_a_2xx_auth_response() {
    // The canonical 2xx entry stays first: it copies `Remote-User` from the auth response onto
    // the request and lets handling continue to the downstream `respond`, which observes the
    // copied header. The user's matcher-less `respond denied 401` entry is ordered after it and
    // must not shadow the 2xx flow.
    let auth = spawn_upstream(200, "", vec![("Remote-User", "alice")]).await;
    let port = free_loopback_port();
    let caddyfile = format!(
        r#"{{
	admin 127.0.0.1:0
	auto_https off
}}

http://127.0.0.1:{port} {{
	forward_auth 127.0.0.1:{auth_port} {{
		uri /auth
		copy_headers Remote-User
		handle_response {{
			respond "denied" 401
		}}
	}}

	respond "user={{http.request.header.Remote-User}}"
}}
"#,
        auth_port = auth.port()
    );
    let runtime = start_caddyfile(&caddyfile).await;
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (status, body) = request(address, "/private").await;
    assert_eq!(status, 200, "canonical 2xx gate passes the request through");
    assert_eq!(
        body,
        Bytes::from_static(b"user=alice"),
        "the canonical header copy must run before the user's handler"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn log_skip_inside_the_user_handle_response_is_rejected_loudly_by_the_runtime() {
    // The adapter now preserves the user's block exactly like Caddy, including `log_skip`
    // (`{"handler":"vars","log_skip":true}`). This build's `handle_response` subset only accepts
    // string `vars` values (T-PROXY-037), so the configuration is refused when the runtime is
    // built with a located `NotImplemented` error instead of silently dropping the handler.
    let port = free_loopback_port();
    let caddyfile = format!(
        r#"{{
	admin 127.0.0.1:0
	auto_https off
}}

http://127.0.0.1:{port} {{
	forward_auth 127.0.0.1:9091 {{
		uri /auth
		handle_response {{
			log_skip
			respond "denied" 401
		}}
	}}
}}
"#
    );
    let adapted = caddy_rs_config::adapt(&caddyfile).expect("Caddyfile adapts");
    assert!(
        adapted.config.to_string().contains("\"log_skip\":true"),
        "the user's log_skip handler must reach the adapted JSON: {}",
        adapted.config
    );
    let config = Config::from_value(adapted.config).expect("adapted config decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("config decodes");
    let mut runtime = ServerRuntime::new(store);
    let error = runtime
        .apply()
        .await
        .expect_err("boolean vars inside handle_response is not implemented");
    let message = error.to_string();
    assert!(message.contains("not implemented"), "{message}");
    assert!(message.contains("T-PROXY-037"), "{message}");
}
