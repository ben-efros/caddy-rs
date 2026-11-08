//! Real-router tests for `http.handlers.acme_server` (T-TLS-085).
//!
//! These exercise the module through [`RouterBuilder`], so the registry wiring, the data-directory
//! contract and the pass-through behaviour of a handler that only owns `<path_prefix>*` are
//! covered in addition to the protocol unit tests in `src/acme_server.rs`.

use std::path::Path;

use caddy_rs_http::{Request, Response, Router, RouterBuilder};
use http::{header, Method, StatusCode, Uri};
use serde_json::{json, Value};

fn request(method: Method, path: &str, host: &str) -> Request {
    let mut request = Request::new(method, path.parse::<Uri>().expect("request URI"));
    request
        .headers
        .insert(header::HOST, host.parse().expect("host header"));
    request
}

fn routes(handler: Value) -> Value {
    json!([{
        "handle": [
            handler,
            {"handler": "static_response", "body": "next handler"}
        ]
    }])
}

fn build(routes: &Value, data_root: Option<&Path>) -> caddy_rs_http::Result<Router> {
    let mut builder = RouterBuilder::new();
    if let Some(root) = data_root {
        builder = builder.with_acme_server_data_root(root);
    }
    builder.build(routes.as_array().expect("routes array"))
}

async fn body_text(response: &Response) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}

#[tokio::test]
async fn router_serves_the_directory_and_passes_other_paths_through() {
    let directory = tempfile::tempdir().expect("data directory");
    let router = build(
        &routes(json!({"handler": "acme_server"})),
        Some(directory.path()),
    )
    .expect("acme_server builds");

    let response = router
        .handle(request(Method::GET, "/acme/local/directory", "acme.test"))
        .await
        .expect("router serves");
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).expect("directory JSON");
    assert_eq!(body["newNonce"], "https://acme.test/acme/local/new-nonce");
    assert_eq!(body["newOrder"], "https://acme.test/acme/local/new-order");

    // Requests outside the configured prefix are passed to the next handler in the chain.
    let response = router
        .handle(request(Method::GET, "/not-acme", "acme.test"))
        .await
        .expect("router serves");
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(body_text(&response).await, "next handler");
}

#[tokio::test]
async fn router_fails_closed_without_a_data_root_or_for_unsupported_challenges() {
    let error = build(&routes(json!({"handler": "acme_server"})), None)
        .err()
        .expect("a router without a data directory must not build acme_server");
    assert!(
        error
            .to_string()
            .contains("requires a Caddy filesystem data directory"),
        "{error}"
    );

    let directory = tempfile::tempdir().expect("data directory");
    let error = build(
        &routes(json!({"handler": "acme_server", "challenges": ["dns-01"]})),
        Some(directory.path()),
    )
    .err()
    .expect("dns-01 cannot be honoured by this build");
    assert!(error.to_string().contains("only http-01"), "{error}");

    let error = build(
        &routes(json!({"handler": "acme_server", "resolvers": ["1.1.1.1:53"]})),
        Some(directory.path()),
    )
    .err()
    .expect("resolvers only matter for dns-01");
    assert!(error.to_string().contains("dns-01"), "{error}");
}

#[tokio::test]
async fn optional_data_root_none_fails_closed_for_non_filesystem_storage() {
    let error = RouterBuilder::new()
        .with_optional_acme_server_data_root(None)
        .build(
            routes(json!({"handler": "acme_server"}))
                .as_array()
                .unwrap(),
        )
        .err()
        .expect("None must not fall back to a relative path");
    assert!(
        error
            .to_string()
            .contains("requires a Caddy filesystem data directory"),
        "{error}"
    );
}
