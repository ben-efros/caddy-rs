//! Server error routes (`handle_errors`) and the `error` handler (T-ROUTE-012).
//!
//! Caddy sources matched: `modules/caddyhttp/server.go` (error chain + `HTTPErrorConfig.WithError`
//! placeholders), `modules/caddyhttp/caddyhttp.go` (`errorEmptyHandler`),
//! `modules/caddyhttp/staticerror.go` (the `error` handler).

use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use serde_json::json;

use caddy_rs_http::{Error, Request, ResponseOutcome, RouterBuilder};

fn request(path: &str) -> Request {
    let mut request = Request::new(Method::GET, path.parse::<Uri>().unwrap());
    request
        .headers
        .insert(http::header::HOST, "example.com".parse().unwrap());
    request
}

fn error_routes() -> serde_json::Value {
    json!({
        "routes": [
            {
                "match": [{"expression": {"expr": "{http.error.status_code} in [403, 410]"}}],
                "handle": [{
                    "handler": "static_response",
                    "status_code": 200,
                    "body": "handled {http.error.status_code} {http.error.status_text}: {http.error.message}"
                }]
            },
            {
                "handle": [{
                    "handler": "static_response",
                    "status_code": 500,
                    "body": "fallback {http.error.status_code}"
                }]
            }
        ]
    })
}

async fn response_for(router: &caddy_rs_http::Router, path: &str) -> (StatusCode, Bytes) {
    match router
        .handle_upgradable(request(path))
        .await
        .expect("serves")
    {
        ResponseOutcome::Response(response) => {
            let response = response.into_buffered().await.expect("buffers");
            (response.status, response.body)
        }
        ResponseOutcome::Upgrade(_) => panic!("unexpected upgrade"),
    }
}

#[tokio::test]
async fn error_routes_run_for_the_error_handler() {
    let routes = json!([
        {
            "match": [{"path": ["/boom*"]}],
            "handle": [
                {"handler": "error", "status_code": 403, "error": "forbidden for {http.request.host}"}
            ]
        },
        {"handle": [{"handler": "static_response", "body": "ok"}]}
    ]);
    let router = RouterBuilder::new()
        .with_error_routes(Some(&error_routes()), "errors")
        .expect("error routes parse")
        .build(routes.as_array().unwrap())
        .expect("routes build");

    // The status-filtered route matches the error handler's 403.
    let (status, body) = response_for(&router, "/boom").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        Bytes::from_static(b"handled 403 Forbidden: forbidden for example.com")
    );

    // A normal (200) response never enters the error chain.
    let (status, body) = response_for(&router, "/fine").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Bytes::from_static(b"ok"));
}

#[tokio::test]
async fn error_routes_run_for_error_status_responses() {
    // caddy-rs routes handler-produced >=400 responses through the error chain when configured
    // (this is what lets `reverse_proxy`'s 502/503 reach `handle_errors`); Caddy's HandlerError
    // path has the same visible result for upstream failures.
    let routes = json!([
        {"handle": [{"handler": "static_response", "status_code": 404, "body": "missing"}]}
    ]);
    let router = RouterBuilder::new()
        .with_error_routes(Some(&error_routes()), "errors")
        .expect("error routes parse")
        .build(routes.as_array().unwrap())
        .expect("routes build");
    let (status, body) = response_for(&router, "/anything").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, Bytes::from_static(b"fallback 404"));
}

#[tokio::test]
async fn unmatched_error_routes_fall_back_to_the_error_status() {
    // The status route matches 403/410; an error with 502 falls through to Caddy's
    // `errorEmptyHandler`, which writes the original error status with an empty body.
    let routes = json!([
        {"handle": [{"handler": "error", "status_code": 502, "error": "upstream failed"}]}
    ]);
    let router = RouterBuilder::new()
        .with_error_routes(
            Some(&json!({
                "routes": [
                    {"match": [{"expression": {"expr": "{http.error.status_code} in [403]"}}],
                     "handle": [{"handler": "static_response", "body": "nope"}]}
                ]
            })),
            "errors",
        )
        .expect("error routes parse")
        .build(routes.as_array().unwrap())
        .expect("routes build");
    let (status, body) = response_for(&router, "/x").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.is_empty());
}

#[tokio::test]
async fn without_error_routes_handler_errors_keep_their_status() {
    let routes = json!([
        {"handle": [{"handler": "error", "status_code": 418, "error": "teapot"}]}
    ]);
    let router = RouterBuilder::new()
        .build(routes.as_array().unwrap())
        .expect("routes build");
    let error = match router.handle(request("/x")).await {
        Ok(_) => panic!("handler error must surface without error routes"),
        Err(error) => error,
    };
    assert_eq!(error.handler_status(), Some(StatusCode::IM_A_TEAPOT));
    assert!(error.handler_message().contains("teapot"));
    assert!(matches!(error, Error::Handler { .. }));
}

#[tokio::test]
async fn error_status_can_be_a_placeholder() {
    let routes = json!([
        {"handle": [
            {"handler": "vars", "custom_status": "451"},
            {"handler": "error", "status_code": "{http.vars.custom_status}", "error": "legal"}
        ]}
    ]);
    let router = RouterBuilder::new()
        .with_error_routes(Some(&json!({"routes": [
            {"handle": [{"handler": "static_response", "body": "{http.error.status_code} {http.error.message}"}]}
        ]})), "errors")
        .expect("error routes parse")
        .build(routes.as_array().unwrap())
        .expect("routes build");
    let (status, body) = response_for(&router, "/x").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Bytes::from_static(b"451 legal"));
}

#[test]
fn malformed_error_routes_are_located_errors() {
    let router = RouterBuilder::new().with_error_routes(
        Some(&json!({"routes": "nope"})),
        "apps.http.servers.srv0.errors",
    );
    assert!(router.is_err(), "non-array routes must be rejected");
    let router = RouterBuilder::new().with_error_routes(Some(&json!([])), "errors");
    assert!(router.is_err(), "errors must be an object");
    let router = RouterBuilder::new()
        .with_error_routes(
            Some(&json!({"routes": [{"handle": [{"handler": "expression"}]}]})),
            "errors",
        )
        .expect("error route parse")
        .build(&[]);
    assert!(router.is_err(), "unknown handler is loud");
}

#[test]
fn expression_matcher_supports_handle_errors_status_filters() {
    // Exact strings emitted by Caddy's `parseHandleErrors` for `handle_errors 404 410` and
    // `handle_errors 5xx`.
    for expression in [
        "{http.error.status_code} in [404, 410]",
        "{http.error.status_code} >= 500 && {http.error.status_code} <= 599",
    ] {
        let matcher = caddy_rs_http::matchers::build_matcher_set(
            &json!({"expression": {"expr": expression}}),
        )
        .unwrap_or_else(|error| panic!("{expression}: {error}"));
        assert_eq!(matcher.len(), 1);
    }
    // Other expressions are loudly unsupported (located config errors) rather than silently
    // non-matching: full CEL matcher functions are not implemented by the documented subset.
    // CEL backtick raw strings are accepted (T-ROUTE-039), so they are no longer in this list.
    for expression in ["method('GET')"] {
        let error = match caddy_rs_http::matchers::build_matcher_set(
            &json!({"expression": {"expr": expression}}),
        ) {
            Ok(_) => panic!("unsupported expression `{expression}` must be loud"),
            Err(error) => error,
        };
        assert!(
            matches!(error, Error::InvalidConfig { .. }),
            "{expression}: {error}"
        );
    }
}
