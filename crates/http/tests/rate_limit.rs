//! Real-router tests for the caddy-rs `rate_limit` extension (T-ROUTE-025).
//!
//! Upstream Caddy v2.11.7 has no built-in `rate_limit` module (it is a plugin), so these tests
//! exercise a clearly-marked extension configured through the caddy-rs handler JSON with a
//! deterministic [`ManualClock`].

use std::sync::Arc;
use std::time::Duration;

use caddy_rs_http::{
    CustomHandlerFactory, ManualClock, RateLimitClock, RateLimitHandler, Request, Response, Router,
    RouterBuilder, SharedHandler,
};
use http::{header, Method, StatusCode};
use serde_json::{json, Value};

fn clocked_router(clock: Arc<ManualClock>, routes: &Value) -> Router {
    let factory: CustomHandlerFactory = Arc::new(
        move |value: &Value, path: &str, _context: &caddy_rs_http::HandlerBuildContext| {
            if value.get("handler").and_then(Value::as_str) == Some("test_rate_limit") {
                let clock_dyn = Arc::clone(&clock) as Arc<dyn RateLimitClock>;
                let handler = RateLimitHandler::from_json_with_clock(value, path, clock_dyn)?;
                Ok(Some(Arc::new(handler) as SharedHandler))
            } else {
                Ok(None)
            }
        },
    );
    RouterBuilder::new()
        .with_custom_handler(factory)
        .build(routes.as_array().expect("routes array"))
        .expect("routes build")
}

fn rate_limit_config(extra: Value) -> Value {
    let mut value = json!({
        "handler": "test_rate_limit",
        "rate": "1r/s",
        "burst": 2,
        "key": "{http.request.header.X-Key}"
    });
    if let (Some(value), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
        for (key, extra) in extra {
            value.insert(key.clone(), extra.clone());
        }
    }
    value
}

fn routes(limit: Value) -> Value {
    json!([{
        "handle": [
            limit,
            {"handler": "static_response", "body": "ok"}
        ]
    }])
}

fn request(key: &str) -> Request {
    let mut request = Request::new(Method::GET, "/".parse().unwrap());
    request.headers.insert("x-key", key.parse().unwrap());
    request
}

async fn serve(router: &Router, key: &str) -> Response {
    router
        .handle_outcome(request(key))
        .await
        .expect("serves")
        .into_response()
}

trait OutcomeExt {
    fn into_response(self) -> Response;
}

impl OutcomeExt for caddy_rs_http::Outcome {
    fn into_response(self) -> Response {
        match self {
            caddy_rs_http::Outcome::Continue(_) => {
                panic!("router returned Continue instead of a response")
            }
            caddy_rs_http::Outcome::Respond(response) => response,
        }
    }
}

#[tokio::test]
async fn route_returns_200s_then_429s_and_refills() {
    let clock = Arc::new(ManualClock::new());
    let router = clocked_router(Arc::clone(&clock), &routes(rate_limit_config(json!({}))));

    // Burst of two is served through the non-terminal limiter, then the third request is limited.
    assert_eq!(serve(&router, "a").await.status, StatusCode::OK);
    assert_eq!(serve(&router, "a").await.status, StatusCode::OK);
    let response = serve(&router, "a").await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers[header::RETRY_AFTER], "1");

    // One second at 1 r/s refills a token; the next request reaches the protected handler.
    clock.advance(Duration::from_secs(1));
    assert_eq!(serve(&router, "a").await.status, StatusCode::OK);
}

#[tokio::test]
async fn limited_response_body_headers_and_status_are_configurable() {
    let clock = Arc::new(ManualClock::new());
    let router = clocked_router(
        clock,
        &routes(rate_limit_config(json!({
            "rate": "1r/s",
            "burst": 1,
            "status_code": 429,
            "headers": {
                "X-RateLimit-Reason": ["slow down"],
                "Retry-After": ["999"]
            },
            "body": "custom limited body"
        }))),
    );
    assert_eq!(serve(&router, "a").await.status, StatusCode::OK);
    let response = serve(&router, "a").await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.body, "custom limited body");
    assert_eq!(response.headers["x-ratelimit-reason"], "slow down");
    // Explicit configuration overrides the computed Retry-After value.
    assert_eq!(response.headers[header::RETRY_AFTER], "999");
}

#[tokio::test]
async fn matcher_scoped_routes_only_limit_matching_requests() {
    let clock = Arc::new(ManualClock::new());
    let router = clocked_router(
        Arc::clone(&clock),
        &json!([
            {
                "match": [{"path": ["/limited"]}],
                "handle": [
                    rate_limit_config(json!({"rate": "1r/s", "burst": 1})),
                    {"handler": "static_response", "body": "ok"}
                ]
            },
            {
                "handle": [{"handler": "static_response", "body": "other"}]
            }
        ]),
    );
    let limited = Request::new(Method::GET, "/limited".parse().unwrap());
    let other = Request::new(Method::GET, "/other".parse().unwrap());
    assert_eq!(
        router
            .handle_outcome(limited.clone())
            .await
            .unwrap()
            .into_response()
            .status,
        StatusCode::OK
    );
    let response = router
        .handle_outcome(limited)
        .await
        .unwrap()
        .into_response();
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        router
            .handle_outcome(other)
            .await
            .unwrap()
            .into_response()
            .body,
        "other"
    );
}

#[tokio::test]
async fn keys_are_independent_through_the_router() {
    let clock = Arc::new(ManualClock::new());
    let router = clocked_router(
        clock,
        &routes(rate_limit_config(json!({"rate": "1r/s", "burst": 1}))),
    );
    assert_eq!(serve(&router, "alice").await.status, StatusCode::OK);
    assert_eq!(serve(&router, "bob").await.status, StatusCode::OK);
    assert_eq!(
        serve(&router, "alice").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        serve(&router, "bob").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn concurrent_router_requests_never_exceed_the_burst() {
    let clock = Arc::new(ManualClock::new());
    let router = Arc::new(clocked_router(
        Arc::clone(&clock),
        &routes(rate_limit_config(json!({
            "rate": "0.000001r/s",
            "burst": 5,
            "key": "global"
        }))),
    ));
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let router = Arc::clone(&router);
        tasks.push(tokio::spawn(async move {
            router
                .handle_outcome(request("global"))
                .await
                .unwrap()
                .into_response()
                .status
        }));
    }
    let mut ok = 0;
    let mut limited = 0;
    for task in tasks {
        match task.await.expect("task") {
            StatusCode::OK => ok += 1,
            StatusCode::TOO_MANY_REQUESTS => limited += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(ok, 5);
    assert_eq!(limited, 45);
}
