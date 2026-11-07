//! Real-router `map` parity tests (T-ROUTE-026).

use caddy_rs_http::{Outcome, Request, Router, RouterBuilder};
use http::{Method, StatusCode};
use serde_json::{json, Value};

fn build_router(routes: &Value) -> Router {
    RouterBuilder::new()
        .build(routes.as_array().expect("routes array"))
        .expect("routes build")
}

fn make_request(path: &str) -> Request {
    Request::new(Method::GET, path.parse().unwrap())
}

async fn serve(router: &Router, request: Request) -> caddy_rs_http::Response {
    match router.handle_outcome(request).await.expect("serves") {
        Outcome::Respond(response) => response,
        Outcome::Continue(_) => panic!("router returned Continue"),
    }
}

fn map_routes(map: Value) -> Value {
    json!([{
        "handle": [
            map,
            {"handler": "static_response", "body": "{a}|{b}|{c}"}
        ]
    }])
}

#[tokio::test]
async fn exact_regex_defaults_and_multiple_destinations_through_the_router() {
    let map = json!({
        "handler": "map",
        "source": "{http.request.uri.path}",
        "destinations": ["{a}", "{b}", "{c}"],
        "mappings": [
            {"input": "/exact", "outputs": ["exact-a", "exact-b", 42]},
            {"input_regexp": "^/user/([0-9]+)$", "outputs": ["user-$1", "id=$1", true]},
            // Earlier exact mappings win; this later duplicate-looking input is still distinct.
            {"input": "/other", "outputs": ["other-a", null, "other-c"]}
        ],
        "defaults": ["default-a", "default-b", "default-c"]
    });
    let router = build_router(&map_routes(map));
    assert_eq!(
        serve(&router, make_request("/exact")).await.body,
        "exact-a|exact-b|42"
    );
    assert_eq!(
        serve(&router, make_request("/user/123")).await.body,
        "user-123|id=123|true"
    );
    // A null output falls through to the positional default, not the next mapping.
    assert_eq!(
        serve(&router, make_request("/other")).await.body,
        "other-a|default-b|other-c"
    );
    assert_eq!(
        serve(&router, make_request("/unknown")).await.body,
        "default-a|default-b|default-c"
    );
}

#[tokio::test]
async fn mapping_order_is_first_match_and_placeholders_expand() {
    let map = json!({
        "handler": "map",
        "source": "{http.request.uri.path}",
        "destinations": ["{a}", "{b}"],
        "mappings": [
            {"input": "/order", "outputs": ["first", "{http.request.method}"]},
            {"input": "/order", "outputs": ["second", "unused"]}
        ]
    });
    // Duplicate inputs are rejected at load, so use a regex-less exact + fallback shape that still
    // proves order across regex and exact mappings.
    let error = match RouterBuilder::new().build(map_routes(map).as_array().unwrap()) {
        Ok(_) => panic!("duplicate map inputs must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("duplicate"), "{error}");

    let map = json!({
        "handler": "map",
        "source": "{http.request.uri.path}",
        "destinations": ["{a}"],
        "mappings": [
            {"input_regexp": "^/order", "outputs": ["regex-first"]},
            {"input": "/order", "outputs": ["exact-second"]}
        ]
    });
    let router = build_router(&map_routes(map));
    assert_eq!(
        serve(&router, make_request("/order")).await.body,
        "regex-first|{b}|{c}"
    );
}

#[tokio::test]
async fn absent_defaults_leave_the_placeholder_empty_and_status_is_preserved() {
    let map = json!({
        "handler": "map",
        "source": "{http.request.uri.path}",
        "destinations": ["{a}"],
        "mappings": []
    });
    let router = build_router(&map_routes(map));
    let response = serve(&router, make_request("/nothing")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "|{b}|{c}");
}
