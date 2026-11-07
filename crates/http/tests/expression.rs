//! Real-router tests for the caddy-rs `expression` matcher subset (T-ROUTE-004).

use caddy_rs_http::{Error, Request, Response, Router, RouterBuilder};
use http::{header, HeaderValue, Method, StatusCode};
use serde_json::{json, Value};

fn build_router(routes: &Value) -> Router {
    RouterBuilder::new()
        .build(routes.as_array().expect("routes array"))
        .expect("routes build")
}

fn route(expression: &str, body: &str) -> Value {
    json!([{
        "match": [{"expression": expression}],
        "handle": [{"handler": "static_response", "body": body}]
    }, {
        "handle": [{"handler": "static_response", "body": "fallback"}]
    }])
}

fn make_request(method: Method, path: &str) -> Request {
    Request::new(method, path.parse().unwrap())
}

async fn serve(router: &Router, request: Request) -> Response {
    match router.handle_outcome(request).await.expect("serves") {
        caddy_rs_http::Outcome::Respond(response) => response,
        caddy_rs_http::Outcome::Continue(_) => panic!("router returned Continue"),
    }
}

#[tokio::test]
async fn real_router_matches_method_path_and_placeholders() {
    let router = build_router(&route(
        "request.method == 'GET' && request.path == '/foo'",
        "matched",
    ));
    assert_eq!(
        serve(&router, make_request(Method::GET, "/foo")).await.body,
        "matched"
    );
    assert_eq!(
        serve(&router, make_request(Method::POST, "/foo"))
            .await
            .body,
        "fallback"
    );
    assert_eq!(
        serve(&router, make_request(Method::GET, "/bar")).await.body,
        "fallback"
    );

    // Caddy-compatible placeholder syntax works alongside the convenience aliases.
    let router = build_router(&route(
        "{http.request.method} == 'GET' && {http.request.uri.path} == '/foo'",
        "matched",
    ));
    assert_eq!(
        serve(&router, make_request(Method::GET, "/foo")).await.body,
        "matched"
    );
}

#[tokio::test]
async fn real_router_matches_header_cookie_and_vars() {
    let router = build_router(&route(
        "request.header('X-Test') == 'yes' && request.cookie('session') == 'abc' && vars.tenant == 'acme'",
        "matched",
    ));
    let mut request = make_request(Method::GET, "/");
    request
        .headers
        .insert("x-test", HeaderValue::from_static("yes"));
    request.headers.insert(
        header::COOKIE,
        HeaderValue::from_static("session=abc; theme=dark"),
    );
    request
        .vars
        .insert("tenant".to_string(), "acme".to_string());
    assert_eq!(serve(&router, request).await.body, "matched");

    // Missing headers and cookies are empty strings, so this conjunction matches; no error.
    let router = build_router(&route(
        "request.header('X-Missing') == '' && request.cookie('missing') == ''",
        "matched",
    ));
    assert_eq!(
        serve(&router, make_request(Method::GET, "/")).await.body,
        "matched"
    );
}

#[tokio::test]
async fn real_router_boolean_operators_and_in_lists() {
    for (expression, path, expected) in [
        ("request.method in ['PUT', 'POST']", "/", "fallback"),
        ("request.method in ['GET', 'HEAD']", "/", "matched"),
        ("!(request.method == 'POST')", "/", "matched"),
        (
            "request.method == 'POST' || request.path == '/'",
            "/",
            "matched",
        ),
        (
            "request.path in ['/a', '/'] && request.method != 'POST'",
            "/",
            "matched",
        ),
    ] {
        let router = build_router(&route(expression, "matched"));
        assert_eq!(
            serve(&router, make_request(Method::GET, path)).await.body,
            expected,
            "{expression}"
        );
    }
}

#[tokio::test]
async fn real_router_missing_values_and_type_errors() {
    // Missing headers and query parameters are empty strings: `== ''` is true.
    let router = build_router(&route(
        "request.header('X-Missing') == '' || request.uri.query == ''",
        "matched",
    ));
    assert_eq!(
        serve(&router, make_request(Method::GET, "/")).await.body,
        "matched"
    );
    // A missing header is an empty string, so this matches.
    let router = build_router(&route("request.header('X-Missing') == ''", "matched"));
    assert_eq!(
        serve(&router, make_request(Method::GET, "/")).await.body,
        "matched"
    );

    // A static type mismatch is a located load error, not a silent non-match or runtime surprise.
    let error = match RouterBuilder::new().build(
        route("request.method == 404", "matched")
            .as_array()
            .unwrap(),
    ) {
        Ok(_) => panic!("type mismatch must fail at load"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::InvalidConfig { .. }), "{error}");
    assert!(error.to_string().contains("type mismatch"), "{error}");

    let error = match RouterBuilder::new().build(
        route("request.unknown == 'x'", "matched")
            .as_array()
            .unwrap(),
    ) {
        Ok(_) => panic!("unknown identifier must fail at load"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::InvalidConfig { .. }), "{error}");
    assert!(error.to_string().contains("unknown identifier"), "{error}");
}

#[tokio::test]
async fn real_router_handle_errors_status_expression_still_works() {
    let routes = json!([{
        "handle": [
            {"handler": "error", "status_code": 404, "error": "missing"}
        ]
    }]);
    let router = RouterBuilder::new()
        .with_error_routes(
            Some(&json!({"routes": [{
                "match": [{"expression": "{http.error.status_code} in [404, 410]"}],
                "handle": [{"handler": "static_response", "body": "handled"}]
            }]})),
            "errors",
        )
        .expect("error routes")
        .build(routes.as_array().unwrap())
        .expect("routes");
    let response = serve(&router, make_request(Method::GET, "/")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "handled");

    // Caddy's v2.11.9 expression_quotes fixture uses backtick raw-string literals.
    let router = RouterBuilder::new()
        .with_error_routes(
            Some(&json!({"routes": [{
                "match": [{"expression": "{http.error.status_code} == `404`"}],
                "handle": [{"handler": "static_response", "body": "backtick-handled"}]
            }]})),
            "errors",
        )
        .expect("error routes")
        .build(
            json!([{"handle": [{"handler": "error", "status_code": 404, "error": "missing"}]}])
                .as_array()
                .unwrap(),
        )
        .expect("routes");
    let response = serve(&router, make_request(Method::GET, "/")).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "backtick-handled");
}
