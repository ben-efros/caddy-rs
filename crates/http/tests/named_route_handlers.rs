//! Runtime check for upstream Caddy ec849f542c43: a simplified (single matcher-less route) named
//! route keeps its whole handler chain, so an authorised request is served and an unauthorised one
//! is challenged *after* the earlier handlers ran.
//!
//! The regression this guards is a security one: before the port the adapted named route kept only
//! its first handler, so `&(protected) { header X-Test retained; basic_auth {...} }` lost the
//! authentication handler and an `invoke` of the route served the site unauthenticated while still
//! applying the header operation.
//!
//! `invoke` (`http.handlers.invoke`) is adapted but not executed by this build (see
//! `docs/compatibility/MODULE-PARITY.md`), so the test expands the emitted `invoke` handler with the
//! emitted `named_routes[<name>]` handlers — exactly the route list an `invoke` runs — and serves
//! that adapted JSON through the real router. Everything the request sees comes from the adapted
//! config; nothing about the handlers is hand-written here.

use bytes::Bytes;
use http::{header, Method, Uri};
use serde_json::{json, Map, Value};

use caddy_rs_http::{Request, RouterBuilder};

/// Upstream Caddy's cost-4 bcrypt hash of `correct horse` (`named_routes_test.go` uses this pair).
const BCRYPT_HASH: &str = "$2a$04$XziKIb5ayw0suaNwlK.1vOqOj9gEveGnkq.anOrdVrnkN5z1bA2A.";
/// `Basic ` + base64("alice:correct horse").
const ALICE_AUTHORIZATION: &str = "Basic YWxpY2U6Y29ycmVjdCBob3JzZQ==";

fn caddyfile() -> String {
    format!(
        "&(protected) {{\n\theader X-Test retained\n\tbasic_auth {{\n\t\talice {BCRYPT_HASH}\n\t}}\n}}\n\n\
         :9080 {{\n\tinvoke protected\n\trespond \"protected\"\n}}\n"
    )
}

/// The adapted site routes, with every `invoke` replaced by the invoked named route's handler list
/// (the expansion Caddy's `invoke` handler performs per request).
fn expanded_site_routes() -> Vec<Value> {
    let adapted = caddy_rs_config::adapt(&caddyfile()).expect("Caddyfile adapts");
    let server = &adapted.config["apps"]["http"]["servers"]["srv0"];
    let named_routes = server["named_routes"]
        .as_object()
        .expect("server carries named_routes");
    let mut routes = server["routes"].as_array().expect("routes").clone();
    expand_invokes(&mut routes, named_routes);
    routes
}

fn expand_invokes(routes: &mut Vec<Value>, named_routes: &Map<String, Value>) {
    for route in routes.iter_mut() {
        let Some(handle) = route.get_mut("handle").and_then(Value::as_array_mut) else {
            continue;
        };
        let mut expanded = Vec::with_capacity(handle.len());
        for handler in handle.drain(..) {
            if handler["handler"] != json!("invoke") {
                expanded.push(handler);
                continue;
            }
            let name = handler["name"]
                .as_str()
                .expect("invoke handler carries a name");
            let handlers = named_routes
                .get(name)
                .unwrap_or_else(|| panic!("named_routes[{name}] is attached to the server"))
                .get("handle")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("named_routes[{name}] is a route with handlers"));
            expanded.extend(handlers.iter().cloned());
        }
        *handle = expanded;
    }
}

fn router() -> caddy_rs_http::Router {
    let routes = expanded_site_routes();
    RouterBuilder::new()
        .build(&routes)
        .expect("adapted routes construct")
}

fn request() -> Request {
    let mut request = Request::new(Method::GET, "/".parse::<Uri>().expect("uri"));
    request
        .headers
        .insert(header::HOST, "localhost".parse().expect("host"));
    request
}

#[test]
fn the_adapted_named_route_keeps_both_handlers_in_order() {
    let adapted = caddy_rs_config::adapt(&caddyfile()).expect("Caddyfile adapts");
    let named = &adapted.config["apps"]["http"]["servers"]["srv0"]["named_routes"]["protected"];
    let handlers = named["handle"]
        .as_array()
        .expect("named route handlers array");
    assert_eq!(
        handlers.len(),
        2,
        "a simplified named route must keep header and basic_auth, got: {named}"
    );
    assert_eq!(handlers[0]["handler"], json!("headers"));
    assert_eq!(handlers[1]["handler"], json!("authentication"));
}

#[tokio::test]
async fn unauthenticated_request_is_challenged_with_earlier_handler_applied() {
    let response = router().handle(request()).await.expect("serves");
    assert_eq!(
        response.status,
        http::StatusCode::UNAUTHORIZED,
        "a request without credentials must not reach the protected response"
    );
    // The `header` handler ran before `basic_auth` and its response header survives the 401.
    assert_eq!(response.headers["x-test"], "retained");
    assert!(
        response.headers.contains_key(header::WWW_AUTHENTICATE),
        "the basic_auth challenge advertises its scheme"
    );
    assert_ne!(
        response.body,
        Bytes::from_static(b"protected"),
        "the protected body must not be served unauthenticated"
    );
}

#[tokio::test]
async fn authorized_request_reaches_the_protected_response_with_earlier_handler_applied() {
    let mut request = request();
    request.headers.insert(
        header::AUTHORIZATION,
        ALICE_AUTHORIZATION.parse().expect("authorization header"),
    );
    let response = router().handle(request).await.expect("serves");
    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(response.body, Bytes::from_static(b"protected"));
    assert_eq!(response.headers["x-test"], "retained");
}

#[tokio::test]
async fn wrong_credentials_are_challenged_with_earlier_handler_applied() {
    let mut request = request();
    request.headers.insert(
        header::AUTHORIZATION,
        "Basic YWxpY2U6d3Jvbmc="
            .parse()
            .expect("authorization header"),
    );
    let response = router().handle(request).await.expect("serves");
    assert_eq!(response.status, http::StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers["x-test"], "retained");
}
