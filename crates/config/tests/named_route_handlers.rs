//! Regression tests for upstream Caddy ec849f542c43: a named route whose body adapts to one
//! matcher-less route must keep the whole route, not just its first handler.
//!
//! Before the port, `build_named_route` emitted `routes[0].handle.first()`, so a definition such as
//! `&(protected) { header ...; basic_auth ... }` lost the authentication handler: an `invoke` of
//! the route still ran the header operations and then passed the request through unauthenticated.
//! Caddy now assigns the whole route (`route = subroute.Routes[0]`), preserving every handler in
//! order; `crates/http/tests/named_route_handlers.rs` evaluates the emitted handlers and proves the
//! authorised/unauthorised behaviour that follows.

use caddy_rs_config::adapt;
use serde_json::{json, Value};

/// Upstream Caddy's cost-4 bcrypt hash of `correct horse` (`bcrypt.VerifyHash` accepted form).
const BCRYPT_HASH: &str = "$2a$04$XziKIb5ayw0suaNwlK.1vOqOj9gEveGnkq.anOrdVrnkN5z1bA2A.";

fn protected_caddyfile() -> String {
    format!(
        "&(protected) {{\n\theader X-Test retained\n\tbasic_auth {{\n\t\talice {BCRYPT_HASH}\n\t}}\n}}\n\n\
         :9080 {{\n\tinvoke protected\n\trespond \"protected\"\n}}\n"
    )
}

#[test]
fn simplified_named_route_keeps_every_handler_in_order() {
    let adapted = adapt(&protected_caddyfile()).expect("Caddyfile adapts");
    let route = &adapted.config["apps"]["http"]["servers"]["srv0"]["named_routes"]["protected"];

    // Caddy's simplification keeps the whole matcher-less route, so both handlers survive in
    // directive order: `header` runs before `basic_auth` (Caddy's directive order).
    assert_eq!(
        *route,
        json!({
            "handle": [
                {
                    "handler": "headers",
                    "response": {"set": {"X-Test": ["retained"]}}
                },
                {
                    "handler": "authentication",
                    "providers": {"http_basic": {
                        "hash": {"algorithm": "bcrypt"},
                        "hash_cache": {},
                        "accounts": [{"username": "alice", "password": BCRYPT_HASH}]
                    }}
                }
            ]
        }),
        "simplified named route must keep all handlers (got: {route})"
    );

    // The simplification is a route, not a wrapper: no `subroute` handler is introduced.
    let handlers = route["handle"].as_array().expect("handle array");
    assert!(
        !handlers
            .iter()
            .any(|handler| handler["handler"] == json!("subroute")),
        "a single matcher-less route must not be wrapped in a subroute: {route}"
    );
}

#[test]
fn named_route_with_a_matcher_keeps_the_subroute_form() {
    let adapted = adapt(
        "&(gated) {\n\t@g path /g/*\n\trespond @g \"gated\"\n}\n\n:9080 {\n\tinvoke gated\n}\n",
    )
    .expect("Caddyfile adapts");
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["named_routes"]["gated"],
        json!({
            "handle": [{
                "handler": "subroute",
                "routes": [{
                    "match": [{"path": ["/g/*"]}],
                    "handle": [{"handler": "static_response", "body": "gated"}]
                }]
            }]
        }),
    );
}

#[test]
fn single_handler_named_route_stays_a_bare_route() {
    // The whole-route form must not regress the common case Caddy's v2.11.9 fixtures pin: one
    // matcher-less route with one handler adapts to exactly that route.
    let adapted = adapt("&(second) {\n\trespond \"second\"\n}\n\n:9080 {\n\tinvoke second\n}\n")
        .expect("Caddyfile adapts");
    assert_eq!(
        adapted.config["apps"]["http"]["servers"]["srv0"]["named_routes"]["second"],
        json!({"handle": [{"handler": "static_response", "body": "second"}]}),
    );
}

#[test]
fn the_adapted_named_route_is_a_valid_route_shape() {
    // Cheap guard against emitting a non-route (e.g. a bare handler or a handler array).
    let adapted = adapt(&protected_caddyfile()).expect("Caddyfile adapts");
    let route: &Value =
        &adapted.config["apps"]["http"]["servers"]["srv0"]["named_routes"]["protected"];
    assert!(route.is_object(), "a named route must be a route object");
    assert!(route.get("handle").is_some(), "a route carries `handle`");
    assert!(
        route.get("match").is_none(),
        "a simplified route has no match"
    );
}
