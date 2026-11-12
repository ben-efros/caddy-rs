//! Differential fixtures for the routing matchers (T-ROUTE-002/T-ROUTE-003).
//!
//! The expected JSON is the output of real Caddy v2.11.7 (`caddy adapt --adapter caddyfile`) for
//! the same Caddyfile input; caddy-rs must adapt those matcher-bearing configurations to the same
//! JSON and be able to build/serve them at runtime.

use std::net::SocketAddr;

use bytes::Bytes;
use http::{Method, Uri};
use serde_json::{json, Value};

use caddy_rs_core::{validate_config, Config, ModuleRegistry};
use caddy_rs_http::{Request, RouterBuilder};

/// Routes exactly as emitted by real Caddy v2.11.7 for [`CADDYFILE`].
fn oracle_routes() -> Value {
    json!([
        {
            "match": [{"path_regexp": {"name": "match", "pattern": "^/foo(.*)$"}}],
            "handle": [{"body": "{http.regexp.match.1}", "handler": "static_response"}]
        },
        {
            "match": [{"remote_ip": {"ranges": [
                "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8",
                "127.0.0.1/8", "fd00::/8", "::1", "203.0.113.0/24"
            ]}}],
            "handle": [{"body": "net", "handler": "static_response"}]
        },
        {
            "match": [{"client_ip": {"ranges": ["10.0.0.0/8"]}}],
            "handle": [{"body": "client", "handler": "static_response"}]
        },
        {
            "match": [{"protocol": "http/2"}],
            "handle": [{"body": "h2", "handler": "static_response"}]
        },
        {
            "match": [{"tls": {}}],
            "handle": [{"body": "tls", "handler": "static_response"}]
        }
    ])
}

fn request(path: &str) -> Request {
    let mut request = Request::new(Method::GET, path.parse::<Uri>().unwrap());
    request
        .headers
        .insert(http::header::HOST, "example.com".parse().unwrap());
    request
}

#[test]
fn caddy_adapts_matcher_json_identically_for_supported_matchers() {
    // The Caddyfile from the oracle run, without the protocol/tls routes (not yet emitted by the
    // Caddyfile adapter; see the report for the adapter gap).
    let caddyfile = r#"
:8080 {
	@re path_regexp match ^/foo(.*)$
	respond @re "{http.regexp.match.1}"

	@net remote_ip private_ranges 203.0.113.0/24
	respond @net "net"

	@client client_ip 10.0.0.0/8
	respond @client "client"
}
"#;
    let adapted = caddy_rs_config::adapt(caddyfile).expect("Caddyfile adapts");
    let routes = adapted.config["apps"]["http"]["servers"]["srv0"]["routes"].clone();
    let expected = json!([
        {
            "match": [{"path_regexp": {"name": "match", "pattern": "^/foo(.*)$"}}],
            "handle": [{"body": "{http.regexp.match.1}", "handler": "static_response"}]
        },
        {
            "match": [{"remote_ip": {"ranges": [
                "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8",
                "127.0.0.1/8", "fd00::/8", "::1", "203.0.113.0/24"
            ]}}],
            "handle": [{"body": "net", "handler": "static_response"}]
        },
        {
            "match": [{"client_ip": {"ranges": ["10.0.0.0/8"]}}],
            "handle": [{"body": "client", "handler": "static_response"}]
        }
    ]);
    assert_eq!(
        routes, expected,
        "adapted JSON must match real Caddy v2.11.7 for these matchers (got: {routes})"
    );
}

#[tokio::test]
async fn oracle_adapted_matcher_routes_build_and_serve() {
    let router = RouterBuilder::new()
        .build(oracle_routes().as_array().unwrap())
        .expect("oracle-adapted routes must construct");

    // path_regexp captures are published and expand in later handlers.
    let response = router.handle(request("/foo/bar")).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"/bar"));

    // The cleaned path is matched (double slashes and dot segments are cleaned first).
    let response = router.handle(request("/foo//./baz")).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"/baz"));

    // Real Caddy v2.11.7 runtime oracle: /other from loopback matches the remote_ip private
    // ranges route (`net-127.0.0.1` in the oracle run; this fixture uses the literal body "net").
    let mut loopback = request("/other");
    loopback.remote_addr = Some("127.0.0.1:34567".parse().unwrap());
    let response = router.handle(loopback).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"net"));

    // remote_ip: a source address inside the private ranges route wins over the client_ip route.
    let mut remote = request("/other");
    remote.remote_addr = Some("203.0.113.9:4444".parse::<SocketAddr>().unwrap());
    let response = router.handle(remote).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"net"));

    // client_ip: the resolved client IP comes from the `client_ip` request variable.
    let mut client = request("/other");
    client.remote_addr = Some("198.51.100.7:5555".parse().unwrap());
    client
        .vars
        .insert("client_ip".to_string(), "10.20.30.40".to_string());
    let response = router.handle(client).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"client"));

    // protocol: TLS + ALPN h2 matches `http/2`.
    let mut h2 = request("/other");
    h2.tls = true;
    h2.vars.insert("tls.alpn".to_string(), "h2".to_string());
    let response = router.handle(h2).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"h2"));

    // tls: plain TLS (no ALPN/version information) matches the TLS matcher, not protocol.
    let mut tls = request("/other");
    tls.tls = true;
    let response = router.handle(tls).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"tls"));

    // Nothing matches a plain cleartext request with an unknown host path: like Caddy's
    // emptyHandler, the route list falls through to an empty 200 response.
    let response = router.handle(request("/other")).await.expect("serves");
    assert_eq!(response.status, http::StatusCode::OK);
    assert!(response.body.is_empty());
}

#[tokio::test]
async fn adapted_subset_routes_build_and_serve() {
    let caddyfile = r#"
:8080 {
	@re path_regexp ^/users/([0-9]+)$
	respond @re "user={http.regexp.1}"

	@net remote_ip 192.0.2.0/24
	respond @net "local net"
}
"#;
    let adapted = caddy_rs_config::adapt(caddyfile).expect("adapts");
    let routes = adapted.config["apps"]["http"]["servers"]["srv0"]["routes"]
        .as_array()
        .expect("routes array")
        .clone();
    let router = RouterBuilder::new()
        .build(&routes)
        .expect("adapted routes construct");

    let response = router.handle(request("/users/42")).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"user=42"));

    let mut remote = request("/other");
    remote.remote_addr = Some("192.0.2.55:1234".parse().unwrap());
    let response = router.handle(remote).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"local net"));
}

#[tokio::test]
async fn named_path_regexp_caddyfile_round_trips_and_serves() {
    let caddyfile = r#"
:8080 {
	@users path_regexp users ^/users/(?P<id>[0-9]+)$
	respond @users "id={http.regexp.users.id} numeric={http.regexp.users.1} bare={http.regexp.id}"
}
"#;
    let adapted = caddy_rs_config::adapt(caddyfile).expect("named path_regexp adapts");
    let routes = adapted.config["apps"]["http"]["servers"]["srv0"]["routes"]
        .as_array()
        .expect("routes array")
        .clone();
    let router = RouterBuilder::new()
        .build(&routes)
        .expect("adapted named path_regexp routes construct");

    let response = router.handle(request("/users/42")).await.expect("serves");
    assert_eq!(
        response.body,
        Bytes::from_static(b"id=42 numeric=42 bare=42")
    );
}

#[test]
fn adapted_matcher_configs_validate_with_the_right_registry() {
    // `path_regexp` is already a built-in matcher, so an adapted configuration using it validates
    // against the default registry.
    let path_regexp_only = r#"
:8080 {
	@re path_regexp match ^/foo(.*)$
	respond @re "{http.regexp.match.1}"
}
"#;
    let adapted = caddy_rs_config::adapt(path_regexp_only).expect("adapts");
    let config = Config::from_value(adapted.config).expect("configuration model decodes");
    validate_config(&config, &ModuleRegistry::builtin())
        .expect("path_regexp is registered, so adapted JSON validates");

    // The network matchers are implemented by the HTTP engine and registered in the core
    // builtin registry (wave-9 core split), so adapted JSON using them validates against the
    // default registry too.
    let subset = r#"
:8080 {
	@net remote_ip private_ranges
	respond @net "net"

	@client client_ip 10.0.0.0/8
	respond @client "client"
}
"#;
    let adapted = caddy_rs_config::adapt(subset).expect("adapts");
    let config = Config::from_value(adapted.config).expect("configuration model decodes");
    validate_config(&config, &ModuleRegistry::builtin())
        .expect("remote_ip/client_ip are registered in the builtin registry");

    // The protocol and tls matchers reach the same validation path.
    let oracle = Config::from_value(json!({
        "apps": {"http": {"servers": {"srv0": {
            "listen": [":8080"],
            "routes": [
                {"match": [{"protocol": "http/2"}], "handle": [{"handler": "static_response", "body": "h2"}]},
                {"match": [{"tls": {}}], "handle": [{"handler": "static_response", "body": "tls"}]}
            ]
        }}}}
    }))
    .expect("oracle matcher JSON decodes");
    validate_config(&oracle, &ModuleRegistry::builtin())
        .expect("protocol/tls matcher JSON validates");
}

/// Upstream Caddy c3fab6576f0e: a `path` wildcard span must not swallow a percent-encoded slash.
///
/// A `%` in a `path` pattern means that part of the request path is compared in raw/escaped space.
/// Before the port, the wildcard span of `/reports*%2f` absorbed the `/` in `/reports/q1%2f`, so a
/// crafted path entered a route gated on the escaped form it must not match (matcher-integrity /
/// access-control bypass).
#[tokio::test]
async fn encoded_slash_path_does_not_enter_a_path_gated_route() {
    let routes = json!([
        {"match": [{"path": ["/reports%2f*"]}],
         "handle": [{"handler": "static_response", "body": "escaped-report"}]},
        {"match": [{"path": ["/reports*%2f"]}],
         "handle": [{"handler": "static_response", "body": "escaped-suffix"}]},
        {"handle": [{"handler": "static_response", "body": "public"}]}
    ]);
    let router = RouterBuilder::new()
        .build(routes.as_array().unwrap())
        .expect("path matcher routes construct");

    // Positive control: the escaped form the gated route asks for is matched.
    let response = router
        .handle(request("/reports%2fq1"))
        .await
        .expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"escaped-report"));

    // The crafted path keeps a literal `/` where the pattern requires `%2f`; it must not be
    // swallowed into the wildcard span, so neither escaped-path route may match.
    let response = router
        .handle(request("/reports/q1%2f"))
        .await
        .expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"public"));
}

/// The same defect seen from a `not path` exclusion: before the port, `/reports/q1%2f` matched the
/// excluded `/reports*%2f` form, was therefore skipped by the checked route and fell through to the
/// privileged handler.
#[tokio::test]
async fn encoded_slash_path_does_not_skip_a_path_exclusion() {
    let routes = json!([
        {"match": [{"not": [{"path": ["/reports*%2f"]}]}],
         "handle": [{"handler": "static_response", "body": "checked"}]},
        {"handle": [{"handler": "static_response", "body": "privileged"}]}
    ]);
    let router = RouterBuilder::new()
        .build(routes.as_array().unwrap())
        .expect("not path matcher routes construct");

    let response = router
        .handle(request("/reports/q1%2f"))
        .await
        .expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"checked"));

    // A path that is not the excluded escaped form is handled the same way.
    let response = router.handle(request("/reports/q1")).await.expect("serves");
    assert_eq!(response.body, Bytes::from_static(b"checked"));
}
