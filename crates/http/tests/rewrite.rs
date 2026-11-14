//! Real-router rewrite-handler tests for Caddy v2.11.9 field semantics (T-ROUTE-040).

use caddy_rs_http::{Outcome, Request, Router, RouterBuilder};
use http::{HeaderValue, Method};
use serde_json::{json, Value};

fn build_router(handler: Value) -> Router {
    let routes = json!([{
        "handle": [
            handler,
            {"handler": "static_response", "body": "{http.request.uri}"}
        ]
    }]);
    RouterBuilder::new()
        .build(routes.as_array().expect("routes"))
        .expect("routes build")
}

fn make_request(path: &str) -> Request {
    Request::new(Method::GET, path.parse().unwrap())
}

async fn rewritten(router: &Router, path: &str) -> String {
    match router
        .handle_outcome(make_request(path))
        .await
        .expect("serves")
    {
        Outcome::Respond(response) => String::from_utf8(response.body.to_vec()).expect("utf8"),
        Outcome::Continue(_) => panic!("router returned Continue"),
    }
}

#[tokio::test]
async fn uri_setter_sets_only_present_components_and_clears_with_question() {
    let router = build_router(json!({"handler": "rewrite", "uri": "/new"}));
    assert_eq!(rewritten(&router, "/old?a=1&b=2").await, "/new?a=1&b=2");

    let router = build_router(json!({"handler": "rewrite", "uri": "?b=3"}));
    assert_eq!(rewritten(&router, "/old?a=1&b=2").await, "/old?b=3");

    let router = build_router(json!({"handler": "rewrite", "uri": "?"}));
    assert_eq!(rewritten(&router, "/old?a=1").await, "/old");
}

#[tokio::test]
async fn uri_setter_query_values_are_escaped_and_duplicates_are_preserved() {
    let router = build_router(json!({
        "handler": "rewrite",
        "uri": "/new?q={http.request.header.X}&a=1&a=2"
    }));
    let mut request = make_request("/old?drop=me");
    request
        .headers
        .insert("x", HeaderValue::from_static("a b&c"));
    let response = match router.handle_outcome(request).await.expect("serves") {
        Outcome::Respond(response) => response,
        Outcome::Continue(_) => panic!("router returned Continue"),
    };
    assert_eq!(
        String::from_utf8(response.body.to_vec()).expect("utf8"),
        "/new?q=a+b%26c&a=1&a=2"
    );
}

#[tokio::test]
async fn uri_setter_canonicalizes_encoded_path_placeholders_like_caddy() {
    // Caddy sets URL.Path from PathUnescape(newPath) and recomputes RawPath, so `%2F` becomes a
    // literal slash in RequestURI while other escaped bytes are re-encoded canonically.
    let router = build_router(json!({
        "handler": "rewrite",
        "uri": "/pre{http.request.uri.path}"
    }));
    assert_eq!(rewritten(&router, "/old%2Fpath").await, "/pre/old/path");
    let router = build_router(json!({
        "handler": "rewrite",
        "uri": "/pre{http.request.uri.path}"
    }));
    assert_eq!(rewritten(&router, "/old%20path").await, "/pre/old%20path");
}

#[tokio::test]
async fn strip_prefix_is_escape_aware_and_cleans_repeated_slashes() {
    let router = build_router(json!({
        "handler": "rewrite",
        "strip_path_prefix": "/foo"
    }));
    // `%6F` decodes to `o` for comparison (prefix is unescaped), then the remainder is untouched.
    assert_eq!(rewritten(&router, "/f%6Fo/bar?q=1").await, "/bar?q=1");
    // With a prefix lacking `//`, Caddy cleans repeated slashes before trimming.
    assert_eq!(rewritten(&router, "/foo//bar").await, "/bar");
    // A trailing slash is preserved/clamped to `/`.
    assert_eq!(rewritten(&router, "/foo/").await, "/");
}

#[tokio::test]
async fn strip_suffix_is_escape_aware_and_preserves_query() {
    let router = build_router(json!({
        "handler": "rewrite",
        "strip_path_suffix": "/foo"
    }));
    assert_eq!(rewritten(&router, "/files/f%6Fo?q=1").await, "/files?q=1");
    // A suffix that does not match leaves the path and query untouched.
    assert_eq!(rewritten(&router, "/files/bar?q=1").await, "/files/bar?q=1");
}

#[tokio::test]
async fn path_regexp_rewrite_supports_named_and_numeric_captures() {
    let router = build_router(json!({
        "handler": "rewrite",
        "path_regexp": [
            {"find": "^/users/(?P<id>[0-9]+)$", "replace": "/accounts/$id"}
        ]
    }));
    assert_eq!(rewritten(&router, "/users/42").await, "/accounts/42");

    let router = build_router(json!({
        "handler": "rewrite",
        "path_regexp": [{"find": "^/old/(.*)$", "replace": "/new/$1"}]
    }));
    assert_eq!(rewritten(&router, "/old/x").await, "/new/x");
}

#[tokio::test]
async fn substring_cleans_the_path_and_handles_repeated_slashes() {
    let router = build_router(json!({
        "handler": "rewrite",
        "uri_substring": [{"find": "old", "replace": "new"}]
    }));
    // No `//` in `find`, so path cleaning merges repeated slashes before replacement.
    assert_eq!(
        rewritten(&router, "/a//old//b?old=1").await,
        "/a/new/b?new=1"
    );

    // `find` containing `//` disables slash merging, so repeated slashes are preserved for the
    // literal replacement.
    let router = build_router(json!({
        "handler": "rewrite",
        "uri_substring": [{"find": "//", "replace": "/"}]
    }));
    assert_eq!(rewritten(&router, "/a//b").await, "/a/b");
}

#[tokio::test]
async fn empty_values_are_noops_and_query_ops_are_ordered() {
    let router = build_router(json!({
        "handler": "rewrite",
        "method": "",
        "uri": "",
        "strip_path_prefix": "",
        "strip_path_suffix": "",
        "uri_substring": [],
        "path_regexp": []
    }));
    assert_eq!(rewritten(&router, "/keep?a=1").await, "/keep?a=1");

    let router = build_router(json!({
        "handler": "rewrite",
        "query": {
            "rename": [{"key": "r", "val": "renamed"}],
            "set": [{"key": "a", "val": "new"}],
            "add": [{"key": "a", "val": "extra"}],
            "replace": [{"key": "*", "search": "old", "replace": "new"}],
            "delete": ["gone"]
        }
    }));
    assert_eq!(
        rewritten(&router, "/q?r=1&a=old&gone=x&z=old").await,
        "/q?a=new&a=extra&renamed=1&z=new"
    );
}

#[tokio::test]
async fn fragment_is_dropped_and_relative_uris_fail_loudly() {
    // Fragments are never sent to the server; they are dropped from the request target.
    let router = build_router(json!({"handler": "rewrite", "uri": "/new#frag"}));
    assert_eq!(rewritten(&router, "/old?a=1").await, "/new?a=1");

    // Caddy permits relative rewrite targets (`foo.html`), but `http::Uri` cannot represent a
    // relative target; caddy-rs reports a located error rather than silently changing semantics.
    let router = build_router(json!({"handler": "rewrite", "uri": "foo.html"}));
    let error = router
        .handle_outcome(make_request("/old?a=1"))
        .await
        .expect_err("relative URI must fail loudly");
    assert!(
        error.to_string().contains("relative rewrite URI"),
        "{error}"
    );
}

#[tokio::test]
async fn uri_setter_embeds_the_current_query_raw_when_used_as_a_key_component() {
    // `{http.request.uri.query}` is already escaped, so Caddy inserts it raw when it forms a query
    // key component and appends the configured keys rather than double-escaping it.
    let router = build_router(json!({
        "handler": "rewrite",
        "uri": "/keep?{http.request.uri.query}&a=b"
    }));
    assert_eq!(
        rewritten(&router, "/old?x=1&y=2").await,
        "/keep?x=1&y=2&a=b"
    );
}

#[tokio::test]
async fn strip_prefix_with_an_escaped_pattern_requires_the_same_escape() {
    let router = build_router(json!({
        "handler": "rewrite",
        "strip_path_prefix": "/f%6Fo"
    }));
    // The configured prefix uses an escape, so the path must literally use that same escape.
    assert_eq!(rewritten(&router, "/f%6Fo/bar").await, "/bar");
    assert_eq!(rewritten(&router, "/foo/bar").await, "/foo/bar");
}

#[tokio::test]
async fn file_matcher_path_placeholder_is_escaped_when_inserted() {
    let router = build_router(json!({
        "handler": "rewrite",
        "uri": "/{http.matchers.file.relative}"
    }));
    let mut request = make_request("/old");
    request.vars.insert(
        "matchers.file.relative".to_string(),
        "dir/a b?c%".to_string(),
    );
    let response = match router.handle_outcome(request).await.expect("serves") {
        Outcome::Respond(response) => response,
        Outcome::Continue(_) => panic!("router returned Continue"),
    };
    assert_eq!(
        String::from_utf8(response.body.to_vec()).expect("utf8"),
        "/dir/a%20b%3Fc%25"
    );
}

fn build_guarded_router(matcher: Value, handler: Value) -> Router {
    let routes = json!([{
        "match": [matcher],
        "handle": [
            handler,
            {"handler": "static_response", "body": "{http.request.uri}"}
        ]
    }]);
    RouterBuilder::new()
        .build(routes.as_array().expect("routes"))
        .expect("routes build")
}

fn pub_matcher() -> Value {
    json!({"path_regexp": {"name": "pub", "pattern": "^/pub/(.*)$"}})
}

#[tokio::test]
async fn regexp_capture_double_encoded_traversal_stays_data() {
    // Port of upstream 7591cff1fb03 (`TestRewriteEscapesRegexpCaptures`): `path_regexp` captures
    // the once-decoded path, so a capture must be percent-encoded (slashes preserved) before it is
    // inserted into the rewritten path; otherwise a second decode turns the capture into a real
    // path separator after route guards have already run.
    let router = build_guarded_router(
        pub_matcher(),
        json!({"handler": "rewrite", "uri": "/files/{http.regexp.pub.1}"}),
    );
    assert_eq!(
        rewritten(&router, "/pub/%252e%252e%252fsecret").await,
        "/files/%252e%252e%252fsecret"
    );
}

#[tokio::test]
async fn regexp_capture_decoded_question_mark_stays_in_path() {
    // A capture that decodes to `?` must not start a real query string.
    let router = build_guarded_router(
        pub_matcher(),
        json!({"handler": "rewrite", "uri": "/files/{http.regexp.pub.1}"}),
    );
    assert_eq!(rewritten(&router, "/pub/a%3Fx=1").await, "/files/a%3Fx=1");
}

#[tokio::test]
async fn regexp_capture_slashes_are_preserved() {
    let router = build_guarded_router(
        pub_matcher(),
        json!({"handler": "rewrite", "uri": "/files/{http.regexp.pub.1}"}),
    );
    assert_eq!(rewritten(&router, "/pub/a/b").await, "/files/a/b");
}

#[tokio::test]
async fn regexp_capture_configured_query_is_unaffected() {
    // Only the path part escapes captures; the query builder keeps its own query escaping.
    let router = build_guarded_router(
        pub_matcher(),
        json!({"handler": "rewrite", "uri": "/files?id={http.regexp.pub.1}"}),
    );
    assert_eq!(rewritten(&router, "/pub/a").await, "/files?id=a");
}

#[tokio::test]
async fn regexp_capture_unnamed_and_named_forms_agree() {
    // The unnamed capture is the same code path; the Caddyfile shorthand `{re.pub.1}` is adapted to
    // `{http.regexp.pub.1}` by `crates/config/src/parser.rs` before it reaches the handler.
    let unnamed = build_guarded_router(
        json!({"path_regexp": {"pattern": "^/pub/(.*)$"}}),
        json!({"handler": "rewrite", "uri": "/files/{http.regexp.1}"}),
    );
    assert_eq!(rewritten(&unnamed, "/pub/a%3Fx=1").await, "/files/a%3Fx=1");
}
