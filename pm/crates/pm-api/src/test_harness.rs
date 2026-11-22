//! A minimal in-process HTTP test harness for the pm API.
//!
//! This exists so the test suite does not depend on `axum-test`, whose transitive
//! `expect-json` -> `chrono` edge put an unmaintained crate in `Cargo.lock`
//! (RUSTSEC-2026-0543). Replacing the harness removes the whole edge rather than
//! allowlisting the advisory, which the policy in `.cargo/audit.toml` and
//! `crates/core/tests/banned_crates.rs` forbids.
//!
//! The surface is deliberately the subset the suite actually uses, measured before
//! writing it (191 `status_code`, 178 `json`, 44 `text`, 41 `header`, 1 `status`,
//! 1 `as_bytes`, 1 `into_body`, 1 `assert_status_ok`):
//!
//!   TestServer::new(router)            -> in-process server
//!   server.get/post/put/patch/delete   -> TestRequest, `.json(&v)` / `.text(&s)` to add a body
//!   TestResponse::status_code()        -> StatusCode
//!   TestResponse::status()             -> StatusCode  (axum-style alias, same value)
//!   TestResponse::json::<T>()          -> T (panics with the body on a parse failure)
//!   TestResponse::text()               -> String
//!   TestResponse::header(name)         -> &str (panics if absent; non-UTF-8 is a test bug)
//!   TestResponse::as_bytes()           -> &[u8]
//!   TestResponse::assert_status_ok()   -> Self
//!
//! `TestResponse` buffers the whole body at construction, so `text()`, `json()` and
//! `as_bytes()` are infallible and repeatable. There is deliberately no `into_body()`: the one
//! test that needs an axum `Body` builds it from `ApiError::into_response()` directly, not from
//! a harness response, so adding one here would be dead code.

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

/// An in-process server that drives a `Router` directly, without binding a port.
pub(crate) struct TestServer {
    router: BoxCloneService,
}

impl TestServer {
    /// Build a server from a `Router`.
    ///
    /// Accepts the `MakeService` that `create_router(state).into_make_service_with_connect_info()`
    /// produces as well as a bare `Router`, because the suite calls both forms and the
    /// connect-info form is load-bearing: `capture_peer_middleware` reads
    /// `ConnectInfo<SocketAddr>` off the request extensions and `require_local_peer` rejects a
    /// request with no peer as `403`, so a harness that dropped the extension would turn every
    /// mutation test into a forbidden-peer test.
    ///
    /// The peer address injected is loopback, matching what a real client on the management port
    /// looks like to the daemon. Tests that need a non-loopback peer set their own extension.
    pub(crate) fn new(service: impl IntoTestRouter) -> Self {
        Self {
            router: service.into_router(),
        }
    }

    pub(crate) fn get(&self, path: &str) -> TestRequest<'_> {
        self.request(axum::http::Method::GET, path)
    }

    pub(crate) fn post(&self, path: &str) -> TestRequest<'_> {
        self.request(axum::http::Method::POST, path)
    }

    pub(crate) fn put(&self, path: &str) -> TestRequest<'_> {
        self.request(axum::http::Method::PUT, path)
    }

    pub(crate) fn patch(&self, path: &str) -> TestRequest<'_> {
        self.request(axum::http::Method::PATCH, path)
    }

    pub(crate) fn delete(&self, path: &str) -> TestRequest<'_> {
        self.request(axum::http::Method::DELETE, path)
    }

    fn request(&self, method: axum::http::Method, path: &str) -> TestRequest<'_> {
        TestRequest {
            server: self,
            method,
            path: path.to_owned(),
            body: Body::empty(),
            content_type: None,
            headers: Vec::new(),
            query: Vec::new(),
            explicit_content_type: None,
        }
    }
}

/// Accepts either a bare `Router` or the `MakeService` produced by
/// `into_make_service_with_connect_info`, turning both into one callable service.
///
/// `IntoMakeServiceWithConnectInfo` keeps its inner router private and has no `into_inner`, so
/// the connect-info form cannot be unwrapped. It is instead *called* with the peer address,
/// which yields an `AddExtension<Router, ConnectInfo<SocketAddr>>` that serves requests and sets
/// the very extension `capture_peer_middleware` reads. Doing it this way keeps the connect-info
/// path honest: the peer reaches the request through axum's own mechanism rather than being
/// hand-inserted by the harness.
pub(crate) trait IntoTestRouter {
    fn into_router(self) -> BoxCloneService;
}

/// A boxed, cloneable `Request -> Response` service.
pub(crate) type BoxCloneService = tower::util::BoxCloneService<
    axum::extract::Request,
    axum::response::Response,
    std::convert::Infallible,
>;

impl IntoTestRouter for Router {
    fn into_router(self) -> BoxCloneService {
        tower::util::BoxCloneService::new(self)
    }
}

impl IntoTestRouter
    for axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, std::net::SocketAddr>
{
    fn into_router(self) -> BoxCloneService {
        // `Service<SocketAddr>` yields the router with `ConnectInfo` layered on; the peer is
        // baked in here, which is why `send()` does not insert the extension itself. The
        // future is a `std::future::Ready`, so it must be awaited rather than unwrapped.
        let service = futures_lite_block_on(tower::Service::call(&mut { self }, TEST_PEER))
            .unwrap_or_else(|infallible| match infallible {});
        tower::util::BoxCloneService::new(service)
    }
}

/// The peer address the connect-info form is built with, and the one `send()` inserts for the
/// bare-`Router` form. Loopback, matching a real client on the management port.
pub(crate) const TEST_PEER: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 54321);

/// A request under construction. Await it to send.
pub(crate) struct TestRequest<'a> {
    server: &'a TestServer,
    method: axum::http::Method,
    path: String,
    body: Body,
    content_type: Option<&'static str>,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    explicit_content_type: Option<String>,
}

impl<'a> TestRequest<'a> {
    /// Serialise `value` as a JSON body and set `content-type: application/json`.
    pub(crate) fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        let encoded = serde_json::to_vec(value).expect("test request body serialises");
        self.body = Body::from(encoded);
        self.content_type = Some("application/json");
        self
    }

    /// Send `value` as a UTF-8 body with `content-type: text/plain`.
    pub(crate) fn text(mut self, value: &str) -> Self {
        self.body = Body::from(value.to_owned());
        self.content_type = Some("text/plain; charset=utf-8");
        self
    }

    /// Add a request header. Accepts `&str`, `String`, or a `HeaderName`/`HeaderValue` pair,
    /// which covers every call shape in the suite (69 uses, mostly `If-Match`/`If-None-Match`).
    pub(crate) fn add_header(
        mut self,
        name: impl AsRef<str>,
        value: impl TryIntoHeaderValue,
    ) -> Self {
        self.headers
            .push((name.as_ref().to_owned(), value.try_into_value()));
        self
    }

    /// Set the request `content-type`, replacing any body-set default. Used by the few tests
    /// that send a body the JSON/text helpers cannot express (wrong content type on purpose).
    pub(crate) fn content_type(mut self, value: impl AsRef<str>) -> Self {
        self.explicit_content_type = Some(value.as_ref().to_owned());
        self
    }

    /// Add query parameters from a JSON object, matching the `serde_json::json!` call shape
    /// the suite uses. Values are rendered the way a browser would send them: strings verbatim,
    /// numbers and booleans by their `Display`.
    pub(crate) fn add_query_params(mut self, params: serde_json::Value) -> Self {
        let object = params
            .as_object()
            .unwrap_or_else(|| panic!("add_query_params expects a JSON object, got {params:?}"));
        for (key, value) in object {
            let rendered = match value {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            self.query.push((key.clone(), rendered));
        }
        self
    }

    async fn send(self) -> TestResponse {
        let mut uri = self.path.clone();
        if !self.query.is_empty() {
            let encoded = self
                .query
                .iter()
                .map(|(key, value)| {
                    format!("{}={}", encode_component(key), encode_component(value))
                })
                .collect::<Vec<_>>()
                .join("&");
            uri.push(if uri.contains('?') { '&' } else { '?' });
            uri.push_str(&encoded);
        }

        // `require_loopback_host` rejects any request without a loopback `Host`, which is what a
        // real client on the management port sends. A harness that omitted it would 403 every
        // route for a reason unrelated to the test, so the default is set here and a test can
        // still override it with `add_header` to exercise the rebinding guard itself.
        let has_host = self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("host"));
        let mut builder = axum::http::Request::builder().method(self.method).uri(&uri);
        if !has_host {
            builder = builder.header(axum::http::header::HOST, "localhost");
        }
        let content_type = self.explicit_content_type.as_deref().or(self.content_type);
        if let Some(content_type) = content_type {
            builder = builder.header(axum::http::header::CONTENT_TYPE, content_type);
        }
        for (name, value) in &self.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder
            .body(self.body)
            .unwrap_or_else(|error| panic!("building a request for {}: {error}", self.path));

        // `oneshot` consumes the service, so the router is cloned per request. `Router` is
        // cheap to clone (it is an `Arc` internally) and this keeps `TestServer` reusable
        // across the many sequential requests each test makes.
        let response = self
            .server
            .router
            .clone()
            .oneshot(request)
            .await
            .unwrap_or_else(|infallible| match infallible {});

        TestResponse::from_axum(response).await
    }
}

impl<'a> std::future::IntoFuture for TestRequest<'a> {
    type Output = TestResponse;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = TestResponse> + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.send())
    }
}

/// A buffered response: status, headers and body are all captured up front.
pub(crate) struct TestResponse {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl TestResponse {
    async fn from_axum(response: axum::http::Response<Body>) -> Self {
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .expect("test response body reads")
            .to_bytes()
            .to_vec();
        Self {
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }

    pub(crate) fn status_code(&self) -> StatusCode {
        self.status
    }

    /// axum-style alias for `status_code`. Both exist because the suite uses both spellings
    /// (191 calls to `status_code`, 1 to `status`), and the migration must not change a
    /// single test body.
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn json<T: serde::de::DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "response body is not valid JSON for the requested type: {error}\n\
                 status: {}\nbody: {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap_or_else(|error| {
            panic!(
                "response body is not UTF-8: {error}\nstatus: {}",
                self.status
            )
        })
    }

    /// The header value. Panics if absent -- a silent default would turn a missing header into
    /// a passing assertion.
    ///
    /// Returns [`HeaderValueRef`] rather than `&str` because the suite uses both shapes:
    /// `assert_eq!(r.header("etag"), "\"h1-r1\"")` compares to a string, and
    /// `r.header("etag").to_str().expect("ascii")` wants the fallible conversion. A plain
    /// `&str` return cannot serve the first without panicking on non-ASCII, and a plain
    /// `&HeaderValue` cannot serve the first at all. The newtype carries both.
    pub(crate) fn header(&self, name: impl AsRef<str>) -> HeaderValueRef<'_> {
        let name: &str = name.as_ref();
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .unwrap_or_else(|error| panic!("invalid header name {name:?}: {error}"));
        let value = self.headers.get(&header_name).unwrap_or_else(|| {
            panic!(
                "response has no {name:?} header\nstatus: {}\npresent: {:?}",
                self.status,
                self.headers.keys().map(|k| k.as_str()).collect::<Vec<_>>()
            )
        });
        HeaderValueRef {
            name: name.to_owned(),
            value,
        }
    }

    /// All response headers, for tests that assert on presence/absence rather than a value.
    pub(crate) fn headers(&self) -> &axum::http::HeaderMap {
        &self.headers
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn assert_status_ok(self) -> Self {
        assert_eq!(
            self.status,
            StatusCode::OK,
            "expected 200 OK, got {}\nbody: {}",
            self.status,
            String::from_utf8_lossy(&self.body)
        );
        self
    }
}

/// A borrowed response header value that behaves like both `&str` and `&HeaderValue`.
pub(crate) struct HeaderValueRef<'a> {
    name: String,
    value: &'a HeaderValue,
}

impl<'a> HeaderValueRef<'a> {
    /// The value as `&str`, panicking with the header name on non-ASCII.
    pub(crate) fn to_str(&self) -> Result<&'a str, HeaderValueError> {
        self.value.to_str().map_err(|_| HeaderValueError {
            name: self.name.clone(),
        })
    }
}

impl<'a> std::fmt::Display for HeaderValueRef<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.value.as_bytes()))
    }
}

impl<'a> std::fmt::Debug for HeaderValueRef<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self.value.as_bytes()))
    }
}

impl<'a> PartialEq<str> for HeaderValueRef<'a> {
    fn eq(&self, other: &str) -> bool {
        self.value.as_bytes() == other.as_bytes()
    }
}

impl<'a> PartialEq<&str> for HeaderValueRef<'a> {
    fn eq(&self, other: &&str) -> bool {
        self.value.as_bytes() == other.as_bytes()
    }
}

impl<'a, 'b> PartialEq<HeaderValueRef<'b>> for HeaderValueRef<'a> {
    fn eq(&self, other: &HeaderValueRef<'b>) -> bool {
        self.value == other.value
    }
}

impl<'a> PartialEq<String> for HeaderValueRef<'a> {
    fn eq(&self, other: &String) -> bool {
        self.value.as_bytes() == other.as_bytes()
    }
}

/// The error type `to_str()` yields on a non-visible-ASCII header value.
#[derive(Debug)]
pub(crate) struct HeaderValueError {
    name: String,
}

impl std::fmt::Display for HeaderValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "header {:?} is not visible ASCII", self.name)
    }
}

impl std::error::Error for HeaderValueError {}

impl std::fmt::Debug for TestResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &String::from_utf8_lossy(&self.body))
            .finish()
    }
}

/// Percent-encode a query component per RFC 3986 (unreserved characters pass through).
fn encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Anything usable as an HTTP header value in a test: `&str`, `String`, or a built
/// `HeaderValue`. Kept as a trait so `add_header` accepts every existing call site unchanged.
pub(crate) trait TryIntoHeaderValue {
    fn try_into_value(self) -> String;
}

impl TryIntoHeaderValue for &str {
    fn try_into_value(self) -> String {
        self.to_owned()
    }
}

impl TryIntoHeaderValue for String {
    fn try_into_value(self) -> String {
        self
    }
}

impl TryIntoHeaderValue for &String {
    fn try_into_value(self) -> String {
        self.clone()
    }
}

impl TryIntoHeaderValue for HeaderValue {
    fn try_into_value(self) -> String {
        String::from_utf8_lossy(self.as_bytes()).into_owned()
    }
}

impl TryIntoHeaderValue for &HeaderValue {
    fn try_into_value(self) -> String {
        String::from_utf8_lossy(self.as_bytes()).into_owned()
    }
}

/// Poll a `Ready` future to completion without a runtime.
///
/// `IntoMakeServiceWithConnectInfo::call` returns `std::future::Ready`, which resolves on the
/// first poll. `TestServer::new` is called from synchronous test setup, so a block_on helper
/// keeps the constructor's signature unchanged instead of forcing every caller to await it.
fn futures_lite_block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};

    let mut future = std::pin::pin!(future);
    // A no-op waker is sound here because `Ready` never registers one.
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match std::future::Future::poll(future.as_mut(), &mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => unreachable!("the connect-info constructor future never pends"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};

    /// The two properties every other test in the suite depends on: a JSON body comes back
    /// parsed, and a non-2xx status is reported as a status rather than panicking.
    ///
    /// These are the harness's own tests. If they break, every pm-api test is suspect, so
    /// they are deliberately small and assert the exact shapes the suite relies on.
    #[tokio::test]
    async fn a_json_body_round_trips_and_a_status_is_reported_not_raised() {
        let router = Router::new()
            .route(
                "/ok",
                get(|| async {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        r#"{"revision":7,"name":"alpha"}"#,
                    )
                }),
            )
            .route(
                "/teapot",
                get(|| async { (StatusCode::IM_A_TEAPOT, "short and stout") }),
            )
            .route("/echo", post(|body: String| async move { body }));

        let server = TestServer::new(router);

        let response = server.get("/ok").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.header("content-type"), "application/json");
        let value: serde_json::Value = response.json();
        assert_eq!(value["revision"], 7);
        assert_eq!(value["name"], "alpha");

        let response = server.get("/teapot").await;
        assert_eq!(response.status_code(), StatusCode::IM_A_TEAPOT);
        assert_eq!(response.text(), "short and stout");

        let response = server.post("/echo").text("body in, body out").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.text(), "body in, body out");
    }

    /// A missing header must fail loudly. A silent default would let an assertion on an
    /// absent header pass, which is the failure mode that makes a harness dangerous.
    #[tokio::test]
    #[should_panic(expected = "response has no \"x-missing\" header")]
    async fn a_missing_header_panics_rather_than_defaulting() {
        let server = TestServer::new(Router::new().route("/ok", get(|| async { "hi" })));
        let response = server.get("/ok").await;
        let _ = response.header("x-missing");
    }

    /// `assert_status_ok` must report the actual body, so a failing assertion explains
    /// itself instead of just naming two status codes.
    #[tokio::test]
    #[should_panic(expected = "expected 200 OK, got 404 Not Found")]
    async fn assert_status_ok_names_the_actual_status() {
        let server = TestServer::new(Router::new().route("/ok", get(|| async { "hi" })));
        let _ = server.get("/missing").await.assert_status_ok();
    }
}
