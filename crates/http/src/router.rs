//! Route tree construction and evaluation.
//!
//! A [`Router`] is an ordered list of routes. Each route has a list of matcher *sets* (OR between
//! sets, AND within a set), a handler chain, and optional `terminal`/`group` semantics. This is
//! the same evaluation model Caddy uses for the HTTP app's `routes`.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::Value;

use crate::auth::{BasicAuthHandler, ForwardAuthHandler};
use crate::body::StreamingResponse;
use crate::file_server::FileServerHandler;
use crate::handlers::{
    EncodeHandler, HeadersHandler, RewriteHandler, StaticResponseHandler, SubrouteHandler,
    VarsHandler,
};
use crate::matchers::build_matcher_set;
use crate::types::{
    Error, Outcome, Request, Response, Result, SharedHandler, SharedMatcher, StreamingOutcome,
};

/// A custom handler factory, used by crates outside this one (for example `caddy-rs-proxy`) to
/// contribute handler modules without creating a dependency cycle.
pub type CustomHandlerFactory =
    Arc<dyn Fn(&Value, &str) -> Result<Option<SharedHandler>> + Send + Sync>;

/// One route.
pub struct Route {
    /// Matcher sets, OR-combined. Empty means "match everything".
    pub matcher_sets: Vec<Vec<SharedMatcher>>,
    /// Handler chain, executed in order.
    pub handlers: Vec<SharedHandler>,
    /// Stop route evaluation when this route matches, even if handlers continue.
    pub terminal: bool,
    /// Mutual-exclusion group.
    pub group: Option<String>,
}

impl Route {
    fn matches(&self, request: &Request) -> bool {
        self.matcher_sets.is_empty()
            || self
                .matcher_sets
                .iter()
                .any(|set| set.iter().all(|matcher| matcher.matches(request)))
    }
}

/// An ordered route list.
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    /// Number of top-level routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the router has no routes.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Evaluate a request through the route tree, returning a buffered response.
    ///
    /// This is the compatibility API used by the server until it adopts the streaming path: a
    /// streaming handler response is collected into [`Response::body`]. Use
    /// [`Router::handle_streaming`] to keep streamed bodies unbuffered.
    pub async fn handle(&self, request: Request) -> Result<Response> {
        let response = self.handle_streaming(request).await?;
        response.into_buffered().await.map_err(Error::from)
    }

    /// Evaluate a request through the route tree, preserving streaming response bodies.
    ///
    /// Handlers that have not opted into streaming still produce buffered responses; see
    /// [`crate::types::Handler::handle_streaming`] and the server integration contract in
    /// [`crate::body`].
    ///
    /// When no route produces a response, this returns `404 Not Found` (the top-level engine
    /// behaviour). Nested routers that must pass control back to their caller use
    /// [`Router::handle_streaming_outcome`], which reports that case as
    /// [`StreamingOutcome::Continue`] — this is what makes an empty `subroute` a no-op.
    pub async fn handle_streaming(&self, request: Request) -> Result<StreamingResponse> {
        match self.handle_streaming_outcome(request).await? {
            StreamingOutcome::Continue(_) => {
                Ok(StreamingResponse::from_buffered(Response::not_found()))
            }
            StreamingOutcome::Respond(response) => Ok(response),
        }
    }

    /// Evaluate a request through the route tree and report whether a route handled it.
    ///
    /// [`StreamingOutcome::Continue`] means every matching route ran its handlers without
    /// producing a response (or no route matched); the caller decides what to do next. This is the
    /// contract Caddy's `RouteList.Compile(next)` implements, and it is what lets a `subroute`
    /// with no routes behave as a no-op that passes control on.
    pub async fn handle_streaming_outcome(&self, request: Request) -> Result<StreamingOutcome> {
        let mut matched_groups: HashSet<&str> = HashSet::new();
        let mut current = request;
        for route in &self.routes {
            if let Some(group) = &route.group {
                if matched_groups.contains(group.as_str()) {
                    continue;
                }
            }
            if !route.matches(&current) {
                continue;
            }
            if let Some(group) = &route.group {
                matched_groups.insert(group.as_str());
            }

            for handler in &route.handlers {
                // A handler consumes the request. Keep the pre-handler request so staged response
                // headers survive into a response produced by a later handler.
                let staged = current.clone();
                match handler.handle_streaming(current).await? {
                    StreamingOutcome::Continue(next) => current = next,
                    StreamingOutcome::Respond(mut response) => {
                        apply_pending_headers(&mut response.headers, &staged);
                        return Ok(StreamingOutcome::Respond(response));
                    }
                }
            }
            if route.terminal {
                let mut response = StreamingResponse::from_buffered(Response::ok());
                apply_pending_headers(&mut response.headers, &current);
                return Ok(StreamingOutcome::Respond(response));
            }
        }
        Ok(StreamingOutcome::Continue(current))
    }

    /// Buffered counterpart of [`Router::handle_streaming_outcome`].
    ///
    /// Streaming responses are collected; use the streaming variant when the caller must preserve
    /// streaming bodies.
    pub async fn handle_outcome(&self, request: Request) -> Result<Outcome> {
        match self.handle_streaming_outcome(request).await? {
            StreamingOutcome::Continue(request) => Ok(Outcome::Continue(request)),
            StreamingOutcome::Respond(response) => {
                Ok(Outcome::Respond(response.into_buffered().await?))
            }
        }
    }
}

fn apply_pending_headers(headers: &mut http::HeaderMap, request: &Request) {
    for (name, value) in &request.pending_response_headers {
        headers.insert(name.clone(), value.clone());
    }
}

/// Builds routers from Caddy JSON route arrays.
pub struct RouterBuilder {
    custom: Option<CustomHandlerFactory>,
}

impl Default for RouterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterBuilder {
    /// A builder with no custom handlers.
    pub fn new() -> Self {
        Self { custom: None }
    }

    /// Register a factory for handler modules owned by another crate.
    pub fn with_custom_handler(mut self, factory: CustomHandlerFactory) -> Self {
        self.custom = Some(factory);
        self
    }

    /// Build a router from a `routes` array.
    pub fn build(&self, routes: &[Value]) -> Result<Router> {
        Ok(Router {
            routes: self.build_routes(routes, "routes")?,
        })
    }

    fn build_routes(&self, routes: &[Value], path: &str) -> Result<Vec<Route>> {
        routes
            .iter()
            .enumerate()
            .map(|(index, route)| self.build_route(route, &format!("{path}[{index}]")))
            .collect()
    }

    fn build_route(&self, value: &Value, path: &str) -> Result<Route> {
        let object = value.as_object().ok_or_else(|| Error::InvalidConfig {
            path: path.to_string(),
            message: "route must be an object".to_string(),
        })?;
        let mut matcher_sets = Vec::new();
        if let Some(matchers) = object.get("match") {
            let matchers = matchers.as_array().ok_or_else(|| Error::InvalidConfig {
                path: format!("{path}.match"),
                message: "`match` must be an array of matcher sets".to_string(),
            })?;
            for (index, set) in matchers.iter().enumerate() {
                matcher_sets.push(build_matcher_set(set).map_err(|error| match error {
                    Error::InvalidConfig {
                        path: inner_path,
                        message,
                    } => Error::InvalidConfig {
                        path: format!("{path}.match[{index}].{inner_path}"),
                        message,
                    },
                    other => other,
                })?);
            }
        }
        let handler_values = object
            .get("handle")
            .map(|handle| {
                handle.as_array().ok_or_else(|| Error::InvalidConfig {
                    path: format!("{path}.handle"),
                    message: "`handle` must be an array".to_string(),
                })
            })
            .transpose()?
            .cloned()
            .unwrap_or_default();
        let mut handlers = Vec::new();
        for (index, handler) in handler_values.iter().enumerate() {
            handlers.push(self.build_handler(handler, &format!("{path}.handle[{index}]"))?);
        }
        Ok(Route {
            matcher_sets,
            handlers,
            terminal: object
                .get("terminal")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            group: object
                .get("group")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    fn build_handler(&self, value: &Value, path: &str) -> Result<SharedHandler> {
        let object = value.as_object().ok_or_else(|| Error::InvalidConfig {
            path: path.to_string(),
            message: "handler must be an object".to_string(),
        })?;
        let name = object
            .get("handler")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidConfig {
                path: path.to_string(),
                message: "handler object is missing `handler`".to_string(),
            })?;
        let handler: SharedHandler = match name {
            "static_response" => Arc::new(StaticResponseHandler::from_json(value, path)?),
            "headers" => Arc::new(HeadersHandler::from_json(value, path)?),
            "vars" => Arc::new(VarsHandler::from_json(value, path)?),
            "rewrite" => Arc::new(RewriteHandler::from_json(value, path)?),
            "encode" => Arc::new(EncodeHandler),
            "file_server" => Arc::new(FileServerHandler::from_json(value, path)?),
            "forward_auth" => Arc::new(ForwardAuthHandler::from_json(value, path)?),
            "authentication" | "basic_auth" => Arc::new(BasicAuthHandler::from_json(value, path)?),
            "subroute" => {
                // Caddy's `subroute.routes` is optional (`json:"routes,omitempty"`): absent,
                // `null` and an empty array all mean "no routes", which compiles to a no-op that
                // passes control to the next handler (core validation accepts these forms too).
                let routes: &[Value] = match object.get("routes") {
                    None | Some(Value::Null) => &[],
                    Some(Value::Array(routes)) => routes,
                    Some(_) => {
                        return Err(Error::InvalidConfig {
                            path: format!("{path}.routes"),
                            message: "subroute handler field `routes` must be an array of routes"
                                .to_string(),
                        })
                    }
                };
                let inner = self.build(routes)?;
                Arc::new(SubrouteHandler::new(inner))
            }
            other => {
                if let Some(factory) = &self.custom {
                    if let Some(handler) = factory(value, path)? {
                        handler
                    } else {
                        return Err(Error::InvalidConfig {
                            path: format!("{path}.handler"),
                            message: format!("handler `{other}` is not implemented by this build"),
                        });
                    }
                } else {
                    return Err(Error::InvalidConfig {
                        path: format!("{path}.handler"),
                        message: format!("handler `{other}` is not implemented by this build"),
                    });
                }
            }
        };
        Ok(handler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Request;
    use http::{Method, Uri};
    use serde_json::json;

    fn request(path: &str, host: &str) -> Request {
        let mut request = Request::new(Method::GET, path.parse::<Uri>().unwrap());
        request
            .headers
            .insert(http::header::HOST, host.parse().unwrap());
        request
    }

    #[tokio::test]
    async fn matches_route_and_runs_handler() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "match": [{"host": ["example.com"]}],
                "handle": [{"handler": "static_response", "body": "matched"}]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(response.body, bytes::Bytes::from_static(b"matched"));
    }

    #[tokio::test]
    async fn unmatched_requests_get_404() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "match": [{"host": ["example.com"]}],
                "handle": [{"handler": "static_response", "body": "matched"}]
            })])
            .unwrap();
        let response = router.handle(request("/", "other.com")).await.unwrap();
        assert_eq!(response.status, http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn headers_apply_to_handler_response() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {"handler": "headers", "response": {"set": {"X-Test": ["ok"]}}},
                    {"handler": "static_response", "body": "body"}
                ]
            })])
            .unwrap();
        let response = router.handle(request("/", "host")).await.unwrap();
        assert_eq!(response.headers["x-test"], "ok");
        assert_eq!(response.body, bytes::Bytes::from_static(b"body"));
    }

    #[tokio::test]
    async fn group_runs_only_first_matching_route() {
        let router = RouterBuilder::new()
            .build(&[
                json!({
                    "group": "g",
                    "match": [{"path": ["/x*"]}],
                    "handle": [{"handler": "static_response", "body": "first"}]
                }),
                json!({
                    "group": "g",
                    "handle": [{"handler": "static_response", "body": "second"}]
                }),
            ])
            .unwrap();
        let response = router.handle(request("/x", "host")).await.unwrap();
        assert_eq!(response.body, bytes::Bytes::from_static(b"first"));
    }

    #[tokio::test]
    async fn subroute_evaluates_nested_routes() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [{
                    "handler": "subroute",
                    "routes": [
                        {"match": [{"path": ["/a"]}], "handle": [{"handler": "static_response", "body": "a"}]},
                        {"handle": [{"handler": "static_response", "body": "fallback"}]}
                    ]
                }]
            })])
            .unwrap();
        let response = router.handle(request("/a", "host")).await.unwrap();
        assert_eq!(response.body, bytes::Bytes::from_static(b"a"));
        let response = router.handle(request("/b", "host")).await.unwrap();
        assert_eq!(response.body, bytes::Bytes::from_static(b"fallback"));
    }

    async fn build_router_for_servers(routes: serde_json::Value) -> Router {
        let config = caddy_rs_core::Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":80"],
                "routes": routes
            }}}}
        }))
        .expect("config model decodes");
        let value = config.to_value().expect("config serializes");
        let routes = value["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array()
            .expect("routes array");
        RouterBuilder::new()
            .build(routes)
            .expect("adapted routes must construct")
    }

    #[tokio::test]
    async fn empty_subroute_is_a_valid_noop() {
        // Caddy's `subroute.routes` is optional; absent, null and empty array all behave as a
        // no-op that continues the outer handler chain.
        for subroute in [
            json!({"handler": "subroute"}),
            json!({"handler": "subroute", "routes": null}),
            json!({"handler": "subroute", "routes": []}),
        ] {
            let router = RouterBuilder::new()
                .build(&[json!({
                    "handle": [
                        subroute.clone(),
                        {"handler": "static_response", "body": "after-subroute"}
                    ]
                })])
                .unwrap_or_else(|error| {
                    panic!("empty subroute `{subroute}` must construct: {error}")
                });
            let response = router
                .handle(request("/", "example.com"))
                .await
                .expect("serves");
            assert_eq!(
                response.body,
                bytes::Bytes::from_static(b"after-subroute"),
                "empty subroute `{subroute}` must pass control to the next handler"
            );

            // A lone empty subroute also constructs and serves without an error.
            let router = RouterBuilder::new()
                .build(&[json!({"handle": [subroute]})])
                .expect("lone empty subroute constructs");
            assert!(router.handle(request("/", "example.com")).await.is_ok());
        }
    }

    #[tokio::test]
    async fn subroute_without_matching_inner_route_continues_outer_chain() {
        // Caddy compiles nested routes with the outer chain as the fallback, so an inner
        // non-match is not a 404: the next outer route runs.
        let router = RouterBuilder::new()
            .build(&[
                json!({
                    "handle": [{
                        "handler": "subroute",
                        "routes": [{
                            "match": [{"path": ["/inner"]}],
                            "handle": [{"handler": "static_response", "body": "inner"}]
                        }]
                    }]
                }),
                json!({"handle": [{"handler": "static_response", "body": "outer"}]}),
            ])
            .unwrap();
        let response = router
            .handle(request("/other", "example.com"))
            .await
            .unwrap();
        assert_eq!(response.body, bytes::Bytes::from_static(b"outer"));
        let response = router
            .handle(request("/inner", "example.com"))
            .await
            .unwrap();
        assert_eq!(response.body, bytes::Bytes::from_static(b"inner"));
    }

    #[tokio::test]
    async fn subroute_non_array_routes_is_a_located_error() {
        for routes in [json!({}), json!("not-an-array"), json!(42)] {
            let error = match RouterBuilder::new()
                .build(&[json!({"handle": [{"handler": "subroute", "routes": routes}]})])
            {
                Ok(_) => panic!("non-array routes must be rejected"),
                Err(error) => error,
            };
            let Error::InvalidConfig { path, message } = error else {
                panic!("expected located InvalidConfig, got {error}");
            };
            assert!(path.contains("handle[0].routes"), "path was {path}");
            assert!(
                message.contains("must be an array"),
                "message was {message}"
            );
        }
    }

    #[tokio::test]
    async fn oracle_matchers_in_route_adapted_json_constructs_and_serves() {
        // Exact adapted JSON from Caddy's `matchers_in_route.caddyfiletest` fixture: a route whose
        // only handler is a subroute with no `routes` key. Core validation accepts it; router
        // construction and serving must not fail.
        let router = build_router_for_servers(json!([{
            "handle": [{"handler": "subroute"}]
        }]))
        .await;
        let response = router
            .handle(request("/", "example.com"))
            .await
            .expect("route with empty subroute must serve without an error");
        // The route must construct and dispatch (no construction failure, no 500). caddy-rs'
        // top-level no-response policy is 404, while Caddy's emptyHandler answers 200 with an
        // empty body; that difference is registered separately from this construction fix.
        assert_eq!(response.status, http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rewrite_then_static_response_sees_expanded_request() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {"handler": "rewrite", "uri": "/new/{http.request.method}"},
                    {"handler": "static_response", "body": "{http.request.method} {http.request.uri.path}"}
                ]
            })])
            .unwrap();
        let response = router.handle(request("/old", "example.com")).await.unwrap();
        assert_eq!(response.body, bytes::Bytes::from_static(b"GET /new/GET"));
    }

    #[tokio::test]
    async fn basic_auth_route_challenges_and_then_authenticates() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {
                        "handler": "basic_auth",
                        "hash": {"algorithm": "plaintext"},
                        "realm": "test",
                        "accounts": [{"username": "alice", "password": "s3cret"}]
                    },
                    {"handler": "static_response", "body": "welcome"}
                ]
            })])
            .unwrap();

        // No credentials -> 401 challenge from the authentication handler.
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(response.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers[http::header::WWW_AUTHENTICATE],
            "Basic realm=\"test\""
        );

        // Valid credentials -> chain continues to static_response.
        let mut authenticated = request("/", "example.com");
        authenticated.headers.insert(
            http::header::AUTHORIZATION,
            "Basic YWxpY2U6czNjcmV0".parse().unwrap(),
        );
        let response = router.handle(authenticated).await.unwrap();
        assert_eq!(response.status, http::StatusCode::OK);
        assert_eq!(response.body, bytes::Bytes::from_static(b"welcome"));
    }

    #[tokio::test]
    async fn router_builds_forward_auth_handler() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [{
                    "handler": "forward_auth",
                    "upstreams": [{"dial": "127.0.0.1:1"}],
                    "uri": "/authz",
                    "copy_headers": ["Remote-User"]
                }]
            })])
            .unwrap();
        // With no auth server listening the handler fails loudly rather than allowing the request.
        let error = router
            .handle(request("/protected", "example.com"))
            .await
            .expect_err("auth upstream is unreachable");
        assert!(
            error.to_string().contains("forward_auth upstream"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn static_response_sets_caddy_content_type_through_router() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [{"handler": "static_response", "body": "hello oracle"}]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(
            response.headers[http::header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );

        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [{"handler": "static_response", "body": "{\"a\":1}"}]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(
            response.headers[http::header::CONTENT_TYPE],
            "application/json"
        );
    }

    #[tokio::test]
    async fn headers_handler_content_type_overrides_static_response_default() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {"handler": "headers", "response": {"set": {"Content-Type": ["application/x-custom"]}}},
                    {"handler": "static_response", "body": "hello"}
                ]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(
            response.headers[http::header::CONTENT_TYPE],
            "application/x-custom"
        );
    }

    #[tokio::test]
    async fn headers_values_expand_against_the_request() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {"handler": "headers", "response": {"set": {"X-Path": ["{http.request.uri.path}"]}}},
                    {"handler": "static_response", "body": "ok"}
                ]
            })])
            .unwrap();
        let response = router.handle(request("/x", "example.com")).await.unwrap();
        assert_eq!(response.headers["x-path"], "/x");
    }

    // ---- streaming handler/router path ------------------------------------------------

    use crate::body::{Body, BodyError, StreamingBody, StreamingResponse};
    use crate::types::{Handler, Outcome, SharedHandler, StreamingOutcome};
    use async_trait::async_trait;
    use bytes::Bytes;
    use http::HeaderMap;
    use http_body_util::BodyExt;
    use tokio::sync::mpsc;

    /// Handler that serves a buffered response on the legacy path and a chunked stream on the
    /// streaming path.
    struct ChunkHandler {
        frames: Vec<std::result::Result<Bytes, BodyError>>,
    }

    #[async_trait]
    impl Handler for ChunkHandler {
        fn name(&self) -> &'static str {
            "test_chunk_handler"
        }

        async fn handle(&self, _request: Request) -> Result<Outcome> {
            Ok(Outcome::Respond(Response::text(
                http::StatusCode::OK,
                "buffered",
            )))
        }

        async fn handle_streaming(&self, _request: Request) -> Result<StreamingOutcome> {
            let (sender, receiver) = mpsc::channel(self.frames.len().max(1));
            for frame in &self.frames {
                // `BodyError` is deliberately not `Clone` (it boxes a source error); the test
                // handler only uses the cancellation variant.
                let frame = match frame {
                    Ok(bytes) => Ok(bytes.clone()),
                    Err(_) => Err(BodyError::Cancelled),
                };
                sender.send(frame).await.expect("test channel has capacity");
            }
            drop(sender);
            Ok(StreamingOutcome::Respond(StreamingResponse::new(
                http::StatusCode::OK,
                HeaderMap::new(),
                Body::from_stream(StreamingBody::from_chunks(receiver)),
            )))
        }
    }

    fn router_with_handlers(handlers: Vec<SharedHandler>) -> Router {
        Router {
            routes: vec![Route {
                matcher_sets: Vec::new(),
                handlers,
                terminal: false,
                group: None,
            }],
        }
    }

    async fn body_frames(body: &mut StreamingBody) -> Vec<Bytes> {
        let mut frames = Vec::new();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        frames.push(data);
                    }
                }
                Err(error) => panic!("unexpected body error: {error}"),
            }
        }
        frames
    }

    #[tokio::test]
    async fn streaming_handler_response_is_preserved_on_streaming_path() {
        let router = router_with_handlers(vec![Arc::new(ChunkHandler {
            frames: vec![Ok(Bytes::from_static(b"a")), Ok(Bytes::from_static(b"bc"))],
        })]);
        let mut response = router
            .handle_streaming(request("/stream", "example.com"))
            .await
            .unwrap();
        assert!(response.is_streaming());
        assert_eq!(response.status, http::StatusCode::OK);
        match &mut response.body {
            Body::Stream(stream) => {
                assert_eq!(
                    body_frames(stream).await,
                    [Bytes::from_static(b"a"), Bytes::from_static(b"bc")]
                );
            }
            Body::Bytes(_) => panic!("expected a streaming body"),
        }
    }

    #[tokio::test]
    async fn buffered_handle_collects_streaming_responses_for_compatibility() {
        let router = router_with_handlers(vec![Arc::new(ChunkHandler {
            frames: vec![
                Ok(Bytes::from_static(b"one")),
                Ok(Bytes::from_static(b"two")),
            ],
        })]);
        let response = router
            .handle(request("/stream", "example.com"))
            .await
            .unwrap();
        assert_eq!(response.status, http::StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"onetwo"));
    }

    #[tokio::test]
    async fn mid_stream_errors_surface_after_headers_on_streaming_path() {
        let router = router_with_handlers(vec![Arc::new(ChunkHandler {
            frames: vec![
                Ok(Bytes::from_static(b"partial")),
                Err(BodyError::Cancelled),
            ],
        })]);
        let mut response = router
            .handle_streaming(request("/stream", "example.com"))
            .await
            .expect("headers are sent before the body fails");
        assert_eq!(response.status, http::StatusCode::OK);
        let Body::Stream(stream) = &mut response.body else {
            panic!("expected a streaming body");
        };
        let first = stream.frame().await.expect("first frame").expect("data");
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"partial"));
        let error = stream
            .frame()
            .await
            .expect("error frame")
            .expect_err("mid-stream error must surface");
        assert!(matches!(error, BodyError::Cancelled));
    }

    #[tokio::test]
    async fn buffered_handle_reports_mid_stream_errors() {
        let router = router_with_handlers(vec![Arc::new(ChunkHandler {
            frames: vec![
                Ok(Bytes::from_static(b"partial")),
                Err(BodyError::Cancelled),
            ],
        })]);
        let error = router
            .handle(request("/stream", "example.com"))
            .await
            .expect_err("buffered compatibility path cannot represent a mid-stream error");
        assert!(
            matches!(error, Error::Body(BodyError::Cancelled)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn buffered_handlers_convert_to_streaming_by_default() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [{"handler": "static_response", "body": "hello"}]
            })])
            .unwrap();
        let response = router
            .handle_streaming(request("/", "example.com"))
            .await
            .unwrap();
        assert!(!response.is_streaming());
        assert_eq!(response.body.exact_size(), Some(5));
        assert_eq!(response.into_buffered().await.unwrap().body, "hello");
    }

    #[tokio::test]
    async fn pending_response_headers_apply_to_streaming_responses() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {"handler": "headers", "response": {"set": {"X-Staged": ["yes"]}}},
                    {"handler": "static_response", "body": "ok"}
                ]
            })])
            .unwrap();
        let response = router
            .handle_streaming(request("/", "example.com"))
            .await
            .unwrap();
        assert_eq!(response.headers["x-staged"], "yes");
    }
}
