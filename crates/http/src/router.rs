//! Route tree construction and evaluation.
//!
//! A [`Router`] is an ordered list of routes. Each route has a list of matcher *sets* (OR between
//! sets, AND within a set), a handler chain, and optional `terminal`/`group` semantics. This is
//! the same evaluation model Caddy uses for the HTTP app's `routes`.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::Value;

use crate::file_server::FileServerHandler;
use crate::handlers::{
    EncodeHandler, HeadersHandler, RewriteHandler, StaticResponseHandler, SubrouteHandler,
    VarsHandler,
};
use crate::matchers::build_matcher_set;
use crate::types::{Error, Outcome, Request, Response, Result, SharedHandler, SharedMatcher};

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

    /// Evaluate a request through the route tree.
    pub async fn handle(&self, request: Request) -> Result<Response> {
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
                match handler.handle(current).await? {
                    Outcome::Continue(next) => current = next,
                    Outcome::Respond(mut response) => {
                        apply_pending_headers(&mut response, &staged);
                        return Ok(response);
                    }
                }
            }
            if route.terminal {
                let mut response = Response::ok();
                apply_pending_headers(&mut response, &current);
                return Ok(response);
            }
        }
        Ok(Response::not_found())
    }
}

fn apply_pending_headers(response: &mut Response, request: &Request) {
    for (name, value) in &request.pending_response_headers {
        response.headers.insert(name.clone(), value.clone());
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
            "subroute" => {
                let routes = object
                    .get("routes")
                    .and_then(Value::as_array)
                    .ok_or_else(|| Error::InvalidConfig {
                        path: format!("{path}.routes"),
                        message: "subroute requires a `routes` array".to_string(),
                    })?;
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
}
