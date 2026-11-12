//! Route tree construction and evaluation.
//!
//! A [`Router`] is an ordered list of routes. Each route has a list of matcher *sets* (OR between
//! sets, AND within a set), a handler chain, and optional `terminal`/`group` semantics. This is
//! the same evaluation model Caddy uses for the HTTP app's `routes`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::acme_server::AcmeServerHandler;
use crate::auth::{BasicAuthHandler, ForwardAuthHandler};
use crate::body::StreamingResponse;
#[cfg(feature = "compression")]
use crate::encode::EncodeHandler;
use crate::file_server::FileServerHandler;
use crate::handlers::{
    ErrorHandler, HeadersHandler, MapHandler, RequestBodyHandler, RewriteHandler,
    StaticResponseHandler, SubrouteHandler, VarsHandler,
};
use crate::matchers::build_matcher_set;
use crate::rate_limit::RateLimitHandler;
use crate::security_headers::{SecurityHeaders, SecurityHeadersConfig, SecurityHeadersMode};
#[cfg(feature = "templates")]
use crate::templates::TemplatesHandler;
use crate::types::{
    Error, Handler, Outcome, Request, Response, ResponseOutcome, Result, SharedHandler,
    SharedMatcher, StreamingOutcome,
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
    /// Whether any handler in this route needs a buffered request body.
    fn requires_buffered_request_body(&self) -> bool {
        self.handlers
            .iter()
            .any(|handler| handler.requires_buffered_request_body())
    }

    /// Whether any handler in this route reads the request body.
    fn consumes_request_body(&self) -> bool {
        self.handlers
            .iter()
            .any(|handler| handler.consumes_request_body())
    }

    fn matches(&self, request: &mut Request) -> bool {
        if self.matcher_sets.is_empty() {
            return true;
        }
        for set in &self.matcher_sets {
            let mut matched = true;
            for matcher in set {
                // `matches_mut` publishes matcher placeholders (for example
                // `{http.matchers.file.relative}`) on a successful match.
                if !matcher.matches_mut(request) {
                    matched = false;
                    break;
                }
            }
            if matched {
                return true;
            }
        }
        false
    }
}

/// Handler modules whose streaming path takes the request body, used to mark the handler for
/// `request_body` limit enforcement.
///
/// This is deliberately **not** the request-buffering decision: whether a router needs the server
/// to buffer a request body comes from [`Handler::requires_buffered_request_body`] (the proxy
/// implements it from its retry/`handle_response` configuration). The proxy's streaming path still
/// consumes the body lazily, so the router needs to know a handler will read it before enforcing a
/// `request_body` limit. Adding a handler here is the extension point for future streaming
/// body-consuming modules.
const BODY_CONSUMING_HANDLERS: &[&str] = &["reverse_proxy"];

/// Wraps a handler that reads the request body on its streaming path
/// ([`BODY_CONSUMING_HANDLERS`]) so [`Handler::consumes_request_body`] is true.
///
/// The wrapper deliberately **forwards** [`Handler::requires_buffered_request_body`] to the inner
/// handler: the proxy can stream request bodies, so its policy decides whether the server buffers
/// (retries/try_duration/handle_response) or streams (default). Body-consumption and
/// buffering-requirement are distinct capabilities.
struct BodyConsumingHandler(SharedHandler);

#[async_trait]
impl Handler for BodyConsumingHandler {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn requires_buffered_request_body(&self) -> bool {
        self.0.requires_buffered_request_body()
    }

    fn consumes_request_body(&self) -> bool {
        true
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        self.0.handle(request).await
    }

    async fn handle_streaming(&self, request: Request) -> Result<StreamingOutcome> {
        self.0.handle_streaming(request).await
    }
}

/// Caddy-shaped response for a `request_body` limit error: `413` with an empty body and no content
/// type, keeping response headers staged by preceding `headers` handlers.
/// Response for a matcher error (Caddy's `MatcherErrorVarKey`): the error status with an empty
/// body and no content type (oracle v2.11.7), keeping staged `headers` response operations.
fn matcher_error_response(
    error: crate::types::MatcherError,
    request: &Request,
) -> StreamingOutcome {
    let mut response = StreamingResponse::from_buffered(Response {
        status: error.status,
        headers: http::HeaderMap::new(),
        body: bytes::Bytes::new(),
    });
    apply_pending_headers(&mut response.headers, request);
    StreamingOutcome::Respond(response)
}

fn body_limit_response(request: &Request) -> StreamingOutcome {
    let mut response = StreamingResponse::from_buffered(Response {
        status: http::StatusCode::PAYLOAD_TOO_LARGE,
        headers: http::HeaderMap::new(),
        body: bytes::Bytes::new(),
    });
    apply_pending_headers(&mut response.headers, request);
    StreamingOutcome::Respond(response)
}

/// An ordered route list.
pub struct Router {
    routes: Vec<Route>,
    /// Server error routes (`apps.http.servers.*.errors.routes`), evaluated when a handler fails
    /// or produces an error status. `None` means no error routes are configured, which is
    /// different from an empty route list (Caddy's nil-vs-empty distinction).
    error_routes: Option<Vec<Route>>,
    requires_buffered_request_body: bool,
    consumes_request_body: bool,
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

    /// Whether any handler in this route tree consumes the request body on its buffered path.
    ///
    /// The server buffers `hyper::body::Incoming` before dispatch when this is true, preserving
    /// the compatibility behaviour of body-consuming handlers (today: `reverse_proxy`, until
    /// request streaming through the proxy lands as T-PROXY-004). Routers without such handlers
    /// receive a streaming request body and never buffer it.
    pub fn requires_buffered_request_body(&self) -> bool {
        self.requires_buffered_request_body
    }

    /// Whether any handler in this route tree reads the request body (streamed or buffered).
    ///
    /// Distinct from [`Router::requires_buffered_request_body`]: a streaming `reverse_proxy`
    /// consumes the body but does not require it pre-buffered. The router uses this flag for
    /// `request_body` lazy-limit enforcement; nested routers report it through their subroute
    /// handler.
    pub fn consumes_request_body(&self) -> bool {
        self.consumes_request_body
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
    /// When no route produces a response, this returns Caddy's top-level "empty handler"
    /// response: `200 OK` with an empty body (Caddy's `emptyHandler`). Nested routers that must
    /// pass control back to their caller use [`Router::handle_streaming_outcome`], which reports
    /// that case as [`StreamingOutcome::Continue`] — this is what makes an empty `subroute` a
    /// no-op.
    pub async fn handle_streaming(&self, request: Request) -> Result<StreamingResponse> {
        match self.handle_streaming_outcome(request).await? {
            StreamingOutcome::Continue(_) => Ok(StreamingResponse::from_buffered(Response::ok())),
            StreamingOutcome::Respond(response) => Ok(response),
            StreamingOutcome::Upgrade(_) => Err(Error::UpgradeNotRepresentable {
                context: "Router::handle_streaming",
            }),
        }
    }

    /// Evaluate a request through the route tree, preserving both streamed bodies and protocol
    /// upgrades.
    ///
    /// This is the entry point the server connection layer uses: it returns either a normal
    /// (possibly streaming) response or an [`UpgradedResponse`] carrying the raw tunnel. An
    /// unmatched request becomes Caddy's top-level "empty handler" response (`200 OK`, empty
    /// body), matching Caddy's `emptyHandler`.
    pub async fn handle_upgradable(&self, request: Request) -> Result<ResponseOutcome> {
        match self.handle_streaming_outcome(request).await? {
            StreamingOutcome::Continue(_) => Ok(ResponseOutcome::Response(
                StreamingResponse::from_buffered(Response::ok()),
            )),
            StreamingOutcome::Respond(response) => Ok(ResponseOutcome::Response(response)),
            StreamingOutcome::Upgrade(response) => Ok(ResponseOutcome::Upgrade(response)),
        }
    }

    /// Evaluate a request through the route tree and report whether a route handled it.
    ///
    /// [`StreamingOutcome::Continue`] means every matching route ran its handlers without
    /// producing a response (or no route matched); the caller decides what to do next. This is the
    /// contract Caddy's `RouteList.Compile(next)` implements, and it is what lets a `subroute`
    /// with no routes behave as a no-op that passes control on.
    pub async fn handle_streaming_outcome(&self, request: Request) -> Result<StreamingOutcome> {
        self.evaluate_routes(&self.routes, request, None).await
    }

    /// Evaluate one route list.
    ///
    /// `error_status` is `None` for the normal request chain and `Some(status)` while running the
    /// server error routes (Caddy's `errorHandlerChain`): in error mode a terminal route or an
    /// unhandled fall-through produces Caddy's `errorEmptyHandler` response (the original error
    /// status with an empty body) instead of the normal 200 empty response, and no nested error
    /// routing happens.
    async fn evaluate_routes(
        &self,
        routes: &[Route],
        request: Request,
        error_status: Option<http::StatusCode>,
    ) -> Result<StreamingOutcome> {
        let mut matched_groups: HashSet<&str> = HashSet::new();
        let mut current = request;
        for route in routes {
            if let Some(group) = &route.group {
                if matched_groups.contains(group.as_str()) {
                    continue;
                }
            }
            let matched = route.matches(&mut current);
            // A matcher can record an error (the `file` matcher's `=NNN` fallback); Caddy aborts
            // route evaluation and responds with that status. Error routes do not re-enter.
            if let Some(error) = current.take_matcher_error() {
                current.mark_middleware_error();
                if error_status.is_none() && self.error_routes.is_some() {
                    return Box::pin(self.run_error_routes(
                        current.clone(),
                        Error::handler(error.status, error.message),
                    ))
                    .await;
                }
                current.clear_response_transforms();
                return Ok(matcher_error_response(error, &current));
            }
            if !matched {
                continue;
            }
            // Caddy's metrics wrapper labels the observation for a matched route with its first
            // handler module (`caddy.GetModuleName(route.Handlers[0])`,
            // `modules/caddyhttp/routes.go:174,320-323`). The shared context keeps the outermost
            // match, which is the frame Caddy instruments at the top of the route tree.
            if let Some(handler) = route.handlers.first() {
                current.set_route_handler(handler.name());
            }
            if let Some(group) = &route.group {
                matched_groups.insert(group.as_str());
            }

            for handler in &route.handlers {
                // `request_body` records a byte limit. Caddy's limit is lazy: only a handler
                // that actually reads the body observes it, so non-reading handlers still pass an
                // oversized body through. When the next handler consumes the body, enforce the
                // limit now: a buffered body can be compared directly, while a streamed body is
                // read up to the limit so an over-limit request returns Caddy's `413` instead of
                // surfacing later as a proxy-side read error.
                if let Some(limit) = current.body_limit() {
                    if handler.consumes_request_body() {
                        if current.has_streaming_body() {
                            match current.collect_body(Some(limit)).await {
                                Ok(_) => {}
                                Err(crate::body::BodyError::TooLarge { .. }) => {
                                    current.mark_middleware_error();
                                    current.clear_response_transforms();
                                    return Ok(body_limit_response(&current));
                                }
                                Err(error) => {
                                    current.mark_middleware_error();
                                    return Ok(StreamingOutcome::Respond(
                                        StreamingResponse::from_buffered(Response::text(
                                            http::StatusCode::BAD_GATEWAY,
                                            format!(
                                                "502 Bad Gateway: cannot read request body: {error}"
                                            ),
                                        )),
                                    ));
                                }
                            }
                        } else if current.body.len() as u64 > limit {
                            current.mark_middleware_error();
                            current.clear_response_transforms();
                            return Ok(body_limit_response(&current));
                        }
                    }
                }
                // A handler consumes the request. Keep the pre-handler request so staged response
                // headers survive into a response produced by a later handler, and so error routes
                // see the request state from before the failing handler (Caddy restores the
                // original request's method/URI/remote address before running error routes).
                let staged = current.clone();
                match handler.handle_streaming(current).await {
                    Ok(StreamingOutcome::Continue(next)) => current = next,
                    Ok(StreamingOutcome::Respond(mut response)) => {
                        // Caddy's error routes only run for handler *errors*; caddy-rs additionally
                        // routes responses with an error status through them when configured so
                        // that upstream error statuses (502/503/504 from `reverse_proxy`) reach
                        // `handle_errors` like Caddy's HandlerError does.
                        if error_status.is_none()
                            && self.error_routes.is_some()
                            && response.status.as_u16() >= 400
                        {
                            // caddy-rs routes upstream error responses through `handle_errors`
                            // like Caddy's HandlerError; count it as a middleware error so the
                            // request-errors counter matches Caddy's intent.
                            staged.mark_middleware_error();
                            let message = response
                                .status
                                .canonical_reason()
                                .unwrap_or("error")
                                .to_string();
                            return self
                                .run_error_routes(staged, Error::handler(response.status, message))
                                .await;
                        }
                        apply_pending_headers(&mut response.headers, &staged);
                        let response = apply_response_transforms(&staged, response).await;
                        return Ok(StreamingOutcome::Respond(response));
                    }
                    Ok(StreamingOutcome::Upgrade(mut response)) => {
                        apply_pending_headers(&mut response.headers, &staged);
                        return Ok(StreamingOutcome::Upgrade(response));
                    }
                    Err(error) => {
                        staged.mark_middleware_error();
                        if error_status.is_none() && self.error_routes.is_some() {
                            return Box::pin(self.run_error_routes(staged, error)).await;
                        }
                        return Err(error);
                    }
                }
            }
            if route.terminal {
                let status = error_status.unwrap_or(http::StatusCode::OK);
                let mut response = StreamingResponse::from_buffered(Response {
                    status,
                    headers: http::HeaderMap::new(),
                    body: bytes::Bytes::new(),
                });
                apply_pending_headers(&mut response.headers, &current);
                return Ok(StreamingOutcome::Respond(response));
            }
        }
        if let Some(status) = error_status {
            // Caddy's `errorEmptyHandler`: the error chain did not produce a response, so answer
            // with the original error status and an empty body.
            let mut response = StreamingResponse::from_buffered(Response {
                status,
                headers: http::HeaderMap::new(),
                body: bytes::Bytes::new(),
            });
            apply_pending_headers(&mut response.headers, &current);
            return Ok(StreamingOutcome::Respond(response));
        }
        Ok(StreamingOutcome::Continue(current))
    }

    /// Run the server's `handle_errors` routes for `error` (Caddy's `errorHandlerChain`).
    ///
    /// Sets Caddy's error placeholders on the request before evaluating the error routes. A second
    /// failure inside the error chain falls back to the original error status with an empty body
    /// (Caddy logs "error handling handler error" and writes the original status).
    async fn run_error_routes(
        &self,
        mut request: Request,
        error: Error,
    ) -> Result<StreamingOutcome> {
        let Some(error_routes) = &self.error_routes else {
            return Err(error);
        };
        let status = error
            .handler_status()
            .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
        let message = error.handler_message();
        let status_text = status.canonical_reason().unwrap_or("").to_string();
        request
            .vars
            .insert("http.error".to_string(), message.clone());
        request.vars.insert(
            "http.error.status_code".to_string(),
            status.as_u16().to_string(),
        );
        request
            .vars
            .insert("http.error.status_text".to_string(), status_text);
        request
            .vars
            .insert("http.error.message".to_string(), message);
        // Caddy sets these only for HandlerError values; caddy-rs has no handler-trace metadata.
        request
            .vars
            .insert("http.error.trace".to_string(), String::new());
        request
            .vars
            .insert("http.error.id".to_string(), String::new());
        // Error routes receive the pre-failure request but must not inherit a lazy body limit or a
        // stale matcher error from the failed chain. Caddy's encode middleware disables encoding
        // completely when a handler errors, so any registered response transform is discarded.
        request.clear_response_transforms();
        match Box::pin(self.evaluate_routes(error_routes, request, Some(status))).await {
            Ok(outcome) => Ok(outcome),
            Err(_second_error) => Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                Response {
                    status,
                    headers: http::HeaderMap::new(),
                    body: bytes::Bytes::new(),
                },
            ))),
        }
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
            StreamingOutcome::Upgrade(_) => Err(Error::UpgradeNotRepresentable {
                context: "Router::handle_outcome",
            }),
        }
    }
}

/// Apply the response transforms registered by middleware handlers (for example `encode`), in
/// reverse registration order (the transform closest to the response runs first, matching Caddy's
/// response-flowing-up middleware model). The stack is drained so nested routers never apply the
/// same transform twice.
async fn apply_response_transforms(
    request: &Request,
    mut response: StreamingResponse,
) -> StreamingResponse {
    for transform in request.take_response_transforms().into_iter().rev() {
        response = transform.transform(response).await;
    }
    response
}

/// Apply the response-header mutations staged by middleware handlers (for example `headers` and
/// `security_headers`) to the outgoing response.
///
/// The staged map is the authoritative middleware view, so it overwrites a same-named response
/// header: this is what lets `headers.response.set` override a handler's implicit defaults (such
/// as `static_response`'s implicit `Content-Type`) and what gives middleware precedence over
/// handler-authored headers. Within the staged map the last handler to run wins; the map travels
/// with the request through `subroute` handlers that continue the chain.
fn apply_pending_headers(headers: &mut http::HeaderMap, request: &Request) {
    for (name, value) in &request.pending_response_headers {
        headers.insert(name.clone(), value.clone());
    }
}

/// Builds routers from Caddy JSON route arrays.
/// What the PKI app says about one certificate authority, for `acme_server`'s provision rules.
///
/// Caddy's ACME server refuses a leaf lifetime that is not strictly shorter than the managed
/// intermediate's lifetime, and skips that rule when the operator supplied the intermediate
/// (`modules/caddypki/acmeserver/acmeserver.go`: `ca.Intermediate == nil`). Both facts come from
/// `apps.pki.certificate_authorities.<id>`, so the server passes them down.
#[derive(Debug, Clone, Copy)]
pub struct AcmeServerAuthority {
    /// `intermediate_lifetime`, or Caddy's 7-day default when the field is absent.
    pub intermediate_lifetime: std::time::Duration,
    /// Whether the operator supplied the intermediate certificate (`intermediate` present).
    pub operator_intermediate: bool,
}

impl Default for AcmeServerAuthority {
    fn default() -> Self {
        Self {
            intermediate_lifetime: caddy_rs_tls::DEFAULT_INTERMEDIATE_LIFETIME,
            operator_intermediate: false,
        }
    }
}

pub struct RouterBuilder {
    custom: Option<CustomHandlerFactory>,
    error_routes: Option<Vec<Value>>,
    /// Caddy data directory used by `http.handlers.acme_server` to persist its internal CA
    /// (`<root>/pki/authorities/<ca>/...`). The server runtime sets this per generation; when it
    /// is absent a configuration that uses `acme_server` fails with a located error instead of
    /// writing CA material into the process working directory.
    acme_server_data_root: Option<PathBuf>,
    /// Certificate-authority ids declared under `apps.pki.certificate_authorities`.
    ///
    /// Caddy's `acme_server` looks its `ca` up in the PKI app and fails with "no certificate
    /// authority configured with id" when the id is neither declared nor the implicitly
    /// provisioned `local` authority. `None` means the caller did not supply the PKI app, so
    /// the lookup is not enforced (unit tests and embedders); the server always supplies it.
    acme_server_authorities: Option<std::collections::BTreeMap<String, AcmeServerAuthority>>,
}

impl Default for RouterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterBuilder {
    /// A builder with no custom handlers.
    pub fn new() -> Self {
        Self {
            custom: None,
            error_routes: None,
            acme_server_data_root: None,
            acme_server_authorities: None,
        }
    }

    /// Configure the server's error routes (`apps.http.servers.*.errors`, Caddy's
    /// `handle_errors`). `None` disables error-route handling; a present object with an empty
    /// `routes` array still routes errors through the (empty) error chain, matching Caddy's
    /// nil-vs-empty distinction.
    pub fn with_error_routes(mut self, errors: Option<&Value>, path: &str) -> Result<Self> {
        let Some(errors) = errors else {
            self.error_routes = None;
            return Ok(self);
        };
        let object = errors.as_object().ok_or_else(|| Error::InvalidConfig {
            path: path.to_string(),
            message: "`errors` must be an object with a `routes` array".to_string(),
        })?;
        let routes: Vec<Value> = match object.get("routes") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(routes)) => routes.clone(),
            Some(_) => {
                return Err(Error::InvalidConfig {
                    path: format!("{path}.routes"),
                    message: "`errors.routes` must be an array of routes".to_string(),
                })
            }
        };
        self.error_routes = Some(routes);
        Ok(self)
    }

    /// Register a factory for handler modules owned by another crate.
    pub fn with_custom_handler(mut self, factory: CustomHandlerFactory) -> Self {
        self.custom = Some(factory);
        self
    }

    /// Set the Caddy data directory used by `http.handlers.acme_server` for internal-CA material.
    ///
    /// The runtime passes the generation's effective data/storage root (the same root automatic
    /// HTTPS uses). Without it, building a router that contains `acme_server` fails closed.
    pub fn with_acme_server_data_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.acme_server_data_root = Some(root.into());
        self
    }

    /// Like [`Self::with_acme_server_data_root`], but the caller may have no filesystem root (for
    /// example a `memory`/`s3` storage backend). `None` keeps the fail-closed behaviour: a router
    /// containing `acme_server` is rejected with a located error instead of writing CA material to
    /// a relative working-directory path.
    pub fn with_optional_acme_server_data_root(mut self, root: Option<PathBuf>) -> Self {
        self.acme_server_data_root = root;
        self
    }

    /// Declare the PKI authorities the configuration exposes to `acme_server`.
    ///
    /// Caddy resolves `acme_server.ca` through the PKI app: `local` is provisioned on demand, any
    /// other id must appear in `apps.pki.certificate_authorities`, otherwise provisioning fails
    /// with `no certificate authority configured with id: <id>`. Supplying the declared ids here
    /// reproduces that rule; without them the lookup is not enforced.
    pub fn with_acme_server_authorities(
        mut self,
        authorities: std::collections::BTreeMap<String, AcmeServerAuthority>,
    ) -> Self {
        self.acme_server_authorities = Some(authorities);
        self
    }

    /// Build a router from a `routes` array.
    ///
    /// Error routes are attached to this top-level router only: nested `subroute` routers must not
    /// inherit them (Caddy's error handler chain is server-level), and re-attaching them to every
    /// nested router would recurse forever because error routes themselves contain subroutes.
    pub fn build(&self, routes: &[Value]) -> Result<Router> {
        let routes = self.build_routes(routes, "routes")?;
        let error_routes = match &self.error_routes {
            Some(error_routes) => Some(self.build_routes(error_routes, "errors.routes")?),
            None => None,
        };
        Ok(self.router_from(routes, error_routes))
    }

    /// Build a nested router (`subroute`) without server-level error routes.
    fn build_nested(&self, routes: &[Value], path: &str) -> Result<Router> {
        let routes = self.build_routes(routes, path)?;
        Ok(self.router_from(routes, None))
    }

    fn router_from(&self, routes: Vec<Route>, error_routes: Option<Vec<Route>>) -> Router {
        // Capability composition: each built handler reports whether it needs a buffered body and
        // whether it reads the body at all. Subroute handlers forward their inner router's flags,
        // so nesting works without re-scanning raw JSON (and a custom handler factory's handler is
        // honoured, unlike a module-name scan).
        let requires_buffered_request_body =
            routes.iter().any(Route::requires_buffered_request_body);
        let consumes_request_body = routes.iter().any(Route::consumes_request_body);
        Router {
            routes,
            error_routes,
            requires_buffered_request_body,
            consumes_request_body,
        }
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
            "error" => Arc::new(ErrorHandler::from_json(value, path)?),
            "headers" => Arc::new(HeadersHandler::from_json_with_mode(
                value,
                path,
                SecurityHeadersMode::Compatible,
            )?),
            // caddy-rs extension (not a Caddy v2.11.9 built-in): secure response headers with
            // defaults, staged through the same response middleware path as `headers`. Handlers are
            // built in `Compatible` mode: the load path already applied the configured mode to the
            // whole configuration, so construction must accept what the load path accepted.
            "security_headers" => {
                let (config, _warnings) = SecurityHeadersConfig::from_json_with_mode(
                    value,
                    path,
                    SecurityHeadersMode::Compatible,
                )?;
                Arc::new(SecurityHeaders::from_validated(config))
            }
            "vars" => Arc::new(VarsHandler::from_json(value, path)?),
            "rewrite" => Arc::new(RewriteHandler::from_json(value, path)?),
            "request_body" => Arc::new(RequestBodyHandler::from_json(value, path)?),
            "map" => Arc::new(MapHandler::from_json(value, path)?),
            #[cfg(feature = "compression")]
            "encode" => Arc::new(EncodeHandler::from_json(value, path)?),
            // caddy-rs extension (not a Caddy v2.11.7 built-in): token-bucket rate limiting.
            "rate_limit" => Arc::new(RateLimitHandler::from_json(value, path)?),
            "acme_server" => {
                let root =
                    self.acme_server_data_root
                        .as_deref()
                        .ok_or_else(|| Error::InvalidConfig {
                            path: path.to_string(),
                            message:
                                "`acme_server` requires a Caddy filesystem data directory for its \
                                  internal CA; the configured storage backend has no path (or this \
                                  router was built without one)"
                                    .to_string(),
                        })?;
                let authority = match &self.acme_server_authorities {
                    Some(authorities) => {
                        // Caddy treats an empty `ca` as the default `local` authority, which the
                        // PKI app provisions on demand rather than requiring in `apps.pki`.
                        let ca = value
                            .get("ca")
                            .and_then(serde_json::Value::as_str)
                            .filter(|ca| !ca.is_empty())
                            .unwrap_or("local");
                        match authorities.get(ca).copied() {
                            Some(authority) => Some(authority),
                            None if ca == "local" => Some(AcmeServerAuthority::default()),
                            None => {
                                return Err(Error::InvalidConfig {
                                    path: format!("{path}.ca"),
                                    message: format!(
                                        "no certificate authority configured with id: {ca}"
                                    ),
                                })
                            }
                        }
                    }
                    None => None,
                };
                Arc::new(match authority {
                    Some(authority) => {
                        AcmeServerHandler::from_json_with_authority(value, path, root, authority)?
                    }
                    None => AcmeServerHandler::from_json(value, path, root)?,
                })
            }
            #[cfg(feature = "templates")]
            "templates" => Arc::new(TemplatesHandler::from_json(value, path)?),
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
                let inner = self.build_nested(routes, &format!("{path}.routes"))?;
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
        // The buffering requirement comes from the handler's own capability (forwarded by the
        // wrapper). The wrapper only marks handlers whose streaming path reads the body so
        // `request_body` can enforce its lazy limit before dispatch.
        let handler: SharedHandler = if BODY_CONSUMING_HANDLERS.contains(&name) {
            Arc::new(BodyConsumingHandler(handler))
        } else {
            handler
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
    async fn unmatched_requests_get_caddy_empty_200() {
        // Real Caddy's top-level `emptyHandler` answers unmatched requests with `200 OK`, an empty
        // body and `Content-Length: 0` (verified against Caddy v2.11.7, see DIV-0068).
        let router = RouterBuilder::new()
            .build(&[json!({
                "match": [{"host": ["example.com"]}],
                "handle": [{"handler": "static_response", "body": "matched"}]
            })])
            .unwrap();
        let response = router.handle(request("/", "other.com")).await.unwrap();
        assert_eq!(response.status, http::StatusCode::OK);
        assert!(response.body.is_empty());
        assert!(response.headers.is_empty());

        // The streaming/upgradable entry points the server uses share the same termination.
        let response = router
            .handle_upgradable(request("/", "other.com"))
            .await
            .unwrap();
        let ResponseOutcome::Response(response) = response else {
            panic!("unmatched request must not be an upgrade");
        };
        assert_eq!(response.status, http::StatusCode::OK);
        assert!(response.into_buffered().await.unwrap().body.is_empty());
    }

    #[tokio::test]
    async fn explicit_handler_404_is_preserved() {
        // Only the implicit termination changes; a handler that explicitly answers 404 must keep
        // doing so with its body/headers.
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [{"handler": "static_response", "status_code": 404, "body": "nope"}]
            })])
            .unwrap();
        let response = router.handle(request("/", "host")).await.unwrap();
        assert_eq!(response.status, http::StatusCode::NOT_FOUND);
        assert_eq!(response.body, bytes::Bytes::from_static(b"nope"));
        assert_eq!(
            response.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
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
        // The route must construct and dispatch without an error, and the top-level no-response
        // policy matches Caddy's emptyHandler: 200 OK with an empty body.
        assert_eq!(response.status, http::StatusCode::OK);
        assert!(response.body.is_empty());
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

    // ---- streaming request bodies (T-PROXY-039 sub-wave: http/server model) -------------

    use crate::body::RequestBody;
    use std::sync::Mutex;

    /// Records request-body chunk sizes delivered on the streaming path and buffered lengths on
    /// the compatibility path.
    struct RequestBodyRecorder {
        streaming_chunks: Arc<Mutex<Vec<usize>>>,
        buffered_lengths: Arc<Mutex<Vec<usize>>>,
    }

    #[async_trait]
    impl Handler for RequestBodyRecorder {
        fn name(&self) -> &'static str {
            "request_body_recorder"
        }

        async fn handle(&self, request: Request) -> Result<Outcome> {
            self.buffered_lengths
                .lock()
                .expect("lock")
                .push(request.body.len());
            Ok(Outcome::Respond(Response::text(
                http::StatusCode::OK,
                "buffered",
            )))
        }

        async fn handle_streaming(&self, mut request: Request) -> Result<StreamingOutcome> {
            assert!(
                request.has_streaming_body(),
                "server handed a streamed body"
            );
            assert!(
                request.body.is_empty(),
                "streaming path must not populate the buffered compatibility accessor"
            );
            let mut body = request.take_body();
            while let Some(frame) = body.next_frame().await {
                let frame = frame?;
                if let Ok(data) = frame.into_data() {
                    self.streaming_chunks.lock().expect("lock").push(data.len());
                }
            }
            Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                Response::text(http::StatusCode::OK, "streamed"),
            )))
        }
    }

    /// A handler factory for the streaming body tests: `request_body_recorder` plus a stub for the
    /// body-buffering `reverse_proxy` module so the router-level flag can be exercised without the
    /// proxy crate.
    fn streaming_factory(recorder: Arc<RequestBodyRecorder>) -> CustomHandlerFactory {
        Arc::new(move |value: &Value, _path: &str| {
            match value.get("handler").and_then(Value::as_str) {
                Some("request_body_recorder") => Ok(Some(Arc::new(RequestBodyRecorder {
                    streaming_chunks: Arc::clone(&recorder.streaming_chunks),
                    buffered_lengths: Arc::clone(&recorder.buffered_lengths),
                }) as SharedHandler)),
                Some("reverse_proxy") => Ok(Some(
                    Arc::new(ChunkHandler { frames: Vec::new() }) as SharedHandler
                )),
                Some("retrying_proxy") => Ok(Some(Arc::new(RetryingProxyStub) as SharedHandler)),
                _ => Ok(None),
            }
        })
    }

    #[tokio::test]
    async fn streaming_request_body_reaches_the_handler_chunk_by_chunk() {
        let recorder = Arc::new(RequestBodyRecorder {
            streaming_chunks: Arc::new(Mutex::new(Vec::new())),
            buffered_lengths: Arc::new(Mutex::new(Vec::new())),
        });
        let router = RouterBuilder::new()
            .with_custom_handler(streaming_factory(Arc::clone(&recorder)))
            .build(&[json!({"handle": [{"handler": "request_body_recorder"}]})])
            .unwrap();
        assert!(!router.requires_buffered_request_body());

        let (sender, receiver) = mpsc::channel(4);
        let mut request = Request::new(Method::POST, "/upload".parse().unwrap());
        request = request
            .with_streaming_body(RequestBody::streaming(StreamingBody::from_chunks(receiver)));
        sender.send(Ok(Bytes::from_static(b"abc"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"defg"))).await.unwrap();
        sender.send(Ok(Bytes::from_static(b"hi"))).await.unwrap();
        drop(sender);

        let response = router
            .handle_streaming(request)
            .await
            .expect("streaming request handled");
        let response = response.into_buffered().await.expect("buffered response");
        assert_eq!(response.body, Bytes::from_static(b"streamed"));
        assert_eq!(
            *recorder.streaming_chunks.lock().expect("lock"),
            vec![3, 4, 2]
        );
        assert!(
            recorder.buffered_lengths.lock().expect("lock").is_empty(),
            "the streaming path must not run the buffered handler"
        );
    }

    /// Stub whose buffering capability is true, like a retrying `reverse_proxy`.
    struct RetryingProxyStub;

    #[async_trait]
    impl Handler for RetryingProxyStub {
        fn name(&self) -> &'static str {
            "retrying_proxy"
        }

        fn requires_buffered_request_body(&self) -> bool {
            true
        }

        async fn handle(&self, _request: Request) -> Result<Outcome> {
            Ok(Outcome::Respond(Response::text(
                http::StatusCode::OK,
                "retried",
            )))
        }
    }

    #[tokio::test]
    async fn router_composes_handler_body_capabilities_including_nested_routes() {
        let recorder = Arc::new(RequestBodyRecorder {
            streaming_chunks: Arc::new(Mutex::new(Vec::new())),
            buffered_lengths: Arc::new(Mutex::new(Vec::new())),
        });
        let builder =
            || RouterBuilder::new().with_custom_handler(streaming_factory(Arc::clone(&recorder)));

        let static_router = builder()
            .build(&[json!({"handle": [{"handler": "static_response", "body": "x"}]})])
            .unwrap();
        assert!(!static_router.requires_buffered_request_body());
        assert!(!static_router.consumes_request_body());

        let recorder_router = builder()
            .build(&[json!({"handle": [{"handler": "request_body_recorder"}]})])
            .unwrap();
        assert!(!recorder_router.requires_buffered_request_body());

        // Streaming `reverse_proxy` (the stub implements the capability as false, like the proxy
        // without retries) must not force server buffering, but it does consume the body.
        let streaming_proxy_router = builder()
            .build(&[json!({"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "localhost:9"}]}]})])
            .unwrap();
        assert!(!streaming_proxy_router.requires_buffered_request_body());
        assert!(streaming_proxy_router.consumes_request_body());

        // A handler that reports the buffering capability (retrying proxy) forces it, and a custom
        // handler supplied through the factory is composed by capability, not by JSON module name.
        let retrying_router = builder()
            .build(&[json!({"handle": [{"handler": "retrying_proxy"}]})])
            .unwrap();
        assert!(retrying_router.requires_buffered_request_body());
        assert!(retrying_router.consumes_request_body());

        // Nested subroutes forward both capabilities.
        let nested_streaming = builder()
            .build(&[json!({
                "handle": [
                    {"handler": "subroute", "routes": [
                        {"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "localhost:9"}]}]}
                    ]}
                ]
            })])
            .unwrap();
        assert!(!nested_streaming.requires_buffered_request_body());
        assert!(nested_streaming.consumes_request_body());

        let nested_buffering = builder()
            .build(&[json!({
                "handle": [
                    {"handler": "static_response", "body": "before"},
                    {"handler": "subroute", "routes": [
                        {"handle": [{"handler": "retrying_proxy"}]}
                    ]}
                ]
            })])
            .unwrap();
        assert!(nested_buffering.requires_buffered_request_body());
        assert!(nested_buffering.consumes_request_body());
    }

    /// Buffered-only handler: records `request.body` through the default `handle_streaming`
    /// delegation, proving the compatibility path still carries full bodies.
    struct BufferedBodyHandler;

    #[async_trait]
    impl Handler for BufferedBodyHandler {
        fn name(&self) -> &'static str {
            "buffered_body_handler"
        }

        // This handler reads `request.body` directly, so it needs the complete body buffered.
        fn requires_buffered_request_body(&self) -> bool {
            true
        }

        async fn handle(&self, request: Request) -> Result<Outcome> {
            Ok(Outcome::Respond(Response::text(
                http::StatusCode::OK,
                format!("body={}", String::from_utf8_lossy(&request.body)),
            )))
        }
    }

    #[tokio::test]
    async fn buffered_compatibility_path_still_sees_the_full_request_body() {
        let factory: CustomHandlerFactory = Arc::new(|value: &Value, _path: &str| {
            match value.get("handler").and_then(Value::as_str) {
                Some("buffered_body_handler") => {
                    Ok(Some(Arc::new(BufferedBodyHandler) as SharedHandler))
                }
                _ => Ok(None),
            }
        });
        let router = RouterBuilder::new()
            .with_custom_handler(factory)
            .build(&[json!({"handle": [{"handler": "buffered_body_handler"}]})])
            .unwrap();
        let mut request = Request::new(Method::POST, "/".parse().unwrap());
        request.body = Bytes::from_static(b"buffered body");
        let response = router.handle(request).await.expect("buffered request");
        assert_eq!(response.body, Bytes::from_static(b"body=buffered body"));
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
        let requires_buffered_request_body = handlers
            .iter()
            .any(|handler| handler.requires_buffered_request_body());
        let consumes_request_body = handlers
            .iter()
            .any(|handler| handler.consumes_request_body());
        Router {
            error_routes: None,
            requires_buffered_request_body,
            consumes_request_body,
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

    // ---- upgrade-aware router path -------------------------------------------------------

    use crate::upgrade::{Tunnel, UpgradedResponse};

    /// Handler that always switches protocols on the streaming path.
    struct UpgradeHandler;

    #[async_trait]
    impl Handler for UpgradeHandler {
        fn name(&self) -> &'static str {
            "test_upgrade_handler"
        }

        async fn handle(&self, request: Request) -> Result<Outcome> {
            Ok(Outcome::Continue(request))
        }

        async fn handle_streaming(&self, _request: Request) -> Result<StreamingOutcome> {
            let (stream, _other) = tokio::io::duplex(8);
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::UPGRADE,
                http::HeaderValue::from_static("websocket"),
            );
            headers.insert(
                http::header::CONNECTION,
                http::HeaderValue::from_static("Upgrade"),
            );
            Ok(StreamingOutcome::Upgrade(UpgradedResponse::new(
                http::StatusCode::SWITCHING_PROTOCOLS,
                headers,
                Tunnel::new(stream),
            )))
        }
    }

    #[tokio::test]
    async fn upgradable_router_path_returns_tunnel_with_staged_headers() {
        let headers_handler = Arc::new(
            HeadersHandler::from_json(
                &json!({
                    "handler": "headers",
                    "response": {"set": {"X-Staged": ["yes"]}}
                }),
                "handle[0]",
            )
            .expect("headers handler builds"),
        );
        let router = router_with_handlers(vec![headers_handler, Arc::new(UpgradeHandler)]);
        let outcome = router
            .handle_upgradable(request("/ws", "example.com"))
            .await
            .expect("upgrade-aware routing");
        let crate::types::ResponseOutcome::Upgrade(response) = outcome else {
            panic!("expected an upgraded response");
        };
        assert_eq!(response.status, http::StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(response.headers[http::header::UPGRADE], "websocket");
        assert_eq!(response.headers["x-staged"], "yes");
    }

    #[tokio::test]
    async fn streaming_and_buffered_router_paths_reject_upgrades_loudly() {
        let router = router_with_handlers(vec![Arc::new(UpgradeHandler)]);
        let streaming_error = router
            .handle_streaming(request("/ws", "example.com"))
            .await
            .expect_err("streaming-only path cannot carry a tunnel");
        assert!(
            matches!(streaming_error, Error::UpgradeNotRepresentable { context }
                if context == "Router::handle_streaming"),
            "{streaming_error}"
        );
        let buffered_error = router
            .handle(request("/ws", "example.com"))
            .await
            .expect_err("buffered path cannot carry a tunnel");
        assert!(
            matches!(buffered_error, Error::UpgradeNotRepresentable { .. }),
            "{buffered_error}"
        );
    }

    #[tokio::test]
    async fn security_headers_apply_to_any_handler_response() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {"handler": "security_headers", "content_security_policy": "default-src 'self'"},
                    {
                        "handler": "static_response",
                        "body": "ok",
                        "headers": {"Content-Type": ["text/plain"]}
                    }
                ]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(response.status, http::StatusCode::OK);
        assert_eq!(response.body, bytes::Bytes::from_static(b"ok"));
        assert_eq!(response.headers["x-frame-options"], "DENY");
        assert_eq!(response.headers["x-content-type-options"], "nosniff");
        assert_eq!(
            response.headers["referrer-policy"],
            "strict-origin-when-cross-origin"
        );
        assert_eq!(
            response.headers["content-security-policy"],
            "default-src 'self'"
        );
        // A response header the middleware does not configure survives the staging merge.
        assert_eq!(response.headers[http::header::CONTENT_TYPE], "text/plain");
    }

    #[tokio::test]
    async fn security_headers_apply_to_response_produced_in_subroute() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {"handler": "security_headers", "content_security_policy": "default-src 'self'"},
                    {
                        "handler": "subroute",
                        "routes": [{"handle": [{"handler": "static_response", "body": "nested"}]}]
                    }
                ]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(response.body, bytes::Bytes::from_static(b"nested"));
        assert_eq!(
            response.headers["content-security-policy"],
            "default-src 'self'"
        );
        assert_eq!(response.headers["x-frame-options"], "DENY");
    }

    #[tokio::test]
    async fn per_route_security_headers_override_global_defaults() {
        let router = RouterBuilder::new()
            .build(&[
                // Global (catch-all) defaults: every request runs this route first.
                json!({
                    "handle": [{
                        "handler": "security_headers",
                        "content_security_policy": "default-src 'self'",
                        "permissions_policy": "camera=()"
                    }]
                }),
                json!({
                    "match": [{"host": ["example.com"]}],
                    "handle": [
                        {"handler": "security_headers", "content_security_policy": "default-src 'none'"},
                        {"handler": "static_response", "body": "ok"}
                    ]
                }),
            ])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        // The per-route handler runs after the global one, so its CSP replaces the global value.
        assert_eq!(
            response.headers["content-security-policy"],
            "default-src 'none'"
        );
        // A header only the global route configured is inherited by the per-route handler.
        assert_eq!(response.headers["permissions-policy"], "camera=()");
        assert_eq!(response.headers["x-frame-options"], "DENY");
    }

    #[tokio::test]
    async fn subroute_security_headers_inherit_and_override_parent() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {
                        "handler": "security_headers",
                        "content_security_policy": "default-src 'self'",
                        "permissions_policy": "camera=()"
                    },
                    {
                        "handler": "subroute",
                        "routes": [{
                            "handle": [{
                                "handler": "security_headers",
                                "content_security_policy": "default-src 'none'"
                            }]
                        }]
                    },
                    {"handler": "static_response", "body": "nested-config"}
                ]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(response.body, bytes::Bytes::from_static(b"nested-config"));
        // The child overrides the parent's CSP.
        assert_eq!(
            response.headers["content-security-policy"],
            "default-src 'none'"
        );
        // Opt-in headers the child did not configure are inherited from the parent route.
        assert_eq!(response.headers["permissions-policy"], "camera=()");
        // The child re-asserts the defaulted headers.
        assert_eq!(response.headers["x-frame-options"], "DENY");
    }

    #[tokio::test]
    async fn security_headers_expand_placeholders_in_values() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {
                        "handler": "security_headers",
                        "content_security_policy": "default-src {http.request.host}; report-uri {unknown.placeholder}",
                        "referrer_policy": "origin-{http.request.host}"
                    },
                    {"handler": "static_response", "body": "ok"}
                ]
            })])
            .unwrap();
        let response = router
            .handle(request("/page", "example.com"))
            .await
            .unwrap();
        // Known placeholders expand; unknown ones stay visible (ReplaceKnown semantics).
        assert_eq!(
            response.headers["content-security-policy"],
            "default-src example.com; report-uri {unknown.placeholder}"
        );
        assert_eq!(response.headers["referrer-policy"], "origin-example.com");
    }

    #[tokio::test]
    async fn deeper_middleware_configuration_overrides_outer_security_default() {
        let router = RouterBuilder::new()
            .build(&[json!({
                "handle": [
                    {"handler": "security_headers", "frame_options": "DENY"},
                    {
                        "handler": "subroute",
                        "routes": [{"handle": [
                            {"handler": "headers", "response": {"set": {"X-Frame-Options": ["SAMEORIGIN"]}}}
                        ]}]
                    },
                    {"handler": "static_response", "body": "ok"}
                ]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        // Route order defines precedence: the deeper `headers` handler stages later and wins.
        assert_eq!(response.headers["x-frame-options"], "SAMEORIGIN");
        // Headers the deeper handler did not configure keep the outer middleware value.
        assert_eq!(response.headers["x-content-type-options"], "nosniff");
    }

    #[tokio::test]
    async fn internal_error_responses_are_not_decorated_unless_configured() {
        // No matching route: no handler runs, so nothing is staged. caddy-rs terminates unmatched
        // requests with Caddy's empty 200 (DIV-0068), not a 404.
        let router = RouterBuilder::new()
            .build(&[json!({
                "match": [{"host": ["example.com"]}],
                "handle": [
                    {"handler": "security_headers"},
                    {"handler": "static_response", "body": "ok"}
                ]
            })])
            .unwrap();
        let response = router.handle(request("/", "other.com")).await.unwrap();
        assert_eq!(response.status, http::StatusCode::OK);
        assert!(response.body.is_empty());
        assert_eq!(response.headers.get("x-frame-options"), None);

        // An `error` handler that fails before `security_headers` runs: `handle_errors` answers
        // 404 without security headers because the middleware never staged them.
        let error_routes = json!({"routes": [{
            "handle": [{"handler": "static_response", "status_code": 404, "body": "missing"}]
        }]});
        let router = RouterBuilder::new()
            .with_error_routes(Some(&error_routes), "handle_errors")
            .unwrap()
            .build(&[json!({
                "handle": [
                    {"handler": "error", "status_code": 404},
                    {"handler": "security_headers"}
                ]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(response.status, http::StatusCode::NOT_FOUND);
        assert_eq!(response.headers.get("x-frame-options"), None);

        // Configuring `security_headers` in the error route is the explicit opt-in.
        let decorated_error_routes = json!({"routes": [{
            "handle": [
                {"handler": "security_headers"},
                {"handler": "static_response", "status_code": 404, "body": "missing"}
            ]
        }]});
        let router = RouterBuilder::new()
            .with_error_routes(Some(&decorated_error_routes), "handle_errors")
            .unwrap()
            .build(&[json!({
                "handle": [
                    {"handler": "error", "status_code": 404},
                    {"handler": "security_headers"}
                ]
            })])
            .unwrap();
        let response = router.handle(request("/", "example.com")).await.unwrap();
        assert_eq!(response.status, http::StatusCode::NOT_FOUND);
        assert_eq!(response.headers["x-frame-options"], "DENY");
    }
}
