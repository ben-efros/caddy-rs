//! HTTP engine: matchers, handlers, route evaluation, and static file serving.
//!
//! The crate is transport-agnostic: it operates on [`types::Request`]/[`types::Response`] and is
//! driven by `caddy-rs-server` over hyper connections. That keeps handler behaviour unit-testable
//! without sockets, which matters for conformance work against Caddy.

#![forbid(unsafe_code)]

pub mod auth;
pub mod body;
pub mod file_server;
pub mod handlers;
pub mod matchers;
pub mod placeholders;
pub mod router;
pub mod types;

pub use auth::{BasicAuthHandler, ForwardAuthHandler};
pub use body::{Body, BodyError, RequestBody, ResponseBody, StreamingBody, StreamingResponse};
pub use handlers::{
    EncodeHandler, HeadersHandler, RewriteHandler, StaticResponseHandler, SubrouteHandler,
    VarsHandler,
};
pub use placeholders::{Replacer, UnknownPlaceholders};
pub use router::{CustomHandlerFactory, Route, Router, RouterBuilder};
pub use types::{
    Error, Handler, Matcher, Outcome, Request, Response, Result, SharedHandler, SharedMatcher,
    StreamingOutcome,
};
