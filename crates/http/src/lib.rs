//! HTTP engine: matchers, handlers, route evaluation, and static file serving.
//!
//! The crate is transport-agnostic: it operates on [`types::Request`]/[`types::Response`] and is
//! driven by `caddy-rs-server` over hyper connections. That keeps handler behaviour unit-testable
//! without sockets, which matters for conformance work against Caddy.

#![forbid(unsafe_code)]

pub mod auth;
pub mod body;
pub mod encode;
mod expression;
pub mod file_server;
pub mod handlers;
pub mod matchers;
pub mod placeholders;
pub mod rate_limit;
pub mod regex_lite;
pub mod router;
pub mod templates;
pub mod types;
pub mod upgrade;

pub use auth::{BasicAuthHandler, ForwardAuthHandler};
pub use body::{Body, BodyError, RequestBody, ResponseBody, StreamingBody, StreamingResponse};
pub use encode::EncodeHandler;
pub use handlers::{
    HeadersHandler, MapHandler, RequestBodyHandler, RewriteHandler, StaticResponseHandler,
    SubrouteHandler, VarsHandler,
};
pub use placeholders::{Replacer, UnknownPlaceholders};
pub use rate_limit::{ManualClock, RateLimitClock, RateLimitHandler, SystemClock};
pub use router::{CustomHandlerFactory, Route, Router, RouterBuilder};
pub use templates::TemplatesHandler;
pub use types::{
    Error, Handler, Matcher, MatcherError, Outcome, Request, Response, ResponseOutcome, Result,
    SharedHandler, SharedMatcher, StreamingOutcome,
};
pub use upgrade::{
    h2c_upgrade_headers, h2c_upgrade_settings, is_h2c_upgrade, requested_upgrade_type,
    H2cSettingsError, Tunnel, TunnelStream, UpgradedResponse, H2C_UPGRADE_TOKEN,
    HTTP2_SETTINGS_HEADER,
};
