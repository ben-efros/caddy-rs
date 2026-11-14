//! HTTP engine: matchers, handlers, route evaluation, and static file serving.
//!
//! The crate is transport-agnostic: it operates on [`types::Request`]/[`types::Response`] and is
//! driven by `caddy-rs-server` over hyper connections. That keeps handler behaviour unit-testable
//! without sockets, which matters for conformance work against Caddy.

#![forbid(unsafe_code)]

pub mod acme_server;
pub mod auth;
pub mod body;
pub mod csp;
#[cfg(feature = "compression")]
pub mod encode;
mod expression;
pub mod file_server;
pub mod handlers;
pub mod matchers;
pub mod placeholders;
pub mod radar_client;
pub mod radar_store;
pub mod rate_limit;
pub mod regex_lite;
pub mod router;
pub mod security_headers;
pub mod security_profile;
#[cfg(feature = "templates")]
pub mod templates;
pub mod types;
pub mod upgrade;

pub use acme_server::{AcmeServerHandler, Http01Fetch, Http01Transport, HyperHttp01Transport};
pub use auth::{BasicAuthHandler, ForwardAuthHandler};
pub use body::{
    Body, BodyCompletion, BodyError, BodyStatus, RequestBody, ResponseBody, ResponseBodyObserver,
    StreamingBody, StreamingResponse,
};
#[cfg(feature = "compression")]
pub use encode::EncodeHandler;
pub use handlers::{
    HeadersHandler, MapHandler, RequestBodyHandler, RewriteHandler, StaticResponseHandler,
    SubrouteHandler, VarsHandler,
};
pub use placeholders::{Replacer, UnknownPlaceholders};
pub use radar_client::{
    is_internet_routable, parse_entries, HyperRadarTransport, PollOutcome, RadarClient,
    RadarConfig, RadarConfigError, RadarEndpoint, RadarEntry, RadarFilters, RadarLog, RadarMetrics,
    RadarMetricsSnapshot, RadarMode, RadarTransport, StderrRadarLog, DEFAULT_BASE_URL,
    DEFAULT_CACHE_TTL, DEFAULT_POLL_INTERVAL, MIN_POLL_INTERVAL,
};
pub use radar_store::{
    FileStorage, MemoryStorage, RadarStorage, RedisStorage, StorageError, StorageSpec,
    DEFAULT_CACHE_PATH,
};
pub use rate_limit::{ManualClock, RateLimitClock, RateLimitHandler, SystemClock};
pub use router::{CustomHandlerFactory, HandlerBuildContext, Route, Router, RouterBuilder};
#[cfg(feature = "templates")]
pub use templates::TemplatesHandler;
pub use types::{
    cipher_suite_name, AccessLogContext, AccessLogUpstream, BodyBytes, ClientCertificate, Error,
    Handler, Matcher, MatcherError, Outcome, Request, Response, ResponseOutcome, Result,
    SharedHandler, SharedMatcher, StreamingOutcome, TlsConnection, TlsVersion,
};
pub use upgrade::{
    h2c_upgrade_headers, h2c_upgrade_settings, is_h2c_upgrade, requested_upgrade_type,
    H2cSettingsError, Tunnel, TunnelStream, UpgradedResponse, H2C_UPGRADE_TOKEN,
    HTTP2_SETTINGS_HEADER,
};
