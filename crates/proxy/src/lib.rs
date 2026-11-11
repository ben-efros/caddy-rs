//! Reverse proxy: upstream model, load balancing, retries, health checks, and the
//! `reverse_proxy` handler.

#![forbid(unsafe_code)]

pub mod balancer;
pub mod client;
pub mod digest;
pub mod dns;
pub mod dynamic_upstreams;
pub mod fastcgi;
pub mod forward_auth;
pub mod handler;
pub mod health;
pub mod passive;
pub mod retry;
pub mod template;
pub mod tls;
pub mod trusted_proxies;
pub mod upstream;
pub mod websocket;

pub use balancer::{
    from_selection_policy, Balancer, BalancerError, CookieHash, First, HashSelection,
    LeastConnections, Random, RandomChoice, RoundRobin, WeightedRoundRobin,
};
pub use dns::{DnsResolver, IpVersion, ResolverAddress, ResolverNetwork, SrvRecord};
pub use dynamic_upstreams::{DynamicUpstreamSource, DynamicUpstreams};
pub use fastcgi::{FastCgiError, FastCgiTransport};
pub use handler::{
    handler_factory, handler_factory_with_status_sink, handler_factory_with_status_sink_and_server_software, FlushInterval, ReverseProxyHandler,
    UpstreamStatus, UpstreamStatusSink,
};
pub use health::{status_matches, HealthCheck, HealthCheckScheduler};
pub use passive::{PassiveHealth, PassiveHealthConfig};
pub use retry::RetryMatch;
pub use tls::UpstreamTls;
pub use trusted_proxies::{IpNet, ServerTrustedProxies};
pub use upstream::Upstream;
pub use websocket::{
    close_frame, is_websocket_handshake, request_is_websocket, response_negotiated_websocket,
    tunnel, write_close_frame, CLOSE_GOING_AWAY, CLOSE_HANDSHAKE_TIMEOUT, CLOSE_NORMAL,
};
