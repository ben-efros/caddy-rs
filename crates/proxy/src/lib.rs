//! Reverse proxy: upstream model, load balancing, retries, health checks, and the
//! `reverse_proxy` handler.

#![forbid(unsafe_code)]

pub mod balancer;
pub mod client;
pub mod handler;
pub mod health;
pub mod passive;
pub mod retry;
pub mod tls;
pub mod upstream;

pub use balancer::{from_policy, Balancer, First, LeastConnections, RoundRobin};
pub use handler::{handler_factory, ReverseProxyHandler};
pub use health::{status_matches, HealthCheck, HealthCheckScheduler};
pub use passive::{PassiveHealth, PassiveHealthConfig};
pub use retry::RetryMatch;
pub use tls::UpstreamTls;
pub use upstream::Upstream;
