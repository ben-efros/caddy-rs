//! L4 connection handlers: TLS termination, PROXY protocol injection, throttling and the metered
//! proxy stage (T-L4-008).
//!
//! Each submodule owns one stage; [`crate::handler::L4Handler`] is the trait the pipeline runs, and
//! [`crate::handler::HandlerPipeline`] executes the stages in the validated order. See
//! [`tls::validate_stage_order`] for the ordering contract.

pub mod http;
pub mod proxy;
pub mod proxy_protocol;
pub mod throttle;
pub mod tls;

pub use http::{http_route, HandoffContext, HandoffError, HttpDispatcher};
pub use proxy::{proxy_connection, proxy_route, ProxyError, ProxyOptions, DEFAULT_IDLE_TIMEOUT};
pub use proxy_protocol::{
    render_proxy_header, ProxyHeaderAddresses, ProxyHeaderError, ProxyProtocolVersion, V2_SIGNATURE,
};
pub use throttle::{RateLimit, RateLimitError, ThrottledStream, THROTTLE_BURST_BYTES};
pub use tls::{validate_stage_order, StageOrderError, TerminateError, TlsTerminator, STAGE_ORDER};
