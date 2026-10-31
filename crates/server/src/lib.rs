//! Server runtime: listener management, hyper serving, admin API binding, and generation-aware
//! reload.
//!
//! Scope of this milestone: HTTP/1.1 and cleartext HTTP/2 (h2c) over TCP and Unix sockets, static
//! responses, file serving, routing, and reverse proxying. TLS termination (M4) and HTTP/3 (M9)
//! are explicit gaps, not silent fallbacks.

#![forbid(unsafe_code)]

pub mod error;
pub mod http;
pub mod listeners;
pub mod runtime;

pub use error::Error;
pub use runtime::{RuntimeStatus, ServerRuntime};

/// The default admin API listen address, matching Caddy.
pub const DEFAULT_ADMIN_LISTEN: &str = "localhost:2019";
