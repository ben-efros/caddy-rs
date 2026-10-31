//! Server runtime: listener management, hyper serving, admin API binding, and generation-aware
//! reload.
//!
//! Scope of this milestone: HTTP/1.1 and cleartext HTTP/2 (h2c) over TCP and Unix sockets, static
//! responses, file serving, routing, and reverse proxying. TLS termination (M4) and HTTP/3 (M9)
//! are explicit gaps, not silent fallbacks.
//!
//! The crate denies unsafe code. The single exception is [`activation`], which must adopt file
//! descriptors passed by systemd (`FromRawFd` is `unsafe`) to implement socket activation; that
//! module allows unsafe code locally and documents every invariant.

#![deny(unsafe_code)]

pub mod activation;
pub mod error;
pub mod http;
pub mod limits;
pub mod listeners;
pub mod runtime;

pub use activation::{
    plan_activation, ActivationPlan, InheritedSocket, LocalSocket, SocketActivation,
};
pub use error::Error;
pub use limits::{parse_caddy_duration, ServerLimits};
pub use runtime::{RuntimeStatus, ServerRuntime};

/// The default admin API listen address, matching Caddy.
pub const DEFAULT_ADMIN_LISTEN: &str = "localhost:2019";
