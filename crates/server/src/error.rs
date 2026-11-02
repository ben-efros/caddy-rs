//! Server runtime errors.

use std::net::SocketAddr;

/// Errors raised while building or running the server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration model/validation.
    #[error("configuration error: {0}")]
    Config(#[from] caddy_rs_core::Error),

    /// Router construction.
    #[error("HTTP engine error: {0}")]
    Http(#[from] caddy_rs_http::Error),

    /// A listener could not be bound.
    #[error("cannot bind listener `{listen}`: {source}")]
    Bind {
        /// Configured listen address.
        listen: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Configured listen address is invalid.
    #[error("invalid listen address `{listen}`: {reason}")]
    Listen {
        /// Configured address.
        listen: String,
        /// Diagnosis.
        reason: String,
    },

    /// A configured capability is not implemented.
    #[error("not implemented: {feature} ({tracking_id})")]
    NotImplemented {
        /// Capability.
        feature: &'static str,
        /// Tracking task.
        tracking_id: &'static str,
    },

    /// Admin listener address could not be resolved.
    #[error("invalid admin listen address `{0}`")]
    AdminAddress(String),

    /// systemd socket activation is inconsistent.
    ///
    /// `path` names the offending environment value (for example `LISTEN_FDS[1]`), so the
    /// operator can find the systemd unit/configuration mismatch.
    #[error("socket activation: invalid `{path}`: {message}")]
    SocketActivation {
        /// Located activation path (`LISTEN_PID`, `LISTEN_FDS[2]`, ...).
        path: String,
        /// Diagnosis naming the offending value.
        message: String,
    },

    /// Server-side TLS configuration errors.
    #[error("TLS error: {0}")]
    Tls(#[from] caddy_rs_tls::Error),

    /// I/O errors.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Observability (access-log / metrics) configuration is invalid.
    ///
    /// The message carries the located JSON path from [`caddy_rs_admin::LoggingConfigError`] and,
    /// for recognised-but-unsupported Caddy features, the tracking id.
    #[error("observability configuration: {0}")]
    Observability(String),
}

impl From<caddy_rs_admin::LoggingConfigError> for Error {
    fn from(error: caddy_rs_admin::LoggingConfigError) -> Self {
        Self::Observability(error.to_string())
    }
}

impl Error {
    pub(crate) fn bind(listen: &str, source: std::io::Error) -> Self {
        Self::Bind {
            listen: listen.to_string(),
            source,
        }
    }
}

/// A listener's actual bound address (useful for `:0` in tests).
pub type BoundAddress = SocketAddr;

/// Result alias for the server crate.
pub type Result<T> = std::result::Result<T, Error>;
