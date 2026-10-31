//! Typed configuration and registry errors. Every error names the offending input.

use std::path::PathBuf;

/// Errors produced by the configuration model, validation, and lifecycle layers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A structural or semantic configuration problem, located by JSON path.
    #[error("invalid configuration at `{path}`: {message}")]
    Invalid {
        /// JSON path of the offending value (for example `apps.http.servers.srv0.listen[1]`).
        path: String,
        /// Human-readable diagnosis naming the offending value.
        message: String,
    },

    /// A module name that the registry does not know how to load.
    #[error("unknown {kind} module `{name}` at `{path}`")]
    UnknownModule {
        /// Module category, for example `HTTP handler`.
        kind: &'static str,
        /// Name as written in the configuration.
        name: String,
        /// JSON path of the reference.
        path: String,
    },

    /// A listen address that cannot be parsed.
    #[error("invalid listen address `{value}` at `{path}`: {reason}")]
    InvalidListen {
        /// The address as written.
        value: String,
        /// JSON path of the address.
        path: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The configuration document could not be read from disk.
    #[error("cannot read config file `{}`: {source}", path.display())]
    ConfigIo {
        /// File that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configuration document was not valid JSON or did not match the model.
    #[error("cannot decode config JSON: {source}")]
    Json {
        /// Underlying serde error.
        #[from]
        source: serde_json::Error,
    },

    /// Two modules were registered with the same id.
    #[error("module registry: module id `{0}` is already registered")]
    DuplicateModule(&'static str),

    /// A requested capability is recognised but intentionally not implemented yet.
    #[error("not implemented: {feature} ({tracking_id})")]
    NotImplemented {
        /// Capability.
        feature: &'static str,
        /// Plan task or divergence id tracking the gap.
        tracking_id: &'static str,
    },
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Convenience constructor for a located invalid-configuration error.
    pub fn invalid(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.into(),
            message: message.into(),
        }
    }
}
