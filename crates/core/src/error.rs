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

    /// A recognised Caddy configuration construct that this build intentionally does not
    /// implement.
    ///
    /// Unlike [`Error::Invalid`], this is not a malformed configuration: Caddy accepts it, and
    /// caddy-rs rejects it loudly (DIV-0016) with a tracking task instead of silently
    /// approximating its behaviour. The message must stay recognisable to the compatibility
    /// tooling's "unsupported" class, hence the "not supported by this build" wording.
    #[error("configuration at `{path}` is not supported by this build: {feature} ({tracking_id})")]
    Unsupported {
        /// JSON path of the unsupported construct.
        path: String,
        /// Human-readable construct name, e.g. ``reverse_proxy `dynamic_upstreams```.
        feature: &'static str,
        /// Plan task id that tracks implementing this construct.
        tracking_id: &'static str,
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

    /// A generation lifecycle hook (provision/start/stop/cleanup) failed.
    ///
    /// The message is located: it names the generation, the phase, and the resource that failed,
    /// so a failed reload can be diagnosed without attaching a debugger. Any additional failures
    /// from the same phase (a cleanup that continues after one resource errors, for example) are
    /// appended to `message`.
    #[error("generation {generation} {phase} failed at resource `{resource}`: {message}")]
    Lifecycle {
        /// Generation id whose lifecycle failed.
        generation: u64,
        /// Phase: `provision`, `start`, `stop`, or `cleanup`.
        phase: &'static str,
        /// Stable resource name reported by the resource's `name()`.
        resource: String,
        /// Failure diagnosis (plus any secondary failures).
        message: String,
    },

    /// A generation lifecycle operation was cancelled before it completed.
    ///
    /// Cancellation is cooperative via [`crate::CancellationToken`]; resources already attached to
    /// the generation are cleaned up exactly once before this error is returned.
    #[error("generation {generation} {phase} was cancelled")]
    LifecycleCancelled {
        /// Generation id whose lifecycle was cancelled.
        generation: u64,
        /// Phase the operation was executing: `provision`, `start`, `stop`, or `cleanup`.
        phase: &'static str,
    },

    /// A lifecycle phase was entered out of order (framework misuse, never user configuration).
    #[error("generation {generation} lifecycle state error: {message}")]
    LifecycleState {
        /// Generation id whose lifecycle state was invalid.
        generation: u64,
        /// What was wrong.
        message: String,
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

    /// Convenience constructor for a located "recognised but unsupported" error.
    pub fn unsupported(
        path: impl Into<String>,
        feature: &'static str,
        tracking_id: &'static str,
    ) -> Self {
        Self::Unsupported {
            path: path.into(),
            feature,
            tracking_id,
        }
    }
}
