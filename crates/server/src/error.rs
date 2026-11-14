//! Server runtime errors.

use std::net::SocketAddr;

/// Errors raised while building or running the server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration model/validation.
    #[error("configuration error: {0}")]
    Config(caddy_rs_core::Error),

    /// Router construction.
    #[error("HTTP engine error: {0}")]
    Http(caddy_rs_http::Error),

    /// A listener could not be bound.
    ///
    /// The I/O error is part of the located `Display` message and is deliberately not exposed as
    /// `source()` (the field is named `cause`, not `source`), so the CLI's `{error:#}` chain prints
    /// it once (T-OPS-033).
    #[error("cannot bind listener `{listen}`: {cause}")]
    Bind {
        /// Configured listen address.
        listen: String,
        /// Underlying I/O error.
        cause: std::io::Error,
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
    Tls(caddy_rs_tls::Error),

    /// I/O errors.
    #[error("I/O error: {0}")]
    Io(std::io::Error),

    /// The certificate/account data directory could not be prepared.
    #[error("data directory: {0}")]
    DataDir(caddy_rs_core::data_dir::DataDirError),

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
            cause: source,
        }
    }

    /// The configuration-model error behind [`Error::Config`], if this is a configuration failure.
    ///
    /// `Config` is not `#[from]` (T-OPS-033), so the [`caddy_rs_core::Error`] is no longer reachable
    /// through [`std::error::Error::source`]; the CLI uses this accessor to keep its stable
    /// `error[code]` prefix for configuration errors raised while the server is starting.
    pub fn core_error(&self) -> Option<&caddy_rs_core::Error> {
        match self {
            Self::Config(error) => Some(error),
            _ => None,
        }
    }
}

/// A listener's actual bound address (useful for `:0` in tests).
pub type BoundAddress = SocketAddr;

/// Result alias for the server crate.
pub type Result<T> = std::result::Result<T, Error>;

impl From<caddy_rs_tls::Error> for Error {
    fn from(error: caddy_rs_tls::Error) -> Self {
        Self::Tls(error)
    }
}

// These four conversions used to be `#[from]` on the variants. `#[from]` also makes thiserror
// expose the embedded error as `source()`, so the CLI's `{error:#}` chain printed the identical
// message twice (once from the variant's Display and once from its source). The conversions stay
// manual and the variants are not `#[from]`, so each message is printed once (T-OPS-033).
// The removed chains are not downcast anywhere: the CLI only downcasts its own `CliExit` and the
// `caddy_rs_core::Error` that the configuration/validation commands put in the chain themselves
// (runtime failures print the plain `error:` form, see `core_error_code`).
impl From<caddy_rs_core::Error> for Error {
    fn from(error: caddy_rs_core::Error) -> Self {
        Self::Config(error)
    }
}

impl From<caddy_rs_http::Error> for Error {
    fn from(error: caddy_rs_http::Error) -> Self {
        Self::Http(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<caddy_rs_core::data_dir::DataDirError> for Error {
    fn from(error: caddy_rs_core::data_dir::DataDirError) -> Self {
        Self::DataDir(error)
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    /// The CLI renders `{error:#}`, which walks the source chain. While `Tls` was a `#[from]`
    /// variant thiserror also exposed the embedded TLS error as the variant's source, so the CLI
    /// printed the same TLS message twice: once from the variant's `Display` and once from its
    /// source. `Tls` must stay a plain field, converted through the manual `From` below
    /// (T-TLS-095).
    #[test]
    fn a_tls_error_is_not_printed_twice_through_its_own_source() {
        let error = Error::Tls(caddy_rs_tls::Error::Certificate("boom".to_string()));
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(format!("{error:#}"), "TLS error: certificate error: boom");
    }

    /// Render an error the way the CLI does (`{error:#}`): Display, then every `source()` joined
    /// by `": "`. While a variant was `#[from]`, the embedded error appeared once in the variant's
    /// Display and again as its source, so the same text was printed twice.
    fn render_like_the_cli(error: &dyn std::error::Error) -> String {
        let mut rendered = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            rendered.push_str(": ");
            rendered.push_str(&cause.to_string());
            source = cause.source();
        }
        rendered
    }

    #[test]
    fn a_configuration_error_is_not_printed_twice_through_its_own_source() {
        let error = Error::Config(caddy_rs_core::Error::invalid(
            "apps.tls.certificates",
            "no certs",
        ));
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(
            render_like_the_cli(&error),
            "configuration error: invalid configuration at `apps.tls.certificates`: no certs"
        );
    }

    #[test]
    fn an_http_engine_error_is_not_printed_twice_through_its_own_source() {
        let error = Error::Http(caddy_rs_http::Error::InvalidConfig {
            path: "routes[0]".to_string(),
            message: "bad handler".to_string(),
        });
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(
            render_like_the_cli(&error),
            "HTTP engine error: invalid configuration at `routes[0]`: bad handler"
        );
    }

    #[test]
    fn an_io_error_is_not_printed_twice_through_its_own_source() {
        let error = Error::Io(std::io::Error::other("boom"));
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(render_like_the_cli(&error), "I/O error: boom");
    }

    #[test]
    fn a_bind_error_is_printed_once_through_its_located_message() {
        let error = Error::bind(
            "127.0.0.1:1234",
            std::io::Error::new(std::io::ErrorKind::AddrInUse, "address already in use"),
        );
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(
            render_like_the_cli(&error),
            "cannot bind listener `127.0.0.1:1234`: address already in use"
        );
    }

    #[test]
    fn a_data_directory_error_is_not_printed_twice_through_its_own_source() {
        let error = Error::DataDir(caddy_rs_core::data_dir::DataDirError {
            path: std::path::PathBuf::from("/var/lib/caddy"),
            operation: "create",
            source: None,
            kind: caddy_rs_core::data_dir::DataDirErrorKind::Io,
            parent: None,
            parent_mode: None,
            process_uid: None,
            hint: None,
        });
        assert!(std::error::Error::source(&error).is_none());
        let rendered = render_like_the_cli(&error);
        assert!(
            rendered.starts_with("data directory: cannot prepare data directory"),
            "{rendered}"
        );
        assert_eq!(
            rendered.matches("cannot prepare data directory").count(),
            1,
            "{rendered}"
        );
    }
}
