//! Validated route actions for the L4 SNI router.
//!
//! Every [`SniAction`] carries the configuration that was validated when the route was built, so a
//! handler never has to re-validate a route at connection time: a connection that arrives during a
//! reload is served by a fully validated [`Route`](crate::router::Route) from the generation that
//! was current when it started.

use std::fmt;

/// Where the L4 router sends a connection whose SNI matched a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SniAction {
    /// Terminate TLS locally (the L4 layer owns the certificate).
    Terminate(TerminateConfig),
    /// Pass the raw byte stream through to an upstream without terminating TLS.
    Passthrough(PassthroughConfig),
    /// Hand the (plaintext) stream to the HTTP server pipeline.
    Http(HttpConfig),
    /// No route matched: the fallback behaviour.
    Fallback(FallbackConfig),
}

impl SniAction {
    /// Short, stable name used in logs and tests.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Terminate(_) => "terminate",
            Self::Passthrough(_) => "passthrough",
            Self::Http(_) => "http",
            Self::Fallback(_) => "fallback",
        }
    }
}

/// Validated configuration for terminating TLS at the L4 layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminateConfig {
    server_name: String,
    alpn: Vec<String>,
}

impl TerminateConfig {
    /// Builds a terminate action for `server_name` (a DNS name, validated and lowercased).
    pub fn new(server_name: impl Into<String>) -> Result<Self, ActionConfigError> {
        let server_name = validate_dns_name("server_name", &server_name.into())?;
        Ok(Self {
            server_name,
            alpn: Vec::new(),
        })
    }

    /// Sets the ALPN protocols advertised for this route (RFC 7301: 1..=255 bytes each, unique).
    pub fn with_alpn<I, S>(mut self, alpn: I) -> Result<Self, ActionConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut protocols = Vec::new();
        for protocol in alpn {
            let protocol = protocol.into();
            if protocol.is_empty() || protocol.len() > 255 {
                return Err(ActionConfigError::new(
                    "alpn",
                    format!("ALPN protocol length must be 1..=255 bytes: {protocol:?}"),
                ));
            }
            if protocols.contains(&protocol) {
                return Err(ActionConfigError::new(
                    "alpn",
                    format!("duplicate ALPN protocol: {protocol:?}"),
                ));
            }
            protocols.push(protocol);
        }
        self.alpn = protocols;
        Ok(self)
    }

    /// The certificate server name for this route.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The configured ALPN protocols, in preference order.
    pub fn alpn(&self) -> &[String] {
        &self.alpn
    }
}

/// Validated configuration for passing a TLS byte stream through to an upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassthroughConfig {
    upstream: String,
    proxy_protocol: bool,
}

impl PassthroughConfig {
    /// Builds a passthrough action for `upstream` (validated as `host:port`).
    pub fn new(upstream: impl Into<String>) -> Result<Self, ActionConfigError> {
        let upstream = upstream.into();
        validate_upstream(&upstream)?;
        Ok(Self {
            upstream,
            proxy_protocol: false,
        })
    }

    /// Enables or disables sending a PROXY protocol v1 header to the upstream.
    pub fn with_proxy_protocol(mut self, enabled: bool) -> Self {
        self.proxy_protocol = enabled;
        self
    }

    /// The `host:port` of the upstream.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// Whether a PROXY protocol header is sent before the stream is copied.
    pub fn proxy_protocol(&self) -> bool {
        self.proxy_protocol
    }
}

/// Validated configuration for handing a connection to the HTTP server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpConfig {
    server_name: Option<String>,
    h2c: bool,
}

impl HttpConfig {
    /// Builds an HTTP handoff action, optionally restricted to a validated server name.
    pub fn new(server_name: Option<String>) -> Result<Self, ActionConfigError> {
        let server_name = match server_name {
            Some(name) => Some(validate_dns_name("server_name", &name)?),
            None => None,
        };
        Ok(Self {
            server_name,
            h2c: false,
        })
    }

    /// Enables or disables HTTP/2 cleartext (h2c) for this route.
    pub fn with_h2c(mut self, enabled: bool) -> Self {
        self.h2c = enabled;
        self
    }

    /// The server name the HTTP handler should use, if any.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Whether h2c is enabled for this route.
    pub fn h2c(&self) -> bool {
        self.h2c
    }
}

/// Why a connection reached the fallback action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackReason {
    /// No route matched the (possibly absent) SNI.
    NoRoute,
    /// The SNI was present but not a valid DNS name.
    InvalidSni,
}

impl fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute => f.write_str("no route matched"),
            Self::InvalidSni => f.write_str("invalid SNI"),
        }
    }
}

/// Validated configuration for the fallback action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FallbackConfig {
    reason: FallbackReason,
}

impl FallbackConfig {
    /// Builds a fallback action with the given reason.
    pub fn new(reason: FallbackReason) -> Self {
        Self { reason }
    }

    /// Why the fallback is being used.
    pub fn reason(&self) -> FallbackReason {
        self.reason
    }
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self::new(FallbackReason::NoRoute)
    }
}

/// A route action configuration that failed validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionConfigError {
    field: &'static str,
    message: String,
}

impl ActionConfigError {
    pub(crate) fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// The configuration field that failed.
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Human-readable reason.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ActionConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {}", self.field, self.message)
    }
}

impl std::error::Error for ActionConfigError {}

/// Validates a DNS name used as SNI/server name and returns its lowercase form.
pub(crate) fn validate_dns_name(
    field: &'static str,
    name: &str,
) -> Result<String, ActionConfigError> {
    let lowered = name.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return Err(ActionConfigError::new(field, "name must not be empty"));
    }
    if lowered.len() > 253 {
        return Err(ActionConfigError::new(
            field,
            format!("name exceeds 253 bytes: {}", lowered.len()),
        ));
    }
    if !lowered
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(ActionConfigError::new(
            field,
            format!("name contains characters outside the DNS hostname set: {lowered:?}"),
        ));
    }
    if lowered.starts_with('.') || lowered.ends_with('.') || lowered.contains("..") {
        return Err(ActionConfigError::new(
            field,
            format!("name has an empty label: {lowered:?}"),
        ));
    }
    for label in lowered.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ActionConfigError::new(
                field,
                format!("label length must be 1..=63 bytes: {label:?}"),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ActionConfigError::new(
                field,
                format!("label must not start or end with '-': {label:?}"),
            ));
        }
    }
    Ok(lowered)
}

/// Validates an upstream `host:port` string.
fn validate_upstream(upstream: &str) -> Result<(), ActionConfigError> {
    if upstream.is_empty() {
        return Err(ActionConfigError::new("upstream", "must not be empty"));
    }
    let Some((host, port)) = upstream.rsplit_once(':') else {
        return Err(ActionConfigError::new(
            "upstream",
            format!("expected host:port, got {upstream:?}"),
        ));
    };
    if host.is_empty() || host == "[]" {
        return Err(ActionConfigError::new("upstream", "host must not be empty"));
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(ActionConfigError::new(
            "upstream",
            format!("invalid port in {upstream:?}"),
        )),
        Ok(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        validate_dns_name, ActionConfigError, FallbackConfig, FallbackReason, HttpConfig,
        PassthroughConfig, SniAction, TerminateConfig,
    };

    #[test]
    fn terminate_config_validates_server_name_and_alpn() {
        let config = TerminateConfig::new("Example.COM")
            .expect("valid names are lowercased")
            .with_alpn(["h2", "http/1.1"])
            .expect("valid ALPN names");
        assert_eq!(config.server_name(), "example.com");
        assert_eq!(config.alpn(), ["h2", "http/1.1"]);

        assert!(TerminateConfig::new("").is_err());
        assert!(TerminateConfig::new("bad name").is_err());
        assert!(TerminateConfig::new("example..com").is_err());
        assert!(TerminateConfig::new("-example.com").is_err());
        let error = TerminateConfig::new("example.com")
            .unwrap()
            .with_alpn([""])
            .expect_err("empty ALPN protocol is invalid");
        assert_eq!(error.field(), "alpn");
        assert!(error.to_string().contains("1..=255"));
    }

    #[test]
    fn passthrough_and_http_configs_validate_their_fields() {
        let passthrough = PassthroughConfig::new("10.0.0.5:8443")
            .expect("valid upstream")
            .with_proxy_protocol(true);
        assert_eq!(passthrough.upstream(), "10.0.0.5:8443");
        assert!(passthrough.proxy_protocol());
        assert!(PassthroughConfig::new("10.0.0.5").is_err());
        assert!(PassthroughConfig::new(":8443").is_err());
        assert!(PassthroughConfig::new("host:0").is_err());

        let http = HttpConfig::new(Some("Example.COM".to_string()))
            .expect("valid server name")
            .with_h2c(true);
        assert_eq!(http.server_name(), Some("example.com"));
        assert!(http.h2c());
        assert_eq!(HttpConfig::new(None).unwrap().server_name(), None);
    }

    #[test]
    fn fallback_and_action_kinds_are_stable() {
        let fallback = FallbackConfig::new(FallbackReason::InvalidSni);
        assert_eq!(fallback.reason(), FallbackReason::InvalidSni);
        assert_eq!(FallbackReason::InvalidSni.to_string(), "invalid SNI");
        assert_eq!(SniAction::Fallback(fallback).kind(), "fallback");
        assert_eq!(
            SniAction::Terminate(TerminateConfig::new("example.com").unwrap()).kind(),
            "terminate"
        );
        assert_eq!(
            SniAction::Passthrough(PassthroughConfig::new("127.0.0.1:443").unwrap()).kind(),
            "passthrough"
        );
        assert_eq!(
            SniAction::Http(HttpConfig::new(None).unwrap()).kind(),
            "http"
        );
    }

    #[test]
    fn dns_validation_is_shared_with_the_router() {
        assert_eq!(
            validate_dns_name("host", "A.Example.COM").unwrap(),
            "a.example.com"
        );
        let error: ActionConfigError = validate_dns_name("host", "a..b").unwrap_err();
        assert_eq!(error.field(), "host");
        assert!(error.message().contains("empty label"));
    }
}
