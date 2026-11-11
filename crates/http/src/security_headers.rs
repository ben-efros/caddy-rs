//! Security response headers middleware (caddy-rs extension).
//!
//! This module is a **caddy-rs extension with no Caddy equivalent**. Caddy v2.11.9 only ships the
//! generic `headers` handler (`modules/caddyhttp/headers/headers.go`), which stages whatever
//! headers the user configures and applies no security defaults of its own. Here a route can opt
//! into a set of security headers with secure defaults instead of spelling out every header by
//! hand.
//!
//! # Defaults and opt-ins
//!
//! [`SecurityHeadersConfig::default`] is the most secure configuration:
//!
//! * `X-Frame-Options: DENY`
//! * `X-Content-Type-Options: nosniff`
//! * `Referrer-Policy: strict-origin-when-cross-origin`
//!
//! These three headers can be overridden per config (or suppressed by setting the field to
//! `None`). The remaining headers are **opt-in** and are only emitted when explicitly configured:
//!
//! * `Content-Security-Policy` — [`SecurityHeadersConfig::content_security_policy`]. There is no
//!   safe default CSP: a restrictive policy that works for one site breaks another, so the
//!   middleware never guesses one.
//! * `Strict-Transport-Security` — [`SecurityHeadersConfig::strict_transport_security`]. HSTS is
//!   only valid over TLS and is hard to undo, so it requires an explicit [`HstsConfig`].
//! * `Permissions-Policy` — [`SecurityHeadersConfig::permissions_policy`]. Feature policy is
//!   site-specific, so it is only emitted when configured.
//!
//! # Staging and precedence
//!
//! [`SecurityHeaders`] is a [`Handler`] that stages its headers into
//! [`Request::pending_response_headers`] and returns [`Outcome::Continue`]; it never touches the
//! request body or the response body. A header is only staged when the pending response does not
//! already carry it, so a handler that set the header explicitly (for example the generic
//! `headers` handler earlier in the chain) wins over the middleware default.
//!
//! [`Request::pending_response_headers`]: crate::types::Request::pending_response_headers

use async_trait::async_trait;
use http::HeaderMap;

use crate::types::{Error, Handler, Outcome, Request, Result};

/// Default `X-Frame-Options` value: refuse framing entirely.
pub const DEFAULT_X_FRAME_OPTIONS: &str = "DENY";
/// Default `X-Content-Type-Options` value: never MIME-sniff a response.
pub const DEFAULT_X_CONTENT_TYPE_OPTIONS: &str = "nosniff";
/// Default `Referrer-Policy` value: send the origin cross-origin, never the full URL.
pub const DEFAULT_REFERRER_POLICY: &str = "strict-origin-when-cross-origin";
/// Minimum `Strict-Transport-Security` `max-age` accepted by browsers (180 days, in seconds).
pub const HSTS_MIN_MAX_AGE: u64 = 15_552_000;

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// `Strict-Transport-Security` configuration (opt-in).
///
/// The emitted value is `max-age=<max_age>` plus `; includeSubDomains` when
/// [`HstsConfig::include_subdomains`] is set and `; preload` when [`HstsConfig::preload`] is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HstsConfig {
    /// `max-age` directive, in seconds. Must be at least [`HSTS_MIN_MAX_AGE`].
    pub max_age: u64,
    /// Emit `includeSubDomains`; also required by `preload`.
    pub include_subdomains: bool,
    /// Emit the `preload` directive (requires `include_subdomains`).
    pub preload: bool,
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            max_age: 31_536_000,
            include_subdomains: false,
            preload: false,
        }
    }
}

impl HstsConfig {
    /// Render the `Strict-Transport-Security` header value for this configuration.
    pub fn header_value(&self) -> String {
        let mut value = format!("max-age={}", self.max_age);
        if self.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if self.preload {
            value.push_str("; preload");
        }
        value
    }
}

/// Security headers middleware configuration.
///
/// [`Default`] applies the secure defaults documented at the module level. The three defaulted
/// headers are `Option<String>` so they can be overridden with a custom value or suppressed
/// entirely with `None`; CSP, HSTS and `Permissions-Policy` are `None` (opt-in) by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHeadersConfig {
    /// `Content-Security-Policy` value. `None` (the default) emits no CSP header.
    pub content_security_policy: Option<String>,
    /// `Strict-Transport-Security` configuration. `None` (the default) emits no HSTS header.
    pub strict_transport_security: Option<HstsConfig>,
    /// `Permissions-Policy` value. `None` (the default) emits no header.
    pub permissions_policy: Option<String>,
    /// `X-Frame-Options` value; defaults to [`DEFAULT_X_FRAME_OPTIONS`]. `None` suppresses it.
    pub x_frame_options: Option<String>,
    /// `X-Content-Type-Options` value; defaults to [`DEFAULT_X_CONTENT_TYPE_OPTIONS`]. `None`
    /// suppresses it.
    pub x_content_type_options: Option<String>,
    /// `Referrer-Policy` value; defaults to [`DEFAULT_REFERRER_POLICY`]. `None` suppresses it.
    pub referrer_policy: Option<String>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            content_security_policy: None,
            strict_transport_security: None,
            permissions_policy: None,
            x_frame_options: Some(DEFAULT_X_FRAME_OPTIONS.to_string()),
            x_content_type_options: Some(DEFAULT_X_CONTENT_TYPE_OPTIONS.to_string()),
            referrer_policy: Some(DEFAULT_REFERRER_POLICY.to_string()),
        }
    }
}

impl SecurityHeadersConfig {
    /// Reject configurations that are invalid or unsafe to emit.
    ///
    /// This is deliberately minimal: it rejects an HSTS configuration browsers would ignore
    /// (`max-age=0`, `max-age` below [`HSTS_MIN_MAX_AGE`], or `preload` without
    /// `includeSubDomains`) and values that cannot be represented as an HTTP header value. The
    /// warning-versus-strict policy for valid-but-unusual configurations belongs to T-HTTP-153.
    pub fn validate(&self) -> Result<()> {
        if let Some(hsts) = &self.strict_transport_security {
            if hsts.max_age == 0 {
                return Err(invalid(
                    "strict_transport_security.max_age",
                    "max_age must be greater than 0",
                ));
            }
            if hsts.max_age < HSTS_MIN_MAX_AGE {
                return Err(invalid(
                    "strict_transport_security.max_age",
                    format!(
                        "max_age must be at least {HSTS_MIN_MAX_AGE} seconds (180 days); \
                         browsers ignore shorter values"
                    ),
                ));
            }
            if hsts.preload && !hsts.include_subdomains {
                return Err(invalid(
                    "strict_transport_security.preload",
                    "preload requires include_subdomains to be enabled",
                ));
            }
        }
        for (path, value) in [
            ("content_security_policy", &self.content_security_policy),
            ("permissions_policy", &self.permissions_policy),
            ("x_frame_options", &self.x_frame_options),
            ("x_content_type_options", &self.x_content_type_options),
            ("referrer_policy", &self.referrer_policy),
        ] {
            if let Some(value) = value {
                value
                    .parse::<http::HeaderValue>()
                    .map_err(|error| invalid(path, format!("invalid header value: {error}")))?;
            }
        }
        Ok(())
    }
}

/// `security_headers`: stage security response headers with secure defaults.
///
/// Construct with [`SecurityHeaders::new`] (validates the configuration) and stage the headers
/// either by running it as a [`Handler`] or by calling [`SecurityHeaders::apply`] directly on a
/// [`HeaderMap`] (used by the route engine in T-HTTP-152).
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    config: SecurityHeadersConfig,
}

impl SecurityHeaders {
    /// Build the middleware, validating the configuration.
    pub fn new(config: SecurityHeadersConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// The effective configuration.
    pub fn config(&self) -> &SecurityHeadersConfig {
        &self.config
    }

    /// Stage the configured security headers on `headers`.
    ///
    /// A header is only inserted when `headers` does not already contain it, so an explicit
    /// response header set earlier in the chain is never clobbered.
    pub fn apply(&self, headers: &mut HeaderMap) {
        let config = &self.config;
        if let Some(value) = &config.x_frame_options {
            set_if_absent(headers, "x-frame-options", value);
        }
        if let Some(value) = &config.x_content_type_options {
            set_if_absent(headers, "x-content-type-options", value);
        }
        if let Some(value) = &config.referrer_policy {
            set_if_absent(headers, "referrer-policy", value);
        }
        if let Some(value) = &config.content_security_policy {
            set_if_absent(headers, "content-security-policy", value);
        }
        if let Some(hsts) = &config.strict_transport_security {
            set_if_absent(headers, "strict-transport-security", &hsts.header_value());
        }
        if let Some(value) = &config.permissions_policy {
            set_if_absent(headers, "permissions-policy", value);
        }
    }
}

/// Insert `value` under `name` unless the map already carries that header.
///
/// Values were validated by [`SecurityHeadersConfig::validate`], so parsing cannot fail here.
fn set_if_absent(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if headers.contains_key(name) {
        return;
    }
    let value = value
        .parse::<http::HeaderValue>()
        .expect("security header value was validated by SecurityHeadersConfig::validate");
    headers.insert(name, value);
}

#[async_trait]
impl Handler for SecurityHeaders {
    fn name(&self) -> &'static str {
        "security_headers"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        self.apply(&mut request.pending_response_headers);
        Ok(Outcome::Continue(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Method, Uri};

    fn request() -> Request {
        Request::new(Method::GET, "/".parse::<Uri>().unwrap())
    }

    fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
        headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_string())
    }

    fn config_with_csp(policy: &str) -> SecurityHeadersConfig {
        SecurityHeadersConfig {
            content_security_policy: Some(policy.to_string()),
            ..SecurityHeadersConfig::default()
        }
    }

    #[tokio::test]
    async fn stages_headers_on_response_without_mutating_body() {
        let middleware = SecurityHeaders::new(SecurityHeadersConfig::default()).unwrap();
        assert_eq!(middleware.name(), "security_headers");
        let mut request = request();
        request.body = Bytes::from_static(b"request body stays put");
        request.headers.insert("x-request", "keep".parse().unwrap());

        let outcome = middleware.handle(request).await.unwrap();
        let Outcome::Continue(request) = outcome else {
            panic!("security_headers must continue the chain");
        };

        // Headers are staged on the response, not written to the request headers.
        assert_eq!(
            header_value(&request.pending_response_headers, "x-frame-options").as_deref(),
            Some("DENY")
        );
        assert_eq!(
            header_value(&request.pending_response_headers, "x-content-type-options").as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            header_value(&request.pending_response_headers, "referrer-policy").as_deref(),
            Some("strict-origin-when-cross-origin")
        );
        assert_eq!(header_value(&request.headers, "x-frame-options"), None);
        // The body is untouched.
        assert_eq!(request.body, Bytes::from_static(b"request body stays put"));
    }

    #[tokio::test]
    async fn x_frame_options_defaults_to_deny() {
        let middleware = SecurityHeaders::new(SecurityHeadersConfig::default()).unwrap();
        let mut headers = HeaderMap::new();
        middleware.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "x-frame-options").as_deref(),
            Some("DENY")
        );
    }

    #[tokio::test]
    async fn x_content_type_options_defaults_to_nosniff() {
        let middleware = SecurityHeaders::new(SecurityHeadersConfig::default()).unwrap();
        let mut headers = HeaderMap::new();
        middleware.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "x-content-type-options").as_deref(),
            Some("nosniff")
        );
    }

    #[tokio::test]
    async fn referrer_policy_defaults_to_strict_origin_when_cross_origin() {
        let middleware = SecurityHeaders::new(SecurityHeadersConfig::default()).unwrap();
        let mut headers = HeaderMap::new();
        middleware.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "referrer-policy").as_deref(),
            Some("strict-origin-when-cross-origin")
        );
    }

    #[tokio::test]
    async fn csp_is_opt_in() {
        // Default configuration emits no CSP header at all.
        let default = SecurityHeaders::new(SecurityHeadersConfig::default()).unwrap();
        let mut headers = HeaderMap::new();
        default.apply(&mut headers);
        assert_eq!(header_value(&headers, "content-security-policy"), None);

        // Explicit configuration emits exactly the configured policy.
        let policy = "default-src 'self'; script-src 'self'";
        let configured = SecurityHeaders::new(config_with_csp(policy)).unwrap();
        let mut headers = HeaderMap::new();
        configured.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "content-security-policy").as_deref(),
            Some(policy)
        );
    }

    #[tokio::test]
    async fn hsts_is_opt_in_and_requires_valid_config() {
        // Default configuration emits no HSTS header.
        let default = SecurityHeaders::new(SecurityHeadersConfig::default()).unwrap();
        let mut headers = HeaderMap::new();
        default.apply(&mut headers);
        assert_eq!(header_value(&headers, "strict-transport-security"), None);

        // Explicit, valid configuration emits the expected directives.
        let enabled = SecurityHeaders::new(SecurityHeadersConfig {
            strict_transport_security: Some(HstsConfig {
                max_age: 31_536_000,
                include_subdomains: true,
                preload: true,
            }),
            ..SecurityHeadersConfig::default()
        })
        .unwrap();
        let mut headers = HeaderMap::new();
        enabled.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "strict-transport-security").as_deref(),
            Some("max-age=31536000; includeSubDomains; preload")
        );

        // Invalid HSTS configurations are rejected with a located InvalidConfig error.
        for (hsts, expected_path) in [
            (
                HstsConfig {
                    max_age: 0,
                    include_subdomains: true,
                    preload: false,
                },
                "strict_transport_security.max_age",
            ),
            (
                HstsConfig {
                    max_age: 86_400,
                    include_subdomains: true,
                    preload: false,
                },
                "strict_transport_security.max_age",
            ),
            (
                HstsConfig {
                    max_age: 31_536_000,
                    include_subdomains: false,
                    preload: true,
                },
                "strict_transport_security.preload",
            ),
        ] {
            let error = SecurityHeaders::new(SecurityHeadersConfig {
                strict_transport_security: Some(hsts),
                ..SecurityHeadersConfig::default()
            })
            .unwrap_err();
            match error {
                Error::InvalidConfig { path, .. } => assert_eq!(path, expected_path),
                other => panic!("expected InvalidConfig, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn permissions_policy_is_opt_in() {
        let default = SecurityHeaders::new(SecurityHeadersConfig::default()).unwrap();
        let mut headers = HeaderMap::new();
        default.apply(&mut headers);
        assert_eq!(header_value(&headers, "permissions-policy"), None);

        let policy = "camera=(), microphone=(), geolocation=()";
        let configured = SecurityHeaders::new(SecurityHeadersConfig {
            permissions_policy: Some(policy.to_string()),
            ..SecurityHeadersConfig::default()
        })
        .unwrap();
        let mut headers = HeaderMap::new();
        configured.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "permissions-policy").as_deref(),
            Some(policy)
        );
    }

    #[tokio::test]
    async fn existing_response_header_is_not_overwritten() {
        let middleware = SecurityHeaders::new(SecurityHeadersConfig::default()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-frame-options", "SAMEORIGIN".parse().unwrap());
        headers.insert("referrer-policy", "no-referrer".parse().unwrap());

        middleware.apply(&mut headers);

        assert_eq!(
            header_value(&headers, "x-frame-options").as_deref(),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            header_value(&headers, "referrer-policy").as_deref(),
            Some("no-referrer")
        );
        // Headers the response did not carry are still staged.
        assert_eq!(
            header_value(&headers, "x-content-type-options").as_deref(),
            Some("nosniff")
        );
    }
}
