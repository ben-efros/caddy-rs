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
//! # HSTS preload requirements
//!
//! The `preload` directive is a commitment that is hard to undo, and the HSTS preload list only
//! accepts a site that sends all of the following (see <https://hstspreload.org>):
//!
//! * a `max-age` of at least one year — [`HSTS_PRELOAD_MIN_MAX_AGE`] seconds (`31536000`);
//! * the `includeSubDomains` directive;
//! * a domain that has been submitted to and accepted by the preload list.
//!
//! [`SecurityHeadersConfig::validate`] rejects the structurally invalid combinations (a too-small
//! `max-age`, or `preload` without `includeSubDomains`). The remaining admission requirements are
//! reported by [`SecurityHeadersConfig::warnings`] instead of failing configuration: a `max-age`
//! below one year is a warning, and membership in the preload list cannot be verified or looked up
//! at config time, so that is always warned about when `preload` is enabled.
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
/// Minimum `max-age` required by the HSTS preload list (1 year, in seconds).
///
/// The preload list also requires `includeSubDomains` and a submitted domain; see the module docs
/// for the full set of admission requirements and how [`SecurityHeadersConfig::warnings`] reports
/// the ones that cannot be enforced at config time.
pub const HSTS_PRELOAD_MIN_MAX_AGE: u64 = 31_536_000;

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
    /// `includeSubDomains`) and values that cannot be represented as an HTTP header value.
    /// Valid configurations that cannot be fully checked here (the HSTS preload-list admission
    /// requirements) are reported by [`SecurityHeadersConfig::warnings`] instead of being rejected.
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

    /// Warnings for HSTS preload requirements this configuration cannot verify at config time.
    ///
    /// Unlike [`Self::validate`], this never fails: it reports HSTS preload-list admission
    /// requirements that are valid configuration but unmet or unverifiable here.
    ///
    /// * `preload` enabled with a `max-age` below [`HSTS_PRELOAD_MIN_MAX_AGE`]: the warning names
    ///   the required one-year (`31536000`) minimum and the configured value.
    /// * `preload` enabled: membership in the HSTS preload list cannot be verified or looked up at
    ///   config time, so the operator is always reminded to confirm the domain at
    ///   <https://hstspreload.org>.
    ///
    /// An empty vector means the configuration is valid and raises no preload warnings.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let Some(hsts) = &self.strict_transport_security else {
            return warnings;
        };
        if !hsts.preload {
            return warnings;
        }
        if hsts.max_age < HSTS_PRELOAD_MIN_MAX_AGE {
            warnings.push(format!(
                "strict_transport_security.preload: preload requires max_age of at least \
                 {HSTS_PRELOAD_MIN_MAX_AGE} seconds (1 year); configured max_age is {}",
                hsts.max_age
            ));
        }
        warnings.push(
            "strict_transport_security.preload: membership in the HSTS preload list cannot be \
             verified or looked up at config time; confirm the domain is admitted at \
             https://hstspreload.org"
                .to_string(),
        );
        warnings
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
    /// This is the **unconditional form**: it never inspects a request and stages
    /// `Strict-Transport-Security` whenever HSTS is configured. It is for callers that already
    /// decided the response is HTTPS (the route engine in T-HTTP-152 calls it from its own staging
    /// path). The [`Handler`] implementation is the HTTPS gate: it only stages HSTS when
    /// [`Request::tls`] is true.
    ///
    /// A header is only inserted when `headers` does not already contain it, so an explicit
    /// response header set earlier in the chain is never clobbered.
    pub fn apply(&self, headers: &mut HeaderMap) {
        self.stage(headers, true);
    }

    /// Shared staging implementation; `include_hsts` gates the `Strict-Transport-Security` header.
    fn stage(&self, headers: &mut HeaderMap, include_hsts: bool) {
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
        if include_hsts {
            if let Some(hsts) = &config.strict_transport_security {
                set_if_absent(headers, "strict-transport-security", &hsts.header_value());
            }
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

/// The [`Handler`] implementation is the HTTPS gate: `Strict-Transport-Security` is staged only
/// when [`Request::tls`] is true, so a plain-HTTP response never carries HSTS even when the
/// configuration enables it. [`SecurityHeaders::apply`] remains the unconditional form (see its
/// documentation).
#[async_trait]
impl Handler for SecurityHeaders {
    fn name(&self) -> &'static str {
        "security_headers"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        let include_hsts = request.tls;
        self.stage(&mut request.pending_response_headers, include_hsts);
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

    fn hsts_config(max_age: u64, include_subdomains: bool, preload: bool) -> SecurityHeadersConfig {
        SecurityHeadersConfig {
            strict_transport_security: Some(HstsConfig {
                max_age,
                include_subdomains,
                preload,
            }),
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

    #[tokio::test]
    async fn hsts_is_staged_on_https_responses_only() {
        let middleware = SecurityHeaders::new(hsts_config(31_536_000, true, true)).unwrap();

        // TLS request: the HSTS header is staged with the configured value.
        let mut https_request = request();
        https_request.tls = true;
        let outcome = middleware.handle(https_request).await.unwrap();
        let Outcome::Continue(https_request) = outcome else {
            panic!("security_headers must continue the chain");
        };
        assert_eq!(
            header_value(
                &https_request.pending_response_headers,
                "strict-transport-security"
            )
            .as_deref(),
            Some("max-age=31536000; includeSubDomains; preload")
        );

        // Plain-HTTP request: HSTS is not staged even though it is configured, while the
        // non-HSTS defaults are still staged.
        let mut http_request = request();
        assert!(!http_request.tls);
        let outcome = middleware.handle(http_request).await.unwrap();
        let Outcome::Continue(http_request) = outcome else {
            panic!("security_headers must continue the chain");
        };
        assert_eq!(
            header_value(
                &http_request.pending_response_headers,
                "strict-transport-security"
            ),
            None
        );
        assert_eq!(
            header_value(&http_request.pending_response_headers, "x-frame-options").as_deref(),
            Some("DENY")
        );
    }

    #[tokio::test]
    async fn hsts_directives_are_configurable() {
        // Bare max-age: neither includeSubDomains nor preload.
        let bare = SecurityHeaders::new(hsts_config(15_552_000, false, false)).unwrap();
        let mut headers = HeaderMap::new();
        bare.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "strict-transport-security").as_deref(),
            Some("max-age=15552000")
        );

        // includeSubDomains without preload.
        let subdomains = SecurityHeaders::new(hsts_config(31_536_000, true, false)).unwrap();
        let mut headers = HeaderMap::new();
        subdomains.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "strict-transport-security").as_deref(),
            Some("max-age=31536000; includeSubDomains")
        );

        // Both directives: preload is emitted last.
        let full = SecurityHeaders::new(hsts_config(63_072_000, true, true)).unwrap();
        let mut headers = HeaderMap::new();
        full.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "strict-transport-security").as_deref(),
            Some("max-age=63072000; includeSubDomains; preload")
        );
    }

    #[tokio::test]
    async fn hsts_header_value_matches_rfc_6797() {
        // RFC 6797 §6.1: `max-age=<seconds>[; includeSubDomains][; preload]`, lowercase directive
        // name, semicolon+space separators, camel-case includeSubDomains, preload last.
        let config = hsts_config(31_536_000, true, true);
        assert_eq!(
            config
                .strict_transport_security
                .as_ref()
                .unwrap()
                .header_value(),
            "max-age=31536000; includeSubDomains; preload"
        );

        let middleware = SecurityHeaders::new(config).unwrap();
        let mut headers = HeaderMap::new();
        middleware.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "strict-transport-security").as_deref(),
            Some("max-age=31536000; includeSubDomains; preload")
        );
    }

    #[test]
    fn preload_below_one_year_warns_with_required_and_configured_max_age() {
        // 180 days is structurally valid (validate passes) but not preload-eligible.
        let config = hsts_config(15_552_000, true, true);
        config.validate().unwrap();

        let warnings = config.warnings();
        let short_max_age = warnings
            .iter()
            .find(|warning| warning.contains("max_age"))
            .expect("preload below one year must warn about max_age");
        assert!(
            short_max_age.contains("31536000"),
            "warning must name the required 31536000 minimum: {short_max_age}"
        );
        assert!(
            short_max_age.contains("15552000"),
            "warning must name the configured value: {short_max_age}"
        );
    }

    #[test]
    fn preload_membership_cannot_be_verified_at_config_time() {
        // A one-year max-age satisfies the measurable requirement, but list membership still
        // cannot be checked at config time.
        let warnings = hsts_config(31_536_000, true, true).warnings();
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("cannot be verified or looked up at config time"),
            "warning must name the unverifiable membership: {}",
            warnings[0]
        );
        assert!(warnings[0].contains("preload list"));
    }

    #[test]
    fn no_preload_warnings_when_preload_is_disabled() {
        assert!(SecurityHeadersConfig::default().warnings().is_empty());
        assert!(hsts_config(31_536_000, true, false).warnings().is_empty());
    }

    #[tokio::test]
    async fn apply_stages_hsts_unconditionally_for_route_engines() {
        // `apply` is the unconditional form used by the route engine (T-HTTP-152); it has no
        // request, so it stages HSTS regardless of transport. The Handler above is the HTTPS gate.
        let middleware = SecurityHeaders::new(hsts_config(31_536_000, true, true)).unwrap();
        let mut headers = HeaderMap::new();
        middleware.apply(&mut headers);
        assert_eq!(
            header_value(&headers, "strict-transport-security").as_deref(),
            Some("max-age=31536000; includeSubDomains; preload")
        );
    }
}
