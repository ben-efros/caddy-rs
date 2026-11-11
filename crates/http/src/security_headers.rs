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
//! # Route integration and ordering
//!
//! [`SecurityHeaders`] is a [`Handler`] that stages its headers into
//! [`Request::pending_response_headers`] and returns [`Outcome::Continue`]; it never touches the
//! request body or the response body. The router merges the staged map onto the response after a
//! handler produces it and before the response is sent (response middleware staging, T-ROUTE-011).
//!
//! Ordering follows route evaluation order, exactly like every other handler:
//!
//! * Handlers run in route order: a global (catch-all) route's handler runs before a more specific
//!   route's handler, and an outer route's handler runs before a nested `subroute`'s handler.
//! * [`SecurityHeaders::stage`] **replaces** the value staged for every header it configures, so
//!   the handler that appears later in the chain wins. A `subroute` that continues the chain shares
//!   the staged map, so its handler overrides the value its parent staged and inherits the headers
//!   it does not configure (the opt-in headers); the three defaulted headers are re-asserted with
//!   their secure default by every handler. A `subroute` that itself produces the response is
//!   merged at its own level first (T-ROUTE-011), and the outer level then applies its unchanged
//!   staged map last, so in that shape the outer value wins.
//! * [`SecurityHeaders::apply`] is the set-if-absent operation for a response header map: it never
//!   clobbers a header the response already carries. The router's staging merge is the last writer
//!   instead (T-ROUTE-011), so a staged value replaces a same-named response header; a handler that
//!   must override the middleware has to stage the header later in the chain (an `headers` handler
//!   that runs after this one) rather than write it directly on the response.
//! * Responses that short-circuit before this handler runs are not decorated: a request that
//!   matches no route, a matcher error, or an `error` handler that fails earlier in the chain never
//!   stages these headers. Configuring `security_headers` inside the `handle_errors` routes is the
//!   explicit opt-in that decorates error responses.
//!
//! Every configured value is expanded at request time with Caddy's `Replacer.ReplaceKnown`
//! semantics: known placeholders such as `{http.request.host}` are substituted, unknown
//! placeholders are left visible verbatim.
//!
//! # JSON configuration (`security_headers` handler)
//!
//! The handler is a caddy-rs extension (Caddy v2.11.9 has no such module). Its object is
//! `{"handler": "security_headers", ...}` with these optional keys:
//!
//! | Key | Type | Emitted header |
//! |---|---|---|
//! | `frame_options` | string or `false` | `X-Frame-Options` (default `DENY`) |
//! | `content_type_options` | string or `false` | `X-Content-Type-Options` (default `nosniff`) |
//! | `referrer_policy` | string or `false` | `Referrer-Policy` (default `strict-origin-when-cross-origin`) |
//! | `content_security_policy` | string or `false` | `Content-Security-Policy` (opt-in) |
//! | `permissions_policy` | string or `false` | `Permissions-Policy` (opt-in) |
//! | `strict_transport_security` | object or `false` | `Strict-Transport-Security` (opt-in) |
//!
//! A string is the emitted value; the boolean `false` (or the string `"false"`) suppresses the
//! header. Omitting a defaulted key keeps the secure default, while omitting an opt-in key emits
//! nothing. `strict_transport_security` is
//! `{"max_age": <u64>, "include_subdomains": <bool>, "preload": <bool>}`; `max_age` is required
//! when the object is present and the booleans default to `false`. Unknown keys at either level are
//! a located [`Error::InvalidConfig`] naming `<json path>.<field>`, as is any configuration the
//! middleware constructor rejects (for example a `max_age` below 180 days).
//!
//! [`Request::pending_response_headers`]: crate::types::Request::pending_response_headers

use async_trait::async_trait;
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

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

    /// Parse the `security_headers` handler object from Caddy JSON.
    ///
    /// The accepted keys are documented at the module level. Defaulted keys keep their secure
    /// default when absent; opt-in keys stay unset. A string is the emitted value and `false` (or
    /// the string `"false"`) suppresses the header. Unknown keys are rejected with a located error
    /// naming `<path>.<key>`, including inside `strict_transport_security`.
    ///
    /// The result is validated through [`SecurityHeaders::new`] so an invalid configuration (such
    /// as a `max_age` below [`HSTS_MIN_MAX_AGE`]) is rejected at load time with the JSON path of the
    /// offending field, not at the first request.
    pub fn from_json(value: &Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "security_headers must be an object"))?;
        let mut config = Self::default();
        for (field, value) in object {
            let field_path = format!("{path}.{field}");
            match field.as_str() {
                // The handler discriminator is consumed by the router.
                "handler" => {}
                "frame_options" => {
                    config.x_frame_options = parse_optional_string(value, &field_path)?
                }
                "content_type_options" => {
                    config.x_content_type_options = parse_optional_string(value, &field_path)?
                }
                "referrer_policy" => {
                    config.referrer_policy = parse_optional_string(value, &field_path)?
                }
                "content_security_policy" => {
                    config.content_security_policy = parse_optional_string(value, &field_path)?
                }
                "permissions_policy" => {
                    config.permissions_policy = parse_optional_string(value, &field_path)?
                }
                "strict_transport_security" => {
                    config.strict_transport_security = parse_hsts(value, &field_path)?
                }
                other => {
                    return Err(invalid(
                        &field_path,
                        format!("unknown security header option `{other}`"),
                    ))
                }
            }
        }
        // Re-locate the constructor's relative error paths onto the JSON document.
        SecurityHeaders::new(config.clone()).map_err(|error| match error {
            Error::InvalidConfig {
                path: inner,
                message,
            } => invalid(&format!("{path}.{inner}"), message),
            other => other,
        })?;
        Ok(config)
    }
}

/// Parse a string-valued header option: a string sets it, `false`/`"false"` suppresses it.
fn parse_optional_string(value: &Value, path: &str) -> Result<Option<String>> {
    match value {
        Value::String(text) if text == "false" => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        Value::Bool(false) => Ok(None),
        Value::Bool(true) => Err(invalid(
            path,
            "expected a header value string or false; `true` does not name a value",
        )),
        other => Err(invalid(
            path,
            format!("expected a header value string or false, got {other}"),
        )),
    }
}

/// Parse the opt-in `strict_transport_security` object into an [`HstsConfig`].
fn parse_hsts(value: &Value, path: &str) -> Result<Option<HstsConfig>> {
    let object = match value {
        Value::Null | Value::Bool(false) => return Ok(None),
        Value::String(text) if text == "false" => return Ok(None),
        Value::Object(object) => object,
        other => {
            return Err(invalid(
                path,
                format!("strict_transport_security must be an object or false, got {other}"),
            ))
        }
    };
    let mut config = HstsConfig::default();
    let mut max_age_seen = false;
    for (field, value) in object {
        let field_path = format!("{path}.{field}");
        match field.as_str() {
            "max_age" => {
                config.max_age = value.as_u64().ok_or_else(|| {
                    invalid(&field_path, "max_age must be a non-negative integer")
                })?;
                max_age_seen = true;
            }
            "include_subdomains" => {
                config.include_subdomains = value
                    .as_bool()
                    .ok_or_else(|| invalid(&field_path, "include_subdomains must be a boolean"))?;
            }
            "preload" => {
                config.preload = value
                    .as_bool()
                    .ok_or_else(|| invalid(&field_path, "preload must be a boolean"))?;
            }
            other => {
                return Err(invalid(
                    &field_path,
                    format!("unknown strict_transport_security option `{other}`"),
                ))
            }
        }
    }
    if !max_age_seen {
        return Err(invalid(
            &format!("{path}.max_age"),
            "max_age is required when strict_transport_security is configured",
        ));
    }
    Ok(Some(config))
}

/// `security_headers`: stage security response headers with secure defaults.
///
/// Construct with [`SecurityHeaders::new`] (validates the configuration) and run it as a
/// [`Handler`] (which calls [`SecurityHeaders::stage`]), or call [`SecurityHeaders::apply`]
/// directly on an outgoing [`HeaderMap`] to fill in the headers it does not already carry.
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

    /// Stage the configured security headers on the request's pending response headers.
    ///
    /// Every configured value is expanded with Caddy's `Replacer.ReplaceKnown` semantics (unknown
    /// placeholders stay visible). Unlike [`SecurityHeaders::apply`], a configured header
    /// **replaces** the pending value: route and subroute handlers run in order, so the handler
    /// that runs later in the chain must win.
    ///
    /// Returns a located error when an expanded value is not a valid header value (for example a
    /// request variable containing control bytes). Configured values were validated at construction
    /// time, so only placeholder expansion can produce such a value.
    pub fn stage(&self, request: &mut Request) -> Result<()> {
        let config = &self.config;
        let mut staged: Vec<(HeaderName, HeaderValue)> = Vec::new();
        if let Some(value) = &config.x_frame_options {
            staged.push(expand(request, "x-frame-options", value)?);
        }
        if let Some(value) = &config.x_content_type_options {
            staged.push(expand(request, "x-content-type-options", value)?);
        }
        if let Some(value) = &config.referrer_policy {
            staged.push(expand(request, "referrer-policy", value)?);
        }
        if let Some(value) = &config.content_security_policy {
            staged.push(expand(request, "content-security-policy", value)?);
        }
        if let Some(hsts) = &config.strict_transport_security {
            staged.push(expand(
                request,
                "strict-transport-security",
                &hsts.header_value(),
            )?);
        }
        if let Some(value) = &config.permissions_policy {
            staged.push(expand(request, "permissions-policy", value)?);
        }
        for (name, value) in staged {
            request.pending_response_headers.insert(name, value);
        }
        Ok(())
    }
}

/// Expand `{...}` placeholders in `value` (ReplaceKnown) and parse the result for `name`.
fn expand(request: &Request, name: &'static str, value: &str) -> Result<(HeaderName, HeaderValue)> {
    let expanded = request.replace_known(value);
    let value = HeaderValue::from_str(&expanded).map_err(|error| {
        invalid(
            name,
            format!("expanded value `{expanded}` is not a valid header value: {error}"),
        )
    })?;
    Ok((HeaderName::from_static(name), value))
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
        self.stage(&mut request)?;
        Ok(Outcome::Continue(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Method, Uri};
    use serde_json::json;

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

    #[test]
    fn from_json_applies_secure_defaults_and_overrides() {
        let config =
            SecurityHeadersConfig::from_json(&json!({"handler": "security_headers"}), "handle[0]")
                .unwrap();
        assert_eq!(config, SecurityHeadersConfig::default());

        let config = SecurityHeadersConfig::from_json(
            &json!({
                "handler": "security_headers",
                "frame_options": "SAMEORIGIN",
                "referrer_policy": "no-referrer",
                "content_security_policy": "default-src 'self'",
                "permissions_policy": "camera=()",
                "strict_transport_security": {
                    "max_age": 31_536_000,
                    "include_subdomains": true,
                    "preload": true
                }
            }),
            "handle[1]",
        )
        .unwrap();
        assert_eq!(config.x_frame_options.as_deref(), Some("SAMEORIGIN"));
        assert_eq!(config.referrer_policy.as_deref(), Some("no-referrer"));
        assert_eq!(
            config.content_security_policy.as_deref(),
            Some("default-src 'self'")
        );
        assert_eq!(config.permissions_policy.as_deref(), Some("camera=()"));
        assert_eq!(
            config.strict_transport_security,
            Some(HstsConfig {
                max_age: 31_536_000,
                include_subdomains: true,
                preload: true,
            })
        );
    }

    #[test]
    fn from_json_false_suppresses_defaulted_and_opt_in_headers() {
        let config = SecurityHeadersConfig::from_json(
            &json!({
                "frame_options": false,
                "referrer_policy": "false",
                "strict_transport_security": false
            }),
            "handle[0]",
        )
        .unwrap();
        assert_eq!(config.x_frame_options, None);
        assert_eq!(config.referrer_policy, None);
        assert_eq!(config.strict_transport_security, None);
        // `content_type_options` was not mentioned: the secure default stands.
        assert_eq!(
            config.x_content_type_options.as_deref(),
            Some(DEFAULT_X_CONTENT_TYPE_OPTIONS)
        );
    }

    #[test]
    fn from_json_rejects_unknown_keys_with_located_paths() {
        let error = SecurityHeadersConfig::from_json(
            &json!({"x_frame_options": "DENY"}),
            "apps.http.servers.srv0.routes[0].handle[0]",
        )
        .unwrap_err();
        match error {
            Error::InvalidConfig { path, message } => {
                assert_eq!(
                    path,
                    "apps.http.servers.srv0.routes[0].handle[0].x_frame_options"
                );
                assert!(message.contains("unknown security header option"));
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }

        let error = SecurityHeadersConfig::from_json(
            &json!({"strict_transport_security": {"max_age": 31_536_000, "subdomains": true}}),
            "handle[0]",
        )
        .unwrap_err();
        match error {
            Error::InvalidConfig { path, message } => {
                assert_eq!(path, "handle[0].strict_transport_security.subdomains");
                assert!(message.contains("unknown strict_transport_security option"));
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn from_json_rejects_invalid_hsts_with_located_path() {
        for (value, expected_path) in [
            (
                json!({"strict_transport_security": {"max_age": 86_400, "include_subdomains": true}}),
                "route.handlers[1].strict_transport_security.max_age",
            ),
            (
                json!({"strict_transport_security": {"max_age": 31_536_000, "preload": true}}),
                "route.handlers[1].strict_transport_security.preload",
            ),
            (
                json!({"strict_transport_security": {}}),
                "route.handlers[1].strict_transport_security.max_age",
            ),
        ] {
            let error = SecurityHeadersConfig::from_json(&value, "route.handlers[1]").unwrap_err();
            match error {
                Error::InvalidConfig { path, .. } => assert_eq!(path, expected_path),
                other => panic!("expected InvalidConfig, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn stage_overrides_staged_values_and_expands_placeholders() {
        let middleware = SecurityHeaders::new(SecurityHeadersConfig {
            content_security_policy: Some(
                "default-src {http.request.host}; report-uri {unknown.placeholder}".to_string(),
            ),
            referrer_policy: Some("origin-{http.request.host}".to_string()),
            ..SecurityHeadersConfig::default()
        })
        .unwrap();
        let mut request = request();
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        request
            .pending_response_headers
            .insert("x-frame-options", "SAMEORIGIN".parse().unwrap());

        middleware.stage(&mut request).unwrap();

        assert_eq!(
            header_value(&request.pending_response_headers, "content-security-policy").as_deref(),
            Some("default-src example.com; report-uri {unknown.placeholder}")
        );
        assert_eq!(
            header_value(&request.pending_response_headers, "referrer-policy").as_deref(),
            Some("origin-example.com")
        );
        // A configured default replaces the value an earlier handler staged.
        assert_eq!(
            header_value(&request.pending_response_headers, "x-frame-options").as_deref(),
            Some("DENY")
        );
    }
}
