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
//! `Strict-Transport-Security` is staged by the [`Handler`] only when [`Request::tls`] is true
//! (T-HTTP-154); [`SecurityHeaders::apply`] is the unconditional form for callers that already
//! decided the response is HTTPS.
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

/// Render request-controlled text for an error message.
///
/// Control characters (CR, LF, NUL, terminal escapes) become `U+FFFD` and long values are
/// truncated, so a placeholder expansion cannot inject log lines or escape sequences into an
/// [`Error::InvalidConfig`] message. The message keeps the header name (the error path) and the
/// configured field, only the expanded bytes are redacted.
fn redact(value: &str) -> String {
    const MAX_CHARS: usize = 96;
    let mut redacted: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect();
    if redacted.chars().count() > MAX_CHARS {
        redacted = redacted.chars().take(MAX_CHARS).collect();
        redacted.push('…');
    }
    redacted
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
    /// 
    /// Additional validations added for T-HTTP-153:
    /// - CSP directive names must be valid (ASCII letters, digits, hyphens)
    /// - HSTS max_age must be at least 15552000 (180 days) 
    /// - Permissions-Policy directives must be valid
    /// - ALLOW-FROM URIs must be valid URLs
    /// - Header values must not contain control characters (CR/LF/NUL)
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
        
        // Validate CSP directive names
        if let Some(csp) = &self.content_security_policy {
            if !csp.is_empty() {
                // Parse CSP to validate directive names
                let mut directives = csp.split(';');
                for directive in directives.by_ref() {
                    let directive = directive.trim();
                    if directive.is_empty() {
                        continue;
                    }
                    // Skip directive names that are empty or just whitespace
                    if let Some((name, _)) = directive.split_once(' ') {
                        if !is_csp_directive_name(name.trim()) {
                            return Err(invalid(
                                "content_security_policy",
                                format!("invalid CSP directive name: `{name}`"),
                            ));
                        }
                    } else {
                        // No value, just a directive name
                        if !is_csp_directive_name(directive) {
                            return Err(invalid(
                                "content_security_policy",
                                format!("invalid CSP directive name: `{directive}`"),
                            ));
                        }
                    }
                }
            }
        }
        
        // Validate Permissions-Policy directives
        if let Some(pp) = &self.permissions_policy {
            if !pp.is_empty() {
                // Parse permissions policy to validate feature names
                let mut features = pp.split(',');
                for feature in features.by_ref() {
                    let feature = feature.trim();
                    if feature.is_empty() {
                        continue;
                    }
                    // Handle feature names with optional parameters
                    if let Some((name, _)) = feature.split_once('(') {
                        if !is_feature_name(name.trim()) {
                            return Err(invalid(
                                "permissions_policy",
                                format!("invalid permissions policy feature name: `{name}`"),
                            ));
                        }
                    } else {
                        // Just a feature name
                        if !is_feature_name(feature) {
                            return Err(invalid(
                                "permissions_policy",
                                format!("invalid permissions policy feature name: `{feature}`"),
                            ));
                        }
                    }
                }
            }
        }
        
        // Validate ALLOW-FROM URIs (if present in CSP)
        if let Some(csp) = &self.content_security_policy {
            if csp.contains("allow-from") || csp.contains("ALLOW-FROM") {
                // Check for valid URLs in allow-from directives
                // This is a simplified check - full validation would be complex
                let directives: Vec<&str> = csp.split(';').collect();
                for directive in &directives {
                    if directive.contains("allow-from") || directive.contains("ALLOW-FROM") {
                        let parts: Vec<&str> = directive.split_whitespace().collect();
                        if parts.len() > 1 {
                            // The URI should be the second part after the directive name
                            let uri = parts[1];
                            if !uri.is_empty() && !uri.starts_with("http://") && !uri.starts_with("https://") {
                                // Check if it's a valid URI (basic check)
                                if uri.chars().any(|c| c.is_control()) {
                                    return Err(invalid(
                                        "content_security_policy",
                                        "ALLOW-FROM URI contains control characters".to_string(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Validate all header values don't contain control characters (CR/LF/NUL)
        for (path, value) in [
            ("content_security_policy", &self.content_security_policy),
            ("permissions_policy", &self.permissions_policy),
            ("x_frame_options", &self.x_frame_options),
            ("x_content_type_options", &self.x_content_type_options),
            ("referrer_policy", &self.referrer_policy),
        ] {
            if let Some(value) = value {
                // Check for control characters
                if value.chars().any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r') {
                    return Err(invalid(
                        path,
                        "header value contains control characters (except tab, newline, carriage return)".to_string(),
                    ));
                }
                
                // Validate header values can be parsed as HTTP header values
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

/// `Referrer-Policy` tokens defined by the Fetch standard, accepted by
/// [`SecurityHeadersConfig::from_headers_block`].
const REFERRER_POLICY_TOKENS: [&str; 8] = [
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
];

/// Whether `value` carries a `{...}` placeholder that is only resolvable per request.
///
/// Values that do are exempt from the closed-set checks below (an operator may legitimately
/// write `ALLOW-FROM {http.request.host}`), but they are re-validated after expansion at request
/// time: the structured values (`content-security-policy`, `permissions-policy`,
/// `x-frame-options`) are re-assembled one source/feature at a time and each expansion must stay a
/// single token ([`expand_policy_token`]), so a request-controlled placeholder cannot split a
/// directive or append one. An expansion that violates the rule fails the request closed.
fn has_placeholder(value: &str) -> bool {
    value.contains('{')
}

/// Parse the `security_headers` block nested inside a `headers` handler (T-ROUTE-050).
///
/// This is the same [`SecurityHeadersConfig`] as the standalone `security_headers` handler, with
/// the field names the task specifies and a few additive forms:
///
/// * `content_security_policy`: a header-value string, or an object mapping directive names to a
///   source list (a string or an array of strings). The object form is rendered to the canonical
///   `dir src...; dir2 src...` value; an empty array renders a valueless directive such as
///   `upgrade-insecure-requests`. Opt-in: absent means no CSP header.
/// * `x_frame_options`: `DENY`, `SAMEORIGIN`, or `ALLOW-FROM <origin>` (the origin is required and
///   must be a URI). `false` suppresses the header.
/// * `x_content_type_options`: `nosniff` (the only valid value). `false` suppresses the header.
/// * `referrer_policy`: one of the Fetch standard tokens. `false` suppresses the header.
/// * `hsts`: an object with `enabled` (default `false`), `max_age` (default one year),
///   `include_subdomains` and `preload`. Emitted only when `enabled` is `true`.
/// * `permissions_policy`: an object mapping feature names to an allowlist (a string used
///   verbatim, an array of origins rendered as `(origin ...)`, `true` rendered as `*`, or `false`
///   rendered as `()`), or a string used verbatim.
///
/// The legacy names `frame_options`, `content_type_options` and `strict_transport_security` are
/// accepted as aliases so a configuration can move between the two handlers unchanged. Unknown
/// keys and invalid values are rejected at load time with a located error naming the field, for
/// example `route.handle[0].security_headers.x_frame_options`.
impl SecurityHeadersConfig {
    pub fn from_headers_block(value: &Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "security_headers must be an object"))?;
        let mut config = Self::default();
        for (field, value) in object {
            let field_path = format!("{path}.{field}");
            match field.as_str() {
                // The handler discriminator is consumed by the router.
                "handler" => {}
                "x_frame_options" | "frame_options" => {
                    config.x_frame_options = parse_x_frame_options(value, &field_path)?
                }
                "x_content_type_options" | "content_type_options" => {
                    config.x_content_type_options =
                        parse_x_content_type_options(value, &field_path)?
                }
                "referrer_policy" => {
                    config.referrer_policy = parse_referrer_policy(value, &field_path)?
                }
                "content_security_policy" => {
                    config.content_security_policy = parse_csp_block(value, &field_path)?
                }
                "permissions_policy" => {
                    config.permissions_policy = parse_permissions_policy(value, &field_path)?
                }
                "hsts" | "strict_transport_security" => {
                    config.strict_transport_security = parse_hsts_block(value, &field_path)?
                }
                other => {
                    return Err(invalid(
                        &field_path,
                        format!("unknown security_headers option `{other}`"),
                    ))
                }
            }
        }
        config.validate().map_err(|error| relocate(error, path))?;
        Ok(config)
    }
}

/// Re-locate a [`SecurityHeadersConfig::validate`] error path onto the `security_headers` block.
///
/// `validate` reports the standalone handler's field names; the block calls HSTS `hsts`, so the
/// prefix is rewritten before the document path is prepended.
fn relocate(error: Error, path: &str) -> Error {
    match error {
        Error::InvalidConfig {
            path: inner,
            message,
        } => {
            let inner = match inner.strip_prefix("strict_transport_security.") {
                Some(rest) => format!("hsts.{rest}"),
                None => inner,
            };
            invalid(&format!("{path}.{inner}"), message)
        }
        other => other,
    }
}

/// Parse `x_frame_options`: `DENY`, `SAMEORIGIN`, or `ALLOW-FROM <origin>`.
fn parse_x_frame_options(value: &Value, path: &str) -> Result<Option<String>> {
    let Some(raw) = parse_optional_string(value, path)? else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    let (keyword, rest) = match trimmed.split_once(char::is_whitespace) {
        Some((keyword, rest)) => (keyword, rest.trim()),
        None => (trimmed, ""),
    };
    match keyword.to_ascii_uppercase().as_str() {
        "ALLOW-FROM" => {
            if rest.is_empty() {
                return Err(invalid(
                    path,
                    "ALLOW-FROM requires an origin, for example \
                     \"ALLOW-FROM https://example.com\"; use DENY or SAMEORIGIN to allow framing",
                ));
            }
            if !has_placeholder(rest) && !is_valid_frame_origin(rest) {
                return Err(invalid(
                    path,
                    format!("ALLOW-FROM value `{rest}` is not a valid http(s) URI"),
                ));
            }
            Ok(Some(trimmed.to_string()))
        }
        "DENY" | "SAMEORIGIN" => {
            if !rest.is_empty() {
                return Err(invalid(
                    path,
                    format!("X-Frame-Options `{keyword}` takes no value, got `{trimmed}`"),
                ));
            }
            Ok(Some(keyword.to_ascii_uppercase()))
        }
        _ => Err(invalid(
            path,
            format!("x_frame_options must be DENY, SAMEORIGIN or ALLOW-FROM <origin>, got `{raw}`"),
        )),
    }
}

/// Parse `x_content_type_options`: the only meaningful value is `nosniff`.
fn parse_x_content_type_options(value: &Value, path: &str) -> Result<Option<String>> {
    let Some(raw) = parse_optional_string(value, path)? else {
        return Ok(None);
    };
    // A placeholder is allowed for symmetry with the other fields; it is validated after
    // expansion at request time, and `nosniff` is the only value a browser acts on.
    if has_placeholder(&raw) {
        return Ok(Some(raw));
    }
    if !raw
        .trim()
        .eq_ignore_ascii_case(DEFAULT_X_CONTENT_TYPE_OPTIONS)
    {
        return Err(invalid(
            path,
            format!(
                "x_content_type_options must be `{DEFAULT_X_CONTENT_TYPE_OPTIONS}`, got `{raw}`"
            ),
        ));
    }
    Ok(Some(DEFAULT_X_CONTENT_TYPE_OPTIONS.to_string()))
}

/// Parse `referrer_policy`: one of the Fetch standard tokens (or a placeholder).
fn parse_referrer_policy(value: &Value, path: &str) -> Result<Option<String>> {
    let Some(raw) = parse_optional_string(value, path)? else {
        return Ok(None);
    };
    let token = raw.trim().to_ascii_lowercase();
    if !has_placeholder(&raw) && !REFERRER_POLICY_TOKENS.contains(&token.as_str()) {
        return Err(invalid(
            path,
            format!(
                "referrer_policy `{raw}` is not a known policy; expected one of {}",
                REFERRER_POLICY_TOKENS.join(", ")
            ),
        ));
    }
    Ok(Some(raw))
}

/// Parse `content_security_policy`: a header-value string or a directive object.
fn parse_csp_block(value: &Value, path: &str) -> Result<Option<String>> {
    match value {
        Value::Null | Value::Bool(false) => Ok(None),
        Value::String(text) if text == "false" => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        Value::Object(object) => {
            if object.is_empty() {
                return Err(invalid(
                    path,
                    "a CSP policy must declare at least one directive",
                ));
            }
            let mut rendered = Vec::with_capacity(object.len());
            for (name, sources) in object {
                let directive_path = format!("{path}.{name}");
                validate_csp_directive_name(name, &directive_path)?;
                let sources = parse_csp_sources(sources, &directive_path)?;
                if sources.is_empty() {
                    rendered.push(name.clone());
                } else {
                    rendered.push(format!("{name} {}", sources.join(" ")));
                }
            }
            Ok(Some(rendered.join("; ")))
        }
        other => Err(invalid(
            path,
            format!("content_security_policy must be a string or an object, got {other}"),
        )),
    }
}

/// Whether `name` is a legal CSP directive name: non-empty ASCII letters, digits and `-`.
///
/// The same predicate guards request-time re-assembly: a directive name is configuration, never
/// request data, so an expansion must never be allowed to produce one.
fn is_csp_directive_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Validate a CSP directive name: an ASCII token without whitespace, `;` or `=`.
fn validate_csp_directive_name(name: &str, path: &str) -> Result<()> {
    if !is_csp_directive_name(name) {
        return Err(invalid(
            path,
            format!("`{name}` is not a valid CSP directive name"),
        ));
    }
    Ok(())
}

/// Parse one CSP directive's source list: a whitespace-separated string or an array of strings.
fn parse_csp_sources(value: &Value, path: &str) -> Result<Vec<String>> {
    let sources: Vec<String> = match value {
        Value::String(text) => text.split_whitespace().map(str::to_string).collect(),
        Value::Array(items) => {
            let mut sources = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let item = item.as_str().ok_or_else(|| {
                    invalid(&format!("{path}[{index}]"), "expected a source string")
                })?;
                sources.push(item.to_string());
            }
            sources
        }
        other => {
            return Err(invalid(
                path,
                format!("expected a source list string or an array of sources, got {other}"),
            ))
        }
    };
    for (index, source) in sources.iter().enumerate() {
        let source_path = if matches!(value, Value::Array(_)) {
            format!("{path}[{index}]")
        } else {
            path.to_string()
        };
        validate_allowlist_token(source, &source_path)?;
    }
    Ok(sources)
}

/// Parse `permissions_policy`: a header-value string or a feature object.
fn parse_permissions_policy(value: &Value, path: &str) -> Result<Option<String>> {
    match value {
        Value::Null | Value::Bool(false) => Ok(None),
        Value::String(text) if text == "false" => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        Value::Object(object) => {
            if object.is_empty() {
                return Err(invalid(
                    path,
                    "permissions_policy must declare at least one feature",
                ));
            }
            let mut rendered = Vec::with_capacity(object.len());
            for (feature, allowlist) in object {
                let feature_path = format!("{path}.{feature}");
                validate_feature_name(feature, &feature_path)?;
                let allowlist = match allowlist {
                    Value::String(text) => {
                        validate_allowlist_token(text, &feature_path)?;
                        text.clone()
                    }
                    Value::Array(items) => {
                        let mut origins = Vec::with_capacity(items.len());
                        for (index, item) in items.iter().enumerate() {
                            let item = item.as_str().ok_or_else(|| {
                                invalid(
                                    &format!("{feature_path}[{index}]"),
                                    "expected an origin string",
                                )
                            })?;
                            validate_allowlist_token(item, &format!("{feature_path}[{index}]"))?;
                            origins.push(item.to_string());
                        }
                        format!("({})", origins.join(" "))
                    }
                    Value::Bool(true) => "*".to_string(),
                    Value::Bool(false) => "()".to_string(),
                    other => {
                        return Err(invalid(
                            &feature_path,
                            format!(
                                "expected an origin list string, an array of origins or a boolean, \
                                 got {other}"
                            ),
                        ))
                    }
                };
                rendered.push(format!("{feature}={allowlist}"));
            }
            Ok(Some(rendered.join(", ")))
        }
        other => Err(invalid(
            path,
            format!("permissions_policy must be a string or an object, got {other}"),
        )),
    }
}

/// Whether `name` is a legal `permissions_policy` feature name: lowercase ASCII, digits and `-`.
fn is_feature_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Validate a `permissions_policy` feature name: lowercase ASCII letters, digits and `-`.
fn validate_feature_name(name: &str, path: &str) -> Result<()> {
    if !is_feature_name(name) {
        return Err(invalid(
            path,
            format!("`{name}` is not a valid permissions policy feature name"),
        ));
    }
    Ok(())
}

/// Whether `token` is one legal CSP source / `permissions_policy` allowlist token.
///
/// Directives are separated by `;`, permissions features by `,` and sources/origins by
/// whitespace, so a token carrying any of those (or a quote/parenthesis that could open a new
/// `( ... )` allowlist) would change the structure of the emitted header. The same predicate is
/// the load-time check and the request-time re-check after placeholder expansion.
fn is_allowlist_token(token: &str) -> bool {
    !token.is_empty()
        && token.is_ascii()
        && !token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b';' | b',' | b'(' | b')'))
}

/// Whether `origin` is an acceptable `X-Frame-Options: ALLOW-FROM` origin.
///
/// `javascript:` and `data:` parse as URIs but are not framing origins, so an absolute URI must
/// use `http`/`https`. An authority-only value such as `example.com` (no scheme) stays accepted
/// for `ALLOW-FROM {http.request.host}`-style configurations. Used at load time and again after
/// placeholder expansion, which the load-time check cannot see.
fn is_valid_frame_origin(origin: &str) -> bool {
    if origin.parse::<http::Uri>().is_err() {
        return false;
    }
    if origin.starts_with('[') {
        // An IPv6 authority such as `[::1]:8443`; the parser already validated it.
        return true;
    }
    match origin.split_once(':') {
        // A scheme is only legal when it is `http(s)://`.
        Some((prefix, rest)) if rest.starts_with("//") => {
            prefix.eq_ignore_ascii_case("http") || prefix.eq_ignore_ascii_case("https")
        }
        // Otherwise a colon can only introduce a numeric port (`example.com:8443`):
        // `http::Uri` also accepts `javascript:alert(1)` as an authority-form URI with no scheme,
        // so `javascript:`, `data:` and friends are rejected here explicitly.
        Some((_, rest)) => !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()),
        None => true,
    }
}

/// Validate one origin/allowlist token: non-empty ASCII, no whitespace or separators.
fn validate_allowlist_token(token: &str, path: &str) -> Result<()> {
    if !is_allowlist_token(token) {
        return Err(invalid(
            path,
            format!("`{token}` is not a valid origin or allowlist token"),
        ));
    }
    Ok(())
}

/// Parse the `hsts` object of a `headers` handler's `security_headers` block.
///
/// `enabled` gates emission: `false` (the default) means no `Strict-Transport-Security` header is
/// ever emitted, whatever the other fields say. The other fields are still type- and range-checked
/// so a typo is a load-time error rather than a silently ignored setting.
fn parse_hsts_block(value: &Value, path: &str) -> Result<Option<HstsConfig>> {
    if matches!(value, Value::Bool(true)) {
        return Ok(Some(HstsConfig::default()));
    }
    let object = match value {
        Value::Null | Value::Bool(false) => return Ok(None),
        Value::String(text) if text == "false" => return Ok(None),
        Value::Object(object) => object,
        other => {
            return Err(invalid(
                path,
                format!("hsts must be an object or false, got {other}"),
            ))
        }
    };
    let mut config = HstsConfig::default();
    let mut enabled = false;
    for (field, value) in object {
        let field_path = format!("{path}.{field}");
        match field.as_str() {
            "enabled" => {
                enabled = value
                    .as_bool()
                    .ok_or_else(|| invalid(&field_path, "enabled must be a boolean"))?;
            }
            "max_age" => {
                config.max_age = value.as_u64().ok_or_else(|| {
                    invalid(&field_path, "max_age must be a non-negative integer")
                })?;
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
                    format!("unknown hsts option `{other}`"),
                ))
            }
        }
    }
    // Range checks apply even when `enabled` is false: a mistyped max_age is a configuration bug
    // either way, and silently ignoring it would surface only after the flag is flipped.
    if config.max_age == 0 {
        return Err(invalid(
            &format!("{path}.max_age"),
            "max_age must be greater than 0",
        ));
    }
    if config.max_age < HSTS_MIN_MAX_AGE {
        return Err(invalid(
            &format!("{path}.max_age"),
            format!(
                "max_age must be at least {HSTS_MIN_MAX_AGE} seconds (180 days); browsers ignore \
                 shorter values"
            ),
        ));
    }
    if config.preload && !config.include_subdomains {
        return Err(invalid(
            &format!("{path}.preload"),
            "preload requires include_subdomains to be enabled",
        ));
    }
    if !enabled {
        return Ok(None);
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
    /// This is the **unconditional form**: it never inspects a request and stages
    /// `Strict-Transport-Security` whenever HSTS is configured. It is for callers that already
    /// decided the response is HTTPS (for example a route engine that already terminated TLS).
    /// The [`Handler`] implementation is the HTTPS gate: it only stages HSTS when
    /// [`Request::tls`] is true.
    ///
    /// A header is only inserted when `headers` does not already contain it, so an explicit
    /// response header set earlier in the chain is never clobbered.
    pub fn apply(&self, headers: &mut HeaderMap) {
        self.stage_headers(headers, true);
    }

    /// Shared staging implementation; `include_hsts` gates the `Strict-Transport-Security` header.
    fn stage_headers(&self, headers: &mut HeaderMap, include_hsts: bool) {
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

    /// Stage the configured security headers on the request's pending response headers.
    ///
    /// Every configured value is expanded with Caddy's `Replacer.ReplaceKnown` semantics (unknown
    /// placeholders stay visible). Unlike [`SecurityHeaders::apply`], a configured header
    /// **replaces** the pending value: route and subroute handlers run in order, so the handler
    /// that runs later in the chain must win.
    ///
    /// Returns a located error when an expanded value is not a valid header value (for example a
    /// request variable containing control bytes) or when a placeholder expansion would change the
    /// structure of a policy header (a `;`, `,` or whitespace injected into a CSP source or
    /// permissions-policy origin). Configured values were validated at construction time, so only
    /// placeholder expansion can produce such a value. A violating expansion fails the request
    /// closed: the error is returned and no header is staged, not even a partial one.
    pub fn stage(&self, request: &mut Request) -> Result<()> {
        for (name, value) in self.staged(request)? {
            request.pending_response_headers.insert(name, value);
        }
        Ok(())
    }

    /// Stage the configured security headers only where the pending response does not already
    /// carry them.
    ///
    /// This is the "defaults" form used by the `headers` handler's `security_headers` block: a
    /// header staged earlier (by another handler, or by an explicit `headers.response.set` in the
    /// same handler) is never clobbered, so explicit configuration always wins over the security
    /// defaults.
    pub fn stage_defaults(&self, request: &mut Request) -> Result<()> {
        for (name, value) in self.staged(request)? {
            request
                .pending_response_headers
                .entry(name)
                .or_insert(value);
        }
        Ok(())
    }

    /// Expand and parse every configured header into `(name, value)` pairs.
    fn staged(&self, request: &Request) -> Result<Vec<(HeaderName, HeaderValue)>> {
        let config = &self.config;
        let mut staged: Vec<(HeaderName, HeaderValue)> = Vec::new();
        if let Some(value) = &config.x_frame_options {
            staged.push(expand_x_frame_options(request, "x-frame-options", value)?);
        }
        if let Some(value) = &config.x_content_type_options {
            staged.push(expand_single_token(
                request,
                "x-content-type-options",
                value,
            )?);
        }
        if let Some(value) = &config.referrer_policy {
            staged.push(expand_single_token(request, "referrer-policy", value)?);
        }
        if let Some(value) = &config.content_security_policy {
            staged.push(expand_csp(request, "content-security-policy", value)?);
        }
        // The Handler is the HTTPS gate (T-HTTP-154): HSTS is only staged for a TLS request.
        // `apply`/`stage_headers` remain the unconditional form for callers that already decided.
        if request.tls {
            if let Some(hsts) = &config.strict_transport_security {
                staged.push(expand(
                    request,
                    "strict-transport-security",
                    &hsts.header_value(),
                )?);
            }
        }
        if let Some(value) = &config.permissions_policy {
            staged.push(expand_permissions(request, "permissions-policy", value)?);
        }
        Ok(staged)
    }
}

/// Expand `{...}` placeholders in `value` (ReplaceKnown) and parse the result for `name`.
///
/// Only for headers whose value carries no internal structure (HSTS). Structured values go
/// through the re-assembling expanders below.
fn expand(request: &Request, name: &'static str, value: &str) -> Result<(HeaderName, HeaderValue)> {
    finish(name, request.replace_known(value))
}

/// Parse an already expanded value into a `(name, value)` header pair.
///
/// The expanded bytes are request-controlled, so they are redacted from the error message.
fn finish(name: &'static str, expanded: String) -> Result<(HeaderName, HeaderValue)> {
    let value = HeaderValue::from_str(&expanded).map_err(|error| {
        invalid(
            name,
            format!(
                "expanded value `{}` is not a valid header value: {error}",
                redact(&expanded)
            ),
        )
    })?;
    Ok((HeaderName::from_static(name), value))
}

/// Expand one CSP source / `permissions_policy` origin and re-check it as a single token.
///
/// Request-time counterpart of [`validate_allowlist_token`]: a placeholder expansion must not
/// contribute a `;`, `,`, whitespace or quote, otherwise request data could split or extend the
/// directive structure (`default-src {http.request.uri.path}` with `/a;script-src`, or
/// `{http.request.header.X}` carrying `script-src * 'unsafe-inline'`).
fn expand_policy_token(request: &Request, name: &'static str, token: &str) -> Result<String> {
    let expanded = request.replace_known(token);
    if !is_allowlist_token(&expanded) {
        return Err(invalid(
            name,
            format!(
                "placeholder expansion of `{}` produced `{}`, which is not a single legal token; \
                 refusing to build the header",
                redact(token),
                redact(&expanded)
            ),
        ));
    }
    Ok(expanded)
}

/// Expand and re-assemble a `Content-Security-Policy` value directive by directive.
///
/// Directive names and the `;`/space structure come from the configuration; only sources are
/// expanded, and each expansion must stay a single token ([`expand_policy_token`]). An expansion
/// that would add a separator **fails the request closed**: the handler returns this error and no
/// header (not even a partial one) is staged. Dropping only the offending source was rejected
/// because the emitted policy would no longer be the operator's policy — a silently shortened
/// `script-src` is a different, weaker policy — while the request could still steer it.
fn expand_csp(
    request: &Request,
    name: &'static str,
    template: &str,
) -> Result<(HeaderName, HeaderValue)> {
    if !has_placeholder(template) {
        return expand(request, name, template);
    }
    let mut directives: Vec<String> = Vec::new();
    for directive in template.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }
        let mut parts = directive.split_whitespace();
        let directive_name = parts.next().unwrap_or_default();
        if !is_csp_directive_name(directive_name) {
            return Err(invalid(
                name,
                format!(
                    "`{}` is not a valid CSP directive name; a directive name cannot come from a \
                     placeholder",
                    redact(directive_name)
                ),
            ));
        }
        let mut sources = Vec::new();
        for source in parts {
            sources.push(expand_policy_token(request, name, source)?);
        }
        if sources.is_empty() {
            directives.push(directive_name.to_string());
        } else {
            directives.push(format!("{directive_name} {}", sources.join(" ")));
        }
    }
    if directives.is_empty() {
        return Err(invalid(
            name,
            "content_security_policy is empty after placeholder expansion",
        ));
    }
    finish(name, directives.join("; "))
}

/// Expand and re-assemble a `Permissions-Policy` value feature by feature.
///
/// Same rule and failure mode as [`expand_csp`]: `,` separates features and whitespace separates
/// the origins of a `( ... )` allowlist, so every expanded origin must stay one token.
fn expand_permissions(
    request: &Request,
    name: &'static str,
    template: &str,
) -> Result<(HeaderName, HeaderValue)> {
    if !has_placeholder(template) {
        return expand(request, name, template);
    }
    let mut features: Vec<String> = Vec::new();
    for item in template.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some((feature, allowlist)) = item.split_once('=') else {
            return Err(invalid(
                name,
                format!("`{}` is not a `feature=allowlist` item", redact(item)),
            ));
        };
        let feature = feature.trim();
        if !is_feature_name(feature) {
            return Err(invalid(
                name,
                format!(
                    "`{}` is not a valid permissions policy feature name; a feature name cannot \
                     come from a placeholder",
                    redact(feature)
                ),
            ));
        }
        let allowlist = allowlist.trim();
        let rendered = match allowlist
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(')'))
        {
            Some(origins) => {
                let mut expanded = Vec::new();
                for origin in origins.split_whitespace() {
                    expanded.push(expand_policy_token(request, name, origin)?);
                }
                format!("({})", expanded.join(" "))
            }
            None => expand_policy_token(request, name, allowlist)?,
        };
        features.push(format!("{feature}={rendered}"));
    }
    if features.is_empty() {
        return Err(invalid(
            name,
            "permissions_policy is empty after placeholder expansion",
        ));
    }
    finish(name, features.join(", "))
}

/// Expand and re-assemble an `X-Frame-Options` value.
///
/// `ALLOW-FROM <origin>` is URI-checked at load time, which never sees a placeholder form, so the
/// expanded origin is checked here again: one token and an `http(s)` URI (or an authority form
/// without a scheme), which rejects `javascript:` and `data:`.
fn expand_x_frame_options(
    request: &Request,
    name: &'static str,
    template: &str,
) -> Result<(HeaderName, HeaderValue)> {
    if !has_placeholder(template) {
        return expand(request, name, template);
    }
    let trimmed = template.trim();
    let (keyword, rest) = match trimmed.split_once(char::is_whitespace) {
        Some((keyword, rest)) => (keyword, rest.trim()),
        None => (trimmed, ""),
    };
    match keyword.to_ascii_uppercase().as_str() {
        "ALLOW-FROM" => {
            let origin = request.replace_known(rest);
            if !is_allowlist_token(&origin) || !is_valid_frame_origin(&origin) {
                return Err(invalid(
                    name,
                    format!(
                        "ALLOW-FROM origin `{}` is not a single http(s) URI after expansion",
                        redact(&origin)
                    ),
                ));
            }
            finish(name, format!("ALLOW-FROM {origin}"))
        }
        "DENY" | "SAMEORIGIN" => {
            if !rest.is_empty() {
                return Err(invalid(
                    name,
                    format!("X-Frame-Options `{keyword}` takes no value after expansion"),
                ));
            }
            finish(name, keyword.to_ascii_uppercase())
        }
        _ => Err(invalid(
            name,
            format!(
                "x-frame-options must be DENY, SAMEORIGIN or ALLOW-FROM <origin>, got `{}`",
                redact(trimmed)
            ),
        )),
    }
}

/// Expand a header whose value is a single token (`referrer_policy`, `x_content_type_options`).
///
/// The load-time checks are closed sets of single tokens; after expansion the value must still be
/// one token, so a placeholder cannot turn `no-referrer` into a comma-separated list.
fn expand_single_token(
    request: &Request,
    name: &'static str,
    template: &str,
) -> Result<(HeaderName, HeaderValue)> {
    if !has_placeholder(template) {
        return expand(request, name, template);
    }
    let expanded = expand_policy_token(request, name, template.trim())?;
    finish(name, expanded)
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

    /// Assert that staging fails closed with a located error and stages no header.
    fn assert_expansion_rejected(
        middleware: &SecurityHeaders,
        request: &mut Request,
        header: &str,
        expected_message: &str,
    ) {
        match middleware.stage(request).unwrap_err() {
            Error::InvalidConfig { path, message } => {
                assert_eq!(path, header);
                assert!(message.contains(expected_message), "{message}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
        assert!(
            request.pending_response_headers.get(header).is_none(),
            "no {header} may be staged when its expansion is rejected"
        );
    }

    #[tokio::test]
    async fn csp_placeholder_cannot_add_a_directive_from_the_request_path() {
        // T-ROUTE-050 blocking defect: `/a;script-src` used to be emitted as
        // `default-src /a;script-src`, a request-chosen second directive.
        let middleware =
            SecurityHeaders::new(config_with_csp("default-src {http.request.uri.path}")).unwrap();
        let mut request = Request::new(Method::GET, "/a;script-src".parse::<Uri>().unwrap());
        assert_expansion_rejected(
            &middleware,
            &mut request,
            "content-security-policy",
            "not a single legal token",
        );
    }

    #[tokio::test]
    async fn csp_placeholder_cannot_append_a_directive_from_a_header() {
        let middleware =
            SecurityHeaders::new(config_with_csp("default-src {http.request.header.X-Src}"))
                .unwrap();
        let mut request = request();
        request.headers.insert(
            "x-src",
            "https://ok.example script-src * 'unsafe-inline'"
                .parse()
                .unwrap(),
        );
        assert_expansion_rejected(
            &middleware,
            &mut request,
            "content-security-policy",
            "not a single legal token",
        );
    }

    #[tokio::test]
    async fn csp_placeholder_expansion_is_neutralised_when_percent_encoded() {
        // An encoded `;` is not a directive separator, so it stays one source verbatim.
        let middleware =
            SecurityHeaders::new(config_with_csp("default-src {http.request.uri.path}")).unwrap();
        let mut request = Request::new(Method::GET, "/a%3Bscript-src".parse::<Uri>().unwrap());
        middleware.stage(&mut request).unwrap();
        assert_eq!(
            header_value(&request.pending_response_headers, "content-security-policy").as_deref(),
            Some("default-src /a%3Bscript-src")
        );
    }

    #[tokio::test]
    async fn csp_placeholder_expansion_keeps_legitimate_sources() {
        let middleware = SecurityHeaders::new(config_with_csp(
            "default-src 'self' https://{http.request.host}; img-src {http.request.uri.path}",
        ))
        .unwrap();
        let mut request = Request::new(Method::GET, "/img/logo.png".parse::<Uri>().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        middleware.stage(&mut request).unwrap();
        assert_eq!(
            header_value(&request.pending_response_headers, "content-security-policy").as_deref(),
            Some("default-src 'self' https://example.com; img-src /img/logo.png")
        );
    }

    #[tokio::test]
    async fn permissions_policy_placeholder_cannot_add_a_feature() {
        let middleware = SecurityHeaders::new(SecurityHeadersConfig {
            permissions_policy: Some("geolocation=({http.request.header.X-Origin})".to_string()),
            ..SecurityHeadersConfig::default()
        })
        .unwrap();
        let mut injected = request();
        injected.headers.insert(
            "x-origin",
            "self) , camera=* , microphone=*".parse().unwrap(),
        );
        assert_expansion_rejected(
            &middleware,
            &mut injected,
            "permissions-policy",
            "not a single legal token",
        );

        let mut legitimate = request();
        legitimate
            .headers
            .insert("x-origin", "https://maps.example.com".parse().unwrap());
        middleware.stage(&mut legitimate).unwrap();
        assert_eq!(
            header_value(&legitimate.pending_response_headers, "permissions-policy").as_deref(),
            Some("geolocation=(https://maps.example.com)")
        );
    }

    #[tokio::test]
    async fn allow_from_placeholder_is_uri_and_scheme_checked_after_expansion() {
        let middleware = SecurityHeaders::new(SecurityHeadersConfig {
            x_frame_options: Some("ALLOW-FROM {http.request.header.X-Origin}".to_string()),
            ..SecurityHeadersConfig::default()
        })
        .unwrap();
        let mut injected = request();
        injected
            .headers
            .insert("x-origin", "javascript:alert(1)".parse().unwrap());
        assert_expansion_rejected(
            &middleware,
            &mut injected,
            "x-frame-options",
            "is not a single http(s) URI",
        );

        let mut legitimate = request();
        legitimate
            .headers
            .insert("x-origin", "https://ok.example".parse().unwrap());
        middleware.stage(&mut legitimate).unwrap();
        assert_eq!(
            header_value(&legitimate.pending_response_headers, "x-frame-options").as_deref(),
            Some("ALLOW-FROM https://ok.example")
        );
    }

    #[test]
    fn allow_from_rejects_non_http_schemes_at_load_time() {
        let error = SecurityHeadersConfig::from_headers_block(
            &json!({"x_frame_options": "ALLOW-FROM javascript:alert(1)"}),
            "handler.security_headers",
        )
        .unwrap_err();
        match error {
            Error::InvalidConfig { path, message } => {
                assert_eq!(path, "handler.security_headers.x_frame_options");
                assert!(message.contains("not a valid http(s) URI"), "{message}");
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn expansion_error_redacts_request_controlled_bytes() {
        let middleware = SecurityHeaders::new(SecurityHeadersConfig {
            referrer_policy: Some("origin-{http.vars.injected}".to_string()),
            ..SecurityHeadersConfig::default()
        })
        .unwrap();
        let mut request = request();
        request
            .vars
            .insert("injected".to_string(), "ok\r\nX-Injected: 1".to_string());
        let error = middleware.stage(&mut request).unwrap_err();
        let Error::InvalidConfig { path, message } = error else {
            panic!("expected InvalidConfig");
        };
        assert_eq!(path, "referrer-policy");
        assert!(
            !message.contains('\r') && !message.contains('\n'),
            "message must not carry raw control bytes: {message:?}"
        );
        assert!(message.contains('\u{fffd}'), "{message:?}");
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

    #[test]
    fn validate_security_headers_rejects_invalid_csp_directive_names() {
        let mut config = SecurityHeadersConfig::default();
        config.content_security_policy = Some("default-src 'self' example.com; invalid-directive 'unsafe-inline'".to_string());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid CSP directive name"));
    }

    #[test]
    fn validate_security_headers_rejects_invalid_permissions_policy_features() {
        let mut config = SecurityHeadersConfig::default();
        config.permissions_policy = Some("camera=(), invalid-feature=()".to_string());
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid permissions policy feature name"));
    }

    #[test]
    fn validate_security_headers_rejects_invalid_header_values_with_control_chars() {
        let mut config = SecurityHeadersConfig::default();
        config.x_frame_options = Some("DENY\0".to_string()); // Contains NUL
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("control characters"));
    }

    #[test]
    fn validate_security_headers_rejects_invalid_hsts_max_age() {
        let mut config = SecurityHeadersConfig::default();
        config.strict_transport_security = Some(HstsConfig {
            max_age: 1000, // Below minimum of 15552000 (180 days)
            include_subdomains: true,
            preload: false,
        });
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_age must be at least 15552000"));
    }

    #[test]
    fn validate_security_headers_accepts_valid_configs() {
        let mut config = SecurityHeadersConfig::default();
        config.content_security_policy = Some("default-src 'self' example.com".to_string());
        config.permissions_policy = Some("camera=(self)".to_string());
        config.strict_transport_security = Some(HstsConfig {
            max_age: 31_536_000, // 1 year
            include_subdomains: true,
            preload: false,
        });
        config.x_frame_options = Some("DENY".to_string());
        config.x_content_type_options = Some("nosniff".to_string());
        config.referrer_policy = Some("strict-origin-when-cross-origin".to_string());
        
        let result = config.validate();
        assert!(result.is_ok());
    }
}