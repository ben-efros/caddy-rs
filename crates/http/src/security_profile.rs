//! The implicit reverse-proxy security profile (ADR-0010 §2, `DIV-0131`).
//!
//! caddy-rs is secure by default (`stock_compat` absent or `false`): every final response
//! produced by a `reverse_proxy` handler carries the five documented headers and has upstream
//! fingerprint headers removed. The exact header set and literals are normative in
//! [`docs/compatibility/STOCK-COMPAT.md`](https://github.com/ben-efros/caddy-rs-project) (the
//! `stock-compat` divergence table) and in ADR-0010 §2; changing a literal here without changing
//! the table is a plan violation.
//!
//! Semantics (ADR-0010 §2, lowest to highest precedence):
//!
//! 1. **Upstream value wins over the profile.** The five security headers are set only when the
//!    final response does not already carry them: the origin application owns its own policy and
//!    the proxy fills gaps rather than overriding it.
//! 2. **The profile wins over "nothing".** A bare `reverse_proxy` gets a browser-facing baseline
//!    without operator action.
//! 3. **An explicit `header` directive or `security_headers` handler wins.** Those handlers stage
//!    into `Request::pending_response_headers`, which the router merges onto the response after the
//!    handler returns, so an operator value overwrites the profile value.
//! 4. **An explicit `security_headers` handler in the same route chain as the `reverse_proxy`
//!    opts that route out of the implicit profile entirely** (`T-PROXY-060` decides this at route
//!    build time).
//!
//! `stock_compat true` makes the whole profile inert: headers pass through untouched (the proxy
//! handler then never calls the profile).
//!
//! `Content-Security-Policy` is deliberately never emitted by the profile (ADR-0010 §8): a default
//! policy encodes the application's asset graph and silently breaks apps whose upstream sets none,
//! and the proposed `frame-ancestors 'self'` would even loosen the profile's `X-Frame-Options:
//! DENY`. The only ways the header appears are an upstream value (precedence 1) or an explicit
//! operator `header` / `security_headers` configuration (precedence 3). The unit tests prove the
//! profile alone never sets it.

use http::HeaderMap;

/// The `Strict-Transport-Security` value the profile emits on TLS proxied responses.
///
/// `includeSubDomains` and `preload` are deliberately omitted: both are long-lived, externally
/// validated commitments the proxy cannot verify (STOCK-COMPAT.md `DIV-0131`).
pub const HSTS_VALUE: &str = "max-age=31536000";

/// The `X-Content-Type-Options` value the profile emits on every proxied response.
pub const X_CONTENT_TYPE_OPTIONS_VALUE: &str = "nosniff";

/// The `X-Frame-Options` value the profile emits on every proxied response.
pub const X_FRAME_OPTIONS_VALUE: &str = "DENY";

/// The `Referrer-Policy` value the profile emits on every proxied response.
pub const REFERRER_POLICY_VALUE: &str = "strict-origin-when-cross-origin";

/// The `Permissions-Policy` value the profile emits on every proxied response.
///
/// The list is deliberately small (features a reverse-proxied application rarely needs) and every
/// entry is overridable by an upstream or an explicit operator value.
pub const PERMISSIONS_POLICY_VALUE: &str =
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), \
     microphone=(), payment=(), usb=()";

/// The upstream fingerprint header removed from every proxied response (`X-Powered-By`).
///
/// Upstream stack/version fingerprint, usually leaked by frameworks with no functional need.
pub const X_POWERED_BY: http::header::HeaderName =
    http::header::HeaderName::from_static("x-powered-by");

/// The `Permissions-Policy` header name.
///
/// The `http` crate exposes no constant for this header (as of `http` 1.5), so the profile pins the
/// canonical spelling here.
pub const PERMISSIONS_POLICY: http::header::HeaderName =
    http::header::HeaderName::from_static("permissions-policy");

/// The immutable reverse-proxy security profile (ADR-0010 §2, `DIV-0131`).
///
/// A value object holding the exact header->value pairs of the default profile. The constants must
/// match `docs/compatibility/STOCK-COMPAT.md` exactly; the unit tests below pin them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityProfile {
    /// `Strict-Transport-Security` on TLS responses only.
    pub hsts: &'static str,
    /// `X-Content-Type-Options`.
    pub x_content_type_options: &'static str,
    /// `X-Frame-Options`.
    pub x_frame_options: &'static str,
    /// `Referrer-Policy`.
    pub referrer_policy: &'static str,
    /// `Permissions-Policy`.
    pub permissions_policy: &'static str,
}

impl SecurityProfile {
    /// The documented default profile (STOCK-COMPAT.md, ADR-0010 §2).
    pub const DEFAULT: Self = Self {
        hsts: HSTS_VALUE,
        x_content_type_options: X_CONTENT_TYPE_OPTIONS_VALUE,
        x_frame_options: X_FRAME_OPTIONS_VALUE,
        referrer_policy: REFERRER_POLICY_VALUE,
        permissions_policy: PERMISSIONS_POLICY_VALUE,
    };

    /// Apply the profile to final response headers: set each documented header only when absent,
    /// and emit `Strict-Transport-Security` only for TLS requests (never on cleartext, matching
    /// the RFC 6797 no-op over cleartext rationale).
    ///
    /// The profile never emits `Content-Security-Policy` (ADR-0010 §8) and never overrides an
    /// upstream-provided value.
    pub fn apply_to(self, headers: &mut HeaderMap, request_is_tls: bool) {
        self.apply_to_with(headers, request_is_tls, |_| false);
    }

    /// Apply the profile while skipping every header name the operator configured explicitly.
    ///
    /// `configured` answers "did the operator configure this header in the handler's own
    /// `headers.response` operations?". ADR-0010 §2 applies the profile *after* those operations
    /// so an operator's `header_down` wins; set-if-absent alone cannot honour an explicit
    /// `header_down -Header`, so the proxy handler passes its operation set here and the profile
    /// leaves those names alone entirely.
    pub fn apply_to_with<F>(self, headers: &mut HeaderMap, request_is_tls: bool, configured: F)
    where
        F: Fn(&http::header::HeaderName) -> bool,
    {
        for (name, value, enabled) in [
            (
                http::header::STRICT_TRANSPORT_SECURITY,
                self.hsts,
                request_is_tls,
            ),
            (
                http::header::X_CONTENT_TYPE_OPTIONS,
                self.x_content_type_options,
                true,
            ),
            (http::header::X_FRAME_OPTIONS, self.x_frame_options, true),
            (http::header::REFERRER_POLICY, self.referrer_policy, true),
            (PERMISSIONS_POLICY, self.permissions_policy, true),
        ] {
            if !enabled || configured(&name) {
                continue;
            }
            set_if_absent(headers, name, value, true);
        }
    }

    /// Remove the fingerprint headers from a proxied response, case-insensitively.
    ///
    /// `http::HeaderMap` normalizes names to lowercase, so `remove` matches any spelling. This is
    /// applied to every `reverse_proxy` output (including HTTP `101` protocol switches), while the
    /// five response headers above are not added to a protocol switch (STOCK-COMPAT.md).
    pub fn strip_fingerprints(self, headers: &mut HeaderMap) {
        headers.remove(http::header::SERVER);
        headers.remove(X_POWERED_BY);
    }
}

/// Insert `value` under `name` only when the response does not already carry the header, and only
/// when `enabled` is true (the TLS gate for HSTS).
fn set_if_absent(
    headers: &mut HeaderMap,
    name: http::header::HeaderName,
    value: &'static str,
    enabled: bool,
) {
    if !enabled {
        return;
    }
    if !headers.contains_key(&name) {
        headers.insert(name, http::header::HeaderValue::from_static(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    fn profile() -> SecurityProfile {
        SecurityProfile::DEFAULT
    }

    fn value<'a>(headers: &'a HeaderMap, name: http::header::HeaderName) -> Option<&'a str> {
        headers.get(name).and_then(|value| value.to_str().ok())
    }

    #[test]
    fn constants_match_the_normative_table() {
        // The normative literals from STOCK-COMPAT.md / ADR-0010 §2. Changing one of these without
        // changing the table is a plan violation; this test pins them.
        assert_eq!(profile().hsts, "max-age=31536000");
        assert_eq!(profile().x_content_type_options, "nosniff");
        assert_eq!(profile().x_frame_options, "DENY");
        assert_eq!(profile().referrer_policy, "strict-origin-when-cross-origin");
        assert_eq!(
            profile().permissions_policy,
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
             magnetometer=(), microphone=(), payment=(), usb=()"
        );
        assert_eq!(
            value(&profile_headers(true), PERMISSIONS_POLICY),
            Some(
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
                   magnetometer=(), microphone=(), payment=(), usb=()"
            )
        );
    }

    fn profile_headers(tls: bool) -> HeaderMap {
        let mut headers = HeaderMap::new();
        profile().apply_to(&mut headers, tls);
        headers
    }

    #[test]
    fn tls_response_carries_all_five_documented_headers() {
        let headers = profile_headers(true);
        assert_eq!(
            value(&headers, http::header::STRICT_TRANSPORT_SECURITY),
            Some("max-age=31536000")
        );
        assert_eq!(
            value(&headers, http::header::X_CONTENT_TYPE_OPTIONS),
            Some("nosniff")
        );
        assert_eq!(value(&headers, http::header::X_FRAME_OPTIONS), Some("DENY"));
        assert_eq!(
            value(&headers, http::header::REFERRER_POLICY),
            Some("strict-origin-when-cross-origin")
        );
        assert_eq!(
            value(&headers, PERMISSIONS_POLICY),
            Some(
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
                   magnetometer=(), microphone=(), payment=(), usb=()"
            )
        );
        // The profile must never emit CSP on its own (ADR-0010 §8).
        assert_eq!(headers.get("content-security-policy"), None);
    }

    #[test]
    fn cleartext_proxied_response_gets_everything_but_hsts() {
        let headers = profile_headers(false);
        assert_eq!(headers.get(http::header::STRICT_TRANSPORT_SECURITY), None);
        assert_eq!(
            value(&headers, http::header::X_CONTENT_TYPE_OPTIONS),
            Some("nosniff")
        );
        assert_eq!(value(&headers, http::header::X_FRAME_OPTIONS), Some("DENY"));
        assert_eq!(
            value(&headers, http::header::REFERRER_POLICY),
            Some("strict-origin-when-cross-origin")
        );
        assert!(headers.contains_key(PERMISSIONS_POLICY));
    }

    #[test]
    fn upstream_values_are_never_overridden() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::X_FRAME_OPTIONS,
            http::header::HeaderValue::from_static("SAMEORIGIN"),
        );
        headers.insert(
            http::header::STRICT_TRANSPORT_SECURITY,
            http::header::HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        );
        headers.insert(
            http::header::REFERRER_POLICY,
            http::header::HeaderValue::from_static("no-referrer"),
        );
        // An explicit upstream CSP must pass through untouched too.
        headers.insert(
            http::header::HeaderName::from_static("content-security-policy"),
            http::header::HeaderValue::from_static("default-src 'self'"),
        );
        profile().apply_to(&mut headers, true);
        assert_eq!(
            value(&headers, http::header::X_FRAME_OPTIONS),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            value(&headers, http::header::STRICT_TRANSPORT_SECURITY),
            Some("max-age=63072000; includeSubDomains; preload")
        );
        assert_eq!(
            value(&headers, http::header::REFERRER_POLICY),
            Some("no-referrer")
        );
        assert_eq!(
            value(
                &headers,
                http::header::HeaderName::from_static("content-security-policy")
            ),
            Some("default-src 'self'")
        );
        // Gaps are still filled.
        assert_eq!(
            value(&headers, http::header::X_CONTENT_TYPE_OPTIONS),
            Some("nosniff")
        );
        assert!(headers.contains_key(PERMISSIONS_POLICY));
    }

    #[test]
    fn fingerprint_stripper_removes_server_and_x_powered_by_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::SERVER,
            http::header::HeaderValue::from_static("Kestrel"),
        );
        headers.insert(
            "X-Powered-By".parse::<http::header::HeaderName>().unwrap(),
            http::header::HeaderValue::from_static("ASP.NET"),
        );
        headers.insert(
            "x-PoWered-By".parse::<http::header::HeaderName>().unwrap(),
            http::header::HeaderValue::from_static("PHP/8.2"),
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            http::header::HeaderValue::from_static("text/plain"),
        );
        profile().strip_fingerprints(&mut headers);
        assert_eq!(headers.get(http::header::SERVER), None);
        assert_eq!(headers.get("x-powered-by"), None);
        assert!(headers.contains_key(http::header::CONTENT_TYPE));
    }

    #[test]
    fn profile_is_inert_when_not_applied() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::SERVER,
            http::header::HeaderValue::from_static("Kestrel"),
        );
        headers.insert(
            "X-Powered-By".parse::<http::header::HeaderName>().unwrap(),
            http::header::HeaderValue::from_static("ASP.NET"),
        );
        // No call to apply_to/strip_fingerprints: headers pass through untouched, which is what
        // `stock_compat true` means for the proxy handler (it never invokes the profile).
        assert_eq!(value(&headers, http::header::SERVER), Some("Kestrel"));
        assert_eq!(
            value(
                &headers,
                "X-Powered-By".parse::<http::header::HeaderName>().unwrap()
            ),
            Some("ASP.NET")
        );
        assert_eq!(headers.get(http::header::X_CONTENT_TYPE_OPTIONS), None);
    }
}
