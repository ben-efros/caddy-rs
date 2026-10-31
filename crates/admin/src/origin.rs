//! Admin API origin enforcement.
//!
//! Port of upstream Caddy's `adminHandler.checkOrigin` / `originAllowed` /
//! `AdminConfig.allowedOrigins` (see `external/caddy/admin.go`).
//!
//! Behaviour replicated from Caddy v2.11.7:
//!
//! - An `Origin` header is validated whenever `enforce_origin` is true *or* the request carries an
//!   `Origin`/`Sec-Fetch-Mode` header (the cross-site mitigation is always on).
//! - When `Origin` is missing, the `Referer` is used instead.
//! - A request with `Origin: null` is rejected with `400` (buggy browser mitigation).
//! - A request with `Sec-Fetch-Mode: no-cors` or a WebSocket upgrade is rejected with `400`.
//! - A disallowed or missing origin is rejected with `403` and Caddy's message text.
//! - `admin.origins` entries are compared by scheme (only when the configured entry has one) and
//!   case-insensitively by host, ignoring path/query/fragment.
//! - When `admin.origins` is empty/absent, the listener address is used as the implicit origin:
//!   loopback listeners get `localhost:<port>`, `127.0.0.1:<port>` and `[::1]:<port>`; a unix
//!   socket accepts no origin by default.
//!
//! Simplifications (see the task report for the divergence entries):
//!
//! - Caddy distinguishes `origins: null` (derive from the listen address) from `origins: []`
//!   (allow none). The shared `AdminConfig` models both as an empty `Vec`; this implementation
//!   treats empty as "not configured", so an explicit empty list derives the defaults instead of
//!   bricking the endpoint.
//! - `url.Parse` is approximated with a small scheme/authority parser; percent-encoded hosts and
//!   userinfo are not supported.
//! - The policy is re-evaluated from the active generation on every request. A real listener is
//!   configured once when the admin endpoint starts, so the server crate may pass a startup
//!   policy with [`crate::AdminApi::with_origin_policy`].

use caddy_rs_core::{AdminConfig, ListenAddr};
use http::{HeaderMap, StatusCode};

/// A configured origin that may access the admin API.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowedOrigin {
    /// Scheme that must match, if the configured origin included one.
    scheme: Option<String>,
    /// Host (including port), compared case-insensitively.
    host: String,
}

/// The effective origin policy for admin requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OriginPolicy {
    enforce_origin: bool,
    allowed: Vec<AllowedOrigin>,
}

/// Why an admin request was rejected by the origin policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginViolation {
    /// HTTP status Caddy returns for this class of violation.
    pub status: StatusCode,
    /// Caddy-compatible error message.
    pub message: String,
}

impl OriginPolicy {
    /// Derive the policy from an `admin` configuration block.
    ///
    /// `None` means "no admin block configured", which uses Caddy's defaults (`localhost:2019`
    /// and no enforced origin).
    pub fn from_admin(admin: Option<&AdminConfig>) -> Self {
        let enforce_origin = admin.is_some_and(|admin| admin.enforce_origin);
        let configured = admin.map(|admin| admin.origins.clone()).unwrap_or_default();

        let allowed = if !configured.is_empty() {
            configured
                .iter()
                .filter_map(|origin| parse_allowed_origin(origin))
                .collect()
        } else {
            let listen = admin
                .map(AdminConfig::listen_addr)
                .unwrap_or("localhost:2019");
            default_origins(listen)
        };

        Self {
            enforce_origin,
            allowed,
        }
    }

    /// The number of allowed origins (used by tests to assert the derived defaults).
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Whether no origin can access the endpoint.
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Whether `admin.enforce_origin` is on.
    pub fn enforce_origin(&self) -> bool {
        self.enforce_origin
    }

    /// Normalized allowed origins (`scheme://host` or `host`) for diagnostics and tests.
    pub fn allowed_origins(&self) -> Vec<String> {
        self.allowed
            .iter()
            .map(|origin| match &origin.scheme {
                Some(scheme) => format!("{scheme}://{}", origin.host),
                None => origin.host.clone(),
            })
            .collect()
    }

    /// Evaluate the policy for a request.
    ///
    /// `Ok(Some(origin))` means the request is allowed and `origin` (normalized as
    /// `scheme://host`) should be echoed in `Access-Control-Allow-Origin`.
    /// `Ok(None)` means the request is allowed and no CORS header is needed.
    /// `Err(violation)` carries the status/message to return.
    pub fn check(&self, headers: &HeaderMap) -> Result<Option<String>, OriginViolation> {
        if headers
            .get(http::header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains("websocket"))
        {
            return Err(OriginViolation {
                status: StatusCode::BAD_REQUEST,
                message: "WebSocket connections aren't allowed.".to_string(),
            });
        }
        if headers
            .get("sec-fetch-mode")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains("no-cors"))
        {
            return Err(OriginViolation {
                status: StatusCode::BAD_REQUEST,
                message: "Disabling same-origin restrictions is not allowed.".to_string(),
            });
        }

        let origin_header = headers
            .get(http::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let has_origin_header = headers.contains_key(http::header::ORIGIN);
        let has_sec_fetch_header = headers.contains_key("sec-fetch-mode");

        if !self.enforce_origin && !has_origin_header && !has_sec_fetch_header {
            return Ok(None);
        }

        if origin_header == "null" {
            return Err(OriginViolation {
                status: StatusCode::BAD_REQUEST,
                message: "Buggy browser is sending null Origin header.".to_string(),
            });
        }

        // Mirror Caddy's getOrigin: fall back to Referer when Origin is absent.
        let raw = if origin_header.is_empty() {
            headers
                .get(http::header::REFERER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
        } else {
            origin_header
        };

        let Some(origin) = parse_origin(raw) else {
            return Err(OriginViolation {
                status: StatusCode::FORBIDDEN,
                message: "required Origin header is missing or invalid".to_string(),
            });
        };

        if !self.origin_allowed(&origin) {
            return Err(OriginViolation {
                status: StatusCode::FORBIDDEN,
                message: format!("client is not allowed to access from origin '{raw}'"),
            });
        }

        Ok(Some(origin.display()))
    }

    fn origin_allowed(&self, origin: &ParsedOrigin) -> bool {
        self.allowed.iter().any(|allowed| {
            if allowed.scheme.is_some() && origin.scheme != allowed.scheme {
                return false;
            }
            allowed.host.eq_ignore_ascii_case(&origin.host)
        })
    }
}

/// A request parsed into the parts Caddy compares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedOrigin {
    scheme: Option<String>,
    host: String,
}

impl ParsedOrigin {
    fn display(&self) -> String {
        match &self.scheme {
            Some(scheme) => format!("{scheme}://{}", self.host),
            None => self.host.clone(),
        }
    }
}

/// Parse an `Origin`/`Referer` value the way Caddy's `url.Parse` + field stripping does:
/// scheme and authority only, no path/query/fragment, host lowercased.
///
/// Returns `None` for syntactically unacceptable values (Caddy returns the 403 "invalid" error
/// when `url.Parse` fails). An empty string is accepted as an empty origin so it fails the
/// allow-list check with Caddy's "client is not allowed ... ''" message.
fn parse_origin(raw: &str) -> Option<ParsedOrigin> {
    if raw.is_empty() {
        return Some(ParsedOrigin {
            scheme: None,
            host: String::new(),
        });
    }
    if raw.chars().any(char::is_whitespace) {
        return None;
    }
    let (scheme, authority) = match raw.split_once("://") {
        Some((scheme, rest)) => {
            if scheme.is_empty()
                || !scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            {
                return None;
            }
            (Some(scheme.to_ascii_lowercase()), rest)
        }
        None => (None, raw),
    };
    let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        // `http://` with no host is invalid in Caddy (url.Parse succeeds but produces an empty
        // Host, which cannot match any allowed origin); represent it as an empty host.
        return Some(ParsedOrigin {
            scheme,
            host: String::new(),
        });
    }
    Some(ParsedOrigin {
        scheme,
        host: authority.to_ascii_lowercase(),
    })
}

/// Parse one configured origin (`scheme://host` or bare `host[:port]`).
fn parse_allowed_origin(raw: &str) -> Option<AllowedOrigin> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    match raw.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
            if authority.is_empty() {
                return None;
            }
            Some(AllowedOrigin {
                scheme: Some(scheme.to_ascii_lowercase()),
                host: authority.to_ascii_lowercase(),
            })
        }
        None => Some(AllowedOrigin {
            scheme: None,
            host: raw.to_ascii_lowercase(),
        }),
    }
}

/// Caddy's implicit origins for a listener address: all loopback spellings for loopback
/// listeners, the listener host:port otherwise, and nothing for unix sockets.
fn default_origins(listen: &str) -> Vec<AllowedOrigin> {
    let Ok(addr) = ListenAddr::parse(listen) else {
        return Vec::new();
    };
    if addr.network == caddy_rs_core::Network::Unix {
        // Caddy disables origin/host checks for unix sockets: browsers cannot reach them and the
        // OS socket permissions are the access control.
        return Vec::new();
    }
    let host = addr.host().trim_start_matches('[').trim_end_matches(']');
    let Some(port) = addr.port() else {
        return Vec::new();
    };
    let loopback = host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if loopback {
        vec![
            AllowedOrigin {
                scheme: None,
                host: format!("localhost:{port}"),
            },
            AllowedOrigin {
                scheme: None,
                host: format!("127.0.0.1:{port}"),
            },
            AllowedOrigin {
                scheme: None,
                host: format!("[::1]:{port}"),
            },
        ]
    } else {
        vec![AllowedOrigin {
            scheme: None,
            host: format!("{host}:{port}"),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(origin: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(origin) = origin {
            headers.insert(http::header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        }
        headers
    }

    fn admin(enforce: bool, origins: &[&str]) -> AdminConfig {
        AdminConfig {
            enforce_origin: enforce,
            origins: origins.iter().map(|origin| origin.to_string()).collect(),
            ..AdminConfig::default()
        }
    }

    #[test]
    fn default_loopback_origins() {
        let policy = OriginPolicy::from_admin(Some(&admin(false, &[])));
        let mut origins = policy.allowed_origins();
        origins.sort();
        assert_eq!(
            origins,
            vec!["127.0.0.1:2019", "[::1]:2019", "localhost:2019"]
        );
    }

    #[test]
    fn configured_origins_are_used_verbatim() {
        let policy = OriginPolicy::from_admin(Some(&admin(true, &["https://example.com"])));
        assert_eq!(policy.allowed_origins(), vec!["https://example.com"]);
        assert!(policy.enforce_origin());
    }

    #[test]
    fn allowed_origin_matches_scheme_and_host() {
        let policy = OriginPolicy::from_admin(Some(&admin(
            true,
            &["https://example.com", "plain.example"],
        )));
        assert_eq!(
            policy.check(&headers(Some("https://example.com"))).unwrap(),
            Some("https://example.com".to_string())
        );
        // Scheme must match when configured with one.
        assert!(policy.check(&headers(Some("http://example.com"))).is_err());
        // Bare host entries match any scheme.
        assert_eq!(
            policy
                .check(&headers(Some("http://plain.example")))
                .unwrap(),
            Some("http://plain.example".to_string())
        );
        // Host comparison is case-insensitive; path is ignored.
        assert_eq!(
            policy
                .check(&headers(Some("HTTPS://EXAMPLE.COM/ignored?q=1")))
                .unwrap(),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn disallowed_and_missing_origins_are_forbidden() {
        let policy = OriginPolicy::from_admin(Some(&admin(true, &["https://example.com"])));
        let violation = policy
            .check(&headers(Some("https://evil.example")))
            .expect_err("disallowed origin");
        assert_eq!(violation.status, StatusCode::FORBIDDEN);
        assert_eq!(
            violation.message,
            "client is not allowed to access from origin 'https://evil.example'"
        );

        let violation = policy.check(&headers(None)).expect_err("missing origin");
        assert_eq!(violation.status, StatusCode::FORBIDDEN);
        assert_eq!(
            violation.message,
            "client is not allowed to access from origin ''"
        );
    }

    #[test]
    fn origin_header_is_checked_even_without_enforce_origin() {
        // Caddy's cross-site mitigation applies whenever an Origin header is present.
        let policy = OriginPolicy::from_admin(None);
        assert_eq!(
            policy.check(&headers(None)).unwrap(),
            None,
            "no Origin header and no enforcement means allowed"
        );
        let violation = policy
            .check(&headers(Some("https://evil.example")))
            .expect_err("cross-site origin");
        assert_eq!(violation.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn null_origin_and_browser_mitigations_are_bad_requests() {
        let policy = OriginPolicy::from_admin(Some(&admin(true, &[])));
        let violation = policy
            .check(&headers(Some("null")))
            .expect_err("null origin");
        assert_eq!(violation.status, StatusCode::BAD_REQUEST);
        assert!(violation.message.contains("null Origin"));

        let mut no_cors = HeaderMap::new();
        no_cors.insert("sec-fetch-mode", HeaderValue::from_static("no-cors"));
        let violation = policy.check(&no_cors).expect_err("no-cors");
        assert_eq!(violation.status, StatusCode::BAD_REQUEST);

        let mut upgrade = HeaderMap::new();
        upgrade.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        let violation = policy.check(&upgrade).expect_err("websocket");
        assert_eq!(violation.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn referer_is_used_when_origin_is_missing() {
        let policy = OriginPolicy::from_admin(Some(&admin(true, &["https://example.com"])));
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            http::header::REFERER,
            HeaderValue::from_static("https://example.com/page"),
        );
        assert_eq!(
            policy.check(&request_headers).unwrap(),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn unix_listener_has_no_implicit_origins() {
        let policy = OriginPolicy::from_admin(Some(&AdminConfig {
            listen: Some("unix//run/caddy.sock".to_string()),
            ..AdminConfig::default()
        }));
        assert!(policy.is_empty());
        // Without enforce_origin and without an Origin header, unix requests are allowed.
        assert_eq!(policy.check(&headers(None)).unwrap(), None);
    }

    #[test]
    fn non_loopback_listener_defaults_to_its_own_authority() {
        let policy = OriginPolicy::from_admin(Some(&AdminConfig {
            listen: Some("example.com:2020".to_string()),
            ..AdminConfig::default()
        }));
        assert_eq!(policy.allowed_origins(), vec!["example.com:2020"]);
    }
}
