//! `reverse_proxy` load-balancing `retry_match` evaluation.
//!
//! Caddy accepts an array of *matcher sets* under `load_balancing.retry_match` (JSON) or one or
//! more `lb_retry_match` blocks (Caddyfile). Set evaluation is Caddy's: sets are OR-combined and
//! matchers inside a set are AND-combined.
//!
//! # Response matching
//!
//! Caddy evaluates `retry_match` against a response only for matcher sets that contain an
//! expression matcher, because only expressions can reference response data
//! (`{http.reverse_proxy.status_code}`, `{http.reverse_proxy.header.*}`). Request-only matcher
//! sets decide transport-error retries only. caddy-rs does not implement the CEL expression
//! matcher yet (`T-ROUTE-009`), so this module mirrors that split with a response-aware `status`
//! matcher instead:
//!
//! * A set containing at least one `status` matcher is evaluated against a response. Request
//!   matchers in the set (`method`, `path`, `host`, `header`, `query`, `not`) are evaluated
//!   against the original request, so a rule can mean "retry 502s for GET /api/*".
//! * A set without a `status` matcher is request-only and never retries a response; it only
//!   gates retries after a transport error (Caddy's `lb_retry_match path /bar*` behaviour).
//!
//! The `status` matcher is a caddy-rs extension: Caddy v2.11.7 has no `status` matcher module,
//! so this configuration is rejected by Caddy and is registered as a divergence.
//!
//! Supported `status` entries: an exact code (`502`), a class (`5xx`), or a range (`500-599`),
//! optionally negated with a leading `!` (`!503`). Values may be a single entry or an array.

use caddy_rs_http::matchers::build_matcher_set;
use caddy_rs_http::{Error as HttpError, Request, Response, Result as HttpResult, SharedMatcher};

use http::StatusCode;
use serde_json::{Map, Value};

/// Parsed `load_balancing.retry_match` configuration.
#[derive(Default)]
pub struct RetryMatch {
    sets: Vec<RetrySet>,
}

struct RetrySet {
    /// Matchers evaluated against the request.
    request: Vec<SharedMatcher>,
    /// Matchers evaluated against the upstream response; presence makes the set response-aware.
    status: Option<StatusMatcher>,
}

impl RetrySet {
    fn is_response_aware(&self) -> bool {
        self.status.is_some()
    }

    fn matches_request(&self, request: &Request) -> bool {
        self.request.iter().all(|matcher| matcher.matches(request))
    }

    fn matches_response(&self, request: &Request, response: &Response) -> bool {
        self.matches_request(request)
            && self
                .status
                .as_ref()
                .is_none_or(|status| status.matches(response.status))
    }
}

impl RetryMatch {
    /// Parse the `load_balancing.retry_match` JSON array.
    pub fn from_json(value: Option<&Value>, path: &str) -> HttpResult<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let sets = value.as_array().ok_or_else(|| {
            invalid(
                path,
                "`load_balancing.retry_match` must be an array of matcher sets",
            )
        })?;
        let mut parsed = Vec::with_capacity(sets.len());
        for (index, set) in sets.iter().enumerate() {
            parsed.push(parse_set(set, &format!("{path}[{index}]"))?);
        }
        Ok(Self { sets: parsed })
    }

    /// Whether any matcher set is configured.
    pub fn is_configured(&self) -> bool {
        !self.sets.is_empty()
    }

    /// Whether a transport error should be retried.
    ///
    /// Matches the same matcher-set rules as Caddy's `tryAgain`: a set matches when every
    /// request matcher matches. Sets that require a response (`status`) never match here.
    pub fn matches_transport_error(&self, request: &Request) -> bool {
        self.sets
            .iter()
            .filter(|set| !set.is_response_aware())
            .any(|set| set.matches_request(request))
    }

    /// Whether an upstream response matches a response-aware retry rule.
    pub fn matches_response(&self, request: &Request, response: &Response) -> bool {
        self.sets
            .iter()
            .filter(|set| set.is_response_aware())
            .any(|set| set.matches_response(request, response))
    }
}

fn parse_set(value: &Value, path: &str) -> HttpResult<RetrySet> {
    let object = value.as_object().ok_or_else(|| {
        invalid(
            path,
            "each `retry_match` entry must be a matcher-set object",
        )
    })?;

    // Split off the response-aware extension before handing the rest to the HTTP engine's
    // matcher builder, which owns request matcher construction (and rejects unsupported ones).
    let mut status = None;
    let mut request_value = Map::new();
    for (key, value) in object {
        if key == "expression" {
            // Caddy can reference response data in retry_match through expression matchers
            // (for example `{http.reverse_proxy.status_code} in [502, 503]`). The CEL subset is
            // owned by the HTTP engine (T-ROUTE-009); until it exists, fail loudly instead of
            // silently not retrying.
            return Err(HttpError::NotImplemented {
                feature: "expression matcher in retry_match (CEL subset)",
                tracking_id: "T-ROUTE-009",
            });
        }
        if key == "status" {
            if status.is_some() {
                return Err(invalid(
                    path,
                    "duplicate `status` matcher in one matcher set",
                ));
            }
            status = Some(StatusMatcher::from_json(value, &format!("{path}.status"))?);
        } else {
            request_value.insert(key.clone(), value.clone());
        }
    }

    let request =
        build_matcher_set(&Value::Object(request_value)).map_err(|error| match error {
            HttpError::InvalidConfig {
                path: inner_path,
                message,
            } => invalid(path, format!("{inner_path}: {message}")),
            other => other,
        })?;

    Ok(RetrySet { request, status })
}

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// Response status matcher: exact codes, status classes (`5xx`) and ranges (`500-599`).
#[derive(Debug)]
struct StatusMatcher {
    ranges: Vec<StatusRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatusRange {
    start: u16,
    end: u16,
    negated: bool,
}

impl StatusRange {
    fn matches(self, code: u16) -> bool {
        let inside = (self.start..=self.end).contains(&code);
        if self.negated {
            !inside
        } else {
            inside
        }
    }
}

impl StatusMatcher {
    fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        let entries: Vec<&Value> = match value {
            Value::Array(values) => values.iter().collect(),
            other => vec![other],
        };
        if entries.is_empty() {
            return Err(invalid(
                path,
                "`status` matcher requires at least one value",
            ));
        }
        let mut ranges = Vec::with_capacity(entries.len());
        for entry in entries {
            ranges.push(parse_status_entry(entry, path)?);
        }
        Ok(Self { ranges })
    }

    fn matches(&self, status: StatusCode) -> bool {
        self.ranges
            .iter()
            .copied()
            .any(|range| range.matches(status.as_u16()))
    }
}

fn parse_status_entry(value: &Value, path: &str) -> HttpResult<StatusRange> {
    let text =
        match value {
            Value::Number(number) => number
                .as_u64()
                .map(|code| code.to_string())
                .ok_or_else(|| invalid(path, "status codes must be non-negative integers"))?,
            Value::String(text) => text.trim().to_string(),
            _ => return Err(invalid(
                path,
                "status entries must be integers or strings like \"502\", \"5xx\" or \"500-599\"",
            )),
        };
    let (negated, body) = match text.strip_prefix('!') {
        Some(rest) => (true, rest.trim()),
        None => (false, text.as_str()),
    };
    if body.is_empty() {
        return Err(invalid(path, "empty status entry"));
    }
    let bounds = if body.len() == 3
        && body[1..].eq_ignore_ascii_case("xx")
        && body.as_bytes()[0].is_ascii_digit()
    {
        let class = u16::from(body.as_bytes()[0] - b'0');
        if !(1..=5).contains(&class) {
            return Err(invalid(
                path,
                format!("status class `{body}` must start with a digit from 1 to 5"),
            ));
        }
        (class * 100, class * 100 + 99)
    } else if let Some((start, end)) = body.split_once('-') {
        let start = parse_status_code(start.trim(), path)?;
        let end = parse_status_code(end.trim(), path)?;
        if start > end {
            return Err(invalid(
                path,
                format!("status range `{body}` has a start greater than its end"),
            ));
        }
        (start, end)
    } else {
        let code = parse_status_code(body, path)?;
        (code, code)
    };
    Ok(StatusRange {
        start: bounds.0,
        end: bounds.1,
        negated,
    })
}

fn parse_status_code(text: &str, path: &str) -> HttpResult<u16> {
    let code: u16 = text
        .parse()
        .map_err(|_| invalid(path, format!("`{text}` is not a status code")))?;
    if !(100..=999).contains(&code) {
        return Err(invalid(
            path,
            format!("status code `{code}` must be between 100 and 999"),
        ));
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method, Uri};
    use serde_json::json;

    fn request(method: Method, path: &str) -> Request {
        let mut request = Request::new(method, path.parse::<Uri>().unwrap());
        request
            .headers
            .insert(http::header::HOST, HeaderValue::from_static("example.com"));
        request
    }

    fn response(status: u16) -> Response {
        Response {
            status: StatusCode::from_u16(status).unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    fn parse(value: Value) -> RetryMatch {
        RetryMatch::from_json(Some(&value), "load_balancing.retry_match").unwrap()
    }

    #[test]
    fn status_matcher_matches_codes_classes_and_ranges() {
        let retry = parse(json!([{"status": [502, "5xx", "429"]}]));
        let get = request(Method::GET, "/");
        assert!(retry.matches_response(&get, &response(502)));
        assert!(retry.matches_response(&get, &response(503)));
        assert!(retry.matches_response(&get, &response(429)));
        assert!(!retry.matches_response(&get, &response(200)));
        assert!(!retry.matches_response(&get, &response(404)));

        let retry = parse(json!([{"status": "500-599"}]));
        assert!(retry.matches_response(&get, &response(550)));
        assert!(!retry.matches_response(&get, &response(499)));
    }

    #[test]
    fn negated_status_entry_matches_everything_else() {
        let retry = parse(json!([{"status": "!2xx"}]));
        let get = request(Method::GET, "/");
        assert!(retry.matches_response(&get, &response(502)));
        assert!(!retry.matches_response(&get, &response(204)));
    }

    #[test]
    fn request_matchers_combine_with_status() {
        let retry = parse(json!([{"status": [502], "method": ["GET"], "path": ["/api/*"]}]));
        let matching = request(Method::GET, "/api/users");
        let wrong_path = request(Method::GET, "/web");
        let wrong_method = request(Method::POST, "/api/users");
        assert!(retry.matches_response(&matching, &response(502)));
        assert!(!retry.matches_response(&wrong_path, &response(502)));
        assert!(!retry.matches_response(&wrong_method, &response(502)));
        // Non-matching status passes through even when the request matchers match.
        assert!(!retry.matches_response(&matching, &response(500)));
    }

    #[test]
    fn response_sets_are_or_combined() {
        let retry = parse(json!([
            {"status": [502], "path": ["/a*"]},
            {"status": [503], "path": ["/b*"]},
        ]));
        assert!(retry.matches_response(&request(Method::GET, "/a/x"), &response(502)));
        assert!(retry.matches_response(&request(Method::GET, "/b/x"), &response(503)));
        assert!(!retry.matches_response(&request(Method::GET, "/b/x"), &response(502)));
    }

    #[test]
    fn request_only_sets_gate_transport_errors_not_responses() {
        let retry = parse(json!([{"method": ["POST"], "path": ["/bar*"]}]));
        assert!(retry.is_configured());
        assert!(!retry.matches_response(&request(Method::POST, "/bar"), &response(502)));
        assert!(retry.matches_transport_error(&request(Method::POST, "/bar")));
        assert!(!retry.matches_transport_error(&request(Method::POST, "/other")));
    }

    #[test]
    fn status_sets_do_not_match_transport_errors() {
        let retry = parse(json!([{"status": [502]}]));
        assert!(!retry.matches_transport_error(&request(Method::GET, "/")));
    }

    #[test]
    fn header_matcher_is_request_based() {
        let retry = parse(json!([{"status": [502], "header": {"X-Retry": ["true"]}}]));
        let mut with_header = request(Method::GET, "/");
        with_header
            .headers
            .insert("x-retry", HeaderValue::from_static("true"));
        assert!(retry.matches_response(&with_header, &response(502)));
        assert!(!retry.matches_response(&request(Method::GET, "/"), &response(502)));
    }

    #[test]
    fn not_matcher_wraps_request_matchers() {
        let retry = parse(json!([{"status": [502], "not": [{"method": ["GET"]}]}]));
        assert!(!retry.matches_response(&request(Method::GET, "/"), &response(502)));
        assert!(retry.matches_response(&request(Method::POST, "/"), &response(502)));
    }

    #[test]
    fn invalid_status_entries_fail_by_name() {
        let error = RetryMatch::from_json(Some(&json!([{"status": "nope"}])), "retry_match")
            .err()
            .expect("invalid status must fail");
        assert!(error.to_string().contains("status"), "{error}");

        let error = RetryMatch::from_json(Some(&json!([{"status": "9xx"}])), "retry_match")
            .err()
            .expect("invalid status class must fail");
        assert!(error.to_string().contains("status class"), "{error}");
    }

    #[test]
    fn unsupported_matchers_fail_loudly() {
        let error = RetryMatch::from_json(
            Some(&json!([{"expression": "{rp.status_code} == 502"}])),
            "retry_match",
        )
        .err()
        .expect("expression matcher must be rejected until T-ROUTE-009");
        let message = error.to_string();
        assert!(message.contains("expression"), "{message}");
        assert!(message.contains("T-ROUTE-009"), "{message}");
    }

    #[test]
    fn empty_configuration_never_retries() {
        let retry = RetryMatch::default();
        assert!(!retry.is_configured());
        assert!(!retry.matches_transport_error(&request(Method::GET, "/")));
        assert!(!retry.matches_response(&request(Method::GET, "/"), &response(502)));
    }
}
