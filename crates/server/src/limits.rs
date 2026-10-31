//! Per-server HTTP limits and timeouts (plan task T-HTTP-013).
//!
//! Caddy's JSON server object (`apps.http.servers.<name>`) carries timeout fields as
//! `caddy.Duration` values: either a Go duration string (`"5s"`, `"1m30s"`, `"250ms"`, `"2d"`)
//! or an integer number of nanoseconds. This module parses them into [`ServerLimits`], the
//! knobs enforced at the hyper connection/request boundary in [`crate::listeners`] and
//! [`crate::http`].
//!
//! Caddy applies defaults of its own during provisioning (`modules/caddyhttp/app.go`):
//! `idle_timeout` defaults to 5 minutes and `read_header_timeout` to 1 minute. The remaining
//! timeout fields have no default (zero means "disabled"), exactly as in Caddy.
//!
//! ## caddy-rs hardening extensions
//!
//! Caddy has no server-level request-body cap (the `request_body` handler applies `max_size`
//! per route) and no connection cap. caddy-rs adds two optional server fields, accepted only by
//! this implementation:
//!
//! * `max_request_body_size`: integer bytes; `0`/absent means unlimited. Exceeding it produces
//!   `413 Request Entity Too Large`.
//! * `max_connections`: maximum concurrent connections for the listener; `0`/absent means
//!   unlimited. Connections above the cap are accepted and closed immediately.
//!
//! A configuration using these fields is **not portable** to Caddy v2.11.7, which rejects
//! unknown server fields; the difference is registered in
//! `docs/compatibility/BEHAVIOR-DIVERGENCES.md` (DIV-0028).

use std::collections::BTreeMap;
use std::time::Duration;

use caddy_rs_core::{Error as CoreError, HttpServer};
use serde_json::Value;

/// Default HTTP server idle timeout, matching Caddy's `defaultIdleTimeout` (5 minutes).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Default HTTP/1 header-read timeout, matching Caddy's `defaultReadHeaderTimeout` (1 minute).
pub const DEFAULT_READ_HEADER_TIMEOUT: Duration = Duration::from_secs(60);

/// caddy-rs extension: maximum request body size in bytes (`0`/absent = unlimited).
pub const MAX_REQUEST_BODY_SIZE_FIELD: &str = "max_request_body_size";

/// caddy-rs extension: maximum concurrent connections on the listener (`0`/absent = unlimited).
pub const MAX_CONNECTIONS_FIELD: &str = "max_connections";

/// Caddy server field for the header-read timeout (typed in Caddy, read from the preserved
/// unknown-field map here).
pub const READ_HEADER_TIMEOUT_FIELD: &str = "read_header_timeout";

/// Caddy server field for the maximum header size.
pub const MAX_HEADER_BYTES_FIELD: &str = "max_header_bytes";

/// Per-server limits parsed from one `apps.http.servers.<name>` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerLimits {
    /// Hard limit for reading one request (headers and body). `None` means no limit.
    ///
    /// Enforced per read operation at the I/O boundary rather than as one deadline over the
    /// whole transfer; see DIV-0029.
    pub read_timeout: Option<Duration>,

    /// Hard limit for writing one response. `None` means no limit.
    ///
    /// Enforced per write operation, like [`ServerLimits::read_timeout`].
    pub write_timeout: Option<Duration>,

    /// Maximum time a connection may stay idle between requests. Always set; Caddy's default is
    /// 5 minutes.
    pub idle_timeout: Duration,

    /// Maximum time to read HTTP/1 request headers. Always set; Caddy's default is 1 minute.
    pub read_header_timeout: Duration,

    /// Maximum size in bytes of the request head. `None` uses the hyper default.
    pub max_header_bytes: Option<usize>,

    /// caddy-rs extension: maximum request body size in bytes. `None` means unlimited.
    pub max_request_body_size: Option<u64>,

    /// caddy-rs extension: maximum concurrent connections. `None` means unlimited.
    pub max_connections: Option<usize>,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            read_timeout: None,
            write_timeout: None,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            read_header_timeout: DEFAULT_READ_HEADER_TIMEOUT,
            max_header_bytes: None,
            max_request_body_size: None,
            max_connections: None,
        }
    }
}

impl ServerLimits {
    /// Parse the limits and timeouts of one Caddy HTTP server object.
    ///
    /// Errors are located at the offending JSON path, for example
    /// `apps.http.servers.srv0.read_timeout`, so an invalid configuration fails loudly when the
    /// runtime applies the generation instead of silently ignoring the field.
    pub fn from_http_server(server_name: &str, server: &HttpServer) -> Result<Self, CoreError> {
        let base = format!("apps.http.servers.{server_name}");

        let read_timeout = optional_timeout(server.read_timeout.as_ref(), &base, "read_timeout")?;
        let write_timeout =
            optional_timeout(server.write_timeout.as_ref(), &base, "write_timeout")?;
        let idle_timeout = optional_timeout(server.idle_timeout.as_ref(), &base, "idle_timeout")?
            .unwrap_or(DEFAULT_IDLE_TIMEOUT);
        let read_header_timeout = optional_timeout(
            server.extra.get(READ_HEADER_TIMEOUT_FIELD),
            &base,
            READ_HEADER_TIMEOUT_FIELD,
        )?
        .unwrap_or(DEFAULT_READ_HEADER_TIMEOUT);

        let max_header_bytes = extra_size(
            &server.extra,
            &base,
            MAX_HEADER_BYTES_FIELD,
            "number of bytes",
        )?
        .map(|bytes| usize::try_from(bytes).unwrap_or(usize::MAX));

        let max_request_body_size = extra_size(
            &server.extra,
            &base,
            MAX_REQUEST_BODY_SIZE_FIELD,
            "number of bytes",
        )?;

        let max_connections = extra_size(
            &server.extra,
            &base,
            MAX_CONNECTIONS_FIELD,
            "connection count",
        )?
        .map(|count| usize::try_from(count).unwrap_or(usize::MAX));

        Ok(Self {
            read_timeout,
            write_timeout,
            idle_timeout,
            read_header_timeout,
            max_header_bytes,
            max_request_body_size,
            max_connections,
        })
    }
}

/// Read a Caddy duration field, converting it to [`Duration`].
///
/// Absent (`None`) or JSON `null` means "not configured", which yields `None`. Zero and negative
/// durations also yield `None`, mirroring Caddy's `if dur > 0` guards.
fn optional_timeout(
    value: Option<&Value>,
    base: &str,
    field: &str,
) -> Result<Option<Duration>, CoreError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let path = format!("{base}.{field}");
    let nanos = parse_caddy_duration(value)
        .map_err(|message| CoreError::invalid(&path, format!("invalid duration: {message}")))?;
    Ok(if nanos > 0 {
        Some(Duration::from_nanos(nanos as u64))
    } else {
        None
    })
}

/// Read one caddy-rs extension field from the preserved unknown-field map.
///
/// `0` means "feature disabled" and is normalized to `None`, matching the "absent means
/// unlimited" wording in the divergence register.
fn extra_size(
    extra: &BTreeMap<String, Value>,
    base: &str,
    field: &str,
    unit: &str,
) -> Result<Option<u64>, CoreError> {
    let Some(value) = extra.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(count) = value.as_u64() else {
        return Err(CoreError::invalid(
            format!("{base}.{field}"),
            format!("`{field}` must be a non-negative integer {unit}, got {value}"),
        ));
    };
    Ok(if count == 0 { None } else { Some(count) })
}

/// Parse a Caddy `caddy.Duration` JSON value.
///
/// Accepted forms match Caddy's `Duration.UnmarshalJSON`:
///
/// * a JSON integer, interpreted as nanoseconds (Caddy's canonical serialization), and
/// * a string in Go duration syntax, with Caddy's extra `d` (day) unit: `"250ms"`, `"5s"`,
///   `"1m30s"`, `"1.5h"`, `"2d"`, `"1d12h"`.
///
/// Returns a signed count of nanoseconds. Negative durations parse successfully (Caddy allows
/// them in JSON) and are treated as "disabled" by [`ServerLimits`].
pub fn parse_caddy_duration(value: &Value) -> Result<i64, String> {
    match value {
        Value::Number(number) => {
            if let Some(nanos) = number.as_i64() {
                Ok(nanos)
            } else if let Some(unsigned) = number.as_u64() {
                i64::try_from(unsigned).map_err(|_| {
                    format!("{unsigned} nanoseconds does not fit in a signed 64-bit count")
                })
            } else {
                Err(format!(
                    "expected an integer number of nanoseconds, got the non-integer number {number}"
                ))
            }
        }
        Value::String(string) => parse_duration_string(string),
        other => Err(format!(
            "expected a duration string or an integer number of nanoseconds, got {}",
            json_kind(other)
        )),
    }
}

/// Parse a Go-style duration string (plus Caddy's `d` unit) into signed nanoseconds.
pub fn parse_duration_string(input: &str) -> Result<i64, String> {
    if input.len() > 1024 {
        return Err("duration string is longer than 1024 bytes".to_string());
    }
    let (negative, rest) = match input.as_bytes().first() {
        Some(b'-') => (true, &input[1..]),
        Some(b'+') => (false, &input[1..]),
        _ => (false, input),
    };
    if rest.is_empty() {
        return Err(format!("invalid duration {input:?}: empty"));
    }
    // Go accepts a bare "0" (after an optional sign) with no unit.
    if rest == "0" {
        return Ok(0);
    }
    let bytes = rest.as_bytes();
    let mut total: u128 = 0;
    let mut index = 0;
    while index < bytes.len() {
        let integer_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let integer_digits = &rest[integer_start..index];
        let mut fraction = 0.0_f64;
        let mut has_digits = !integer_digits.is_empty();
        if index < bytes.len() && bytes[index] == b'.' {
            index += 1;
            let fraction_start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            let fraction_digits = &rest[fraction_start..index];
            // Go's `time.ParseDuration` accepts "1.h" (empty fraction), so only the absence of
            // *all* digits is invalid.
            if !fraction_digits.is_empty() {
                fraction = fraction_digits.parse::<f64>().unwrap_or(0.0)
                    / 10.0_f64.powi(fraction_digits.len() as i32);
                has_digits = true;
            }
        }
        if !has_digits {
            return Err(format!("invalid duration {input:?}: expected a number"));
        }
        let unit_start = index;
        while index < bytes.len() && !bytes[index].is_ascii_digit() && bytes[index] != b'.' {
            index += 1;
        }
        let unit = &rest[unit_start..index];
        if unit.is_empty() {
            return Err(format!(
                "invalid duration {input:?}: missing unit in duration (for example \"5s\")"
            ));
        }
        let Some(unit_nanos) = duration_unit(unit) else {
            return Err(format!("invalid duration {input:?}: unknown unit {unit:?}"));
        };
        let integer_part = if integer_digits.is_empty() {
            0_u128
        } else {
            integer_digits
                .parse::<u128>()
                .map_err(|_| format!("invalid duration {input:?}: number is too large"))?
        };
        let component = integer_part
            .checked_mul(unit_nanos)
            .and_then(|value| value.checked_add((fraction * unit_nanos as f64) as u128))
            .ok_or_else(|| format!("invalid duration {input:?}: duration overflows"))?;
        total = total
            .checked_add(component)
            .ok_or_else(|| format!("invalid duration {input:?}: duration overflows"))?;
        if total > i64::MAX as u128 {
            return Err(format!(
                "invalid duration {input:?}: duration overflows 64-bit nanoseconds"
            ));
        }
    }
    let total = total as i64;
    Ok(if negative { -total } else { total })
}

/// Nanoseconds per unit for the units Caddy accepts.
fn duration_unit(unit: &str) -> Option<u128> {
    match unit {
        "ns" => Some(1),
        "us" | "µs" | "μs" => Some(1_000),
        "ms" => Some(1_000_000),
        "s" => Some(1_000_000_000),
        "m" => Some(60_000_000_000),
        "h" => Some(3_600_000_000_000),
        // Caddy adds a day unit, defined as exactly 24 hours.
        "d" => Some(86_400_000_000_000),
        _ => None,
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nanos(value: Value) -> Result<i64, String> {
        parse_caddy_duration(&value)
    }

    #[test]
    fn parses_duration_strings_like_caddy() {
        let cases = [
            ("5s", 5_000_000_000),
            ("1m30s", 90_000_000_000),
            ("1.5h", 5_400_000_000_000),
            ("250ms", 250_000_000),
            ("1µs", 1_000),
            ("2d", 172_800_000_000_000),
            ("1d12h", 129_600_000_000_000),
            ("+5s", 5_000_000_000),
            ("-5s", -5_000_000_000),
            ("0", 0),
            (".5h", 1_800_000_000_000),
            ("1.h", 3_600_000_000_000),
        ];
        for (input, expected) in cases {
            assert_eq!(
                parse_duration_string(input),
                Ok(expected),
                "duration string {input:?}"
            );
        }
    }

    #[test]
    fn parses_caddy_integer_nanoseconds() {
        assert_eq!(nanos(json!(5_000_000_000_i64)), Ok(5_000_000_000));
        assert_eq!(nanos(json!(0)), Ok(0));
        assert_eq!(nanos(json!(-1_000_000_000_i64)), Ok(-1_000_000_000));
    }

    #[test]
    fn rejects_malformed_durations() {
        for value in [
            json!(""),
            json!("abc"),
            json!("5"),
            json!("1h 30m"),
            json!("1.2.3h"),
            json!(".h"),
            json!("5 s"),
            json!("s5"),
            json!("1x"),
            json!(1.5),
            json!(true),
            json!({}),
            json!([]),
        ] {
            assert!(
                parse_caddy_duration(&value).is_err(),
                "duration {value} must be rejected"
            );
        }
        assert!(parse_duration_string(&"9".repeat(1025)).is_err());
        assert!(parse_duration_string("99999999999999999999h").is_err());
    }

    fn parse_limits(server: Value) -> Result<ServerLimits, CoreError> {
        let server: HttpServer = serde_json::from_value(server).expect("server decodes");
        ServerLimits::from_http_server("srv0", &server)
    }

    #[test]
    fn parses_caddy_timeout_fields_and_defaults() {
        let limits = parse_limits(json!({
            "listen": [":80"],
            "read_timeout": "5s",
            "write_timeout": 2_000_000_000_i64,
            "idle_timeout": "1m"
        }))
        .unwrap();
        assert_eq!(limits.read_timeout, Some(Duration::from_secs(5)));
        assert_eq!(limits.write_timeout, Some(Duration::from_secs(2)));
        assert_eq!(limits.idle_timeout, Duration::from_secs(60));
        assert_eq!(
            limits.read_header_timeout,
            Duration::from_secs(60),
            "Caddy's read_header_timeout default is 1 minute"
        );

        let defaults = parse_limits(json!({"listen": [":80"]})).unwrap();
        assert_eq!(defaults.read_timeout, None);
        assert_eq!(defaults.write_timeout, None);
        assert_eq!(
            defaults.idle_timeout,
            Duration::from_secs(5 * 60),
            "Caddy's idle_timeout default is 5 minutes"
        );
        assert_eq!(defaults.max_request_body_size, None);
        assert_eq!(defaults.max_connections, None);
    }

    #[test]
    fn zero_and_negative_timeouts_disable_the_limit() {
        let limits = parse_limits(json!({
            "listen": [":80"],
            "read_timeout": 0,
            "write_timeout": "-5s",
            "idle_timeout": "0s"
        }))
        .unwrap();
        assert_eq!(limits.read_timeout, None);
        assert_eq!(limits.write_timeout, None);
        assert_eq!(
            limits.idle_timeout, DEFAULT_IDLE_TIMEOUT,
            "a zero idle timeout means Caddy's default, not 'disabled'"
        );
    }

    #[test]
    fn parses_hardening_extensions() {
        let limits = parse_limits(json!({
            "listen": [":80"],
            "max_request_body_size": 1024,
            "max_connections": 7,
            "max_header_bytes": 8192,
            "read_header_timeout": "2s"
        }))
        .unwrap();
        assert_eq!(limits.max_request_body_size, Some(1024));
        assert_eq!(limits.max_connections, Some(7));
        assert_eq!(limits.max_header_bytes, Some(8192));
        assert_eq!(limits.read_header_timeout, Duration::from_secs(2));
    }

    #[test]
    fn rejects_malformed_limits_with_located_paths() {
        let error = parse_limits(json!({"listen": [":80"], "read_timeout": "soon"}))
            .expect_err("malformed read_timeout must fail");
        let message = error.to_string();
        assert!(
            message.contains("apps.http.servers.srv0.read_timeout"),
            "error must name the field: {message}"
        );

        let error = parse_limits(json!({"listen": [":80"], "max_request_body_size": "1MiB"}))
            .expect_err("non-integer body limit must fail");
        let message = error.to_string();
        assert!(
            message.contains("apps.http.servers.srv0.max_request_body_size"),
            "error must name the field: {message}"
        );

        let error = parse_limits(json!({"listen": [":80"], "max_connections": -1}))
            .expect_err("negative connection limit must fail");
        assert!(error
            .to_string()
            .contains("apps.http.servers.srv0.max_connections"));
    }
}
