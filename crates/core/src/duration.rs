//! Caddy `Duration` values (`caddy.Duration`).
//!
//! Caddy marshals a `caddy.Duration` as an integer number of nanoseconds in JSON, but accepts a Go
//! duration string (`"5s"`, `"1m30s"`, `"250ms"`, `"2h45m"`) when unmarshalling. This module
//! mirrors that behaviour for the typed configuration fields (for example
//! `apps.http.grace_period` and `apps.http.shutdown_delay`) so invalid durations fail configuration
//! decoding with a located error instead of being accepted as opaque JSON.

use std::fmt;
use std::time::Duration;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A Caddy `Duration`: an integer number of nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CaddyDuration(u64);

impl CaddyDuration {
    /// Construct from a number of nanoseconds.
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Construct from a [`Duration`], saturating at `u64::MAX` nanoseconds.
    pub fn from_duration(duration: Duration) -> Self {
        Self(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
    }

    /// The value in nanoseconds.
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Convert to a [`Duration`].
    pub fn as_duration(self) -> Duration {
        Duration::from_nanos(self.0)
    }

    /// Whether the duration is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl From<Duration> for CaddyDuration {
    fn from(value: Duration) -> Self {
        Self::from_duration(value)
    }
}

impl From<CaddyDuration> for Duration {
    fn from(value: CaddyDuration) -> Self {
        value.as_duration()
    }
}

impl fmt::Display for CaddyDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ns", self.0)
    }
}

impl Serialize for CaddyDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

struct CaddyDurationVisitor;

impl<'de> Visitor<'de> for CaddyDurationVisitor {
    type Value = CaddyDuration;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Caddy duration string (for example \"5s\") or integer nanoseconds")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(CaddyDuration(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        if value < 0 {
            return Err(E::custom("Caddy duration must not be negative"));
        }
        Ok(CaddyDuration(value as u64))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        parse_caddy_duration(value).map_err(E::custom)
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.visit_str(&value)
    }
}

impl<'de> Deserialize<'de> for CaddyDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CaddyDurationVisitor)
    }
}

/// Parse a Go-style duration string into nanoseconds.
///
/// Supported units: `ns`, `us`, `µs`, `μs`, `ms`, `s`, `m`, `h`. Only non-negative values are
/// accepted because Caddy's duration-bearing configuration fields are non-negative.
pub fn parse_caddy_duration(input: &str) -> Result<CaddyDuration, String> {
    let text = input.trim();
    if text.is_empty() {
        return Err("duration string is empty".to_string());
    }
    if text == "0" {
        return Ok(CaddyDuration(0));
    }
    if text.starts_with('-') {
        return Err(format!("duration `{input}` must not be negative"));
    }

    let mut total_nanos: u128 = 0;
    let mut rest = text;
    let mut parsed_any = false;
    while !rest.is_empty() {
        let digit_end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if digit_end == 0 {
            return Err(format!("duration `{input}` is missing a number"));
        }
        let number = &rest[..digit_end];
        if number.matches('.').count() > 1 {
            return Err(format!(
                "duration `{input}` has an invalid number `{number}`"
            ));
        }
        let value: f64 = number
            .parse()
            .map_err(|_| format!("duration `{input}` has an invalid number `{number}`"))?;
        rest = &rest[digit_end..];

        let (unit_nanos, unit_len) = if rest.starts_with("ns") {
            (1u128, 2)
        } else if rest.starts_with("us") || rest.starts_with("µs") || rest.starts_with("μs") {
            (1_000u128, 2)
        } else if rest.starts_with("ms") {
            (1_000_000u128, 2)
        } else if rest.starts_with('s') {
            (1_000_000_000u128, 1)
        } else if rest.starts_with('m') {
            (60 * 1_000_000_000u128, 1)
        } else if rest.starts_with('h') {
            (3_600 * 1_000_000_000u128, 1)
        } else {
            return Err(format!(
                "duration `{input}` has an unknown unit; use ns, us, µs, ms, s, m or h"
            ));
        };
        total_nanos = total_nanos
            .checked_add((value * unit_nanos as f64).round() as u128)
            .ok_or_else(|| format!("duration `{input}` is too large"))?;
        rest = &rest[unit_len..];
        parsed_any = true;
    }
    if !parsed_any {
        return Err(format!("duration `{input}` is missing a unit"));
    }
    let nanos =
        u64::try_from(total_nanos).map_err(|_| format!("duration `{input}` is too large"))?;
    Ok(CaddyDuration(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_duration_units() {
        assert_eq!(
            parse_caddy_duration("5s").unwrap().as_nanos(),
            5_000_000_000
        );
        assert_eq!(
            parse_caddy_duration("250ms").unwrap().as_nanos(),
            250_000_000
        );
        assert_eq!(
            parse_caddy_duration("1500us").unwrap().as_nanos(),
            1_500_000
        );
        assert_eq!(
            parse_caddy_duration("1m30s").unwrap().as_nanos(),
            90_000_000_000
        );
        assert_eq!(
            parse_caddy_duration("2h").unwrap().as_nanos(),
            7_200_000_000_000
        );
        assert_eq!(
            parse_caddy_duration("1.5s").unwrap().as_nanos(),
            1_500_000_000
        );
        assert_eq!(parse_caddy_duration("0").unwrap().as_nanos(), 0);
    }

    #[test]
    fn rejects_invalid_durations() {
        for input in ["", "5", "s", "5x", "-1s", "5s5", "1.2.3s", "5 s"] {
            assert!(
                parse_caddy_duration(input).is_err(),
                "duration {input:?} must be rejected"
            );
        }
    }

    #[test]
    fn serde_accepts_string_or_nanoseconds_and_serializes_nanoseconds() {
        let string: CaddyDuration = serde_json::from_value(serde_json::json!("5s")).unwrap();
        assert_eq!(string.as_nanos(), 5_000_000_000);
        let number: CaddyDuration =
            serde_json::from_value(serde_json::json!(5_000_000_000u64)).unwrap();
        assert_eq!(number, string);
        assert_eq!(
            serde_json::to_value(string).unwrap(),
            serde_json::json!(5_000_000_000u64)
        );
    }

    #[test]
    fn serde_rejects_invalid_strings_and_negative_numbers() {
        assert!(serde_json::from_value::<CaddyDuration>(serde_json::json!("soon")).is_err());
        assert!(serde_json::from_value::<CaddyDuration>(serde_json::json!(-1)).is_err());
    }
}
