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

/// A Caddy `Duration` that may be negative.
///
/// Caddy's `grace_period` and `shutdown_delay` are plain `caddy.Duration` values, and its runtime
/// tests them with `> 0`, so a negative value is accepted and means "no limit" — an eternal grace
/// period or no shutdown delay (`modules/caddyhttp/app.go` 731, 757). [`CaddyDuration`] cannot
/// represent that, so those two fields use this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CaddySignedDuration(i64);

impl CaddySignedDuration {
    /// Construct from a number of nanoseconds, which may be negative.
    pub const fn from_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    /// The value in nanoseconds (may be negative).
    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    /// Caddy's runtime treats any non-positive value as "unset".
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }
}

impl std::fmt::Display for CaddySignedDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ns", self.0)
    }
}

impl Serialize for CaddySignedDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.0)
    }
}

struct CaddySignedDurationVisitor;

impl<'de> Visitor<'de> for CaddySignedDurationVisitor {
    type Value = CaddySignedDuration;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Caddy duration string (for example \"-1s\") or integer nanoseconds")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(CaddySignedDuration(value as i64))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(CaddySignedDuration(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        parse_caddy_signed_duration(value).map_err(E::custom)
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.visit_str(&value)
    }
}

impl<'de> Deserialize<'de> for CaddySignedDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CaddySignedDurationVisitor)
    }
}

/// Parse a Go-style duration string that may be negative (`"-1s"`, `"-1"`).
pub fn parse_caddy_signed_duration(input: &str) -> Result<CaddySignedDuration, String> {
    let text = input.trim();
    if let Some(rest) = text.strip_prefix('-') {
        let inner = parse_caddy_duration(rest)?;
        let nanos =
            i64::try_from(inner.as_nanos()).map_err(|_| format!("duration `{input}` overflows"))?;
        return Ok(CaddySignedDuration(-nanos));
    }
    let inner = parse_caddy_duration(text)?;
    let nanos =
        i64::try_from(inner.as_nanos()).map_err(|_| format!("duration `{input}` overflows"))?;
    Ok(CaddySignedDuration(nanos))
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

        // The consumed length must come from the matched unit itself: `µs` and `μs` are three
        // bytes (a two-byte rune plus `s`), so a hard-coded length left a trailing `s` in `rest`
        // and reported the misleading "missing a number" for a valid microsecond duration.
        // Two-byte units are listed before their one-byte prefixes (`ms` before `s`/`m`).
        const UNITS: [(&str, u128); 8] = [
            ("ns", 1),
            ("us", 1_000),
            ("µs", 1_000),
            ("μs", 1_000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60 * 1_000_000_000),
            ("h", 3_600 * 1_000_000_000),
        ];
        let Some((unit, unit_nanos)) = UNITS.iter().find(|(unit, _)| rest.starts_with(unit)) else {
            return Err(format!(
                "duration `{input}` has an unknown unit; use ns, us, µs, μs, ms, s, m or h"
            ));
        };
        // `unit` was matched with `starts_with`, so this is always a `char` boundary.
        let unit_len = unit.len();
        total_nanos = total_nanos
            .checked_add((value * *unit_nanos as f64).round() as u128)
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

/// Parse a Caddy `caddy.Duration` JSON value into signed nanoseconds.
///
/// This is the signed counterpart of [`parse_caddy_duration`] used by load-time validation of
/// HTTP server timeout fields: Caddy's `Duration.UnmarshalJSON` accepts integer nanoseconds,
/// negative integers and Go duration strings (including the extra `d` day unit), and the server
/// provisioning code treats non-positive values as "disabled". Validation only rejects values
/// that Caddy's JSON decoding itself would reject.
pub fn parse_caddy_duration_json(value: &serde_json::Value) -> Result<i64, String> {
    match value {
        serde_json::Value::Number(number) => {
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
        serde_json::Value::String(string) => parse_caddy_duration_string(string),
        other => Err(format!(
            "expected a duration string or an integer number of nanoseconds, got {}",
            json_kind(other)
        )),
    }
}

/// Parse a Go-style duration string (plus Caddy's `d` unit) into signed nanoseconds.
pub fn parse_caddy_duration_string(input: &str) -> Result<i64, String> {
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

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
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
    fn parses_every_microsecond_spelling() {
        // `us` is two bytes; `µs` (U+00B5) and `μs` (U+03BC) are three. All three must parse to
        // the same value; the multibyte spellings used to fail with "missing a number".
        for input in ["5us", "5µs", "5μs"] {
            assert_eq!(
                parse_caddy_duration(input).unwrap().as_nanos(),
                5_000,
                "duration {input:?} must parse as 5 microseconds"
            );
            assert_eq!(
                serde_json::from_value::<CaddyDuration>(serde_json::json!(input))
                    .unwrap()
                    .as_nanos(),
                5_000,
                "serde path must accept {input:?}"
            );
        }
    }

    #[test]
    fn multibyte_microsecond_spellings_are_equivalent() {
        let micro_sign = parse_caddy_duration("250\u{00B5}s").unwrap();
        let greek_mu = parse_caddy_duration("250\u{03BC}s").unwrap();
        let ascii = parse_caddy_duration("250us").unwrap();
        assert_eq!(micro_sign, greek_mu);
        assert_eq!(micro_sign, ascii);
        assert_eq!(micro_sign.as_nanos(), 250_000);
        // Compound components mixing the spellings stay consistent too.
        assert_eq!(
            parse_caddy_duration("1µs500μs").unwrap().as_nanos(),
            501_000
        );
    }

    #[test]
    fn unit_values_are_exact() {
        for (input, expected) in [
            ("5ms", 5_000_000),
            ("5s", 5_000_000_000),
            ("5m", 300_000_000_000),
            ("5h", 18_000_000_000_000),
            ("5ns", 5),
        ] {
            assert_eq!(
                parse_caddy_duration(input).unwrap().as_nanos(),
                expected,
                "duration {input:?}"
            );
        }
        // This parser's documented grammar has no day unit; only the Caddyfile/Go parser adds `d`.
        assert!(parse_caddy_duration("5d").is_err());
    }

    #[test]
    fn rejects_malformed_durations_without_panicking() {
        let very_long = format!("{}h", "9".repeat(100_000));
        for input in [
            "",
            " ",
            "5",
            "5u",
            "5uss",
            "µ",
            "μ",
            "5µ",
            "5μ",
            "us",
            "µs",
            "s",
            "5 s",
            "1.2.3s",
            "5x",
            "-1s",
            "18446744073709551616s",
            "999999999999999999999999999999h",
            very_long.as_str(),
        ] {
            assert!(
                parse_caddy_duration(input).is_err(),
                "duration {input:?} must be rejected"
            );
        }
        // A truncated multibyte unit must not be accepted either.
        assert!(parse_caddy_duration("5\u{00B5}").is_err());
        assert!(parse_caddy_duration("5\u{03BC}").is_err());
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
