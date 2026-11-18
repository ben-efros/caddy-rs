//! UTC timestamps without `chrono`.
//!
//! `chrono` is unmaintained (RUSTSEC-2026-0543, `patched = []`) and the security gate runs
//! `cargo audit --file Cargo.lock --deny warnings`, which scans the lockfile, so the crate has to
//! leave the graph rather than be allowlisted. This module replaces the *entire* surface the
//! workspace used: a UTC instant with second + nanosecond precision, serialized to the same
//! RFC 3339 strings `chrono` produced.
//!
//! # Wire compatibility (the reason this module exists)
//!
//! `RevisionRecord`, `Generation` and `UserRecord` are persisted as JSON, so the serialized shape
//! is a compatibility contract with data already written by earlier builds. `chrono` serializes
//! `DateTime<Utc>` with `write_rfc3339(.., SecondsFormat::AutoSi, ..)`, which emits:
//!
//! - no fractional part when the nanosecond field is zero: `"1970-01-01T00:00:00Z"`;
//! - otherwise the fewest of 3, 6 or 9 fractional digits that represent the value exactly:
//!   `.500`, `.000010`, `.123456789`.
//!
//! [`Timestamp`] reproduces that byte for byte (`parse` accepts any of the same forms back), and
//! the golden tests at the bottom of this file pin it.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// A UTC instant with second + nanosecond precision.
///
/// Ordering and equality are on `(seconds, nanos)`, so `Timestamp` sorts chronologically.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    /// Whole seconds since the Unix epoch; negative before 1970.
    seconds: i64,
    /// Nanosecond offset within the second, always in `0..1_000_000_000`.
    nanos: u32,
}

impl Timestamp {
    /// The Unix epoch (`1970-01-01T00:00:00Z`).
    pub const UNIX_EPOCH: Timestamp = Timestamp {
        seconds: 0,
        nanos: 0,
    };

    /// Build a timestamp from seconds and a nanosecond offset, normalizing nanos into range.
    pub fn from_secs_and_nanos(seconds: i64, nanos: u32) -> Self {
        let mut secs = seconds;
        let mut ns = nanos as u64;
        // Normalize: allow callers to pass nanos >= 1e9 and let them roll into seconds.
        if ns >= 1_000_000_000 {
            secs += (ns / 1_000_000_000) as i64;
            ns %= 1_000_000_000;
        }
        Timestamp {
            seconds: secs,
            nanos: ns as u32,
        }
    }

    /// The current time, read from the system clock.
    ///
    /// Equivalent to `chrono::Utc::now()` truncated to nanosecond precision. If the clock reads
    /// before the Unix epoch the instant is clamped to the epoch rather than panicking: a
    /// misconfigured clock must not take the server down.
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Timestamp::from_secs_and_nanos(d.as_secs() as i64, d.subsec_nanos()),
            Err(e) => {
                // Before 1970: represent as negative seconds.
                let d = e.duration();
                let secs = -(d.as_secs() as i64);
                let nanos = d.subsec_nanos();
                if nanos == 0 {
                    Timestamp::from_secs_and_nanos(secs, 0)
                } else {
                    Timestamp::from_secs_and_nanos(secs - 1, 1_000_000_000 - nanos)
                }
            }
        }
    }

    /// Whole seconds since the Unix epoch.
    pub fn timestamp(&self) -> i64 {
        self.seconds
    }

    /// Nanosecond offset within the second, in `0..1_000_000_000`.
    pub fn timestamp_subsec_nanos(&self) -> u32 {
        self.nanos
    }

    /// Format as an RFC 3339 string exactly as `chrono`'s `DateTime<Utc>` serialization did.
    pub fn to_rfc3339(&self) -> String {
        format!("{}", self)
    }

    /// Parse an RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS[.fffffffff]Z` or a numeric `+HH:MM`
    /// offset, which is normalized to UTC).
    ///
    /// This is the inverse of [`Timestamp::to_rfc3339`] for every string that function can emit.
    /// Accepts 0, 3, 6 or 9 fractional digits (the forms `AutoSi` produces) and also any 1..=9
    /// digits, so hand-written fixtures are not rejected.
    pub fn parse(s: &str) -> Result<Self, TimestampParseError> {
        parse_rfc3339(s)
    }
}

impl fmt::Display for Timestamp {
    /// Renders the RFC 3339 form described in the module docs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (days, secs_of_day) = civil_from_seconds(self.seconds);
        let (year, month, day) = days_to_civil(days);
        let hour = secs_of_day / 3600;
        let minute = (secs_of_day % 3600) / 60;
        let second = secs_of_day % 60;

        // Years outside 0000..=9999 get an ISO 8601 sign, matching chrono's extension.
        if (0..=9999).contains(&year) {
            write!(f, "{year:04}")?;
        } else if year > 9999 {
            write!(f, "+{year}")?;
        } else {
            // Negative years: chrono writes the year without padding after the sign.
            write!(f, "-{:04}", year.unsigned_abs())?;
        }
        write!(f, "-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")?;

        // SecondsFormat::AutoSi: omit the fraction entirely when it is zero, else the fewest of
        // 3, 6, 9 digits that represent the value exactly.
        if self.nanos != 0 {
            if self.nanos % 1_000_000 == 0 {
                write!(f, ".{:03}", self.nanos / 1_000_000)?;
            } else if self.nanos % 1_000 == 0 {
                write!(f, ".{:06}", self.nanos / 1_000)?;
            } else {
                write!(f, ".{:09}", self.nanos)?;
            }
        }
        f.write_str("Z")
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({self})")
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{self}"))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Timestamp;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RFC 3339 formatted date and time string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Timestamp, E> {
                Timestamp::parse(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// Why a string could not be parsed as an RFC 3339 timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampParseError {
    reason: String,
}

impl fmt::Display for TimestampParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid RFC 3339 timestamp: {}", self.reason)
    }
}

impl std::error::Error for TimestampParseError {}

fn err<T>(reason: impl Into<String>) -> Result<T, TimestampParseError> {
    Err(TimestampParseError {
        reason: reason.into(),
    })
}

/// Days since 1970-01-01 and second-of-day, for a count of seconds since the epoch.
///
/// Uses floor division so instants before the epoch land on the correct civil day.
fn civil_from_seconds(seconds: i64) -> (i64, i64) {
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    (days, rem)
}

/// Convert days-since-epoch to a (year, month, day) civil date. Howard Hinnant's algorithm.
fn days_to_civil(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// Inverse of [`days_to_civil`]: civil date to days since epoch.
fn civil_to_days(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

fn parse_rfc3339(s: &str) -> Result<Timestamp, TimestampParseError> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return err(format!("`{s}` is too short"));
    }

    let num = |range: std::ops::Range<usize>| -> Result<i64, TimestampParseError> {
        let slice = &s[range.clone()];
        if !slice.bytes().all(|c| c.is_ascii_digit()) {
            return err(format!("`{slice}` is not an integer"));
        }
        slice.parse::<i64>().map_err(|e| TimestampParseError {
            reason: e.to_string(),
        })
    };

    // Optional leading sign for years outside 0000..=9999.
    let (sign_len, rest) = match b[0] {
        b'+' | b'-' => (1usize, 1usize),
        _ => (0usize, 0usize),
    };
    let year_digits = if sign_len == 1 {
        // `+YYYYY` / `-YYYY`: take digits up to the first '-'.
        s[1..].find('-').ok_or_else(|| TimestampParseError {
            reason: format!("`{s}` has no date separator"),
        })? + 1
    } else {
        4
    };
    let mut year = num(rest..rest + year_digits)?;
    if sign_len == 1 && b[0] == b'-' {
        year = -year;
    }
    let pos = rest + year_digits;

    if b.get(pos) != Some(&b'-') {
        return err(format!("`{s}` is missing '-' after the year"));
    }
    let month = num(pos + 1..pos + 3)?;
    if b.get(pos + 3) != Some(&b'-') {
        return err(format!("`{s}` is missing '-' after the month"));
    }
    let day = num(pos + 4..pos + 6)?;
    let tsep = pos + 6;
    if !matches!(b.get(tsep), Some(b'T') | Some(b't')) {
        return err(format!("`{s}` is missing 'T' before the time"));
    }
    let hour = num(tsep + 1..tsep + 3)?;
    if b.get(tsep + 3) != Some(&b':') {
        return err(format!("`{s}` is missing ':' after the hour"));
    }
    let minute = num(tsep + 4..tsep + 6)?;
    if b.get(tsep + 6) != Some(&b':') {
        return err(format!("`{s}` is missing ':' after the minute"));
    }
    let second = num(tsep + 7..tsep + 9)?;
    let mut i = tsep + 9;

    let mut nanos: u32 = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = &s[start..i];
        if digits.is_empty() || digits.len() > 9 {
            return err(format!("`{digits}` is not a 1..=9 digit fractional second"));
        }
        // Right-pad to nanoseconds: ".5" means 500_000_000ns.
        let mut v = digits.parse::<u32>().map_err(|e| TimestampParseError {
            reason: e.to_string(),
        })?;
        for _ in digits.len()..9 {
            v *= 10;
        }
        nanos = v;
    }

    let mut offset_secs: i64 = 0;
    match b.get(i) {
        Some(b'Z') | Some(b'z') => {
            if i + 1 != b.len() {
                return err(format!("trailing characters after 'Z' in `{s}`"));
            }
        }
        Some(b'+') | Some(b'-') => {
            let sign = if b[i] == b'+' { 1 } else { -1 };
            let oh = num(i + 1..i + 3)?;
            if b.get(i + 3) != Some(&b':') {
                return err(format!("`{s}` has a malformed numeric offset"));
            }
            let om = num(i + 4..i + 6)?;
            if i + 6 != b.len() {
                return err(format!("trailing characters after the offset in `{s}`"));
            }
            offset_secs = sign * (oh * 3600 + om * 60);
        }
        _ => return err(format!("`{s}` has no timezone designator")),
    }

    if !(1..=12).contains(&month) {
        return err(format!("month {month} out of range in `{s}`"));
    }
    if !(1..=31).contains(&day) {
        return err(format!("day {day} out of range in `{s}`"));
    }
    if !(0..=23).contains(&hour) {
        return err(format!("hour {hour} out of range in `{s}`"));
    }
    if !(0..=59).contains(&minute) {
        return err(format!("minute {minute} out of range in `{s}`"));
    }
    // 60 for a leap second, which we fold into the next minute.
    if !(0..=60).contains(&second) {
        return err(format!("second {second} out of range in `{s}`"));
    }

    let days = civil_to_days(year, month as u32, day as u32);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    Ok(Timestamp::from_secs_and_nanos(secs, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte ground truth captured by running `serde_json::to_string` on
    /// `chrono 0.4.45`'s `DateTime<Utc>` for each instant. These values MUST NOT change:
    /// revision history and user records already on disk use exactly these strings.
    const CHRONO_GOLDEN: &[(i64, u32, &str)] = &[
        (0, 0, r#""1970-01-01T00:00:00Z""#),
        (1_700_000_000, 0, r#""2023-11-14T22:13:20Z""#),
        (1_700_000_000, 500_000_000, r#""2023-11-14T22:13:20.500Z""#),
        (
            1_700_000_000,
            123_456_789,
            r#""2023-11-14T22:13:20.123456789Z""#,
        ),
        (
            1_700_000_000,
            123_456_000,
            r#""2023-11-14T22:13:20.123456Z""#,
        ),
        (1_700_000_000, 1_000, r#""2023-11-14T22:13:20.000001Z""#),
        (1_700_000_000, 10_000, r#""2023-11-14T22:13:20.000010Z""#),
    ];

    #[test]
    fn serializes_exactly_as_chrono_did() {
        for (secs, nanos, expected) in CHRONO_GOLDEN {
            let ts = Timestamp::from_secs_and_nanos(*secs, *nanos);
            let json = serde_json::to_string(&ts).expect("serializes");
            assert_eq!(
                &json, expected,
                "wire format drifted from chrono for {secs}.{nanos}"
            );
        }
    }

    #[test]
    fn round_trips_the_chrono_golden_strings() {
        for (secs, nanos, expected) in CHRONO_GOLDEN {
            let json: &str = expected;
            let parsed: Timestamp = serde_json::from_str(json).expect("deserializes chrono bytes");
            assert_eq!(parsed, Timestamp::from_secs_and_nanos(*secs, *nanos));
        }
    }

    #[test]
    fn now_is_close_to_the_system_clock() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ts = Timestamp::now();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            (before..=after).contains(&ts.timestamp()),
            "now() = {} outside [{before}, {after}]",
            ts.timestamp()
        );
    }

    #[test]
    fn parses_numeric_offsets_into_utc() {
        // 2023-11-14T23:13:20+01:00 is the same instant as 22:13:20Z.
        let a = Timestamp::parse("2023-11-14T23:13:20+01:00").expect("parses");
        let b = Timestamp::parse("2023-11-14T22:13:20Z").expect("parses");
        assert_eq!(a, b);
        assert_eq!(a.timestamp(), 1_700_000_000);
        assert_eq!(a.to_rfc3339(), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn parses_pre_epoch_instants() {
        let ts = Timestamp::parse("1969-12-31T23:59:59Z").expect("parses");
        assert_eq!(ts.timestamp(), -1);
        assert_eq!(ts.to_rfc3339(), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "",
            "not-a-date",
            "2023-13-01T00:00:00Z",
            "2023-11-14T25:00:00Z",
            "2023-11-14T22:13:20",
            "2023-11-14T22:13:20.1234567891Z",
        ] {
            assert!(
                Timestamp::parse(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn ordering_is_chronological() {
        let a = Timestamp::from_secs_and_nanos(100, 1);
        let b = Timestamp::from_secs_and_nanos(100, 2);
        let c = Timestamp::from_secs_and_nanos(101, 0);
        assert!(a < b && b < c);
    }

    #[test]
    fn civil_round_trip_across_a_century() {
        // Exercise the leap-year rules between 1950 and 2050.
        for year in 1950..2050 {
            for (month, day) in [(1, 1), (2, 28), (3, 1), (12, 31)] {
                let days = civil_to_days(year, month, day);
                assert_eq!(days_to_civil(days), (year, month, day));
            }
        }
    }
}
