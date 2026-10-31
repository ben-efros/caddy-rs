//! Minimal offline build of the `httpdate` crate surface used by `hyper`.
//!
//! Upstream crate: <https://crates.io/crates/httpdate> (MIT OR Apache-2.0).
//! The network sandbox for this build cannot fetch crates, so this vendored copy implements
//! the subset hyper actually uses: `HttpDate` with `Display` and `From<SystemTime>`, plus
//! IMF-fixdate parsing/formatting helpers. It is replaced by the upstream crate when online.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// An HTTP date, rendered as an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpDate(SystemTime);

impl HttpDate {
    pub fn from_system_time(t: SystemTime) -> Self {
        HttpDate(t)
    }
    pub fn into_system_time(self) -> SystemTime {
        self.0
    }
}

impl From<SystemTime> for HttpDate {
    fn from(t: SystemTime) -> Self {
        HttpDate(t)
    }
}

impl From<HttpDate> for SystemTime {
    fn from(d: HttpDate) -> Self {
        d.0
    }
}

impl fmt::Display for HttpDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dur = self.0.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
        let secs = dur.as_secs() as i64;
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let weekday = (days + 4).rem_euclid(7) as usize;
        write!(
            f,
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
            DAYS[weekday],
            day,
            MONTHS[(month - 1) as usize],
            year,
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    }
}

/// Format a `SystemTime` as an IMF-fixdate.
pub fn fmt_http_date(t: SystemTime) -> String {
    HttpDate(t).to_string()
}

fn parse_imf(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() != 29 {
        return None;
    }
    let day: u32 = s.get(5..7)?.parse().ok()?;
    let mon_str = s.get(8..11)?;
    let mon = MONTHS.iter().position(|m| *m == mon_str)? as u32 + 1;
    let year: i64 = s.get(12..16)?.parse().ok()?;
    let hour: u64 = s.get(17..19)?.parse().ok()?;
    let min: u64 = s.get(20..22)?.parse().ok()?;
    let sec: u64 = s.get(23..25)?.parse().ok()?;
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let secs = days_from_civil(year, mon, day) * 86_400 + (hour * 3600 + min * 60 + sec) as i64;
    if secs < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// Parse an IMF-fixdate. Returns `None` for unrecognised formats.
pub fn parse_http_date(s: &str) -> Option<SystemTime> {
    parse_imf(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_rfc_example() {
        let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(fmt_http_date(t), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn round_trips() {
        let t = UNIX_EPOCH + Duration::from_secs(1_760_000_000);
        assert_eq!(parse_http_date(&fmt_http_date(t)), Some(t));
    }
}
