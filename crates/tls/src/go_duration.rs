//! Go's `time.Duration.String()` formatting for diagnostics.
//!
//! Caddy interpolates `time.Duration` values into error text (for example the ACME server's
//! `certificate lifetime (168h0m0s) should be less than intermediate certificate lifetime (...)`),
//! so a located caddy-rs error has to reproduce Go's formatting rather than Rust's `Debug` output.

use std::time::Duration;

/// Format a duration the way Go's `time.Duration.String` does.
///
/// Durations of at least one second print as `[-]HhMmSs` with a fractional second only when
/// non-zero; shorter durations print as `[-]Nms`, `[-]Nus` or `[-]Nns` at the first unit that
/// represents them exactly enough. Values here are certificate lifetimes (hours to years), so the
/// sub-second branches exist for completeness and for error text symmetry.
pub fn format_go_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos == 0 {
        return "0s".to_string();
    }

    // Sub-second: Go prints the largest unit with a fractional remainder (`1.5ms`, `1.5µs`), not a
    // whole number of smaller units.
    if nanos < 1_000_000_000 {
        let (unit_nanos, suffix) = if nanos < 1_000 {
            (1_u128, "ns")
        } else if nanos < 1_000_000 {
            (1_000_u128, "µs")
        } else {
            (1_000_000_u128, "ms")
        };
        let whole = nanos / unit_nanos;
        let remainder = nanos % unit_nanos;
        if remainder == 0 {
            return format!("{whole}{suffix}");
        }
        let width = match unit_nanos {
            1_000_000 => 6,
            1_000 => 3,
            _ => 0,
        };
        let mut fraction = format!("{remainder:0width$}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        return format!("{whole}.{fraction}{suffix}");
    }

    let total_seconds = nanos / 1_000_000_000;
    let fraction_nanos = nanos % 1_000_000_000;
    let hours = total_seconds / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;

    // Go prints leading zero units only after a non-zero higher unit: `168h0m0s` but `1.5s`.
    let mut text = String::new();
    if hours > 0 {
        text.push_str(&format!("{hours}h"));
    }
    if hours > 0 || minutes > 0 {
        text.push_str(&format!("{minutes}m"));
    }
    if hours > 0 || minutes > 0 || seconds > 0 {
        text.push_str(&format!("{seconds}"));
    }
    if fraction_nanos != 0 {
        let mut fraction = format!("{fraction_nanos:09}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        text.push('.');
        text.push_str(&fraction);
    }
    text.push('s');
    text
}

#[cfg(test)]
mod tests {
    use super::format_go_duration;
    use std::time::Duration;

    #[test]
    fn matches_go_duration_strings() {
        // Expected strings taken from Go's time.Duration.String().
        for (duration, expected) in [
            (Duration::from_secs(0), "0s"),
            (Duration::from_secs(12 * 3600), "12h0m0s"),
            (Duration::from_secs(168 * 3600), "168h0m0s"),
            (Duration::from_secs(144 * 3600), "144h0m0s"),
            (Duration::from_secs(3600 + 30 * 60), "1h30m0s"),
            (Duration::from_secs(1) + Duration::from_millis(500), "1.5s"),
            (Duration::from_millis(500), "500ms"),
            (Duration::from_micros(1500), "1.5ms"),
            (Duration::from_nanos(1500), "1.5µs"),
            (Duration::from_micros(250), "250µs"),
            (Duration::from_nanos(7), "7ns"),
        ] {
            assert_eq!(format_go_duration(duration), expected, "{duration:?}");
        }
    }
}
