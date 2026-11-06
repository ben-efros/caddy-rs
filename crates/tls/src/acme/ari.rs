//! ACME Renewal Information (ARI, RFC 9773).
//!
//! A CA advertises a `renewalInfo` endpoint in its directory. For a certificate, the client
//! requests `<renewalInfo>/<certID>` where `certID` is `base64url(AKI) . base64url(serial DER
//! integer bytes)`. The response carries a `suggestedWindow`; the client selects a uniform random
//! time inside it and renews at/after that time (minus the maintenance check interval), falling
//! back to its local renewal heuristic when the endpoint is absent, errors, returns no usable
//! window, or the certificate enters certmagic's emergency window.
//!
//! This module contains the pure protocol pieces (certificate identifier, response parsing,
//! RFC 3339 timestamps and window selection) so they are testable without network access.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

use super::AcmeError;
use crate::Result;

/// A CA-suggested renewal window (RFC 9773 `suggestedWindow`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedWindow {
    /// Start of the window.
    pub start: SystemTime,
    /// End of the window (exclusive for selection).
    pub end: SystemTime,
}

/// ACME Renewal Information for one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalInfo {
    /// The CA's suggested window.
    pub suggested_window: SuggestedWindow,
    /// Optional explanation URL supplied by the CA.
    pub explanation_url: Option<String>,
    /// ARI certificate identifier used for this query.
    pub unique_identifier: String,
    /// Next time the ARI document should be refreshed (`Retry-After`), if provided.
    pub retry_after: Option<SystemTime>,
    /// Uniform random time selected inside the window.
    pub selected_time: Option<SystemTime>,
}

impl RenewalInfo {
    /// Whether the window is valid for selecting a renewal time.
    pub fn has_window(&self) -> bool {
        self.suggested_window.end > self.suggested_window.start
    }

    /// Whether the ARI document should be refreshed at `now` (`Retry-After` elapsed).
    pub fn needs_refresh(&self, now: SystemTime) -> bool {
        match self.retry_after {
            Some(retry_after) => now >= retry_after,
            None => false,
        }
    }

    /// Select a uniform random time in `[start+1s, end)` like acmez's `GetRenewalInfo`.
    ///
    /// Falls back to the window boundary when the interval is too small, matching acmez.
    pub fn select_time(&self) -> Option<SystemTime> {
        let (Ok(start), Ok(end)) = (
            self.suggested_window.start.duration_since(UNIX_EPOCH),
            self.suggested_window.end.duration_since(UNIX_EPOCH),
        ) else {
            return None;
        };
        let start = start.as_secs().saturating_add(1);
        let end = end.as_secs();
        if end > start {
            let span = end - start;
            let selected = start + rand::random::<u64>() % span;
            return Some(UNIX_EPOCH + Duration::from_secs(selected));
        }
        if start > 0 {
            return Some(UNIX_EPOCH + Duration::from_secs(start));
        }
        if end > 0 {
            return Some(UNIX_EPOCH + Duration::from_secs(end));
        }
        None
    }
}

/// Wire shape of the ARI response.
#[derive(Debug, Deserialize)]
struct AriWire {
    #[serde(rename = "suggestedWindow")]
    suggested_window: SuggestedWindowWire,
    #[serde(rename = "explanationURL", default)]
    explanation_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SuggestedWindowWire {
    start: String,
    end: String,
}

impl RenewalInfo {
    /// Parse an ARI response body and select a renewal time.
    ///
    /// Invalid windows (missing/equal/reversed timestamps) return an [`AcmeError::Ari`] error so
    /// the caller can fall back to its local renewal heuristic, like acmez.
    pub fn parse(cert_id: &str, body: &[u8]) -> Result<Self> {
        let wire: AriWire = serde_json::from_slice(body).map_err(|error| AcmeError::Ari {
            reason: format!("invalid ARI response for `{cert_id}`: {error}"),
        })?;
        let start = parse_rfc3339(&wire.suggested_window.start).ok_or_else(|| AcmeError::Ari {
            reason: format!(
                "invalid ARI suggestedWindow start `{}` for `{cert_id}`",
                wire.suggested_window.start
            ),
        })?;
        let end = parse_rfc3339(&wire.suggested_window.end).ok_or_else(|| AcmeError::Ari {
            reason: format!(
                "invalid ARI suggestedWindow end `{}` for `{cert_id}`",
                wire.suggested_window.end
            ),
        })?;
        if end <= start {
            return Err(AcmeError::Ari {
                reason: format!(
                    "invalid ARI suggestedWindow for `{cert_id}`: end must be after start"
                ),
            }
            .into());
        }
        let mut info = Self {
            suggested_window: SuggestedWindow { start, end },
            explanation_url: wire.explanation_url,
            unique_identifier: cert_id.to_string(),
            retry_after: None,
            selected_time: None,
        };
        info.selected_time = info.select_time();
        Ok(info)
    }

    /// Attach a `Retry-After` duration from the HTTP response.
    pub fn with_retry_after(mut self, now: SystemTime, retry_after: Option<Duration>) -> Self {
        self.retry_after = retry_after.map(|duration| now + duration);
        self
    }
}

/// Compute the RFC 9773 ARI certificate identifier from a DER-encoded leaf certificate.
///
/// Returns `base64url(AKI keyIdentifier) . base64url(serial INTEGER content)` with trailing `=`
/// stripped. Errors when the certificate has no Authority Key Identifier or serial number.
pub fn unique_identifier(certificate_der: &[u8]) -> Result<String> {
    let (tag, cert_body, _) = read_tlv(certificate_der)?;
    if tag != 0x30 {
        return Err(AcmeError::Ari {
            reason: "ARI: certificate is not a DER SEQUENCE".to_string(),
        }
        .into());
    }
    let (tbs_tag, tbs_body, _) = read_tlv(cert_body)?;
    if tbs_tag != 0x30 {
        return Err(AcmeError::Ari {
            reason: "ARI: TBSCertificate is not a DER SEQUENCE".to_string(),
        }
        .into());
    }
    let mut offset = 0;
    // Optional [0] EXPLICIT version precedes the serial number.
    let (first_tag, _, first_len) = read_tlv(&tbs_body[offset..])?;
    if first_tag == 0xA0 {
        offset += first_len;
    }
    let (serial_tag, serial, serial_len) = read_tlv(&tbs_body[offset..])?;
    if serial_tag != 0x02 {
        return Err(AcmeError::Ari {
            reason: "ARI: certificate has no DER serial number".to_string(),
        }
        .into());
    }
    offset += serial_len;
    // signature algorithm, issuer, validity, subject, subjectPublicKeyInfo
    for _ in 0..5 {
        let (_, _, len) = read_tlv(&tbs_body[offset..])?;
        offset += len;
    }
    // Remaining fields may contain [1]/[2] issuerUniqueID/subjectUniqueID and [3] extensions.
    let mut key_identifier = None;
    while offset < tbs_body.len() {
        let (tag, content, len) = read_tlv(&tbs_body[offset..])?;
        offset += len;
        if tag == 0xA3 {
            let (extensions_tag, extensions, _) = read_tlv(content)?;
            if extensions_tag != 0x30 {
                continue;
            }
            let mut extensions_offset = 0;
            while extensions_offset < extensions.len() {
                let (extension_tag, extension, extension_len) =
                    read_tlv(&extensions[extensions_offset..])?;
                extensions_offset += extension_len;
                if extension_tag != 0x30 {
                    continue;
                }
                let mut ext_offset = 0;
                let (oid_tag, oid, oid_len) = read_tlv(&extension[ext_offset..])?;
                ext_offset += oid_len;
                let is_aki = oid_tag == 0x06 && oid == AKI_OID_VALUE;
                if !is_aki {
                    continue;
                }
                // Optional critical BOOLEAN, then extnValue OCTET STRING.
                let (next_tag, _, next_len) = read_tlv(&extension[ext_offset..])?;
                if next_tag == 0x01 {
                    ext_offset += next_len;
                }
                let (value_tag, value, _) = read_tlv(&extension[ext_offset..])?;
                if value_tag != 0x04 {
                    continue;
                }
                let (aki_tag, aki_body, _) = read_tlv(value)?;
                if aki_tag != 0x30 {
                    continue;
                }
                let (kid_tag, kid, _) = read_tlv(aki_body)?;
                if kid_tag == 0x80 {
                    key_identifier = Some(kid);
                }
            }
        }
    }
    let Some(key_identifier) = key_identifier else {
        return Err(AcmeError::Ari {
            reason: "ARI: certificate has no Authority Key Identifier keyIdentifier".to_string(),
        }
        .into());
    };
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(key_identifier),
        URL_SAFE_NO_PAD.encode(serial)
    ))
}

/// DER encoding of the `id-ce-authorityKeyIdentifier` OID content (`2.5.29.35`).
const AKI_OID_VALUE: &[u8] = &[0x55, 0x1D, 0x23];

fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], usize)> {
    let tag = *input.first().ok_or_else(|| AcmeError::Ari {
        reason: "truncated DER".to_string(),
    })?;
    let first = *input.get(1).ok_or_else(|| AcmeError::Ari {
        reason: "truncated DER length".to_string(),
    })?;
    let (length, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || input.len() < 2 + count {
            return Err(AcmeError::Ari {
                reason: "invalid DER length".to_string(),
            }
            .into());
        }
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    if input.len() < header + length {
        return Err(AcmeError::Ari {
            reason: "truncated DER content".to_string(),
        }
        .into());
    }
    Ok((tag, &input[header..header + length], header + length))
}

/// Parse an RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`).
pub fn parse_rfc3339(value: &str) -> Option<SystemTime> {
    let value = value.trim();
    if value.len() < 20 {
        return None;
    }
    let year: i64 = value.get(0..4)?.parse().ok()?;
    let month: u32 = value.get(5..7)?.parse().ok()?;
    let day: u32 = value.get(8..10)?.parse().ok()?;
    let hour: u32 = value.get(11..13)?.parse().ok()?;
    let minute: u32 = value.get(14..16)?.parse().ok()?;
    let second: u32 = value.get(17..19)?.parse().ok()?;
    if value.as_bytes().get(4)? != &b'-'
        || value.as_bytes().get(7)? != &b'-'
        || value.as_bytes().get(10)? != &b'T'
        || value.as_bytes().get(13)? != &b':'
        || value.as_bytes().get(16)? != &b':'
    {
        return None;
    }
    let mut index = 19;
    let mut nanos = 0u32;
    if value.as_bytes().get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while value.as_bytes().get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        let fraction = value.get(start..index)?;
        let digits = fraction.len().min(9);
        nanos = fraction.get(..digits)?.parse::<u32>().ok()?;
        for _ in digits..9 {
            nanos *= 10;
        }
    }
    let offset_seconds = match value.as_bytes().get(index)? {
        b'Z' | b'z' => 0i64,
        b'+' | b'-' => {
            let sign = if value.as_bytes()[index] == b'+' {
                1
            } else {
                -1
            };
            let offset = value.get(index + 1..index + 6)?;
            let hours: i64 = offset.get(0..2)?.parse().ok()?;
            let minutes: i64 = offset.get(3..5)?.parse().ok()?;
            if offset.as_bytes().get(2)? != &b':' {
                return None;
            }
            sign * (hours * 3600 + minutes * 60)
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let seconds =
        days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64 - offset_seconds;
    if seconds < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::new(seconds as u64, nanos))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_with_offsets_and_fractions() {
        let time = parse_rfc3339("2026-04-01T00:00:00Z").unwrap();
        assert_eq!(
            time.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1_775_001_600
        );
        let offset = parse_rfc3339("2026-04-01T02:00:00+02:00").unwrap();
        assert_eq!(offset, time);
        let fractional = parse_rfc3339("2026-04-01T00:00:00.5Z").unwrap();
        assert_eq!(fractional.duration_since(time).unwrap().as_millis(), 500);
        assert!(parse_rfc3339("not-a-date").is_none());
        assert!(parse_rfc3339("2026-04-01T00:00:00").is_none());
    }

    #[test]
    fn rejects_invalid_windows() {
        let err = RenewalInfo::parse(
            "id",
            br#"{"suggestedWindow":{"start":"2026-04-01T00:00:00Z","end":"2026-04-01T00:00:00Z"}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("end must be after start"), "{err}");
        let err = RenewalInfo::parse("id", b"{}").unwrap_err();
        assert!(err.to_string().contains("invalid ARI response"), "{err}");
    }

    #[test]
    fn selects_uniform_time_inside_window() {
        let info = RenewalInfo::parse(
            "id",
            br#"{"suggestedWindow":{"start":"2026-04-01T00:00:00Z","end":"2026-04-03T00:00:00Z"},"explanationURL":"https://ca.test/why"}"#,
        )
        .unwrap();
        let start = parse_rfc3339("2026-04-01T00:00:01Z").unwrap();
        let end = parse_rfc3339("2026-04-03T00:00:00Z").unwrap();
        let selected = info.selected_time.expect("selected time");
        assert!(selected >= start && selected < end, "{selected:?}");
        assert_eq!(info.explanation_url.as_deref(), Some("https://ca.test/why"));
    }
}
