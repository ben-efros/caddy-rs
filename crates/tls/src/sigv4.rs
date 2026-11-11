//! AWS Signature Version 4 request signing, shared by the Route 53 DNS provider and the
//! S3-compatible storage backend (T-TLS-022).
//!
//! The signer is checked against the AWS published S3 GET example vector (also used by the
//! Route 53 tests).

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use sha2::{Digest, Sha256};

/// AWS credentials used for SigV4.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AwsCredentials {
    /// Access key ID.
    pub(crate) access_key_id: String,
    /// Secret access key (never printed).
    pub(crate) secret_access_key: String,
    /// Optional temporary-session token.
    pub(crate) session_token: Option<String>,
}

/// One request to sign.
pub(crate) struct SigV4Request<'a> {
    /// HTTP method.
    pub(crate) method: &'a str,
    /// Request host (including port when not the default).
    pub(crate) host: &'a str,
    /// URL path (already percent-encoded where required; `/` preserved).
    pub(crate) path: &'a str,
    /// Query parameters (they are encoded and sorted by the signer).
    pub(crate) query: &'a [(String, String)],
    /// Request payload body.
    pub(crate) payload: &'a [u8],
    /// Additional headers to sign (lowercase names, original values).
    pub(crate) extra_headers: &'a [(&'a str, &'a str)],
    /// Credentials.
    pub(crate) credentials: &'a AwsCredentials,
    /// AWS region.
    pub(crate) region: &'a str,
    /// AWS service (`s3`, `route53`, ...).
    pub(crate) service: &'a str,
    /// `YYYYMMDDTHHMMSSZ` timestamp.
    pub(crate) amz_date: &'a str,
}

/// AWS URI-encoding set: encode everything except unreserved characters; the path additionally
/// preserves `/`.
const AWS_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Percent-encode one AWS URI component.
pub(crate) fn aws_uri_encode(value: &str) -> String {
    utf8_percent_encode(value, AWS_SET).to_string()
}

/// Canonical query string (encoded keys/values sorted by the encoded pair).
pub(crate) fn canonical_query(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(key, value)| (aws_uri_encode(key), aws_uri_encode(value)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // INFEASIBLE: HMAC accepts keys of any length.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Sign an AWS request (SigV4) and return the headers to send (wire-cased, excluding `Accept`).
pub(crate) fn sign_sigv4(request: SigV4Request<'_>) -> Vec<(String, String)> {
    let payload_hash = sha256_hex(request.payload);
    let mut headers: Vec<(String, String)> = Vec::new();
    headers.push(("host".to_string(), request.host.to_string()));
    headers.push(("x-amz-date".to_string(), request.amz_date.to_string()));
    headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));
    if let Some(token) = &request.credentials.session_token {
        headers.push(("x-amz-security-token".to_string(), token.clone()));
    }
    for (name, value) in request.extra_headers {
        headers.push((name.to_ascii_lowercase(), value.to_string()));
    }
    headers.sort_by(|left, right| left.0.cmp(&right.0));
    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect::<String>();
    let signed_headers = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_path = if request.path.is_empty() {
        "/".to_string()
    } else {
        request.path.to_string()
    };
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        canonical_path,
        canonical_query(request.query),
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let scope = format!(
        "{}/{}/{}/aws4_request",
        &request.amz_date[..8],
        request.region,
        request.service
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        request.amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes())
    );
    let date_key = hmac_sha256(
        format!("AWS4{}", request.credentials.secret_access_key).as_bytes(),
        request.amz_date[..8].as_bytes(),
    );
    let region_key = hmac_sha256(&date_key, request.region.as_bytes());
    let service_key = hmac_sha256(&region_key, request.service.as_bytes());
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        request.credentials.access_key_id, scope, signed_headers, signature
    );
    let mut out: Vec<(String, String)> = headers
        .into_iter()
        .map(|(name, value)| (wire_header_name(&name), value))
        .collect();
    out.push(("Authorization".to_string(), authorization));
    out
}

/// Wire casing for the headers the signer emits.
pub(crate) fn wire_header_name(name: &str) -> String {
    match name {
        "host" => "Host".to_string(),
        "x-amz-date" => "X-Amz-Date".to_string(),
        "x-amz-content-sha256" => "X-Amz-Content-Sha256".to_string(),
        "x-amz-security-token" => "X-Amz-Security-Token".to_string(),
        "content-type" => "Content-Type".to_string(),
        "if-none-match" => "If-None-Match".to_string(),
        other => other.to_string(),
    }
}

/// Format a Unix time as `YYYYMMDDTHHMMSSZ` for AWS.
pub(crate) fn format_amz_date(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u32;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS published S3 GET example vector (also used by the Route 53 tests).
    #[test]
    fn sigv4_matches_aws_published_vector() {
        let credentials = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };
        let headers = sign_sigv4(SigV4Request {
            method: "GET",
            host: "examplebucket.s3.amazonaws.com",
            path: "/test.txt",
            query: &[],
            payload: b"",
            extra_headers: &[("range", "bytes=0-9")],
            credentials: &credentials,
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
        });
        let authorization = headers
            .iter()
            .find(|(name, _)| name == "Authorization")
            .map(|(_, value)| value.as_str())
            .expect("Authorization header");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }
}
