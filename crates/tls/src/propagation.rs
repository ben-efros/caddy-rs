//! Authoritative propagation checks for ACME DNS-01 challenges.
//!
//! After a DNS provider creates the `_acme-challenge.<domain>` TXT record, ACME validation can
//! only succeed once the record is visible through the DNS resolvers the CA uses. Waiting on the
//! provider API itself is not sufficient (the provider may acknowledge a write long before
//! authoritative servers serve it), so this module defines a small [`PropagationChecker`]
//! abstraction and a production implementation that queries DNS-over-HTTPS.
//!
//! [`DohPropagationChecker`] speaks the Cloudflare DoH JSON API
//! (`https://cloudflare-dns.com/dns-query?name=<fqdn>&type=TXT` with
//! `Accept: application/dns-json`). It is generic over the crate's transport-neutral
//! [`AcmeTransport`], so production uses the existing hyper/rustls [`HyperTransport`] and tests
//! drive a scripted mock without network access.
//!
//! Caddy checks propagation using the configured DNS `resolvers` (raw DNS). caddy-rs uses DoH
//! only: the `resolvers` setting is accepted but not used yet, and the DoH endpoint is fixed to
//! Cloudflare's public resolver (reported as a divergence). Unlike the provider `list` API, a DoH
//! answer proves the record is actually served.
//!
//! [`HyperTransport`]: crate::acme::HyperTransport

use async_trait::async_trait;
use serde::Deserialize;

use crate::acme::{AcmeTransport, HttpRequest};
use crate::dns::DnsError;
use crate::{Error, Result};

/// Cloudflare's public DNS-over-HTTPS JSON endpoint.
pub const CLOUDFLARE_DOH_ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";

/// DNS record type for TXT records (RFC 1035).
const DNS_TYPE_TXT: u32 = 16;

/// Checks whether a TXT record is visible through authoritative DNS.
#[async_trait]
pub trait PropagationChecker: Send + Sync {
    /// Return `Ok(true)` when a TXT record for `fqdn` with exactly `value` is served.
    ///
    /// Records that do not exist yet must be reported as `Ok(false)` (that is the normal
    /// pre-propagation state); transport/decoding failures are `Err` so the caller can surface a
    /// real problem instead of waiting for a timeout.
    async fn txt_record_visible(&self, fqdn: &str, value: &str) -> Result<bool>;
}

/// DNS-over-HTTPS [`PropagationChecker`] using the JSON API (`application/dns-json`).
pub struct DohPropagationChecker<T: AcmeTransport> {
    transport: T,
    endpoint: String,
}

impl<T: AcmeTransport> DohPropagationChecker<T> {
    /// Check via Cloudflare's public DoH resolver.
    pub fn cloudflare(transport: T) -> Self {
        Self {
            transport,
            endpoint: CLOUDFLARE_DOH_ENDPOINT.to_string(),
        }
    }

    /// Check via an explicit DoH endpoint (tests and private resolvers).
    pub fn with_endpoint(transport: T, endpoint: impl Into<String>) -> Self {
        Self {
            transport,
            endpoint: endpoint.into(),
        }
    }

    /// The DoH endpoint this checker queries.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn query_url(&self, fqdn: &str) -> String {
        // ACME record names contain only `[a-z0-9._-]` (validated by `DnsProvider` callers), all of
        // which are safe in a query string.
        format!("{}?name={}&type=TXT", self.endpoint, fqdn)
    }
}

#[async_trait]
impl<T: AcmeTransport> PropagationChecker for DohPropagationChecker<T> {
    async fn txt_record_visible(&self, fqdn: &str, value: &str) -> Result<bool> {
        let url = self.query_url(fqdn);
        let response = self
            .transport
            .request(HttpRequest::get(url.clone()).with_header("Accept", "application/dns-json"))
            .await?;
        if !response.is_success() {
            return Err(Error::Dns(DnsError::Provider {
                provider: "dns-over-https".to_string(),
                message: format!(
                    "DNS-over-HTTPS query for `{fqdn}` failed with HTTP {}",
                    response.status
                ),
            }));
        }
        let answer: DohResponse = serde_json::from_slice(&response.body).map_err(|error| {
            Error::Dns(DnsError::Provider {
                provider: "dns-over-https".to_string(),
                message: format!(
                    "invalid DNS-over-HTTPS response for `{fqdn}` (HTTP {}): {error}",
                    response.status
                ),
            })
        })?;
        match answer.status {
            // NOERROR: inspect the answers.
            0 => Ok(answer
                .answers
                .iter()
                .filter(|entry| entry.record_type == DNS_TYPE_TXT)
                .any(|entry| txt_data_matches(&entry.data, value))),
            // NXDOMAIN: the name does not exist yet; keep polling.
            3 => Ok(false),
            other => Err(Error::Dns(DnsError::Provider {
                provider: "dns-over-https".to_string(),
                message: format!("DNS-over-HTTPS query for `{fqdn}` returned DNS status {other}"),
            })),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Status", default)]
    status: u32,
    #[serde(rename = "Answer", default)]
    answers: Vec<DohAnswer>,
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[serde(rename = "type", default)]
    record_type: u32,
    #[serde(default)]
    data: String,
}

/// Compare a DoH TXT `data` field to the expected record value.
///
/// DNS TXT data is quoted (`"value"`) and a single TXT record may be split into several
/// character-strings (`"part1" "part2"`); this concatenates the character-strings before
/// comparing. caddy-rs writes single-string records, but a provider/CDN could split them.
pub fn txt_data_matches(data: &str, value: &str) -> bool {
    let data = data.trim();
    if !data.starts_with('"') {
        return data == value;
    }
    let mut joined = String::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for character in data.chars() {
        if in_quotes {
            if escaped {
                current.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                joined.push_str(&current);
                current.clear();
                in_quotes = false;
            } else {
                current.push(character);
            }
        } else if character == '"' {
            in_quotes = true;
        } else if !character.is_whitespace() {
            // Malformed trailing bytes outside of a quoted string: no match.
            return false;
        }
    }
    if in_quotes {
        return false;
    }
    joined == value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::{HttpMethod, HttpResponse};
    use std::sync::Mutex;

    #[derive(Default)]
    struct ScriptedTransport {
        responses: Mutex<Vec<HttpResponse>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl ScriptedTransport {
        fn new(response: HttpResponse) -> Self {
            Self {
                responses: Mutex::new(vec![response]),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AcmeTransport for ScriptedTransport {
        async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.requests.lock().unwrap().push(request);
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                panic!("scripted transport exhausted");
            }
            Ok(responses.remove(0))
        }
    }

    fn json_response(status: u16, body: serde_json::Value) -> HttpResponse {
        HttpResponse::with_json(status, &body).unwrap()
    }

    fn answer(status: u32, answers: serde_json::Value) -> HttpResponse {
        json_response(
            200,
            serde_json::json!({"Status": status, "Answer": answers}),
        )
    }

    #[tokio::test]
    async fn visible_record_is_reported_and_request_shape_is_correct() {
        let transport = ScriptedTransport::new(answer(
            0,
            serde_json::json!([
                {"name": "_acme-challenge.example.com", "type": 16, "TTL": 5, "data": "\"expected-value\""}
            ]),
        ));
        let checker = DohPropagationChecker::with_endpoint(transport, "https://doh.test/dns-query");
        assert!(checker
            .txt_record_visible("_acme-challenge.example.com", "expected-value")
            .await
            .unwrap());

        let requests = checker.transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, HttpMethod::Get);
        assert_eq!(
            requests[0].url,
            "https://doh.test/dns-query?name=_acme-challenge.example.com&type=TXT"
        );
        assert_eq!(requests[0].header("Accept"), Some("application/dns-json"));
    }

    #[tokio::test]
    async fn missing_wrong_or_nxdomain_records_are_not_visible() {
        let transport = ScriptedTransport::new(answer(0, serde_json::json!([])));
        let checker = DohPropagationChecker::cloudflare(transport);
        assert!(!checker
            .txt_record_visible("_acme-challenge.example.com", "value")
            .await
            .unwrap());

        let transport = ScriptedTransport::new(answer(
            0,
            serde_json::json!([{"type": 16, "data": "\"other-value\""}]),
        ));
        let checker = DohPropagationChecker::cloudflare(transport);
        assert!(!checker
            .txt_record_visible("_acme-challenge.example.com", "value")
            .await
            .unwrap());

        // CNAME/A answers do not count as TXT visibility.
        let transport = ScriptedTransport::new(answer(
            0,
            serde_json::json!([{"type": 1, "data": "192.0.2.1"}]),
        ));
        let checker = DohPropagationChecker::cloudflare(transport);
        assert!(!checker
            .txt_record_visible("_acme-challenge.example.com", "value")
            .await
            .unwrap());

        let transport = ScriptedTransport::new(answer(3, serde_json::json!([])));
        let checker = DohPropagationChecker::cloudflare(transport);
        assert!(!checker
            .txt_record_visible("_acme-challenge.example.com", "value")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn dns_and_transport_errors_are_loud() {
        let transport = ScriptedTransport::new(json_response(
            503,
            serde_json::json!({"error": "unavailable"}),
        ));
        let checker = DohPropagationChecker::cloudflare(transport);
        let error = checker
            .txt_record_visible("_acme-challenge.example.com", "value")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("HTTP 503"), "{error}");

        let transport = ScriptedTransport::new(answer(2, serde_json::json!([])));
        let checker = DohPropagationChecker::cloudflare(transport);
        let error = checker
            .txt_record_visible("_acme-challenge.example.com", "value")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("DNS status 2"), "{error}");

        let transport =
            ScriptedTransport::new(HttpResponse::new(200).with_body(b"not-json".to_vec()));
        let checker = DohPropagationChecker::cloudflare(transport);
        let error = checker
            .txt_record_visible("_acme-challenge.example.com", "value")
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid DNS-over-HTTPS response"),
            "{error}"
        );
    }

    #[test]
    fn txt_data_comparison_handles_quotes_and_split_strings() {
        assert!(txt_data_matches("\"value\"", "value"));
        assert!(txt_data_matches("value", "value"));
        assert!(txt_data_matches("\"part1\" \"part2\"", "part1part2"));
        assert!(!txt_data_matches("\"other\"", "value"));
        assert!(!txt_data_matches("\"unterminated", "value"));
        assert!(!txt_data_matches("garbage value", "value"));
        assert!(txt_data_matches("\"quo\\\"ted\"", "quo\"ted"));
    }
}
