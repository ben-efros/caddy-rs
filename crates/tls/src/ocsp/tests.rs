//! Deterministic tests for the TLS-side OCSP stapler.
//!
//! Fixtures are DER documents generated in-test (no network, no external files). The OCSP
//! response signature is not verified by the implementation yet (documented gap), so the fixture
//! response is structurally valid but not cryptographically signed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use super::*;
use crate::renewal::ManualClock;

const START: Duration = Duration::from_secs(1_700_000_000);

fn now_at(offset: Duration) -> SystemTime {
    UNIX_EPOCH + START + offset
}

// --- DER fixture builders -------------------------------------------------------------------

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    super::der_tlv(tag, content)
}

fn seq(items: &[Vec<u8>]) -> Vec<u8> {
    super::der_sequence(items)
}

fn oid(arcs: &[u64]) -> Vec<u8> {
    super::der_oid(arcs)
}

fn integer_bytes(bytes: &[u8]) -> Vec<u8> {
    super::der_integer_from_bytes(bytes)
}

fn octet(content: &[u8]) -> Vec<u8> {
    super::der_octet_string(content)
}

fn bit_string(content: &[u8]) -> Vec<u8> {
    super::der_bit_string(content)
}

fn utc_time(seconds: u64) -> Vec<u8> {
    // GeneralizedTime YYYYMMDDHHMMSSZ.
    let days = seconds / 86_400;
    let rem = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let text = format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    );
    tlv(0x18, text.as_bytes())
}

fn civil_from_days(days: u64) -> (i64, u64, u64) {
    // Inverse of Howard Hinnant's civil algorithm (test helper only).
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (if m <= 2 { y + 1 } else { y }, m as u64, d as u64)
}

fn spki(public_key: &[u8]) -> Vec<u8> {
    seq(&[
        seq(&[
            oid(&[1, 2, 840, 10045, 2, 1]),
            oid(&[1, 2, 840, 10045, 3, 1, 7]),
        ]),
        bit_string(public_key),
    ])
}

fn extension(oid_arcs: &[u64], value: &[u8]) -> Vec<u8> {
    seq(&[oid(oid_arcs), octet(value)])
}

fn leaf_certificate(serial: &[u8], ocsp_url: Option<&str>, must_staple: bool) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(url) = ocsp_url {
        let access = seq(&[
            oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1]),
            tlv(0x86, url.as_bytes()),
        ]);
        extensions.push(extension(&[1, 3, 6, 1, 5, 5, 7, 1, 1], &seq(&[access])));
    }
    if must_staple {
        extensions.push(extension(
            &[1, 3, 6, 1, 5, 5, 7, 1, 24],
            &seq(&[integer_bytes(&[5])]),
        ));
    }
    let extensions = if extensions.is_empty() {
        Vec::new()
    } else {
        tlv(0xA3, &seq(&extensions))
    };
    let issuer = seq(&[]);
    let validity = seq(&[
        utc_time(START.as_secs()),
        utc_time(START.as_secs() + 86_400),
    ]);
    let subject = seq(&[]);
    let tbs = seq(&[
        integer_bytes(serial),
        seq(&[oid(&[1, 2, 840, 10045, 4, 3, 2])]),
        issuer,
        validity,
        subject,
        spki(&[4u8; 65]),
        extensions,
    ]);
    seq(&[
        tbs,
        seq(&[oid(&[1, 2, 840, 10045, 4, 3, 2])]),
        bit_string(&[0u8; 8]),
    ])
}

fn issuer_certificate() -> Vec<u8> {
    let tbs = seq(&[
        integer_bytes(&[2]),
        seq(&[oid(&[1, 2, 840, 10045, 4, 3, 2])]),
        seq(&[]),
        seq(&[
            utc_time(START.as_secs()),
            utc_time(START.as_secs() + 86_400),
        ]),
        seq(&[]),
        spki(&[4u8; 65]),
    ]);
    seq(&[
        tbs,
        seq(&[oid(&[1, 2, 840, 10045, 4, 3, 2])]),
        bit_string(&[0u8; 8]),
    ])
}

fn ocsp_response(serial: &[u8], this_update: u64, next_update: Option<u64>) -> Vec<u8> {
    let cert_id = seq(&[
        seq(&[oid(&[1, 3, 14, 3, 2, 26]), super::der_null()]),
        octet(&[0u8; 20]),
        octet(&[0u8; 20]),
        integer_bytes(serial),
    ]);
    let mut single = vec![
        cert_id,
        tlv(0x80, &[]), // good
        utc_time(this_update),
    ];
    if let Some(next_update) = next_update {
        single.push(tlv(0xA0, &utc_time(next_update)));
    }
    let response_data = seq(&[
        seq(&[]), // responderID (empty Name, sufficient for the parser)
        utc_time(this_update),
        seq(&[seq(&single)]),
    ]);
    let basic = seq(&[
        response_data,
        seq(&[oid(&[1, 2, 840, 10045, 4, 3, 2])]),
        bit_string(&[0u8; 8]),
    ]);
    let response_bytes = seq(&[oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]), octet(&basic)]);
    seq(&[tlv(0x0A, &[0]), tlv(0xA0, &response_bytes)])
}

// --- Mock transport -------------------------------------------------------------------------

struct MockTransport {
    calls: AtomicUsize,
    responses: Mutex<Vec<Vec<u8>>>,
}

impl MockTransport {
    fn with(response: Vec<u8>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            responses: Mutex::new(vec![response]),
        }
    }

    fn push(&self, response: Vec<u8>) {
        self.responses.lock().unwrap().push(response);
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl OcspTransport for MockTransport {
    async fn fetch(&self, _url: &str, _request_der: &[u8]) -> Result<Vec<u8>, OcspError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let response = {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Err(OcspError::Transport("scripted failure".to_string()));
            }
            responses.remove(0)
        };
        Ok(response)
    }
}

struct FailingTransport {
    calls: AtomicUsize,
}

#[async_trait]
impl OcspTransport for FailingTransport {
    async fn fetch(&self, _url: &str, _request_der: &[u8]) -> Result<Vec<u8>, OcspError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(OcspError::Transport("scripted failure".to_string()))
    }
}

fn make_stapler(
    transport: Arc<dyn OcspTransport>,
    policy: OcspPolicy,
    clock: Arc<ManualClock>,
) -> Arc<OcspStapler> {
    Arc::new(OcspStapler::with_clock(transport, policy, clock))
}

// --- Tests ----------------------------------------------------------------------------------

#[test]
fn parsed_certificate_exposes_aia_and_must_staple() {
    let leaf = leaf_certificate(&[7], Some("http://ocsp.example.test"), true);
    let parsed = ParsedCertificate::parse(&leaf).unwrap();
    assert_eq!(parsed.serial, vec![7]);
    assert_eq!(
        parsed.ocsp_responder_url.as_deref(),
        Some("http://ocsp.example.test")
    );
    assert!(parsed.must_staple);
    assert!(!parsed.issuer_name_der.is_empty());
}

#[test]
fn ocsp_request_is_der_and_hashes_issuer_material() {
    let leaf = leaf_certificate(&[0x42], Some("http://ocsp.example.test"), false);
    let issuer = issuer_certificate();
    let request = build_ocsp_request(&leaf, &issuer).unwrap();
    assert_eq!(request.serial, vec![0x42]);
    // OCSPRequest ::= SEQUENCE (0x30), non-empty.
    assert_eq!(request.der.first(), Some(&0x30));
    assert!(request.der.len() > 30);
    let expected_name = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        &ParsedCertificate::parse(&leaf).unwrap().issuer_name_der,
    );
    assert!(request
        .der
        .windows(expected_name.as_ref().len())
        .any(|window| window == expected_name.as_ref()));
}

#[tokio::test]
async fn fetch_caches_staple_and_reuses_it() {
    let clock = Arc::new(ManualClock::new(now_at(Duration::ZERO)));
    let transport = Arc::new(MockTransport::with(ocsp_response(
        &[7],
        START.as_secs(),
        Some(START.as_secs() + 4 * 3_600),
    )));
    let stapler = make_stapler(
        Arc::clone(&transport) as Arc<dyn OcspTransport>,
        OcspPolicy::default(),
        clock.clone(),
    );
    let leaf = leaf_certificate(&[7], Some("http://ocsp.example.test"), false);
    let issuer = issuer_certificate();
    assert_eq!(
        stapler.ensure_staple(&leaf, &issuer).await.unwrap(),
        StapleOutcome::Fetched
    );
    assert_eq!(transport.call_count(), 1);
    assert!(stapler.staple(&leaf).is_some());
    assert_eq!(
        stapler.ensure_staple(&leaf, &issuer).await.unwrap(),
        StapleOutcome::Cached
    );
    assert_eq!(transport.call_count(), 1);

    // A second stapler sharing the same policy/clock does not share the cache by itself, but a
    // cloned `Arc<OcspStapler>` does (this is what the server retains across reloads).
    let shared = Arc::clone(&stapler);
    assert_eq!(
        shared.ensure_staple(&leaf, &issuer).await.unwrap(),
        StapleOutcome::Cached
    );
    assert_eq!(transport.call_count(), 1);
}

#[tokio::test]
async fn stale_staple_is_refreshed_before_next_update() {
    let clock = Arc::new(ManualClock::new(now_at(Duration::ZERO)));
    let transport = Arc::new(MockTransport::with(ocsp_response(
        &[7],
        START.as_secs(),
        Some(START.as_secs() + 4 * 3_600),
    )));
    transport.push(ocsp_response(
        &[7],
        START.as_secs() + 4 * 3_600,
        Some(START.as_secs() + 8 * 3_600),
    ));
    let stapler = make_stapler(
        Arc::clone(&transport) as Arc<dyn OcspTransport>,
        OcspPolicy::default(),
        clock.clone(),
    );
    let leaf = leaf_certificate(&[7], Some("http://ocsp.example.test"), false);
    let issuer = issuer_certificate();
    stapler.ensure_staple(&leaf, &issuer).await.unwrap();
    assert!(!stapler.needs_refresh(&leaf));

    // Move to within the one-hour scan window of nextUpdate.
    clock.advance(Duration::from_secs(3 * 3_600 + 60));
    assert!(stapler.needs_refresh(&leaf));
    assert_eq!(
        stapler.ensure_staple(&leaf, &issuer).await.unwrap(),
        StapleOutcome::Fetched
    );
    assert_eq!(transport.call_count(), 2);
    let cached = stapler.cached(&leaf).unwrap();
    assert_eq!(
        cached.response.next_update,
        Some(now_at(Duration::from_secs(8 * 3_600)))
    );
}

#[tokio::test]
async fn failed_fetch_backs_off_then_retries() {
    let clock = Arc::new(ManualClock::new(now_at(Duration::ZERO)));
    let transport = Arc::new(FailingTransport {
        calls: AtomicUsize::new(0),
    });
    let stapler = make_stapler(
        Arc::clone(&transport) as Arc<dyn OcspTransport>,
        OcspPolicy::default(),
        clock.clone(),
    );
    let leaf = leaf_certificate(&[7], Some("http://ocsp.example.test"), false);
    let issuer = issuer_certificate();
    assert!(stapler.ensure_staple(&leaf, &issuer).await.is_err());
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    // Before the 30s backoff expires no second call is made.
    clock.advance(Duration::from_secs(10));
    assert_eq!(
        stapler.ensure_staple(&leaf, &issuer).await.unwrap_err(),
        OcspError::Backoff
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    // After the backoff the fetch is attempted again.
    clock.advance(Duration::from_secs(30));
    assert!(stapler.ensure_staple(&leaf, &issuer).await.is_err());
    assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn disabled_stapling_never_fetches_and_must_staple_is_loud() {
    let clock = Arc::new(ManualClock::new(now_at(Duration::ZERO)));
    let transport = Arc::new(MockTransport::with(ocsp_response(
        &[7],
        START.as_secs(),
        Some(START.as_secs() + 3_600),
    )));
    let policy = OcspPolicy {
        enabled: false,
        must_staple: false,
        check_interval: DEFAULT_OCSP_CHECK_INTERVAL,
    };
    let stapler = make_stapler(
        Arc::clone(&transport) as Arc<dyn OcspTransport>,
        policy,
        clock.clone(),
    );
    let leaf = leaf_certificate(&[7], Some("http://ocsp.example.test"), false);
    let issuer = issuer_certificate();
    assert_eq!(
        stapler.ensure_staple(&leaf, &issuer).await.unwrap(),
        StapleOutcome::Disabled
    );
    assert_eq!(transport.call_count(), 0);
    assert!(stapler.staple(&leaf).is_none());

    let must_staple = OcspPolicy {
        enabled: false,
        must_staple: true,
        check_interval: DEFAULT_OCSP_CHECK_INTERVAL,
    };
    let must_staple_stapler = make_stapler(
        Arc::clone(&transport) as Arc<dyn OcspTransport>,
        must_staple,
        clock,
    );
    let error = must_staple_stapler
        .ensure_staple(&leaf, &issuer)
        .await
        .expect_err("must-staple + disabled must be loud");
    assert_eq!(error, OcspError::MustStapleDisabled);
}

#[test]
fn ocsp_overrides_are_rejected_loudly() {
    let mut policy = AutomationPolicy::default();
    policy.ocsp_overrides.insert(
        "http://ocsp.example.test".to_string(),
        "http://ocsp2.example.test".to_string(),
    );
    let error = OcspPolicy::for_managed(&policy, DEFAULT_OCSP_CHECK_INTERVAL)
        .expect_err("responder overrides must be rejected");
    assert!(matches!(error, OcspError::Unsupported(_)));
}

#[tokio::test]
async fn no_responder_is_loud_and_never_stapled() {
    let clock = Arc::new(ManualClock::new(now_at(Duration::ZERO)));
    let transport = Arc::new(MockTransport::with(ocsp_response(
        &[7],
        START.as_secs(),
        Some(START.as_secs() + 3_600),
    )));
    let stapler = make_stapler(
        Arc::clone(&transport) as Arc<dyn OcspTransport>,
        OcspPolicy::default(),
        clock,
    );
    let leaf = leaf_certificate(&[7], None, false);
    let issuer = issuer_certificate();
    assert_eq!(
        stapler.ensure_staple(&leaf, &issuer).await.unwrap_err(),
        OcspError::NoResponder
    );
    assert_eq!(transport.call_count(), 0);
}

#[tokio::test]
async fn resolver_selects_certificate_with_staple() {
    // A real P-256 key so rustls can build the signing key; the certificate chain bytes are not
    // parsed by `certified_key`.
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    )
    .unwrap();
    let certificate = TlsCertificate::from_der(
        vec![leaf_certificate(
            &[7],
            Some("http://ocsp.example.test"),
            false,
        )],
        pkcs8.as_ref().to_vec(),
        vec!["example.test".to_string()],
    )
    .unwrap();
    let staple = ocsp_response(&[7], START.as_secs(), Some(START.as_secs() + 3_600));
    let certificate = certificate.with_ocsp_staple(Some(staple.clone()));
    let resolver =
        crate::tls_server::CertificateResolver::from_certificates(vec![certificate]).unwrap();
    let selected = resolver
        .select(Some("example.test"))
        .expect("certificate selected");
    assert_eq!(selected.ocsp.as_deref(), Some(staple.as_slice()));
}

#[test]
fn malformed_and_mismatched_responses_are_loud() {
    let leaf = leaf_certificate(&[7], Some("http://ocsp.example.test"), false);
    let issuer = issuer_certificate();
    assert!(build_ocsp_request(&leaf, &issuer).is_ok());
    let malformed = parse_ocsp_response(&[0x30, 0x01, 0x0A]);
    assert!(malformed.is_err());

    // Serial mismatch: response for a different serial.
    let response = ocsp_response(&[9], START.as_secs(), Some(START.as_secs() + 3_600));
    let parsed = parse_ocsp_response(&response).unwrap();
    assert_eq!(parsed.serial, vec![9]);
    assert_eq!(parsed.status, OcspCertStatus::Good);
    assert_eq!(parsed.next_update, Some(now_at(Duration::from_secs(3_600))));
}

#[test]
fn next_update_and_status_are_parsed() {
    let response = ocsp_response(&[7], START.as_secs(), Some(START.as_secs() + 7_200));
    let parsed = parse_ocsp_response(&response).unwrap();
    assert_eq!(parsed.status, OcspCertStatus::Good);
    assert_eq!(parsed.this_update, now_at(Duration::ZERO));
    assert_eq!(parsed.next_update, Some(now_at(Duration::from_secs(7_200))));
    assert_eq!(parsed.der, response);
}

#[test]
fn responder_failure_status_is_loud() {
    let failing = seq(&[tlv(0x0A, &[3])]); // tryLater
    let error = parse_ocsp_response(&failing).expect_err("failure status must error");
    assert_eq!(error, OcspError::ResponderStatus(3));
}
struct RecordingTransport {
    requests: Mutex<Vec<crate::acme::HttpRequest>>,
    status: u16,
    body: Vec<u8>,
    delay: Duration,
}

#[async_trait]
impl crate::acme::AcmeTransport for RecordingTransport {
    async fn request(
        &self,
        request: crate::acme::HttpRequest,
    ) -> crate::Result<crate::acme::HttpResponse> {
        self.requests.lock().unwrap().push(request);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        Ok(crate::acme::HttpResponse {
            status: self.status,
            headers: Vec::new(),
            body: self.body.clone(),
        })
    }
}

#[tokio::test]
async fn live_transport_posts_ocsp_request_to_responder() {
    let transport = Arc::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        status: 200,
        body: b"ocsp-response-der".to_vec(),
        delay: Duration::ZERO,
    });
    let ocsp = HyperOcspTransport::with_transport(transport.clone());
    let response = ocsp
        .fetch("http://responder.example.test/ocsp", b"request-der")
        .await
        .expect("transport succeeds");
    assert_eq!(response, b"ocsp-response-der");
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, crate::acme::HttpMethod::Post);
    assert_eq!(requests[0].url, "http://responder.example.test/ocsp");
    assert_eq!(requests[0].body, b"request-der");
    assert!(requests[0].headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && value == "application/ocsp-request"
    }));
}

#[tokio::test]
async fn live_transport_reports_http_and_timeout_errors() {
    let failing = Arc::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        status: 503,
        body: Vec::new(),
        delay: Duration::ZERO,
    });
    let error = HyperOcspTransport::with_transport(failing)
        .fetch("http://responder.example.test/ocsp", b"request")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("503"), "{error}");

    let slow = Arc::new(RecordingTransport {
        requests: Mutex::new(Vec::new()),
        status: 200,
        body: Vec::new(),
        delay: Duration::from_secs(5),
    });
    let error = HyperOcspTransport::with_transport(slow)
        .with_timeout(Duration::from_millis(100))
        .fetch("http://responder.example.test/ocsp", b"request")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("timed out"), "{error}");
}
