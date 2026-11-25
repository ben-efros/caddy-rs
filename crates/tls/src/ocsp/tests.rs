//! Deterministic tests for the TLS-side OCSP stapler.
//!
//! Fixtures are DER documents generated in-test (no network, no external files): a test CA, a
//! leaf and delegated responder certificates, and OCSP responses signed with real ECDSA keys, so
//! the signature / CertID / freshness checks (SEC-MEDIUM D1) run against genuine signatures.

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

// --- Real-key PKI fixtures -------------------------------------------------------------------
//
// Every certificate and OCSP response below is signed with a freshly generated ECDSA P-256 key
// (aws-lc-rs, already a dependency), so the stapler's signature verification is exercised against
// genuine signatures, not structural placeholders (SEC-MEDIUM D1).

use std::sync::OnceLock;

use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

struct TestKey {
    pair: EcdsaKeyPair,
}

impl TestKey {
    fn generate() -> Self {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        Self { pair }
    }

    fn public(&self) -> Vec<u8> {
        self.pair.public_key().as_ref().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        self.pair.sign(&rng, message).unwrap().as_ref().to_vec()
    }
}

fn ecdsa_sha256_alg() -> Vec<u8> {
    seq(&[oid(&[1, 2, 840, 10045, 4, 3, 2])])
}

fn name(common_name: &str) -> Vec<u8> {
    seq(&[tlv(
        0x31,
        &seq(&[oid(&[2, 5, 4, 3]), tlv(0x0C, common_name.as_bytes())]),
    )])
}

struct CertSpec<'a> {
    serial: &'a [u8],
    issuer: Vec<u8>,
    subject: Vec<u8>,
    key: &'a TestKey,
    signer: &'a TestKey,
    not_before: u64,
    not_after: u64,
    ocsp_url: Option<&'a str>,
    must_staple: bool,
    /// `None`: no ExtendedKeyUsage extension. `Some(true)`: id-kp-OCSPSigning. `Some(false)`:
    /// id-kp-serverAuth only.
    eku_ocsp_signing: Option<bool>,
    /// Mark the EKU extension `critical TRUE` (real certificates often do).
    critical_eku: bool,
}

fn build_cert(spec: &CertSpec<'_>) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(url) = spec.ocsp_url {
        let access = seq(&[
            oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1]),
            tlv(0x86, url.as_bytes()),
        ]);
        extensions.push(extension(&[1, 3, 6, 1, 5, 5, 7, 1, 1], &seq(&[access])));
    }
    if spec.must_staple {
        extensions.push(extension(
            &[1, 3, 6, 1, 5, 5, 7, 1, 24],
            &seq(&[integer_bytes(&[5])]),
        ));
    }
    if let Some(ocsp_signing) = spec.eku_ocsp_signing {
        let purpose = if ocsp_signing {
            oid(&[1, 3, 6, 1, 5, 5, 7, 3, 9])
        } else {
            oid(&[1, 3, 6, 1, 5, 5, 7, 3, 1])
        };
        let value = seq(&[purpose]);
        if spec.critical_eku {
            extensions.push(seq(&[
                oid(&[2, 5, 29, 37]),
                tlv(0x01, &[0xFF]),
                octet(&value),
            ]));
        } else {
            extensions.push(extension(&[2, 5, 29, 37], &value));
        }
    }
    let extensions = if extensions.is_empty() {
        Vec::new()
    } else {
        tlv(0xA3, &seq(&extensions))
    };
    let tbs = seq(&[
        tlv(0xA0, &integer_bytes(&[2])),
        integer_bytes(spec.serial),
        ecdsa_sha256_alg(),
        spec.issuer.clone(),
        seq(&[utc_time(spec.not_before), utc_time(spec.not_after)]),
        spec.subject.clone(),
        spki(&spec.key.public()),
        extensions,
    ]);
    let signature = spec.signer.sign(&tbs);
    seq(&[tbs, ecdsa_sha256_alg(), bit_string(&signature)])
}

struct Pki {
    ca: TestKey,
    ca_name: Vec<u8>,
    ca_cert: Vec<u8>,
    leaf_key: TestKey,
    /// An unrelated key/identity that is NOT the issuer.
    rogue: TestKey,
    rogue_name: Vec<u8>,
}

fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let ca = TestKey::generate();
        let ca_name = name("Test OCSP CA");
        let ca_cert = build_cert(&CertSpec {
            serial: &[2],
            issuer: ca_name.clone(),
            subject: ca_name.clone(),
            key: &ca,
            signer: &ca,
            not_before: START.as_secs() - 86_400,
            not_after: START.as_secs() + 365 * 86_400,
            ocsp_url: None,
            must_staple: false,
            eku_ocsp_signing: None,
            critical_eku: false,
        });
        Pki {
            ca,
            ca_name,
            ca_cert,
            leaf_key: TestKey::generate(),
            rogue: TestKey::generate(),
            rogue_name: name("Rogue CA"),
        }
    })
}

fn leaf_certificate(serial: &[u8], ocsp_url: Option<&str>, must_staple: bool) -> Vec<u8> {
    let pki = pki();
    build_cert(&CertSpec {
        serial,
        issuer: pki.ca_name.clone(),
        subject: name("leaf.example.test"),
        key: &pki.leaf_key,
        signer: &pki.ca,
        not_before: START.as_secs(),
        not_after: START.as_secs() + 86_400,
        ocsp_url,
        must_staple,
        eku_ocsp_signing: None,
        critical_eku: false,
    })
}

fn issuer_certificate() -> Vec<u8> {
    pki().ca_cert.clone()
}

/// A delegated OCSP responder certificate (RFC 6960 section 4.2.2.2) with a fresh key, issued by
/// `issuer_key` under `issuer_name`. Returns `(responder key, responder subject Name, certificate)`.
fn delegated_responder(
    issuer_name: &[u8],
    issuer_key: &TestKey,
    eku_ocsp_signing: Option<bool>,
    not_before: u64,
    not_after: u64,
) -> (TestKey, Vec<u8>, Vec<u8>) {
    let key = TestKey::generate();
    let subject = name("Delegated OCSP Responder");
    let cert = build_cert(&CertSpec {
        serial: &[0x44],
        issuer: issuer_name.to_vec(),
        subject: subject.clone(),
        key: &key,
        signer: issuer_key,
        not_before,
        not_after,
        ocsp_url: None,
        must_staple: false,
        eku_ocsp_signing,
        critical_eku: true,
    });
    (key, subject, cert)
}

/// Everything about a test OCSP response that a test may want to bend.
struct ResponseSpec<'a> {
    /// Raw INTEGER content (may be empty).
    serial: Vec<u8>,
    status_tag: u8,
    this_update: u64,
    next_update: Option<u64>,
    /// Complete ResponderID TLV (`[1] byName` / `[2] byKey`).
    responder_id: Vec<u8>,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
    signer: &'a TestKey,
    /// Sign a different message than the ResponseData that is transmitted (tampered body).
    sign_other_message: bool,
    /// Flip one bit of the signature after signing.
    corrupt_signature: bool,
    signature_algorithm: Vec<u8>,
    certs: Vec<Vec<u8>>,
}

impl ResponseSpec<'static> {
    /// A well-formed `good` response for `serial`, signed directly by the issuer (CA) key.
    fn good(serial: &[u8], this_update: u64, next_update: Option<u64>) -> Self {
        let pki = pki();
        ResponseSpec {
            serial: serial.to_vec(),
            status_tag: 0x80,
            this_update,
            next_update,
            responder_id: tlv(0xA1, &pki.ca_name),
            issuer_name_hash: Sha1::digest(&pki.ca_name).to_vec(),
            issuer_key_hash: Sha1::digest(pki.ca.public()).to_vec(),
            signer: &pki.ca,
            sign_other_message: false,
            corrupt_signature: false,
            signature_algorithm: ecdsa_sha256_alg(),
            certs: Vec::new(),
        }
    }
}

impl<'a> ResponseSpec<'a> {
    fn signed_by<'b>(self, signer: &'b TestKey) -> ResponseSpec<'b> {
        ResponseSpec { signer, ..self }
    }

    fn build(&self) -> Vec<u8> {
        let cert_id = seq(&[
            seq(&[oid(&[1, 3, 14, 3, 2, 26]), super::der_null()]),
            octet(&self.issuer_name_hash),
            octet(&self.issuer_key_hash),
            tlv(0x02, &self.serial),
        ]);
        let mut single = vec![
            cert_id,
            tlv(self.status_tag, &[]),
            utc_time(self.this_update),
        ];
        if let Some(next_update) = self.next_update {
            single.push(tlv(0xA0, &utc_time(next_update)));
        }
        let response_data = seq(&[
            self.responder_id.clone(),
            utc_time(self.this_update),
            seq(&[seq(&single)]),
        ]);
        let signed = if self.sign_other_message {
            let mut other = response_data.clone();
            let last = other.len() - 1;
            other[last] ^= 0x01;
            other
        } else {
            response_data.clone()
        };
        let mut signature = self.signer.sign(&signed);
        if self.corrupt_signature {
            let last = signature.len() - 1;
            signature[last] ^= 0x01;
        }
        let mut basic = vec![
            response_data,
            self.signature_algorithm.clone(),
            bit_string(&signature),
        ];
        if !self.certs.is_empty() {
            basic.push(tlv(0xA0, &seq(&self.certs)));
        }
        let response_bytes = seq(&[oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]), octet(&seq(&basic))]);
        seq(&[tlv(0x0A, &[0]), tlv(0xA0, &response_bytes)])
    }
}

fn ocsp_response(serial: &[u8], this_update: u64, next_update: Option<u64>) -> Vec<u8> {
    ResponseSpec::good(serial, this_update, next_update).build()
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
    // The refreshed response is produced when the refresh happens (clock = START + 3h + 60s); a
    // thisUpdate an hour in the future would now be rejected as not yet valid (SEC-MEDIUM D1).
    transport.push(ocsp_response(
        &[7],
        START.as_secs() + 3 * 3_600 + 60,
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
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::EcdsaKeyPair::generate_pkcs8(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
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

// --- SEC-MEDIUM D1: signature / CertID / freshness verification -------------------------------

const HOUR: u64 = 3_600;

/// Drive one response through `ensure_staple` at `START + at` and return the outcome together with
/// the stapler (so a test can assert that a rejected response was never cached).
async fn stapling_outcome(
    response: Vec<u8>,
    at: Duration,
) -> (Result<StapleOutcome, OcspError>, Arc<OcspStapler>, Vec<u8>) {
    let clock = Arc::new(ManualClock::new(now_at(at)));
    let transport = Arc::new(MockTransport::with(response));
    let stapler = make_stapler(
        transport as Arc<dyn OcspTransport>,
        OcspPolicy::default(),
        clock,
    );
    let leaf = leaf_certificate(&[7], Some("http://ocsp.example.test"), false);
    let issuer = issuer_certificate();
    let outcome = stapler.ensure_staple(&leaf, &issuer).await;
    (outcome, stapler, leaf)
}

fn good(this_update: u64, next_update: Option<u64>) -> ResponseSpec<'static> {
    ResponseSpec::good(&[7], this_update, next_update)
}

async fn assert_rejected(
    response: Vec<u8>,
    at: Duration,
    matcher: impl FnOnce(&OcspError) -> bool,
    what: &str,
) {
    let (outcome, stapler, leaf) = stapling_outcome(response, at).await;
    match outcome {
        Ok(outcome) => panic!("{what}: a forged/invalid response was accepted ({outcome:?})"),
        Err(error) => assert!(matcher(&error), "{what}: unexpected error {error:?}"),
    }
    assert!(
        stapler.staple(&leaf).is_none(),
        "{what}: a rejected response must never be cached for stapling"
    );
}

#[tokio::test]
async fn valid_response_signed_by_issuer_is_accepted() {
    let response = good(START.as_secs(), Some(START.as_secs() + 4 * HOUR)).build();
    let (outcome, stapler, leaf) = stapling_outcome(response.clone(), Duration::ZERO).await;
    assert_eq!(outcome.unwrap(), StapleOutcome::Fetched);
    assert_eq!(stapler.staple(&leaf), Some(response));
}

#[tokio::test]
async fn valid_response_with_responder_id_by_key_is_accepted() {
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    spec.responder_id = tlv(0xA2, &octet(&Sha1::digest(pki().ca.public())));
    let (outcome, _, _) = stapling_outcome(spec.build(), Duration::ZERO).await;
    assert_eq!(outcome.unwrap(), StapleOutcome::Fetched);
}

#[tokio::test]
async fn response_signed_by_an_unrelated_key_is_rejected() {
    // A forged "good" response: right CertID, claims to be the issuer, signed by the attacker.
    let pki = pki();
    let spec = good(START.as_secs(), Some(START.as_secs() + HOUR)).signed_by(&pki.rogue);
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::SignatureInvalid(_)),
        "wrong signer",
    )
    .await;
}

#[tokio::test]
async fn response_with_tampered_body_is_rejected() {
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    spec.sign_other_message = true;
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::SignatureInvalid(_)),
        "tampered body",
    )
    .await;
}

#[tokio::test]
async fn response_with_corrupted_signature_is_rejected() {
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    spec.corrupt_signature = true;
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::SignatureInvalid(_)),
        "corrupted signature",
    )
    .await;
}

#[tokio::test]
async fn response_with_unsupported_signature_algorithm_is_rejected() {
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    // ecdsa-with-SHA1: deliberately not supported.
    spec.signature_algorithm = seq(&[oid(&[1, 2, 840, 10045, 4, 1])]);
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::SignatureInvalid(_)),
        "unsupported algorithm",
    )
    .await;
}

#[tokio::test]
async fn forged_revoked_response_is_a_signature_failure_not_a_trusted_revocation() {
    let pki = pki();
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR)).signed_by(&pki.rogue);
    spec.status_tag = 0xA1; // revoked [1] IMPLICIT RevokedInfo
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::SignatureInvalid(_)),
        "forged revoked",
    )
    .await;
}

#[tokio::test]
async fn genuine_revoked_and_unknown_responses_are_never_stapled() {
    for tag in [0xA1u8, 0x82u8] {
        let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
        spec.status_tag = tag;
        assert_rejected(
            spec.build(),
            Duration::ZERO,
            |error| matches!(error, OcspError::ResponderStatus(_)),
            "non-good status",
        )
        .await;
    }
}

#[tokio::test]
async fn response_for_a_different_serial_is_rejected() {
    let spec = ResponseSpec::good(&[9], START.as_secs(), Some(START.as_secs() + HOUR));
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::SerialMismatch),
        "wrong serial",
    )
    .await;
}

#[tokio::test]
async fn serial_match_ignores_redundant_leading_zero_but_not_value() {
    // 0x0007 and 0x07 are the same number; 0x0107 is not.
    let spec = ResponseSpec::good(&[0, 7], START.as_secs(), Some(START.as_secs() + HOUR));
    let (outcome, _, _) = stapling_outcome(spec.build(), Duration::ZERO).await;
    assert_eq!(outcome.unwrap(), StapleOutcome::Fetched);
    let spec = ResponseSpec::good(&[1, 7], START.as_secs(), Some(START.as_secs() + HOUR));
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::SerialMismatch),
        "different serial value",
    )
    .await;
}

#[tokio::test]
async fn response_with_empty_serial_is_rejected() {
    // The old check `response.serial != request.serial && !response.serial.is_empty()` let an
    // empty serial skip matching entirely.
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    spec.serial = Vec::new();
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::Malformed(_) | OcspError::SerialMismatch),
        "empty serial",
    )
    .await;
}

#[tokio::test]
async fn response_with_wrong_issuer_hashes_is_rejected() {
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    spec.issuer_name_hash = vec![0u8; 20];
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::IssuerMismatch),
        "wrong issuerNameHash",
    )
    .await;

    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    spec.issuer_key_hash = vec![0u8; 20];
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::IssuerMismatch),
        "wrong issuerKeyHash",
    )
    .await;
}

#[tokio::test]
async fn expired_response_is_rejected_and_next_update_boundary_is_exclusive() {
    let spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    // One second before nextUpdate: still valid.
    let (outcome, _, _) = stapling_outcome(spec.build(), Duration::from_secs(HOUR - 1)).await;
    assert_eq!(outcome.unwrap(), StapleOutcome::Fetched);
    // At nextUpdate and after: stale.
    for at in [HOUR, HOUR + 1, 10 * HOUR] {
        assert_rejected(
            spec.build(),
            Duration::from_secs(at),
            |error| matches!(error, OcspError::Expired),
            "expired",
        )
        .await;
    }
}

#[tokio::test]
async fn not_yet_valid_response_is_rejected_beyond_the_clock_skew() {
    // thisUpdate is `ahead` seconds after "now" (START).
    let at_skew = good(START.as_secs() + 300, Some(START.as_secs() + 2 * HOUR));
    let (outcome, _, _) = stapling_outcome(at_skew.build(), Duration::ZERO).await;
    assert_eq!(
        outcome.unwrap(),
        StapleOutcome::Fetched,
        "5 minutes of skew is tolerated"
    );
    let beyond = good(START.as_secs() + 301, Some(START.as_secs() + 2 * HOUR));
    assert_rejected(
        beyond.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::NotYetValid),
        "future thisUpdate",
    )
    .await;
}

#[tokio::test]
async fn response_without_next_update_is_accepted_when_otherwise_valid() {
    // RFC 6960 makes nextUpdate optional; certmagic treats a missing nextUpdate as "no expiry
    // information" and refreshes by schedule. A valid, signed response without it still staples.
    let (outcome, _, _) =
        stapling_outcome(good(START.as_secs(), None).build(), Duration::ZERO).await;
    assert_eq!(outcome.unwrap(), StapleOutcome::Fetched);
}

#[tokio::test]
async fn garbage_and_truncated_responses_are_rejected() {
    let valid = good(START.as_secs(), Some(START.as_secs() + HOUR)).build();
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"not der at all".to_vec(),
        vec![0x30, 0x00],
        valid[..valid.len() / 2].to_vec(),
        valid[..valid.len() - 1].to_vec(),
    ];
    for input in inputs {
        assert_rejected(
            input,
            Duration::ZERO,
            |error| matches!(error, OcspError::Malformed(_)),
            "garbage",
        )
        .await;
    }
}

#[tokio::test]
async fn response_without_signature_is_rejected() {
    // BasicOCSPResponse with only tbsResponseData (no signatureAlgorithm / signature).
    let spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    let full = spec.build();
    // Re-wrap: parse out nothing, rebuild a basic response lacking the signature fields.
    let pki = pki();
    let cert_id = seq(&[
        seq(&[oid(&[1, 3, 14, 3, 2, 26]), super::der_null()]),
        octet(&Sha1::digest(&pki.ca_name)),
        octet(&Sha1::digest(pki.ca.public())),
        tlv(0x02, &[7]),
    ]);
    let single = seq(&[
        cert_id,
        tlv(0x80, &[]),
        utc_time(START.as_secs()),
        tlv(0xA0, &utc_time(START.as_secs() + HOUR)),
    ]);
    let data = seq(&[
        tlv(0xA1, &pki.ca_name),
        utc_time(START.as_secs()),
        seq(&[single]),
    ]);
    let basic = seq(&[data]);
    let response_bytes = seq(&[oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]), octet(&basic)]);
    let unsigned = seq(&[tlv(0x0A, &[0]), tlv(0xA0, &response_bytes)]);
    assert_ne!(unsigned, full);
    assert_rejected(
        unsigned,
        Duration::ZERO,
        |error| {
            matches!(
                error,
                OcspError::Malformed(_) | OcspError::SignatureInvalid(_)
            )
        },
        "unsigned",
    )
    .await;
}

// --- Delegated responders ---------------------------------------------------------------------

fn delegated_response(
    eku: Option<bool>,
    cert_not_before: u64,
    cert_not_after: u64,
    cert_issuer_is_ca: bool,
) -> Vec<u8> {
    let pki = pki();
    let (issuer_name, issuer_key) = if cert_issuer_is_ca {
        (pki.ca_name.clone(), &pki.ca)
    } else {
        (pki.rogue_name.clone(), &pki.rogue)
    };
    let (key, subject, cert) = delegated_responder(
        &issuer_name,
        issuer_key,
        eku,
        cert_not_before,
        cert_not_after,
    );
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR)).signed_by(&key);
    spec.responder_id = tlv(0xA1, &subject);
    spec.certs = vec![cert];
    spec.build()
}

#[tokio::test]
async fn delegated_responder_with_ocsp_signing_eku_is_accepted() {
    let response = delegated_response(
        Some(true),
        START.as_secs() - HOUR,
        START.as_secs() + 30 * 86_400,
        true,
    );
    let (outcome, _, _) = stapling_outcome(response, Duration::ZERO).await;
    assert_eq!(outcome.unwrap(), StapleOutcome::Fetched);
}

#[tokio::test]
async fn delegated_responder_without_ocsp_signing_eku_is_rejected() {
    for eku in [None, Some(false)] {
        let response = delegated_response(
            eku,
            START.as_secs() - HOUR,
            START.as_secs() + 30 * 86_400,
            true,
        );
        assert_rejected(
            response,
            Duration::ZERO,
            |error| matches!(error, OcspError::UnauthorizedResponder(_)),
            "delegated responder without id-kp-OCSPSigning",
        )
        .await;
    }
}

#[tokio::test]
async fn delegated_responder_not_issued_by_the_issuer_is_rejected() {
    let response = delegated_response(
        Some(true),
        START.as_secs() - HOUR,
        START.as_secs() + 30 * 86_400,
        false,
    );
    assert_rejected(
        response,
        Duration::ZERO,
        |error| matches!(error, OcspError::UnauthorizedResponder(_)),
        "delegated responder chained to another CA",
    )
    .await;
}

#[tokio::test]
async fn delegated_responder_outside_its_validity_is_rejected() {
    // Expired responder certificate.
    let expired = delegated_response(
        Some(true),
        START.as_secs() - 2 * HOUR,
        START.as_secs() - HOUR,
        true,
    );
    assert_rejected(
        expired,
        Duration::ZERO,
        |error| matches!(error, OcspError::UnauthorizedResponder(_)),
        "expired responder certificate",
    )
    .await;
    // Not yet valid responder certificate.
    let future = delegated_response(
        Some(true),
        START.as_secs() + HOUR,
        START.as_secs() + 2 * HOUR,
        true,
    );
    assert_rejected(
        future,
        Duration::ZERO,
        |error| matches!(error, OcspError::UnauthorizedResponder(_)),
        "not-yet-valid responder certificate",
    )
    .await;
}

#[tokio::test]
async fn delegated_responder_certificate_must_match_the_response_signature() {
    // Valid delegated cert attached, but the response is signed by a different (attacker) key.
    let pki = pki();
    let (_key, subject, cert) = delegated_responder(
        &pki.ca_name,
        &pki.ca,
        Some(true),
        START.as_secs() - HOUR,
        START.as_secs() + 30 * 86_400,
    );
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR)).signed_by(&pki.rogue);
    spec.responder_id = tlv(0xA1, &subject);
    spec.certs = vec![cert];
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::SignatureInvalid(_)),
        "delegated cert attached but signed by someone else",
    )
    .await;
}

// --- Signature-algorithm coverage (direct) -----------------------------------------------------

#[test]
fn verify_signature_covers_every_supported_algorithm_and_rejects_mismatches() {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P384_SHA384_ASN1_SIGNING,
    };
    let rng = SystemRandom::new();
    let message = b"tbsResponseData";

    // Ed25519.
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let ed = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let signature = ed.sign(message);
    let public = ed.public_key().as_ref().to_vec();
    super::verify_signature(&[0x2B, 0x65, 0x70], &public, message, signature.as_ref()).unwrap();
    assert!(
        super::verify_signature(&[0x2B, 0x65, 0x70], &public, b"other", signature.as_ref())
            .is_err()
    );

    // ECDSA P-384 / SHA-384.
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
    let p384 = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
    let signature = p384.sign(&rng, message).unwrap();
    let public = p384.public_key().as_ref().to_vec();
    let sha384 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
    super::verify_signature(&sha384, &public, message, signature.as_ref()).unwrap();
    assert!(super::verify_signature(&sha384, &public, b"other", signature.as_ref()).is_err());
    // A P-256 key cannot satisfy a P-384 signature.
    let other = TestKey::generate();
    assert!(
        super::verify_signature(&sha384, &other.public(), message, signature.as_ref()).is_err()
    );

    // RSA PKCS#1 v1.5 / SHA-256 (2048-bit).
    let rsa = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let mut signature = vec![0u8; rsa.public_modulus_len()];
    rsa.sign(
        &aws_lc_rs::signature::RSA_PKCS1_SHA256,
        &rng,
        message,
        &mut signature,
    )
    .unwrap();
    let public = rsa.public_key().as_ref().to_vec();
    let rsa_sha256 = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
    super::verify_signature(&rsa_sha256, &public, message, &signature).unwrap();
    assert!(super::verify_signature(&rsa_sha256, &public, b"other", &signature).is_err());

    // Unknown algorithm OID.
    assert!(super::verify_signature(&[0x2A, 0x03], &public, message, &signature).is_err());
}
