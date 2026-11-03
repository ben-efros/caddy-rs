//! End-to-end automatic-HTTPS tests: a fake local ACME CA issues certificates through the real
//! issuer/order/challenge path, the server derives the HTTP challenge/redirect listener, and
//! HTTPS is served from the obtained certificate.
//!
//! Nothing here touches the network: the fake CA is an in-process [`AcmeTransport`] that speaks
//! just enough RFC 8555 for the existing [`caddy_rs_tls::AcmeIssuer`], and signs the CSR produced
//! during finalization with an embedded test CA so the resulting certificate is usable for a real
//! rustls handshake.

use std::net::SocketAddr;
use std::os::fd::IntoRawFd;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::{ServerRuntime, SocketActivation};
use caddy_rs_tls::{
    AcmeTransport, CertificateStorage, FileStorage, HttpMethod, HttpRequest, HttpResponse,
};

const CA_PEM: &str = include_str!("../../tls/testdata/auto-https/ca.pem");
const CA_KEY_PEM: &str = include_str!("../../tls/testdata/auto-https/ca.key");

const DIRECTORY: &str = "https://acme.test/directory";
const NEW_ACCOUNT: &str = "https://acme.test/new-account";
const NEW_ORDER: &str = "https://acme.test/new-order";
const ACCOUNT: &str = "https://acme.test/account/1";
const ORDER: &str = "https://acme.test/order/1";
const AUTHZ: &str = "https://acme.test/authz/1";
const CHALLENGE: &str = "https://acme.test/challenge/1";
const TLS_ALPN_CHALLENGE: &str = "https://acme.test/challenge/tls-alpn/1";
const FINALIZE: &str = "https://acme.test/finalize/1";
const CERTIFICATE: &str = "https://acme.test/cert/1";

// ---- fake ACME CA ----------------------------------------------------------------------------

#[derive(Debug, Default)]
struct CaState {
    domains: Vec<String>,
    csr: Option<Vec<u8>>,
    challenge_acked: bool,
    cert_pem: Option<String>,
    fail_new_order: bool,
    /// Which challenge type the issuer selected ("http-01" or "tls-alpn-01").
    selected_challenge: Option<String>,
    /// When set, `tls-alpn-01` acknowledgements probe this TLS listener like a real ACME CA.
    tls_alpn_probe: Option<SocketAddr>,
    /// Challenge certificate captured by the TLS-ALPN-01 probe.
    tls_alpn_certificate: Option<Vec<u8>>,
    /// Number of successful TLS-ALPN-01 probes.
    tls_alpn_validations: usize,
    /// Probe failure detail, when the CA could not validate TLS-ALPN-01.
    probe_failure: Option<String>,
}

/// A local fake ACME CA. Enough RFC 8555 to drive `AcmeIssuer`; it signs the finalize CSR with
/// the embedded test CA so the certificate is valid for a rustls client that trusts that CA.
#[derive(Clone)]
struct FakeCa {
    state: Arc<Mutex<CaState>>,
    ca_cert_der: Vec<u8>,
    ca_key: Arc<EcdsaKeyPair>,
}

impl FakeCa {
    fn new(fail_new_order: bool) -> Self {
        let ca_cert_der = caddy_rs_tls::certificates_from_pem(CA_PEM).expect("CA fixture parses")
            [0]
        .as_ref()
        .to_vec();
        let key_der = pem_der(CA_KEY_PEM, "PRIVATE KEY");
        let rng = SystemRandom::new();
        let ca_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key_der, &rng)
            .expect("CA key parses");
        Self {
            state: Arc::new(Mutex::new(CaState {
                fail_new_order,
                ..CaState::default()
            })),
            ca_cert_der,
            ca_key: Arc::new(ca_key),
        }
    }

    fn domains(&self) -> Vec<String> {
        self.state.lock().unwrap().domains.clone()
    }

    fn set_fail_new_order(&self, fail: bool) {
        self.state.lock().unwrap().fail_new_order = fail;
    }

    /// Configure the CA to validate `tls-alpn-01` challenges by connecting to this TLS listener
    /// with ALPN `acme-tls/1` (a real RFC 8737 validation).
    fn with_tls_alpn_probe(self, address: SocketAddr) -> Self {
        self.state.lock().unwrap().tls_alpn_probe = Some(address);
        self
    }

    fn selected_challenge(&self) -> Option<String> {
        self.state.lock().unwrap().selected_challenge.clone()
    }

    fn tls_alpn_validations(&self) -> usize {
        self.state.lock().unwrap().tls_alpn_validations
    }

    fn tls_alpn_certificate(&self) -> Option<Vec<u8>> {
        self.state.lock().unwrap().tls_alpn_certificate.clone()
    }

    fn probe_failure(&self) -> Option<String> {
        self.state.lock().unwrap().probe_failure.clone()
    }
}

fn pem_der(pem: &str, label: &str) -> Vec<u8> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut inside = false;
    let mut encoded = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line == begin {
            inside = true;
        } else if line == end {
            inside = false;
        } else if inside {
            encoded.push_str(line);
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .expect("PEM base64 decodes")
}

fn json_response(status: u16, body: serde_json::Value) -> HttpResponse {
    HttpResponse::with_json(status, &body)
        .expect("JSON response")
        .with_header("Replay-Nonce", "nonce-1")
}

fn signed_payload(request: &HttpRequest) -> serde_json::Value {
    let jws: serde_json::Value = serde_json::from_slice(&request.body).expect("JWS body");
    let payload = jws["payload"].as_str().expect("payload");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .expect("payload base64");
    serde_json::from_slice(&bytes).expect("payload JSON")
}

#[async_trait::async_trait]
impl AcmeTransport for FakeCa {
    async fn request(&self, request: HttpRequest) -> caddy_rs_tls::Result<HttpResponse> {
        let url = request.url.clone();
        if request.method == HttpMethod::Get && url.ends_with("/directory") {
            return Ok(json_response(
                200,
                serde_json::json!({
                    "newNonce": "https://acme.test/new-nonce",
                    "newAccount": NEW_ACCOUNT,
                    "newOrder": NEW_ORDER,
                    "revokeCert": "https://acme.test/revoke",
                    "meta": {}
                }),
            ));
        }
        if url == NEW_ACCOUNT {
            return Ok(json_response(
                201,
                serde_json::json!({
                    "status": "valid",
                    "contact": ["mailto:ops@example.com"],
                    "orders": "https://acme.test/account/1/orders"
                }),
            )
            .with_header("Location", ACCOUNT));
        }
        if url == NEW_ORDER {
            let payload = signed_payload(&request);
            let domains: Vec<String> = payload["identifiers"]
                .as_array()
                .map(|identifiers| {
                    identifiers
                        .iter()
                        .filter_map(|identifier| identifier["value"].as_str())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let fail = self.state.lock().unwrap().fail_new_order;
            if fail {
                return Ok(HttpResponse::with_problem(
                    400,
                    &serde_json::json!({
                        "type": "urn:ietf:params:acme:error:serverInternal",
                        "detail": "fake CA is configured to fail newOrder",
                        "status": 400
                    }),
                )
                .unwrap()
                .with_header("Replay-Nonce", "nonce-1"));
            }
            self.state.lock().unwrap().domains = domains;
            return Ok(json_response(
                201,
                serde_json::json!({
                    "status": "pending",
                    "identifiers": payload["identifiers"],
                    "authorizations": [AUTHZ],
                    "finalize": FINALIZE
                }),
            )
            .with_header("Location", ORDER));
        }
        if url == AUTHZ {
            let state = self.state.lock().unwrap();
            let status = if state.challenge_acked {
                "valid"
            } else {
                "pending"
            };
            let challenge_status = if state.challenge_acked {
                "valid"
            } else {
                "pending"
            };
            return Ok(json_response(
                200,
                serde_json::json!({
                    "status": status,
                    "identifier": {"type": "dns", "value": state.domains.first().cloned().unwrap_or_default()},
                    "challenges": [
                        {
                            "type": "http-01",
                            "url": CHALLENGE,
                            "token": "token-1",
                            "status": challenge_status
                        },
                        {
                            "type": "tls-alpn-01",
                            "url": TLS_ALPN_CHALLENGE,
                            "token": "token-1",
                            "status": challenge_status
                        }
                    ]
                }),
            ));
        }
        if url == CHALLENGE || url == TLS_ALPN_CHALLENGE {
            let challenge_type = if url == CHALLENGE {
                "http-01"
            } else {
                "tls-alpn-01"
            };
            let (probe, domain) = {
                let mut state = self.state.lock().unwrap();
                state.selected_challenge = Some(challenge_type.to_string());
                (state.tls_alpn_probe, state.domains.first().cloned())
            };
            if challenge_type == "tls-alpn-01" {
                let Some(address) = probe else {
                    let detail = "fake CA has no TLS-ALPN-01 probe configured".to_string();
                    self.state.lock().unwrap().probe_failure = Some(detail.clone());
                    return Ok(HttpResponse::with_problem(
                        400,
                        &serde_json::json!({
                            "type": "urn:ietf:params:acme:error:connection",
                            "detail": detail,
                            "status": 400
                        }),
                    )
                    .unwrap()
                    .with_header("Replay-Nonce", "nonce-1"));
                };
                let domain = domain.unwrap_or_default();
                match tls_alpn_probe(address, &domain).await {
                    Ok(certificate) => {
                        if let Err(error) = verify_tls_alpn_certificate(&certificate, &domain) {
                            self.state.lock().unwrap().probe_failure = Some(error.clone());
                            return Ok(HttpResponse::with_problem(
                                400,
                                &serde_json::json!({
                                    "type": "urn:ietf:params:acme:error:connection",
                                    "detail": error,
                                    "status": 400
                                }),
                            )
                            .unwrap()
                            .with_header("Replay-Nonce", "nonce-1"));
                        }
                        let mut state = self.state.lock().unwrap();
                        state.tls_alpn_certificate = Some(certificate);
                        state.tls_alpn_validations += 1;
                        state.challenge_acked = true;
                    }
                    Err(error) => {
                        self.state.lock().unwrap().probe_failure = Some(error.clone());
                        return Ok(HttpResponse::with_problem(
                            400,
                            &serde_json::json!({
                                "type": "urn:ietf:params:acme:error:connection",
                                "detail": error,
                                "status": 400
                            }),
                        )
                        .unwrap()
                        .with_header("Replay-Nonce", "nonce-1"));
                    }
                }
            } else {
                self.state.lock().unwrap().challenge_acked = true;
            }
            return Ok(json_response(
                200,
                serde_json::json!({
                    "type": challenge_type,
                    "url": url,
                    "token": "token-1",
                    "status": "processing"
                }),
            ));
        }
        if url == ORDER {
            let state = self.state.lock().unwrap();
            let status = if state.cert_pem.is_some() {
                "valid"
            } else {
                "ready"
            };
            let mut order = serde_json::json!({
                "status": status,
                "identifiers": state
                    .domains
                    .iter()
                    .map(|domain| serde_json::json!({"type": "dns", "value": domain}))
                    .collect::<Vec<_>>(),
                "authorizations": [AUTHZ],
                "finalize": FINALIZE
            });
            if state.cert_pem.is_some() {
                order["certificate"] = serde_json::json!(CERTIFICATE);
            }
            return Ok(json_response(200, order));
        }
        if url == FINALIZE {
            let payload = signed_payload(&request);
            let csr = payload["csr"].as_str().expect("csr field");
            let csr = URL_SAFE_NO_PAD
                .decode(csr.as_bytes())
                .expect("CSR base64url");
            let mut state = self.state.lock().unwrap();
            let domains = state.domains.clone();
            state.csr = Some(csr.clone());
            let leaf = issue_certificate(&self.ca_cert_der, &self.ca_key, &csr, &domains);
            state.cert_pem = Some(format!("{}\n{CA_PEM}", pem_encode("CERTIFICATE", &leaf)));
            return Ok(json_response(
                200,
                serde_json::json!({
                    "status": "processing",
                    "identifiers": domains
                        .iter()
                        .map(|domain| serde_json::json!({"type": "dns", "value": domain}))
                        .collect::<Vec<_>>(),
                    "authorizations": [AUTHZ],
                    "finalize": FINALIZE
                }),
            ));
        }
        if url == CERTIFICATE {
            let state = self.state.lock().unwrap();
            let pem = state.cert_pem.clone().expect("certificate issued");
            return Ok(HttpResponse::new(200)
                .with_header("Content-Type", "application/pem-certificate-chain")
                .with_header("Replay-Nonce", "nonce-1")
                .with_body(pem.into_bytes()));
        }
        Err(caddy_rs_tls::Error::Issuer(format!(
            "unexpected fake ACME request {} {}",
            request.method, url
        )))
    }
}

// ---- TLS-ALPN-01 CA validation ---------------------------------------------------------------

/// Test-only verifier that accepts the CA's own self-signed challenge certificate. A real ACME
/// CA does not chain-validate this certificate either; it only inspects the acmeIdentifier
/// extension.
#[derive(Debug)]
struct AcceptAnyCertificate {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_challenge_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_challenge_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Verify a handshake signature using the challenge certificate's P-256 public key.
///
/// `rustls::crypto::verify_tls13_signature` parses the certificate with webpki, which rejects the
/// challenge certificate's critical `id-pe-acmeIdentifier` extension; a real ACME CA ignores
/// normal path validation, so the test verifier extracts the SubjectPublicKeyInfo itself and
/// verifies the ECDSA signature with ring.
fn verify_challenge_signature(
    message: &[u8],
    certificate: &CertificateDer<'_>,
    signature: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    if signature.scheme != SignatureScheme::ECDSA_NISTP256_SHA256 {
        return Err(rustls::Error::General(
            "unsupported challenge certificate signature scheme".to_string(),
        ));
    }
    let public_key = certificate_public_key(certificate.as_ref());
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, signature.signature())
        .map(|()| HandshakeSignatureValid::assertion())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))
}

fn certificate_public_key(der: &[u8]) -> Vec<u8> {
    let outer = read_tlv(der);
    let parts = children_with_offsets(outer.content);
    let tbs = parts.first().expect("tbs certificate");
    let fields = children_with_offsets(tbs.content);
    let mut index = 0;
    if fields.first().is_some_and(|field| field.tag == 0xA0) {
        index += 1; // explicit version
    }
    // serial, signature algorithm, issuer, validity, subject, subjectPublicKeyInfo
    let spki = fields.get(index + 5).expect("subjectPublicKeyInfo");
    let spki_fields = children_with_offsets(spki.content);
    let key_bits = spki_fields.get(1).expect("subjectPublicKey BIT STRING");
    // BIT STRING content is `unused-bits-byte || key bytes`; it is not itself DER-encoded.
    key_bits
        .content
        .get(1..)
        .expect("public key bits after the unused-bits byte")
        .to_vec()
}

/// Connect like an ACME CA: ALPN `acme-tls/1`, accept the self-signed challenge certificate and
/// return its DER encoding.
async fn tls_alpn_probe(address: SocketAddr, domain: &str) -> Result<Vec<u8>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(AcceptAnyCertificate {
        provider: Arc::clone(&provider),
    });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("client protocol versions: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| format!("connect to TLS listener {address}: {error}"))?;
    let server_name = ServerName::try_from(domain.to_string())
        .map_err(|error| format!("invalid challenge domain {domain:?}: {error}"))?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("acme-tls/1 handshake failed: {error}"))?;
    let (_, session) = tls.get_ref();
    if session.alpn_protocol() != Some(b"acme-tls/1".as_slice()) {
        return Err(format!(
            "server did not negotiate acme-tls/1; got {:?}",
            session.alpn_protocol()
        ));
    }
    let certificates = session
        .peer_certificates()
        .ok_or_else(|| "acme-tls/1 server presented no certificate".to_string())?;
    let certificate = certificates
        .first()
        .ok_or_else(|| "acme-tls/1 server presented no certificate".to_string())?;
    Ok(certificate.as_ref().to_vec())
}

fn der_content<'a>(certificate: &'a [u8], tlv: &Tlv<'a>) -> &'a [u8] {
    // `Tlv` slices created by `children_with_offsets` already point at their content.
    let _ = certificate;
    tlv.content
}

/// Verify RFC 8737 challenge evidence: a subjectAltName dNSName for `domain` plus the critical
/// `id-pe-acmeIdentifier` extension wrapping a 32-byte SHA-256 digest.
fn verify_tls_alpn_certificate(certificate_der: &[u8], domain: &str) -> Result<(), String> {
    const SAN_OID: &[u8] = &[0x55, 0x1D, 0x11];
    const ACME_IDENTIFIER_OID_DER: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1F];

    let outer = read_tlv(certificate_der);
    if outer.tag != 0x30 {
        return Err("challenge certificate is not a DER SEQUENCE".to_string());
    }
    let parts = children_with_offsets(outer.content);
    if parts.len() < 3 {
        return Err("challenge certificate is truncated".to_string());
    }
    let tbs = &parts[0];
    let fields = children_with_offsets(tbs.content);
    let mut index = 0;
    if fields.first().is_some_and(|field| field.tag == 0xA0) {
        index += 1; // explicit version
    }
    // serial, signature algorithm, issuer, validity, subject, subjectPublicKeyInfo, [3] extensions
    let extensions = fields
        .get(index + 6)
        .filter(|field| field.tag == 0xA3)
        .ok_or_else(|| "challenge certificate has no extensions".to_string())?;
    let extension_sequence = read_tlv(extensions.content);
    if extension_sequence.tag != 0x30 {
        return Err("challenge certificate extensions are malformed".to_string());
    }

    let mut saw_subject_alt_name = false;
    let mut saw_identifier = false;
    for extension in children_with_offsets(extension_sequence.content) {
        let extension_fields = children_with_offsets(extension.content);
        let Some(oid) = extension_fields.first() else {
            continue;
        };
        if oid.tag != 0x06 {
            continue;
        }
        let oid_content = der_content(extension.content, oid);
        if oid_content == SAN_OID {
            let Some(value) = extension_fields.get(1) else {
                continue;
            };
            let names = read_tlv(value.content);
            for name in children_with_offsets(names.content) {
                if name.tag == 0x82 && der_content(names.content, &name) == domain.as_bytes() {
                    saw_subject_alt_name = true;
                }
            }
        } else if oid_content == ACME_IDENTIFIER_OID_DER {
            let Some(critical) = extension_fields.get(1).filter(|field| field.tag == 0x01) else {
                return Err("acmeIdentifier extension is not marked critical".to_string());
            };
            if der_content(extension.content, critical) != [0xFF] {
                return Err("acmeIdentifier extension critical flag is false".to_string());
            }
            let Some(value) = extension_fields.get(2).filter(|field| field.tag == 0x04) else {
                return Err("acmeIdentifier extension has no value".to_string());
            };
            let digest = read_tlv(value.content);
            if digest.tag != 0x04 || digest.content.len() != 32 {
                return Err(format!(
                    "acmeIdentifier must wrap a 32-byte OCTET STRING, got {} bytes",
                    digest.content.len()
                ));
            }
            saw_identifier = true;
        }
    }
    if !saw_subject_alt_name {
        return Err(format!(
            "challenge certificate SAN does not contain {domain:?}"
        ));
    }
    if !saw_identifier {
        return Err("challenge certificate has no id-pe-acmeIdentifier extension".to_string());
    }
    Ok(())
}

// ---- minimal X.509 issuance from the finalize CSR --------------------------------------------

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    start: usize,
    total: usize,
}

fn read_tlv(input: &[u8]) -> Tlv<'_> {
    assert!(input.len() >= 2, "truncated DER");
    let tag = input[0];
    let first = input[1];
    let (length, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    assert!(input.len() >= header + length, "truncated DER content");
    Tlv {
        tag,
        content: &input[header..header + length],
        start: 0,
        total: header + length,
    }
}

fn children_with_offsets(content: &[u8]) -> Vec<Tlv<'_>> {
    let mut children = Vec::new();
    let mut offset = 0;
    while offset < content.len() {
        let mut tlv = read_tlv(&content[offset..]);
        tlv.start = offset;
        offset += tlv.total;
        children.push(tlv);
    }
    children
}

fn raw<'a>(content: &'a [u8], tlv: &Tlv<'_>) -> &'a [u8] {
    &content[tlv.start..tlv.start + tlv.total]
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut bytes = length.to_be_bytes().to_vec();
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    let mut encoded = vec![0x80 | bytes.len() as u8];
    encoded.extend(bytes);
    encoded
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    encoded.extend(der_length(content.len()));
    encoded.extend_from_slice(content);
    encoded
}

fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    der_tlv(0x30, &items.concat())
}

fn der_set(items: &[Vec<u8>]) -> Vec<u8> {
    der_tlv(0x31, &items.concat())
}

fn der_integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = bytes[first..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der_tlv(0x02, &content)
}

fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut value = *arc;
        let mut stack = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            stack.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        stack.reverse();
        content.extend(stack);
    }
    der_tlv(0x06, &content)
}

fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut inner = vec![0u8];
    inner.extend_from_slice(content);
    der_tlv(0x03, &inner)
}

fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tlv(0x04, content)
}

fn der_utf8(value: &str) -> Vec<u8> {
    der_tlv(0x0C, value.as_bytes())
}

fn der_utc_time(value: &str) -> Vec<u8> {
    assert_eq!(value.len(), 13, "UTCTime is YYMMDDHHMMSSZ");
    der_tlv(0x17, value.as_bytes())
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn ca_issuer_name(ca_der: &[u8]) -> Vec<u8> {
    let outer = read_tlv(ca_der);
    let certificate = children_with_offsets(outer.content);
    let tbs = &certificate[0];
    let tbs_children = children_with_offsets(tbs.content);
    let mut index = 0;
    if tbs_children[0].tag == 0xA0 {
        index += 1; // explicit version
    }
    // serial, signature algorithm, issuer
    raw(tbs.content, &tbs_children[index + 2]).to_vec()
}

fn issue_certificate(
    ca_der: &[u8],
    ca_key: &EcdsaKeyPair,
    csr_der: &[u8],
    domains: &[String],
) -> Vec<u8> {
    let request = read_tlv(csr_der);
    let request_children = children_with_offsets(request.content);
    let info = &request_children[0];
    let info_children = children_with_offsets(info.content);
    // version, subject, subjectPKInfo, attributes
    let spki = raw(info.content, &info_children[2]).to_vec();

    let signature_algorithm = der_sequence(&[der_oid(&[1, 2, 840, 10045, 4, 3, 2])]);
    let issuer = ca_issuer_name(ca_der);
    let validity = der_sequence(&[der_utc_time("250101000000Z"), der_utc_time("350101000000Z")]);
    let common_name = domains.first().cloned().unwrap_or_default();
    let subject = der_sequence(&[der_set(&[der_sequence(&[
        der_oid(&[2, 5, 4, 3]),
        der_utf8(&common_name),
    ])])]);
    let general_names = domains
        .iter()
        .map(|domain| der_tlv(0x82, domain.as_bytes()))
        .collect::<Vec<_>>();
    let subject_alt_name = der_sequence(&[
        der_oid(&[2, 5, 29, 17]),
        der_octet_string(&der_sequence(&general_names)),
    ]);
    let basic_constraints = der_sequence(&[
        der_oid(&[2, 5, 29, 19]),
        der_octet_string(&der_sequence(&[der_tlv(0x01, &[0x00])])),
    ]);
    let extensions = der_sequence(&[subject_alt_name, basic_constraints]);
    let tbs = der_sequence(&[
        der_tlv(0xA0, &der_integer(2)),
        der_integer(1),
        signature_algorithm.clone(),
        issuer,
        validity,
        subject,
        spki,
        der_tlv(0xA3, &extensions),
    ]);
    let rng = SystemRandom::new();
    let signature = ca_key.sign(&rng, &tbs).expect("CA signs the leaf");
    der_sequence(&[tbs, signature_algorithm, der_bit_string(signature.as_ref())])
}

// ---- server configuration + clients ----------------------------------------------------------

fn config(
    listen: &str,
    http_port: Option<u16>,
    disable_redirects: bool,
    auto_https_disable: bool,
    storage_root: &str,
) -> Config {
    config_with_admin(
        listen,
        http_port,
        disable_redirects,
        auto_https_disable,
        storage_root,
        serde_json::json!({"disabled": true}),
    )
}

fn config_with_admin(
    listen: &str,
    http_port: Option<u16>,
    disable_redirects: bool,
    auto_https_disable: bool,
    storage_root: &str,
    admin: serde_json::Value,
) -> Config {
    let mut server = serde_json::json!({
        "listen": [listen],
        "tls_connection_policies": [{}],
        "routes": [{
            "match": [{"host": ["example.com"]}],
            "handle": [{"handler": "static_response", "body": "hello https"}]
        }]
    });
    if disable_redirects || auto_https_disable {
        let mut automatic_https = serde_json::Map::new();
        if disable_redirects {
            automatic_https.insert("disable_redirects".to_string(), serde_json::json!(true));
        }
        if auto_https_disable {
            automatic_https.insert("disable".to_string(), serde_json::json!(true));
        }
        server["automatic_https"] = serde_json::Value::Object(automatic_https);
    }
    let mut http = serde_json::json!({"servers": {"srv0": server}});
    if let Some(http_port) = http_port {
        http["http_port"] = serde_json::json!(http_port);
    }
    Config::from_value(serde_json::json!({
        "admin": admin,
        "storage": {"module": "file_system", "root": storage_root},
        "apps": {
            "tls": {"automation": {"policies": [{
                "subjects": ["example.com"],
                "issuers": [{"module": "acme", "ca": DIRECTORY, "email": "ops@example.com"}]
            }]}},
            "http": http
        }
    }))
    .expect("test config decodes")
}

fn client_config() -> Arc<rustls::ClientConfig> {
    client_config_with_alpn(&[])
}

fn client_config_with_alpn(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in caddy_rs_tls::certificates_from_pem(CA_PEM).expect("CA parses") {
        roots.add(certificate).expect("CA is a valid root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

async fn tls_connect(address: SocketAddr, server_name: &str) -> TlsStream<TcpStream> {
    tls_connect_result(address, server_name, client_config())
        .await
        .expect("TLS handshake")
}

async fn tls_connect_result(
    address: SocketAddr,
    server_name: &str,
    config: Arc<rustls::ClientConfig>,
) -> Result<TlsStream<TcpStream>, String> {
    let connector = TlsConnector::from(config);
    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| format!("TCP connect: {error}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|error| format!("invalid server name: {error}"))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("TLS handshake failed: {error}"))
}

async fn read_response<S>(stream: &mut S) -> (u16, Vec<(String, String)>, String)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("read response");
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers")
        + 4;
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    (
        status,
        headers,
        String::from_utf8_lossy(&response[split..]).into_owned(),
    )
}

async fn http_get<S>(stream: &mut S, host: &str, path: &str) -> (u16, Vec<(String, String)>, String)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    read_response(stream).await
}

async fn plain_get(
    address: SocketAddr,
    host: &str,
    path: &str,
) -> (u16, Vec<(String, String)>, String) {
    let mut stream = TcpStream::connect(address).await.expect("TCP connect");
    http_get(&mut stream, host, path).await
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

async fn apply(
    auto_https_disable: bool,
) -> (ServerRuntime, SocketAddr, SocketAddr, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config(
            "127.0.0.1:0",
            Some(0),
            false,
            auto_https_disable,
            &root,
        ))
        .expect("config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(Arc::new(FakeCa::new(false)))
        .with_data_root(directory.path());
    runtime.apply().await.expect("automatic HTTPS apply");
    let https = runtime
        .listener_address("127.0.0.1:0")
        .expect("HTTPS listener bound");
    let http = runtime
        .listener_address(":0")
        .expect("derived HTTP listener bound");
    (runtime, https, http, directory)
}

/// A fixed loopback port that is currently free (released immediately before use).
fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Send `POST <path>` over a fresh connection and return the status code.
async fn post_plain(address: SocketAddr, path: &str) -> u16 {
    let mut stream = TcpStream::connect(address).await.expect("connect for POST");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write POST");
    read_response(&mut stream).await.0
}

/// Pre-bind the TLS listener and hand it to the runtime as a systemd-style inherited socket.
///
/// This gives the CA probe a deterministic address without a reserve/drop race, and exercises the
/// normal inherited-socket binding path used in production.
fn prebound_listener() -> (SocketAddr, SocketActivation) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("pre-bind TLS listener");
    let address = listener.local_addr().expect("pre-bound address");
    let activation = SocketActivation::from_raw_descriptors(vec![(
        listener.into_raw_fd(),
        Some("https".to_string()),
    )])
    .expect("valid inherited descriptor");
    (address, activation)
}

/// A fixed port number that is currently free, for tests that need a connection to fail (probing a
/// closed port). The port is released immediately, so a refused connection is deterministic.
fn closed_port() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(23_000);
    for _ in 0..100 {
        let port = NEXT.fetch_add(1, Ordering::Relaxed);
        if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            drop(listener);
            return port;
        }
    }
    panic!("no free fixed port");
}

/// Automatic-HTTPS config with a fixed TLS listen address and optional ACME challenge options
/// (for example `{"http": {"disabled": true}}` to force TLS-ALPN-01).
fn tls_alpn_config(
    listen: &str,
    http_port: Option<u16>,
    challenges: Option<serde_json::Value>,
    storage_root: &str,
) -> Config {
    let mut issuer = serde_json::json!({
        "module": "acme",
        "ca": DIRECTORY,
        "email": "ops@example.com"
    });
    if let Some(challenges) = challenges {
        issuer["challenges"] = challenges;
    }
    let mut http = serde_json::json!({"servers": {"srv0": {
        "listen": [listen],
        "tls_connection_policies": [{}],
        "automatic_https": {"disable_redirects": true},
        "routes": [{
            "match": [{"host": ["example.com"]}],
            "handle": [{"handler": "static_response", "body": "hello https"}]
        }]
    }}});
    if let Some(http_port) = http_port {
        http["http_port"] = serde_json::json!(http_port);
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "storage": {"module": "file_system", "root": storage_root},
        "apps": {
            "tls": {"automation": {"policies": [{
                "subjects": ["example.com"],
                "issuers": [issuer]
            }]}},
            "http": http
        }
    }))
    .expect("TLS-ALPN test config decodes")
}

// ---- tests -----------------------------------------------------------------------------------

#[tokio::test]
async fn fake_acme_issues_certificate_and_site_serves_https() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config("127.0.0.1:0", Some(0), false, false, &root))
        .expect("config validates");
    let fake = Arc::new(FakeCa::new(false));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path());
    runtime.apply().await.expect("automatic HTTPS apply");
    let https = runtime.listener_address("127.0.0.1:0").unwrap();

    let mut stream = tls_connect(https, "example.com").await;
    let (status, _, body) = http_get(&mut stream, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello https");
    assert_eq!(fake.domains(), vec!["example.com".to_string()]);

    // T-ADMIN-024: the automatic-HTTPS certificate is exported to the certificate metrics wired
    // into the same registry the admin /metrics endpoint renders.
    let metrics = runtime.metrics().render();
    assert!(
        metrics.contains("caddy_rs_tls_certificate_expiration_seconds"),
        "certificate expiry metric missing:\n{metrics}"
    );
    assert!(
        metrics.contains("subject=\"example.com\""),
        "certificate metric must be labelled with the subject:\n{metrics}"
    );

    // The issued certificate is persisted in Caddy's storage layout.
    let storage = FileStorage::new(directory.path());
    let keys = storage.list("").await.expect("storage list");
    assert_eq!(keys.len(), 1, "one persisted certificate, got {keys:?}");
    runtime.shutdown().await;
}

#[tokio::test]
async fn derived_http_listener_serves_acme_challenge() {
    let (runtime, _https, http, _directory) = apply(false).await;
    runtime
        .challenge_tokens()
        .insert("token-1", "token-1.thumbprint", "example.com")
        .expect("token registers");
    let (status, headers, body) =
        plain_get(http, "example.com", "/.well-known/acme-challenge/token-1").await;
    assert_eq!(status, 200);
    assert_eq!(body, "token-1.thumbprint");
    assert_eq!(
        header(&headers, "content-type"),
        Some("text/plain; charset=utf-8")
    );
    // Unknown tokens are a 404, not a redirect to HTTPS.
    let (status, _, _) =
        plain_get(http, "example.com", "/.well-known/acme-challenge/unknown").await;
    assert_eq!(status, 404);
    runtime.shutdown().await;
}

#[tokio::test]
async fn http_to_https_redirect_returns_308_preserving_path_and_query() {
    let (runtime, _https, http, _directory) = apply(false).await;
    let (status, headers, _body) = plain_get(http, "example.com", "/some/path?x=1&y=2").await;
    assert_eq!(status, 308);
    assert_eq!(
        header(&headers, "location"),
        Some("https://example.com/some/path?x=1&y=2")
    );
    // Hosts not managed by automatic HTTPS are not redirected.
    let (status, _, _) = plain_get(http, "other.example", "/").await;
    assert_ne!(status, 308);
    runtime.shutdown().await;
}

#[tokio::test]
async fn disable_redirects_serves_http_without_redirect() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config("127.0.0.1:0", Some(0), true, false, &root))
        .expect("config validates");
    let mut runtime = ServerRuntime::new(store)
        .with_acme_transport(Arc::new(FakeCa::new(false)))
        .with_data_root(directory.path());
    runtime.apply().await.expect("apply");
    let http = runtime.listener_address(":0").unwrap();
    let (status, headers, _) = plain_get(http, "example.com", "/path").await;
    assert_ne!(status, 308, "disable_redirects must not redirect");
    assert!(header(&headers, "location").is_none());
    runtime.shutdown().await;
}

#[tokio::test]
async fn auto_https_off_fails_loudly_without_certificates() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config("127.0.0.1:0", Some(0), false, true, &root))
        .expect("config validates");
    let mut runtime = ServerRuntime::new(store)
        .with_acme_transport(Arc::new(FakeCa::new(false)))
        .with_data_root(directory.path());
    let error = runtime
        .apply()
        .await
        .expect_err("AUTO_HTTPS disabled + TLS listener without certs must fail");
    let message = error.to_string();
    assert!(message.contains("apps.tls.certificates"), "{message}");
    assert!(message.contains("terminates TLS"), "{message}");
}

#[tokio::test]
async fn failed_issuance_keeps_the_old_generation_serving() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    // First generation: plain cleartext static response.
    store
        .load(
            Config::from_value(serde_json::json!({
                "admin": {"disabled": true},
                "apps": {"http": {"servers": {"srv0": {
                    "listen": ["127.0.0.1:0"],
                    "routes": [{"handle": [{"handler": "static_response", "body": "old"}]}]
                }}}}
            }))
            .unwrap(),
        )
        .unwrap();
    let fake = Arc::new(FakeCa::new(false));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path());
    runtime.apply().await.expect("first apply");
    let old_address = runtime.listener_address("127.0.0.1:0").unwrap();
    let old_generation = runtime.status().generation_id;
    let (status, _, body) = plain_get(old_address, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "old");

    // Second generation: automatic HTTPS whose fake CA fails newOrder.
    store
        .load(config("127.0.0.1:0", Some(0), false, false, &root))
        .expect("second config validates");
    fake.set_fail_new_order(true);
    let error = runtime
        .apply()
        .await
        .expect_err("failed issuance must fail the apply");
    assert!(
        error.to_string().contains("automatic HTTPS"),
        "error must name automatic HTTPS: {error}"
    );
    // The old listener and generation remain active.
    assert_eq!(runtime.status().generation_id, old_generation);
    let (status, _, body) = plain_get(old_address, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "old");
    runtime.shutdown().await;
}

#[tokio::test]
async fn cleartext_static_regression() {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(
            Config::from_value(serde_json::json!({
                "admin": {"disabled": true},
                "apps": {"http": {"servers": {"srv0": {
                    "listen": ["127.0.0.1:0"],
                    "routes": [{"handle": [{"handler": "static_response", "body": "plain"}]}]
                }}}}
            }))
            .unwrap(),
        )
        .unwrap();
    let mut runtime = ServerRuntime::new(store);
    runtime.apply().await.expect("apply");
    let address = runtime.listener_address("127.0.0.1:0").unwrap();
    let (status, _, body) = plain_get(address, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "plain");
    runtime.shutdown().await;
}

// ---- TLS-ALPN-01 server integration ----------------------------------------------------------

#[tokio::test]
async fn tls_alpn01_challenge_validates_and_issues_certificate() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let (address, activation) = prebound_listener();
    let listen = address.to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(tls_alpn_config(
            &listen,
            Some(0),
            Some(serde_json::json!({"http": {"disabled": true}})),
            &root,
        ))
        .expect("config validates");
    let fake = Arc::new(FakeCa::new(false).with_tls_alpn_probe(address));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path())
        .with_socket_activation(activation);
    runtime
        .apply()
        .await
        .expect("TLS-ALPN-01 issuance through the live listener must succeed");

    // The CA selected TLS-ALPN-01 (HTTP-01 was disabled) and validated it over `acme-tls/1`.
    assert_eq!(
        fake.selected_challenge().as_deref(),
        Some("tls-alpn-01"),
        "TLS-ALPN-01 must be selected when HTTP-01 is disabled"
    );
    assert_eq!(
        fake.tls_alpn_validations(),
        1,
        "the CA must perform exactly one acme-tls/1 validation"
    );
    let challenge_certificate = fake
        .tls_alpn_certificate()
        .expect("the CA captured the challenge certificate");
    verify_tls_alpn_certificate(&challenge_certificate, "example.com")
        .expect("challenge certificate carries valid RFC 8737 evidence");

    // The issued certificate is now served for normal clients at the same listener.
    let address = runtime
        .listener_address(&listen)
        .expect("TLS listener bound");
    let mut stream = tls_connect(address, "example.com").await;
    let (status, _, body) = http_get(&mut stream, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello https");
    runtime.shutdown().await;
}

#[tokio::test]
async fn normal_tls_clients_are_unaffected_by_tls_alpn_overlay() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let (address, activation) = prebound_listener();
    let listen = address.to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(tls_alpn_config(
            &listen,
            Some(0),
            Some(serde_json::json!({"http": {"disabled": true}})),
            &root,
        ))
        .expect("config validates");
    let fake = Arc::new(FakeCa::new(false).with_tls_alpn_probe(address));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path())
        .with_socket_activation(activation);
    runtime.apply().await.expect("apply");
    let address = runtime
        .listener_address(&listen)
        .expect("TLS listener bound");

    // A normal client (no ALPN) still gets the issued certificate and the route.
    let mut normal = tls_connect(address, "example.com").await;
    let (status, _, body) = http_get(&mut normal, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello https");
    let (_, session) = normal.get_ref();
    let served_certificate = session
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .expect("issued certificate")
        .as_ref()
        .to_vec();
    let challenge_certificate = fake.tls_alpn_certificate().expect("challenge certificate");
    assert_ne!(
        served_certificate, challenge_certificate,
        "normal handshakes must not be served the challenge certificate"
    );

    // Unknown SNI completes/would complete with the default cert but the client rejects the name
    // mismatch; either way the handshake does not succeed for the client.
    let unknown_sni = tls_connect_result(address, "unknown.example", client_config()).await;
    assert!(
        unknown_sni.is_err(),
        "a client must not accept the default certificate for an unknown SNI"
    );

    // An ALPN the server does not support is rejected cleanly instead of being served as HTTP.
    let unsupported_alpn = tls_connect_result(
        address,
        "example.com",
        client_config_with_alpn(&[b"bogus/1"]),
    )
    .await;
    assert!(
        unsupported_alpn.is_err(),
        "unknown ALPN must fail the handshake, not fall back to a normal protocol"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn http01_is_preferred_when_both_challenges_are_available() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let (address, activation) = prebound_listener();
    let listen = address.to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    // No `challenges` options: HTTP-01 and TLS-ALPN-01 are both enabled.
    store
        .load(tls_alpn_config(&listen, Some(0), None, &root))
        .expect("config validates");
    let fake = Arc::new(FakeCa::new(false).with_tls_alpn_probe(address));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path())
        .with_socket_activation(activation);
    runtime.apply().await.expect("apply");
    assert_eq!(
        fake.selected_challenge().as_deref(),
        Some("http-01"),
        "Caddy prefers HTTP-01 when both challenges are available"
    );
    assert_eq!(
        fake.tls_alpn_validations(),
        0,
        "TLS-ALPN-01 must not be used when HTTP-01 succeeds"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn tls_alpn_probe_failure_keeps_previous_generation() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    // First generation: cleartext static response.
    store
        .load(
            Config::from_value(serde_json::json!({
                "admin": {"disabled": true},
                "apps": {"http": {"servers": {"srv0": {
                    "listen": ["127.0.0.1:0"],
                    "routes": [{"handle": [{"handler": "static_response", "body": "old"}]}]
                }}}}
            }))
            .unwrap(),
        )
        .unwrap();
    // The CA's TLS-ALPN probe points at a port where nothing listens, so validation fails once the
    // second (automatic-HTTPS) generation is applied.
    let closed_port = closed_port();
    let fake = Arc::new(
        FakeCa::new(false).with_tls_alpn_probe(SocketAddr::from(([127, 0, 0, 1], closed_port))),
    );
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path());
    runtime.apply().await.expect("first apply");
    let old_address = runtime.listener_address("127.0.0.1:0").unwrap();
    let old_generation = runtime.status().generation_id;

    // Second generation: automatic HTTPS whose TLS-ALPN-01 validation cannot connect. The TLS
    // listener is pre-bound and injected, so the failed apply does not race for a port.
    let (address, activation) = prebound_listener();
    let listen = address.to_string();
    runtime = runtime.with_socket_activation(activation);
    store
        .load(tls_alpn_config(
            &listen,
            Some(0),
            Some(serde_json::json!({"http": {"disabled": true}})),
            &root,
        ))
        .expect("second config validates");
    let error = runtime
        .apply()
        .await
        .expect_err("TLS-ALPN-01 probe failure must fail the apply");
    assert!(
        error.to_string().contains("automatic HTTPS"),
        "error must name automatic HTTPS: {error}"
    );
    assert!(
        fake.probe_failure().is_some(),
        "the CA must record the failed TLS-ALPN-01 probe"
    );

    // The old generation and its cleartext listener are untouched by the failed apply.
    assert_eq!(runtime.status().generation_id, old_generation);
    let (status, _, body) = plain_get(old_address, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "old");
    runtime.shutdown().await;
}

/// `POST /stop` must terminate the supervisor loop even when the active generation is an
/// automatic-HTTPS generation (two-phase apply, DERIVED HTTP challenge listener, certificate
/// provisioning). The real-Caddy-oracle finding was that the process kept running after a 200
/// response because nothing watched the store for the "configuration removed" state.
#[tokio::test]
async fn admin_stop_ends_runtime_loop_with_automatic_https() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let admin_port = free_loopback_port();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config_with_admin(
            "127.0.0.1:0",
            Some(0),
            false,
            false,
            &root,
            serde_json::json!({"listen": format!("127.0.0.1:{admin_port}")}),
        ))
        .expect("automatic-HTTPS config validates");
    let runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(Arc::new(FakeCa::new(false)))
        .with_data_root(directory.path());

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let running = tokio::spawn(async move { runtime.run(shutdown_rx).await });

    // Wait for the two-phase apply to finish and the admin listener to accept connections.
    let admin = SocketAddr::from(([127, 0, 0, 1], admin_port));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "admin API did not start; store generation: {:?}",
            store.current().map(|generation| generation.id())
        );
        if TcpStream::connect(admin).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(post_plain(admin, "/stop").await, 200);

    let joined = tokio::time::timeout(Duration::from_secs(15), running)
        .await
        .expect("runtime loop must exit after /stop with automatic HTTPS");
    joined
        .expect("runtime task")
        .expect("runtime run returns Ok");
    assert!(
        store.current().is_none(),
        "the stop must unload the automatic-HTTPS generation"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(admin).await.is_ok() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "admin listener must close after /stop"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---- generation-scoped renewal scheduler lifecycle -------------------------------------------

#[tokio::test]
async fn renewal_scheduler_survives_reloads_and_previous_generation_is_stopped() {
    let (mut runtime, https, _http, directory) = apply(false).await;
    let first_generation = runtime.status().generation_id.expect("generation active");
    assert_eq!(
        runtime.renewal_scheduler_count(),
        1,
        "one generation-scoped renewal scheduler after automatic-HTTPS apply"
    );
    assert!(
        runtime
            .renewal_scheduler(first_generation)
            .expect("generation owns a scheduler")
            .is_running(),
        "the scheduler must be kept alive by the runtime"
    );
    assert!(runtime.has_running_renewal_schedulers());

    let store = Arc::clone(runtime.store());
    let root = directory.path().to_string_lossy().to_string();

    // Reload: the previous generation's scheduler must be stopped and dropped, not accumulated.
    store
        .load(config("127.0.0.1:0", Some(0), false, false, &root))
        .expect("second generation validates");
    runtime.apply().await.expect("reload applies");
    let second_generation = runtime
        .status()
        .generation_id
        .expect("second generation active");
    assert_ne!(first_generation, second_generation);
    assert_eq!(
        runtime.renewal_scheduler_count(),
        1,
        "the retired generation's scheduler must be stopped and removed"
    );
    assert!(
        runtime.renewal_scheduler(first_generation).is_none(),
        "the previous generation must not keep renewal ownership"
    );
    assert!(
        runtime
            .renewal_scheduler(second_generation)
            .expect("new generation owns a scheduler")
            .is_running(),
        "the new generation's scheduler must be running"
    );

    // The listener (and the issued certificate) keep serving across the reload.
    let mut stream = tls_connect(https, "example.com").await;
    let (status, _, body) = http_get(&mut stream, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello https");

    // Repeated reloads do not accumulate schedulers.
    for _ in 0..3 {
        store
            .load(config("127.0.0.1:0", Some(0), false, false, &root))
            .expect("reload generation validates");
        runtime.apply().await.expect("reload applies");
        assert_eq!(
            runtime.renewal_scheduler_count(),
            1,
            "repeated reloads must not accumulate renewal schedulers"
        );
    }
    assert!(runtime.has_running_renewal_schedulers());
    runtime.shutdown().await;
}

#[tokio::test]
async fn stopping_the_configuration_stops_all_renewal_schedulers() {
    let (mut runtime, _https, _http, _directory) = apply(false).await;
    assert_eq!(runtime.renewal_scheduler_count(), 1);
    assert!(runtime.has_running_renewal_schedulers());

    // `POST /stop` (and any external store stop) removes the active generation; the supervisor then
    // runs the no-generation apply path, which must stop every scheduler.
    runtime.store().stop();
    runtime
        .apply()
        .await
        .expect("apply without an active generation stops the runtime resources");
    assert_eq!(runtime.renewal_scheduler_count(), 0);
    assert!(
        !runtime.has_running_renewal_schedulers(),
        "no renewal scheduler may outlive the stopped configuration"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn failed_apply_aborts_the_new_scheduler_and_keeps_the_previous_one() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config("127.0.0.1:0", Some(0), false, false, &root))
        .expect("first generation validates");
    let fake = Arc::new(FakeCa::new(false));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path());
    runtime.apply().await.expect("first automatic-HTTPS apply");
    let old_generation = runtime
        .status()
        .generation_id
        .expect("first generation active");
    assert_eq!(runtime.renewal_scheduler_count(), 1);
    assert!(runtime
        .renewal_scheduler(old_generation)
        .expect("first generation scheduler")
        .is_running());

    // Remove the persisted certificate so the reload must issue again, then make the fake CA fail
    // newOrder: provisioning (and the renewal scheduler it would start) fails, while the previous
    // generation's in-memory certificate and scheduler keep running.
    let storage = FileStorage::new(directory.path());
    for key in storage.list("").await.expect("storage list") {
        storage
            .delete(&key)
            .await
            .expect("delete persisted certificate");
    }
    store
        .load(config("127.0.0.1:0", Some(0), false, false, &root))
        .expect("second generation validates");
    let failed_generation = store.current().expect("second generation loaded").id();
    fake.set_fail_new_order(true);
    let error = runtime
        .apply()
        .await
        .expect_err("failed issuance must fail the apply");
    assert!(
        error.to_string().contains("automatic HTTPS"),
        "error must name automatic HTTPS: {error}"
    );

    // The newly started scheduler was aborted with the dropped PreparedAutomaticHttps; the previous
    // generation's scheduler is still owned and running.
    assert_eq!(
        runtime.renewal_scheduler_count(),
        1,
        "a failed apply must not leave a scheduler for the failed generation"
    );
    assert!(
        runtime.renewal_scheduler(failed_generation).is_none(),
        "the failed generation must not own a renewal scheduler"
    );
    assert_eq!(runtime.status().generation_id, Some(old_generation));
    assert!(runtime
        .renewal_scheduler(old_generation)
        .expect("previous scheduler retained")
        .is_running());

    // The previous generation's listener and certificate keep serving.
    let old_listener = runtime
        .listener_address("127.0.0.1:0")
        .expect("old TLS listener still bound");
    let mut stream = tls_connect(old_listener, "example.com").await;
    let (status, _, body) = http_get(&mut stream, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello https");
    runtime.shutdown().await;
}

// ---- default-on automatic HTTPS -------------------------------------------------------------

/// An implicit-HTTPS config: no `apps.tls`, no `tls_connection_policies`, just a host matcher on
/// the HTTPS listener (what an adapted `example.com { respond ... }` Caddyfile looks like).
fn implicit_https_config(
    listen: &str,
    http_port: u16,
    https_port: u16,
    storage_root: &str,
    automatic_https: Option<serde_json::Value>,
) -> Config {
    let mut server = serde_json::json!({
        "listen": [listen],
        "routes": [{
            "match": [{"host": ["example.com"]}],
            "handle": [{"handler": "static_response", "body": "hello default https"}]
        }]
    });
    if let Some(automatic_https) = automatic_https {
        server["automatic_https"] = automatic_https;
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "storage": {"module": "file_system", "root": storage_root},
        "apps": {"http": {
            "http_port": http_port,
            "https_port": https_port,
            "servers": {"srv0": server}
        }}
    }))
    .expect("implicit HTTPS config decodes")
}

#[tokio::test]
async fn default_on_issues_certificate_for_implicit_https_site() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let (https_address, activation) = prebound_listener();
    let listen = https_address.to_string();
    let https_port = https_address.port();
    let http_port = free_loopback_port();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(implicit_https_config(
            &listen, http_port, https_port, &root, None,
        ))
        .expect("implicit HTTPS config validates");
    let fake = Arc::new(FakeCa::new(false));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path())
        .with_socket_activation(activation);
    runtime
        .apply()
        .await
        .expect("default-on automatic HTTPS must obtain a certificate");

    // The default ACME policy managed the implicit host, without any apps.tls automation.
    assert_eq!(fake.domains(), vec!["example.com".to_string()]);
    let address = runtime
        .listener_address(&listen)
        .expect("implicit HTTPS listener bound");
    let mut stream = tls_connect(address, "example.com").await;
    let (status, _, body) = http_get(&mut stream, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello default https");

    // A derived cleartext listener redirects the host to the HTTPS port.
    let http = runtime
        .listener_address(&format!(":{http_port}"))
        .expect("derived HTTP redirect listener bound");
    let (status, headers, _) = plain_get(http, "example.com", "/path?q=1").await;
    assert_eq!(status, 308);
    let location = header(&headers, "location").expect("redirect Location");
    assert_eq!(
        location,
        format!("https://example.com:{https_port}/path?q=1")
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn default_on_disable_does_not_issue_and_fails_loudly_without_certificates() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let (https_address, activation) = prebound_listener();
    let listen = https_address.to_string();
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(implicit_https_config(
            &listen,
            free_loopback_port(),
            https_address.port(),
            &root,
            Some(serde_json::json!({"disable": true})),
        ))
        .expect("auto_https off config validates");
    let fake = Arc::new(FakeCa::new(false));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path())
        .with_socket_activation(activation);
    let error = runtime
        .apply()
        .await
        .expect_err("auto_https off with a TLS listener and no certificates must fail loudly");
    assert!(
        error.to_string().contains("apps.tls.certificates"),
        "{error}"
    );
    assert!(error.to_string().contains("terminates TLS"), "{error}");
    assert!(
        fake.domains().is_empty(),
        "auto_https off must not obtain certificates"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn default_on_caddyfile_end_to_end() {
    let directory = tempfile::tempdir().unwrap();
    let http_port = free_loopback_port();
    let https_port = free_loopback_port();
    let caddyfile = format!(
        "{{\n\thttp_port {http_port}\n\thttps_port {https_port}\n}}\n\nexample.com {{\n\trespond \"hello caddyfile\"\n}}\n"
    );
    let adapted = caddy_rs_config::adapt_with_source(&caddyfile, None)
        .expect("simple public-host Caddyfile adapts");
    let config = Config::from_value(adapted.config).expect("adapted JSON decodes");
    // The adapter relies on Caddy's default-on automatic HTTPS: no apps.tls automation, no
    // explicit tls_connection_policies are required.
    assert!(
        config
            .tls()
            .map(|tls| tls.automation_policies().is_empty())
            .unwrap_or(true),
        "test must not rely on explicit automation policies"
    );
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("adapted Caddyfile validates");
    let fake = Arc::new(FakeCa::new(false));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path());
    runtime
        .apply()
        .await
        .expect("adapted Caddyfile gets automatic HTTPS by default");
    assert_eq!(fake.domains(), vec!["example.com".to_string()]);

    let https = SocketAddr::from(([127, 0, 0, 1], https_port));
    let mut stream = tls_connect(https, "example.com").await;
    let (status, _, body) = http_get(&mut stream, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello caddyfile");

    let http = SocketAddr::from(([127, 0, 0, 1], http_port));
    let (status, headers, _) = plain_get(http, "example.com", "/").await;
    assert_eq!(status, 308);
    assert_eq!(
        header(&headers, "location"),
        Some(format!("https://example.com:{https_port}/").as_str())
    );
    runtime.shutdown().await;
}

/// Config with implicit HTTPS on an arbitrary listener port (no `apps.tls`, no
/// `tls_connection_policies`, no `apps.http.https_port` match): Caddy treats this as HTTPS on the
/// listener's port.
fn implicit_nonstandard_https_config(listen: &str, http_port: u16, storage_root: &str) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "storage": {"module": "file_system", "root": storage_root},
        "apps": {"http": {
            "http_port": http_port,
            "servers": {"srv0": {
                "listen": [listen],
                "routes": [{
                    "match": [{"host": ["example.com"]}],
                    "handle": [{"handler": "static_response", "body": "hello nonstandard https"}]
                }]
            }}
        }}
    }))
    .expect("implicit non-standard HTTPS config decodes")
}

#[tokio::test]
async fn adapted_plain_http_site_serves_cleartext() {
    // Regression: Caddyfile `http://127.0.0.1:<port>` adapts to a host matcher on a non-standard
    // port plus server-level `automatic_https.skip`; it must stay plaintext instead of failing
    // with "host matchers require TLS".
    let directory = tempfile::tempdir().unwrap();
    let port = free_loopback_port();
    let caddyfile = format!("http://127.0.0.1:{port} {{\n\trespond \"plain ok\"\n}}\n");
    let adapted =
        caddy_rs_config::adapt_with_source(&caddyfile, None).expect("plain HTTP Caddyfile adapts");
    let config = Config::from_value(adapted.config).expect("adapted JSON decodes");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config)
        .expect("adapted plain HTTP config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime
        .apply()
        .await
        .expect("skipped host must not demand automatic HTTPS");
    runtime
        .listener_address(&format!(":{port}"))
        .expect("plain HTTP listener bound");
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let (status, _, body) = plain_get(address, "127.0.0.1", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "plain ok");
    runtime.shutdown().await;
}

#[tokio::test]
async fn implicit_https_on_non_standard_port_terminates_tls_and_redirects_to_it() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_string_lossy().to_string();
    let (https_address, activation) = prebound_listener();
    let https_port = https_address.port();
    let listen = https_address.to_string();
    let http_port = free_loopback_port();
    assert_ne!(https_port, 443, "pre-bound test port is non-standard");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(implicit_nonstandard_https_config(&listen, http_port, &root))
        .expect("implicit non-standard HTTPS config validates");
    let fake = Arc::new(FakeCa::new(false));
    let mut runtime = ServerRuntime::new(Arc::clone(&store))
        .with_acme_transport(fake.clone())
        .with_data_root(directory.path())
        .with_socket_activation(activation);
    runtime
        .apply()
        .await
        .expect("implicit HTTPS on a non-standard port must issue and serve");

    assert_eq!(fake.domains(), vec!["example.com".to_string()]);
    let address = runtime
        .listener_address(&listen)
        .expect("implicit non-standard HTTPS listener bound");
    let mut stream = tls_connect(address, "example.com").await;
    let (status, _, body) = http_get(&mut stream, "example.com", "/").await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello nonstandard https");

    // Redirect destination must be the listener's own HTTPS port, not apps.http.https_port (443).
    let http = runtime
        .listener_address(&format!(":{http_port}"))
        .expect("derived HTTP redirect listener bound");
    let (status, headers, _) = plain_get(http, "example.com", "/path?q=1").await;
    assert_eq!(status, 308);
    assert_eq!(
        header(&headers, "location"),
        Some(format!("https://example.com:{https_port}/path?q=1").as_str())
    );
    runtime.shutdown().await;
}
