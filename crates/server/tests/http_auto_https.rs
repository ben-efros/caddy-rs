//! End-to-end automatic-HTTPS tests: a fake local ACME CA issues certificates through the real
//! issuer/order/challenge path, the server derives the HTTP challenge/redirect listener, and
//! HTTPS is served from the obtained certificate.
//!
//! Nothing here touches the network: the fake CA is an in-process [`AcmeTransport`] that speaks
//! just enough RFC 8555 for the existing [`caddy_rs_tls::AcmeIssuer`], and signs the CSR produced
//! during finalization with an embedded test CA so the resulting certificate is usable for a real
//! rustls handshake.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
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
        if request.method == HttpMethod::Get && url == DIRECTORY {
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
                    "challenges": [{
                        "type": "http-01",
                        "url": CHALLENGE,
                        "token": "token-1",
                        "status": challenge_status
                    }]
                }),
            ));
        }
        if url == CHALLENGE {
            self.state.lock().unwrap().challenge_acked = true;
            return Ok(json_response(
                200,
                serde_json::json!({
                    "type": "http-01",
                    "url": CHALLENGE,
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
        "admin": {"disabled": true},
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
    let mut roots = rustls::RootCertStore::empty();
    for certificate in caddy_rs_tls::certificates_from_pem(CA_PEM).expect("CA parses") {
        roots.add(certificate).expect("CA is a valid root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("safe protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn tls_connect(address: SocketAddr, server_name: &str) -> TlsStream<TcpStream> {
    let connector = TlsConnector::from(client_config());
    let stream = TcpStream::connect(address).await.expect("TCP connect");
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .expect("valid server name");
    connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake")
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
