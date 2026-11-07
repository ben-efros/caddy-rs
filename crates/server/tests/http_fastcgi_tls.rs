//! End-to-end TLS metadata for FastCGI: a TLS listener negotiates a session, the server threads
//! the version/cipher into the internal request, and `reverse_proxy` with `transport: fastcgi`
//! sets Caddy's `SSL_PROTOCOL`/`SSL_CIPHER` CGI variables (Caddy v2.11.9
//! `modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go` buildEnv TLS branch; `tlsProtocolStrings`
//! maps Go's `tls.Version*` values to `TLSv1`/`TLSv1.1`/`TLSv1.2`/`TLSv1.3` and `SSL_CIPHER` comes
//! from `tls.CipherSuites()` names, i.e. IANA/Go naming).
//!
//! A minimal FastCGI responder records the CGI parameters; the tests drive real TLS handshakes
//! (TLS 1.3 default, TLS 1.2 forced) and a plaintext listener that must omit the TLS variables.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const EXAMPLE_CERT: &str = include_str!("../../tls/testdata/https/example.com.pem");
const EXAMPLE_KEY: &str = include_str!("../../tls/testdata/https/example.com.key");

const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDOUT: u8 = 6;
const FCGI_VERSION_1: u8 = 1;

fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local address")
        .port()
}

/// Minimal FastCGI responder: captures the CGI parameters of the first request and answers with
/// a CGI head + body.
fn spawn_fastcgi_upstream() -> (String, Arc<Mutex<Option<BTreeMap<String, String>>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fastcgi upstream");
    let address = listener.local_addr().expect("upstream address");
    listener.set_nonblocking(true).expect("nonblocking");
    let captured = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                let params = match read_fastcgi_params(&mut stream).await {
                    Ok(params) => params,
                    Err(_) => return,
                };
                *sink.lock().unwrap() = Some(params);
                let _ = write_record(
                    &mut stream,
                    FCGI_STDOUT,
                    b"Content-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
                )
                .await;
                let _ = write_record(&mut stream, FCGI_STDOUT, b"").await;
                let _ = write_record(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
            });
        }
    });
    (address.to_string(), captured)
}

async fn read_record(stream: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; 8];
    stream.read_exact(&mut header).await?;
    if header[0] != FCGI_VERSION_1 {
        return Err(std::io::Error::other("bad FastCGI version"));
    }
    let kind = header[1];
    let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let padding = usize::from(header[6]);
    let mut content = vec![0_u8; length];
    stream.read_exact(&mut content).await?;
    if padding > 0 {
        let mut padding_bytes = vec![0_u8; padding];
        stream.read_exact(&mut padding_bytes).await?;
    }
    Ok((kind, content))
}

async fn read_fastcgi_params(stream: &mut TcpStream) -> std::io::Result<BTreeMap<String, String>> {
    let mut params_bytes = Vec::new();
    loop {
        let (kind, content) = read_record(stream).await?;
        match kind {
            FCGI_BEGIN_REQUEST => {}
            FCGI_PARAMS => {
                if content.is_empty() {
                    break;
                }
                params_bytes.extend_from_slice(&content);
            }
            _ => {}
        }
    }
    Ok(decode_params(&params_bytes))
}

fn decode_params(bytes: &[u8]) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    let mut index = 0;
    let read_length = |index: &mut usize| -> usize {
        let first = bytes[*index];
        if first & 0x80 != 0 {
            let value = u32::from_be_bytes([
                bytes[*index],
                bytes[*index + 1],
                bytes[*index + 2],
                bytes[*index + 3],
            ]) & 0x7fff_ffff;
            *index += 4;
            value as usize
        } else {
            *index += 1;
            first as usize
        }
    };
    while index < bytes.len() {
        let name_len = read_length(&mut index);
        let value_len = read_length(&mut index);
        let name = String::from_utf8_lossy(&bytes[index..index + name_len]).into_owned();
        index += name_len;
        let value = String::from_utf8_lossy(&bytes[index..index + value_len]).into_owned();
        index += value_len;
        params.insert(name, value);
    }
    params
}

async fn write_record(stream: &mut TcpStream, kind: u8, content: &[u8]) -> std::io::Result<()> {
    let padding = (8 - content.len() % 8) % 8;
    let mut record = Vec::with_capacity(8 + content.len() + padding);
    record.push(FCGI_VERSION_1);
    record.push(kind);
    record.extend_from_slice(&1_u16.to_be_bytes());
    record.extend_from_slice(&(content.len() as u16).to_be_bytes());
    record.push(padding as u8);
    record.push(0);
    record.extend_from_slice(content);
    record.extend(std::iter::repeat_n(0_u8, padding));
    stream.write_all(&record).await
}

fn config(fastcgi: &str, tls: bool) -> Config {
    let mut server = serde_json::json!({
        "listen": ["127.0.0.1:0"],
        "routes": [{"handle": [{
            "handler": "reverse_proxy",
            "upstreams": [{"dial": fastcgi}],
            "transport": {"protocol": "fastcgi"}
        }]}]
    });
    if tls {
        server["tls_connection_policies"] = serde_json::json!([{}]);
    }
    let mut http = serde_json::json!({"servers": {"srv0": server}});
    http["http_port"] = serde_json::json!(free_loopback_port());
    let mut apps = serde_json::json!({"http": http});
    if tls {
        apps["tls"] = serde_json::json!({
            "certificates": {
                "load_pem": [{"certificate": EXAMPLE_CERT, "key": EXAMPLE_KEY}]
            }
        });
    }
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": apps
    }))
    .expect("test config decodes")
}

async fn start(config: Config) -> (ServerRuntime, SocketAddr) {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store.load(config).expect("test config validates");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");
    let address = runtime
        .listener_address("127.0.0.1:0")
        .expect("listener is bound");
    (runtime, address)
}

fn client_config(force_tls12: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in
        caddy_rs_tls::certificates_from_pem(EXAMPLE_CERT).expect("fixture PEM parses")
    {
        roots.add(certificate).expect("fixture is a valid root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider);
    let builder = if force_tls12 {
        builder
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2 client versions")
    } else {
        builder
            .with_safe_default_protocol_versions()
            .expect("safe protocol versions")
    };
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Send one HTTP/1.1 request over a fresh TLS connection and return (status line, body).
async fn https_get(address: SocketAddr, force_tls12: bool) -> (String, String) {
    let connector = TlsConnector::from(client_config(force_tls12));
    let stream = TcpStream::connect(address).await.expect("TCP connect");
    let server_name = ServerName::try_from("example.com".to_string()).expect("valid name");
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    read_http_response(&mut stream).await
}

async fn plain_get(address: SocketAddr) -> (String, String) {
    let mut stream = TcpStream::connect(address).await.expect("TCP connect");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    read_http_response(&mut stream).await
}

async fn read_http_response<S>(stream: &mut S) -> (String, String)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text.lines().next().unwrap_or_default().to_string();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

fn captured(captured: &Arc<Mutex<Option<BTreeMap<String, String>>>>) -> BTreeMap<String, String> {
    captured
        .lock()
        .unwrap()
        .clone()
        .expect("FastCGI upstream captured parameters")
}

#[tokio::test]
async fn fastcgi_tls13_request_sets_ssl_protocol_and_cipher() {
    let (fastcgi, captured_params) = spawn_fastcgi_upstream();
    let (runtime, address) = start(config(&fastcgi, true)).await;
    let (status, body) = https_get(address, false).await;
    assert_eq!(status, "HTTP/1.1 200 OK", "{status}");
    assert!(body.contains("ok"), "response body: {body:?}");
    let params = captured(&captured_params);
    assert_eq!(params.get("HTTPS").map(String::as_str), Some("on"));
    assert_eq!(
        params.get("SSL_PROTOCOL").map(String::as_str),
        Some("TLSv1.3"),
        "Caddy maps tls.VersionTLS13 to TLSv1.3: {params:?}"
    );
    let cipher = params
        .get("SSL_CIPHER")
        .unwrap_or_else(|| panic!("SSL_CIPHER missing: {params:?}"));
    assert!(
        matches!(
            cipher.as_str(),
            "TLS_AES_256_GCM_SHA384" | "TLS_AES_128_GCM_SHA256" | "TLS_CHACHA20_POLY1305_SHA256"
        ),
        "unexpected TLS 1.3 cipher name: {cipher}"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn fastcgi_tls12_request_sets_ssl_protocol_and_cipher() {
    let (fastcgi, captured_params) = spawn_fastcgi_upstream();
    let (runtime, address) = start(config(&fastcgi, true)).await;
    let (status, body) = https_get(address, true).await;
    assert_eq!(status, "HTTP/1.1 200 OK", "{status}");
    assert!(body.contains("ok"), "response body: {body:?}");
    let params = captured(&captured_params);
    assert_eq!(
        params.get("SSL_PROTOCOL").map(String::as_str),
        Some("TLSv1.2"),
        "Caddy maps tls.VersionTLS12 to TLSv1.2: {params:?}"
    );
    let cipher = params
        .get("SSL_CIPHER")
        .unwrap_or_else(|| panic!("SSL_CIPHER missing: {params:?}"));
    assert!(
        cipher.starts_with("TLS_ECDHE_"),
        "Go/IANA TLS 1.2 cipher name expected: {cipher}"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn fastcgi_plain_http_omits_tls_cgi_variables() {
    let (fastcgi, captured_params) = spawn_fastcgi_upstream();
    let (runtime, address) = start(config(&fastcgi, false)).await;
    let (status, body) = plain_get(address).await;
    assert_eq!(status, "HTTP/1.1 200 OK", "{status}");
    assert!(body.contains("ok"), "response body: {body:?}");
    let params = captured(&captured_params);
    for key in ["HTTPS", "SSL_PROTOCOL", "SSL_CIPHER"] {
        assert_eq!(
            params.get(key),
            None,
            "plaintext FastCGI requests must not set {key}: {params:?}"
        );
    }
    runtime.shutdown().await;
}

#[tokio::test]
async fn request_tls_metadata_maps_iana_values() {
    // Server-side mapping unit check: rustls's numeric version/cipher values become Caddy's names.
    let tls13 =
        caddy_rs_http::TlsConnection::from_iana(0x0304, 0x1301).expect("TLS 1.3 metadata maps");
    assert_eq!(tls13.version.caddy_name(), "TLSv1.3");
    assert_eq!(
        tls13.cipher_suite.as_deref(),
        Some("TLS_AES_128_GCM_SHA256")
    );

    let tls12 =
        caddy_rs_http::TlsConnection::from_iana(0x0303, 0xC02F).expect("TLS 1.2 metadata maps");
    assert_eq!(tls12.version.caddy_name(), "TLSv1.2");
    assert_eq!(
        tls12.cipher_suite.as_deref(),
        Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    );

    // Unknown version/cipher: no metadata / no cipher name (Caddy omits SSL_CIPHER when the
    // suite is not in tls.CipherSuites()).
    assert!(caddy_rs_http::TlsConnection::from_iana(0x9999, 0x1301).is_none());
    assert!(caddy_rs_http::TlsConnection::from_iana(0x0304, 0x9999)
        .expect("version maps")
        .cipher_suite
        .is_none());
}
