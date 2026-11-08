//! End-to-end `{http.request.tls.client.*}` placeholders over real TLS listeners (T-TLS-077).
//!
//! Caddy v2.11.9 exposes the presented client certificate through these placeholders
//! (`modules/caddyhttp/replacer.go`); with no certificate it substitutes a dummy empty certificate,
//! so known fields expand to empty strings rather than staying literal.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const SERVER_CERT: &str = include_str!("../../tls/testdata/https/example.com.pem");
const SERVER_KEY: &str = include_str!("../../tls/testdata/https/example.com.key");
const CLIENT_CA: &str = include_str!("../../tls/testdata/auto-https/ca.pem");
const CLIENT_CERT: &str = include_str!("../../tls/testdata/client-auth/client.pem");
const CLIENT_KEY: &str = include_str!("../../tls/testdata/client-auth/client.key");
const UNTRUSTED_CERT: &str = include_str!("../../tls/testdata/client-auth/untrusted-client.pem");
const UNTRUSTED_KEY: &str = include_str!("../../tls/testdata/client-auth/untrusted-client.key");

const BODY: &str =
    "subject=[{http.request.tls.client.subject}] issuer=[{http.request.tls.client.issuer}] \
serial=[{http.request.tls.client.serial}] fingerprint=[{http.request.tls.client.fingerprint}] \
san0=[{http.request.tls.client.san.dns_names.0}] san=[{http.request.tls.client.san.dns_names}] \
pem=[{http.request.tls.client.certificate_pem}]";

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn client_ca_base64() -> String {
    use base64::engine::general_purpose::STANDARD;
    let der = caddy_rs_tls::certificates_from_pem(CLIENT_CA)
        .expect("client CA parses")
        .remove(0);
    STANDARD.encode(der.as_ref())
}

fn config(mode: &str, with_ca: bool) -> Config {
    let mut client_authentication = serde_json::json!({"mode": mode});
    if with_ca {
        client_authentication["ca"] = serde_json::json!({
            "provider": "inline",
            "trusted_ca_certs": [client_ca_base64()]
        });
    }
    let http = serde_json::json!({
        "http_port": free_port(),
        "servers": {"srv0": {
            "listen": ["127.0.0.1:0"],
            "tls_connection_policies": [{"client_authentication": client_authentication}],
            "routes": [{"handle": [{"handler": "static_response", "body": BODY}]}]
        }}
    });
    let tls = serde_json::json!({
        "certificates": {"load_pem": [{"certificate": SERVER_CERT, "key": SERVER_KEY}]}
    });
    Config::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": http, "tls": tls}
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

fn client_config(identity: Option<(&str, &str)>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in caddy_rs_tls::certificates_from_pem(SERVER_CERT).expect("server cert parses")
    {
        roots.add(certificate).expect("server cert is a root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(roots);
    let mut config = match identity {
        Some((certificate, key)) => {
            let chain = caddy_rs_tls::certificates_from_pem(certificate).expect("client cert");
            let key = caddy_rs_tls::TlsCertificate::from_pem(certificate, key)
                .expect("client key")
                .private_key()
                .clone_key();
            builder
                .with_client_auth_cert(chain, key)
                .expect("client identity")
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

async fn request(address: SocketAddr, identity: Option<(&str, &str)>) -> String {
    let connector = TlsConnector::from(client_config(identity));
    let stream = TcpStream::connect(address).await.expect("TCP connect");
    let server_name = ServerName::try_from("example.com").expect("server name");
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8_lossy(&response);
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn require_and_verify_mtls_exposes_client_certificate_placeholders() {
    let (_runtime, address) = start(config("require_and_verify", true)).await;
    let body = request(address, Some((CLIENT_CERT, CLIENT_KEY))).await;
    assert!(body.contains("subject=[CN=client.example.com]"), "{body}");
    assert!(
        body.contains("issuer=[CN=caddy-rs auto-HTTPS test CA]"),
        "{body}"
    );
    assert!(
        body.contains("serial=[") && !body.contains("serial=[]"),
        "serial placeholder must be populated: {body}"
    );
    assert!(
        body.contains("fingerprint=[") && !body.contains("fingerprint=[]"),
        "fingerprint placeholder must be populated: {body}"
    );
    assert!(body.contains("san0=[client.example.com]"), "{body}");
    assert!(body.contains("san=[client.example.com]"), "{body}");
    assert!(
        body.contains("pem=[-----BEGIN CERTIFICATE-----"),
        "PEM placeholder must be populated: {body}"
    );
}

#[tokio::test]
async fn request_mode_without_client_certificate_expands_known_fields_to_empty() {
    let (_runtime, address) = start(config("request", true)).await;
    // No client certificate: Caddy's dummy certificate makes every known field empty.
    let body = request(address, None).await;
    assert!(body.contains("subject=[]"), "{body}");
    assert!(body.contains("issuer=[]"), "{body}");
    assert!(body.contains("serial=[]"), "{body}");
    assert!(body.contains("fingerprint=[]"), "{body}");
    assert!(body.contains("san0=[]"), "{body}");
    assert!(body.contains("san=[]"), "{body}");
    assert!(body.contains("pem=[]"), "{body}");
}

#[tokio::test]
async fn require_mode_exposes_unverified_certificate_fields() {
    // `require` does not verify the chain: an untrusted self-signed client certificate is still
    // presented and its fields are exposed (Caddy's `RequireAnyClientCert`).
    let (_runtime, address) = start(config("require", false)).await;
    let body = request(address, Some((UNTRUSTED_CERT, UNTRUSTED_KEY))).await;
    assert!(
        body.contains("subject=[CN=untrusted.example.com]"),
        "{body}"
    );
    assert!(body.contains("issuer=[CN=untrusted.example.com]"), "{body}");
    assert!(body.contains("san0=[untrusted.example.com]"), "{body}");
}

/// Caddy provisions a default `local` PKI authority when `apps.pki` declares none, so a client-auth
/// pool may reference `pki_root`/`pki_intermediate` with `authority` `local` without configuring the
/// PKI app. caddy-rs resolved only explicitly declared authorities and rejected the config
/// (DIV-0085 residual, T-TLS-083).
#[test]
fn implicit_local_ca_authority_resolves_for_client_auth_pools() {
    let directory = tempfile::tempdir().expect("tempdir");
    let authority = directory
        .path()
        .join("pki")
        .join("authorities")
        .join("local");
    std::fs::create_dir_all(&authority).expect("authority dir");
    std::fs::write(authority.join("root.crt"), CLIENT_CA).expect("root.crt");

    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(implicit_local_ca_config())
        .expect("config decodes");
    let runtime = ServerRuntime::new(store).with_data_root(directory.path());
    runtime
        .validate_provisioning()
        .expect("implicit local authority must resolve like Caddy");

    // Without the on-disk material the failure stays loud and names the authority/file.
    let empty = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(implicit_local_ca_config())
        .expect("config decodes");
    let runtime = ServerRuntime::new(store).with_data_root(empty.path());
    let error = runtime
        .validate_provisioning()
        .expect_err("missing local CA material must fail");
    let message = error.to_string();
    assert!(
        message.contains("local") && message.contains("root.crt"),
        "error must name the authority and file: {message}"
    );
}

fn implicit_local_ca_config() -> Config {
    serde_json::from_value(serde_json::json!({
        "admin": {"disabled": true},
        "apps": {
            "tls": {
                "certificates": {
                    "load_pem": [{"certificate": SERVER_CERT, "key": SERVER_KEY}]
                }
            },
            "http": {"servers": {"srv0": {
                "listen": ["127.0.0.1:0"],
                "tls_connection_policies": [{
                    "client_authentication": {
                        "mode": "require_and_verify",
                        "ca": {"provider": "pki_root", "authority": ["local"]}
                    }
                }],
                "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}
        }
    }))
    .expect("implicit local CA config decodes")
}
