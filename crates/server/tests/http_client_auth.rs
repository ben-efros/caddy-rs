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
        // Never bind the default port 80; port 0 makes the derived HTTP listener ephemeral.
        "http_port": 0,
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
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
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

/// Caddy provisions the default `local` PKI authority on demand (`ProvisionDefaultCA`/`GetCA`), so
/// a client-auth pool may reference `pki_root`/`pki_intermediate` with `authority` `local` without
/// configuring the PKI app — including `caddy-rs validate`, which has no storage root.
/// (DIV-0085, T-TLS-083.)
#[test]
fn implicit_local_ca_authority_is_provisioned_for_client_auth_pools() {
    let directory = tempfile::tempdir().expect("tempdir");
    let runtime = runtime_with_data_root(directory.path());
    runtime
        .validate_provisioning()
        .expect("the implicit local authority must be provisioned like Caddy");

    let authority = directory
        .path()
        .join("pki")
        .join("authorities")
        .join("local");
    let root_pem = std::fs::read_to_string(authority.join("root.crt"))
        .expect("root.crt was provisioned at the loader's location");
    let intermediate_pem = std::fs::read_to_string(authority.join("intermediate.crt"))
        .expect("intermediate.crt was provisioned at the loader's location");
    assert!(root_pem.contains("BEGIN CERTIFICATE"), "{root_pem}");
    assert!(
        intermediate_pem.contains("BEGIN CERTIFICATE"),
        "{intermediate_pem}"
    );
    assert!(authority.join("root.key").is_file());
    assert!(authority.join("intermediate.key").is_file());

    // A second validate (fresh runtime and store) must reuse the material, not regenerate it.
    runtime_with_data_root(directory.path())
        .validate_provisioning()
        .expect("the provisioned local authority must be reusable");
    assert_eq!(
        std::fs::read_to_string(authority.join("root.crt")).expect("root.crt"),
        root_pem
    );
    assert_eq!(
        std::fs::read_to_string(authority.join("intermediate.crt")).expect("intermediate.crt"),
        intermediate_pem
    );
}

/// `caddy-rs validate` constructs the runtime without `--data-dir`; Caddy still provisions the
/// implicit `local` CA in its default data directory.
#[test]
fn validate_without_a_storage_root_provisions_the_implicit_local_ca() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let directory = tempfile::tempdir().expect("tempdir");
    let data_home = directory.path().join("data");
    // Pre-create Caddy's data directory so `resolve_server_data_dir` selects it deterministically:
    // a legacy `.caddy-rs` left in the package directory by another test binary is only preferred
    // when the Caddy path does not exist yet.
    std::fs::create_dir_all(data_home.join("caddy")).expect("Caddy data directory");
    let _xdg = EnvVarGuard::set("XDG_DATA_HOME", &data_home);
    let _no_override = EnvVarGuard::remove("CADDY_RS_DATA_DIR");

    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(implicit_local_ca_config())
        .expect("config decodes");
    // No `with_data_root`: this is `caddy-rs validate` with no explicit storage.
    let runtime = ServerRuntime::new(store);
    runtime
        .validate_provisioning()
        .expect("validate with no storage root must accept a pool referencing `local`");

    // Caddy's drop-in data path is `$XDG_DATA_HOME/caddy`; the loader reads the same directory.
    let authority = data_home
        .join("caddy")
        .join("pki")
        .join("authorities")
        .join("local");
    let root_pem = std::fs::read_to_string(authority.join("root.crt"))
        .expect("root.crt under the default data directory");
    let intermediate_pem = std::fs::read_to_string(authority.join("intermediate.crt"))
        .expect("intermediate.crt under the default data directory");

    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(implicit_local_ca_config())
        .expect("config decodes");
    ServerRuntime::new(store)
        .validate_provisioning()
        .expect("the second validate must reuse the provisioned CA");
    assert_eq!(
        std::fs::read_to_string(authority.join("root.crt")).expect("root.crt"),
        root_pem
    );
    assert_eq!(
        std::fs::read_to_string(authority.join("intermediate.crt")).expect("intermediate.crt"),
        intermediate_pem
    );
}

/// A storage root that cannot hold the default CA fails loudly with a located provisioning error
/// instead of silently validating. A regular file as the root is a deterministic `ENOTDIR` even
/// when the tests run as root (a mode `0555` directory would still be writable for uid 0).
#[test]
fn unwritable_storage_root_fails_loudly_for_the_implicit_local_ca() {
    let directory = tempfile::tempdir().expect("tempdir");
    let not_a_directory = directory.path().join("storage-root-file");
    std::fs::write(&not_a_directory, b"not a directory").expect("write file");
    let error = runtime_with_data_root(&not_a_directory)
        .validate_provisioning()
        .expect_err("an unwritable storage root must not validate");
    let message = error.to_string();
    assert!(
        message.contains("implicit default PKI authority `local`")
            && message.contains("authorities/local"),
        "error must locate the provisioning failure: {message}"
    );
}

/// Environment variables are process-global; serialize the one test that resolves the default
/// data directory and restore whatever the test process had.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

fn runtime_with_data_root(root: &std::path::Path) -> ServerRuntime {
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(implicit_local_ca_config())
        .expect("config decodes");
    ServerRuntime::new(store).with_data_root(root)
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
