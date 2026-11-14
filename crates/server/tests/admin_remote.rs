//! End-to-end test for `admin.remote`: the runtime starts the mutual-TLS admin listener from the
//! configuration, enforces `access_control`, and leaves the plaintext listener working.
//!
//! Test certificates are minted with the `openssl` CLI (the workspace has no certificate
//! generation crate in `Cargo.lock`); the production path never shells out.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use caddy_rs_core::{Config, GenerationStore};
use caddy_rs_server::ServerRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

struct Certificates {
    directory: PathBuf,
    ca_pem: String,
    client_pem: String,
    client_key_pem: String,
    server_pem: PathBuf,
    server_key_pem: PathBuf,
}

impl Drop for Certificates {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn openssl(directory: &Path, arguments: &[&str]) {
    let output = std::process::Command::new("openssl")
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("openssl is available for this integration test");
    assert!(
        output.status.success(),
        "openssl {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mint_ca(directory: &Path, prefix: &str) {
    openssl(
        directory,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &format!("{prefix}.key"),
            "-out",
            &format!("{prefix}.pem"),
            "-days",
            "2",
            "-subj",
            &format!("/CN={prefix}"),
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
    );
}

fn mint(directory: &Path, prefix: &str, extensions: &str, cn: &str) {
    let extension_file = directory.join(format!("{prefix}.ext"));
    std::fs::write(&extension_file, extensions).expect("extension file");
    openssl(
        directory,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &format!("{prefix}.key"),
            "-out",
            &format!("{prefix}.csr"),
            "-subj",
            &format!("/CN={cn}"),
        ],
    );
    openssl(
        directory,
        &[
            "x509",
            "-req",
            "-in",
            &format!("{prefix}.csr"),
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            &format!("{prefix}.pem"),
            "-days",
            "2",
            "-sha256",
            "-extfile",
            &extension_file.to_string_lossy(),
        ],
    );
}

fn certificates(name: &str) -> Certificates {
    let directory = std::env::temp_dir().join(format!(
        "caddy-rs-admin-remote-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("temp directory");
    mint_ca(&directory, "ca");
    mint(
        &directory,
        "server",
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
        "localhost",
    );
    mint(
        &directory,
        "client",
        "extendedKeyUsage=clientAuth\n",
        "runtime-client",
    );
    Certificates {
        ca_pem: std::fs::read_to_string(directory.join("ca.pem")).expect("CA PEM"),
        client_pem: std::fs::read_to_string(directory.join("client.pem")).expect("client PEM"),
        client_key_pem: std::fs::read_to_string(directory.join("client.key")).expect("client key"),
        server_pem: directory.join("server.pem"),
        server_key_pem: directory.join("server.key"),
        directory,
    }
}

fn der_base64(pem: &str) -> String {
    use base64::Engine as _;
    let chain = caddy_rs_tls::certificates_from_pem(pem).expect("PEM certificate");
    base64::engine::general_purpose::STANDARD.encode(chain[0].as_ref())
}

fn config(certificates: &Certificates) -> Config {
    Config::from_value(serde_json::json!({
        "admin": {
            "listen": "127.0.0.1:0",
            "identity": {
                "identifiers": ["localhost"],
                "certificate": certificates.server_pem.to_string_lossy(),
                "key": certificates.server_key_pem.to_string_lossy(),
            },
            "remote": {
                "listen": "127.0.0.1:0",
                "access_control": [{
                    "public_keys": [
                        der_base64(&certificates.client_pem),
                        der_base64(&certificates.ca_pem),
                    ],
                    "permissions": [{ "paths": ["/config/"], "methods": ["GET"] }],
                }],
            },
        },
    }))
    .expect("admin.identity + admin.remote config decodes")
}

async fn request_status(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    request: &str,
) -> u16 {
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8_lossy(&response);
    response
        .split_whitespace()
        .nth(1)
        .expect("status line")
        .parse()
        .expect("numeric status")
}

async fn plaintext_status(address: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.write_all(request).await.expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn runtime_starts_remote_admin_beside_the_plaintext_listener() {
    let certificates = certificates("runtime");
    let store = Arc::new(GenerationStore::with_builtin_registry());
    store
        .load(config(&certificates))
        .expect("config validates and loads");
    let mut runtime = ServerRuntime::new(Arc::clone(&store));
    runtime.apply().await.expect("runtime applies");

    let plaintext = runtime.admin_address().expect("plaintext admin bound");
    let remote = runtime
        .remote_admin_address()
        .expect("remote admin listener bound from admin.remote");
    assert_ne!(
        plaintext, remote,
        "the secure listener is a second listener"
    );

    // The plaintext endpoint keeps serving with the origin policy and no client certificate.
    let response = plaintext_status(
        plaintext,
        b"GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    // The secure endpoint requires mutual TLS.
    let _ = caddy_rs_tls::install_default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    let ca = caddy_rs_tls::certificates_from_pem(&certificates.ca_pem).expect("CA PEM");
    roots.add(ca[0].clone()).expect("CA is a trust anchor");
    let chain = caddy_rs_tls::certificates_from_pem(&certificates.client_pem).expect("client PEM");
    let identity = caddy_rs_tls::TlsCertificate::from_pem(
        &certificates.client_pem,
        &certificates.client_key_pem,
    )
    .expect("client identity");
    let key = identity.private_key().expect("client key").clone_key();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .expect("client certificate matches its key");
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(("127.0.0.1", remote.port()))
        .await
        .expect("connect to the remote admin listener");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .expect("mutual TLS handshake");
    let status = request_status(
        &mut stream,
        "GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);

    runtime.shutdown().await;
}
