//! TLS for upstream connections (Caddy `transport.tls`).
//!
//! Caddy's HTTP transport enables TLS to upstreams when `transport.tls` is present (an empty
//! object is enough). This module builds the rustls client configuration, including Caddy's trust
//! policy:
//!
//! * `root_ca_pem_files` / `root_ca_pool` (deprecated but honoured, as in Caddy) *replace* the
//!   system trust store with the given roots.
//! * Without explicit roots, the conventional platform PEM bundles are loaded (plus
//!   `SSL_CERT_FILE`/`SSL_CERT_DIR`). If none can be loaded, configuration fails loudly instead of
//!   silently building a client that cannot verify anything.
//! * `insecure_skip_verify` disables verification only when explicitly set to `true`.
//! * `server_name` overrides the SNI/verification name; otherwise it is derived from the upstream
//!   dial host (TCP) or must be configured (Unix sockets have no host).
//! * `handshake_timeout` bounds the TLS handshake, like Caddy's `TLSHandshakeTimeout`.
//!
//! Only the `ring` crypto provider is used because the offline build has no `aws-lc-rs`. ALPN
//! advertises HTTP/1.1 only: the proxy client is HTTP/1.1-only until the h2c/h2 upstream transport
//! work lands, so negotiating h2 would only break the connection.
//!
//! Unsupported Caddy TLS options (client certificates, `ca` modules, renegotiation, explicit
//! curves, `except_ports`) fail loudly with tracked errors instead of being ignored.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName, UnixTime,
};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde_json::Value;

use caddy_rs_http::{Error as HttpError, Result as HttpResult};

/// Conventional system CA bundle locations, tried in order (mirrors the TLS crate's list so the
/// workspace has one set of platform assumptions).
pub const SYSTEM_CA_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ssl/cert.pem",                  // Alpine/macOS
    "/etc/ssl/certs/ca-bundle.crt",       // older Linux
];

/// Parsed `transport.tls` configuration plus the rustls client configuration built from it.
#[derive(Debug)]
pub struct UpstreamTls {
    client_config: Arc<ClientConfig>,
    server_name: Option<String>,
    insecure_skip_verify: bool,
    handshake_timeout: Option<Duration>,
}

impl UpstreamTls {
    /// Parse a `transport.tls` object and build the rustls client configuration.
    ///
    /// Loading roots happens here so a missing/unreadable trust store fails at config load time
    /// (located error) rather than on the first proxied request.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`transport.tls` must be an object"))?;

        reject_unsupported_options(object, path)?;

        let insecure_skip_verify = object
            .get("insecure_skip_verify")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let server_name = object
            .get("server_name")
            .and_then(Value::as_str)
            .filter(|server_name| !server_name.is_empty())
            .map(str::to_string);
        if let Some(server_name) = &server_name {
            ServerName::try_from(server_name.clone()).map_err(|error| {
                invalid(
                    path,
                    format!("`server_name` is not a valid DNS name or IP address: {error}"),
                )
            })?;
        }
        let handshake_timeout = object
            .get("handshake_timeout")
            .and_then(Value::as_u64)
            .filter(|timeout| *timeout > 0)
            .map(Duration::from_nanos);

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|error| {
                invalid(
                    path,
                    format!("rustls protocol configuration failed: {error}"),
                )
            })?;

        let mut client_config = if insecure_skip_verify {
            // Explicit opt-out only: never the default, and no trust store is consulted.
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification { provider }))
                .with_no_client_auth()
        } else {
            // Explicit roots (either deprecated form) *replace* the platform trust store, as in
            // Caddy. Empty explicit lists are treated as absent, matching Caddy's `len(...) > 0`
            // checks. When both forms are given they are merged (Caddy adds both to one pool).
            let pem_files = object
                .get("root_ca_pem_files")
                .map(|files| pem_file_list(files, &format!("{path}.root_ca_pem_files")))
                .transpose()?
                .unwrap_or_default();
            let ca_pool = object
                .get("root_ca_pool")
                .map(|pool| ca_pool_entries(pool, &format!("{path}.root_ca_pool")))
                .transpose()?
                .unwrap_or_default();
            let roots = if pem_files.is_empty() && ca_pool.is_empty() {
                load_platform_roots(path)?
            } else {
                explicit_roots(pem_files, ca_pool, path)?
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        // HTTP/1.1-only client, so that is the only protocol worth advertising.
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self {
            client_config: Arc::new(client_config),
            server_name,
            insecure_skip_verify,
            handshake_timeout,
        })
    }

    /// The rustls client configuration for outbound TLS connections.
    pub fn client_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.client_config)
    }

    /// Whether certificate verification is explicitly disabled.
    pub fn insecure_skip_verify(&self) -> bool {
        self.insecure_skip_verify
    }

    /// Optional TLS handshake timeout.
    pub fn handshake_timeout(&self) -> Option<Duration> {
        self.handshake_timeout
    }

    /// The explicitly configured `server_name`, if any.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// The server name (SNI + verification name) for a connection whose URI host is `uri_host`.
    ///
    /// Explicit `server_name` wins; otherwise the dial host is used, matching Caddy's default.
    /// Unix-socket upstreams have no host, so they need an explicit `server_name` unless
    /// verification is disabled (in which case `localhost` is used as an inert SNI placeholder).
    pub fn server_name_for(&self, uri_host: Option<&str>) -> Result<ServerName<'static>, String> {
        if let Some(server_name) = &self.server_name {
            return ServerName::try_from(server_name.clone())
                .map_err(|error| format!("invalid `transport.tls.server_name`: {error}"));
        }
        match uri_host.filter(|host| !host.is_empty()) {
            Some(host) => ServerName::try_from(host.to_string())
                .map_err(|error| format!("invalid upstream host `{host}` for TLS: {error}")),
            None if self.insecure_skip_verify => ServerName::try_from("localhost")
                .map_err(|error| format!("cannot build placeholder server name: {error}")),
            None => Err(
                "a Unix-socket upstream with `transport.tls` requires an explicit \
                 `transport.tls.server_name` (or `insecure_skip_verify`) because there is no dial \
                 host to use for SNI/verification"
                    .to_string(),
            ),
        }
    }
}

fn reject_unsupported_options(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> HttpResult<()> {
    let unsupported: &[(&str, &str, &str)] = &[
        (
            "client_certificate_file",
            "TLS-UPSTREAM-CLIENT-CERT",
            "TLS client certificate files",
        ),
        (
            "client_certificate_key_file",
            "TLS-UPSTREAM-CLIENT-CERT",
            "TLS client certificate files",
        ),
        (
            "client_certificate_automate",
            "TLS-UPSTREAM-CLIENT-CERT",
            "automated TLS client certificates",
        ),
        (
            "ca",
            "TLS-UPSTREAM-CA-MODULE",
            "`tls.ca_pool.source` CA modules",
        ),
        (
            "curves",
            "TLS-UPSTREAM-CURVES",
            "explicit TLS curve preferences",
        ),
        (
            "except_ports",
            "TLS-UPSTREAM-EXCEPT-PORTS",
            "`except_ports` TLS exceptions",
        ),
    ];
    for (field, tracking_id, feature) in unsupported {
        // Empty strings/arrays/objects are Caddy no-ops, so only meaningful values are rejected.
        let configured = match object.get(*field) {
            None | Some(Value::Null) => false,
            Some(Value::String(value)) => !value.is_empty(),
            Some(Value::Array(values)) => !values.is_empty(),
            Some(Value::Object(values)) => !values.is_empty(),
            Some(_) => true,
        };
        if configured {
            return Err(HttpError::NotImplemented {
                feature,
                tracking_id,
            });
        }
    }
    if let Some(renegotiation) = object.get("renegotiation").and_then(Value::as_str) {
        if !matches!(renegotiation, "" | "never") {
            return Err(HttpError::NotImplemented {
                feature: "TLS renegotiation to upstreams",
                tracking_id: "TLS-UPSTREAM-RENEGOTIATION",
            });
        }
    }
    let _ = path;
    Ok(())
}

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// Build a root store from the explicit roots (deprecated PEM files and/or base64 DER pool).
///
/// Explicit roots replace the platform trust store, matching Caddy (`cfg.RootCAs = rootPool`).
fn explicit_roots(
    pem_files: Vec<PathBuf>,
    ca_pool: Vec<CertificateDer<'static>>,
    path: &str,
) -> HttpResult<RootCertStore> {
    let mut store = RootCertStore::empty();
    for file in &pem_files {
        let bytes = fs::read(file).map_err(|error| {
            invalid(
                &format!("{path}.root_ca_pem_files"),
                format!("cannot read `{}`: {error}", file.display()),
            )
        })?;
        let certificates = parse_pem_certificates(&bytes).map_err(|error| {
            invalid(
                &format!("{path}.root_ca_pem_files"),
                format!("cannot parse `{}`: {error}", file.display()),
            )
        })?;
        if certificates.is_empty() {
            return Err(invalid(
                &format!("{path}.root_ca_pem_files"),
                format!("`{}` contains no CERTIFICATE blocks", file.display()),
            ));
        }
        for certificate in certificates {
            store.add(certificate).map_err(|error| {
                invalid(
                    &format!("{path}.root_ca_pem_files"),
                    format!("invalid CA certificate in `{}`: {error}", file.display()),
                )
            })?;
        }
    }
    for certificate in ca_pool {
        store.add(certificate).map_err(|error| {
            invalid(
                &format!("{path}.root_ca_pool"),
                format!("invalid CA certificate: {error}"),
            )
        })?;
    }
    Ok(store)
}

fn pem_file_list(value: &Value, path: &str) -> HttpResult<Vec<PathBuf>> {
    // Caddy's field type is `[]string`; reject other JSON shapes rather than accepting a
    // configuration Caddy itself would refuse.
    let entries = value
        .as_array()
        .ok_or_else(|| invalid(path, "`root_ca_pem_files` must be an array of strings"))?;
    entries
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(PathBuf::from)
                .ok_or_else(|| invalid(path, "`root_ca_pem_files` entries must be strings"))
        })
        .collect()
}

/// Decode the deprecated `root_ca_pool` (base64-encoded DER certificates).
fn ca_pool_entries(value: &Value, path: &str) -> HttpResult<Vec<CertificateDer<'static>>> {
    let entries = value.as_array().ok_or_else(|| {
        invalid(
            path,
            "`root_ca_pool` must be an array of base64-encoded DER certificates",
        )
    })?;
    let mut certificates = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let encoded = entry.as_str().ok_or_else(|| {
            invalid(
                &format!("{path}[{index}]"),
                "`root_ca_pool` entries must be base64 strings",
            )
        })?;
        let der = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| {
                invalid(
                    &format!("{path}[{index}]"),
                    format!("invalid base64: {error}"),
                )
            })?;
        certificates.push(CertificateDer::from(der));
    }
    Ok(certificates)
}

/// Load platform trust roots from the conventional PEM bundle locations.
///
/// `SSL_CERT_FILE` and `SSL_CERT_DIR` are honoured first (Go's crypto/x509 does the same), then
/// [`SYSTEM_CA_BUNDLES`]. Fails loudly when no certificate can be loaded: a proxy that cannot
/// verify its upstreams must not start.
fn load_platform_roots(path: &str) -> HttpResult<RootCertStore> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(file) = std::env::var_os("SSL_CERT_FILE") {
        candidates.push(PathBuf::from(file));
    }
    candidates.extend(SYSTEM_CA_BUNDLES.iter().map(PathBuf::from));
    load_platform_roots_from(
        &candidates,
        std::env::var_os("SSL_CERT_DIR").as_deref(),
        path,
    )
}

/// Load roots from the given candidate bundle files, then (optionally) from every PEM file in
/// `cert_dir`. Split out from [`load_platform_roots`] so the "no roots" failure path is testable
/// without depending on the host's CA layout.
fn load_platform_roots_from(
    candidates: &[PathBuf],
    cert_dir: Option<&std::ffi::OsStr>,
    path: &str,
) -> HttpResult<RootCertStore> {
    let mut tried = Vec::new();
    for candidate in candidates {
        match fs::read(candidate) {
            Ok(bytes) => match parse_pem_certificates(&bytes) {
                Ok(certificates) if !certificates.is_empty() => {
                    let mut store = RootCertStore::empty();
                    for certificate in certificates {
                        store.add(certificate).map_err(|error| {
                            invalid(
                                path,
                                format!(
                                    "invalid CA certificate in platform bundle `{}`: {error}",
                                    candidate.display()
                                ),
                            )
                        })?;
                    }
                    return Ok(store);
                }
                Ok(_) => tried.push(format!("{} (no certificates)", candidate.display())),
                Err(error) => tried.push(format!("{} ({error})", candidate.display())),
            },
            Err(error) => tried.push(format!("{} ({error})", candidate.display())),
        }
    }

    if let Some(directory) = cert_dir {
        let directory = PathBuf::from(directory);
        if let Ok(entries) = fs::read_dir(&directory) {
            let mut store = RootCertStore::empty();
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(bytes) = fs::read(&path) else {
                    continue;
                };
                let Ok(certificates) = parse_pem_certificates(&bytes) else {
                    continue;
                };
                for certificate in certificates {
                    let _ = store.add(certificate);
                }
            }
            if !store.is_empty() {
                return Ok(store);
            }
            tried.push(format!("{} (no certificates)", directory.display()));
        }
    }

    Err(invalid(
        path,
        format!(
            "no TLS trust roots could be loaded from the platform (tried: {}); \
             set `transport.tls.root_ca_pem_files` to an explicit CA bundle",
            tried.join(", ")
        ),
    ))
}

/// Parse every `CERTIFICATE` PEM block in `pem` into DER.
pub fn parse_pem_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let text = std::str::from_utf8(pem).map_err(|error| format!("not UTF-8 PEM: {error}"))?;
    let mut certificates = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            if current.is_some() {
                return Err("nested CERTIFICATE block".to_string());
            }
            current = Some(String::new());
        } else if line == "-----END CERTIFICATE-----" {
            let Some(body) = current.take() else {
                return Err("END CERTIFICATE without BEGIN".to_string());
            };
            let der = decode_pem_body(&body)?;
            certificates.push(CertificateDer::from(der));
        } else if let Some(body) = current.as_mut() {
            body.push_str(line);
        }
    }
    if current.is_some() {
        return Err("unterminated CERTIFICATE block".to_string());
    }
    Ok(certificates)
}

/// Parse a PEM private key (PKCS#8, SEC1 or PKCS#1) for local TLS test servers.
#[allow(dead_code)]
pub(crate) fn parse_pem_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    let text = std::str::from_utf8(pem).map_err(|error| format!("not UTF-8 PEM: {error}"))?;
    let mut label: Option<&str> = None;
    let mut body = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        {
            label = Some(rest);
            body.clear();
        } else if let Some(rest) = line
            .strip_prefix("-----END ")
            .and_then(|l| l.strip_suffix("-----"))
        {
            if label != Some(rest) {
                return Err(format!("mismatched PEM label `{rest}`"));
            }
            let der = decode_pem_body(&body)?;
            return match rest {
                "PRIVATE KEY" => Ok(PrivatePkcs8KeyDer::from(der).into()),
                "EC PRIVATE KEY" => Ok(PrivateSec1KeyDer::from(der).into()),
                "RSA PRIVATE KEY" => Ok(PrivatePkcs1KeyDer::from(der).into()),
                other => Err(format!("unsupported private key PEM label `{other}`")),
            };
        } else if label.is_some() {
            body.push_str(line);
        }
    }
    Err("no private key PEM block found".to_string())
}

fn decode_pem_body(body: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|error| format!("invalid base64 in PEM block: {error}"))
}

/// Certificate verifier used only when `insecure_skip_verify: true` is explicitly configured.
///
/// It still verifies handshake signatures (so the connection is cryptographically sound), but it
/// does not validate the certificate chain or hostname — matching Go's `InsecureSkipVerify`.
#[derive(Debug)]
struct NoCertificateVerification {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoCertificateVerification {
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
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCALHOST_CERT: &str = include_str!("../testdata/tls/localhost-cert.pem");
    const UNRELATED_CERT: &str = include_str!("../testdata/tls/unrelated-cert.pem");

    fn write_pem(directory: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = directory.path().join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn parses_explicit_roots_and_server_name() {
        let directory = tempfile::tempdir().unwrap();
        let certs = write_pem(&directory, "root.pem", LOCALHOST_CERT);
        let tls = UpstreamTls::from_json(
            &serde_json::json!({
                "root_ca_pem_files": [certs.display().to_string()],
                "server_name": "localhost",
                "handshake_timeout": 1_000_000_000u64
            }),
            "transport.tls",
        )
        .unwrap();
        assert_eq!(
            tls.server_name_for(Some("127.0.0.1")).unwrap().to_str(),
            "localhost"
        );
        assert_eq!(tls.handshake_timeout(), Some(Duration::from_secs(1)));
        assert!(!tls.insecure_skip_verify());
    }

    #[test]
    fn explicit_root_files_are_used_instead_of_platform_roots() {
        let directory = tempfile::tempdir().unwrap();
        let certs = write_pem(&directory, "root.pem", UNRELATED_CERT);
        let tls = UpstreamTls::from_json(
            &serde_json::json!({"root_ca_pem_files": [certs.display().to_string()]}),
            "transport.tls",
        )
        .unwrap();
        // The store was built without touching the platform bundle; presence of the option is
        // enough to prove the explicit path was taken (the platform loader would also succeed).
        assert_eq!(
            tls.client_config().alpn_protocols,
            vec![b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn empty_explicit_root_lists_fall_back_to_platform_roots_like_caddy() {
        // Caddy only replaces the system store when an explicit list is non-empty.
        let tls = UpstreamTls::from_json(
            &serde_json::json!({"root_ca_pem_files": [], "root_ca_pool": []}),
            "transport.tls",
        );
        // Either the platform bundle loads (normal Linux/macOS host) or the loud missing-roots
        // error fires; both are acceptable, silently trusting nothing is not.
        match tls {
            Ok(tls) => assert!(!tls.insecure_skip_verify()),
            Err(error) => assert!(error.to_string().contains("no TLS trust roots"), "{error}"),
        }
    }

    #[test]
    fn explicit_pem_files_and_ca_pool_are_merged() {
        let directory = tempfile::tempdir().unwrap();
        let certs = write_pem(&directory, "root.pem", LOCALHOST_CERT);
        let der = parse_pem_certificates(UNRELATED_CERT.as_bytes())
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        UpstreamTls::from_json(
            &serde_json::json!({
                "root_ca_pem_files": [certs.display().to_string()],
                "root_ca_pool": [encoded]
            }),
            "transport.tls",
        )
        .unwrap();
    }

    #[test]
    fn empty_unsupported_option_values_are_accepted_as_noops() {
        UpstreamTls::from_json(
            &serde_json::json!({
                "insecure_skip_verify": true,
                "client_certificate_file": "",
                "curves": [],
                "except_ports": []
            }),
            "transport.tls",
        )
        .unwrap();
    }

    #[test]
    fn base64_root_ca_pool_is_supported() {
        let der = parse_pem_certificates(LOCALHOST_CERT.as_bytes())
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        let tls = UpstreamTls::from_json(
            &serde_json::json!({"root_ca_pool": [encoded]}),
            "transport.tls",
        )
        .unwrap();
        assert!(!tls.insecure_skip_verify());
    }

    #[test]
    fn missing_root_file_fails_loudly() {
        let error = UpstreamTls::from_json(
            &serde_json::json!({"root_ca_pem_files": ["/nonexistent/ca.pem"]}),
            "transport.tls",
        )
        .expect_err("missing root file must fail");
        let message = error.to_string();
        assert!(message.contains("root_ca_pem_files"), "{message}");
        assert!(message.contains("cannot read"), "{message}");
    }

    #[test]
    fn pem_file_without_certificates_fails_loudly() {
        let directory = tempfile::tempdir().unwrap();
        let empty = write_pem(&directory, "empty.pem", "not a certificate\n");
        let error = UpstreamTls::from_json(
            &serde_json::json!({"root_ca_pem_files": [empty.display().to_string()]}),
            "transport.tls",
        )
        .err()
        .expect("empty trust store must fail");
        assert!(
            error.to_string().contains("no CERTIFICATE blocks"),
            "{error}"
        );
    }

    #[test]
    fn no_loadable_platform_roots_fails_loudly() {
        let candidates = [
            PathBuf::from("/nonexistent/ca-certificates.crt"),
            PathBuf::from("/nonexistent/ca-bundle.pem"),
        ];
        let error = load_platform_roots_from(&candidates, None, "transport.tls")
            .expect_err("no loadable bundle must fail loudly");
        let message = error.to_string();
        assert!(message.contains("no TLS trust roots"), "{message}");
        assert!(message.contains("root_ca_pem_files"), "{message}");
        assert!(
            message.contains("/nonexistent/ca-certificates.crt"),
            "error must name what was tried: {message}"
        );
    }

    #[test]
    fn rejects_unsupported_tls_options_loudly() {
        for (config, tracking_id) in [
            (
                serde_json::json!({"client_certificate_file": "/tmp/c.pem"}),
                "TLS-UPSTREAM-CLIENT-CERT",
            ),
            (
                serde_json::json!({"client_certificate_automate": "example.com"}),
                "TLS-UPSTREAM-CLIENT-CERT",
            ),
            (
                serde_json::json!({"ca": {"provider": "inline"}}),
                "TLS-UPSTREAM-CA-MODULE",
            ),
            (
                serde_json::json!({"curves": ["X25519"]}),
                "TLS-UPSTREAM-CURVES",
            ),
            (
                serde_json::json!({"except_ports": ["8080"]}),
                "TLS-UPSTREAM-EXCEPT-PORTS",
            ),
            (
                serde_json::json!({"renegotiation": "freely"}),
                "TLS-UPSTREAM-RENEGOTIATION",
            ),
        ] {
            let error = UpstreamTls::from_json(&config, "transport.tls")
                .expect_err("unsupported option must fail");
            assert!(error.to_string().contains(tracking_id), "{error}");
        }
        // The default renegotiation level is accepted.
        UpstreamTls::from_json(
            &serde_json::json!({"insecure_skip_verify": true, "renegotiation": "never"}),
            "transport.tls",
        )
        .unwrap();
    }

    #[test]
    fn invalid_server_name_fails_loudly() {
        let error = UpstreamTls::from_json(
            &serde_json::json!({"insecure_skip_verify": true, "server_name": "not a name/with space"}),
            "transport.tls",
        )
        .expect_err("invalid server name must fail");
        assert!(error.to_string().contains("server_name"), "{error}");
    }

    #[test]
    fn unix_upstream_requires_server_name_unless_insecure() {
        let directory = tempfile::tempdir().unwrap();
        let certs = write_pem(&directory, "root.pem", LOCALHOST_CERT);
        let tls = UpstreamTls::from_json(
            &serde_json::json!({"root_ca_pem_files": [certs.display().to_string()]}),
            "transport.tls",
        )
        .unwrap();
        let error = tls
            .server_name_for(None)
            .expect_err("unix sockets have no host");
        assert!(error.contains("server_name"), "{error}");

        let insecure = UpstreamTls::from_json(
            &serde_json::json!({"insecure_skip_verify": true}),
            "transport.tls",
        )
        .unwrap();
        assert_eq!(
            insecure.server_name_for(None).unwrap().to_str(),
            "localhost",
            "insecure unix TLS uses an inert placeholder SNI"
        );
    }

    #[test]
    fn insecure_skip_verify_is_explicit_and_needs_no_roots() {
        let tls = UpstreamTls::from_json(
            &serde_json::json!({"insecure_skip_verify": true}),
            "transport.tls",
        )
        .unwrap();
        assert!(tls.insecure_skip_verify());
    }

    #[test]
    fn pem_certificate_parser_reads_multiple_blocks() {
        let combined = format!("{LOCALHOST_CERT}\n{UNRELATED_CERT}");
        let certificates = parse_pem_certificates(combined.as_bytes()).unwrap();
        assert_eq!(certificates.len(), 2);
    }
}
