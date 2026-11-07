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
//! * `ca` selects a `tls.ca_pool.source` module for custom trust roots: `inline`
//!   (`trusted_ca_certs`), `file` (`pem_files`), `system`, or `combined` (`sources`, whose sources
//!   must expose certificates: inline/file). It conflicts with the deprecated root options, like
//!   in Caddy.
//! * `client_certificate_file` / `client_certificate_key_file` configure a client certificate for
//!   mutual TLS to the upstream (PEM certificate chain + PKCS#8/SEC1/PKCS#1 private key).
//! * `client_certificate` is a caddy-rs extension for inline PEM client certificates
//!   (`{"certificate": "-----BEGIN CERTIFICATE...", "key": "-----BEGIN PRIVATE KEY..."}`).
//!   Caddy v2.11.9 has no such HTTP-transport field (it ignores unknown JSON fields), so this
//!   extension is documented in DIV-0010/DIV-0086 and is mutually exclusive with the file fields.
//! * `except_ports` lists upstream ports that must be dialed without TLS even when `tls` is
//!   configured (Caddy skips TLS for those ports).
//! * `insecure_skip_verify` disables verification only when explicitly set to `true`.
//! * `server_name` overrides the SNI/verification name; otherwise it is derived from the upstream
//!   dial host (TCP) or must be configured (Unix sockets have no host).
//! * `handshake_timeout` bounds the TLS handshake, like Caddy's `TLSHandshakeTimeout`.
//!
//! Only the `ring` crypto provider is used because the offline build has no `aws-lc-rs`.
//!
//! Unsupported Caddy TLS options (`client_certificate_automate`, explicit `curves`, any
//! `renegotiation` other than "never") fail loudly with tracked errors instead of being ignored.

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
    /// Upstream ports that must be dialed without TLS (Caddy `except_ports`).
    except_ports: Vec<u16>,
}

/// ALPN protocol identifier for HTTP/1.1.
const ALPN_HTTP11: &[u8] = b"http/1.1";
/// ALPN protocol identifier for HTTP/2 (RFC 7540).
const ALPN_H2: &[u8] = b"h2";

impl UpstreamTls {
    /// Parse a `transport.tls` object and build the rustls client configuration.
    ///
    /// Loading roots happens here so a missing/unreadable trust store fails at config load time
    /// (located error) rather than on the first proxied request.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        Self::from_json_with_alpn(value, path, &[ALPN_HTTP11])
    }

    /// Parse `transport.tls` and advertise the given ALPN protocols.
    ///
    /// The handler derives these from `transport.versions`: Caddy/Go offer `["h2","http/1.1"]`
    /// when HTTP/2 is enabled for TLS upstreams (HTTP/1.1 remains a fallback), and
    /// `["http/1.1"]` when only HTTP/1.1 is configured.
    pub fn from_json_with_alpn(
        value: &Value,
        path: &str,
        alpn_protocols: &[&[u8]],
    ) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`transport.tls` must be an object"))?;

        validate_unsupported_options(object, path)?;
        validate_known_options(object, path)?;
        let except_ports = parse_except_ports(object, &format!("{path}.except_ports"))?;
        let inline_client = object
            .get("client_certificate")
            .filter(|value| !matches!(value, Value::Null));
        let file_client = object
            .get("client_certificate_file")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
            || object
                .get("client_certificate_key_file")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty());
        if inline_client.is_some() && file_client {
            return Err(invalid(
                path,
                "`client_certificate` cannot be combined with `client_certificate_file` / \
                 `client_certificate_key_file`",
            ));
        }
        let client_auth = match inline_client {
            Some(value) => Some(parse_inline_client_certificate(value, path)?),
            None => parse_client_auth(object, path)?,
        };

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

        // Trust configuration: the `ca` module (new) or the deprecated root options; the
        // deprecated roots replace the platform store, and either form conflicts with `ca`.
        let deprecated_roots = {
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
            (!pem_files.is_empty() || !ca_pool.is_empty()).then_some((pem_files, ca_pool))
        };
        let configured_ca = object
            .get("ca")
            .filter(|value| !matches!(value, Value::Null))
            .map(|value| parse_ca_module(value, &format!("{path}.ca")))
            .transpose()?;
        if configured_ca.is_some() && deprecated_roots.is_some() {
            return Err(invalid(path, "conflicting config for Root CA pool"));
        }

        let builder = if insecure_skip_verify {
            // Explicit opt-out only: never the default, and no trust store is consulted.
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification { provider }))
        } else {
            let roots = match configured_ca {
                Some(roots) => roots,
                None => match deprecated_roots {
                    Some((pem_files, ca_pool)) => explicit_roots(pem_files, ca_pool, path)?,
                    None => load_platform_roots(path)?,
                },
            };
            builder.with_root_certificates(roots)
        };
        let mut client_config =
            match client_auth {
                Some((certificates, key)) => builder
                    .with_client_auth_cert(certificates, key)
                    .map_err(|error| {
                        invalid(path, format!("loading TLS client certificate: {error}"))
                    })?,
                None => builder.with_no_client_auth(),
            };
        client_config.alpn_protocols = alpn_protocols
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();

        Ok(Self {
            client_config: Arc::new(client_config),
            server_name,
            insecure_skip_verify,
            handshake_timeout,
            except_ports,
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

    /// Upstream ports for which TLS is skipped (Caddy `except_ports`).
    pub fn except_ports(&self) -> &[u16] {
        &self.except_ports
    }

    /// Whether TLS should be used for an upstream whose dial port is `port`.
    pub fn should_use_tls(&self, port: Option<u16>) -> bool {
        !port.is_some_and(|port| self.except_ports.contains(&port))
    }

    /// The explicitly configured `server_name`, if any.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// ALPN protocols this client offers.
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.client_config.alpn_protocols
    }

    /// A clone that offers HTTP/2 and HTTP/1.1 via ALPN (Caddy's TLS-upstream HTTP/2 default).
    pub fn with_http2_alpn(&self) -> Self {
        self.with_alpn(&[ALPN_H2, ALPN_HTTP11])
    }

    /// A clone that offers HTTP/1.1 only.
    ///
    /// Used for protocol-upgrade (WebSocket) requests when the main transport prefers HTTP/2:
    /// Caddy disables ALPN h2 for upgradable connections because HTTP/1.1 upgrades cannot be
    /// carried over HTTP/2.
    pub fn h1_only(&self) -> Self {
        self.with_alpn(&[ALPN_HTTP11])
    }

    fn with_alpn(&self, alpn_protocols: &[&[u8]]) -> Self {
        let mut client_config = (*self.client_config).clone();
        client_config.alpn_protocols = alpn_protocols
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        Self {
            client_config: Arc::new(client_config),
            server_name: self.server_name.clone(),
            insecure_skip_verify: self.insecure_skip_verify,
            handshake_timeout: self.handshake_timeout,
            except_ports: self.except_ports.clone(),
        }
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

/// Every field Caddy v2.11.9's `HTTPTransport.TLSConfig` accepts, plus the caddy-rs inline
/// `client_certificate` extension. Caddy decodes module configuration strictly, so an unknown
/// field is a configuration error rather than being silently ignored.
const KNOWN_TLS_OPTIONS: &[&str] = &[
    "ca",
    "root_ca_pool",
    "root_ca_pem_files",
    "client_certificate_file",
    "client_certificate_key_file",
    "client_certificate_automate",
    "client_certificate", // caddy-rs extension (DIV-0010/DIV-0086)
    "insecure_skip_verify",
    "handshake_timeout",
    "server_name",
    "renegotiation",
    "except_ports",
    "curves",
];

/// Reject unknown `transport.tls` fields like Caddy's strict module decoding does.
fn validate_known_options(object: &serde_json::Map<String, Value>, path: &str) -> HttpResult<()> {
    for field in object.keys() {
        if !KNOWN_TLS_OPTIONS.contains(&field.as_str()) {
            return Err(invalid(
                &format!("{path}.{field}"),
                format!("unknown TLS transport option `{field}`"),
            ));
        }
    }
    Ok(())
}

/// Options that are genuinely unsupported fail loudly; everything else is parsed by the caller.
fn validate_unsupported_options(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> HttpResult<()> {
    const UNSUPPORTED: &[(&str, &str, &str)] = &[
        (
            "client_certificate_automate",
            "TLS-UPSTREAM-CLIENT-CERT",
            "automated TLS client certificates",
        ),
        (
            "curves",
            "TLS-UPSTREAM-CURVES",
            "explicit TLS curve preferences",
        ),
    ];
    for (field, tracking_id, feature) in UNSUPPORTED {
        // Empty strings/arrays are Caddy no-ops, so only meaningful values are rejected.
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

/// Parse `except_ports` (Caddy `[]string` of port numbers; TLS is skipped for those upstreams).
fn parse_except_ports(object: &serde_json::Map<String, Value>, path: &str) -> HttpResult<Vec<u16>> {
    let Some(value) = object.get("except_ports") else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let entries = value
        .as_array()
        .ok_or_else(|| invalid(path, "`except_ports` must be an array of port strings"))?;
    let mut ports = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let text = entry.as_str().ok_or_else(|| {
            invalid(
                &format!("{path}[{index}]"),
                "`except_ports` entries must be strings",
            )
        })?;
        let port = text.parse::<u16>().map_err(|_| {
            invalid(
                &format!("{path}[{index}]"),
                format!("`{text}` is not a valid TCP port"),
            )
        })?;
        ports.push(port);
    }
    Ok(ports)
}

type ClientAuth = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// Parse the mutual-TLS client certificate pair (Caddy `client_certificate_file` +
/// `client_certificate_key_file`).
fn parse_client_auth(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> HttpResult<Option<ClientAuth>> {
    let certificate_file = object
        .get("client_certificate_file")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let key_file = object
        .get("client_certificate_key_file")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    match (certificate_file, key_file) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(invalid(
            path,
            "`client_certificate_file` specified without `client_certificate_key_file`",
        )),
        (None, Some(_)) => Err(invalid(
            path,
            "`client_certificate_key_file` specified without `client_certificate_file`",
        )),
        (Some(certificate_file), Some(key_file)) => {
            let certificate_path = PathBuf::from(certificate_file);
            let bytes = fs::read(&certificate_path).map_err(|error| {
                invalid(
                    path,
                    format!(
                        "cannot read TLS client certificate `{}`: {error}",
                        certificate_path.display()
                    ),
                )
            })?;
            let certificates = parse_client_certificates(&bytes, path, "certificate")?;
            let key_path = PathBuf::from(key_file);
            let key_bytes = fs::read(&key_path).map_err(|error| {
                invalid(
                    path,
                    format!(
                        "cannot read TLS client certificate key `{}`: {error}",
                        key_path.display()
                    ),
                )
            })?;
            let key = parse_client_key(&key_bytes, path, "key")?;
            Ok(Some((certificates, key)))
        }
    }
}

/// Parse an inline `client_certificate` extension (`{"certificate": PEM, "key": PEM}`).
fn parse_inline_client_certificate(
    value: &Value,
    path: &str,
) -> HttpResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let object = value.as_object().ok_or_else(|| {
        invalid(
            &format!("{path}.client_certificate"),
            "`client_certificate` must be an object with `certificate` and `key` PEM strings",
        )
    })?;
    let certificate = object
        .get("certificate")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid(
                &format!("{path}.client_certificate.certificate"),
                "`client_certificate.certificate` must be a non-empty PEM string",
            )
        })?;
    let key = object
        .get("key")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid(
                &format!("{path}.client_certificate.key"),
                "`client_certificate.key` must be a non-empty PEM string",
            )
        })?;
    let certificates = parse_client_certificates(
        certificate.as_bytes(),
        &format!("{path}.client_certificate"),
        "certificate",
    )?;
    let key = parse_client_key(key.as_bytes(), &format!("{path}.client_certificate"), "key")?;
    Ok((certificates, key))
}

fn parse_client_certificates(
    pem: &[u8],
    path: &str,
    field: &str,
) -> HttpResult<Vec<CertificateDer<'static>>> {
    let certificates = parse_pem_certificates(pem)
        .map_err(|error| invalid(path, format!("cannot parse TLS client {field}: {error}")))?;
    if certificates.is_empty() {
        return Err(invalid(
            path,
            format!("TLS client {field} contains no CERTIFICATE blocks"),
        ));
    }
    Ok(certificates)
}

fn parse_client_key(pem: &[u8], path: &str, field: &str) -> HttpResult<PrivateKeyDer<'static>> {
    parse_pem_private_key(pem)
        .map_err(|error| invalid(path, format!("cannot parse TLS client {field}: {error}")))
}

/// Parse a Caddy `ca` module (`namespace=tls.ca_pool.source`, `inline_key=provider`).
///
/// Supported providers: `inline` (`trusted_ca_certs` base64 DER), `file` (`pem_files`), `system`,
/// and `combined` (`sources`, which must expose certificates — inline/file only, as in Caddy).
/// Other providers are rejected loudly with the module names this build supports.
fn parse_ca_module(value: &Value, path: &str) -> HttpResult<RootCertStore> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "`ca` must be a CA pool source module object"))?;
    let provider = object
        .get("provider")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(path, "`ca` module is missing its `provider`"))?;
    match provider {
        "inline" => {
            let entries = object.get("trusted_ca_certs").ok_or_else(|| {
                invalid(
                    path,
                    "`ca` inline provider requires `trusted_ca_certs`",
                )
            })?;
            let certificates = ca_pool_entries(entries, &format!("{path}.trusted_ca_certs"))?;
            if certificates.is_empty() {
                return Err(invalid(
                    path,
                    "`ca` inline provider has no `trusted_ca_certs`",
                ));
            }
            roots_from_certificates(certificates, path)
        }
        "file" => {
            let entries = object
                .get("pem_files")
                .ok_or_else(|| invalid(path, "`ca` file provider requires `pem_files`"))?;
            let files = pem_file_list(entries, &format!("{path}.pem_files"))?;
            if files.is_empty() {
                return Err(invalid(path, "`ca` file provider has no `pem_files`"));
            }
            let certificates = read_pem_files(&files, &format!("{path}.pem_files"))?;
            roots_from_certificates(certificates, path)
        }
        "system" => load_platform_roots(path),
        "combined" => {
            let sources = object
                .get("sources")
                .ok_or_else(|| invalid(path, "`ca` combined provider requires `sources`"))?
                .as_array()
                .ok_or_else(|| invalid(&format!("{path}.sources"), "`sources` must be an array"))?;
            if sources.is_empty() {
                return Err(invalid(path, "`ca` combined provider has no sources"));
            }
            let mut certificates = Vec::new();
            for (index, source) in sources.iter().enumerate() {
                let source_path = format!("{path}.sources[{index}]");
                let source_object = source.as_object().ok_or_else(|| {
                    invalid(&source_path, "CA pool source must be a module object")
                })?;
                let source_provider = source_object
                    .get("provider")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid(&source_path, "CA pool source is missing `provider`"))?;
                match source_provider {
                    "inline" => {
                        let entries =
                            source_object.get("trusted_ca_certs").ok_or_else(|| {
                                invalid(
                                    &source_path,
                                    "`ca` inline provider requires `trusted_ca_certs`",
                                )
                            })?;
                        certificates.extend(ca_pool_entries(
                            entries,
                            &format!("{source_path}.trusted_ca_certs"),
                        )?);
                    }
                    "file" => {
                        let entries = source_object.get("pem_files").ok_or_else(|| {
                            invalid(&source_path, "`ca` file provider requires `pem_files`")
                        })?;
                        let files = pem_file_list(entries, &format!("{source_path}.pem_files"))?;
                        certificates.extend(read_pem_files(
                            &files,
                            &format!("{source_path}.pem_files"),
                        )?);
                    }
                    "system" => {
                        // Caddy's SystemCAPool does not implement CertificateProvider, so it
                        // cannot be a `combined` source.
                        return Err(invalid(
                            &source_path,
                            "`ca` combined sources cannot include `system` (it exposes no certificates)",
                        ));
                    }
                    other => {
                        return Err(invalid(
                            &source_path,
                            format!(
                                "`ca` provider `{other}` is not implemented (supported: inline, file, system, combined; TLS-UPSTREAM-CA-MODULE)"
                            ),
                        ))
                    }
                }
            }
            if certificates.is_empty() {
                return Err(invalid(
                    path,
                    "`ca` combined provider produced no certificates",
                ));
            }
            roots_from_certificates(certificates, path)
        }
        other => Err(invalid(
            path,
            format!(
                "`ca` provider `{other}` is not implemented (supported: inline, file, system, combined; TLS-UPSTREAM-CA-MODULE)"
            ),
        )),
    }
}

fn read_pem_files(files: &[PathBuf], path: &str) -> HttpResult<Vec<CertificateDer<'static>>> {
    let mut certificates = Vec::new();
    for file in files {
        let bytes = fs::read(file)
            .map_err(|error| invalid(path, format!("cannot read `{}`: {error}", file.display())))?;
        let parsed = parse_pem_certificates(&bytes).map_err(|error| {
            invalid(path, format!("cannot parse `{}`: {error}", file.display()))
        })?;
        if parsed.is_empty() {
            return Err(invalid(
                path,
                format!("`{}` contains no CERTIFICATE blocks", file.display()),
            ));
        }
        certificates.extend(parsed);
    }
    Ok(certificates)
}

fn roots_from_certificates(
    certificates: Vec<CertificateDer<'static>>,
    path: &str,
) -> HttpResult<RootCertStore> {
    let mut store = RootCertStore::empty();
    for certificate in certificates {
        store
            .add(certificate)
            .map_err(|error| invalid(path, format!("invalid CA certificate: {error}")))?;
    }
    if store.is_empty() {
        return Err(invalid(path, "CA pool is empty"));
    }
    Ok(store)
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

/// Parse a PEM private key (PKCS#8, SEC1 or PKCS#1) for upstream client certificates and tests.
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
    const LOCALHOST_KEY: &str = include_str!("../testdata/tls/localhost-key.pem");
    const UNRELATED_CERT: &str = include_str!("../testdata/tls/unrelated-cert.pem");
    const CLIENT_CERT: &str = include_str!("../testdata/tls/client-cert.pem");
    const CLIENT_KEY: &str = include_str!("../testdata/tls/client-key.pem");
    const CLIENT_CA: &str = include_str!("../testdata/tls/client-ca-cert.pem");

    fn write_pem(directory: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = directory.path().join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn inline_client_certificate_extension_parses() {
        UpstreamTls::from_json(
            &serde_json::json!({
                "client_certificate": {
                    "certificate": CLIENT_CERT,
                    "key": CLIENT_KEY
                }
            }),
            "transport.tls",
        )
        .expect("inline client certificate is accepted");

        // Mutually exclusive with the file fields and validated field by field.
        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "client_certificate": {"certificate": CLIENT_CERT, "key": CLIENT_KEY},
                "client_certificate_file": "/tmp/client.pem",
                "client_certificate_key_file": "/tmp/client-key.pem"
            }),
            "transport.tls",
        )
        .expect_err("inline and file client certificates conflict");
        assert!(error.to_string().contains("cannot be combined"), "{error}");

        let error = UpstreamTls::from_json(
            &serde_json::json!({"client_certificate": {"certificate": CLIENT_CERT}}),
            "transport.tls",
        )
        .expect_err("missing inline key fails");
        assert!(
            error.to_string().contains("client_certificate.key"),
            "located at the missing key: {error}"
        );

        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "client_certificate": {"certificate": "not pem", "key": CLIENT_KEY}
            }),
            "transport.tls",
        )
        .expect_err("bad inline certificate fails");
        assert!(
            error.to_string().contains("TLS client certificate"),
            "{error}"
        );

        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "client_certificate": {"certificate": CLIENT_CERT, "key": "not pem"}
            }),
            "transport.tls",
        )
        .expect_err("bad inline key fails");
        assert!(
            error.to_string().contains("cannot parse TLS client key"),
            "{error}"
        );
    }

    #[test]
    fn client_certificate_file_errors_are_located_and_validated_at_load() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = write_pem(&directory, "client.pem", CLIENT_CERT);
        let key = write_pem(&directory, "client-key.pem", CLIENT_KEY);

        let missing = directory.path().join("missing.pem");
        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "client_certificate_file": missing.display().to_string(),
                "client_certificate_key_file": key.display().to_string()
            }),
            "transport.tls",
        )
        .expect_err("missing client certificate file fails");
        assert!(
            error
                .to_string()
                .contains("cannot read TLS client certificate"),
            "{error}"
        );

        let bad_pem = write_pem(&directory, "bad.pem", "not a certificate");
        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "client_certificate_file": bad_pem.display().to_string(),
                "client_certificate_key_file": key.display().to_string()
            }),
            "transport.tls",
        )
        .expect_err("bad certificate PEM fails");
        assert!(
            error.to_string().contains("TLS client certificate"),
            "{error}"
        );

        // Encrypted PKCS#8 keys are not supported by Go's `tls.LoadX509KeyPair` either; caddy-rs
        // fails loudly at configuration load.
        let encrypted = write_pem(
            &directory,
            "encrypted-key.pem",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----",
        );
        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "client_certificate_file": certificate.display().to_string(),
                "client_certificate_key_file": encrypted.display().to_string()
            }),
            "transport.tls",
        )
        .expect_err("encrypted client key fails");
        assert!(
            error
                .to_string()
                .contains("unsupported private key PEM label"),
            "{error}"
        );

        // rustls validates that the client key matches the certificate at configuration load.
        let server_key = write_pem(&directory, "server-key.pem", LOCALHOST_KEY);
        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "client_certificate_file": certificate.display().to_string(),
                "client_certificate_key_file": server_key.display().to_string()
            }),
            "transport.tls",
        )
        .expect_err("mismatched client certificate/key fails");
        assert!(
            error.to_string().contains("loading TLS client certificate"),
            "{error}"
        );
    }

    #[test]
    fn invalid_root_ca_pool_entries_are_located_errors() {
        let error = UpstreamTls::from_json(
            &serde_json::json!({"root_ca_pool": ["not base64!!"]}),
            "transport.tls",
        )
        .expect_err("invalid base64 DER pool entry fails");
        assert!(error.to_string().contains("root_ca_pool"), "{error}");
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
        .expect_err("empty trust store must fail");
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
    fn unknown_tls_options_are_rejected_like_caddys_strict_decoding() {
        let error = UpstreamTls::from_json(
            &serde_json::json!({"tls_timeout": 1_000_000_000u64}),
            "transport.tls",
        )
        .expect_err("unknown TLS option is rejected");
        let message = error.to_string();
        assert!(
            message.contains("transport.tls.tls_timeout") && message.contains("unknown TLS"),
            "located error naming the field: {message}"
        );
    }

    #[test]
    fn rejects_unsupported_tls_options_loudly() {
        for (config, tracking_id) in [
            (
                serde_json::json!({"client_certificate_automate": "example.com"}),
                "TLS-UPSTREAM-CLIENT-CERT",
            ),
            (
                serde_json::json!({"curves": ["X25519"]}),
                "TLS-UPSTREAM-CURVES",
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
    fn parses_except_ports() {
        let tls = UpstreamTls::from_json(
            &serde_json::json!({
                "insecure_skip_verify": true,
                "except_ports": ["8080", "9000"]
            }),
            "transport.tls",
        )
        .unwrap();
        assert_eq!(tls.except_ports(), &[8080, 9000]);
        assert!(!tls.should_use_tls(Some(8080)));
        assert!(tls.should_use_tls(Some(8443)));
        assert!(tls.should_use_tls(None));

        let error = UpstreamTls::from_json(
            &serde_json::json!({"except_ports": ["http"]}),
            "transport.tls",
        )
        .expect_err("non-numeric except_ports entries must fail");
        assert!(
            error.to_string().contains("not a valid TCP port"),
            "{error}"
        );
    }

    #[test]
    fn client_certificate_pair_requires_both_files() {
        let error = UpstreamTls::from_json(
            &serde_json::json!({"client_certificate_file": "/tmp/c.pem"}),
            "transport.tls",
        )
        .expect_err("certificate without key must fail");
        assert!(
            error
                .to_string()
                .contains("without `client_certificate_key_file`"),
            "{error}"
        );
        let error = UpstreamTls::from_json(
            &serde_json::json!({"client_certificate_key_file": "/tmp/k.pem"}),
            "transport.tls",
        )
        .expect_err("key without certificate must fail");
        assert!(
            error
                .to_string()
                .contains("without `client_certificate_file`"),
            "{error}"
        );
        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "client_certificate_file": "/nonexistent/client.pem",
                "client_certificate_key_file": "/nonexistent/client-key.pem"
            }),
            "transport.tls",
        )
        .expect_err("missing client certificate files must fail");
        assert!(
            error
                .to_string()
                .contains("cannot read TLS client certificate"),
            "{error}"
        );
    }

    #[test]
    fn loads_client_certificate_and_key() {
        let directory = tempfile::tempdir().unwrap();
        let cert = write_pem(&directory, "client.pem", CLIENT_CERT);
        let key = write_pem(&directory, "client-key.pem", CLIENT_KEY);
        let tls = UpstreamTls::from_json(
            &serde_json::json!({
                "insecure_skip_verify": true,
                "client_certificate_file": cert.display().to_string(),
                "client_certificate_key_file": key.display().to_string()
            }),
            "transport.tls",
        )
        .unwrap();
        assert_eq!(tls.alpn_protocols(), &[b"http/1.1".to_vec()]);
        assert_eq!(
            tls.client_config().alpn_protocols,
            vec![b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn ca_module_file_and_inline_providers() {
        let directory = tempfile::tempdir().unwrap();
        let ca_file = write_pem(&directory, "ca.pem", LOCALHOST_CERT);
        let file_tls = UpstreamTls::from_json(
            &serde_json::json!({
                "ca": {"provider": "file", "pem_files": [ca_file.display().to_string()]}
            }),
            "transport.tls",
        )
        .unwrap();
        assert!(!file_tls.insecure_skip_verify());

        let der = parse_pem_certificates(LOCALHOST_CERT.as_bytes())
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        UpstreamTls::from_json(
            &serde_json::json!({
                "ca": {"provider": "inline", "trusted_ca_certs": [encoded]}
            }),
            "transport.tls",
        )
        .unwrap();
    }

    #[test]
    fn ca_module_combined_provider_merges_sources() {
        let directory = tempfile::tempdir().unwrap();
        let ca_file = write_pem(&directory, "ca.pem", LOCALHOST_CERT);
        let der = parse_pem_certificates(UNRELATED_CERT.as_bytes())
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        UpstreamTls::from_json(
            &serde_json::json!({
                "ca": {
                    "provider": "combined",
                    "sources": [
                        {"provider": "file", "pem_files": [ca_file.display().to_string()]},
                        {"provider": "inline", "trusted_ca_certs": [encoded]}
                    ]
                }
            }),
            "transport.tls",
        )
        .unwrap();
        // `system` cannot be a combined source (Caddy's SystemCAPool exposes no certificates).
        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "ca": {"provider": "combined", "sources": [{"provider": "system"}]}
            }),
            "transport.tls",
        )
        .expect_err("system cannot be combined");
        assert!(
            error.to_string().contains("cannot include `system`"),
            "{error}"
        );
    }

    #[test]
    fn ca_module_system_provider_uses_platform_roots() {
        // Caddy `tls.ca_pool.source.system`: same platform trust store as the default policy.
        // Either a platform bundle loads or the loud missing-roots error fires; silently trusting
        // nothing is not acceptable.
        match UpstreamTls::from_json(
            &serde_json::json!({"ca": {"provider": "system"}}),
            "transport.tls",
        ) {
            Ok(tls) => assert!(!tls.insecure_skip_verify()),
            Err(error) => assert!(error.to_string().contains("no TLS trust roots"), "{error}"),
        }
    }

    #[test]
    fn ca_module_unknown_provider_and_conflicts_fail_loudly() {
        let error = UpstreamTls::from_json(
            &serde_json::json!({"ca": {"provider": "magic"}}),
            "transport.tls",
        )
        .expect_err("unknown CA provider must fail");
        let message = error.to_string();
        assert!(message.contains("magic"), "{message}");
        assert!(message.contains("TLS-UPSTREAM-CA-MODULE"), "{message}");

        let directory = tempfile::tempdir().unwrap();
        let ca_file = write_pem(&directory, "ca.pem", LOCALHOST_CERT);
        let error = UpstreamTls::from_json(
            &serde_json::json!({
                "ca": {"provider": "file", "pem_files": [ca_file.display().to_string()]},
                "root_ca_pem_files": [ca_file.display().to_string()]
            }),
            "transport.tls",
        )
        .expect_err("ca module conflicts with deprecated roots");
        assert!(
            error
                .to_string()
                .contains("conflicting config for Root CA pool"),
            "{error}"
        );
    }

    #[test]
    fn client_ca_fixture_chains_from_client_ca() {
        // Sanity: the mTLS fixtures are internally consistent (client cert signed by client CA).
        let ca = parse_pem_certificates(CLIENT_CA.as_bytes()).unwrap();
        let client = parse_pem_certificates(CLIENT_CERT.as_bytes()).unwrap();
        assert_eq!(ca.len(), 1);
        assert_eq!(client.len(), 1);
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
