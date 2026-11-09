//! Production ACME HTTP transport (hyper + rustls).
//!
//! [`AcmeTransport`](super::AcmeTransport) is deliberately an HTTP-message-level trait so ACME
//! protocol logic can be tested with a scripted mock (see `super::tests` and
//! [`order`](super::order) tests). This module supplies the production implementation:
//!
//! * `http://` and `https://` via hyper 1.x's legacy client and `hyper-rustls`;
//! * rustls with the aws-lc-rs provider (the same provider as the server terminator), so
//!   ECDSA P-521 certificates and account keys use one consistent crypto stack;
//! * trust roots loaded from the platform CA bundle (best effort: the usual Linux locations),
//!   or supplied explicitly for tests and private ACME CAs.
//!
//! Network access only happens when a request is made; constructing a transport reads CA
//! certificates from disk but never contacts the network.

use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use super::{AcmeError, AcmeTransport, HttpMethod, HttpRequest, HttpResponse};
use crate::{Error, Result};

/// User agent sent on every ACME request (mirrors certmagic's practice of identifying the client).
pub const DEFAULT_USER_AGENT: &str = concat!("caddy-rs/", env!("CARGO_PKG_VERSION"));

/// Conventional system CA bundle locations, tried in order.
pub const SYSTEM_CA_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ssl/cert.pem",                  // Alpine/macOS
    "/etc/ssl/certs/ca-bundle.crt",       // older Linux
];

type HyperClient =
    Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Full<Bytes>>;
type ProxyClient = Client<ProxyConnector, Full<Bytes>>;

#[derive(Clone)]
enum ClientKind {
    Direct(HyperClient),
    Proxied(ProxyClient),
}

/// Production [`AcmeTransport`] backed by hyper and rustls.
///
/// Supports HTTP/2 via ALPN (hyper-rustls negotiates the highest configured version), Caddy's
/// `acme_timeout` (applied per request) and `network_proxy` (a forward HTTP proxy: HTTPS targets
/// are tunnelled with `CONNECT` and then TLS-upgraded; Caddy's `caddy.network_proxy.url` module).
pub struct HyperTransport {
    client: ClientKind,
    user_agent: String,
    roots: Vec<CertificateDer<'static>>,
    timeout: Option<Duration>,
    proxy: Option<String>,
}

impl std::fmt::Debug for HyperTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HyperTransport")
            .field("user_agent", &self.user_agent)
            .field("has_trusted_roots", &!self.roots.is_empty())
            .field("timeout", &self.timeout)
            .field("network_proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

impl Clone for HyperTransport {
    fn clone(&self) -> Self {
        Self::from_parts(
            self.roots.clone(),
            self.timeout,
            self.proxy.clone(),
            self.user_agent.clone(),
        )
        .expect("cloning a configured HyperTransport cannot fail")
    }
}

impl HyperTransport {
    /// Create a transport that trusts the platform CA bundle.
    pub fn new() -> Result<Self> {
        Self::with_root_certificates(load_system_root_certificates()?)
    }

    /// Create a transport with explicit trust roots.
    ///
    /// This is the entry point for tests, private CAs configured through
    /// `trusted_roots_pem_files`, and environments without a detectable system bundle.
    pub fn with_root_certificates(roots: Vec<CertificateDer<'static>>) -> Result<Self> {
        Self::from_parts(roots, None, None, DEFAULT_USER_AGENT.to_string())
    }

    fn from_parts(
        roots: Vec<CertificateDer<'static>>,
        timeout: Option<Duration>,
        proxy: Option<String>,
        user_agent: String,
    ) -> Result<Self> {
        if roots.is_empty() {
            return Err(AcmeError::Transport {
                url: "https://".to_string(),
                reason: "no trust roots configured for the ACME HTTP transport".to_string(),
            }
            .into());
        }
        let tls = Arc::new(client_config(&roots, false)?);
        let client = match &proxy {
            Some(proxy) => {
                let proxy_tls = Arc::new(client_config(&roots, true)?);
                let connector = ProxyConnector::parse(proxy, proxy_tls)?;
                ClientKind::Proxied(Client::builder(TokioExecutor::new()).build(connector))
            }
            None => {
                let connector = HttpsConnectorBuilder::new()
                    .with_tls_config((*tls).clone())
                    .https_or_http()
                    .enable_http1()
                    .enable_http2()
                    .build();
                ClientKind::Direct(Client::builder(TokioExecutor::new()).build(connector))
            }
        };
        Ok(Self {
            client,
            user_agent,
            roots,
            timeout,
            proxy,
        })
    }

    /// Create a transport from a PEM bundle file.
    pub fn with_root_certificates_pem_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::with_root_certificates(read_root_certificates_pem_file(path)?)
    }

    /// Create a transport from several PEM bundle files (Caddy's `trusted_roots_pem_files`).
    ///
    /// The configured roots replace the platform trust store entirely, matching certmagic.
    pub fn with_root_certificates_pem_files(paths: &[PathBuf]) -> Result<Self> {
        Self::with_root_certificates(read_root_certificates_pem_files(paths)?)
    }

    /// Override the `User-Agent` header sent with every request.
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// The `User-Agent` header value this transport sends.
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Apply Caddy's `acme_timeout` per ACME HTTP request.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Route ACME HTTP requests through an `http://` forward proxy (Caddy `network_proxy`).
    pub fn with_proxy(self, proxy: impl Into<String>) -> Result<Self> {
        let proxy = proxy.into();
        Self::from_parts(
            self.roots.clone(),
            self.timeout,
            Some(proxy),
            self.user_agent.clone(),
        )
    }
}

fn client_config(roots: &[CertificateDer<'static>], set_alpn: bool) -> Result<ClientConfig> {
    let mut store = RootCertStore::empty();
    for certificate in roots {
        store
            .add(certificate.clone())
            .map_err(|error| AcmeError::Transport {
                url: "https://".to_string(),
                reason: format!("invalid trust root: {error}"),
            })?;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| AcmeError::Transport {
            url: "https://".to_string(),
            reason: format!("rustls protocol configuration failed: {error}"),
        })?
        .with_root_certificates(store)
        .with_no_client_auth();
    if set_alpn {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    Ok(config)
}

// ---- network_proxy (Caddy caddy.network_proxy.url) ------------------------------------------

type BoxError = Box<dyn std::error::Error + Send + Sync>;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

struct ProxyIo {
    inner: TokioIo<Box<dyn AsyncReadWrite>>,
    http2: bool,
}

impl hyper::rt::Read for ProxyIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for ProxyIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connection for ProxyIo {
    fn connected(&self) -> Connected {
        if self.http2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}

#[derive(Clone)]
struct ProxyConnector {
    host: String,
    port: u16,
    tls: Arc<ClientConfig>,
}

impl ProxyConnector {
    fn parse(url: &str, tls: Arc<ClientConfig>) -> Result<Self> {
        let rest = url.strip_prefix("http://").ok_or_else(|| AcmeError::Transport {
            url: url.to_string(),
            reason: "network_proxy must be an `http://host:port` URL (https/socks proxies are not implemented)"
                .to_string(),
        })?;
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port = port.parse::<u16>().map_err(|_| AcmeError::Transport {
                    url: url.to_string(),
                    reason: format!("network_proxy has an invalid port `{port}`"),
                })?;
                (host.to_string(), port)
            }
            None => (authority.to_string(), 80),
        };
        if host.is_empty() {
            return Err(AcmeError::Transport {
                url: url.to_string(),
                reason: "network_proxy URL is missing a host".to_string(),
            }
            .into());
        }
        Ok(Self { host, port, tls })
    }
}

impl Service<hyper::Uri> for ProxyConnector {
    type Response = ProxyIo;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<ProxyIo, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: hyper::Uri) -> Self::Future {
        let host = self.host.clone();
        let port = self.port;
        let tls = Arc::clone(&self.tls);
        Box::pin(async move {
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            let target_host = uri
                .host()
                .ok_or("proxy request URI has no host")?
                .to_string();
            let target_port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });
            let authority = format!("{target_host}:{target_port}");
            stream
                .write_all(
                    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
                )
                .await?;
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                stream.read_exact(&mut byte).await?;
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
                if head.len() > 16 * 1024 {
                    return Err("proxy CONNECT response header too large".into());
                }
            }
            let head_text = String::from_utf8_lossy(&head);
            let status = head_text
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|status| status.parse::<u16>().ok())
                .unwrap_or(0);
            if status != 200 {
                return Err(format!("proxy CONNECT failed with status {status}").into());
            }
            if uri.scheme_str() == Some("https") {
                let server_name = ServerName::try_from(target_host)?;
                let stream = TlsConnector::from(tls).connect(server_name, stream).await?;
                let http2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                Ok(ProxyIo {
                    inner: TokioIo::new(Box::new(stream) as Box<dyn AsyncReadWrite>),
                    http2,
                })
            } else {
                Ok(ProxyIo {
                    inner: TokioIo::new(Box::new(stream) as Box<dyn AsyncReadWrite>),
                    http2: false,
                })
            }
        })
    }
}

#[async_trait]
impl AcmeTransport for HyperTransport {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
        match self.timeout {
            None => self.perform(request).await,
            Some(timeout) => {
                let url = request.url.clone();
                tokio::time::timeout(timeout, self.perform(request))
                    .await
                    .map_err(|_| {
                        crate::Error::Acme(Box::new(AcmeError::Transport {
                            url,
                            reason: format!(
                                "ACME request timed out after {}ms (acme_timeout)",
                                timeout.as_millis()
                            ),
                        }))
                    })?
            }
        }
    }

    fn with_trusted_roots(
        &self,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<Arc<dyn AcmeTransport>> {
        Ok(Arc::new(Self::from_parts(
            roots,
            self.timeout,
            self.proxy.clone(),
            self.user_agent.clone(),
        )?))
    }

    fn with_network_proxy(&self, proxy: &str) -> Result<Arc<dyn AcmeTransport>> {
        Ok(Arc::new(Self::from_parts(
            self.roots.clone(),
            self.timeout,
            Some(proxy.to_string()),
            self.user_agent.clone(),
        )?))
    }

    fn with_request_timeout(&self, timeout: Duration) -> Result<Arc<dyn AcmeTransport>> {
        Ok(Arc::new(Self::from_parts(
            self.roots.clone(),
            Some(timeout),
            self.proxy.clone(),
            self.user_agent.clone(),
        )?))
    }
}

impl HyperTransport {
    async fn perform(&self, request: HttpRequest) -> Result<HttpResponse> {
        let url = request.url.clone();
        let uri: hyper::Uri = url.parse().map_err(|error| AcmeError::Transport {
            url: url.clone(),
            reason: format!("invalid URL: {error}"),
        })?;
        let method = match request.method {
            HttpMethod::Get => hyper::Method::GET,
            HttpMethod::Head => hyper::Method::HEAD,
            HttpMethod::Post => hyper::Method::POST,
            HttpMethod::Delete => hyper::Method::DELETE,
            HttpMethod::Put => hyper::Method::PUT,
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(hyper::header::USER_AGENT, self.user_agent.as_str());
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let hyper_request =
            builder
                .body(Full::new(Bytes::from(request.body)))
                .map_err(|error| AcmeError::Transport {
                    url: url.clone(),
                    reason: format!("cannot build request: {error}"),
                })?;

        let response = match &self.client {
            ClientKind::Direct(client) => client.request(hyper_request).await,
            ClientKind::Proxied(client) => client.request(hyper_request).await,
        }
        .map_err(|error| AcmeError::Transport {
            url: url.clone(),
            reason: describe_error(&error),
        })?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| AcmeError::Transport {
                url: url.clone(),
                reason: format!("cannot read response body: {error}"),
            })?
            .to_bytes()
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// ACME transport for a generation whose automation policies are all internal.
///
/// No network ACME request is possible in that case; any request fails loudly instead of silently
/// falling back to the platform transport. Used by automatic HTTPS when a config only manages
/// local names (for example `localhost`) and no ACME issuer is configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAcmeTransport;

#[async_trait]
impl AcmeTransport for NoAcmeTransport {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
        Err(AcmeError::Transport {
            url: request.url,
            reason:
                "automatic HTTPS generation has no ACME issuer; refusing a network ACME request"
                    .to_string(),
        }
        .into())
    }
}

/// Load trust roots from the platform CA bundle.
///
/// Tries [`SYSTEM_CA_BUNDLES`] in order. Returns a located error when no bundle is found so an
/// operator learns why HTTPS ACME cannot work instead of seeing an empty trust store.
pub fn load_system_root_certificates() -> Result<Vec<CertificateDer<'static>>> {
    let mut tried = Vec::new();
    for path in SYSTEM_CA_BUNDLES {
        match fs::read(path) {
            Ok(bytes) => {
                let certificates =
                    parse_pem_certificates(&bytes).map_err(|error| AcmeError::Transport {
                        url: "https://".to_string(),
                        reason: format!("cannot parse CA bundle `{path}`: {error}"),
                    })?;
                if certificates.is_empty() {
                    tried.push(format!("{path} (no certificates)"));
                    continue;
                }
                return Ok(certificates);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tried.push(format!("{path} (missing)"));
            }
            Err(error) => {
                return Err(AcmeError::Transport {
                    url: "https://".to_string(),
                    reason: format!("cannot read CA bundle `{path}`: {error}"),
                }
                .into())
            }
        }
    }
    Err(AcmeError::Transport {
        url: "https://".to_string(),
        reason: format!(
            "no system CA bundle found (tried: {}); configure explicit trust roots for the ACME transport",
            tried.join(", ")
        ),
    }
    .into())
}

/// Read and parse a PEM file into DER certificates.
pub fn read_root_certificates_pem_file(
    path: impl AsRef<Path>,
) -> Result<Vec<CertificateDer<'static>>> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| AcmeError::Transport {
        url: "https://".to_string(),
        reason: format!("cannot read trust roots `{}`: {error}", path.display()),
    })?;
    parse_pem_certificates(&bytes).map_err(|error| {
        AcmeError::Transport {
            url: "https://".to_string(),
            reason: format!("cannot parse trust roots `{}`: {error}", path.display()),
        }
        .into()
    })
}

/// Read and parse several PEM bundle files into one trust-root set.
///
/// Used by Caddy's `trusted_roots_pem_files` / `acme_ca_root`. Every path is read and parsed
/// eagerly: a missing, unreadable, empty or malformed file is a located error, never a reason to
/// fall back to the platform bundle. Calling this with no paths is also an error; callers that
/// want platform roots must ask for them explicitly.
pub fn read_root_certificates_pem_files(paths: &[PathBuf]) -> Result<Vec<CertificateDer<'static>>> {
    if paths.is_empty() {
        return Err(AcmeError::Transport {
            url: "https://".to_string(),
            reason: "no trusted root PEM files configured for the ACME HTTP transport".to_string(),
        }
        .into());
    }
    let mut roots = Vec::new();
    for path in paths {
        let certificates = read_root_certificates_pem_file(path)?;
        if certificates.is_empty() {
            return Err(AcmeError::Transport {
                url: "https://".to_string(),
                reason: format!(
                    "trusted roots file `{}` contains no CERTIFICATE blocks",
                    path.display()
                ),
            }
            .into());
        }
        roots.extend(certificates);
    }
    Ok(roots)
}

/// Parse all `CERTIFICATE` blocks in a PEM document into DER certificates.
pub fn parse_pem_certificates(
    pem: &[u8],
) -> std::result::Result<Vec<CertificateDer<'static>>, String> {
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
                return Err("CERTIFICATE END without BEGIN".to_string());
            };
            if body.is_empty() {
                return Err("empty CERTIFICATE block".to_string());
            }
            let der = STANDARD
                .decode(body.as_bytes())
                .map_err(|error| format!("CERTIFICATE block is not valid base64: {error}"))?;
            certificates.push(CertificateDer::from(der));
        } else if let Some(body) = current.as_mut() {
            body.extend(line.chars().filter(|character| !character.is_whitespace()));
        }
    }
    if current.is_some() {
        return Err("unterminated CERTIFICATE block".to_string());
    }
    Ok(certificates)
}

/// Render an error and its source chain, so transport failures keep the underlying cause (for
/// example a rustls certificate error) instead of hyper's generic "client error (Connect)".
fn describe_error(error: &(dyn std::error::Error + 'static)) -> String {
    let mut description = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        description.push_str(": ");
        description.push_str(&cause.to_string());
        source = cause.source();
    }
    description
}

/// Convenience for tests and unit callers: map any displayable error into a located transport
/// error.
#[allow(dead_code)]
fn transport_error(url: &str, error: impl std::fmt::Display) -> Error {
    AcmeError::Transport {
        url: url.to_string(),
        reason: error.to_string(),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    const TEST_CERT_PEM: &str = include_str!("../../testdata/acme/localhost-cert.pem");
    const TEST_KEY_PEM: &str = include_str!("../../testdata/acme/localhost-key.pem");
    /// An unrelated self-signed certificate used as a non-matching trust root.
    const UNRELATED_CERT_PEM: &str = include_str!("../../testdata/acme/unrelated-cert.pem");

    #[derive(Debug, Clone, Default)]
    struct RecordedRequest {
        method: String,
        uri: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct ScriptedReply {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    type Recorder = Arc<Mutex<Vec<RecordedRequest>>>;
    type Replies = Arc<Mutex<Vec<ScriptedReply>>>;

    async fn reply_service(
        request: Request<hyper::body::Incoming>,
        replies: Replies,
        recorder: Recorder,
    ) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
        let (parts, body) = request.into_parts();
        let body = body.collect().await.map(|collected| collected.to_bytes());
        let body = body.unwrap_or_default();
        recorder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(RecordedRequest {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.to_string(),
                            value.to_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect(),
                body: body.to_vec(),
            });
        let reply = replies
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop()
            .unwrap_or(ScriptedReply {
                status: 404,
                headers: Vec::new(),
                body: b"no scripted reply".to_vec(),
            });
        let mut response = Response::builder().status(StatusCode::from_u16(reply.status).unwrap());
        for (name, value) in &reply.headers {
            response = response.header(name.as_str(), value.as_str());
        }
        Ok(response.body(Full::new(Bytes::from(reply.body))).unwrap())
    }

    /// Serve plain HTTP on 127.0.0.1 and return the bound port.
    fn spawn_http_server(replies: Replies, recorder: Recorder) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let listener = TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let replies = replies.clone();
                let recorder = recorder.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        reply_service(request, replies.clone(), recorder.clone())
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        port
    }

    /// Serve HTTPS on 127.0.0.1 with the embedded self-signed test certificate.
    fn spawn_https_server(
        replies: Replies,
        recorder: Recorder,
    ) -> (u16, Vec<CertificateDer<'static>>, Arc<Mutex<Vec<String>>>) {
        let server_errors: Arc<Mutex<Vec<String>>> = Arc::default();
        let certificates = parse_pem_certificates(TEST_CERT_PEM.as_bytes()).unwrap();
        assert_eq!(
            certificates.len(),
            1,
            "test fixture must hold one certificate"
        );
        let key = pem_block_der(TEST_KEY_PEM, "PRIVATE KEY");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                certificates.clone(),
                rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let errors = server_errors.clone();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let listener = TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let replies = replies.clone();
                let recorder = recorder.clone();
                let errors = errors.clone();
                tokio::spawn(async move {
                    let stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            errors
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .push(format!("tls accept: {error}"));
                            return;
                        }
                    };
                    let service = service_fn(move |request| {
                        reply_service(request, replies.clone(), recorder.clone())
                    });
                    if let Err(error) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        errors
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(format!("serve connection: {error}"));
                    }
                });
            }
        });
        (port, certificates, server_errors)
    }

    fn pem_block_der(pem: &str, label: &str) -> Vec<u8> {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let mut inside = false;
        let mut base64 = String::new();
        for line in pem.lines() {
            let line = line.trim();
            if line == begin {
                inside = true;
            } else if line == end {
                inside = false;
            } else if inside {
                base64.push_str(line);
            }
        }
        STANDARD.decode(base64.as_bytes()).unwrap()
    }

    fn replay(replies: &Replies, reply: ScriptedReply) {
        replies
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(0, reply);
    }

    #[test]
    fn parses_certificate_pem_bundle_and_reports_errors() {
        let certificates = parse_pem_certificates(TEST_CERT_PEM.as_bytes()).unwrap();
        assert_eq!(certificates.len(), 1);
        assert!(parse_pem_certificates(b"not a pem").unwrap().is_empty());
        let error = parse_pem_certificates(b"-----BEGIN CERTIFICATE-----\nAAAA\n").unwrap_err();
        assert!(error.contains("unterminated"), "{error}");
        let error = parse_pem_certificates(
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap_err();
        assert!(error.contains("base64"), "{error}");
    }

    #[tokio::test]
    async fn http_transport_performs_get_and_returns_headers_and_body() {
        let replies = Replies::default();
        let recorder = Recorder::default();
        let port = spawn_http_server(replies.clone(), recorder.clone());
        replay(
            &replies,
            ScriptedReply {
                status: 200,
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("Replay-Nonce".to_string(), "nonce-1".to_string()),
                ],
                body: b"{\"ok\":true}".to_vec(),
            },
        );
        let transport = HyperTransport::new().unwrap_or_else(|_| {
            // Environments without a system CA bundle can still exercise plain HTTP, but the
            // constructor requires roots; fall back to the embedded test certificate.
            HyperTransport::with_root_certificates(
                parse_pem_certificates(TEST_CERT_PEM.as_bytes()).unwrap(),
            )
            .unwrap()
        });
        assert_eq!(transport.user_agent(), DEFAULT_USER_AGENT);
        let url = format!("http://127.0.0.1:{port}/directory");
        let response = transport.request(HttpRequest::get(&url)).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.header("content-type"), Some("application/json"));
        assert_eq!(response.replay_nonce(), Some("nonce-1"));
        assert_eq!(response.body, b"{\"ok\":true}");
        let recorded = recorder.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, "GET");
        assert_eq!(recorded[0].uri, "/directory");
        let user_agent = recorded[0]
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .map(|(_, value)| value.as_str());
        assert_eq!(user_agent, Some(DEFAULT_USER_AGENT));
    }

    #[tokio::test]
    async fn http_transport_posts_body_and_extra_headers() {
        let replies = Replies::default();
        let recorder = Recorder::default();
        let port = spawn_http_server(replies.clone(), recorder.clone());
        replay(
            &replies,
            ScriptedReply {
                status: 201,
                headers: vec![(
                    "Location".to_string(),
                    "https://ca.test/order/1".to_string(),
                )],
                body: b"{}".to_vec(),
            },
        );
        let transport = HyperTransport::with_root_certificates(
            parse_pem_certificates(TEST_CERT_PEM.as_bytes()).unwrap(),
        )
        .unwrap();
        let url = format!("http://127.0.0.1:{port}/order");
        let request = HttpRequest::post_jose(&url, b"jws-body".to_vec())
            .with_header("Accept", "application/pem-certificate-chain");
        let response = transport.request(request).await.unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(response.location(), Some("https://ca.test/order/1"));
        let recorded = recorder.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, "POST");
        assert_eq!(recorded[0].body, b"jws-body");
        let header = |name: &str| {
            recorded[0]
                .headers
                .iter()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(header("content-type"), Some("application/jose+json"));
        assert_eq!(header("accept"), Some("application/pem-certificate-chain"));
    }

    #[tokio::test]
    async fn https_transport_handshakes_with_explicit_trust_root() {
        let replies = Replies::default();
        let recorder = Recorder::default();
        let (port, roots, server_errors) = spawn_https_server(replies.clone(), recorder.clone());
        replay(
            &replies,
            ScriptedReply {
                status: 200,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: b"{\"secure\":true}".to_vec(),
            },
        );
        let transport = HyperTransport::with_root_certificates(roots).unwrap();
        let url = format!("https://127.0.0.1:{port}/secure");
        let response = match transport.request(HttpRequest::get(&url)).await {
            Ok(response) => response,
            Err(error) => panic!(
                "https request failed: {error}; server errors: {:?}",
                server_errors
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            ),
        };
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"secure\":true}");
        assert_eq!(recorder.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn https_transport_rejects_untrusted_certificate() {
        let replies = Replies::default();
        let recorder = Recorder::default();
        let (port, _roots, _server_errors) = spawn_https_server(replies, recorder);
        // Trust only an unrelated root: the server's certificate must be rejected by the client.
        let other_root = parse_pem_certificates(UNRELATED_CERT_PEM.as_bytes()).unwrap();
        let transport = HyperTransport::with_root_certificates(other_root).unwrap();
        let url = format!("https://127.0.0.1:{port}/secure");
        let error = transport.request(HttpRequest::get(&url)).await.unwrap_err();
        let message = error.to_string();
        assert!(message.contains("transport"), "{message}");
        assert!(message.contains(&url), "{message}");
        assert!(
            message.contains("invalid peer certificate") || message.contains("UnknownIssuer"),
            "expected a certificate verification failure, got: {message}"
        );
    }

    #[tokio::test]
    async fn reports_http_error_status_without_transport_failure() {
        let replies = Replies::default();
        let recorder = Recorder::default();
        let port = spawn_http_server(replies.clone(), recorder);
        replay(
            &replies,
            ScriptedReply {
                status: 500,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                body: b"server on fire".to_vec(),
            },
        );
        let transport = HyperTransport::with_root_certificates(
            parse_pem_certificates(TEST_CERT_PEM.as_bytes()).unwrap(),
        )
        .unwrap();
        let url = format!("http://127.0.0.1:{port}/directory");
        let response = transport.request(HttpRequest::get(&url)).await.unwrap();
        assert_eq!(response.status, 500);
        assert_eq!(response.body_text(), "server on fire");
    }

    #[test]
    fn rejects_empty_trust_root_set() {
        let error = HyperTransport::with_root_certificates(Vec::new()).unwrap_err();
        assert!(error.to_string().contains("no trust roots"), "{error}");
    }

    #[test]
    fn transport_error_helper_is_located() {
        let error = transport_error("https://ca.test/dir", "boom");
        assert!(error.to_string().contains("https://ca.test/dir"));
        assert!(error.to_string().contains("boom"));
    }

    #[test]
    fn reads_multiple_trust_root_pem_files_and_rejects_bad_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.pem");
        let second = directory.path().join("second.pem");
        std::fs::write(&first, TEST_CERT_PEM).unwrap();
        std::fs::write(&second, UNRELATED_CERT_PEM).unwrap();
        let roots = read_root_certificates_pem_files(&[first, second]).unwrap();
        assert_eq!(roots.len(), 2);

        let error = read_root_certificates_pem_files(&[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("no trusted root PEM files"), "{error}");

        let missing = directory.path().join("missing.pem");
        let error = read_root_certificates_pem_files(&[missing.clone()])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(missing.to_string_lossy().as_ref()),
            "error should name the missing file: {error}"
        );
        assert!(error.contains("cannot read"), "{error}");

        let empty = directory.path().join("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        let error = read_root_certificates_pem_files(&[empty])
            .unwrap_err()
            .to_string();
        assert!(error.contains("no CERTIFICATE blocks"), "{error}");

        let invalid = directory.path().join("invalid.pem");
        std::fs::write(&invalid, b"not a pem").unwrap();
        let error = read_root_certificates_pem_files(&[invalid])
            .unwrap_err()
            .to_string();
        assert!(error.contains("no CERTIFICATE blocks"), "{error}");
    }

    #[tokio::test]
    async fn transport_built_from_pem_root_files_verifies_local_tls_server() {
        let replies = Replies::default();
        let recorder = Recorder::default();
        let (port, _roots, _server_errors) = spawn_https_server(replies.clone(), recorder);
        replay(
            &replies,
            ScriptedReply {
                status: 200,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: b"{\"rooted\":true}".to_vec(),
            },
        );
        let directory = tempfile::tempdir().unwrap();
        let root_file = directory.path().join("root.pem");
        std::fs::write(&root_file, TEST_CERT_PEM).unwrap();
        let transport = HyperTransport::with_root_certificates_pem_files(&[root_file])
            .expect("rooted transport");
        let url = format!("https://127.0.0.1:{port}/secure");
        let response = transport.request(HttpRequest::get(&url)).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"rooted\":true}");
    }

    #[tokio::test]
    async fn with_trusted_roots_replaces_existing_platform_roots() {
        let replies = Replies::default();
        let recorder = Recorder::default();
        let (port, server_roots, _server_errors) = spawn_https_server(replies.clone(), recorder);
        replay(
            &replies,
            ScriptedReply {
                status: 200,
                headers: Vec::new(),
                body: b"{\"secure\":true}".to_vec(),
            },
        );
        // Start from an unrelated root: only the explicit roots can make the request succeed.
        let base = HyperTransport::with_root_certificates(
            parse_pem_certificates(UNRELATED_CERT_PEM.as_bytes()).unwrap(),
        )
        .unwrap();
        let rooted = base
            .with_trusted_roots(server_roots)
            .expect("transport supports explicit roots");
        let url = format!("https://127.0.0.1:{port}/secure");
        let response = rooted.request(HttpRequest::get(&url)).await.unwrap();
        assert_eq!(response.status, 200);
    }

    #[test]
    fn transport_without_root_support_fails_loudly() {
        struct UnconfigurableTransport;

        #[async_trait]
        impl AcmeTransport for UnconfigurableTransport {
            async fn request(&self, _request: HttpRequest) -> Result<HttpResponse> {
                Err(Error::Issuer("unused test transport".to_string()))
            }
        }

        let roots = parse_pem_certificates(TEST_CERT_PEM.as_bytes()).unwrap();
        let error = match UnconfigurableTransport.with_trusted_roots(roots) {
            Ok(_) => panic!("transport unexpectedly accepted explicit trusted roots"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("does not support explicit trusted roots"),
            "expected a loud unsupported-transport error, got: {error}"
        );
    }

    /// Serve HTTPS with ALPN forced to `h2` and a hyper HTTP/2 server.
    fn spawn_h2_server(
        replies: Replies,
        recorder: Recorder,
    ) -> (u16, Vec<CertificateDer<'static>>) {
        let certificates = parse_pem_certificates(TEST_CERT_PEM.as_bytes()).unwrap();
        let key = pem_block_der(TEST_KEY_PEM, "PRIVATE KEY");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                certificates.clone(),
                rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
            )
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let listener = TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let replies = replies.clone();
                let recorder = recorder.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request| {
                        reply_service(request, replies.clone(), recorder.clone())
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        (port, certificates)
    }

    #[tokio::test]
    async fn negotiates_http2_via_alpn() {
        let replies: Replies = Arc::default();
        let recorder: Recorder = Arc::default();
        let (port, roots) = spawn_h2_server(replies.clone(), recorder.clone());
        replay(
            &replies,
            ScriptedReply {
                status: 200,
                headers: Vec::new(),
                body: b"h2-ok".to_vec(),
            },
        );
        let transport = HyperTransport::with_root_certificates(roots).unwrap();
        // The local server only serves HTTP/2 (ALPN h2), so a successful request proves the
        // transport negotiated HTTP/2.
        let response = transport
            .request(HttpRequest::get(format!(
                "https://127.0.0.1:{port}/directory"
            )))
            .await
            .expect("HTTP/2 request through ALPN");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"h2-ok");
        // `hyper::server` lowercases the HTTP/2 pseudo-headers into `:path`; the recorded URI
        // still carries the path.
        assert_eq!(recorder.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn network_proxy_tunnels_every_https_request() {
        let replies: Replies = Arc::default();
        let recorder: Recorder = Arc::default();
        let (origin_port, roots) = spawn_h2_server(replies.clone(), recorder.clone());
        for _ in 0..4 {
            replay(
                &replies,
                ScriptedReply {
                    status: 200,
                    headers: Vec::new(),
                    body: b"via-proxy".to_vec(),
                },
            );
        }

        // A minimal CONNECT proxy that records the tunnel target and pipes bytes to the origin.
        let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        proxy_listener.set_nonblocking(true).unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let proxy_listener = TcpListener::from_std(proxy_listener).unwrap();
        let connects: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen = Arc::clone(&connects);
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = proxy_listener.accept().await else {
                    break;
                };
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if client.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&head);
                    let authority = head
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("")
                        .to_string();
                    seen.lock().unwrap().push(authority.clone());
                    let mut origin = match TcpStream::connect(authority.as_str()).await {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                    let _ = client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut origin).await;
                });
            }
        });

        let transport = HyperTransport::with_root_certificates(roots)
            .unwrap()
            .with_proxy(format!("http://127.0.0.1:{proxy_port}"))
            .unwrap();
        for path in ["/directory", "/new-nonce", "/order/1", "/cert/1"] {
            let response = transport
                .request(HttpRequest::get(format!(
                    "https://127.0.0.1:{origin_port}{path}"
                )))
                .await
                .expect("proxied HTTPS ACME request");
            assert_eq!(response.status, 200, "{path}");
        }
        let connects = connects.lock().unwrap();
        assert!(
            !connects.is_empty(),
            "proxied transport must use a proxy tunnel"
        );
        // The hyper client pools the HTTPS connection, so several requests can reuse one CONNECT
        // tunnel; when network_proxy is set there is no direct connector at all.
        assert!(
            connects
                .iter()
                .all(|authority| authority == &format!("127.0.0.1:{origin_port}")),
            "{connects:?}"
        );
        assert!(connects.len() <= 4, "{connects:?}");
    }

    #[tokio::test]
    async fn acme_timeout_bounds_slow_requests() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let listener = TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            let Ok((_stream, _)) = listener.accept().await else {
                return;
            };
            // Never respond: the request must time out.
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let roots = parse_pem_certificates(TEST_CERT_PEM.as_bytes()).unwrap();
        let transport = HyperTransport::with_root_certificates(roots)
            .unwrap()
            .with_timeout(Duration::from_millis(150));
        let started = std::time::Instant::now();
        let error = transport
            .request(HttpRequest::get(format!("http://127.0.0.1:{port}/slow")))
            .await
            .expect_err("slow ACME request must time out");
        assert!(
            error.to_string().contains("timed out"),
            "expected a typed timeout error, got: {error}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout must not hang"
        );
    }
}
