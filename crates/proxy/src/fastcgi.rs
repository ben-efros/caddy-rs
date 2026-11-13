//! Caddy's `http.reverse_proxy.transport.fastcgi` transport.
//!
//! Caddy has no generic fastcgi module: the Caddyfile `php_fastcgi` directive and the
//! `transport fastcgi` block adapt to a `reverse_proxy` handler whose `transport.protocol` is
//! `fastcgi`, with the FastCGI-specific fields at the top level of the transport object:
//!
//! ```json
//! "transport": {
//!   "protocol": "fastcgi",
//!   "root": "/srv/http",
//!   "split_path": [".php"],
//!   "env": {"APP_ENV": "production"},
//!   "resolve_root_symlink": false,
//!   "dial_timeout": 3000000000,
//!   "read_timeout": 0,
//!   "write_timeout": 0,
//!   "capture_stderr": false
//! }
//! ```
//!
//! This module implements the transport: CGI environment construction (matching Caddy's
//! `buildEnv`), the FastCGI record protocol (BEGIN_REQUEST/PARAMS/STDIN/STDOUT/STDERR/
//! END_REQUEST, request id 1, no multiplexing) over TCP or Unix sockets, CGI response header
//! parsing (`Status:`), chunked CGI response decoding, streamed request bodies and a streamed
//! response body.
//!
//! Divergences from Caddy are documented where they occur. `SERVER_PROTOCOL` reflects the
//! negotiated request version, and `HTTPS`/`SSL_PROTOCOL`/`SSL_CIPHER` come from the TLS session
//! metadata threaded through `Request` (`SSL_CIPHER` is omitted when the cipher suite is not known,
//! matching Caddy's lookup loop; HTTP/3 currently exposes the version without a cipher because
//! quinn does not expose the negotiated suite).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use caddy_rs_http::body::{BodyError, RequestBody, StreamingBody};
use caddy_rs_http::{Error as HttpError, Request, Result as HttpResult};

use crate::template::{Template, TemplateContext};
use crate::upstream::{Transport, Upstream};

/// FastCGI protocol version.
const FCGI_VERSION_1: u8 = 1;
/// Record types used by this client.
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
/// `RESPONDER` role.
const FCGI_RESPONDER: u16 = 1;
/// END_REQUEST protocol status: request completed successfully.
const FCGI_REQUEST_COMPLETE: u8 = 0;
/// Record header size.
const FCGI_HEADER_LEN: usize = 8;
/// Maximum record content length used by Caddy's writer for compatibility.
const MAX_WRITE: usize = 65500;
/// Request id used by Caddy (single request per connection, no multiplexing).
const REQUEST_ID: u16 = 1;
/// Caddy's default dial timeout for FastCGI.
const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// FastCGI transport errors.
#[derive(Debug, thiserror::Error)]
pub enum FastCgiError {
    /// Could not establish a connection (retryable like Caddy's `DialError`).
    #[error("dialing FastCGI upstream: {0}")]
    Connect(String),
    /// The backend violated the FastCGI protocol or closed early.
    #[error("FastCGI protocol error: {0}")]
    Protocol(String),
    /// A read/write operation exceeded the configured timeout.
    #[error("FastCGI timeout: {0}")]
    Timeout(String),
    /// The request could not be converted into FastCGI parameters (for example a body of
    /// unknown length, which FastCGI cannot express).
    #[error("invalid FastCGI request: {0}")]
    Request(String),
    /// I/O failure while exchanging records.
    #[error("FastCGI I/O error: {0}")]
    Io(String),
}

impl FastCgiError {
    /// Whether this failure happened before a request could be transmitted (Caddy retries dial
    /// errors for any method).
    pub fn is_connect(&self) -> bool {
        matches!(self, Self::Connect(_))
    }

    /// An HTTP status Caddy would surface for this failure, when it is not a generic 502.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Request(message) if message.contains("CONTENT_LENGTH") => {
                Some(StatusCode::LENGTH_REQUIRED)
            }
            Self::Request(_) => Some(StatusCode::BAD_REQUEST),
            _ => None,
        }
    }
}

/// Parsed `transport.protocol: "fastcgi"` configuration (Caddy `fastcgi.Transport`).
#[derive(Debug)]
pub struct FastCgiTransport {
    /// Root directory (Caddy default `{http.vars.root}`; `"."` when the placeholder is empty).
    root: Template,
    /// Split path suffixes, ASCII-lowercased (Caddy `split_path`; empty means Caddy's index 0).
    split_path: Vec<String>,
    /// Resolve the root through symlinks (`resolve_root_symlink`).
    resolve_root_symlink: bool,
    /// Extra environment variables (values support Caddy placeholders).
    env: Vec<(String, Template)>,
    /// Connection timeout (Caddy default 3s).
    dial_timeout: Duration,
    /// Read deadline for upstream reads (0 = none).
    read_timeout: Duration,
    /// Write deadline for upstream writes (0 = none).
    write_timeout: Duration,
    /// Capture and log FastCGI STDERR output.
    capture_stderr: bool,
    /// `SERVER_SOFTWARE` value for the configured server identity; `None` omits it (T-CONF-060).
    server_software: Option<String>,
}

/// A FastCGI response head plus a streaming body.
pub struct FastCgiResponse {
    /// Response status parsed from the CGI `Status:` header (default 200).
    pub status: StatusCode,
    /// Response headers parsed from the CGI header block (hop-by-hop headers are still present;
    /// the proxy strips them like for HTTP transports).
    pub headers: HeaderMap,
    /// Streamed response body.
    pub body: StreamingBody,
}

impl FastCgiTransport {
    /// Parse a `protocol: "fastcgi"` transport object.
    ///
    /// Caddy's FastCGI transport has no HTTP version/TLS options; any other field (including
    /// `tls`/`versions`, which would silently do nothing) fails loudly rather than being ignored.
    pub fn from_json(value: &Value, path: &str) -> HttpResult<Self> {
        Self::from_json_with_server_software(
            value,
            path,
            Some(format!("caddy-rs/{}", env!("CARGO_PKG_VERSION"))),
        )
    }

    /// Parse a FastCGI transport and use `server_software` for the `SERVER_SOFTWARE` parameter.
    ///
    /// The HTTP server's identity mode is resolved by the server runtime and passed in; `None`
    /// omits the parameter (identity mode `none`, caddy-rs extension T-CONF-060).
    pub fn from_json_with_server_software(
        value: &Value,
        path: &str,
        server_software: Option<String>,
    ) -> HttpResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "`transport` for fastcgi must be an object"))?;
        const SUPPORTED: &[&str] = &[
            "protocol",
            "root",
            "split_path",
            "resolve_root_symlink",
            "env",
            "dial_timeout",
            "read_timeout",
            "write_timeout",
            "capture_stderr",
        ];
        for key in object.keys() {
            if !SUPPORTED.contains(&key.as_str()) {
                return Err(invalid(
                    path,
                    format!("`transport` field `{key}` is not supported by the fastcgi transport"),
                ));
            }
        }

        let root = match object.get("root") {
            None | Some(Value::Null) => Template::parse("{http.vars.root}"),
            Some(value) => Template::parse(
                value
                    .as_str()
                    .ok_or_else(|| invalid(&format!("{path}.root"), "`root` must be a string"))?,
            ),
        };

        let split_path = match object.get("split_path") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => {
                let entries = value.as_array().ok_or_else(|| {
                    invalid(
                        &format!("{path}.split_path"),
                        "`split_path` must be an array of strings",
                    )
                })?;
                let mut paths = Vec::with_capacity(entries.len());
                for (index, entry) in entries.iter().enumerate() {
                    let text = entry.as_str().ok_or_else(|| {
                        invalid(
                            &format!("{path}.split_path[{index}]"),
                            "`split_path` entries must be strings",
                        )
                    })?;
                    if !text.is_ascii() {
                        return Err(invalid(
                            &format!("{path}.split_path[{index}]"),
                            "split path contains non-ASCII characters",
                        ));
                    }
                    paths.push(text.to_ascii_lowercase());
                }
                paths
            }
        };

        let resolve_root_symlink = object
            .get("resolve_root_symlink")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let env = match object.get("env") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => {
                let entries = value.as_object().ok_or_else(|| {
                    invalid(
                        &format!("{path}.env"),
                        "`env` must be an object of string values",
                    )
                })?;
                let mut env = Vec::with_capacity(entries.len());
                for (key, value) in entries {
                    let value = value.as_str().ok_or_else(|| {
                        invalid(
                            &format!("{path}.env.{key}"),
                            "environment values must be strings",
                        )
                    })?;
                    env.push((key.clone(), Template::parse(value)));
                }
                env
            }
        };

        let dial_timeout = match object.get("dial_timeout").and_then(Value::as_u64) {
            Some(nanos) if nanos > 0 => Duration::from_nanos(nanos),
            _ => DEFAULT_DIAL_TIMEOUT,
        };
        let read_timeout = object
            .get("read_timeout")
            .and_then(Value::as_u64)
            .filter(|nanos| *nanos > 0)
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);
        let write_timeout = object
            .get("write_timeout")
            .and_then(Value::as_u64)
            .filter(|nanos| *nanos > 0)
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);
        let capture_stderr = object
            .get("capture_stderr")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        Ok(Self {
            root,
            split_path,
            resolve_root_symlink,
            env,
            dial_timeout,
            read_timeout,
            write_timeout,
            capture_stderr,
            server_software,
        })
    }

    /// FastCGI requires `CONTENT_LENGTH`, so the proxy must buffer the request body before
    /// dispatch (Caddy does the same through `request_buffers` defaults).
    pub fn requires_buffered_request_body(&self) -> bool {
        true
    }

    /// Perform one FastCGI exchange and return the response head with a streaming body.
    ///
    /// `method` and `path_and_query` are the (possibly rewritten) values sent to the backend;
    /// `request` is the original request used for headers, remote address, vars and
    /// `REQUEST_URI`.
    pub async fn forward(
        &self,
        upstream: &Upstream,
        request: &Request,
        method: Method,
        path_and_query: &str,
        body: RequestBody,
    ) -> Result<FastCgiResponse, FastCgiError> {
        let content_length = body.exact_size().ok_or_else(|| {
            FastCgiError::Request(
                "request body has no known length; increase request_buffers so the body can be \
                 buffered in full to determine CONTENT_LENGTH"
                    .to_string(),
            )
        })?;
        let params = self.build_params(request, &method, path_and_query, content_length)?;

        let stream = self.dial(upstream).await?;
        // Caddy sets absolute connection deadlines once, right after dialing: they are not
        // refreshed per read/write, so `read_timeout`/`write_timeout` bound the whole exchange.
        let write_deadline = deadline_after(self.write_timeout);
        let read_deadline = deadline_after(self.read_timeout);
        let (mut reader, mut writer) = tokio::io::split(stream);
        self.write_request(&mut writer, &params, body, write_deadline)
            .await?;

        let header = self.read_response_head(&mut reader, read_deadline).await?;
        let ResponseHead {
            status,
            headers,
            leftover,
            stderr,
        } = header;
        if self.capture_stderr && !stderr.is_empty() {
            log_stderr(&stderr, status);
        }

        // Caddy's `chunked(te)` only inspects the first transfer-coding token.
        let chunked = headers
            .get(http::header::TRANSFER_ENCODING)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .is_some_and(|token| token.trim().eq_ignore_ascii_case("chunked"));
        let content_length = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        let body_allowed = fastcgi_body_allowed(method.as_str(), status);
        let declared = if chunked || !body_allowed {
            None
        } else {
            content_length
        };
        let mut headers = headers;
        if chunked {
            // The decoded body length differs from any CGI Content-Length; drop it so the server
            // never advertises a mismatched length.
            headers.remove(http::header::CONTENT_LENGTH);
        }

        let (sender, receiver) = mpsc::channel(8);
        let capture_stderr = self.capture_stderr;
        tokio::spawn(async move {
            stream_response_body(
                reader,
                leftover,
                chunked,
                sender,
                capture_stderr,
                status,
                body_allowed,
                declared,
                read_deadline,
            )
            .await;
        });

        Ok(FastCgiResponse {
            status,
            headers,
            body: StreamingBody::from_chunks(receiver),
        })
    }

    /// Build the CGI environment (Caddy's `buildEnv`).
    fn build_params(
        &self,
        request: &Request,
        method: &Method,
        path_and_query: &str,
        content_length: u64,
    ) -> Result<BTreeMap<String, String>, FastCgiError> {
        let context = TemplateContext {
            request,
            response_status: None,
            response_headers: None,
            vars: Some(&request.vars),
        };
        let mut root_text = self.root.expand(&context);
        if root_text.is_empty() {
            root_text = ".".to_string();
        }
        let mut root = absolute_path(Path::new(&root_text))
            .map_err(|error| FastCgiError::Request(format!("resolving root: {error}")))?;
        if self.resolve_root_symlink {
            root = std::fs::canonicalize(&root).map_err(|error| {
                FastCgiError::Request(format!(
                    "resolving root symlinks for `{}`: {error}",
                    root.display()
                ))
            })?;
        }
        let root = path_to_string(&root);

        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((path_and_query, ""));
        // Caddy derives the CGI path variables from the decoded, cleaned request path
        // (`NormalizedPath`); a NUL byte anywhere in the path is a 400 before any dialing.
        let fpath = normalized_script_path(path)?;

        // Caddy's `splitPos`: an empty split-path list yields index 0 (whole path is PATH_INFO).
        let split_pos: Option<usize> = cgi_split_pos(&self.split_path, &fpath);
        let (document_uri, mut path_info, mut script_name) = match split_pos {
            Some(pos) => {
                let (document_uri, path_info) = fpath.split_at(pos);
                let script_name = fpath.strip_suffix(path_info).unwrap_or(fpath.as_str());
                (
                    document_uri.to_string(),
                    path_info.to_string(),
                    script_name.to_string(),
                )
            }
            None => (fpath.to_string(), String::new(), fpath.to_string()),
        };
        // Caddy falls back to the file matcher remainder when nothing was split.
        if path_info.is_empty() {
            if let Some(remainder) = request.vars.get("http.matchers.file.remainder") {
                path_info = remainder.clone();
                script_name = fpath
                    .strip_suffix(path_info.as_str())
                    .unwrap_or(fpath.as_str())
                    .to_string();
            }
        }
        let script_filename = sanitized_path_join(&root, &script_name).ok_or_else(|| {
            FastCgiError::Request(format!("SCRIPT_FILENAME escapes root `{}`", root))
        })?;
        let root_path = Path::new(&root);
        let script_path = Path::new(&script_filename);
        if !script_path.starts_with(root_path) {
            return Err(FastCgiError::Request(format!(
                "SCRIPT_FILENAME `{}` escapes root `{}`",
                script_filename, root
            )));
        }
        if !script_name.is_empty() && !script_name.starts_with('/') {
            script_name.insert(0, '/');
        }

        let (host_name, host_port) = split_host_port(request.host().unwrap_or_default());
        let (remote_ip, remote_port) = match request.remote_addr {
            Some(address) => (address.ip().to_string(), address.port().to_string()),
            // Caddy's Unix-socket peer is the literal `"@"`; REMOTE_PORT is empty there.
            None => ("@".to_string(), String::new()),
        };
        let request_scheme = if request.tls { "https" } else { "http" };
        let auth_user = request
            .vars
            .get("http.auth.user.id")
            .cloned()
            .unwrap_or_default();
        let request_uri = request
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_string();

        let mut env: BTreeMap<String, String> = BTreeMap::new();
        env.insert("AUTH_TYPE".to_string(), String::new());
        env.insert("CONTENT_LENGTH".to_string(), content_length.to_string());
        env.insert(
            "CONTENT_TYPE".to_string(),
            request
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string(),
        );
        env.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
        env.insert("PATH_INFO".to_string(), path_info.clone());
        env.insert("QUERY_STRING".to_string(), query.to_string());
        env.insert("REMOTE_ADDR".to_string(), remote_ip.clone());
        env.insert("REMOTE_HOST".to_string(), remote_ip);
        env.insert("REMOTE_PORT".to_string(), remote_port);
        env.insert("REMOTE_IDENT".to_string(), String::new());
        env.insert("REMOTE_USER".to_string(), auth_user);
        env.insert("REQUEST_METHOD".to_string(), method.as_str().to_string());
        env.insert("REQUEST_SCHEME".to_string(), request_scheme.to_string());
        env.insert("SERVER_NAME".to_string(), host_name.clone());
        // Caddy uses `r.Proto` here (caddy-rs carries the negotiated version on Request).
        env.insert(
            "SERVER_PROTOCOL".to_string(),
            match request.version {
                http::Version::HTTP_09 => "HTTP/0.9",
                http::Version::HTTP_10 => "HTTP/1.0",
                http::Version::HTTP_2 => "HTTP/2.0",
                http::Version::HTTP_3 => "HTTP/3.0",
                _ => "HTTP/1.1",
            }
            .to_string(),
        );
        if let Some(software) = &self.server_software {
            env.insert("SERVER_SOFTWARE".to_string(), software.clone());
        }
        env.insert("DOCUMENT_ROOT".to_string(), root.clone());
        env.insert("DOCUMENT_URI".to_string(), document_uri);
        env.insert(
            "HTTP_HOST".to_string(),
            request.host().unwrap_or_default().to_string(),
        );
        env.insert("REQUEST_URI".to_string(), request_uri);
        env.insert("SCRIPT_FILENAME".to_string(), script_filename);
        env.insert("SCRIPT_NAME".to_string(), script_name);

        if !path_info.is_empty() {
            if let Some(path_translated) = sanitized_path_join(&root, &path_info) {
                env.insert("PATH_TRANSLATED".to_string(), path_translated);
            }
        }
        if !host_port.is_empty() {
            env.insert("SERVER_PORT".to_string(), host_port);
        } else if request.tls {
            env.insert("SERVER_PORT".to_string(), "443".to_string());
        } else {
            env.insert("SERVER_PORT".to_string(), "80".to_string());
        }
        if request.tls {
            env.insert("HTTPS".to_string(), "on".to_string());
            // Caddy's `buildEnv` TLS branch (fastcgi.go): SSL_PROTOCOL from the Go
            // `tls.Version*` mapping and SSL_CIPHER from the `tls.CipherSuites()` name (both
            // Apache mod_ssl-compatible). The server threads these through `Request`.
            if let Some(tls) = &request.tls_connection {
                env.insert(
                    "SSL_PROTOCOL".to_string(),
                    tls.version.caddy_name().to_string(),
                );
                if let Some(cipher_suite) = &tls.cipher_suite {
                    env.insert("SSL_CIPHER".to_string(), cipher_suite.clone());
                }
            }
        }
        // Caddy's `SERVER_ADDR` comes from the connection's local address; the server exposes it
        // as request variables until the placeholder set covers local addresses.
        if let Some(local) = request
            .vars
            .get("http.request.local.host")
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        {
            env.insert("SERVER_ADDR".to_string(), local.to_string());
        }

        // HTTP_* from request headers (Caddy skips Host — HTTP_HOST comes from the routed
        // host — and the Proxy header for HTTPoxy mitigation).
        for (name, _) in request.headers.iter() {
            if name.as_str() == "proxy" || name.as_str() == "host" {
                continue;
            }
            let env_name = format!(
                "HTTP_{}",
                name.as_str().to_ascii_uppercase().replace('-', "_")
            );
            let mut values = Vec::new();
            for value in request.headers.get_all(name) {
                values.push(value.to_str().unwrap_or_default());
            }
            env.insert(env_name, values.join(", "));
        }

        // Configured env vars are added last (Caddy: "so a client header cannot override an
        // HTTP_* variable set by the operator"); placeholders are expanded like Caddy.
        for (key, value) in &self.env {
            env.insert(key.clone(), value.expand(&context));
        }

        // Per-method CGI overrides matching Caddy's client helpers.
        match *method {
            Method::HEAD | Method::OPTIONS => {
                env.insert("CONTENT_LENGTH".to_string(), "0".to_string());
            }
            Method::GET => {}
            _ => {
                if env
                    .get("CONTENT_TYPE")
                    .is_some_and(|content_type| content_type.is_empty())
                {
                    env.insert(
                        "CONTENT_TYPE".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    );
                }
            }
        }
        env.insert("REQUEST_METHOD".to_string(), method.as_str().to_string());

        Ok(env)
    }

    async fn dial(&self, upstream: &Upstream) -> Result<FastCgiStream, FastCgiError> {
        let Some(transport) = upstream.transport() else {
            return Err(FastCgiError::Request(
                "FastCGI upstreams require a fixed dial address; placeholder dials are rejected at configuration time"
                    .to_string(),
            ));
        };
        match transport {
            Transport::Tcp { address } => {
                let connect = tokio::net::TcpStream::connect(address);
                match tokio::time::timeout(self.dial_timeout, connect).await {
                    Ok(Ok(stream)) => Ok(FastCgiStream::Tcp(stream)),
                    Ok(Err(error)) => Err(FastCgiError::Connect(format!("{address}: {error}"))),
                    Err(_) => Err(FastCgiError::Connect(format!(
                        "{address}: dial timed out after {:?}",
                        self.dial_timeout
                    ))),
                }
            }
            #[cfg(unix)]
            Transport::Unix { path } => {
                let connect = tokio::net::UnixStream::connect(path);
                match tokio::time::timeout(self.dial_timeout, connect).await {
                    Ok(Ok(stream)) => Ok(FastCgiStream::Unix(stream)),
                    Ok(Err(error)) => Err(FastCgiError::Connect(format!(
                        "{}: {error}",
                        path.display()
                    ))),
                    Err(_) => Err(FastCgiError::Connect(format!(
                        "{}: dial timed out after {:?}",
                        path.display(),
                        self.dial_timeout
                    ))),
                }
            }
            #[cfg(not(unix))]
            Transport::Unix { .. } => Err(FastCgiError::Connect(
                "unix sockets are not supported on this platform".to_string(),
            )),
        }
    }

    async fn write_request<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        params: &BTreeMap<String, String>,
        mut body: RequestBody,
        write_deadline: IoDeadline,
    ) -> Result<(), FastCgiError> {
        // BEGIN_REQUEST: role RESPONDER, flags 0 (no keep-connection request), reserved.
        let mut begin = [0_u8; 8];
        begin[0] = (FCGI_RESPONDER >> 8) as u8;
        begin[1] = FCGI_RESPONDER as u8;
        write_record(writer, FCGI_BEGIN_REQUEST, &begin, write_deadline).await?;

        // PARAMS records, terminated by an empty PARAMS record.
        //
        // Truncation policy (SEC-FU-FASTCGI-PARAM-TRUNC-POLICY): keep Caddy's truncation instead
        // of rejecting the request. The backend-visible CGI environment has to stay identical to
        // Caddy v2.11.9 (DIV-0082 documents the 65500-byte record budget and the truncation); the
        // condition is only reachable when an operator raises `max_header_bytes` above ~65.5 KiB
        // or configures an over-long `env` value.
        // Rejecting an over-long value would turn that configuration-dependent edge into a 5xx
        // with no upstream equivalent, so the divergence is limited to observability: the warning
        // below makes the silent shortening visible.
        //
        // The warning is emitted once per request (not once per parameter) with parameter names
        // and byte lengths only. The value itself is never logged: it can be operator-supplied or
        // attacker-controlled and may carry a credential.
        let mut truncated_params: Vec<(&str, usize, usize)> = Vec::new();
        let mut buffer = Vec::with_capacity(MAX_WRITE);
        for (name, value) in params {
            let mut encoded = Vec::with_capacity(name.len() + value.len() + 8);
            encode_pair(&mut encoded, name, value);
            if encoded.len() > MAX_WRITE {
                // Caddy truncates over-long values so a record never exceeds the write limit.
                // The budget is in bytes, but the cut must land on a UTF-8 boundary: `params`
                // values are `String`s here, and slicing mid-character would panic (SEC-FU-
                // FASTCGI-WRITE-TRUNC). Cutting on the floor boundary keeps the value valid
                // UTF-8 and never exceeds `allowed`; ASCII values are unaffected.
                let allowed = MAX_WRITE.saturating_sub(8 + name.len());
                let end = floor_char_boundary(value, allowed);
                let mut truncated = Vec::new();
                encode_pair(&mut truncated, name, &value[..end]);
                encoded = truncated;
                truncated_params.push((name.as_str(), value.len(), end));
            }
            if buffer.len() + encoded.len() > MAX_WRITE && !buffer.is_empty() {
                write_record(writer, FCGI_PARAMS, &buffer, write_deadline).await?;
                buffer.clear();
            }
            buffer.extend_from_slice(&encoded);
        }
        if !buffer.is_empty() {
            write_record(writer, FCGI_PARAMS, &buffer, write_deadline).await?;
        }
        write_record(writer, FCGI_PARAMS, &[], write_deadline).await?;
        if !truncated_params.is_empty() {
            tracing::warn!(
                truncated = truncated_params.len(),
                params = %describe_truncated_params(&truncated_params),
                "FastCGI CGI parameter value truncated to the 65500-byte record budget; the \
                 backend receives a shortened value (raise max_header_bytes only if intended)"
            );
        }

        // STDIN records: stream the body frame by frame (already buffered by policy, but keep the
        // generic Body contract so a future streaming policy can use this unchanged).
        while let Some(frame) = body.frame().await {
            let frame = frame
                .map_err(|error| FastCgiError::Request(format!("reading request body: {error}")))?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            for chunk in data.chunks(MAX_WRITE) {
                write_record(writer, FCGI_STDIN, chunk, write_deadline).await?;
            }
        }
        write_record(writer, FCGI_STDIN, &[], write_deadline).await?;
        writer
            .flush()
            .await
            .map_err(|error| FastCgiError::Io(format!("flushing request: {error}")))?;
        Ok(())
    }

    async fn read_response_head<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        read_deadline: IoDeadline,
    ) -> Result<ResponseHead, FastCgiError> {
        let mut header_bytes = BytesMut::new();
        let mut stderr = BytesMut::new();
        loop {
            let record = read_record(reader, read_deadline).await?;
            match record.kind {
                FCGI_STDOUT => {
                    header_bytes.extend_from_slice(&record.content);
                    if let Some((header_len, body_start)) = find_cgi_header_end(&header_bytes) {
                        let (status, headers) = parse_cgi_head(&header_bytes[..header_len])?;
                        let leftover = Bytes::copy_from_slice(&header_bytes[body_start..]);
                        return Ok(ResponseHead {
                            status,
                            headers,
                            leftover,
                            stderr: stderr.freeze(),
                        });
                    }
                }
                FCGI_STDERR => stderr.extend_from_slice(&record.content),
                FCGI_END_REQUEST => {
                    let end = parse_end_request(&record.content)?;
                    return Err(FastCgiError::Protocol(format!(
                        "upstream ended before sending response headers (application status {}, protocol status {})",
                        end.application_status, end.protocol_status
                    )));
                }
                // Unknown record types are ignored, like Go's fcgi client.
                _ => {}
            }
        }
    }
}

struct ResponseHead {
    status: StatusCode,
    headers: HeaderMap,
    leftover: Bytes,
    stderr: Bytes,
}

/// Write request-body / response-body records, honouring the write timeout per record.
async fn write_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u8,
    content: &[u8],
    deadline: IoDeadline,
) -> Result<(), FastCgiError> {
    let padding = (8 - content.len() % 8) % 8;
    let mut record = Vec::with_capacity(FCGI_HEADER_LEN + content.len() + padding);
    let content_len = u16::try_from(content.len())
        .map_err(|_| FastCgiError::Protocol("record content too large".to_string()))?;
    record.push(FCGI_VERSION_1);
    record.push(kind);
    record.extend_from_slice(&REQUEST_ID.to_be_bytes());
    record.extend_from_slice(&content_len.to_be_bytes());
    record.push(padding as u8);
    record.push(0);
    record.extend_from_slice(content);
    record.extend(std::iter::repeat_n(0_u8, padding));
    let write = writer.write_all(&record);
    match timeout_or_none(deadline, write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(FastCgiError::Io(format!("writing record: {error}"))),
        Err(_) => Err(FastCgiError::Timeout(
            "writing FastCGI record timed out (connection write deadline)".to_string(),
        )),
    }
}

struct Record {
    kind: u8,
    content: Bytes,
}

/// Read one FastCGI record (header, content, padding).
async fn read_record<R: AsyncRead + Unpin>(
    reader: &mut R,
    deadline: IoDeadline,
) -> Result<Record, FastCgiError> {
    let mut header = [0_u8; FCGI_HEADER_LEN];
    read_exact(reader, &mut header, deadline).await?;
    if header[0] != FCGI_VERSION_1 {
        return Err(FastCgiError::Protocol(format!(
            "invalid record version {}",
            header[0]
        )));
    }
    let kind = header[1];
    let request_id = u16::from_be_bytes([header[2], header[3]]);
    if request_id != REQUEST_ID {
        return Err(FastCgiError::Protocol(format!(
            "unexpected request id {request_id}"
        )));
    }
    let content_length = u16::from_be_bytes([header[4], header[5]]) as usize;
    let padding = header[6] as usize;
    let mut content = vec![0_u8; content_length];
    read_exact(reader, &mut content, deadline).await?;
    if padding > 0 {
        let mut padding_bytes = vec![0_u8; padding];
        read_exact(reader, &mut padding_bytes, deadline).await?;
    }
    Ok(Record {
        kind,
        content: Bytes::from(content),
    })
}

async fn read_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    deadline: IoDeadline,
) -> Result<(), FastCgiError> {
    match timeout_or_none(deadline, reader.read_exact(buffer)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(FastCgiError::Io(format!("reading record: {error}"))),
        Err(_) => Err(FastCgiError::Timeout(
            "reading from FastCGI upstream timed out (connection read deadline)".to_string(),
        )),
    }
}

/// Run `future` with an optional timeout. `Err(())` means the timeout elapsed.
/// An absolute I/O deadline (`None` means unlimited), like Go's `SetReadDeadline`.
type IoDeadline = Option<tokio::time::Instant>;

/// Compute a connection deadline from a configured duration (`0` = no deadline).
fn deadline_after(duration: Duration) -> IoDeadline {
    (!duration.is_zero()).then(|| tokio::time::Instant::now() + duration)
}

async fn timeout_or_none<F: std::future::Future>(
    deadline: IoDeadline,
    future: F,
) -> Result<F::Output, ()> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| ()),
        None => Ok(future.await),
    }
}

/// Caddy's `bodyAllowed` rule (net/http response body rules).
fn fastcgi_body_allowed(method: &str, status: StatusCode) -> bool {
    method != "HEAD"
        && !(status.as_u16() >= 100 && status.as_u16() <= 199)
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED
}

/// Largest index `<= max` (and `<= value.len()`) that is a UTF-8 character boundary.
///
/// Used to truncate a CGI parameter value to a byte budget without splitting a multibyte
/// character, which would panic when slicing a `&str`.
fn floor_char_boundary(value: &str, max: usize) -> usize {
    let mut end = max.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Render the truncated-parameter warning payload: `NAME originalB->keptB`, joined by commas.
///
/// Only names and byte lengths are rendered. The value is deliberately absent: it can be
/// operator data or an attacker-controlled header and may contain a credential, so it must not
/// reach the log.
fn describe_truncated_params(truncated: &[(&str, usize, usize)]) -> String {
    truncated
        .iter()
        .map(|(name, original, kept)| format!("{name} {original}B->{kept}B"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Encode a name/value pair using FastCGI's 1-or-4-byte length encoding.
fn encode_pair(out: &mut Vec<u8>, name: &str, value: &str) {
    encode_length(out, name.len());
    encode_length(out, value.len());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn encode_length(out: &mut Vec<u8>, length: usize) {
    if length > 127 {
        let tagged = (length as u32) | (1 << 31);
        out.extend_from_slice(&tagged.to_be_bytes());
    } else {
        out.push(length as u8);
    }
}

struct EndRequest {
    application_status: u32,
    protocol_status: u8,
}

fn parse_end_request(content: &[u8]) -> Result<EndRequest, FastCgiError> {
    if content.len() < 8 {
        return Err(FastCgiError::Protocol(
            "END_REQUEST record shorter than 8 bytes".to_string(),
        ));
    }
    Ok(EndRequest {
        application_status: u32::from_be_bytes([content[0], content[1], content[2], content[3]]),
        protocol_status: content[4],
    })
}

/// Find the end of the CGI header block, returning `(header_len, body_offset)`.
fn find_cgi_header_end(buffer: &[u8]) -> Option<(usize, usize)> {
    for (index, window) in buffer.windows(4).enumerate() {
        if window == b"\r\n\r\n" {
            return Some((index, index + 4));
        }
    }
    for (index, window) in buffer.windows(2).enumerate() {
        if window == b"\n\n" {
            return Some((index, index + 2));
        }
    }
    None
}

/// Caddy's `splitPos`: index just past the first case-insensitive `split_path` match in `fpath`
/// (0 when the split list is empty), or `None` when nothing matches.
///
/// `fpath` is the percent-decoded request path and may contain multibyte UTF-8, so the scan
/// compares `as_bytes()` (like Go's byte-oriented `strings.Index`) instead of slicing `&str` at
/// raw byte offsets. The returned offset is always a char boundary: `split_path` entries are
/// validated ASCII, so a byte match cannot begin inside a multibyte character, and the boundary
/// checks keep the result total (and `fpath.split_at` panic-free) for any input.
fn cgi_split_pos(split_path: &[String], fpath: &str) -> Option<usize> {
    if split_path.is_empty() {
        return Some(0);
    }
    split_path
        .iter()
        .filter(|split| !split.is_empty() && split.len() <= fpath.len())
        .find_map(|split| {
            let needle = split.as_bytes();
            (0..=fpath.len() - split.len())
                .find(|start| {
                    let end = start + split.len();
                    fpath
                        .as_bytes()
                        .get(*start..end)
                        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(needle))
                        && fpath.is_char_boundary(*start)
                        && fpath.is_char_boundary(end)
                })
                .map(|start| start + split.len())
        })
}

/// Caddy's `caddyhttp.NormalizedPath` for CGI path derivation: decode the URI path, reject NUL
/// bytes, then clean `.`/`..`/duplicate slashes while preserving a trailing slash.
fn normalized_script_path(raw: &str) -> Result<String, FastCgiError> {
    if raw.contains('\0') {
        return Err(FastCgiError::Request("invalid request path".to_string()));
    }
    let decoded = percent_decode_path(raw)
        .ok_or_else(|| FastCgiError::Request("invalid request path".to_string()))?;
    if decoded.contains('\0') {
        return Err(FastCgiError::Request("invalid request path".to_string()));
    }
    let escapes = decoded
        .split('/')
        .scan(0_i32, |depth, component| {
            match component {
                "" | "." => {}
                ".." => *depth -= 1,
                _ => *depth += 1,
            }
            Some(*depth)
        })
        .any(|depth| depth < 0);
    if escapes {
        return Err(FastCgiError::Request("invalid request path".to_string()));
    }
    let cleaned = normalize_slash_path(&decoded);
    if cleaned.is_empty() {
        if decoded.is_empty() {
            Ok(String::new())
        } else {
            Ok("/".to_string())
        }
    } else {
        Ok(cleaned)
    }
}

/// Percent-decode a URI path (Caddy's `r.URL.Path` is decoded by net/http; `+` is literal here).
fn percent_decode_path(path: &str) -> Option<String> {
    if !path.contains('%') {
        return Some(path.to_string());
    }
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = path.get(index + 1..index + 3)?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// Trim one response-body chunk to the declared Content-Length; surplus bytes are discarded (the
/// FastCGI stream is still drained to END_REQUEST, matching Caddy's `declaredBody`).
fn bounded_body_chunk(data: Bytes, remaining: &mut Option<u64>) -> Option<Bytes> {
    match remaining {
        None => Some(data),
        Some(left) if *left == 0 => None,
        Some(left) => {
            let allowed = usize::try_from(*left).unwrap_or(usize::MAX).min(data.len());
            *left -= allowed as u64;
            Some(data.slice(..allowed))
        }
    }
}

/// Parse the CGI response head: CGI headers (including `Status:`) terminated by a blank line.
fn parse_cgi_head(bytes: &[u8]) -> Result<(StatusCode, HeaderMap), FastCgiError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| FastCgiError::Protocol(format!("CGI headers are not UTF-8: {error}")))?;
    let mut status = StatusCode::OK;
    let mut status_seen = false;
    let mut headers = HeaderMap::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        // Caddy parses these with Go's MIME header reader: every line must be a header, so an
        // HTTP status line or any other colon-less line is a protocol error (502).
        let Some((name, value)) = line.split_once(':') else {
            return Err(FastCgiError::Protocol(format!(
                "malformed CGI header line `{line}`"
            )));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("status") {
            let code = value
                .split_whitespace()
                .next()
                .ok_or_else(|| FastCgiError::Protocol("empty Status header".to_string()))?;
            status = parse_status_code(code)?;
            status_seen = true;
            continue;
        }
        let header_name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|error| {
            FastCgiError::Protocol(format!("invalid CGI header name `{name}`: {error}"))
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|error| {
            FastCgiError::Protocol(format!("invalid CGI header value for `{name}`: {error}"))
        })?;
        headers.append(header_name, header_value);
    }
    // Caddy: without a `Status` header a response with a Location header is a 302.
    if !status_seen && headers.contains_key(http::header::LOCATION) {
        status = StatusCode::FOUND;
    }
    Ok((status, headers))
}

fn parse_status_code(text: &str) -> Result<StatusCode, FastCgiError> {
    let code: u16 = text
        .parse()
        .map_err(|_| FastCgiError::Protocol(format!("invalid CGI status code `{text}`")))?;
    StatusCode::from_u16(code)
        .map_err(|error| FastCgiError::Protocol(format!("invalid CGI status code: {error}")))
}

/// Stream the response body records to the proxy.
#[allow(clippy::too_many_arguments)]
async fn stream_response_body<R: AsyncRead + Unpin>(
    mut reader: R,
    leftover: Bytes,
    chunked: bool,
    sender: mpsc::Sender<std::result::Result<Bytes, BodyError>>,
    capture_stderr: bool,
    status: StatusCode,
    body_allowed: bool,
    declared_length: Option<u64>,
    read_deadline: IoDeadline,
) {
    let mut stderr = BytesMut::new();
    let mut decoder = ChunkedDecoder::default();
    let mut remaining = declared_length;
    if chunked {
        decoder.feed(&leftover);
    } else if body_allowed {
        if let Some(data) = bounded_body_chunk(leftover, &mut remaining) {
            if !data.is_empty() && sender.send(Ok(data)).await.is_err() {
                return;
            }
        }
    }
    loop {
        let record = match read_record(&mut reader, read_deadline).await {
            Ok(record) => record,
            Err(error) => {
                if capture_stderr {
                    log_stderr(&stderr, status);
                }
                let _ = sender
                    .send(Err(BodyError::upstream(std::io::Error::other(
                        error.to_string(),
                    ))))
                    .await;
                return;
            }
        };
        match record.kind {
            FCGI_STDOUT => {
                if chunked {
                    decoder.feed(&record.content);
                    for chunk in decoder.drain() {
                        match chunk {
                            Ok(chunk) => {
                                if !chunk.is_empty() && sender.send(Ok(chunk)).await.is_err() {
                                    return;
                                }
                            }
                            Err(message) => {
                                let _ = sender
                                    .send(Err(BodyError::upstream(std::io::Error::other(message))))
                                    .await;
                                return;
                            }
                        }
                    }
                } else if body_allowed {
                    if let Some(data) = bounded_body_chunk(record.content, &mut remaining) {
                        if !data.is_empty() && sender.send(Ok(data)).await.is_err() {
                            return;
                        }
                    }
                }
            }
            FCGI_STDERR => stderr.extend_from_slice(&record.content),
            FCGI_END_REQUEST => {
                if capture_stderr {
                    log_stderr(&stderr, status);
                }
                if chunked {
                    for chunk in decoder.finish() {
                        match chunk {
                            Ok(chunk) => {
                                if !chunk.is_empty() && sender.send(Ok(chunk)).await.is_err() {
                                    return;
                                }
                            }
                            Err(message) => {
                                let _ = sender
                                    .send(Err(BodyError::upstream(std::io::Error::other(message))))
                                    .await;
                                return;
                            }
                        }
                    }
                }
                match parse_end_request(&record.content) {
                    Ok(end) => {
                        if end.protocol_status != FCGI_REQUEST_COMPLETE {
                            let _ = sender
                                .send(Err(BodyError::upstream(std::io::Error::other(format!(
                                    "FastCGI application did not complete the request (protocol status {})",
                                    end.protocol_status
                                )))))
                                .await;
                        } else if end.application_status != 0 {
                            let _ = sender
                                .send(Err(BodyError::upstream(std::io::Error::other(format!(
                                    "FastCGI application returned status {}",
                                    end.application_status
                                )))))
                                .await;
                        }
                    }
                    Err(error) => {
                        let _ = sender
                            .send(Err(BodyError::upstream(std::io::Error::other(
                                error.to_string(),
                            ))))
                            .await;
                    }
                }
                return;
            }
            _ => {}
        }
    }
}

fn log_stderr(stderr: &[u8], status: StatusCode) {
    if stderr.is_empty() {
        return;
    }
    // Caddy logs stderr at WARN by default and ERROR for 4xx and 5xx responses.
    let level = if status.is_client_error() || status.is_server_error() {
        "error"
    } else {
        "warn"
    };
    eprintln!(
        "caddy-rs: fastcgi upstream stderr ({level}): {}",
        String::from_utf8_lossy(stderr).trim_end()
    );
}

/// Incremental decoder for CGI responses that declare `Transfer-Encoding: chunked`.
#[derive(Debug, Default)]
struct ChunkedDecoder {
    buffer: Vec<u8>,
    state: ChunkState,
    finished: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
enum ChunkState {
    #[default]
    Size,
    Data(u64),
    DataCrlf,
    Trailers,
    Done,
}

impl ChunkedDecoder {
    fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Extract all currently decodable chunks.
    fn drain(&mut self) -> Vec<Result<Bytes, String>> {
        let mut out = Vec::new();
        loop {
            match self.state {
                ChunkState::Size => {
                    let Some(line_end) = find_crlf(&self.buffer) else {
                        return out;
                    };
                    let line = String::from_utf8_lossy(&self.buffer[..line_end]).to_string();
                    self.buffer.drain(..line_end + 2);
                    let size_text = line.split(';').next().unwrap_or("").trim();
                    match u64::from_str_radix(size_text, 16) {
                        Ok(0) => self.state = ChunkState::Trailers,
                        Ok(size) => self.state = ChunkState::Data(size),
                        Err(_) => {
                            out.push(Err(format!("invalid chunk size `{size_text}`")));
                            self.state = ChunkState::Done;
                            return out;
                        }
                    }
                }
                ChunkState::Data(remaining) => {
                    if self.buffer.is_empty() {
                        return out;
                    }
                    let take = (self.buffer.len() as u64).min(remaining) as usize;
                    let chunk: Vec<u8> = self.buffer.drain(..take).collect();
                    out.push(Ok(Bytes::from(chunk)));
                    if take as u64 == remaining {
                        self.state = ChunkState::DataCrlf;
                    } else {
                        self.state = ChunkState::Data(remaining - take as u64);
                        return out;
                    }
                }
                ChunkState::DataCrlf => {
                    if self.buffer.len() < 2 {
                        return out;
                    }
                    self.buffer.drain(..2);
                    self.state = ChunkState::Size;
                }
                ChunkState::Trailers => {
                    // Trailers (if any) are terminated by an empty line; they are not forwarded.
                    if let Some(index) = find_double_crlf(&self.buffer) {
                        self.buffer.drain(..index + 4);
                        self.state = ChunkState::Done;
                        self.finished = true;
                    }
                    return out;
                }
                ChunkState::Done => {
                    self.finished = true;
                    return out;
                }
            }
        }
    }

    /// Final chunks and validation once END_REQUEST arrives.
    fn finish(&mut self) -> Vec<Result<Bytes, String>> {
        let mut out = self.drain();
        if !self.finished {
            if self.state == ChunkState::Trailers && self.buffer.is_empty() {
                // An empty trailer section may already have been consumed by `find_double_crlf`
                // returning index 0 (no trailers) only when the buffer held the final CRLF.
                self.finished = true;
            } else {
                out.push(Err(
                    "chunked FastCGI response ended before the final chunk".to_string()
                ));
                self.finished = true;
            }
        }
        out
    }
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

fn find_double_crlf(buffer: &[u8]) -> Option<usize> {
    if buffer.starts_with(b"\r\n") {
        return Some(0);
    }
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// A FastCGI connection (TCP or Unix socket).
enum FastCgiStream {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl AsyncRead for FastCgiStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            Self::Unix(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for FastCgiStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            Self::Unix(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Caddy's `caddy.FastAbs`: clean absolute paths, resolve relative ones against the cwd.
fn absolute_path(path: &Path) -> std::io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(normalize_components(path));
    }
    let cwd = std::env::current_dir()?;
    Ok(normalize_components(&cwd.join(path)))
}

/// Lexical path cleaning (`.`/`..`/duplicate separators), like Go's `filepath.Clean`.
fn normalize_components(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

/// Caddy's `caddyhttp.SanitizedPathJoin`: join under `root`, refusing escaping paths.
fn sanitized_path_join(root: &str, request_path: &str) -> Option<String> {
    let mut cleaned = String::from("/");
    cleaned.push_str(request_path);
    let relative = cleaned.trim_start_matches('/');
    let escapes = relative
        .split('/')
        .scan(0_i32, |depth, component| {
            match component {
                "" | "." => {}
                ".." => *depth -= 1,
                _ => *depth += 1,
            }
            Some(*depth)
        })
        .any(|depth| depth < 0);
    if escapes {
        return None;
    }
    if relative.is_empty() {
        return Some(root.to_string());
    }
    let cleaned = normalize_slash_path(&cleaned);
    let relative = cleaned.trim_start_matches('/');
    let mut joined = String::from(root.trim_end_matches('/'));
    joined.push('/');
    joined.push_str(relative);
    if request_path.ends_with('/') && request_path.len() > 1 {
        joined.push('/');
    }
    Some(joined)
}

fn normalize_slash_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut normalized = String::new();
    for segment in segments {
        normalized.push('/');
        normalized.push_str(segment);
    }
    if path.ends_with('/') && !normalized.is_empty() {
        normalized.push('/');
    }
    normalized
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Split a `Host` value into name and port, tolerating IPv6 brackets.
fn split_host_port(host: &str) -> (String, String) {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some((inside, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').unwrap_or_default().to_string();
            return (inside.to_string(), port);
        }
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|character| character.is_ascii_digit()) => {
            (name.to_string(), port.to_string())
        }
        _ => (host.to_string(), String::new()),
    }
}

fn invalid(path: &str, message: impl Into<String>) -> HttpError {
    HttpError::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_http::{Handler, Outcome};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    use tokio::time::Duration as TokioDuration;

    #[derive(Debug, Clone, Default)]
    struct CapturedFastCgi {
        params: BTreeMap<String, String>,
        stdin: Bytes,
    }

    #[derive(Clone)]
    enum Behavior {
        /// Standard CGI head + body, optional stderr and END_REQUEST statuses.
        Respond {
            headers: &'static str,
            body: &'static [u8],
            stderr: &'static [u8],
            application_status: u32,
            protocol_status: u8,
        },
        /// `Transfer-Encoding: chunked` body split across STDOUT records.
        Chunked {
            headers: &'static str,
            chunks: Vec<&'static str>,
        },
        /// Headers and first body chunk, then a delay before the rest (streaming evidence).
        SlowBody {
            headers: &'static str,
            first: &'static [u8],
            rest: &'static [u8],
            delay: TokioDuration,
        },
        /// Accept the request and never answer (timeout tests).
        Silent,
        /// Raw FastCGI bytes written verbatim (malformed-protocol tests).
        Raw { bytes: Vec<u8>, keep_open: bool },
        /// Several STDOUT records with a delay between them (absolute read-deadline tests).
        SlowRecords {
            headers: &'static str,
            chunks: Vec<&'static [u8]>,
            gap: TokioDuration,
        },
    }

    impl Behavior {
        fn responds(application_status: u32) -> Self {
            Self::Respond {
                headers: "Content-Type: text/plain\r\n\r\n",
                body: b"ok",
                stderr: b"",
                application_status,
                protocol_status: FCGI_REQUEST_COMPLETE,
            }
        }
    }

    type Captured = Arc<Mutex<Option<CapturedFastCgi>>>;

    async fn read_fastcgi_request<S: AsyncRead + Unpin>(
        reader: &mut S,
    ) -> std::io::Result<CapturedFastCgi> {
        let mut params_bytes = Vec::new();
        let mut stdin = Vec::new();
        let mut params_done = false;
        loop {
            let record = read_record(reader, None)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            match record.kind {
                FCGI_BEGIN_REQUEST => {}
                FCGI_PARAMS => {
                    if record.content.is_empty() {
                        params_done = true;
                    } else {
                        params_bytes.extend_from_slice(&record.content);
                    }
                }
                FCGI_STDIN => {
                    if record.content.is_empty() && params_done {
                        break;
                    }
                    stdin.extend_from_slice(&record.content);
                }
                _ => {}
            }
        }
        Ok(CapturedFastCgi {
            params: decode_params(&params_bytes),
            stdin: Bytes::from(stdin),
        })
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

    async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        behavior: Behavior,
        captured: Captured,
    ) {
        let request = match read_fastcgi_request(&mut stream).await {
            Ok(request) => request,
            Err(_) => return,
        };
        *captured.lock().unwrap() = Some(request);
        match behavior {
            Behavior::Silent => {
                // Hold the connection open without responding until the client times out.
                tokio::time::sleep(TokioDuration::from_secs(30)).await;
            }
            Behavior::Respond {
                headers,
                body,
                stderr,
                application_status,
                protocol_status,
            } => {
                let _ = write_record(&mut stream, FCGI_STDOUT, headers.as_bytes(), None).await;
                if !body.is_empty() {
                    let _ = write_record(&mut stream, FCGI_STDOUT, body, None).await;
                }
                let _ = write_record(&mut stream, FCGI_STDOUT, &[], None).await;
                if !stderr.is_empty() {
                    let _ = write_record(&mut stream, FCGI_STDERR, stderr, None).await;
                }
                write_end_request(&mut stream, application_status, protocol_status).await;
            }
            Behavior::Chunked { headers, chunks } => {
                let _ = write_record(&mut stream, FCGI_STDOUT, headers.as_bytes(), None).await;
                for chunk in chunks {
                    let encoded = format!("{:x}\r\n{chunk}\r\n", chunk.len());
                    let _ = write_record(&mut stream, FCGI_STDOUT, encoded.as_bytes(), None).await;
                }
                let _ = write_record(&mut stream, FCGI_STDOUT, b"0\r\n\r\n", None).await;
                let _ = write_record(&mut stream, FCGI_STDOUT, &[], None).await;
                write_end_request(&mut stream, 0, FCGI_REQUEST_COMPLETE).await;
            }
            Behavior::Raw { bytes, keep_open } => {
                let _ = stream.write_all(&bytes).await;
                if keep_open {
                    tokio::time::sleep(TokioDuration::from_secs(10)).await;
                }
            }
            Behavior::SlowRecords {
                headers,
                chunks,
                gap,
            } => {
                let _ = write_record(&mut stream, FCGI_STDOUT, headers.as_bytes(), None).await;
                for chunk in chunks {
                    tokio::time::sleep(gap).await;
                    let _ = write_record(&mut stream, FCGI_STDOUT, chunk, None).await;
                }
                let _ = write_record(&mut stream, FCGI_STDOUT, &[], None).await;
                write_end_request(&mut stream, 0, FCGI_REQUEST_COMPLETE).await;
            }
            Behavior::SlowBody {
                headers,
                first,
                rest,
                delay,
            } => {
                let _ = write_record(&mut stream, FCGI_STDOUT, headers.as_bytes(), None).await;
                let _ = write_record(&mut stream, FCGI_STDOUT, first, None).await;
                tokio::time::sleep(delay).await;
                let _ = write_record(&mut stream, FCGI_STDOUT, rest, None).await;
                let _ = write_record(&mut stream, FCGI_STDOUT, &[], None).await;
                write_end_request(&mut stream, 0, FCGI_REQUEST_COMPLETE).await;
            }
        }
    }

    async fn write_end_request<S: AsyncWrite + Unpin>(
        stream: &mut S,
        application_status: u32,
        protocol_status: u8,
    ) {
        let mut content = [0_u8; 8];
        content[..4].copy_from_slice(&application_status.to_be_bytes());
        content[4] = protocol_status;
        let _ = write_record(stream, FCGI_END_REQUEST, &content, None).await;
    }

    async fn spawn_tcp_mock(behavior: Behavior) -> (String, Captured) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured: Captured = Arc::new(Mutex::new(None));
        let captured_server = Arc::clone(&captured);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let behavior = behavior.clone();
                let captured = Arc::clone(&captured_server);
                let _ = stream.set_nodelay(true);
                tokio::spawn(serve_connection(stream, behavior, captured));
            }
        });
        (address.to_string(), captured)
    }

    #[cfg(unix)]
    async fn spawn_unix_mock(path: std::path::PathBuf, behavior: Behavior) -> Captured {
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let captured: Captured = Arc::new(Mutex::new(None));
        let captured_server = Arc::clone(&captured);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let behavior = behavior.clone();
                let captured = Arc::clone(&captured_server);
                tokio::spawn(serve_connection(stream, behavior, captured));
            }
        });
        captured
    }

    fn transport_json(extra: Value) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("protocol".to_string(), Value::String("fastcgi".to_string()));
        if let Value::Object(extra) = extra {
            object.extend(extra);
        }
        Value::Object(object)
    }

    fn build_handler(dial: &str, transport: Value) -> super::super::handler::ReverseProxyHandler {
        super::super::handler::ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": dial}],
                "transport": transport
            }),
            "handler",
        )
        .expect("fastcgi handler builds")
    }

    fn build_handler_with_server_software(
        dial: &str,
        transport: Value,
        server_software: Option<String>,
    ) -> super::super::handler::ReverseProxyHandler {
        super::super::handler::ReverseProxyHandler::from_json_with_server_software(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": dial}],
                "transport": transport
            }),
            "handler",
            server_software,
        )
        .expect("fastcgi handler builds")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_software_follows_the_configured_identity_mode() {
        let default_identity = format!("caddy-rs/{}", env!("CARGO_PKG_VERSION"));
        let modes: [(Option<String>, Option<String>); 5] = [
            (
                Some(default_identity),
                Some(format!("caddy-rs/{}", env!("CARGO_PKG_VERSION"))),
            ),
            (Some("Caddy".to_string()), Some("Caddy".to_string())),
            (
                Some("Caddy/2.11.9".to_string()),
                Some("Caddy/2.11.9".to_string()),
            ),
            (
                Some("Acme Server/2".to_string()),
                Some("Acme Server/2".to_string()),
            ),
            (None, None),
        ];
        for (configured, expected) in modes {
            let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
            let handler = build_handler_with_server_software(
                &dial,
                transport_json(serde_json::json!({})),
                configured,
            );
            let response = respond(&handler, request(Method::GET, "/index.php"));
            assert_eq!(response.status, StatusCode::OK);
            let captured = captured.lock().unwrap().clone().expect("captured request");
            assert_eq!(
                captured.params.get("SERVER_SOFTWARE"),
                expected.as_ref(),
                "SERVER_SOFTWARE must follow the configured identity mode"
            );
        }
    }

    fn request(method: Method, uri: &str) -> Request {
        let mut request = Request::new(method, uri.parse().unwrap());
        request.remote_addr = Some("203.0.113.7:5555".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "app.example.com".parse().unwrap());
        request
    }

    fn respond(
        handler: &super::super::handler::ReverseProxyHandler,
        request: Request,
    ) -> caddy_rs_http::Response {
        let outcome = futures_block_on(handler.handle(request));
        let Outcome::Respond(response) = outcome.expect("handler result") else {
            panic!("expected proxied response");
        };
        response
    }

    /// Minimal poll-once executor for tests that don't need a runtime split (handlers are async
    /// but are driven inside `#[tokio::test]`; this helper is only used from sync test bodies).
    fn futures_block_on<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    }

    fn body_string(response: &caddy_rs_http::Response) -> String {
        String::from_utf8(response.body.to_vec()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_params_env_and_script_filename_match_caddy() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(
            &dial,
            transport_json(serde_json::json!({
                "root": "/srv/www",
                "split_path": [".php"],
                "env": {
                    "APP_ENV": "production",
                    "HOST_PLACEHOLDER": "{http.request.host}"
                }
            })),
        );
        let mut request = request(Method::POST, "/index.php/extra?x=1");
        request.body = Bytes::from_static(b"body-bytes");
        request
            .headers
            .insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        request.headers.insert("x-custom", "abc".parse().unwrap());
        let response = respond(&handler, request);
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(body_string(&response), "ok");

        let captured = captured.lock().unwrap().clone().expect("captured request");
        let params = &captured.params;
        assert_eq!(params["GATEWAY_INTERFACE"], "CGI/1.1");
        assert_eq!(params["REQUEST_METHOD"], "POST");
        assert_eq!(params["REQUEST_SCHEME"], "http");
        assert_eq!(params["SERVER_PROTOCOL"], "HTTP/1.1");
        assert_eq!(
            params["SERVER_SOFTWARE"],
            format!("caddy-rs/{}", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(params["SERVER_NAME"], "app.example.com");
        assert_eq!(params["SERVER_PORT"], "80");
        assert_eq!(params["DOCUMENT_ROOT"], "/srv/www");
        assert_eq!(params["DOCUMENT_URI"], "/index.php");
        assert_eq!(params["SCRIPT_NAME"], "/index.php");
        assert_eq!(params["SCRIPT_FILENAME"], "/srv/www/index.php");
        assert_eq!(params["PATH_INFO"], "/extra");
        assert_eq!(params["PATH_TRANSLATED"], "/srv/www/extra");
        assert_eq!(params["QUERY_STRING"], "x=1");
        assert_eq!(params["REQUEST_URI"], "/index.php/extra?x=1");
        assert_eq!(params["HTTP_HOST"], "app.example.com");
        assert_eq!(params["CONTENT_TYPE"], "text/plain");
        assert_eq!(params["CONTENT_LENGTH"], "10");
        assert_eq!(params["REMOTE_ADDR"], "203.0.113.7");
        assert_eq!(params["REMOTE_PORT"], "5555");
        assert_eq!(params["HTTP_X_CUSTOM"], "abc");
        assert_eq!(params["APP_ENV"], "production");
        assert_eq!(params["HOST_PLACEHOLDER"], "app.example.com");
        assert!(!params.contains_key("HTTP_PROXY"), "HTTPoxy mitigation");
        assert_eq!(captured.stdin, Bytes::from_static(b"body-bytes"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_head_and_get_content_length_semantics() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::HEAD, "/index.php"));
        assert_eq!(response.status, StatusCode::OK);
        let params = captured.lock().unwrap().clone().unwrap().params;
        assert_eq!(params["REQUEST_METHOD"], "HEAD");
        assert_eq!(params["CONTENT_LENGTH"], "0");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_parses_status_and_headers() {
        let (dial, _captured) = spawn_tcp_mock(Behavior::Respond {
            headers: "Status: 201 Created\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n",
            body: b"created",
            stderr: b"",
            application_status: 0,
            protocol_status: FCGI_REQUEST_COMPLETE,
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/"));
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(body_string(&response), "created");
        assert_eq!(response.headers["content-type"], "text/plain");
        assert_eq!(response.headers.get_all("set-cookie").iter().count(), 2);
        // The proxy adds Via and strips hop-by-hop headers.
        assert_eq!(response.headers[http::header::VIA], "1.1 Caddy");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_defaults_to_200_without_status_header() {
        let (dial, _captured) = spawn_tcp_mock(Behavior::Respond {
            headers: "Content-Type: text/html\r\n\r\n",
            body: b"<html>",
            stderr: b"",
            application_status: 0,
            protocol_status: FCGI_REQUEST_COMPLETE,
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/"));
        assert_eq!(response.status, StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_decodes_chunked_response() {
        let (dial, _captured) = spawn_tcp_mock(Behavior::Chunked {
            headers: "Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
            chunks: vec!["hello", " world"],
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(body_string(&response), "hello world");
        assert!(
            !response
                .headers
                .contains_key(http::header::TRANSFER_ENCODING),
            "chunked is decoded and the hop-by-hop header removed"
        );
        assert!(
            !response.headers.contains_key(http::header::CONTENT_LENGTH),
            "a decoded chunked body must not advertise a CGI Content-Length"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_nonzero_application_status_maps_to_502() {
        let (dial, _captured) = spawn_tcp_mock(Behavior::Respond {
            headers: "",
            body: b"",
            stderr: b"boom",
            application_status: 1,
            protocol_status: FCGI_REQUEST_COMPLETE,
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/broken"));
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_nonzero_protocol_status_maps_to_502() {
        let (dial, _captured) = spawn_tcp_mock(Behavior::Respond {
            headers: "Content-Type: text/plain\r\n\r\n",
            body: b"partial",
            stderr: b"",
            application_status: 0,
            protocol_status: 2, // FCGI_OVERLOADED
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/"));
        assert_eq!(
            response.status,
            StatusCode::BAD_GATEWAY,
            "a non-complete FastCGI protocol status is an upstream failure"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_timeout_maps_to_502() {
        let (dial, _captured) = spawn_tcp_mock(Behavior::Silent).await;
        let handler = build_handler(
            &dial,
            transport_json(serde_json::json!({"read_timeout": 50_000_000u64})),
        );
        let started = std::time::Instant::now();
        let response = respond(&handler, request(Method::GET, "/slow"));
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "read_timeout must bound the exchange"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_unreachable_upstream_maps_to_502_and_is_retryable_dial_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = listener.local_addr().unwrap().to_string();
        drop(listener);
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/"));
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_streaming_request_body_is_buffered_and_forwarded() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        assert!(
            handler.requires_buffered_request_body(),
            "fastcgi requires CONTENT_LENGTH, so the body must be buffered"
        );
        let (sender, receiver) = mpsc::channel(4);
        let mut request = request(Method::POST, "/upload");
        request = request
            .with_streaming_body(RequestBody::streaming(StreamingBody::from_chunks(receiver)));
        sender
            .send(Ok(Bytes::from_static(b"chunk-one-")))
            .await
            .unwrap();
        sender
            .send(Ok(Bytes::from_static(b"chunk-two")))
            .await
            .unwrap();
        drop(sender);
        let response = respond(&handler, request);
        assert_eq!(response.status, StatusCode::OK);
        let captured = captured.lock().unwrap().clone().unwrap();
        assert_eq!(captured.stdin, Bytes::from_static(b"chunk-one-chunk-two"));
        assert_eq!(captured.params["CONTENT_LENGTH"], "19");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_streams_response_body_before_completion() {
        let (dial, _captured) = spawn_tcp_mock(Behavior::SlowBody {
            headers: "Content-Type: text/plain\r\n\r\n",
            first: b"first",
            rest: b"-second",
            delay: TokioDuration::from_millis(300),
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let started = std::time::Instant::now();
        let outcome = handler
            .handle_streaming(request(Method::GET, "/stream"))
            .await
            .unwrap();
        let caddy_rs_http::StreamingOutcome::Respond(response) = outcome else {
            panic!("expected a proxied response");
        };
        assert!(
            started.elapsed() < TokioDuration::from_millis(250),
            "response headers must arrive before the upstream finishes the body"
        );
        assert!(response.is_streaming());
        let response = response.into_buffered().await.unwrap();
        assert_eq!(body_string(&response), "first-second");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_over_unix_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("php-fpm.sock");
        let captured = spawn_unix_mock(socket.clone(), Behavior::responds(0)).await;
        let dial = format!("unix/{}", socket.display());
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(body_string(&response), "ok");
        assert_eq!(
            captured.lock().unwrap().clone().unwrap().params["REQUEST_METHOD"],
            "GET"
        );
    }

    #[test]
    fn fastcgi_unknown_transport_fields_fail_loudly() {
        let error = FastCgiTransport::from_json(
            &serde_json::json!({"protocol": "fastcgi", "unknown_field": true}),
            "handler.transport",
        )
        .expect_err("unknown fastcgi transport field must be rejected");
        assert!(error.to_string().contains("unknown_field"), "{error}");

        let error = FastCgiTransport::from_json(
            &serde_json::json!({"protocol": "fastcgi", "tls": {}}),
            "handler.transport",
        )
        .expect_err("TLS is not a FastCGI transport option");
        assert!(error.to_string().contains("tls"), "{error}");

        let error = FastCgiTransport::from_json(
            &serde_json::json!({"protocol": "fastcgi", "split_path": ["\u{00e9}.php"]}),
            "handler.transport",
        )
        .expect_err("non-ASCII split paths are rejected");
        assert!(error.to_string().contains("non-ASCII"), "{error}");

        let error = FastCgiTransport::from_json(
            &serde_json::json!({"protocol": "fastcgi", "env": {"X": 1}}),
            "handler.transport",
        )
        .expect_err("non-string env values are rejected");
        assert!(error.to_string().contains("strings"), "{error}");
    }

    #[test]
    fn fastcgi_active_health_checks_fail_loudly() {
        let error = super::super::handler::ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:9000"}],
                "transport": {"protocol": "fastcgi"},
                "health_checks": {"active": {"uri": "/ping"}}
            }),
            "handler",
        )
        .err()
        .expect("active health checks over fastcgi are unsupported");
        assert!(
            error.to_string().contains("PROXY-FASTCGI-HEALTH"),
            "{error}"
        );
    }

    #[test]
    fn fastcgi_unknown_protocol_fails_loudly() {
        let error = super::super::handler::ReverseProxyHandler::from_json(
            &serde_json::json!({
                "handler": "reverse_proxy",
                "upstreams": [{"dial": "localhost:9000"}],
                "transport": {"protocol": "fastcgi2"}
            }),
            "handler",
        )
        .err()
        .expect("unknown transport protocol must be rejected");
        assert!(
            error.to_string().contains("PROXY-TRANSPORT-PROTOCOL"),
            "{error}"
        );
    }

    #[test]
    fn sanitized_path_join_prevents_traversal() {
        assert_eq!(
            sanitized_path_join("/srv/www", "/index.php"),
            Some("/srv/www/index.php".to_string())
        );
        assert_eq!(
            sanitized_path_join("/srv/www", "/"),
            Some("/srv/www".to_string())
        );
        assert_eq!(sanitized_path_join("/srv/www", "/../etc/passwd"), None);
        assert_eq!(
            sanitized_path_join("/srv/www", "/a/../b"),
            Some("/srv/www/b".to_string())
        );
    }

    #[test]
    fn split_pos_matches_caddy_semantics() {
        // Non-empty split matches case-insensitively and ends the script name.
        assert_eq!(
            cgi_split_pos(&[".php".to_string()], "/dir/index.PHP/extra"),
            Some(14)
        );
        // No match -> None (Caddy -1).
        assert_eq!(cgi_split_pos(&[".php".to_string()], "/plain/path"), None);
        // Empty split list -> Some(0) (Caddy returns 0, whole path is PATH_INFO).
        assert_eq!(cgi_split_pos(&[], "/anything"), Some(0));
    }

    #[test]
    fn cgi_split_pos_ascii_paths_keep_existing_behaviour() {
        // SEC-L9-PROXY regression guard: plain ASCII keeps the exact offsets the existing
        // integration tests assert (`/index.php/extra` -> DOCUMENT_URI `/index.php`,
        // PATH_INFO `/extra`).
        let split_path = [".php".to_string()];
        assert_eq!(cgi_split_pos(&split_path, "/index.php/extra"), Some(10));
        assert_eq!(
            "/index.php/extra".split_at(10),
            ("/index.php", "/extra"),
            "ASCII split yields the same DOCUMENT_URI/PATH_INFO pair as before"
        );
        assert_eq!(
            cgi_split_pos(&split_path, "/dir name/script.php"),
            Some(20),
            "a space in the path is still matched normally"
        );
    }

    #[test]
    fn cgi_split_pos_multibyte_paths_do_not_panic_on_non_boundaries() {
        // SEC-L9-PROXY: the scan probes offsets inside multibyte characters (`/caf\u{e9}` puts
        // byte 5 inside `\u{e9}`); slicing `&str` there panicked with "byte index 5 is not a char
        // boundary". Byte comparison must instead find the real match at the end of the path.
        let split_path = [".php".to_string()];
        assert_eq!(cgi_split_pos(&split_path, "/caf\u{e9}/x.php"), Some(12));
        assert_eq!(
            cgi_split_pos(&split_path, "/caf\u{e9}/x.php/more"),
            Some(12)
        );
        assert_eq!(
            cgi_split_pos(&split_path, "/\u{4f60}\u{597d}.php"),
            Some(11)
        );
        // A suffix that starts inside a multibyte character is not a match, and not a panic.
        assert_eq!(cgi_split_pos(&split_path, "/caf\u{e9}/x"), None);
        // Defensive: `split_path` entries are ASCII-validated at config load, but a match that
        // would end inside a character is skipped rather than sliced (the offset must stay a
        // char boundary for `fpath.split_at`).
        assert_eq!(
            cgi_split_pos(&["\u{a9}\u{c3}".to_string()], "\u{e9}\u{e9}"),
            None
        );
    }

    #[test]
    fn split_host_port_handles_ipv6_and_default_ports() {
        assert_eq!(
            split_host_port("example.com:8080"),
            ("example.com".to_string(), "8080".to_string())
        );
        assert_eq!(
            split_host_port("example.com"),
            ("example.com".to_string(), String::new())
        );
        assert_eq!(
            split_host_port("[::1]:8080"),
            ("::1".to_string(), "8080".to_string())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_server_protocol_and_unix_remote_match_caddy() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let mut request = request(Method::GET, "/protocol");
        request.version = http::Version::HTTP_2;
        request.remote_addr = None;
        assert_eq!(respond(&handler, request).status, StatusCode::OK);
        let captured = captured.lock().unwrap();
        let captured = captured.as_ref().expect("mock captured the request");
        assert_eq!(
            captured.params.get("SERVER_PROTOCOL").map(String::as_str),
            Some("HTTP/2.0")
        );
        assert_eq!(
            captured.params.get("REMOTE_ADDR").map(String::as_str),
            Some("@")
        );
        assert_eq!(
            captured.params.get("REMOTE_PORT").map(String::as_str),
            Some("")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_rejects_http_status_lines_like_caddys_mime_parser() {
        // Caddy parses CGI headers with Go's MIME reader: a bare `HTTP/1.1 200 OK` line has no
        // colon and is a protocol error (502), not a status shortcut.
        let (dial, _captured) = spawn_tcp_mock(Behavior::Respond {
            headers: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
            body: b"ok",
            stderr: b"",
            application_status: 0,
            protocol_status: FCGI_REQUEST_COMPLETE,
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        assert_eq!(
            respond(&handler, request(Method::GET, "/status-line")).status,
            StatusCode::BAD_GATEWAY
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_chunked_takes_precedence_over_content_length() {
        // Caddy's `chunked(te)` wins over Content-Length; the decoded body is sent and the
        // mismatched CGI Content-Length is dropped.
        let (dial, _captured) = spawn_tcp_mock(Behavior::Chunked {
            headers: "Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\
                      Content-Length: 999\r\n\r\n",
            chunks: vec!["hello"],
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/chunked"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(body_string(&response), "hello");
        assert!(
            !response.headers.contains_key(http::header::CONTENT_LENGTH),
            "chunked responses must not keep the CGI Content-Length"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_tls_session_sets_ssl_protocol_and_cipher() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        for (version, cipher, expected_protocol, expected_cipher) in [
            (
                caddy_rs_http::TlsVersion::Tls12,
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLSv1.2",
                Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            ),
            (
                caddy_rs_http::TlsVersion::Tls13,
                "TLS_AES_256_GCM_SHA384",
                "TLSv1.3",
                Some("TLS_AES_256_GCM_SHA384"),
            ),
        ] {
            let mut request = request(Method::GET, "/tls");
            request.tls = true;
            request.tls_connection = Some(caddy_rs_http::TlsConnection {
                version,
                cipher_suite: Some(cipher.to_string()),
            });
            assert_eq!(respond(&handler, request).status, StatusCode::OK);
            let captured = captured.lock().unwrap();
            let params = &captured.as_ref().expect("mock captured the request").params;
            assert_eq!(params.get("HTTPS").map(String::as_str), Some("on"));
            assert_eq!(
                params.get("SSL_PROTOCOL").map(String::as_str),
                Some(expected_protocol)
            );
            assert_eq!(
                params.get("SSL_CIPHER").map(String::as_str),
                expected_cipher
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_plain_http_omits_tls_cgi_variables() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        assert_eq!(
            respond(&handler, request(Method::GET, "/plain")).status,
            StatusCode::OK
        );
        let captured = captured.lock().unwrap();
        let params = &captured.as_ref().expect("mock captured the request").params;
        for key in ["HTTPS", "SSL_PROTOCOL", "SSL_CIPHER"] {
            assert_eq!(
                params.get(key),
                None,
                "plain HTTP must not set {key}: {params:?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_location_without_status_is_a_302() {
        // Caddy: no `Status:` header but a `Location` header implies 302 Found.
        let (dial, _captured) = spawn_tcp_mock(Behavior::Respond {
            headers: "Location: /next\r\nContent-Type: text/plain\r\n\r\n",
            body: b"",
            stderr: b"",
            application_status: 0,
            protocol_status: FCGI_REQUEST_COMPLETE,
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/redirect"));
        assert_eq!(response.status, StatusCode::FOUND);
        assert_eq!(response.headers[http::header::LOCATION], "/next");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_response_body_is_bounded_by_declared_content_length() {
        // Caddy's `declaredBody` truncates the FastCGI STDOUT stream to the parsed
        // Content-Length and discards surplus bytes while still draining to END_REQUEST.
        let (dial, _captured) = spawn_tcp_mock(Behavior::Respond {
            headers: "Content-Type: text/plain\r\nContent-Length: 5\r\n\r\n",
            body: b"hello-world",
            stderr: b"",
            application_status: 0,
            protocol_status: FCGI_REQUEST_COMPLETE,
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/bounded"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.headers[http::header::CONTENT_LENGTH], "5");
        assert_eq!(
            body_string(&response),
            "hello",
            "surplus body bytes are discarded"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_body_is_suppressed_for_no_body_statuses_and_head() {
        let (dial, _captured) = spawn_tcp_mock(Behavior::Respond {
            headers: "Status: 204 No Content\r\n\r\n",
            body: b"should-not-appear",
            stderr: b"",
            application_status: 0,
            protocol_status: FCGI_REQUEST_COMPLETE,
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::GET, "/no-content"));
        assert_eq!(response.status, StatusCode::NO_CONTENT);
        assert!(response.body.is_empty(), "204 responses carry no body");

        // HEAD responses must not carry a body either (Caddy's bodyAllowed rule).
        let (dial, _captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let response = respond(&handler, request(Method::HEAD, "/head"));
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty(), "HEAD responses carry no body");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_configured_env_wins_over_client_headers_and_duplicates_join() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(
            &dial,
            transport_json(serde_json::json!({"env": {"HTTP_X_FOO": "configured"}})),
        );
        let mut request = request(Method::GET, "/env");
        request
            .headers
            .insert("x-foo", "from-client".parse().unwrap());
        request.headers.append("x-multi", "a".parse().unwrap());
        request.headers.append("x-multi", "b".parse().unwrap());
        assert_eq!(respond(&handler, request).status, StatusCode::OK);
        let captured = captured.lock().unwrap();
        let captured = captured.as_ref().expect("mock captured the request");
        assert_eq!(
            captured.params.get("HTTP_X_FOO").map(String::as_str),
            Some("configured"),
            "configured env is applied after headers so a client cannot override it"
        );
        assert_eq!(
            captured.params.get("HTTP_X_MULTI").map(String::as_str),
            Some("a, b")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_script_variables_use_the_decoded_cleaned_path() {
        // Caddy derives SCRIPT_NAME/DOCUMENT_URI/PATH_INFO from `NormalizedPath(r.URL.Path)`:
        // percent-decoded, `.`/`..`/duplicate slashes cleaned.
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(
            &dial,
            transport_json(serde_json::json!({
                "root": "/srv/www",
                "split_path": [".php"]
            })),
        );
        let request = request(Method::GET, "/dir%20name/a/../script.php/more?x=1");
        assert_eq!(respond(&handler, request).status, StatusCode::OK);
        let captured = captured.lock().unwrap();
        let captured = captured.as_ref().expect("mock captured the request");
        for (key, expected) in [
            ("SCRIPT_NAME", "/dir name/script.php"),
            ("DOCUMENT_URI", "/dir name/script.php"),
            ("PATH_INFO", "/more"),
            ("SCRIPT_FILENAME", "/srv/www/dir name/script.php"),
            ("QUERY_STRING", "x=1"),
            // REQUEST_URI stays the original (encoded) client URI, like Caddy's OriginalRequest.
            ("REQUEST_URI", "/dir%20name/a/../script.php/more?x=1"),
        ] {
            assert_eq!(
                captured.params.get(key).map(String::as_str),
                Some(expected),
                "{key}: {captured:?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_multibyte_path_splits_like_the_ascii_equivalent() {
        // SEC-L9-PROXY: `GET /caf%C3%A9/x.php` panicked ("byte index 5 is not a char boundary")
        // because the split scan sliced the decoded multibyte `fpath` at byte offsets. The split
        // must be byte-oriented and identical to the ASCII-equivalent path.
        async fn capture(uri: &str) -> BTreeMap<String, String> {
            let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
            let handler = build_handler(
                &dial,
                transport_json(serde_json::json!({
                    "root": "/srv/www",
                    "split_path": [".php"]
                })),
            );
            assert_eq!(
                respond(&handler, request(Method::GET, uri)).status,
                StatusCode::OK
            );
            let captured = captured.lock().unwrap();
            captured
                .as_ref()
                .expect("mock captured the request")
                .params
                .clone()
        }

        // Exact reviewer reproduction: no panic, whole decoded path is the script.
        let exact = capture("/caf%C3%A9/x.php").await;
        assert_eq!(exact["SCRIPT_NAME"], "/caf\u{e9}/x.php");
        assert_eq!(exact["DOCUMENT_URI"], "/caf\u{e9}/x.php");
        assert_eq!(exact["SCRIPT_FILENAME"], "/srv/www/caf\u{e9}/x.php");
        assert_eq!(exact["PATH_INFO"], "");

        let multibyte = capture("/caf%C3%A9/x.php/more").await;
        assert_eq!(multibyte["SCRIPT_NAME"], "/caf\u{e9}/x.php");
        assert_eq!(multibyte["DOCUMENT_URI"], "/caf\u{e9}/x.php");
        assert_eq!(multibyte["SCRIPT_FILENAME"], "/srv/www/caf\u{e9}/x.php");
        assert_eq!(multibyte["PATH_INFO"], "/more");
        assert_eq!(multibyte["PATH_TRANSLATED"], "/srv/www/more");

        // Same split offsets as the ASCII path: DOCUMENT_URI + PATH_INFO == decoded path.
        let ascii = capture("/cafe/x.php/more").await;
        for (key, value) in [
            ("DOCUMENT_URI", "/cafe/x.php"),
            ("PATH_INFO", "/more"),
            ("SCRIPT_FILENAME", "/srv/www/cafe/x.php"),
        ] {
            assert_eq!(ascii[key], value, "{key}: {ascii:?}");
        }
        assert_eq!(
            format!("{}{}", multibyte["DOCUMENT_URI"], multibyte["PATH_INFO"]),
            "/caf\u{e9}/x.php/more"
        );
        assert_eq!(
            format!("{}{}", ascii["DOCUMENT_URI"], ascii["PATH_INFO"]),
            "/cafe/x.php/more"
        );
    }

    /// SEC-FU-FASTCGI-WRITE-TRUNC: `write_request` truncates an over-budget parameter value to
    /// `MAX_WRITE - 8 - name.len()` bytes. The cut must land on a UTF-8 character boundary
    /// (slicing a `&str` mid-character panics, which the release profile's `panic = "abort"`
    /// turns into a process kill) and must never exceed the byte budget.
    #[tokio::test]
    async fn fastcgi_over_long_param_values_truncate_on_a_char_boundary() {
        const NAME: &str = "HTTP_X_LONG";
        let budget = MAX_WRITE - 8 - NAME.len();

        /// Write one over-long-able parameter and decode what the upstream would receive.
        async fn write(value: &str) -> String {
            let transport = FastCgiTransport::from_json(
                &transport_json(serde_json::json!({ "root": "/srv/www" })),
                "transport",
            )
            .expect("fastcgi transport builds");
            let params = BTreeMap::from([(NAME.to_string(), value.to_string())]);
            let mut written = Vec::new();
            transport
                .write_request(&mut written, &params, RequestBody::empty(), None)
                .await
                .expect("request writes");

            let mut reader: &[u8] = &written;
            let mut params_bytes = Vec::new();
            loop {
                let record = read_record(&mut reader, None).await.expect("record parses");
                match record.kind {
                    FCGI_PARAMS => params_bytes.extend_from_slice(&record.content),
                    FCGI_STDIN => break,
                    _ => {}
                }
            }
            decode_params(&params_bytes)
                .remove(NAME)
                .expect("truncated parameter is present")
        }

        // (a) ASCII: truncated to exactly the byte budget, byte-for-byte the same as before.
        let written = write(&"a".repeat(MAX_WRITE)).await;
        assert_eq!(written, "a".repeat(budget));

        // (b) Multibyte with the cut inside a character: no panic, <= budget, char boundary.
        // `budget` (65481) is odd, so the trailing half of the last 2-byte `é` does not fit.
        let multibyte = "\u{e9}".repeat(MAX_WRITE); // 2 bytes each => 131 000 bytes.
        let written = write(&multibyte).await;
        assert!(written.len() <= budget, "{} > {budget}", written.len());
        assert!(written.is_char_boundary(written.len()));
        assert!(multibyte.starts_with(&written));
        assert_eq!(written, "\u{e9}".repeat(budget / 2));

        // (c) A value shorter than the budget is untouched.
        let short = "\u{e9}".repeat(100);
        assert_eq!(write(&short).await, short);

        // The boundary helper never splits a character and never exceeds `max`.
        assert_eq!(floor_char_boundary("\u{e9}", 1), 0);
        assert_eq!(floor_char_boundary("\u{e9}", 2), 2);
        assert_eq!(floor_char_boundary("abc", 2), 2);
        assert_eq!(floor_char_boundary("abc", usize::MAX), 3);
    }

    /// Records the events tracing emits on the test thread, so the truncation warning can be
    /// asserted without installing a logging backend.
    #[derive(Clone, Default)]
    struct CapturedWarnings(Arc<Mutex<Vec<String>>>);

    impl tracing::Subscriber for CapturedWarnings {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        // Without a level hint a thread-local subscriber may lose the race against the global
        // level filter (other tests exercise the same callsite concurrently), so declare the
        // most permissive filter explicitly.
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct Visitor {
                message: String,
                fields: Vec<String>,
            }
            impl tracing::field::Visit for Visitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.message = format!("{value:?}");
                    } else {
                        self.fields.push(format!("{}={value:?}", field.name()));
                    }
                }
            }
            let mut visitor = Visitor {
                message: String::new(),
                fields: Vec::new(),
            };
            event.record(&mut visitor);
            self.0.lock().unwrap().push(format!(
                "{} {} | {}",
                event.metadata().level(),
                visitor.message,
                visitor.fields.join(" ")
            ));
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// SEC-FU-FASTCGI-PARAM-TRUNC-POLICY: truncation is kept for Caddy parity, so it must not be
    /// silent. One WARN per request names every shortened parameter and its byte lengths; the
    /// value itself (which may be a credential or attacker-controlled) must never be logged.
    #[tokio::test]
    async fn fastcgi_over_long_params_warn_once_with_names_and_lengths_only() {
        fn transport() -> FastCgiTransport {
            FastCgiTransport::from_json(
                &transport_json(serde_json::json!({ "root": "/srv/www" })),
                "transport",
            )
            .expect("fastcgi transport builds")
        }

        async fn write(transport: &FastCgiTransport, params: BTreeMap<String, String>) {
            transport
                .write_request(&mut Vec::new(), &params, RequestBody::empty(), None)
                .await
                .expect("request writes");
        }

        let warnings = CapturedWarnings::default();
        let guard = tracing::subscriber::set_default(warnings.clone());
        // Other truncation tests trigger the same callsite concurrently with no subscriber
        // installed, which can win the lazy callsite-registration race against this thread-local
        // dispatch; rebuild the interest cache and retry until the event reaches this subscriber.
        let mut events = Vec::new();
        for _ in 0..20 {
            tracing::callsite::rebuild_interest_cache();
            let params = BTreeMap::from([
                ("HTTP_X_LONG".to_string(), "a".repeat(MAX_WRITE)),
                ("QUERY_STRING".to_string(), "\u{e9}".repeat(MAX_WRITE)),
            ]);
            write(&transport(), params).await;
            events = warnings.0.lock().unwrap().clone();
            if !events.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        drop(guard);

        let events = warnings.0.lock().unwrap().clone();
        assert_eq!(
            events.len(),
            1,
            "exactly one warning per request: {events:?}"
        );
        let event = &events[0];
        assert!(event.starts_with("WARN"), "{event}");
        assert!(event.contains("HTTP_X_LONG 65500B->65481B"), "{event}");
        assert!(event.contains("QUERY_STRING 131000B->65480B"), "{event}");
        // Names and lengths only: neither repeated filler value may appear in the event.
        assert!(!event.contains("aaaaaaaa"), "{event}");
        assert!(!event.contains('\u{e9}'), "{event}");

        // A request whose parameters all fit emits no warning at all.
        let warnings = CapturedWarnings::default();
        let guard = tracing::subscriber::set_default(warnings.clone());
        tracing::callsite::rebuild_interest_cache();
        let params = BTreeMap::from([("QUERY_STRING".to_string(), "q=1".to_string())]);
        write(&transport(), params).await;
        drop(guard);
        assert!(
            warnings.0.lock().unwrap().is_empty(),
            "no warning without truncation"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_script_filename_valid_path_within_root() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(
            &dial,
            transport_json(serde_json::json!({
                "root": "/var/www",
                "split_path": [".php"]
            })),
        );
        let request = request(Method::GET, "/index.php");
        let response = respond(&handler, request);
        assert_eq!(response.status, StatusCode::OK);
        let captured = captured.lock().unwrap();
        let params = &captured.as_ref().expect("mock captured the request").params;
        assert_eq!(params["SCRIPT_FILENAME"], "/var/www/index.php");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_script_filename_escapes_root_is_rejected() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(
            &dial,
            transport_json(serde_json::json!({
                "root": "/var/www",
                "split_path": [".php"]
            })),
        );
        let response = respond(&handler, request(Method::GET, "/../etc/passwd"));
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(
            captured.lock().unwrap().is_none(),
            "an escaping SCRIPT_FILENAME must be rejected before connecting to the upstream"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_null_byte_path_is_rejected_with_400() {
        // Caddy rejects NUL bytes in the request path with 400 before dialing (PHP may execute a
        // non-PHP file as code otherwise, Caddy #4574).
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(
            &dial,
            transport_json(serde_json::json!({"split_path": [".php"]})),
        );
        let response = respond(&handler, request(Method::GET, "/evil%00.php"));
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(
            captured.lock().unwrap().is_none(),
            "a NUL path must be rejected before connecting to the upstream"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_server_addr_comes_from_the_local_address() {
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        let mut request = request(Method::GET, "/addr");
        request.vars.insert(
            "http.request.local.host".to_string(),
            "127.0.0.1".to_string(),
        );
        assert_eq!(respond(&handler, request).status, StatusCode::OK);
        let captured = captured.lock().unwrap();
        assert_eq!(
            captured
                .as_ref()
                .expect("mock captured the request")
                .params
                .get("SERVER_ADDR")
                .map(String::as_str),
            Some("127.0.0.1")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_read_timeout_is_an_absolute_connection_deadline() {
        // Caddy sets one read deadline after dialing, so several short gaps still exceed the
        // configured timeout in total; a per-operation timeout would incorrectly succeed.
        let (dial, _captured) = spawn_tcp_mock(Behavior::SlowRecords {
            headers: "Content-Type: text/plain\r\n\r\n",
            chunks: vec![b"a", b"b", b"c", b"d", b"e"],
            gap: TokioDuration::from_millis(50),
        })
        .await;
        let handler = build_handler(
            &dial,
            transport_json(serde_json::json!({"read_timeout": 150_000_000u64})),
        );
        let response = respond(&handler, request(Method::GET, "/slow"));
        assert_eq!(
            response.status,
            StatusCode::BAD_GATEWAY,
            "the absolute read deadline must fail the response body"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_malformed_records_are_rejected() {
        // Wrong FastCGI version: header 8 bytes with version 2.
        let (dial, _captured) = spawn_tcp_mock(Behavior::Raw {
            bytes: vec![2, FCGI_STDOUT, 0, 1, 0, 0, 0, 0],
            keep_open: true,
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        assert_eq!(
            respond(&handler, request(Method::GET, "/bad-version")).status,
            StatusCode::BAD_GATEWAY
        );

        // Wrong request id for a valid version-1 record.
        let (dial, _captured) = spawn_tcp_mock(Behavior::Raw {
            bytes: vec![FCGI_VERSION_1, FCGI_STDOUT, 0, 9, 0, 0, 0, 0],
            keep_open: true,
        })
        .await;
        let handler = build_handler(&dial, transport_json(serde_json::json!({})));
        assert_eq!(
            respond(&handler, request(Method::GET, "/bad-id")).status,
            StatusCode::BAD_GATEWAY
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fastcgi_resolve_root_symlink_canonicalizes_document_root() {
        let directory = tempfile::tempdir().unwrap();
        let real_root = directory.path().join("real-root");
        std::fs::create_dir(&real_root).unwrap();
        let link = directory.path().join("link-root");
        std::os::unix::fs::symlink(&real_root, &link).unwrap();
        let (dial, captured) = spawn_tcp_mock(Behavior::responds(0)).await;
        let handler = build_handler(
            &dial,
            transport_json(serde_json::json!({
                "root": link.display().to_string(),
                "resolve_root_symlink": true
            })),
        );
        assert_eq!(
            respond(&handler, request(Method::GET, "/x")).status,
            StatusCode::OK
        );
        let captured = captured.lock().unwrap();
        let canonical = std::fs::canonicalize(&real_root).unwrap();
        assert_eq!(
            captured
                .as_ref()
                .expect("mock captured the request")
                .params
                .get("DOCUMENT_ROOT")
                .map(String::as_str),
            Some(canonical.to_string_lossy().as_ref())
        );
    }
}
