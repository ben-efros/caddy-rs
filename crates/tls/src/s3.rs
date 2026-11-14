//! S3-compatible certificate/account storage (T-TLS-022).
//!
//! Caddy v2.11.7 ships only `caddy.storage.file_system`; the well-known
//! `caddy.storage.s3` module is a community plugin, so this backend is a **caddy-rs extension**
//! configured as `{"module": "s3", ...}`. It implements the existing
//! [`CertificateStorage`](crate::storage::CertificateStorage) and
//! [`AcmeStorage`](crate::acme::AcmeStorage) traits over a small S3 REST client:
//! `GET`/`HEAD`/`PUT`/`DELETE` plus `ListObjectsV2` with pagination, SigV4 signing, path-style
//! or virtual-host addressing, and an injectable transport (tests use a scripted mock, the same
//! [`AcmeTransport`] abstraction the ACME/Route53 clients use).
//!
//! Locks are simplified: `lock` performs a conditional `PUT` with `If-None-Match: *` under
//! `locks/<name>` and `unlock` deletes it. CertMagic's full lock contract (expiry, refresh,
//! multi-process coordination) is not implemented; see the module docs on `storage` and the task
//! report.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::acme::{AcmeTransport, HttpMethod, HttpRequest, HttpResponse};
use crate::renewal::{RenewalClock, SystemClock};
use crate::sigv4::{
    aws_uri_encode, canonical_query, format_amz_date, sign_sigv4, AwsCredentials, SigV4Request,
};

/// Errors from the S3-compatible backend.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum S3Error {
    /// Invalid S3 settings.
    #[error("invalid s3 storage configuration: {0}")]
    Config(String),
    /// The injected HTTP transport failed.
    #[error("s3 transport failed: {0}")]
    Transport(String),
    /// The server returned an unexpected status or an S3 error document.
    #[error("s3 request to `{url}` failed with status {status}: {code}: {message}")]
    Http {
        /// Request URL (bucket/key only; no credentials).
        url: String,
        /// HTTP status.
        status: u16,
        /// S3 error code (`Code`), when present.
        code: String,
        /// S3 error message (`Message`), when present.
        message: String,
    },
    /// Malformed `ListObjectsV2` XML.
    #[error("malformed S3 response: {0}")]
    Malformed(String),
    /// A lock object already exists.
    #[error("s3 lock is already held: {0}")]
    LockHeld(String),
}

impl From<S3Error> for crate::Error {
    fn from(error: S3Error) -> Self {
        crate::Error::Storage(error.to_string())
    }
}

/// Settings for the S3-compatible backend.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Settings {
    /// Endpoint base URL (for example `https://s3.us-east-1.amazonaws.com` or a MinIO URL).
    pub endpoint: String,
    /// Bucket name.
    pub bucket: String,
    /// AWS region used for SigV4.
    pub region: String,
    /// Key prefix below the bucket (empty or ending with `/`).
    pub prefix: String,
    /// Path-style addressing (`endpoint/bucket/key`) instead of virtual-host addressing.
    pub path_style: bool,
    /// AWS credentials.
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl fmt::Debug for S3Settings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3Settings")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

fn config_error(message: impl Into<String>) -> S3Error {
    S3Error::Config(message.into())
}

fn setting_string(
    extra: &std::collections::BTreeMap<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<String>, S3Error> {
    let Some(value) = extra.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| config_error(format!("`{path}.{key}` must be a string")))?;
    crate::cloudflare::resolve_env_placeholders(text)
        .map_err(|error| config_error(format!("`{path}.{key}`: {error}")))
        .map(Some)
}

impl S3Settings {
    /// Parse `{"module":"s3",...}` settings from a Caddy storage module object.
    pub fn from_storage_config(
        storage: &caddy_rs_core::config::StorageConfig,
        path: &str,
    ) -> Result<Self, S3Error> {
        let extra = &storage.extra;
        let region = setting_string(extra, "region", path)?
            .or_else(|| std::env::var("AWS_REGION").ok())
            .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
            .unwrap_or_else(|| "us-east-1".to_string());
        let bucket = setting_string(extra, "bucket", path)?
            .or_else(|| std::env::var("AWS_BUCKET").ok())
            .ok_or_else(|| config_error(format!("`{path}.bucket` is required")))?;
        if bucket.is_empty() || bucket.contains('/') {
            return Err(config_error(format!(
                "`{path}.bucket` must be a non-empty bucket name without `/`"
            )));
        }
        let endpoint = match setting_string(extra, "endpoint", path)? {
            Some(endpoint) => endpoint,
            None => format!("https://s3.{region}.amazonaws.com"),
        };
        if !(endpoint.starts_with("https://") || endpoint.starts_with("http://")) {
            return Err(config_error(format!(
                "`{path}.endpoint` must start with `http://` or `https://` (got `{endpoint}`)"
            )));
        }
        let path_style = match extra.get("path_style") {
            Some(serde_json::Value::Bool(value)) => *value,
            Some(_) => {
                return Err(config_error(format!(
                    "`{path}.path_style` must be a boolean"
                )))
            }
            // AWS endpoints use virtual-host addressing by default; custom endpoints (MinIO) use
            // path-style so a single-IP MinIO needs no wildcard DNS.
            None => !endpoint.contains("amazonaws.com"),
        };
        let prefix = setting_string(extra, "prefix", path)?.unwrap_or_default();
        let prefix = if prefix.is_empty() {
            String::new()
        } else if prefix.ends_with('/') {
            prefix
        } else {
            format!("{prefix}/")
        };
        let access_key_id = setting_string(extra, "access_key_id", path)?
            .or_else(|| std::env::var("AWS_ACCESS_KEY_ID").ok())
            .ok_or_else(|| {
                config_error(format!(
                    "`{path}.access_key_id` (or AWS_ACCESS_KEY_ID) is required"
                ))
            })?;
        let secret_access_key = setting_string(extra, "secret_access_key", path)?
            .or_else(|| std::env::var("AWS_SECRET_ACCESS_KEY").ok())
            .ok_or_else(|| {
                config_error(format!(
                    "`{path}.secret_access_key` (or AWS_SECRET_ACCESS_KEY) is required"
                ))
            })?;
        let session_token = setting_string(extra, "session_token", path)?
            .or_else(|| std::env::var("AWS_SESSION_TOKEN").ok());
        Ok(Self {
            endpoint,
            bucket,
            region,
            prefix,
            path_style,
            access_key_id,
            secret_access_key,
            session_token,
        })
    }

    fn credentials(&self) -> AwsCredentials {
        AwsCredentials {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
        }
    }

    /// Object key with the configured prefix.
    pub fn object_key(&self, key: &str) -> String {
        format!("{}{}", self.prefix, key.trim_start_matches('/'))
    }
}

/// S3 REST client used by the storage backend.
pub struct S3Client {
    settings: S3Settings,
    transport: Arc<dyn AcmeTransport>,
    clock: Arc<dyn RenewalClock>,
}

impl fmt::Debug for S3Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3Client")
            .field("settings", &self.settings)
            .finish()
    }
}

impl S3Client {
    /// Create a client with the production clock.
    pub fn new(settings: S3Settings, transport: Arc<dyn AcmeTransport>) -> Self {
        Self::with_clock(settings, transport, Arc::new(SystemClock))
    }

    /// Create a client with an injected clock (deterministic SigV4 tests).
    pub fn with_clock(
        settings: S3Settings,
        transport: Arc<dyn AcmeTransport>,
        clock: Arc<dyn RenewalClock>,
    ) -> Self {
        Self {
            settings,
            transport,
            clock,
        }
    }

    /// The settings in use.
    pub fn settings(&self) -> &S3Settings {
        &self.settings
    }

    fn request_target(
        &self,
        key: &str,
        query: &[(String, String)],
    ) -> Result<(String, String, String), S3Error> {
        let (scheme, rest) = self
            .settings
            .endpoint
            .split_once("://")
            .ok_or_else(|| config_error("S3 endpoint has no scheme"))?;
        let (authority, base_path) = match rest.split_once('/') {
            Some((authority, path)) => {
                let path = path.trim_matches('/');
                (
                    authority.to_string(),
                    if path.is_empty() {
                        String::new()
                    } else {
                        format!("/{path}")
                    },
                )
            }
            None => (rest.to_string(), String::new()),
        };
        let encoded_key = key
            .split('/')
            .filter(|segment| !segment.is_empty())
            .map(aws_uri_encode)
            .collect::<Vec<_>>()
            .join("/");
        let (url_host, canonical_path) = if self.settings.path_style {
            let mut path = format!("{base_path}/{bucket}", bucket = self.settings.bucket);
            if !encoded_key.is_empty() {
                path.push('/');
                path.push_str(&encoded_key);
            }
            (authority, path)
        } else {
            let host = format!("{}.{}", self.settings.bucket, authority);
            let mut path = format!("{base_path}/");
            path.push_str(&encoded_key);
            (host, path)
        };
        let query_string = canonical_query(query);
        let url = if query_string.is_empty() {
            format!("{scheme}://{url_host}{canonical_path}")
        } else {
            format!("{scheme}://{url_host}{canonical_path}?{query_string}")
        };
        Ok((url, url_host, canonical_path))
    }

    async fn send(
        &self,
        method: HttpMethod,
        key: &str,
        query: &[(String, String)],
        body: Vec<u8>,
        extra_headers: &[(&str, &str)],
    ) -> Result<HttpResponse, S3Error> {
        let (url, host, canonical_path) = self.request_target(key, query)?;
        let amz_date = format_amz_date(self.clock.now());
        let credentials = self.settings.credentials();
        let signed = sign_sigv4(SigV4Request {
            method: method.as_str(),
            host: &host,
            path: &canonical_path,
            query,
            payload: &body,
            extra_headers,
            credentials: &credentials,
            region: &self.settings.region,
            service: "s3",
            amz_date: &amz_date,
        });
        let headers: Vec<(String, String)> = signed
            .into_iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
            .collect();
        let request = HttpRequest {
            method,
            url: url.clone(),
            headers,
            body,
        };
        self.transport
            .request(request)
            .await
            .map_err(|error| S3Error::Transport(format!("{error}")))
    }

    /// GET an object; `Ok(None)` for a missing key.
    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, S3Error> {
        let response = self
            .send(HttpMethod::Get, key, &[], Vec::new(), &[])
            .await?;
        match response.status {
            200 => Ok(Some(response.body)),
            404 => Ok(None),
            status => Err(self.http_error(key, status, &response.body)),
        }
    }

    /// HEAD an object; returns its size for an existing key.
    pub async fn head(&self, key: &str) -> Result<Option<u64>, S3Error> {
        let response = self
            .send(HttpMethod::Head, key, &[], Vec::new(), &[])
            .await?;
        match response.status {
            200 => Ok(response
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.parse().ok())
                .or(Some(0))),
            404 => Ok(None),
            status => Err(self.http_error(key, status, &response.body)),
        }
    }

    /// PUT an object (also used for conditional lock creation via `extra_headers`).
    pub async fn put(
        &self,
        key: &str,
        body: Vec<u8>,
        extra_headers: &[(&str, &str)],
    ) -> Result<(), S3Error> {
        let mut headers = vec![("content-type", "application/octet-stream")];
        headers.extend_from_slice(extra_headers);
        let response = self.send(HttpMethod::Put, key, &[], body, &headers).await?;
        match response.status {
            200 | 201 | 204 => Ok(()),
            409 | 412 => Err(S3Error::LockHeld(key.to_string())),
            status => Err(self.http_error(key, status, &response.body)),
        }
    }

    /// DELETE an object; missing keys are not an error (idempotent).
    pub async fn delete(&self, key: &str) -> Result<(), S3Error> {
        let response = self
            .send(HttpMethod::Delete, key, &[], Vec::new(), &[])
            .await?;
        match response.status {
            200 | 204 | 404 => Ok(()),
            status => Err(self.http_error(key, status, &response.body)),
        }
    }

    /// List all object keys under `prefix` (handles `ListObjectsV2` pagination).
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, S3Error> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut query = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), prefix.to_string()),
            ];
            if let Some(token) = &continuation {
                query.push(("continuation-token".to_string(), token.clone()));
            }
            let response = self
                .send(HttpMethod::Get, "", &query, Vec::new(), &[])
                .await?;
            if response.status != 200 {
                return Err(self.http_error(prefix, response.status, &response.body));
            }
            let page = parse_list_objects(&response.body)?;
            keys.extend(page.keys);
            match page.next_continuation_token {
                Some(token) if page.is_truncated => continuation = Some(token),
                _ => break,
            }
        }
        Ok(keys)
    }

    /// Acquire a simplified storage lock (`PUT locks/<name>` with `If-None-Match: *`).
    pub async fn lock(&self, name: &str) -> Result<(), S3Error> {
        let key = format!("locks/{}", name.trim_start_matches('/'));
        self.put(&key, Vec::new(), &[("if-none-match", "*")]).await
    }

    /// Release a storage lock.
    pub async fn unlock(&self, name: &str) -> Result<(), S3Error> {
        let key = format!("locks/{}", name.trim_start_matches('/'));
        self.delete(&key).await
    }

    fn http_error(&self, key: &str, status: u16, body: &[u8]) -> S3Error {
        let document = String::from_utf8_lossy(body);
        let code = xml_value(&document, "Code").unwrap_or_default();
        let message = xml_value(&document, "Message").unwrap_or_default();
        S3Error::Http {
            url: self.settings.object_key(key),
            status,
            code,
            message,
        }
    }
}

struct ListObjectsPage {
    keys: Vec<String>,
    is_truncated: bool,
    next_continuation_token: Option<String>,
}

fn parse_list_objects(xml: &[u8]) -> Result<ListObjectsPage, S3Error> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut keys = Vec::new();
    let mut is_truncated = false;
    let mut next_continuation_token = None;
    let mut current_tag = String::new();
    let mut inside_contents = false;
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = String::from_utf8_lossy(element.name().as_ref()).into_owned();
                if name == "Contents" {
                    inside_contents = true;
                }
                current_tag = name;
            }
            Ok(Event::End(element)) => {
                let name = String::from_utf8_lossy(element.name().as_ref()).into_owned();
                if name == "Contents" {
                    inside_contents = false;
                }
                current_tag.clear();
            }
            Ok(Event::Text(text)) => {
                let value = unescape_xml(&String::from_utf8_lossy(text.as_ref()));
                match current_tag.as_str() {
                    "Key" if inside_contents => keys.push(value),
                    "IsTruncated" => is_truncated = value.eq_ignore_ascii_case("true"),
                    "NextContinuationToken" => next_continuation_token = Some(value),
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(S3Error::Malformed(error.to_string())),
        }
    }
    Ok(ListObjectsPage {
        keys,
        is_truncated,
        next_continuation_token,
    })
}

fn xml_value(document: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = document.find(&open)? + open.len();
    let end = document[start..].find(&close)? + start;
    Some(unescape_xml(document[start..end].trim()))
}

fn unescape_xml(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// S3-backed certificate and ACME account storage.
pub struct S3Storage {
    client: S3Client,
}

impl fmt::Debug for S3Storage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3Storage")
            .field("client", &self.client)
            .finish()
    }
}

impl S3Storage {
    /// Build from settings and a transport.
    pub fn new(settings: S3Settings, transport: Arc<dyn AcmeTransport>) -> Self {
        Self {
            client: S3Client::new(settings, transport),
        }
    }

    /// Build with an injected clock (SigV4 tests).
    pub fn with_clock(
        settings: S3Settings,
        transport: Arc<dyn AcmeTransport>,
        clock: Arc<dyn RenewalClock>,
    ) -> Self {
        Self {
            client: S3Client::with_clock(settings, transport, clock),
        }
    }

    /// The underlying client (for lock tests/inspection).
    pub fn client(&self) -> &S3Client {
        &self.client
    }

    fn certificate_prefix(&self, key: &str) -> String {
        self.client
            .settings
            .object_key(&format!("certificates/{key}"))
    }

    /// Acquire the CertMagic lock object for `name` (simplified; see module docs).
    pub async fn lock(&self, name: &str) -> Result<(), S3Error> {
        self.client.lock(name).await
    }

    /// Release the CertMagic lock object for `name`.
    pub async fn unlock(&self, name: &str) -> Result<(), S3Error> {
        self.client.unlock(name).await
    }
}

#[async_trait]
impl crate::storage::CertificateStorage for S3Storage {
    fn name(&self) -> &'static str {
        "s3"
    }

    async fn load(&self, key: &str) -> crate::Result<Option<crate::storage::StoredCertificate>> {
        use crate::storage::{
            caddy_certificate_name_from_storage, certificate_chain_pem, certificate_not_after_unix,
            private_key_pem, split_storage_key, CaddyCertificateMetadata,
        };
        let prefix = self.certificate_prefix(key);
        let Some(certificate_bytes) = self
            .client
            .get(&format!("{prefix}.crt"))
            .await
            .map_err(crate::Error::from)?
        else {
            return Ok(None);
        };
        let certificate_text = String::from_utf8(certificate_bytes).map_err(|error| {
            crate::Error::Storage(format!("S3 object `{key}.crt` is not UTF-8 PEM: {error}"))
        })?;
        let certificate_pem = certificate_chain_pem(&certificate_text)?;
        let private_key_bytes = self
            .client
            .get(&format!("{prefix}.key"))
            .await
            .map_err(crate::Error::from)?
            .ok_or_else(|| {
                crate::Error::Storage(format!(
                    "S3 certificate `{key}` has no private key object `{prefix}.key`"
                ))
            })?;
        let private_key_text = String::from_utf8(private_key_bytes).map_err(|error| {
            crate::Error::Storage(format!("S3 object `{key}.key` is not UTF-8 PEM: {error}"))
        })?;
        let private_key_pem = private_key_pem(&private_key_text)?;
        let metadata = self
            .client
            .get(&format!("{prefix}.json"))
            .await
            .map_err(crate::Error::from)?;
        let (_, stored_name) = split_storage_key(key)?;
        let (domains, issuer_data, metadata_extra) = match metadata {
            Some(bytes) => {
                let metadata: CaddyCertificateMetadata =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        crate::Error::Storage(format!(
                            "cannot decode S3 certificate metadata `{key}.json`: {error}"
                        ))
                    })?;
                let domains = match metadata.sans {
                    Some(sans) if !sans.is_empty() => sans,
                    _ => vec![caddy_certificate_name_from_storage(&stored_name)],
                };
                (domains, metadata.issuer_data, metadata.extra)
            }
            None => (
                vec![caddy_certificate_name_from_storage(&stored_name)],
                None,
                Default::default(),
            ),
        };
        let not_after_unix = certificate_not_after_unix(&certificate_pem[0])?;
        Ok(Some(crate::storage::StoredCertificate {
            certificate_pem,
            private_key_pem,
            token_key: None,
            domains,
            not_after_unix,
            issuer_data,
            metadata_extra,
        }))
    }

    async fn store(
        &self,
        key: &str,
        certificate: &crate::storage::StoredCertificate,
    ) -> crate::Result<()> {
        use crate::storage::serialize_certificate_metadata;
        if certificate.certificate_pem.is_empty() {
            return Err(crate::Error::Storage(format!(
                "certificate `{key}` has an empty PEM chain"
            )));
        }
        let prefix = self.certificate_prefix(key);
        let mut chain = String::new();
        for block in &certificate.certificate_pem {
            chain.push_str(block.trim_end());
            chain.push('\n');
        }
        self.client
            .put(&format!("{prefix}.crt"), chain.into_bytes(), &[])
            .await
            .map_err(crate::Error::from)?;
        let mut key_pem = certificate.private_key_pem.trim_end().to_string();
        key_pem.push('\n');
        self.client
            .put(&format!("{prefix}.key"), key_pem.into_bytes(), &[])
            .await
            .map_err(crate::Error::from)?;
        let metadata = serialize_certificate_metadata(
            &certificate.domains,
            certificate.issuer_data.as_ref(),
            &certificate.metadata_extra,
        )?;
        self.client
            .put(&format!("{prefix}.json"), metadata, &[])
            .await
            .map_err(crate::Error::from)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> crate::Result<()> {
        let prefix = self.certificate_prefix(key);
        for suffix in [".crt", ".key", ".json"] {
            self.client
                .delete(&format!("{prefix}{suffix}"))
                .await
                .map_err(crate::Error::from)?;
        }
        Ok(())
    }

    async fn list(&self, prefix: &str) -> crate::Result<Vec<String>> {
        let base = self.client.settings.object_key("certificates");
        let base = format!("{base}/");
        let objects = self.client.list(&base).await.map_err(crate::Error::from)?;
        let mut keys = Vec::new();
        for object in objects {
            let Some(relative) = object.strip_prefix(&base) else {
                continue;
            };
            let Some(key) = relative.strip_suffix(".crt") else {
                continue;
            };
            if prefix.is_empty() || key.starts_with(prefix) {
                keys.push(key.to_string());
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
}

#[async_trait]
impl crate::acme::AcmeStorage for S3Storage {
    fn name(&self) -> &'static str {
        "s3"
    }

    async fn load(&self, key: &str) -> crate::Result<Option<Vec<u8>>> {
        let key = self.client.settings.object_key(key);
        self.client.get(&key).await.map_err(crate::Error::from)
    }

    async fn store(&self, key: &str, value: &[u8]) -> crate::Result<()> {
        let key = self.client.settings.object_key(key);
        self.client
            .put(&key, value.to_vec(), &[])
            .await
            .map_err(crate::Error::from)
    }

    async fn delete(&self, key: &str) -> crate::Result<()> {
        let key = self.client.settings.object_key(key);
        self.client.delete(&key).await.map_err(crate::Error::from)
    }
}

#[cfg(test)]
mod tests;
