//! `encode` response-compression middleware (Caddy `http.handlers.encode`).
//!
//! Mirrors Caddy v2.11.7 `modules/caddyhttp/encode`:
//!
//! * configuration: `{"handler":"encode","encodings":{"gzip":{...},"zstd":{...}},
//!   "prefer":[...],"minimum_length":N,"match":{...}}` (the Caddyfile adapter emits this shape);
//! * negotiation: `Accept-Encoding` q-values with Caddy's `prefer` tie-break (default preference
//!   `zstd, br, gzip` filtered to the enabled encoders), `q=0` rejected, WebSocket handshakes not
//!   encoded, request `Cache-Control: no-transform` honoured;
//! * eligibility: response `Content-Encoding` empty, response `Cache-Control` without
//!   `no-transform`, the response matcher (Caddy's default is a text-ish `Content-Type` list) and
//!   `minimum_length` (default 512; Caddy's check is "first write chunk length > min OR
//!   Content-Length > min");
//! * headers: `Content-Encoding`, `Vary: Accept-Encoding`, removed `Content-Length` and
//!   `Accept-Ranges`, strong ETag suffixed with `-<encoding>` (and the suffix stripped from the
//!   request's `If-None-Match` before downstream handlers run), and `Vary` added to 304 responses;
//! * encoders: gzip via `flate2` (Caddy's default level 5) and zstd via `zstd` (Caddy's default
//!   speed `default`; optional checksum), compressing streaming bodies chunk by chunk rather than
//!   buffering the whole body.
//!
//! Unsupported configuration is rejected loudly: unknown encoder names/options, duplicate or
//! disabled `prefer` entries, malformed response matchers, and gzip levels the Rust backend cannot
//! express (Caddy's negative "stateless" levels). Custom `match` blocks are supported.

use std::io::Write;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use http_body::Body as HttpBody;
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::body::{Body, BodyError, StreamingBody, StreamingResponse};
use crate::types::{Error, Handler, Outcome, Request, ResponseTransform, Result};

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

fn not_implemented(feature: &'static str, tracking_id: &'static str) -> Error {
    Error::NotImplemented {
        feature,
        tracking_id,
    }
}

/// Default `minimum_length` (Caddy's `defaultMinLength`).
const DEFAULT_MIN_LENGTH: i64 = 512;

/// Caddy's default response matcher: `Content-Type` values that benefit from compression.
const DEFAULT_CONTENT_TYPES: &[&str] = &[
    "application/atom+xml*",
    "application/eot*",
    "application/font*",
    "application/geo+json*",
    "application/graphql+json*",
    "application/graphql-response+json*",
    "application/javascript*",
    "application/json*",
    "application/ld+json*",
    "application/manifest+json*",
    "application/opentype*",
    "application/otf*",
    "application/rss+xml*",
    "application/truetype*",
    "application/ttf*",
    "application/vnd.api+json*",
    "application/vnd.ms-fontobject*",
    "application/wasm*",
    "application/x-httpd-cgi*",
    "application/x-javascript*",
    "application/x-opentype*",
    "application/x-otf*",
    "application/x-perl*",
    "application/x-protobuf*",
    "application/x-ttf*",
    "application/xhtml+xml*",
    "application/xml*",
    "font/ttf*",
    "font/otf*",
    "image/svg+xml*",
    "image/vnd.microsoft.icon*",
    "image/x-icon*",
    "multipart/bag*",
    "multipart/mixed*",
    "text/*",
];

/// One enabled encoder and its settings.
#[derive(Debug, Clone)]
struct EncodingConfig {
    name: String,
    kind: EncoderKind,
}

/// Encoder implementation details (validated at configuration load).
#[derive(Debug, Clone)]
enum EncoderKind {
    Gzip { level: u32 },
    Zstd { level: i32, checksum: bool },
}

/// A response-matcher header value.
#[derive(Debug, Clone)]
enum HeaderMatcher {
    /// The field must be absent (`null` in JSON).
    Absent,
    /// The field must be present (empty array in JSON).
    Present,
    /// Caddy wildcard values (`*`, `prefix*`, `*suffix`, `*substring*`, exact).
    Values(Vec<String>),
}

/// Caddy's `ResponseMatcher` subset used by `encode.match`.
#[derive(Debug, Clone, Default)]
struct ResponseMatcher {
    /// `None` matches any status.
    status_codes: Option<Vec<u16>>,
    headers: Vec<(HeaderName, HeaderMatcher)>,
}

impl ResponseMatcher {
    fn matches(&self, status: StatusCode, headers: &HeaderMap) -> bool {
        let status_ok = match &self.status_codes {
            None => true,
            Some(codes) => codes
                .iter()
                .copied()
                .any(|configured| status_matches(status.as_u16(), configured)),
        };
        status_ok
            && self.headers.iter().all(|(name, matcher)| match matcher {
                HeaderMatcher::Absent => !headers.contains_key(name),
                HeaderMatcher::Present => headers.contains_key(name),
                HeaderMatcher::Values(patterns) => headers
                    .get_all(name)
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .any(|value| {
                        patterns
                            .iter()
                            .any(|pattern| header_wildcard_match(pattern, value))
                    }),
            })
    }
}

/// Caddy's `StatusCodeMatches`: a one-digit code matches a whole class.
fn status_matches(actual: u16, configured: u16) -> bool {
    if actual == configured {
        return true;
    }
    configured < 100 && actual >= configured * 100 && actual < (configured + 1) * 100
}

/// Caddy header-matcher wildcard semantics.
fn header_wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        if let Some(substring) = suffix.strip_suffix('*') {
            return value.contains(substring);
        }
        return value.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

/// Validated `encode` configuration.
#[derive(Debug)]
struct EncodeConfig {
    encodings: Vec<EncodingConfig>,
    prefer: Vec<String>,
    min_length: i64,
    matcher: ResponseMatcher,
}

/// Caddy's `http.handlers.encode` middleware.
pub struct EncodeHandler {
    config: Arc<EncodeConfig>,
}

impl EncodeHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "encode handler must be an object"))?;
        for field in object.keys() {
            if !matches!(
                field.as_str(),
                "handler" | "encodings" | "prefer" | "minimum_length" | "match"
            ) {
                return Err(invalid(
                    path,
                    format!("unknown encode field `{field}` (supported: encodings, prefer, minimum_length, match)"),
                ));
            }
        }
        let mut encodings = Vec::new();
        if let Some(configured) = object.get("encodings") {
            let configured = configured
                .as_object()
                .ok_or_else(|| invalid(path, "`encodings` must be an object"))?;
            for (name, options) in configured {
                let options = options.as_object().ok_or_else(|| {
                    invalid(path, format!("encoder `{name}` options must be an object"))
                })?;
                let kind = match name.as_str() {
                    "gzip" => parse_gzip(options, &format!("{path}.encodings.gzip"))?,
                    "zstd" => parse_zstd(options, &format!("{path}.encodings.zstd"))?,
                    other => {
                        return Err(invalid(
                            path,
                            format!("unknown encoder `{other}`; this build supports gzip and zstd"),
                        ))
                    }
                };
                encodings.push(EncodingConfig {
                    name: name.clone(),
                    kind,
                });
            }
        }
        let prefer = match object.get("prefer") {
            None | Some(serde_json::Value::Null) => {
                // Caddy: default preference order zstd, br, gzip filtered to enabled encoders.
                let mut prefer = Vec::new();
                for name in ["zstd", "br", "gzip"] {
                    if encodings.iter().any(|encoding| encoding.name == name) {
                        prefer.push(name.to_string());
                    }
                }
                prefer
            }
            Some(value) => value
                .as_array()
                .ok_or_else(|| invalid(path, "`prefer` must be an array of encoder names"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| invalid(path, "`prefer` entries must be strings"))
                })
                .collect::<Result<Vec<_>>>()?,
        };
        let mut seen = std::collections::BTreeSet::new();
        for name in &prefer {
            if !encodings.iter().any(|encoding| &encoding.name == name) {
                return Err(invalid(
                    path,
                    format!("`prefer` contains encoding `{name}` that is not enabled"),
                ));
            }
            if !seen.insert(name.clone()) {
                return Err(invalid(
                    path,
                    format!("`prefer` contains encoding `{name}` more than once"),
                ));
            }
        }
        let min_length = match object.get("minimum_length") {
            None | Some(serde_json::Value::Null) => DEFAULT_MIN_LENGTH,
            Some(value) => {
                let configured = value.as_i64().ok_or_else(|| {
                    invalid(path, "`minimum_length` must be an integer number of bytes")
                })?;
                // Caddy: `if enc.MinLength == 0 { enc.MinLength = defaultMinLength }`.
                if configured == 0 {
                    DEFAULT_MIN_LENGTH
                } else {
                    configured
                }
            }
        };
        let matcher = match object.get("match") {
            None | Some(serde_json::Value::Null) => ResponseMatcher {
                status_codes: None,
                headers: vec![(
                    header::CONTENT_TYPE,
                    HeaderMatcher::Values(
                        DEFAULT_CONTENT_TYPES
                            .iter()
                            .map(|value| (*value).to_string())
                            .collect(),
                    ),
                )],
            },
            Some(value) => parse_response_matcher(value, &format!("{path}.match"))?,
        };
        Ok(Self {
            config: Arc::new(EncodeConfig {
                encodings,
                prefer,
                min_length,
                matcher,
            }),
        })
    }

    /// Select the encoding for this request, honouring request `no-transform` and WebSocket.
    fn select_encoding(&self, request: &Request) -> Option<&EncodingConfig> {
        if !cache_control_allows(
            request
                .headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
        ) {
            return None;
        }
        // Caddy's AcceptedEncodings never offers non-identity encodings for WebSocket handshakes.
        if request.headers.contains_key("sec-websocket-key") {
            return None;
        }
        let accepted = accepted_encodings(
            request
                .headers
                .get(header::ACCEPT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            &self.config.prefer,
        );
        accepted.into_iter().find_map(|name| {
            self.config
                .encodings
                .iter()
                .find(|encoding| encoding.name == name)
        })
    }

    /// Strip the `-<encoding>"` suffix the encode middleware appends to strong ETags from the
    /// request's `If-None-Match` header so upstream handlers can honour client caches (Caddy's
    /// ServeHTTP does this before invoking the next handler).
    fn strip_if_none_match(encoding: &str, request: &mut Request) {
        let Some(value) = request
            .headers
            .get(header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
        else {
            return;
        };
        if value.starts_with("W/") {
            return;
        }
        let suffix = format!("-{encoding}\"");
        let Some(base) = value.strip_suffix(&suffix) else {
            return;
        };
        let stripped = format!("{base}\"");
        if let Ok(value) = HeaderValue::from_str(&stripped) {
            request.headers.insert(header::IF_NONE_MATCH, value);
        }
    }
}

fn parse_gzip(
    options: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<EncoderKind> {
    let mut level = 5;
    for (key, value) in options {
        match key.as_str() {
            "level" => {
                let configured = value
                    .as_i64()
                    .ok_or_else(|| invalid(path, "`level` must be an integer"))?;
                // Caddy/klauspost accepts -2..=9 (stateless/constant compression etc.); flate2's
                // Rust backend only expresses 0..=9, so negative levels are rejected loudly.
                if !(0..=9).contains(&configured) {
                    return Err(not_implemented(
                        "gzip levels outside 0..=9 (flate2 backend)",
                        "T-ROUTE-022",
                    ));
                }
                // Caddy: `if g.Level == 0 { g.Level = defaultGzipLevel }`.
                level = if configured == 0 {
                    5
                } else {
                    configured as u32
                };
            }
            other => return Err(invalid(path, format!("unknown gzip option `{other}`"))),
        }
    }
    Ok(EncoderKind::Gzip { level })
}

fn parse_zstd(
    options: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<EncoderKind> {
    let mut level = zstd_level("default")?;
    // Caddy's zstd encoder uses klauspost's default frame checksum (enabled) unless
    // `disable_checksum`/`"checksum": false` is configured.
    let mut checksum = true;
    for (key, value) in options {
        match key.as_str() {
            "level" => {
                let configured = value
                    .as_str()
                    .ok_or_else(|| invalid(path, "`level` must be a string"))?;
                level = if configured.is_empty() {
                    zstd_level("default")?
                } else {
                    zstd_level(configured)?
                };
            }
            "checksum" => {
                checksum = value
                    .as_bool()
                    .ok_or_else(|| invalid(path, "`checksum` must be a boolean"))?;
            }
            other => return Err(invalid(path, format!("unknown zstd option `{other}`"))),
        }
    }
    Ok(EncoderKind::Zstd { level, checksum })
}

/// Map Caddy's zstd level names to the zstd crate's numeric levels.
///
/// Caddy/klauspost: `fastest` is the fastest usable level, `default` balances speed/ratio,
/// `better` improves ratio, `best` maximises ratio. The numeric mapping matches the zstd
/// reference encoder's conventional levels.
fn zstd_level(name: &str) -> Result<i32> {
    match name {
        "fastest" => Ok(1),
        "default" => Ok(3),
        "better" => Ok(7),
        "best" => Ok(11),
        other => Err(invalid(
            "encode.encodings.zstd.level",
            format!(
                "unexpected compression level `{other}`; use `fastest`, `default`, `better` or `best`"
            ),
        )),
    }
}

fn parse_response_matcher(value: &serde_json::Value, path: &str) -> Result<ResponseMatcher> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "`match` must be an object"))?;
    let mut matcher = ResponseMatcher::default();
    for (key, value) in object {
        match key.as_str() {
            "status_code" => {
                let codes = value
                    .as_array()
                    .ok_or_else(|| invalid(path, "`match.status_code` must be an array"))?;
                let mut parsed = Vec::with_capacity(codes.len());
                for (index, code) in codes.iter().enumerate() {
                    let code = code.as_u64().ok_or_else(|| {
                        invalid(
                            path,
                            format!("`match.status_code[{index}]` must be an integer"),
                        )
                    })?;
                    parsed.push(u16::try_from(code).map_err(|_| {
                        invalid(
                            path,
                            format!("`match.status_code[{index}]` does not fit in u16"),
                        )
                    })?);
                }
                matcher.status_codes = Some(parsed);
            }
            "headers" => {
                let headers = value
                    .as_object()
                    .ok_or_else(|| invalid(path, "`match.headers` must be an object"))?;
                for (field, values) in headers {
                    let name: HeaderName = field.parse().map_err(|error| {
                        invalid(path, format!("invalid header name `{field}`: {error}"))
                    })?;
                    let matcher_value = match values {
                        serde_json::Value::Null => HeaderMatcher::Absent,
                        serde_json::Value::Array(values) => {
                            if values.is_empty() {
                                HeaderMatcher::Present
                            } else {
                                HeaderMatcher::Values(
                                    values
                                        .iter()
                                        .map(|value| {
                                            value.as_str().map(str::to_string).ok_or_else(|| {
                                                invalid(
                                                    path,
                                                    "`match.headers` values must be strings",
                                                )
                                            })
                                        })
                                        .collect::<Result<Vec<_>>>()?,
                                )
                            }
                        }
                        _ => {
                            return Err(invalid(
                                path,
                                "`match.headers` values must be an array or null",
                            ))
                        }
                    };
                    matcher.headers.push((name, matcher_value));
                }
            }
            other => {
                return Err(invalid(
                    path,
                    format!(
                    "unknown response matcher field `{other}` (supported: status_code, headers)"
                ),
                ))
            }
        }
    }
    Ok(matcher)
}

#[async_trait]
impl Handler for EncodeHandler {
    fn name(&self) -> &'static str {
        "encode"
    }

    async fn handle(&self, mut request: Request) -> Result<Outcome> {
        let Some(encoding) = self.select_encoding(&request) else {
            // No supported encoding accepted (or no-transform/WebSocket): pass through untouched,
            // matching Caddy (which only wraps the writer when an encoding is selected).
            return Ok(Outcome::Continue(request));
        };
        let transform = EncodeTransform {
            config: Arc::clone(&self.config),
            kind: encoding.kind.clone(),
            encoding_name: encoding.name.clone(),
        };
        Self::strip_if_none_match(&encoding.name, &mut request);
        request.push_response_transform(Arc::new(transform));
        Ok(Outcome::Continue(request))
    }
}

/// The response transform registered by [`EncodeHandler`].
struct EncodeTransform {
    config: Arc<EncodeConfig>,
    kind: EncoderKind,
    encoding_name: String,
}

#[async_trait]
impl ResponseTransform for EncodeTransform {
    async fn transform(&self, mut response: StreamingResponse) -> StreamingResponse {
        // Caddy's encode WriteHeader adds `Vary: Accept-Encoding` to 304 responses even though no
        // body is written.
        if response.status == StatusCode::NOT_MODIFIED {
            ensure_vary(&mut response.headers);
            return response;
        }
        // 1xx/204 responses never enter Caddy's encoder initialization path, and Caddy's
        // WriteHeader explicitly disables dynamic encoding for partial (206) representations.
        if response.status.as_u16() < 200
            || response.status == StatusCode::NO_CONTENT
            || response.status == StatusCode::PARTIAL_CONTENT
        {
            return response;
        }
        // Already encoded by a handler/upstream: leave untouched.
        if response
            .headers
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| !value.is_empty())
        {
            return response;
        }
        if !cache_control_allows(
            response
                .headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
        ) {
            return response;
        }
        let declared_length = response
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<i64>().ok());

        // Caddy's minimum_length trigger: the first write chunk must be larger than MinLength, or
        // Content-Length must be. For a streaming body the first frame plays the role of the first
        // write; for a buffered body the whole body is the first write.
        let response_body = std::mem::replace(&mut response.body, Body::empty());
        let (body, first_chunk_len) = match response_body {
            Body::Bytes(bytes) => {
                let len = bytes.len() as i64;
                (BufferedOrStreamed::Buffered(bytes), len)
            }
            Body::Stream(stream) => match read_first_frame(stream).await {
                Ok(Some((first, rest))) => {
                    let len = first.len() as i64;
                    (BufferedOrStreamed::Streamed { first, rest }, len)
                }
                Ok(None) => {
                    // Empty stream: equivalent to no write; nothing to encode.
                    return StreamingResponse {
                        status: response.status,
                        headers: response.headers,
                        body: Body::empty(),
                    };
                }
                Err(_) => return response,
            },
        };
        let large_enough = first_chunk_len > self.config.min_length
            || declared_length.is_some_and(|length| length > self.config.min_length);
        if !large_enough {
            let body = match body {
                BufferedOrStreamed::Buffered(bytes) => Body::Bytes(bytes),
                BufferedOrStreamed::Streamed { first, rest } => replay_stream(first, rest),
            };
            return StreamingResponse {
                status: response.status,
                headers: response.headers,
                body,
            };
        }
        // Caddy sniffs a missing Content-Type from the first write chunk before evaluating the
        // response matcher (so `text/*` rules can apply to handlers that did not set one).
        if response
            .headers
            .get(header::CONTENT_TYPE)
            .is_none_or(|value| value.is_empty())
        {
            let sample = match &body {
                BufferedOrStreamed::Buffered(bytes) => &bytes[..],
                BufferedOrStreamed::Streamed { first, .. } => &first[..],
            };
            let detected = detect_content_type(sample);
            if let Ok(value) = HeaderValue::from_str(detected) {
                response.headers.insert(header::CONTENT_TYPE, value);
            }
        }
        if !self
            .config
            .matcher
            .matches(response.status, &response.headers)
        {
            let body = match body {
                BufferedOrStreamed::Buffered(bytes) => Body::Bytes(bytes),
                BufferedOrStreamed::Streamed { first, rest } => replay_stream(first, rest),
            };
            return StreamingResponse {
                status: response.status,
                headers: response.headers,
                body,
            };
        }
        let compressor = match Compressor::new(&self.kind) {
            Ok(compressor) => compressor,
            Err(_) => {
                let body = match body {
                    BufferedOrStreamed::Buffered(bytes) => Body::Bytes(bytes),
                    BufferedOrStreamed::Streamed { first, rest } => replay_stream(first, rest),
                };
                return StreamingResponse {
                    status: response.status,
                    headers: response.headers,
                    body,
                };
            }
        };
        match body {
            BufferedOrStreamed::Buffered(bytes) => {
                // Compress the whole buffered body; on a codec failure leave the response
                // untouched instead of sending a broken representation.
                let mut compressor = compressor;
                let compressed = match compressor.write_flush(&bytes) {
                    Ok(first) => match compressor.finish() {
                        Ok(tail) => concat_bytes(first, tail),
                        Err(_) => bytes.clone(),
                    },
                    Err(_) => bytes.clone(),
                };
                apply_encoding_headers(&mut response.headers, &self.encoding_name);
                StreamingResponse {
                    status: response.status,
                    headers: response.headers,
                    body: Body::Bytes(compressed),
                }
            }
            BufferedOrStreamed::Streamed { first, rest } => {
                apply_encoding_headers(&mut response.headers, &self.encoding_name);
                StreamingResponse {
                    status: response.status,
                    headers: response.headers,
                    body: compress_stream(first, rest, compressor),
                }
            }
        }
    }
}

/// A response body split for the minimum-length streaming decision.
enum BufferedOrStreamed {
    Buffered(Bytes),
    Streamed { first: Bytes, rest: StreamingBody },
}

fn concat_bytes(first: Bytes, second: Bytes) -> Bytes {
    if second.is_empty() {
        return first;
    }
    let mut combined = Vec::with_capacity(first.len() + second.len());
    combined.extend_from_slice(&first);
    combined.extend_from_slice(&second);
    Bytes::from(combined)
}

/// Apply Caddy's `init` header mutations for a dynamically encoded response.
fn apply_encoding_headers(headers: &mut HeaderMap, encoding_name: &str) {
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::ACCEPT_RANGES);
    if let Ok(value) = HeaderValue::from_str(encoding_name) {
        headers.insert(header::CONTENT_ENCODING, value);
    }
    ensure_vary(headers);
    // Strong ETags need to be distinct per selected representation (RFC 9110 8.8.3.3).
    if let Some(etag) = headers
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
    {
        if !etag.starts_with("W/") {
            if let Some(base) = etag.strip_suffix('"') {
                let modified = format!("{base}-{encoding_name}\"");
                if let Ok(value) = HeaderValue::from_str(&modified) {
                    headers.insert(header::ETAG, value);
                }
            }
        }
    }
}

/// Add `Vary: Accept-Encoding` if no `Vary` value already includes it (Caddy's `hasVaryValue`).
fn ensure_vary(headers: &mut HeaderMap) {
    let has_vary = headers.get_all(header::VARY).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|entry| entry.trim().eq_ignore_ascii_case("accept-encoding"))
        })
    });
    if !has_vary {
        headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

/// A conservative port of Go's `http.DetectContentType` for the cases the encode matcher cares
/// about: HTML/XML/text bodies are recognised as text; everything else is binary.
fn detect_content_type(data: &[u8]) -> &'static str {
    let prefix = &data[..data.len().min(512)];
    let trimmed = prefix
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|start| &prefix[start..])
        .unwrap_or(prefix);
    let starts_with_ignore_case = |needle: &[u8]| {
        trimmed.len() >= needle.len() && trimmed[..needle.len()].eq_ignore_ascii_case(needle)
    };
    if starts_with_ignore_case(b"<!doctype html")
        || starts_with_ignore_case(b"<html")
        || starts_with_ignore_case(b"<head")
        || starts_with_ignore_case(b"<body")
    {
        return "text/html; charset=utf-8";
    }
    if starts_with_ignore_case(b"<?xml") {
        return "text/xml; charset=utf-8";
    }
    let text_like = !prefix.is_empty()
        && prefix
            .iter()
            .all(|byte| matches!(*byte, b'\t' | b'\n' | b'\r' | 0x0c | 0x20..=0x7e | 0x80..=0xff))
        && std::str::from_utf8(prefix).is_ok();
    if text_like {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

/// Caddy's `isEncodeAllowed`: `Cache-Control` must not contain `no-transform`.
fn cache_control_allows(cache_control: Option<&str>) -> bool {
    !cache_control.is_some_and(|value| value.contains("no-transform"))
}

/// Caddy's `AcceptedEncodings`: parse q-values and order by client preference, then server
/// `prefer` order for equal q-values. `*` is not expanded (Caddy only matches exact names);
/// `q=0` is rejected; WebSocket handshakes never select non-identity encodings (handled by the
/// caller before this function is used).
fn accepted_encodings(header: Option<&str>, preferred_order: &[String]) -> Vec<String> {
    let Some(header) = header else {
        return Vec::new();
    };
    if header.trim().is_empty() {
        return Vec::new();
    }
    let mut preferences: Vec<(String, f64, i64)> = Vec::new();
    for accepted in header.split(',') {
        let (name, params) = accepted.split_once(';').unwrap_or((accepted, ""));
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let mut q = 1.0_f64;
        if !params.is_empty() {
            // Caddy takes the first parameter and only parses it when it starts with `q=`.
            let first = params.split(';').next().unwrap_or("").trim();
            if first.len() >= 2 && first[..2].eq_ignore_ascii_case("q=") {
                if let Ok(parsed) = first[2..].parse::<f32>() {
                    let parsed = f64::from(parsed);
                    if (0.0..=1.0).contains(&parsed) {
                        q = parsed;
                    }
                }
            }
        }
        if q < 0.00001 {
            continue;
        }
        let preference = match preferred_order
            .iter()
            .position(|preferred| *preferred == name)
        {
            Some(index) => preferred_order.len() as i64 - index as i64,
            None => -1,
        };
        preferences.push((name, q, preference));
    }
    preferences.sort_by(|left, right| {
        if (left.1 - right.1).abs() < 0.00001 {
            right.2.cmp(&left.2)
        } else {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        }
    });
    preferences.into_iter().map(|(name, _, _)| name).collect()
}

// ---- streaming compression -------------------------------------------------------------------

/// A streaming gzip/zstd compressor whose output chunks can be forwarded as they are produced.
enum Compressor {
    Gzip(GzEncoder<Vec<u8>>),
    Zstd(ZstdEncoder<'static, Vec<u8>>),
}

impl Compressor {
    fn new(kind: &EncoderKind) -> std::io::Result<Self> {
        match kind {
            EncoderKind::Gzip { level } => Ok(Self::Gzip(GzEncoder::new(
                Vec::new(),
                Compression::new(*level),
            ))),
            EncoderKind::Zstd { level, checksum } => {
                let mut encoder = ZstdEncoder::new(Vec::new(), *level)?;
                // Caddy limits the zstd window to 128 KiB for client compatibility.
                encoder.window_log(17)?;
                if *checksum {
                    encoder.include_checksum(true)?;
                }
                Ok(Self::Zstd(encoder))
            }
        }
    }

    /// Write one chunk, flush the codec, and return the bytes produced so far.
    fn write_flush(&mut self, data: &[u8]) -> std::io::Result<Bytes> {
        match self {
            Self::Gzip(encoder) => {
                encoder.write_all(data)?;
                encoder.flush()?;
                Ok(Bytes::from(std::mem::take(encoder.get_mut())))
            }
            Self::Zstd(encoder) => {
                encoder.write_all(data)?;
                encoder.flush()?;
                Ok(Bytes::from(std::mem::take(encoder.get_mut())))
            }
        }
    }

    fn finish(self) -> std::io::Result<Bytes> {
        match self {
            Self::Gzip(encoder) => Ok(Bytes::from(encoder.finish()?)),
            Self::Zstd(encoder) => Ok(Bytes::from(encoder.finish()?)),
        }
    }
}

/// Read the first data frame from a streaming body, returning it plus a body that replays the
/// remaining frames.
async fn read_first_frame(
    stream: StreamingBody,
) -> std::result::Result<Option<(Bytes, StreamingBody)>, BodyError> {
    let mut source = Box::pin(stream);
    loop {
        let frame =
            std::future::poll_fn(|context| HttpBody::poll_frame(source.as_mut(), context)).await;
        match frame {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    return Ok(Some((data, relay_remaining(source))));
                }
                // Trailers before any data: drop them (there is no representation yet).
            }
            Some(Err(error)) => return Err(error),
            None => return Ok(None),
        }
    }
}

/// Relay the remaining frames of a boxed source body into a new streaming body.
fn relay_remaining(mut source: std::pin::Pin<Box<StreamingBody>>) -> StreamingBody {
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        loop {
            let frame =
                std::future::poll_fn(|context| HttpBody::poll_frame(source.as_mut(), context))
                    .await;
            match frame {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        if sender.send(Ok(http_body::Frame::data(data))).await.is_err() {
                            return;
                        }
                    }
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            if sender
                                .send(Ok(http_body::Frame::trailers(trailers)))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                },
                Some(Err(error)) => {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
                None => return,
            }
        }
    });
    StreamingBody::from_frames(receiver)
}

/// Rebuild an uncompressed streaming body from a split first chunk and remainder.
fn replay_stream(first: Bytes, rest: StreamingBody) -> Body {
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        if sender
            .send(Ok(http_body::Frame::data(first)))
            .await
            .is_err()
        {
            return;
        }
        let mut rest = Box::pin(rest);
        loop {
            let frame =
                std::future::poll_fn(|context| HttpBody::poll_frame(rest.as_mut(), context)).await;
            match frame {
                Some(Ok(frame)) => {
                    if sender.send(Ok(frame)).await.is_err() {
                        return;
                    }
                }
                Some(Err(error)) => {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
                None => return,
            }
        }
    });
    Body::from_stream(StreamingBody::from_frames(receiver))
}

/// Compress a streamed response: the already-read first chunk is compressed synchronously, then
/// the remaining frames are compressed on a background task and exposed as a streaming body.
fn compress_stream(first: Bytes, rest: StreamingBody, mut compressor: Compressor) -> Body {
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    let first_output = compressor.write_flush(&first);
    tokio::spawn(async move {
        match first_output {
            Ok(chunk) => {
                if !chunk.is_empty() && sender.send(Ok(chunk)).await.is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.send(Err(BodyError::upstream(error))).await;
                return;
            }
        }
        let mut rest = Box::pin(rest);
        loop {
            let frame =
                std::future::poll_fn(|context| HttpBody::poll_frame(rest.as_mut(), context)).await;
            match frame {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        match compressor.write_flush(&data) {
                            Ok(chunk) => {
                                if !chunk.is_empty() && sender.send(Ok(chunk)).await.is_err() {
                                    return;
                                }
                            }
                            Err(error) => {
                                let _ = sender.send(Err(BodyError::upstream(error))).await;
                                return;
                            }
                        }
                    }
                }
                Some(Err(error)) => {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
                None => break,
            }
        }
        match compressor.finish() {
            Ok(tail) => {
                if !tail.is_empty() {
                    let _ = sender.send(Ok(tail)).await;
                }
            }
            Err(error) => {
                let _ = sender.send(Err(BodyError::upstream(error))).await;
            }
        }
    });
    Body::from_stream(StreamingBody::from_chunks(receiver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::Body;
    use crate::body::StreamingResponse;
    use crate::types::Request;
    use http::Method;
    use std::io::Read;

    fn handler(config: serde_json::Value) -> EncodeHandler {
        EncodeHandler::from_json(&config, "handler").expect("encode config")
    }

    fn make_request(accept: &str) -> Request {
        let mut request = Request::new(Method::GET, "/".parse().unwrap());
        if !accept.is_empty() {
            request
                .headers
                .insert(header::ACCEPT_ENCODING, accept.parse().unwrap());
        }
        request
    }

    fn make_response(body: &[u8], content_type: &str) -> StreamingResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap(),
        );
        StreamingResponse::from_buffered(crate::types::Response {
            status: StatusCode::OK,
            headers,
            body: Bytes::copy_from_slice(body),
        })
    }

    async fn transform(
        handler: &EncodeHandler,
        request: &mut Request,
        mut response: StreamingResponse,
    ) -> StreamingResponse {
        let Outcome::Continue(updated) = handler
            .handle(std::mem::replace(
                request,
                Request::new(Method::GET, "/".parse().unwrap()),
            ))
            .await
            .expect("encode handler")
        else {
            panic!("encode is a middleware");
        };
        *request = updated;
        let transforms = request.take_response_transforms();
        for transform in transforms.into_iter().rev() {
            response = transform.transform(response).await;
        }
        response
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        let mut decoder = flate2::read::GzDecoder::new(bytes);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).expect("valid gzip");
        output
    }

    fn unzstd(bytes: &[u8]) -> Vec<u8> {
        zstd::stream::decode_all(bytes).expect("valid zstd")
    }

    async fn body_bytes(response: StreamingResponse) -> Vec<u8> {
        response.body.into_bytes().await.expect("body").to_vec()
    }

    #[tokio::test]
    async fn gzip_compresses_large_text_and_sets_headers() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 10
        }));
        let mut request = make_request("gzip");
        let payload = b"hello hello hello hello";
        let response = transform(
            &handler,
            &mut request,
            make_response(payload, "text/plain; charset=utf-8"),
        )
        .await;
        assert_eq!(response.headers[header::CONTENT_ENCODING], "gzip");
        assert_eq!(response.headers[header::VARY], "Accept-Encoding");
        assert!(!response.headers.contains_key(header::CONTENT_LENGTH));
        let compressed = body_bytes(response).await;
        assert_eq!(gunzip(&compressed), payload.to_vec());
        assert!(!compressed.is_empty());
        assert!(
            compressed.len() > 10,
            "gzip framing is present: {compressed:?}"
        );
    }

    #[tokio::test]
    async fn compressed_gzip_round_trips() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 1
        }));
        let mut request = make_request("gzip");
        let payload = b"the quick brown fox jumps over the lazy dog";
        let response =
            transform(&handler, &mut request, make_response(payload, "text/plain")).await;
        assert_eq!(gunzip(&body_bytes(response).await), payload.to_vec());
    }

    #[tokio::test]
    async fn compressed_zstd_round_trips_and_prefers_zstd() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}, "zstd": {}},
            "minimum_length": 1
        }));
        let mut request = make_request("gzip, zstd");
        let payload = b"the quick brown fox jumps over the lazy dog";
        let response =
            transform(&handler, &mut request, make_response(payload, "text/plain")).await;
        assert_eq!(response.headers[header::CONTENT_ENCODING], "zstd");
        assert_eq!(unzstd(&body_bytes(response).await), payload.to_vec());
    }

    #[test]
    fn negotiation_matrix_matches_caddy() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}, "zstd": {}},
            "prefer": ["gzip", "zstd"]
        }));
        let cases = [
            ("", None),
            ("identity", None),
            ("gzip", Some("gzip")),
            ("zstd", Some("zstd")),
            ("br", None),
            ("gzip, zstd", Some("gzip")),
            ("zstd;q=0.5, gzip;q=0.9", Some("gzip")),
            ("gzip;q=0, zstd", Some("zstd")),
            ("gzip;q=0, zstd;q=0", None),
            ("*", None),
            ("deflate, gzip", Some("gzip")),
            ("gzip;q=0.0001", Some("gzip")),
            ("GZIP", Some("gzip")),
            ("zstd;q=1.0, gzip;q=1.0", Some("gzip")),
        ];
        for (accept, expected) in cases {
            let request = make_request(accept);
            assert_eq!(
                handler
                    .select_encoding(&request)
                    .map(|encoding| encoding.name.as_str()),
                expected,
                "Accept-Encoding: {accept}"
            );
        }
    }

    #[tokio::test]
    async fn minimum_length_boundary_is_strict() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 10
        }));
        for (length, compressed) in [(9usize, false), (10, false), (11, true)] {
            let mut request = make_request("gzip");
            let payload = vec![b'a'; length];
            let response = transform(
                &handler,
                &mut request,
                make_response(&payload, "text/plain"),
            )
            .await;
            assert_eq!(
                response.headers.contains_key(header::CONTENT_ENCODING),
                compressed,
                "length {length}"
            );
        }
    }

    #[tokio::test]
    async fn minimum_length_uses_content_length_for_empty_body() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 10
        }));
        let mut request = make_request("gzip");
        let mut response = make_response(b"", "text/plain");
        response
            .headers
            .insert(header::CONTENT_LENGTH, "100".parse().unwrap());
        let response = transform(&handler, &mut request, response).await;
        assert_eq!(response.headers[header::CONTENT_ENCODING], "gzip");
        assert!(!response.headers.contains_key(header::CONTENT_LENGTH));
        assert_eq!(gunzip(&body_bytes(response).await).len(), 0);
    }

    #[tokio::test]
    async fn already_encoded_responses_pass_through() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 1
        }));
        let mut request = make_request("gzip");
        let mut response = make_response(b"already compressed bytes", "text/plain");
        response
            .headers
            .insert(header::CONTENT_ENCODING, "br".parse().unwrap());
        let response = transform(&handler, &mut request, response).await;
        assert_eq!(response.headers[header::CONTENT_ENCODING], "br");
        assert!(!response.headers.contains_key(header::VARY));
        assert_eq!(body_bytes(response).await, b"already compressed bytes");
    }

    #[tokio::test]
    async fn content_type_matcher_skips_non_text() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 1
        }));
        let mut request = make_request("gzip");
        let response = transform(
            &handler,
            &mut request,
            make_response(b"\x89PNG\r\n\x1a\nbinary image data", "image/png"),
        )
        .await;
        assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
        assert!(!response.headers.contains_key(header::VARY));
    }

    #[tokio::test]
    async fn response_matcher_status_and_header() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 1,
            "match": {"status_code": [2], "headers": {"X-Compress": ["yes"]}}
        }));
        let mut request = make_request("gzip");
        let mut response = make_response(b"aaaaaaaaaaaaaaaa", "text/plain");
        response
            .headers
            .insert("x-compress", "yes".parse().unwrap());
        let response = transform(&handler, &mut request, response).await;
        assert_eq!(response.headers[header::CONTENT_ENCODING], "gzip");
        let mut request = make_request("gzip");
        let response = transform(
            &handler,
            &mut request,
            make_response(b"aaaaaaaaaaaaaaaa", "text/plain"),
        )
        .await;
        assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
    }

    #[tokio::test]
    async fn etag_gets_encoding_suffix_and_if_none_match_is_stripped() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 1
        }));
        let mut request = make_request("gzip");
        request
            .headers
            .insert(header::IF_NONE_MATCH, "\"abc-gzip\"".parse().unwrap());
        let mut response = make_response(b"aaaaaaaaaaaaaaaa", "text/plain");
        response
            .headers
            .insert(header::ETAG, "\"abc\"".parse().unwrap());
        let response = transform(&handler, &mut request, response).await;
        assert_eq!(response.headers[header::ETAG], "\"abc-gzip\"");
        assert_eq!(request.headers[header::IF_NONE_MATCH], "\"abc\"");
    }

    #[tokio::test]
    async fn not_modified_gets_vary_without_encoding() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}}
        }));
        let mut request = make_request("gzip");
        let response = StreamingResponse::from_buffered(crate::types::Response {
            status: StatusCode::NOT_MODIFIED,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        });
        let response = transform(&handler, &mut request, response).await;
        assert_eq!(response.headers[header::VARY], "Accept-Encoding");
        assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
    }

    #[tokio::test]
    async fn no_transform_and_no_accept_encoding_disable_encoding() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 1
        }));
        let mut request = make_request("gzip");
        request
            .headers
            .insert(header::CACHE_CONTROL, "no-transform".parse().unwrap());
        let response = transform(
            &handler,
            &mut request,
            make_response(b"aaaaaaaaaaaaaaaa", "text/plain"),
        )
        .await;
        assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
        let mut request = make_request("");
        let response = transform(
            &handler,
            &mut request,
            make_response(b"aaaaaaaaaaaaaaaa", "text/plain"),
        )
        .await;
        assert!(!response.headers.contains_key(header::CONTENT_ENCODING));
        assert!(!response.headers.contains_key(header::VARY));
    }

    #[tokio::test]
    async fn streaming_body_is_compressed_incrementally() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}},
            "minimum_length": 1
        }));
        let mut request = make_request("gzip");
        // A chunked body with no known length: the first frame determines the minimum-length
        // decision and compression must happen while streaming.
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            for chunk in [b"hello ".as_slice(), b"streaming ", b"world"] {
                sender
                    .send(Ok(Bytes::copy_from_slice(chunk)))
                    .await
                    .unwrap();
            }
        });
        let response = StreamingResponse::new(
            StatusCode::OK,
            {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
                headers
            },
            Body::from_stream(StreamingBody::from_chunks(receiver)),
        );
        let mut response = transform(&handler, &mut request, response).await;
        assert_eq!(response.headers[header::CONTENT_ENCODING], "gzip");
        assert!(!response.headers.contains_key(header::CONTENT_LENGTH));
        let body = response.body.into_bytes().await.expect("body");
        assert_eq!(gunzip(&body), b"hello streaming world".to_vec());
    }

    #[test]
    fn unknown_encoders_and_options_are_loud() {
        for config in [
            serde_json::json!({"handler": "encode", "encodings": {"br": {}}}),
            serde_json::json!({"handler": "encode", "encodings": {"gzip": {"bogus": 1}}}),
            serde_json::json!({"handler": "encode", "encodings": {"gzip": {}}, "prefer": ["zstd"]}),
            serde_json::json!({"handler": "encode", "encodings": {"gzip": {}}, "prefer": ["gzip", "gzip"]}),
            serde_json::json!({"handler": "encode", "encodings": {"zstd": {"level": "extreme"}}}),
            serde_json::json!({"handler": "encode", "encodings": {"gzip": {"level": -2}}}),
            serde_json::json!({"handler": "encode", "encodings": {"gzip": {}}, "unknown_field": 1}),
            serde_json::json!({"handler": "encode", "encodings": {"gzip": {}}, "match": {"bogus": []}}),
        ] {
            assert!(
                EncodeHandler::from_json(&config, "handler").is_err(),
                "config must be rejected: {config}"
            );
        }
    }

    #[test]
    fn defaults_match_caddy() {
        let handler = handler(serde_json::json!({
            "handler": "encode",
            "encodings": {"gzip": {}, "zstd": {}}
        }));
        assert_eq!(handler.config.min_length, 512);
        assert_eq!(handler.config.prefer, vec!["zstd", "gzip"]);
        let gzip = handler
            .config
            .encodings
            .iter()
            .find(|encoding| encoding.name == "gzip")
            .unwrap();
        assert!(matches!(gzip.kind, EncoderKind::Gzip { level: 5 }));
        let zstd = handler
            .config
            .encodings
            .iter()
            .find(|encoding| encoding.name == "zstd")
            .unwrap();
        assert!(matches!(
            zstd.kind,
            EncoderKind::Zstd {
                level: 3,
                checksum: true
            }
        ));
    }
}
