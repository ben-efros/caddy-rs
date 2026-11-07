//! Static file serving (`file_server`).
//!
//! Semantics follow Caddy v2.11.7 `modules/caddyhttp/fileserver/staticfiles.go`, which delegates the
//! representation transfer to Go's `net/http.ServeContent`: precompressed sidecar selection,
//! `Vary: Accept-Encoding`, ETag/Last-Modified, conditional requests (If-Match,
//! If-Unmodified-Since, If-None-Match, If-Modified-Since, If-Range), single and multipart byte
//! ranges, 206/304/412/416 responses, HEAD, and `Accept-Ranges: bytes`.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use tokio::fs;

use crate::matchers::{glob_match, percent_decode};
use crate::types::{Error, Handler, Outcome, Request, Response, Result};

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// Precompressed sidecar encodings supported by this build, with their file suffixes (Caddy's
/// `http.precompressed.{gzip,brotli,zstd}` modules).
const PRECOMPRESSED_SUFFIXES: &[(&str, &str)] = &[("gzip", ".gz"), ("br", ".br"), ("zstd", ".zst")];

/// Serve files from a root directory.
pub struct FileServerHandler {
    root: String,
    hide: Vec<String>,
    index_names: Vec<String>,
    browse: bool,
    pass_thru: bool,
    status_code: Option<StatusOverride>,
    canonical_uris: bool,
    /// Encodings whose sidecar files may be served (`precompressed` module map keys).
    precompressed: Vec<String>,
    /// Server preference for equally-accepted encodings (`precompressed_order`).
    precompressed_order: Vec<String>,
    /// File suffixes to read an ETag from instead of computing one (`etag_file_extensions`).
    etag_file_extensions: Vec<String>,
}

enum StatusOverride {
    Fixed(StatusCode),
    Template(String),
}

impl FileServerHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "file_server must be an object"))?;
        // Caddy's file_server defaults its root to `{http.vars.root}`; the adapter sets that
        // variable from the `root` directive. Placeholders are expanded per request in `handle`.
        let root = object
            .get("root")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("{http.vars.root}")
            .to_string();
        if let Some(fs_value) = object.get("fs").and_then(serde_json::Value::as_str) {
            if !fs_value.is_empty() {
                return Err(Error::NotImplemented {
                    feature: "file_server `fs` (non-default filesystem modules)",
                    tracking_id: "T-ROUTE-033",
                });
            }
        }
        let hide = object
            .get("hide")
            .map(|hide| {
                hide.as_array()
                    .ok_or_else(|| invalid(path, "`hide` must be an array of strings"))?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| invalid(path, "`hide` entries must be strings"))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_else(|| vec!["./Caddyfile".to_string()]);
        let index_names = object
            .get("index_names")
            .map(|names| {
                names
                    .as_array()
                    .ok_or_else(|| invalid(path, "`index_names` must be an array"))?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| invalid(path, "`index_names` entries must be strings"))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_else(|| vec!["index.html".to_string(), "index.txt".to_string()]);
        let browse = object
            .get("browse")
            .map(|browse| browse.as_bool().unwrap_or(browse.is_object()))
            .unwrap_or(false);
        let pass_thru = object
            .get("pass_thru")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let status_code = match object.get("status_code") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Number(number)) => {
                let code = number
                    .as_u64()
                    .and_then(|code| u16::try_from(code).ok())
                    .and_then(|code| StatusCode::from_u16(code).ok())
                    .ok_or_else(|| invalid(path, "`status_code` is not a valid HTTP status"))?;
                Some(StatusOverride::Fixed(code))
            }
            Some(serde_json::Value::String(text)) => match text.parse::<u16>() {
                Ok(code) => StatusCode::from_u16(code)
                    .map(|code| Some(StatusOverride::Fixed(code)))
                    .map_err(|_| invalid(path, "`status_code` is not a valid HTTP status"))?,
                // Caddy's WeakString allows placeholders; expanded per request.
                Err(_) => Some(StatusOverride::Template(text.clone())),
            },
            Some(_) => return Err(invalid(path, "`status_code` must be a number or string")),
        };
        let canonical_uris = object
            .get("canonical_uris")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        // `precompressed` is a module map (`{"gzip": {}, ...}`); only formats this build ships
        // with are accepted, matching Caddy's module lookup failure for unknown names.
        let mut precompressed = Vec::new();
        if let Some(config) = object.get("precompressed") {
            let config = config
                .as_object()
                .ok_or_else(|| invalid(path, "`precompressed` must be an object"))?;
            for name in config.keys() {
                if !PRECOMPRESSED_SUFFIXES
                    .iter()
                    .any(|(format, _)| format == name)
                {
                    return Err(invalid(
                        path,
                        format!(
                            "unsupported precompressed format `{name}`; this build supports gzip, br and zstd"
                        ),
                    ));
                }
                precompressed.push(name.clone());
            }
        }
        let precompressed_order = object
            .get("precompressed_order")
            .map(|order| {
                order
                    .as_array()
                    .ok_or_else(|| invalid(path, "`precompressed_order` must be an array"))?
                    .iter()
                    .map(|item| {
                        item.as_str().map(str::to_string).ok_or_else(|| {
                            invalid(path, "`precompressed_order` entries must be strings")
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let etag_file_extensions = object
            .get("etag_file_extensions")
            .map(|suffixes| {
                suffixes
                    .as_array()
                    .ok_or_else(|| invalid(path, "`etag_file_extensions` must be an array"))?
                    .iter()
                    .map(|item| {
                        item.as_str().map(str::to_string).ok_or_else(|| {
                            invalid(path, "`etag_file_extensions` entries must be strings")
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            root,
            hide,
            index_names,
            browse,
            pass_thru,
            status_code,
            canonical_uris,
            precompressed,
            precompressed_order,
            etag_file_extensions,
        })
    }

    fn not_found(&self, request: Request) -> Result<Outcome> {
        if self.pass_thru {
            Ok(Outcome::Continue(request))
        } else {
            Ok(Outcome::Respond(Response::not_found()))
        }
    }

    fn hidden(&self, relative: &str, request: &Request) -> bool {
        let name = Path::new(relative)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(relative);
        self.hide.iter().any(|pattern| {
            // Caddy: `hide[i] = repl.ReplaceAll(fsrv.Hide[i], "")` (staticfiles.go).
            let expanded = request.replace_all(pattern);
            if expanded.is_empty() {
                // Caddy compares hide patterns against path components, so an empty expansion
                // (for example a missing placeholder) never hides anything.
                return false;
            }
            let pattern = expanded.strip_prefix("./").unwrap_or(&expanded);
            glob_match(pattern, relative, false) || glob_match(pattern, name, false)
        })
    }

    /// Serve one regular file through Caddy's `ServeContent` pipeline.
    async fn serve_file(
        &self,
        request: Request,
        filename: &Path,
        original_name: &str,
    ) -> Result<Outcome> {
        let original_metadata = fs::metadata(filename)
            .await
            .map_err(|error| Error::Io(error))?;
        let modtime = mod_time(&original_metadata);
        let useful_modtime = modtime.is_some_and(|time| time.unix != 0 && time.unix != 1);

        // Response headers staged by earlier `headers` handlers (Caddy's `respHeader`).
        let mut headers = request.pending_response_headers.clone();
        // Caddy always adds `Vary: Accept-Encoding` for static files, compressed or not.
        headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));

        // Precompressed sidecar selection (Caddy's `AcceptedEncodings` loop).
        let mut representation = filename.to_path_buf();
        let mut representation_metadata = original_metadata;
        let mut content_encoding: Option<&str> = None;
        for encoding in accepted_encodings(&request, &self.precompressed_order) {
            if !self.precompressed.iter().any(|format| format == &encoding) {
                continue;
            }
            let Some((_, suffix)) = PRECOMPRESSED_SUFFIXES
                .iter()
                .find(|(format, _)| *format == encoding)
            else {
                continue;
            };
            let sidecar = PathBuf::from(format!("{}{suffix}", filename.display()));
            let Ok(info) = fs::metadata(&sidecar).await else {
                continue;
            };
            if info.is_dir() {
                continue;
            }
            representation = sidecar;
            representation_metadata = info;
            content_encoding = Some(match encoding.as_str() {
                "gzip" => "gzip",
                "br" => "br",
                "zstd" => "zstd",
                _ => unreachable!(),
            });
            break;
        }
        if let Some(encoding) = content_encoding {
            headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
            // Caddy sets Content-Length for the encoded representation for non-range requests;
            // Go's ServeContent does not (it skips Content-Length when Content-Encoding is set).
            if !request.headers.contains_key(header::RANGE) {
                headers.insert(
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&representation_metadata.len().to_string())
                        .expect("decimal length is a valid header value"),
                );
            }
        }

        // Caddy rejects methods other than GET/HEAD after inspecting the representation but before
        // setting ETag/Content-Type (issue #5166); headers already staged for the representation
        // (Vary, and Content-Encoding/Content-Length for precompressed files) are preserved.
        if request.method != http::Method::GET && request.method != http::Method::HEAD {
            headers.insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            if !headers.contains_key(header::CONTENT_LENGTH) {
                headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
            }
            return Ok(Outcome::Respond(Response {
                status: StatusCode::METHOD_NOT_ALLOWED,
                headers,
                body: Bytes::new(),
            }));
        }

        // ETag: an explicit earlier `Etag` header wins, then an etag sidecar file, then the
        // computed strong validator over the representation's (mtime, size).
        let mut etag = headers
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if etag.is_empty() && !self.etag_file_extensions.is_empty() {
            if let Some(from_file) =
                read_etag_sidecar(&representation, &self.etag_file_extensions).await?
            {
                etag = from_file;
            }
        }
        if etag.is_empty() && useful_modtime {
            etag = calculate_etag(&representation_metadata);
        }
        if !etag.is_empty() {
            headers.insert(
                header::ETAG,
                HeaderValue::from_str(&etag)
                    .map_err(|error| invalid("file_server", format!("invalid ETag: {error}")))?,
            );
        }

        // Last-Modified (original file, not the sidecar) and Content-Type (original extension).
        if useful_modtime {
            let time = modtime.expect("useful modtime");
            headers.insert(
                header::LAST_MODIFIED,
                HeaderValue::from_str(&format_http_date(time.unix))
                    .expect("formatted date is a valid header value"),
            );
        }
        if !headers.contains_key(header::CONTENT_TYPE) {
            match mime_type(original_name) {
                Some(mime) => {
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
                }
                None => {
                    // Caddy explicitly leaves Content-Type unset so Go does not sniff it.
                    headers.remove(header::CONTENT_TYPE);
                }
            }
        }

        let body = Bytes::from(fs::read(&representation).await.map_err(Error::Io)?);
        let size = representation_metadata.len();

        // Conditional requests, following Go's `checkPreconditions` (RFC 7232 section 6).
        if let Some(status) = conditional_status(&request, &headers, modtime, useful_modtime) {
            if status == StatusCode::NOT_MODIFIED {
                // Go's `writeNotModified`: representation metadata is removed; `Etag` wins over
                // `Last-Modified` when present.
                for name in [
                    header::CONTENT_TYPE,
                    header::CONTENT_LENGTH,
                    header::CONTENT_ENCODING,
                ] {
                    headers.remove(name);
                }
                if !response_etag(&headers).is_empty() {
                    headers.remove(header::LAST_MODIFIED);
                }
            } else if status == StatusCode::PRECONDITION_FAILED {
                // Go writes only the status; net/http adds Content-Length: 0 when the
                // representation did not already stage one (precompressed files stage the
                // sidecar's length before preconditions are evaluated).
                if !headers.contains_key(header::CONTENT_LENGTH) {
                    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
                }
            }
            return Ok(Outcome::Respond(Response {
                status,
                headers,
                body: Bytes::new(),
            }));
        }

        // Range handling, following Go's `parseRange`/`serveContent`.
        let mut ranges = match request
            .headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
        {
            Some(range_header) if check_if_range(&request, &etag, modtime, useful_modtime) => {
                parse_range(range_header, size as i64)
            }
            _ => Ok(Vec::new()),
        };
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let mut status = StatusCode::OK;
        let mut body = body;
        let mut send_size = size;
        match ranges {
            Err(RangeError::NoOverlap) if size == 0 => {
                // Ignore range requests on empty files (Go's special case).
                ranges = Ok(Vec::new());
            }
            Err(RangeError::NoOverlap) => {
                headers.insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{size}"))
                        .expect("content range is a valid header value"),
                );
                return Ok(Outcome::Respond(serve_error(
                    request.method == http::Method::HEAD,
                    headers,
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "invalid range: failed to overlap",
                )));
            }
            Err(RangeError::Invalid) => {
                return Ok(Outcome::Respond(serve_error(
                    request.method == http::Method::HEAD,
                    headers,
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "invalid range",
                )));
            }
            Ok(parsed) => {
                let mut parsed = parsed;
                if parsed.iter().map(|range| range.length).sum::<i64>() > size as i64 {
                    // Total range size exceeds the file: ignore the range request (anti-abuse).
                    parsed = Vec::new();
                }
                ranges = Ok(parsed);
            }
        }
        let ranges = ranges.expect("range errors handled");
        if ranges.len() == 1 {
            let range = ranges[0];
            status = StatusCode::PARTIAL_CONTENT;
            headers.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&range.content_range(size as i64))
                    .expect("content range is a valid header value"),
            );
            send_size = range.length as u64;
            body = Bytes::copy_from_slice(
                &body[range.start as usize..(range.start + range.length) as usize],
            );
        } else if ranges.len() > 1 {
            status = StatusCode::PARTIAL_CONTENT;
            let boundary = multipart_boundary();
            let multipart = multipart_body(&ranges, &content_type, size as i64, &boundary, &body);
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&format!("multipart/byteranges; boundary={boundary}"))
                    .expect("multipart content type is a valid header value"),
            );
            send_size = multipart.len() as u64;
            body = Bytes::from(multipart);
            if !content_encoding_present(&headers) {
                headers.remove(header::CONTENT_RANGE);
            }
        }

        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        // Go: always set Content-Length for range responses; for full responses only when the
        // representation is not content-encoded (Caddy pre-sets it for precompressed files).
        if !ranges.is_empty() || !content_encoding_present(&headers) {
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&send_size.to_string())
                    .expect("decimal length is a valid header value"),
            );
        }

        let mut response = Response {
            status,
            headers,
            body,
        };
        if let Some(override_status) = self.status_override(&request)? {
            response.status = override_status;
        }
        if request.method == http::Method::HEAD {
            response.body = Bytes::new();
        }
        Ok(Outcome::Respond(response))
    }

    /// Caddy's status-code override: configured `status_code` wins, otherwise an error-context
    /// request (serving an error page) keeps the original error status.
    fn status_override(&self, request: &Request) -> Result<Option<StatusCode>> {
        match &self.status_code {
            Some(StatusOverride::Fixed(status)) => return Ok(Some(*status)),
            Some(StatusOverride::Template(template)) => {
                let expanded = request.replace_all(template);
                return expanded
                    .trim()
                    .parse::<u16>()
                    .ok()
                    .and_then(|code| StatusCode::from_u16(code).ok())
                    .map(Some)
                    .ok_or_else(|| {
                        Error::handler(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("invalid status code `{expanded}`"),
                        )
                    });
            }
            None => {}
        }
        Ok(request
            .vars
            .get("http.error.status_code")
            .and_then(|code| code.parse::<u16>().ok())
            .and_then(|code| StatusCode::from_u16(code).ok()))
    }
}

#[async_trait]
impl Handler for FileServerHandler {
    fn name(&self) -> &'static str {
        "file_server"
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        let decoded_path = percent_decode(request.path());
        if decoded_path.contains("..") || decoded_path.contains('\0') {
            return Ok(Outcome::Respond(Response::text(
                StatusCode::FORBIDDEN,
                "403 Forbidden",
            )));
        }
        let relative = decoded_path.trim_start_matches('/');
        // Caddy trims a trailing `/` before stating the path ("remove any trailing `/` as it
        // breaks fs.ValidPath"); the request path keeps it for the canonical redirect.
        let stat_relative = relative.trim_end_matches('/');
        if self.hidden(stat_relative, &request) {
            return self.not_found(request);
        }
        // Expand `{http.vars.root}` and friends (Caddy's file_server root supports placeholders).
        let expanded_root = request.replace_all(&self.root);
        let root = if expanded_root.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(expanded_root)
        };
        let full_path = root.join(stat_relative);
        let request_path = request.uri.path().to_string();

        let metadata = match fs::metadata(&full_path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return self.not_found(request)
            }
            Err(error) => return Err(Error::Io(error)),
        };

        let mut filename = full_path;
        let mut metadata = metadata;
        let mut implicit_index = false;
        if metadata.is_dir() && !self.index_names.is_empty() {
            for index in &self.index_names {
                // Caddy: `indexPage := repl.ReplaceAll(indexPage, "")` (staticfiles.go).
                let index = request.replace_all(index);
                if index.is_empty() {
                    continue;
                }
                let candidate = filename.join(index);
                if let Ok(index_metadata) = fs::metadata(&candidate).await {
                    if index_metadata.is_file() {
                        filename = candidate;
                        metadata = index_metadata;
                        implicit_index = true;
                        break;
                    }
                }
            }
        }

        if metadata.is_dir() {
            if self.canonical_uris && !request_path.ends_with('/') {
                return Ok(Outcome::Respond(permanent_redirect(
                    &request_path,
                    &format!("{request_path}/"),
                    request.uri.query(),
                    request.method == http::Method::HEAD,
                )));
            }
            if self.browse {
                let body = browse_html(&filename, request.uri.clone(), relative).await?;
                return Ok(Outcome::Respond(Response::bytes(
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                    body,
                )));
            }
            return self.not_found(request);
        }

        if !metadata.is_file() {
            return self.not_found(request);
        }
        if self.hidden(&filename.to_string_lossy(), &request) {
            return self.not_found(request);
        }
        if self.canonical_uris {
            if implicit_index && !request_path.ends_with('/') {
                return Ok(Outcome::Respond(permanent_redirect(
                    &request_path,
                    &format!("{request_path}/"),
                    request.uri.query(),
                    request.method == http::Method::HEAD,
                )));
            }
            if !implicit_index && request_path.ends_with('/') {
                let trimmed = request_path.trim_end_matches('/');
                let to = if trimmed.is_empty() { "/" } else { trimmed };
                return Ok(Outcome::Respond(permanent_redirect(
                    &request_path,
                    to,
                    request.uri.query(),
                    request.method == http::Method::HEAD,
                )));
            }
        }
        let original_name = filename.to_string_lossy().to_string();
        self.serve_file(request, &filename, &original_name).await
    }
}

/// Caddy's `redirect` (`http.Redirect` with status 308): same-origin path, query preserved, HTML
/// body for GET.
fn permanent_redirect(_from: &str, to: &str, query: Option<&str>, head: bool) -> Response {
    // Caddy strips leading `//` to prevent protocol-relative open redirects.
    let mut target = to.to_string();
    while target.starts_with("//") {
        target.remove(0);
    }
    if let Some(query) = query {
        if !query.is_empty() {
            target.push('?');
            target.push_str(query);
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&target).expect("location is a valid header value"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    let body_text = format!(
        "<a href=\"{}\">{}</a>.\n",
        html_escape(&target),
        "Permanent Redirect"
    );
    let body = Bytes::from(format!("{body_text}\n"));
    if head {
        // Go's http.Redirect writes no body (and no Content-Length) for HEAD requests.
        return Response {
            status: StatusCode::PERMANENT_REDIRECT,
            headers,
            body: Bytes::new(),
        };
    }
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).expect("length is a valid header value"),
    );
    Response {
        status: StatusCode::PERMANENT_REDIRECT,
        headers,
        body,
    }
}

/// Go's `http.Error`: clears caching/representation headers, then writes a text/plain body (with a
/// trailing newline) and a length.
fn serve_error(head: bool, mut headers: HeaderMap, status: StatusCode, message: &str) -> Response {
    for name in [
        header::CACHE_CONTROL,
        header::CONTENT_ENCODING,
        header::ETAG,
        header::LAST_MODIFIED,
    ] {
        headers.remove(name);
    }
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    let body = Bytes::from(format!("{message}\n"));
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).expect("length is a valid header value"),
    );
    Response {
        status,
        headers,
        body: if head { Bytes::new() } else { body },
    }
}

/// The modification time of a file as Unix seconds/nanoseconds, when representable.
#[derive(Debug, Clone, Copy)]
struct ModTime {
    unix: i64,
    unix_nano: i64,
}

fn mod_time(metadata: &std::fs::Metadata) -> Option<ModTime> {
    let modified = metadata.modified().ok()?;
    let (seconds, nanos) = match modified.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs() as i64, duration.subsec_nanos()),
        Err(error) => {
            let duration = error.duration();
            (
                -(duration.as_secs() as i64) - i64::from(duration.subsec_nanos() > 0),
                if duration.subsec_nanos() > 0 {
                    1_000_000_000 - duration.subsec_nanos()
                } else {
                    0
                },
            )
        }
    };
    Some(ModTime {
        unix: seconds,
        unix_nano: seconds * 1_000_000_000 + i64::from(nanos),
    })
}

fn base36(mut value: i64) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if value == 0 {
        return "0".to_string();
    }
    let negative = value < 0;
    if negative {
        value = -value;
    }
    let mut digits = Vec::new();
    while value > 0 {
        digits.push(DIGITS[(value % 36) as usize]);
        value /= 36;
    }
    if negative {
        digits.push(b'-');
    }
    digits.reverse();
    String::from_utf8(digits).expect("base36 is ASCII")
}

/// Caddy's `calculateEtag`: a strong validator built from mtime nanoseconds and size.
fn calculate_etag(metadata: &std::fs::Metadata) -> String {
    let Some(time) = mod_time(metadata) else {
        return String::new();
    };
    if time.unix == 0 || time.unix == 1 {
        return String::new();
    }
    format!(
        "\"{}-{}\"",
        base36(time.unix_nano),
        base36(metadata.len() as i64)
    )
}

/// Read an ETag from a sidecar file (`etag_file_extensions`), removing newlines like Caddy.
async fn read_etag_sidecar(filename: &Path, suffixes: &[String]) -> Result<Option<String>> {
    for suffix in suffixes {
        let candidate = PathBuf::from(format!("{}{suffix}", filename.display()));
        match fs::read(&candidate).await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).replace('\n', "");
                return Ok(Some(text));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(Error::Handler {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    message: format!(
                        "cannot read etag from file {}: {error}",
                        candidate.display()
                    ),
                })
            }
        }
    }
    Ok(None)
}

fn content_encoding_present(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .map(|value| !value.is_empty())
        .unwrap_or(false)
}

/// Caddy's `encode.AcceptedEncodings`: parse Accept-Encoding, drop q=0/WebSocket, sort by q
/// descending then server preference.
fn accepted_encodings(request: &Request, preferred_order: &[String]) -> Vec<String> {
    let Some(raw) = request.headers.get(header::ACCEPT_ENCODING) else {
        return Vec::new();
    };
    let Ok(raw) = raw.to_str() else {
        return Vec::new();
    };
    if raw.trim().is_empty() {
        return Vec::new();
    }
    let websocket = request
        .headers
        .get("sec-websocket-key")
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    let mut preferences: Vec<(String, f64, i64)> = Vec::new();
    for accepted in raw.split(',') {
        let (name, params) = accepted.split_once(';').unwrap_or((accepted, ""));
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let mut q = 1.0_f64;
        if !params.is_empty() {
            for param in params.split(';') {
                let param = param.trim();
                if let Some(value) = param
                    .strip_prefix("q=")
                    .or_else(|| param.strip_prefix("Q="))
                {
                    if let Ok(parsed) = value.trim().parse::<f32>() {
                        let parsed = f64::from(parsed);
                        if (0.0..=1.0).contains(&parsed) {
                            q = parsed;
                        }
                    }
                    break;
                }
            }
        }
        if q < 0.00001 {
            continue;
        }
        if websocket && name != "identity" {
            continue;
        }
        let preference = match preferred_order.iter().position(|format| *format == name) {
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
    preferences
        .into_iter()
        .map(|(encoding, _, _)| encoding)
        .collect()
}

// ---- conditional requests (Go net/http fs.go) ------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cond {
    None,
    True,
    False,
}

/// The `Etag` header value carried by the response headers, for precondition checks.
fn response_etag(headers: &HeaderMap) -> String {
    headers
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn scan_etag(value: &str) -> (String, String) {
    let value = value.trim();
    let start = if value.starts_with("W/") { 2 } else { 0 };
    if value.len() < start + 2 || value.as_bytes().get(start) != Some(&b'"') {
        return (String::new(), String::new());
    }
    for (index, byte) in value.as_bytes().iter().enumerate().skip(start + 1) {
        match *byte {
            0x21 | 0x23..=0x7e | 0x80..=0xff => {}
            b'"' => return (value[..=index].to_string(), value[index + 1..].to_string()),
            _ => return (String::new(), String::new()),
        }
    }
    (String::new(), String::new())
}

fn etag_strong_match(left: &str, right: &str) -> bool {
    left == right && !left.is_empty() && left.starts_with('"')
}

fn etag_weak_match(left: &str, right: &str) -> bool {
    left.strip_prefix("W/").unwrap_or(left) == right.strip_prefix("W/").unwrap_or(right)
}

fn check_if_match(request: &Request, etag: &str) -> Cond {
    let Some(value) = request
        .headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
    else {
        return Cond::None;
    };
    let mut remaining = value;
    loop {
        remaining = remaining.trim();
        if remaining.is_empty() {
            break;
        }
        if let Some(rest) = remaining.strip_prefix(',') {
            remaining = rest;
            continue;
        }
        if remaining.starts_with('*') {
            return Cond::True;
        }
        let (candidate, rest) = scan_etag(remaining);
        if candidate.is_empty() {
            break;
        }
        if etag_strong_match(&candidate, etag) {
            return Cond::True;
        }
        remaining = &remaining[remaining.len() - rest.len()..];
    }
    Cond::False
}

fn check_if_unmodified_since(request: &Request, modtime: Option<ModTime>) -> Cond {
    let Some(value) = request
        .headers
        .get(header::IF_UNMODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
    else {
        return Cond::None;
    };
    let Some(time) = modtime else {
        return Cond::None;
    };
    let Some(parsed) = parse_http_date(value) else {
        return Cond::None;
    };
    if time.unix <= parsed {
        Cond::True
    } else {
        Cond::False
    }
}

fn check_if_none_match(request: &Request, etag: &str) -> Cond {
    let Some(value) = request
        .headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    else {
        return Cond::None;
    };
    let mut remaining = value;
    loop {
        remaining = remaining.trim();
        if remaining.is_empty() {
            break;
        }
        if let Some(rest) = remaining.strip_prefix(',') {
            remaining = rest;
            continue;
        }
        if remaining.starts_with('*') {
            return Cond::False;
        }
        let (candidate, rest) = scan_etag(remaining);
        if candidate.is_empty() {
            break;
        }
        if etag_weak_match(&candidate, etag) {
            return Cond::False;
        }
        remaining = &remaining[remaining.len() - rest.len()..];
    }
    Cond::True
}

fn check_if_modified_since(request: &Request, modtime: Option<ModTime>) -> Cond {
    if request.method != http::Method::GET && request.method != http::Method::HEAD {
        return Cond::None;
    }
    let Some(value) = request
        .headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
    else {
        return Cond::None;
    };
    let Some(time) = modtime else {
        return Cond::None;
    };
    let Some(parsed) = parse_http_date(value) else {
        return Cond::None;
    };
    if time.unix <= parsed {
        Cond::False
    } else {
        Cond::True
    }
}

fn check_if_range(request: &Request, etag: &str, modtime: Option<ModTime>, useful: bool) -> bool {
    let Some(value) = request
        .headers
        .get(header::IF_RANGE)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let (candidate, _) = scan_etag(value);
    if !candidate.is_empty() {
        return etag_strong_match(&candidate, etag);
    }
    let Some(time) = modtime else {
        return false;
    };
    if !useful {
        return false;
    }
    parse_http_date(value).is_some_and(|parsed| parsed == time.unix)
}

/// Go's `checkPreconditions`: returns the short-circuit status (304/412), if any.
fn conditional_status(
    request: &Request,
    headers: &HeaderMap,
    modtime: Option<ModTime>,
    useful_modtime: bool,
) -> Option<StatusCode> {
    let etag = response_etag(headers);
    let modtime = if useful_modtime { modtime } else { None };
    let mut check = check_if_match(request, &etag);
    if check == Cond::None {
        check = check_if_unmodified_since(request, modtime);
    }
    if check == Cond::False {
        return Some(StatusCode::PRECONDITION_FAILED);
    }
    match check_if_none_match(request, &etag) {
        Cond::False => {
            if request.method == http::Method::GET || request.method == http::Method::HEAD {
                return Some(StatusCode::NOT_MODIFIED);
            }
            return Some(StatusCode::PRECONDITION_FAILED);
        }
        Cond::None => {
            if check_if_modified_since(request, modtime) == Cond::False {
                return Some(StatusCode::NOT_MODIFIED);
            }
        }
        Cond::True => {}
    }
    None
}

// ---- ranges (Go net/http fs.go) ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ByteRange {
    start: i64,
    length: i64,
}

impl ByteRange {
    fn content_range(self, size: i64) -> String {
        format!(
            "bytes {}-{}/{}",
            self.start,
            self.start + self.length - 1,
            size
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RangeError {
    Invalid,
    NoOverlap,
}

fn parse_range(header: &str, size: i64) -> std::result::Result<Vec<ByteRange>, RangeError> {
    if header.is_empty() {
        return Ok(Vec::new());
    }
    let Some(spec) = header.strip_prefix("bytes=") else {
        return Err(RangeError::Invalid);
    };
    let mut ranges: Vec<ByteRange> = Vec::new();
    let mut no_overlap = false;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((start, end)) = part.split_once('-') else {
            return Err(RangeError::Invalid);
        };
        let (start, end) = (start.trim(), end.trim());
        if start.is_empty() {
            if end.is_empty() || end.starts_with('-') {
                return Err(RangeError::Invalid);
            }
            let parsed: i64 = end.parse().map_err(|_| RangeError::Invalid)?;
            if parsed < 0 {
                return Err(RangeError::Invalid);
            }
            let length = parsed.min(size);
            ranges.push(ByteRange {
                start: size - length,
                length,
            });
        } else {
            let parsed_start: i64 = start.parse().map_err(|_| RangeError::Invalid)?;
            if parsed_start < 0 {
                return Err(RangeError::Invalid);
            }
            if parsed_start >= size {
                no_overlap = true;
                continue;
            }
            let length = if end.is_empty() {
                size - parsed_start
            } else {
                let parsed_end: i64 = end.parse().map_err(|_| RangeError::Invalid)?;
                if parsed_start > parsed_end {
                    return Err(RangeError::Invalid);
                }
                let parsed_end = parsed_end.min(size - 1);
                parsed_end - parsed_start + 1
            };
            ranges.push(ByteRange {
                start: parsed_start,
                length,
            });
        }
    }
    if no_overlap && ranges.is_empty() {
        return Err(RangeError::NoOverlap);
    }
    Ok(ranges)
}

/// A random 60-hex-digit multipart boundary (Go's `mime/multipart.randomBoundary`).
fn multipart_boundary() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let process = std::process::id() as u128;
    let mut state = nanos.wrapping_mul(6364136223846793005) ^ process.rotate_left(32);
    let mut output = String::with_capacity(60);
    for _ in 0..60 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let digit = ((state >> 60) & 0xf) as u8;
        output.push(char::from(b"0123456789abcdef"[digit as usize]));
    }
    output
}

fn multipart_body(
    ranges: &[ByteRange],
    content_type: &str,
    size: i64,
    boundary: &str,
    representation: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    for range in ranges {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Range: {}\r\n", range.content_range(size)).as_bytes(),
        );
        body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        body.extend_from_slice(b"\r\n");
        let start = range.start as usize;
        let end = (range.start + range.length) as usize;
        body.extend_from_slice(&representation[start..end]);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

async fn browse_html(root: &Path, uri: Uri, relative: &str) -> Result<Vec<u8>> {
    let mut entries = fs::read_dir(root).await?;
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry
            .file_type()
            .await
            .map(|file_type| file_type.is_dir())
            .unwrap_or(false);
        names.push((name, is_dir));
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Index</title></head><body><h1>Index of ");
    html.push_str(&html_escape(uri.path()));
    html.push_str("</h1><ul>");
    if !relative.is_empty() {
        html.push_str("<li><a href=\"../\">../</a></li>");
    }
    for (name, is_dir) in names {
        let suffix = if is_dir { "/" } else { "" };
        html.push_str("<li><a href=\"");
        html.push_str(&percent_encode_path_segment(&name));
        html.push_str(suffix);
        html.push_str("\">");
        html.push_str(&html_escape(&name));
        html.push_str(suffix);
        html.push_str("</a></li>");
    }
    html.push_str("</ul></body></html>");
    Ok(html.into_bytes())
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn percent_encode_path_segment(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            other => output.push_str(&format!("%{other:02X}")),
        }
    }
    output
}

/// Go's `mime.TypeByExtension` values for the extensions this server commonly serves (`None` means
/// no Content-Type is sent; Caddy prevents Go from sniffing the content).
fn mime_type(name: &str) -> Option<&'static str> {
    let extension = name.rsplit_once('.').map(|(_, extension)| extension)?;
    let extension = extension.to_ascii_lowercase();
    Some(match extension.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "xml" => "text/xml; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/vnd.microsoft.icon",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "gz" => "application/gzip",
        "br" => "application/octet-stream",
        _ => return None,
    })
}

// ---- HTTP dates -------------------------------------------------------------------------------

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Format Unix seconds as an RFC 1123 date in GMT (Go's `TimeFormat`).
fn format_http_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let seconds_of_day = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let weekday = WEEKDAYS[((days + 4).rem_euclid(7)) as usize];
    format!(
        "{weekday}, {day:02} {} {year:04} {hour:02}:{minute:02}:{second:02} GMT",
        MONTHS[(month - 1) as usize]
    )
}

/// Howard Hinnant's `civil_from_days` (proleptic Gregorian calendar, days since 1970-01-01).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Parse the three date formats Go's `http.ParseTime` accepts.
fn parse_http_date(value: &str) -> Option<i64> {
    let value = value.trim();
    let tokens: Vec<&str> = value.split_whitespace().collect();
    match tokens.as_slice() {
        // RFC1123: "Thu, 02 Jan 2025 03:04:05 GMT" (Go's TimeFormat always has the weekday).
        [_, day, month, year, time, "GMT"] => parse_time_parts(day, month, year, time),
        // RFC850: "Thursday, 02-Jan-25 03:04:05 GMT".
        [_, date, time, "GMT"] => {
            let parts: Vec<&str> = date.split('-').collect();
            match parts.as_slice() {
                [day, month, year] => parse_time_parts(day, month, year, time),
                _ => None,
            }
        }
        // ANSI C asctime: "Thu Jan  2 03:04:05 2025".
        [_, month, day, time, year] => parse_time_parts(day, month, year, time),
        _ => None,
    }
}

fn parse_time_parts(day: &str, month: &str, year: &str, time: &str) -> Option<i64> {
    let day: i64 = day.trim_start_matches('0').parse().ok().or_else(|| {
        if day == "0" {
            Some(0)
        } else {
            None
        }
    })?;
    let month = MONTHS
        .iter()
        .position(|candidate| *candidate == month)
        .map(|index| index as i64 + 1)?;
    let mut year: i64 = year.parse().ok()?;
    if year < 100 {
        // RFC850 two-digit years are interpreted relative to the current century.
        year += if year < 70 { 2000 } else { 1900 };
    }
    let mut parts = time.split(':');
    let hour: i64 = parts.next()?.parse().ok()?;
    let minute: i64 = parts.next()?.parse().ok()?;
    let second: i64 = parts.next()?.parse().ok()?;
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Request;
    use http::Method;

    async fn handler(root: &Path) -> FileServerHandler {
        FileServerHandler::from_json(
            &serde_json::json!({"handler": "file_server", "root": root}),
            "handler",
        )
        .unwrap()
    }

    fn set_mtime(path: &Path, seconds: i64) {
        let file = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open file for mtime");
        file.set_modified(UNIX_EPOCH + std::time::Duration::from_secs(seconds as u64))
            .expect("set mtime");
    }

    fn make_request(method: Method, path: &str) -> Request {
        Request::new(method, path.parse().unwrap())
    }

    async fn respond(handler: &FileServerHandler, request: Request) -> Response {
        match handler.handle(request).await.unwrap() {
            Outcome::Respond(response) => response,
            Outcome::Continue(_) => panic!("expected a response"),
        }
    }

    fn header(response: &Response, name: header::HeaderName) -> String {
        response
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    #[tokio::test]
    async fn serves_existing_file_with_mime_type() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hello.txt");
        std::fs::write(&file, b"hi").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/hello.txt")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"hi"));
        assert_eq!(
            header(&response, header::CONTENT_TYPE),
            "text/plain; charset=utf-8"
        );
        assert_eq!(header(&response, header::ACCEPT_RANGES), "bytes");
        assert_eq!(header(&response, header::VARY), "Accept-Encoding");
        assert_eq!(header(&response, header::CONTENT_LENGTH), "2");
        assert!(header(&response, header::LAST_MODIFIED).ends_with("GMT"));
        assert_eq!(
            header(&response, header::ETAG),
            calculate_etag(&std::fs::metadata(&file).unwrap())
        );
    }

    #[tokio::test]
    async fn serves_directory_index() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs/index.html"), b"<h1>docs</h1>").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/docs/")).await;
        assert_eq!(response.body, Bytes::from_static(b"<h1>docs</h1>"));
    }

    #[tokio::test]
    async fn pass_thru_continues_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let handler = FileServerHandler::from_json(
            &serde_json::json!({"handler": "file_server", "root": dir.path(), "pass_thru": true}),
            "handler",
        )
        .unwrap();
        let request = Request::new(Method::GET, "/missing".parse().unwrap());
        assert!(matches!(
            handler.handle(request).await.unwrap(),
            Outcome::Continue(_)
        ));
    }

    #[tokio::test]
    async fn rejects_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(dir.path()).await;
        let request = Request::new(Method::GET, "/../etc/passwd".parse().unwrap());
        let Outcome::Respond(response) = handler.handle(request).await.unwrap() else {
            panic!("expected rejection");
        };
        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn single_range_returns_partial_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=2-5".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.body, Bytes::from_static(b"2345"));
        assert_eq!(header(&response, header::CONTENT_RANGE), "bytes 2-5/10");
        assert_eq!(header(&response, header::CONTENT_LENGTH), "4");
    }

    #[tokio::test]
    async fn suffix_and_open_ranges_match_caddy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        let handler = handler(dir.path()).await;
        for (range, expected, content_range) in [
            ("bytes=-3", "789", "bytes 7-9/10"),
            ("bytes=7-", "789", "bytes 7-9/10"),
            ("bytes=0-100", "0123456789", "bytes 0-9/10"),
        ] {
            let mut request = make_request(Method::GET, "/file.txt");
            request
                .headers
                .insert(header::RANGE, range.parse().unwrap());
            let response = respond(&handler, request).await;
            assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
            assert_eq!(response.body, Bytes::from_static(expected.as_bytes()));
            assert_eq!(header(&response, header::CONTENT_RANGE), content_range);
        }
    }

    #[tokio::test]
    async fn multipart_ranges_are_served() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=0-1,4-5".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        let content_type = header(&response, header::CONTENT_TYPE);
        let boundary = content_type
            .strip_prefix("multipart/byteranges; boundary=")
            .expect("multipart content type");
        let text = String::from_utf8(response.body.to_vec()).unwrap();
        assert!(text.contains(&format!("--{boundary}\r\n")));
        assert!(text.contains("Content-Range: bytes 0-1/10"));
        assert!(text.contains("Content-Range: bytes 4-5/10"));
        assert!(text.ends_with(&format!("--{boundary}--\r\n")));
        assert_eq!(
            header(&response, header::CONTENT_LENGTH),
            response.body.len().to_string()
        );
    }

    #[tokio::test]
    async fn unsatisfiable_range_is_416_with_content_range() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=99-100".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(header(&response, header::CONTENT_RANGE), "bytes */10");
        assert_eq!(
            header(&response, header::CONTENT_TYPE),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.body,
            Bytes::from_static(b"invalid range: failed to overlap\n")
        );
        assert!(header(&response, header::ETAG).is_empty());
        assert!(header(&response, header::LAST_MODIFIED).is_empty());
    }

    #[tokio::test]
    async fn invalid_range_is_416() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=abc".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.body, Bytes::from_static(b"invalid range\n"));
    }

    #[tokio::test]
    async fn empty_file_ignores_range() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.txt"), b"").unwrap();
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::GET, "/empty.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=0-0".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());
        assert_eq!(header(&response, header::CONTENT_LENGTH), "0");
    }

    #[tokio::test]
    async fn oversized_range_sum_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=0-9,0-9".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"0123456789"));
    }

    #[tokio::test]
    async fn head_has_full_headers_and_no_body() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::HEAD, "/file.txt")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());
        assert_eq!(header(&response, header::CONTENT_LENGTH), "10");
        assert_eq!(
            header(&response, header::CONTENT_TYPE),
            "text/plain; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn other_methods_are_405_with_allow() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::POST, "/file.txt")).await;
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(header(&response, header::ALLOW), "GET, HEAD");
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn if_none_match_returns_304_with_etag_and_vary() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"0123456789").unwrap();
        let etag = calculate_etag(&std::fs::metadata(&file).unwrap());
        let handler = handler(dir.path()).await;
        for condition in [
            etag.clone(),
            format!("W/{etag}"),
            format!("\"bogus\", {etag}"),
        ] {
            let mut request = make_request(Method::GET, "/file.txt");
            request
                .headers
                .insert(header::IF_NONE_MATCH, condition.parse().unwrap());
            let response = respond(&handler, request).await;
            assert_eq!(response.status, StatusCode::NOT_MODIFIED);
            assert!(response.body.is_empty());
            assert_eq!(header(&response, header::ETAG), etag);
            assert_eq!(header(&response, header::VARY), "Accept-Encoding");
            assert!(header(&response, header::CONTENT_TYPE).is_empty());
            assert!(header(&response, header::CONTENT_LENGTH).is_empty());
            assert!(header(&response, header::LAST_MODIFIED).is_empty());
        }
    }

    #[tokio::test]
    async fn if_modified_since_returns_304() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"x").unwrap();
        set_mtime(&file, 1_735_787_045);
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::GET, "/file.txt");
        request.headers.insert(
            header::IF_MODIFIED_SINCE,
            "Thu, 02 Jan 2025 03:04:05 GMT".parse().unwrap(),
        );
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::NOT_MODIFIED);
        let mut request = make_request(Method::GET, "/file.txt");
        request.headers.insert(
            header::IF_MODIFIED_SINCE,
            "Wed, 01 Jan 2025 03:04:05 GMT".parse().unwrap(),
        );
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn failed_preconditions_are_412() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::IF_MATCH, "\"bogus\"".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        let mut request = make_request(Method::GET, "/file.txt");
        request.headers.insert(
            header::IF_UNMODIFIED_SINCE,
            "Wed, 01 Jan 2025 03:04:05 GMT".parse().unwrap(),
        );
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn if_range_controls_range_support() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"0123456789").unwrap();
        let etag = calculate_etag(&std::fs::metadata(&file).unwrap());
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=0-3".parse().unwrap());
        request
            .headers
            .insert(header::IF_RANGE, etag.parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=0-3".parse().unwrap());
        request
            .headers
            .insert(header::IF_RANGE, "\"bogus\"".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"0123456789"));
    }

    #[tokio::test]
    async fn unknown_extension_has_no_content_type() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.unknown"), b"x").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/file.unknown")).await;
        assert!(response.headers.get(header::CONTENT_TYPE).is_none());
    }

    #[tokio::test]
    async fn status_override_applies_to_success_and_ranges() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        let handler = FileServerHandler::from_json(
            &serde_json::json!({"handler": "file_server", "root": dir.path(), "status_code": 404}),
            "handler",
        )
        .unwrap();
        let response = respond(&handler, make_request(Method::GET, "/file.txt")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=0-1".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn directory_requests_redirect_with_slash_and_html_body() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/index.html"), b"index").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/sub")).await;
        assert_eq!(response.status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(header(&response, header::LOCATION), "/sub/");
        assert_eq!(
            response.body,
            Bytes::from_static(b"<a href=\"/sub/\">Permanent Redirect</a>.\n\n")
        );
    }

    async fn precompressed_handler(root: &Path, order: &[&str]) -> FileServerHandler {
        FileServerHandler::from_json(
            &serde_json::json!({
                "handler": "file_server",
                "root": root,
                "precompressed": {"gzip": {}, "br": {}},
                "precompressed_order": order
            }),
            "handler",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn precompressed_sidecar_selection_and_headers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("side.txt"), b"0123456789").unwrap();
        std::fs::write(dir.path().join("side.txt.gz"), b"GZIPBYTES01").unwrap();
        std::fs::write(dir.path().join("side.txt.br"), b"BRBYTES01").unwrap();
        let handler = precompressed_handler(dir.path(), &["gzip", "br"]).await;
        let mut request = make_request(Method::GET, "/side.txt");
        request
            .headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"GZIPBYTES01"));
        assert_eq!(header(&response, header::CONTENT_ENCODING), "gzip");
        assert_eq!(
            header(&response, header::CONTENT_TYPE),
            "text/plain; charset=utf-8"
        );
        assert_eq!(header(&response, header::CONTENT_LENGTH), "11");
        assert_eq!(header(&response, header::VARY), "Accept-Encoding");
        let gz = std::fs::metadata(dir.path().join("side.txt.gz")).unwrap();
        assert_eq!(header(&response, header::ETAG), calculate_etag(&gz));

        // Br is chosen when the q-values/preference order prefer it.
        let mut request = make_request(Method::GET, "/side.txt");
        request.headers.insert(
            header::ACCEPT_ENCODING,
            "gzip;q=0.5, br;q=0.9".parse().unwrap(),
        );
        let response = respond(&handler, request).await;
        assert_eq!(header(&response, header::CONTENT_ENCODING), "br");
        assert_eq!(response.body, Bytes::from_static(b"BRBYTES01"));
    }

    #[tokio::test]
    async fn precompressed_ranges_apply_to_the_encoded_representation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("side.txt"), b"0123456789").unwrap();
        std::fs::write(dir.path().join("side.txt.gz"), b"GZIPBYTES01").unwrap();
        let handler = precompressed_handler(dir.path(), &["gzip"]).await;
        let mut request = make_request(Method::GET, "/side.txt");
        request
            .headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        request
            .headers
            .insert(header::RANGE, "bytes=1-3".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.body, Bytes::from_static(b"ZIP"));
        assert_eq!(header(&response, header::CONTENT_RANGE), "bytes 1-3/11");
        assert_eq!(header(&response, header::CONTENT_ENCODING), "gzip");
    }

    #[tokio::test]
    async fn precompressed_missing_sidecar_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("plain.txt"), b"0123456789").unwrap();
        let handler = precompressed_handler(dir.path(), &["gzip"]).await;
        let mut request = make_request(Method::GET, "/plain.txt");
        request
            .headers
            .insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let response = respond(&handler, request).await;
        assert!(header(&response, header::CONTENT_ENCODING).is_empty());
        assert_eq!(response.body, Bytes::from_static(b"0123456789"));
    }

    #[test]
    fn unsupported_file_server_forms_are_loud() {
        let error = match FileServerHandler::from_json(
            &serde_json::json!({"handler": "file_server", "fs": "custom"}),
            "handler",
        ) {
            Ok(_) => panic!("custom filesystems are not implemented"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::NotImplemented { .. }), "{error}");
        let error = match FileServerHandler::from_json(
            &serde_json::json!({"handler": "file_server", "precompressed": {"deflate": {}}}),
            "handler",
        ) {
            Ok(_) => panic!("unknown precompressed formats are loud"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("deflate"), "{error}");
    }

    #[test]
    fn http_date_round_trips_and_matches_caddy_format() {
        assert_eq!(
            format_http_date(1_735_787_045),
            "Thu, 02 Jan 2025 03:04:05 GMT"
        );
        assert_eq!(
            parse_http_date("Thu, 02 Jan 2025 03:04:05 GMT"),
            Some(1_735_787_045)
        );
        assert_eq!(
            parse_http_date("Thursday, 02-Jan-25 03:04:05 GMT"),
            Some(1_735_787_045)
        );
        assert_eq!(
            parse_http_date("Thu Jan  2 03:04:05 2025"),
            Some(1_735_787_045)
        );
        assert_eq!(parse_http_date("garbage"), None);
    }

    #[tokio::test]
    async fn head_range_keeps_partial_headers_without_a_body() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        let handler = handler(dir.path()).await;
        let mut request = make_request(Method::HEAD, "/file.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=2-5".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert!(response.body.is_empty());
        assert_eq!(header(&response, header::CONTENT_LENGTH), "4");
        assert_eq!(header(&response, header::CONTENT_RANGE), "bytes 2-5/10");
    }

    #[tokio::test]
    async fn etag_file_extensions_override_the_computed_validator() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"0123456789").unwrap();
        std::fs::write(dir.path().join("file.txt.etag"), b"\"custom-etag\"\n").unwrap();
        let handler = FileServerHandler::from_json(
            &serde_json::json!({
                "handler": "file_server",
                "root": dir.path(),
                "etag_file_extensions": [".etag"]
            }),
            "handler",
        )
        .unwrap();
        let response = respond(&handler, make_request(Method::GET, "/file.txt")).await;
        assert_eq!(header(&response, header::ETAG), "\"custom-etag\"");
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::IF_NONE_MATCH, "\"custom-etag\"".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn missing_etag_sidecar_falls_back_to_the_computed_validator() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"0123456789").unwrap();
        let handler = FileServerHandler::from_json(
            &serde_json::json!({
                "handler": "file_server",
                "root": dir.path(),
                "etag_file_extensions": [".etag", ".sha256"]
            }),
            "handler",
        )
        .unwrap();
        let response = respond(&handler, make_request(Method::GET, "/file.txt")).await;
        assert_eq!(
            header(&response, header::ETAG),
            calculate_etag(&std::fs::metadata(&file).unwrap())
        );
    }

    #[tokio::test]
    async fn zero_mtime_suppresses_validators() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"0123456789").unwrap();
        let epoch = std::fs::File::options().write(true).open(&file).unwrap();
        epoch.set_modified(UNIX_EPOCH).expect("set epoch mtime");
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/file.txt")).await;
        assert!(header(&response, header::LAST_MODIFIED).is_empty());
        assert!(header(&response, header::ETAG).is_empty());
        // `If-None-Match: *` still matches a representation without an ETag (Go semantics).
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .headers
            .insert(header::IF_NONE_MATCH, "*".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::NOT_MODIFIED);
        assert!(header(&response, header::ETAG).is_empty());
        assert_eq!(header(&response, header::VARY), "Accept-Encoding");
    }

    #[tokio::test]
    async fn status_code_placeholder_is_expanded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
        let handler = FileServerHandler::from_json(
            &serde_json::json!({
                "handler": "file_server",
                "root": dir.path(),
                "status_code": "{http.vars.file_status}"
            }),
            "handler",
        )
        .unwrap();
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .vars
            .insert("file_status".to_string(), "418".to_string());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn precompressed_server_order_breaks_equal_q_value_ties() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("side.txt"), b"0123456789").unwrap();
        std::fs::write(dir.path().join("side.txt.gz"), b"GZIPBYTES01").unwrap();
        std::fs::write(dir.path().join("side.txt.br"), b"BRBYTES01").unwrap();
        let handler = precompressed_handler(dir.path(), &["br", "gzip"]).await;
        let mut request = make_request(Method::GET, "/side.txt");
        request
            .headers
            .insert(header::ACCEPT_ENCODING, "gzip, br".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(header(&response, header::CONTENT_ENCODING), "br");
    }

    #[tokio::test]
    async fn head_redirect_has_no_body_or_content_length() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/index.html"), b"index").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::HEAD, "/sub")).await;
        assert_eq!(response.status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(header(&response, header::LOCATION), "/sub/");
        assert!(response.headers.get(header::CONTENT_LENGTH).is_none());
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn trailing_slash_file_redirects_and_preserves_the_query() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/file.txt/?a=1")).await;
        assert_eq!(response.status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(header(&response, header::LOCATION), "/file.txt?a=1");
        assert_eq!(
            response.body,
            Bytes::from_static(b"<a href=\"/file.txt?a=1\">Permanent Redirect</a>.\n\n")
        );
    }

    #[test]
    fn mime_table_matches_caddy_common_types() {
        assert_eq!(mime_type("a.md"), Some("text/markdown; charset=utf-8"));
        assert_eq!(mime_type("a.ico"), Some("image/vnd.microsoft.icon"));
        assert_eq!(mime_type("a.xml"), Some("text/xml; charset=utf-8"));
        assert_eq!(mime_type("a.unknown"), None);
        assert_eq!(mime_type("no-extension"), None);
    }

    #[test]
    fn etag_and_base36_match_caddy() {
        assert_eq!(base36(0), "0");
        assert_eq!(base36(10), "a");
        assert_eq!(base36(1_735_787_045_000_000_000), "d6r95k3vlgjk");
        assert_eq!(parse_range("bytes=0-0", 0), Err(RangeError::NoOverlap));
        assert_eq!(parse_range("items=0-1", 10), Err(RangeError::Invalid));
        assert_eq!(
            parse_range("bytes=5-4", 10),
            Err(RangeError::Invalid),
            "start > end is invalid"
        );
    }

    #[tokio::test]
    async fn root_hide_and_index_names_expand_placeholders() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("site");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("file.txt"), b"hello").unwrap();
        std::fs::write(root.join("secret.txt"), b"hidden").unwrap();
        std::fs::write(root.join("index.html"), b"index-body").unwrap();

        // `root` uses ReplaceAll semantics (`{http.vars.root}` plus custom vars).
        let handler = FileServerHandler::from_json(
            &serde_json::json!({"handler": "file_server", "root": "{http.vars.root}",
                "hide": ["{http.request.header.X-Hide}"],
                "index_names": ["{http.request.header.X-Index}"]}),
            "handler",
        )
        .unwrap();
        let mut request = make_request(Method::GET, "/file.txt");
        request
            .vars
            .insert("root".to_string(), root.display().to_string());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"hello"));

        // `hide` expands per request (Caddy: `repl.ReplaceAll(fsrv.Hide[i], "")`).
        let mut request = make_request(Method::GET, "/secret.txt");
        request
            .vars
            .insert("root".to_string(), root.display().to_string());
        request
            .headers
            .insert("x-hide", "secret.txt".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert!(
            !response.body.is_empty() || response.status == StatusCode::NOT_FOUND,
            "hidden file must not be served"
        );

        // `index_names` expands per request (Caddy: `repl.ReplaceAll(indexPage, "")`).
        let mut request = make_request(Method::GET, "/");
        request
            .vars
            .insert("root".to_string(), root.display().to_string());
        request
            .headers
            .insert("x-index", "index.html".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"index-body"));
    }

    #[tokio::test]
    async fn placeholder_expansion_does_not_bypass_traversal_guard() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("site");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(parent.path().join("outside.txt"), b"outside").unwrap();
        let handler = FileServerHandler::from_json(
            &serde_json::json!({"handler": "file_server", "root": "{http.vars.root}",
                "hide": ["{http.vars.hide_pattern}"]}),
            "handler",
        )
        .unwrap();
        let mut request = make_request(Method::GET, "/../outside.txt");
        request
            .vars
            .insert("root".to_string(), root.display().to_string());
        request
            .vars
            .insert("hide_pattern".to_string(), "outside.txt".to_string());
        let response = respond(&handler, request).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "request-path traversal remains rejected after placeholder expansion"
        );
    }
}
