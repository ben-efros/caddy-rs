//! Static file serving (`file_server`).
//!
//! Semantics follow Caddy v2.11.7 `modules/caddyhttp/fileserver/staticfiles.go`, which delegates the
//! representation transfer to Go's `net/http.ServeContent`: precompressed sidecar selection,
//! `Vary: Accept-Encoding`, ETag/Last-Modified, conditional requests (If-Match,
//! If-Unmodified-Since, If-None-Match, If-Modified-Since, If-Range), single and multipart byte
//! ranges, 206/304/412/416 responses, HEAD, and `Accept-Ranges: bytes`.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use tokio::fs;

use crate::body::StreamingResponse;
use crate::handlers::clean_path;
use crate::matchers::{glob_match, percent_decode};
use crate::types::{Error, Handler, Outcome, Request, Response, Result, StreamingOutcome};

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

/// Environment the file server resolves its automatic hide entries against, mirroring Caddy's
/// `FileServer.Provision`: both directories are looked up from the process environment and the
/// working directory once, when the module is provisioned.
#[derive(Debug, Clone)]
struct AutoHideEnv {
    cwd: PathBuf,
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
    xdg_data_home: Option<OsString>,
}

impl AutoHideEnv {
    fn from_process() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            xdg_config_home: std::env::var_os(caddy_rs_core::autosave::XDG_CONFIG_HOME_ENV),
            home: std::env::var_os(caddy_rs_core::autosave::HOME_ENV),
            xdg_data_home: std::env::var_os(caddy_rs_core::data_dir::XDG_DATA_HOME_ENV),
        }
    }
}

/// Lexically clean an absolute path like Go's `filepath.Clean`, keeping the root. Used for
/// Caddy's `FastAbs` comparisons, which never touch the filesystem. (The request-path
/// `clean_path` of the trailing-separator rejection is a separate, string-based helper.)
fn cleaned_absolute_path(path: &Path) -> PathBuf {
    let absolute = path.is_absolute();
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !cleaned.pop() && !absolute {
                    cleaned.push("..");
                }
            }
            other => cleaned.push(other.as_os_str()),
        }
    }
    cleaned
}

/// Caddy's `FastAbs`: lexical absolute form against the working directory.
fn fast_abs(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        cleaned_absolute_path(path)
    } else {
        cleaned_absolute_path(&cwd.join(path))
    }
}

/// The absolute hide entries Caddy's `FileServer.Provision` adds for a relative app data directory
/// (which holds private keys) or app config directory (which holds `autosave.json`, the loaded
/// configuration): both sit under the working directory when their XDG/HOME base is unavailable,
/// so serving `.` must not expose them (`caddy@a97bc460cfe5`, follow-up to #8327). Absolute
/// directories are skipped, and an entry is added once even when both directories resolve to the
/// same path.
fn auto_hide_entries(env: &AutoHideEnv) -> Vec<String> {
    let data =
        caddy_rs_core::data_dir::app_data_dir_with(env.xdg_data_home.clone(), env.home.clone());
    let config =
        caddy_rs_core::autosave::config_dir_with(env.xdg_config_home.clone(), env.home.clone());
    let mut entries: Vec<String> = Vec::new();
    for dir in [data, config] {
        if dir.is_absolute() {
            continue;
        }
        let entry = fast_abs(&dir, &env.cwd).to_string_lossy().into_owned();
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }
    entries
}

/// Precompressed sidecar encodings supported by this build, with their file suffixes (Caddy's
/// `http.precompressed.{gzip,brotli,zstd}` modules).
const PRECOMPRESSED_SUFFIXES: &[(&str, &str)] = &[("gzip", ".gz"), ("br", ".br"), ("zstd", ".zst")];

/// Upstream's `Browse` object (`modules/caddyhttp/fileserver/browse.go`).
///
/// `browse` used to be parsed as `as_bool().unwrap_or(is_object())`, so an OBJECT enabled browsing
/// and every key in it was discarded: an operator writing `{"browse": {"reveal_symlinks": true}}`
/// got neither the behaviour nor an error. AGENTS.md is explicit that silent approximation is a
/// defect.
///
/// `sort`, `file_limit` and `template_file` are upstream options caddy-rs does not implement. They
/// are a located error rather than a silent ignore. Unknown keys are refused too, so a future
/// upstream option cannot be dropped in silence the way these were -- default-ALLOW is what made the
/// original defect possible.
#[derive(Default, Clone, Debug)]
struct BrowseOptions {
    /// `reveal_symlinks`: show the symlink target path in the listing (T-BROWSE-OPTIONS-*).
    reveal_symlinks: bool,
    /// `plain_time_format`: a literal suffix appended to each entry's modification time.
    plain_time_format: Option<String>,
}

impl BrowseOptions {
    const KNOWN: &'static [&'static str] = &[
        "reveal_symlinks",
        "plain_time_format",
        "sort",
        "file_limit",
        "template_file",
    ];
    /// Upstream options caddy-rs does not implement.
    const UNIMPLEMENTED: &'static [&'static str] = &["sort", "file_limit", "template_file"];

    fn parse(value: &serde_json::Value, path: &str) -> Result<Option<Self>> {
        match value {
            serde_json::Value::Bool(true) => Ok(Some(Self::default())),
            serde_json::Value::Bool(false) => Ok(None),
            serde_json::Value::Object(map) => {
                if let Some(unknown) = map.keys().find(|key| !Self::KNOWN.contains(&key.as_str())) {
                    return Err(invalid(
                        path,
                        &format!(
                            "`browse` has no option `{unknown}`; the options are {}",
                            Self::KNOWN.join(", ")
                        ),
                    ));
                }
                for unsupported in Self::UNIMPLEMENTED {
                    if map.contains_key(*unsupported) {
                        return Err(invalid(
                            path,
                            &format!(
                                "`browse.{unsupported}` is not implemented by caddy-rs; remove it \
                                 rather than leaving it silently ignored"
                            ),
                        ));
                    }
                }
                let reveal_symlinks = match map.get("reveal_symlinks") {
                    None => false,
                    Some(flag) => flag.as_bool().ok_or_else(|| {
                        invalid(path, "`browse.reveal_symlinks` must be a boolean")
                    })?,
                };
                let plain_time_format = match map.get("plain_time_format") {
                    None => None,
                    Some(value) => Some(
                        value
                            .as_str()
                            .ok_or_else(|| {
                                invalid(path, "`browse.plain_time_format` must be a string")
                            })?
                            .to_string(),
                    ),
                };
                Ok(Some(Self {
                    reveal_symlinks,
                    plain_time_format,
                }))
            }
            _ => Err(invalid(path, "`browse` must be a boolean or an object")),
        }
    }
}

/// Serve files from a root directory.
pub struct FileServerHandler {
    root: String,
    hide: Vec<String>,
    index_names: Vec<String>,
    browse: Option<BrowseOptions>,
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

/// Is `path` absolute for the given target's path semantics?
///
/// A drive-letter path (`c:/site/x`) is absolute on Windows and merely relative on Unix, so the
/// host's `Path::is_absolute` cannot answer this when the code is being exercised for another
/// target (a test, or a cross-compiled build).
fn is_absolute_for(path: &str, windows: bool) -> bool {
    windows && {
        let bytes = path.as_bytes();
        bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'/' || bytes[2] == b'\\')
    }
}

/// Does one hide entry (already placeholder-expanded) hide `filename_abs`?
///
/// `filename_abs` is supplied in normalised form: `/` separators, and on Windows lower-cased.
/// `windows` controls the same normalisation for the entry, so the behaviour can be exercised for
/// a target that is not the host (a Linux CI run can still prove the Windows path).
fn hide_entry_matches(expanded: &str, filename_abs: &str, cwd: &Path, windows: bool) -> bool {
    if expanded.is_empty() {
        // An empty expansion (for example a missing placeholder) never hides anything.
        return false;
    }
    let normalise = |path: String| -> String {
        if windows {
            path.replace('\\', "/").to_ascii_lowercase()
        } else {
            path
        }
    };
    // Normalise the separator form BEFORE deciding whether the entry contains a path separator.
    // A native Windows entry (`C:\\site\\secret.txt`) has no `/` in it, so testing
    // `contains('/')` on the raw text sent it down the no-separator branch, where it was matched
    // only as a bare path component and could never match the normalised filename -- turning a
    // hidden file into a served one.
    let expanded = normalise(expanded.to_owned());
    let pattern = if expanded.contains('/') {
        // Only make the entry absolute when the host's own path semantics say it is relative.
        // A Windows drive entry (`c:/site/secret.txt`) is absolute for the Windows target but NOT
        // for `Path::is_absolute` on a Unix host, so probing with the host's `Path` would prefix
        // the cwd and produce an entry that can never match. Judge absoluteness for the target.
        if is_absolute_for(expanded.as_str(), windows) || Path::new(&expanded).is_absolute() {
            expanded
        } else {
            normalise(
                fast_abs(Path::new(&expanded), cwd)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    } else {
        expanded
    };
    if !pattern.contains('/') {
        if filename_abs
            .split('/')
            .any(|component| glob_match(&pattern, component, windows))
        {
            return true;
        }
    } else if let Some(rest) = filename_abs.strip_prefix(pattern.as_str()) {
        if rest.starts_with('/') {
            return true;
        }
    }
    glob_match(&pattern, filename_abs, windows)
}

impl FileServerHandler {
    /// Build from Caddy JSON.
    pub fn from_json(value: &serde_json::Value, path: &str) -> Result<Self> {
        Self::from_json_with_env(value, path, &AutoHideEnv::from_process())
    }

    fn from_json_with_env(
        value: &serde_json::Value,
        path: &str,
        env: &AutoHideEnv,
    ) -> Result<Self> {
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
        let mut hide = object
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
        // Caddy appends the automatically hidden app data/config directories in `Provision`, after
        // the configured entries; an explicit entry with the same absolute path is not repeated.
        for entry in auto_hide_entries(env) {
            if !hide.contains(&entry) {
                hide.push(entry);
            }
        }
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
        let browse = match object.get("browse") {
            None => None,
            Some(value) => BrowseOptions::parse(value, path)?,
        };
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

    /// Caddy's `fileHidden`: hide entries are filesystem paths whose base is the working directory,
    /// not the site root (`staticfiles.go`). An entry without a separator hides every path
    /// component with that name; an entry with a separator is made absolute (`FastAbs`) and hides
    /// itself and everything below it (prefix match on a separator boundary) or glob-matches the
    /// absolute filename. Automatic entries from [`auto_hide_entries`] are absolute, so this is
    /// where the relative app data/config directories become effective.
    fn hidden(&self, filename: &str, request: &Request) -> bool {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        // On Windows `PathBuf` yields `\` separators, which the `/`-based matching below would never
        // split on (so `hide .env` never matched a basename); compare in `/` form, case-insensitively.
        let normalise = |path: String| -> String {
            if cfg!(windows) {
                path.replace('\\', "/").to_ascii_lowercase()
            } else {
                path
            }
        };
        let filename_abs = normalise(
            fast_abs(Path::new(filename), &cwd)
                .to_string_lossy()
                .into_owned(),
        );
        self.hide.iter().any(|pattern| {
            // Caddy: `hide[i] = repl.ReplaceAll(fsrv.Hide[i], "")` (staticfiles.go).
            let expanded = request.replace_all(pattern);
            hide_entry_matches(&expanded, &filename_abs, &cwd, cfg!(windows))
        })
    }

    /// Serve one regular file through Caddy's `ServeContent` pipeline.
    async fn serve_file(
        &self,
        request: Request,
        filename: &Path,
        original_name: &str,
        root: &Path,
    ) -> Result<Outcome> {
        if path_contains_symlink(filename, root).await? {
            return Ok(Outcome::Respond(Response::text(
                StatusCode::FORBIDDEN,
                "403 Forbidden",
            )));
        }
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
            if path_contains_symlink(&sidecar, root).await? {
                return Ok(Outcome::Respond(Response::text(
                    StatusCode::FORBIDDEN,
                    "403 Forbidden",
                )));
            }
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

        // SEC-MEDIUM-HTTP B2: nothing is read from disk yet. Preconditions (304/412), HEAD and
        // Range responses are decided from `stat` alone, and only the bytes a response actually
        // carries are read afterwards, so a 1-byte range, a HEAD or a 304 of a multi-GiB file
        // costs no memory.
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
        let range_header = request
            .headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok());
        let if_range_ok = check_if_range(&request, &etag, modtime, useful_modtime);
        let head = request.method == http::Method::HEAD;
        // A HEAD never opens the file. A GET opens it (no read yet) so the length the ranges are
        // checked against is the one of the handle the bytes will come from, not a stale `stat`.
        let (file, available) = if head {
            (None, size)
        } else {
            let file = fs::File::open(&representation).await.map_err(Error::Io)?;
            let available = file.metadata().await.map_err(Error::Io)?.len();
            (Some(file), available)
        };
        let RangePlan {
            status,
            mut headers,
            segments,
            send_size,
            ranged,
        } = match apply_ranges(head, headers, range_header, if_range_ok, size, available) {
            RangeOutcome::Serve(plan) => plan,
            RangeOutcome::Reject(response) => return Ok(Outcome::Respond(response)),
        };

        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        // Go: always set Content-Length for range responses; for full responses only when the
        // representation is not content-encoded (Caddy pre-sets it for precompressed files).
        if ranged || !content_encoding_present(&headers) {
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&send_size.to_string())
                    .expect("decimal length is a valid header value"),
            );
        }

        // Materialise the body: nothing for HEAD; a large body is handed to the streaming path
        // (when the caller runs one) instead of being read into memory.
        let mut body = Bytes::new();
        if let Some(mut file) = file {
            if streaming_requested() && file_bytes(&segments) > STREAM_THRESHOLD {
                stash_streamed_file(StreamedFile { file, segments });
            } else {
                body = read_segments(&mut file, &segments)
                    .await
                    .map_err(Error::Io)?;
            }
        }
        let mut response = Response {
            status,
            headers,
            body,
        };
        if let Some(override_status) = self.status_override(&request)? {
            response.status = override_status;
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
        for component in decoded_path.split('/') {
            if component == ".." {
                return Ok(Outcome::Respond(Response::text(
                    StatusCode::FORBIDDEN,
                    "403 Forbidden",
                )));
            }
        }
        if decoded_path.contains('\0') {
            return Ok(Outcome::Respond(Response::text(
                StatusCode::FORBIDDEN,
                "403 Forbidden",
            )));
        }
        let relative = decoded_path.trim_start_matches('/');
        // Caddy states the cleaned request path with its trailing separator removed ("remove any
        // trailing separator as it breaks fs.ValidPath"), except on a filesystem root, which must
        // keep it: `/` must not become an empty path and `C:\` must not become `C:` (upstream
        // 5bd0b9355d44). caddy-rs trims only the relative part, so joining it to the root keeps
        // the root itself; the untrimmed path stays available for the canonical redirect and for
        // the trailing-separator rejection below.
        let stat_relative = sanitized_relative(&decoded_path);
        // The `..` scan above splits on `/` only, but on Windows `\` is a separator too: `..\x`
        // would be a parent reference and `C:\x` / `\\host\x` would make `root.join` discard the
        // root. `request_path_escapes_root` applies the platform's separator rules to the decoded
        // path; the native component check below is defence in depth (`filepath.IsLocal`).
        let not_local = !std::path::Path::new(&stat_relative)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)));
        if not_local || request_path_escapes_root(&decoded_path, cfg!(windows)) {
            return Ok(Outcome::Respond(Response::text(
                StatusCode::FORBIDDEN,
                "403 Forbidden",
            )));
        }
        // Expand `{http.vars.root}` and friends (Caddy's file_server root supports placeholders).
        let expanded_root = request.replace_all(&self.root);
        let root = if expanded_root.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(expanded_root)
        };
        let full_path = root.join(&stat_relative);
        // Caddy hides against the file's filesystem path (absolute when possible), so this runs
        // after the root is expanded.
        if self.hidden(&full_path.to_string_lossy(), &request) {
            return self.not_found(request);
        }
        let request_path = request.uri.path().to_string();

        if path_contains_symlink(&full_path, &root).await? {
            return Ok(Outcome::Respond(Response::text(
                StatusCode::FORBIDDEN,
                "403 Forbidden",
            )));
        }

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
                if path_contains_symlink(&candidate, &root).await? {
                    return Ok(Outcome::Respond(Response::text(
                        StatusCode::FORBIDDEN,
                        "403 Forbidden",
                    )));
                }
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
            if let Some(browse) = &self.browse {
                let body =
                    browse_html(&filename, request.uri.clone(), relative, browse, &|entry| {
                        self.hidden(entry, &request)
                    })
                    .await?;
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
        // A trailing separator denotes a directory, and `path` matchers never see `/secret.env/`
        // as `/secret.env`: serving the regular file here would bypass them. The canonical
        // redirect above covers the same request when `canonical_uris` is enabled, so this is
        // reachable with it disabled (or for a decoded separator the redirect path does not
        // recognise, e.g. `/file%2F`), and it must not serve the file (upstream 5bd0b9355d44).
        if !implicit_index && has_trailing_separator(&decoded_path) {
            return self.not_found(request);
        }
        let original_name = filename.to_string_lossy().to_string();
        self.serve_file(request, &filename, &original_name, &root)
            .await
    }

    /// The streaming path runs the same request logic as [`Handler::handle`] (so every header,
    /// precondition and range rule is shared) but lets `serve_file` hand a large body over as an
    /// open file to stream in chunks instead of reading it into memory (SEC-MEDIUM-HTTP B2).
    async fn handle_streaming(&self, request: Request) -> Result<StreamingOutcome> {
        let (outcome, streamed) = STREAMED_FILE
            .scope(std::cell::RefCell::new(None), async {
                let outcome = self.handle(request).await;
                let streamed = STREAMED_FILE.with(|slot| slot.borrow_mut().take());
                (outcome, streamed)
            })
            .await;
        Ok(match outcome? {
            Outcome::Continue(request) => StreamingOutcome::Continue(request),
            Outcome::Respond(response) => match streamed {
                Some(streamed) => StreamingOutcome::Respond(StreamingResponse::new(
                    response.status,
                    response.headers,
                    stream_file(streamed),
                )),
                None => StreamingOutcome::Respond(StreamingResponse::from_buffered(response)),
            },
        })
    }
}

/// Whether a decoded request path can address anything outside the served root once joined to it.
///
/// `windows` selects the host's path syntax so both behaviours are testable on any platform. On
/// Windows a decoded `\` is a separator, so `..\x` is a parent reference; a drive prefix (`C:`), a
/// UNC or rooted path (`\\host\share`, `\x`) makes `PathBuf::join` discard the root; and `:`
/// otherwise names an NTFS alternate data stream (`file::$DATA`) that bypasses extension and `hide`
/// matching. Win32 also strips trailing dots and spaces from a component (`..  ` and `...` can
/// mean `..`, `secret.env.` opens `secret.env` behind a `hide *.env`), so any component ending in
/// a dot or space is refused. On other platforms `\` and `:` are
/// ordinary file-name bytes and only a `/`-separated `..` is a parent reference.
fn request_path_escapes_root(decoded_path: &str, windows: bool) -> bool {
    if !windows {
        return decoded_path.split('/').any(|component| component == "..");
    }
    if decoded_path.contains(':') {
        return true;
    }
    // A leading `/` is the URL's own root (repeated `/` are collapsed by `clean_path`); a `\` right
    // after it (`/\host\share`) is a rooted or UNC path that `PathBuf::join` treats as absolute.
    let after_url_root = decoded_path.trim_start_matches('/');
    if after_url_root.starts_with('\\') {
        return true;
    }
    // Win32 path normalisation drops trailing dots and spaces *after* `hide` and the matchers have
    // looked at the name: `secret.env.` and `secret.env ` open `secret.env` while `*.env` does not
    // match them. Refuse any component that would be altered that way (`.` itself is a no-op).
    // Device names (`NUL`, `COM1`, ...) open a device, not a file; Go's `filepath.IsLocal`, which
    // stock Caddy's `SanitizedPathJoin` relies on, refuses them too.
    decoded_path.split(['/', '\\']).any(|component| {
        (component != "." && component.trim_end_matches(['.', ' ']) != component)
            || is_windows_reserved_name(component)
    })
}

/// Whether a path component names a Windows device (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`,
/// `LPT1`-`LPT9` with the superscript digits, `CONIN$`, `CONOUT$`), with any extension or stream
/// suffix. Mirrors Go's `isReservedName` (`internal/filepathlite`), but refuses a device name with
/// an extension unconditionally: Go consults `RtlIsDosDeviceName_U` for that case because Windows
/// 11 no longer treats `CON.txt` as a device, and this check cannot call it from a portable test.
fn is_windows_reserved_name(component: &str) -> bool {
    // Device names can have arbitrary trailing characters after a dot or colon; trailing spaces in
    // the base are ignored.
    let base = component.split(['.', ':']).next().unwrap_or("");
    let upper = base.trim_end_matches(' ').to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    ["COM", "LPT"].iter().any(|prefix| {
        upper.strip_prefix(prefix).is_some_and(|digit| {
            matches!(digit, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                || matches!(digit, "\u{b2}" | "\u{b3}" | "\u{b9}")
        })
    })
}

/// Caddy's `SanitizedPathJoin` relative part for a decoded request path: `path.Clean` (which drops
/// `.` segments and repeated separators; `..` is rejected before this) without the trailing
/// separator. Trimming only the relative part preserves a filesystem root, where `root.join("")` is
/// the root: trimming the joined string instead turned `/` into an empty path and `C:\` into `C:`,
/// serving the wrong directory or failing (upstream 5bd0b9355d44).
fn sanitized_relative(decoded_path: &str) -> String {
    let cleaned = clean_path(decoded_path, true);
    let relative = cleaned.strip_prefix('/').unwrap_or(&cleaned);
    trim_trailing_separators(relative).to_string()
}

/// Whether the decoded request path ends with a directory separator. On Windows a decoded `\` is a
/// separator too (Caddy's `NormalizedPath`), so `/file\`, `/file/` and `/file%5c` all denote a
/// directory; on unix `\` is an ordinary filename byte.
fn has_trailing_separator(decoded_path: &str) -> bool {
    if cfg!(windows) {
        clean_path(&decoded_path.replace('\\', "/"), false).ends_with('/')
    } else {
        clean_path(decoded_path, false).ends_with('/')
    }
}

/// Trim trailing separators so the target names the file, without turning a filesystem root into an
/// empty relative path: the result is joined to the configured root by the caller.
fn trim_trailing_separators(path: &str) -> &str {
    if cfg!(windows) {
        path.trim_end_matches(['/', '\\'])
    } else {
        path.trim_end_matches('/')
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

/// Returns `true` if `path` or any directory component between `path` and `root`
/// is a symbolic link.
async fn path_contains_symlink(path: &Path, root: &Path) -> Result<bool> {
    let mut current = path;
    loop {
        match fs::symlink_metadata(current).await {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // The path (or a parent) does not exist; keep checking ancestors.
            }
            Err(error) => return Err(Error::Io(error)),
        }
        if current == root || current.parent().is_none() {
            return Ok(false);
        }
        let Some(parent) = current.parent() else {
            return Ok(false);
        };
        current = parent;
    }
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

/// How a `Range` request resolved against the representation's staged size and the bytes that were
/// actually read from disk.
enum RangeOutcome {
    Serve(RangePlan),
    /// The request must be answered with this response instead of the representation.
    Reject(Response),
}

/// One piece of a response body, described without reading the file: either literal bytes
/// (multipart framing) or a byte span of the representation read from disk when it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BodySegment {
    Literal(Bytes),
    File { start: u64, length: u64 },
}

/// Bytes of the representation the segments will read from disk.
fn file_bytes(segments: &[BodySegment]) -> u64 {
    segments
        .iter()
        .map(|segment| match segment {
            BodySegment::File { length, .. } => *length,
            BodySegment::Literal(_) => 0,
        })
        .sum()
}

/// Total length of the response body the segments describe.
fn segments_len(segments: &[BodySegment]) -> u64 {
    segments
        .iter()
        .map(|segment| match segment {
            BodySegment::File { length, .. } => *length,
            BodySegment::Literal(bytes) => bytes.len() as u64,
        })
        .sum()
}

/// The representation slice a successful `Range` request resolved to.
struct RangePlan {
    status: StatusCode,
    headers: HeaderMap,
    segments: Vec<BodySegment>,
    send_size: u64,
    /// Whether a byte range was applied (Go always sets `Content-Length` for range responses).
    ranged: bool,
}

/// Apply the request's `Range` header to a representation whose `size` was staged from `stat` and
/// of which `available` bytes exist on the open handle, following Go's `parseRange`/`serveContent`.
/// No file content is read here: the plan only describes which spans to read.
fn apply_ranges(
    head: bool,
    mut headers: HeaderMap,
    range_header: Option<&str>,
    if_range_ok: bool,
    size: u64,
    available: u64,
) -> RangeOutcome {
    let mut ranges = match range_header {
        Some(header) if if_range_ok => parse_range(header, size as i64),
        _ => Ok(Vec::new()),
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut status = StatusCode::OK;
    let mut segments = vec![BodySegment::File {
        start: 0,
        length: size,
    }];
    let mut send_size = size;
    match ranges {
        Err(RangeError::NoOverlap) if size == 0 => {
            // Ignore range requests on empty files (Go's special case).
            ranges = Ok(Vec::new());
        }
        Err(RangeError::NoOverlap) => {
            return RangeOutcome::Reject(range_not_satisfiable(
                head,
                headers,
                size,
                "invalid range: failed to overlap",
            ));
        }
        Err(RangeError::Invalid) => {
            return RangeOutcome::Reject(serve_error(
                head,
                headers,
                StatusCode::RANGE_NOT_SATISFIABLE,
                "invalid range",
            ));
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
    // INFEASIBLE: every error arm above returned, so only `Ok` reaches this point.
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
        let Some((range_start, range_end)) = range_bounds(&range, available) else {
            // The file shrank between `stat` and `read`: the `Content-Range` staged above is
            // stale, so replace it with RFC 7233's unsatisfied form (`bytes */<complete-length>`)
            // rather than advertising a range the representation no longer has.
            return RangeOutcome::Reject(range_not_satisfiable(
                head,
                headers,
                size,
                "invalid range: the file changed while it was being served",
            ));
        };
        segments = vec![BodySegment::File {
            start: range_start,
            length: range_end - range_start,
        }];
    } else if ranges.len() > 1 {
        status = StatusCode::PARTIAL_CONTENT;
        let boundary = multipart_boundary();
        let Some(multipart) =
            multipart_segments(&ranges, &content_type, size as i64, &boundary, available)
        else {
            // Same stale-range condition as the single-range arm above: answer 416 with the
            // unsatisfied `Content-Range` instead of failing the request with a 500.
            return RangeOutcome::Reject(range_not_satisfiable(
                head,
                headers,
                size,
                "invalid range: the file changed while it was being served",
            ));
        };
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(&format!("multipart/byteranges; boundary={boundary}"))
                .expect("multipart content type is a valid header value"),
        );
        send_size = segments_len(&multipart);
        segments = multipart;
        if !content_encoding_present(&headers) {
            headers.remove(header::CONTENT_RANGE);
        }
    }
    RangeOutcome::Serve(RangePlan {
        status,
        headers,
        segments,
        send_size,
        ranged: !ranges.is_empty(),
    })
}

/// A 416 carrying RFC 7233's `Content-Range: bytes */<complete-length>` form.
fn range_not_satisfiable(head: bool, mut headers: HeaderMap, size: u64, message: &str) -> Response {
    headers.insert(
        header::CONTENT_RANGE,
        HeaderValue::from_str(&format!("bytes */{size}"))
            .expect("content range is a valid header value"),
    );
    serve_error(head, headers, StatusCode::RANGE_NOT_SATISFIABLE, message)
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

/// Clamp a parsed byte range to the bytes that exist on the open handle. Returns `None` when the
/// range does not fit, which happens when the file changed between `stat` and `open`; callers must
/// turn that into a rejection instead of reading past the end.
fn range_bounds(range: &ByteRange, available: u64) -> Option<(u64, u64)> {
    let start = u64::try_from(range.start).ok()?;
    let length = u64::try_from(range.length).ok()?;
    let end = start.checked_add(length)?;
    (end <= available).then_some((start, end))
}

/// Describe a `multipart/byteranges` body, or `None` when a range no longer fits the bytes that
/// exist on the open handle (the file shrank between `stat` and `open`). Only the framing is
/// materialised; each part's content stays a [`BodySegment::File`] span read when sent.
fn multipart_segments(
    ranges: &[ByteRange],
    content_type: &str,
    size: i64,
    boundary: &str,
    available: u64,
) -> Option<Vec<BodySegment>> {
    let mut segments = Vec::with_capacity(ranges.len() * 2 + 1);
    for range in ranges {
        let mut framing = Vec::new();
        framing.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        framing.extend_from_slice(
            format!("Content-Range: {}\r\n", range.content_range(size)).as_bytes(),
        );
        framing.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        framing.extend_from_slice(b"\r\n");
        segments.push(BodySegment::Literal(Bytes::from(framing)));
        let (start, end) = range_bounds(range, available)?;
        segments.push(BodySegment::File {
            start,
            length: end - start,
        });
        segments.push(BodySegment::Literal(Bytes::from_static(b"\r\n")));
    }
    segments.push(BodySegment::Literal(Bytes::from(format!(
        "--{boundary}--\r\n"
    ))));
    Some(segments)
}

/// Bodies whose file content exceeds this are streamed from the file handle instead of read into
/// memory first (when the caller runs the streaming path). Smaller bodies are read inline, which
/// keeps small-file latency and framing exactly as before.
const STREAM_THRESHOLD: u64 = 256 * 1024;

/// Chunk size of a streamed file body.
const STREAM_CHUNK: usize = 64 * 1024;

/// Read the file spans of `segments` (and splice the literals) into one buffer. Only used for
/// bodies at or below [`STREAM_THRESHOLD`] and by the buffered compatibility path.
async fn read_segments(file: &mut fs::File, segments: &[BodySegment]) -> std::io::Result<Bytes> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut body = Vec::with_capacity(usize::try_from(segments_len(segments)).unwrap_or(0));
    for segment in segments {
        match segment {
            BodySegment::Literal(bytes) => body.extend_from_slice(bytes),
            BodySegment::File { start, length } => {
                file.seek(std::io::SeekFrom::Start(*start)).await?;
                let read = file.take(*length).read_to_end(&mut body).await?;
                if (read as u64) < *length {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "the file changed while it was being served",
                    ));
                }
            }
        }
    }
    Ok(Bytes::from(body))
}

/// A response body to stream from an open file.
struct StreamedFile {
    file: fs::File,
    segments: Vec<BodySegment>,
}

tokio::task_local! {
    /// Set by [`FileServerHandler::handle_streaming`] around the shared request logic. When it is
    /// present, `serve_file` parks large bodies here instead of buffering them.
    static STREAMED_FILE: std::cell::RefCell<Option<StreamedFile>>;
}

/// Whether the current request is being served on the streaming path.
fn streaming_requested() -> bool {
    STREAMED_FILE.try_with(|_| ()).is_ok()
}

fn stash_streamed_file(streamed: StreamedFile) {
    // INFEASIBLE: only called when `streaming_requested()` held in the same task.
    let _ = STREAMED_FILE.try_with(|slot| *slot.borrow_mut() = Some(streamed));
}

/// Turn a parked file into a chunked body. The producer task stops as soon as the client goes away
/// (the receiver is dropped), and a file that shrinks mid-transfer ends the body with an I/O error
/// so the connection is aborted instead of delivering a silently truncated representation.
fn stream_file(streamed: StreamedFile) -> crate::body::Body {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    // Exact length of everything the producer below will send, so `Content-Length` survives the
    // server's framing policy (Go's `ServeContent` always sets it).
    let total = segments_len(&streamed.segments);
    tokio::spawn(async move {
        let StreamedFile { mut file, segments } = streamed;
        for segment in segments {
            match segment {
                BodySegment::Literal(bytes) => {
                    if sender.send(Ok(bytes)).await.is_err() {
                        return;
                    }
                }
                BodySegment::File { start, length } => {
                    if let Err(error) = file.seek(std::io::SeekFrom::Start(start)).await {
                        let _ = sender.send(Err(error.into())).await;
                        return;
                    }
                    let mut remaining = length;
                    while remaining > 0 {
                        let want = remaining.min(STREAM_CHUNK as u64) as usize;
                        let mut chunk = vec![0u8; want];
                        match file.read_exact(&mut chunk).await {
                            Ok(_) => {}
                            Err(error) => {
                                let _ = sender.send(Err(error.into())).await;
                                return;
                            }
                        }
                        remaining -= want as u64;
                        if sender.send(Ok(Bytes::from(chunk))).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });
    crate::body::Body::from_stream(crate::body::StreamingBody::from_chunks_with_len(
        receiver, total,
    ))
}

async fn browse_html(
    root: &Path,
    uri: Uri,
    relative: &str,
    options: &BrowseOptions,
    is_hidden: &(dyn Fn(&str) -> bool + Sync),
) -> Result<Vec<u8>> {
    let mut entries = fs::read_dir(root).await?;
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        // SEC-MEDIUM-HTTP B3: an entry the `hide` setting makes unfetchable (404) must not be
        // listed either; names and mtimes of `.env`/`.git` would otherwise leak. Caddy's
        // `directoryListing` skips `fileHidden` entries the same way.
        if is_hidden(&path.to_string_lossy()) {
            continue;
        }
        let file_type = entry.file_type().await.ok();
        let is_dir = file_type
            .map(|file_type| file_type.is_dir())
            .unwrap_or(false);
        let is_symlink = file_type
            .map(|file_type| file_type.is_symlink())
            .unwrap_or(false);
        // `reveal_symlinks` shows where a symlink points. The link is only read when the option
        // asks for it: without it the target is not part of the listing at all.
        let symlink_target = if is_symlink && options.reveal_symlinks {
            fs::read_link(&path)
                .await
                .ok()
                .map(|target| target.to_string_lossy().to_string())
        } else {
            None
        };
        // `plain_time_format` is a literal suffix appended to the entry's modification time.
        let modified = if options.plain_time_format.is_some() {
            fs::metadata(&path)
                .await
                .ok()
                .and_then(|metadata| metadata.modified().ok())
        } else {
            None
        };
        names.push((name, is_dir, symlink_target, modified));
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Index</title></head><body><h1>Index of ");
    html.push_str(&html_escape(uri.path()));
    html.push_str("</h1><ul>");
    if !relative.is_empty() {
        html.push_str("<li><a href=\"../\">../</a></li>");
    }
    for (name, is_dir, symlink_target, modified) in names {
        let suffix = if is_dir { "/" } else { "" };
        html.push_str("<li><a href=\"");
        html.push_str(&percent_encode_path_segment(&name));
        html.push_str(suffix);
        html.push_str("\">");
        html.push_str(&html_escape(&name));
        html.push_str(suffix);
        html.push_str("</a>");
        if let Some(target) = symlink_target {
            html.push_str(" -&gt; ");
            html.push_str(&html_escape(&target));
        }
        if let Some(modified) = modified {
            // Seconds since the Unix epoch, then the caller's literal suffix. Caddy renders a Go
            // time layout; caddy-rs does not implement that syntax, which is why only the literal
            // suffix is honoured here (see `BrowseOptions`).
            if let Ok(since_epoch) = modified.duration_since(std::time::UNIX_EPOCH) {
                html.push_str(" <span class=\"time\">");
                html.push_str(&since_epoch.as_secs().to_string());
                if let Some(format) = &options.plain_time_format {
                    html.push_str(&html_escape(format));
                }
                html.push_str("</span>");
            }
        }
        html.push_str("</li>");
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

    #[test]
    fn windows_separators_and_prefixes_escape_the_root() {
        for path in [
            r"/..\secret.txt",
            r"/a\..\..\secret.txt",
            r"/..\..\Windows\win.ini",
            "/C:/Windows/win.ini",
            "/c:win.ini",
            r"/\Windows\win.ini",
            r"/\\host\share\x",
            "/file.txt::$DATA",
            "/index.html:stream",
            "/.. /secret",
            "/.../secret",
            r"/a\... \b",
            "/secret.env.",
            "/secret.env ",
            "/secret.env. .",
            "/dir/secret.env./x",
            "/NUL",
            "/nul.txt",
            "/dir/COM1",
            "/LPT9.log",
            "/CONIN$",
            "/conout$",
            "/aux ",
            "/COM\u{b9}",
        ] {
            assert!(
                request_path_escapes_root(path, true),
                "{path:?} must be refused on Windows"
            );
        }
    }

    #[test]
    fn ordinary_windows_paths_are_served() {
        for path in [
            "/",
            "/index.html",
            "/a/b/c.txt",
            "//double//slash.txt",
            r"/dir\file.txt",
            r"/dir\",
            "/.hidden",
            "/a.b.c",
            "/trailing.dot.txt",
            "/./x",
            "/name with spaces.txt",
            "/CONSOLE",
            "/COM10",
            "/COM0",
            "/nullable.txt",
            "/auxiliary",
            "/connect/lpt",
        ] {
            assert!(
                !request_path_escapes_root(path, true),
                "{path:?} is a plain in-root path on Windows"
            );
        }
    }

    #[test]
    fn non_windows_treats_backslash_and_colon_as_filename_bytes() {
        for path in [
            r"/..\secret.txt",
            "/C:/x",
            r"/\x",
            "/a:b",
            "/.. /x",
            "/.../x",
        ] {
            assert!(
                !request_path_escapes_root(path, false),
                "{path:?} is a literal file name outside Windows"
            );
        }
        assert!(request_path_escapes_root("/../secret", false));
        assert!(request_path_escapes_root("/a/../../secret", false));
    }

    /// The platform-native guard must refuse parent references for the host this runs on, and a
    /// plain file must still be served.
    #[tokio::test]
    async fn handler_refuses_parent_references_and_still_serves_files() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("ok.txt"), b"ok").unwrap();
        let handler = handler(root.path()).await;

        let allowed = respond(&handler, make_request(Method::GET, "/ok.txt")).await;
        assert_eq!(allowed.status, StatusCode::OK);

        let mut escapes = vec!["/%2e%2e/secret", "/a/%2E%2E/%2e%2e/secret"];
        if cfg!(windows) {
            escapes.extend(["/..%5csecret", "/C:/Windows/win.ini", "/%5cWindows/win.ini"]);
        }
        for path in escapes {
            let response = respond(&handler, make_request(Method::GET, path)).await;
            assert_eq!(response.status, StatusCode::FORBIDDEN, "{path} must be 403");
        }
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

    // --- SEC-MEDIUM-HTTP B2: the file is not read into memory per request ----------------------

    /// Peak resident set size of this process in KiB, after resetting the high-water mark so
    /// earlier tests in the same binary do not hide an allocation (Linux only).
    #[cfg(target_os = "linux")]
    fn reset_peak_rss() {
        std::fs::write("/proc/self/clear_refs", "5").expect("reset VmHWM");
    }

    #[cfg(target_os = "linux")]
    fn peak_rss_kib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
            .expect("VmHWM")
    }

    /// 1 GiB sparse file: cheap to create, but `fs::read` would allocate and zero-fill all of it.
    #[cfg(target_os = "linux")]
    fn sparse_file(dir: &Path, name: &str, len: u64) {
        let file = std::fs::File::create(dir.join(name)).unwrap();
        file.set_len(len).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn range_head_and_not_modified_of_a_huge_file_do_not_load_it() {
        const GIB: u64 = 1 << 30;
        const BUDGET_KIB: u64 = 192 * 1024; // concurrent tests (argon2id) add process-wide noise
        let dir = tempfile::tempdir().unwrap();
        sparse_file(dir.path(), "huge.bin", GIB);
        set_mtime(&dir.path().join("huge.bin"), 1_700_000_000);
        let handler = handler(dir.path()).await;

        // A 1-byte range.
        reset_peak_rss();
        let before = peak_rss_kib();
        let mut request = make_request(Method::GET, "/huge.bin");
        request.headers.insert(
            header::RANGE,
            "bytes=1073741823-1073741823".parse().unwrap(),
        );
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.body.len(), 1);
        assert_eq!(
            header(&response, header::CONTENT_RANGE),
            "bytes 1073741823-1073741823/1073741824"
        );
        let range_growth = peak_rss_kib().saturating_sub(before);

        // HEAD reports the full length without a body.
        reset_peak_rss();
        let before = peak_rss_kib();
        let response = respond(&handler, make_request(Method::HEAD, "/huge.bin")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());
        assert_eq!(header(&response, header::CONTENT_LENGTH), GIB.to_string());
        let head_growth = peak_rss_kib().saturating_sub(before);

        // A satisfied conditional request is a bodyless 304.
        let etag = header(&response, header::ETAG);
        assert!(!etag.is_empty());
        reset_peak_rss();
        let before = peak_rss_kib();
        let mut request = make_request(Method::GET, "/huge.bin");
        request
            .headers
            .insert(header::IF_NONE_MATCH, etag.parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::NOT_MODIFIED);
        let not_modified_growth = peak_rss_kib().saturating_sub(before);

        assert!(
            range_growth < BUDGET_KIB
                && head_growth < BUDGET_KIB
                && not_modified_growth < BUDGET_KIB,
            "the file was read into memory: peak RSS grew by range={range_growth} KiB, \
             head={head_growth} KiB, not_modified={not_modified_growth} KiB"
        );
    }

    /// A full GET of a large file on the streaming path is delivered in chunks, never buffered.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn large_full_get_is_streamed_not_buffered() {
        use http_body_util::BodyExt;
        const LEN: u64 = 512 << 20;
        const BUDGET_KIB: u64 = 192 * 1024; // concurrent tests (argon2id) add process-wide noise
        let dir = tempfile::tempdir().unwrap();
        sparse_file(dir.path(), "big.bin", LEN);
        let handler = handler(dir.path()).await;

        reset_peak_rss();
        let before = peak_rss_kib();
        let outcome = handler
            .handle_streaming(make_request(Method::GET, "/big.bin"))
            .await
            .unwrap();
        let StreamingOutcome::Respond(response) = outcome else {
            panic!("expected a response");
        };
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some(LEN.to_string().as_str())
        );
        let mut body = Box::pin(response.body);
        let mut received = 0u64;
        while let Some(frame) = body.frame().await {
            let frame = frame.expect("body frame");
            if let Some(data) = frame.data_ref() {
                received += data.len() as u64;
            }
        }
        assert_eq!(received, LEN);
        let growth = peak_rss_kib().saturating_sub(before);
        assert!(
            growth < BUDGET_KIB,
            "a {LEN}-byte file was buffered: peak RSS grew by {growth} KiB"
        );
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    async fn streamed(handler: &FileServerHandler, request: Request) -> (Response, bool) {
        let StreamingOutcome::Respond(response) = handler.handle_streaming(request).await.unwrap()
        else {
            panic!("expected a response");
        };
        let was_stream = matches!(response.body, crate::body::Body::Stream(_));
        let body = response.body.into_bytes().await.unwrap();
        (
            Response {
                status: response.status,
                headers: response.headers,
                body,
            },
            was_stream,
        )
    }

    /// Streamed bodies (above the threshold) are byte-identical to the buffered path, for full,
    /// single-range and multipart responses.
    #[tokio::test]
    async fn streamed_bodies_match_the_content_and_buffered_framing() {
        let dir = tempfile::tempdir().unwrap();
        let content = pattern(1_000_000);
        std::fs::write(dir.path().join("big.txt"), &content).unwrap();
        let handler = handler(dir.path()).await;

        let (response, was_stream) =
            streamed(&handler, make_request(Method::GET, "/big.txt")).await;
        assert!(was_stream, "a large body must be streamed");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, content);
        assert_eq!(header(&response, header::CONTENT_LENGTH), "1000000");

        let mut request = make_request(Method::GET, "/big.txt");
        request
            .headers
            .insert(header::RANGE, "bytes=100-599999".parse().unwrap());
        let (response, was_stream) = streamed(&handler, request).await;
        assert!(was_stream);
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.body, content[100..600_000]);
        assert_eq!(
            header(&response, header::CONTENT_RANGE),
            "bytes 100-599999/1000000"
        );

        let mut request = make_request(Method::GET, "/big.txt");
        request.headers.insert(
            header::RANGE,
            "bytes=0-299999,400000-699999".parse().unwrap(),
        );
        let (response, was_stream) = streamed(&handler, request).await;
        assert!(was_stream);
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        let boundary = header(&response, header::CONTENT_TYPE)
            .strip_prefix("multipart/byteranges; boundary=")
            .expect("multipart")
            .to_string();
        let mut expected = Vec::new();
        for (start, end) in [(0usize, 299_999usize), (400_000, 699_999)] {
            expected.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Range: bytes {start}-{end}/1000000\r\n\
                     Content-Type: text/plain; charset=utf-8\r\n\r\n"
                )
                .as_bytes(),
            );
            expected.extend_from_slice(&content[start..=end]);
            expected.extend_from_slice(b"\r\n");
        }
        expected.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        assert_eq!(response.body.len(), expected.len());
        assert!(response.body == expected, "multipart body differs");
        assert_eq!(
            header(&response, header::CONTENT_LENGTH),
            expected.len().to_string()
        );
    }

    /// Small bodies keep the inline read (no producer task, same framing as before).
    #[tokio::test]
    async fn small_bodies_are_not_streamed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("small.txt"), pattern(1000)).unwrap();
        let handler = handler(dir.path()).await;
        let (response, was_stream) =
            streamed(&handler, make_request(Method::GET, "/small.txt")).await;
        assert!(!was_stream);
        assert_eq!(response.body, pattern(1000));
    }

    /// Range correctness at the start, middle and end, suffix and open-ended ranges, multiple
    /// ranges, and `If-Range` (validator match serves the range; mismatch serves the full file).
    #[tokio::test]
    async fn range_variants_read_exactly_the_requested_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let content = pattern(100);
        std::fs::write(dir.path().join("f.bin"), &content).unwrap();
        set_mtime(&dir.path().join("f.bin"), 1_700_000_000);
        let handler = handler(dir.path()).await;

        let cases: [(&str, usize, usize); 6] = [
            ("bytes=0-0", 0, 1),
            ("bytes=50-59", 50, 60),
            ("bytes=99-99", 99, 100),
            ("bytes=-10", 90, 100),
            ("bytes=90-", 90, 100),
            ("bytes=95-1000", 95, 100),
        ];
        for (spec, start, end) in cases {
            let mut request = make_request(Method::GET, "/f.bin");
            request.headers.insert(header::RANGE, spec.parse().unwrap());
            let response = respond(&handler, request).await;
            assert_eq!(response.status, StatusCode::PARTIAL_CONTENT, "{spec}");
            assert_eq!(response.body, content[start..end], "{spec}");
            assert_eq!(
                header(&response, header::CONTENT_RANGE),
                format!("bytes {}-{}/100", start, end - 1),
                "{spec}"
            );
            assert_eq!(
                header(&response, header::CONTENT_LENGTH),
                (end - start).to_string(),
                "{spec}"
            );
        }

        let mut request = make_request(Method::GET, "/f.bin");
        request
            .headers
            .insert(header::RANGE, "bytes=0-9,20-29".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        let text = response.body.to_vec();
        for window in [&content[0..10], &content[20..30]] {
            assert!(text.windows(10).any(|candidate| candidate == window));
        }

        // If-Range with the current ETag keeps the range; a stale one serves everything.
        let head = respond(&handler, make_request(Method::HEAD, "/f.bin")).await;
        let etag = header(&head, header::ETAG);
        let mut request = make_request(Method::GET, "/f.bin");
        request
            .headers
            .insert(header::RANGE, "bytes=10-19".parse().unwrap());
        request
            .headers
            .insert(header::IF_RANGE, etag.parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.body, content[10..20]);

        let mut request = make_request(Method::GET, "/f.bin");
        request
            .headers
            .insert(header::RANGE, "bytes=10-19".parse().unwrap());
        request
            .headers
            .insert(header::IF_RANGE, "\"stale\"".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, content);

        // Past the end is still a 416 and a HEAD with a range reports the range without a body.
        let mut request = make_request(Method::GET, "/f.bin");
        request
            .headers
            .insert(header::RANGE, "bytes=100-".parse().unwrap());
        assert_eq!(
            respond(&handler, request).await.status,
            StatusCode::RANGE_NOT_SATISFIABLE
        );
        let mut request = make_request(Method::HEAD, "/f.bin");
        request
            .headers
            .insert(header::RANGE, "bytes=10-19".parse().unwrap());
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
        assert!(response.body.is_empty());
        assert_eq!(header(&response, header::CONTENT_LENGTH), "10");
    }

    /// A file that shrinks between `stat` and the read must not deliver a truncated 200 or panic:
    /// the buffered read reports it as an I/O error.
    #[tokio::test]
    async fn read_segments_reports_a_file_shorter_than_planned() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("short.bin"), b"abc").unwrap();
        let mut file = fs::File::open(dir.path().join("short.bin")).await.unwrap();
        let error = read_segments(
            &mut file,
            &[BodySegment::File {
                start: 0,
                length: 10,
            }],
        )
        .await
        .expect_err("short file");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        let body = read_segments(
            &mut file,
            &[
                BodySegment::Literal(Bytes::from_static(b"[")),
                BodySegment::File {
                    start: 1,
                    length: 2,
                },
                BodySegment::Literal(Bytes::from_static(b"]")),
            ],
        )
        .await
        .unwrap();
        assert_eq!(body, Bytes::from_static(b"[bc]"));
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

    #[test]
    fn auto_hide_adds_relative_app_config_and_data_dirs_once() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("site");
        std::fs::create_dir_all(&cwd).unwrap();
        let data_home = temp.path().join("data-home");

        // The acceptance environment for `caddy@a97bc460cfe5`: XDG_DATA_HOME is absolute, so the
        // data directory is skipped; XDG_CONFIG_HOME and HOME are unset, so the config directory
        // falls back to the relative `./caddy` under the working directory and must be hidden.
        let env = AutoHideEnv {
            cwd: cwd.clone(),
            xdg_config_home: None,
            home: None,
            xdg_data_home: Some(data_home.into_os_string()),
        };
        let mut handler = FileServerHandler::from_json_with_env(
            &serde_json::json!({"handler": "file_server", "root": cwd, "hide": []}),
            "handler",
            &env,
        )
        .unwrap();
        let expected = cwd.join("caddy");
        let expected = expected.to_string_lossy().into_owned();
        assert_eq!(
            handler
                .hide
                .iter()
                .filter(|entry| **entry == expected)
                .count(),
            1,
            "the relative config directory is hidden exactly once: {:?}",
            handler.hide
        );
        assert_eq!(auto_hide_entries(&env), vec![expected.clone()]);

        // Both directories fall back to `./caddy`: the effective hide list still holds one entry.
        let same_env = AutoHideEnv {
            xdg_config_home: None,
            home: None,
            xdg_data_home: None,
            ..env.clone()
        };
        assert_eq!(auto_hide_entries(&same_env), vec![expected.clone()]);

        // Absolute directories are skipped, as upstream does.
        let absolute_env = AutoHideEnv {
            cwd: cwd.clone(),
            xdg_config_home: Some(temp.path().join("config-home").into_os_string()),
            home: None,
            xdg_data_home: Some(temp.path().join("data-home-2").into_os_string()),
        };
        assert!(auto_hide_entries(&absolute_env).is_empty());

        // An explicit entry that already names the absolute directory is not duplicated.
        handler = FileServerHandler::from_json_with_env(
            &serde_json::json!({"handler": "file_server", "root": cwd, "hide": [expected.clone()]}),
            "handler",
            &env,
        )
        .unwrap();
        assert_eq!(
            handler
                .hide
                .iter()
                .filter(|entry| **entry == expected)
                .count(),
            1,
            "an explicit absolute entry is not repeated: {:?}",
            handler.hide
        );
    }

    #[tokio::test]
    async fn auto_hidden_config_dir_files_are_not_served() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("site");
        std::fs::create_dir_all(root.join("caddy")).unwrap();
        std::fs::write(root.join("caddy/autosave.json"), b"{\"admin\":{}}").unwrap();
        std::fs::write(root.join("caddyfile.go"), b"not the config dir").unwrap();

        let env = AutoHideEnv {
            cwd: root.clone(),
            xdg_config_home: None,
            home: None,
            xdg_data_home: Some(temp.path().join("data-home").into_os_string()),
        };
        let handler = FileServerHandler::from_json_with_env(
            &serde_json::json!({"handler": "file_server", "root": root, "hide": []}),
            "handler",
            &env,
        )
        .unwrap();

        let response = respond(&handler, make_request(Method::GET, "/caddy/autosave.json")).await;
        assert_eq!(
            response.status,
            StatusCode::NOT_FOUND,
            "the relative config directory is hidden, like upstream Provision"
        );

        // A sibling whose name merely starts with the hidden directory's name stays visible: the
        // prefix match requires a separator boundary.
        let response = respond(&handler, make_request(Method::GET, "/caddyfile.go")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"not the config dir"));
    }

    #[tokio::test]
    async fn hide_entries_follow_caddy_file_hidden_semantics() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("site");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(root.join("subdir")).unwrap();
        std::fs::write(root.join("sub/secret.txt"), b"secret").unwrap();
        std::fs::write(root.join("subdir/secret.txt"), b"visible").unwrap();
        std::fs::write(root.join("visible.txt"), b"visible").unwrap();
        std::fs::create_dir_all(root.join("hidden")).unwrap();
        std::fs::write(root.join("hidden/file.txt"), b"component").unwrap();

        let env = AutoHideEnv {
            cwd: root.clone(),
            xdg_config_home: Some(temp.path().join("config-home").into_os_string()),
            home: None,
            xdg_data_home: Some(temp.path().join("data-home").into_os_string()),
        };
        let sub = root.join("sub").to_string_lossy().into_owned();
        let handler = FileServerHandler::from_json_with_env(
            &serde_json::json!({"handler": "file_server", "root": root, "hide": [sub, "hidden"]}),
            "handler",
            &env,
        )
        .unwrap();

        // An absolute entry with a separator hides its subtree ...
        let response = respond(&handler, make_request(Method::GET, "/sub/secret.txt")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        // ... but not a sibling whose name only shares the prefix ("sub" vs "subdir").
        let response = respond(&handler, make_request(Method::GET, "/subdir/secret.txt")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"visible"));
        // An entry without a separator hides every path component with that name.
        let response = respond(&handler, make_request(Method::GET, "/hidden/file.txt")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        let response = respond(&handler, make_request(Method::GET, "/visible.txt")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"visible"));
    }

    /// A hide entry written with native Windows separators must still hide its file.
    ///
    /// Regression test: the filename was normalised to `/` form but the entry was not, so
    /// `C:\\site\\secret.txt` contains no `/`, skipped the absolute-path branch, was compared
    /// only as a bare path component, and never matched -- serving a hidden file. Driven through
    /// `hide_entry_matches` with `windows = true` so a Linux CI run proves the Windows behaviour.
    #[test]
    fn a_backslash_hide_entry_still_hides_on_windows() {
        let cwd = Path::new("/srv/site");
        // The filename as `hidden()` normalises it on Windows: `/` form, lower-cased.
        let filename_abs = "c:/site/secret.txt";
        assert!(
            hide_entry_matches("C:\\site\\secret.txt", filename_abs, cwd, true),
            "a native Windows absolute entry must hide the file it names"
        );
        // A sibling must stay visible: the entry is a path, not a prefix.
        assert!(
            !hide_entry_matches("C:\\site\\secret.txt", "c:/site/visible.txt", cwd, true),
            "the entry must not hide a sibling file"
        );
        // Case-insensitive on Windows.
        assert!(
            hide_entry_matches("c:\\SITE\\Secret.TXT", filename_abs, cwd, true),
            "Windows matching is case-insensitive"
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

    #[tokio::test]
    #[cfg(unix)]
    async fn symlink_to_outside_root_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"secret").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/link.txt")).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "symlink pointing outside the root must be rejected"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn symlink_to_hidden_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let hidden = dir.path().join(".htpasswd");
        std::fs::write(&hidden, b"secret").unwrap();
        let link = dir.path().join("safe.txt");
        std::os::unix::fs::symlink(&hidden, &link).unwrap();

        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/safe.txt")).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "symlink pointing to a hidden file must be rejected"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn symlink_directory_to_outside_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let outside_dir = dir.path().join("outside");
        std::fs::create_dir(&outside_dir).unwrap();
        std::fs::write(outside_dir.join("secret.txt"), b"secret").unwrap();
        let link_dir = dir.path().join("linkdir");
        std::os::unix::fs::symlink(&outside_dir, &link_dir).unwrap();

        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/linkdir/secret.txt")).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "symlink directory pointing outside the root must be rejected"
        );
    }

    #[tokio::test]
    async fn legitimate_file_still_served() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"hello").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/file.txt")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn legitimate_filename_with_double_dots_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo..bar.txt"), b"hello").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/foo..bar.txt")).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "files with .. in the name should be allowed"
        );
    }

    #[tokio::test]
    async fn path_traversal_with_dotdot_component_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.txt"), b"hello").unwrap();
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/a/../b.txt")).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "path traversal via .. component should be rejected"
        );
    }

    fn configured_handler(root: &Path, extra: serde_json::Value) -> FileServerHandler {
        let mut config = serde_json::json!({"handler": "file_server", "root": root});
        let object = config.as_object_mut().expect("handler config object");
        for (key, value) in extra.as_object().expect("extra handler config") {
            object.insert(key.clone(), value.clone());
        }
        FileServerHandler::from_json(&config, "handler").unwrap()
    }

    fn trailing_separator_fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret.env"), b"secret").unwrap();
        std::fs::write(dir.path().join("secret.env.gz"), b"gzip-sidecar").unwrap();
        std::fs::create_dir(dir.path().join("dir")).unwrap();
        std::fs::write(dir.path().join("dir/index.html"), b"index").unwrap();
        dir
    }

    #[tokio::test]
    async fn canonical_redirect_for_a_trailing_separator_on_a_file_is_kept() {
        let dir = trailing_separator_fixture();
        // `canonical_uris` defaults to true, as in Caddy.
        let handler = handler(dir.path()).await;
        let response = respond(&handler, make_request(Method::GET, "/secret.env/")).await;
        assert_eq!(response.status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(header(&response, header::LOCATION), "/secret.env");
    }

    #[tokio::test]
    async fn a_regular_file_addressed_with_a_trailing_separator_is_not_served() {
        let dir = trailing_separator_fixture();
        let handler = configured_handler(dir.path(), serde_json::json!({"canonical_uris": false}));
        for path in [
            "/secret.env/",
            "/secret.env/./",
            "/secret.env//",
            "/secret.env%2F",
            "/secret.env%5c",
            "/secret.env%5C",
        ] {
            let response = respond(&handler, make_request(Method::GET, path)).await;
            assert_eq!(
                response.status,
                StatusCode::NOT_FOUND,
                "`{path}` addresses a regular file as a directory and must not be served"
            );
        }
        // The file itself still serves: only the trailing-separator forms are rejected.
        let response = respond(&handler, make_request(Method::GET, "/secret.env")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"secret"));
    }

    #[tokio::test]
    async fn a_precompressed_sidecar_does_not_resurrect_a_trailing_separator() {
        let dir = trailing_separator_fixture();
        let handler = configured_handler(
            dir.path(),
            serde_json::json!({"canonical_uris": false, "precompressed": {"gzip": {}}}),
        );
        let mut request = make_request(Method::GET, "/secret.env/");
        request
            .headers
            .insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let response = respond(&handler, request).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_trailing_separator_on_a_file_passes_through_to_the_next_handler() {
        let dir = trailing_separator_fixture();
        let handler = configured_handler(
            dir.path(),
            serde_json::json!({"canonical_uris": false, "pass_thru": true}),
        );
        match handler
            .handle(make_request(Method::GET, "/secret.env/"))
            .await
            .unwrap()
        {
            Outcome::Continue(_) => {}
            Outcome::Respond(response) => {
                panic!("expected pass-through, got {}", response.status)
            }
        }
    }

    #[tokio::test]
    async fn directories_keep_the_implicit_index_and_reject_an_index_file_as_a_directory() {
        let dir = trailing_separator_fixture();
        let handler = configured_handler(dir.path(), serde_json::json!({"canonical_uris": false}));
        for path in ["/dir/", "/dir"] {
            let response = respond(&handler, make_request(Method::GET, path)).await;
            assert_eq!(
                response.status,
                StatusCode::OK,
                "`{path}` should serve the index"
            );
            assert_eq!(response.body, Bytes::from_static(b"index"), "`{path}`");
        }
        let response = respond(&handler, make_request(Method::GET, "/dir/index.html/")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_filesystem_root_keeps_its_separator_and_still_browses() {
        let dir = trailing_separator_fixture();
        let handler = configured_handler(dir.path(), serde_json::json!({"browse": true}));
        let response = respond(&handler, make_request(Method::GET, "/")).await;
        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body.to_vec()).unwrap();
        assert!(
            body.contains("secret.env"),
            "root listing should list the fixture file: {body}"
        );
    }

    #[test]
    fn multipart_ranges_beyond_the_read_bytes_are_rejected() {
        // A file that shrank between `stat` and `read` used to slice the representation out of
        // bounds and panic.
        let ranges = [ByteRange {
            start: 5,
            length: 10,
        }];
        assert!(
            multipart_segments(&ranges, "text/plain", 100, "boundary", 5).is_none(),
            "range beyond the read bytes must be rejected"
        );
    }

    /// A single range that fits the `stat` size but not the bytes actually read (the file shrank
    /// between `stat` and `read`) must answer 416 with RFC 7233's unsatisfied form
    /// `Content-Range: bytes */<complete-length>`, not the stale `bytes <start>-<end>/<size>`.
    #[test]
    fn stale_single_range_is_416_with_unsatisfied_content_range() {
        let outcome = apply_ranges(false, HeaderMap::new(), Some("bytes=5-9"), true, 10, 5);
        let RangeOutcome::Reject(response) = outcome else {
            panic!("a stale single range must be rejected");
        };
        assert_eq!(response.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response
                .headers
                .get(header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok()),
            Some("bytes */10")
        );
        assert_eq!(
            response.body,
            Bytes::from_static(b"invalid range: the file changed while it was being served\n")
        );
    }

    /// The multipart arm must answer the same stale-range condition exactly like the single-range
    /// arm: 416 with `Content-Range: bytes */<complete-length>`, never a 500.
    #[test]
    fn stale_multipart_range_is_416_with_unsatisfied_content_range() {
        let outcome = apply_ranges(false, HeaderMap::new(), Some("bytes=0-1,4-5"), true, 10, 5);
        let RangeOutcome::Reject(response) = outcome else {
            panic!("a stale multipart range must be rejected");
        };
        assert_eq!(response.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response
                .headers
                .get(header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok()),
            Some("bytes */10")
        );
        assert_eq!(
            response
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
    }

    /// Guard: a range that fits the bytes actually read still returns 206 with its own
    /// `Content-Range`.
    #[test]
    fn valid_single_range_still_returns_206_with_its_content_range() {
        let outcome = apply_ranges(false, HeaderMap::new(), Some("bytes=0-1"), true, 10, 10);
        let RangeOutcome::Serve(plan) = outcome else {
            panic!("a valid range must be served");
        };
        assert_eq!(plan.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            plan.headers
                .get(header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok()),
            Some("bytes 0-1/10")
        );
        assert_eq!(plan.send_size, 2);
        assert_eq!(
            plan.segments,
            vec![BodySegment::File {
                start: 0,
                length: 2
            }]
        );
        assert!(plan.ranged);
    }

    /// Guard: a valid multipart range still returns 206 with a `multipart/byteranges` body and no
    /// top-level `Content-Range`.
    #[test]
    fn valid_multipart_range_still_returns_206() {
        let outcome = apply_ranges(false, HeaderMap::new(), Some("bytes=0-1,4-5"), true, 10, 10);
        let RangeOutcome::Serve(plan) = outcome else {
            panic!("a valid multipart range must be served");
        };
        assert_eq!(plan.status, StatusCode::PARTIAL_CONTENT);
        assert!(plan
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("multipart/byteranges; boundary=")));
        assert!(plan.headers.get(header::CONTENT_RANGE).is_none());
        assert_eq!(plan.send_size, segments_len(&plan.segments));
        assert_eq!(file_bytes(&plan.segments), 4);
        assert!(plan.ranged);
    }

    // --- the two honoured options change what is SERVED (T-BROWSE-OPTIONS-SILENTLY-DROPPED) ------

    // --- SEC-MEDIUM-HTTP B3: the browse listing honours `hide` -----------------------------------

    fn hidden_fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("visible.txt"), "v").unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::fs::write(dir.path().join("notes.bak"), "b").unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/.env"), "SECRET=2").unwrap();
        std::fs::write(dir.path().join("sub/ok.txt"), "o").unwrap();
        dir
    }

    /// Names, mtimes and existence of hidden files must not leak through a directory listing that
    /// the same `hide` setting makes unfetchable (Caddy's `directoryListing` skips `fileHidden`).
    #[tokio::test]
    async fn browse_listing_omits_hidden_entries_in_the_root_and_in_subdirectories() {
        let dir = hidden_fixture();
        let handler = configured_handler(
            dir.path(),
            serde_json::json!({
                "browse": {"plain_time_format": " UTC"},
                "hide": [".env", ".git", "*.bak"]
            }),
        );
        for path in ["/", "/sub/"] {
            let response = respond(&handler, make_request(Method::GET, path)).await;
            assert_eq!(response.status, StatusCode::OK, "{path}");
            let body = String::from_utf8(response.body.to_vec()).unwrap();
            assert!(!body.contains(".env"), "{path} leaked .env: {body}");
            assert!(!body.contains(".git"), "{path} leaked .git: {body}");
            assert!(!body.contains("notes.bak"), "{path} leaked *.bak: {body}");
        }
        let root = String::from_utf8(
            respond(&handler, make_request(Method::GET, "/"))
                .await
                .body
                .to_vec(),
        )
        .unwrap();
        assert!(
            root.contains("visible.txt") && root.contains("sub/"),
            "{root}"
        );
        let sub = String::from_utf8(
            respond(&handler, make_request(Method::GET, "/sub/"))
                .await
                .body
                .to_vec(),
        )
        .unwrap();
        assert!(sub.contains("ok.txt"), "{sub}");

        // The hidden entry is also not fetchable, so listing and fetch now agree.
        let response = respond(&handler, make_request(Method::GET, "/.env")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }

    /// Without `hide` the listing is unchanged (dotfiles are served by default, like Caddy), and a
    /// path-style hide entry (absolute path) hides that entry from the listing too.
    #[tokio::test]
    async fn browse_listing_is_unchanged_without_hide_and_honours_path_entries() {
        let dir = hidden_fixture();
        let handler =
            configured_handler(dir.path(), serde_json::json!({"browse": true, "hide": []}));
        let body = String::from_utf8(
            respond(&handler, make_request(Method::GET, "/"))
                .await
                .body
                .to_vec(),
        )
        .unwrap();
        for name in [".env", ".git", "notes.bak", "visible.txt"] {
            assert!(body.contains(name), "{name} missing without hide: {body}");
        }

        let absolute = dir.path().join("notes.bak");
        let handler = configured_handler(
            dir.path(),
            serde_json::json!({"browse": true, "hide": [absolute.to_string_lossy()]}),
        );
        let body = String::from_utf8(
            respond(&handler, make_request(Method::GET, "/"))
                .await
                .body
                .to_vec(),
        )
        .unwrap();
        assert!(!body.contains("notes.bak"), "{body}");
        assert!(body.contains(".env"), "{body}");
    }

    fn browse_fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.txt"), "x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("real.txt", dir.path().join("alias.txt")).unwrap();
        dir
    }

    async fn browse_body(dir: &Path, browse: serde_json::Value) -> String {
        let handler = configured_handler(dir, serde_json::json!({"browse": browse}));
        let response = respond(&handler, make_request(Method::GET, "/")).await;
        assert_eq!(response.status, StatusCode::OK);
        String::from_utf8(response.body.to_vec()).unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reveal_symlinks_shows_the_target_and_default_hides_it() {
        // The option must change the listing. If `reveal_symlinks` were parsed and then ignored --
        // the defect this task removed -- both bodies would be identical.
        let dir = browse_fixture();
        let hidden = browse_body(dir.path(), serde_json::json!({})).await;
        let revealed = browse_body(dir.path(), serde_json::json!({"reveal_symlinks": true})).await;
        assert!(
            !hidden.contains("real.txt</a> -&gt;"),
            "the default listing must not reveal symlink targets: {hidden}"
        );
        assert!(
            revealed.contains("alias.txt</a> -&gt; real.txt"),
            "reveal_symlinks must show the symlink target: {revealed}"
        );
        assert_ne!(hidden, revealed, "reveal_symlinks must change the listing");
    }

    #[tokio::test]
    async fn plain_time_format_appends_its_literal_and_default_omits_times() {
        let dir = browse_fixture();
        let plain = browse_body(dir.path(), serde_json::json!({})).await;
        let formatted =
            browse_body(dir.path(), serde_json::json!({"plain_time_format": " Z"})).await;
        assert!(
            !plain.contains("class=\"time\""),
            "the default listing must not render times: {plain}"
        );
        assert!(
            formatted.contains("class=\"time\""),
            "plain_time_format must render a time: {formatted}"
        );
        assert!(
            formatted.contains(" Z</span>"),
            "plain_time_format must append its literal suffix: {formatted}"
        );
    }
}

// --- `browse` options (T-BROWSE-OPTIONS-SILENTLY-DROPPED) ------------------------------------
//
// Before these, `browse` was parsed as `as_bool().unwrap_or(is_object())`: an object enabled
// browsing and every key in it was discarded, so an operator writing
// `{"browse": {"reveal_symlinks": true}}` got neither the behaviour nor an error.

/// Parse `browse` the way an operator's JSON does: through `from_json`, not by calling the
/// options parser directly. Calling `BrowseOptions::parse` in isolation would keep these tests
/// green even if `from_json` reverted to the old silent `as_bool().unwrap_or(is_object())`
/// parse -- which is exactly the defect being removed, so the tests must cross that call site.
fn parse_browse(value: serde_json::Value) -> Result<FileServerHandler> {
    FileServerHandler::from_json(
        &serde_json::json!({"handler": "file_server", "root": "/tmp", "browse": value}),
        "handler",
    )
}

fn browse_options(value: serde_json::Value) -> Result<Option<BrowseOptions>> {
    parse_browse(value).map(|handler| handler.browse)
}

#[test]
fn a_boolean_browse_still_works() {
    assert!(browse_options(serde_json::json!(true)).unwrap().is_some());
    assert!(browse_options(serde_json::json!(false)).unwrap().is_none());
}

#[test]
fn browse_options_are_read_rather_than_discarded() {
    let options = browse_options(serde_json::json!({
        "reveal_symlinks": true,
        "plain_time_format": " UTC"
    }))
    .unwrap()
    .expect("an object enables browsing");
    // These assertions are the whole point: the values must survive parsing. Under the old
    // implementation the object became `true` and both fields were lost.
    assert!(options.reveal_symlinks);
    assert_eq!(options.plain_time_format.as_deref(), Some(" UTC"));
}

#[test]
fn browse_defaults_are_off() {
    let options = browse_options(serde_json::json!({})).unwrap().unwrap();
    assert!(!options.reveal_symlinks);
    assert!(options.plain_time_format.is_none());
}

#[test]
fn an_unimplemented_browse_option_is_a_located_error() {
    // Accepting these and ignoring them is the defect; refusing them is the advertised outcome.
    for option in ["sort", "file_limit", "template_file"] {
        let error = browse_options(serde_json::json!({ option: [] }))
            .expect_err(&format!("`browse.{option}` must be refused, not ignored"));
        let message = error.to_string();
        assert!(
            message.contains(&format!("browse.{option}")),
            "the error must name the field `browse.{option}`: {message}"
        );
        assert!(
            message.contains("not implemented"),
            "the error must say the option is unimplemented: {message}"
        );
    }
}

#[test]
fn an_unknown_browse_option_is_a_located_error() {
    // Default-ALLOW is what let the original defect exist: a key nobody parsed was dropped in
    // silence. A future upstream option must not inherit that.
    let error = browse_options(serde_json::json!({"reveal_symlinks": true, "no_such_option": 1}))
        .expect_err("an unknown key must be refused");
    let message = error.to_string();
    assert!(
        message.contains("no_such_option"),
        "the error must name the key: {message}"
    );
    assert!(
        message.contains("reveal_symlinks"),
        "the error must list the real options: {message}"
    );
}

#[test]
fn browse_option_types_are_checked() {
    let error = browse_options(serde_json::json!({"reveal_symlinks": "yes"}))
        .expect_err("a non-boolean reveal_symlinks must be refused");
    assert!(error.to_string().contains("reveal_symlinks"), "{error}");
    let error = browse_options(serde_json::json!({"plain_time_format": 7}))
        .expect_err("a non-string plain_time_format must be refused");
    assert!(error.to_string().contains("plain_time_format"), "{error}");
}

#[test]
fn a_non_boolean_non_object_browse_is_refused() {
    let error = browse_options(serde_json::json!("yes")).expect_err("a string is not valid");
    assert!(
        error.to_string().contains("boolean or an object"),
        "{error}"
    );
}
