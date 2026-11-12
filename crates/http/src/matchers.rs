//! Caddy-compatible request matchers.
//!
//! A *matcher set* is a JSON object in which every key is a matcher module; the request matches
//! the set when every matcher matches. A route's `match` array is a list of matcher sets combined
//! with OR (the route matches when any set matches), mirroring Caddy.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde_json::Value;

use crate::regex_lite::Regex;
use crate::types::{Error, Matcher, MatcherError, Request, Result, SharedMatcher};

/// Build a matcher set from one JSON object.
pub fn build_matcher_set(value: &Value) -> Result<Vec<SharedMatcher>> {
    let object = value.as_object().ok_or_else(|| Error::InvalidConfig {
        path: "match".to_string(),
        message: "matcher set must be a JSON object".to_string(),
    })?;
    let mut matchers: Vec<SharedMatcher> = Vec::new();
    for (key, value) in object {
        if key == "not" {
            let sets = value.as_array().ok_or_else(|| Error::InvalidConfig {
                path: "match.not".to_string(),
                message: "`not` must be an array of matcher sets".to_string(),
            })?;
            let mut inner = Vec::new();
            for (index, set) in sets.iter().enumerate() {
                for matcher in build_matcher_set(set).map_err(|error| {
                    if let Error::InvalidConfig { path, message } = error {
                        Error::InvalidConfig {
                            path: format!("match.not[{index}].{path}"),
                            message,
                        }
                    } else {
                        error
                    }
                })? {
                    inner.push(matcher);
                }
            }
            matchers.push(Arc::new(NotMatcher { inner }));
            continue;
        }
        let matcher = build_single_matcher(key, value)?;
        matchers.push(matcher);
    }
    Ok(matchers)
}

fn strings(value: &Value, path: &str) -> Result<Vec<String>> {
    match value {
        Value::String(value) => Ok(vec![value.clone()]),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| Error::InvalidConfig {
                        path: path.to_string(),
                        message: "expected an array of strings".to_string(),
                    })
            })
            .collect(),
        _ => Err(Error::InvalidConfig {
            path: path.to_string(),
            message: "expected a string or array of strings".to_string(),
        }),
    }
}

fn build_single_matcher(name: &str, value: &Value) -> Result<SharedMatcher> {
    let path = format!("match.{name}");
    match name {
        "host" => Ok(Arc::new(HostMatcher {
            patterns: strings(value, &path)?,
        })),
        "path" => Ok(Arc::new(PathMatcher {
            patterns: strings(value, &path)?,
        })),
        "method" => Ok(Arc::new(MethodMatcher {
            methods: strings(value, &path)?
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect(),
        })),
        "header" => {
            let object = value.as_object().ok_or_else(|| Error::InvalidConfig {
                path: path.clone(),
                message: "header matcher must be an object of field -> values".to_string(),
            })?;
            let mut fields = Vec::new();
            for (field, values) in object {
                fields.push((field.clone(), strings(values, &format!("{path}.{field}"))?));
            }
            Ok(Arc::new(HeaderMatcher { fields }))
        }
        "query" => {
            let object = value.as_object().ok_or_else(|| Error::InvalidConfig {
                path: path.clone(),
                message: "query matcher must be an object of key -> values".to_string(),
            })?;
            let mut pairs = Vec::new();
            for (key, values) in object {
                for value in strings(values, &format!("{path}.{key}"))? {
                    pairs.push((key.clone(), value));
                }
            }
            Ok(Arc::new(QueryMatcher { pairs }))
        }
        "file" => Ok(Arc::new(FileMatcher::from_json(value, &path)?)),
        "path_regexp" => Ok(Arc::new(PathRegexpMatcher::from_json(value, &path)?)),
        "remote_ip" => Ok(Arc::new(RemoteIpMatcher::from_json(value, &path)?)),
        "client_ip" => Ok(Arc::new(ClientIpMatcher::from_json(value, &path)?)),
        "local_ip" => Ok(Arc::new(LocalIpMatcher::from_json(value, &path)?)),
        "protocol" => Ok(Arc::new(ProtocolMatcher::from_json(value, &path)?)),
        "tls" => Ok(Arc::new(TlsMatcher::from_json(value, &path)?)),
        "expression" => Ok(Arc::new(ExpressionMatcher::from_json(value, &path)?)),
        other => Err(Error::InvalidConfig {
            path,
            message: format!("matcher `{other}` is not implemented by the HTTP engine"),
        }),
    }
}

/// Matcher that succeeds when the wrapped set does not.
struct NotMatcher {
    inner: Vec<SharedMatcher>,
}

impl Matcher for NotMatcher {
    fn matches(&self, request: &Request) -> bool {
        !self.inner.iter().all(|matcher| matcher.matches(request))
    }

    fn describe(&self) -> String {
        "not".to_string()
    }
}

/// Match the request Host (case-insensitive, port-insensitive, `*` wildcards).
pub struct HostMatcher {
    /// Host patterns.
    pub patterns: Vec<String>,
}

impl Matcher for HostMatcher {
    fn matches(&self, request: &Request) -> bool {
        let Some(host) = request.host_without_port() else {
            return false;
        };
        self.patterns.iter().any(|pattern| {
            // Caddy: `host = repl.ReplaceAll(host, "")` in MatchHost.
            let pattern = request.replace_all(pattern);
            glob_match(&pattern.to_ascii_lowercase(), &host, true)
        })
    }

    fn describe(&self) -> String {
        format!("host {}", self.patterns.join(" "))
    }
}

/// Match the request path (`*` wildcards, case-sensitive).
pub struct PathMatcher {
    /// Path patterns.
    pub patterns: Vec<String>,
}

impl Matcher for PathMatcher {
    fn matches(&self, request: &Request) -> bool {
        let path = request.path();
        let escaped = percent_decode(path);
        self.patterns.iter().any(|pattern| {
            // Caddy: `matchPattern = repl.ReplaceAll(matchPattern, "")` in MatchPath.
            let pattern = request.replace_all(pattern);
            // A '%' in the pattern means that part of the path is compared in raw/escaped space
            // (Caddy: `if strings.Contains(matchPattern, "%")` in MatchPath.matches).
            if pattern.contains('%') {
                match_pattern_with_escape_sequence(path, &pattern)
            } else {
                glob_match(&pattern, &escaped, false) || glob_match(&pattern, path, false)
            }
        })
    }

    fn describe(&self) -> String {
        format!("path {}", self.patterns.join(" "))
    }
}

/// Match the request method.
pub struct MethodMatcher {
    /// Uppercase methods.
    pub methods: Vec<String>,
}

impl Matcher for MethodMatcher {
    fn matches(&self, request: &Request) -> bool {
        self.methods
            .iter()
            .any(|method| method.as_str() == request.method.as_str())
    }

    fn describe(&self) -> String {
        format!("method {}", self.methods.join(" "))
    }
}

/// Match request headers. A value of `*` matches presence; `!value` negates.
pub struct HeaderMatcher {
    /// Field name and accepted values.
    pub fields: Vec<(String, Vec<String>)>,
}

impl Matcher for HeaderMatcher {
    fn matches(&self, request: &Request) -> bool {
        self.fields.iter().all(|(field, expected)| {
            let Ok(name) = field
                .to_ascii_lowercase()
                .parse::<http::header::HeaderName>()
            else {
                return false;
            };
            let values: Vec<&str> = request
                .headers
                .get_all(&name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            expected.iter().any(|pattern| {
                // Caddy: `allowedFieldVal = repl.ReplaceAll(allowedFieldVal, "")` in matchHeaders.
                let expanded = request.replace_all(pattern);
                if let Some(negated) = expanded.strip_prefix('!') {
                    !values.iter().any(|value| glob_match(negated, value, false))
                } else if expanded == "*" {
                    !values.is_empty()
                } else {
                    values
                        .iter()
                        .any(|value| glob_match(&expanded, value, false))
                }
            })
        })
    }

    fn describe(&self) -> String {
        format!(
            "header {}",
            self.fields
                .iter()
                .map(|(field, values)| format!("{field}={}", values.join("|")))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

/// Match query parameters.
pub struct QueryMatcher {
    /// Key/value pairs; `*` wildcards are supported on both.
    pub pairs: Vec<(String, String)>,
}

impl Matcher for QueryMatcher {
    fn matches(&self, request: &Request) -> bool {
        let Some(query) = request.query() else {
            return false;
        };
        let pairs: Vec<(String, String)> = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                (percent_decode(key), percent_decode(value))
            })
            .collect();
        self.pairs.iter().all(|(key, value)| {
            // Caddy: `param = repl.ReplaceAll(param, "")` and the same for each value in
            // MatchQuery (matchers.go).
            let key = request.replace_all(key);
            let value = request.replace_all(value);
            pairs.iter().any(|(actual_key, actual_value)| {
                glob_match(&key, actual_key, false) && glob_match(&value, actual_value, false)
            })
        })
    }

    fn describe(&self) -> String {
        format!(
            "query {}",
            self.pairs
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

/// How the `file` matcher chooses among its `try_files` candidates
/// (Caddy's `try_policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileTryPolicy {
    /// The first candidate that exists (Caddy's default).
    #[default]
    FirstExist,
    /// Like [`FileTryPolicy::FirstExist`], but the last candidate always matches (fallback).
    FirstExistFallback,
    /// The existing candidate with the smallest size.
    SmallestSize,
    /// The existing candidate with the largest size.
    LargestSize,
    /// The existing candidate with the most recent modification time.
    MostRecentlyModified,
}

impl FileTryPolicy {
    fn parse(value: Option<&str>) -> Result<Self> {
        match value.unwrap_or("") {
            "" | "first_exist" => Ok(Self::FirstExist),
            "first_exist_fallback" => Ok(Self::FirstExistFallback),
            "smallest_size" => Ok(Self::SmallestSize),
            "largest_size" => Ok(Self::LargestSize),
            "most_recently_modified" => Ok(Self::MostRecentlyModified),
            other => Err(Error::InvalidConfig {
                path: "match.file.try_policy".to_string(),
                message: format!(
                    "unsupported try_policy `{other}`; expected first_exist, first_exist_fallback, smallest_size, largest_size or most_recently_modified"
                ),
            }),
        }
    }
}

/// One candidate produced by expanding a `try_files` pattern.
struct FileCandidate {
    /// Filesystem path (`root` + cleaned, sanitized relative path).
    fullpath: String,
    /// Path relative to `root`, with a leading `/` (Caddy's placeholder value).
    relative: String,
    /// Remainder after a `split_path` split.
    remainder: String,
}

/// A matched file candidate plus whether it is a directory.
struct SelectedFile {
    candidate: FileCandidate,
    is_dir: bool,
}

/// `file` matcher: match the request by testing files under `root` (Caddy's `http.matchers.file`).
///
/// Supported JSON fields: `root` (placeholders allowed; defaults to `{http.vars.root}`),
/// `try_files` (defaults to `{http.request.uri.path}`), `try_policy` and `split_path`.
/// On a match the matcher publishes `http.matchers.file.relative`, `.absolute`, `.type` and
/// `.remainder` for later handlers (for example the adapter's try_files rewrite to
/// `{http.matchers.file.relative}`).
///
/// `try_files` patterns are expanded like Caddy's `makeCandidates`: placeholders are expanded with
/// glob metacharacters in their values escaped (so request data cannot inject globs), then Go
/// `filepath.Glob` semantics apply — `*`, `?`, `[...]` classes and `\` escapes per path component,
/// sorted results, existing paths only, and meta-patterns ending in a path separator matching
/// nothing. Patterns without metacharacters behave like Go's `Glob`: the path itself when it
/// exists, else no candidate (so a nonexistent literal fallback does not match).
///
/// In `first_exist`/`first_exist_fallback`, a `try_files` entry of the form `=NNN` (100–999) is
/// Caddy's error fallback: matching aborts route evaluation and the router responds with that
/// status (an empty-body response, matching the Caddy v2.11.7 oracle). Other policies treat `=NNN`
/// as a literal candidate, like Caddy.
///
/// Not supported (loud/absent rather than approximated): custom filesystem modules (`fs`; loud
/// `NotImplemented`). Glob subset gaps: malformed patterns/classes are treated as non-matching
/// rather than `ErrBadPattern`, non-UTF-8 file names are lossily compared, and the offline build
/// does not implement Go's `filepath.Match` escapes beyond the documented `\` form.
#[derive(Debug)]
pub struct FileMatcher {
    root: String,
    try_files: Vec<String>,
    try_policy: FileTryPolicy,
    split_path: Vec<String>,
}

impl FileMatcher {
    /// Build from a `file` matcher JSON value.
    pub fn from_json(value: &Value, path: &str) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| Error::InvalidConfig {
            path: path.to_string(),
            message: "file matcher must be an object".to_string(),
        })?;
        if object.contains_key("fs") {
            return Err(Error::NotImplemented {
                feature: "file matcher `fs` (custom filesystem modules)",
                tracking_id: "T-ROUTE-027",
            });
        }
        for field in object.keys() {
            if !matches!(
                field.as_str(),
                "root" | "try_files" | "try_policy" | "split_path"
            ) {
                return Err(Error::InvalidConfig {
                    path: format!("{path}.{field}"),
                    message: format!("unsupported file matcher field `{field}`"),
                });
            }
        }
        let root = match object.get("root") {
            None | Some(Value::Null) => "{http.vars.root}".to_string(),
            Some(Value::String(root)) => root.clone(),
            Some(_) => {
                return Err(Error::InvalidConfig {
                    path: format!("{path}.root"),
                    message: "`root` must be a string".to_string(),
                })
            }
        };
        let try_files = match object.get("try_files") {
            None | Some(Value::Null) => vec!["{http.request.uri.path}".to_string()],
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| Error::InvalidConfig {
                            path: format!("{path}.try_files"),
                            message: "`try_files` must be an array of strings".to_string(),
                        })
                })
                .collect::<Result<Vec<_>>>()?,
            Some(_) => {
                return Err(Error::InvalidConfig {
                    path: format!("{path}.try_files"),
                    message: "`try_files` must be an array of strings".to_string(),
                })
            }
        };
        let try_policy = FileTryPolicy::parse(
            object
                .get("try_policy")
                .and_then(Value::as_str)
                .or(None::<&str>),
        )
        .map_err(|error| match error {
            Error::InvalidConfig { message, .. } => Error::InvalidConfig {
                path: format!("{path}.try_policy"),
                message,
            },
            other => other,
        })?;
        let split_path = match object.get("split_path") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => {
                let mut splits = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    let split = item.as_str().ok_or_else(|| Error::InvalidConfig {
                        path: format!("{path}.split_path"),
                        message: "`split_path` must be an array of strings".to_string(),
                    })?;
                    if split.is_empty() {
                        return Err(Error::InvalidConfig {
                            path: format!("{path}.split_path[{index}]"),
                            message: "split delimiter must not be empty".to_string(),
                        });
                    }
                    splits.push(split.to_string());
                }
                splits
            }
            Some(_) => {
                return Err(Error::InvalidConfig {
                    path: format!("{path}.split_path"),
                    message: "`split_path` must be an array of strings".to_string(),
                })
            }
        };
        Ok(Self {
            root,
            try_files,
            try_policy,
            split_path,
        })
    }

    fn expanded_root(&self, request: &Request) -> String {
        // Caddy: filepath.Clean(repl.ReplaceAll(root, ".")). `ReplaceAll` substitutes "."
        // for every *empty* replacement value (including unknown placeholders, whose value is
        // nil/empty), then the root is lexically cleaned. This matters for roots such as
        // `{unknown}/sub`: Caddy cleans `./sub` to `sub`, whereas replacing the placeholder with
        // nothing would produce an absolute `/sub`.
        path_clean(&expand_root_placeholders(request, &self.root))
    }

    /// Expand and clean one `try_files` pattern into candidate file paths.
    ///
    /// Mirrors Caddy's `makeCandidates`: placeholders are expanded with glob metacharacters in
    /// their *values* escaped, the path is cleaned/split, joined under the root, and then expanded
    /// with Go `filepath.Glob` semantics (`*`, `?`, `[...]`, `\` escapes; sorted; existing files
    /// only; a glob pattern with a trailing separator matches nothing).
    fn candidates(&self, root: &str, request: &Request, pattern: &str) -> Vec<FileCandidate> {
        let expanded = expand_glob_safe(request, pattern);
        // Caddy cleans the *expanded* path and restores its trailing slash before splitting and
        // joining under the root (so `{path}` for `/dir/` still identifies a directory), then
        // rejects directory candidates whose pattern did not end in `/` (so `/dir/` falls through
        // to a later `{path}/index.php` entry).
        let mut cleaned = path_clean(&expanded);
        if expanded.ends_with('/') && !cleaned.ends_with('/') {
            cleaned.push('/');
        }
        let (before_split, remainder) = first_split(&cleaned, &self.split_path);
        if before_split != "/" && before_split.ends_with('/') && !pattern.ends_with('/') {
            return Vec::new();
        }
        let fullpath = sanitized_join(root, &before_split);
        let trailing = fullpath.ends_with('/');
        let glob_pattern = if trailing {
            fullpath.trim_end_matches('/').to_string()
        } else {
            fullpath.clone()
        };
        let glob_pattern = if glob_pattern.is_empty() {
            "/".to_string()
        } else {
            glob_pattern
        };
        // Go's `filepath.Glob`: a pattern containing metacharacters and ending in a path separator
        // matches nothing (the last, empty component never matches a directory entry).
        if trailing && path_has_glob_meta(&glob_pattern) {
            return Vec::new();
        }
        let mut results = glob_expand(&glob_pattern);
        results.sort();
        results
            .into_iter()
            .map(|mut fullpath| {
                if trailing && !fullpath.ends_with('/') {
                    fullpath.push('/');
                }
                let relative = fullpath
                    .strip_prefix(root)
                    .map(str::to_string)
                    .unwrap_or_else(|| fullpath.clone());
                FileCandidate {
                    fullpath,
                    relative,
                    remainder: remainder.clone(),
                }
            })
            .collect()
    }

    /// Caddy's `makeLiteralCandidate`: the final `first_exist_fallback` entry matches
    /// unconditionally, even when the file (or glob) does not exist. It does not glob or escape
    /// placeholder values.
    fn literal_candidate(&self, root: &str, request: &Request, pattern: &str) -> FileCandidate {
        let expanded = expand_placeholders_raw(request, pattern);
        let cleaned = path_clean(&expanded);
        let (mut before_split, remainder) = first_split(&cleaned, &self.split_path);
        if pattern.ends_with('/') {
            before_split.push('/');
        }
        let fullpath = sanitized_join(root, &before_split);
        let relative = fullpath
            .strip_prefix(root)
            .map(str::to_string)
            .unwrap_or_else(|| fullpath.clone());
        FileCandidate {
            fullpath,
            relative,
            remainder,
        }
    }

    fn select(&self, request: &Request) -> std::result::Result<Option<SelectedFile>, MatcherError> {
        let root = self.expanded_root(request);
        match self.try_policy {
            FileTryPolicy::FirstExist | FileTryPolicy::FirstExistFallback => {
                let fallback_index = if self.try_policy == FileTryPolicy::FirstExistFallback {
                    self.try_files.len().checked_sub(1)
                } else {
                    None
                };
                for (index, pattern) in self.try_files.iter().enumerate() {
                    // A `=NNN` candidate is Caddy's error fallback: it aborts route evaluation and
                    // responds with that status instead of matching a file. Caddy's error message
                    // is the status digits (`fmt.Errorf("%s", input[1:])`).
                    if let Some(status) = parse_error_code(pattern) {
                        return Err(MatcherError {
                            status,
                            message: pattern[1..].to_string(),
                        });
                    }
                    let mut candidates = self.candidates(&root, request, pattern);
                    let is_fallback = Some(index) == fallback_index;
                    if is_fallback && candidates.is_empty() {
                        // Caddy's last `first_exist_fallback` entry is a literal fallback that
                        // matches even when the file is absent.
                        candidates.push(self.literal_candidate(&root, request, pattern));
                    }
                    for candidate in candidates {
                        if is_fallback {
                            return Ok(Some(SelectedFile {
                                candidate,
                                is_dir: false,
                            }));
                        }
                        if let Some(is_dir) = strict_file_exists(&candidate.fullpath) {
                            return Ok(Some(SelectedFile { candidate, is_dir }));
                        }
                    }
                }
                Ok(None)
            }
            FileTryPolicy::SmallestSize | FileTryPolicy::LargestSize => {
                let mut best: Option<(SelectedFile, u64)> = None;
                for pattern in &self.try_files {
                    for candidate in self.candidates(&root, request, pattern) {
                        let Ok(metadata) = std::fs::metadata(&candidate.fullpath) else {
                            continue;
                        };
                        let size = metadata.len();
                        let is_dir = metadata.is_dir();
                        best = match best {
                            None => Some((SelectedFile { candidate, is_dir }, size)),
                            Some((current, current_size)) => {
                                let replace = if self.try_policy == FileTryPolicy::SmallestSize {
                                    // Caddy's condition: smallestSize == 0 || size < smallestSize
                                    current_size == 0 || size < current_size
                                } else {
                                    size > current_size
                                };
                                if replace {
                                    Some((SelectedFile { candidate, is_dir }, size))
                                } else {
                                    Some((current, current_size))
                                }
                            }
                        };
                    }
                }
                Ok(best.map(|(selected, _)| selected))
            }
            FileTryPolicy::MostRecentlyModified => {
                let mut best: Option<(SelectedFile, std::time::SystemTime)> = None;
                for pattern in &self.try_files {
                    for candidate in self.candidates(&root, request, pattern) {
                        let Ok(metadata) = std::fs::metadata(&candidate.fullpath) else {
                            continue;
                        };
                        let Ok(modified) = metadata.modified() else {
                            continue;
                        };
                        let is_dir = metadata.is_dir();
                        let replace = best.as_ref().is_none_or(|(_, current)| modified > *current);
                        if replace {
                            best = Some((SelectedFile { candidate, is_dir }, modified));
                        }
                    }
                }
                Ok(best.map(|(selected, _)| selected))
            }
        }
    }
}

impl Matcher for FileMatcher {
    fn matches(&self, request: &Request) -> bool {
        self.select(request).ok().flatten().is_some()
    }

    fn matches_mut(&self, request: &mut Request) -> bool {
        let selected = match self.select(request) {
            Ok(Some(selected)) => selected,
            Ok(None) => return false,
            Err(error) => {
                request.set_matcher_error(error.status, error.message);
                return false;
            }
        };
        let vars = &mut request.vars;
        vars.insert(
            "matchers.file.relative".to_string(),
            selected.candidate.relative,
        );
        vars.insert(
            "matchers.file.absolute".to_string(),
            selected.candidate.fullpath,
        );
        vars.insert(
            "matchers.file.remainder".to_string(),
            selected.candidate.remainder,
        );
        vars.insert(
            "matchers.file.type".to_string(),
            if selected.is_dir {
                "directory".to_string()
            } else {
                "file".to_string()
            },
        );
        true
    }

    fn describe(&self) -> String {
        format!("file try_files {}", self.try_files.join(" "))
    }
}

/// Caddy's `cleanPath`: Go `path.Clean` plus preservation of a trailing slash.
fn caddy_clean_path(path: &str) -> String {
    let mut cleaned = path_clean(path);
    if cleaned != "/" && path.ends_with('/') && !cleaned.ends_with('/') {
        cleaned.push('/');
    }
    cleaned
}

/// `http.matchers.path_regexp`: RE2-subset regular expression match on the cleaned request path.
///
/// JSON shape: `{"path_regexp": {"name": "optional-name", "pattern": "^/foo(.*)$"}}`. On a match
/// the capture groups are published like Caddy's `MatchRegexp.Match`:
/// `{http.regexp.<name>.<index>}` (when a name is configured) and `{http.regexp.<index>}` for every
/// index (0 = whole match), plus named groups by name (matching Caddy's `MatchRegexp.Match`).
/// The pattern is compiled with the linear-time `regex` crate (RE2 syntax): look-around and
/// backreferences are rejected loudly as in Go, while named groups, word boundaries, lazy
/// quantifiers and inline flags are supported. Unicode-aware `\w`/`\d`/`\s`/`\b` classes are
/// the documented DIV-0015 residual.
pub struct PathRegexpMatcher {
    /// Optional capture namespace (Caddy `name`; must be word characters when set).
    pub name: Option<String>,
    /// The configured pattern (kept for diagnostics).
    pub pattern: String,
    regex: Regex,
}

impl PathRegexpMatcher {
    fn from_json(value: &Value, path: &str) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| Error::InvalidConfig {
            path: path.to_string(),
            message: "path_regexp matcher must be an object with `pattern` and optional `name`"
                .to_string(),
        })?;
        let pattern = object
            .get("pattern")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidConfig {
                path: format!("{path}.pattern"),
                message: "path_regexp matcher requires a string `pattern`".to_string(),
            })?;
        let name = match object.get("name") {
            None => None,
            Some(Value::String(name)) => {
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
                {
                    return Err(Error::InvalidConfig {
                        path: format!("{path}.name"),
                        message: format!(
                            "invalid regexp name (must contain only word characters): {name}"
                        ),
                    });
                }
                Some(name.clone())
            }
            Some(_) => {
                return Err(Error::InvalidConfig {
                    path: format!("{path}.name"),
                    message: "path_regexp matcher `name` must be a string".to_string(),
                })
            }
        };
        let regex = Regex::new(pattern).map_err(|error| Error::InvalidConfig {
            path: format!("{path}.pattern"),
            message: format!("path_regexp `{pattern}`: {error}"),
        })?;
        Ok(Self {
            name,
            pattern: pattern.to_string(),
            regex,
        })
    }

    fn record_captures(&self, request: &mut Request, cleaned_path: &str) {
        let Some(captures) = self.regex.captures(cleaned_path) else {
            return;
        };
        for index in 0..=captures.group_count() {
            let value = captures
                .group(index)
                .and_then(|(start, end)| cleaned_path.get(start..end))
                .unwrap_or("")
                .to_string();
            if let Some(name) = &self.name {
                request
                    .vars
                    .insert(format!("http.regexp.{name}.{index}"), value.clone());
            }
            request.vars.insert(format!("http.regexp.{index}"), value);
        }
        // Caddy then publishes named groups by name, in both the scoped and unscoped form.
        for (index, name) in self.regex.capture_names().enumerate() {
            let Some(name) = name else { continue };
            if index == 0 {
                continue;
            }
            let value = captures
                .group(index)
                .and_then(|(start, end)| cleaned_path.get(start..end))
                .unwrap_or("")
                .to_string();
            if let Some(scope) = &self.name {
                request
                    .vars
                    .insert(format!("http.regexp.{scope}.{name}"), value.clone());
            }
            request.vars.insert(format!("http.regexp.{name}"), value);
        }
    }
}

impl Matcher for PathRegexpMatcher {
    fn matches(&self, request: &Request) -> bool {
        let path = percent_decode(request.path());
        self.regex.is_match(&caddy_clean_path(&path))
    }

    fn matches_mut(&self, request: &mut Request) -> bool {
        let path = percent_decode(request.path());
        let cleaned_path = caddy_clean_path(&path);
        if self.regex.captures(&cleaned_path).is_none() {
            return false;
        }
        self.record_captures(request, &cleaned_path);
        true
    }

    fn describe(&self) -> String {
        match &self.name {
            Some(name) => format!("path_regexp {name} {}", self.pattern),
            None => format!("path_regexp {}", self.pattern),
        }
    }
}

/// Caddy's private-network CIDR list (`internal.PrivateRangesCIDR`), used when a matcher range
/// says `private_ranges` (the Caddyfile adapter normally expands this before JSON).
pub const PRIVATE_RANGES: &[&str] = &[
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
    "127.0.0.1/8",
    "fd00::/8",
    "::1",
];

/// One parsed IP address or CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    base: IpAddr,
    prefix: u8,
}

impl IpRange {
    /// Parse one IP or CIDR string (Caddy also accepts a zone suffix, which is ignored here).
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.split('%').next().unwrap_or(value).trim();
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
            None => (value, None),
        };
        let base: IpAddr = address.parse().ok()?;
        let max = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(Self { base, prefix })
    }

    /// Whether `address` is inside this range.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.base, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(base) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(base) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

/// Expand `{env.NAME}` placeholders in a matcher range at provision time (Caddy's provisioners
/// run `ReplaceAll` over the configured ranges; the offline replacer exposes environment values).
fn expand_env(value: &str) -> String {
    if !value.contains('{') {
        return value.to_string();
    }
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('{') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            output.push_str(&rest[start..]);
            return output;
        };
        let name = &after[..end];
        match name.strip_prefix("env.") {
            Some(variable) => output.push_str(&std::env::var(variable).unwrap_or_default()),
            None => {
                output.push('{');
                output.push_str(name);
                output.push('}');
            }
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    output
}

/// Parse a `{"ranges": [...]}` matcher object into IP ranges.
fn parse_ip_ranges(value: &Value, path: &str) -> Result<Vec<IpRange>> {
    let object = value.as_object().ok_or_else(|| Error::InvalidConfig {
        path: path.to_string(),
        message: "matcher must be an object with a `ranges` array".to_string(),
    })?;
    let mut ranges = Vec::new();
    match object.get("ranges") {
        None | Some(Value::Null) => {}
        Some(Value::Array(values)) => {
            for (index, value) in values.iter().enumerate() {
                let range_path = format!("{path}.ranges[{index}]");
                let range = value.as_str().ok_or_else(|| Error::InvalidConfig {
                    path: range_path.clone(),
                    message: "each range must be a string".to_string(),
                })?;
                let range = expand_env(range);
                if range == "private_ranges" {
                    for private in PRIVATE_RANGES {
                        ranges.push(IpRange::parse(private).expect("built-in range is valid"));
                    }
                    continue;
                }
                let parsed = IpRange::parse(&range).ok_or_else(|| Error::InvalidConfig {
                    path: range_path,
                    message: format!("`{range}` is not a valid IP address or CIDR range"),
                })?;
                ranges.push(parsed);
            }
        }
        Some(_) => {
            return Err(Error::InvalidConfig {
                path: format!("{path}.ranges"),
                message: "`ranges` must be an array of IP addresses or CIDR ranges".to_string(),
            })
        }
    }
    Ok(ranges)
}

/// `http.matchers.remote_ip`: match the direct connection's peer IP against IP/CIDR ranges.
pub struct RemoteIpMatcher {
    /// Parsed ranges.
    pub ranges: Vec<IpRange>,
}

impl RemoteIpMatcher {
    fn from_json(value: &Value, path: &str) -> Result<Self> {
        Ok(Self {
            ranges: parse_ip_ranges(value, path)?,
        })
    }
}

impl Matcher for RemoteIpMatcher {
    fn matches(&self, request: &Request) -> bool {
        let Some(remote) = request.remote_addr else {
            return false;
        };
        self.ranges.iter().any(|range| range.contains(remote.ip()))
    }

    fn describe(&self) -> String {
        "remote_ip".to_string()
    }
}

/// Parse an address-ish string (`ip`, `host:port`, `[v6]:port`) into an IP.
fn parse_address_ip(value: &str) -> Option<IpAddr> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Some(address.ip());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }
    value
        .rsplit_once(':')
        .and_then(|(host, _)| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
}

/// `http.matchers.client_ip`: match the resolved client IP, considering trusted proxies.
///
/// Caddy stores the resolved client IP in the `client_ip` request variable; caddy-rs's server sets
/// it when trusted-proxy resolution is enabled. When the variable is absent this falls back to the
/// direct peer IP (the same value Caddy's server uses when no proxy is trusted).
pub struct ClientIpMatcher {
    /// Parsed ranges.
    pub ranges: Vec<IpRange>,
}

impl ClientIpMatcher {
    fn from_json(value: &Value, path: &str) -> Result<Self> {
        Ok(Self {
            ranges: parse_ip_ranges(value, path)?,
        })
    }
}

impl Matcher for ClientIpMatcher {
    fn matches(&self, request: &Request) -> bool {
        let client_ip = request
            .vars
            .get("client_ip")
            .and_then(|value| parse_address_ip(value))
            .or_else(|| request.remote_addr.map(|remote| remote.ip()));
        let Some(client_ip) = client_ip else {
            return false;
        };
        self.ranges.iter().any(|range| range.contains(client_ip))
    }

    fn describe(&self) -> String {
        "client_ip".to_string()
    }
}

/// `http.matchers.local_ip` (caddy-rs extension): match the connection's local (listener) address.
///
/// Caddy v2.11.7 has no HTTP `local_ip` matcher (the name exists only as a TLS connection-policy
/// matcher); caddy-rs exposes the listener address as `http.request.local.host` request variables
/// (set by the server, including the PROXY protocol destination address), so the same filtering is
/// available for HTTP routes. JSON shape matches `remote_ip`: `{"ranges": [...]}`.
pub struct LocalIpMatcher {
    /// Parsed ranges.
    pub ranges: Vec<IpRange>,
}

impl LocalIpMatcher {
    fn from_json(value: &Value, path: &str) -> Result<Self> {
        Ok(Self {
            ranges: parse_ip_ranges(value, path)?,
        })
    }
}

impl Matcher for LocalIpMatcher {
    fn matches(&self, request: &Request) -> bool {
        let local_ip = request
            .vars
            .get("http.request.local.host")
            .and_then(|value| value.parse::<IpAddr>().ok())
            .or_else(|| {
                request
                    .vars
                    .get("http.request.local")
                    .and_then(|value| parse_address_ip(value))
            });
        let Some(local_ip) = local_ip else {
            return false;
        };
        self.ranges.iter().any(|range| range.contains(local_ip))
    }

    fn describe(&self) -> String {
        "local_ip".to_string()
    }
}

/// The HTTP version inferred for `protocol` matching.
///
/// The server propagates the effective negotiated protocol on [`Request::version`] from the hyper
/// connection (hyper reports HTTP/1.1 for HTTP/1.1 connections and HTTP/2 for h2, prior-knowledge
/// h2c, and h2c-upgraded requests alike). The negotiated TLS ALPN (`tls.alpn`) remains a fallback
/// for requests built without a transport.
fn request_http_version(request: &Request) -> Option<(u8, u8)> {
    if let Some(alpn) = request.vars.get("tls.alpn") {
        return match alpn.as_str() {
            "h2" => Some((2, 0)),
            "h3" => Some((3, 0)),
            "http/1.1" => Some((1, 1)),
            "http/1.0" => Some((1, 0)),
            _ => None,
        };
    }
    match request.version {
        http::Version::HTTP_2 => Some((2, 0)),
        http::Version::HTTP_3 => Some((3, 0)),
        http::Version::HTTP_11 => Some((1, 1)),
        http::Version::HTTP_10 => Some((1, 0)),
        _ => None,
    }
}

/// `http.matchers.protocol`: match the request protocol (Caddy's `http`, `https`, `grpc` and
/// HTTP-version strings such as `http/2` or `http/2+`).
pub struct ProtocolMatcher {
    /// Configured protocol string (Caddy passes it through; unknown values never match).
    pub protocol: String,
}

impl ProtocolMatcher {
    fn from_json(value: &Value, path: &str) -> Result<Self> {
        let protocol = value.as_str().ok_or_else(|| Error::InvalidConfig {
            path: path.to_string(),
            message: "protocol matcher must be a string".to_string(),
        })?;
        Ok(Self {
            protocol: protocol.to_ascii_lowercase(),
        })
    }
}

impl Matcher for ProtocolMatcher {
    fn matches(&self, request: &Request) -> bool {
        match self.protocol.as_str() {
            "grpc" => request
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("application/grpc")),
            "https" => request.tls,
            "http" => !request.tls,
            version => {
                let Some((major, minor)) = request_http_version(request) else {
                    return false;
                };
                match version {
                    "http/1.0" => (major, minor) == (1, 0),
                    "http/1.1" => (major, minor) == (1, 1),
                    "http/2" => major == 2,
                    "http/3" => major == 3,
                    "http/1.0+" => (major, minor) >= (1, 0),
                    "http/1.1+" => (major, minor) >= (1, 1),
                    "http/2+" => major >= 2,
                    "http/3+" => major >= 3,
                    _ => false,
                }
            }
        }
    }

    fn describe(&self) -> String {
        format!("protocol {}", self.protocol)
    }
}

/// `http.matchers.tls`: match TLS (and Caddy's `handshake_complete` early-data predicate).
///
/// Caddy v2.11.7's TLS matcher only exposes `handshake_complete`; TLS version, cipher suite, SNI
/// and resumption are not HTTP route matcher fields (they are connection-policy fields and
/// `{http.request.tls.*}` placeholders). Configuring those here is rejected loudly rather than
/// silently ignored; see the report for the server-side TLS-metadata wiring that a caddy-rs
/// extension would need.
pub struct TlsMatcher {
    /// `handshake_complete`: `Some(false)` is Caddy's Caddyfile `tls early_data` form.
    pub handshake_complete: Option<bool>,
}

impl TlsMatcher {
    fn from_json(value: &Value, path: &str) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| Error::InvalidConfig {
            path: path.to_string(),
            message: "tls matcher must be an object".to_string(),
        })?;
        let mut handshake_complete = None;
        for (key, value) in object {
            match key.as_str() {
                "handshake_complete" => {
                    let flag = value.as_bool().ok_or_else(|| Error::InvalidConfig {
                        path: format!("{path}.handshake_complete"),
                        message: "handshake_complete must be a boolean".to_string(),
                    })?;
                    handshake_complete = Some(flag);
                }
                _ => {
                    return Err(Error::NotImplemented {
                        feature: "tls matcher fields version_min/version_max/cipher_suites/sni/resumed (not part of Caddy v2.11.7's HTTP TLS matcher; TLS metadata does not reach the HTTP engine yet)",
                        tracking_id: "TLS-MATCHER-METADATA",
                    });
                }
            }
        }
        Ok(Self { handshake_complete })
    }
}

impl Matcher for TlsMatcher {
    fn matches(&self, request: &Request) -> bool {
        if !request.tls {
            return false;
        }
        // caddy-rs serves TLS only after a completed handshake (no 0-RTT early data).
        match self.handshake_complete {
            Some(false) => false,
            Some(true) | None => true,
        }
    }

    fn describe(&self) -> String {
        "tls".to_string()
    }
}

/// `http.matchers.expression`: Caddy's CEL expression matcher (documented caddy-rs subset). The
/// parser, static type check and evaluator live in [`crate::expression`].
use crate::expression::ExpressionMatcher;

/// Caddy's `=NNN` error fallback: a pattern of the form `=404` aborts matching and responds with
/// that status (`100..=999`; other `=...` strings are ordinary literal candidates).
fn parse_error_code(pattern: &str) -> Option<http::StatusCode> {
    let digits = pattern.strip_prefix('=')?;
    if digits.is_empty() {
        return None;
    }
    let code: i64 = digits.parse().ok()?;
    if (100..=999).contains(&code) {
        http::StatusCode::from_u16(code as u16).ok()
    } else {
        None
    }
}

/// Expand placeholders in a `try_files` pattern like Caddy's `ReplaceFunc`, escaping glob
/// metacharacters in the replacement *values* so request/placeholder data cannot inject globs.
fn expand_glob_safe(request: &Request, pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut output = String::with_capacity(pattern.len());
    let mut index = 0;
    while index < chars.len() {
        let current = chars[index];
        // Escaped braces are literal, matching the replacer's `\{`/`\}` handling.
        if current == '\\'
            && index + 1 < chars.len()
            && (chars[index + 1] == '{' || chars[index + 1] == '}')
        {
            output.push(chars[index + 1]);
            index += 2;
            continue;
        }
        if current == '{' {
            if let Some(offset) = chars[index + 1..].iter().position(|c| *c == '}') {
                let name: String = chars[index + 1..index + 1 + offset].iter().collect();
                let value = request.get_placeholder(&name).unwrap_or_default();
                output.push_str(&escape_glob_metacharacters(&value));
                index += offset + 2;
                continue;
            }
        }
        output.push(current);
        index += 1;
    }
    output
}

/// Expand placeholders without escaping glob metacharacters (Caddy's `makeLiteralCandidate`).
fn expand_placeholders_raw(request: &Request, pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut output = String::with_capacity(pattern.len());
    let mut index = 0;
    while index < chars.len() {
        let current = chars[index];
        if current == '\\'
            && index + 1 < chars.len()
            && (chars[index + 1] == '{' || chars[index + 1] == '}')
        {
            output.push(chars[index + 1]);
            index += 2;
            continue;
        }
        if current == '{' {
            if let Some(offset) = chars[index + 1..].iter().position(|c| *c == '}') {
                let name: String = chars[index + 1..index + 1 + offset].iter().collect();
                output.push_str(&request.get_placeholder(&name).unwrap_or_default());
                index += offset + 2;
                continue;
            }
        }
        output.push(current);
        index += 1;
    }
    output
}

fn escape_glob_metacharacters(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '*' | '[' | '?' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// Whether the pattern contains unescaped glob metacharacters (`*`, `?`, `[`).
fn path_has_glob_meta(pattern: &str) -> bool {
    let mut escaped = false;
    for character in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '*' | '?' | '[') {
            return true;
        }
    }
    false
}

/// Expand a filesystem glob with Go `filepath.Glob` semantics: `*`, `?`, `[...]` and `\` escapes
/// per path component, sorted results, and only paths that exist (`Lstat` succeeds). A pattern
/// without metacharacters behaves like Go's `Glob`: the path itself when it exists, else nothing.
fn glob_expand(pattern: &str) -> Vec<String> {
    let absolute = pattern.starts_with('/');
    let (mut results, body): (Vec<String>, &str) = if absolute {
        (vec!["/".to_string()], &pattern[1..])
    } else if let Some(rest) = pattern.strip_prefix("./") {
        (vec!["./".to_string()], rest)
    } else {
        (vec![String::new()], pattern)
    };

    for component in body.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if path_has_glob_meta(component) {
            let mut next = Vec::new();
            for base in &results {
                let directory = if base.is_empty() { "." } else { base.as_str() };
                let Ok(entries) = std::fs::read_dir(directory) else {
                    continue;
                };
                let mut names: Vec<String> = entries
                    .filter_map(|entry| entry.ok())
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                for name in names {
                    if glob_path_match(component, &name) {
                        next.push(join_glob_path(base, &name));
                    }
                }
            }
            results = next;
        } else {
            let literal = unescape_glob(component);
            results = results
                .into_iter()
                .map(|base| join_glob_path(&base, &literal))
                .collect();
        }
        if results.is_empty() {
            return Vec::new();
        }
    }

    results = results
        .into_iter()
        .map(|path| {
            if path.is_empty() {
                ".".to_string()
            } else {
                path
            }
        })
        .collect();
    // Go's Glob uses Lstat for literal patterns and only returns names that exist.
    results.retain(|path| std::fs::symlink_metadata(path).is_ok());
    results
}

fn join_glob_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else if base == "/" {
        format!("/{name}")
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

fn unescape_glob(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut unescaped = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\\' && index + 1 < chars.len() {
            unescaped.push(chars[index + 1]);
            index += 2;
        } else {
            unescaped.push(chars[index]);
            index += 1;
        }
    }
    unescaped
}

/// Match one path component against a Go `path.Match` pattern (`*`, `?`, `[class]`, `\` escapes).
fn glob_path_match(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    glob_match_here(&pattern, &name)
}

fn glob_match_here(pattern: &[char], name: &[char]) -> bool {
    let Some(current) = pattern.first() else {
        return name.is_empty();
    };
    match current {
        '*' => {
            let mut rest = pattern;
            while rest.first() == Some(&'*') {
                rest = &rest[1..];
            }
            for index in 0..=name.len() {
                if glob_match_here(rest, &name[index..]) {
                    return true;
                }
            }
            false
        }
        '?' => !name.is_empty() && glob_match_here(&pattern[1..], &name[1..]),
        '[' => {
            if name.is_empty() {
                return false;
            }
            match parse_glob_class(pattern, name[0]) {
                Some((matched, consumed)) => {
                    matched && glob_match_here(&pattern[consumed..], &name[1..])
                }
                None => false,
            }
        }
        '\\' if pattern.len() > 1 => {
            !name.is_empty() && name[0] == pattern[1] && glob_match_here(&pattern[2..], &name[1..])
        }
        literal => {
            !name.is_empty() && name[0] == *literal && glob_match_here(&pattern[1..], &name[1..])
        }
    }
}

/// Parse a `[...]` class at the start of `pattern`; returns whether `name` matched and how many
/// pattern characters the class consumed.
fn parse_glob_class(pattern: &[char], name: char) -> Option<(bool, usize)> {
    let mut index = 1;
    let mut negated = false;
    if pattern.get(index) == Some(&'^') {
        negated = true;
        index += 1;
    }
    let mut matched = false;
    let mut first = true;
    while index < pattern.len() {
        let current = pattern[index];
        if current == ']' && !first {
            return Some((matched != negated, index + 1));
        }
        first = false;
        let mut start = current;
        if start == '\\' {
            index += 1;
            start = *pattern.get(index)?;
        }
        index += 1;
        let mut end = start;
        if pattern.get(index) == Some(&'-')
            && pattern.get(index + 1).is_some_and(|next| *next != ']')
        {
            index += 1;
            let mut last = *pattern.get(index)?;
            if last == '\\' {
                index += 1;
                last = *pattern.get(index)?;
            }
            index += 1;
            end = last;
        }
        if name >= start && name <= end {
            matched = true;
        }
    }
    None
}

/// Expand placeholders in a file-matcher root with Caddy's `Replacer.ReplaceAll(root, ".")`
/// fallback: every empty value (unknown or known-empty) is replaced with ".".
fn expand_root_placeholders(request: &Request, root: &str) -> String {
    let chars: Vec<char> = root.chars().collect();
    let mut output = String::with_capacity(root.len());
    let mut index = 0usize;
    while index < chars.len() {
        let current = chars[index];
        if current == '\\'
            && index + 1 < chars.len()
            && (chars[index + 1] == '{' || chars[index + 1] == '}')
        {
            output.push(chars[index + 1]);
            index += 2;
            continue;
        }
        if current == '{' {
            if let Some(offset) = chars[index + 1..].iter().position(|c| *c == '}') {
                let name: String = chars[index + 1..index + 1 + offset].iter().collect();
                let value = request.get_placeholder(&name).unwrap_or_default();
                if value.is_empty() {
                    output.push('.');
                } else {
                    output.push_str(&value);
                }
                index += offset + 2;
                continue;
            }
        }
        output.push(current);
        index += 1;
    }
    output
}

/// A lexical `path.Clean` for slash-separated paths (Go's `path.Clean` semantics).
fn path_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let body = parts.join("/");
    if rooted {
        format!("/{body}")
    } else if body.is_empty() {
        ".".to_string()
    } else {
        body
    }
}

/// Caddy's `SanitizedPathJoin`: join a request path under `root` without escaping it.
fn sanitized_join(root: &str, request_path: &str) -> String {
    let root = if root.is_empty() { "." } else { root };
    let cleaned = path_clean(&format!("/{request_path}"));
    let relative = cleaned.trim_start_matches('/');
    if !relative.is_empty() && !is_local_path(relative) {
        // Unsafe path (traversal or absolute); Caddy returns the root itself.
        return root.to_string();
    }
    let mut full = root.trim_end_matches('/').to_string();
    if full.is_empty() {
        full.push('/');
    }
    if !relative.is_empty() {
        if !full.ends_with('/') {
            full.push('/');
        }
        full.push_str(relative);
    }
    if request_path.ends_with('/') && request_path.len() > 1 && !full.ends_with('/') {
        full.push('/');
    }
    full
}

/// Whether a clean relative path only contains normal components (`filepath.IsLocal`).
fn is_local_path(relative: &str) -> bool {
    use std::path::Component;
    std::path::Path::new(relative)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
}

/// Caddy's `strictFileExists`: a path ending in `/` must be a directory; otherwise it must not.
fn strict_file_exists(fullpath: &str) -> Option<bool> {
    let metadata = std::fs::metadata(fullpath).ok()?;
    if fullpath.ends_with('/') {
        metadata.is_dir().then_some(true)
    } else {
        (!metadata.is_dir()).then_some(false)
    }
}

/// Caddy's `firstSplit`: split at the first case-insensitive occurrence of a configured delimiter
/// that ends a path component.
fn first_split(path: &str, split_path: &[String]) -> (String, String) {
    for split in split_path {
        if let Some(index) = index_fold(path, split) {
            let position = index + split.len();
            let is_component_end = position == path.len() || path[position..].starts_with('/');
            if !is_component_end {
                continue;
            }
            return (path[..position].to_string(), path[position..].to_string());
        }
    }
    (path.to_string(), String::new())
}

fn index_fold(haystack: &str, needle: &str) -> Option<usize> {
    let needle_len = needle.len();
    if needle_len == 0 || haystack.len() < needle_len {
        return None;
    }
    haystack
        .char_indices()
        .map(|(index, _)| index)
        .find(|index| {
            haystack
                .get(*index..*index + needle_len)
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(needle))
        })
}

/// Simple `*` wildcard matcher. When `case_insensitive` is true both sides are compared lowercased.
pub fn glob_match(pattern: &str, value: &str, case_insensitive: bool) -> bool {
    let pattern: Vec<char> = if case_insensitive {
        pattern.to_ascii_lowercase().chars().collect()
    } else {
        pattern.chars().collect()
    };
    let value: Vec<char> = if case_insensitive {
        value.to_ascii_lowercase().chars().collect()
    } else {
        value.chars().collect()
    };
    let (mut p, mut v) = (0, 0);
    let mut star: Option<usize> = None;
    let mut star_value = 0;
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            star_value = v;
            p += 1;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            star_value += 1;
            v = star_value;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Match an escaped request path against a pattern containing `%` hints, ported from Caddy
/// `MatchPath.matchPatternWithEscapeSequence` (upstream c3fab6576f0e).
///
/// A `%` in the pattern means the corresponding part of the path is compared in raw/escaped
/// space. The pattern and path are walked in lock-step; the cursor into the path advances by the
/// full width of an escape sequence only when that sequence is actually consumed, so a wildcard
/// span starting at an escape sequence cannot swallow a percent-encoded separator (`%2f`) and
/// over-match a `path` pattern (a matcher-integrity/access-control bypass).
fn match_pattern_with_escape_sequence(escaped_path: &str, match_pattern: &str) -> bool {
    let path = escaped_path.as_bytes();
    let pattern = match_pattern.as_bytes();
    let mut matched = Vec::with_capacity(path.len());
    let (mut i_pattern, mut i_path) = (0usize, 0usize);
    while i_pattern < pattern.len() && i_path < path.len() {
        // next character of the request path, decoded when it is an escape sequence
        let mut path_ch_len = 1;
        let mut escaped_path_ch: &[u8] = b"";
        let mut path_ch = path[i_path];
        if path_ch == b'%' && path.len() >= i_path + 3 {
            escaped_path_ch = &path[i_path..i_path + 3];
            match decode_escape_sequence(escaped_path_ch) {
                Some(decoded) => path_ch = decoded,
                // should be impossible unless the request path holds an invalid sequence
                None => return false,
            }
            path_ch_len = 3;
        }

        // now the next character of the pattern
        let mut normalize = true;
        if pattern[i_pattern] == b'%' {
            if pattern.len() >= i_pattern + 3 && pattern[i_pattern + 1] != b'*' {
                // not a wildcard ("%*"): compare literally, consuming the escape sequence
                matched.extend_from_slice(escaped_path_ch);
                i_path += path_ch_len;
                i_pattern += 3;
                continue;
            }
            // escaped wildcard: consume the '*' only, keeping the span in escaped space
            i_pattern += 1;
            normalize = false;
        }
        if pattern[i_pattern] == b'*' {
            // consume up to the character that terminates the wildcard span
            let remaining = &path[i_path..];
            let mut until = remaining.len();
            if i_pattern < pattern.len() - 1 {
                let next_ch = pattern[i_pattern + 1];
                match remaining.iter().position(|byte| *byte == next_ch) {
                    Some(position) => until = position,
                    // terminating character of the wildcard span not found: definitely no match
                    None => return false,
                }
            }
            if until > 0 {
                let span = &remaining[..until];
                if normalize {
                    match unescape_path(span) {
                        Some(unescaped) => matched.extend_from_slice(&unescaped),
                        None => return false,
                    }
                } else {
                    matched.extend_from_slice(span);
                }
                i_path += until;
            }
        } else {
            matched.push(path_ch);
            i_path += path_ch_len;
        }
        i_pattern += 1;
    }

    // if the pattern was fully consumed before the path, the remaining path still has to be part
    // of the compared string; otherwise a pattern without a trailing wildcard would behave like a
    // prefix match. The pattern has no escape hints left here, so compare in normalised space.
    if i_path < path.len() {
        let remaining = &path[i_path..];
        matched.extend_from_slice(&unescape_path(remaining).unwrap_or_else(|| remaining.to_vec()));
    }

    // the matched string is now in escaped space where the pattern asked for it, so `%*` wildcards
    // can be treated as regular wildcards
    let pattern = match_pattern.replace("%*", "*");
    escaped_path_glob_match(&pattern, &String::from_utf8_lossy(&matched))
}

/// Glob used by the escaped-path matcher: like [`glob_match`], but a wildcard never crosses a path
/// separator (Go `path.Match`), so a wildcard span cannot absorb a `/`.
fn escaped_path_glob_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0, 0);
    // pattern index after the last wildcard, and the start of the span it has consumed so far
    let mut star: Option<(usize, usize)> = None;
    loop {
        if v == value.len() {
            while p < pattern.len() && pattern[p] == '*' {
                p += 1;
            }
            return p == pattern.len();
        }
        if p < pattern.len() && pattern[p] == '*' {
            star = Some((p + 1, v));
            p += 1;
        } else if p < pattern.len()
            && (pattern[p] == value[v] || (pattern[p] == '?' && value[v] != '/'))
        {
            p += 1;
            v += 1;
        } else if let Some((star_pattern, star_start)) = star {
            // extend the wildcard span by one character, but never across a path separator
            if value[star_start] == '/' {
                return false;
            }
            star = Some((star_pattern, star_start + 1));
            p = star_pattern;
            v = star_start + 1;
        } else {
            return false;
        }
    }
}

/// Decode the escape sequence `%XX` at the start of `sequence`.
fn decode_escape_sequence(sequence: &[u8]) -> Option<u8> {
    let high = hex_value(*sequence.get(1)?)?;
    let low = hex_value(*sequence.get(2)?)?;
    Some(high * 16 + low)
}

/// Decode `%XX` sequences like Go's `url.PathUnescape`, failing on malformed sequences.
fn unescape_path(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' {
            output.push(decode_escape_sequence(input.get(index..index + 3)?)?);
            index += 3;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
    Some(output)
}

/// Percent-decode a URI component, leaving malformed escapes untouched.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = hex_value(bytes[index + 1]);
            let low = hex_value(bytes[index + 2]);
            if let (Some(high), Some(low)) = (high, low) {
                output.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Request;
    use http::{Method, Uri};

    fn request(uri: &str, host: &str) -> Request {
        let mut request = Request::new(Method::GET, uri.parse::<Uri>().unwrap());
        request
            .headers
            .insert(http::header::HOST, host.parse().unwrap());
        request
    }

    #[test]
    fn host_path_header_and_query_patterns_expand_placeholders() {
        // Caddy v2.11.7 expands matcher patterns with `ReplaceAll`:
        // MatchHost (matchers.go:344), MatchPath (:441), MatchQuery (:1011/:1017) and the
        // header matcher's allowed values (:1167). Unknown placeholders expand to "".
        let mut matcher = HostMatcher {
            patterns: vec!["{http.vars.allowed_host}".to_string()],
        };
        let mut req = request("/", "allowed.example");
        req.vars
            .insert("allowed_host".to_string(), "allowed.example".to_string());
        assert!(matcher.matches(&req));
        req.vars
            .insert("allowed_host".to_string(), "other.example".to_string());
        assert!(!matcher.matches(&req));
        matcher.patterns = vec!["{http.vars.missing}".to_string()];
        // Missing var -> ReplaceAll blanks the pattern, which matches the empty host only.
        assert!(!matcher.matches(&req));

        let path = PathMatcher {
            patterns: vec!["{http.vars.prefix}/*".to_string()],
        };
        let mut req = request("/api/users", "x");
        req.vars.insert("prefix".to_string(), "/api".to_string());
        assert!(path.matches(&req));
        req.vars.insert("prefix".to_string(), "/other".to_string());
        assert!(!path.matches(&req));

        let header = HeaderMatcher {
            fields: vec![(
                "x-session".to_string(),
                vec!["{http.vars.session}".to_string()],
            )],
        };
        let mut req = request("/", "x");
        req.headers.insert("x-session", "abc".parse().unwrap());
        req.vars.insert("session".to_string(), "abc".to_string());
        assert!(header.matches(&req));
        req.vars.insert("session".to_string(), "other".to_string());
        assert!(!header.matches(&req));

        let query = QueryMatcher {
            pairs: vec![(
                "{http.vars.key}".to_string(),
                "{http.vars.value}".to_string(),
            )],
        };
        let mut req = request("/?user=alice", "x");
        req.vars.insert("key".to_string(), "user".to_string());
        req.vars.insert("value".to_string(), "alice".to_string());
        assert!(query.matches(&req));
        req.vars.insert("value".to_string(), "bob".to_string());
        assert!(!query.matches(&req));
    }

    #[test]
    fn host_matching_strips_port_and_is_case_insensitive() {
        let matcher = HostMatcher {
            patterns: vec!["example.com".to_string()],
        };
        assert!(matcher.matches(&request("/", "EXAMPLE.com:8443")));
        assert!(!matcher.matches(&request("/", "other.com")));
    }

    #[test]
    fn host_wildcard_matches_subdomains() {
        let matcher = HostMatcher {
            patterns: vec!["*.example.com".to_string()],
        };
        assert!(matcher.matches(&request("/", "api.example.com")));
        assert!(!matcher.matches(&request("/", "example.com")));
    }

    #[test]
    fn path_wildcards_match_prefix_and_suffix() {
        let matcher = PathMatcher {
            patterns: vec!["/api/*".to_string()],
        };
        assert!(matcher.matches(&request("/api/users", "x")));
        assert!(!matcher.matches(&request("/other", "x")));
        assert!(glob_match("/foo*bar", "/foo/baz/bar", false));
    }

    #[test]
    fn path_matcher_keeps_escaped_cursor_at_wildcard_span_start() {
        // Port of upstream Caddy c3fab6576f0e `TestEscapedPathWildcardCursor`.
        //
        // A `%` in a `path` pattern means "compare that part of the request path in raw/escaped
        // space". A wildcard span must never swallow a percent-encoded slash (`%2f`): otherwise an
        // unauthenticated client can craft a path that matches a `path` pattern it must not match
        // (e.g. entering a privileged `/admin*`-style route or skipping a `not path` exclusion),
        // which is a matcher-integrity/access-control bypass.
        for (pattern, target, want) in [
            // true: the escaped slash is not inside the wildcard span
            ("/foo*bar%2f", "/fooXbar%2f", true),
            ("/foo*bar%2f", "/foobar%2f", true),
            ("/foo*bar%2f", "/foo%41bar%2f", true),
            ("/foo*bar%2f", "/foo%252fbar%2f", true),
            ("/foo%2f*bar%2f", "/foo%2fXbar%2f", true),
            ("/foo%2f*", "/foo%2f%41", true),
            ("/foo%*bar%2f", "/foo%2fbar%2f", true),
            // false: a wildcard span would have to absorb an encoded (or literal) slash
            ("/foo*bar%2f", "/foo/bar/", false),
            ("/foo*bar%2f", "/foo/bar%2f", false),
            ("/foo*bar%2f", "/foo%2fbar%2f", false),
            ("/foo*bar%2f", "/foo%2Fbar%2F", false),
            ("/foo%2f*bar%2f", "/foo%2f%2fbar%2f", false),
            ("/foo%2f*", "/foo%2f%2f", false),
            ("/foo%*bar%2f", "/foo/bar%2f", false),
        ] {
            let matcher = PathMatcher {
                patterns: vec![pattern.to_string()],
            };
            assert_eq!(
                matcher.matches(&request(target, "example.com")),
                want,
                "path {pattern} vs {target}"
            );
        }
    }

    #[test]
    fn path_matcher_escaped_patterns_are_exact_and_compare_in_escaped_space() {
        // Boundary cases for the escape-aware matcher (upstream c3fab6576f0e): a pattern with
        // escapes is an exact match, an escape only matches the same escape in the request path
        // (not its decoded form), and a wildcard span never crosses a path separator.
        for (pattern, target, want) in [
            ("/foo%2fbar", "/foo%2fbar", true),
            ("/foo%2fbar", "/foo%2fbarbaz", false),
            ("/foo%2fbar", "/foo/bar", false),
            ("/foo%2fbar", "/foo%2fbar%2f", false),
            ("/foo%*bar", "/foo%2fbar", true),
            ("/foo%*bar", "/foo/bar", false),
            ("/foo%2f*", "/foo%2f", true),
            ("/foo%2f*", "/foo%2fbar/baz", false),
        ] {
            let matcher = PathMatcher {
                patterns: vec![pattern.to_string()],
            };
            assert_eq!(
                matcher.matches(&request(target, "example.com")),
                want,
                "path {pattern} vs {target}"
            );
        }
    }

    #[test]
    fn header_matcher_supports_wildcard_and_negation() {
        let mut request = request("/", "x");
        request.headers.insert("x-test", "hello".parse().unwrap());
        let matcher = HeaderMatcher {
            fields: vec![
                ("X-Test".to_string(), vec!["h*".to_string()]),
                ("X-Missing".to_string(), vec!["!anything".to_string()]),
            ],
        };
        assert!(matcher.matches(&request));
    }

    #[test]
    fn query_matcher_decodes_and_wildcards() {
        let matcher = QueryMatcher {
            pairs: vec![("name".to_string(), "j*".to_string())],
        };
        assert!(matcher.matches(&request("/?name=jane", "x")));
        assert!(!matcher.matches(&request("/?name=bob", "x")));
    }

    #[test]
    fn not_matcher_negates_the_whole_set() {
        let inner = build_matcher_set(&serde_json::json!({"host": ["example.com"]})).unwrap();
        let matcher = NotMatcher { inner };
        assert!(matcher.matches(&request("/", "other.com")));
        assert!(!matcher.matches(&request("/", "example.com")));
    }

    // ---- file matcher ------------------------------------------------------------------

    fn file_request(path: &str, root: &std::path::Path) -> Request {
        let mut request = request(path, "example.com");
        request
            .vars
            .insert("root".to_string(), root.to_string_lossy().to_string());
        request
    }

    fn file_matcher(json: serde_json::Value) -> FileMatcher {
        FileMatcher::from_json(&json, "match.file").expect("file matcher builds")
    }

    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::write(directory.path().join("index.html"), b"<h1>index</h1>").unwrap();
        std::fs::write(directory.path().join("style.css"), b"body{}").unwrap();
        std::fs::create_dir(directory.path().join("sub")).unwrap();
        std::fs::write(directory.path().join("sub").join("nested.txt"), b"nested").unwrap();
        directory
    }

    #[test]
    fn file_matcher_finds_existing_file_and_sets_placeholders() {
        let directory = fixture();
        let root = directory.path().to_string_lossy().to_string();
        let matcher = file_matcher(serde_json::json!({
            "root": root,
            "try_files": ["{http.request.uri.path}"]
        }));
        let mut request = file_request("/index.html", directory.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/index.html")
        );
        let expected_absolute = directory.path().join("index.html");
        assert_eq!(
            request
                .vars
                .get("matchers.file.absolute")
                .map(String::as_str),
            Some(expected_absolute.to_string_lossy().as_ref())
        );
        assert_eq!(
            request.vars.get("matchers.file.type").map(String::as_str),
            Some("file")
        );
        // The placeholder the adapter's try_files rewrite uses:
        assert_eq!(
            request.replace_all("{http.matchers.file.relative}"),
            "/index.html"
        );
    }

    #[test]
    fn file_matcher_trailing_slash_patterns_match_directories_only() {
        let directory = fixture();
        let root = directory.path().to_string_lossy().to_string();
        let matcher = file_matcher(serde_json::json!({
            "root": root,
            "try_files": ["{http.request.uri.path}/"]
        }));
        let mut request = file_request("/sub", directory.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/sub/")
        );
        assert_eq!(
            request.vars.get("matchers.file.type").map(String::as_str),
            Some("directory")
        );
        // A regular file does not satisfy a trailing-slash (directory) candidate.
        assert!(!matcher.matches(&file_request("/style.css", directory.path())));
        // The same path without the trailing-slash pattern does not match a directory.
        let file_only = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["{http.request.uri.path}"]
        }));
        assert!(!file_only.matches(&file_request("/sub", directory.path())));
    }

    #[test]
    fn file_matcher_defaults_root_and_try_files() {
        let directory = fixture();
        let mut request = file_request("/index.html", directory.path());
        let matcher = FileMatcher::from_json(&serde_json::json!({}), "match.file").unwrap();
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/index.html")
        );
    }

    #[test]
    fn file_matcher_first_exist_fallback_returns_last_candidate() {
        let directory = fixture();
        let matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["/missing.txt", "/index.html"],
            "try_policy": "first_exist_fallback"
        }));
        let mut request = file_request("/anything", directory.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/index.html")
        );

        // Caddy v2.11.9's `makeLiteralCandidate`: the final `first_exist_fallback` entry matches
        // unconditionally even when its file is absent, so routing still reaches the fallback
        // handler (for example a rewrite to an SPA index).
        let fallback_missing = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["/missing.txt", "/also-missing.html"],
            "try_policy": "first_exist_fallback"
        }));
        let mut request = file_request("/anything", directory.path());
        assert!(fallback_missing.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/also-missing.html")
        );
        assert_eq!(
            request.vars.get("matchers.file.type").map(String::as_str),
            Some("file")
        );
        let first_exist = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["/missing.txt", "/also-missing.html"]
        }));
        assert!(!first_exist.matches(&file_request("/anything", directory.path())));
    }

    #[test]
    fn file_matcher_size_and_mtime_policies() {
        let directory = tempfile::tempdir().unwrap();
        let small = directory.path().join("small.txt");
        let large = directory.path().join("large.txt");
        std::fs::write(&small, b"123").unwrap();
        std::fs::write(&large, vec![b'x'; 64]).unwrap();
        let root = directory.path().to_string_lossy().to_string();
        let matcher = |policy: &str| {
            file_matcher(serde_json::json!({
                "root": root,
                "try_files": ["/small.txt", "/large.txt"],
                "try_policy": policy
            }))
        };
        let mut request = file_request("/anything", directory.path());
        assert!(matcher("smallest_size").matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/small.txt")
        );
        let mut request = file_request("/anything", directory.path());
        assert!(matcher("largest_size").matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/large.txt")
        );

        // Make `small.txt` newer than `large.txt` and select it by modification time.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&small, b"123").unwrap();
        let mut request = file_request("/anything", directory.path());
        assert!(matcher("most_recently_modified").matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/small.txt")
        );
    }

    #[test]
    fn file_matcher_no_match_leaves_placeholders_absent() {
        let directory = fixture();
        let matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["/missing.txt"]
        }));
        let mut request = file_request("/missing.txt", directory.path());
        assert!(!matcher.matches_mut(&mut request));
        assert!(!request.vars.contains_key("matchers.file.relative"));
    }

    #[test]
    fn file_matcher_split_path_sets_remainder() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("remote.php"), b"php").unwrap();
        let matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["{http.request.uri.path}"],
            "split_path": [".php"]
        }));
        let mut request = file_request("/remote.php/dav/", directory.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/remote.php")
        );
        // Caddy v2.11.9 restores the trailing slash from the expanded pattern before splitting,
        // so the remainder preserves it (v2.11.7 dropped it before the split).
        assert_eq!(
            request
                .vars
                .get("matchers.file.remainder")
                .map(String::as_str),
            Some("/dav/")
        );
    }

    #[test]
    fn file_matcher_never_escapes_its_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        std::fs::create_dir(&root).unwrap();
        // A secret *outside* the root must not be reachable through try_files.
        std::fs::write(parent.path().join("secret.txt"), b"secret").unwrap();
        let matcher = file_matcher(serde_json::json!({
            "root": root.to_string_lossy(),
            "try_files": ["/../secret.txt", "{http.vars.attempt}"]
        }));
        assert!(!matcher.matches(&file_request("/../secret.txt", &root)));
        let mut request = file_request("/attempt", &root);
        request
            .vars
            .insert("attempt".to_string(), "../secret.txt".to_string());
        assert!(!matcher.matches(&request));
    }

    #[test]
    fn file_matcher_expands_root_placeholders_per_request() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::write(first.path().join("index.html"), "first").unwrap();
        std::fs::write(second.path().join("index.html"), "second").unwrap();
        let matcher = file_matcher(serde_json::json!({
            "root": "{http.vars.root}",
            "try_files": ["{http.request.uri.path}"]
        }));
        let mut request = file_request("/index.html", first.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.absolute")
                .map(String::as_str),
            Some(first.path().join("index.html").to_string_lossy().as_ref())
        );
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/index.html")
        );
        // The same configured root expression switches to the second directory for this request.
        let mut request = file_request("/index.html", second.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.absolute")
                .map(String::as_str),
            Some(second.path().join("index.html").to_string_lossy().as_ref())
        );

        // `{http.request.uri.path}` is expanded into the root too.
        let nested = tempfile::tempdir().unwrap();
        std::fs::create_dir(nested.path().join("site")).unwrap();
        std::fs::write(nested.path().join("site/index.html"), "nested").unwrap();
        let matcher = file_matcher(serde_json::json!({
            "root": format!("{}{{http.request.uri.path}}", nested.path().to_string_lossy()),
            "try_files": ["/index.html"]
        }));
        let mut request = file_request("/site", nested.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.absolute")
                .map(String::as_str),
            Some(
                nested
                    .path()
                    .join("site/index.html")
                    .to_string_lossy()
                    .as_ref()
            )
        );
    }

    #[test]
    fn file_matcher_root_expansion_uses_caddy_empty_fallback() {
        let request = file_request("/", std::path::Path::new("."));
        let matcher = file_matcher(serde_json::json!({
            "root": "{unknown.root.placeholder}/sub",
            "try_files": ["/x"]
        }));
        // Caddy's ReplaceAll(root, ".") turns the empty/unknown placeholder into `.`, so the
        // cleaned root is relative `sub`, not absolute `/sub`.
        assert_eq!(matcher.expanded_root(&request), "sub");

        let matcher = file_matcher(serde_json::json!({
            "root": "{unknown.root.placeholder}",
            "try_files": ["/x"]
        }));
        assert_eq!(matcher.expanded_root(&request), ".");
    }

    #[test]
    fn file_matcher_expands_environment_roots() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("env.txt"), "env").unwrap();
        let variable = format!("CADDY_RS_W23_ROOT_{}", std::process::id());
        std::env::set_var(&variable, directory.path());
        let matcher = file_matcher(serde_json::json!({
            "root": format!("{{env.{variable}}}"),
            "try_files": ["/env.txt"]
        }));
        let mut request = file_request("/env.txt", directory.path());
        let matches = matcher.matches_mut(&mut request);
        std::env::remove_var(&variable);
        assert!(matches);
        assert_eq!(
            request
                .vars
                .get("matchers.file.absolute")
                .map(String::as_str),
            Some(directory.path().join("env.txt").to_string_lossy().as_ref())
        );
    }

    #[test]
    fn file_matcher_expanded_root_still_contains_try_files() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(parent.path().join("secret.txt"), "secret").unwrap();
        let matcher = file_matcher(serde_json::json!({
            "root": "{http.vars.root}",
            "try_files": ["/../secret.txt", "{http.vars.attempt}"]
        }));
        let mut request = file_request("/../secret.txt", &root);
        assert!(!matcher.matches_mut(&mut request));
        let mut request = file_request("/attempt", &root);
        request
            .vars
            .insert("attempt".to_string(), "../secret.txt".to_string());
        assert!(!matcher.matches_mut(&mut request));
    }

    #[test]
    fn file_matcher_unknown_try_files_placeholder_falls_through() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("index.html"), "index").unwrap();
        let matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["{unknown.try.files.placeholder}", "/index.html"]
        }));
        let mut request = file_request("/", directory.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/index.html")
        );
    }

    #[test]
    fn file_matcher_config_is_strict() {
        let error =
            FileMatcher::from_json(&serde_json::json!({"fs": "custom"}), "match.file").unwrap_err();
        assert!(error.to_string().contains("T-ROUTE-027"), "{error}");

        let error =
            FileMatcher::from_json(&serde_json::json!({"try_policy": "bogus"}), "match.file")
                .unwrap_err();
        assert!(error.to_string().contains("try_policy"), "{error}");

        let error = FileMatcher::from_json(
            &serde_json::json!({"try_files": "index.html"}),
            "match.file",
        )
        .unwrap_err();
        assert!(error.to_string().contains("try_files"), "{error}");

        let error =
            FileMatcher::from_json(&serde_json::json!({"root": 42}), "match.file").unwrap_err();
        assert!(error.to_string().contains("root"), "{error}");

        let error = FileMatcher::from_json(
            &serde_json::json!({"try_files": ["/x"], "split_path": [""]}),
            "match.file",
        )
        .unwrap_err();
        assert!(error.to_string().contains("split_path"), "{error}");

        let error = FileMatcher::from_json(&serde_json::json!({"unexpected": true}), "match.file")
            .unwrap_err();
        assert!(
            error.to_string().contains("unsupported file matcher field"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn adapted_try_files_json_serves_fixtures_via_file_server() {
        use crate::router::RouterBuilder;
        use bytes::Bytes;
        use http::Method;

        let directory = fixture();
        let root = directory.path().to_string_lossy().to_string();
        // Canonical JSON shape emitted by the Caddyfile adapter for
        //   root * <dir>
        //   try_files {path} /index.html
        //   file_server
        let routes = vec![
            serde_json::json!({"handle": [{"handler": "vars", "root": root}]}),
            serde_json::json!({
                "match": [{"file": {"try_files": [
                    "{http.request.uri.path}",
                    "/index.html"
                ]}}],
                "handle": [{"handler": "rewrite", "uri": "{http.matchers.file.relative}"}]
            }),
            serde_json::json!({"handle": [{
                "handler": "file_server",
                "root": "{http.vars.root}"
            }]}),
        ];
        let router = RouterBuilder::new().build(&routes).expect("router builds");

        let mut request = Request::new(Method::GET, "/missing.html".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let response = router.handle(request).await.expect("handled");
        assert_eq!(response.status, http::StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"<h1>index</h1>"));

        // An existing file is served directly (the first try_files candidate).
        let mut request = Request::new(Method::GET, "/style.css".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let response = router.handle(request).await.expect("handled");
        assert_eq!(response.status, http::StatusCode::OK);
        assert_eq!(response.body, Bytes::from_static(b"body{}"));
    }

    #[test]
    fn file_matcher_placeholder_directory_trailing_slash_falls_through_to_index() {
        // Caddy v2.11.9 restores the expanded trailing slash, then rejects a directory candidate
        // when the *pattern* did not end in `/`, so `/sub/` falls through to `{path}/index.html`.
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("sub")).unwrap();
        std::fs::write(directory.path().join("sub").join("index.html"), b"index").unwrap();
        let matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": [
                "{http.request.uri.path}",
                "{http.request.uri.path}/index.html"
            ]
        }));
        let mut request = file_request("/sub/", directory.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/sub/index.html")
        );
        // A literal pattern ending in `/` still matches the directory itself.
        let directory_matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["/sub/"]
        }));
        let mut request = file_request("/anything", directory.path());
        assert!(directory_matcher.matches_mut(&mut request));
        assert_eq!(
            request.vars.get("matchers.file.type").map(String::as_str),
            Some("directory")
        );
    }

    #[test]
    fn file_matcher_glob_fallback_with_missing_entries_uses_literal_candidate() {
        // The final `first_exist_fallback` entry is literal (no glob expansion), matching Caddy's
        // `makeLiteralCandidate`; placeholders in it are not glob-escaped.
        let directory = tempfile::tempdir().unwrap();
        let matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["/missing-*.txt", "/fallback/{http.request.uri.path}"],
            "try_policy": "first_exist_fallback"
        }));
        let mut request = file_request("/spa", directory.path());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/fallback/spa")
        );
    }

    #[tokio::test]
    async fn file_matcher_error_code_reaches_error_routes_with_caddy_message() {
        use crate::router::RouterBuilder;
        use http::Method;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_string_lossy().to_string();
        let error_routes = serde_json::json!({
            "routes": [{
                "handle": [{
                    "handler": "static_response",
                    "status_code": 404,
                    "body": "status={http.error.status_code} message={http.error.message}"
                }]
            }]
        });
        let router = RouterBuilder::new()
            .with_error_routes(Some(&error_routes), "errors")
            .expect("error routes build")
            .build(&[serde_json::json!({
                "match": [{"file": {"root": root, "try_files": ["=404"]}}],
                "handle": [{"handler": "static_response", "body": "should not run"}]
            })])
            .expect("router builds");
        let mut request = Request::new(Method::GET, "/anything".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let response = router.handle(request).await.expect("handled");
        assert_eq!(response.status, http::StatusCode::NOT_FOUND);
        assert_eq!(
            String::from_utf8_lossy(&response.body),
            "status=404 message=404"
        );
    }

    fn glob_fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(directory.path().join("assets").join("nested")).unwrap();
        std::fs::write(directory.path().join("assets").join("app.css"), b"APP").unwrap();
        std::fs::write(directory.path().join("assets").join("z.css"), b"Z").unwrap();
        std::fs::write(directory.path().join("assets").join("b.js"), b"B").unwrap();
        std::fs::write(
            directory
                .path()
                .join("assets")
                .join("nested")
                .join("deep.css"),
            b"DEEP",
        )
        .unwrap();
        std::fs::write(directory.path().join("index.html"), b"INDEX").unwrap();
        directory
    }

    #[test]
    fn file_matcher_glob_expands_existing_files_in_sorted_order() {
        let directory = glob_fixture();
        let root = directory.path().to_string_lossy().to_string();
        let mut request = file_request("/anything", directory.path());
        let matcher = file_matcher(serde_json::json!({
            "root": root,
            "try_files": ["/assets/*.css"]
        }));
        assert!(matcher.matches_mut(&mut request));
        // Go's Glob sorts matches: app.css before z.css.
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/assets/app.css")
        );
        assert_eq!(
            request
                .vars
                .get("matchers.file.absolute")
                .map(String::as_str),
            Some(
                directory
                    .path()
                    .join("assets")
                    .join("app.css")
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert_eq!(
            request.vars.get("matchers.file.type").map(String::as_str),
            Some("file")
        );
    }

    #[test]
    fn file_matcher_glob_classes_and_fallback() {
        let directory = glob_fixture();
        let root = directory.path().to_string_lossy().to_string();
        let class_matcher = file_matcher(serde_json::json!({
            "root": root,
            "try_files": ["/assets/[az]*.css"]
        }));
        let mut request = file_request("/anything", directory.path());
        assert!(class_matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/assets/app.css")
        );

        // A glob with no matches falls through to the next candidate.
        let fallback = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["/nope/*.css", "/index.html"]
        }));
        let mut request = file_request("/anything", directory.path());
        assert!(fallback.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/index.html")
        );
    }

    #[test]
    fn file_matcher_escapes_glob_metacharacters_from_placeholders() {
        let directory = glob_fixture();
        let matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["{http.vars.attempt}"]
        }));
        // A placeholder value containing `*` must be treated literally, not as a glob (Caddy's
        // globSafeRepl). `/assets/*` does not exist even though `/assets/app.css` matches `*`.
        let mut request = file_request("/anything", directory.path());
        request
            .vars
            .insert("attempt".to_string(), "/assets/*".to_string());
        assert!(!matcher.matches(&request));
        // A placeholder value pointing at an existing file still matches.
        let mut request = file_request("/anything", directory.path());
        request
            .vars
            .insert("attempt".to_string(), "/assets/app.css".to_string());
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request
                .vars
                .get("matchers.file.relative")
                .map(String::as_str),
            Some("/assets/app.css")
        );
    }

    #[test]
    fn file_matcher_globs_cannot_escape_the_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::write(root.join("assets").join("ok.css"), b"OK").unwrap();
        std::fs::write(parent.path().join("secret.css"), b"SECRET").unwrap();
        let matcher = file_matcher(serde_json::json!({
            "root": root.to_string_lossy(),
            "try_files": ["{http.vars.attempt}"]
        }));
        let mut request = file_request("/anything", &root);
        request
            .vars
            .insert("attempt".to_string(), "/../*.css".to_string());
        assert!(!matcher.matches(&request));
        // The escaped glob stays inside the root: a pattern matching only inside root works.
        let mut request = file_request("/anything", &root);
        request
            .vars
            .insert("attempt".to_string(), "/assets/*.css".to_string());
        let mut request_for_match = file_request("/anything", &root);
        assert!(!matcher.matches_mut(&mut request));
        // Also verify a literal containment case even when the placeholder contains no globs.
        request_for_match
            .vars
            .insert("attempt".to_string(), "/../secret.css".to_string());
        assert!(!matcher.matches(&request_for_match));
    }

    #[test]
    fn file_matcher_trailing_slash_glob_matches_nothing() {
        let directory = glob_fixture();
        let matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["/assets/*/"]
        }));
        // Go's filepath.Glob treats the trailing separator as an empty last component, so a glob
        // pattern ending in `/` matches nothing (Caddy oracle v2.11.7).
        assert!(!matcher.matches(&file_request("/anything", directory.path())));
    }

    #[test]
    fn file_matcher_error_code_sets_matcher_error() {
        let directory = glob_fixture();
        let matcher = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["=404"]
        }));
        let mut request = file_request("/anything", directory.path());
        assert!(!matcher.matches_mut(&mut request));
        let error = request
            .take_matcher_error()
            .expect("=404 records a matcher error");
        assert_eq!(error.status, http::StatusCode::NOT_FOUND);
        assert_eq!(
            error.message, "404",
            "Caddy's matcher error message is the status digits (fmt.Errorf(\"%s\", input[1:]))"
        );

        // `=1000` is not a valid status-code fallback; it is an ordinary literal candidate.
        let literal = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["=1000"]
        }));
        let mut request = file_request("/anything", directory.path());
        assert!(!literal.matches_mut(&mut request));
        assert!(request.take_matcher_error().is_none());

        // Only `first_exist`/`first_exist_fallback` treat `=NNN` specially; other policies try it
        // as a literal candidate.
        let policy = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["=404"],
            "try_policy": "largest_size"
        }));
        let mut request = file_request("/anything", directory.path());
        assert!(!policy.matches_mut(&mut request));
        assert!(request.take_matcher_error().is_none());
    }

    #[tokio::test]
    async fn file_matcher_error_code_short_circuits_route_evaluation() {
        use crate::router::RouterBuilder;
        use http::Method;

        let directory = glob_fixture();
        let root = directory.path().to_string_lossy().to_string();
        let routes = vec![
            serde_json::json!({
                "match": [{"file": {"root": root, "try_files": ["=418"]}}],
                "handle": [{"handler": "static_response", "body": "should not run"}]
            }),
            serde_json::json!({
                "handle": [{"handler": "static_response", "body": "default route"}]
            }),
        ];
        let router = RouterBuilder::new().build(&routes).expect("router builds");
        let mut request = Request::new(Method::GET, "/anything".parse().unwrap());
        request
            .headers
            .insert(http::header::HOST, "example.com".parse().unwrap());
        let response = router.handle(request).await.expect("handled");
        assert_eq!(response.status, http::StatusCode::IM_A_TEAPOT);
        assert!(response.body.is_empty());
        assert!(response.headers.is_empty());
    }
}

#[cfg(test)]
mod matcher_network_tls_tests {
    use super::*;
    use http::{Method, Uri};

    fn make_request(uri: &str) -> Request {
        Request::new(Method::GET, uri.parse::<Uri>().unwrap())
    }

    /// Test wrapper giving `Result<..>` a `Debug` bound for `expect`/`expect_err`.
    struct TestMatcher(SharedMatcher);

    impl std::fmt::Debug for TestMatcher {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("TestMatcher")
        }
    }

    impl std::ops::Deref for TestMatcher {
        type Target = dyn Matcher;

        fn deref(&self) -> &Self::Target {
            &*self.0
        }
    }

    fn build(name: &str, value: serde_json::Value) -> Result<TestMatcher> {
        build_single_matcher(name, &value).map(TestMatcher)
    }

    #[test]
    fn path_regexp_records_captures_and_placeholders() {
        let matcher = build(
            "path_regexp",
            serde_json::json!({"name": "match", "pattern": "^/foo(.*)$"}),
        )
        .expect("compiles");
        let mut request = make_request("/foo/bar/baz");
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request.vars.get("http.regexp.match.1").map(String::as_str),
            Some("/bar/baz")
        );
        assert_eq!(
            request.vars.get("http.regexp.1").map(String::as_str),
            Some("/bar/baz")
        );
        assert_eq!(
            request.vars.get("http.regexp.match.0").map(String::as_str),
            Some("/foo/bar/baz")
        );
        assert_eq!(
            request.replace_all("{http.regexp.match.1}"),
            "/bar/baz",
            "captured placeholder resolves through the request replacer"
        );
        assert_eq!(request.replace_all("{http.regexp.1}"), "/bar/baz");

        // Unnamed path_regexp matchers only publish numeric placeholders.
        let matcher =
            build("path_regexp", serde_json::json!({"pattern": "^/(a)(b)$"})).expect("compiles");
        let mut request = make_request("/ab");
        assert!(matcher.matches_mut(&mut request));
        assert_eq!(
            request.vars.get("http.regexp.1").map(String::as_str),
            Some("a")
        );
        assert_eq!(
            request.vars.get("http.regexp.2").map(String::as_str),
            Some("b")
        );
        assert!(!request.vars.contains_key("http.regexp.match.1"));
    }

    #[test]
    fn path_regexp_matches_cleaned_and_decoded_paths() {
        let matcher =
            build("path_regexp", serde_json::json!({"pattern": "^/foo/bar$"})).expect("compiles");
        assert!(matcher.matches(&make_request("/foo//bar")));
        assert!(matcher.matches(&make_request("/foo/./bar")));
        assert!(matcher.matches(&make_request("/foo/../foo/bar")));
        // The trailing slash is preserved by Caddy's cleanPath.
        let slash =
            build("path_regexp", serde_json::json!({"pattern": "^/foo/$"})).expect("compiles");
        assert!(slash.matches(&make_request("/foo/")));
        // Percent-encoded request paths are decoded before matching, like Go's URL.Path.
        let encoded =
            build("path_regexp", serde_json::json!({"pattern": "^/a b$"})).expect("compiles");
        assert!(encoded.matches(&make_request("/a%20b")));
    }

    #[test]
    fn path_regexp_publishes_named_captures() {
        let matcher = build(
            "path_regexp",
            serde_json::json!({"name": "re", "pattern": "^/users/(?P<id>[0-9]+)/(?<rest>.*)$"}),
        )
        .expect("named captures compile");
        let mut request = make_request("/users/42/profile");
        assert!(matcher.matches_mut(&mut request));

        for key in [
            "http.regexp.re.id",
            "http.regexp.re.1",
            "http.regexp.id",
            "http.regexp.1",
        ] {
            assert_eq!(
                request.vars.get(key).map(String::as_str),
                Some("42"),
                "{key}"
            );
        }
        for key in [
            "http.regexp.re.rest",
            "http.regexp.re.2",
            "http.regexp.rest",
            "http.regexp.2",
        ] {
            assert_eq!(
                request.vars.get(key).map(String::as_str),
                Some("profile"),
                "{key}"
            );
        }
        assert_eq!(request.replace_all("{http.regexp.re.id}"), "42");
        assert_eq!(request.replace_all("{http.regexp.id}"), "42");
    }

    #[test]
    fn path_regexp_supports_re2_constructs() {
        // Word boundaries (now supported by the crate engine).
        let boundary =
            build("path_regexp", serde_json::json!({"pattern": "^/foo\\b"})).expect("compiles");
        assert!(boundary.matches(&make_request("/foo")));
        assert!(!boundary.matches(&make_request("/foobar")));

        // Lazy quantifiers.
        let lazy =
            build("path_regexp", serde_json::json!({"pattern": "^/a+?b"})).expect("compiles");
        assert!(lazy.matches(&make_request("/aaab")));

        // Mid-pattern inline flags.
        let flag = build(
            "path_regexp",
            serde_json::json!({"pattern": "^/foo(?i)/bar$"}),
        )
        .expect("compiles");
        assert!(flag.matches(&make_request("/foo/BAR")));

        // ASCII names still match; the crate's `\w` is Unicode-aware (DIV-0015 residual).
        let word =
            build("path_regexp", serde_json::json!({"pattern": "^/\\w+$"})).expect("compiles");
        assert!(word.matches(&make_request("/cafe")));
    }

    #[test]
    fn path_regexp_rejects_non_re2_constructs_loudly() {
        // Go's RE2 (and therefore Caddy) does not support look-around or backreferences.
        for pattern in ["(?=a)", "(?!a)", "(?<=a)", "(a)\\1"] {
            let error = build("path_regexp", serde_json::json!({"pattern": pattern}))
                .expect_err("non-RE2 construct must be loud");
            let message = error.to_string();
            assert!(message.contains("path_regexp"), "{pattern}: {message}");
            assert!(message.contains(".pattern"), "{pattern}: {message}");
        }

        // Constructs RE2 does support now compile.
        for pattern in [
            "(?P<name>a)",
            "(?<name>a)",
            "\\bword\\b",
            "a+?",
            "(?i)^/foo",
            "a(?:b)?",
        ] {
            build("path_regexp", serde_json::json!({"pattern": pattern}))
                .unwrap_or_else(|error| panic!("{pattern} should compile: {error}"));
        }

        let error = build(
            "path_regexp",
            serde_json::json!({"name": "bad-name", "pattern": "a"}),
        )
        .expect_err("invalid regexp name");
        assert!(error.to_string().contains("word characters"), "{error}");

        let error =
            build("path_regexp", serde_json::json!({"pattern": "("})).expect_err("invalid pattern");
        assert!(error.to_string().contains(".pattern"), "{error}");
    }

    #[test]
    fn remote_ip_matches_ip_and_cidr_ranges() {
        let matcher = build(
            "remote_ip",
            serde_json::json!({"ranges": ["10.0.0.0/8", "203.0.113.7", "2001:db8::/32"]}),
        )
        .expect("valid ranges");
        let mut inside = make_request("/");
        inside.remote_addr = Some("10.1.2.3:5000".parse().unwrap());
        assert!(matcher.matches(&inside));
        let mut exact = make_request("/");
        exact.remote_addr = Some("203.0.113.7:1234".parse().unwrap());
        assert!(matcher.matches(&exact));
        let mut outside = make_request("/");
        outside.remote_addr = Some("198.51.100.1:1234".parse().unwrap());
        assert!(!matcher.matches(&outside));
        let mut v6 = make_request("/");
        v6.remote_addr = Some("[2001:db8::1]:443".parse().unwrap());
        assert!(matcher.matches(&v6));
        assert!(
            !matcher.matches(&make_request("/")),
            "no peer address never matches"
        );

        // The Caddyfile `private_ranges` expansion as accepted in JSON.
        let matcher = build(
            "remote_ip",
            serde_json::json!({"ranges": ["private_ranges"]}),
        )
        .expect("private ranges");
        let mut private = make_request("/");
        private.remote_addr = Some("192.168.1.10:80".parse().unwrap());
        assert!(matcher.matches(&private));
    }

    #[test]
    fn remote_ip_rejects_invalid_ranges_loudly() {
        for ranges in [
            serde_json::json!(["not-an-ip"]),
            serde_json::json!(["10.0.0.0/33"]),
            serde_json::json!("10.0.0.0/8"),
            serde_json::json!([42]),
        ] {
            let value = serde_json::json!({"ranges": ranges});
            let error = build("remote_ip", value).expect_err("invalid ranges");
            assert!(error.to_string().contains("match.remote_ip"), "{error}");
        }
    }

    #[test]
    fn client_ip_uses_the_resolved_client_address() {
        let matcher = build("client_ip", serde_json::json!({"ranges": ["10.0.0.0/8"]}))
            .expect("valid ranges");
        let mut request = make_request("/");
        request.remote_addr = Some("198.51.100.1:443".parse().unwrap());
        assert!(!matcher.matches(&request));
        request
            .vars
            .insert("client_ip".to_string(), "10.9.8.7".to_string());
        assert!(matcher.matches(&request));
        // Falls back to the peer address when no trusted-proxy resolution happened.
        let mut fallback = make_request("/");
        fallback.remote_addr = Some("10.1.1.1:443".parse().unwrap());
        assert!(matcher.matches(&fallback));
    }

    #[test]
    fn local_ip_matches_the_listener_address_variable() {
        let matcher = build(
            "local_ip",
            serde_json::json!({"ranges": ["198.51.100.0/24"]}),
        )
        .expect("valid ranges");
        let mut request = make_request("/");
        assert!(!matcher.matches(&request), "no local address available");
        request.vars.insert(
            "http.request.local.host".to_string(),
            "198.51.100.10".to_string(),
        );
        assert!(matcher.matches(&request));
        let mut outside = make_request("/");
        outside.vars.insert(
            "http.request.local.host".to_string(),
            "203.0.113.1".to_string(),
        );
        assert!(!matcher.matches(&outside));
    }

    #[test]
    fn protocol_matches_scheme_versions_and_grpc() {
        let plain = build("protocol", serde_json::json!("http")).expect("protocol");
        assert!(plain.matches(&make_request("/")));
        let mut tls = make_request("/");
        tls.tls = true;
        assert!(!plain.matches(&tls));

        let https = build("protocol", serde_json::json!("https")).expect("protocol");
        assert!(https.matches(&tls));
        assert!(!https.matches(&make_request("/")));

        // HTTP/1.1 is the assumed cleartext version (h2c is indistinguishable).
        let http11 = build("protocol", serde_json::json!("http/1.1")).expect("protocol");
        assert!(http11.matches(&make_request("/")));
        let http2 = build("protocol", serde_json::json!("http/2")).expect("protocol");
        let mut h2 = make_request("/");
        h2.tls = true;
        h2.vars.insert("tls.alpn".to_string(), "h2".to_string());
        assert!(http2.matches(&h2));
        let http2_plus = build("protocol", serde_json::json!("http/2+")).expect("protocol");
        assert!(http2_plus.matches(&h2));

        let grpc = build("protocol", serde_json::json!("grpc")).expect("protocol");
        let mut grpc_request = make_request("/");
        grpc_request.headers.insert(
            http::header::CONTENT_TYPE,
            "application/grpc+proto".parse().unwrap(),
        );
        assert!(grpc.matches(&grpc_request));
        assert!(!grpc.matches(&make_request("/")));

        // Unknown protocol strings never match (Caddy behaviour) and are accepted.
        let unknown = build("protocol", serde_json::json!("http/9")).expect("protocol accepted");
        assert!(!unknown.matches(&make_request("/")));
    }

    #[test]
    fn tls_matcher_checks_tls_and_handshake_completeness() {
        let matcher = build("tls", serde_json::json!({})).expect("tls");
        assert!(!matcher.matches(&make_request("/")));
        let mut tls = make_request("/");
        tls.tls = true;
        assert!(matcher.matches(&tls));

        // Caddy's Caddyfile `tls early_data` emits handshake_complete=false, which only matches a
        // 0-RTT (incomplete) handshake; caddy-rs has no early data, so it never matches.
        let early = build("tls", serde_json::json!({"handshake_complete": false})).expect("tls");
        assert!(!early.matches(&tls));
        let complete = build("tls", serde_json::json!({"handshake_complete": true})).expect("tls");
        assert!(complete.matches(&tls));

        // TLS metadata fields are not part of Caddy's matcher; they fail loudly instead of being
        // silently ignored.
        let error = build("tls", serde_json::json!({"version_min": "tls1.3"}))
            .expect_err("unsupported tls field");
        assert!(matches!(error, Error::NotImplemented { .. }), "{error}");
    }

    #[test]
    fn not_matcher_negates_network_matchers() {
        let inner =
            build("remote_ip", serde_json::json!({"ranges": ["10.0.0.0/8"]})).expect("valid");
        let not = NotMatcher {
            inner: vec![inner.0],
        };
        let mut inside = make_request("/");
        inside.remote_addr = Some("10.1.1.1:1".parse().unwrap());
        assert!(!not.matches(&inside));
        let mut outside = make_request("/");
        outside.remote_addr = Some("203.0.113.1:1".parse().unwrap());
        assert!(not.matches(&outside));
    }
}
