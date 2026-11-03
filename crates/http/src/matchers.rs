//! Caddy-compatible request matchers.
//!
//! A *matcher set* is a JSON object in which every key is a matcher module; the request matches
//! the set when every matcher matches. A route's `match` array is a list of matcher sets combined
//! with OR (the route matches when any set matches), mirroring Caddy.

use std::sync::Arc;

use serde_json::Value;

use crate::types::{Error, Matcher, Request, Result, SharedMatcher};

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
        "path_regexp" => Err(Error::NotImplemented {
            feature: "path_regexp matcher (no regex dependency in the offline build)",
            tracking_id: "CORE-MATCH-REGEXP",
        }),
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
        self.patterns
            .iter()
            .any(|pattern| glob_match(&pattern.to_ascii_lowercase(), &host, true))
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
        self.patterns
            .iter()
            .any(|pattern| glob_match(pattern, &escaped, false) || glob_match(pattern, path, false))
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
                if let Some(negated) = pattern.strip_prefix('!') {
                    !values.iter().any(|value| glob_match(negated, value, false))
                } else if pattern == "*" {
                    !values.is_empty()
                } else {
                    values.iter().any(|value| glob_match(pattern, value, false))
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
            pairs.iter().any(|(actual_key, actual_value)| {
                glob_match(key, actual_key, false) && glob_match(value, actual_value, false)
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
/// Not supported (reported in the task divergences): custom filesystem modules (`fs`), glob
/// expansion in `try_files`, and the `=NNN` error fallback of `first_exist` (both are loud/absent
/// rather than approximated).
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
        // Caddy: filepath.Clean(repl.ReplaceAll(root, ".")) — an empty placeholder value becomes
        // ".", and the result is lexically cleaned.
        let expanded = request.replace_all(&self.root);
        let expanded = if expanded.is_empty() { "." } else { &expanded };
        path_clean(expanded)
    }

    /// Expand and clean one `try_files` pattern into candidate file paths.
    fn candidates(&self, root: &str, request: &Request, pattern: &str) -> Vec<FileCandidate> {
        let expanded = request.replace_all(pattern);
        let cleaned = path_clean(&expanded);
        let (mut before_split, remainder) = first_split(&cleaned, &self.split_path);
        // Caddy restores the trailing slash from the *original* pattern after cleaning/splitting so
        // directories can be matched by convention.
        if pattern.ends_with('/') {
            before_split.push('/');
        }
        let fullpath = sanitized_join(root, &before_split);
        let relative = fullpath
            .strip_prefix(root)
            .map(str::to_string)
            .unwrap_or_else(|| fullpath.clone());
        vec![FileCandidate {
            fullpath,
            relative,
            remainder,
        }]
    }

    fn select(&self, request: &Request) -> Option<SelectedFile> {
        let root = self.expanded_root(request);
        match self.try_policy {
            FileTryPolicy::FirstExist | FileTryPolicy::FirstExistFallback => {
                let fallback_index = if self.try_policy == FileTryPolicy::FirstExistFallback {
                    self.try_files.len().checked_sub(1)
                } else {
                    None
                };
                for (index, pattern) in self.try_files.iter().enumerate() {
                    for candidate in self.candidates(&root, request, pattern) {
                        if Some(index) == fallback_index {
                            // The last candidate always matches under `first_exist_fallback`.
                            return Some(SelectedFile {
                                candidate,
                                is_dir: false,
                            });
                        }
                        if let Some(is_dir) = strict_file_exists(&candidate.fullpath) {
                            return Some(SelectedFile { candidate, is_dir });
                        }
                    }
                }
                None
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
                best.map(|(selected, _)| selected)
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
                best.map(|(selected, _)| selected)
            }
        }
    }
}

impl Matcher for FileMatcher {
    fn matches(&self, request: &Request) -> bool {
        self.select(request).is_some()
    }

    fn matches_mut(&self, request: &mut Request) -> bool {
        let Some(selected) = self.select(request) else {
            return false;
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
                parts.pop();
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

        // Fallback also matches when *no* candidate exists, unlike first_exist.
        let fallback = file_matcher(serde_json::json!({
            "root": directory.path().to_string_lossy(),
            "try_files": ["/missing.txt", "/also-missing.html"],
            "try_policy": "first_exist_fallback"
        }));
        assert!(fallback.matches(&file_request("/anything", directory.path())));
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
        // Caddy splits `path.Clean("/remote.php/dav/")`, which drops the trailing slash.
        assert_eq!(
            request
                .vars
                .get("matchers.file.remainder")
                .map(String::as_str),
            Some("/dav")
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
}
