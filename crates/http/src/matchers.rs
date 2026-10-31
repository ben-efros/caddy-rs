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
}
