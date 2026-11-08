//! RE2-compatible regular expressions backed by the linear-time `regex` crate.
//!
//! This module used to contain a hand-written backtracking VM. It is now a thin compatibility
//! wrapper around [`regex`] so every existing caller (path_regexp, map, query.replace and the
//! proxy health check) uses the same secure engine:
//!
//! * linear-time matching — no catastrophic backtracking / ReDoS;
//! * RE2 syntax — look-around and backreferences are rejected, matching Go's `regexp`;
//! * named capture groups, word boundaries, lazy quantifiers and inline flags are supported;
//! * `$N`/`${N}`/`$name` replacement expansion follows Go's `Regexp.ReplaceAllString` closely.
//!
//! The wrapper exists only to keep the `Regex`/`Captures` API and the located configuration error
//! type used by this crate; it is not a regex implementation.

use crate::types::Error;

/// A compiled RE2-compatible regular expression.
#[derive(Debug, Clone)]
pub struct Regex {
    inner: regex::Regex,
}

/// Captures from one successful match. Byte offsets index the input passed to [`Regex::captures`].
#[derive(Debug)]
pub struct Captures<'r> {
    inner: regex::Captures<'r>,
}

impl Regex {
    /// Compile `pattern`, returning a located configuration error when it is not RE2-compatible.
    pub fn new(pattern: &str) -> Result<Self, Error> {
        // `regex` defaults to Unicode scalar semantics for `.`, like Go's regexp. Its `\w`,
        // `\d`, `\s` and `\b` are Unicode-aware while Go's are ASCII; that known difference is
        // documented in DIV-0015. Disabling Unicode makes `.` byte-oriented and rejects common
        // `.*` patterns on `&str`, so the Unicode default is the compatible choice here.
        regex::Regex::new(pattern)
            .map(|inner| Self { inner })
            .map_err(|error| Error::InvalidConfig {
                path: "regex".to_string(),
                message: format!("unsupported regular expression `{pattern}`: {error}"),
            })
    }

    /// Find the leftmost-first match anywhere in `input`.
    pub fn captures<'r>(&self, input: &'r str) -> Option<Captures<'r>> {
        self.inner.captures(input).map(|inner| Captures { inner })
    }

    /// Whether `input` contains a match.
    pub fn is_match(&self, input: &str) -> bool {
        self.inner.is_match(input)
    }

    /// Number of capture groups, not counting the whole-match group 0.
    pub fn group_count(&self) -> usize {
        self.inner.captures_len().saturating_sub(1)
    }

    /// Names of the capture groups, aligned with group index (index 0 is always `None`).
    pub fn capture_names(&self) -> impl Iterator<Item = Option<&str>> {
        self.inner.capture_names()
    }

    /// Expand Go-style `$N`/`${N}`/`$name` capture references in `template`.
    pub fn expand(&self, template: &str, _input: &str, captures: &Captures<'_>) -> String {
        let mut output = String::new();
        captures.inner.expand(template, &mut output);
        output
    }

    /// Replace every non-overlapping match with `template` (Go `Regexp.ReplaceAllString`).
    pub fn replace_all(&self, input: &str, template: &str) -> String {
        self.inner.replace_all(input, template).into_owned()
    }
}

impl Captures<'_> {
    /// Number of capture groups, not counting the whole-match group 0.
    pub fn group_count(&self) -> usize {
        self.inner.len().saturating_sub(1)
    }

    /// Byte range for capture group `index` (0 = whole match).
    pub fn group(&self, index: usize) -> Option<(usize, usize)> {
        self.inner
            .get(index)
            .map(|capture| (capture.start(), capture.end()))
    }

    /// Byte range for a named capture group.
    pub fn name(&self, name: &str) -> Option<(usize, usize)> {
        self.inner
            .name(name)
            .map(|capture| (capture.start(), capture.end()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captures<'r>(pattern: &str, input: &'r str) -> Option<Captures<'r>> {
        Regex::new(pattern)
            .expect("pattern compiles")
            .captures(input)
    }

    #[test]
    fn matches_literals_anchors_and_search() {
        assert!(captures("abc", "xxabcxx").is_some());
        assert!(captures("^abc$", "abc").is_some());
        assert!(captures("^abc$", "xabc").is_none());
        assert!(captures("a.c", "abc").is_some());
        assert!(captures("a.*c", "a123c").is_some());
    }

    #[test]
    fn captures_and_expands_go_style_references() {
        let regex = Regex::new("(xyz)").unwrap();
        let caps = regex.captures("/ABCxyzDEF").expect("match");
        assert_eq!(regex.expand("...${1}...", "/ABCxyzDEF", &caps), "...xyz...");
        let regex = Regex::new("(/abc)").unwrap();
        let caps = regex.captures("/abcdef").expect("match");
        assert_eq!(regex.expand("${1}", "/abcdef", &caps), "/abc");
        let regex = Regex::new("(?P<word>[a-z]+)").unwrap();
        let caps = regex.captures("/abc").expect("match");
        assert_eq!(regex.expand("$word", "/abc", &caps), "abc");
        assert_eq!(caps.name("word"), Some((1, 4)));
    }

    #[test]
    fn supports_classes_alternation_and_case_insensitive_flag() {
        assert!(captures("[a-z]+", "123abc").is_some());
        assert!(captures("[^0-9]+", "abc").is_some());
        assert!(captures("a|bc", "bc").is_some());
        assert!(captures("(?i)abc", "xxABC").is_some());
        assert!(captures(r"(\^|`|<|>|%|\\|\{|\}|\|)", "a|b").is_some());
        assert!(captures(r"\d+", "abc123").is_some());
        assert!(captures(r"\bword\b", "a word here").is_some());
        assert!(captures("a+?", "aaa").is_some());
    }

    #[test]
    fn replaces_all_matches_with_capture_expansion() {
        let regex = Regex::new("([a-z]+)").unwrap();
        assert_eq!(regex.replace_all("/foo/bar", "<${1}>"), "/<foo>/<bar>");
        let anchored = Regex::new("^/old/(.*)$").unwrap();
        assert_eq!(anchored.replace_all("/old/rest", "/new/${1}"), "/new/rest");
        let named = Regex::new("^/users/(?P<id>[0-9]+)$").unwrap();
        assert_eq!(
            named.replace_all("/users/42", "/accounts/$id"),
            "/accounts/42"
        );
    }

    #[test]
    fn rejects_non_re2_constructs() {
        for pattern in ["(?=a)", "(?!a)", "(?<=a)", "(a)\\1"] {
            let error = Regex::new(pattern).expect_err("non-RE2 construct must fail");
            assert!(
                error.to_string().contains("unsupported regular expression"),
                "{pattern}: {error}"
            );
        }
    }
}
