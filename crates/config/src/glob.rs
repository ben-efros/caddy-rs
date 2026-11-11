//! Shared iterative glob matching for Caddyfile `import` patterns and TLS automation-policy
//! subject patterns.
//!
//! Both patterns come straight from the configuration file, so an attacker-controlled pattern is
//! possible. A naive recursive matcher is a denial of service in two ways: it uses one stack frame
//! per pattern/name byte (a long pattern aborts the process with a stack overflow), and it
//! backtracks into both branches at every `*`, which is exponential for patterns with several
//! wildcards.
//!
//! The matcher here is the classic iterative algorithm with a single backtrack point (the last `*`
//! seen): no recursion, O(name len * pattern len) time in the worst case, O(1) extra space. A
//! single backtrack point is sufficient because a `*` may only ever need to absorb more of the
//! name; retrying an earlier `*` after extending a later one cannot succeed where the later one
//! fails, so the greedy "extend the most recent `*`" strategy is complete.

/// Anchored glob match used for `import` file globs: `*` matches any run of bytes (including none)
/// and `?` matches exactly one byte. Every other byte matches itself, case sensitively.
pub(crate) fn match_import_glob(name: &str, pattern: &str) -> bool {
    matches(name, pattern, true)
}

/// Anchored glob match used for automation-policy subject patterns, as `certmagic.MatchWildcard`:
/// only `*` is special (`?` is a literal byte) and a `*` may cover any number of labels.
pub(crate) fn match_subject_wildcard(name: &str, pattern: &str) -> bool {
    matches(name, pattern, false)
}

fn matches(name: &str, pattern: &str, question_mark_is_wildcard: bool) -> bool {
    let name = name.as_bytes();
    let pattern = pattern.as_bytes();
    let mut n = 0usize;
    let mut p = 0usize;
    // The last `*` consumed and the name offset it was first tried at: the only backtrack point.
    let mut star_pattern = None;
    let mut star_name = 0usize;
    while n < name.len() {
        if p < pattern.len()
            && (pattern[p] == name[n] || (question_mark_is_wildcard && pattern[p] == b'?'))
        {
            n += 1;
            p += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_pattern = Some(p);
            star_name = n;
            p += 1;
        } else if let Some(star) = star_pattern {
            // Mismatch after a `*`: let that `*` absorb one more byte and resume right after it.
            star_name += 1;
            n = star_name;
            p = star + 1;
        } else {
            return false;
        }
    }
    // Trailing `*`s may absorb the (now empty) remainder of the name.
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::{match_import_glob, match_subject_wildcard};
    use std::time::{Duration, Instant};

    /// Pre-fix recursive matcher, kept as the reference for equivalence. Only ever called with the
    /// tiny inputs below, so its recursion depth stays bounded.
    fn reference(name: &str, pattern: &str, question_mark_is_wildcard: bool) -> bool {
        fn go(name: &[u8], pattern: &[u8], qmark: bool) -> bool {
            match pattern.first() {
                None => name.is_empty(),
                Some(b'*') => {
                    go(name, &pattern[1..], qmark)
                        || (!name.is_empty() && go(&name[1..], pattern, qmark))
                }
                Some(b'?') if qmark => !name.is_empty() && go(&name[1..], &pattern[1..], qmark),
                Some(expected) => {
                    name.first() == Some(expected) && go(&name[1..], &pattern[1..], qmark)
                }
            }
        }
        go(
            name.as_bytes(),
            pattern.as_bytes(),
            question_mark_is_wildcard,
        )
    }

    fn candidates(alphabet: &[char], max_len: usize) -> Vec<String> {
        let mut out = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for ch in alphabet {
                    let mut s = prefix.clone();
                    s.push(*ch);
                    next.push(s);
                }
            }
            out.extend(next.iter().cloned());
            frontier = next;
        }
        out
    }

    #[test]
    fn agrees_with_reference_on_all_tiny_inputs() {
        let names = candidates(&['a', 'b'], 4);
        for (qmark, matcher) in [
            (true, match_import_glob as fn(&str, &str) -> bool),
            (false, match_subject_wildcard as fn(&str, &str) -> bool),
        ] {
            for pattern in candidates(&['a', 'b', '*', '?'], 4) {
                for name in &names {
                    assert_eq!(
                        matcher(name, &pattern),
                        reference(name, &pattern, qmark),
                        "name={name:?} pattern={pattern:?} qmark_wildcard={qmark}"
                    );
                }
            }
        }
    }

    #[test]
    fn agrees_with_reference_on_ordinary_patterns() {
        let cases = [
            ("file.caddyfile", "*.caddyfile"),
            ("file.conf", "*.caddyfile"),
            ("a.b.caddyfile", "*.caddyfile"),
            ("caddyfile", "caddyfile"),
            ("caddyfile", "Caddyfile"),
            ("abc", "a?c"),
            ("ac", "a?c"),
            ("example.com", "*.example.com"),
            ("a.example.com", "*.example.com"),
            ("a.b.example.com", "*.example.com"),
            ("*.example.com", "*.example.com"),
            ("axbyc", "*a*b*c"),
            ("cba", "*a*b*c"),
            ("", "*"),
            ("", ""),
            ("x", ""),
            ("anything", "*"),
            ("a/b/c.conf", "*/c.conf"),
            ("a/b/c.conf", "a/*/c.conf"),
            ("aaaa", "a*a*a*a"),
            ("aaaa", "a*a*a*ab"),
        ];
        for (name, pattern) in cases {
            for (qmark, matcher) in [
                (true, match_import_glob as fn(&str, &str) -> bool),
                (false, match_subject_wildcard as fn(&str, &str) -> bool),
            ] {
                assert_eq!(
                    matcher(name, pattern),
                    reference(name, pattern, qmark),
                    "name={name:?} pattern={pattern:?} qmark_wildcard={qmark}"
                );
            }
        }
    }

    #[test]
    fn long_pattern_does_not_overflow_the_stack() {
        // 100k pattern bytes: the pre-fix recursive matcher aborted here with a stack overflow.
        let long_literal = "a".repeat(100_000);
        assert!(match_import_glob(&"a".repeat(100_000), &long_literal));
        assert!(!match_import_glob("a", &long_literal));
        let long_wildcards = "*".repeat(100_000);
        assert!(match_import_glob("name", &long_wildcards));
        assert!(!match_import_glob("name", &format!("{long_wildcards}b")));
        assert!(match_subject_wildcard("example.com", &long_wildcards));
        // Long name, short pattern: the pre-fix matcher recursed once per name byte here.
        assert!(match_subject_wildcard(&"a".repeat(100_000), "*"));
    }

    #[test]
    fn many_wildcards_are_bounded() {
        // `("*a" * 16) + "b"` against 28 `a`s: 1.7 s with the pre-fix exponential matcher, no match.
        let pattern = "*a".repeat(16) + "b";
        let name = "a".repeat(28);
        let start = Instant::now();
        let result = match_import_glob(&name, &pattern);
        let elapsed = start.elapsed();
        assert!(!result);
        // The iterative matcher needs microseconds; the recursive one needed seconds and doubled
        // with every extra `*a` pair.
        assert!(
            elapsed < Duration::from_millis(500),
            "adversarial glob took {elapsed:?}"
        );

        // Twenty-four pairs and 40 `a`s: the recursive matcher is effectively unbounded here
        // (2^24 backtracks); the iterative one still finishes immediately.
        let pattern = "*a".repeat(24) + "b";
        let name = "a".repeat(40);
        let start = Instant::now();
        assert!(!match_import_glob(&name, &pattern));
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "adversarial glob took {elapsed:?}"
        );
    }
}
