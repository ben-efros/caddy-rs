//! `caddy-rs fmt`: format a Caddyfile exactly like Caddy v2.11.9.
//!
//! The formatter is a faithful port of `caddyconfig/caddyfile/formatter.go` from the pinned
//! upstream source (`external/caddy`, v2.11.9). It is a rune-by-rune state machine: words,
//! comments, placeholders, quoted strings, backticked strings, escaped characters and heredocs are
//! preserved literally, while bracing, indentation and inter-token whitespace are rewritten.
//!
//! The command surface mirrors `cmd/commandfuncs.go::cmdFmt`: `--overwrite` rewrites the file and
//! exits 0 without a formatting check; `--diff` prints the difflib-style (non-patch) difference;
//! a path of `-` reads stdin and always prints to stdout. When the formatted output differs from
//! the input the command prints the result (or diff) first and then fails with Caddy's located
//! `file:line:` message and exit code 1.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use crate::environ::io_error_text;

/// Formats a Caddyfile.
pub(crate) fn run(
    config: Option<String>,
    overwrite: bool,
    diff: bool,
    paths: Vec<String>,
) -> anyhow::Result<()> {
    // cmdFmt resolves the file from raw argument strings: the first positional argument wins, and
    // an empty value means "not set" (Caddy's `fl.Arg(0)` returns "" for both a missing and an
    // explicitly empty argument), so `fmt ''` and `fmt -c ''` both format ./Caddyfile.
    let config_flag = config.unwrap_or_default();
    let config_file_arg = paths.first().cloned().unwrap_or_default();

    // cmdFmt rejects multiple inputs before it resolves the default path. The message is
    // Caddy's verbatim text, including the two spaces when `--config` is absent.
    if paths.len() > 1 || (!config_flag.is_empty() && !config_file_arg.is_empty()) {
        bail!(
            "fmt does not support multiple files {config_flag} {}",
            paths.join(" ")
        );
    }

    let config_file = if config_file_arg.is_empty() {
        if config_flag.is_empty() {
            PathBuf::from("Caddyfile")
        } else {
            PathBuf::from(config_flag)
        }
    } else {
        PathBuf::from(config_file_arg)
    };

    // `-` is Caddy's stdin special case. `--overwrite`/`--diff` are ignored: stdin is always
    // formatted to stdout, and the formatting-difference check is skipped.
    if config_file == Path::new("-") {
        let mut input = Vec::new();
        std::io::stdin()
            .read_to_end(&mut input)
            .context("reading stdin")?;
        std::io::stdout()
            .write_all(&format(&input))
            .context("writing stdout")?;
        return Ok(());
    }

    // Caddy reports the raw `os.ReadFile` error, which Go renders as `open <path>: <reason>`;
    // reuse environ's Go-style wording instead of Rust's `(os error N)` suffix.
    let input = std::fs::read(&config_file).map_err(|error| {
        anyhow::anyhow!(
            "reading input file: open {}: {}",
            config_file.display(),
            io_error_text(&error)
        )
    })?;
    let output = format(&input);

    if overwrite {
        std::fs::write(&config_file, &output)
            .with_context(|| format!("overwriting formatted file: {}", config_file.display()))?;
        return Ok(());
    }

    if diff {
        let mut rendered = Vec::new();
        let input_lines = split_lines(&input);
        let output_lines = split_lines(&output);
        for record in line_diff(&input_lines, &output_lines) {
            match record.delta {
                Delta::Common => rendered.extend_from_slice(b"  "),
                Delta::LeftOnly => rendered.extend_from_slice(b"- "),
                Delta::RightOnly => rendered.extend_from_slice(b"+ "),
            }
            rendered.extend_from_slice(&record.payload);
            rendered.push(b'\n');
        }
        std::io::stdout()
            .write_all(&rendered)
            .context("writing stdout")?;
    } else {
        std::io::stdout()
            .write_all(&output)
            .context("writing stdout")?;
    }

    // Caddy's lint: the output was already printed, but an unformatted input is still a failure.
    if let Some(warning) = formatting_difference(&config_file.to_string_lossy(), &input) {
        bail!(
            "{}:{}: Caddyfile input is not formatted; Tip: use '--overwrite' to update your Caddyfile in-place instead of previewing it. Consult '--help' for more options",
            warning.file,
            warning.line
        );
    }

    Ok(())
}

/// `caddyconfig/caddyfile.Format`: format `input` and always end with exactly one newline.
pub(crate) fn format(input: &[u8]) -> Vec<u8> {
    let trimmed_input = trim_space(input);
    let mut runes = Vec::with_capacity(trimmed_input.len());
    let mut offset = 0;
    while offset < trimmed_input.len() {
        let (ch, width) = decode_rune(&trimmed_input[offset..]);
        runes.push(ch);
        offset += width;
    }

    let mut formatter = Formatter::new();
    formatter.run(&runes);

    // The Caddyfile does not need leading or trailing spaces, but it must end with a newline
    // because newlines are significant to the syntax.
    let mut result = formatter.out.trim().as_bytes().to_vec();
    result.push(b'\n');
    result
}

#[derive(Default)]
struct Formatter {
    out: String,
    /// The last rune written to the result.
    last: char,
    /// Whether the current/previous character was whitespace (the beginning counts as space).
    space: bool,
    beginning_of_line: bool,
    /// Whether the current word/token is or started with an open curly brace.
    open_brace: bool,
    /// If `open_brace`, whether that brace was written yet.
    open_brace_written: bool,
    /// Whether there was a non-newline space before the open brace.
    open_brace_space: bool,
    new_lines: usize,
    comment: bool,
    /// Encountered quotes: `""`, `` ` ``, `"`, `"`` ``, `` `" ``.
    quotes: &'static str,
    escaped: bool,
    heredoc: HeredocState,
    heredoc_escaped: bool,
    heredoc_marker: Vec<char>,
    heredoc_closing_marker: Vec<char>,
    nesting: usize,
    current_token: String,
    current_line_first_token: String,
    previous_line_was_top_level_import: bool,
    open_brace_own_line: bool,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum HeredocState {
    #[default]
    Closed,
    Opening,
    Opened,
}

impl Formatter {
    fn new() -> Self {
        Self {
            // The beginning of the input counts as space.
            space: true,
            beginning_of_line: true,
            ..Self::default()
        }
    }

    fn run(&mut self, runes: &[char]) {
        for &ch in runes {
            // Detect whether we have the start of a heredoc.
            if self.quotes.is_empty()
                && self.heredoc == HeredocState::Closed
                && !self.heredoc_escaped
                && self.space
                && self.last == '<'
                && ch == '<'
            {
                self.write(ch);
                self.heredoc = HeredocState::Opening;
                self.space = false;
                continue;
            }

            if self.heredoc == HeredocState::Opening {
                if ch == '\n' {
                    if !self.heredoc_marker.is_empty() && is_heredoc_marker(&self.heredoc_marker) {
                        self.heredoc = HeredocState::Opened;
                    } else {
                        self.heredoc_marker.clear();
                        self.heredoc = HeredocState::Closed;
                        self.next_line();
                        continue;
                    }
                    self.write(ch);
                    continue;
                }
                if ch.is_whitespace() {
                    // A space means it's just a regular token and not a heredoc.
                    self.heredoc_marker.clear();
                    self.heredoc = HeredocState::Closed;
                } else {
                    self.heredoc_marker.push(ch);
                    self.write(ch);
                    continue;
                }
            }

            // If we're in a heredoc, all characters are read and written as-is.
            if self.heredoc == HeredocState::Opened {
                self.heredoc_closing_marker.push(ch);
                if self.heredoc_closing_marker.len() > self.heredoc_marker.len() + 1 {
                    // Assert that the closing marker is followed by whitespace.
                    self.heredoc_closing_marker.remove(0);
                }
                let closed = ch.is_whitespace()
                    && self.heredoc_closing_marker[..self.heredoc_closing_marker.len() - 1]
                        == self.heredoc_marker[..];
                if closed {
                    self.heredoc_marker.clear();
                    self.heredoc_closing_marker.clear();
                    self.heredoc = HeredocState::Closed;
                } else {
                    self.write(ch);
                    if ch == '\n' {
                        self.heredoc_closing_marker.clear();
                    }
                    continue;
                }
            }

            if self.last == '<' && self.space {
                self.space = false;
            }

            if self.comment {
                if ch == '\n' {
                    self.comment = false;
                    self.space = true;
                    self.next_line();
                    continue;
                }
                self.write(ch);
                continue;
            }

            if !self.escaped && ch == '\\' {
                if self.space {
                    self.write(' ');
                    self.space = false;
                }
                self.write(ch);
                self.escaped = true;
                continue;
            }

            if self.escaped {
                if ch == '<' {
                    self.heredoc_escaped = true;
                }
                self.write(ch);
                self.escaped = false;
                continue;
            }

            if ch == '`' {
                self.quotes = match self.quotes {
                    "\"`" => "\"",
                    "`" => "",
                    "\"" => "\"`",
                    _ => "`",
                };
            }

            if self.quotes == "\"" {
                if ch == '"' {
                    self.quotes = "";
                }
                self.write(ch);
                continue;
            }

            if ch == '"' {
                match self.quotes {
                    "" => {
                        if self.space {
                            self.quotes = "\"";
                        }
                    }
                    "`\"" => self.quotes = "`",
                    "\"`" => self.quotes = "",
                    _ => {}
                }
            }

            if self.quotes.contains('`') {
                if ch == '`' && self.space && !self.beginning_of_line {
                    self.write(' ');
                }
                self.write(ch);
                self.space = false;
                continue;
            }

            if ch.is_whitespace() {
                self.finish_token();
                self.space = true;
                self.heredoc_escaped = false;
                if ch == '\n' {
                    self.finish_line();
                    self.new_lines += 1;
                }
                continue;
            }
            let space_prior = self.space;
            self.space = false;

            // By this point the character is not whitespace, not in a literal segment (comment,
            // quoted string, heredoc) and not escaped.
            if ch == '#' {
                self.comment = true;
            }

            if self.open_brace && space_prior && !self.open_brace_written {
                self.flush_open_brace();
            }

            match ch {
                '{' => {
                    self.finish_token();
                    if self.open_brace && !self.open_brace_written {
                        self.flush_open_brace();
                    }
                    self.open_brace = true;
                    self.open_brace_space = space_prior && !self.beginning_of_line;
                    self.open_brace_own_line = self.new_lines > 0;
                    if self.open_brace_space && self.new_lines == 0 {
                        self.write(' ');
                    }
                    self.open_brace_written = false;
                    if self.quotes == "`" {
                        self.write('{');
                        self.open_brace_written = true;
                        self.open_brace_own_line = false;
                    }
                    continue;
                }
                '}' if space_prior || !self.open_brace => {
                    self.finish_token();
                    if self.quotes == "`" {
                        self.write('}');
                        continue;
                    }
                    if self.last != '\n' {
                        self.next_line();
                    }
                    if self.nesting > 0 {
                        self.nesting -= 1;
                    }
                    self.indent();
                    self.write('}');
                    self.new_lines = 0;
                    continue;
                }
                _ => {}
            }

            if self.new_lines > 2 {
                self.new_lines = 2;
            }
            for _ in 0..self.new_lines {
                self.next_line();
            }
            self.new_lines = 0;
            if self.beginning_of_line {
                self.indent();
            }
            if self.nesting == 0 && self.last == '}' && self.beginning_of_line {
                self.next_line();
                self.next_line();
            }

            if !self.beginning_of_line && space_prior {
                self.write(' ');
            }

            if self.open_brace && !self.open_brace_written {
                self.write('{');
                self.open_brace_written = true;
            }

            if space_prior && ch == '<' {
                self.space = true;
            }

            self.current_token.push(ch);
            self.write(ch);
            self.beginning_of_line = false;
        }

        if self.open_brace && !self.open_brace_written {
            self.flush_open_brace();
        }
    }

    fn finish_token(&mut self) {
        if self.current_token.is_empty() {
            return;
        }
        if self.current_line_first_token.is_empty() {
            self.current_line_first_token = self.current_token.clone();
        }
        self.current_token.clear();
    }

    fn finish_line(&mut self) {
        self.finish_token();
        if !self.current_line_first_token.is_empty() {
            self.previous_line_was_top_level_import =
                self.nesting == 0 && self.current_line_first_token == "import";
        } else if !self.open_brace || !self.open_brace_own_line || self.open_brace_written {
            self.previous_line_was_top_level_import = false;
        }
        self.current_line_first_token.clear();
    }

    fn write(&mut self, ch: char) {
        self.out.push(ch);
        self.last = ch;
    }

    fn indent(&mut self) {
        for _ in 0..self.nesting {
            self.write('\t');
        }
    }

    fn next_line(&mut self) {
        self.write('\n');
        self.beginning_of_line = true;
    }

    fn flush_open_brace(&mut self) {
        if self.nesting == 0 && self.last == '}' {
            self.next_line();
            self.next_line();
        }

        self.open_brace = false;
        if self.open_brace_own_line && self.previous_line_was_top_level_import {
            if self.last != '\n' {
                self.next_line();
            }
            self.indent();
        } else if self.beginning_of_line {
            self.indent();
        } else if !self.open_brace_space || !self.last.is_whitespace() {
            self.write(' ');
        }
        self.write('{');
        self.open_brace_written = true;
        self.open_brace_own_line = false;
        self.next_line();
        self.new_lines = 0;
        // Prevent infinite nesting from ridiculous inputs (Caddy issue #4169).
        if self.nesting < 10 {
            self.nesting += 1;
        }
    }
}

/// `isHeredocMarker` from `caddyconfig/caddyfile/lexer.go`.
fn is_heredoc_marker(marker: &[char]) -> bool {
    if marker.is_empty() {
        return false;
    }
    marker
        .iter()
        .all(|&ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

/// The located result of `caddyfile.FormattingDifference`.
pub(crate) struct FormattingWarning {
    pub(crate) file: String,
    pub(crate) line: usize,
}

/// `caddyfile.FormattingDifference`: the first line at which the normalized input differs from
/// its formatted form, or `None` when the input is already formatted.
pub(crate) fn formatting_difference(filename: &str, body: &[u8]) -> Option<FormattingWarning> {
    // Replace Windows-style newlines to normalize the comparison.
    let normalized_body = replace_crlf(body);

    let formatted = format(&normalized_body);
    if formatted == normalized_body {
        return None;
    }

    // Find where the difference is.
    let mut line = 1;
    for (index, &ch) in normalized_body.iter().enumerate() {
        if index >= formatted.len() || ch != formatted[index] {
            break;
        }
        if ch == b'\n' {
            line += 1;
        }
    }
    Some(FormattingWarning {
        file: filename.to_string(),
        line,
    })
}

fn replace_crlf(body: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        if body[index] == b'\r' && body.get(index + 1) == Some(&b'\n') {
            normalized.push(b'\n');
            index += 2;
        } else {
            normalized.push(body[index]);
            index += 1;
        }
    }
    normalized
}

/// `strings.Split(string(body), "\n")`: every newline starts a new line, including a trailing
/// empty line after a final newline.
fn split_lines(body: &[u8]) -> Vec<Vec<u8>> {
    body.split(|&byte| byte == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Delta {
    Common,
    LeftOnly,
    RightOnly,
}

struct DiffRecord {
    payload: Vec<u8>,
    delta: Delta,
}

/// `github.com/aryann/difflib.Diff`: an LCS diff over lines, emitted in forward order.
fn line_diff(seq1: &[Vec<u8>], seq2: &[Vec<u8>]) -> Vec<DiffRecord> {
    let (start, end) = num_equal_start_and_end_elements(seq1, seq2);

    let mut records = Vec::new();
    for content in &seq1[..start] {
        records.push(DiffRecord {
            payload: content.clone(),
            delta: Delta::Common,
        });
    }
    records.extend(compute(
        &seq1[start..seq1.len() - end],
        &seq2[start..seq2.len() - end],
    ));
    for content in &seq1[seq1.len() - end..] {
        records.push(DiffRecord {
            payload: content.clone(),
            delta: Delta::Common,
        });
    }
    records
}

fn num_equal_start_and_end_elements(seq1: &[Vec<u8>], seq2: &[Vec<u8>]) -> (usize, usize) {
    let mut start = 0;
    while start < seq1.len() && start < seq2.len() && seq1[start] == seq2[start] {
        start += 1;
    }
    let mut i = seq1.len() as isize - 1;
    let mut j = seq2.len() as isize - 1;
    let mut end = 0;
    while i > start as isize && j > start as isize && seq1[i as usize] == seq2[j as usize] {
        i -= 1;
        j -= 1;
        end += 1;
    }
    (start, end)
}

fn compute(seq1: &[Vec<u8>], seq2: &[Vec<u8>]) -> Vec<DiffRecord> {
    let n = seq1.len();
    let m = seq2.len();
    let mut matrix = vec![vec![0usize; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            if seq1[n - i] == seq2[m - j] {
                matrix[i][j] = matrix[i - 1][j - 1] + 1;
            } else {
                matrix[i][j] = matrix[i - 1][j].max(matrix[i][j - 1]);
            }
        }
    }

    let mut records = Vec::new();
    let mut i = n;
    let mut j = m;
    while i > 0 || j > 0 {
        if i > 0 && matrix[i][j] == matrix[i - 1][j] {
            records.push(DiffRecord {
                payload: seq1[n - i].clone(),
                delta: Delta::LeftOnly,
            });
            i -= 1;
        } else if j > 0 && matrix[i][j] == matrix[i][j - 1] {
            records.push(DiffRecord {
                payload: seq2[m - j].clone(),
                delta: Delta::RightOnly,
            });
            j -= 1;
        } else if i > 0 && j > 0 {
            records.push(DiffRecord {
                payload: seq1[n - i].clone(),
                delta: Delta::Common,
            });
            i -= 1;
            j -= 1;
        } else {
            break;
        }
    }
    records
}

/// Go's `bytes.TrimSpace`, including its handling of invalid UTF-8 (an invalid byte is the rune
/// `U+FFFD`, which is not whitespace, so trimming stops there).
fn trim_space(input: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < input.len() {
        let (ch, width) = decode_rune(&input[start..]);
        if !ch.is_whitespace() {
            break;
        }
        start += width;
    }
    if start == input.len() {
        return &[];
    }

    let mut end = start;
    let mut offset = start;
    while offset < input.len() {
        let (ch, width) = decode_rune(&input[offset..]);
        if !ch.is_whitespace() {
            end = offset + width;
        }
        offset += width;
    }
    &input[start..end]
}

/// Go's `utf8.DecodeRune`: a valid rune and its width, or `U+FFFD` with width 1 for invalid
/// encoding (including a truncated sequence).
fn decode_rune(bytes: &[u8]) -> (char, usize) {
    let end = bytes.len().min(4);
    match std::str::from_utf8(&bytes[..end]) {
        Ok(valid) => {
            // INFEASIBLE: `format`/`trim_space` only call this with a non-empty slice, so a
            // successful decode always yields at least one char.
            let ch = valid.chars().next().expect("non-empty slice");
            (ch, ch.len_utf8())
        }
        Err(error) if error.valid_up_to() > 0 => {
            let valid =
                std::str::from_utf8(&bytes[..error.valid_up_to()]).expect("valid_up_to prefix");
            // INFEASIBLE: the prefix is valid UTF-8 and `valid_up_to() > 0`, so it is non-empty.
            let ch = valid.chars().next().expect("non-empty prefix");
            (ch, ch.len_utf8())
        }
        Err(_) => (char::REPLACEMENT_CHARACTER, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::{format, formatting_difference};

    /// The table from upstream `caddyconfig/caddyfile/formatter_test.go` (v2.11.9).
    #[test]
    fn matches_upstream_formatter_corpus() {
        for (description, input, expect) in upstream_corpus() {
            // The formatter always ends its output with one newline; the upstream table omits it
            // except where the expected value already carries one.
            let expect = if expect.ends_with('\n') {
                expect.to_string()
            } else {
                format!("{expect}\n")
            };
            let actual = format(input.as_bytes());
            assert_eq!(
                String::from_utf8(actual).expect("formatted output is UTF-8"),
                expect,
                "case: {description}"
            );
        }
    }

    #[test]
    fn formatting_difference_locates_the_first_changed_line() {
        let warning = formatting_difference("Caddyfile", b"a b\n  c d\n").expect("differs");
        assert_eq!(warning.file, "Caddyfile");
        assert_eq!(warning.line, 2);

        assert!(formatting_difference("Caddyfile", b"a b\nc {\n\td\n}\n").is_none());
        // CRLF is normalized for the comparison, so an otherwise-formatted file is clean.
        assert!(formatting_difference("Caddyfile", b"a b\r\n").is_none());
    }

    /// Deterministic fuzz test for [`format`].
    ///
    /// The formatter is the one place in the CLI that rewrites arbitrary operator bytes into
    /// different arbitrary bytes, and it is stateful: ~20 fields track quoting, heredocs, escaping,
    /// brace nesting and blank-line policy. Its two properties are:
    ///
    ///   1. **Totality.** It never panics, for any input. It slices `&bytes[offset..]` and calls
    ///      `decode_rune`, so a width bug would panic or loop forever.
    ///   2. **Oracle parity, including non-idempotence.** caddy-rs must reproduce upstream Caddy's
    ///      formatter byte for byte — *including its bugs*. Upstream's own `formatter_fuzz.go`
    ///      treats `Format(x) == Format(Format(x))` as the success property, and that property
    ///      does **not** hold upstream: `Format("c{\\")` is `"c\\ {\n"` but formatting *that* gives
    ///      `"c\\  {\n"`. A trailing backslash before `{` grows a space on the second pass. This was
    ///      confirmed against the pinned oracle (external/caddy v2.11.9), which returns the same
    ///      two outputs. So non-idempotence here is a *compatibility requirement*, not a defect:
    ///      "fixing" it would make caddy-rs diverge from Caddy. The oracle fixtures below pin that.
    ///
    // ---------------------------------------------------------------------------------------------
    // Tier 1 knobs (FUZZ_SEED / FUZZ_CASES) — test-only
    // ---------------------------------------------------------------------------------------------
    //
    // Everything in this block is inside `#[cfg(test)] mod tests`, so none of it is compiled into
    // the shipped binary and the environment cannot affect `run`, `format` or
    // `formatting_difference`. That confinement is the point: this is production source, so an env
    // read reachable at runtime would make shipped behaviour depend on the environment.

    /// Tier-0 seed, used when `FUZZ_SEED` is unset.
    const SEED: u64 = 0x0F0F_0000_0000_0042;
    /// Tier-0 case count, used when `FUZZ_CASES` is unset.
    const CASES: usize = 8_000;
    /// Ceiling for `FUZZ_CASES`; the suite must stay CI-fast, so an out-of-range value is a loud
    /// error rather than a slow suite.
    const MAX_CASES: usize = 50_000;

    /// Read a knob. `Ok(None)` when unset (the silent tier-0 path); `Ok(Some(v))` when set to a
    /// valid value; `Err` naming the variable and the offending value when set to something
    /// unusable — so a misconfigured sweep fails loudly instead of silently running tier 0 and
    /// reporting green.
    #[cfg(test)]
    fn knob<T>(name: &str, max: Option<T>) -> Result<Option<T>, String>
    where
        T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
    {
        knob_from(name, std::env::var(name), max)
    }

    /// The body of [`knob`], taking the looked-up value as a parameter so the "present" branch is
    /// testable without mutating the process environment (which is global and would race the other
    /// tests running in parallel). A test that called [`parse_knob`] directly would bypass this
    /// function and miss a wrapper that swallowed the error.
    #[cfg(test)]
    fn knob_from<T>(
        name: &str,
        looked_up: Result<String, std::env::VarError>,
        max: Option<T>,
    ) -> Result<Option<T>, String>
    where
        T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
    {
        match looked_up {
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(err) => Err(format!("{name} is set but unreadable: {err}")),
            Ok(raw) => parse_knob(name, &raw, max),
        }
    }

    /// Validate one raw knob value. Split out of [`knob`] so the parsing contract can be tested
    /// without touching the process environment, which is global and would race tests running in
    /// parallel.
    ///
    /// `Ok(Some(v))` when `raw` parses and is within `max`; `Err` naming the variable and the
    /// offending value otherwise.
    #[cfg(test)]
    fn parse_knob<T>(name: &str, raw: &str, max: Option<T>) -> Result<Option<T>, String>
    where
        T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
    {
        let value = raw.parse::<T>().map_err(|_| {
            format!("{name}={raw:?} is not a valid value; unset it to run tier 0 (using the in-file constant), or pass a parseable value")
        })?;
        if let Some(max) = max {
            if value > max {
                return Err(format!(
                    "{name}={raw:?} is out of range: must be at most {max}; unset it to run tier 0 (using the in-file constant)"
                ));
            }
        }
        Ok(Some(value))
    }

    /// Resolved knob values for one run. Test-only.
    #[cfg(test)]
    struct FuzzKnobs {
        seed: Option<u64>,
        cases: Option<usize>,
    }

    #[cfg(test)]
    impl FuzzKnobs {
        /// Resolve both knobs from the environment, failing loudly on an invalid value.
        fn from_env() -> Result<Self, String> {
            Ok(Self {
                seed: knob::<u64>("FUZZ_SEED", None)?,
                cases: knob::<usize>("FUZZ_CASES", Some(MAX_CASES))?,
            })
        }

        /// The seed the loop starts from: the tier-1 `FUZZ_SEED` when set, else the constant.
        fn seed(&self) -> u64 {
            self.seed.unwrap_or(SEED)
        }

        /// Cases the loop runs: the tier-1 `FUZZ_CASES` when set, else the constant.
        ///
        /// This test has a single flat loop, so `FUZZ_CASES` is the suite total directly — no
        /// ratio to divide by, unlike the multi-generator targets.
        fn cases(&self) -> usize {
            self.cases.unwrap_or(CASES)
        }

        /// Cases actually executed. Mirrors the loop, which is flat, so it equals `cases()`;
        /// kept as its own method so the announcement goes through a name that would have to be
        /// updated if the loop ever gained a multiplier (the adapter's per-seed defect).
        fn cases_total(&self) -> usize {
            self.cases()
        }

        /// Print the resolved seed and case count so the corpus is identifiable from the log.
        fn announce(&self, cases: usize) {
            match (self.seed, self.cases) {
                (None, None) => println!(
                    "fmt fuzz: tier 0 (FUZZ_SEED/FUZZ_CASES unset) — seed {SEED}, cases {cases} total"
                ),
                (seed, requested) => println!(
                    "fmt fuzz: tier 1 — resolved FUZZ_SEED={:?}, FUZZ_CASES={:?} ({cases} cases total)",
                    seed, requested
                ),
            }
        }
    }

    /// Determinism: inputs come from a seeded xorshift64 PRNG implemented in this module's test
    /// code. No external fuzzing crate and no ambient randomness, so a failure reproduces from the
    /// seed.
    ///
    /// Tier: **tier 1** (T-FUZZ-SEED-FMT). The seed and case count are the constants below unless
    /// overridden by `FUZZ_SEED` (u64) and `FUZZ_CASES` (usize), read by [`FuzzKnobs`]. Knob
    /// contract, per `docs/compatibility/TESTING.md` §Fuzzing:
    ///
    /// - **absent ⇒ silent tier 0**: with both variables unset the test uses the constants, so a
    ///   plain `cargo test` is byte-identical to the pre-tier behaviour;
    /// - **present ⇒ tier 1**: the value replaces the constant, so a scheduled sweep explores a
    ///   different corpus each run. Still deterministic *within* a run;
    /// - **present-but-invalid ⇒ loud failure**, naming the variable and the offending value.
    ///
    /// The knobs live in `#[cfg(test)]` code and are unreachable from the shipped binary: nothing
    /// in `run`, `format` or `formatting_difference` reads the environment.
    #[test]
    fn format_is_total_and_preserves_output_invariants() {
        // xorshift64 — deterministic, dependency-free PRNG.
        fn xorshift(state: &mut u64) -> u64 {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            x
        }

        // The bytes that drive the formatter's state machine: braces, quotes, backslashes,
        // whitespace, comment markers, heredoc markers and multi-byte UTF-8.
        const ALPHABET: &[u8] = b"ab{}[]()\"`#\\ \t\r\n,<>=*\xc3\xa9\xe2\x82\xac";

        let knobs = FuzzKnobs::from_env().unwrap_or_else(|err| panic!("fmt fuzz: {err}"));
        let cases = knobs.cases();
        knobs.announce(cases);
        assert_eq!(
            cases,
            knobs.cases_total(),
            "the announced total must be the count the loop runs"
        );

        let mut state = knobs.seed();
        let mut checked = 0_usize;
        for case in 0..cases {
            let len = (xorshift(&mut state) % 48) as usize;
            let mut input = Vec::with_capacity(len);
            for _ in 0..len {
                let index = (xorshift(&mut state) as usize) % ALPHABET.len();
                input.push(ALPHABET[index]);
            }

            // Property 1: totality. A panic here fails the test with the input named.
            let once = std::panic::catch_unwind(|| format(&input)).unwrap_or_else(|_| {
                panic!(
                    "format panicked on case {case} ({} bytes): {:?}",
                    input.len(),
                    String::from_utf8_lossy(&input)
                )
            });

            // Property 2a: the output is always valid UTF-8. `format` builds from `char`s, so this
            // is a cheap invariant that would catch a byte-level regression.
            let once_text = String::from_utf8(once.clone()).unwrap_or_else(|error| {
                panic!("format produced non-UTF-8 output on case {case}: {error}")
            });

            // Property 2b: the output always ends with exactly one newline (a documented contract:
            // "the Caddyfile must end with a newline because newlines are significant").
            //
            // `format` pushes that newline unconditionally, so `ends_with('\n')` alone would only
            // detect the push being deleted. These two assertions test the *trimming* instead,
            // which is the part that can actually regress: the output must be non-empty (every
            // input yields at least the newline), and the text before the final newline must carry
            // no trailing whitespace, because `formatter.out` is trimmed.
            assert!(
                !once_text.is_empty(),
                "format output must never be empty, case {case}"
            );
            let before_newline = once_text
                .strip_suffix('\n')
                .expect("output ends with a newline");
            assert_eq!(
                before_newline.trim_end(),
                before_newline,
                "format output must have no trailing whitespace before its final newline, \
                 case {case}: {once_text:?}"
            );

            // Property 2c: formatting is total on its own output too — it must not panic when fed
            // back in. Note this deliberately does NOT assert idempotence: upstream is not
            // idempotent (see the doc comment), so neither is caddy-rs.
            let twice = std::panic::catch_unwind(|| format(&once)).unwrap_or_else(|_| {
                panic!("format panicked re-formatting its own output, case {case}: {once_text:?}")
            });
            // Re-formatting must be total; its result is not asserted equal to `once`, because the
            // formatter is not idempotent (see the doc comment and the oracle fixture below).
            let _ = twice;

            // Track that the corpus actually exercises the formatter's interesting paths. If the
            // alphabet or the generator regressed, every output would be a bare newline and the
            // assertions above would pass vacuously.
            if once_text.trim() != once_text.trim_end_matches('\n') || once_text.contains('{') {
                checked += 1;
            }
        }
        assert!(
            checked > cases / 2,
            "only {checked} of {cases} cases produced brace-bearing or multi-line output; the \
             generator is no longer exercising the formatter"
        );
    }

    /// Tier 1 must actually vary the corpus between runs: two different `FUZZ_SEED` values must
    /// produce different case streams, while a repeated value reproduces exactly.
    #[test]
    fn different_resolved_seeds_produce_different_case_streams() {
        fn xorshift(state: &mut u64) -> u64 {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            x
        }
        let stream = |seed: u64| {
            let mut state = seed;
            (0..16)
                .map(|_| {
                    let len = (xorshift(&mut state) % 48) as usize;
                    (0..len)
                        .map(|_| (xorshift(&mut state) as usize % 26) as u8)
                        .collect::<Vec<u8>>()
                })
                .collect::<Vec<Vec<u8>>>()
        };
        assert_ne!(
            stream(1),
            stream(2),
            "FUZZ_SEED=1 and FUZZ_SEED=2 produced identical streams; tier 1 would be a no-op"
        );
        assert_eq!(
            stream(1),
            stream(1),
            "the same seed must reproduce exactly (determinism within a run)"
        );
    }

    /// A present knob must actually override its constant. Without this, a resolver that silently
    /// ignored the environment would run tier 0 and report green — the failure the tier contract
    /// forbids, and one that slipped through on an earlier target until it was pinned.
    #[test]
    fn present_knobs_actually_override_the_constants() {
        let tier0 = FuzzKnobs {
            seed: None,
            cases: None,
        };
        let tier1 = FuzzKnobs {
            seed: Some(12345),
            cases: Some(50),
        };
        assert_ne!(
            tier1.seed(),
            tier0.seed(),
            "FUZZ_SEED must change the seed, not silently fall back to the constant"
        );
        assert_ne!(
            tier1.cases(),
            tier0.cases(),
            "FUZZ_CASES must change the case count, not silently fall back to the constant"
        );
        assert_eq!(tier1.cases(), 50, "FUZZ_CASES=50 must run exactly 50 cases");
        // Tier 0 stays exactly the constants.
        assert_eq!(tier0.seed(), SEED);
        assert_eq!(tier0.cases(), CASES);
    }

    /// An unparsable or out-of-range knob must be a loud `Err` naming the variable and the
    /// offending value — never a silent fallback to the constant, which would let a misconfigured
    /// sweep run tier 0 and report green.
    #[test]
    fn invalid_knob_values_are_loud_errors_naming_variable_and_value() {
        // Unparsable: the message names the variable and the offending value.
        let err = parse_knob::<u64>("FUZZ_SEED", "abc", None)
            .expect_err("an unparsable FUZZ_SEED must be an error, not a silent fallback");
        assert!(err.contains("FUZZ_SEED"), "must name the variable: {err}");
        assert!(err.contains("abc"), "must name the offending value: {err}");
        assert!(
            err.contains("not a valid value"),
            "must say the value is invalid: {err}"
        );

        // Out of range: the message names the variable, the value and the bound.
        let err = parse_knob::<usize>("FUZZ_CASES", "999999", Some(MAX_CASES))
            .expect_err("an out-of-range FUZZ_CASES must be an error");
        assert!(err.contains("FUZZ_CASES"), "must name the variable: {err}");
        assert!(
            err.contains("999999"),
            "must name the offending value: {err}"
        );
        assert!(
            err.contains("out of range") && err.contains(&MAX_CASES.to_string()),
            "must name the range: {err}"
        );

        // The full knob path — including the present/unparsable branch, which is where a wrapper
        // that swallowed the error would hide — must also be loud.
        let err = knob_from::<u64>("FUZZ_SEED", Ok("abc".to_string()), None)
            .expect_err("the full knob path must propagate the error, not swallow it");
        assert!(err.contains("FUZZ_SEED") && err.contains("abc"), "{err}");

        let err = knob_from::<usize>("FUZZ_CASES", Ok("999999".to_string()), Some(MAX_CASES))
            .expect_err("the full knob path must propagate an out-of-range error");
        assert!(
            err.contains("FUZZ_CASES") && err.contains("999999"),
            "{err}"
        );

        // Valid values parse through, and the absent path is a silent Ok(None).
        assert_eq!(
            parse_knob::<u64>("FUZZ_SEED", "12345", None),
            Ok(Some(12345))
        );
        assert_eq!(
            parse_knob::<usize>("FUZZ_CASES", "50", Some(MAX_CASES)),
            Ok(Some(50))
        );
        assert_eq!(
            knob::<u64>("CADDY_RS_TEST_UNSET_FUZZ_SEED", None),
            Ok(None),
            "an unset knob must be the silent tier-0 path"
        );
    }

    /// Oracle parity for the formatter's non-idempotent quirk, with the exact bytes the pinned
    /// oracle (external/caddy v2.11.9) returns.
    ///
    /// These are regression fixtures: if someone "fixes" the double space, caddy-rs stops matching
    /// Caddy and this test fails. The correct fix, if upstream ever changes, is to update this
    /// fixture together with the oracle pin.
    #[test]
    fn matches_oracle_non_idempotent_quirk() {
        // Upstream: Format("c{\\") == "c\\ {\n"; Format("c\\ {\n") == "c\\  {\n".
        let first = format(b"c{\\");
        assert_eq!(String::from_utf8(first.clone()).unwrap(), "c\\ {\n");
        let second = format(&first);
        assert_eq!(String::from_utf8(second.clone()).unwrap(), "c\\  {\n");
        assert_ne!(
            first, second,
            "this fixture exists because the oracle is NOT idempotent here; if this now passes, \
             re-check upstream Caddy v2.11.9 before deleting the fixture"
        );
    }

    /// The corpus a previous fuzz run found to be non-idempotent, kept so a change to the
    /// formatter's quote/escape handling is visible even if the random corpus misses it.
    ///
    /// This asserts *totality* only (re-formatting must not panic and must still end with a
    /// newline). It deliberately does not assert that re-formatting is stable, because the oracle
    /// is not stable either — see [`matches_oracle_non_idempotent_quirk`].
    #[test]
    fn oracle_corpus_is_total_on_reformatting() {
        let corpus: Vec<&[u8]> = vec![
            b"c{\\",
            b"\\{",
            b"a\\{b",
            b"{\\",
            b"x{\\y",
            b"c{\\\\\\",
            b"q{\\ {",
            b"c{\\ {",
            b"c{\\  {",
            b"a{\\b",
            b"{\\}",
            b"\tc\t{\t``\r`bb\\{}",
            b"b\r\na\"\t\"cb\" }\n\r\r\t\n{\"\rc#\nb\\\" \"\"\\b{\r\\",
        ];
        for input in corpus {
            let once = format(input);
            // Total on its own output: must not panic, and must still end with a newline.
            let twice = format(&once);
            assert!(
                twice.ends_with(b"\n"),
                "output must end with a newline for input {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    fn upstream_corpus() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            (
                "very simple",
                "abc   def\n\tg hi jkl\nmn",
                "abc def\ng hi jkl\nmn",
            ),
            (
                "basic indentation, line breaks, and nesting",
                "  a\nb\n\n\tc {\n\t\td\n}\n\ne { f\n}\n\n\n\ng {\nh {\ni\n}\n}\n\nj { k {\nl\n}\n}\n\nm {\n\tn { o\n\t}\n\tp { q r\ns }\n}\n\n\t{\n{ t\n\t\tu\n\n\tv\n\nw\n}\n}",
                "a\nb\n\nc {\n\td\n}\n\ne {\n\tf\n}\n\ng {\n\th {\n\t\ti\n\t}\n}\n\nj {\n\tk {\n\t\tl\n\t}\n}\n\nm {\n\tn {\n\t\to\n\t}\n\tp {\n\t\tq r\n\t\ts\n\t}\n}\n\n{\n\t{\n\t\tt\n\t\tu\n\n\t\tv\n\n\t\tw\n\t}\n}",
            ),
            (
                "block spacing",
                "a{\n\tb\n}\n\nc{ d\n}",
                "a {\n\tb\n}\n\nc {\n\td\n}",
            ),
            (
                "advanced spacing",
                "abc {\ndef\n}ghi{\n\tjkl mno\npqr}",
                "abc {\n\tdef\n}\n\nghi {\n\tjkl mno\n\tpqr\n}",
            ),
            (
                "env var placeholders",
                "{$A}\n\nb {\n{$C}\n}\n\nd { {$E}\n}\n\n{ {$F}\n}\n",
                "{$A}\n\nb {\n\t{$C}\n}\n\nd {\n\t{$E}\n}\n\n{\n\t{$F}\n}",
            ),
            ("env var placeholders with port", ":{$PORT}", ":{$PORT}"),
            (
                "comments",
                "#a \"\\n\"\n\n #b {\n\tc\n}\n\nd {\ne#f\n# g\n}\n\nh { # i\n}",
                "#a \"\\n\"\n\n#b {\nc\n}\n\nd {\n\te#f\n\t# g\n}\n\nh {\n\t# i\n}",
            ),
            (
                "quotes and escaping",
                "\"a \\\"b\\\" \"#c\n\td\n\ne {\n\"f\"\n}\n\ng { \"h\"\n}\n\ni {\n\t\"foo\nbar\"\n}\n\nj {\n\"\\\"k\\\" l m\"\n}",
                "\"a \\\"b\\\" \"#c\nd\n\ne {\n\t\"f\"\n}\n\ng {\n\t\"h\"\n}\n\ni {\n\t\"foo\nbar\"\n}\n\nj {\n\t\"\\\"k\\\" l m\"\n}",
            ),
            (
                "bad nesting (too many open)",
                "a\n{\n\t{\n}",
                "a {\n\t{\n\t}\n",
            ),
            (
                "bad nesting (too many close)",
                "a\n{\n\t{\n}}}",
                "a {\n\t{\n\t}\n}\n}\n",
            ),
            (
                "json",
                "foo\nbar      \"{\\\"key\\\":34}\"\n",
                "foo\nbar \"{\\\"key\\\":34}\"",
            ),
            (
                "escaping after spaces",
                "foo \\\"literal\\\"",
                "foo \\\"literal\\\"",
            ),
            (
                "simple placeholders as standalone tokens",
                "foo {bar}",
                "foo {bar}",
            ),
            (
                "simple placeholders within tokens",
                "foo{bar} foo{bar}baz",
                "foo{bar} foo{bar}baz",
            ),
            (
                "placeholders and malformed braces",
                "foo{bar} foo{ bar}baz",
                "foo{bar} foo {\n\tbar\n}\n\nbaz",
            ),
            (
                "hash within string is not a comment",
                "redir / /some/#/path",
                "redir / /some/#/path",
            ),
            (
                "brace does not fold into comment above",
                "# comment\n{\n\tfoo\n}",
                "# comment\n{\n\tfoo\n}",
            ),
            (
                "matthewpi/vscode-caddyfile-support#13",
                "{\n\temail {$ACMEEMAIL}\n\t#debug\n}\n\nblock {\n}\n",
                "{\n\temail {$ACMEEMAIL}\n\t#debug\n}\n\nblock {\n}\n",
            ),
            (
                "matthewpi/vscode-caddyfile-support#13 - bad formatting",
                "{\n\temail {$ACMEEMAIL}\n\t#debug\n\t}\n\n\tblock {\n\t}\n",
                "{\n\temail {$ACMEEMAIL}\n\t#debug\n}\n\nblock {\n}\n",
            ),
            (
                "keep heredoc as-is",
                "block {\n\theredoc <<HEREDOC\n\tHere's more than one space       Here's more than one space\n\tHEREDOC\n}\n",
                "block {\n\theredoc <<HEREDOC\n\tHere's more than one space       Here's more than one space\n\tHEREDOC\n}",
            ),
            (
                "Mixing heredoc with regular part",
                "block {\n\theredoc <<HEREDOC\n\tHere's more than one space       Here's more than one space\n\tHEREDOC\n\trespond \"More than one space will be eaten\"     200\n}\n\nblock2 {\n\theredoc <<HEREDOC\n\tHere's more than one space       Here's more than one space\n\tHEREDOC\n\trespond \"More than one space will be eaten\" 200\n}\n",
                "block {\n\theredoc <<HEREDOC\n\tHere's more than one space       Here's more than one space\n\tHEREDOC\n\trespond \"More than one space will be eaten\" 200\n}\n\nblock2 {\n\theredoc <<HEREDOC\n\tHere's more than one space       Here's more than one space\n\tHEREDOC\n\trespond \"More than one space will be eaten\" 200\n}",
            ),
            (
                "Heredoc as regular token",
                "block {\n\theredoc <<HEREDOC                                 \"More than one space will be eaten\"\n}\n",
                "block {\n\theredoc <<HEREDOC \"More than one space will be eaten\"\n}",
            ),
            (
                "Escape heredoc",
                "block {\n\theredoc \\<<HEREDOC\n\trespond \"More than one space will be eaten\"                           200\n}\n",
                "block {\n\theredoc \\<<HEREDOC\n\trespond \"More than one space will be eaten\" 200\n}",
            ),
            (
                "Preserve braces wrapped by backquotes",
                "block {respond `All braces should remain: {{now | date \"2006\"}}`}",
                "block {respond `All braces should remain: {{now | date \"2006\"}}`}",
            ),
            (
                "Preserve braces wrapped by quotes",
                "block {respond \"All braces should remain: {{now | date `2006`}}\"}",
                "block {respond \"All braces should remain: {{now | date `2006`}}\"}",
            ),
            (
                "Preserve quoted brace arguments",
                "block {\n\trespond \"{\"\n\trespond \"}\"\n}",
                "block {\n\trespond \"{\"\n\trespond \"}\"\n}",
            ),
            (
                "Preserve quoted backticks and backticked quotes",
                "block { respond \"`\" } block { respond `\"`}",
                "block {\n\trespond \"`\"\n}\n\nblock {\n\trespond `\"`\n}",
            ),
            (
                "No trailing space on line before env variable",
                "{\n\ta\n\n\t{$ENV_VAR}\n}\n",
                "{\n\ta\n\n\t{$ENV_VAR}\n}",
            ),
            (
                "issue #7425: multiline backticked string indentation",
                "https://localhost:8953 {\n    respond `Here are some random numbers:\n\n{{randNumeric 16}}\n\nHope this helps.`\n}",
                "https://localhost:8953 {\n\trespond `Here are some random numbers:\n\n{{randNumeric 16}}\n\nHope this helps.`\n}",
            ),
            (
                "imports before global options block keep standalone brace",
                "import ./conf.d/matcher_my_subnet.caddy\nimport ./conf.d/matcher_not_my_subnet.caddy\n{\n\torder crowdsec first\n\torder appsec after crowdsec\n}",
                "import ./conf.d/matcher_my_subnet.caddy\nimport ./conf.d/matcher_not_my_subnet.caddy\n{\n\torder crowdsec first\n\torder appsec after crowdsec\n}",
            ),
            ("keep an opening brace that ends the input", "localhost {", "localhost {"),
            ("keep a standalone opening brace that ends the input", "{", "{"),
            (
                "keep adjacent opening braces that end the input",
                "{{",
                "{\n\t{",
            ),
            (
                "keep spaced opening braces that end the input",
                "{ {",
                "{\n\t{",
            ),
        ]
    }
}
