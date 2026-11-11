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

/// Formats a Caddyfile.
pub(crate) fn run(
    config: Option<PathBuf>,
    overwrite: bool,
    diff: bool,
    paths: Vec<PathBuf>,
) -> anyhow::Result<()> {
    // Caddy treats an empty `--config` value as "not set".
    let config = config.filter(|path| !path.as_os_str().is_empty());

    // cmdFmt rejects multiple inputs before it resolves the default path. The message is
    // Caddy's verbatim text, including the two spaces when `--config` is absent.
    if paths.len() > 1 || (config.is_some() && !paths.is_empty()) {
        let config_flag = config
            .as_deref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let joined = paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        bail!("fmt does not support multiple files {config_flag} {joined}");
    }

    let config_file = paths
        .first()
        .cloned()
        .or(config)
        .unwrap_or_else(|| PathBuf::from("Caddyfile"));

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

    let input = std::fs::read(&config_file)
        .with_context(|| format!("reading input file: {}", config_file.display()))?;
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
