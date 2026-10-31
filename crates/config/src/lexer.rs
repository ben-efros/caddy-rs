//! Caddyfile lexer.
//!
//! The lexer follows Caddy's token model closely enough for the supported directive subset:
//! words, quoted strings (`"..."` with escapes), backtick raw strings, braces as structural
//! tokens, comments (`#` to end of line), newlines as significant separators, heredocs
//! (`<<MARKER`) and backslash line continuation.
//!
//! Heredocs and continuation are ported from Caddy v2.11.7 `caddyconfig/caddyfile/lexer.go` so
//! that whitespace stripping and the diagnostics match the upstream implementation exactly:
//!
//! * A heredoc starts with a token that begins `<<` and is followed on the same line only by its
//!   marker, then a newline. A space before the newline makes `<<...` an ordinary token.
//! * The *closing* marker line's leading whitespace is the indentation stripped from every
//!   non-blank content line. Content lines whose leading whitespace does not start with that
//!   exact padding are rejected, which is how Caddy detects "extra indentation".
//! * The marker may contain ASCII letters, digits, `_` and `-`. Caddy has no shell-style
//!   `<<-MARKER` strip mode: `<<-EOF` is a heredoc whose marker is literally `-EOF`.
//! * A backslash immediately before a newline continues the argument list onto the next line
//!   (the newline is not a token separator).
//!
//! Environment placeholders (`{$ENV}`, `{$ENV:default}`) are *not* handled here: like Caddy,
//! they are expanded on the raw source before lexing (see [`crate::parser::expand_env_vars`]).

use std::fmt;
use std::iter::Peekable;
use std::str::CharIndices;

/// Location of a token in the source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}", self.line)
    }
}

/// Token category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A bare word.
    Word,
    /// A quoted, backtick-delimited, or heredoc string.
    Quoted,
    /// `{`.
    LeftBrace,
    /// `}`.
    RightBrace,
    /// A line break.
    Newline,
}

/// A lexical token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Category.
    pub kind: TokenKind,
    /// Decoded text.
    pub text: String,
    /// Source position.
    pub position: Position,
}

/// A lexing error naming the offending input and position.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Caddyfile {}: {}", position, message)]
pub struct LexError {
    /// Where the problem was found.
    pub position: Position,
    /// What was found and what was expected.
    pub message: String,
}

impl LexError {
    fn new(line: usize, column: usize, message: impl Into<String>) -> Self {
        Self {
            position: Position { line, column },
            message: message.into(),
        }
    }
}

type Cursor<'a> = Peekable<CharIndices<'a>>;

/// Returns the character `offset` positions ahead of the cursor (0 is the character that
/// [`Iterator::peek`] would report).
fn peek_ahead(cursor: &Cursor<'_>, offset: usize) -> Option<char> {
    let mut probe = cursor.clone();
    for _ in 0..offset {
        probe.next()?;
    }
    probe.next().map(|(_, ch)| ch)
}

/// Tokenize Caddyfile input.
pub fn lex(input: &str) -> Result<Vec<Token>, LexError> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    let mut line = 1;
    let mut column = 1;

    while let Some(&(_, ch)) = chars.peek() {
        let position = Position { line, column };
        match ch {
            ' ' | '\t' | '\r' => {
                // Caddy ignores carriage returns rather than treating them as separators; this
                // keeps Windows line endings equivalent to Unix ones.
                chars.next();
                column += 1;
            }
            '\n' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::Newline,
                    text: "\n".to_string(),
                    position,
                });
                line += 1;
                column = 1;
            }
            '#' => {
                while let Some(&(_, next)) = chars.peek() {
                    if next == '\n' {
                        break;
                    }
                    chars.next();
                    column += 1;
                }
            }
            '\\' => {
                // Backslash immediately before a line break continues the previous token line:
                // the newline is consumed without producing a [`TokenKind::Newline`] token, so
                // arguments can be chained across lines. A backslash before any other whitespace
                // is dropped, matching Caddy (which never unescapes whitespace).
                match peek_ahead(&chars, 1) {
                    Some('\n') => {
                        chars.next();
                        chars.next();
                        line += 1;
                        column = 1;
                    }
                    Some('\r') if peek_ahead(&chars, 2) == Some('\n') => {
                        chars.next();
                        chars.next();
                        chars.next();
                        line += 1;
                        column = 1;
                    }
                    Some(next) if next.is_whitespace() => {
                        chars.next();
                        column += 1;
                    }
                    None => {
                        chars.next();
                        column += 1;
                    }
                    _ => match scan_word(&mut chars, position, &mut column) {
                        Some(token) => tokens.push(token),
                        None => unreachable!("a word starting with `\\` must consume input"),
                    },
                }
            }
            '<' if peek_ahead(&chars, 1) == Some('<') => match lex_heredoc(&mut chars, position)? {
                Some((token, end_line, end_column)) => {
                    tokens.push(token);
                    line = end_line;
                    column = end_column;
                }
                None => match scan_word(&mut chars, position, &mut column) {
                    Some(token) => tokens.push(token),
                    None => unreachable!("a word starting with `<` must consume input"),
                },
            },
            '{' => {
                if brace_is_standalone(&chars, '{') {
                    chars.next();
                    tokens.push(Token {
                        kind: TokenKind::LeftBrace,
                        text: "{".to_string(),
                        position,
                    });
                    column += 1;
                } else {
                    match scan_word(&mut chars, position, &mut column) {
                        Some(token) => tokens.push(token),
                        None => {
                            chars.next();
                            column += 1;
                        }
                    }
                }
            }
            '}' => {
                if brace_is_standalone(&chars, '}') {
                    chars.next();
                    tokens.push(Token {
                        kind: TokenKind::RightBrace,
                        text: "}".to_string(),
                        position,
                    });
                    column += 1;
                } else {
                    match scan_word(&mut chars, position, &mut column) {
                        Some(token) => tokens.push(token),
                        None => {
                            chars.next();
                            column += 1;
                        }
                    }
                }
            }
            '"' => {
                let token = scan_quoted(&mut chars, position, &mut column)?;
                tokens.push(token);
            }
            '`' => {
                let token = scan_backtick(&mut chars, position, &mut line, &mut column)?;
                tokens.push(token);
            }
            _ => match scan_word(&mut chars, position, &mut column) {
                Some(token) => tokens.push(token),
                None => {
                    // Defensive: never loop forever on an unexpected character.
                    chars.next();
                    column += 1;
                }
            },
        }
    }
    Ok(tokens)
}

/// Caddy does not tokenize braces: a token is a whitespace-delimited run, and the parser decides
/// that a token whose text is exactly `{` or `}` is structural. This mirrors that rule so that
/// placeholder tokens such as `{block}`, `{args[0]}` and `{http.request.uri}` are single words and
/// can be embedded in larger words (`prefix-{args[0]}`). `{}` remains a structural empty-block
/// pair for backwards compatibility with the previous lexer.
fn brace_is_standalone(chars: &Cursor<'_>, brace: char) -> bool {
    match peek_ahead(chars, 1) {
        None => true,
        Some(next) if next.is_whitespace() => true,
        Some('}') if brace == '{' => match peek_ahead(chars, 2) {
            None => true,
            Some(next) => next.is_whitespace(),
        },
        Some(_) => false,
    }
}

/// Scan a bare word, applying Caddy's backslash rules.
fn scan_word(cursor: &mut Cursor<'_>, position: Position, column: &mut usize) -> Option<Token> {
    let mut text = String::new();
    while let Some(&(_, ch)) = cursor.peek() {
        if ch.is_whitespace() || matches!(ch, '"' | '`') {
            break;
        }
        if ch == '\\' {
            match peek_ahead(cursor, 1) {
                // Line continuation: leave the backslash for the main loop, which consumes the
                // sequence without emitting a newline token.
                Some('\n') => break,
                Some('\r') if peek_ahead(cursor, 2) == Some('\n') => break,
                // A backslash before whitespace is dropped and terminates the word.
                Some(next) if next.is_whitespace() => {
                    cursor.next();
                    *column += 1;
                }
                // A trailing backslash at end of input is dropped, like Caddy.
                None => {
                    cursor.next();
                    *column += 1;
                    break;
                }
                // `\<` escapes the heredoc introducer: the backslash is dropped and the `<` (and
                // anything following) stays literal, so `\<<EOF` is the word `<<EOF`.
                Some('<') => {
                    cursor.next();
                    cursor.next();
                    *column += 2;
                    text.push('<');
                }
                // No other character is unescaped: Caddy keeps the backslash verbatim.
                Some(next) => {
                    cursor.next();
                    cursor.next();
                    *column += 2;
                    text.push('\\');
                    text.push(next);
                }
            }
            continue;
        }
        text.push(ch);
        cursor.next();
        *column += 1;
    }
    if text.is_empty() {
        return None;
    }
    Some(Token {
        kind: TokenKind::Word,
        text,
        position,
    })
}

/// Scan a `"..."` string. Escape handling matches the previous lexer: `\n`, `\r`, `\t`, `\"`,
/// `\\` are decoded and any other escape keeps its backslash.
fn scan_quoted(
    cursor: &mut Cursor<'_>,
    position: Position,
    column: &mut usize,
) -> Result<Token, LexError> {
    cursor.next();
    *column += 1;
    let mut text = String::new();
    let mut closed = false;
    while let Some((_, next)) = cursor.next() {
        *column += 1;
        match next {
            '"' => {
                closed = true;
                break;
            }
            '\\' => {
                let Some((_, escaped)) = cursor.next() else {
                    return Err(LexError::new(
                        position.line,
                        position.column,
                        "unterminated escape sequence in quoted string",
                    ));
                };
                *column += 1;
                match escaped {
                    'n' => text.push('\n'),
                    'r' => text.push('\r'),
                    't' => text.push('\t'),
                    '"' => text.push('"'),
                    '\\' => text.push('\\'),
                    other => {
                        text.push('\\');
                        text.push(other);
                    }
                }
            }
            '\n' => {
                return Err(LexError::new(
                    position.line,
                    position.column,
                    "unterminated quoted string before newline",
                ));
            }
            other => text.push(other),
        }
    }
    if !closed {
        return Err(LexError::new(
            position.line,
            position.column,
            "unterminated quoted string",
        ));
    }
    Ok(Token {
        kind: TokenKind::Quoted,
        text,
        position,
    })
}

/// Scan a backtick-delimited raw string.
fn scan_backtick(
    cursor: &mut Cursor<'_>,
    position: Position,
    line: &mut usize,
    column: &mut usize,
) -> Result<Token, LexError> {
    cursor.next();
    *column += 1;
    let mut text = String::new();
    let mut closed = false;
    while let Some((_, next)) = cursor.next() {
        *column += 1;
        if next == '`' {
            closed = true;
            break;
        }
        if next == '\n' {
            *line += 1;
            *column = 1;
        }
        text.push(next);
    }
    if !closed {
        return Err(LexError::new(
            position.line,
            position.column,
            "unterminated backtick string",
        ));
    }
    Ok(Token {
        kind: TokenKind::Quoted,
        text,
        position,
    })
}

/// Attempt to lex a heredoc starting at `<<`.
///
/// Returns `Ok(None)` when the input at the cursor is an ordinary token that merely starts with
/// `<<` (for example `<<EOF arg` on one line, or a trailing `<<` at end of input); the cursor is
/// left untouched in that case.
fn lex_heredoc(
    cursor: &mut Cursor<'_>,
    start: Position,
) -> Result<Option<(Token, usize, usize)>, LexError> {
    // Probe the rest of the announcing line. Caddy treats a space before the newline as proof
    // that this is a normal token; a CR is ignored; any other character belongs to the marker.
    let mut probe = cursor.clone();
    probe.next(); // first `<`
    probe.next(); // second `<`
    let mut marker = String::new();
    loop {
        match probe.next() {
            // End of input before the end of the line: an ordinary word.
            None => return Ok(None),
            Some((_, '\r')) => {}
            Some((_, ' ')) => return Ok(None),
            Some((_, '\n')) => break,
            Some((_, ch)) => marker.push(ch),
        }
    }

    if marker.is_empty() {
        return Err(LexError::new(
            start.line,
            start.column,
            format!(
                "missing opening heredoc marker on line #{}; must contain only alphanumeric \
                 characters, dashes and underscores; got empty string",
                start.line
            ),
        ));
    }
    // Caddy checks the third character of `<<<...`, i.e. whether the marker itself starts `<`.
    if marker.starts_with('<') {
        return Err(LexError::new(
            start.line,
            start.column,
            format!(
                "too many '<' for heredoc on line #{}; only use two, for example <<END",
                start.line
            ),
        ));
    }
    if !marker
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(LexError::new(
            start.line,
            start.column,
            format!(
                "heredoc marker on line #{} must contain only alphanumeric characters, dashes \
                 and underscores; got '{}'",
                start.line, marker
            ),
        ));
    }

    // Commit: the announcing line (through its newline) has been validated and is not part of the
    // token text.
    *cursor = probe;

    let mut body = String::new();
    let mut body_newlines = 0usize;
    loop {
        let Some((_, ch)) = cursor.next() else {
            return Err(LexError::new(
                start.line,
                start.column,
                format!(
                    "incomplete heredoc <<{} on line #{}, expected ending marker {}",
                    marker,
                    start.line + 1 + body_newlines,
                    marker
                ),
            ));
        };
        body.push(ch);
        if ch == '\n' {
            body_newlines += 1;
        }
        // Caddy accepts the marker as soon as it appears at the end of the characters read so
        // far, even in the middle of a line; the whitespace check in `finalize_heredoc` then
        // reports the mismatch with the closing marker's indentation.
        if body.ends_with(marker.as_str()) {
            body.truncate(body.len() - marker.len());
            let text = finalize_heredoc(&body, &marker, start.line)?;
            let end_line = start.line + 1 + body_newlines;
            let closing_padding = match body.rfind('\n') {
                Some(index) => body[index + 1..].chars().count(),
                None => body.chars().count(),
            };
            let end_column = closing_padding + marker.chars().count() + 1;
            return Ok(Some((
                Token {
                    kind: TokenKind::Quoted,
                    text,
                    position: start,
                },
                end_line,
                end_column,
            )));
        }
    }
}

/// Strip the closing marker's leading whitespace from every non-blank heredoc content line.
///
/// This mirrors Caddy's `finalizeHeredoc`: blank lines are preserved as empty lines, and a
/// non-blank line whose prefix is not exactly the closing marker's indentation is an error.
fn finalize_heredoc(body: &str, marker: &str, start_line: usize) -> Result<String, LexError> {
    let last_newline = body.rfind('\n');
    let padding = match last_newline {
        Some(index) => &body[index + 1..],
        None => body,
    };
    // Caddy's `Split` of the content up to and including the last newline yields one element per
    // content line plus a trailing empty element, which is dropped. When the body contains no
    // newline at all there are no content lines.
    let lines: Vec<&str> = match last_newline {
        Some(index) => body[..index].split('\n').collect(),
        None => Vec::new(),
    };

    let mut out = String::new();
    for (line_index, line_text) in lines.iter().enumerate() {
        if line_text.is_empty() || *line_text == "\r" {
            out.push('\n');
            continue;
        }
        if !line_text.starts_with(padding) {
            let line = start_line + line_index + 1;
            let clean = line_text.trim_end_matches(['\r', '\n']);
            return Err(LexError::new(
                line,
                1,
                format!(
                    "mismatched leading whitespace in heredoc <<{} on line #{} [{}], expected \
                     whitespace [{}] to match the closing marker",
                    marker, line, clean, padding
                ),
            ));
        }
        out.push_str(&line_text[padding.len()..]);
        out.push('\n');
    }
    // Caddy removes all carriage returns from heredoc content lines (Windows line endings).
    if out.contains('\r') {
        out = out.replace('\r', "");
    }
    if out.ends_with('\n') {
        out.pop();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(input: &str) -> Vec<(TokenKind, String)> {
        lex(input)
            .expect("lexes")
            .into_iter()
            .map(|t| (t.kind, t.text))
            .collect()
    }

    fn lines(input: &str) -> Vec<(usize, TokenKind, String)> {
        lex(input)
            .expect("lexes")
            .into_iter()
            .map(|t| (t.position.line, t.kind, t.text))
            .collect()
    }

    fn error(input: &str) -> LexError {
        lex(input).expect_err("lexing must fail")
    }

    #[test]
    fn lexes_directives_quotes_and_comments() {
        let tokens = texts(":80 {\n\trespond \"hello world\" # trailing\n}\n");
        assert!(tokens.contains(&(TokenKind::Word, ":80".to_string())));
        assert!(tokens.contains(&(TokenKind::Quoted, "hello world".to_string())));
        assert!(!tokens.iter().any(|(_, t)| t == "# trailing"));
        assert_eq!(
            tokens
                .iter()
                .filter(|(k, _)| *k == TokenKind::LeftBrace)
                .count(),
            1
        );
    }

    #[test]
    fn rejects_unterminated_quote_with_position() {
        let error = lex(":80 {\n\trespond \"oops\n}\n").expect_err("unterminated");
        assert_eq!(error.position.line, 2);
        assert!(error.message.contains("unterminated"));
    }

    #[test]
    fn backtick_strings_are_raw() {
        let tokens = texts("respond `line1\nline2`\n");
        assert!(tokens.contains(&(TokenKind::Quoted, "line1\nline2".to_string())));
    }

    #[test]
    fn heredoc_basic() {
        let tokens = texts("heredoc <<EOF\ncontent\nEOF same-line-arg\n");
        assert!(tokens.contains(&(TokenKind::Word, "heredoc".to_string())));
        assert!(tokens.contains(&(TokenKind::Quoted, "content".to_string())));
        // The closing marker line is the heredoc's last line; a following argument keeps it.
        assert!(tokens.contains(&(TokenKind::Word, "same-line-arg".to_string())));
        let lines = lines("heredoc <<EOF\ncontent\nEOF same-line-arg\n");
        assert_eq!(lines[0], (1, TokenKind::Word, "heredoc".to_string()));
        assert_eq!(lines[1], (1, TokenKind::Quoted, "content".to_string()));
        assert_eq!(lines[2], (3, TokenKind::Word, "same-line-arg".to_string()));
    }

    #[test]
    fn heredoc_strips_closing_marker_indentation() {
        let tokens = texts("respond <<EOF\n\tline1\n\t\tline2\n\tEOF\n");
        assert!(
            tokens.contains(&(TokenKind::Quoted, "line1\n\tline2".to_string())),
            "{tokens:?}"
        );
    }

    #[test]
    fn heredoc_keeps_blank_lines() {
        let tokens =
            texts("heredoc <<EOF\nThe next line is blank\n\nThe previous line is blank\nEOF");
        assert!(tokens.contains(&(
            TokenKind::Quoted,
            "The next line is blank\n\nThe previous line is blank".to_string()
        )));
    }

    #[test]
    fn heredoc_empty_bodies() {
        // Closing marker immediately after the announcing line.
        assert!(texts("heredoc <<EOF\nEOF\n").contains(&(TokenKind::Quoted, String::new())));
        // Indented closing marker with no content.
        assert!(texts("heredoc <<EOF\n\t\tEOF same-line-arg\n")
            .contains(&(TokenKind::Quoted, String::new())));
    }

    #[test]
    fn heredoc_marker_may_contain_dashes_and_underscores() {
        let tokens = texts("respond <<VERY-LONG_MARKER\ncontent\nVERY-LONG_MARKER\n");
        assert!(tokens.contains(&(TokenKind::Quoted, "content".to_string())));
    }

    #[test]
    fn heredoc_dash_prefix_is_part_of_the_marker() {
        // Caddy has no shell-style `<<-` strip mode: the marker is literally `-EOF`.
        let tokens = texts("respond <<-EOF\n\tcontent\n\t-EOF\n");
        assert!(tokens.contains(&(TokenKind::Quoted, "content".to_string())));
    }

    #[test]
    fn heredoc_escaped_introducer_is_a_word() {
        let tokens = texts("escaped-heredoc \\<< >>");
        assert!(tokens.contains(&(TokenKind::Word, "<<".to_string())));
    }

    #[test]
    fn angle_brackets_that_are_not_heredocs_are_words() {
        assert!(
            texts("not-a-heredoc <EOF\ncontent\n").contains(&(TokenKind::Word, "<EOF".to_string()))
        );
        assert!(texts("not-a-heredoc <<<EOF content")
            .contains(&(TokenKind::Word, "<<<EOF".to_string())));
        assert!(texts("not-a-heredoc << >>").contains(&(TokenKind::Word, "<<".to_string())));
        assert!(
            texts("not-a-heredoc <<HERE SAME LINE\ncontent\nHERE same-line-arg\n")
                .contains(&(TokenKind::Word, "<<HERE".to_string()))
        );
    }

    #[test]
    fn heredoc_missing_marker_is_rejected() {
        let error = error("not-a-heredoc <<\n");
        assert_eq!(
            error.message,
            "missing opening heredoc marker on line #1; must contain only alphanumeric \
             characters, dashes and underscores; got empty string"
        );
    }

    #[test]
    fn heredoc_too_many_angle_brackets_is_rejected() {
        let error = error("heredoc <<<EOF\ncontent\nEOF\n");
        assert_eq!(
            error.message,
            "too many '<' for heredoc on line #1; only use two, for example <<END"
        );
    }

    #[test]
    fn heredoc_invalid_marker_is_rejected_by_name() {
        let error = error("handle {\n    respond <<END!\n    Hello\n    END!\n}\n");
        assert!(
            error
                .message
                .contains("heredoc marker on line #2 must contain only alphanumeric"),
            "{}",
            error.message
        );
        assert!(error.message.contains("'END!'"), "{}", error.message);
    }

    #[test]
    fn heredoc_incomplete_is_rejected() {
        let error = error("heredoc <<EOF\ncontent\n");
        assert_eq!(
            error.message,
            "incomplete heredoc <<EOF on line #3, expected ending marker EOF"
        );
    }

    #[test]
    fn heredoc_mismatched_whitespace_is_rejected() {
        // Extra indentation on the content relative to the closing marker.
        let extra_indent_error = error("heredoc <<EOF\n\tcontent\n\t\tEOF\n");
        assert_eq!(
            extra_indent_error.message,
            "mismatched leading whitespace in heredoc <<EOF on line #2 [\tcontent], expected \
             whitespace [\t\t] to match the closing marker"
        );
        // A blank line with less indentation than the padding is also an error.
        let blank_line_error = error("heredoc <<EOF\n\t\tline\n\t\n\t\tEOF\n");
        assert_eq!(
            blank_line_error.message,
            "mismatched leading whitespace in heredoc <<EOF on line #3 [\t], expected \
             whitespace [\t\t] to match the closing marker"
        );
    }

    #[test]
    fn heredoc_marker_substring_terminates_early_and_reports_mismatch() {
        // Mirrors upstream `heredoc_incomplete.caddyfiletest`: the `EOF` inside the comment ends
        // the heredoc, so the text before it becomes the closing marker's "indentation".
        let input = ":80\n\nhandle {\n    respond <<EOF\n    Hello\n# missing EOF marker\n}\n";
        let error = error(input);
        assert_eq!(
            error.message,
            "mismatched leading whitespace in heredoc <<EOF on line #5 [    Hello], expected \
             whitespace [# missing ] to match the closing marker"
        );
    }

    #[test]
    fn heredoc_line_numbers_survive_multiple_content_lines() {
        let lines = lines(
            "prev-line\nheredoc <<EOF\n\tmulti\n\tline\n\tcontent\nEOF same-line-arg\nnext-line\n",
        );
        assert_eq!(lines[0], (1, TokenKind::Word, "prev-line".to_string()));
        assert_eq!(lines[1], (1, TokenKind::Newline, "\n".to_string()));
        assert_eq!(lines[2], (2, TokenKind::Word, "heredoc".to_string()));
        assert_eq!(
            lines[3],
            (
                2,
                TokenKind::Quoted,
                "\tmulti\n\tline\n\tcontent".to_string()
            )
        );
        assert_eq!(lines[4], (6, TokenKind::Word, "same-line-arg".to_string()));
        assert_eq!(lines[5], (6, TokenKind::Newline, "\n".to_string()));
        assert_eq!(lines[6], (7, TokenKind::Word, "next-line".to_string()));
    }

    #[test]
    fn heredoc_handles_crlf() {
        let tokens = texts("respond <<EOF\r\n\tcontent\r\n\tEOF\r\n");
        assert!(tokens.contains(&(TokenKind::Quoted, "content".to_string())));
    }

    #[test]
    fn backslash_continuation_suppresses_newline() {
        let tokens = lex("respond ok \\\ncontinued\n").expect("lexes");
        let words: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Word)
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(words, vec!["respond", "ok", "continued"]);
        assert_eq!(
            tokens
                .iter()
                .filter(|t| t.kind == TokenKind::Newline)
                .count(),
            1
        );
        // The continued token is reported on the line it physically appears on.
        let continued = tokens
            .iter()
            .find(|t| t.text == "continued")
            .expect("continued token");
        assert_eq!(continued.position.line, 2);
    }

    #[test]
    fn escaped_quote_in_unquoted_word_retains_backslash() {
        let tokens = texts("foo\\\"bar\n");
        assert!(tokens.contains(&(TokenKind::Word, "foo\\\"bar".to_string())));
    }

    #[test]
    fn heredoc_tab_after_marker_is_an_invalid_marker() {
        // A space after the marker makes it an ordinary token, but a tab is collected into the marker
        // and rejected, matching Caddy.
        let tokens = texts("not-a-heredoc <<HERE SAME LINE\ncontent\nHERE same-line-arg\n");
        assert!(tokens.contains(&(TokenKind::Word, "<<HERE".to_string())));

        let error = error("heredoc <<EOF\t\ncontent\nEOF\n");
        assert!(
            error
                .message
                .contains("heredoc marker on line #1 must contain only"),
            "{}",
            error.message
        );
        assert!(error.message.contains("'EOF\t'"), "{}", error.message);
    }

    #[test]
    fn heredoc_blank_line_indentation_rules() {
        // A carriage-return-only blank line is preserved as an empty line, and a tab-only blank
        // line must still match the closing marker indentation when it carries whitespace.
        let tokens = texts("heredoc <<EOF\nOne tab indented line\n\nAnother line\nEOF");
        assert!(tokens.contains(&(
            TokenKind::Quoted,
            "One tab indented line\n\nAnother line".to_string()
        )));

        let tokens = texts("heredoc <<EOF\nThe next line is blank with one tab\n\t\nThe previous line is blank with one tab\nEOF");
        assert!(tokens.contains(&(
            TokenKind::Quoted,
            "The next line is blank with one tab\n\t\nThe previous line is blank with one tab"
                .to_string()
        )));

        let error = error("heredoc <<EOF\n\t\tThe next line is blank with one tab less\n\t\n\t\tThe previous line\n\t\tEOF\n");
        assert_eq!(
            error.message,
            "mismatched leading whitespace in heredoc <<EOF on line #3 [\t], expected whitespace \
         [\t\t] to match the closing marker"
        );
    }

    #[test]
    fn heredoc_body_may_contain_braces_and_quotes() {
        let tokens = texts("respond <<EOF\n{\"json\": true}\nEOF\n");
        assert!(tokens.contains(&(TokenKind::Quoted, "{\"json\": true}".to_string())));
    }
    #[test]
    fn brace_delimited_placeholders_are_single_words() {
        // Caddy does not tokenize braces; `{...}` runs are ordinary words.
        let tokens = texts("header_up Host {host}\n");
        assert!(
            tokens.contains(&(TokenKind::Word, "{host}".to_string())),
            "{tokens:?}"
        );
        let tokens = texts("respond {block}\n");
        assert!(tokens.contains(&(TokenKind::Word, "{block}".to_string())));
        let tokens = texts("respond {args[0]} {args[:]}\n");
        assert!(tokens.contains(&(TokenKind::Word, "{args[0]}".to_string())));
        assert!(tokens.contains(&(TokenKind::Word, "{args[:]}".to_string())));
        // Placeholders may be embedded in a larger word.
        let tokens = texts("root /srv/{args[0]}/www\n");
        assert!(
            tokens.contains(&(TokenKind::Word, "/srv/{args[0]}/www".to_string())),
            "{tokens:?}"
        );
        let tokens = texts("header X-Test prefix-{http.request.host}\n");
        assert!(tokens.contains(&(TokenKind::Word, "prefix-{http.request.host}".to_string())));
    }

    #[test]
    fn structural_braces_are_still_recognised() {
        let tokens = texts(":80 {\n respond ok\n}\n");
        assert_eq!(
            tokens
                .iter()
                .filter(|(k, _)| *k == TokenKind::LeftBrace)
                .count(),
            1
        );
        assert_eq!(
            tokens
                .iter()
                .filter(|(k, _)| *k == TokenKind::RightBrace)
                .count(),
            1
        );
        // Empty block pair.
        let tokens = texts(":80 {}\n");
        assert_eq!(
            tokens
                .iter()
                .filter(|(k, _)| *k == TokenKind::LeftBrace)
                .count(),
            1
        );
        assert_eq!(
            tokens
                .iter()
                .filter(|(k, _)| *k == TokenKind::RightBrace)
                .count(),
            1
        );
    }
}
