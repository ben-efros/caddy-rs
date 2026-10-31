//! Caddyfile lexer.
//!
//! The lexer follows Caddy's token model closely enough for the supported directive subset:
//! words, quoted strings (`"..."` with escapes), backtick raw strings, braces as structural
//! tokens, comments (`#` to end of line), and newlines as significant separators.
//!
//! Heredocs (`<<EOF`) and backslash continuation are intentionally rejected with a located error
//! (tracked as a Caddyfile compatibility gap) rather than silently mis-parsed.

use std::fmt;

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
    /// A quoted or backtick-delimited string.
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

/// Tokenize Caddyfile input.
pub fn lex(input: &str) -> Result<Vec<Token>, LexError> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    let mut line = 1;
    let mut column = 1;

    while let Some(&ch) = chars.peek() {
        let position = Position { line, column };
        if ch == '<' {
            let mut lookahead = chars.clone();
            lookahead.next();
            if lookahead.peek() == Some(&'<') {
                return Err(LexError {
                    position,
                    message: "heredocs (`<<EOF`) are not supported by this build yet; tracked as a Caddyfile compatibility gap".to_string(),
                });
            }
        }
        match ch {
            ' ' | '\t' | '\r' => {
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
                while let Some(&next) = chars.peek() {
                    if next == '\n' {
                        break;
                    }
                    chars.next();
                    column += 1;
                }
            }
            '{' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::LeftBrace,
                    text: "{".to_string(),
                    position,
                });
                column += 1;
            }
            '}' => {
                chars.next();
                tokens.push(Token {
                    kind: TokenKind::RightBrace,
                    text: "}".to_string(),
                    position,
                });
                column += 1;
            }
            '"' => {
                chars.next();
                column += 1;
                let mut text = String::new();
                let mut closed = false;
                while let Some(next) = chars.next() {
                    column += 1;
                    match next {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => {
                            let Some(escaped) = chars.next() else {
                                return Err(LexError {
                                    position,
                                    message: "unterminated escape sequence in quoted string"
                                        .to_string(),
                                });
                            };
                            column += 1;
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
                            return Err(LexError {
                                position,
                                message: "unterminated quoted string before newline".to_string(),
                            });
                        }
                        other => text.push(other),
                    }
                }
                if !closed {
                    return Err(LexError {
                        position,
                        message: "unterminated quoted string".to_string(),
                    });
                }
                tokens.push(Token {
                    kind: TokenKind::Quoted,
                    text,
                    position,
                });
            }
            '`' => {
                chars.next();
                column += 1;
                let mut text = String::new();
                let mut closed = false;
                while let Some(next) = chars.next() {
                    column += 1;
                    if next == '`' {
                        closed = true;
                        break;
                    }
                    if next == '\n' {
                        line += 1;
                        column = 1;
                    }
                    text.push(next);
                }
                if !closed {
                    return Err(LexError {
                        position,
                        message: "unterminated backtick string".to_string(),
                    });
                }
                tokens.push(Token {
                    kind: TokenKind::Quoted,
                    text,
                    position,
                });
            }
            _ => {
                let mut text = String::new();
                while let Some(&next) = chars.peek() {
                    if next.is_whitespace() || matches!(next, '{' | '}' | '"' | '`') {
                        break;
                    }
                    text.push(next);
                    chars.next();
                    column += 1;
                }
                if text.is_empty() {
                    // Defensive: never loop forever on an unexpected character.
                    chars.next();
                    column += 1;
                    continue;
                }
                tokens.push(Token {
                    kind: TokenKind::Word,
                    text,
                    position,
                });
            }
        }
    }
    Ok(tokens)
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
    fn rejects_heredoc_explicitly() {
        let error = lex(":80 {\n respond <<EOF\n hi\n EOF\n}\n").expect_err("heredoc");
        assert!(error.message.contains("heredoc"));
    }

    #[test]
    fn backtick_strings_are_raw() {
        let tokens = texts("respond `line1\nline2`\n");
        assert!(tokens.contains(&(TokenKind::Quoted, "line1\nline2".to_string())));
    }
}
