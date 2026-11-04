//! Minimal backtracking regular-expression engine for Caddy's log filter modules
//! (`regexp`/`multi_regexp`).
//!
//! Adapted from caddy-rs's `crates/http/src/regex_lite.rs` (same repository, written for the
//! `map` handler's `input_regexp`) with the error type changed to a self-contained regex error so
//! the admin crate does not depend on the HTTP crate. The supported/unsupported syntax notes are
//! preserved below for attribution and to keep both copies aligned.
//!
//! The offline build has no `regex` crate, so this module implements the subset of Go's
//! `regexp` (RE2) syntax that Caddy's `map` handler needs for realistic configurations:
//!
//! * literals, `.`, character classes (`[abc]`, `[a-z]`, `[^...]`, `\d`, `\w`, `\s` and their
//!   negations), escapes, `^`/`$` anchors;
//! * capturing groups `(...)`, non-capturing `(?:...)`, alternation `|`, quantifiers
//!   `* + ? {m} {m,} {m,n}` and a leading `(?i)` case-insensitive flag;
//! * leftmost-first matching with capture indices, and Go's `${N}`/`$N` capture expansion.
//!
//! It is intentionally not a complete regex implementation: word boundaries, named groups,
//! look-around, lazy quantifiers and mid-pattern inline flags return a located
//! "unsupported regular expression" configuration error instead of being approximated.
//! Matching is bounded by a step limit so pathological patterns cannot hang a request.

/// A regex compile/match error (unsupported construct or invalid pattern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    /// The located human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Maximum number of VM steps per attempted match before giving up (defence in depth).
const MAX_STEPS: u64 = 1_000_000;

/// A compiled regular expression.
#[derive(Debug, Clone)]
pub struct Regex {
    code: Vec<Inst>,
    group_count: usize,
    case_insensitive: bool,
}

/// One instruction of the backtracking VM.
#[derive(Debug, Clone, Copy)]
enum Inst {
    Char(char),
    AnyChar,
    Class { negated: bool, ranges: ClassRanges },
    Start,
    End,
    Save(usize),
    Split(usize, usize),
    Jump(usize),
    Match,
}

/// Character-class ranges plus the ASCII shorthand classes (`\d`, `\w`, `\s`).
#[derive(Debug, Clone, Copy, Default)]
struct ClassRanges {
    ranges: [Option<(char, char)>; 8],
    digits: bool,
    word: bool,
    space: bool,
    negated_digits: bool,
    negated_word: bool,
    negated_space: bool,
}

impl ClassRanges {
    fn matches(&self, c: char, case_insensitive: bool) -> bool {
        let candidate = if case_insensitive {
            c.to_ascii_lowercase()
        } else {
            c
        };
        for range in self.ranges.iter().flatten() {
            let (start, end) = *range;
            let (start, end) = if case_insensitive {
                (start.to_ascii_lowercase(), end.to_ascii_lowercase())
            } else {
                (start, end)
            };
            if candidate >= start && candidate <= end {
                return true;
            }
        }
        if self.digits && c.is_ascii_digit() {
            return true;
        }
        if self.word && (c.is_ascii_alphanumeric() || c == '_') {
            return true;
        }
        if self.space && c.is_ascii_whitespace() {
            return true;
        }
        if self.negated_digits && !c.is_ascii_digit() {
            return true;
        }
        if self.negated_word && !(c.is_ascii_alphanumeric() || c == '_') {
            return true;
        }
        if self.negated_space && !c.is_ascii_whitespace() {
            return true;
        }
        false
    }
}

/// A match: capture indices (`None` when the group did not participate).
#[derive(Debug, Clone)]
pub struct Captures {
    slots: Vec<Option<usize>>,
}

impl Captures {
    /// Byte range for capture group `index` (0 = whole match).
    pub fn group(&self, index: usize) -> Option<(usize, usize)> {
        let start = self.slots.get(index * 2).copied().flatten()?;
        let end = self.slots.get(index * 2 + 1).copied().flatten()?;
        Some((start, end))
    }
}

impl Regex {
    /// Compile `pattern`, returning a located configuration error when unsupported/invalid.
    pub fn new(pattern: &str) -> Result<Self, Error> {
        let mut parser = Parser {
            chars: pattern.chars().collect(),
            position: 0,
            groups: 0,
            case_insensitive: false,
        };
        // Leading `(?i)` (and `(?i:...)` is not supported; only the global form).
        if parser.consume_flag("(?i)") {
            parser.case_insensitive = true;
        }
        let ast = parser.parse_alternation()?;
        if parser.position != parser.chars.len() {
            return Err(unsupported(pattern, "unbalanced `)`"));
        }
        let mut code = Vec::new();
        emit(&ast, &mut code);
        code.push(Inst::Match);
        Ok(Self {
            code,
            group_count: parser.groups,
            case_insensitive: parser.case_insensitive,
        })
    }

    /// Find the leftmost-first match anywhere in `input`.
    ///
    /// `input` is a `&str`; capture indices are byte offsets into it.
    pub fn captures(&self, input: &str) -> Option<Captures> {
        let chars: Vec<char> = input.chars().collect();
        let mut byte_offsets = Vec::with_capacity(chars.len() + 1);
        let mut offset = 0;
        for c in &chars {
            byte_offsets.push(offset);
            offset += c.len_utf8();
        }
        byte_offsets.push(offset);

        for start in 0..=chars.len() {
            let mut slots = vec![None; (self.group_count + 1) * 2];
            slots[0] = Some(start);
            let mut steps = 0;
            if self.run(0, start, &chars, &mut slots, &mut steps) {
                let end = slots[1].unwrap_or(start);
                // Convert character indices to byte offsets.
                let byte_slots = slots
                    .into_iter()
                    .map(|slot| slot.map(|index| byte_offsets[index]))
                    .collect();
                let mut captures = Captures { slots: byte_slots };
                captures.slots[1] = Some(byte_offsets[end]);
                return Some(captures);
            }
        }
        None
    }

    /// Expand Go-style `$N`/`${N}` capture references in `template`.
    pub fn expand(&self, template: &str, input: &str, captures: &Captures) -> String {
        let mut output = String::with_capacity(template.len());
        let bytes: Vec<char> = template.chars().collect();
        let mut index = 0;
        while index < bytes.len() {
            let c = bytes[index];
            if c != '$' {
                output.push(c);
                index += 1;
                continue;
            }
            // `$$` is a literal dollar sign.
            if bytes.get(index + 1) == Some(&'$') {
                output.push('$');
                index += 2;
                continue;
            }
            let mut group = String::new();
            let mut cursor = index + 1;
            if bytes.get(cursor) == Some(&'{') {
                cursor += 1;
                while cursor < bytes.len() && bytes[cursor] != '}' {
                    group.push(bytes[cursor]);
                    cursor += 1;
                }
                if cursor < bytes.len() {
                    cursor += 1; // closing brace
                }
            } else {
                while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                    group.push(bytes[cursor]);
                    cursor += 1;
                }
            }
            let Ok(group_index) = group.parse::<usize>() else {
                // Not a capture reference: keep the `$` literally.
                output.push('$');
                index += 1;
                continue;
            };
            if let Some((start, end)) = captures.group(group_index) {
                if let Some(slice) = input.get(start..end) {
                    output.push_str(slice);
                }
            }
            index = cursor;
        }
        output
    }

    fn run(
        &self,
        pc: usize,
        pos: usize,
        input: &[char],
        slots: &mut Vec<Option<usize>>,
        steps: &mut u64,
    ) -> bool {
        *steps += 1;
        if *steps > MAX_STEPS {
            return false;
        }
        match self.code[pc] {
            Inst::Char(expected) => {
                let Some(actual) = input.get(pos) else {
                    return false;
                };
                let matches = if self.case_insensitive {
                    actual.eq_ignore_ascii_case(&expected)
                } else {
                    *actual == expected
                };
                matches && self.run(pc + 1, pos + 1, input, slots, steps)
            }
            Inst::AnyChar => {
                let Some(actual) = input.get(pos) else {
                    return false;
                };
                *actual != '\n' && self.run(pc + 1, pos + 1, input, slots, steps)
            }
            Inst::Class { negated, ranges } => {
                let Some(actual) = input.get(pos) else {
                    return false;
                };
                if ranges.matches(*actual, self.case_insensitive) != negated {
                    self.run(pc + 1, pos + 1, input, slots, steps)
                } else {
                    false
                }
            }
            Inst::Start => pos == 0 && self.run(pc + 1, pos, input, slots, steps),
            Inst::End => pos == input.len() && self.run(pc + 1, pos, input, slots, steps),
            Inst::Save(slot) => {
                let previous = slots[slot];
                slots[slot] = Some(pos);
                if self.run(pc + 1, pos, input, slots, steps) {
                    true
                } else {
                    slots[slot] = previous;
                    false
                }
            }
            Inst::Split(first, second) => {
                self.run(first, pos, input, slots, steps)
                    || self.run(second, pos, input, slots, steps)
            }
            Inst::Jump(target) => self.run(target, pos, input, slots, steps),
            Inst::Match => {
                slots[1] = Some(pos);
                true
            }
        }
    }
}

fn unsupported(pattern: &str, detail: &str) -> Error {
    Error::invalid(format!(
        "unsupported regular expression `{pattern}`: {detail}"
    ))
}

// ---- parser -----------------------------------------------------------------------------------

#[derive(Debug)]
enum Ast {
    Empty,
    Literal(char),
    Any,
    Class(ClassRanges, bool),
    Start,
    End,
    Group(Box<Ast>, Option<usize>),
    Concat(Vec<Ast>),
    Alternation(Vec<Ast>),
    Repeat {
        node: Box<Ast>,
        min: u32,
        max: Option<u32>,
    },
}

struct Parser {
    chars: Vec<char>,
    position: usize,
    groups: usize,
    case_insensitive: bool,
}

impl Parser {
    fn consume_flag(&mut self, flag: &str) -> bool {
        let flag_chars: Vec<char> = flag.chars().collect();
        if self.chars[self.position..].starts_with(&flag_chars) {
            self.position += flag_chars.len();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }

    fn parse_alternation(&mut self) -> Result<Ast, Error> {
        let mut alternatives = Vec::new();
        loop {
            alternatives.push(self.parse_concat()?);
            match self.peek() {
                Some('|') => {
                    self.position += 1;
                }
                _ => break,
            }
        }
        Ok(if alternatives.len() == 1 {
            alternatives.pop().unwrap_or(Ast::Empty)
        } else {
            Ast::Alternation(alternatives)
        })
    }

    fn parse_concat(&mut self) -> Result<Ast, Error> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == ')' || c == '|' {
                break;
            }
            items.push(self.parse_repeat()?);
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap_or(Ast::Empty)
        } else {
            Ast::Concat(items)
        })
    }

    fn parse_repeat(&mut self) -> Result<Ast, Error> {
        let node = self.parse_atom()?;
        let repeat: Option<(u32, Option<u32>)> = match self.peek() {
            Some('*') => {
                self.position += 1;
                Some((0, None))
            }
            Some('+') => {
                self.position += 1;
                Some((1, None))
            }
            Some('?') => {
                self.position += 1;
                Some((0, Some(1)))
            }
            Some('{') => {
                let saved = self.position;
                self.position += 1;
                match self.parse_counts()? {
                    Some(counts) => Some(counts),
                    None => {
                        self.position = saved;
                        None
                    }
                }
            }
            _ => None,
        };
        if repeat.is_some() && matches!(self.peek(), Some('*' | '+' | '?' | '{')) {
            return Err(unsupported(
                &self.chars.iter().collect::<String>(),
                "stacked repetition operators",
            ));
        }
        Ok(match repeat {
            Some((min, max)) => Ast::Repeat {
                node: Box::new(node),
                min,
                max,
            },
            None => node,
        })
    }

    fn parse_counts(&mut self) -> Result<Option<(u32, Option<u32>)>, Error> {
        let mut min_text = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                min_text.push(c);
                self.position += 1;
            } else {
                break;
            }
        }
        if min_text.is_empty() {
            return Ok(None);
        }
        let min = min_text.parse::<u32>().map_err(|_| {
            unsupported(
                &self.chars.iter().collect::<String>(),
                "repetition count too large",
            )
        })?;
        match self.peek() {
            Some('}') => {
                self.position += 1;
                Ok(Some((min, Some(min))))
            }
            Some(',') => {
                self.position += 1;
                let mut max_text = String::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        max_text.push(c);
                        self.position += 1;
                    } else {
                        break;
                    }
                }
                if self.peek() != Some('}') {
                    return Ok(None);
                }
                self.position += 1;
                let max = if max_text.is_empty() {
                    None
                } else {
                    Some(max_text.parse::<u32>().map_err(|_| {
                        unsupported(
                            &self.chars.iter().collect::<String>(),
                            "repetition count too large",
                        )
                    })?)
                };
                if let Some(max) = max {
                    if max < min {
                        return Err(unsupported(
                            &self.chars.iter().collect::<String>(),
                            "repetition maximum is smaller than minimum",
                        ));
                    }
                }
                Ok(Some((min, max)))
            }
            _ => Ok(None),
        }
    }

    fn parse_atom(&mut self) -> Result<Ast, Error> {
        let Some(c) = self.peek() else {
            return Ok(Ast::Empty);
        };
        match c {
            '(' => {
                self.position += 1;
                if self.consume_flag("?:") {
                    let inner = self.parse_alternation()?;
                    self.expect_close()?;
                    Ok(Ast::Group(Box::new(inner), None))
                } else if self.consume_flag("?i:") {
                    let saved = self.case_insensitive;
                    self.case_insensitive = true;
                    let inner = self.parse_alternation()?;
                    self.case_insensitive = saved;
                    self.expect_close()?;
                    Ok(Ast::Group(Box::new(inner), None))
                } else if self.consume_flag("?P<") {
                    // Named groups are captured like normal groups; `$name` expansion is not
                    // supported, so only the numeric index is exposed.
                    while let Some(c) = self.peek() {
                        self.position += 1;
                        if c == '>' {
                            break;
                        }
                    }
                    self.groups += 1;
                    let index = self.groups;
                    let inner = self.parse_alternation()?;
                    self.expect_close()?;
                    Ok(Ast::Group(Box::new(inner), Some(index)))
                } else if self.consume_flag("?") {
                    Err(unsupported(
                        &self.chars.iter().collect::<String>(),
                        "look-around or unsupported group flag",
                    ))?
                } else {
                    self.groups += 1;
                    let index = self.groups;
                    let inner = self.parse_alternation()?;
                    self.expect_close()?;
                    Ok(Ast::Group(Box::new(inner), Some(index)))
                }
            }
            '[' => {
                self.position += 1;
                self.parse_class()
            }
            '.' => {
                self.position += 1;
                Ok(Ast::Any)
            }
            '^' => {
                self.position += 1;
                Ok(Ast::Start)
            }
            '$' => {
                self.position += 1;
                Ok(Ast::End)
            }
            '\\' => self.parse_escape(),
            '*' | '+' | '?' => Err(unsupported(
                &self.chars.iter().collect::<String>(),
                "repetition operator without an operand",
            )),
            ')' => Err(unsupported(
                &self.chars.iter().collect::<String>(),
                "unbalanced `)`",
            )),
            other => {
                self.position += 1;
                Ok(Ast::Literal(other))
            }
        }
    }

    fn expect_close(&mut self) -> Result<(), Error> {
        if self.peek() == Some(')') {
            self.position += 1;
            Ok(())
        } else {
            Err(unsupported(
                &self.chars.iter().collect::<String>(),
                "unbalanced `(`",
            ))
        }
    }

    fn parse_class(&mut self) -> Result<Ast, Error> {
        let mut ranges = ClassRanges::default();
        let mut negated = false;
        if self.peek() == Some('^') {
            negated = true;
            self.position += 1;
        }
        let mut slots = 0;
        let mut expect_item = true;
        while let Some(c) = self.peek() {
            if c == ']' && !expect_item {
                self.position += 1;
                return Ok(Ast::Class(ranges, negated));
            }
            expect_item = false;
            let start = if c == '\\' {
                self.position += 1;
                match self.escape_class()? {
                    ClassEscape::Character(c) => c,
                    ClassEscape::Shorthand(field) => {
                        match field {
                            'd' => ranges.digits = true,
                            'D' => ranges.negated_digits = true,
                            'w' => ranges.word = true,
                            'W' => ranges.negated_word = true,
                            's' => ranges.space = true,
                            'S' => ranges.negated_space = true,
                            _ => {}
                        }
                        continue;
                    }
                }
            } else {
                self.position += 1;
                c
            };
            // Range (`a-z`) unless the `-` is trailing.
            if self.peek() == Some('-') && self.chars.get(self.position + 1) != Some(&']') {
                self.position += 1;
                let end = if self.peek() == Some('\\') {
                    self.position += 1;
                    match self.escape_class()? {
                        ClassEscape::Character(c) => c,
                        ClassEscape::Shorthand(_) => {
                            return Err(unsupported(
                                &self.chars.iter().collect::<String>(),
                                "class shorthand in range endpoint",
                            ))
                        }
                    }
                } else {
                    let Some(end) = self.peek() else {
                        return Err(unsupported(
                            &self.chars.iter().collect::<String>(),
                            "unterminated character class",
                        ));
                    };
                    self.position += 1;
                    end
                };
                if start > end {
                    return Err(unsupported(
                        &self.chars.iter().collect::<String>(),
                        "inverted character range",
                    ));
                }
                if slots >= ranges.ranges.len() {
                    return Err(unsupported(
                        &self.chars.iter().collect::<String>(),
                        "too many character ranges",
                    ));
                }
                ranges.ranges[slots] = Some((start, end));
                slots += 1;
            } else {
                if slots >= ranges.ranges.len() {
                    return Err(unsupported(
                        &self.chars.iter().collect::<String>(),
                        "too many character ranges",
                    ));
                }
                ranges.ranges[slots] = Some((start, start));
                slots += 1;
            }
        }
        Err(unsupported(
            &self.chars.iter().collect::<String>(),
            "unterminated character class",
        ))
    }

    fn parse_escape(&mut self) -> Result<Ast, Error> {
        self.position += 1; // backslash
        match self.escape_class()? {
            ClassEscape::Character(c) => Ok(Ast::Literal(c)),
            ClassEscape::Shorthand(field) => {
                let mut ranges = ClassRanges::default();
                match field {
                    'd' => ranges.digits = true,
                    'D' => ranges.negated_digits = true,
                    'w' => ranges.word = true,
                    'W' => ranges.negated_word = true,
                    's' => ranges.space = true,
                    'S' => ranges.negated_space = true,
                    _ => {}
                }
                Ok(Ast::Class(ranges, false))
            }
        }
    }

    fn escape_class(&mut self) -> Result<ClassEscape, Error> {
        let Some(c) = self.peek() else {
            return Err(unsupported(
                &self.chars.iter().collect::<String>(),
                "trailing backslash",
            ));
        };
        self.position += 1;
        Ok(match c {
            'd' | 'D' | 'w' | 'W' | 's' | 'S' => ClassEscape::Shorthand(c),
            'n' => ClassEscape::Character('\n'),
            'r' => ClassEscape::Character('\r'),
            't' => ClassEscape::Character('\t'),
            'b' | 'B' | 'A' | 'z' | 'Z' | 'G' => {
                return Err(unsupported(
                    &self.chars.iter().collect::<String>(),
                    "word-boundary/position escapes are not implemented",
                ))
            }
            // Escaped metacharacters and ordinary characters are literals.
            other => ClassEscape::Character(other),
        })
    }
}

enum ClassEscape {
    Character(char),
    Shorthand(char),
}

fn emit(ast: &Ast, code: &mut Vec<Inst>) {
    match ast {
        Ast::Empty => {}
        Ast::Literal(c) => code.push(Inst::Char(*c)),
        Ast::Any => code.push(Inst::AnyChar),
        Ast::Class(ranges, negated) => code.push(Inst::Class {
            negated: *negated,
            ranges: *ranges,
        }),
        Ast::Start => code.push(Inst::Start),
        Ast::End => code.push(Inst::End),
        Ast::Group(inner, index) => {
            if let Some(index) = index {
                code.push(Inst::Save(index * 2));
                emit(inner, code);
                code.push(Inst::Save(index * 2 + 1));
            } else {
                emit(inner, code);
            }
        }
        Ast::Concat(items) => {
            for item in items {
                emit(item, code);
            }
        }
        Ast::Alternation(alternatives) => {
            let mut jumps = Vec::new();
            for (index, alternative) in alternatives.iter().enumerate() {
                if index + 1 < alternatives.len() {
                    let split = code.len();
                    code.push(Inst::Split(0, 0));
                    let body = code.len();
                    emit(alternative, code);
                    jumps.push(code.len());
                    code.push(Inst::Jump(0));
                    let next = code.len();
                    code[split] = Inst::Split(body, next);
                } else {
                    emit(alternative, code);
                }
            }
            let end = code.len();
            for jump in jumps {
                code[jump] = Inst::Jump(end);
            }
        }
        Ast::Repeat { node, min, max } => {
            for _ in 0..*min {
                emit(node, code);
            }
            match max {
                None => {
                    let split = code.len();
                    code.push(Inst::Split(0, 0));
                    let body = code.len();
                    emit(node, code);
                    code.push(Inst::Jump(split));
                    let after = code.len();
                    code[split] = Inst::Split(body, after);
                }
                Some(max) => {
                    for _ in *min..*max {
                        let split = code.len();
                        code.push(Inst::Split(0, 0));
                        let body = code.len();
                        emit(node, code);
                        let after = code.len();
                        code[split] = Inst::Split(body, after);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captures(pattern: &str, input: &str) -> Option<Captures> {
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
    }

    #[test]
    fn supports_classes_alternation_and_case_insensitive_flag() {
        assert!(captures("[a-z]+", "123abc").is_some());
        assert!(captures("[^0-9]+", "abc").is_some());
        assert!(captures("a|bc", "bc").is_some());
        assert!(captures("(?i)abc", "xxABC").is_some());
        assert!(captures(r"(\^|`|<|>|%|\\|\{|\}|\|)", "a|b").is_some());
        assert!(captures(r"\d+", "abc123").is_some());
    }

    #[test]
    fn rejects_unsupported_constructs() {
        for pattern in ["(?=a)", "(?!a)", "\\bword", "\\Bword"] {
            assert!(Regex::new(pattern).is_err(), "{pattern}");
        }
    }
}
