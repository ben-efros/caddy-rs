//! T-COMPAT-012: deterministic property/mutation tests for the Caddyfile adapter.
//!
//! Property under test: for *any* input, [`caddy_rs_config::adapt`] (and the byte-oriented
//! [`caddy_rs_core::ConfigAdapter`] impl) returns either `Ok` with a JSON object or a located
//! error. It must never panic, hang, or allocate without bound.
//!
//! Determinism: all inputs are produced by a seeded 64-bit LCG implemented in this file. No
//! external fuzzing crate (and no randomness from the environment) is used, so a failure is
//! exactly reproducible from the seed printed in the panic message. The suite is bounded to
//! well under 5,000 cases and small inputs so it stays CI-fast.
//!
//! Hang detection: every case runs on a short-lived worker thread and is awaited with a timeout.
//! A hang fails with the offending input printed; the default libtest process would otherwise
//! only time out at the CI level with no reproducer.
//!
//! Defect policy: any case that panics is reported with its input so it can be copied into
//! [`REGRESSION_CORPUS`]. That corpus is always executed (panics/hangs fail the test), so a fixed
//! defect cannot silently regress, and a known-bad input keeps its reproducer in-tree.
//!
//! Re-run just this file:
//! `CARGO_TARGET_DIR=... cargo test --offline -p caddy-rs-config --test adapter_fuzz`

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use caddy_rs_config::{adapt, CaddyfileAdapter};
use caddy_rs_core::ConfigAdapter;
use serde_json::Value;

/// Per-case watchdog. Generous for a bound input on a debug build; a true hang trips it.
const CASE_TIMEOUT: Duration = Duration::from_secs(5);

/// Worker stack size. Inputs here are bounded to a few KiB, so this is far above what the
/// recursive-descent parser needs for them; an overflow would abort the whole process instead of
/// failing one case, which is why generation is size-bounded.
const CASE_STACK_SIZE: usize = 2 * 1024 * 1024;

// -------------------------------------------------------------------------------------------------
// Deterministic LCG
// -------------------------------------------------------------------------------------------------

/// Numerical Recipes 64-bit LCG. Deterministic across platforms and Rust versions.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn below(&mut self, upper: usize) -> usize {
        assert!(upper > 0, "below(0) has no result");
        (self.next_u64() % upper as u64) as usize
    }

    fn range(&mut self, low: usize, high: usize) -> usize {
        assert!(low < high, "empty range {low}..{high}");
        low + self.below(high - low)
    }

    fn coin(&mut self, percent: u64) -> bool {
        self.next_u64() % 100 < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        assert!(!items.is_empty(), "cannot pick from an empty slice");
        &items[self.below(items.len())]
    }
}

// -------------------------------------------------------------------------------------------------
// Guarded case execution
// -------------------------------------------------------------------------------------------------

enum Outcome {
    Ok(Value),
    Err(String),
    Panic(String),
}

/// Run one UTF-8 input through the adapter with panic and hang containment.
fn check_str(input: &str) {
    let owned = input.to_string();
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name("adapter-fuzz-case".to_string())
        .stack_size(CASE_STACK_SIZE)
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| match adapt(&owned) {
                Ok(adapted) => Outcome::Ok(adapted.config),
                Err(error) => Outcome::Err(error.to_string()),
            }));
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(payload) => Outcome::Panic(panic_message(payload)),
            };
            // The receiver may have gone away after a timeout; ignore the send error.
            let _ = sender.send(outcome);
        })
        .expect("spawn fuzz worker thread");

    match receiver.recv_timeout(CASE_TIMEOUT) {
        Ok(Outcome::Ok(config)) => {
            assert!(
                config.is_object(),
                "adapter returned non-object JSON {config} for input {:?}",
                input
            );
        }
        Ok(Outcome::Err(message)) => {
            assert!(
                !message.is_empty(),
                "adapter returned an empty error message for input {input:?}"
            );
            // Every error from `adapt(&str)` goes through parse_error/adapter_error, which prefix
            // the source position. A located error is the compatibility contract for malformed
            // input (no silent acceptance).
            assert!(
                message.contains("Caddyfile line"),
                "adapter error is not located (no line number): {message:?} for input {input:?}"
            );
        }
        Ok(Outcome::Panic(message)) => {
            panic!("adapter panicked ({message}) on input {input:?}");
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "adapter did not finish within {CASE_TIMEOUT:?} on input {input:?} \
                 (possible infinite loop / hang)"
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("adapter worker died (stack overflow or abort) on input {input:?}");
        }
    }
}

/// Same property, but through the byte-oriented adapter (exercises the UTF-8 rejection path).
fn check_bytes(input: &[u8]) {
    let owned = input.to_vec();
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name("adapter-fuzz-bytes".to_string())
        .stack_size(CASE_STACK_SIZE)
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| match CaddyfileAdapter.adapt(&owned) {
                Ok(adapted) => Outcome::Ok(adapted.config),
                Err(error) => Outcome::Err(error.to_string()),
            }));
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(payload) => Outcome::Panic(panic_message(payload)),
            };
            let _ = sender.send(outcome);
        })
        .expect("spawn fuzz worker thread");

    match receiver.recv_timeout(CASE_TIMEOUT) {
        Ok(Outcome::Ok(config)) => assert!(
            config.is_object(),
            "byte adapter returned non-object JSON {config} for input {input:?}"
        ),
        Ok(Outcome::Err(message)) => assert!(
            !message.is_empty(),
            "byte adapter returned an empty error message for input {input:?}"
        ),
        Ok(Outcome::Panic(message)) => {
            panic!("byte adapter panicked ({message}) on input {input:?}");
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("byte adapter hung on input {input:?}");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("byte adapter worker died on input {input:?}");
        }
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

// -------------------------------------------------------------------------------------------------
// Corpus and generators
// -------------------------------------------------------------------------------------------------

/// Tokens used to build syntactically plausible and implausible Caddyfiles.
const TOKENS: &[&str] = &[
    "example.com",
    "localhost",
    "localhost:8080",
    ":80",
    ":443",
    ":8080",
    "http://",
    "https://",
    "http://example.com",
    "respond",
    "\"ok\"",
    "\"hello world\"",
    "reverse_proxy",
    "localhost:8096",
    "file_server",
    "root",
    "/srv",
    "header",
    "X-Test",
    "redir",
    "route",
    "handle",
    "handle_path",
    "encode",
    "gzip",
    "method",
    "GET",
    "tls",
    "internal",
    "bind",
    "log",
    "import",
    "@m",
    "not",
    "path",
    "/api/*",
    "host",
    "upstream",
    "to",
    "auto_https",
    "off",
    "http_port",
    "8080",
    "https_port",
    "8443",
    "servers",
    "listen",
    "header_up",
    "header_down",
    "lb_policy",
    "round_robin",
    "pass_thru",
    "hide",
    "{",
    "}",
    "\n",
    "\t",
    " ",
    "\"unterminated",
    "\"escaped\\\"quote\"",
    "`raw\nstring`",
    "#comment",
    "\\",
    ",",
    ";",
    "=",
];

/// Characters that historically break hand-written lexers/parsers: structural characters,
/// quotes, escapes, separators, Unicode, and control characters.
const SPECIAL_CHARS: &[char] = &[
    '{', '}', '"', '`', '#', '\n', '\r', '\t', '\\', ',', '<', '>', '\u{0}', '\u{1f}', 'é', '例',
    '🎉', '\u{202e}', '\u{200b}', '\u{feff}',
];

/// Prefixes that make a generated line look like a directive or site address.
const DIRECTIVE_NAMES: &[&str] = &[
    "respond",
    "redir",
    "header",
    "reverse_proxy",
    "file_server",
    "root",
    "encode",
    "route",
    "handle",
    "handle_path",
    "method",
    "bind",
    "tls",
    "log",
    "import",
];

/// Argument-shaped strings for structured generation.
const ARGUMENTS: &[&str] = &[
    "ok",
    "\"ok\"",
    "localhost:8096",
    "localhost:8096 localhost:8097",
    "/srv",
    "X-Test",
    "value",
    "gzip zstd",
    "308",
    "/old /new",
    "GET",
    "internal",
    "127.0.0.1",
    "*",
    "\"quoted arg\"",
    "`raw arg`",
    "one two three",
];

/// A few handcrafted seeds, including deliberately malformed ones.
const HANDWRITTEN_SEEDS: &[&str] = &[
    ":80 {\n\trespond \"ok\"\n}\n",
    "example.com {\n\treverse_proxy localhost:8096\n}\n",
    "example.com {\n\thandle_path /api/* {\n\t\treverse_proxy localhost:9000\n\t}\n\tfile_server\n}\n",
    "{\n\tauto_https off\n\thttp_port 8080\n}\n:80 {\n\trespond ok\n}\n",
    "example.com, www.example.com {\n\tredir https://example.com{uri}\n}\n",
    ":80 {\n\trespond \"/broken\n}\n",
    "site",
    "",
    "{",
    "}",
    "\"",
    "`",
    "#only a comment\n",
    ":80 { respond ok }",
    "a{",
];

/// Regression corpus: each entry must return `Ok` or a located error; the guarded runner turns a
/// panic or hang into a failure that prints the reproducer.
///
/// This suite's ~3.8k generated cases (seeded LCG, deterministic) found **no catchable panics or
/// hangs** in the lexer, parser, or adapter, so this corpus currently records the malformed-input
/// classes that must stay located errors (the classes that historically break hand-written
/// Caddyfile lexers). The one defect this suite found — unbounded parser nesting, which aborted
/// the process on a deeply nested Caddyfile — has been fixed by the parser's `MAX_BLOCK_DEPTH`
/// bound; the former reproducer is asserted as a located error in
/// `former_stack_overflow_reproducer_is_a_located_error`.
///
/// Add entries here when a fuzz case finds a panic: copy the `input=...` value from the failure
/// message, keep the smallest reproducer, and note the defect (this file is the executable
/// record; the program-level DIV entry is written by the compatibility owner).
const REGRESSION_CORPUS: &[&str] = &[
    // Plain valid config: guards against an accidentally empty corpus.
    ":80 {\n\trespond ok\n}\n",
    // Unterminated quoted string must be a located lexical error.
    ":80 {\n\trespond \"unterminated\n}\n",
    // Unterminated backtick string must be a located lexical error.
    ":80 {\n\trespond `unterminated\n}\n",
    // Heredoc bodies (supported, T-CONF-003) must never be mis-lexed as structure or hang.
    ":80 {\n\trespond <<EOF\n\tbody\n\tEOF\n}\n",
    // Stray closing brace without a block.
    "}\n",
    // Unclosed block at end of file.
    ":80 {\n\trespond ok\n",
    // Quoted string containing a NUL and an emoji must not confuse position tracking.
    ":80 {\n\trespond \"\u{0}🎉\"\n}\n",
];

/// Load every local adapter fixture as an additional seed. Sorted so the corpus is deterministic
/// regardless of directory iteration order.
fn fixture_seeds() -> Vec<String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/local");
    let mut paths: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .map(|entry| entry.expect("fixture dir entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "caddyfile"))
            .collect(),
        Err(_) => Vec::new(),
    };
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect()
}

fn seeds() -> Vec<String> {
    let mut seeds: Vec<String> = fixture_seeds();
    seeds.extend(HANDWRITTEN_SEEDS.iter().map(|seed| (*seed).to_string()));
    seeds
}

/// Random token soup: no structure at all.
fn token_soup(rng: &mut Lcg) -> String {
    let count = rng.below(60);
    let mut out = String::new();
    for _ in 0..count {
        let token = if rng.coin(15) {
            let mut special = String::new();
            for _ in 0..rng.range(1, 8) {
                special.push(*rng.pick(SPECIAL_CHARS));
            }
            special
        } else {
            (*rng.pick(TOKENS)).to_string()
        };
        out.push_str(&token);
        match rng.below(3) {
            0 => out.push(' '),
            1 => out.push('\n'),
            _ => {}
        }
    }
    out
}

/// Structured generator: plausible site blocks, directives, and nested blocks with random
/// argument counts. More likely to reach adapter code paths than pure token soup.
fn structured_caddyfile(rng: &mut Lcg) -> String {
    let mut out = String::new();
    if rng.coin(30) {
        out.push_str("{\n");
        if rng.coin(60) {
            out.push_str("\tauto_https ");
            out.push_str(rng.pick(&["off", "on", "disable_redirects", "bogus"]));
            out.push('\n');
        }
        if rng.coin(50) {
            out.push_str("\thttp_port ");
            out.push_str(rng.pick(&["80", "8080", "not-a-port", "0", "70000"]));
            out.push('\n');
        }
        if rng.coin(20) {
            out.push_str("\thttps_port 8443\n");
        }
        out.push_str("}\n");
    }
    let site_count = rng.range(1, 4);
    for site in 0..site_count {
        match rng.below(6) {
            0 => out.push_str(":80"),
            1 => out.push_str("example.com"),
            2 => out.push_str(&format!("site{site}.example.test")),
            3 => out.push_str("http://localhost:8080"),
            4 => out.push_str("localhost, 127.0.0.1"),
            _ => out.push_str("https://example.com, example.org"),
        }
        out.push_str(" {\n");
        let directive_count = rng.range(0, 5);
        for _ in 0..directive_count {
            generate_directive(rng, 0, &mut out);
        }
        out.push_str("}\n");
    }
    out
}

fn generate_directive(rng: &mut Lcg, depth: usize, out: &mut String) {
    let name = *rng.pick(DIRECTIVE_NAMES);
    out.push('\t');
    for _ in 0..depth {
        out.push('\t');
    }
    out.push_str(name);
    let argument_count = rng.below(4);
    for _ in 0..argument_count {
        out.push(' ');
        out.push_str(rng.pick(ARGUMENTS));
    }
    if depth < 3 && rng.coin(30) {
        out.push_str(" {\n");
        let child_count = rng.range(0, 3);
        for _ in 0..child_count {
            if rng.coin(20) {
                generate_matcher(rng, depth + 1, out);
            } else {
                generate_directive(rng, depth + 1, out);
            }
        }
        for _ in 0..depth {
            out.push('\t');
        }
        out.push_str("\t}\n");
    } else {
        out.push('\n');
    }
}

fn generate_matcher(rng: &mut Lcg, depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push('\t');
    }
    match rng.below(6) {
        0 => out.push_str("@m path /api/*\n"),
        1 => out.push_str("@m host example.com\n"),
        2 => {
            out.push_str("@m {\n");
            out.push_str("\t\tpath /api/*\n");
            out.push_str("\t\tmethod GET\n");
            for _ in 0..depth {
                out.push('\t');
            }
            out.push_str("\t}\n");
        }
        3 => out.push_str("@m not path /health\n"),
        4 => out.push_str("@m header X-Test value\n"),
        _ => out.push_str("@m query key value\n"),
    }
}

/// Apply one to three random mutations to `seed`, never leaving the `char` domain so inputs stay
/// valid UTF-8 (the byte-oriented suite covers invalid UTF-8 separately).
fn mutate(rng: &mut Lcg, seed: &str) -> String {
    let mut chars: Vec<char> = seed.chars().collect();
    let mutations = rng.range(1, 4);
    for _ in 0..mutations {
        match rng.below(10) {
            // Truncate at a random position.
            0 => {
                let length = rng.below(chars.len() + 1);
                chars.truncate(length);
            }
            // Delete a range.
            1 if !chars.is_empty() => {
                let start = rng.below(chars.len());
                let end = rng.range(start, chars.len() + 1);
                chars.drain(start..end);
            }
            // Insert a random run of special characters.
            2 => {
                let position = rng.below(chars.len() + 1);
                let mut run = Vec::new();
                for _ in 0..rng.range(1, 16) {
                    run.push(*rng.pick(SPECIAL_CHARS));
                }
                chars.splice(position..position, run);
            }
            // Insert a random token.
            3 => {
                let position = rng.below(chars.len() + 1);
                let token: Vec<char> = rng.pick(TOKENS).chars().collect();
                chars.splice(position..position, token);
            }
            // Replace a range with a random token.
            4 if !chars.is_empty() => {
                let start = rng.below(chars.len());
                let end = rng.range(start, chars.len() + 1);
                let token: Vec<char> = rng.pick(TOKENS).chars().collect();
                chars.splice(start..end, token);
            }
            // Duplicate a range.
            5 if !chars.is_empty() => {
                let start = rng.below(chars.len());
                let end = rng.range(start, chars.len() + 1);
                let copy: Vec<char> = chars[start..end].to_vec();
                chars.splice(end..end, copy);
            }
            // Replace a random char with a special one.
            6 if !chars.is_empty() => {
                let position = rng.below(chars.len());
                chars[position] = *rng.pick(SPECIAL_CHARS);
            }
            // Global newline removal, reproducing the "everything on one line" failure class.
            7 if !chars.is_empty() => {
                chars.retain(|ch| *ch != '\n');
            }
            // Splice a fragment of another seed.
            8 => {
                let other: Vec<char> = (*rng.pick(HANDWRITTEN_SEEDS)).chars().collect();
                if !other.is_empty() {
                    let start = rng.below(other.len());
                    let end = rng.range(start, other.len() + 1);
                    let position = rng.below(chars.len() + 1);
                    chars.splice(position..position, other[start..end].to_vec());
                }
            }
            // Append a token soup suffix.
            _ => {
                let soup = token_soup(rng);
                chars.extend(soup.chars());
            }
        }
    }
    chars.into_iter().collect()
}

fn random_bytes(rng: &mut Lcg) -> Vec<u8> {
    let length = rng.below(512);
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        bytes.push(rng.below(256) as u8);
    }
    bytes
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[test]
fn token_soup_returns_json_or_located_error() {
    let mut rng = Lcg::new(0x5eed_0001);
    for _ in 0..800 {
        check_str(&token_soup(&mut rng));
    }
}

#[test]
fn structured_caddyfiles_return_json_or_located_error() {
    let mut rng = Lcg::new(0x5eed_0002);
    for _ in 0..1200 {
        check_str(&structured_caddyfile(&mut rng));
    }
}

#[test]
fn mutated_corpus_returns_json_or_located_error() {
    let mut rng = Lcg::new(0x5eed_0003);
    let seeds = seeds();
    assert!(!seeds.is_empty(), "seed corpus must not be empty");
    for seed in &seeds {
        for _ in 0..40 {
            check_str(&mutate(&mut rng, seed));
        }
    }
}

#[test]
fn random_bytes_are_rejected_cleanly_or_adapted() {
    let mut rng = Lcg::new(0x5eed_0004);
    for _ in 0..1000 {
        check_bytes(&random_bytes(&mut rng));
    }
}

#[test]
fn unicode_control_and_boundary_corpus() {
    let corpus: &[String] = &[
        "\u{feff}:80 {\n\trespond ok\n}\n".to_string(),
        "例え.テスト {\n\trespond \"こんにちは\"\n}\n".to_string(),
        "e\u{0301}xample.com {\n\trespond ok\n}\n".to_string(),
        "\u{202e}:80 {\n\trespond ok\n}\n".to_string(),
        "\u{0}:80 {\n\trespond ok\n}\u{0}".to_string(),
        ":80 {\r\trespond ok\r}\r".to_string(),
        "{{{{}}}}".to_string(),
        "}}}}".to_string(),
        "\"".to_string(),
        "`".to_string(),
        "\\".to_string(),
        "#".to_string(),
        "\n".repeat(1000),
        "a".repeat(4096),
        "\u{0}".repeat(128),
        "\"\\".repeat(256),
        "{\n".repeat(256),
        "}\n".repeat(256),
        format!(":80 {{\n\trespond \"{}\"\n}}\n", "🎉".repeat(256)),
        ":80 {\n\trespond \"\\u{1F600}\"\n}\n".to_string(),
        ":80 {\n\trespond \"\\q\\\"\\\\\"\n}\n".to_string(),
        ":80 {\n\trespond `unterminated\n".to_string(),
        ":80 {\n\theader X-Test \"unterminated\n}\n".to_string(),
        ":80 {\n\treverse_proxy\n}\n".to_string(),
        ":80 {\n\trespond\n}\n".to_string(),
        ":80 {\n\tfile_server {\n\t\tbrowse {\n\t\t\tsort name\n\t\t}\n\t}\n}\n".to_string(),
        "{\n\thttp_port 999999999999999999999\n}\n:80 {\n\trespond ok\n}\n".to_string(),
        "{\n\thttp_port -1\n}\n:80 {\n\trespond ok\n}\n".to_string(),
    ];
    for input in corpus {
        check_str(input);
    }
}

/// Build a valid nesting-depth probe: a site block containing `depth` nested `route { ... }`
/// blocks around a single `respond`.
fn nested_blocks(depth: usize) -> String {
    let mut input = String::from(":80 {\n");
    for _ in 0..depth {
        input.push_str("\troute {\n");
    }
    input.push_str("\t\trespond ok\n");
    for _ in 0..depth {
        input.push_str("\t}\n");
    }
    input.push_str("}\n");
    input
}

/// Nesting-depth contract (T-COMPAT-012 defect, fixed by the parser `MAX_BLOCK_DEPTH` bound):
/// the parser accepts at most 128 braced block levels including the site block and turns deeper
/// nesting into a located parse error instead of recursing until the process aborts. The former
/// reproducer — a ~2.5 KB Caddyfile with a site block plus 400 nested `route` blocks — used to
/// abort with SIGABRT; it is now rejected cleanly in-process (second test below).
#[test]
fn nesting_depth_within_the_parser_budget_is_handled() {
    // The site block counts as level 1. Depth 127 reaches exactly the parser's 128-level budget;
    // every value here must be accepted.
    for depth in [0usize, 1, 4, 8, 16, 32, 64, 96, 127] {
        check_str(&nested_blocks(depth));
    }
}

#[test]
fn former_stack_overflow_reproducer_is_a_located_error() {
    // Exact shape of the T-COMPAT-012 reproducer (previously an uncatchable stack-overflow
    // abort). `adapt` must return a located parser error without recursing past the limit, so
    // this is safe to run directly on the test thread — if the bound regresses, this test aborts
    // the process instead of hanging in the watchdog.
    let error = adapt(&nested_blocks(400)).expect_err("deep nesting must be rejected, not abort");
    let message = error.to_string();
    assert!(
        message.contains("Caddyfile line"),
        "error must be located: {message}"
    );
    assert!(
        message.contains("maximum depth"),
        "error must name the nesting limit: {message}"
    );
}

#[test]
fn generated_inputs_are_deterministic() {
    // Same seed => identical generated corpus. This is what makes a CI failure reproducible.
    let mut first = Lcg::new(42);
    let mut second = Lcg::new(42);
    for _ in 0..100 {
        assert_eq!(
            token_soup(&mut first),
            token_soup(&mut second),
            "token soup generator is not deterministic"
        );
        assert_eq!(
            structured_caddyfile(&mut first),
            structured_caddyfile(&mut second),
            "structured generator is not deterministic"
        );
        assert_eq!(
            mutate(&mut first, ":80 {\n\trespond ok\n}\n"),
            mutate(&mut second, ":80 {\n\trespond ok\n}\n"),
            "mutation generator is not deterministic"
        );
    }
}

#[test]
fn regression_corpus_never_panics_or_hangs() {
    for input in REGRESSION_CORPUS {
        check_str(input);
    }
}

#[test]
fn regression_corpus_and_seeds_are_valid_utf8_smoke() {
    // The regression corpus must itself be well formed enough to run; an empty/blank entry would
    // make the regression test vacuous.
    for input in REGRESSION_CORPUS {
        assert!(!input.trim().is_empty(), "blank regression input");
    }
    for seed in seeds() {
        check_str(&seed);
    }
}
