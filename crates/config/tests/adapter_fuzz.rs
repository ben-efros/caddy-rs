//! T-COMPAT-012: deterministic property/mutation tests for the Caddyfile adapter.
//!
//! Property under test: for *any* input, [`caddy_rs_config::adapt`] (and the byte-oriented
//! [`caddy_rs_core::ConfigAdapter`] impl) returns either `Ok` with a JSON object or a located
//! error. It must never panic, hang, or allocate without bound.
//!
//! Determinism: all inputs are produced by a seeded 64-bit LCG implemented in this file. No
//! external fuzzing crate is used, so a failure is exactly reproducible from the seed printed in
//! the panic message. The suite is bounded to well under 5,000 cases and small inputs so it stays
//! CI-fast.
//!
//! Tier: **tier 1** (T-FUZZ-SEED-ADAPTER). The LCG seed and case counts are the in-file constants
//! below unless overridden by `FUZZ_SEED` (u64) and `FUZZ_CASES` (usize). Knob contract, per
//! `docs/compatibility/TESTING.md` §Fuzzing and `agents-prompts/fuzz-runner.md` §4:
//!
//! - **absent ⇒ silent tier 0**: with both variables unset the suite uses the constants, so a
//!   plain `cargo test` is byte-identical to the pre-tier behaviour and the CI PR path is unchanged;
//! - **present ⇒ tier 1**: the value replaces the constant, so a scheduled sweep explores a
//!   different corpus each run. Still deterministic *within* a run — the same value always produces
//!   the same stream;
//! - **present-but-invalid ⇒ loud failure**, naming the variable and the offending value. A
//!   misconfigured sweep must never quietly degrade to tier 0 and report green.
//!
//! The resolved seed and case count are printed at the start of every run (`--nocapture` to see
//! them), so the corpus a run exercised is identifiable from its log.
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
// Tier 1 knobs (FUZZ_SEED / FUZZ_CASES)
// -------------------------------------------------------------------------------------------------

/// Tier-0 seed for the token-soup generator. Used when `FUZZ_SEED` is unset.
const SEED_TOKEN_SOUP: u64 = 0x5eed_0001;
/// Tier-0 seed for the structured-Caddyfile generator. Used when `FUZZ_SEED` is unset.
const SEED_STRUCTURED: u64 = 0x5eed_0002;
/// Tier-0 seed for the mutation generator. Used when `FUZZ_SEED` is unset.
const SEED_MUTATED: u64 = 0x5eed_0003;
/// Tier-0 seed for the raw-bytes generator. Used when `FUZZ_SEED` is unset.
const SEED_RANDOM_BYTES: u64 = 0x5eed_0004;

/// Tier-0 case counts. Used when `FUZZ_CASES` is unset.
const CASES_TOKEN_SOUP: usize = 800;
const CASES_STRUCTURED: usize = 1200;
const CASES_MUTATED_PER_SEED: usize = 40;
const CASES_RANDOM_BYTES: usize = 1000;

/// Ceiling for `FUZZ_CASES`. The suite must stay CI-fast (house style: total added wall time under
/// 60 s, case counts bounded), so an out-of-range value is a loud error rather than a slow suite.
const MAX_CASES: usize = 10_000;

/// Read a knob. `Ok(None)` when unset (the silent tier-0 path); `Ok(Some(v))` when set to a valid
/// value; `Err` naming the variable and the offending value when set to something unusable — so a
/// misconfigured sweep fails loudly instead of silently running tier 0 and reporting green.
fn knob<T>(name: &str, max: Option<T>) -> Result<Option<T>, String>
where
    T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
{
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(format!("{name} is set but unreadable: {err}")),
        Ok(raw) => {
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
    }
}

/// Resolved knob values for one run: the tier the run executed and the seeds/counts it used.
struct Knobs {
    seed: Option<u64>,
    cases: Option<usize>,
}

impl Knobs {
    /// Resolve both knobs from the environment, failing loudly on an invalid value.
    fn from_env() -> Result<Self, String> {
        Ok(Self {
            seed: knob::<u64>("FUZZ_SEED", None)?,
            cases: knob::<usize>("FUZZ_CASES", Some(MAX_CASES))?,
        })
    }

    /// Seed for a generator: the tier-1 `FUZZ_SEED` when set, else this generator's tier-0 constant.
    ///
    /// Every generator is offset by a distinct constant so that a given `FUZZ_SEED` still yields a
    /// different stream per generator, exactly as the tier-0 constants do.
    fn seed(&self, tier0: u64) -> u64 {
        match self.seed {
            Some(seed) => seed.wrapping_add(tier0),
            None => tier0,
        }
    }

    /// Case count for a generator that runs its `tier0` count once per generated case.
    ///
    /// `FUZZ_CASES`, when set, is the total across the suite and is divided by the tier-0 total, so
    /// `FUZZ_CASES=50` runs a few cases per generator rather than 50 per generator. The tier-0
    /// ratio between generators is preserved.
    fn cases(&self, tier0: usize) -> usize {
        match self.cases {
            None => tier0,
            Some(total) => {
                let scaled = total * tier0 / tier0_total();
                // At least one case, so a tiny FUZZ_CASES still exercises every generator.
                scaled.max(1)
            }
        }
    }

    /// Case count for a generator that runs its count once per seed, so the cases it actually
    /// executes are `result * seeds`. Dividing the scaled budget by `seeds` keeps the generator's
    /// contribution to the suite total equal to its share, instead of multiplying it by the seed
    /// count.
    fn cases_per_seed(&self, tier0: usize, seeds: usize) -> usize {
        match self.cases {
            None => tier0,
            Some(_) => {
                let scaled = self.cases(tier0);
                // At least one case per seed, so a tiny FUZZ_CASES still exercises every seed.
                (scaled / seeds.max(1)).max(1)
            }
        }
    }

    /// Print the resolved seed and case count once per run so the corpus is identifiable.
    ///
    /// The count is `cases_total()`, which mirrors the actual loops — including the mutated
    /// generator running once per seed — so the announcement never overstates or understates what
    /// ran.
    fn announce(&self) {
        match (self.seed, self.cases) {
            (None, None) => println!(
                "adapter_fuzz: tier 0 (FUZZ_SEED/FUZZ_CASES unset) — seeds {:?}, cases {} total",
                [
                    SEED_TOKEN_SOUP,
                    SEED_STRUCTURED,
                    SEED_MUTATED,
                    SEED_RANDOM_BYTES
                ],
                self.cases_total()
            ),
            (seed, cases) => println!(
                "adapter_fuzz: tier 1 — resolved FUZZ_SEED={:?}, FUZZ_CASES={:?} ({} cases total)",
                seed,
                cases,
                self.cases_total()
            ),
        }
    }

    /// Cases this run actually executes. Mirrors the four test loops exactly, so the announced
    /// figure is the executed figure.
    fn cases_total(&self) -> usize {
        let mutated_seeds = seeds().len();
        self.cases(CASES_TOKEN_SOUP)
            + self.cases(CASES_STRUCTURED)
            + self.cases_per_seed(CASES_MUTATED_PER_SEED, mutated_seeds) * mutated_seeds
            + self.cases(CASES_RANDOM_BYTES)
    }
}

/// Sum of the four tier-0 case *constants*, used only as the ratio denominator when scaling
/// `FUZZ_CASES` across the generators.
///
/// This is deliberately NOT the number of cases a tier-0 run executes: the mutated generator runs
/// `CASES_MUTATED_PER_SEED` once per seed, so it contributes `CASES_MUTATED_PER_SEED * seeds.len()`
/// and the executed total is larger. Use [`Knobs::cases_total`] for the executed figure.
fn tier0_total() -> usize {
    CASES_TOKEN_SOUP + CASES_STRUCTURED + CASES_MUTATED_PER_SEED + CASES_RANDOM_BYTES
}

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

/// Resolve the knobs, announcing the resolved seed and case count for this run.
///
/// Fails with the variable name and offending value when a knob is present but invalid, so a
/// misconfigured sweep is a loud failure rather than a silent tier-0 fallback.
fn knobs_or_fail() -> Knobs {
    let knobs = Knobs::from_env().unwrap_or_else(|err| panic!("adapter_fuzz: {err}"));
    knobs.announce();
    knobs
}

#[test]
fn token_soup_returns_json_or_located_error() {
    run_token_soup(&knobs_or_fail());
}

/// Runs the token-soup loop and returns how many cases it executed.
fn run_token_soup(knobs: &Knobs) -> usize {
    let cases = knobs.cases(CASES_TOKEN_SOUP);
    let mut rng = Lcg::new(knobs.seed(SEED_TOKEN_SOUP));
    for _ in 0..cases {
        check_str(&token_soup(&mut rng));
    }
    cases
}

#[test]
fn structured_caddyfiles_return_json_or_located_error() {
    run_structured(&knobs_or_fail());
}

/// Runs the structured-Caddyfile loop and returns how many cases it executed.
fn run_structured(knobs: &Knobs) -> usize {
    let cases = knobs.cases(CASES_STRUCTURED);
    let mut rng = Lcg::new(knobs.seed(SEED_STRUCTURED));
    for _ in 0..cases {
        check_str(&structured_caddyfile(&mut rng));
    }
    cases
}

#[test]
fn mutated_corpus_returns_json_or_located_error() {
    run_mutated(&knobs_or_fail());
}

/// Runs the mutation loop and returns how many cases it executed - the per-seed count times the
/// number of seeds, which is where an announcement most easily drifts from the loop.
fn run_mutated(knobs: &Knobs) -> usize {
    let seeds = seeds();
    assert!(!seeds.is_empty(), "seed corpus must not be empty");
    let per_seed = knobs.cases_per_seed(CASES_MUTATED_PER_SEED, seeds.len());
    let mut rng = Lcg::new(knobs.seed(SEED_MUTATED));
    for seed in &seeds {
        for _ in 0..per_seed {
            check_str(&mutate(&mut rng, seed));
        }
    }
    per_seed * seeds.len()
}

#[test]
fn random_bytes_are_rejected_cleanly_or_adapted() {
    run_random_bytes(&knobs_or_fail());
}

/// Runs the raw-bytes loop and returns how many cases it executed.
fn run_random_bytes(knobs: &Knobs) -> usize {
    let cases = knobs.cases(CASES_RANDOM_BYTES);
    let mut rng = Lcg::new(knobs.seed(SEED_RANDOM_BYTES));
    for _ in 0..cases {
        check_bytes(&random_bytes(&mut rng));
    }
    cases
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

/// Tier 1 must actually vary the corpus between runs: two different `FUZZ_SEED` values must
/// produce different case streams, while a repeated value reproduces exactly.
#[test]
fn different_resolved_seeds_produce_different_case_streams() {
    let stream = |seed: u64| {
        let mut rng = Lcg::new(seed);
        (0..32).map(|_| token_soup(&mut rng)).collect::<Vec<_>>()
    };
    let a = stream(1);
    let b = stream(2);
    assert_ne!(
        a, b,
        "FUZZ_SEED=1 and FUZZ_SEED=2 produced identical streams; tier 1 would be a no-op"
    );
    assert_eq!(
        a,
        stream(1),
        "the same seed must reproduce exactly (determinism within a run)"
    );
    // The per-generator offset keeps generators distinct for one FUZZ_SEED, as tier 0 does.
    let offset_seed = |tier0: u64| {
        let knobs = Knobs {
            seed: Some(12345),
            cases: None,
        };
        knobs.seed(tier0)
    };
    assert_ne!(offset_seed(SEED_TOKEN_SOUP), offset_seed(SEED_STRUCTURED));
}

/// The announced total must equal the number of cases the real loops execute, and a tier-1 sweep
/// must stay inside the documented cap.
///
/// The sum comes from the same `run_*` functions the four `#[test]`s call, each of which returns
/// its own executed count. So this compares the announcement against real executions rather than
/// re-deriving the loops' shape: if a loop's per-seed division or floor diverges from
/// `cases_total`, the sums disagree here.
#[test]
fn announced_case_total_matches_the_executed_loops() {
    let n = seeds().len();
    assert!(n > 1, "expected several seed fixtures");

    let tier0 = Knobs {
        seed: None,
        cases: None,
    };
    // Tier 0 counts the mutated generator once per seed - it is not the sum of the four constants.
    assert_eq!(
        tier0.cases_total(),
        CASES_TOKEN_SOUP + CASES_STRUCTURED + CASES_MUTATED_PER_SEED * n + CASES_RANDOM_BYTES,
        "tier-0 announcement must count the mutated generator once per seed"
    );
    assert_ne!(
        tier0.cases_total(),
        tier0_total(),
        "the executed total must not be the sum of the four constants; the mutated generator \
         runs once per seed"
    );

    for total in [
        None,
        Some(1usize),
        Some(50),
        Some(1000),
        Some(3040),
        Some(MAX_CASES),
    ] {
        let knobs = Knobs {
            seed: Some(1),
            cases: total,
        };
        let executed = run_token_soup(&knobs)
            + run_structured(&knobs)
            + run_mutated(&knobs)
            + run_random_bytes(&knobs);
        assert_eq!(
            knobs.cases_total(),
            executed,
            "announcement must equal the executed total for FUZZ_CASES={total:?}"
        );
        if total.is_some() {
            assert!(
                executed <= MAX_CASES,
                "FUZZ_CASES={total:?} must stay within the {MAX_CASES}-case cap, got {executed}"
            );
        }
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
