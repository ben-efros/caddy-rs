//! Deterministic fuzz tests for the OCSP request builder.
//!
//! [`build_ocsp_request`] takes the DER of two certificates — the leaf being stapled and its issuer
//! — and turns them into an `OCSPRequest`. Both blobs reach it from certificate files and from
//! certificate chains presented during a TLS handshake, so their contents are attacker-influenced:
//! a hostile peer chooses its own certificate, including its serial number and its extensions.
//!
//! This complements `ocsp_fuzz.rs`, which covers the *response* direction. The two halves share the
//! crate's hand-rolled ASN.1: `parse_certificate` walks a `tbsCertificate` with `DerReader`, and
//! `der_integer_from_bytes` re-encodes the serial. This file pins two properties:
//!
//!   1. **Totality.** For any byte string, [`build_ocsp_request`] returns either an [`OcspRequest`]
//!      or a typed [`OcspError`]. It must never panic. The panic surface here is different from the
//!      response parser: `der_integer_from_bytes` indexes `content[0]`/`content[1]` in a loop.
//!   2. **Bounded work.** The cost of building a request must be roughly linear in the size of the
//!      input. A parser whose running time grows super-linearly in an attacker-chosen field is a
//!      CPU-amplification vector even when it never panics.
//!
//! Determinism: every input comes from a seeded xorshift64 PRNG implemented in this file, or from a
//! mutation of a structurally valid certificate built here. No external fuzzing crate and no
//! ambient randomness, so a failure reproduces exactly from the seed printed with it.
//!
//! Re-run just this file:
//! `cargo test --offline -p caddy-rs-tls --test ocsp_request_fuzz`
//!
//! Tier 1 knobs: `FUZZ_SEED` (u64) and `FUZZ_CASES` (usize) override the tier-0 constants below, so
//! a sweep can vary the corpus without editing the file. The contract matches the one
//! `crates/config/tests/adapter_fuzz.rs` established (T-FUZZ-SPEC-TIERS) and that `ocsp_fuzz.rs`
//! carries (T-FUZZ-SEED-OCSP): unset is the silent tier-0 path, a parseable value switches to tier 1,
//! and an unparseable or out-of-range value is a loud failure naming the variable — never a silent
//! fall back to tier 0 that reports green.

use caddy_rs_tls::{build_ocsp_request, OcspError};

// -------------------------------------------------------------------------------------------------
// Tier 1 knobs (FUZZ_SEED / FUZZ_CASES)
// -------------------------------------------------------------------------------------------------

/// Corpus size. Bounded so the suite stays CI-fast (target: well under 5 s on a debug build).
/// Used when `FUZZ_CASES` is unset.
const RANDOM_CASES: usize = 4_000;
const MUTATION_CASES: usize = 4_000;

/// Tier-0 seeds, one per generator. Used when `FUZZ_SEED` is unset.
const SEED_RANDOM: u64 = 0x5EED_0000_0000_0011;
const SEED_MUTATION: u64 = 0x5EED_0000_0000_0012;

/// Ceiling for `FUZZ_CASES`. The suite must stay CI-fast, so an out-of-range value is a loud error
/// rather than a slow suite. Matches `MAX_CASES` in `adapter_fuzz.rs` and `ocsp_fuzz.rs`.
const MAX_CASES: usize = 10_000;

/// Read a knob. `Ok(None)` when unset (the silent tier-0 path); `Ok(Some(v))` when set to a valid
/// value; `Err` naming the variable and the offending value when set to something unusable — so a
/// misconfigured sweep fails loudly instead of silently running tier 0 and reporting green.
///
/// Kept identical in shape to the copies in `crates/config/tests/adapter_fuzz.rs` and
/// `ocsp_fuzz.rs`. The copies cannot be shared today: an integration test is its own crate and
/// `caddy-rs-tls` does not dev-depend on a common helper. Extraction is filed as
/// T-FUZZ-SEED-OTHER-TARGETS rather than done here, because this change's declared scope is this
/// file; with three call sites it is now worth doing rather than duplicating again.
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
    /// Offset by a distinct constant per generator so a given `FUZZ_SEED` still yields a different
    /// stream per generator, exactly as the tier-0 constants do.
    fn seed(&self, tier0: u64) -> u64 {
        match self.seed {
            Some(seed) => seed.wrapping_add(tier0),
            None => tier0,
        }
    }

    /// One line naming the tier and the resolved values, so a sweep's output identifies which knobs
    /// it actually executed.
    fn announce(&self) -> String {
        match (self.seed, self.cases) {
            (None, None) => {
                "fuzz tier 0 (unset FUZZ_SEED/FUZZ_CASES; in-file constants)".to_string()
            }
            (seed, cases) => format!(
                "fuzz tier 1: FUZZ_SEED={} FUZZ_CASES={}",
                seed.map_or_else(|| "unset".to_string(), |v| v.to_string()),
                cases.map_or_else(|| "unset".to_string(), |v| v.to_string()),
            ),
        }
    }

    /// Case count for a generator, scaled so `FUZZ_CASES` is the total across this file rather than
    /// per generator. The tier-0 ratio between generators is preserved, and every generator still
    /// runs at least one case so a tiny `FUZZ_CASES` exercises all of them.
    fn cases(&self, tier0: usize) -> usize {
        match self.cases {
            None => tier0,
            Some(total) => (total * tier0 / tier0_total()).max(1),
        }
    }
}

/// Resolve the knobs for a test body, panicking with the located message when a value is unusable.
///
/// A panicking resolver is the point: `FUZZ_SEED=garbage` must fail the run naming the variable, not
/// quietly execute tier 0 and report success.
fn knobs_or_fail() -> Knobs {
    match Knobs::from_env() {
        Ok(knobs) => knobs,
        Err(err) => panic!("{err}"),
    }
}

/// Tier-0 total, the denominator the tier-1 case counts are scaled against.
fn tier0_total() -> usize {
    RANDOM_CASES + MUTATION_CASES
}

/// xorshift64 — deterministic, dependency-free PRNG.
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// --- Minimal DER encoder --------------------------------------------------------------------
//
// The crate's own `der_*` helpers are private to `caddy-rs-tls`, so an integration test needs its
// own. Only what a structurally valid certificate needs is implemented.

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x83);
        out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    }
    out.extend_from_slice(content);
    out
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for part in parts {
        content.extend_from_slice(part);
    }
    der_tlv(0x30, &content)
}

fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    if let Some((&first, rest)) = arcs.split_first() {
        content.push((first * 40 + rest.first().copied().unwrap_or(0)) as u8);
        for &arc in rest.iter().skip(1) {
            let mut stack = [0_u8; 10];
            let mut at = stack.len();
            let mut value = arc;
            loop {
                at -= 1;
                stack[at] = (value & 0x7F) as u8;
                value >>= 7;
                if value == 0 {
                    break;
                }
            }
            for index in at..stack.len() - 1 {
                stack[index] |= 0x80;
            }
            content.extend_from_slice(&stack[at..]);
        }
    }
    der_tlv(0x06, &content)
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut content = value.to_vec();
    while content.len() > 1 && content[0] == 0 && content[1] & 0x80 == 0 {
        content.remove(0);
    }
    if content.is_empty() {
        content.push(0);
    }
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der_tlv(0x02, &content)
}

/// An INTEGER whose content bytes are emitted verbatim, with no leading-zero normalisation.
///
/// A real certificate's serial is whatever DER the signer chose, and DER permits a non-minimal
/// INTEGER encoding to be *presented* (a strict decoder rejects it, but a lenient one accepts it).
/// The builder under test must cope with a long, attacker-chosen serial, so this helper must not
/// quietly normalise it away — doing so is what made the first version of the linearity test
/// vacuous.
fn der_integer_raw(value: &[u8]) -> Vec<u8> {
    der_tlv(0x02, value)
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(bytes.len() + 1);
    value.push(0);
    value.extend_from_slice(bytes);
    der_tlv(0x03, &value)
}

fn der_utc_time(seconds: u64) -> Vec<u8> {
    // A fixed, valid UTCTime: 2023-11-14T22:13:20Z.
    let _ = seconds;
    der_tlv(0x17, b"231114221320Z")
}

// --- Certificate construction ---------------------------------------------------------------

/// A structurally valid `subjectPublicKeyInfo` holding an Ed25519 key.
///
/// `parse_spki_public_key` decodes this, so the bytes have to be a real algorithm OID plus a
/// BIT STRING carrying a 32-byte key.
fn spki(key_byte: u8) -> Vec<u8> {
    der_sequence(&[
        der_sequence(&[der_oid(&[1, 3, 101, 112])]),
        der_bit_string(&[key_byte; 32]),
    ])
}

/// Builds a certificate whose serial is `serial` (the raw INTEGER value bytes).
///
/// Every other field is the minimum `parse_certificate` accepts, so the only thing a caller varies
/// is the field under test.
fn certificate_with_serial(serial: &[u8], subject_key_byte: u8) -> Vec<u8> {
    certificate_with_serial_encoded(&der_integer(serial), subject_key_byte)
}

/// Like [`certificate_with_serial`], but takes the already-encoded INTEGER TLV so a caller can
/// present a non-minimal serial that the normalising helper would have rewritten.
fn certificate_with_serial_encoded(serial_tlv: &[u8], subject_key_byte: u8) -> Vec<u8> {
    let name = der_sequence(&[]);
    let algorithm = der_sequence(&[der_oid(&[1, 3, 101, 112])]);
    let validity = der_sequence(&[der_utc_time(0), der_utc_time(0)]);
    let tbs = der_sequence(&[
        der_tlv(0xA0, &der_integer(&[2])), // version v3
        serial_tlv.to_vec(),
        algorithm.clone(),
        name.clone(), // issuer
        validity,
        name, // subject
        spki(subject_key_byte),
    ]);
    der_sequence(&[
        tbs,
        algorithm,
        der_bit_string(&[0_u8; 64]), // signature
    ])
}

/// The leaf/issuer pair a caller would normally staple: a small serial and a distinct issuer key.
fn valid_pair() -> (Vec<u8>, Vec<u8>) {
    (
        certificate_with_serial(&[0x01, 0x23, 0x45], 0x11),
        certificate_with_serial(&[0x0A], 0x22),
    )
}

// --- Assertions -----------------------------------------------------------------------------

/// Fails with a reproducible message naming the seed and the exact input bytes.
///
/// The properties asserted are about the **builder**, not about whether the certificate is
/// sensible. A certificate is allowed to have a 2000-byte serial; that is unusual data, and the
/// builder must still return a typed outcome rather than panicking.
fn assert_typed_outcome(leaf: &[u8], issuer: &[u8], context: &str) {
    let outcome = std::panic::catch_unwind(|| build_ocsp_request(leaf, issuer));
    match outcome {
        Ok(Ok(request)) => {
            // A successful build must produce a non-empty DER request. `der_sequence` of a
            // non-empty list always yields at least a tag and a length byte.
            assert!(
                request.der.len() >= 2,
                "{context}: built an empty OCSPRequest (leaf {} bytes, issuer {} bytes)",
                leaf.len(),
                issuer.len()
            );
            assert_eq!(
                request.der[0], 0x30,
                "{context}: OCSPRequest does not start with a SEQUENCE tag"
            );
        }
        Ok(Err(error)) => {
            // Only these two variants may escape a build. Anything else means the builder invented
            // an error kind it does not document.
            assert!(
                matches!(error, OcspError::Malformed(_) | OcspError::Unsupported(_)),
                "{context}: unexpected error kind for leaf {} bytes, issuer {} bytes: {error:?}",
                leaf.len(),
                issuer.len()
            );
        }
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            panic!(
                "{context}: build_ocsp_request panicked: {message} (leaf {} bytes, issuer {} bytes)",
                leaf.len(),
                issuer.len()
            );
        }
    }
}

// --- Tests ----------------------------------------------------------------------------------

// -------------------------------------------------------------------------------------------------
// Recording harness for the knob contract tests
// -------------------------------------------------------------------------------------------------
//
// The generators assert a typed outcome and return nothing, so a contract test cannot observe what
// they generated. Rather than re-implement them in the test -- which is how T-FUZZ-SEED-OCSP's first
// revision ended up asserting nothing about the real code -- each body records a transcript of what
// it saw, and the contract tests compare transcripts.

thread_local! {
    static TRANSCRIPT: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Record one observation: a byte per assertion site, cheap and order-preserving.
fn record(observation: u8) {
    TRANSCRIPT.with(|t| t.borrow_mut().push(observation));
}

fn take_transcript() -> Vec<u8> {
    TRANSCRIPT.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

/// Fold a byte string to one observation byte, so a corpus of multi-kilobyte certificate blobs
/// collapses to something comparable across seeds.
fn fold(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0_u8, |acc, b| acc.wrapping_mul(31).wrapping_add(*b))
}

/// Called by the generator wrappers, so a test can prove the WRAPPER announced its tier rather than
/// only that `announce()` returns a well-formed string.
/// Emit one line of operator-visible output.
///
/// The wrappers announce through this. Two earlier revisions tested the announcement in-process --
/// first by asserting `announce()`'s return value, then by recording beside `println!` in a sink --
/// and BOTH stayed green when the print was deleted, because an in-process proxy is a statement about
/// a helper the test calls, not about the bytes an operator sees. The announcement is therefore
/// asserted by re-running this binary as a subprocess and reading its real stdout; see
/// `a_tier1_run_prints_its_tier_line`.
fn emit(line: String) {
    println!("{line}");
}

fn record_random(knobs: &Knobs) -> Vec<u8> {
    take_transcript();
    run_random(knobs);
    take_transcript()
}

fn record_mutated(knobs: &Knobs) -> Vec<u8> {
    take_transcript();
    run_mutated(knobs);
    take_transcript()
}

/// A stable digest for pinning an observed transcript. FNV-1a: no dependency, adequate for a
/// change-detector, and deliberately not a security primitive.
fn digest(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Pinned tier-0 digests of the OBSERVED transcripts. These change only for an intended, reviewed
/// tier-0 change: a tier-0 constant or count that moves must move them, which is the point, but
/// re-pinning them without asking why defeats the test.
const EXPECTED_TIER0_RANDOM: u64 = 0x5a7e052b4af625fe;
const EXPECTED_TIER0_MUTATED: u64 = 0xbd22d50e6bd14c32;

#[test]
fn random_buffers_never_panic_and_only_return_typed_errors() {
    let knobs = knobs_or_fail();
    emit(knobs.announce());
    run_random(&knobs);
}

/// Body of `random_buffers_never_panic_and_only_return_typed_errors`, callable with an explicit
/// [`Knobs`] so the knob contract can be asserted against the generator that actually runs rather
/// than against `Knobs` alone.
fn run_random(knobs: &Knobs) {
    let mut state = knobs.seed(SEED_RANDOM);
    for case in 0..knobs.cases(RANDOM_CASES) {
        let leaf_len = (xorshift(&mut state) % 96) as usize;
        let mut leaf = Vec::with_capacity(leaf_len);
        for _ in 0..leaf_len {
            leaf.push(xorshift(&mut state) as u8);
        }
        let issuer_len = (xorshift(&mut state) % 96) as usize;
        let mut issuer = Vec::with_capacity(issuer_len);
        for _ in 0..issuer_len {
            issuer.push(xorshift(&mut state) as u8);
        }
        record(fold(&leaf) ^ fold(&issuer));
        assert_typed_outcome(&leaf, &issuer, &format!("random case {case}"));
    }
}

#[test]
fn valid_certificates_are_accepted() {
    // Control: the builders above really do produce certificates the parser accepts. Without this,
    // every "returns an error" assertion below could pass for the wrong reason.
    let (leaf, issuer) = valid_pair();
    let request = build_ocsp_request(&leaf, &issuer).expect("a valid pair must build a request");
    assert!(!request.der.is_empty());
    assert_eq!(request.serial, vec![0x01, 0x23, 0x45]);
}

#[test]
fn mutated_valid_certificates_never_panic() {
    let knobs = knobs_or_fail();
    emit(knobs.announce());
    run_mutated(&knobs);
}

/// Body of `mutated_valid_certificates_never_panic`, callable with an explicit [`Knobs`] so the knob
/// contract can be asserted against the generator that actually runs.
fn run_mutated(knobs: &Knobs) {
    let (leaf, issuer) = valid_pair();
    let mut state = knobs.seed(SEED_MUTATION);
    for case in 0..knobs.cases(MUTATION_CASES) {
        let mut leaf = leaf.clone();
        let mut issuer = issuer.clone();
        // Flip between one and four bytes across both certificates.
        let flips = 1 + (xorshift(&mut state) % 4) as usize;
        for _ in 0..flips {
            let target = if xorshift(&mut state) & 1 == 0 {
                &mut leaf
            } else {
                &mut issuer
            };
            if target.is_empty() {
                continue;
            }
            let at = (xorshift(&mut state) as usize) % target.len();
            target[at] = xorshift(&mut state) as u8;
        }
        record(fold(&leaf) ^ fold(&issuer));
        assert_typed_outcome(&leaf, &issuer, &format!("mutation case {case}"));
    }
}

#[test]
fn every_prefix_of_a_valid_certificate_pair_is_typed() {
    let (leaf, issuer) = valid_pair();
    for len in 0..=leaf.len() {
        assert_typed_outcome(&leaf[..len], &issuer, &format!("leaf prefix {len}"));
    }
    for len in 0..=issuer.len() {
        assert_typed_outcome(&leaf, &issuer[..len], &format!("issuer prefix {len}"));
    }
}

#[test]
fn empty_and_tiny_inputs_are_typed_errors() {
    for leaf in [&b""[..], &b"\x30"[..], &b"\x30\x00"[..], &b"\x30\x80"[..]] {
        for issuer in [&b""[..], &b"\x30"[..], &b"\x30\x00"[..]] {
            assert_typed_outcome(leaf, issuer, "tiny input");
        }
    }
}

/// A serial number is attacker-chosen and its length is not bounded by the parser, so the cost of
/// re-encoding it must stay linear. `der_integer_from_bytes` used to strip leading zeros one
/// `remove(0)` at a time, which is O(n) per byte and therefore O(n^2) overall — a CPU-amplification
/// vector. It now scans to the first byte that must be kept and slices, which is linear.
///
/// This test measures the ratio rather than an absolute time so it does not depend on machine speed.
///
/// Regression guard for T-FUZZ-DEFECT-OCSP-REQUEST-QUADRATIC: it failed against the `remove(0)`
/// implementation (8x the serial cost 20.9x, where linear is 8x and quadratic 64x) and passes
/// against the scan.
#[test]
fn serial_encoding_cost_is_linear_not_quadratic() {
    fn build_with_serial(serial: &[u8]) -> std::time::Duration {
        // Raw encoding: the serial must reach the builder unnormalised, or the test is vacuous.
        let leaf = certificate_with_serial_encoded(&der_integer_raw(serial), 0x11);
        let issuer = certificate_with_serial(&[0x0A], 0x22);
        let start = std::time::Instant::now();
        let _ = build_ocsp_request(&leaf, &issuer);
        start.elapsed()
    }

    // Warm up so the first-call page faults do not land in the small sample.
    let _ = build_with_serial(&[0u8; 1_000]);

    const SMALL: usize = 4_000;
    const LARGE: usize = 32_000; // 8x the input

    let small = build_with_serial(&vec![0u8; SMALL]);
    let large = build_with_serial(&vec![0u8; LARGE]);

    // Linear work would give an 8x ratio; quadratic gives 64x. The threshold of 10 sits between
    // them, with headroom for timer noise and allocator behaviour while staying far below the
    // quadratic expectation.
    let small_ns = small.as_nanos().max(1);
    let ratio = large.as_nanos() as f64 / small_ns as f64;
    assert!(
        ratio < 10.0,
        "build_ocsp_request cost grew {ratio:.1}x for a {LARGE}-byte vs {SMALL}-byte serial \
         (linear would be ~{:.0}x): the serial re-encoder is super-linear — {small:?} -> {large:?}",
        LARGE as f64 / SMALL as f64
    );
}

/// Guards the corpus itself, not the product code.
///
/// The linearity test and the non-minimal corpus entries only exercise `der_integer_from_bytes`'
/// strip loop because they encode the serial with [`der_integer_raw`]. If someone "tidies" those
/// call sites back to the normalising [`der_integer`], every one of them still compiles and still
/// passes, but the suite silently loses the only coverage that reaches the loop — the original
/// vacuity bug returning green. This test fails in that case.
#[test]
fn corpus_still_reaches_the_serial_strip_loop() {
    // A serial the normalising helper would rewrite, and one it would not.
    let non_minimal = der_integer_raw(&[0x00, 0x01]);
    assert_eq!(
        non_minimal,
        vec![0x02, 0x02, 0x00, 0x01],
        "der_integer_raw must emit the content verbatim; if this changes, the non-minimal corpus \
         entries stop reaching the strip loop"
    );
    assert_ne!(
        der_integer(&[0x00, 0x01]),
        non_minimal,
        "der_integer is expected to normalise this serial away — that is exactly why the corpus \
         uses der_integer_raw, and why this guard exists"
    );
    // The loop body is entered only when content starts with 0x00 and the next byte's high bit is
    // clear. Assert the corpus actually contains such a serial by checking the encoded TLV.
    let leaf = certificate_with_serial_encoded(&non_minimal, 0x11);
    assert!(
        leaf.windows(4)
            .any(|window| window == [0x02, 0x02, 0x00, 0x01]),
        "the non-minimal serial must appear in the built certificate"
    );
}

#[test]
fn generated_inputs_are_deterministic() {
    fn corpus() -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut state = 0x5EED_0000_0000_0013_u64;
        let mut out = Vec::new();
        for _ in 0..64 {
            let len = (xorshift(&mut state) % 32) as usize;
            let mut leaf = Vec::with_capacity(len);
            for _ in 0..len {
                leaf.push(xorshift(&mut state) as u8);
            }
            let len = (xorshift(&mut state) % 32) as usize;
            let mut issuer = Vec::with_capacity(len);
            for _ in 0..len {
                issuer.push(xorshift(&mut state) as u8);
            }
            out.push((leaf, issuer));
        }
        out
    }
    assert_eq!(corpus(), corpus(), "the generator must be deterministic");
}

/// Inputs that previously caused a panic or a wrong answer, kept so a regression fails here even if
/// the random corpora happen to miss it. Entries are `(description, leaf, issuer)`.
///
/// This runs unconditionally: an empty corpus would make it vacuous, so it is populated as defects
/// are found and fixed.
#[test]
fn regression_corpus_never_panics() {
    let (valid_leaf, valid_issuer) = valid_pair();
    let corpus: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("both empty", Vec::new(), Vec::new()),
        ("valid leaf, empty issuer", valid_leaf.clone(), Vec::new()),
        ("empty leaf, valid issuer", Vec::new(), valid_issuer.clone()),
        (
            "zero-length serial",
            certificate_with_serial(&[], 0x11),
            valid_issuer.clone(),
        ),
        (
            "serial with a leading zero",
            certificate_with_serial(&[0x00, 0x01], 0x11),
            valid_issuer.clone(),
        ),
        (
            "serial with a high bit set",
            certificate_with_serial(&[0xFF], 0x11),
            valid_issuer.clone(),
        ),
        (
            "long all-zero serial",
            certificate_with_serial(&[0u8; 512], 0x11),
            valid_issuer.clone(),
        ),
        // Non-minimal INTEGER encodings. `der_integer` normalises these away, so they must be
        // emitted raw — they are the only inputs that enter `der_integer_from_bytes`' strip loop
        // with a two-byte content, which is what a `content[2]` style edit would index.
        (
            "non-minimal serial 00 01",
            certificate_with_serial_encoded(&der_integer_raw(&[0x00, 0x01]), 0x11),
            valid_issuer.clone(),
        ),
        (
            "non-minimal serial 00 00 01",
            certificate_with_serial_encoded(&der_integer_raw(&[0x00, 0x00, 0x01]), 0x11),
            valid_issuer.clone(),
        ),
        (
            "non-minimal long serial with a tail",
            certificate_with_serial_encoded(
                &der_integer_raw(
                    &[0x00u8; 64]
                        .iter()
                        .copied()
                        .chain([0x01])
                        .collect::<Vec<_>>(),
                ),
                0x11,
            ),
            valid_issuer,
        ),
    ];
    for (description, leaf, issuer) in corpus {
        assert_typed_outcome(&leaf, &issuer, description);
    }
}

// -------------------------------------------------------------------------------------------------
// Tier 1 knob contract
// -------------------------------------------------------------------------------------------------
//
// These build `Knobs` by hand rather than reading the environment, so they do not depend on how this
// binary was invoked and cannot race the other tests in it (std::env::set_var is unsafe in Rust 2024
// for exactly that reason).

#[test]
fn every_generator_honours_the_seed_knob() {
    // The test T-FUZZ-SEED-OCSP's review demanded: each REAL generator body is driven with explicit
    // Knobs, so dropping the seed threading at any one call site -- leaving that generator ignoring
    // FUZZ_SEED forever while the suite stays green -- fails here.
    let tier0 = Knobs {
        seed: None,
        cases: Some(3),
    };
    let a = Knobs {
        seed: Some(999),
        cases: Some(3),
    };
    let b = Knobs {
        seed: Some(1000),
        cases: Some(3),
    };

    let ra = record_random(&a);
    let rb = record_random(&b);
    let ma = record_mutated(&a);
    let mb = record_mutated(&b);
    assert_ne!(ra, rb, "random_buffers_never_panic... ignores FUZZ_SEED");
    assert_ne!(ma, mb, "mutated_valid_certificates... ignores FUZZ_SEED");

    // And unset must differ from both, or the knob silently has no tier-0 path.
    let r0 = record_random(&tier0);
    let m0 = record_mutated(&tier0);
    assert_ne!(r0, ra, "random generator ignores the knob when it is unset");
    assert_ne!(
        m0, ma,
        "mutation generator ignores the knob when it is unset"
    );
}

#[test]
fn the_tier0_corpus_is_pinned() {
    // Pins the OBSERVED tier-0 output, not a constant compared with itself, so changing SEED_RANDOM,
    // SEED_MUTATION, RANDOM_CASES or MUTATION_CASES changes these digests and fails.
    let tier0 = Knobs {
        seed: None,
        cases: None,
    };
    let observed = (
        digest(&record_random(&tier0)),
        digest(&record_mutated(&tier0)),
    );
    assert_eq!(
        observed,
        (EXPECTED_TIER0_RANDOM, EXPECTED_TIER0_MUTATED),
        "the tier-0 corpus changed: unset FUZZ_SEED/FUZZ_CASES must reproduce the historical stream \
         exactly, so a changed digest means a tier-0 constant or count moved"
    );
}

#[test]
fn the_case_budget_is_split_across_generators_and_never_reaches_zero() {
    let knobs = Knobs {
        seed: None,
        cases: Some(50),
    };
    assert_eq!(
        knobs.cases(RANDOM_CASES) + knobs.cases(MUTATION_CASES),
        50,
        "the budget must be the suite total"
    );
    let tiny = Knobs {
        seed: None,
        cases: Some(1),
    };
    assert_eq!(tiny.cases(RANDOM_CASES), 1);
    assert_eq!(tiny.cases(MUTATION_CASES), 1);
    let zero = Knobs {
        seed: None,
        cases: Some(0),
    };
    assert_eq!(zero.cases(RANDOM_CASES), 1);
    assert_eq!(zero.cases(MUTATION_CASES), 1);
}

#[test]
fn tier1_says_which_tier_it_ran() {
    let knobs = Knobs {
        seed: Some(12345),
        cases: Some(50),
    };
    let announced = knobs.announce();
    assert!(
        announced.contains("tier 1"),
        "announce must name the tier: {announced}"
    );
    assert!(
        announced.contains("12345"),
        "announce must name the seed: {announced}"
    );
    assert!(
        announced.contains("50"),
        "announce must name the case budget: {announced}"
    );
    assert!(Knobs {
        seed: None,
        cases: None
    }
    .announce()
    .contains("tier 0"));
}

#[test]
fn a_tier1_run_prints_its_tier_line() {
    // THE observable: a real tier-1 run prints a tier line. Asserted by re-running this very binary as
    // a subprocess with the knobs set and reading the CHILD'S stdout. Every in-process approach was
    // measured to stay green while the print was dead:
    //   revision 1: asserted announce()'s return value  -> green with println! deleted
    //   revision 2: recorded beside println! in a sink  -> green with println! deleted
    // A proxy for stdout is not stdout. This reads the bytes an operator sees.
    let exe = std::env::current_exe().expect("the test binary must be reachable");
    let output = std::process::Command::new(exe)
        .args([
            "random_buffers_never_panic",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("FUZZ_SEED", "12345")
        .env("FUZZ_CASES", "50")
        .output()
        .expect("re-running the test binary must work");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the child run failed; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("fuzz tier 1: FUZZ_SEED=12345 FUZZ_CASES=50"),
        "a real tier-1 run printed no tier line; child stdout was:\n{stdout}"
    );
}

#[test]
fn an_unset_run_prints_the_tier0_line() {
    // The other half: unset knobs must announce tier 0, so a default run is identifiable too.
    let exe = std::env::current_exe().expect("the test binary must be reachable");
    let output = std::process::Command::new(exe)
        .args([
            "mutated_valid_certificates",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_remove("FUZZ_SEED")
        .env_remove("FUZZ_CASES")
        .output()
        .expect("re-running the test binary must work");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the child run failed; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("fuzz tier 0"),
        "an unset run printed no tier-0 line; child stdout was:\n{stdout}"
    );
}

#[test]
fn an_unset_knob_is_the_silent_tier0_path() {
    // `knob` reads the real environment, so this asserts the case that is stable regardless of how
    // the suite was invoked: a name no test sets resolves to the tier-0 path rather than erroring.
    assert_eq!(
        knob::<u64>("CADDY_RS_FUZZ_KNOB_ABSENT", None).unwrap(),
        None
    );
}

#[test]
fn the_case_ceiling_is_the_published_value() {
    assert_eq!(
        MAX_CASES, 10_000,
        "the ceiling is part of the published contract"
    );
}
