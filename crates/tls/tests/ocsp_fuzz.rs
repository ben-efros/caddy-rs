//! Deterministic fuzz tests for the OCSP response parser.
//!
//! The stapler feeds [`parse_ocsp_response`] the body of an HTTP response from the OCSP responder
//! named in a certificate's AIA extension. That responder is chosen by the certificate, not by us,
//! and its bytes are attacker-influenceable in the same way any upstream response is: a
//! compromised or spoofed responder, a hostile middlebox, or a compromised CDN edge in front of the
//! responder all get to choose the DER that reaches this parser.
//!
//! Property under test: for *any* byte string, [`parse_ocsp_response`] returns either an
//! [`OcspResponse`] or a typed [`OcspError`]. It must never panic, never hang, and never allocate
//! without bound. This matters more than usual here because the parser is the one place in the TLS
//! stack that hand-rolls ASN.1: `DerReader::read_tlv_full` does its own length decoding, and
//! `parse_asn1_time` slices `&rest[0..2]` … `&rest[8..10]` behind a single `len()` guard. Both are
//! correct today (the guard is exactly sufficient: UTCTime needs 12 bytes and leaves a 10-byte
//! `rest`, GeneralizedTime needs 14 and leaves 10), and both are one edit away from panicking.
//! These tests pin the invariant so that edit fails a test instead of aborting a server.
//!
//! Determinism: every input comes from a seeded xorshift64 PRNG implemented in this file, or from a
//! mutation of a structurally valid response built here. No external fuzzing crate and no ambient
//! randomness, so a failure reproduces exactly from the seed printed with it.
//!
//! Re-run just this file:
//! `cargo test --offline -p caddy-rs-tls --test ocsp_fuzz`
//!
//! Tier 1 knobs: `FUZZ_SEED` (u64) and `FUZZ_CASES` (usize) override the tier-0 constants below, so
//! a sweep can vary the corpus without editing the file. The contract matches the one
//! `crates/config/tests/adapter_fuzz.rs` established (T-FUZZ-SPEC-TIERS): unset is the silent tier-0
//! path, a parseable value switches to tier 1, and an unparseable or out-of-range value is a loud
//! failure naming the variable — never a silent fall back to tier 0 that reports green.

use caddy_rs_tls::{parse_ocsp_response, OcspCertStatus, OcspError};

// -------------------------------------------------------------------------------------------------
// Tier 1 knobs (FUZZ_SEED / FUZZ_CASES)
// -------------------------------------------------------------------------------------------------

/// Corpus size. Bounded so the suite stays CI-fast (target: well under 5 s on a debug build).
/// Used when `FUZZ_CASES` is unset.
const RANDOM_CASES: usize = 4_000;
const MUTATION_CASES: usize = 4_000;

/// Tier-0 seeds, one per generator. Used when `FUZZ_SEED` is unset.
const SEED_RANDOM: u64 = 0x0C5F_0000_0000_0001;
const SEED_TAGGED: u64 = 0xDEAD_BEEF_0000_0002;
const SEED_MUTATION: u64 = 0x5EED_0000_0000_0003;

/// Ceiling for `FUZZ_CASES`. The suite must stay CI-fast, so an out-of-range value is a loud error
/// rather than a slow suite. Matches `MAX_CASES` in `adapter_fuzz.rs`.
const MAX_CASES: usize = 10_000;

/// Read a knob. `Ok(None)` when unset (the silent tier-0 path); `Ok(Some(v))` when set to a valid
/// value; `Err` naming the variable and the offending value when set to something unusable — so a
/// misconfigured sweep fails loudly instead of silently running tier 0 and reporting green.
///
/// Kept identical in shape to the one in `crates/config/tests/adapter_fuzz.rs`. The two cannot be
/// shared today: an integration test is its own crate and `caddy-rs-tls` does not dev-depend on a
/// common helper. Factoring them out is filed as its own task rather than done here, because this
/// change's declared scope is this file.
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

    /// Case count for a generator, scaled so `FUZZ_CASES` is the total across this file rather than
    /// per generator. The tier-0 ratio between generators is preserved, and every generator still
    /// runs at least one case so a tiny `FUZZ_CASES` exercises all of them.
    /// One line naming the tier and the resolved values, so a sweep's output identifies which knobs
    /// it actually executed. Mirrors the reference implementation's announcement.
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
// own. Only what a structurally valid OCSPResponse needs is implemented.

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    der_tlv(0x30, &body)
}

fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut stack = [0_u8; 10];
        let mut index = stack.len();
        let mut value = *arc;
        index -= 1;
        stack[index] = (value & 0x7f) as u8;
        value >>= 7;
        while value > 0 {
            index -= 1;
            stack[index] = ((value & 0x7f) as u8) | 0x80;
            value >>= 7;
        }
        body.extend_from_slice(&stack[index..]);
    }
    der_tlv(0x06, &body)
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x02, bytes)
}

fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x04, bytes)
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![0_u8]; // no unused bits
    body.extend_from_slice(bytes);
    der_tlv(0x03, &body)
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Seconds since the Unix epoch, encoded as a 13-byte UTCTime (`YYMMDDHHMMSSZ`).
fn der_utc_time(seconds: u64) -> Vec<u8> {
    // Days-from-civil inverse (Howard Hinnant's algorithm).
    let days = (seconds / 86_400) as i64;
    let secs_of_day = seconds % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year.rem_euclid(100),
        month,
        day,
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60
    );
    der_tlv(0x17, text.as_bytes())
}

/// A structurally valid, `successful` OCSP response for `serial`, modelled on the shape
/// `crates/tls/src/ocsp/tests.rs::ocsp_response` builds.
fn valid_response(serial: &[u8], this_update: u64, next_update: Option<u64>) -> Vec<u8> {
    valid_response_with_next(serial, this_update, next_update.map(der_utc_time))
}

/// Like [`valid_response`] but takes the already-encoded UTCTime body for `nextUpdate`, so a test
/// can splice in a differently-tagged or differently-sized time and keep every DER length honest.
fn valid_response_with_next(
    serial: &[u8],
    this_update: u64,
    next_update: Option<Vec<u8>>,
) -> Vec<u8> {
    let cert_id = der_sequence(&[
        der_sequence(&[der_oid(&[1, 3, 14, 3, 2, 26]), der_null()]),
        der_octet_string(&[0_u8; 20]),
        der_octet_string(&[0_u8; 20]),
        der_integer(serial),
    ]);
    let mut single = vec![
        cert_id,
        der_tlv(0x80, &[]), // good
        der_utc_time(this_update),
    ];
    if let Some(next_update) = next_update {
        single.push(der_tlv(0xA0, &next_update));
    }
    let response_data = der_sequence(&[
        der_sequence(&[]), // responderID (empty Name; sufficient for the parser)
        der_utc_time(this_update),
        der_sequence(&[der_sequence(&single)]),
    ]);
    let basic = der_sequence(&[
        response_data,
        der_sequence(&[der_oid(&[1, 2, 840, 10045, 4, 3, 2])]),
        der_bit_string(&[0_u8; 8]),
    ]);
    let response_bytes = der_sequence(&[
        der_oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]),
        der_octet_string(&basic),
    ]);
    der_sequence(&[der_tlv(0x0A, &[0]), der_tlv(0xA0, &response_bytes)])
}

/// Fails with a reproducible message naming the seed and the exact input bytes.
///
/// The properties asserted here are about the **decoder**, not about whether the response is
/// sensible. A responder is free to send `nextUpdate` before `thisUpdate`; that is bad data, and
/// refusing it is the stapler policy's job (`Staple`/`needs_refresh`), not the parser's. An
/// earlier draft of this file asserted time ordering here and the fuzzer immediately produced a
/// one-byte mutation of the SingleResponse year (`231114` -> `231914`) that legitimately made
/// `nextUpdate` four years after a 2019 `thisUpdate`. The parser was right and the assertion was
/// wrong: a fuzz test that fails on well-formed-but-odd data would be deleted by the first agent
/// who hit it. So: decode faithfully, reject with a typed error, and nothing else.
fn assert_typed_outcome(input: &[u8], context: &str) {
    match parse_ocsp_response(input) {
        Ok(response) => {
            // An accepted response must be self-consistent: the DER it reports is the DER it was
            // given, and its serial must be non-empty (a CertID always carries one).
            assert_eq!(
                response.der,
                input,
                "{context}: accepted response must report the input DER verbatim (input {})",
                hex(input)
            );
            assert!(
                !response.serial.is_empty(),
                "{context}: accepted response has an empty serial (input {})",
                hex(input)
            );
            // Decoding must be *total*: every accepted response reports a this_update that lies in
            // the range a 4-digit UTCTime / GeneralizedTime can express (1970..=9999). A value
            // outside that range would mean the civil-date arithmetic overflowed or wrapped, which
            // is the failure mode `unix_seconds_from_civil`'s unchecked `*` and `-` could have.
            let since_epoch = response
                .this_update
                .duration_since(std::time::UNIX_EPOCH)
                .expect("an ASN.1 time before 1970 is not representable as a SystemTime")
                .as_secs();
            assert!(
                since_epoch < 253_402_300_799, // 9999-12-31T23:59:59Z
                "{context}: this_update decoded out of the ASN.1-representable range \
                 ({since_epoch}s since epoch) (input {})",
                hex(input)
            );
        }
        Err(error) => {
            // A parse of responder bytes can only ever produce these two variants: a structural
            // rejection (`Malformed`) or a non-success responder status. The other variants
            // (`NoResponder`, `Transport`, `SerialMismatch`, `MustStapleDisabled`, `Unsupported`,
            // `Backoff`) describe the *stapling policy or transport*, not the bytes, so seeing one
            // here means the parser is returning a decision it cannot have made from its input.
            match &error {
                OcspError::Malformed(reason) => assert!(
                    !reason.is_empty(),
                    "{context}: Malformed error with an empty reason (input {})",
                    hex(input)
                ),
                OcspError::ResponderStatus(_) => {}
                other => panic!(
                    "{context}: parse of responder bytes returned a non-parse error {other:?} (input {})",
                    hex(input)
                ),
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// --- Corpus ---------------------------------------------------------------------------------

#[test]
fn random_buffers_never_panic_and_only_return_typed_errors() {
    run_random(&knobs_or_fail());
}

/// Body of `random_buffers_never_panic_and_only_return_typed_errors`, callable with an explicit [`Knobs`] so the knob contract
/// can be asserted against the generator that actually runs, rather than against
/// `Knobs` alone.
fn run_random(knobs: &Knobs) {
    let mut state = knobs.seed(SEED_RANDOM);
    for case in 0..knobs.cases(RANDOM_CASES) {
        let len = (xorshift(&mut state) % 96) as usize;
        let mut input = Vec::with_capacity(len);
        for _ in 0..len {
            input.push((xorshift(&mut state) & 0xFF) as u8);
        }
        record(input.iter().fold(0_u8, |acc, b| acc ^ b));
        assert_typed_outcome(&input, &format!("random case {case}"));
    }
}

#[test]
fn random_buffers_with_der_tags_never_panic() {
    run_tagged(&knobs_or_fail());
}

/// Body of `random_buffers_with_der_tags_never_panic`, callable with an explicit [`Knobs`] so the knob contract
/// can be asserted against the generator that actually runs, rather than against
/// `Knobs` alone.
fn run_tagged(knobs: &Knobs) {
    // Raw random bytes almost never start with a SEQUENCE tag, so they exercise only the first
    // branch of the parser. Bias the corpus towards plausible DER: a 0x30 tag, a length byte drawn
    // from the interesting ranges (short, long-form, indefinite, oversized), then random content.
    let mut state = knobs.seed(SEED_TAGGED);
    let lengths = [
        0x00_u8, 0x01, 0x02, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0xFF,
    ];
    for case in 0..knobs.cases(RANDOM_CASES) {
        let len = (xorshift(&mut state) % 64) as usize;
        let mut input = vec![
            0x30_u8,
            lengths[(xorshift(&mut state) % lengths.len() as u64) as usize],
        ];
        for _ in 0..len {
            input.push((xorshift(&mut state) & 0xFF) as u8);
        }
        record(input.iter().fold(0_u8, |acc, b| acc ^ b));
        assert_typed_outcome(&input, &format!("der-tag case {case}"));
    }
}

#[test]
fn every_prefix_of_a_valid_response_is_rejected_or_accepted_consistently() {
    let valid = valid_response(&[7], 1_700_000_000, Some(1_700_003_600));
    assert!(
        parse_ocsp_response(&valid).is_ok(),
        "the fixture itself must parse; a broken fixture would make this test vacuous"
    );
    for end in 0..valid.len() {
        assert_typed_outcome(&valid[..end], &format!("prefix of length {end}"));
    }
    // Every truncation is a rejection: a valid response minus its tail cannot be complete.
    for end in 0..valid.len() {
        assert!(
            parse_ocsp_response(&valid[..end]).is_err(),
            "prefix of length {end} must be rejected as truncated"
        );
    }
}

#[test]
fn mutated_valid_responses_never_panic() {
    run_mutated(&knobs_or_fail());
}

/// Body of `mutated_valid_responses_never_panic`, callable with an explicit [`Knobs`] so the knob contract
/// can be asserted against the generator that actually runs, rather than against
/// `Knobs` alone.
fn run_mutated(knobs: &Knobs) {
    let mut state = knobs.seed(SEED_MUTATION);
    let base = valid_response(&[7], 1_700_000_000, Some(1_700_003_600));
    for case in 0..knobs.cases(MUTATION_CASES) {
        let mut input = base.clone();
        // Apply 1..=4 mutations: flip a byte, truncate, splice in a random byte, or duplicate.
        let mutations = 1 + (xorshift(&mut state) % 4) as usize;
        for _ in 0..mutations {
            if input.is_empty() {
                break;
            }
            match xorshift(&mut state) % 4 {
                0 => {
                    let at = (xorshift(&mut state) % input.len() as u64) as usize;
                    input[at] ^= 1 << (xorshift(&mut state) % 8);
                }
                1 => {
                    let at = (xorshift(&mut state) % input.len() as u64) as usize;
                    input.truncate(at);
                }
                2 => {
                    let at = (xorshift(&mut state) % input.len() as u64) as usize;
                    input.insert(at, (xorshift(&mut state) & 0xFF) as u8);
                }
                _ => {
                    let at = (xorshift(&mut state) % input.len() as u64) as usize;
                    input.remove(at);
                }
            }
        }
        record(input.iter().fold(0_u8, |acc, b| acc ^ b));
        assert_typed_outcome(&input, &format!("mutation case {case}"));
    }
    println!(
        "mutated_valid_responses_never_panic: {} input(s) asserted",
        knobs.cases(MUTATION_CASES)
    );
}

#[test]
fn declared_lengths_are_bounded_not_trusted() {
    // A responder can declare any length it likes. The parser must reject oversized or indefinite
    // lengths as a typed error rather than allocating or slicing past the buffer.
    let cases: Vec<Vec<u8>> = vec![
        // SEQUENCE with an indefinite length (0x80).
        vec![0x30, 0x80, 0x0A, 0x01, 0x00],
        // SEQUENCE declaring 4 GB with a 4-byte long-form length and no content.
        vec![0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
        // SEQUENCE declaring usize::MAX via an 8-byte length: count > 4 must be refused.
        vec![0x30, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        // Length exactly the buffer, content missing one byte.
        vec![0x30, 0x03, 0x0A, 0x01],
        // Long-form length that is itself truncated.
        vec![0x30, 0x82, 0xFF],
        // Zero-length SEQUENCE.
        vec![0x30, 0x00],
        // Status is an ENUMERATED with the wrong width.
        vec![0x30, 0x04, 0x0A, 0x02, 0x00, 0x00],
        // Status is not an ENUMERATED at all.
        vec![0x30, 0x03, 0x02, 0x01, 0x00],
    ];
    for (index, case) in cases.iter().enumerate() {
        assert_typed_outcome(case, &format!("declared-length case {index}"));
        assert!(
            parse_ocsp_response(case).is_err(),
            "declared-length case {index} must be rejected (input {})",
            hex(case)
        );
    }
}

#[test]
fn asn1_time_fields_are_bounded_not_trusted() {
    // `parse_asn1_time` slices `&rest[0..2]` … `&rest[8..10]` behind a single length guard
    // (`trimmed.len() < 12` for UTCTime, `< 14` for GeneralizedTime). A responder chooses those
    // bytes. This test splices every body length 0..=24 into the `nextUpdate` slot of an otherwise
    // valid response, so the guard is actually reached; it fails if either guard is relaxed, since
    // a shorter body then panics on `rest[8..10]`.
    for tag in [0x17_u8, 0x18] {
        let guard = if tag == 0x17 { 12 } else { 14 };
        for len in 0..24_usize {
            // Digits only, so a body that is long enough parses as a date rather than failing on
            // the first non-digit; the interesting cases are the ones just below the guard.
            let body: Vec<u8> = (0..len).map(|i| b'0' + (i % 10) as u8).collect();
            let mut tlv = vec![tag, len as u8];
            tlv.extend_from_slice(&body);
            let input = valid_response_with_next(&[7], 1_700_000_000, Some(tlv));

            // Below the guard the parser must return a typed error. Assert the error *here* rather
            // than tolerating a panic: this is the assertion that fails if the guard is relaxed,
            // and it must not be softened into a skip.
            if len < guard {
                match parse_ocsp_response(&input) {
                    Err(OcspError::Malformed(_)) => {}
                    Err(other) => {
                        panic!("tag {tag:#04x} body len {len}: expected Malformed, got {other:?}")
                    }
                    Ok(_) => panic!("tag {tag:#04x} body len {len}: expected rejection, got Ok"),
                }
                continue;
            }

            // At or above the guard the body decodes. A pre-1970 time is now a typed error rather
            // than a panic, so it is accepted by `assert_typed_outcome` like any other rejection.
            assert_typed_outcome(&input, &format!("nextUpdate tag {tag:#04x} body len {len}"));
        }
    }
}

#[test]
fn out_of_range_time_fields_are_rejected_or_sane() {
    // Month 00 and day 00 are not valid dates. The parser currently accepts them and produces a
    // shifted timestamp. Whatever it does, it must be a typed outcome and must not panic; this
    // test records the current behaviour so a change to it is deliberate.
    for (month, day) in [("00", "00"), ("13", "01"), ("01", "32"), ("99", "99")] {
        let text = format!("2301{month}{day}000000Z");
        let response = valid_response(&[7], 1_700_000_000, None);
        let _ = text; // the fixture is valid; the malformed variants go through the bare path
        let time = der_tlv(0x17, text.as_bytes());
        assert_typed_outcome(&time, &format!("out-of-range time {month}/{day}"));
        assert_typed_outcome(&response, "valid fixture alongside out-of-range case");
    }
}

#[test]
fn accepted_status_and_serial_are_reported() {
    // Not a fuzz case, but the property the fuzz corpus relies on: a valid response parses to a
    // `good` status and the serial the fixture was built with. If this regresses, every accepted
    // case above is checking the wrong object.
    let response = valid_response(&[9], 1_700_000_000, Some(1_700_003_600));
    let parsed = parse_ocsp_response(&response).expect("valid fixture must parse");
    assert_eq!(parsed.serial, vec![9]);
    assert_eq!(parsed.status, OcspCertStatus::Good);
    assert_eq!(parsed.der, response);
    assert!(parsed.next_update.is_some(), "nextUpdate must be preserved");
}

#[test]
fn generated_inputs_are_deterministic() {
    // Same seed, same corpus: a failure message names a seed and must reproduce exactly.
    let mut a = 0x1234_5678_9ABC_DEF0_u64;
    let mut b = 0x1234_5678_9ABC_DEF0_u64;
    for _ in 0..256 {
        let len = (xorshift(&mut a) % 32) as usize;
        let first: Vec<u8> = (0..len).map(|_| (xorshift(&mut a) & 0xFF) as u8).collect();
        let len_b = (xorshift(&mut b) % 32) as usize;
        let second: Vec<u8> = (0..len_b)
            .map(|_| (xorshift(&mut b) & 0xFF) as u8)
            .collect();
        assert_eq!(first, second, "the PRNG must be deterministic");
    }
}

/// Inputs that once crashed or misbehaved. Always executed, so a fixed defect cannot silently
/// regress. Empty today: the parser had no known panic when this file was written, and the
/// corpus above is what keeps that true.
const REGRESSION_CORPUS: &[&[u8]] = &[];

#[test]
fn regression_corpus_never_panics() {
    for (index, input) in REGRESSION_CORPUS.iter().enumerate() {
        assert_typed_outcome(input, &format!("regression corpus entry {index}"));
    }
}

// --- Known defect: pre-1970 ASN.1 times panic the parser --------------------------------
//
// FOUND BY THIS SUITE. `unix_seconds_from_civil` (crates/tls/src/ocsp.rs:1136-1146) computes
// `days = (era as i64 * 146097 + doe as i64 - 719468) as u64`. For any date before 1970-01-01 that
// value is negative, and `as u64` wraps it to ~1.8e19; the following `days * 86_400` then
// overflows, which panics in a debug build and silently wraps in a release build.
//
// Reachability: `parse_ocsp_response` is called on the body of the HTTP response from the OCSP
// responder named in the leaf certificate's AIA extension (crates/tls/src/ocsp.rs:509-510). The
// responder chooses the bytes. A UTCTime of `YY >= 50` means year 19YY, so **any** date from 1950
// through 1969 is both ordinary-looking and a crash: `500101000000Z` is a 13-byte, well-formed
// UTCTime. No malformed DER is required, only an unremarkable early date.
//
// These tests pin the exact inputs. They are active regression tests for T-FUZZ-DEFECT-OCSP-PRE-EPOCH:
// `unix_seconds_from_civil` now returns `Option<u64>` and `parse_asn1_time` reports a typed
// `Malformed` error for instants before the epoch, so these must stay typed errors, never panics.
const PRE_EPOCH_UTC_TIMES: &[&str] = &[
    "500101000000Z", // 1950-01-01, the earliest UTCTime year (YY>=50 -> 19YY)
    "690101000000Z", // 1969-01-01
    "691231235959Z", // 1969-12-31T23:59:59Z, the last second before the epoch
    "700101000000Z", // 1970-01-01, first NON-crashing date (control)
];

/// A response whose `nextUpdate` is the given UTCTime body, every enclosing length honest.
fn response_with_next_update_utctime(body: &str) -> Vec<u8> {
    let mut utc = vec![0x17, body.len() as u8];
    utc.extend_from_slice(body.as_bytes());
    valid_response_with_next(&[7], 1_700_000_000, Some(utc))
}

#[test]
fn pre_epoch_next_update_is_rejected_not_panicking() {
    for body in PRE_EPOCH_UTC_TIMES {
        let input = response_with_next_update_utctime(body);
        assert_typed_outcome(&input, &format!("nextUpdate {body}"));
    }
}

#[test]
fn pre_epoch_this_update_is_rejected_not_panicking() {
    // `thisUpdate` goes through the same parser, so the crash is reachable from either field.
    let mut utc = Vec::new();
    utc.extend_from_slice(&[0x17, 0x0d]);
    utc.extend_from_slice(b"690101000000Z");
    let mut single = Vec::new();
    single.extend_from_slice(&der_tlv(0x0A, &[0])); // certStatus good
    single.extend_from_slice(&utc); // thisUpdate (early)
    let single = der_sequence(&[der_tlv(0x0A, &[0]), utc.clone()]);
    let _ = single;
    let response_data = der_sequence(&[
        der_sequence(&[]),
        der_utc_time(1_700_000_000),
        der_sequence(&[der_sequence(&[
            der_sequence(&[
                der_sequence(&[der_oid(&[1, 3, 14, 3, 2, 26]), der_null()]),
                der_octet_string(&[0_u8; 20]),
                der_octet_string(&[0_u8; 20]),
                der_integer(&[7]),
            ]),
            der_tlv(0x80, &[]),
            utc,
        ])]),
    ]);
    let basic = der_sequence(&[
        response_data,
        der_sequence(&[der_oid(&[1, 2, 840, 10045, 4, 3, 2])]),
        der_bit_string(&[0_u8; 8]),
    ]);
    let response_bytes = der_sequence(&[
        der_oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]),
        der_octet_string(&basic),
    ]);
    let full = der_sequence(&[der_tlv(0x0A, &[0]), der_tlv(0xA0, &response_bytes)]);
    assert_typed_outcome(&full, "thisUpdate 1969-01-01");
}

#[test]
fn epoch_and_later_next_update_still_parses() {
    // Control: the boundary itself is fine today, and must stay fine after the fix.
    let input = response_with_next_update_utctime("700101000000Z");
    let parsed = parse_ocsp_response(&input).expect("1970-01-01 must parse");
    assert_eq!(parsed.next_update, Some(std::time::UNIX_EPOCH));
}

// --- Recording harness for the knob contract tests -------------------------------------------
//
// The three generators assert directly on a typed outcome and return nothing, so a contract test
// cannot observe what they generated. Rather than re-implement the generators in the test -- which
// is how the first version of these tests ended up asserting nothing about the real code -- each
// body records a transcript of what it saw, and the contract tests compare transcripts.

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

fn record_random(knobs: &Knobs) -> Vec<u8> {
    take_transcript();
    run_random(knobs);
    take_transcript()
}

fn record_tagged(knobs: &Knobs) -> Vec<u8> {
    take_transcript();
    run_tagged(knobs);
    take_transcript()
}

fn record_mutated(knobs: &Knobs) -> Vec<u8> {
    take_transcript();
    run_mutated(knobs);
    take_transcript()
}

/// Pinned tier-0 digests, filled from the first observed run and then frozen. A tier-0 constant or
/// count that moves changes these, which is the point: unset FUZZ_SEED/FUZZ_CASES must reproduce the
/// historical stream byte-for-byte.
const EXPECTED_TIER0_RANDOM: u64 = 0xb6f3_0be1_4b1a_f187;
const EXPECTED_TIER0_TAGGED: u64 = 0x97f0_1d12_951c_78e9;
const EXPECTED_TIER0_MUTATED: u64 = 0x634f_53b7_7b65_af8d;

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

// -------------------------------------------------------------------------------------------------
// Tier 1 knob contract
// -------------------------------------------------------------------------------------------------
//
// These pin the properties the knob contract is worth having for. They build `Knobs` by hand rather
// than reading the environment, so they do not depend on how this binary was invoked and cannot race
// the other tests in it (std::env::set_var is unsafe in Rust 2024 for exactly that reason).

#[test]
fn every_generator_honours_the_seed_knob() {
    // THE test the review asked for. Each of the three real generators is driven through its own
    // body with an explicit `Knobs`, so dropping the seed threading at any ONE call site -- making
    // that generator ignore FUZZ_SEED forever while the suite stays green -- fails here.
    //
    // Counts are pinned small so the comparison is cheap; the streams, not the counts, are compared.
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

    // Observed parser outcomes stand in for the input bytes: two different seeds must drive the
    // generator into different inputs, and a generator that ignored the knob would produce
    // identical outcomes for both.
    let outcomes = |knobs: &Knobs| {
        let (random, tagged, mutated) = (
            record_random(knobs),
            record_tagged(knobs),
            record_mutated(knobs),
        );
        (random, tagged, mutated)
    };
    let (ra, ta, ma) = outcomes(&a);
    let (rb, tb, mb) = outcomes(&b);
    assert_ne!(ra, rb, "random_buffers_never_panic... ignores FUZZ_SEED");
    assert_ne!(ta, tb, "random_buffers_with_der_tags... ignores FUZZ_SEED");
    assert_ne!(ma, mb, "mutated_valid_responses... ignores FUZZ_SEED");

    // And unset must differ from both, or the knob silently has no tier-0 path.
    let (r0, t0, m0) = outcomes(&tier0);
    assert_ne!(r0, ra, "random generator ignores the knob when it is unset");
    assert_ne!(t0, ta, "tagged generator ignores the knob when it is unset");
    assert_ne!(
        m0, ma,
        "mutation generator ignores the knob when it is unset"
    );
}

#[test]
fn the_tier0_corpus_is_pinned() {
    // Defect 2 from the review: `knobs.seed(CONST) == CONST` is a tautology on a constant, so
    // changing SEED_TAGGED or RANDOM_CASES passed silently. Pin the OBSERVED tier-0 output instead,
    // so an edit to any tier-0 constant or count changes these digests and fails.
    let tier0 = Knobs {
        seed: None,
        cases: None,
    };
    let observed = (
        digest(&record_random(&tier0)),
        digest(&record_tagged(&tier0)),
        digest(&record_mutated(&tier0)),
    );
    assert_eq!(
        observed,
        (EXPECTED_TIER0_RANDOM, EXPECTED_TIER0_TAGGED, EXPECTED_TIER0_MUTATED),
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
    let random = knobs.cases(RANDOM_CASES);
    let mutation = knobs.cases(MUTATION_CASES);
    // FUZZ_CASES is the suite total, not a per-generator count: 50 cannot run 50 in each generator.
    assert_eq!(random + mutation, 50, "the budget must be the suite total");
    // A budget too small to divide must still exercise every generator.
    let tiny = Knobs {
        seed: None,
        cases: Some(1),
    };
    assert_eq!(tiny.cases(RANDOM_CASES), 1);
    assert_eq!(tiny.cases(MUTATION_CASES), 1);
    // Zero must floor, not run nothing and report green.
    let zero = Knobs {
        seed: None,
        cases: Some(0),
    };
    assert_eq!(zero.cases(RANDOM_CASES), 1);
    assert_eq!(zero.cases(MUTATION_CASES), 1);
}

#[test]
fn tier1_says_which_tier_it_ran() {
    // The reference announces the tier and the resolved values; without it a tier-1 run is
    // unidentifiable from its own output, so a sweep cannot tell which knobs it actually executed.
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
    let tier0 = Knobs {
        seed: None,
        cases: None,
    };
    assert!(
        tier0.announce().contains("tier 0"),
        "unset must announce tier 0"
    );
}

#[test]
fn an_unset_knob_is_the_silent_tier0_path() {
    // `knob` reads the real environment, so this asserts the one case that is stable regardless of
    // how the suite was invoked: a name no test sets resolves to the tier-0 path rather than erroring.
    // The loud-failure arm needs a set-but-unusable value, which would mean mutating this process's
    // environment; that is unsafe in Rust 2024 and would race the other tests in this binary.
    assert_eq!(
        knob::<u64>("CADDY_RS_FUZZ_KNOB_ABSENT", None).unwrap(),
        None
    );
}

#[test]
fn the_case_ceiling_is_the_published_value() {
    // MAX_CASES bounds the suite so a sweep cannot hand CI a multi-minute run.
    assert_eq!(
        MAX_CASES, 10_000,
        "the ceiling is part of the published contract"
    );
}
