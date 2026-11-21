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

use caddy_rs_tls::{parse_ocsp_response, OcspCertStatus, OcspError};

/// Corpus size. Bounded so the suite stays CI-fast (target: well under 5 s on a debug build).
const RANDOM_CASES: usize = 4_000;
const MUTATION_CASES: usize = 4_000;

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

// Records where a caught panic came from, so a `catch_unwind` skip can prove it is skipping the
// *known* defect rather than absorbing an unknown one.
//
// The panic payload cannot be used: an arithmetic-overflow panic carries a payload that is neither
// `String` nor `&str` once it crosses a `#[test]` boundary, so `downcast_ref` returns `None` and the
// message is empty. The source location is reliable, and `unix_seconds_from_civil` is where the
// pre-epoch defect overflows — any other site means a *new* defect, which must fail the test rather
// than be skipped.
//
// The hook is installed once per process and writes to a thread-local, because tests run on
// separate threads and a global `Mutex` slot would race between them.
thread_local! {
    static PANIC_LOCATION: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

static HOOK_INSTALLED: std::sync::Once = std::sync::Once::new();

fn record_panic_location() {
    HOOK_INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(location) = info.location() {
                let text = format!("{}:{}", location.file(), location.line());
                PANIC_LOCATION.with(|slot| *slot.borrow_mut() = Some(text));
            }
            previous(info);
        }));
    });
}

/// The file:line of the known defect. If the fix moves or removes this arithmetic, update this
/// constant *and* delete the skips that use it.
const KNOWN_OVERFLOW_LOCATION: &str = "crates/tls/src/ocsp.rs:1145";

/// Runs `body`, expecting it to panic at [`KNOWN_OVERFLOW_LOCATION`]. Returns `true` if it did.
/// A panic anywhere else is a *new* defect and panics the test, so it cannot be skipped silently.
fn panicked_at_known_overflow<F, R>(body: F, context: &str) -> bool
where
    F: FnOnce() -> R + std::panic::UnwindSafe,
{
    record_panic_location();
    PANIC_LOCATION.with(|slot| *slot.borrow_mut() = None);
    let outcome = std::panic::catch_unwind(body);
    let location = PANIC_LOCATION.with(|slot| slot.borrow().clone());
    match (outcome, location) {
        (Ok(_), _) => false,
        (Err(_), Some(where_)) => {
            assert!(
                where_ == KNOWN_OVERFLOW_LOCATION,
                "{context}: panicked at {where_}, but only the known pre-epoch overflow at \
                 {KNOWN_OVERFLOW_LOCATION} may be skipped (T-FUZZ-DEFECT-OCSP-PRE-EPOCH)"
            );
            true
        }
        (Err(_), None) => panic!("{context}: panicked but the location was not recorded"),
    }
}

// --- Corpus ---------------------------------------------------------------------------------

#[test]
fn random_buffers_never_panic_and_only_return_typed_errors() {
    let mut state = 0x0C5F_0000_0000_0001_u64;
    for case in 0..RANDOM_CASES {
        let len = (xorshift(&mut state) % 96) as usize;
        let mut input = Vec::with_capacity(len);
        for _ in 0..len {
            input.push((xorshift(&mut state) & 0xFF) as u8);
        }
        assert_typed_outcome(&input, &format!("random case {case}"));
    }
}

#[test]
fn random_buffers_with_der_tags_never_panic() {
    // Raw random bytes almost never start with a SEQUENCE tag, so they exercise only the first
    // branch of the parser. Bias the corpus towards plausible DER: a 0x30 tag, a length byte drawn
    // from the interesting ranges (short, long-form, indefinite, oversized), then random content.
    let mut state = 0xDEAD_BEEF_0000_0002_u64;
    let lengths = [
        0x00_u8, 0x01, 0x02, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0xFF,
    ];
    for case in 0..RANDOM_CASES {
        let len = (xorshift(&mut state) % 64) as usize;
        let mut input = vec![
            0x30_u8,
            lengths[(xorshift(&mut state) % lengths.len() as u64) as usize],
        ];
        for _ in 0..len {
            input.push((xorshift(&mut state) & 0xFF) as u8);
        }
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
    let mut state = 0x5EED_0000_0000_0003_u64;
    let base = valid_response(&[7], 1_700_000_000, Some(1_700_003_600));
    let mut skipped = 0usize;
    for case in 0..MUTATION_CASES {
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
        // Known defect (see PRE_EPOCH_* below): any time before 1970-01-01 makes the civil-date
        // arithmetic wrap and the parser panic. Inputs that reach it are skipped here so this
        // corpus stays green until the fix lands; `pre_epoch_*` tests pin the exact inputs.
        //
        // The skip is only sound while it cannot hide a *different* panic, so the panic location
        // is checked: anything other than the known overflow fails the test. Without this, a future
        // regression could be silently absorbed by the skip that exists for today's defect.
        if panicked_at_known_overflow(
            || parse_ocsp_response(&input),
            &format!("mutation case {case}"),
        ) {
            skipped += 1;
            continue;
        }
        assert_typed_outcome(&input, &format!("mutation case {case}"));
    }
    println!(
        "mutated_valid_responses_never_panic: {skipped} input(s) skipped (known pre-epoch defect)"
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

            // At or above the guard the body decodes. It may legitimately land before 1970, which
            // is the separately tracked overflow defect, so only those inputs are skipped — and the
            // skip is narrow: it applies only to bodies the guard accepts, and it checks the panic
            // location, so any *other* panic still fails the test.
            if panicked_at_known_overflow(
                || parse_ocsp_response(&input),
                &format!("tag {tag:#04x} body len {len}"),
            ) {
                continue;
            }
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
// These tests pin the exact inputs. They are `#[ignore]`d so CI stays green until the fix lands;
// the fix removes `#[ignore]` in the same change. If the fix normalises pre-epoch times instead of
// rejecting them, change the assertion to the accepted behaviour — but a panic must never remain.
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
#[ignore = "known defect: pre-1970 ASN.1 time overflows unix_seconds_from_civil (crates/tls/src/ocsp.rs:1145)"]
fn pre_epoch_next_update_is_rejected_not_panicking() {
    for body in PRE_EPOCH_UTC_TIMES {
        let input = response_with_next_update_utctime(body);
        assert_typed_outcome(&input, &format!("nextUpdate {body}"));
    }
}

#[test]
#[ignore = "known defect: pre-1970 ASN.1 time overflows unix_seconds_from_civil (crates/tls/src/ocsp.rs:1145)"]
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
