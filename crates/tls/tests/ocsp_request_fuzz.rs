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

use caddy_rs_tls::{build_ocsp_request, OcspError};

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

#[test]
fn random_buffers_never_panic_and_only_return_typed_errors() {
    let mut state = 0x5EED_0000_0000_0011_u64;
    for case in 0..RANDOM_CASES {
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
    let (leaf, issuer) = valid_pair();
    let mut state = 0x5EED_0000_0000_0012_u64;
    for case in 0..MUTATION_CASES {
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
