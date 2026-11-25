//! Review round 2 for SEC-MEDIUM D1: parser hardening (network-reachable panics), strict DER
//! envelope, revocation/expiry handling, serial comparison and signature-algorithm policy.

use super::*;

/// Replace the first `needle` in `haystack` with `replacement` (same length).
fn patch_bytes(haystack: &mut [u8], needle: &[u8], replacement: &[u8]) {
    assert_eq!(needle.len(), replacement.len());
    let at = haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("needle present");
    haystack[at..at + needle.len()].copy_from_slice(replacement);
}

#[test]
fn asn1_time_with_multibyte_characters_is_an_error_not_a_panic() {
    // "201é0101000000Z": the é (C3 A9) straddles the `[0..4]` / `[4..6]` slice boundary.
    assert!(parse_asn1_time(0x18, "201é0101000000Z".as_bytes()).is_err());
    // UTCTime `17 0E 32 C3 A9 ...`: the é sits inside the YY slice.
    assert!(parse_asn1_time(0x17, b"2\xC3\xA9\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30Z").is_err());
    // Multi-byte characters anywhere, in every position, and non-UTF-8 bytes.
    for position in 0..14 {
        let mut bytes = b"20231114221320Z".to_vec();
        bytes.splice(position..position + 1, [0xC3, 0xA9]);
        assert!(
            parse_asn1_time(0x18, &bytes).is_err(),
            "position {position}"
        );
        let mut bytes = b"231114221320Z".to_vec();
        let at = position.min(11);
        bytes.splice(at..at + 1, [0xFF]);
        assert!(parse_asn1_time(0x17, &bytes).is_err(), "utc {position}");
    }
    // Signs, spaces and other non-digits that `str::parse` used to accept.
    for bad in ["+023111422132Z", "2023-114221320Z", " 0231114221320Z"] {
        assert!(parse_asn1_time(0x18, bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn asn1_time_field_ranges_are_validated() {
    // Day 00 / month 00 used to underflow `day - 1` (a panic in debug, a wrap in release).
    for bad in [
        "20230300000000Z", // day 00, month 03
        "20230000000000Z",
        "20231300000000Z", // month 13
        "20230132000000Z", // day 32
        "20230431000000Z", // April has 30 days
        "20230229000000Z", // 2023 is not a leap year
        "20231114240000Z", // hour 24
        "20231114226000Z", // minute 60
        "20231114221360Z", // second 60
        "2023111422132Z",  // too short
        "202311142213200Z",
        "20231114221320X", // not a Z
    ] {
        assert!(parse_asn1_time(0x18, bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(
        parse_asn1_time(0x18, b"20240229000000Z").is_ok(),
        "leap day"
    );
    assert!(parse_asn1_time(0x17, b"231114221320Z").is_ok());
    assert!(
        parse_asn1_time(0x17, b"231114221320").is_ok(),
        "Z is optional"
    );
}

#[test]
fn forged_multibyte_times_in_a_response_are_rejected_before_any_signature_check() {
    let valid = ocsp_response(&[7], START.as_secs(), Some(START.as_secs() + HOUR));
    let text = b"20231114221320Z";
    assert!(valid.windows(text.len()).any(|window| window == text));
    // Same-length replacement: the é lands across a slice boundary of the old code.
    let mut forged = valid.clone();
    let replacement = "202\u{e9}114221320Z"; // 15 bytes
    assert_eq!(replacement.len(), 15);
    patch_bytes(&mut forged, text, replacement.as_bytes());
    assert!(parse_ocsp_response(&forged).is_err());
    // The report's exact producedAt: `18 10 "201é0101000000Z"` spliced in place of the real one
    // (enclosing lengths are stale, which must still be a plain error, never a panic).
    let mut forged = valid.clone();
    let mut produced = vec![0x18, 0x10];
    produced.extend_from_slice("201é0101000000Z".as_bytes());
    let at = (0..forged.len() - 2)
        .find(|&i| forged[i] == 0x18 && forged[i + 1] == 0x0F)
        .expect("producedAt");
    forged.splice(at..at + 17, produced);
    assert!(parse_ocsp_response(&forged).is_err());
}

#[test]
fn every_truncation_and_bit_flip_of_a_valid_response_is_an_error_or_a_clean_result() {
    let pki = pki();
    let (key, subject, cert) = delegated_responder(
        &pki.ca_name,
        &pki.ca,
        Some(true),
        START.as_secs() - HOUR,
        START.as_secs() + 30 * 86_400,
    );
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR)).signed_by(&key);
    spec.responder_id = tlv(0xA1, &subject);
    spec.certs = vec![cert];
    let valid = spec.build();
    assert!(parse_ocsp_response(&valid).is_ok());
    for length in 0..valid.len() {
        assert!(
            parse_ocsp_response(&valid[..length]).is_err(),
            "prefix of {length} bytes must not parse"
        );
    }
    let leaf = ParsedCertificate::parse(&leaf_certificate(&[7], None, false)).unwrap();
    let issuer = ParsedCertificate::parse(&issuer_certificate()).unwrap();
    for index in 0..valid.len() {
        for mask in [0x01u8, 0x80, 0xFF] {
            let mut mutated = valid.clone();
            mutated[index] ^= mask;
            if let Ok(response) = parse_ocsp_response(&mutated) {
                let _ = verify_ocsp_response(&response, &leaf, &issuer, now_at(Duration::ZERO));
            }
        }
    }
}

#[test]
fn bytes_appended_at_any_envelope_level_are_rejected() {
    let pki = pki();
    let (key, subject, cert) = delegated_responder(
        &pki.ca_name,
        &pki.ca,
        Some(true),
        START.as_secs() - HOUR,
        START.as_secs() + 30 * 86_400,
    );
    for with_certs in [true, false] {
        for level in 0..=6usize {
            if level == 5 && !with_certs {
                continue; // no certs wrapper to append to
            }
            let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
            if with_certs {
                spec = spec.signed_by(&key);
                spec.responder_id = tlv(0xA1, &subject);
                spec.certs = vec![cert.clone()];
            }
            assert!(parse_ocsp_response(&spec.build()).is_ok());
            for extra in [vec![0x00u8, 0x00], vec![0x05, 0x00], vec![0x30, 0x00]] {
                spec.extra_at = Some((level, extra.clone()));
                assert!(
                    parse_ocsp_response(&spec.build()).is_err(),
                    "level {level} extra {extra:?} certs {with_certs} was accepted"
                );
            }
        }
    }
}

#[test]
fn non_minimal_length_encodings_are_rejected_at_every_level() {
    for level in 0..=4usize {
        let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
        assert!(parse_ocsp_response(&spec.build()).is_ok());
        spec.nonminimal_level = Some(level);
        assert!(
            parse_ocsp_response(&spec.build()).is_err(),
            "non-minimal length at level {level} was accepted"
        );
    }
    // The report's exact form: `84 00 00 01 23`.
    let valid = ocsp_response(&[7], START.as_secs(), Some(START.as_secs() + HOUR));
    assert_eq!(valid[1], 0x82, "outer length is two bytes");
    let length = ((valid[2] as usize) << 8) | valid[3] as usize;
    let mut rewritten = vec![0x30, 0x84, 0, 0, valid[2], valid[3]];
    rewritten.extend_from_slice(&valid[4..4 + length]);
    assert!(parse_ocsp_response(&rewritten).is_err());
}

#[tokio::test]
async fn a_tampered_envelope_is_never_stapled() {
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    spec.extra_at = Some((6, vec![0x00, 0x00]));
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::Malformed(_)),
        "trailing bytes after a genuine response",
    )
    .await;
}

#[tokio::test]
async fn a_verified_revoked_response_evicts_the_cached_good_staple() {
    let clock = Arc::new(ManualClock::new(now_at(Duration::ZERO)));
    let transport = Arc::new(MockTransport::with(ocsp_response(
        &[7],
        START.as_secs(),
        Some(START.as_secs() + HOUR),
    )));
    let stapler = make_stapler(
        Arc::clone(&transport) as Arc<dyn OcspTransport>,
        OcspPolicy::default(),
        clock.clone(),
    );
    let leaf = leaf_certificate(&[7], Some("http://ocsp.example.test"), false);
    let issuer = issuer_certificate();
    assert_eq!(
        stapler.ensure_staple(&leaf, &issuer).await.unwrap(),
        StapleOutcome::Fetched
    );
    assert!(stapler.staple(&leaf).is_some());
    clock.advance(Duration::from_secs(50 * 60));
    let mut revoked = ResponseSpec::good(
        &[7],
        START.as_secs() + 3_000,
        Some(START.as_secs() + 3_000 + HOUR),
    );
    revoked.status_tag = 0xA1;
    transport.push(revoked.build());
    let error = stapler
        .ensure_staple(&leaf, &issuer)
        .await
        .expect_err("revoked is not stapled");
    assert!(error.to_string().contains("revoked"), "{error}");
    assert!(
        stapler.staple(&leaf).is_none(),
        "the old good staple must not stay in service after a verified revocation"
    );
}

#[tokio::test]
async fn an_expired_cached_staple_is_not_served() {
    let clock = Arc::new(ManualClock::new(now_at(Duration::ZERO)));
    let transport = Arc::new(MockTransport::with(ocsp_response(
        &[7],
        START.as_secs(),
        Some(START.as_secs() + HOUR),
    )));
    let stapler = make_stapler(
        transport as Arc<dyn OcspTransport>,
        OcspPolicy::default(),
        clock.clone(),
    );
    let leaf = leaf_certificate(&[7], Some("http://ocsp.example.test"), false);
    stapler
        .ensure_staple(&leaf, &issuer_certificate())
        .await
        .unwrap();
    assert!(stapler.staple(&leaf).is_some());
    clock.advance(Duration::from_secs(HOUR - 1));
    assert!(
        stapler.staple(&leaf).is_some(),
        "still fresh one second early"
    );
    clock.advance(Duration::from_secs(1));
    assert!(
        stapler.staple(&leaf).is_none(),
        "nextUpdate <= now: the staple must not be served"
    );
}

#[tokio::test]
async fn serial_comparison_distinguishes_negative_from_positive_encodings() {
    // Leaf serial 0x0085 is +133; a response INTEGER `85` is -123. They must not match.
    let leaf = leaf_certificate(&[0x00, 0x85], Some("http://ocsp.example.test"), false);
    let spec = ResponseSpec::good(&[0x85], START.as_secs(), Some(START.as_secs() + HOUR));
    let clock = Arc::new(ManualClock::new(now_at(Duration::ZERO)));
    let stapler = make_stapler(
        Arc::new(MockTransport::with(spec.build())) as Arc<dyn OcspTransport>,
        OcspPolicy::default(),
        clock.clone(),
    );
    let outcome = stapler.ensure_staple(&leaf, &issuer_certificate()).await;
    assert!(
        matches!(
            outcome,
            Err(OcspError::SerialMismatch) | Err(OcspError::Malformed(_))
        ),
        "-123 must not match 133: {outcome:?}"
    );
    // The genuine canonical encoding matches.
    let spec = ResponseSpec::good(&[0x00, 0x85], START.as_secs(), Some(START.as_secs() + HOUR));
    let stapler = make_stapler(
        Arc::new(MockTransport::with(spec.build())) as Arc<dyn OcspTransport>,
        OcspPolicy::default(),
        clock,
    );
    assert_eq!(
        stapler
            .ensure_staple(&leaf, &issuer_certificate())
            .await
            .unwrap(),
        StapleOutcome::Fetched
    );
}

#[test]
fn non_canonical_response_serials_are_malformed() {
    for serial in [vec![0x00, 0x07], vec![0xFF, 0x85], vec![0x00, 0x00, 0x85]] {
        let spec = ResponseSpec::good(&serial, START.as_secs(), Some(START.as_secs() + HOUR));
        let error = parse_ocsp_response(&spec.build()).expect_err("non-minimal INTEGER");
        assert!(
            matches!(error, OcspError::Malformed(_)),
            "{serial:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn a_response_listing_our_certificate_second_fails_closed() {
    // The first SingleResponse is for another serial; ours is second. Only the first is read, so
    // verification fails closed (SerialMismatch) rather than trusting either entry.
    let pki = pki();
    let other = seq(&[
        seq(&[
            seq(&[oid(&[1, 3, 14, 3, 2, 26]), super::super::der_null()]),
            octet(&Sha1::digest(&pki.ca_name)),
            octet(&Sha1::digest(pki.ca.public())),
            tlv(0x02, &[9]),
        ]),
        tlv(0x80, &[]),
        utc_time(START.as_secs()),
    ]);
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR));
    spec.leading_singles = vec![other];
    assert_rejected(
        spec.build(),
        Duration::ZERO,
        |error| matches!(error, OcspError::SerialMismatch),
        "ours second",
    )
    .await;
}

#[tokio::test]
async fn delegate_certificate_listed_after_a_non_matching_certificate_is_found() {
    let pki = pki();
    let (key, subject, cert) = delegated_responder(
        &pki.ca_name,
        &pki.ca,
        Some(true),
        START.as_secs() - HOUR,
        START.as_secs() + 30 * 86_400,
    );
    let mut spec = good(START.as_secs(), Some(START.as_secs() + HOUR)).signed_by(&key);
    spec.responder_id = tlv(0xA1, &subject);
    // An unrelated certificate (the leaf) comes first; the delegate must still be found.
    spec.certs = vec![leaf_certificate(&[7], None, false), cert];
    let (outcome, _, _) = stapling_outcome(spec.build(), Duration::ZERO).await;
    assert_eq!(outcome.unwrap(), StapleOutcome::Fetched);
}

#[test]
fn sha1_and_pss_response_signatures_are_rejected_with_a_typed_error() {
    // x/crypto/ocsp (Go) accepts sha1WithRSA; caddy-rs deliberately does not (documented
    // divergence in SEC-MEDIUM-TLS.md D1): fail closed, never staple.
    let sha1_with_rsa = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
    let rsa_pss = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
    for algorithm in [&sha1_with_rsa[..], &rsa_pss[..]] {
        let error = verify_signature(algorithm, &[0x04; 65], b"message", &[0u8; 64])
            .expect_err("unsupported algorithm");
        assert!(
            matches!(&error, OcspError::SignatureInvalid(reason) if reason.contains("unsupported")),
            "{error:?}"
        );
    }
}
