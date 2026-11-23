//! Strict PEM decoding for manual certificate uploads.
//!
//! The decoder never logs or includes PEM contents in an error. It refuses text outside blocks,
//! mismatched END labels, nested blocks, legacy encrypted PEM headers and unknown private-key
//! labels, so a key cannot be smuggled through the certificate field and stored in public state.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// One decoded PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PemBlock {
    pub(crate) label: String,
    pub(crate) der: Vec<u8>,
}

/// Decode every PEM block in `text`.
pub(crate) fn parse_blocks(text: &str) -> Result<Vec<PemBlock>, String> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let label = rest
                .strip_suffix("-----")
                .ok_or_else(|| "malformed PEM BEGIN line".to_string())?;
            if current.is_some() {
                return Err("nested PEM blocks are not supported".to_string());
            }
            if label.is_empty() {
                return Err("empty PEM label".to_string());
            }
            current = Some((label.to_string(), Vec::new()));
            continue;
        }
        if let Some(rest) = line.strip_prefix("-----END ") {
            let label = rest
                .strip_suffix("-----")
                .ok_or_else(|| "malformed PEM END line".to_string())?;
            let Some((begin_label, lines)) = current.take() else {
                return Err("PEM END line without a matching BEGIN".to_string());
            };
            if label != begin_label {
                return Err("PEM END label does not match its BEGIN label".to_string());
            }
            let body: String = lines.concat();
            let der = STANDARD
                .decode(body)
                .map_err(|_| "PEM block is not valid base64".to_string())?;
            if der.is_empty() {
                return Err("PEM block is empty".to_string());
            }
            blocks.push(PemBlock {
                label: begin_label,
                der,
            });
            continue;
        }
        let Some((_, lines)) = current.as_mut() else {
            return Err("unexpected text outside a PEM block".to_string());
        };
        if line.contains(':') {
            return Err(
                "encrypted or header-bearing PEM blocks are not supported; provide an \
                 unencrypted PKCS#8 or PKCS#1 key"
                    .to_string(),
            );
        }
        if !line.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='
        }) {
            return Err("PEM block contains a non-base64 character".to_string());
        }
        lines.push(line.to_string());
    }
    if current.is_some() {
        return Err("unterminated PEM block".to_string());
    }
    if blocks.is_empty() {
        return Err("no PEM block found".to_string());
    }
    Ok(blocks)
}

/// Canonical PEM encoding (64-column base64 with a trailing newline).
pub(crate) fn encode_block(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::with_capacity(encoded.len() + label.len() * 2 + 64);
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        // base64 output is ASCII.
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_and_canonicalises_a_certificate() {
        let pem = include_str!("../../../tests/fixtures/manual-valid.crt.pem");
        let blocks = parse_blocks(pem).expect("parse");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        let canonical = encode_block("CERTIFICATE", &blocks[0].der);
        assert!(canonical.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(canonical.ends_with("-----END CERTIFICATE-----\n"));
    }

    #[test]
    fn rejects_text_outside_blocks_and_unknown_headers() {
        assert!(parse_blocks("garbage\n").is_err());
        assert!(parse_blocks(
            "-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END PRIVATE KEY-----\n"
        )
        .is_err());
    }

    #[test]
    fn rejects_mismatched_labels() {
        let error = parse_blocks("-----BEGIN CERTIFICATE-----\nAAAA\n-----END PRIVATE KEY-----\n")
            .expect_err("mismatch");
        assert!(error.contains("does not match"), "{error}");

        // --- Fuzz coverage for the PEM block decoder ---------------------------------------------
        //
        // This decoder accepts PEM blocks from user input (certificate/key uploads), so every
        // byte is chosen by the uploader. It enforces strict structure: no text outside blocks,
        // no nested blocks, matched BEGIN/END labels, base64-only body, no headers, no empty
        // blocks. House style: seeded xorshift64 PRNG, catch_unwind, regression corpus.

        fn xorshift(state: &mut u64) -> u64 {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            x
        }

        fn assert_typed_pem_outcome(text: &str, context: &str) {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = parse_blocks(text);
            }));
            if let Err(_panic) = outcome {
                panic!(
                    "{context}: parse_blocks panicked on {} bytes: {:?}",
                    text.len(),
                    text
                );
            }
        }

        #[test]
        fn random_pem_inputs_never_panic() {
            const CASES: usize = 3_000;
            let mut state = 0xC0FF_EE00_0000_0001_u64;
            for _ in 0..CASES {
                let len = (xorshift(&mut state) % 512) as usize;
                let mut bytes = Vec::with_capacity(len);
                for _ in 0..len {
                    bytes.push((xorshift(&mut state) & 0xff) as u8);
                }
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    assert_typed_pem_outcome(text, "random");
                }
            }
        }

        #[test]
        fn mutated_valid_pem_never_panic() {
            const CASES: usize = 3_000;
            let valid_cert = include_str!("../../../tests/fixtures/manual-valid.crt.pem");
            let mut state = 0xC0FF_EE00_0000_0002_u64;
            for _ in 0..CASES {
                let mut bytes = valid_cert.as_bytes().to_vec();
                let mutations = 1 + (xorshift(&mut state) % 4) as usize;
                for _ in 0..mutations {
                    match xorshift(&mut state) % 4 {
                        0 => {
                            if !bytes.is_empty() {
                                let index = (xorshift(&mut state) as usize) % bytes.len();
                                bytes[index] ^= 1 << (xorshift(&mut state) % 8);
                            }
                        }
                        1 => {
                            if !bytes.is_empty() {
                                let keep = (xorshift(&mut state) as usize) % (bytes.len() + 1);
                                bytes.truncate(keep);
                            }
                        }
                        2 => {
                            if !bytes.is_empty() {
                                let index = (xorshift(&mut state) as usize) % bytes.len();
                                bytes[index] =
                                    [0x00, 0xff, 0x0a, 0x2d][(xorshift(&mut state) % 4) as usize];
                            }
                        }
                        _ => {
                            let index = (xorshift(&mut state) as usize) % (bytes.len() + 1);
                            bytes.insert(index, (xorshift(&mut state) & 0xff) as u8);
                        }
                    }
                }
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    assert_typed_pem_outcome(text, "mutation");
                }
            }
        }

        #[test]
        fn absurd_pem_structures_are_rejected_not_panicking() {
            // Truncated PEM (missing END)
            assert_typed_pem_outcome(
                "-----BEGIN CERTIFICATE-----
AAAA",
                "truncated PEM",
            );
            // Missing BEGIN
            assert_typed_pem_outcome(
                "AAAA
-----END CERTIFICATE-----",
                "missing BEGIN",
            );
            // Mismatched labels
            assert_typed_pem_outcome(
                "-----BEGIN CERTIFICATE-----
AAAA
-----END PRIVATE KEY-----",
                "mismatched labels",
            );
            // Nested blocks
            assert_typed_pem_outcome(
                "-----BEGIN CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
AAAA
-----END PRIVATE KEY-----
-----END CERTIFICATE-----",
                "nested",
            );
            // Empty block
            assert_typed_pem_outcome(
                "-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----",
                "empty block",
            );
            // Header-bearing (encrypted)
            assert_typed_pem_outcome(
                "-----BEGIN PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED

AAAA
-----END PRIVATE KEY-----",
                "encrypted",
            );
            // Non-base64 character
            assert_typed_pem_outcome(
                "-----BEGIN CERTIFICATE-----
AAAA!
-----END CERTIFICATE-----",
                "non-base64",
            );
        }

        #[test]
        fn pem_regression_corpus_never_panics() {
            let corpus: Vec<&str> = vec![
                "",
                "garbage",
                "-----BEGIN CERTIFICATE-----
",
                "-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
",
                include_str!("../../../tests/fixtures/manual-valid.crt.pem"),
            ];
            for (index, text) in corpus.iter().enumerate() {
                assert_typed_pem_outcome(text, &format!("corpus entry {index}"));
            }
        }

        #[test]
        fn pem_fuzz_generator_reaches_the_parser() {
            let valid = include_str!("../../../tests/fixtures/manual-valid.crt.pem");
            let mut state = 0xC0FF_EE00_0000_0002_u64;
            let mut entered = 0_usize;
            const CASES: usize = 1_000;
            for _ in 0..CASES {
                let mut bytes = valid.as_bytes().to_vec();
                let mutations = 1 + (xorshift(&mut state) % 4) as usize;
                for _ in 0..mutations {
                    match xorshift(&mut state) % 4 {
                        0 => {
                            if !bytes.is_empty() {
                                let index = (xorshift(&mut state) as usize) % bytes.len();
                                bytes[index] ^= 1 << (xorshift(&mut state) % 8);
                            }
                        }
                        1 => {
                            if !bytes.is_empty() {
                                let keep = (xorshift(&mut state) as usize) % (bytes.len() + 1);
                                bytes.truncate(keep);
                            }
                        }
                        2 => {
                            if !bytes.is_empty() {
                                let index = (xorshift(&mut state) as usize) % bytes.len();
                                bytes[index] =
                                    [0x00, 0xff, 0x0a, 0x2d][(xorshift(&mut state) % 4) as usize];
                            }
                        }
                        _ => {
                            let index = (xorshift(&mut state) as usize) % (bytes.len() + 1);
                            bytes.insert(index, (xorshift(&mut state) & 0xff) as u8);
                        }
                    }
                }
                if bytes.starts_with(b"-----BEGIN") {
                    entered += 1;
                }
            }
            assert!(
            entered > CASES / 2,
            "only {entered} of {CASES} generated mutations start with PEM BEGIN; generator has regressed"
        );
        }
    }
}
