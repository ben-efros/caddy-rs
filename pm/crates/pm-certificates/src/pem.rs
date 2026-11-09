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
    }
}
