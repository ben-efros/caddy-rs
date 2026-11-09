//! Classification of PEM/DER private keys for located TLS configuration errors.
//!
//! rustls' aws-lc-rs provider implements RSA, ECDSA on P-256/P-384/P-521 and Ed25519. Every
//! other key type must be rejected with a message that names the detected type and, where Caddy
//! rejects the same key, uses Caddy's wording (`x509: unsupported elliptic curve`, `encrypted
//! private keys are not supported; ...`) so an oracle comparison is meaningful.
//!
//! The classifier reads only what the PEM label and the outer ASN.1 structure expose: the
//! private-key algorithm OID from PKCS#8 `PrivateKeyInfo` and the named-curve OID from SEC1
//! `ECPrivateKey`. It never attempts to decode the secret scalar.

/// Outcome of classifying a private key.
pub(crate) enum KeySupport {
    /// The provider implements this key type.
    Supported,
    /// The provider does not implement this key type; the string is the located-error message.
    Unsupported(String),
}

// Algorithm OIDs.
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_DSA: &str = "1.2.840.10040.4.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";
const OID_X25519: &str = "1.3.101.110";
const OID_X448: &str = "1.3.101.111";

// Named-curve OIDs.
const OID_PRIME256V1: &str = "1.2.840.10045.3.1.7";
const OID_SECP384R1: &str = "1.3.132.0.34";
const OID_SECP521R1: &str = "1.3.132.0.35";
const OID_SECP256K1: &str = "1.3.132.0.10";

/// Classify one PEM block by its label and DER payload.
///
/// Returns `None` only when the block is an inspectable private key encoding whose type cannot be
/// determined (for example a SEC1 key without the optional named-curve parameters): the caller
/// then falls back to the crypto provider's own error instead of guessing. Malformed DER and
/// unsupported algorithms return `Some(KeySupport::Unsupported(..))` with a specific message.
pub(crate) fn classify(label: &str, der: &[u8]) -> Option<KeySupport> {
    match label {
        "PRIVATE KEY" => classify_pkcs8(der),
        "EC PRIVATE KEY" => classify_sec1(der),
        "RSA PRIVATE KEY" => Some(KeySupport::Supported),
        "ENCRYPTED PRIVATE KEY" => Some(KeySupport::Unsupported(
            "encrypted private keys are not supported; please decrypt the key first".to_string(),
        )),
        "DSA PRIVATE KEY" => Some(KeySupport::Unsupported(dsa_message())),
        "OPENSSH PRIVATE KEY" => Some(KeySupport::Unsupported(
            "OpenSSH private keys are not supported; convert the key to PKCS#8 or SEC1 PEM"
                .to_string(),
        )),
        other if other.ends_with("PRIVATE KEY") => Some(KeySupport::Unsupported(format!(
            "`{other}` PEM private keys are not supported by this build: rustls' aws-lc-rs \
             provider reads PKCS#8, SEC1 and PKCS#1 private keys"
        ))),
        _ => None,
    }
}

fn classify_pkcs8(der: &[u8]) -> Option<KeySupport> {
    let Some((algorithm, parameters)) = pkcs8_algorithm_identifier(der) else {
        return Some(KeySupport::Unsupported(malformed_der_message(
            "PRIVATE KEY",
            "PKCS#8 PrivateKeyInfo",
        )));
    };
    Some(match algorithm.as_str() {
        OID_RSA_ENCRYPTION | OID_RSASSA_PSS => KeySupport::Supported,
        OID_EC_PUBLIC_KEY => {
            let Some(curve) = parameters.and_then(named_curve_from_parameters) else {
                return Some(KeySupport::Unsupported(malformed_der_message(
                    "PRIVATE KEY",
                    "PKCS#8 EC PrivateKeyInfo without named-curve parameters",
                )));
            };
            classify_curve(&curve)
        }
        OID_ED25519 => KeySupport::Supported,
        OID_ED448 => KeySupport::Unsupported(format!(
            "Ed448 (algorithm OID {OID_ED448}) private keys are not supported by this build: \
             rustls' aws-lc-rs provider implements Ed25519 only"
        )),
        OID_DSA => KeySupport::Unsupported(dsa_message()),
        OID_X25519 | OID_X448 => KeySupport::Unsupported(format!(
            "key-agreement private keys (algorithm OID {algorithm}) are not signing keys and are \
             not supported by this build"
        )),
        other => KeySupport::Unsupported(format!(
            "private key algorithm OID {other} is not supported by this build: rustls' aws-lc-rs \
             provider implements RSA, ECDSA (P-256, P-384, P-521) and Ed25519"
        )),
    })
}

/// Result of inspecting the optional named-curve parameters of a SEC1 `ECPrivateKey`.
enum Sec1Curve {
    Named(String),
    /// Valid SEC1 structure without `parameters [0]`; the provider must infer the curve.
    Absent,
    Malformed,
}

fn classify_sec1(der: &[u8]) -> Option<KeySupport> {
    match sec1_named_curve(der) {
        Sec1Curve::Named(oid) => Some(classify_curve(&oid)),
        Sec1Curve::Absent => None,
        Sec1Curve::Malformed => Some(KeySupport::Unsupported(malformed_der_message(
            "EC PRIVATE KEY",
            "SEC1 ECPrivateKey",
        ))),
    }
}

fn classify_curve(oid: &str) -> KeySupport {
    match oid {
        OID_PRIME256V1 | OID_SECP384R1 | OID_SECP521R1 => KeySupport::Supported,
        _ => KeySupport::Unsupported(unsupported_curve_message(oid)),
    }
}

fn malformed_der_message(label: &str, structure: &str) -> String {
    format!(
        "`{label}` block is not a valid DER {structure}: the ASN.1 is truncated, has trailing \
         data, or is not a private key"
    )
}

fn unsupported_curve_message(oid: &str) -> String {
    match curve_display_name(oid) {
        Some(name) => format!(
            "ECDSA {name} ({oid}) private keys are not supported by this build: \
             x509: unsupported elliptic curve"
        ),
        None => format!(
            "ECDSA private key with curve OID {oid} is not supported by this build: \
             x509: unsupported elliptic curve"
        ),
    }
}

fn dsa_message() -> String {
    format!(
        "DSA (algorithm OID {OID_DSA}) private keys are not supported by this build: rustls' \
         aws-lc-rs provider implements RSA, ECDSA (P-256, P-384, P-521) and Ed25519"
    )
}

fn curve_display_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        OID_PRIME256V1 => "P-256 (secp256r1)",
        OID_SECP384R1 => "P-384 (secp384r1)",
        OID_SECP521R1 => "P-521 (secp521r1)",
        OID_SECP256K1 => "secp256k1",
        "1.3.132.0.32" => "secp224k1",
        "1.3.132.0.33" => "secp224r1",
        "1.2.840.10045.3.1.1" => "prime192v1",
        "1.3.36.3.3.2.8.1.1.1" => "brainpoolP160r1",
        "1.3.36.3.3.2.8.1.1.2" => "brainpoolP160t1",
        "1.3.36.3.3.2.8.1.1.3" => "brainpoolP192r1",
        "1.3.36.3.3.2.8.1.1.4" => "brainpoolP192t1",
        "1.3.36.3.3.2.8.1.1.5" => "brainpoolP224r1",
        "1.3.36.3.3.2.8.1.1.6" => "brainpoolP224t1",
        "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.8" => "brainpoolP256t1",
        "1.3.36.3.3.2.8.1.1.9" => "brainpoolP320r1",
        "1.3.36.3.3.2.8.1.1.10" => "brainpoolP320t1",
        "1.3.36.3.3.2.8.1.1.11" => "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.12" => "brainpoolP384t1",
        "1.3.36.3.3.2.8.1.1.13" => "brainpoolP512r1",
        "1.3.36.3.3.2.8.1.1.14" => "brainpoolP512t1",
        _ => return None,
    })
}

/// Extract `(algorithm OID, AlgorithmIdentifier parameters)` from a PKCS#8 `PrivateKeyInfo`.
fn pkcs8_algorithm_identifier(der: &[u8]) -> Option<(String, Option<(u8, &[u8])>)> {
    let (tag, body, total) = read_tlv(der)?;
    if tag != 0x30 || total != der.len() {
        return None;
    }
    let (version_tag, _, version_len) = read_tlv(body)?;
    if version_tag != 0x02 {
        return None;
    }
    let (algorithm_tag, algorithm_body, algorithm_len) = read_tlv(&body[version_len..])?;
    if algorithm_tag != 0x30 {
        return None;
    }
    // The privateKey OCTET STRING must follow the AlgorithmIdentifier for this to be PKCS#8.
    let (key_tag, _, _) = read_tlv(&body[version_len + algorithm_len..])?;
    if key_tag != 0x04 {
        return None;
    }
    let (oid_tag, oid_content, oid_len) = read_tlv(algorithm_body)?;
    if oid_tag != 0x06 {
        return None;
    }
    let algorithm = decode_oid(oid_content)?;
    let parameters = if oid_len < algorithm_body.len() {
        let (tag, content, total) = read_tlv(&algorithm_body[oid_len..])?;
        // AlgorithmIdentifier must contain only the OID plus one optional parameters value.
        if oid_len + total != algorithm_body.len() {
            return None;
        }
        Some((tag, content))
    } else {
        None
    };
    Some((algorithm, parameters))
}

/// Extract the named-curve OID from a SEC1 `ECPrivateKey` (`parameters [0]`).
fn sec1_named_curve(der: &[u8]) -> Sec1Curve {
    let Some((tag, body, total)) = read_tlv(der) else {
        return Sec1Curve::Malformed;
    };
    if tag != 0x30 || total != der.len() {
        return Sec1Curve::Malformed;
    }
    let Some((version_tag, _, version_len)) = read_tlv(body) else {
        return Sec1Curve::Malformed;
    };
    if version_tag != 0x02 {
        return Sec1Curve::Malformed;
    }
    let Some((private_tag, _, private_len)) = read_tlv(&body[version_len..]) else {
        return Sec1Curve::Malformed;
    };
    if private_tag != 0x04 {
        return Sec1Curve::Malformed;
    }
    let mut offset = version_len + private_len;
    while offset < body.len() {
        let Some((tag, content, consumed)) = read_tlv(&body[offset..]) else {
            return Sec1Curve::Malformed;
        };
        offset += consumed;
        if tag == 0xA0 {
            let Some((curve_tag, curve_content, _)) = read_tlv(content) else {
                return Sec1Curve::Malformed;
            };
            if curve_tag != 0x06 {
                return Sec1Curve::Malformed;
            }
            return match decode_oid(curve_content) {
                Some(oid) => Sec1Curve::Named(oid),
                None => Sec1Curve::Malformed,
            };
        }
    }
    Sec1Curve::Absent
}

/// A named curve stored as `AlgorithmIdentifier.parameters` (an OID).
fn named_curve_from_parameters(parameters: (u8, &[u8])) -> Option<String> {
    let (tag, content) = parameters;
    if tag != 0x06 {
        return None;
    }
    decode_oid(content)
}

/// Read one DER TLV: `(tag, content, total encoded length)`.
fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (length, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || input.len() < 2 + count {
            return None;
        }
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    if input.len() < header + length {
        return None;
    }
    Some((tag, &input[header..header + length], header + length))
}

/// Decode a DER OBJECT IDENTIFIER into dotted-decimal form.
fn decode_oid(content: &[u8]) -> Option<String> {
    let (first, rest) = content.split_first()?;
    let mut arcs = vec![u64::from(first / 40), u64::from(first % 40)];
    let mut value: u64 = 0;
    let mut pending = false;
    for byte in rest {
        value = value.checked_shl(7)? | u64::from(byte & 0x7f);
        pending = true;
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
            pending = false;
        }
    }
    if pending {
        return None;
    }
    Some(
        arcs.iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_decoding_covers_the_workspace_curves() {
        // DER content of 1.3.132.0.35 (secp521r1): 2b 81 04 00 23.
        assert_eq!(
            decode_oid(&[0x2b, 0x81, 0x04, 0x00, 0x23]),
            Some("1.3.132.0.35".into())
        );
        assert_eq!(
            decode_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            Some("1.2.840.10045.2.1".into())
        );
    }

    #[test]
    fn labels_that_never_need_der_are_classified() {
        assert!(matches!(
            classify("RSA PRIVATE KEY", &[]),
            Some(KeySupport::Supported)
        ));
        let encrypted = classify("ENCRYPTED PRIVATE KEY", &[]).expect("classified");
        let KeySupport::Unsupported(message) = encrypted else {
            panic!("encrypted keys must be rejected");
        };
        assert!(
            message.contains("encrypted private keys are not supported"),
            "{message}"
        );
        let dsa = classify("DSA PRIVATE KEY", &[]).expect("classified");
        let KeySupport::Unsupported(message) = dsa else {
            panic!("DSA keys must be rejected");
        };
        assert!(message.contains("DSA"), "{message}");
        assert!(message.contains(OID_DSA), "{message}");
    }

    #[test]
    fn malformed_der_names_the_block_label() {
        let result = classify("PRIVATE KEY", &[0x30, 0x82, 0x01, 0x00]).expect("classified");
        let KeySupport::Unsupported(message) = result else {
            panic!("truncated DER must be rejected");
        };
        assert!(message.contains("`PRIVATE KEY` block"), "{message}");
        assert!(message.contains("truncated"), "{message}");
    }
}
