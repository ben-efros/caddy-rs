//! Minimal, strict DER parsing for the certificate fields the PM needs.
//!
//! The parser extracts subjectAlternativeName DNS entries, the common name, validity and the
//! SubjectPublicKeyInfo. It never verifies the certificate signature: chain building and
//! trust-anchor validation belong to the data plane, and a manual certificate is a user-supplied
//! public object. Every input is bounded by the caller before this module runs.

use std::fmt;

const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// Elliptic curve named by a certificate's SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EcCurve {
    P256,
    P384,
}

impl EcCurve {
    pub(crate) fn point_len(self) -> usize {
        match self {
            Self::P256 => 65,
            Self::P384 => 97,
        }
    }
}

/// The public key carried by a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PublicKey {
    /// DER-encoded PKCS#1 `RSAPublicKey` (the BIT STRING payload).
    Rsa(Vec<u8>),
    /// Uncompressed SEC1 point (0x04 || X || Y).
    Ec { curve: EcCurve, point: Vec<u8> },
}

/// Parsed fields of an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedCertificate {
    pub(crate) der: Vec<u8>,
    pub(crate) not_before_unix: i64,
    pub(crate) not_after_unix: i64,
    pub(crate) dns_names: Vec<String>,
    pub(crate) common_name: Option<String>,
    pub(crate) public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct X509Error(pub(crate) String);

impl fmt::Display for X509Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn error(message: impl Into<String>) -> X509Error {
    X509Error(message.into())
}

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

impl<'a> Tlv<'a> {
    fn parse(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), X509Error> {
        if bytes.len() < 2 {
            return Err(error("truncated DER element"));
        }
        let tag = bytes[0];
        let (length, header) = parse_length(&bytes[1..])?;
        let start = 1 + header;
        let end = start
            .checked_add(length)
            .ok_or_else(|| error("DER length overflow"))?;
        if end > bytes.len() {
            return Err(error("DER element extends past its input"));
        }
        Ok((
            Self {
                tag,
                content: &bytes[start..end],
            },
            &bytes[end..],
        ))
    }

    fn children(&self) -> Result<Vec<Self>, X509Error> {
        let mut children = Vec::new();
        let mut remaining = self.content;
        while !remaining.is_empty() {
            let (child, rest) = Self::parse(remaining)?;
            children.push(child);
            remaining = rest;
        }
        Ok(children)
    }
}

fn parse_length(bytes: &[u8]) -> Result<(usize, usize), X509Error> {
    let Some(&first) = bytes.first() else {
        return Err(error("missing DER length"));
    };
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 || bytes.len() < 1 + count {
        return Err(error("unsupported DER length encoding"));
    }
    let mut length = 0usize;
    for byte in &bytes[1..1 + count] {
        length = (length << 8) | usize::from(*byte);
    }
    Ok((length, 1 + count))
}

pub(crate) fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate, X509Error> {
    let (certificate, trailing) = Tlv::parse(der)?;
    if !trailing.is_empty() {
        return Err(error("trailing bytes after certificate"));
    }
    if certificate.tag != 0x30 {
        return Err(error("certificate is not a SEQUENCE"));
    }
    let parts = certificate.children()?;
    if parts.len() < 3 {
        return Err(error("certificate SEQUENCE is missing fields"));
    }
    let tbs = &parts[0];
    if tbs.tag != 0x30 {
        return Err(error("tbsCertificate is not a SEQUENCE"));
    }
    let fields = tbs.children()?;
    let mut index = 0;
    if fields.first().is_some_and(|field| field.tag == 0xa0) {
        // Explicit version.
        index += 1;
    }
    let serial = fields
        .get(index)
        .ok_or_else(|| error("missing serial number"))?;
    if serial.tag != 0x02 {
        return Err(error("serial number is not an INTEGER"));
    }
    let _signature_algorithm = fields
        .get(index + 1)
        .ok_or_else(|| error("missing signature algorithm"))?;
    let _issuer = fields
        .get(index + 2)
        .ok_or_else(|| error("missing issuer"))?;
    let validity = fields
        .get(index + 3)
        .ok_or_else(|| error("missing validity"))?;
    let subject = fields
        .get(index + 4)
        .ok_or_else(|| error("missing subject"))?;
    let spki = fields
        .get(index + 5)
        .ok_or_else(|| error("missing SubjectPublicKeyInfo"))?;
    if validity.tag != 0x30 || spki.tag != 0x30 {
        return Err(error("malformed validity or SubjectPublicKeyInfo"));
    }
    let validity_fields = validity.children()?;
    if validity_fields.len() != 2 {
        return Err(error("validity must contain notBefore and notAfter"));
    }
    let not_before_unix = parse_time(&validity_fields[0])?;
    let not_after_unix = parse_time(&validity_fields[1])?;
    let dns_names = find_dns_names(&fields, index + 6)?;
    let common_name = find_common_name(subject)?;
    let public_key = parse_public_key(spki)?;

    Ok(ParsedCertificate {
        der: der.to_vec(),
        not_before_unix,
        not_after_unix,
        dns_names,
        common_name,
        public_key,
    })
}

fn parse_time(tlv: &Tlv<'_>) -> Result<i64, X509Error> {
    let text =
        std::str::from_utf8(tlv.content).map_err(|_| error("certificate time is not ASCII"))?;
    // The length checks below count bytes, but slicing is only safe at a UTF-8 character
    // boundary. Certificate times are ASCII by definition; reject any multi-byte input before
    // indexing so a crafted certificate cannot panic the parser.
    if !text.is_ascii() {
        return Err(error("certificate time is not ASCII"));
    }
    let (year, rest) = match tlv.tag {
        0x17 => {
            if text.len() != 13 || !text.ends_with('Z') {
                return Err(error("UTCTime is not in YYMMDDHHMMSSZ form"));
            }
            let year: i64 = text[0..2]
                .parse()
                .map_err(|_| error("invalid UTCTime year"))?;
            let year = if year >= 50 { 1900 + year } else { 2000 + year };
            (year, &text[2..12])
        }
        0x18 => {
            if text.len() != 15 || !text.ends_with('Z') {
                return Err(error("GeneralizedTime is not in YYYYMMDDHHMMSSZ form"));
            }
            let year: i64 = text[0..4]
                .parse()
                .map_err(|_| error("invalid GeneralizedTime year"))?;
            (year, &text[4..14])
        }
        _ => return Err(error("unsupported certificate time encoding")),
    };
    let number = |range: std::ops::Range<usize>| -> Result<i64, X509Error> {
        rest.get(range)
            .ok_or_else(|| error("truncated certificate time"))?
            .parse()
            .map_err(|_| error("invalid certificate time digit"))
    };
    let month = number(0..2)?;
    let day = number(2..4)?;
    let hour = number(4..6)?;
    let minute = number(6..8)?;
    let second = number(8..10)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return Err(error("certificate time is out of range"));
    }

    // Howard Hinnant's days_from_civil algorithm.
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days.checked_mul(86_400)
        .and_then(|seconds| seconds.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| error("certificate time is out of range"))
}

fn find_dns_names(fields: &[Tlv<'_>], start: usize) -> Result<Vec<String>, X509Error> {
    let Some(extensions) = fields
        .get(start..)
        .unwrap_or_default()
        .iter()
        .find(|field| field.tag == 0xa3)
    else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    let mut seen_san = false;
    // `[3]` is EXPLICIT: its content is the `Extensions` SEQUENCE, not a list of extensions.
    let (extensions, trailing) = Tlv::parse(extensions.content)?;
    if !trailing.is_empty() || extensions.tag != 0x30 {
        return Err(error("extensions wrapper is not a SEQUENCE"));
    }
    for extension in extensions.children()? {
        if extension.tag != 0x30 {
            continue;
        }
        let parts = extension.children()?;
        if parts.len() < 2 || parts[0].tag != 0x06 {
            continue;
        }
        if parts[0].content != OID_SUBJECT_ALT_NAME {
            continue;
        }
        if seen_san {
            return Err(error(
                "certificate has more than one subjectAltName extension",
            ));
        }
        seen_san = true;
        let value = parts
            .last()
            .ok_or_else(|| error("subjectAltName has no value"))?;
        if value.tag != 0x04 {
            return Err(error("subjectAltName value is not an OCTET STRING"));
        }
        let (general_names, trailing) = Tlv::parse(value.content)?;
        if !trailing.is_empty() || general_names.tag != 0x30 {
            return Err(error("subjectAltName is not a SEQUENCE"));
        }
        for general_name in general_names.children()? {
            // dNSName is [2] IMPLICIT IA5String.
            if general_name.tag != 0x82 {
                continue;
            }
            let name = std::str::from_utf8(general_name.content)
                .map_err(|_| error("subjectAltName dNSName is not UTF-8"))?;
            if !name.is_ascii() {
                return Err(error("subjectAltName dNSName is not ASCII"));
            }
            names.push(name.to_string());
        }
    }
    Ok(names)
}

fn find_common_name(name: &Tlv<'_>) -> Result<Option<String>, X509Error> {
    if name.tag != 0x30 {
        return Err(error("certificate subject is not a SEQUENCE"));
    }
    for set in name.children()? {
        if set.tag != 0x31 {
            continue;
        }
        for attribute in set.children()? {
            if attribute.tag != 0x30 {
                continue;
            }
            let pair = attribute.children()?;
            if pair.len() < 2 || pair[0].tag != 0x06 {
                continue;
            }
            if pair[0].content == OID_COMMON_NAME {
                return decode_directory_string(&pair[1]).map(Some);
            }
        }
    }
    Ok(None)
}

fn decode_directory_string(tlv: &Tlv<'_>) -> Result<String, X509Error> {
    match tlv.tag {
        0x0c | 0x13 | 0x16 | 0x14 => std::str::from_utf8(tlv.content)
            .map(str::to_owned)
            .map_err(|_| error("common name is not valid UTF-8")),
        0x1e => {
            if tlv.content.len() % 2 != 0 {
                return Err(error("BMPString common name has an odd length"));
            }
            let units: Vec<u16> = tlv
                .content
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect();
            Ok(String::from_utf16_lossy(&units))
        }
        _ => Err(error("unsupported common-name string encoding")),
    }
}

fn parse_public_key(spki: &Tlv<'_>) -> Result<PublicKey, X509Error> {
    let parts = spki.children()?;
    if parts.len() != 2 || parts[0].tag != 0x30 || parts[1].tag != 0x03 {
        return Err(error("SubjectPublicKeyInfo is malformed"));
    }
    let algorithm = parts[0].children()?;
    let oid = algorithm
        .first()
        .filter(|field| field.tag == 0x06)
        .ok_or_else(|| error("SubjectPublicKeyInfo has no algorithm OID"))?;
    let key = parts[1].content;
    let Some((&unused_bits, key)) = key.split_first() else {
        return Err(error("SubjectPublicKeyInfo BIT STRING is empty"));
    };
    if unused_bits != 0 {
        return Err(error("SubjectPublicKeyInfo BIT STRING has unused bits"));
    }

    if oid.content == OID_RSA_ENCRYPTION {
        let (rsa, trailing) = Tlv::parse(key)?;
        if !trailing.is_empty() || rsa.tag != 0x30 {
            return Err(error("RSA public key is not a SEQUENCE"));
        }
        let fields = rsa.children()?;
        if fields.len() != 2 || fields.iter().any(|field| field.tag != 0x02) {
            return Err(error("RSA public key is not two INTEGERs"));
        }
        return Ok(PublicKey::Rsa(key.to_vec()));
    }

    if oid.content == OID_EC_PUBLIC_KEY {
        let curve_oid = algorithm
            .get(1)
            .filter(|field| field.tag == 0x06)
            .ok_or_else(|| error("EC public key has no named curve"))?;
        let curve = if curve_oid.content == OID_PRIME256V1 {
            EcCurve::P256
        } else if curve_oid.content == OID_SECP384R1 {
            EcCurve::P384
        } else {
            return Err(error("unsupported EC named curve"));
        };
        if key.len() != curve.point_len() || key.first() != Some(&0x04) {
            return Err(error(
                "EC public key is not an uncompressed point of the named curve",
            ));
        }
        return Ok(PublicKey::Ec {
            curve,
            point: key.to_vec(),
        });
    }

    Err(error(
        "unsupported certificate public-key algorithm; supported algorithms are RSA and ECDSA \
         P-256/P-384",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = include_bytes!("../../../tests/fixtures/manual-valid.crt.pem");

    fn pem_der(pem: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(pem).expect("utf8");
        let body: String = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("base64")
    }

    #[test]
    fn parses_dns_names_validity_and_spki() {
        let parsed = parse_certificate(&pem_der(VALID)).expect("parse certificate");
        assert_eq!(
            parsed.dns_names,
            vec![
                "manual.example.com".to_string(),
                "www.manual.example.com".to_string()
            ]
        );
        assert_eq!(parsed.common_name.as_deref(), Some("manual.example.com"));
        assert_eq!(parsed.not_before_unix, 1_735_689_600);
        assert_eq!(parsed.not_after_unix, 4_891_363_200);
        assert!(matches!(parsed.public_key, PublicKey::Rsa(_)));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut der = pem_der(VALID);
        der.push(0);
        assert!(parse_certificate(&der).is_err());
    }

    // --- Fuzz coverage for the X.509 certificate parser ----------------------------------------
    //
    // This parser accepts user-supplied certificate DER (manual uploads), so every byte is
    // chosen by the uploader. House style: seeded xorshift64 PRNG in this file (no
    // cargo-fuzz/libFuzzer/proptest/rand), `catch_unwind` so a panic names the input, and an
    // always-executed regression corpus.

    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn assert_typed_x509_outcome(bytes: &[u8], context: &str) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = parse_certificate(bytes);
        }));
        if let Err(_panic) = outcome {
            panic!(
                "{context}: parse_certificate panicked on {} bytes: {:02x?}",
                bytes.len(),
                bytes
            );
        }
    }

    #[test]
    fn random_x509_certs_never_panic() {
        const CASES: usize = 4_000;
        let mut state = 0xC0FF_EE00_0000_0001_u64;
        for case in 0..CASES {
            let len = (xorshift(&mut state) % 1024) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push((xorshift(&mut state) & 0xff) as u8);
            }
            if case % 2 == 0 && bytes.len() >= 2 {
                bytes[0] = 0x30;
                bytes[1] = if bytes.len() > 2 {
                    (bytes.len() - 2) as u8
                } else {
                    0
                };
            }
            assert_typed_x509_outcome(&bytes, &format!("random case {case}"));
        }
    }

    #[test]
    fn mutated_valid_x509_certs_never_panic() {
        const CASES: usize = 4_000;
        let base = pem_der(VALID);
        let mut state = 0xC0FF_EE00_0000_0002_u64;
        for case in 0..CASES {
            let mut bytes = base.clone();
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
                            bytes[index] = [0x00, 0xff, 0x30][(xorshift(&mut state) % 3) as usize];
                        }
                    }
                    _ => {
                        let index = (xorshift(&mut state) as usize) % (bytes.len() + 1);
                        bytes.insert(index, (xorshift(&mut state) & 0xff) as u8);
                    }
                }
            }
            assert_typed_x509_outcome(&bytes, &format!("mutation case {case}"));
        }
    }

    #[test]
    fn absurd_x509_structures_are_rejected_not_panicking() {
        assert_typed_x509_outcome(&[0x30], "truncated SEQUENCE");
        assert_typed_x509_outcome(&[0x30, 0xff, 0xff, 0xff, 0xff], "oversized length");
        assert_typed_x509_outcome(&[0x02, 0x01, 0x00], "INTEGER instead of SEQUENCE");
        assert_typed_x509_outcome(
            &[0x30, 0x05, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
            "missing fields",
        );
        assert_typed_x509_outcome(
            &[
                0x30, 0x0a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            ],
            "invalid version tag",
        );
        assert_typed_x509_outcome(
            &[0x30, 0x0a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00],
            "serial not INTEGER",
        );
        let mut utc = [
            0x30, 0x12, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x17,
            0x0d, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5a,
        ];
        utc[1] = 0x12;
        assert_typed_x509_outcome(&utc, "invalid time tag");
    }

    #[test]
    fn x509_regression_corpus_never_panics() {
        let corpus: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0x30],
            vec![0x30, 0x00],
            vec![0x30, 0x03, 0x02, 0x01, 0x00],
            pem_der(VALID),
            {
                let mut d = pem_der(VALID);
                d.push(0);
                d
            },
            [
                vec![0x30, 0x0a],
                vec![
                    0x18, 0x0d, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30,
                    0x30, 0x30, 0x30, 0x5a,
                ],
            ]
            .concat(),
        ];
        for (index, bytes) in corpus.iter().enumerate() {
            assert_typed_x509_outcome(bytes, &format!("corpus entry {index}"));
        }
    }

    #[test]
    fn x509_fuzz_generator_reaches_the_parser() {
        let base = pem_der(VALID);
        let mut state = 0xC0FF_EE00_0000_0002_u64;
        let mut entered = 0_usize;
        const CASES: usize = 1_000;
        for case in 0..CASES {
            let mut bytes = base.clone();
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
                            bytes[index] = [0x00, 0xff, 0x30][(xorshift(&mut state) % 3) as usize];
                        }
                    }
                    _ => {
                        let index = (xorshift(&mut state) as usize) % (bytes.len() + 1);
                        bytes.insert(index, (xorshift(&mut state) & 0xff) as u8);
                    }
                }
            }
            if bytes.first() == Some(&0x30) {
                entered += 1;
            }
        }
        assert!(
            entered > CASES / 2,
            "only {entered} of {CASES} generated mutations start with SEQUENCE tag; the mutation generator has regressed"
        );
    }
}

#[cfg(test)]
mod time_tests {
    use super::*;

    #[test]
    fn rejects_non_ascii_time_without_panicking() {
        // 13 bytes: a 3-byte U+20AC followed by 9 ASCII bytes and `Z`. The byte length passes the
        // UTCTime check, but index 2 is not a char boundary.
        let utc = Tlv {
            tag: 0x17,
            content: "€abcdefghiZ".as_bytes(),
        };
        assert!(parse_time(&utc).is_err());
        let generalized = Tlv {
            tag: 0x18,
            content: "€abcdefghijZ".as_bytes(),
        };
        assert!(parse_time(&generalized).is_err());
    }
}
