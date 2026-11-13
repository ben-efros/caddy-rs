//! COSE_Key (CBOR) and SPKI PEM parsing for FIDO2/WebAuthn public keys.
//!
//! Only the two algorithms a passkey actually uses are accepted:
//! `ES256` (COSE alg `-7`, EC2 / P-256) and `EdDSA` (COSE alg `-8`, OKP / Ed25519).
//! Anything else is rejected by name; this module never guesses.
//!
//! No third-party CBOR/COSE dependency is used: the subset of CBOR a `COSE_Key` occupies is small
//! (unsigned/negative ints, byte strings, text strings, arrays and maps with definite lengths), so
//! it is decoded here. The same applies to the two SPKI shapes accepted from PEM.

use base64::Engine as _;
use thiserror::Error;

/// COSE key family (`COSE_Key` label `1`, `kty`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// `EC2` (`kty` = 2): an elliptic-curve key with `x` and `y` coordinates.
    Ec2,
    /// `OKP` (`kty` = 1): an octet key pair (Ed25519).
    Okp,
}

/// Curve identifier (`COSE_Key` label `-1`, `crv`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256 (`crv` = 1).
    P256,
    /// Ed25519 (`crv` = 6).
    Ed25519,
}

/// Signature algorithm the key is registered for (`COSE_Key` label `3`, `alg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ECDSA with SHA-256 over P-256 (COSE `-7`).
    Es256,
    /// EdDSA over Ed25519 (COSE `-8`).
    EdDsa,
}

/// A validated public key from a `COSE_Key` or an SPKI PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosePublicKey {
    /// Key family.
    pub kind: KeyKind,
    /// Signature algorithm the key is bound to.
    pub algorithm: KeyAlgorithm,
    /// Curve the key belongs to.
    pub curve: Curve,
    /// `x` coordinate (EC2) or the raw public key (OKP).
    pub x: Vec<u8>,
    /// `y` coordinate; present exactly for EC2 keys.
    pub y: Option<Vec<u8>>,
}

/// Why a key was rejected.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoseError {
    /// The CBOR payload is malformed or uses an unsupported encoding.
    #[error("CBOR decode error: {0}")]
    Cbor(String),
    /// The CBOR payload is not a map, so it cannot be a `COSE_Key`.
    #[error("COSE key is not a CBOR map")]
    NotAMap,
    /// `kty` is not EC2 or OKP.
    #[error("unsupported key type {0} (expected EC2=2 or OKP=1)")]
    UnsupportedKeyType(i64),
    /// `alg` is not ES256 or EdDSA.
    #[error("unsupported algorithm {0} (expected ES256=-7 or EdDSA=-8)")]
    UnsupportedAlgorithm(i64),
    /// `crv` is not P-256 or Ed25519.
    #[error("unsupported curve {0} (expected P-256=1 or Ed25519=6)")]
    UnsupportedCurve(i64),
    /// `kty`, `alg` and `crv` do not describe one key.
    #[error("inconsistent COSE key: kty {kty}, alg {alg}, crv {crv}")]
    Inconsistent {
        /// Observed `kty`.
        kty: i64,
        /// Observed `alg`.
        alg: i64,
        /// Observed `crv`.
        crv: i64,
    },
    /// A required `COSE_Key` label is absent.
    #[error("missing COSE field `{0}`")]
    MissingField(&'static str),
    /// A field has the wrong length.
    #[error("invalid `{field}` length {len} (expected {expected})")]
    InvalidLength {
        /// Field name.
        field: &'static str,
        /// Observed length.
        len: usize,
        /// Required length.
        expected: usize,
    },
    /// The PEM block is malformed.
    #[error("PEM error: {0}")]
    Pem(String),
    /// The DER inside the PEM block is malformed.
    #[error("DER error: {0}")]
    Der(String),
    /// The PEM contains a key type outside the supported set.
    #[error("unsupported PEM/SPKI algorithm (expected Ed25519 or P-256)")]
    UnsupportedPemAlgorithm,
    /// A base64 payload is malformed.
    #[error("base64 error: {0}")]
    Base64(String),
}

impl CosePublicKey {
    /// Parse a `COSE_Key` from its raw CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CoseError> {
        let value = Cbor::new(bytes).parse_one()?;
        let CborValue::Map(entries) = value else {
            return Err(CoseError::NotAMap);
        };

        let mut kty = None;
        let mut alg = None;
        let mut crv = None;
        let mut x = None;
        let mut y = None;

        for (label, value) in entries {
            let Some(label) = label_as_i64(&label) else {
                continue;
            };
            match label {
                1 => kty = Some(value_as_i64(&value)?),
                3 => alg = Some(value_as_i64(&value)?),
                -1 => crv = Some(value_as_i64(&value)?),
                -2 => x = Some(value_as_bytes(&value, "x")?),
                -3 => y = Some(value_as_bytes(&value, "y")?),
                _ => {}
            }
        }

        let kty = kty.ok_or(CoseError::MissingField("kty"))?;
        let alg = alg.ok_or(CoseError::MissingField("alg"))?;
        let crv = crv.ok_or(CoseError::MissingField("crv"))?;
        let x = x.ok_or(CoseError::MissingField("x"))?;

        Self::assemble(kty, alg, crv, x, y)
    }

    /// Parse a public key from a PEM block (SPKI `PUBLIC KEY`).
    ///
    /// Ed25519 and P-256 SubjectPublicKeyInfo are accepted; anything else is refused by name.
    pub fn from_pem(pem: &str) -> Result<Self, CoseError> {
        let der = pem_to_der(pem)?;
        let (tag, seq) = der_tlv(&der, &mut 0)?;
        if tag != 0x30 {
            return Err(CoseError::Der("SPKI is not a SEQUENCE".to_string()));
        }
        let mut i = 0;
        let (alg_tag, alg_body) = der_tlv(seq, &mut i)?;
        if alg_tag != 0x30 {
            return Err(CoseError::Der(
                "AlgorithmIdentifier is not a SEQUENCE".to_string(),
            ));
        }
        let (bits_tag, bits) = der_tlv(seq, &mut i)?;
        if bits_tag != 0x03 {
            return Err(CoseError::Der(
                "subjectPublicKey is not a BIT STRING".to_string(),
            ));
        }
        let (unused, rest) = bits
            .split_first()
            .ok_or_else(|| CoseError::Der("BIT STRING is empty".to_string()))?;
        if *unused != 0 {
            return Err(CoseError::Der("BIT STRING has unused bits".to_string()));
        }
        let bits = rest;

        let mut j = 0;
        let (oid_tag, oid) = der_tlv(alg_body, &mut j)?;
        if oid_tag != 0x06 {
            return Err(CoseError::Der("missing algorithm OID".to_string()));
        }

        match oid {
            // 1.3.101.112 — id-Ed25519
            [0x2b, 0x65, 0x70] => {
                if bits.len() != 32 {
                    return Err(CoseError::InvalidLength {
                        field: "Ed25519 public key",
                        len: bits.len(),
                        expected: 32,
                    });
                }
                Ok(Self {
                    kind: KeyKind::Okp,
                    algorithm: KeyAlgorithm::EdDsa,
                    curve: Curve::Ed25519,
                    x: bits.to_vec(),
                    y: None,
                })
            }
            // 1.2.840.10045.2.1 — id-ecPublicKey; parameters must be prime256v1
            [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] => {
                let (curve_tag, curve_oid) = der_tlv(alg_body, &mut j)?;
                if curve_tag != 0x06 {
                    return Err(CoseError::Der(
                        "EC key is missing its named-curve OID".to_string(),
                    ));
                }
                // 1.2.840.10045.3.1.7 — prime256v1
                if curve_oid != [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] {
                    return Err(CoseError::UnsupportedPemAlgorithm);
                }
                // Uncompressed point: 0x04 || X(32) || Y(32)
                if bits.len() != 65 || bits[0] != 0x04 {
                    return Err(CoseError::Der(
                        "P-256 subjectPublicKey is not an uncompressed point".to_string(),
                    ));
                }
                Ok(Self {
                    kind: KeyKind::Ec2,
                    algorithm: KeyAlgorithm::Es256,
                    curve: Curve::P256,
                    x: bits[1..33].to_vec(),
                    y: Some(bits[33..65].to_vec()),
                })
            }
            _ => Err(CoseError::UnsupportedPemAlgorithm),
        }
    }

    /// Parse a key from either a PEM block or a base64url `COSE_Key`, sniffing the form.
    pub fn parse(text: &str) -> Result<Self, CoseError> {
        let trimmed = text.trim();
        if trimmed.starts_with("-----BEGIN") {
            return Self::from_pem(trimmed);
        }
        let bytes = decode_base64(trimmed)?;
        Self::from_cbor(&bytes)
    }

    fn assemble(
        kty: i64,
        alg: i64,
        crv: i64,
        x: Vec<u8>,
        y: Option<Vec<u8>>,
    ) -> Result<Self, CoseError> {
        let kind = match kty {
            1 => KeyKind::Okp,
            2 => KeyKind::Ec2,
            other => return Err(CoseError::UnsupportedKeyType(other)),
        };
        let algorithm = match alg {
            -7 => KeyAlgorithm::Es256,
            -8 => KeyAlgorithm::EdDsa,
            other => return Err(CoseError::UnsupportedAlgorithm(other)),
        };
        let curve = match crv {
            1 => Curve::P256,
            6 => Curve::Ed25519,
            other => return Err(CoseError::UnsupportedCurve(other)),
        };

        let consistent = matches!(
            (kind, algorithm, curve),
            (KeyKind::Ec2, KeyAlgorithm::Es256, Curve::P256)
                | (KeyKind::Okp, KeyAlgorithm::EdDsa, Curve::Ed25519)
        );
        if !consistent {
            return Err(CoseError::Inconsistent { kty, alg, crv });
        }

        match curve {
            Curve::P256 => {
                if x.len() != 32 {
                    return Err(CoseError::InvalidLength {
                        field: "x",
                        len: x.len(),
                        expected: 32,
                    });
                }
                let y = y.ok_or(CoseError::MissingField("y"))?;
                if y.len() != 32 {
                    return Err(CoseError::InvalidLength {
                        field: "y",
                        len: y.len(),
                        expected: 32,
                    });
                }
                Ok(Self {
                    kind,
                    algorithm,
                    curve,
                    x,
                    y: Some(y),
                })
            }
            Curve::Ed25519 => {
                if x.len() != 32 {
                    return Err(CoseError::InvalidLength {
                        field: "x",
                        len: x.len(),
                        expected: 32,
                    });
                }
                Ok(Self {
                    kind,
                    algorithm,
                    curve,
                    x,
                    y: None,
                })
            }
        }
    }
}

/// Decode base64url (unpadded or padded) and, for tolerance, standard base64.
fn decode_base64(text: &str) -> Result<Vec<u8>, CoseError> {
    const URL_NO_PAD: base64::engine::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;
    const URL_PAD: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE;
    const STD_NO_PAD: base64::engine::GeneralPurpose =
        base64::engine::general_purpose::STANDARD_NO_PAD;

    URL_NO_PAD
        .decode(text)
        .or_else(|_| URL_PAD.decode(text))
        .or_else(|_| STD_NO_PAD.decode(text))
        .map_err(|e| CoseError::Base64(e.to_string()))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, CoseError> {
    let begin = pem
        .find("-----BEGIN PUBLIC KEY-----")
        .ok_or_else(|| CoseError::Pem("missing `BEGIN PUBLIC KEY` block".to_string()))?;
    let end = pem
        .find("-----END PUBLIC KEY-----")
        .ok_or_else(|| CoseError::Pem("missing `END PUBLIC KEY` block".to_string()))?;
    if end <= begin {
        return Err(CoseError::Pem("PEM markers are out of order".to_string()));
    }
    let body = &pem[begin + "-----BEGIN PUBLIC KEY-----".len()..end];
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|e| CoseError::Base64(e.to_string()))
}

/// Read one DER TLV at `*i`, advancing it; returns `(tag, value)`.
fn der_tlv<'a>(data: &'a [u8], i: &mut usize) -> Result<(u8, &'a [u8]), CoseError> {
    let tag = *data
        .get(*i)
        .ok_or_else(|| CoseError::Der("truncated TLV tag".to_string()))?;
    *i += 1;
    let first = *data
        .get(*i)
        .ok_or_else(|| CoseError::Der("truncated TLV length".to_string()))?;
    *i += 1;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(CoseError::Der(format!(
                "unsupported DER length form ({n} bytes)"
            )));
        }
        let mut len = 0usize;
        for _ in 0..n {
            let byte = *data
                .get(*i)
                .ok_or_else(|| CoseError::Der("truncated DER length".to_string()))?;
            *i += 1;
            len = len
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(byte)))
                .ok_or_else(|| CoseError::Der("DER length overflow".to_string()))?;
        }
        len
    };
    let end = i
        .checked_add(len)
        .ok_or_else(|| CoseError::Der("DER length overflow".to_string()))?;
    let value = data
        .get(*i..end)
        .ok_or_else(|| CoseError::Der("truncated TLV value".to_string()))?;
    *i = end;
    Ok((tag, value))
}

// ---------------------------------------------------------------------------
// Minimal CBOR subset
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum CborValue {
    Uint(u64),
    Nint(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
}

struct Cbor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cbor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn parse_one(&mut self) -> Result<CborValue, CoseError> {
        let value = self.item(0)?;
        if self.pos != self.data.len() {
            return Err(CoseError::Cbor(format!(
                "{} trailing bytes after the top-level item",
                self.data.len() - self.pos
            )));
        }
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, CoseError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| CoseError::Cbor("unexpected end of input".to_string()))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CoseError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| CoseError::Cbor("length overflow".to_string()))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| CoseError::Cbor("unexpected end of input".to_string()))?;
        self.pos = end;
        Ok(slice)
    }

    /// Read the argument for `additional info` of a head byte.
    fn read_arg(&mut self, info: u8) -> Result<u64, CoseError> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => Ok(u64::from(self.byte()?)),
            25 => {
                let b = self.take(2)?;
                Ok(u64::from(u16::from_be_bytes([b[0], b[1]])))
            }
            26 => {
                let b = self.take(4)?;
                Ok(u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
            }
            27 => {
                let b = self.take(8)?;
                Ok(u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            31 => Err(CoseError::Cbor(
                "indefinite-length items are not valid in a COSE_Key here".to_string(),
            )),
            other => Err(CoseError::Cbor(format!("reserved additional info {other}"))),
        }
    }

    fn item(&mut self, depth: usize) -> Result<CborValue, CoseError> {
        if depth > 16 {
            return Err(CoseError::Cbor("nesting too deep".to_string()));
        }
        let head = self.byte()?;
        let major = head >> 5;
        let info = head & 0x1f;
        match major {
            0 => Ok(CborValue::Uint(self.read_arg(info)?)),
            1 => {
                let arg = self.read_arg(info)?;
                let n = i64::try_from(arg)
                    .map_err(|_| CoseError::Cbor("negative integer out of range".to_string()))?;
                Ok(CborValue::Nint(-1 - n))
            }
            2 => {
                let len = self.read_arg(info)?;
                let len = usize::try_from(len)
                    .map_err(|_| CoseError::Cbor("byte string too long".to_string()))?;
                Ok(CborValue::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.read_arg(info)?;
                let len = usize::try_from(len)
                    .map_err(|_| CoseError::Cbor("text string too long".to_string()))?;
                let raw = self.take(len)?;
                let text = std::str::from_utf8(raw)
                    .map_err(|_| CoseError::Cbor("text string is not UTF-8".to_string()))?;
                Ok(CborValue::Text(text.to_string()))
            }
            4 => {
                let len = self.read_arg(info)?;
                if len > 4096 {
                    return Err(CoseError::Cbor("array too long".to_string()));
                }
                let mut items = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    items.push(self.item(depth + 1)?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                let len = self.read_arg(info)?;
                if len > 4096 {
                    return Err(CoseError::Cbor("map too long".to_string()));
                }
                let mut items = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    let key = self.item(depth + 1)?;
                    let value = self.item(depth + 1)?;
                    items.push((key, value));
                }
                Ok(CborValue::Map(items))
            }
            7 => match info {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                other => Err(CoseError::Cbor(format!("unsupported simple value {other}"))),
            },
            other => Err(CoseError::Cbor(format!("unsupported major type {other}"))),
        }
    }
}

fn label_as_i64(value: &CborValue) -> Option<i64> {
    match value {
        CborValue::Uint(v) => i64::try_from(*v).ok(),
        CborValue::Nint(v) => Some(*v),
        _ => None,
    }
}

fn value_as_i64(value: &CborValue) -> Result<i64, CoseError> {
    label_as_i64(value)
        .ok_or_else(|| CoseError::Cbor("COSE integer field is not a CBOR integer".to_string()))
}

fn value_as_bytes(value: &CborValue, field: &'static str) -> Result<Vec<u8>, CoseError> {
    match value {
        CborValue::Bytes(b) => Ok(b.clone()),
        _ => Err(CoseError::Cbor(format!(
            "`{field}` is not a CBOR byte string"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(major: u8, n: u64) -> Vec<u8> {
        match n {
            0..=23 => vec![(major << 5) | n as u8],
            24..=255 => vec![(major << 5) | 24, n as u8],
            _ => unreachable!("test helper only needs short arguments"),
        }
    }

    fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut out = head(2, bytes.len() as u64);
        out.extend_from_slice(bytes);
        out
    }

    fn cbor_int(v: i64) -> Vec<u8> {
        if v >= 0 {
            head(0, v as u64)
        } else {
            let encoded = u64::try_from(-1 - v).expect("test integers are in range");
            head(1, encoded)
        }
    }

    fn cose_map(alg: i64, kty: i64, crv: i64, x: &[u8], y: Option<&[u8]>) -> Vec<u8> {
        let mut pairs: Vec<(i64, Vec<u8>)> = vec![
            (1, cbor_int(kty)),
            (3, cbor_int(alg)),
            (-1, cbor_int(crv)),
            (-2, cbor_bytes(x)),
        ];
        if let Some(y) = y {
            pairs.push((-3, cbor_bytes(y)));
        }
        let mut out = head(5, pairs.len() as u64);
        for (label, value) in pairs {
            out.extend_from_slice(&cbor_int(label));
            out.extend_from_slice(&value);
        }
        out
    }

    fn spki_der(alg: &[u8], key: &[u8]) -> Vec<u8> {
        // AlgorithmIdentifier ::= SEQUENCE { OID, [OID] }
        let mut alg_body = vec![0x06, alg.len() as u8];
        alg_body.extend_from_slice(alg);
        let alg_seq = vec![0x30, alg_body.len() as u8]
            .into_iter()
            .chain(alg_body)
            .collect::<Vec<u8>>();
        // BIT STRING with 0 unused bits
        let mut bits = vec![0x03, (key.len() + 1) as u8, 0x00];
        bits.extend_from_slice(key);
        let mut body = alg_seq;
        body.extend_from_slice(&bits);
        let mut out = vec![0x30];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else {
            out.push(0x81);
            out.push(body.len() as u8);
        }
        out.extend_from_slice(&body);
        out
    }

    fn pem(der: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
    }

    const ED25519_OID: [u8; 3] = [0x2b, 0x65, 0x70];
    const EC_OID: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const P256_OID: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    fn p256_spki() -> Vec<u8> {
        // AlgorithmIdentifier for id-ecPublicKey with prime256v1 parameters needs two OIDs.
        let mut alg_body = vec![0x06, EC_OID.len() as u8];
        alg_body.extend_from_slice(&EC_OID);
        alg_body.push(0x06);
        alg_body.push(P256_OID.len() as u8);
        alg_body.extend_from_slice(&P256_OID);
        let alg_seq = [vec![0x30, alg_body.len() as u8], alg_body].concat();
        let mut point = vec![0x04];
        point.extend_from_slice(&[0x11; 32]);
        point.extend_from_slice(&[0x22; 32]);
        let mut bits = vec![0x03, (point.len() + 1) as u8, 0x00];
        bits.extend_from_slice(&point);
        let body = [alg_seq, bits].concat();
        [vec![0x30, 0x81, body.len() as u8], body].concat()
    }

    #[test]
    fn parses_es256_cose_key() {
        let bytes = cose_map(-7, 2, 1, &[0x01; 32], Some(&[0x02; 32]));
        let key = CosePublicKey::from_cbor(&bytes).expect("ES256 key parses");
        assert_eq!(key.algorithm, KeyAlgorithm::Es256);
        assert_eq!(key.kind, KeyKind::Ec2);
        assert_eq!(key.curve, Curve::P256);
        assert_eq!(key.x, vec![0x01; 32]);
        assert_eq!(key.y, Some(vec![0x02; 32]));
    }

    #[test]
    fn parses_eddsa_cose_key() {
        let bytes = cose_map(-8, 1, 6, &[0x03; 32], None);
        let key = CosePublicKey::from_cbor(&bytes).expect("EdDSA key parses");
        assert_eq!(key.algorithm, KeyAlgorithm::EdDsa);
        assert_eq!(key.kind, KeyKind::Okp);
        assert_eq!(key.curve, Curve::Ed25519);
        assert_eq!(key.x, vec![0x03; 32]);
        assert_eq!(key.y, None);
    }

    #[test]
    fn rejects_unknown_algorithm_by_number() {
        let bytes = cose_map(-9, 2, 1, &[0x01; 32], Some(&[0x02; 32]));
        assert_eq!(
            CosePublicKey::from_cbor(&bytes),
            Err(CoseError::UnsupportedAlgorithm(-9))
        );
    }

    #[test]
    fn rejects_inconsistent_kty_alg_crv() {
        // OKP with ES256 is not a real key.
        let bytes = cose_map(-7, 1, 6, &[0x01; 32], None);
        assert_eq!(
            CosePublicKey::from_cbor(&bytes),
            Err(CoseError::Inconsistent {
                kty: 1,
                alg: -7,
                crv: 6
            })
        );
    }

    #[test]
    fn rejects_short_coordinate() {
        let bytes = cose_map(-7, 2, 1, &[0x01; 31], Some(&[0x02; 32]));
        assert_eq!(
            CosePublicKey::from_cbor(&bytes),
            Err(CoseError::InvalidLength {
                field: "x",
                len: 31,
                expected: 32
            })
        );
    }

    #[test]
    fn rejects_non_map_cbor() {
        let bytes = cbor_bytes(&[1, 2, 3]);
        assert_eq!(CosePublicKey::from_cbor(&bytes), Err(CoseError::NotAMap));
    }

    #[test]
    fn parses_ed25519_spki_pem() {
        let der = spki_der(&ED25519_OID, &[0x07; 32]);
        let key = CosePublicKey::from_pem(&pem(&der)).expect("Ed25519 PEM parses");
        assert_eq!(key.algorithm, KeyAlgorithm::EdDsa);
        assert_eq!(key.x, vec![0x07; 32]);
    }

    #[test]
    fn parses_p256_spki_pem() {
        let key = CosePublicKey::from_pem(&pem(&p256_spki())).expect("P-256 PEM parses");
        assert_eq!(key.algorithm, KeyAlgorithm::Es256);
        assert_eq!(key.x, vec![0x11; 32]);
        assert_eq!(key.y, Some(vec![0x22; 32]));
    }

    #[test]
    fn rejects_unsupported_pem_algorithm() {
        let rsa_oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        let der = spki_der(&rsa_oid, &[0x00; 64]);
        assert_eq!(
            CosePublicKey::from_pem(&pem(&der)),
            Err(CoseError::UnsupportedPemAlgorithm)
        );
    }

    #[test]
    fn parse_sniffs_base64url_cose() {
        let bytes = cose_map(-8, 1, 6, &[0x09; 32], None);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let key = CosePublicKey::parse(&encoded).expect("base64url COSE parses");
        assert_eq!(key.x, vec![0x09; 32]);
    }
}
