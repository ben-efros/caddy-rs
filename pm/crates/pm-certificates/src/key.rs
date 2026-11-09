//! Private-key parsing and proof that a key matches a certificate public key.
//!
//! The PM never trusts a filename, a `modulus` hint or a PEM label. It signs a fixed message with
//! the supplied private key and verifies the signature with the leaf certificate's SubjectPublicKeyInfo.
//! That proves possession and equality without ever serialising a public key from the private key.
//! No error carries key bytes or PEM text.

use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, RsaKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256,
};

use crate::pem::PemBlock;
use crate::x509::{EcCurve, PublicKey};
use crate::{CertificateValidationError, KeyType};

/// A challenge signed with the uploaded key. The exact bytes are irrelevant to security as long as
/// they are fixed and never confused with a certificate/TLS signature.
const KEY_MATCH_MESSAGE: &[u8] = b"caddy-rs-pm-manual-certificate-key-match-v1";

pub(crate) enum ParsedPrivateKey {
    Rsa(RsaKeyPair),
    EcdsaP256(EcdsaKeyPair),
    EcdsaP384(EcdsaKeyPair),
}

/// Parse one private-key PEM block for the algorithm named by the certificate.
pub(crate) fn parse_private_key(
    block: &PemBlock,
    certificate_key: &PublicKey,
) -> Result<(ParsedPrivateKey, KeyType), CertificateValidationError> {
    match certificate_key {
        PublicKey::Rsa(_) => {
            let key = match block.label.as_str() {
                "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&block.der),
                "RSA PRIVATE KEY" => RsaKeyPair::from_der(&block.der),
                "EC PRIVATE KEY" => {
                    return Err(CertificateValidationError::UnsupportedKeyFormat {
                        reason:
                            "SEC1 EC PRIVATE KEY is not supported; provide a PKCS#8 PRIVATE KEY"
                                .to_string(),
                    })
                }
                "ENCRYPTED PRIVATE KEY" => {
                    return Err(CertificateValidationError::UnsupportedKeyFormat {
                        reason: "encrypted private keys are not supported".to_string(),
                    })
                }
                _ => {
                    return Err(CertificateValidationError::UnsupportedKeyFormat {
                        reason: "certificate has an RSA key but the private key is not PKCS#8 or \
                                 PKCS#1 RSA"
                            .to_string(),
                    })
                }
            }
            .map_err(|_| CertificateValidationError::UnsupportedKeyFormat {
                reason: "private key is not a valid unencrypted RSA key".to_string(),
            })?;
            let key_type = match key.public().modulus_len() {
                256 => KeyType::Rsa2048,
                512 => KeyType::Rsa4096,
                _ => {
                    return Err(CertificateValidationError::UnsupportedKeyType {
                        reason: "supported RSA key sizes are 2048 and 4096 bits".to_string(),
                    })
                }
            };
            Ok((ParsedPrivateKey::Rsa(key), key_type))
        }
        PublicKey::Ec { curve, .. } => {
            if block.label != "PRIVATE KEY" {
                return Err(CertificateValidationError::UnsupportedKeyFormat {
                    reason: "EC certificates require an unencrypted PKCS#8 PRIVATE KEY".to_string(),
                });
            }
            let rng = SystemRandom::new();
            match curve {
                EcCurve::P256 => {
                    let key =
                        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &block.der, &rng)
                            .map_err(|_| CertificateValidationError::UnsupportedKeyFormat {
                                reason: "private key is not a valid unencrypted P-256 PKCS#8 key"
                                    .to_string(),
                            })?;
                    Ok((ParsedPrivateKey::EcdsaP256(key), KeyType::P256))
                }
                EcCurve::P384 => {
                    let key =
                        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &block.der, &rng)
                            .map_err(|_| CertificateValidationError::UnsupportedKeyFormat {
                                reason: "private key is not a valid unencrypted P-384 PKCS#8 key"
                                    .to_string(),
                            })?;
                    Ok((ParsedPrivateKey::EcdsaP384(key), KeyType::P384))
                }
            }
        }
    }
}

/// Sign a fixed message with `key` and verify it with the certificate's public key.
pub(crate) fn verify_key_matches(
    key: &ParsedPrivateKey,
    certificate_key: &PublicKey,
) -> Result<(), CertificateValidationError> {
    let rng = SystemRandom::new();
    match (key, certificate_key) {
        (ParsedPrivateKey::Rsa(key), PublicKey::Rsa(public_der)) => {
            let mut signature = vec![0u8; key.public().modulus_len()];
            key.sign(&RSA_PKCS1_SHA256, &rng, KEY_MATCH_MESSAGE, &mut signature)
                .map_err(|_| CertificateValidationError::KeyMismatch)?;
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_der)
                .verify(KEY_MATCH_MESSAGE, &signature)
                .map_err(|_| CertificateValidationError::KeyMismatch)
        }
        (ParsedPrivateKey::EcdsaP256(key), PublicKey::Ec { curve, point })
            if *curve == EcCurve::P256 =>
        {
            let signature = key
                .sign(&rng, KEY_MATCH_MESSAGE)
                .map_err(|_| CertificateValidationError::KeyMismatch)?;
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
                .verify(KEY_MATCH_MESSAGE, signature.as_ref())
                .map_err(|_| CertificateValidationError::KeyMismatch)
        }
        (ParsedPrivateKey::EcdsaP384(key), PublicKey::Ec { curve, point })
            if *curve == EcCurve::P384 =>
        {
            let signature = key
                .sign(&rng, KEY_MATCH_MESSAGE)
                .map_err(|_| CertificateValidationError::KeyMismatch)?;
            UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, point)
                .verify(KEY_MATCH_MESSAGE, signature.as_ref())
                .map_err(|_| CertificateValidationError::KeyMismatch)
        }
        _ => Err(CertificateValidationError::KeyMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem::parse_blocks;
    use crate::x509::parse_certificate;

    fn der(pem: &str) -> Vec<u8> {
        use base64::Engine as _;
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("base64")
    }

    #[test]
    fn accepts_a_matching_rsa_key() {
        let cert = include_str!("../../../tests/fixtures/manual-valid.crt.pem");
        let key = include_str!("../../../tests/fixtures/manual-valid.key.pem");
        let parsed = parse_certificate(&der(cert)).expect("certificate");
        let block = parse_blocks(key).expect("key pem").remove(0);
        let (key, key_type) = parse_private_key(&block, &parsed.public_key).expect("key");
        assert_eq!(key_type, KeyType::Rsa2048);
        verify_key_matches(&key, &parsed.public_key).expect("matching key");
    }

    #[test]
    fn rejects_a_different_rsa_key() {
        let cert = include_str!("../../../tests/fixtures/manual-valid.crt.pem");
        let key = include_str!("../../../tests/fixtures/manual-other.key.pem");
        let parsed = parse_certificate(&der(cert)).expect("certificate");
        let block = parse_blocks(key).expect("key pem").remove(0);
        let (key, _) = parse_private_key(&block, &parsed.public_key).expect("key");
        assert!(matches!(
            verify_key_matches(&key, &parsed.public_key),
            Err(CertificateValidationError::KeyMismatch)
        ));
    }
}
