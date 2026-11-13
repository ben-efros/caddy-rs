//! End-to-end tests for the static passkey registry (T-AUTH-009).

use base64::Engine as _;
use caddy_rs_auth::{KeyAlgorithm, KeyRegistry, RegistryError};
use serde_json::json;

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
        head(1, u64::try_from(-1 - v).expect("in range"))
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

fn es256_b64url() -> String {
    let bytes = cose_map(-7, 2, 1, &[0x11; 32], Some(&[0x22; 32]));
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn eddsa_b64url() -> String {
    let bytes = cose_map(-8, 1, 6, &[0x33; 32], None);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn ed25519_pem() -> String {
    // SPKI: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING 0x00 || 32 bytes }
    let mut body = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    body.extend_from_slice(&[0x03, 0x21, 0x00]);
    body.extend_from_slice(&[0x44; 32]);
    let der = [vec![0x30, body.len() as u8], body].concat();
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
}

#[test]
fn loads_keys_from_apps_auth_passkeys() {
    let config = json!({
        "apps": {
            "auth": {
                "passkeys": [
                    {
                        "key_id": "yubikey-5-nfc",
                        "user": "admin",
                        "cose_key": es256_b64url(),
                        "name": "YubiKey 5 NFC",
                        "tags": ["admin", "prod"],
                        "transports": ["usb", "nfc"],
                        "added_at": 1_700_000_000u64
                    },
                    {
                        "key_id": "macbook-touchid",
                        "key": eddsa_b64url(),
                        "transports": "internal",
                        "name": "MacBook Touch ID"
                    }
                ]
            }
        }
    });

    let registry = KeyRegistry::from_config(&config).expect("config loads");
    assert_eq!(registry.len(), 2);

    let yubikey = registry.get("yubikey-5-nfc").expect("first key present");
    assert_eq!(yubikey.algorithm, KeyAlgorithm::Es256);
    assert_eq!(yubikey.name.as_deref(), Some("YubiKey 5 NFC"));
    assert_eq!(yubikey.tags, vec!["admin", "prod"]);
    assert_eq!(yubikey.transports, vec!["usb", "nfc"]);
    assert_eq!(yubikey.added_at, 1_700_000_000);

    let macbook = registry.get("macbook-touchid").expect("second key present");
    assert_eq!(macbook.algorithm, KeyAlgorithm::EdDsa);
    assert_eq!(macbook.user, "admin", "user defaults to admin");
    assert_eq!(macbook.transports, vec!["internal"]);
    assert_eq!(registry.keys_for_user("admin").len(), 2);
    assert_eq!(
        registry.algorithms(),
        vec![KeyAlgorithm::Es256, KeyAlgorithm::EdDsa]
    );
}

#[test]
fn accepts_pem_key_in_config() {
    let config = json!({ "auth": { "passkeys": [
        { "key_id": "pem-key", "pem": ed25519_pem() }
    ] } });
    let registry = KeyRegistry::from_config(&config).expect("PEM entry loads");
    let entry = registry.get("pem-key").expect("entry present");
    assert_eq!(entry.algorithm, KeyAlgorithm::EdDsa);
    assert_eq!(entry.key.x, vec![0x44; 32]);
}

#[test]
fn empty_or_absent_passkey_array_is_an_empty_registry() {
    let registry = KeyRegistry::from_config(&json!({ "apps": { "http": {} } }))
        .expect("no passkeys is not an error");
    assert!(registry.is_empty());
}

#[test]
fn invalid_key_is_rejected_with_the_json_path() {
    let config = json!({
        "apps": { "auth": { "passkeys": [
            { "key_id": "good", "cose_key": es256_b64url() },
            { "key_id": "bad", "cose_key": "not-base64!" }
        ] } }
    });
    let error = KeyRegistry::from_config(&config).expect_err("bad key must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("apps.auth.passkeys[1].cose_key"),
        "error must locate the entry: {message}"
    );
    assert!(
        message.contains("invalid public key"),
        "error must say the key is invalid: {message}"
    );
}

#[test]
fn unsupported_algorithm_names_the_algorithm() {
    let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cose_map(
        -9,
        2,
        1,
        &[0x11; 32],
        Some(&[0x22; 32]),
    ));
    let config = json!({ "passkeys": [{ "key_id": "rsa-ish", "cose_key": bad }] });
    let error = KeyRegistry::from_config(&config).expect_err("alg -9 must be rejected");
    assert!(
        error.to_string().contains("unsupported algorithm -9"),
        "error should name the algorithm: {error}"
    );
}

#[test]
fn duplicate_key_id_is_rejected() {
    let config = json!({ "passkeys": [
        { "key_id": "same", "cose_key": es256_b64url() },
        { "key_id": "same", "cose_key": eddsa_b64url() }
    ] });
    match KeyRegistry::from_config(&config) {
        Err(RegistryError::DuplicateKey { key_id, .. }) => assert_eq!(key_id, "same"),
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
}

#[test]
fn loads_flat_authorized_passkeys_file() {
    let text = format!(
        "# key_id          user   cose_key                  transports   name\n\
         yubikey-5-nfc      admin  {es}  usb,nfc      YubiKey5\n\
         \n\
         macbook-touchid    admin  {ed}  internal\n",
        es = es256_b64url(),
        ed = eddsa_b64url()
    );
    let registry =
        KeyRegistry::from_file_text("authorized_passkeys.txt", &text).expect("flat file loads");
    assert_eq!(registry.len(), 2);
    let yubikey = registry.get("yubikey-5-nfc").expect("key present");
    assert_eq!(yubikey.transports, vec!["usb", "nfc"]);
    assert_eq!(yubikey.name.as_deref(), Some("YubiKey5"));
    let macbook = registry.get("macbook-touchid").expect("key present");
    assert_eq!(macbook.transports, vec!["internal"]);
    assert!(macbook.name.is_none());
}

#[test]
fn malformed_flat_file_line_is_located_by_line_number() {
    let text = format!(
        "# comment\n\
         good admin {es} usb\n\
         broken-line\n",
        es = es256_b64url()
    );
    let error = KeyRegistry::from_file_text("authorized_passkeys.txt", &text)
        .expect_err("short line must be rejected");
    assert!(
        error.to_string().contains("authorized_passkeys.txt:3"),
        "error must name the line: {error}"
    );
}

#[test]
fn missing_key_id_is_located() {
    let config = json!({ "apps": { "auth": { "passkeys": [
        { "cose_key": es256_b64url() }
    ] } } });
    let error = KeyRegistry::from_config(&config).expect_err("missing key_id rejected");
    assert!(
        error.to_string().contains("apps.auth.passkeys[0]"),
        "error must name the entry: {error}"
    );
    assert!(
        error.to_string().contains("key_id"),
        "error must name the field: {error}"
    );
}
