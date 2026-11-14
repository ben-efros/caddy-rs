//! Cross-CA identity-spoofing regression for `admin.remote.access_control` (T-ADMIN-061).
//!
//! Every `public_keys` entry is a TLS trust anchor. A client certificate issued by a *different*
//! configured CA that copies a configured identity's subject DN must not inherit that identity's
//! permissions: identity binding is by key material (SubjectPublicKeyInfo / verified chain), never
//! by a CA-chosen distinguished name.
//!
//! The test PKI under `testdata/access-control` has two CAs and two client certificates with the
//! identical subject `CN=admin-a,O=caddy-rs`; each client is issued by its own CA. These tests fail
//! against the DN-matching implementation (the CA-B client would be treated as identity A).

use caddy_rs_admin::{access::decide, AdminClientIdentity};
use caddy_rs_core::AdminRemote;
use http::{Method, StatusCode};

const CA_A_PEM: &str = include_str!("../testdata/access-control/ca-a.pem");
const CA_B_PEM: &str = include_str!("../testdata/access-control/ca-b.pem");
const CLIENT_A_PEM: &str = include_str!("../testdata/access-control/client-a.pem");
const CLIENT_B_PEM: &str = include_str!("../testdata/access-control/client-b.pem");
const ROOT_CA_PEM: &str = include_str!("../testdata/access-control/root-ca.pem");
const INTERMEDIATE_CA_PEM: &str = include_str!("../testdata/access-control/intermediate-ca.pem");
const CLIENT_C_PEM: &str = include_str!("../testdata/access-control/client-c.pem");

fn certificate_der(pem: &str) -> Vec<u8> {
    caddy_rs_tls::certificates_from_pem(pem)
        .expect("PEM certificate")
        .first()
        .expect("one certificate")
        .as_ref()
        .to_vec()
}

fn certificate_base64(pem: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(certificate_der(pem))
}

/// The identity the TLS layer derives from a client that presents exactly one certificate.
fn identity(pem: &str) -> AdminClientIdentity {
    let leaf = certificate_der(pem);
    let info = caddy_rs_tls::ClientCertificateInfo::parse(&leaf, true).expect("certificate info");
    AdminClientIdentity {
        certificates: vec![leaf],
        subject: info.subject,
        issuer: info.issuer,
        serial: info.serial,
    }
}

fn remote(value: serde_json::Value) -> AdminRemote {
    serde_json::from_value(value).expect("valid admin.remote configuration")
}

fn get(remote: &AdminRemote, identity: &AdminClientIdentity, path: &str) -> Result<(), StatusCode> {
    decide(Some(remote), Some(identity), &Method::GET, path).map_err(|denial| denial.status)
}

#[test]
fn copied_subject_dn_from_another_configured_ca_gets_403_not_identity_permissions() {
    let victim = identity(CLIENT_A_PEM);
    let attacker = identity(CLIENT_B_PEM);
    assert_eq!(
        victim.subject, attacker.subject,
        "spoof precondition: the CA-B client copies identity A's subject DN"
    );
    assert_ne!(victim.issuer, attacker.issuer);

    // Entry A names identity A's subject as an advisory filter; the CA-B client copies that DN.
    let remote = remote(serde_json::json!({
        "access_control": [
            {
                "public_keys": [certificate_base64(CA_A_PEM)],
                "subjects": [victim.subject.clone()],
                "permissions": [{ "paths": ["/config/"] }]
            },
            {
                "public_keys": [certificate_base64(CA_B_PEM)],
                "permissions": [{ "paths": ["/id/"] }]
            }
        ]
    }));

    // Recognized as a CA-B client, so its own permissions decide: 403, not identity A's access.
    assert_eq!(
        get(&remote, &attacker, "/config/"),
        Err(StatusCode::FORBIDDEN)
    );
    assert_eq!(get(&remote, &attacker, "/id/"), Ok(()));
    assert_eq!(get(&remote, &victim, "/config/"), Ok(()));
}

#[test]
fn configured_leaf_anchor_binds_to_the_key_not_the_subject_dn() {
    let remote = remote(serde_json::json!({
        "access_control": [{
            "public_keys": [certificate_base64(CLIENT_A_PEM)],
            "permissions": [{ "paths": ["/config/"] }]
        }]
    }));
    let victim = identity(CLIENT_A_PEM);
    let attacker = identity(CLIENT_B_PEM);
    assert_eq!(get(&remote, &victim, "/config/"), Ok(()));
    assert_eq!(
        get(&remote, &attacker, "/config/"),
        Err(StatusCode::UNAUTHORIZED),
        "a copied subject DN must not match a configured leaf certificate"
    );
}

/// Build the identity the TLS layer derives from a client that presents `pems` leaf first.
fn identity_with_chain(pems: &[&str]) -> AdminClientIdentity {
    let certificates: Vec<Vec<u8>> = pems.iter().map(|pem| certificate_der(pem)).collect();
    let info = caddy_rs_tls::ClientCertificateInfo::parse(&certificates[0], true)
        .expect("certificate info");
    AdminClientIdentity {
        certificates,
        subject: info.subject,
        issuer: info.issuer,
        serial: info.serial,
    }
}

/// Review finding: a CA-B client appends CA-A's public certificate to its chain
/// (`[leaf_B, ca_A_cert]`). rustls verifies the leaf against CA-B's anchor, so the client is a
/// legitimate CA-B identity; the appended certificate must not make entry A (which requires CA-A)
/// match, or the client would inherit entry A's permissions without possessing a CA-A key.
#[test]
fn appended_foreign_ca_certificate_does_not_grant_that_entry() {
    let attacker = identity_with_chain(&[CLIENT_B_PEM, CA_A_PEM]);

    // Preconditions: the appended certificate really carries CA-A's key, and CA-A did not issue
    // the leaf (no verified path to CA-A).
    let appended = caddy_rs_tls::ClientCertificateInfo::parse(&attacker.certificates[1], false)
        .expect("appended certificate info");
    let ca_a = caddy_rs_tls::ClientCertificateInfo::parse(&certificate_der(CA_A_PEM), false)
        .expect("CA-A certificate info");
    assert_eq!(appended.public_key_der, ca_a.public_key_der);
    assert!(!caddy_rs_tls::chain_anchored_by(
        &certificate_der(CA_A_PEM),
        &attacker.certificates
    ));

    let remote = remote(serde_json::json!({
        "access_control": [
            {
                "public_keys": [certificate_base64(CA_A_PEM)],
                "permissions": [{ "paths": ["/config/"] }]
            },
            {
                "public_keys": [certificate_base64(CA_B_PEM)],
                "permissions": [{ "paths": ["/id/"] }]
            }
        ]
    }));

    // Recognized as a CA-B client only: 403 for entry A's path, its own entry still applies.
    assert_eq!(
        get(&remote, &attacker, "/config/"),
        Err(StatusCode::FORBIDDEN),
        "an unverified appended certificate must not bind the client to another entry"
    );
    assert_eq!(get(&remote, &attacker, "/id/"), Ok(()));
}

/// Intermediate-anchor semantics: a configured intermediate is a trust anchor only for leaves it
/// issued, verified through WebPKI (never by scanning the presented chain for its key). A
/// configured root above it still verifies through the client-presented intermediate.
#[test]
fn configured_intermediate_anchor_authorizes_only_the_leaves_it_issued() {
    let intermediate_remote = remote(serde_json::json!({
        "access_control": [{
            "public_keys": [certificate_base64(INTERMEDIATE_CA_PEM)],
            "permissions": [{ "paths": ["/config/"] }]
        }]
    }));

    // WebPKI tries the configured anchor before presented intermediates, so the leaf alone and
    // the leaf with its intermediate both verify.
    assert_eq!(
        get(&intermediate_remote, &identity(CLIENT_C_PEM), "/config/"),
        Ok(())
    );
    let chain_c = identity_with_chain(&[CLIENT_C_PEM, INTERMEDIATE_CA_PEM]);
    assert_eq!(get(&intermediate_remote, &chain_c, "/config/"), Ok(()));

    // The intermediate is not a blanket pass: a CA-B leaf does not chain to it.
    assert_eq!(
        get(&intermediate_remote, &identity(CLIENT_B_PEM), "/config/"),
        Err(StatusCode::UNAUTHORIZED)
    );

    // A configured root verifies the same chain through the presented intermediate.
    let root_remote = remote(serde_json::json!({
        "access_control": [{
            "public_keys": [certificate_base64(ROOT_CA_PEM)],
            "permissions": [{ "paths": ["/config/"] }]
        }]
    }));
    assert_eq!(get(&root_remote, &chain_c, "/config/"), Ok(()));
}
