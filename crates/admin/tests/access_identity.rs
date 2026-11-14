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
