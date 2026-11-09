use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use caddy_rs_pm_core::{CertificateId, CertificateOrigin, TlsMode};
use caddy_rs_pm_state::MemoryStore;
use tempfile::TempDir;

use super::*;

const NOW: i64 = 1_750_000_000;

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn valid() -> (String, String) {
    (
        fixture("manual-valid.crt.pem"),
        fixture("manual-valid.key.pem"),
    )
}

fn repo() -> (TempDir, CertificateRepository) {
    let dir = TempDir::new().expect("temp dir");
    let store: Arc<dyn StateStore> = Arc::new(MemoryStore::new());
    let repo = CertificateRepository::new(store, dir.path().join("secrets"));
    (dir, repo)
}

#[test]
fn accepts_a_valid_rsa_certificate_and_key() {
    let (certificate, key) = valid();
    let validated =
        validate_manual_certificate(&certificate, &key, &["manual.example.com".to_string()], NOW)
            .expect("valid");
    assert_eq!(
        validated.domains(),
        &[
            "manual.example.com".to_string(),
            "www.manual.example.com".to_string()
        ]
    );
    assert_eq!(validated.key_type(), KeyType::Rsa2048);
    assert_eq!(validated.expires_at_unix(), 4_891_363_200);
    assert_eq!(validated.fingerprint_sha256().len(), 64);
}

#[test]
fn accepts_a_wildcard_covering_exactly_one_label() {
    let validated = validate_manual_certificate(
        &fixture("manual-wildcard.crt.pem"),
        &fixture("manual-wildcard.key.pem"),
        &["one.wild.example.com".to_string()],
        NOW,
    )
    .expect("wildcard covers one label");
    assert_eq!(validated.domains(), &["*.wild.example.com".to_string()]);

    let error = validate_manual_certificate(
        &fixture("manual-wildcard.crt.pem"),
        &fixture("manual-wildcard.key.pem"),
        &["a.b.wild.example.com".to_string()],
        NOW,
    )
    .expect_err("wildcard does not cover two labels");
    assert!(matches!(
        error,
        CertificateValidationError::DomainNotCovered { .. }
    ));
}

#[test]
fn accepts_a_certificate_without_a_san_using_the_common_name() {
    let validated = validate_manual_certificate(
        &fixture("manual-cn-only.crt.pem"),
        &fixture("manual-cn-only.key.pem"),
        &["cn.example.com".to_string()],
        NOW,
    )
    .expect("CN fallback");
    assert_eq!(validated.domains(), &["cn.example.com".to_string()]);
}

#[test]
fn accepts_a_pkcs1_rsa_key_and_an_ec_key() {
    validate_manual_certificate(
        &fixture("manual-valid.crt.pem"),
        &fixture("manual-valid-rsa-pkcs1.key.pem"),
        &["manual.example.com".to_string()],
        NOW,
    )
    .expect("PKCS#1 RSA key");

    let validated = validate_manual_certificate(
        &fixture("manual-ec.crt.pem"),
        &fixture("manual-ec.key.pem"),
        &["ec.example.com".to_string()],
        NOW,
    )
    .expect("P-256 key");
    assert_eq!(validated.key_type(), KeyType::P256);
}

#[test]
fn accepts_a_leaf_and_root_chain() {
    let validated = validate_manual_certificate(
        &fixture("manual-chain.crt.pem"),
        &fixture("manual-chain.key.pem"),
        &["chain.example.com".to_string()],
        NOW,
    )
    .expect("chain");
    assert_eq!(validated.domains(), &["chain.example.com".to_string()]);
    assert_eq!(
        validated
            .certificate_chain_pem
            .matches("-----BEGIN CERTIFICATE-----")
            .count(),
        2
    );
}

#[test]
fn rejects_a_mismatched_key() {
    let error = validate_manual_certificate(
        &fixture("manual-valid.crt.pem"),
        &fixture("manual-other.key.pem"),
        &["manual.example.com".to_string()],
        NOW,
    )
    .expect_err("mismatch");
    assert!(matches!(error, CertificateValidationError::KeyMismatch));
    assert_eq!(error.location(), "privateKey");
    assert!(!error.to_string().contains("PRIVATE KEY"));
}

#[test]
fn rejects_an_expired_certificate() {
    let error = validate_manual_certificate(
        &fixture("manual-expired.crt.pem"),
        &fixture("manual-expired.key.pem"),
        &["expired.example.com".to_string()],
        NOW,
    )
    .expect_err("expired");
    assert!(matches!(error, CertificateValidationError::Expired { .. }));
    assert_eq!(error.location(), "certificate");
}

#[test]
fn rejects_a_certificate_that_is_not_yet_valid() {
    let error = validate_manual_certificate(
        &fixture("manual-future.crt.pem"),
        &fixture("manual-future.key.pem"),
        &["future.example.com".to_string()],
        NOW,
    )
    .expect_err("future");
    assert!(matches!(
        error,
        CertificateValidationError::NotYetValid { .. }
    ));
}

#[test]
fn rejects_a_domain_outside_the_certificate() {
    let error = validate_manual_certificate(
        &fixture("manual-valid.crt.pem"),
        &fixture("manual-valid.key.pem"),
        &["other.example.com".to_string()],
        NOW,
    )
    .expect_err("coverage");
    assert!(matches!(
        error,
        CertificateValidationError::DomainNotCovered { .. }
    ));
    assert_eq!(error.location(), "domains");
}

#[test]
fn rejects_oversized_and_wrong_label_inputs_without_echoing_them() {
    let (certificate, key) = valid();
    let oversized = "x".repeat(MAX_CERTIFICATE_PEM_BYTES + 1);
    let error =
        validate_manual_certificate(&oversized, &key, &["manual.example.com".to_string()], NOW)
            .expect_err("oversized");
    assert!(matches!(
        error,
        CertificateValidationError::InputTooLarge {
            field: "certificate",
            ..
        }
    ));

    let error = validate_manual_certificate(
        &certificate,
        &key.replace("PRIVATE KEY", "CERTIFICATE"),
        &["manual.example.com".to_string()],
        NOW,
    )
    .expect_err("wrong key label");
    assert!(!error.to_string().contains("BEGIN CERTIFICATE"));
}

#[test]
fn rejects_a_key_placed_in_the_certificate_field() {
    let (_, key) = valid();
    let error = validate_manual_certificate(&key, &key, &["manual.example.com".to_string()], NOW)
        .expect_err("key in certificate field");
    assert!(matches!(
        error,
        CertificateValidationError::InvalidPem {
            field: "certificate",
            ..
        }
    ));
}

#[test]
fn rejects_an_encrypted_or_sec1_key_with_a_typed_error() {
    let error = validate_manual_certificate(
        &fixture("manual-valid.crt.pem"),
        &fixture("manual-ec.key.pem").replace("PRIVATE KEY", "EC PRIVATE KEY"),
        &["manual.example.com".to_string()],
        NOW,
    )
    .expect_err("SEC1");
    assert!(matches!(
        error,
        CertificateValidationError::UnsupportedKeyFormat { .. }
    ));
}

#[test]
fn repository_stores_metadata_and_secret_files_with_owner_only_permissions() {
    let dir = TempDir::new().expect("temp dir");
    let store = Arc::new(MemoryStore::new());
    let repo = CertificateRepository::new(store.clone(), dir.path().join("secrets"));
    let (certificate, key) = valid();
    let validated =
        validate_manual_certificate(&certificate, &key, &["manual.example.com".to_string()], NOW)
            .expect("validated");
    let stored = repo.create(validated, NOW).expect("store");
    assert_eq!(stored.certificate.id, CertificateId(1));
    assert_eq!(stored.certificate.origin, CertificateOrigin::Manual);
    assert_eq!(stored.certificate.status, CertificateStatus::Pending);
    assert_eq!(repo.list().expect("list").len(), 1);

    let directory = repo.secrets_dir();
    assert_eq!(
        std::fs::metadata(directory)
            .expect("secrets metadata")
            .mode()
            & 0o777,
        0o700
    );
    for file in [
        &stored.certificate.certificate_file,
        &stored.certificate.key_file,
    ] {
        let metadata = std::fs::metadata(directory.join(file)).expect("secret metadata");
        assert_eq!(metadata.mode() & 0o777, 0o600, "file {file}");
    }

    // The metadata document and any error rendering never contain key material.
    let document = store
        .get("pm.certificates", "1")
        .expect("state")
        .expect("document");
    let text = serde_json::to_string(&document.value).expect("json");
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains(&key.lines().nth(1).expect("key body").to_string()));
    assert!(text.contains("manual-1.key.pem"));
}

#[test]
fn repository_allocates_monotonic_ids_and_refuses_overwrite() {
    let (_dir, repo) = repo();
    let (certificate, key) = valid();
    let material = || {
        validate_manual_certificate(&certificate, &key, &["manual.example.com".to_string()], NOW)
            .expect("validated")
    };
    let first = repo.create(material(), NOW).expect("first");
    let second = repo.create(material(), NOW).expect("second");
    assert_eq!(first.certificate.id, CertificateId(1));
    assert_eq!(second.certificate.id, CertificateId(2));

    // A pre-created target file is never overwritten; the attempt consumes an id and fails.
    let blocked_path = repo.secret_path("manual-3.key.pem");
    std::fs::write(&blocked_path, b"do not overwrite").expect("seed file");
    let error = repo.create(material(), NOW).expect_err("refuse overwrite");
    assert!(matches!(error, CertificateError::SecretFile { .. }));
    assert_eq!(
        std::fs::read(&blocked_path).expect("blocked file"),
        b"do not overwrite"
    );
    assert_eq!(repo.list().expect("list").len(), 2);
}

#[test]
fn repository_refuses_a_symlinked_secrets_directory() {
    let dir = TempDir::new().expect("temp dir");
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("real");
    std::os::unix::fs::symlink(&real, dir.path().join("secrets")).expect("symlink");
    let store: Arc<dyn StateStore> = Arc::new(MemoryStore::new());
    let repo = CertificateRepository::new(store, dir.path().join("secrets"));
    let (certificate, key) = valid();
    let validated =
        validate_manual_certificate(&certificate, &key, &["manual.example.com".to_string()], NOW)
            .expect("validated");
    let error = repo.create(validated, NOW).expect_err("symlink");
    assert!(matches!(error, CertificateError::UnsafeSecretPath { .. }));
}

#[test]
fn repository_delete_tombstones_the_id_and_removes_files() {
    let (_dir, repo) = repo();
    let (certificate, key) = valid();
    let validated =
        validate_manual_certificate(&certificate, &key, &["manual.example.com".to_string()], NOW)
            .expect("validated");
    let stored = repo.create(validated, NOW).expect("store");
    let paths = [
        repo.secret_path(&stored.certificate.certificate_file),
        repo.secret_path(&stored.certificate.key_file),
    ];
    assert!(paths.iter().all(|path| path.exists()));

    let wrong = repo
        .delete(stored.certificate.id, stored.revision + 1)
        .expect_err("stale revision");
    assert!(matches!(
        wrong,
        CertificateError::State(StateError::Conflict { .. })
    ));
    repo.delete(stored.certificate.id, stored.revision)
        .expect("delete");
    assert!(repo.get(stored.certificate.id).expect("get").is_none());
    assert!(paths.iter().all(|path| !path.exists()));
    assert!(matches!(
        repo.delete(stored.certificate.id, stored.revision),
        Err(CertificateError::NotFound(_))
    ));
}

#[test]
fn explicit_host_modes_only_bind_their_own_origin() {
    assert!(explicit_mode_allows_origin(
        TlsMode::Manual,
        CertificateOrigin::Manual
    ));
    assert!(!explicit_mode_allows_origin(
        TlsMode::InternalCa,
        CertificateOrigin::Manual
    ));
    assert!(!explicit_mode_allows_origin(
        TlsMode::AcmeConfigured,
        CertificateOrigin::Manual
    ));
}
