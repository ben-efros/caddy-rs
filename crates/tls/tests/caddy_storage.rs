//! Compatibility test: load a Caddy/CertMagic data-directory layout created in a temp dir.
//!
//! The fixture tree under `tests/fixtures/caddy-data` mirrors the real layout Caddy writes:
//!
//! ```text
//! certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.{crt,key,json}
//! certificates/local/wildcard_.example.net/wildcard_.example.net.{crt,key,json}
//! ```

use std::path::Path;

use caddy_rs_tls::{
    caddy_certificate_storage_name, caddy_issuer_key, CertificateStorage, FileStorage,
    StoredCertificate,
};

fn fixture_directory() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/caddy-data")
}

/// Recursively copy a fixture tree (files only) into `destination`.
fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

#[tokio::test]
async fn loads_caddy_layout_fixture_tree_from_temp_dir() {
    let temporary = tempfile::tempdir().unwrap();
    copy_tree(&fixture_directory(), temporary.path());
    let storage = FileStorage::new(temporary.path());

    let mut keys = storage.list("").await.unwrap();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "acme-v02.api.letsencrypt.org-directory/example.com".to_string(),
            "local/*.example.net".to_string(),
        ]
    );

    let certificate = storage
        .load("acme-v02.api.letsencrypt.org-directory/example.com")
        .await
        .unwrap()
        .expect("fixture certificate should load");
    assert_eq!(
        certificate.domains,
        vec!["example.com".to_string(), "www.example.com".to_string()]
    );
    assert_eq!(certificate.not_after_unix, 1_775_001_600); // 2026-04-01T00:00:00Z
    assert_eq!(certificate.certificate_pem.len(), 2, "leaf plus CA");
    assert!(certificate.private_key_pem.contains("PRIVATE KEY"));

    let wildcard = storage
        .load("local/*.example.net")
        .await
        .unwrap()
        .expect("wildcard fixture should load");
    assert_eq!(wildcard.domains, vec!["*.example.net".to_string()]);
    assert_eq!(wildcard.not_after_unix, 1_784_073_600); // 2026-07-15T00:00:00Z
}

#[tokio::test]
async fn writes_caddy_layout_and_reloads_it() {
    let temporary = tempfile::tempdir().unwrap();
    copy_tree(&fixture_directory(), temporary.path());
    let storage = FileStorage::new(temporary.path());

    // Round-trip the fixture certificate under a new issuer/name.
    let source = storage
        .load("acme-v02.api.letsencrypt.org-directory/example.com")
        .await
        .unwrap()
        .expect("fixture certificate should load");
    let stored = StoredCertificate {
        domains: vec!["stored.example.org".to_string()],
        ..source
    };
    let key = format!("{}/stored.example.org", caddy_issuer_key("local"));
    storage.store(&key, &stored).await.unwrap();

    let directory = temporary
        .path()
        .join("certificates")
        .join("local")
        .join(caddy_certificate_storage_name("stored.example.org"));
    let expected = directory.join("stored.example.org.crt");
    assert!(expected.is_file(), "expected `{}`", expected.display());
    assert!(directory.join("stored.example.org.key").is_file());
    assert!(directory.join("stored.example.org.json").is_file());
    // Written files are pure PEM / JSON, so Caddy tooling can inspect them.
    let chain = std::fs::read_to_string(&expected).unwrap();
    assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 2);
    let metadata = std::fs::read_to_string(directory.join("stored.example.org.json")).unwrap();
    assert!(metadata.contains("\"stored.example.org\""));

    let reloaded = storage.load(&key).await.unwrap().unwrap();
    assert_eq!(reloaded.domains, vec!["stored.example.org".to_string()]);
    assert_eq!(reloaded.not_after_unix, 1_775_001_600);
    assert_eq!(reloaded.certificate_pem, stored.certificate_pem);
    assert_eq!(
        reloaded.private_key_pem,
        stored.private_key_pem.trim_end().to_string()
    );
}

#[tokio::test]
async fn a_realistic_caddy_data_directory_is_reused_without_conversion() {
    // Simulates the migration scenario from DIV-0013: an existing Caddy data directory is pointed
    // at directly and its certificates are read back.
    let temporary = tempfile::tempdir().unwrap();
    copy_tree(&fixture_directory(), temporary.path());
    let storage = FileStorage::new(temporary.path());

    let all = storage
        .list("acme-v02.api.letsencrypt.org-directory/")
        .await
        .unwrap();
    assert_eq!(
        all,
        vec!["acme-v02.api.letsencrypt.org-directory/example.com".to_string()]
    );
    let local = storage.list("local/").await.unwrap();
    assert_eq!(local, vec!["local/*.example.net".to_string()]);
}
