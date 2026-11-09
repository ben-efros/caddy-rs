use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use caddy_rs_pm_config::ConfigSettings;
use caddy_rs_pm_core::{
    AutoCertificatePolicy, AutoMode, HostSpec, HostTls, PolicyId, ProxySpec, Upstream,
    UpstreamScheme,
};
use caddy_rs_pm_service::HostDraft;
use caddy_rs_pm_state::StateError;
use serde_json::json;

use super::*;

fn temp_data_dir() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("create temp dir");
    let data_dir = temp.path().join("data");
    (temp, data_dir)
}

fn open(data_dir: &Path) -> PmRuntime {
    PmRuntime::open(RuntimeConfig::new(data_dir)).expect("open runtime")
}

fn open_error(data_dir: &Path) -> RuntimeError {
    match PmRuntime::open(RuntimeConfig::new(data_dir)) {
        Ok(_) => panic!("open unexpectedly succeeded for {}", data_dir.display()),
        Err(error) => error,
    }
}

fn proxy_spec() -> HostSpec {
    HostSpec::Proxy(ProxySpec::new(Upstream::new(
        UpstreamScheme::Http,
        "10.0.0.5",
        8080,
    )))
}

fn disabled_draft(domains: &[&str]) -> HostDraft {
    HostDraft::new(
        domains.iter().map(|domain| (*domain).to_string()).collect(),
        HostTls::disabled(),
        proxy_spec(),
    )
}

fn auto_draft(domain: &str, policy_id: u64) -> HostDraft {
    HostDraft::new(
        vec![domain.to_string()],
        HostTls::for_auto(PolicyId(policy_id)),
        proxy_spec(),
    )
}

fn auto_policy(id: u64, subjects: &[&str]) -> AutoCertificatePolicy {
    AutoCertificatePolicy {
        id: PolicyId(id),
        name: format!("policy-{id}"),
        subjects: subjects.iter().map(|value| (*value).to_string()).collect(),
        mode: AutoMode::OnDemand,
        issuer: Some("letsencrypt".to_string()),
        key_type: None,
        renewal_window_ratio: Some(0.3),
        challenge: caddy_rs_pm_core::AcmeChallenge::Http01,
        enabled: true,
    }
}

fn file_names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("read directory")
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

#[test]
fn open_creates_pm_state_and_secures_created_directories() {
    let (_temp, data_dir) = temp_data_dir();
    let runtime = open(&data_dir);

    assert_eq!(runtime.data_dir(), data_dir.as_path());
    assert_eq!(runtime.state_path(), data_dir.join("pm/state.json"));
    assert!(runtime.state_path().is_file());
    assert!(!data_dir.join("state.json").exists());
    assert_eq!(file_names(&data_dir.join("pm")), vec!["state.json"]);

    #[cfg(unix)]
    {
        assert_eq!(mode(&data_dir), 0o700);
        assert_eq!(mode(&data_dir.join("pm")), 0o700);
        assert_eq!(mode(runtime.state_path()), 0o600);
    }
}

#[test]
fn reopen_preserves_a_host_created_through_the_service() {
    let (_temp, data_dir) = temp_data_dir();
    let created = {
        let runtime = open(&data_dir);
        runtime
            .service()
            .create(disabled_draft(&["example.com"]))
            .expect("create host")
    };

    let reopened = open(&data_dir);
    let hosts = reopened.hosts().list().expect("list hosts");
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host.id, created.host.id);
    assert_eq!(hosts[0].host.domains, vec!["example.com".to_string()]);
    assert_eq!(hosts[0].revision, created.revision);
    assert!(reopened.state_path().is_file());
}

#[test]
fn status_counts_are_current_store_reads() {
    let (_temp, data_dir) = temp_data_dir();
    let runtime = open(&data_dir);

    let status = runtime.status().expect("initial status");
    assert_eq!(status.host_count, 0);
    assert_eq!(status.policy_count, 0);
    assert!(!status.legacy_caddy_detected);
    assert!(status.warnings.is_empty());
    assert_eq!(status.data_dir, data_dir);
    assert_eq!(status.state_path, data_dir.join("pm/state.json"));

    runtime
        .policies()
        .create(auto_policy(1, &["example.com"]))
        .expect("create policy");
    let created = runtime
        .service()
        .create(auto_draft("example.com", 1))
        .expect("create auto host");

    let status = runtime.status().expect("status after create");
    assert_eq!(status.host_count, 1);
    assert_eq!(status.policy_count, 1);

    runtime
        .service()
        .delete(created.host.id, created.revision)
        .expect("delete host");

    let status = runtime.status().expect("status after delete");
    assert_eq!(status.host_count, 0);
    assert_eq!(status.policy_count, 1);
}

#[test]
fn rejects_file_as_data_dir() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let data_dir = temp.path().join("data");
    fs::write(&data_dir, b"not a directory").expect("write file");

    let error = open_error(&data_dir);
    let rendered = error.to_string();
    match &error {
        RuntimeError::NotADirectory { path } => assert_eq!(path, &data_dir),
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(rendered.contains(&data_dir.display().to_string()));
    assert_eq!(
        fs::read(&data_dir).expect("read file"),
        b"not a directory".to_vec()
    );
}

#[test]
fn rejects_empty_data_dir() {
    let error = match PmRuntime::open(RuntimeConfig::new(PathBuf::new())) {
        Ok(_) => panic!("open unexpectedly succeeded"),
        Err(error) => error,
    };
    match &error {
        RuntimeError::InvalidDataDir { path, reason } => {
            assert!(path.as_os_str().is_empty());
            assert!(reason.contains("empty"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(error.to_string().contains("invalid PM data directory"));
}

#[test]
fn write_probe_failure_names_the_pm_directory_and_never_opens_state() {
    let (_temp, data_dir) = temp_data_dir();
    let pm_dir = data_dir.join("pm");

    let error = match PmRuntime::open_inner(RuntimeConfig::new(data_dir.clone()), |path| {
        assert_eq!(path, pm_dir.as_path());
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "simulated EACCES",
        ))
    }) {
        Ok(_) => panic!("open unexpectedly succeeded"),
        Err(error) => error,
    };

    let rendered = error.to_string();
    match &error {
        RuntimeError::DataDirNotWritable { path, source } => {
            assert_eq!(path, &pm_dir);
            assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(rendered.contains(&pm_dir.display().to_string()));
    assert!(rendered.contains("ownership"));
    assert!(rendered.contains("permissions"));
    assert!(!pm_dir.join("state.json").exists());
}

#[test]
fn legacy_caddy_markers_warn_and_remain_untouched() {
    let (_temp, data_dir) = temp_data_dir();
    fs::create_dir_all(data_dir.join("certificates")).expect("certificates dir");
    fs::create_dir_all(data_dir.join("acme")).expect("acme dir");
    fs::create_dir_all(data_dir.join("pki")).expect("pki dir");
    fs::write(
        data_dir.join("certificates/leaf.pem"),
        b"legacy certificate",
    )
    .expect("certificate file");
    fs::write(data_dir.join("acme/account.json"), b"legacy account").expect("account file");
    fs::write(data_dir.join("pki/root.pem"), b"legacy root").expect("root file");
    fs::write(data_dir.join("instance.uuid"), b"legacy-instance-id").expect("instance file");
    fs::write(data_dir.join("caddy.db"), b"legacy database").expect("database file");
    fs::write(data_dir.join("caddy.db-wal"), b"legacy wal").expect("wal file");

    let runtime = open(&data_dir);
    let status = runtime.status().expect("status");

    assert!(status.legacy_caddy_detected);
    assert_eq!(
        runtime.legacy_markers(),
        [
            "acme/",
            "caddy.db",
            "caddy.db-wal",
            "certificates/",
            "instance.uuid",
            "pki/",
        ]
    );
    assert_eq!(status.warnings.len(), 1);
    let warning = &status.warnings[0];
    assert!(warning.contains("legacy Caddy data"));
    for marker in runtime.legacy_markers() {
        assert!(
            warning.contains(marker),
            "warning should name {marker}: {warning}"
        );
    }
    assert!(warning.contains("never reads, adopts, migrates or modifies"));

    // PM state is under pm/, never in the data directory root.
    assert!(data_dir.join("pm/state.json").is_file());
    assert!(!data_dir.join("state.json").exists());
    assert!(!data_dir.join("certificates/state.json").exists());

    // The legacy paths were not read into PM state, adopted or modified.
    assert_eq!(
        fs::read(data_dir.join("certificates/leaf.pem")).expect("read certificate"),
        b"legacy certificate".to_vec()
    );
    assert_eq!(
        fs::read(data_dir.join("acme/account.json")).expect("read account"),
        b"legacy account".to_vec()
    );
    assert_eq!(
        fs::read(data_dir.join("pki/root.pem")).expect("read root"),
        b"legacy root".to_vec()
    );
    assert_eq!(
        fs::read(data_dir.join("instance.uuid")).expect("read instance"),
        b"legacy-instance-id".to_vec()
    );
    assert_eq!(
        fs::read(data_dir.join("caddy.db")).expect("read database"),
        b"legacy database".to_vec()
    );
    assert_eq!(
        fs::read(data_dir.join("caddy.db-wal")).expect("read wal"),
        b"legacy wal".to_vec()
    );
    assert_eq!(file_names(&data_dir.join("certificates")).len(), 1);
    assert_eq!(file_names(&data_dir.join("acme")).len(), 1);
    assert_eq!(file_names(&data_dir.join("pki")).len(), 1);
}

#[test]
fn no_legacy_markers_means_no_warning() {
    let (_temp, data_dir) = temp_data_dir();
    let runtime = open(&data_dir);
    let status = runtime.status().expect("status");
    assert!(!status.legacy_caddy_detected);
    assert!(status.warnings.is_empty());
    assert!(runtime.legacy_markers().is_empty());
}

#[cfg(unix)]
#[test]
fn open_does_not_change_existing_ownership_or_permissions() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let (_temp, data_dir) = temp_data_dir();
    fs::create_dir_all(&data_dir).expect("data dir");
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o750)).expect("set mode");
    let before = fs::metadata(&data_dir).expect("metadata before");
    assert_eq!(before.permissions().mode() & 0o777, 0o750);

    let runtime = open(&data_dir);
    drop(runtime);

    let after = fs::metadata(&data_dir).expect("metadata after");
    assert_eq!(after.uid(), before.uid(), "open must not chown");
    assert_eq!(after.gid(), before.gid(), "open must not chgrp");
    assert_eq!(after.permissions().mode() & 0o777, 0o750);
    assert_eq!(mode(&data_dir.join("pm")), 0o700);
}

#[test]
fn state_open_error_carries_the_state_path() {
    let (_temp, data_dir) = temp_data_dir();
    fs::create_dir_all(data_dir.join("pm")).expect("pm dir");
    let state_path = data_dir.join("pm/state.json");
    fs::write(&state_path, b"").expect("empty state file");

    let error = open_error(&data_dir);
    let rendered = error.to_string();
    match &error {
        RuntimeError::State { path, source } => {
            assert_eq!(path, &state_path);
            assert!(matches!(source, StateError::Corrupt(_)));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(rendered.contains(&state_path.display().to_string()));
}

#[test]
fn compile_and_assemble_use_the_stored_hosts() {
    let (_temp, data_dir) = temp_data_dir();
    let runtime = open(&data_dir);
    runtime
        .policies()
        .create(auto_policy(1, &["example.com"]))
        .expect("create policy");
    runtime
        .service()
        .create(auto_draft("example.com", 1))
        .expect("create host");

    let compiled = runtime.compile().expect("compile stored hosts");
    assert_eq!(compiled.http.len(), 1);
    assert_eq!(compiled.https.len(), 1);

    let config = runtime
        .assemble(ConfigSettings::new(8080, 8443))
        .expect("assemble config");
    assert_eq!(config["apps"]["http"]["http_port"], json!(8080));
    assert_eq!(config["apps"]["http"]["https_port"], json!(8443));
    assert_eq!(
        config["apps"]["http"]["servers"]["pm_http"]["listen"],
        json!([":8080"])
    );
    assert_eq!(
        config["apps"]["http"]["servers"]["pm_https"]["listen"],
        json!([":8443"])
    );
    let https_routes = config["apps"]["http"]["servers"]["pm_https"]["routes"]
        .as_array()
        .expect("https routes");
    assert_eq!(https_routes.len(), 1);
    assert_eq!(https_routes[0]["match"][0]["host"][0], json!("example.com"));
    assert_eq!(
        config["apps"]["tls"]["certificates"]["automate"],
        json!(["example.com"])
    );
    assert_eq!(
        config["apps"]["tls"]["automation"]["policies"][0]["subjects"],
        json!(["example.com"])
    );
    assert_eq!(
        config["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["module"],
        json!("acme")
    );
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("create symlink");
}

#[cfg(unix)]
fn open_allowing_symlinks(data_dir: &Path) -> PmRuntime {
    PmRuntime::open(RuntimeConfig::new(data_dir).allow_symlink_data_dir(true))
        .expect("open runtime with symlink override")
}

#[cfg(unix)]
fn open_allowing_symlinks_error(data_dir: &Path) -> RuntimeError {
    match PmRuntime::open(RuntimeConfig::new(data_dir).allow_symlink_data_dir(true)) {
        Ok(_) => panic!("open unexpectedly succeeded for {}", data_dir.display()),
        Err(error) => error,
    }
}

#[cfg(unix)]
#[test]
fn dangling_symlink_as_data_dir_is_a_located_error() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let data_dir = temp.path().join("data");
    let target = temp.path().join("missing");
    symlink(&target, &data_dir);

    let error = open_error(&data_dir);
    match &error {
        RuntimeError::SymlinkNotAllowed {
            path,
            target: named,
        } => {
            assert_eq!(path, &data_dir);
            assert_eq!(named, &target);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    let rendered = error.to_string();
    assert!(rendered.contains(&data_dir.display().to_string()));
    assert!(rendered.contains(&target.display().to_string()));
    assert!(rendered.contains("allow_symlink_data_dir"));
    assert!(!target.exists());
}

#[cfg(unix)]
#[test]
fn dangling_symlink_as_pm_dir_is_a_located_error() {
    let (_temp, data_dir) = temp_data_dir();
    fs::create_dir_all(&data_dir).expect("data dir");
    let pm_dir = data_dir.join("pm");
    let target = data_dir.join("missing-pm");
    symlink(&target, &pm_dir);

    let error = open_error(&data_dir);
    match &error {
        RuntimeError::SymlinkNotAllowed {
            path,
            target: named,
        } => {
            assert_eq!(path, &pm_dir);
            assert_eq!(named, &target);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    let rendered = error.to_string();
    assert!(rendered.contains(&pm_dir.display().to_string()));
    assert!(rendered.contains(&target.display().to_string()));
    assert!(!target.exists());
}

#[cfg(unix)]
#[test]
fn symlinked_data_dir_is_refused_by_default() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let target = temp.path().join("real-data");
    fs::create_dir_all(&target).expect("target dir");
    let data_dir = temp.path().join("data");
    symlink(&target, &data_dir);

    let error = open_error(&data_dir);
    match &error {
        RuntimeError::SymlinkNotAllowed {
            path,
            target: named,
        } => {
            assert_eq!(path, &data_dir);
            assert_eq!(named, &target);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        fs::read_dir(&target).expect("read target").count(),
        0,
        "refusal must not write through the symlink"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_pm_dir_is_refused_by_default() {
    let (_temp, data_dir) = temp_data_dir();
    fs::create_dir_all(&data_dir).expect("data dir");
    let target = data_dir.join("real-pm");
    fs::create_dir_all(&target).expect("target dir");
    let pm_dir = data_dir.join("pm");
    symlink(&target, &pm_dir);

    let error = open_error(&data_dir);
    match &error {
        RuntimeError::SymlinkNotAllowed {
            path,
            target: named,
        } => {
            assert_eq!(path, &pm_dir);
            assert_eq!(named, &target);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        fs::read_dir(&target).expect("read target").count(),
        0,
        "refusal must not write through the symlink"
    );
}

#[cfg(unix)]
#[test]
fn symlink_override_resolves_a_symlinked_data_dir() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let target = temp.path().join("real-data");
    fs::create_dir_all(&target).expect("target dir");
    let data_dir = temp.path().join("data");
    symlink(&target, &data_dir);

    let runtime = open_allowing_symlinks(&data_dir);
    let canonical = fs::canonicalize(&target).expect("canonical target");
    assert_eq!(runtime.data_dir(), canonical.as_path());
    assert_eq!(
        runtime.state_path(),
        canonical.join("pm").join("state.json")
    );
    assert!(canonical.join("pm").join("state.json").is_file());
    assert_eq!(runtime.status().expect("status").data_dir, canonical);
}

#[cfg(unix)]
#[test]
fn symlink_override_resolves_a_symlinked_pm_dir() {
    let (_temp, data_dir) = temp_data_dir();
    fs::create_dir_all(&data_dir).expect("data dir");
    let target = data_dir.join("real-pm");
    fs::create_dir_all(&target).expect("target dir");
    let pm_dir = data_dir.join("pm");
    symlink(&target, &pm_dir);

    let runtime = open_allowing_symlinks(&data_dir);
    let canonical = fs::canonicalize(&target).expect("canonical target");
    assert_eq!(runtime.data_dir(), data_dir.as_path());
    assert_eq!(runtime.state_path(), canonical.join("state.json"));
    assert!(canonical.join("state.json").is_file());
}

#[cfg(unix)]
#[test]
fn dangling_symlink_is_located_even_with_the_override() {
    let temp = tempfile::tempdir().expect("create temp dir");

    let data_dir = temp.path().join("data");
    let data_target = temp.path().join("missing-data");
    symlink(&data_target, &data_dir);
    let error = open_allowing_symlinks_error(&data_dir);
    match &error {
        RuntimeError::SymlinkUnresolvable {
            path,
            target,
            source,
        } => {
            assert_eq!(path, &data_dir);
            assert_eq!(target, &data_target);
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    let rendered = error.to_string();
    assert!(rendered.contains(&data_dir.display().to_string()));
    assert!(rendered.contains(&data_target.display().to_string()));
    assert!(rendered.contains("cannot be resolved"));

    let pm_data = temp.path().join("pm-data");
    fs::create_dir_all(&pm_data).expect("pm data dir");
    let pm_dir = pm_data.join("pm");
    let pm_target = pm_data.join("missing-pm");
    symlink(&pm_target, &pm_dir);
    let error = open_allowing_symlinks_error(&pm_data);
    match &error {
        RuntimeError::SymlinkUnresolvable {
            path,
            target,
            source,
        } => {
            assert_eq!(path, &pm_dir);
            assert_eq!(target, &pm_target);
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn symlink_to_a_file_is_rejected_with_the_override() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let target = temp.path().join("not-a-dir");
    fs::write(&target, b"file").expect("write target");
    let data_dir = temp.path().join("data");
    symlink(&target, &data_dir);

    let error = open_allowing_symlinks_error(&data_dir);
    let canonical = fs::canonicalize(&target).expect("canonical target");
    match &error {
        RuntimeError::SymlinkTargetNotDirectory {
            path,
            target: named,
        } => {
            assert_eq!(path, &data_dir);
            assert_eq!(named, &canonical);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(error.to_string().contains("not a directory"));
}
