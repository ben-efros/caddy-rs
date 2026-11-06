//! CLI integration tests. These exercise the compiled binary, not the library API.

use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_caddy-rs")
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(binary())
        .args(args)
        .output()
        .expect("run caddy-rs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn version_reports_implementation_and_caddy_baseline() {
    let (code, stdout, _stderr) = run(&["version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("caddy-rs 0.1.0"), "{stdout}");
    assert!(stdout.contains("v2.11.7"), "{stdout}");

    let (code, stdout, _stderr) = run(&["version", "--json"]);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["caddy_compat_baseline"], "v2.11.7");
}

#[test]
fn list_modules_includes_implemented_handlers() {
    let (code, stdout, _stderr) = run(&["list-modules", "--json"]);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let modules = value["modules"].as_array().expect("modules array");
    let ids: Vec<&str> = modules
        .iter()
        .filter_map(|module| module["id"].as_str())
        .collect();
    assert!(ids.contains(&"http.handlers.reverse_proxy"), "{ids:?}");
    assert!(ids.contains(&"http.handlers.file_server"), "{ids:?}");
    assert!(ids.contains(&"http.matchers.host"), "{ids:?}");
}

#[test]
fn adapts_caddyfile_to_caddy_json() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("Caddyfile");
    std::fs::write(&config, "example.com {\n\trespond \"hello\"\n}\n").unwrap();
    let (code, stdout, stderr) = run(&["adapt", "--config", config.to_str().unwrap(), "--pretty"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("adapted JSON");
    assert_eq!(
        value["apps"]["http"]["servers"]["srv0"]["listen"][0],
        ":443"
    );
    assert_eq!(
        value["apps"]["http"]["servers"]["srv0"]["routes"][0]["match"][0]["host"][0],
        "example.com"
    );
}

#[test]
fn validate_accepts_and_rejects() {
    let directory = tempfile::tempdir().unwrap();
    let valid = directory.path().join("valid.json");
    std::fs::write(
        &valid,
        serde_json::to_string(&serde_json::json!({
            "admin": {"disabled": true},
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}}
        }))
        .unwrap(),
    )
    .unwrap();
    let (code, stdout, stderr) = run(&["validate", "--config", valid.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("Valid configuration"));

    let invalid = directory.path().join("invalid.json");
    std::fs::write(
        &invalid,
        serde_json::to_string(&serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [{"handle": [{"handler": "not_a_module"}]}]
            }}}}
        }))
        .unwrap(),
    )
    .unwrap();
    let (code, _stdout, stderr) = run(&["validate", "--config", invalid.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(stderr.contains("not_a_module"), "{stderr}");
}

#[test]
fn adapt_surfaces_unsupported_directive_as_error() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("Caddyfile");
    std::fs::write(&config, ":80 {\n\tsome_unknown_directive foo\n}\n").unwrap();
    let (code, _stdout, stderr) = run(&[
        "adapt",
        "--config",
        config.to_str().unwrap(),
        "--adapter",
        "caddyfile",
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("some_unknown_directive"), "{stderr}");
    assert!(stderr.contains("docs/compatibility"), "{stderr}");
}

#[test]
fn adapt_resolves_file_imports_relative_to_the_config_path() {
    let directory = tempfile::tempdir().unwrap();
    let snippets = directory.path().join("snippets");
    std::fs::create_dir_all(&snippets).unwrap();
    std::fs::write(snippets.join("respond.conf"), "respond \"imported\"\n").unwrap();
    let config = directory.path().join("Caddyfile");
    std::fs::write(&config, ":80 {\n\timport snippets/respond.conf\n}\n").unwrap();
    // Run from a different working directory to prove imports are relative to the config path.
    let output = Command::new(binary())
        .args(["adapt", "--config", config.to_str().unwrap()])
        .current_dir(std::env::temp_dir())
        .output()
        .expect("run caddy-rs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("adapted JSON");
    assert_eq!(
        value["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["body"],
        "imported"
    );
}

// ---- server runtime integration (real spawned `caddy-rs run` process) -------------------------
//
// These tests drive the compiled CLI as a child process: a Caddyfile-derived `:PORT` site (the
// wildcard-listener regression) and the admin `POST /stop` shutdown path for both the JSON and
// Caddyfile adapters (the real-Caddy-oracle `admin-stop#stop` finding).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Serialises tests that touch the default admin port (2019).
static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn ipv6_loopback_available() -> bool {
    TcpListener::bind("[::1]:0").is_ok()
}

fn spawn_run(
    config: &Path,
    adapter: &str,
    log_dir: &Path,
    name: &str,
) -> (Child, std::path::PathBuf) {
    let log = log_dir.join(format!("{name}.stderr"));
    let file = std::fs::File::create(&log).expect("create child log");
    let child = Command::new(binary())
        .args([
            "run",
            "--config",
            config.to_str().expect("utf-8 config path"),
            "--adapter",
            adapter,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .expect("spawn caddy-rs run");
    (child, log)
}

fn child_failure(child: &mut Child, log: &Path, detail: &str) -> ! {
    let _ = child.kill();
    let _ = child.wait();
    let contents = std::fs::read_to_string(log).unwrap_or_default();
    panic!("{detail}\nchild stderr:\n{contents}");
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn connect_admin(port: u16) -> Option<TcpStream> {
    for address in [
        SocketAddr::from(([127, 0, 0, 1], port)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
    ] {
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            return Some(stream);
        }
    }
    None
}

/// Send one HTTP/1.1 request to `address` and return (status, body).
fn http_request(address: SocketAddr, method: &str, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?
        + 4;
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())?;
    Some((
        status,
        String::from_utf8_lossy(&response[split..]).into_owned(),
    ))
}

fn admin_post_stop(port: u16) -> u16 {
    let stream = connect_admin(port).unwrap_or_else(|| panic!("admin API not listening on {port}"));
    drop(stream);
    let address = if TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(100),
    )
    .is_ok()
    {
        SocketAddr::from(([127, 0, 0, 1], port))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port))
    };
    http_request(address, "POST", "/stop")
        .unwrap_or_else(|| panic!("POST /stop failed on admin {port}"))
        .0
}

#[test]
fn run_serves_hostless_caddyfile_site_and_admin_stop_exits() {
    let _guard = SERVER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let directory = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let config = directory.path().join("Caddyfile");
    std::fs::write(
        &config,
        format!("{{\n\tauto_https off\n}}\n:{port} {{\n\trespond \"cli-wildcard\"\n}}\n"),
    )
    .expect("write Caddyfile");

    let (mut child, log) = spawn_run(&config, "caddyfile", directory.path(), "caddyfile");
    // A Caddyfile-derived `:PORT` must bind the wildcard and serve IPv4 immediately...
    let served = wait_until(Duration::from_secs(15), || {
        http_request(SocketAddr::from(([127, 0, 0, 1], port)), "GET", "/")
            .is_some_and(|(status, body)| status == 200 && body == "cli-wildcard")
    });
    if !served {
        child_failure(
            &mut child,
            &log,
            "hostless Caddyfile site did not serve IPv4",
        );
    }
    // ...and IPv6 too, matching Caddy's dual-stack `:port` semantics (when the host has IPv6).
    if ipv6_loopback_available() {
        let served_v6 = wait_until(Duration::from_secs(5), || {
            http_request(
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
                "GET",
                "/",
            )
            .is_some_and(|(status, body)| status == 200 && body == "cli-wildcard")
        });
        if !served_v6 {
            child_failure(
                &mut child,
                &log,
                "hostless Caddyfile site did not serve IPv6 (Caddy binds dual-stack)",
            );
        }
    }

    // The Caddyfile run uses the default admin port 2019; `POST /stop` must exit the process.
    let exit = if wait_until(Duration::from_secs(10), || connect_admin(2019).is_some()) {
        assert_eq!(admin_post_stop(2019), 200, "POST /stop returns 200");
        wait_for_child_exit(&mut child, Duration::from_secs(10))
    } else {
        None
    };
    let Some(status) = exit else {
        child_failure(
            &mut child,
            &log,
            "caddy-rs run (Caddyfile) did not exit after POST /stop",
        );
    };
    assert!(
        status.success(),
        "run should exit successfully after /stop, got {status:?}"
    );
}

#[test]
fn run_json_adapter_admin_stop_exits_process() {
    let _guard = SERVER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let directory = tempfile::tempdir().expect("tempdir");
    let admin_port = free_port();
    let config = directory.path().join("config.json");
    std::fs::write(
        &config,
        serde_json::to_string(&serde_json::json!({
            "admin": {"listen": format!("127.0.0.1:{admin_port}")},
            "apps": {"http": {"servers": {"srv0": {
                "listen": ["127.0.0.1:0"],
                "routes": [{"handle": [{"handler": "static_response", "body": "json-ok"}]}]
            }}}}
        }))
        .expect("serialize config"),
    )
    .expect("write config");

    let (mut child, log) = spawn_run(&config, "json", directory.path(), "json");
    if !wait_until(Duration::from_secs(15), || {
        connect_admin(admin_port).is_some()
    }) {
        child_failure(&mut child, &log, "JSON-adapter admin API did not start");
    }
    assert_eq!(admin_post_stop(admin_port), 200, "POST /stop returns 200");

    let Some(status) = wait_for_child_exit(&mut child, Duration::from_secs(10)) else {
        child_failure(
            &mut child,
            &log,
            "caddy-rs run (JSON adapter) did not exit after POST /stop",
        );
    };
    assert!(
        status.success(),
        "JSON-adapter run should exit successfully after /stop, got {status:?}"
    );
}

#[test]
fn run_resume_loads_the_last_autosave_and_prefers_it_over_config() {
    let _guard = SERVER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let directory = tempfile::tempdir().expect("tempdir");
    let site_port = free_port();
    let admin_port = free_port();
    let other_port = free_port();
    let autosave = directory.path().join("custom-autosave.json");
    std::fs::write(
        &autosave,
        serde_json::to_string(&serde_json::json!({
            "admin": {"listen": format!("127.0.0.1:{admin_port}")},
            "apps": {"http": {"servers": {"srv0": {
                "listen": [format!("127.0.0.1:{site_port}")],
                "routes": [{"handle": [{"handler": "static_response", "body": "resumed"}]}]
            }}}}
        }))
        .expect("serialize autosave"),
    )
    .expect("write autosave");
    // A --config passed alongside --resume must be ignored (Caddy's precedence) and warned about.
    let ignored_config = directory.path().join("ignored.json");
    std::fs::write(
        &ignored_config,
        serde_json::to_string(&serde_json::json!({
            "admin": {"disabled": true},
            "apps": {"http": {"servers": {"srv0": {
                "listen": [format!("127.0.0.1:{other_port}")],
                "routes": [{"handle": [{"handler": "static_response", "body": "config-file"}]}]
            }}}}
        }))
        .expect("serialize ignored config"),
    )
    .expect("write ignored config");

    let log = directory.path().join("resume.stderr");
    let file = std::fs::File::create(&log).expect("create child log");
    let mut child = Command::new(binary())
        .args([
            "run",
            "--resume",
            "--autosave-path",
            autosave.to_str().expect("utf-8 autosave path"),
            "--config",
            ignored_config.to_str().expect("utf-8 config path"),
            "--adapter",
            "json",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .expect("spawn caddy-rs run --resume");

    if !wait_until(Duration::from_secs(15), || {
        connect_admin(admin_port).is_some()
    }) {
        child_failure(&mut child, &log, "resumed admin API did not start");
    }

    // The autosave configuration is served ...
    let served = wait_until(Duration::from_secs(10), || {
        http_request(SocketAddr::from(([127, 0, 0, 1], site_port)), "GET", "/")
            .is_some_and(|(status, body)| status == 200 && body == "resumed")
    });
    if !served {
        child_failure(
            &mut child,
            &log,
            "resumed autosave configuration was not served",
        );
    }
    // ... the --config file was ignored (its listener never opens) ...
    assert!(
        http_request(SocketAddr::from(([127, 0, 0, 1], other_port)), "GET", "/").is_none(),
        "--config must be ignored when --resume loads an autosave"
    );
    // ... and the precedence is announced on stderr.
    let stderr = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        stderr.contains("resuming from last configuration"),
        "resume must be announced, stderr:\n{stderr}"
    );

    assert_eq!(admin_post_stop(admin_port), 200, "POST /stop returns 200");
    let Some(status) = wait_for_child_exit(&mut child, Duration::from_secs(10)) else {
        child_failure(
            &mut child,
            &log,
            "resumed caddy-rs run did not exit after POST /stop",
        );
    };
    assert!(
        status.success(),
        "resumed run should exit successfully after /stop, got {status:?}"
    );
}

// ---- PKI / trust commands (read-only local CA material) --------------------------------------
//
// The fixtures live in the admin crate (`crates/admin/tests/fixtures/pki/authorities/...`); they
// are read-only test data generated for this task (root + intermediate certificates for `local`
// and `staging` CAs in Caddy's data-directory layout).

use std::path::PathBuf;

fn pki_fixture_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../admin/tests/fixtures")
}

fn run_pki(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(binary())
        .args(args)
        .output()
        .expect("run caddy-rs pki");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn assert_pem_count(pem: &str, count: usize) {
    assert_eq!(
        pem.matches("-----BEGIN CERTIFICATE-----").count(),
        count,
        "PEM block count in:\n{pem}"
    );
    assert_eq!(
        pem.matches("-----END CERTIFICATE-----").count(),
        count,
        "PEM end-block count in:\n{pem}"
    );
}

#[test]
fn pki_list_reports_provisioned_cas_and_json_shape() {
    let data_dir = pki_fixture_data_dir();
    let (code, stdout, stderr) =
        run_pki(&["pki", "list", "--data-dir", data_dir.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("ID"), "{stdout}");
    assert!(stdout.contains("local"), "{stdout}");
    assert!(stdout.contains("staging"), "{stdout}");
    assert!(stdout.contains("caddy-rs test root"), "{stdout}");
    assert!(stdout.contains("caddy-rs test intermediate"), "{stdout}");

    let (code, stdout, stderr) = run_pki(&[
        "pki",
        "list",
        "--json",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("list JSON");
    let authorities = value["authorities"].as_array().expect("authorities array");
    assert_eq!(authorities.len(), 2);
    assert_eq!(authorities[0]["id"], "local");
    assert_eq!(authorities[0]["root_common_name"], "caddy-rs test root");
    assert_eq!(
        authorities[0]["intermediate_common_name"],
        "caddy-rs test intermediate"
    );
    assert!(authorities[0]["directory"]
        .as_str()
        .unwrap()
        .ends_with("authorities/local"));
    assert!(authorities[0]["root_not_after"].is_string());
    assert!(authorities[0]["has_intermediate"].as_bool().unwrap());

    // `$CADDY_RS_DATA_DIR` is respected when --data-dir is absent.
    let output = Command::new(binary())
        .args(["pki", "list"])
        .env("CADDY_RS_DATA_DIR", &data_dir)
        .output()
        .expect("run with env data dir");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("local"), "{stdout}");
    assert!(stdout.contains("staging"), "{stdout}");

    // An empty/missing data dir lists nothing but is not an error.
    let empty = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) =
        run_pki(&["pki", "list", "--data-dir", empty.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("no local certificate authorities"),
        "{stdout}"
    );
}

#[test]
fn pki_export_writes_root_intermediate_and_chain_pem() {
    let data_dir = pki_fixture_data_dir();
    let data_dir = data_dir.to_str().unwrap();
    let root_expected =
        std::fs::read_to_string(pki_fixture_data_dir().join("pki/authorities/local/root.crt"))
            .expect("root fixture");
    let intermediate_expected = std::fs::read_to_string(
        pki_fixture_data_dir().join("pki/authorities/local/intermediate.crt"),
    )
    .expect("intermediate fixture");

    let (code, stdout, stderr) = run_pki(&["pki", "export", "local", "--data-dir", data_dir]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_pem_count(&stdout, 1);
    assert_eq!(
        stdout.trim(),
        root_expected.trim(),
        "default export is the root"
    );

    let (code, stdout, _) = run_pki(&["pki", "export", "local", "--root", "--data-dir", data_dir]);
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), root_expected.trim());

    let (code, stdout, _) = run_pki(&[
        "pki",
        "export",
        "local",
        "--intermediate",
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, 0);
    assert_pem_count(&stdout, 1);
    assert_eq!(stdout.trim(), intermediate_expected.trim());

    // Caddy chain order: intermediate(s) first, root last.
    let (code, stdout, _) = run_pki(&["pki", "export", "local", "--chain", "--data-dir", data_dir]);
    assert_eq!(code, 0);
    assert_pem_count(&stdout, 2);
    assert!(
        stdout.trim().starts_with(intermediate_expected.trim()),
        "{stdout}"
    );
    assert!(stdout.trim().ends_with(root_expected.trim()), "{stdout}");

    // Unknown CA is a loud, located error with nothing on stdout.
    let (code, stdout, stderr) =
        run_pki(&["pki", "export", "does-not-exist", "--data-dir", data_dir]);
    assert_ne!(code, 0);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("no certificate authority configured with id `does-not-exist`"),
        "{stderr}"
    );
    assert!(stderr.contains("must be provisioned"), "{stderr}");

    // `--root` and `--chain` conflict at the argument-parsing level.
    let (code, _stdout, stderr) = run_pki(&[
        "pki",
        "export",
        "local",
        "--root",
        "--chain",
        "--data-dir",
        data_dir,
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
}

#[test]
fn trust_dry_run_prints_instructions_and_changes_nothing() {
    let data_dir = pki_fixture_data_dir();
    let (code, stdout, stderr) = run_pki(&[
        "trust",
        "--dry-run",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("CA id: local"), "{stdout}");
    assert!(stdout.contains("root certificate:"), "{stdout}");
    assert!(
        stdout.contains("pki/authorities/local/root.crt"),
        "{stdout}"
    );
    assert!(stdout.contains("caddy-rs test root"), "{stdout}");
    assert!(stdout.contains("no changes made (--dry-run)"), "{stdout}");
    assert!(stdout.contains("to install manually, run:"), "{stdout}");
    if cfg!(target_os = "linux") {
        assert!(
            stdout.contains("update-ca-certificates"),
            "Linux instructions must name update-ca-certificates:\n{stdout}"
        );
    }

    // A non-default CA can be inspected too.
    let (code, stdout, _) = run_pki(&[
        "trust",
        "--dry-run",
        "--ca",
        "staging",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("CA id: staging"), "{stdout}");
    assert!(stdout.contains("caddy-rs staging root"), "{stdout}");
}

#[test]
fn trust_fails_loudly_before_touching_the_os_when_the_ca_is_missing() {
    let data_dir = pki_fixture_data_dir();
    let (code, stdout, stderr) = run_pki(&[
        "trust",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--ca",
        "does-not-exist",
    ]);
    assert_ne!(code, 0, "trust must fail for an unknown CA");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("no certificate authority configured with id `does-not-exist`"),
        "{stderr}"
    );
    assert!(stderr.contains("must be provisioned"), "{stderr}");

    // A missing data directory fails at CA lookup, before any installation step could run.
    let empty = tempfile::tempdir().unwrap();
    let (code, _stdout, stderr) = run_pki(&["trust", "--data-dir", empty.path().to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("no certificate authority configured with id `local`"),
        "{stderr}"
    );
}

#[test]
fn validate_reports_a_stable_error_code_and_a_did_you_mean_hint() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.json");
    std::fs::write(
        &config,
        r#"{"admin":{"disabled":true},"apps":{"http":{"servers":{"srv0":{"listen":["127.0.0.1:0"],"routes":[{"handle":[{"handler":"revers_proxy"}]}]}}}}}"#,
    )
    .unwrap();
    let (code, stdout, stderr) = run(&["validate", "--config", config.to_str().unwrap()]);
    assert_ne!(code, 0, "an unknown handler must fail validation");
    assert!(stdout.is_empty(), "{stdout}");
    // Machine-readable code for tooling, then the located message including the suggestion.
    assert!(
        stderr.contains("error[module.unknown]:"),
        "the error must carry its stable code: {stderr}"
    );
    assert!(
        stderr.contains("unknown HTTP handler module `revers_proxy`"),
        "{stderr}"
    );
    assert!(
        stderr.contains("(did you mean `reverse_proxy`?)"),
        "{stderr}"
    );
}

#[test]
fn validate_keeps_the_plain_error_form_for_non_configuration_failures() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("does-not-exist.json");
    let (code, _stdout, stderr) = run(&["validate", "--config", missing.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("caddy-rs: error: ") && !stderr.contains("error["),
        "a missing file is not a configuration error code: {stderr}"
    );
}

// ---- Trust-store installation against stub tools -------------------------------------------
//
// These run the real `trust` verb with an injected PATH/HOME/JAVA_HOME and a throwaway
// CADDY_RS_TRUST_PREFIX, so the platform, NSS/Firefox and Java targets are exercised without
// touching the host's trust stores. The stub tools emulate `certutil`/`keytool` idempotency with
// marker files and log their invocations.

#[cfg(unix)]
fn write_stub(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
struct TrustFixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    java_home: PathBuf,
    platform_prefix: PathBuf,
    calls: PathBuf,
    nss_marker: PathBuf,
    java_marker: PathBuf,
}

#[cfg(unix)]
fn trust_fixture(stub_tools: bool) -> TrustFixture {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().to_path_buf();
    let root = base.join("rootfs");
    let home = base.join("home");
    let nss = home.join(".pki/nssdb");
    std::fs::create_dir_all(&nss).unwrap();
    std::fs::write(nss.join("cert9.db"), b"").unwrap();
    let java_home = base.join("jdk");
    std::fs::create_dir_all(java_home.join("lib/security")).unwrap();
    std::fs::write(java_home.join("lib/security/cacerts"), b"stub-keystore").unwrap();
    let bin = base.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let calls = base.join("calls.log");
    let nss_marker = base.join("nss-installed");
    let java_marker = base.join("java-installed");
    if stub_tools {
        write_stub(
            &bin.join("update-ca-certificates"),
            &format!(
                "#!/bin/sh\necho update-ca-certificates >> '{}'\nexit 0\n",
                calls.display()
            ),
        );
        write_stub(
            &bin.join("certutil"),
            &format!(
                "#!/bin/sh\necho \"certutil $*\" >> '{}'\ncase \" $* \" in\n  *\" -L \"*) test -f '{}' && exit 0 || exit 1 ;;\n  *\" -A \"*) : > '{}'; exit 0 ;;\nesac\nexit 0\n",
                calls.display(), nss_marker.display(), nss_marker.display()
            ),
        );
        write_stub(
            &bin.join("keytool"),
            &format!(
                "#!/bin/sh\necho \"keytool $*\" >> '{}'\ncase \" $* \" in\n  *\" -list \"*) test -f '{}' && exit 0 || exit 1 ;;\n  *\" -importcert \"*) : > '{}'; exit 0 ;;\nesac\nexit 0\n",
                calls.display(), java_marker.display(), java_marker.display()
            ),
        );
    }
    TrustFixture {
        _directory: directory,
        root,
        home,
        bin,
        java_home,
        platform_prefix: base.join("prefix"),
        calls,
        nss_marker,
        java_marker,
    }
}

#[cfg(unix)]
fn run_trust_with_fixture(
    fixture: &TrustFixture,
    extra: &[&str],
    path_override: Option<&str>,
) -> (i32, String, String) {
    let mut command = Command::new(binary());
    command
        .args(["trust", "--data-dir"])
        .arg(pki_fixture_data_dir())
        .args(extra)
        .env("HOME", &fixture.home)
        .env("JAVA_HOME", &fixture.java_home)
        .env("CADDY_RS_TRUST_PREFIX", &fixture.platform_prefix)
        .env(
            "PATH",
            path_override.map_or_else(|| fixture.bin.display().to_string(), str::to_string),
        );
    let output = command.output().expect("run caddy-rs trust");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[cfg(unix)]
#[test]
fn trust_dry_run_lists_platform_nss_and_java_targets() {
    let fixture = trust_fixture(true);
    let (code, stdout, stderr) = run_trust_with_fixture(&fixture, &["--dry-run"], None);
    assert_eq!(code, 0, "stderr: {stderr}\nstdout: {stdout}");
    assert!(stdout.contains("trust stores:"), "{stdout}");
    assert!(stdout.contains("platform trust store: ready"), "{stdout}");
    assert!(stdout.contains("NSS/Firefox database"), "{stdout}");
    assert!(stdout.contains("Java keystore"), "{stdout}");
    assert!(stdout.contains("update-ca-certificates"), "{stdout}");
    assert!(stdout.contains("certutil -d sql:"), "{stdout}");
    assert!(stdout.contains("keytool -importcert"), "{stdout}");
    assert!(stdout.contains("no changes made (--dry-run)"), "{stdout}");
    // Dry-run must not touch the stubs or the prefix.
    assert!(!fixture.calls.exists(), "dry-run executed a stub");
    assert!(
        !fixture.platform_prefix.exists(),
        "dry-run created the prefix"
    );
}

#[cfg(unix)]
#[test]
fn trust_installs_with_stub_tools_and_is_idempotent() {
    let fixture = trust_fixture(true);
    let (code, stdout, stderr) = run_trust_with_fixture(&fixture, &[], None);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    let installed_certificate = fixture
        .platform_prefix
        .join("usr/local/share/ca-certificates/caddy-rs-local.crt");
    assert!(
        installed_certificate.is_file(),
        "{}",
        installed_certificate.display()
    );
    assert!(
        fixture.nss_marker.is_file(),
        "NSS import stub was not called; stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        fixture.java_marker.is_file(),
        "Java import stub was not called; stdout: {stdout}\nstderr: {stderr}"
    );
    let first_log = std::fs::read_to_string(&fixture.calls).unwrap();
    assert_eq!(first_log.matches(" -A ").count(), 1, "{first_log}");
    assert_eq!(first_log.matches(" -importcert ").count(), 1, "{first_log}");

    let (code, stdout, stderr) = run_trust_with_fixture(&fixture, &[], None);
    assert_eq!(code, 0, "second run stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("already trusted"), "{stderr}");
    let second_log = std::fs::read_to_string(&fixture.calls).unwrap();
    assert_eq!(
        second_log.matches(" -A ").count(),
        1,
        "idempotent re-run must not re-import into NSS: {second_log}"
    );
    assert_eq!(
        second_log.matches(" -importcert ").count(),
        1,
        "idempotent re-run must not re-import into Java: {second_log}"
    );
}

#[cfg(unix)]
#[test]
fn trust_reports_missing_nss_and_java_tools_loudly_but_installs_platform_store() {
    let fixture = trust_fixture(true);
    // Only update-ca-certificates is available: NSS/Java tools are missing.
    let only_platform_bin = fixture._directory.path().join("platform-only-bin");
    std::fs::create_dir_all(&only_platform_bin).unwrap();
    write_stub(
        &only_platform_bin.join("update-ca-certificates"),
        "#!/bin/sh\nexit 0\n",
    );
    let (code, stdout, stderr) =
        run_trust_with_fixture(&fixture, &[], Some(only_platform_bin.to_str().unwrap()));
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("warning"), "{stderr}");
    assert!(stderr.contains("certutil"), "{stderr}");
    assert!(stderr.contains("keytool"), "{stderr}");
    assert!(
        stderr.contains("nss-tools") || stderr.contains("certutil"),
        "{stderr}"
    );
    assert!(fixture
        .platform_prefix
        .join("usr/local/share/ca-certificates/caddy-rs-local.crt")
        .is_file());
}

#[cfg(unix)]
#[test]
fn trust_fails_loudly_when_no_trust_store_can_be_updated() {
    let fixture = trust_fixture(false);
    let (code, stdout, stderr) = run_trust_with_fixture(&fixture, &[], Some(""));
    assert_ne!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("no trust store could be updated"),
        "{stderr}"
    );
    assert!(stderr.contains("update-ca-certificates"), "{stderr}");
    assert!(stderr.contains("certutil"), "{stderr}");
    assert!(stderr.contains("keytool"), "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
}

#[cfg(unix)]
#[test]
fn trust_honours_install_trust_false_from_config_as_a_clear_no_op() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.json");
    std::fs::write(
        &config,
        r#"{"apps":{"pki":{"certificate_authorities":{"local":{"name":"Test Local CA","install_trust":false}}}}}"#,
    )
    .unwrap();
    let (code, stdout, stderr) = run_pki(&[
        "trust",
        "--config",
        config.to_str().unwrap(),
        "--data-dir",
        pki_fixture_data_dir().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("install_trust: false"),
        "the disabled setting must be named: {stderr}"
    );
    assert!(stderr.contains("no changes made"), "{stderr}");
    assert!(
        stderr.contains("unconfigured clients may show warnings"),
        "{stderr}"
    );
}
