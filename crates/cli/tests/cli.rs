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
