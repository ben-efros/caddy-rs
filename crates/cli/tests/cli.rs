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

/// Run the binary with a bounded wait.
///
/// A regression that makes the server start (for example the `--adapt-mode` flag being ignored)
/// must fail this test instead of hanging the whole suite on a foreground `run` process.
fn run_within(args: &[&str], timeout: Duration) -> (i32, String, String) {
    let mut child = Command::new(binary())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn caddy-rs");
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("poll caddy-rs").is_some() {
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stdout.take() {
                let _ = pipe.read_to_string(&mut stdout);
            }
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            let status = child.wait().expect("reap caddy-rs");
            return (status.code().unwrap_or(-1), stdout, stderr);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("caddy-rs did not exit within {timeout:?}: {args:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn version_reports_implementation_and_caddy_baseline() {
    let (code, stdout, _stderr) = run(&["version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("caddy-rs 0.1.0"), "{stdout}");
    assert!(stdout.contains("v2.11.9"), "{stdout}");

    let (code, stdout, _stderr) = run(&["version", "--json"]);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["caddy_compat_baseline"], "v2.11.9");
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

#[test]
fn run_honours_admin_config_persist_false_and_does_not_autosave() {
    let _guard = SERVER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let directory = tempfile::tempdir().expect("tempdir");
    let site_port = free_port();
    let admin_port = free_port();
    let autosave = directory.path().join("autosave.json");
    let config = directory.path().join("config.json");
    std::fs::write(
        &config,
        serde_json::to_string(&serde_json::json!({
            "admin": {
                "listen": format!("127.0.0.1:{admin_port}"),
                "config": {"persist": false}
            },
            "apps": {"http": {"servers": {"srv0": {
                "listen": [format!("127.0.0.1:{site_port}")],
                "routes": [{"handle": [{"handler": "static_response", "body": "ok"}]}]
            }}}}
        }))
        .expect("serialize config"),
    )
    .expect("write config");

    let log = directory.path().join("persist.stderr");
    let file = std::fs::File::create(&log).expect("create child log");
    let mut child = Command::new(binary())
        .args([
            "run",
            "--config",
            config.to_str().expect("utf-8 config path"),
            "--adapter",
            "json",
            "--autosave-path",
            autosave.to_str().expect("utf-8 autosave path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .expect("spawn caddy-rs run");

    if !wait_until(Duration::from_secs(15), || {
        connect_admin(admin_port).is_some()
    }) {
        child_failure(&mut child, &log, "admin API did not start");
    }

    assert!(
        !autosave.exists(),
        "admin.config.persist=false must suppress autosave"
    );
    // The message is written by the run loop after the admin listener is up, so asserting on a
    // single read races it (CI failed here while the same test passed locally). Wait for it, then
    // report the whole log on timeout.
    let announced = wait_until(Duration::from_secs(5), || {
        std::fs::read_to_string(&log)
            .map(|stderr| stderr.contains("config persistence disabled"))
            .unwrap_or(false)
    });
    assert!(
        announced,
        "stderr must announce the persistence opt-out:\n{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );

    assert_eq!(admin_post_stop(admin_port), 200, "POST /stop returns 200");
    let Some(status) = wait_for_child_exit(&mut child, Duration::from_secs(10)) else {
        child_failure(
            &mut child,
            &log,
            "caddy-rs run with persist=false did not exit after POST /stop",
        );
    };
    assert!(
        status.success(),
        "run should exit successfully after /stop, got {status:?}"
    );
}

#[test]
fn environ_prints_the_process_environment() {
    let (code, stdout, stderr) = run(&["environ"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.lines().any(|line| line.starts_with("PATH=")),
        "{stdout}"
    );
}

#[test]
fn adapt_loads_an_envfile_before_adaptation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("Caddyfile");
    std::fs::write(
        &config,
        ":8080 {\n\trespond \"{$CADDY_TEST_GREETING}\"\n}\n",
    )
    .expect("write Caddyfile");
    let envfile = directory.path().join("test.env");
    std::fs::write(&envfile, "CADDY_TEST_GREETING=hellofromenv\n").expect("write envfile");
    let (code, stdout, stderr) = run(&[
        "adapt",
        "--config",
        config.to_str().expect("utf-8 config"),
        "--envfile",
        envfile.to_str().expect("utf-8 envfile"),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("adapted JSON");
    assert_eq!(
        value["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["body"],
        "hellofromenv"
    );
}

#[test]
fn run_discovers_caddyfile_in_the_working_directory() {
    let _guard = SERVER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let directory = tempfile::tempdir().expect("tempdir");
    let site_port = free_port();
    let admin_port = free_port();
    std::fs::write(
        directory.path().join("Caddyfile"),
        format!(
            "{{\n\tauto_https off\n\tadmin 127.0.0.1:{admin_port}\n}}\n:{site_port} {{\n\trespond \"discovered\"\n}}\n"
        ),
    )
    .expect("write Caddyfile");
    let log = directory.path().join("discovery.stderr");
    let file = std::fs::File::create(&log).expect("create child log");
    let mut child = Command::new(binary())
        .arg("run")
        .arg("--autosave-path")
        .arg(directory.path().join("autosave.json"))
        .env("XDG_CONFIG_HOME", directory.path().join("config"))
        .env("XDG_DATA_HOME", directory.path().join("data"))
        .current_dir(directory.path())
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .expect("spawn caddy-rs run");
    let served = wait_until(Duration::from_secs(15), || {
        http_request(SocketAddr::from(([127, 0, 0, 1], site_port)), "GET", "/")
            .is_some_and(|(status, body)| status == 200 && body == "discovered")
    });
    if !served {
        child_failure(
            &mut child,
            &log,
            "Caddyfile was not discovered in the working directory",
        );
    }
    assert_eq!(admin_post_stop(admin_port), 200);
    let Some(status) = wait_for_child_exit(&mut child, Duration::from_secs(10)) else {
        child_failure(&mut child, &log, "run did not exit after /stop");
    };
    assert!(status.success());
}

#[cfg(unix)]
#[test]
fn run_sends_systemd_notifications() {
    let _guard = SERVER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use std::os::unix::net::UnixDatagram;

    let directory = tempfile::tempdir().expect("tempdir");
    let site_port = free_port();
    let admin_port = free_port();
    let notify_path = directory.path().join("notify.sock");
    let receiver = UnixDatagram::bind(&notify_path).expect("bind notify socket");
    receiver
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("read timeout");

    let config = directory.path().join("config.json");
    std::fs::write(
        &config,
        serde_json::to_string(&serde_json::json!({
            "admin": {"listen": format!("127.0.0.1:{admin_port}")},
            "apps": {"http": {"servers": {"srv0": {
                "listen": [format!("127.0.0.1:{site_port}")],
                "routes": [{"handle": [{"handler": "static_response", "body": "notify"}]}]
            }}}}
        }))
        .expect("serialize config"),
    )
    .expect("write config");
    let log = directory.path().join("notify.stderr");
    let file = std::fs::File::create(&log).expect("create child log");
    let mut child = Command::new(binary())
        .args([
            "run",
            "--config",
            config.to_str().expect("utf-8 config"),
            "--adapter",
            "json",
            "--data-dir",
            directory
                .path()
                .join("data")
                .to_str()
                .expect("utf-8 data dir"),
            "--autosave-path",
            directory
                .path()
                .join("autosave.json")
                .to_str()
                .expect("utf-8 autosave"),
        ])
        .env("NOTIFY_SOCKET", &notify_path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .expect("spawn caddy-rs run");

    let mut messages = Vec::new();
    let mut buffer = [0_u8; 256];
    let mut saw_ready = false;
    while !saw_ready {
        let size = receiver.recv(&mut buffer).expect("receive notify message");
        let message = String::from_utf8_lossy(&buffer[..size]).to_string();
        saw_ready = message == "READY=1";
        messages.push(message);
    }
    assert!(
        messages.iter().any(|message| message == "RELOADING=1"),
        "expected RELOADING before READY, got {messages:?}"
    );

    assert!(
        wait_until(Duration::from_secs(10), || connect_admin(admin_port)
            .is_some()),
        "admin API did not become reachable"
    );
    assert_eq!(admin_post_stop(admin_port), 200);
    let mut saw_stopping = false;
    while !saw_stopping {
        let size = receiver
            .recv(&mut buffer)
            .expect("receive stopping message");
        let message = String::from_utf8_lossy(&buffer[..size]).to_string();
        saw_stopping = message == "STOPPING=1";
    }
    let Some(status) = wait_for_child_exit(&mut child, Duration::from_secs(10)) else {
        child_failure(&mut child, &log, "run did not exit after /stop");
    };
    assert!(status.success());
}

// ---- PKI / trust commands (read-only local CA material) --------------------------------------
//
// The certificate fixtures live in the admin crate (`crates/admin/tests/fixtures/pki/...`) in
// Caddy's data-directory layout. The key file is borrowed from the TLS test corpus: `pki show` only
// reports whether `<ca>/root.key` and `<ca>/intermediate.key` exist (it never parses keys).

use std::path::PathBuf;

fn pki_fixture_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../admin/tests/fixtures")
}

fn pki_key_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tls/testdata/https/example.com.key")
}

/// Copy the fixture CAs (certificates only) into a fresh Caddy-style data directory.
fn copy_fixture_cas(data_dir: &Path) {
    let source = pki_fixture_data_dir();
    for id in ["local", "staging"] {
        let target = data_dir.join("pki/authorities").join(id);
        std::fs::create_dir_all(&target).expect("create CA fixture directory");
        for file in ["root.crt", "intermediate.crt"] {
            std::fs::copy(
                source.join("pki/authorities").join(id).join(file),
                target.join(file),
            )
            .expect("copy certificate fixture");
        }
    }
}

/// A temporary data directory with root/intermediate certificates and key files for `local` and
/// `staging`, matching the layout Caddy's `caddypki` writes.
fn pki_data_dir_with_keys() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temp data dir");
    copy_fixture_cas(directory.path());
    for id in ["local", "staging"] {
        let ca = directory.path().join("pki/authorities").join(id);
        for file in ["root.key", "intermediate.key"] {
            std::fs::copy(pki_key_fixture(), ca.join(file)).expect("copy key fixture");
        }
    }
    directory
}

fn run_pki(args: &[&str]) -> (i32, String, String) {
    run_pki_with(args, |_command| {})
}

fn run_pki_with(args: &[&str], configure: impl FnOnce(&mut Command)) -> (i32, String, String) {
    let mut command = Command::new(binary());
    command.args(args);
    configure(&mut command);
    let output = command.output().expect("run caddy-rs pki");
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

fn row_for<'a>(stdout: &'a str, id: &str) -> &'a str {
    stdout
        .lines()
        .find(|line| line.starts_with(&format!("{id} ")))
        .unwrap_or_else(|| panic!("no `{id}` row in:\n{stdout}"))
}

#[test]
fn pki_list_reports_provisioned_cas_and_json_shape() {
    let data = pki_data_dir_with_keys();
    let data_dir = data.path().to_str().unwrap();
    let trust_prefix = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) =
        run_pki_with(&["pki", "list", "--data-dir", data_dir], |command| {
            command.env("CADDY_RS_TRUST_PREFIX", trust_prefix.path());
        });
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("ID"), "{stdout}");
    assert!(stdout.contains("ROOT_CN"), "{stdout}");
    assert!(stdout.contains("ROOT_EXPIRES"), "{stdout}");
    assert!(stdout.contains("INTERMEDIATE_EXPIRES"), "{stdout}");
    assert!(stdout.contains("TRUST"), "{stdout}");
    assert!(stdout.contains("local"), "{stdout}");
    assert!(stdout.contains("staging"), "{stdout}");
    assert!(stdout.contains("caddy-rs test root"), "{stdout}");
    assert!(stdout.contains("caddy-rs test intermediate"), "{stdout}");

    let (code, stdout, stderr) = run_pki_with(
        &["pki", "list", "--json", "--data-dir", data_dir],
        |command| {
            command.env("CADDY_RS_TRUST_PREFIX", trust_prefix.path());
        },
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("list JSON");
    assert_eq!(value["data_dir"], data_dir);
    assert!(value["authorities_dir"]
        .as_str()
        .unwrap()
        .ends_with("authorities"));
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
    assert_eq!(authorities[0]["trust"]["install_trust"], "default");
    assert!(
        ["installed", "missing", "unknown"]
            .contains(&authorities[0]["trust"]["state"].as_str().unwrap()),
        "{stdout}"
    );

    // `$CADDY_RS_DATA_DIR` is respected when --data-dir is absent.
    let (code, stdout, stderr) = run_pki_with(&["pki", "list"], |command| {
        command
            .env("CADDY_RS_DATA_DIR", data_dir)
            .env("CADDY_RS_TRUST_PREFIX", trust_prefix.path());
    });
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("local"), "{stdout}");
    assert!(stdout.contains("staging"), "{stdout}");
}

#[test]
fn pki_list_names_the_directory_checked_when_empty() {
    let empty = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) =
        run_pki(&["pki", "list", "--data-dir", empty.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("no local certificate authorities"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&empty.path().join("pki/authorities").display().to_string()),
        "empty listing must name the authorities directory checked:\n{stdout}"
    );
    // The data directory is a prefix of the authorities path, so a contains() on the bare path
    // would pass even if the "(data directory ...)" clause were missing. Assert the clause itself.
    let expected_clause = format!("data directory `{}`", empty.path().display());
    assert!(
        stdout.contains(&expected_clause),
        "empty listing must name the data directory checked:\n{stdout}"
    );
}

#[test]
fn pki_list_fails_loudly_for_a_missing_data_directory() {
    let base = tempfile::tempdir().unwrap();
    let missing = base.path().join("does/not/exist");
    let (code, stdout, stderr) = run_pki(&["pki", "list", "--data-dir", missing.to_str().unwrap()]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("does not exist"), "{stderr}");
    assert!(stderr.contains(&missing.display().to_string()), "{stderr}");
    assert!(stderr.contains("from --data-dir"), "{stderr}");
    assert!(stderr.contains("CADDY_RS_DATA_DIR"), "{stderr}");

    // The same preflight protects `show` and `export`.
    for subcommand in ["show local", "export local"] {
        let mut args = vec!["pki"];
        args.extend(subcommand.split(' '));
        args.extend(["--data-dir", missing.to_str().unwrap()]);
        let (code, stdout, stderr) = run_pki(&args);
        assert_eq!(code, 1, "pki {subcommand}: {stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains("does not exist"), "{stderr}");
        assert!(stderr.contains(&missing.display().to_string()), "{stderr}");
    }
}

#[test]
fn pki_list_fails_loudly_when_the_data_directory_is_a_file() {
    let base = tempfile::tempdir().unwrap();
    let file = base.path().join("data-dir-is-a-file");
    std::fs::write(&file, b"not a directory").unwrap();
    let (code, stdout, stderr) = run_pki(&["pki", "list", "--data-dir", file.to_str().unwrap()]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("is not a directory"), "{stderr}");
    assert!(stderr.contains(&file.display().to_string()), "{stderr}");
}

#[test]
fn pki_list_uses_the_same_data_directory_resolution_as_run() {
    // A configured `storage.root` is the storage the server writes, so it wins over `--data-dir`
    // (the server's precedence in `caddy_rs_core::data_dir::resolve_server_data_dir`).
    let data = pki_data_dir_with_keys();
    let elsewhere = tempfile::tempdir().unwrap();
    let config = elsewhere.path().join("caddy.json");
    let config_value = serde_json::json!({
        "storage": {"module": "file_system", "root": data.path().to_string_lossy()},
    });
    std::fs::write(&config, serde_json::to_vec(&config_value).unwrap()).unwrap();
    let (code, stdout, stderr) = run_pki(&[
        "pki",
        "list",
        "--json",
        "--config",
        config.to_str().unwrap(),
        "--data-dir",
        elsewhere.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("list JSON");
    assert_eq!(
        value["data_dir"].as_str().unwrap(),
        data.path().to_str().unwrap()
    );
    assert_eq!(value["authorities"].as_array().unwrap().len(), 2);

    // Caddy's `AppDataDir()`: `$XDG_DATA_HOME/caddy` is the default when no override is supplied.
    let base = tempfile::tempdir().unwrap();
    let xdg = base.path().join("xdg");
    let work = base.path().join("work");
    let home = base.path().join("home");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    copy_fixture_cas(&xdg.join("caddy"));
    let trust_prefix = base.path().join("prefix");
    let (code, stdout, stderr) = run_pki_with(&["pki", "list", "--json"], |command| {
        command
            .current_dir(&work)
            .env_remove("CADDY_RS_DATA_DIR")
            .env("XDG_DATA_HOME", &xdg)
            .env("HOME", &home)
            .env("CADDY_RS_TRUST_PREFIX", &trust_prefix);
    });
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("list JSON");
    assert_eq!(
        value["data_dir"].as_str().unwrap(),
        xdg.join("caddy").to_str().unwrap()
    );
    assert_eq!(value["authorities"].as_array().unwrap().len(), 2);

    // The legacy `.caddy-rs` working-directory directory is still found, like the server's fallback.
    let legacy_base = tempfile::tempdir().unwrap();
    let legacy_cwd = legacy_base.path().join("work");
    let legacy_home = legacy_base.path().join("home");
    let empty_xdg = legacy_base.path().join("xdg");
    std::fs::create_dir_all(&legacy_cwd).unwrap();
    std::fs::create_dir_all(&legacy_home).unwrap();
    copy_fixture_cas(&legacy_cwd.join(".caddy-rs"));
    let (code, stdout, stderr) = run_pki_with(&["pki", "list", "--json"], |command| {
        command
            .current_dir(&legacy_cwd)
            .env_remove("CADDY_RS_DATA_DIR")
            .env("XDG_DATA_HOME", &empty_xdg)
            .env("HOME", &legacy_home)
            .env("CADDY_RS_TRUST_PREFIX", legacy_base.path().join("prefix"));
    });
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("list JSON");
    assert!(
        value["data_dir"].as_str().unwrap().ends_with(".caddy-rs"),
        "{stdout}"
    );
    assert_eq!(value["authorities"].as_array().unwrap().len(), 2);
}

#[cfg(unix)]
#[test]
fn pki_list_reports_platform_trust_store_state() {
    let data = pki_data_dir_with_keys();
    let fixture = trust_fixture(true);
    let data_dir = data.path().to_str().unwrap();
    let run = |extra: &[&str]| {
        let mut args = vec!["pki", "list", "--data-dir", data_dir];
        args.extend_from_slice(extra);
        run_pki_with(&args, |command| {
            command
                .env("HOME", &fixture.home)
                .env("JAVA_HOME", &fixture.java_home)
                .env("PATH", &fixture.bin)
                .env("CADDY_RS_TRUST_PREFIX", &fixture.platform_prefix);
        })
    };

    let (code, stdout, stderr) = run(&[]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(row_for(&stdout, "local").contains("missing"), "{stdout}");
    assert!(row_for(&stdout, "staging").contains("missing"), "{stdout}");

    // Plant the exact root PEM where the Linux platform plan installs it.
    let installed = fixture
        .platform_prefix
        .join("usr/local/share/ca-certificates/caddy-rs-local.crt");
    std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
    std::fs::copy(
        data.path().join("pki/authorities/local/root.crt"),
        &installed,
    )
    .unwrap();
    if cfg!(target_os = "linux") {
        // A matching staged copy plus a stale generated CA bundle is not trusted yet.
        let bundle = fixture
            .platform_prefix
            .join("etc/ssl/certs/ca-certificates.crt");
        std::fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        std::fs::write(&bundle, b"-----BEGIN CERTIFICATE-----\nstale bundle\n").unwrap();
        let (code, stdout, stderr) = run(&[]);
        assert_eq!(code, 0, "stderr: {stderr}");
        assert!(
            row_for(&stdout, "local").contains("missing"),
            "stale CA bundle must be reported as missing:\n{stdout}"
        );
        std::fs::copy(data.path().join("pki/authorities/local/root.crt"), &bundle).unwrap();
    }
    let (code, stdout, stderr) = run(&[]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(row_for(&stdout, "local").contains("installed"), "{stdout}");
    assert!(row_for(&stdout, "staging").contains("missing"), "{stdout}");

    // `install_trust: false` is reported as disabled, matching Caddy skipping `installRoot`.
    let config = data.path().join("caddy.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "apps": {"pki": {"certificate_authorities": {
                "local": {"install_trust": false}
            }}},
        }))
        .unwrap(),
    )
    .unwrap();
    let (code, stdout, stderr) = run(&["--config", config.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(row_for(&stdout, "local").contains("disabled"), "{stdout}");
}

#[test]
fn pki_show_prints_subject_expiry_keys_and_ca_info() {
    let data = pki_data_dir_with_keys();
    let data_dir = data.path().to_str().unwrap();
    let trust_prefix = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_pki_with(
        &["pki", "show", "local", "--data-dir", data_dir],
        |command| {
            command.env("CADDY_RS_TRUST_PREFIX", trust_prefix.path());
        },
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    for expected in [
        "CA: local",
        "name: local",
        "root certificate:",
        "subject: CN=caddy-rs test root",
        "issuer: CN=caddy-rs test root",
        "not before:",
        "not after:",
        "intermediates: 1",
        "subject: CN=caddy-rs test intermediate",
        "root.key (present)",
        "intermediate.key (present)",
        "trust:",
    ] {
        assert!(
            stdout.contains(expected),
            "show output misses `{expected}`:\n{stdout}"
        );
    }

    let (code, stdout, stderr) = run_pki_with(
        &["pki", "show", "--json", "local", "--data-dir", data_dir],
        |command| {
            command.env("CADDY_RS_TRUST_PREFIX", trust_prefix.path());
        },
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("show JSON");
    assert_eq!(value["id"], "local");
    assert_eq!(value["name"], "local");
    assert_eq!(value["root_common_name"], "caddy-rs test root");
    assert_eq!(
        value["intermediate_common_name"],
        "caddy-rs test intermediate"
    );
    assert!(value["root_certificate"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE-----"));
    assert_pem_count(value["intermediate_certificate"].as_str().unwrap(), 1);
    assert_eq!(value["root"]["subject"], "CN=caddy-rs test root");
    assert!(value["root"]["not_after"].is_string());
    assert_eq!(value["root"]["key_present"], true);
    let intermediates = value["intermediates"].as_array().unwrap();
    assert_eq!(intermediates.len(), 1);
    assert_eq!(intermediates[0]["index"], 1);
    assert_eq!(intermediates[0]["key_present"], true);
    assert!(value["trust"]["state"].is_string());

    // An unknown CA is a loud, located error, not an empty report.
    let (code, stdout, stderr) =
        run_pki(&["pki", "show", "does-not-exist", "--data-dir", data_dir]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("no certificate authority configured with id `does-not-exist`"),
        "{stderr}"
    );
    assert!(stderr.contains("must be provisioned"), "{stderr}");
}

#[test]
fn pki_show_uses_configured_name_and_install_trust() {
    let data = pki_data_dir_with_keys();
    let config = data.path().join("caddy.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "apps": {"pki": {"certificate_authorities": {
                "local": {"name": "Test Local CA", "install_trust": false}
            }}},
        }))
        .unwrap(),
    )
    .unwrap();
    let (code, stdout, stderr) = run_pki(&[
        "pki",
        "show",
        "local",
        "--config",
        config.to_str().unwrap(),
        "--data-dir",
        data.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("name: Test Local CA"), "{stdout}");
    assert!(
        stdout.contains("trust: disabled (install_trust: disabled)"),
        "{stdout}"
    );

    let (code, stdout, stderr) = run_pki(&[
        "pki",
        "show",
        "--json",
        "local",
        "--config",
        config.to_str().unwrap(),
        "--data-dir",
        data.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("show JSON");
    assert_eq!(value["name"], "Test Local CA");
    assert_eq!(value["trust"]["state"], "disabled");
    assert_eq!(value["trust"]["install_trust"], "disabled");
}

#[test]
fn pki_export_round_trips_root_and_intermediate_byte_identically() {
    let data = pki_data_dir_with_keys();
    let data_dir = data.path().to_str().unwrap();
    let root_expected =
        std::fs::read(pki_fixture_data_dir().join("pki/authorities/local/root.crt"))
            .expect("root fixture");
    let intermediate_expected =
        std::fs::read(pki_fixture_data_dir().join("pki/authorities/local/intermediate.crt"))
            .expect("intermediate fixture");
    let mut chain_expected = intermediate_expected.clone();
    chain_expected.extend_from_slice(&root_expected);

    // Default export is the root certificate, byte-for-byte.
    let (code, stdout, stderr) = run_pki(&["pki", "export", "local", "--data-dir", data_dir]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout.as_bytes(), root_expected.as_slice());
    assert_pem_count(&stdout, 1);

    // The documented task form: `export --ca <id> --type root|intermediate --out <path>`.
    let out = data.path().join("exported-root.crt");
    let (code, stdout, stderr) = run_pki(&[
        "pki",
        "export",
        "--ca",
        "local",
        "--type",
        "root",
        "--out",
        out.to_str().unwrap(),
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(std::fs::read(&out).unwrap(), root_expected);
    assert!(stderr.contains("exported root certificate"), "{stderr}");

    let out = data.path().join("exported-intermediate.crt");
    let (code, stdout, stderr) = run_pki(&[
        "pki",
        "export",
        "--ca",
        "local",
        "--type",
        "intermediate",
        "--out",
        out.to_str().unwrap(),
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(std::fs::read(&out).unwrap(), intermediate_expected);
    assert_pem_count(&std::fs::read_to_string(&out).unwrap(), 1);

    let out = data.path().join("exported-chain.crt");
    let (code, stdout, stderr) = run_pki(&[
        "pki",
        "export",
        "local",
        "--type",
        "chain",
        "--out",
        out.to_str().unwrap(),
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(std::fs::read(&out).unwrap(), chain_expected);

    // The pre-existing flag aliases keep working.
    let (code, stdout, _) = run_pki(&["pki", "export", "local", "--root", "--data-dir", data_dir]);
    assert_eq!(code, 0);
    assert_eq!(stdout.as_bytes(), root_expected.as_slice());
    let (code, stdout, _) = run_pki(&[
        "pki",
        "export",
        "local",
        "--intermediate",
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, 0);
    assert_eq!(stdout.as_bytes(), intermediate_expected.as_slice());
    let (code, stdout, _) = run_pki(&["pki", "export", "local", "--chain", "--data-dir", data_dir]);
    assert_eq!(code, 0);
    assert_eq!(stdout.as_bytes(), chain_expected.as_slice());
}

#[test]
fn pki_export_rejects_ambiguous_selectors_and_bad_output_paths() {
    let data = pki_data_dir_with_keys();
    let data_dir = data.path().to_str().unwrap();

    // No CA selector at all.
    let (code, stdout, stderr) = run_pki(&["pki", "export", "--data-dir", data_dir]);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("required arguments"), "{stderr}");

    // Positional ID and --ca together.
    let (code, _stdout, stderr) = run_pki(&[
        "pki",
        "export",
        "local",
        "--ca",
        "local",
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stderr.contains("cannot be used with"), "{stderr}");

    // --type and a legacy type flag together.
    let (code, _stdout, stderr) = run_pki(&[
        "pki",
        "export",
        "local",
        "--type",
        "root",
        "--root",
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stderr.contains("cannot be used with"), "{stderr}");

    let (code, _stdout, stderr) = run_pki(&[
        "pki",
        "export",
        "local",
        "--type",
        "leaf",
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(
        stderr.contains("possible values: root, intermediate, chain"),
        "{stderr}"
    );

    // An unknown CA is a loud, located error with nothing on stdout.
    let (code, stdout, stderr) =
        run_pki(&["pki", "export", "does-not-exist", "--data-dir", data_dir]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("no certificate authority configured with id `does-not-exist`"),
        "{stderr}"
    );
    assert!(stderr.contains("must be provisioned"), "{stderr}");

    // A missing output directory fails before writing anything and names the path.
    let out = data.path().join("missing-dir/root.crt");
    let (code, stdout, stderr) = run_pki(&[
        "pki",
        "export",
        "--ca",
        "local",
        "--type",
        "root",
        "--out",
        out.to_str().unwrap(),
        "--data-dir",
        data_dir,
    ]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("output directory"), "{stderr}");
    assert!(stderr.contains("missing-dir"), "{stderr}");
    assert!(!out.exists());

    // A CA with no intermediate reports that plainly instead of writing an empty file.
    let root_only = tempfile::tempdir().unwrap();
    let ca = root_only.path().join("pki/authorities/root-only");
    std::fs::create_dir_all(&ca).unwrap();
    std::fs::copy(
        pki_fixture_data_dir().join("pki/authorities/local/root.crt"),
        ca.join("root.crt"),
    )
    .unwrap();
    let out = root_only.path().join("intermediate.crt");
    let (code, stdout, stderr) = run_pki(&[
        "pki",
        "export",
        "--ca",
        "root-only",
        "--type",
        "intermediate",
        "--out",
        out.to_str().unwrap(),
        "--data-dir",
        root_only.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("has no intermediate certificate"),
        "{stderr}"
    );
    assert!(!out.exists());
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
fn trust_uses_the_shared_data_directory_resolution() {
    // `trust` must resolve the data directory exactly like `run`/`pki`: with no `--data-dir`,
    // Caddy's `AppDataDir()` ($XDG_DATA_HOME/caddy) is used, and a legacy `.caddy-rs` directory is
    // only a fallback. Before T-CLI-011 trust kept the legacy resolver, so this test fails if the
    // shared resolver is dropped.
    let base = tempfile::tempdir().unwrap();
    let xdg = base.path().join("xdg");
    let data = xdg.join("caddy");
    std::fs::create_dir_all(data.join("pki/authorities")).unwrap();
    copy_fixture_cas(&data);
    let fixture = trust_fixture(true);
    let mut command = Command::new(binary());
    command
        .args(["trust", "--dry-run"])
        .env("XDG_DATA_HOME", &xdg)
        .env("HOME", &fixture.home)
        .env("JAVA_HOME", &fixture.java_home)
        .env("CADDY_RS_TRUST_PREFIX", &fixture.platform_prefix)
        .env("PATH", fixture.bin.display().to_string());
    let output = command.output().expect("run caddy-rs trust");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("root certificate:"),
        "trust did not find the CA under $XDG_DATA_HOME/caddy:\n{stdout}\n{stderr}"
    );
    assert!(stdout.contains("no changes made (--dry-run)"), "{stdout}");
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

// ---- --adapt-mode (T-HTTP-050) -----------------------------------------------------------------

fn write_caddyfile(directory: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
    let config = directory.path().join("Caddyfile");
    std::fs::write(&config, body).expect("write Caddyfile");
    config
}

#[test]
fn adapt_mode_flag_controls_deprecated_alias_handling() {
    let directory = tempfile::tempdir().unwrap();
    let config = write_caddyfile(&directory, ":8080 {\n\tskip_log\n\trespond \"ok\"\n}\n");
    let path = config.to_str().unwrap();

    // compatible (default): alias accepted with Caddy's deprecation warning, same JSON.
    let (code, stdout, stderr) = run(&["adapt", "--config", path]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stderr.contains("the 'skip_log' directive is deprecated, please use 'log_skip' instead!"),
        "{stderr}"
    );
    let compatible: serde_json::Value = serde_json::from_str(&stdout).expect("compatible JSON");

    // warn: alias accepted, Caddy's deprecation warning emitted, JSON unchanged.
    let (code, stdout, stderr) = run(&["adapt", "--config", path, "--adapt-mode", "warn"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stderr.contains("the 'skip_log' directive is deprecated, please use 'log_skip' instead!"),
        "{stderr}"
    );
    let warned: serde_json::Value = serde_json::from_str(&stdout).expect("warn JSON");
    assert_eq!(warned, compatible);

    // strict: rejected with a located error naming both spellings, no warning-then-accept.
    let (code, _stdout, stderr) = run(&["adapt", "--config", path, "--adapt-mode", "strict"]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("`skip_log` is a deprecated alias for `log_skip`"),
        "{stderr}"
    );
    assert!(stderr.contains("Caddyfile line 2"), "{stderr}");
    assert!(!stderr.contains("warning:"), "{stderr}");
}

#[test]
fn adapt_mode_strict_still_accepts_log_skip() {
    let directory = tempfile::tempdir().unwrap();
    let config = write_caddyfile(&directory, ":8080 {\n\tlog_skip\n\trespond \"ok\"\n}\n");
    let (code, stdout, stderr) = run(&[
        "adapt",
        "--config",
        config.to_str().unwrap(),
        "--adapt-mode",
        "strict",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON");
    assert_eq!(
        value["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["handler"],
        "vars"
    );
}

#[test]
fn validate_honours_adapt_mode() {
    let directory = tempfile::tempdir().unwrap();
    let skip_log = write_caddyfile(&directory, ":8080 {\n\tskip_log\n\trespond \"ok\"\n}\n");

    let (code, stdout, stderr) = run(&["validate", "--config", skip_log.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("Valid configuration"), "{stdout}");
    assert!(
        stderr.contains("the 'skip_log' directive is deprecated, please use 'log_skip' instead!"),
        "{stderr}"
    );

    let (code, _stdout, stderr) = run(&[
        "validate",
        "--config",
        skip_log.to_str().unwrap(),
        "--adapt-mode",
        "strict",
    ]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("deprecated alias for `log_skip`"),
        "{stderr}"
    );
    assert!(stderr.contains("skip_log"), "{stderr}");
}

#[test]
fn run_honours_adapt_mode_before_starting_listeners() {
    let directory = tempfile::tempdir().unwrap();
    let config = write_caddyfile(&directory, ":8080 {\n\tskip_log\n\trespond \"ok\"\n}\n");
    let (code, _stdout, stderr) = run_within(
        &[
            "run",
            "--config",
            config.to_str().unwrap(),
            "--adapt-mode",
            "strict",
        ],
        Duration::from_secs(30),
    );
    assert_ne!(code, 0);
    assert!(
        stderr.contains("deprecated alias for `log_skip`"),
        "{stderr}"
    );
}

#[test]
fn unknown_adapt_mode_is_rejected_with_the_three_modes() {
    let directory = tempfile::tempdir().unwrap();
    let config = write_caddyfile(&directory, ":8080 {\n\trespond \"ok\"\n}\n");
    let (code, _stdout, stderr) = run(&[
        "adapt",
        "--config",
        config.to_str().unwrap(),
        "--adapt-mode",
        "reckless",
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("reckless"), "{stderr}");
    assert!(stderr.contains("compatible"), "{stderr}");
    assert!(stderr.contains("warn"), "{stderr}");
    assert!(stderr.contains("strict"), "{stderr}");
}

#[test]
fn adapt_help_documents_adapt_mode() {
    let (code, stdout, _stderr) = run(&["adapt", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--adapt-mode"), "{stdout}");
    assert!(stdout.contains("compatible"), "{stdout}");
    assert!(stdout.contains("strict"), "{stdout}");
}

#[test]
fn build_info_reports_the_rust_toolchain_and_build_settings() {
    let (code, stdout, stderr) = run(&["build-info"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.starts_with("rustc\t"), "{stdout}");
    assert!(stdout.contains("\npath\tcaddy-rs\n"), "{stdout}");
    assert!(
        stdout.contains(&format!("\nmod\tcaddy-rs\t{}\t", env!("CARGO_PKG_VERSION"))),
        "{stdout}"
    );

    let profile = stdout
        .lines()
        .find_map(|line| line.strip_prefix("build\t-profile="))
        .expect("profile build setting");
    assert!(
        matches!(profile, "debug" | "release"),
        "unexpected build profile {profile}"
    );

    let target = stdout
        .lines()
        .find_map(|line| line.strip_prefix("build\t-target="))
        .expect("target build setting");
    assert!(!target.is_empty(), "empty target triple");
    let host_arch = match std::env::consts::ARCH {
        "x86" => "i686",
        other => other,
    };
    let host_os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    assert!(
        target.starts_with(host_arch),
        "target {target} does not start with host arch {host_arch}"
    );
    assert!(
        target.contains(host_os),
        "target {target} does not contain host OS {host_os}"
    );

    assert!(
        stdout.contains("\nbuild\t-features="),
        "feature list missing: {stdout}"
    );
    let modules: usize = stdout
        .lines()
        .find_map(|line| line.strip_prefix("build\t-modules="))
        .expect("module count build setting")
        .parse()
        .expect("numeric module count");

    // The count must agree with the same registry that `list-modules` walks; a hardcoded or
    // stale number must fail this assertion.
    let (list_code, list_stdout, list_stderr) = run(&["list-modules"]);
    assert_eq!(list_code, 0, "list-modules stderr: {list_stderr}");
    let listed = list_stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    assert_eq!(
        modules, listed,
        "build-info module count must match list-modules"
    );

    assert!(
        stdout.contains("\nbuild\t-caddy-baseline=v2.11.9\n"),
        "{stdout}"
    );
}

#[test]
fn environ_prints_caddys_header_and_the_process_environment() {
    let (code, stdout, stderr) = run(&["environ"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let header = stdout
        .split("\n\n")
        .next()
        .expect("header before blank line");
    let keys: Vec<&str> = header
        .lines()
        .map(|line| line.split('=').next().unwrap_or(line))
        .collect();
    assert_eq!(
        keys,
        [
            "caddy.HomeDir",
            "caddy.AppDataDir",
            "caddy.AppConfigDir",
            "caddy.ConfigAutosavePath",
            "caddy.Version",
            "runtime.GOOS",
            "runtime.GOARCH",
            "runtime.Compiler",
            "runtime.NumCPU",
            "runtime.GOMAXPROCS",
            "runtime.Version",
            "os.Getwd",
        ],
        "{stdout}"
    );
    assert!(header.contains("runtime.Compiler=rustc"), "{stdout}");
    assert!(
        stdout.contains(&format!("caddy.Version={}", env!("CARGO_PKG_VERSION"))),
        "{stdout}"
    );
    assert!(
        stdout.contains("\nPATH="),
        "environment variables missing: {stdout}"
    );
}

#[test]
fn environ_loads_envfiles_without_overwriting_and_reports_parse_errors() {
    let directory = tempfile::tempdir().unwrap();
    let suffix = std::process::id();
    let key = format!("CADDY_RS_ENVFILE_TEST_{suffix}");
    let exported = format!("CADDY_RS_ENVFILE_EXPORTED_{suffix}");
    let keep = format!("CADDY_RS_ENVFILE_KEEP_{suffix}");
    let duplicate = format!("CADDY_RS_ENVFILE_DUP_{suffix}");
    let envfile = directory.path().join("caddy.env");
    std::fs::write(
        &envfile,
        format!(
            "# comment\n\
             export {exported}=exported\n\
             {key}=\"line one\nline two\"\n\
             {keep}=from-file\n\
             {duplicate}=first\n\
             {duplicate}=second\n"
        ),
    )
    .unwrap();

    // Seed `keep` in the child's *process* environment. Caddy's loader must not overwrite it.
    let output = Command::new(binary())
        .args(["environ", "--envfile", envfile.to_str().unwrap()])
        .env(&keep, "from-process")
        .output()
        .expect("run caddy-rs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let environment = stdout.split("\n\n").nth(1).unwrap_or_default();
    let lines: Vec<&str> = environment.lines().collect();

    let key_line = lines
        .iter()
        .position(|line| *line == format!("{key}=line one"))
        .expect("quoted first line in environment output");
    assert_eq!(lines.get(key_line + 1), Some(&"line two"), "{stdout}");
    assert!(
        lines
            .iter()
            .any(|line| *line == format!("{exported}=exported")),
        "{stdout}"
    );
    assert!(
        lines
            .iter()
            .any(|line| *line == format!("{keep}=from-process")),
        "existing process variable was overwritten: {stdout}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| *line == format!("{keep}=from-file")),
        "envfile value replaced the process environment: {stdout}"
    );
    assert!(
        lines
            .iter()
            .any(|line| *line == format!("{duplicate}=second")),
        "last duplicate key must win: {stdout}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| *line == format!("{duplicate}=first")),
        "{stdout}"
    );

    let malformed = directory.path().join("malformed.env");
    std::fs::write(&malformed, "not-a-pair\n").unwrap();
    let (code, _stdout, stderr) = run(&["environ", "--envfile", malformed.to_str().unwrap()]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("line 1"), "{stderr}");
    assert!(stderr.contains("KEY=VALUE"), "{stderr}");

    let missing = directory.path().join("missing.env");
    let (code, _stdout, stderr) = run(&["environ", "--envfile", missing.to_str().unwrap()]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains(&format!(
            "open {}: no such file or directory",
            missing.display()
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("os error"), "{stderr}");
}

#[test]
fn completion_scripts_cover_every_subcommand_and_shell() {
    let (code, stdout, stderr) = run(&["completion", "bash"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(!stdout.trim().is_empty(), "empty bash completion script");
    for command in [
        "version",
        "build-info",
        "list-modules",
        "adapt",
        "validate",
        "run",
        "reload",
        "stop",
        "environ",
        "completion",
        "manpage",
        "pki",
        "trust",
    ] {
        assert!(
            stdout.contains(&format!("\"{command}\") opts="))
                || stdout.contains(&format!(" {command} ")),
            "bash completion misses {command}: {stdout}"
        );
    }
    assert!(stdout.contains("--envfile"), "{stdout}");
    assert!(stdout.contains("--directory"), "{stdout}");
    assert!(
        stdout.contains("complete -o default -F _caddy_rs caddy-rs"),
        "{stdout}"
    );

    for shell in ["zsh", "fish", "powershell"] {
        let (code, stdout, stderr) = run(&["completion", shell]);
        assert_eq!(code, 0, "{shell} stderr: {stderr}");
        assert!(!stdout.trim().is_empty(), "empty {shell} completion script");
        assert!(stdout.contains("caddy-rs"), "{shell}: {stdout}");
        assert!(stdout.contains("pki"), "{shell}: {stdout}");
    }

    let (code, _stdout, stderr) = run(&["completion"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("accepts 1 arg(s), received 0"), "{stderr}");

    let (code, _stdout, stderr) = run(&["completion", "bash", "zsh"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("accepts 1 arg(s), received 2"), "{stderr}");

    let (code, _stdout, stderr) = run(&["completion", "nope"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("invalid argument \"nope\" for \"caddy-rs completion\""),
        "{stderr}"
    );
}

#[test]
fn manpage_writes_root_and_subcommand_roff_pages() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("man");
    let (code, stdout, stderr) = run(&["manpage", "--directory", output.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");

    for filename in [
        "caddy-rs.8",
        "caddy-rs-adapt.8",
        "caddy-rs-completion.8",
        "caddy-rs-environ.8",
        "caddy-rs-pki.8",
        "caddy-rs-pki-list.8",
    ] {
        assert!(
            output.join(filename).is_file(),
            "missing man page {filename}"
        );
    }

    let root = std::fs::read_to_string(output.join("caddy-rs.8")).unwrap();
    assert!(root.starts_with(".TH \"CADDY-RS\" \"8\""), "{root}");
    assert!(root.contains("\n.SH NAME\n"), "{root}");
    assert!(root.contains("\n.SH SYNOPSIS\n"), "{root}");
    assert!(root.contains("\n.SH SUBCOMMANDS\n"), "{root}");
    for command in ["environ", "completion", "manpage"] {
        assert!(root.contains(command), "root man page misses {command}");
    }
    assert!(root.contains("build\\-info"), "{root}");

    let adapt = std::fs::read_to_string(output.join("caddy-rs-adapt.8")).unwrap();
    assert!(adapt.starts_with(".TH \"CADDY-RS-ADAPT\" \"8\""), "{adapt}");
    assert!(adapt.contains("\\-\\-config"), "{adapt}");
    assert!(adapt.contains("\\-\\-pretty"), "{adapt}");
    assert!(
        !adapt.contains("\\-\\-pretty \\fI<"),
        "boolean flag rendered with a value: {adapt}"
    );
}

#[test]
fn manpage_requires_an_output_directory_with_caddys_exit_code() {
    let (code, _stdout, stderr) = run(&["manpage"]);
    assert_eq!(code, 3, "{stderr}");
    assert!(
        stderr.contains("designated output directory and specified section are required"),
        "{stderr}"
    );

    let (code, _stdout, stderr) = run(&["manpage", "-o", ""]);
    assert_eq!(
        code, 3,
        "empty --directory must be treated as missing: {stderr}"
    );
    assert!(
        stderr.contains("designated output directory and specified section are required"),
        "{stderr}"
    );
}
