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

/// Run the binary in `directory` with the given arguments.
fn run_in(directory: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(binary())
        .current_dir(directory)
        .args(args)
        .output()
        .expect("run caddy-rs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Run the binary with `stdin` supplied on its standard input.
fn run_with_stdin(args: &[&str], stdin: &str) -> (i32, String, String) {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn caddy-rs");
    child
        .stdin
        .as_mut()
        .expect("stdin pipe")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait for caddy-rs");
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

const FMT_LINT: &str = "Caddyfile input is not formatted; Tip: use '--overwrite' to update your Caddyfile in-place instead of previewing it. Consult '--help' for more options";

#[test]
fn fmt_formats_and_locates_unformatted_input() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("Caddyfile");

    // Caddy prints the formatted result and then fails with a located message.
    std::fs::write(&config, "  a   b\nc {\nd\ne\n}\n").unwrap();
    let (code, stdout, stderr) = run(&["fmt", config.to_str().unwrap()]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert_eq!(stdout, "a b\nc {\n\td\n\te\n}\n");
    assert!(
        stderr.contains(&format!("{}:1: {FMT_LINT}", config.display())),
        "stderr: {stderr}"
    );

    // An already-formatted file prints the same bytes and exits 0.
    let formatted = "a b\nc {\n\td\n\te\n}\n";
    std::fs::write(&config, formatted).unwrap();
    let (code, stdout, stderr) = run(&["fmt", config.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, formatted);
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn fmt_preserves_heredocs_and_quoted_literals() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("Caddyfile");
    let input =
        "block {\n\theredoc <<EOF\n\tkeep   these    spaces\n\tEOF\n\trespond \"a  b\"\n}\n";
    std::fs::write(&config, input).unwrap();

    let (code, stdout, stderr) = run(&["fmt", config.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, input);
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn fmt_overwrite_rewrites_in_place_and_skips_the_lint() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("Caddyfile");
    let formatted = "a b\nc {\n\td\n\te\n}\n";

    std::fs::write(&config, "  a   b\nc {\nd\ne\n}\n").unwrap();
    let (code, stdout, stderr) = run(&["fmt", "--overwrite", config.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), formatted);

    // `--overwrite` wins over `--diff`, exactly like Caddy.
    std::fs::write(&config, "  a   b\n").unwrap();
    let (code, stdout, _stderr) = run(&["fmt", "-w", "-d", config.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), "a b\n");
}

#[test]
fn fmt_diff_prints_aligned_changes_and_still_fails() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("Caddyfile");
    std::fs::write(&config, "a b\nc {\nd\ne\n}\n").unwrap();

    let (code, stdout, stderr) = run(&["fmt", "--diff", config.to_str().unwrap()]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert_eq!(stdout, "  a b\n  c {\n- d\n- e\n+ \td\n+ \te\n  }\n  \n");
    assert!(
        stderr.contains(&format!("{}:3: {FMT_LINT}", config.display())),
        "stderr: {stderr}"
    );

    // A formatted file diffs as all-common and exits 0.
    std::fs::write(&config, "a b\nc {\n\td\n\te\n}\n").unwrap();
    let (code, stdout, _stderr) = run(&["fmt", "-d", config.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(stdout, "  a b\n  c {\n  \td\n  \te\n  }\n  \n");
}

#[test]
fn fmt_reads_stdin_for_dash_and_ignores_overwrite_and_diff() {
    for args in [
        &["fmt", "-"][..],
        &["fmt", "--overwrite", "-"][..],
        &["fmt", "--diff", "-"][..],
    ] {
        let (code, stdout, stderr) = run_with_stdin(args, "  a   b\n");
        assert_eq!(code, 0, "args {args:?}, stderr: {stderr}");
        assert_eq!(stdout, "a b\n", "args {args:?}");
        assert!(stderr.is_empty(), "args {args:?}, stderr: {stderr}");
    }
}

#[test]
fn fmt_reads_the_config_flag_as_the_path() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("site.caddy");
    std::fs::write(&config, "a b\n").unwrap();

    let (code, stdout, stderr) = run(&["fmt", "--config", config.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "a b\n");
}

#[test]
fn fmt_defaults_to_the_caddyfile_in_the_working_directory() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("Caddyfile"), "  a   b\n").unwrap();

    let (code, stdout, stderr) = run_in(directory.path(), &["fmt"]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert_eq!(stdout, "a b\n");
    assert!(
        stderr.contains(&format!("Caddyfile:1: {FMT_LINT}")),
        "{stderr}"
    );

    std::fs::write(directory.path().join("Caddyfile"), "a b\n").unwrap();
    let (code, _stdout, stderr) = run_in(directory.path(), &["fmt"]);
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn fmt_treats_an_empty_value_as_unset() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("Caddyfile"), "  a   b\n").unwrap();

    // Caddy's cmdFmt resolves an empty `--config` value to the default Caddyfile.
    let (code, stdout, stderr) = run_in(directory.path(), &["fmt", "-c", ""]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert_eq!(stdout, "a b\n");
    assert!(
        stderr.contains(&format!("Caddyfile:1: {FMT_LINT}")),
        "{stderr}"
    );

    // The same is true for an explicitly empty positional path.
    std::fs::write(directory.path().join("Caddyfile"), "a b\n").unwrap();
    let (code, stdout, stderr) = run_in(directory.path(), &["fmt", ""]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "a b\n");

    // Caddy also allows `--config <path> ''`: the empty positional path is unset, so the config
    // flag supplies the file instead of triggering the multiple-inputs error.
    let config = directory.path().join("site.caddy");
    std::fs::write(&config, "a b\n").unwrap();
    let (code, stdout, stderr) = run(&["fmt", "--config", config.to_str().unwrap(), ""]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "a b\n");

    // Two empty positional arguments are still two inputs, and Caddy rejects them with its
    // verbatim message (an absent `--config` leaves the two spaces before the joined paths).
    let (code, _stdout, stderr) = run(&["fmt", "", ""]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("fmt does not support multiple files   "),
        "{stderr}"
    );

    // An empty value with no ./Caddyfile still reports the default path as the open target.
    let empty = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_in(empty.path(), &["fmt", "-c", ""]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(
        stderr.contains("reading input file: open Caddyfile: no such file or directory"),
        "{stderr}"
    );
}

#[test]
fn fmt_rejects_multiple_inputs_like_caddy() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("a.caddy");
    let second = directory.path().join("b.caddy");
    std::fs::write(&first, "a\n").unwrap();
    std::fs::write(&second, "b\n").unwrap();
    let (first, second) = (first.to_str().unwrap(), second.to_str().unwrap());

    let (code, stdout, stderr) = run(&["fmt", first, second]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(
        stderr.contains(&format!(
            "fmt does not support multiple files  {first} {second}"
        )),
        "stderr: {stderr}"
    );

    let (code, _stdout, stderr) = run(&["fmt", "--config", first, second]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains(&format!(
            "fmt does not support multiple files {first} {second}"
        )),
        "stderr: {stderr}"
    );
}

#[test]
fn fmt_reports_an_unreadable_file_with_caddys_io_wording() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.caddy");

    let (code, stdout, stderr) = run(&["fmt", missing.to_str().unwrap()]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    // Caddy prints `reading input file: open <path>: no such file or directory` (the Go
    // `os.ReadFile` error), not Rust's `(os error 2)` rendering.
    assert!(
        stderr.contains(&format!(
            "reading input file: open {}: no such file or directory",
            missing.display()
        )),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("os error"), "stderr: {stderr}");
}

#[test]
fn fmt_help_matches_caddys_usage_and_flags() {
    let (code, stdout, stderr) = run(&["fmt", "--help"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("Usage: caddy-rs fmt [--overwrite] [--diff] [<path>]"),
        "{stdout}"
    );
    for flag in [
        "-c, --config <CONFIG>",
        "-w, --overwrite",
        "-d, --diff",
        "If --diff is specified, the output will be compared against the input",
        "use - as the path",
    ] {
        assert!(stdout.contains(flag), "missing {flag:?} in:\n{stdout}");
    }
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
fn adapt_surfaces_an_unknown_directive_as_an_invalid_configuration() {
    // T-HTTP-052 split the classes: a directive Caddy does not register at all is `config.invalid`
    // with Caddy's own "unrecognized directive" wording, not the "not supported by this build"
    // message (which is reserved for directives Caddy accepts).
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
    assert!(stderr.contains("config.invalid"), "{stderr}");
    assert!(stderr.contains("some_unknown_directive"), "{stderr}");
    assert!(
        stderr.contains("unrecognized directive"),
        "Caddy's wording, not the unsupported message: {stderr}"
    );
}

#[test]
fn adapt_surfaces_a_registered_but_unimplemented_directive_as_unsupported() {
    // The other half of the split: Caddy adapts `abort`, so refusing it is a documented gap and
    // must keep the "not supported by this build" class and the pointer to the compatibility doc.
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("Caddyfile");
    std::fs::write(&config, ":80 {\n\tabort\n}\n").unwrap();
    let (code, _stdout, stderr) = run(&[
        "adapt",
        "--config",
        config.to_str().unwrap(),
        "--adapter",
        "caddyfile",
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("config.unsupported"), "{stderr}");
    assert!(stderr.contains("abort"), "{stderr}");
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

use caddy_rs_test_support::{free_port, is_address_in_use};

/// Serialises tests that touch the default admin port (2019).
static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Attempts for a server start whose configured port was taken before the child could bind it.
const START_ATTEMPTS: usize = 8;

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

/// Whether the child stopped because a configured port was claimed before it could bind.
///
/// `free_port` keeps every issued number out of this process's own allocations, but the kernel can
/// still hand a just-released number to another process before `caddy-rs run` binds it. The child
/// reports that as `Address already in use`; the caller retries with a fresh port.
fn child_lost_port_race(log: &Path) -> bool {
    std::fs::read_to_string(log)
        .map(|stderr| is_address_in_use(&stderr))
        .unwrap_or(false)
}

/// Poll `ready` until it is true, the child exits, or `timeout` expires.
fn wait_until_serving(
    child: &mut Child,
    timeout: Duration,
    mut ready: impl FnMut() -> bool,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        if child.try_wait().expect("poll caddy-rs").is_some() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Start the CLI, retrying with the ports `start` allocates if the child lost the bind race.
///
/// `start` writes the configuration for the ports it just allocated and spawns the child; `ready`
/// polls the freshly started process and receives whatever state the caller needs afterwards.
fn spawn_until_ready<S>(
    mut start: impl FnMut() -> (Child, std::path::PathBuf, S),
    mut ready: impl FnMut(&mut Child, &mut S) -> bool,
    detail: &str,
) -> (Child, std::path::PathBuf, S) {
    for attempt in 0..START_ATTEMPTS {
        let (mut child, log, mut state) = start();
        if ready(&mut child, &mut state) {
            return (child, log, state);
        }
        if attempt + 1 < START_ATTEMPTS && child_lost_port_race(&log) {
            let _ = child.kill();
            let _ = child.wait();
            continue;
        }
        child_failure(&mut child, &log, detail);
    }
    unreachable!("child_failure diverges")
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
    let config = directory.path().join("Caddyfile");
    let (mut child, log, port) = spawn_until_ready(
        || {
            let port = free_port();
            std::fs::write(
                &config,
                format!("{{\n\tauto_https off\n}}\n:{port} {{\n\trespond \"cli-wildcard\"\n}}\n"),
            )
            .expect("write Caddyfile");
            let (child, log) = spawn_run(&config, "caddyfile", directory.path(), "caddyfile");
            (child, log, port)
        },
        |child, port| {
            // A Caddyfile-derived `:PORT` must bind the wildcard and serve IPv4 immediately...
            wait_until_serving(child, Duration::from_secs(15), || {
                http_request(SocketAddr::from(([127, 0, 0, 1], *port)), "GET", "/")
                    .is_some_and(|(status, body)| status == 200 && body == "cli-wildcard")
            })
        },
        "hostless Caddyfile site did not serve IPv4",
    );
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
    let config = directory.path().join("config.json");
    let (mut child, log, admin_port) = spawn_until_ready(
        || {
            let admin_port = free_port();
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
            let (child, log) = spawn_run(&config, "json", directory.path(), "json");
            (child, log, admin_port)
        },
        |child, admin_port| {
            wait_until_serving(child, Duration::from_secs(15), || {
                connect_admin(*admin_port).is_some()
            })
        },
        "JSON-adapter admin API did not start",
    );
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
    let autosave = directory.path().join("custom-autosave.json");
    // A --config passed alongside --resume must be ignored (Caddy's precedence) and warned about.
    let ignored_config = directory.path().join("ignored.json");
    let log = directory.path().join("resume.stderr");
    let (mut child, log, (site_port, admin_port, other_port)) = spawn_until_ready(
        || {
            let site_port = free_port();
            let admin_port = free_port();
            let other_port = free_port();
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
            let file = std::fs::File::create(&log).expect("create child log");
            let child = Command::new(binary())
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
            (child, log.clone(), (site_port, admin_port, other_port))
        },
        |child, (_, admin_port, _)| {
            wait_until_serving(child, Duration::from_secs(15), || {
                connect_admin(*admin_port).is_some()
            })
        },
        "resumed admin API did not start",
    );

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
    let autosave = directory.path().join("autosave.json");
    let config = directory.path().join("config.json");
    let log = directory.path().join("persist.stderr");
    let (mut child, log, (_site_port, admin_port)) = spawn_until_ready(
        || {
            let site_port = free_port();
            let admin_port = free_port();
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
            let file = std::fs::File::create(&log).expect("create child log");
            let child = Command::new(binary())
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
            (child, log.clone(), (site_port, admin_port))
        },
        |child, (_, admin_port)| {
            wait_until_serving(child, Duration::from_secs(15), || {
                connect_admin(*admin_port).is_some()
            })
        },
        "admin API did not start",
    );

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
    let log = directory.path().join("discovery.stderr");
    let (mut child, log, (_site_port, admin_port)) = spawn_until_ready(
        || {
            let site_port = free_port();
            let admin_port = free_port();
            std::fs::write(
                directory.path().join("Caddyfile"),
                format!(
                    "{{\n\tauto_https off\n\tadmin 127.0.0.1:{admin_port}\n}}\n:{site_port} {{\n\trespond \"discovered\"\n}}\n"
                ),
            )
            .expect("write Caddyfile");
            let file = std::fs::File::create(&log).expect("create child log");
            let child = Command::new(binary())
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
            (child, log.clone(), (site_port, admin_port))
        },
        |child, (site_port, _)| {
            wait_until_serving(child, Duration::from_secs(15), || {
                http_request(SocketAddr::from(([127, 0, 0, 1], *site_port)), "GET", "/")
                    .is_some_and(|(status, body)| status == 200 && body == "discovered")
            })
        },
        "Caddyfile was not discovered in the working directory",
    );
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
    let notify_path = directory.path().join("notify.sock");
    let config = directory.path().join("config.json");
    let log = directory.path().join("notify.stderr");
    let (mut child, log, (_site_port, admin_port, receiver, messages)) = spawn_until_ready(
        || {
            let site_port = free_port();
            let admin_port = free_port();
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
            // A retry re-binds the notify socket, so drop the previous attempt's path first.
            let _ = std::fs::remove_file(&notify_path);
            let receiver = UnixDatagram::bind(&notify_path).expect("bind notify socket");
            receiver
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("read timeout");
            let file = std::fs::File::create(&log).expect("create child log");
            let child = Command::new(binary())
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
            (
                child,
                log.clone(),
                (site_port, admin_port, receiver, Vec::new()),
            )
        },
        |child, (_, _, receiver, messages)| {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut buffer = [0_u8; 256];
            while Instant::now() < deadline {
                match receiver.recv(&mut buffer) {
                    Ok(size) => {
                        let message = String::from_utf8_lossy(&buffer[..size]).to_string();
                        let ready = message == "READY=1";
                        messages.push(message);
                        if ready {
                            return true;
                        }
                    }
                    Err(_) => {
                        // A notification read timeout is expected before READY; stop early if
                        // the child already exited because its port was taken.
                        if child.try_wait().expect("poll caddy-rs").is_some() {
                            return false;
                        }
                    }
                }
            }
            false
        },
        "systemd notification run did not become ready",
    );
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
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_stopping = false;
    let mut buffer = [0_u8; 256];
    while !saw_stopping && Instant::now() < deadline {
        if let Ok(size) = receiver.recv(&mut buffer) {
            saw_stopping = String::from_utf8_lossy(&buffer[..size]) == "STOPPING=1";
        }
    }
    assert!(saw_stopping, "expected STOPPING=1 notification");
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

fn write_json_config(
    directory: &tempfile::TempDir,
    name: &str,
    value: &serde_json::Value,
) -> std::path::PathBuf {
    let config = directory.path().join(name);
    std::fs::write(
        &config,
        serde_json::to_string(value).expect("serialize JSON config"),
    )
    .expect("write JSON config");
    config
}

/// A minimal JSON config whose single route carries one `security_headers` handler with `fields`.
fn security_headers_json(fields: serde_json::Value) -> serde_json::Value {
    let mut handler = serde_json::Map::new();
    handler.insert(
        "handler".to_string(),
        serde_json::Value::String("security_headers".to_string()),
    );
    if let Some(fields) = fields.as_object() {
        for (key, value) in fields {
            handler.insert(key.clone(), value.clone());
        }
    }
    serde_json::json!({
        "admin": {"disabled": true},
        "apps": {"http": {"servers": {"srv0": {
            "listen": [":8080"],
            "routes": [{"handle": [serde_json::Value::Object(handler)]}]
        }}}}
    })
}

#[test]
fn validate_applies_adapt_mode_to_security_headers() {
    let directory = tempfile::tempdir().unwrap();

    // Acceptance (1): an invalid CSP fails validation with the located JSON path of the offending
    // directive and source (Caddyfile line/column locations belong to the adapter, T-ROUTE-051).
    let invalid_csp = write_json_config(
        &directory,
        "invalid-csp.json",
        &security_headers_json(serde_json::json!({
            "content_security_policy": "default-src 'self'; img-src h\u{e9}llo"
        })),
    );
    let (code, _stdout, stderr) = run(&["validate", "--config", invalid_csp.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains(
            "apps.http.servers.srv0.routes[0].handle[0].content_security_policy.img-src[0]"
        ),
        "{stderr}"
    );
    assert!(stderr.contains("non-ASCII"), "{stderr}");

    // Acceptance (2): an HSTS max-age below 180 days warns in compatible mode and rejects in
    // strict mode.
    let short_hsts = write_json_config(
        &directory,
        "short-hsts.json",
        &security_headers_json(serde_json::json!({
            "strict_transport_security": {"max_age": 86400, "include_subdomains": true}
        })),
    );
    let (code, stdout, stderr) = run(&["validate", "--config", short_hsts.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("Valid configuration"), "{stdout}");
    assert!(stderr.contains("caddy-rs: warning:"), "{stderr}");
    assert!(
        stderr.contains("below the browser-enforced minimum"),
        "{stderr}"
    );
    assert!(stderr.contains("compatible"), "{stderr}");
    let (code, _stdout, stderr) = run(&[
        "validate",
        "--config",
        short_hsts.to_str().unwrap(),
        "--adapt-mode",
        "strict",
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("15552000"), "{stderr}");
    assert!(
        stderr.contains(
            "apps.http.servers.srv0.routes[0].handle[0].strict_transport_security.max_age"
        ),
        "{stderr}"
    );

    // Acceptance (4) and (5): strict rejects unknown security-header fields, compatible accepts
    // them with a warning.
    let unknown = write_json_config(
        &directory,
        "unknown.json",
        &security_headers_json(serde_json::json!({"frame_options_typo": "DENY"})),
    );
    let (code, _stdout, stderr) = run(&["validate", "--config", unknown.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stderr.contains("caddy-rs: warning:") && stderr.contains("frame_options_typo"),
        "{stderr}"
    );
    let (code, _stdout, stderr) = run(&[
        "validate",
        "--config",
        unknown.to_str().unwrap(),
        "--adapt-mode",
        "strict",
    ]);
    assert_ne!(code, 0);
    assert!(
        stderr.contains("unknown security header option"),
        "{stderr}"
    );
    assert!(
        stderr.contains("apps.http.servers.srv0.routes[0].handle[0].frame_options_typo"),
        "{stderr}"
    );
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
fn completion_install_writes_detected_shells_to_xdg_paths() {
    const MARKER: &str = "# generated by caddy-rs completion install; safe to delete with 'caddy-rs completion uninstall'";
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();
    // Fish is detected by its config directory, not by a binary on PATH.
    std::fs::create_dir_all(config.join("fish")).unwrap();
    std::fs::write(home.join(".bashrc"), "# user rc\n").unwrap();

    let (code, stdout, stderr) = run_with_layout(
        &["completion", "install"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");

    let bash = data.join("bash-completion/completions/caddy-rs");
    let fish = config.join("fish/completions/caddy-rs.fish");
    let (_, bash_script, _) = run(&["completion", "bash"]);
    let (_, fish_script, _) = run(&["completion", "fish"]);
    for (path, script) in [(&bash, &bash_script), (&fish, &fish_script)] {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            contents.lines().next(),
            Some(MARKER),
            "{} does not start with the marker: {contents}",
            path.display()
        );
        assert_eq!(
            contents,
            format!("{MARKER}\n{script}"),
            "{} differs from `completion` output",
            path.display()
        );
    }
    assert!(
        stdout.contains(&format!("installed {}", bash.display())),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("installed {}", fish.display())),
        "{stdout}"
    );
    assert!(
        !data.join("zsh/site-functions/_caddy-rs").exists(),
        "zsh was not detected but was installed"
    );
    assert!(
        !config.join("powershell/Completions/caddy-rs.ps1").exists(),
        "powershell was not detected but was installed"
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".bashrc")).unwrap(),
        "# user rc\n",
        "install modified a shell rc file"
    );
}

#[test]
fn completion_install_shell_selects_only_that_shell() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(config.join("fish")).unwrap();

    // Both bash ($SHELL) and fish (~/.config/fish) are detected, but only zsh is selected; the
    // mixed-case value also covers case-insensitive parsing.
    let (code, stdout, stderr) = run_with_layout(
        &["completion", "install", "--shell", "ZSH"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");

    let zsh = data.join("zsh/site-functions/_caddy-rs");
    assert!(zsh.is_file(), "zsh completion was not written");
    assert!(
        !data.join("bash-completion/completions/caddy-rs").exists(),
        "bash was installed despite --shell zsh"
    );
    assert!(
        !config.join("fish/completions/caddy-rs.fish").exists(),
        "fish was installed despite --shell zsh"
    );

    let (_, script, _) = run(&["completion", "zsh"]);
    let contents = std::fs::read_to_string(&zsh).unwrap();
    assert_eq!(
        contents,
        format!(
            "# generated by caddy-rs completion install; safe to delete with 'caddy-rs completion uninstall'\n{script}"
        )
    );

    // Comma-separated values select several shells in one invocation.
    let (code, stdout, stderr) = run_with_layout(
        &["completion", "install", "--shell", "bash,fish", "--dry-run"],
        &home,
        &data,
        &config,
        "/bin/sh",
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains(&format!(
            "would install {}",
            data.join("bash-completion/completions/caddy-rs").display()
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "would install {}",
            config.join("fish/completions/caddy-rs.fish").display()
        )),
        "{stdout}"
    );
}

#[test]
fn completion_install_is_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();

    let (code, _stdout, stderr) = run_with_layout(
        &["completion", "install"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");
    let bash = data.join("bash-completion/completions/caddy-rs");
    let first = std::fs::read(&bash).unwrap();

    let (code, stdout, stderr) = run_with_layout(
        &["completion", "install"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains(&format!("already up to date {}", bash.display())),
        "{stdout}"
    );
    assert_eq!(
        std::fs::read(&bash).unwrap(),
        first,
        "second run changed bytes"
    );
}

#[test]
fn completion_status_reports_installed_then_stale() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();

    let (code, _stdout, stderr) = run_with_layout(
        &["completion", "install"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");
    let bash = data.join("bash-completion/completions/caddy-rs");

    let (code, stdout, stderr) = run_with_layout(
        &["completion", "status"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("bash:\n  detected: yes"), "{stdout}");
    assert!(stdout.contains("$SHELL is /bin/bash"), "{stdout}");
    assert!(
        stdout.contains(&format!("target: {}", bash.display())),
        "{stdout}"
    );
    assert!(stdout.contains("state: installed"), "{stdout}");
    assert!(stdout.contains("zsh:\n  detected: no"), "{stdout}");
    assert!(stdout.contains("state: not installed"), "{stdout}");

    // A stale file keeps the marker and differs from the currently generated script, as after a
    // binary upgrade that changed the command tree.
    let mut drifted = std::fs::read_to_string(&bash).unwrap();
    drifted.push_str("# stale drift\n");
    std::fs::write(&bash, drifted).unwrap();

    let (code, stdout, stderr) = run_with_layout(
        &["completion", "status"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("state: stale"), "{stdout}");
}

#[test]
fn completion_uninstall_removes_only_marked_files() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(config.join("fish")).unwrap();
    std::fs::write(home.join(".bashrc"), "# user rc\n").unwrap();

    let (code, _stdout, stderr) = run_with_layout(
        &["completion", "install"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");
    let bash = data.join("bash-completion/completions/caddy-rs");
    let fish = config.join("fish/completions/caddy-rs.fish");
    let zsh = data.join("zsh/site-functions/_caddy-rs");
    std::fs::create_dir_all(zsh.parent().unwrap()).unwrap();
    std::fs::write(&zsh, "# not ours\n").unwrap();

    // The bare command visits every target path: it removes the owned bash and fish files, and
    // refuses the same-named zsh file whose first line lacks the marker.
    let (code, stdout, stderr) = run_with_layout(
        &["completion", "uninstall"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(!bash.exists(), "owned bash file was not removed");
    assert!(!fish.exists(), "owned fish file was not removed");
    assert_eq!(std::fs::read_to_string(&zsh).unwrap(), "# not ours\n");
    assert!(
        stderr.contains(&format!(
            "refusing to remove {}: not installed by caddy-rs",
            zsh.display()
        )),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".bashrc")).unwrap(),
        "# user rc\n",
        "uninstall modified a shell rc file"
    );
    assert!(
        !config.join("powershell/Completions/caddy-rs.ps1").exists(),
        "uninstall created a file"
    );
}

#[test]
fn completion_install_refuses_to_overwrite_a_foreign_file() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();
    let bash = data.join("bash-completion/completions/caddy-rs");
    std::fs::create_dir_all(bash.parent().unwrap()).unwrap();
    std::fs::write(&bash, "# user managed\n").unwrap();

    let (code, _stdout, stderr) = run_with_layout(
        &["completion", "install", "--shell", "bash"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains(&format!("refusing to overwrite {}", bash.display())),
        "{stderr}"
    );
    assert_eq!(std::fs::read_to_string(&bash).unwrap(), "# user managed\n");
}

#[cfg(unix)]
#[test]
fn completion_install_refuses_a_dangling_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();
    let bash = data.join("bash-completion/completions/caddy-rs");
    std::fs::create_dir_all(bash.parent().unwrap()).unwrap();
    let destination = temp.path().join("outside-completions/caddy-rs");
    std::os::unix::fs::symlink(&destination, &bash).unwrap();
    assert!(!destination.exists(), "the symlink must start dangling");

    let (code, _stdout, stderr) = run_with_layout(
        &["completion", "install", "--shell", "bash"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains(&format!("refusing to replace {}", bash.display())),
        "{stderr}"
    );
    assert!(stderr.contains("symbolic link"), "{stderr}");
    assert!(
        !destination.exists(),
        "install followed the dangling link and created {}",
        destination.display()
    );
    assert!(
        std::fs::symlink_metadata(&bash)
            .unwrap()
            .file_type()
            .is_symlink(),
        "install replaced the link instead of refusing"
    );
}

#[test]
fn completion_install_writes_atomically_and_leaves_no_temporary_file() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();

    let (code, _stdout, stderr) = run_with_layout(
        &["completion", "install", "--shell", "bash"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");

    let directory = data.join("bash-completion/completions");
    let bash = directory.join("caddy-rs");
    let (_, script, _) = run(&["completion", "bash"]);
    let installed = std::fs::read_to_string(&bash).unwrap();
    assert!(
        installed.ends_with(&script),
        "installed file is not the complete generated script"
    );
    let leftovers: Vec<String> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "caddy-rs")
        .collect();
    assert!(
        leftovers.is_empty(),
        "atomic write left temporary files: {leftovers:?}"
    );
}

#[test]
fn completion_install_and_uninstall_dry_run_write_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();

    let (code, stdout, stderr) = run_with_layout(
        &["completion", "install", "--dry-run"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("would install"), "{stdout}");
    let bash = data.join("bash-completion/completions/caddy-rs");
    assert!(!bash.exists(), "dry-run created {}", bash.display());
    assert!(!data.exists(), "dry-run created {}", data.display());

    let (code, _stdout, stderr) = run_with_layout(
        &["completion", "install"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(bash.exists());

    let (code, stdout, stderr) = run_with_layout(
        &["completion", "uninstall", "--dry-run"],
        &home,
        &data,
        &config,
        "/bin/bash",
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains(&format!("would remove {}", bash.display())),
        "{stdout}"
    );
    assert!(bash.exists(), "dry-run removed {}", bash.display());
}

#[test]
fn completion_shell_flag_rejects_unknown_values_with_the_accepted_set() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();

    for action in ["install", "uninstall"] {
        let (code, _stdout, stderr) = run_with_layout(
            &["completion", action, "--shell", "tcsh"],
            &home,
            &data,
            &config,
            "/bin/bash",
        );
        assert_eq!(code, 1, "{action}: {stderr}");
        assert!(
            stderr.contains("unknown shell `tcsh` for --shell"),
            "{stderr}"
        );
        assert!(stderr.contains("bash, zsh, fish, powershell"), "{stderr}");
    }
}

#[test]
fn completion_install_without_a_detected_shell_fails() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("xdg-data");
    let config = temp.path().join("xdg-config");
    std::fs::create_dir_all(&home).unwrap();

    let (code, _stdout, stderr) =
        run_with_layout(&["completion", "install"], &home, &data, &config, "/bin/sh");
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("no supported shell detected"), "{stderr}");
    assert!(stderr.contains("bash, zsh, fish, powershell"), "{stderr}");
}

/// Run the binary against a synthetic HOME/XDG layout so tests never mutate the real home.
fn run_with_layout(
    args: &[&str],
    home: &Path,
    data: &Path,
    config: &Path,
    shell: &str,
) -> (i32, String, String) {
    let output = Command::new(binary())
        .args(args)
        .env("HOME", home)
        .env("XDG_DATA_HOME", data)
        .env("XDG_CONFIG_HOME", config)
        .env("PATH", home.join("empty-bin"))
        .env("SHELL", shell)
        .output()
        .expect("run caddy-rs with a synthetic home");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
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

// ---- `caddy-rs respond` (real spawned process, real HTTP responses) --------------------------
//
// Each test starts the compiled binary, reads the `Server address:` line Caddy documents, issues
// a real HTTP/1.1 request, and asserts the status line, the headers Caddy's `static_response`
// handler sets, and the body. The helpers kill the child on drop, so a failing assertion cannot
// leave a listener behind.

use std::io::{BufRead, BufReader};
use std::sync::mpsc;

/// A spawned `caddy-rs respond` process plus a line reader for its stdout.
struct RespondProcess {
    child: Child,
    lines: mpsc::Receiver<String>,
    log: std::path::PathBuf,
}

impl RespondProcess {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Send SIGTERM and wait for a graceful exit, returning the captured stderr.
    fn terminate(&mut self) -> String {
        // SAFETY: `child.id()` is this live child's pid; SIGTERM is a valid signal.
        unsafe { libc::kill(self.child.id() as libc::c_int, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if self.child.try_wait().expect("poll respond child").is_some() {
                break;
            }
            if Instant::now() >= deadline {
                self.stop();
                panic!(
                    "respond did not exit after SIGTERM\nstderr:\n{}",
                    std::fs::read_to_string(&self.log).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The next stdout line, or a panic naming the child's stderr.
    fn next_line(&mut self) -> String {
        match self.lines.recv_timeout(Duration::from_secs(15)) {
            Ok(line) => line,
            Err(error) => {
                self.stop();
                panic!(
                    "respond printed no `Server address:` line ({error})\nstderr:\n{}",
                    std::fs::read_to_string(&self.log).unwrap_or_default()
                );
            }
        }
    }

    /// The next `Server address:` line's address.
    fn next_address(&mut self) -> SocketAddr {
        let line = self.next_line();
        let address = line
            .strip_prefix("Server address: ")
            .unwrap_or_else(|| panic!("unexpected respond stdout line: {line:?}"));
        address
            .parse()
            .unwrap_or_else(|error| panic!("unparsable address {address:?}: {error}"))
    }
}

impl Drop for RespondProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn `caddy-rs respond` with `args`, optionally feeding `stdin`.
fn spawn_respond(directory: &Path, args: &[&str], stdin: Option<&str>) -> RespondProcess {
    let mut command = Command::new(binary());
    command.arg("respond").args(args);
    spawn_respond_command(command, directory, stdin)
}

/// Spawn an already-built `respond` command (used to inject process environment and descriptors).
fn spawn_respond_command(
    command: Command,
    directory: &Path,
    stdin: Option<&str>,
) -> RespondProcess {
    let Some(data) = stdin else {
        return spawn_respond_with_stdin(command, directory, Stdio::null());
    };
    let mut process = spawn_respond_with_stdin(command, directory, Stdio::piped());
    let mut pipe = process.child.stdin.take().expect("respond stdin pipe");
    pipe.write_all(data.as_bytes())
        .expect("write respond stdin");
    drop(pipe);
    process
}

/// Spawn an already-built `respond` command with an explicit stdin descriptor, so tests can also
/// redirect stdin from a regular file (a FIFO is covered by `Stdio::piped`).
fn spawn_respond_with_stdin(
    mut command: Command,
    directory: &Path,
    stdin: Stdio,
) -> RespondProcess {
    let log = directory.join("respond.stderr");
    let file = std::fs::File::create(&log).expect("create respond stderr log");
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::from(file))
        .stdin(stdin);
    let mut child = command.spawn().expect("spawn caddy-rs respond");
    let stdout = child.stdout.take().expect("respond stdout pipe");
    let (sender, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    RespondProcess { child, lines, log }
}

/// An HTTP/1.1 response with headers preserved (lower-cased names) and the raw body.
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Send one HTTP/1.1 request to `address` (an unspecified bind is reached over IPv4 loopback).
fn http_exchange(address: SocketAddr, method: &str) -> HttpResponse {
    let target = if address.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], address.port()))
    } else {
        address
    };
    let mut stream =
        TcpStream::connect_timeout(&target, Duration::from_secs(5)).expect("connect respond");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    write!(
        stream,
        "{method} / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response header terminator")
        + 4;
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status code");
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    HttpResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&response[split..]).into_owned(),
    }
}

/// A contiguous pair of free loopback ports (a `respond --listen` port range).
fn free_port_pair() -> u16 {
    for base in 20000..60000 {
        let first = TcpListener::bind(("127.0.0.1", base));
        let second = TcpListener::bind(("127.0.0.1", base + 1));
        if first.is_ok() && second.is_ok() {
            return base;
        }
    }
    panic!("no contiguous free port pair");
}

#[test]
fn respond_serves_the_documented_default_and_prints_the_listen_address() {
    let directory = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut server = spawn_respond(directory.path(), &["--listen", &listen], None);

    let line = server.next_line();
    assert_eq!(line, format!("Server address: {listen}"));
    let address = server.next_address_after(&line);
    let response = http_exchange(address, "GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "");
    // Caddy writes no Content-Type for an empty body (`static_response` only infers one from a
    // non-empty body).
    assert_eq!(response.header("content-type"), None);
    assert_eq!(response.header("content-length"), Some("0"));

    // A random-port listener (`:0`, the default) prints the actual bound address.
    let mut random = spawn_respond(directory.path(), &["--listen", ":0"], None);
    let line = random.next_line();
    assert!(line.starts_with("Server address: "), "{line}");
    let address = random.next_address_after(&line);
    assert_ne!(address.port(), 0);
    assert_eq!(http_exchange(address, "GET").status, 200);
}

/// Parse the address out of an already-consumed `Server address:` line.
impl RespondProcess {
    fn next_address_after(&self, line: &str) -> SocketAddr {
        line.strip_prefix("Server address: ")
            .unwrap_or_else(|| panic!("unexpected respond stdout line: {line:?}"))
            .parse()
            .unwrap_or_else(|error| panic!("unparsable address in {line:?}: {error}"))
    }
}

#[test]
fn respond_serves_custom_status_body_and_headers() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut server = spawn_respond(
        directory.path(),
        &[
            "--listen",
            "127.0.0.1:0",
            "--status",
            "418",
            "--body",
            "teapot",
            "--header",
            "X-Test: yes",
            "--header",
            "Content-Language: en",
        ],
        None,
    );
    let address = server.next_address();
    let response = http_exchange(address, "GET");
    assert_eq!(response.status, 418);
    assert_eq!(response.body, "teapot");
    assert_eq!(response.header("x-test"), Some("yes"));
    assert_eq!(response.header("content-language"), Some("en"));
    assert_eq!(
        response.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(response.header("content-length"), Some("6"));

    // JSON bodies get Caddy's implicit application/json type; an explicit header still wins.
    let mut json = spawn_respond(
        directory.path(),
        &["--listen", "127.0.0.1:0", "--body", "{\"a\":1}"],
        None,
    );
    let response = http_exchange(json.next_address(), "GET");
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.body, "{\"a\":1}");

    let mut explicit = spawn_respond(
        directory.path(),
        &[
            "--listen",
            "127.0.0.1:0",
            "--body",
            "hello",
            "--header",
            "Content-Type: application/xml",
        ],
        None,
    );
    let response = http_exchange(explicit.next_address(), "GET");
    assert_eq!(response.header("content-type"), Some("application/xml"));
}

#[test]
fn respond_honours_head_semantics_and_caddy_positional_arguments() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut server = spawn_respond(
        directory.path(),
        &["--listen", "127.0.0.1:0", "--body", "hello"],
        None,
    );
    let response = http_exchange(server.next_address(), "HEAD");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "");
    assert_eq!(
        response.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(response.header("content-length"), Some("5"));

    // A 3-digit unnamed argument is the status code.
    let mut status = spawn_respond(directory.path(), &["--listen", "127.0.0.1:0", "404"], None);
    let response = http_exchange(status.next_address(), "GET");
    assert_eq!(response.status, 404);
    assert_eq!(response.body, "");

    // Any other unnamed argument is the body.
    let mut body = spawn_respond(
        directory.path(),
        &["--listen", "127.0.0.1:0", "hello"],
        None,
    );
    let response = http_exchange(body.next_address(), "GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hello");

    // `--status`/`--body` override the argument; a literal "404" body with a 200 status works.
    let mut overridden = spawn_respond(
        directory.path(),
        &["--listen", "127.0.0.1:0", "--status", "201", "404"],
        None,
    );
    let response = http_exchange(overridden.next_address(), "GET");
    assert_eq!(response.status, 201);
    assert_eq!(response.body, "404");
}

#[test]
fn respond_reads_a_piped_stdin_body() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut server = spawn_respond(
        directory.path(),
        &["--listen", "127.0.0.1:0"],
        Some("from-stdin"),
    );
    let response = http_exchange(server.next_address(), "GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "from-stdin");
    assert_eq!(
        response.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
}

#[test]
fn respond_ignores_a_regular_file_stdin_redirect() {
    let directory = tempfile::tempdir().expect("tempdir");
    let page = directory.path().join("page.html");
    std::fs::write(&page, "file-body").expect("write stdin file");
    let stdin = std::fs::File::open(&page).expect("open stdin file");
    let mut command = Command::new(binary());
    command.arg("respond").args(["--listen", "127.0.0.1:0"]);
    // Caddy reads a body only from a named pipe (`os.ModeNamedPipe`); a regular-file redirect
    // leaves the body empty, unlike `!stdin.is_terminal()`. A real FIFO is covered above by
    // `respond_reads_a_piped_stdin_body` (`Stdio::piped`).
    let mut server = spawn_respond_with_stdin(command, directory.path(), Stdio::from(stdin));
    let response = http_exchange(server.next_address(), "GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "");
}

#[test]
fn respond_expands_a_port_range_with_template_variables() {
    let directory = tempfile::tempdir().expect("tempdir");
    let base = free_port_pair();
    let listen = format!("127.0.0.1:{base}-{}", base + 1);
    let mut server = spawn_respond(
        directory.path(),
        &[
            "--listen",
            &listen,
            "--body",
            "n={{.N}} port={{.Port}} addr={{.Address}}",
        ],
        None,
    );
    let first = server.next_address();
    let second = server.next_address();
    assert_eq!(first.to_string(), format!("127.0.0.1:{base}"));
    assert_eq!(second.to_string(), format!("127.0.0.1:{}", base + 1));

    let response = http_exchange(first, "GET");
    assert_eq!(
        response.body,
        format!("n=0 port={base} addr=127.0.0.1:{base}")
    );
    let response = http_exchange(second, "GET");
    assert_eq!(
        response.body,
        format!("n=1 port={} addr=127.0.0.1:{}", base + 1, base + 1)
    );
}

#[test]
fn respond_writes_the_access_log_when_requested() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut server = spawn_respond(
        directory.path(),
        &[
            "--listen",
            "127.0.0.1:0",
            "--access-log",
            "--body",
            "logged",
        ],
        None,
    );
    let response = http_exchange(server.next_address(), "GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "logged");
    // A graceful shutdown flushes the buffered access-log sink; SIGKILL would not.
    let stderr = server.terminate();
    assert!(
        stderr.contains("http.log.access") && stderr.contains("\"status\":200"),
        "access log not written:\n{stderr}"
    );
}

#[test]
fn respond_rejects_debug_with_a_located_error() {
    // `--debug` maps to Caddy's debug-level internal logging, which this build does not have; it
    // must fail loudly instead of being silently ignored.
    let (code, stdout, stderr) = run_within(
        &["respond", "--debug", "--listen", "127.0.0.1:0"],
        Duration::from_secs(10),
    );
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("--debug"), "{stderr}");
    assert!(stderr.contains("not supported"), "{stderr}");
}

#[test]
fn respond_rejects_interim_1xx_statuses_with_a_located_error() {
    // Caddy sends a 1xx as an interim response and then keeps handling (200 with the body); this
    // build has no interim-response plumbing, so it must reject 1xx at startup rather than answer
    // every request with a 500.
    for status in ["100", "102", "103", "199"] {
        let (code, stdout, stderr) = run_within(
            &["respond", "--status", status, "--listen", "127.0.0.1:0"],
            Duration::from_secs(10),
        );
        assert_eq!(code, 1, "status {status}: stdout {stdout}\nstderr {stderr}");
        assert!(stdout.is_empty(), "status {status}: {stdout}");
        assert!(stderr.contains("--status"), "status {status}: {stderr}");
        assert!(stderr.contains("interim"), "status {status}: {stderr}");
        assert!(stderr.contains("200-999"), "status {status}: {stderr}");
    }
}

#[test]
#[cfg(unix)]
fn respond_ignores_systemd_socket_activation() {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;

    // Caddy's `respond` does not consult LISTEN_FDS; an inherited descriptor must not make the
    // command fail. The shell sets LISTEN_PID to the pid the final process keeps across exec.
    let directory = tempfile::tempdir().expect("tempdir");
    let inherited = TcpListener::bind("127.0.0.1:0").expect("inherited listener");
    let fd = inherited.as_raw_fd();
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("export LISTEN_PID=$$; exec \"$0\" respond --listen 127.0.0.1:0")
        .arg(binary())
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "unrelated");
    // SAFETY: the closure only duplicates a descriptor this test owns; `dup2`/`fcntl` are
    // async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if fd != 3 {
                if libc::dup2(fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut server = spawn_respond_command(command, directory.path(), None);
    let response = http_exchange(server.next_address(), "GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "");
}

#[test]
fn respond_accepts_the_network_prefixes_caddy_drops() {
    let directory = tempfile::tempdir().expect("tempdir");
    // Caddy's `buildHTTPServer` rebuilds the address with `JoinHostPort`, dropping the network
    // prefix; all of these end up as plain TCP listeners.
    let mut listens = vec!["tcp4/127.0.0.1:0", "udp/127.0.0.1:0", "udp4/127.0.0.1:0"];
    if ipv6_loopback_available() {
        listens.push("tcp6/[::1]:0");
    }
    for listen in listens {
        let mut server = spawn_respond(
            directory.path(),
            &["--listen", listen, "--body", "prefixed"],
            None,
        );
        let response = http_exchange(server.next_address(), "GET");
        assert_eq!(response.status, 200, "{listen}");
        assert_eq!(response.body, "prefixed", "{listen}");
    }
}

#[test]
fn respond_sanitizes_header_values_and_drops_bad_names_like_caddy() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut server = spawn_respond(
        directory.path(),
        &[
            "--listen",
            "127.0.0.1:0",
            "--body",
            "hi",
            "--header",
            "X-Lf: a\nb",
            "--header",
            "X-Cr: a\rb",
            "--header",
            "X-Ctl: a\u{1}b",
            "--header",
            "Bad Header: x",
            "--header",
            "X-Kept: yes",
        ],
        None,
    );
    let response = http_exchange(server.next_address(), "GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hi");
    assert_eq!(response.header("x-lf"), Some("a b"));
    assert_eq!(response.header("x-cr"), Some("a b"));
    assert_eq!(response.header("x-ctl"), Some("a b"));
    assert_eq!(response.header("x-kept"), Some("yes"));
    assert_eq!(response.header("bad header"), None);
}

#[test]
fn respond_applies_caddys_read_header_timeout() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut server = spawn_respond(directory.path(), &["--listen", "127.0.0.1:0"], None);
    let address = server.next_address();
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).expect("connect respond");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("read timeout");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .expect("write request line");
    // Caddy's `buildHTTPServer` uses a 10 s read-header timeout; a header sent after it must not
    // be answered.
    std::thread::sleep(Duration::from_secs(11));
    let _ = stream.write_all(b"X-Late: yes\r\nConnection: close\r\n\r\n");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    assert!(
        response.is_empty(),
        "server answered after its 10s header timeout: {:?}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn respond_rejects_invalid_headers_arguments_and_templates() {
    for (args, needle) in [
        (
            vec!["respond", "--header", "X-Bad", "--listen", "127.0.0.1:0"],
            "header 0: invalid format \"X-Bad\"",
        ),
        (vec!["respond", "a", "b"], "too many unflagged arguments"),
        (
            vec![
                "respond",
                "--status",
                "201",
                "--body",
                "x",
                "y",
                "--listen",
                "127.0.0.1:0",
            ],
            "unflagged argument \"y\" is overridden by flags",
        ),
        (
            vec!["respond", "--body", "{{.Foo}}", "--listen", "127.0.0.1:0"],
            "unsupported template expression",
        ),
        (
            vec!["respond", "--listen", "unixpacket//tmp/x.sock"],
            "SOCK_SEQPACKET",
        ),
        (
            vec!["respond", "--listen", "unix/relative.sock"],
            "unix socket path must be absolute",
        ),
        (
            vec!["respond", "--status", "99", "--listen", "127.0.0.1:0"],
            "--status: 99",
        ),
    ] {
        let (code, stdout, stderr) = run_within(&args, Duration::from_secs(10));
        assert_eq!(code, 1, "args {args:?}: stdout {stdout}\nstderr {stderr}");
        assert!(stdout.is_empty(), "args {args:?}: {stdout}");
        assert!(stderr.contains(needle), "args {args:?}: {stderr}");
    }
}

// ---------------------------------------------------------------------------
// `caddy storage` (T-CLI-010): parity with `caddy storage export|import`.
// ---------------------------------------------------------------------------

/// Run the binary and return raw standard output (tar archives are not UTF-8).
fn run_capture(args: &[&str]) -> (i32, Vec<u8>, String) {
    let output = Command::new(binary())
        .args(args)
        .output()
        .expect("run caddy-rs");
    (
        output.status.code().unwrap_or(-1),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Run the binary with raw bytes on standard input, returning raw standard output.
fn run_with_stdin_capture(args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>, String) {
    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn caddy-rs");
    child
        .stdin
        .as_mut()
        .expect("stdin pipe")
        .write_all(stdin)
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait for caddy-rs");
    (
        output.status.code().unwrap_or(-1),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Run the binary in `directory` with extra environment variables.
fn run_with_env(directory: &Path, env: &[(&str, &str)], args: &[&str]) -> (i32, String, String) {
    let mut command = Command::new(binary());
    command.current_dir(directory);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.args(args).output().expect("run caddy-rs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// One entry read back from a tar archive.
struct ArchivedEntry {
    name: String,
    mode: u32,
    mtime: u64,
    contents: Vec<u8>,
}

fn archive_entries(bytes: &[u8]) -> Vec<ArchivedEntry> {
    let mut entries = Vec::new();
    let mut archive = tar::Archive::new(bytes);
    for entry in archive.entries().expect("tar entries") {
        let mut entry = entry.expect("tar entry");
        let header = entry.header().clone();
        let name = entry
            .path()
            .expect("entry path")
            .to_string_lossy()
            .into_owned();
        let mode = header.mode().expect("entry mode");
        let mtime = header.mtime().expect("entry mtime");
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents).expect("entry contents");
        entries.push(ArchivedEntry {
            name,
            mode,
            mtime,
            contents,
        });
    }
    entries
}

fn read_archive(path: &Path) -> Vec<ArchivedEntry> {
    archive_entries(&std::fs::read(path).expect("read archive"))
}

/// Write a JSON config whose `storage.root` is `root`.
fn storage_config(directory: &Path, name: &str, root: &Path) -> std::path::PathBuf {
    let config = directory.join(name);
    std::fs::write(
        &config,
        format!(
            "{{\"storage\":{{\"module\":\"file_system\",\"root\":\"{}\"}}}}\n",
            root.display()
        ),
    )
    .expect("write config");
    config
}

/// Populate a Caddy-style storage tree and return its (key, contents) pairs in key order.
fn populate_storage(root: &Path) -> Vec<(&'static str, &'static str)> {
    let files = vec![
        (
            "certificates/local/example.com/example.com.crt",
            "CERT-PEM\n",
        ),
        (
            "certificates/local/example.com/example.com.key",
            "KEY-PEM\n",
        ),
        ("pki/authorities/local/root.crt", "ROOT-CA\n"),
    ];
    for (relative, contents) in &files {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create storage dir");
        std::fs::write(&path, contents).expect("write storage file");
    }
    files
}

/// A hand-built tar with one regular-file entry.
///
/// The `tar` crate refuses to *write* a name containing `..`, so the archive an attacker could hand
/// to `storage import` has to be assembled byte by byte.
fn crafted_tar(name: &str, contents: &[u8]) -> Vec<u8> {
    fn put(header: &mut [u8; 512], offset: usize, value: &[u8]) {
        header[offset..offset + value.len()].copy_from_slice(value);
    }
    assert!(
        name.len() <= 100,
        "fixture name must fit the tar name field"
    );
    let mut header = [0u8; 512];
    put(&mut header, 0, name.as_bytes());
    put(&mut header, 100, b"0000600\0");
    put(&mut header, 108, b"0000000\0");
    put(&mut header, 116, b"0000000\0");
    put(
        &mut header,
        124,
        format!("{:011o}\0", contents.len()).as_bytes(),
    );
    put(&mut header, 136, b"00000000000\0");
    put(&mut header, 156, b"0");
    put(&mut header, 257, b"ustar\0");
    put(&mut header, 263, b"00");
    header[148..156].fill(b' ');
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    put(&mut header, 148, format!("{checksum:06o}\0 ").as_bytes());
    let mut archive = header.to_vec();
    archive.extend_from_slice(contents);
    archive.resize(archive.len() + (512 - contents.len() % 512) % 512, 0);
    archive.extend_from_slice(&[0u8; 1024]);
    archive
}

#[test]
fn storage_help_matches_caddys_usage_and_flags() {
    let (code, stdout, stderr) = run(&["storage", "--help"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    for text in [
        "Usage: caddy-rs storage [COMMAND]",
        "combined in a pipeline to transfer directly from one storage to another",
        "$ caddy-rs storage export --config Caddyfile.old --output - |",
        "> caddy-rs storage import --config Caddyfile.new --input -",
        "The - argument refers to stdout and stdin, respectively.",
        "should be run as the user that owns the associated root path",
        "EXPERIMENTAL: May be changed or removed.",
        "Exports storage assets as a tarball",
        "Imports storage assets from a tarball.",
    ] {
        assert!(stdout.contains(text), "missing {text:?} in:\n{stdout}");
    }

    // Caddy's parent `storage` command has no handler: cobra prints its help and exits 0. A bare
    // `caddy-rs storage` must do the same instead of a clap "missing subcommand" error.
    let (code, bare_stdout, stderr) = run(&["storage"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    for text in [
        "Usage: caddy-rs storage [COMMAND]",
        "Exports storage assets as a tarball",
        "Imports storage assets from a tarball.",
    ] {
        assert!(
            bare_stdout.contains(text),
            "bare: missing {text:?} in:\n{bare_stdout}"
        );
    }

    let (code, stdout, stderr) = run(&["storage", "export", "--help"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    for text in [
        "Usage: caddy-rs storage export --config <path> --output <path>",
        "The contents of the configured storage module (TLS certificates, etc)",
        "are exported via a tarball.",
        "--output is required, - can be given for stdout.",
        "-c, --config <CONFIG>",
        "Input configuration file (required)",
        "-o, --output <OUTPUT>",
        "Output path",
    ] {
        assert!(stdout.contains(text), "missing {text:?} in:\n{stdout}");
    }

    let (code, stdout, stderr) = run(&["storage", "import", "--help"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    for text in [
        "Usage: caddy-rs storage import --config <path> --input <path>",
        "Imports storage assets to the configured storage module. The import file must be",
        "a tar archive.",
        "--input is required, - can be given for stdin.",
        "-c, --config <CONFIG>",
        "Configuration file to load (required)",
        "-i, --input <INPUT>",
        "Tar of assets to load (required)",
    ] {
        assert!(stdout.contains(text), "missing {text:?} in:\n{stdout}");
    }

    // The parent command appears in the top-level command list.
    let (code, stdout, stderr) = run(&["--help"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("Commands for working with Caddy's storage (EXPERIMENTAL)"),
        "{stdout}"
    );
}

#[test]
fn storage_export_writes_a_sorted_tar_of_the_storage_tree() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    let files = populate_storage(&root);
    let config = storage_config(directory.path(), "config.json", &root);
    let output = directory.path().join("storage.tar");
    // Caddy truncates the output file: a stale archive must not survive in front of the new one.
    std::fs::write(&output, b"stale bytes that are not a tar archive").unwrap();

    let (code, stdout, stderr) = run(&[
        "storage",
        "export",
        "--config",
        config.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(stdout, "");
    assert_eq!(stderr, "");

    let entries = read_archive(&output);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(
        names,
        files.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        "keys are listed in certmagic's lexical order"
    );
    for (entry, (key, contents)) in entries.iter().zip(files.iter()) {
        assert_eq!(entry.name, *key);
        assert_eq!(entry.contents, contents.as_bytes(), "contents of {key}");
        assert_eq!(entry.mode, 0o600, "mode of {key}");
        assert!(entry.mtime > 0, "mtime of {key} is {}", entry.mtime);
    }
}

#[test]
fn storage_export_to_stdout_and_import_from_stdin_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let files = populate_storage(&source);
    let source_config = storage_config(directory.path(), "source.json", &source);

    // `-` means stdout/stdin, so the documented pipeline works unchanged.
    let (code, archive, stderr) = run_capture(&[
        "storage",
        "export",
        "-c",
        source_config.to_str().unwrap(),
        "-o",
        "-",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(!archive.is_empty(), "the archive must be written to stdout");
    let entries = archive_entries(&archive);
    assert_eq!(entries.len(), files.len());

    let target = directory.path().join("target");
    std::fs::create_dir_all(&target).unwrap();
    let target_config = storage_config(directory.path(), "target.json", &target);
    let (code, stdout, stderr) = run_with_stdin_capture(
        &[
            "storage",
            "import",
            "-c",
            target_config.to_str().unwrap(),
            "-i",
            "-",
        ],
        &archive,
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "Successfully imported storage\n"
    );
    assert_eq!(stderr, "");
    for (key, contents) in &files {
        assert_eq!(
            std::fs::read(target.join(key)).expect("imported file"),
            contents.as_bytes(),
            "contents of {key}"
        );
    }
}

#[cfg(unix)]
#[test]
fn storage_import_writes_files_with_owner_only_mode() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let files = populate_storage(&source);
    let source_config = storage_config(directory.path(), "source.json", &source);
    let archive = directory.path().join("storage.tar");
    let (code, _, stderr) = run(&[
        "storage",
        "export",
        "-c",
        source_config.to_str().unwrap(),
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");

    let target = directory.path().join("target");
    let target_config = storage_config(directory.path(), "target.json", &target);
    for attempt in 0..2 {
        let (code, stdout, stderr) = run(&[
            "storage",
            "import",
            "-c",
            target_config.to_str().unwrap(),
            "-i",
            archive.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "attempt {attempt}: stderr: {stderr}");
        assert_eq!(stdout, "Successfully imported storage\n");
        for (key, contents) in &files {
            let path = target.join(key);
            assert_eq!(std::fs::read(&path).unwrap(), contents.as_bytes());
            // certmagic replaces the target through a 0600 temporary file, so a re-import tightens
            // an existing key's mode too.
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode of {key} on attempt {attempt}");
        }
        // Loosen one file between imports to prove the second import resets it.
        let loosened = target.join(files[0].0);
        std::fs::set_permissions(&loosened, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}

#[test]
fn storage_requires_config_and_output_or_input_flags() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    std::fs::create_dir_all(&root).unwrap();
    let config = storage_config(directory.path(), "config.json", &root);
    let missing = directory.path().join("missing.json");
    let unwritable_output = directory.path().join("out.tar");
    let missing_archive = directory.path().join("missing.tar");
    let cases: Vec<(Vec<&str>, i32, &str)> = vec![
        (vec!["storage", "export"], 1, "--config is required"),
        (
            vec!["storage", "export", "-c", config.to_str().unwrap()],
            1,
            "--output is required",
        ),
        (vec!["storage", "import"], 1, "--config is required"),
        (
            vec!["storage", "import", "-c", config.to_str().unwrap()],
            1,
            "--input is required",
        ),
        (
            vec![
                "storage",
                "export",
                "-c",
                missing.to_str().unwrap(),
                "-o",
                unwritable_output.to_str().unwrap(),
            ],
            1,
            "cannot read config",
        ),
        (
            vec![
                "storage",
                "import",
                "-c",
                config.to_str().unwrap(),
                "-i",
                missing_archive.to_str().unwrap(),
            ],
            1,
            "opening input file",
        ),
    ];
    for (args, expected, needle) in cases {
        let (code, stdout, stderr) = run(&args);
        assert_eq!(code, expected, "args {args:?}: stderr {stderr}");
        assert_eq!(stdout, "", "args {args:?}");
        assert!(
            stderr.contains(needle),
            "args {args:?}: missing {needle:?} in {stderr}"
        );
    }
}

#[test]
fn storage_export_fails_when_the_storage_root_is_missing_and_leaves_the_output_alone() {
    let directory = tempfile::tempdir().unwrap();
    let missing_root = directory.path().join("does-not-exist");
    let config = storage_config(directory.path(), "config.json", &missing_root);
    let output = directory.path().join("storage.tar");
    let (code, _, stderr) = run(&[
        "storage",
        "export",
        "--config",
        config.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("cannot list storage") && stderr.contains("does-not-exist"),
        "{stderr}"
    );
    // Caddy lists the keys before it opens the output, so a listing failure creates nothing.
    assert!(!output.exists(), "the output file must not be created");
}

#[test]
fn storage_export_writes_an_empty_archive_for_an_empty_root() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("empty");
    std::fs::create_dir_all(&root).unwrap();
    let config = storage_config(directory.path(), "config.json", &root);
    let output = directory.path().join("empty.tar");
    let (code, _, stderr) = run(&[
        "storage",
        "export",
        "-c",
        config.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let bytes = std::fs::read(&output).unwrap();
    assert!(archive_entries(&bytes).is_empty());
    assert!(
        !bytes.is_empty() && bytes.len() % 512 == 0,
        "an empty tar is the two zero blocks: {} bytes",
        bytes.len()
    );
}

#[test]
fn storage_rejects_an_unsupported_storage_module() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.json");
    std::fs::write(
        &config,
        "{\"storage\":{\"module\":\"s3\",\"root\":\"/x\"}}\n",
    )
    .unwrap();
    let (code, _, stderr) = run(&[
        "storage",
        "export",
        "-c",
        config.to_str().unwrap(),
        "-o",
        directory.path().join("out.tar").to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("unsupported storage module `s3`") && stderr.contains("file_system"),
        "{stderr}"
    );
}

#[test]
fn storage_import_refuses_archive_keys_outside_the_root() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    std::fs::create_dir_all(&root).unwrap();
    let config = storage_config(directory.path(), "config.json", &root);

    for (name, needle) in [
        ("../escape.txt", "refusing key"),
        ("/etc/escape.txt", "refusing key"),
    ] {
        let archive = crafted_tar(name, b"pwned\n");
        let (code, _, stderr) = run_with_stdin_capture(
            &[
                "storage",
                "import",
                "-c",
                config.to_str().unwrap(),
                "-i",
                "-",
            ],
            &archive,
        );
        assert_eq!(code, 3, "key {name:?}: stderr {stderr}");
        assert!(
            stderr.contains("reading archive") && stderr.contains(needle),
            "key {name:?}: {stderr}"
        );
    }
    // Nothing was written outside the configured root.
    assert!(!directory.path().join("escape.txt").exists());
    assert!(!directory.path().join("storage").join("escape.txt").exists());
}

#[test]
fn storage_import_reports_a_non_tar_input_and_leaves_the_root_empty() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    std::fs::create_dir_all(&root).unwrap();
    let config = storage_config(directory.path(), "config.json", &root);
    let (code, stdout, stderr) = run_with_stdin_capture(
        &[
            "storage",
            "import",
            "-c",
            config.to_str().unwrap(),
            "-i",
            "-",
        ],
        b"this is not a tar archive",
    );
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(
        stdout.is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&stdout)
    );
    assert!(stderr.contains("reading archive"), "{stderr}");
    assert_eq!(
        std::fs::read_dir(&root).unwrap().count(),
        0,
        "a broken archive stores nothing"
    );
}

#[test]
fn storage_accepts_an_empty_archive_as_a_successful_no_op() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    std::fs::create_dir_all(&root).unwrap();
    let config = storage_config(directory.path(), "config.json", &root);
    // Go's tar.Reader reports EOF for a zero-byte input, so Caddy imports nothing and succeeds.
    let (code, stdout, stderr) = run_with_stdin_capture(
        &[
            "storage",
            "import",
            "-c",
            config.to_str().unwrap(),
            "-i",
            "-",
        ],
        b"",
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "Successfully imported storage\n"
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn storage_defaults_to_the_caddy_data_directory() {
    let directory = tempfile::tempdir().unwrap();
    let data_home = directory.path().join("xdg");
    let storage_root = data_home.join("caddy");
    std::fs::create_dir_all(storage_root.join("acme")).unwrap();
    std::fs::write(storage_root.join("acme/acme-v02.api.json"), "ACCOUNT\n").unwrap();
    let config = directory.path().join("config.json");
    std::fs::write(&config, "{}\n").unwrap();
    let output = directory.path().join("storage.tar");

    let (code, _, stderr) = run_with_env(
        directory.path(),
        &[
            ("XDG_DATA_HOME", data_home.to_str().unwrap()),
            ("CADDY_RS_DATA_DIR", ""),
        ],
        &[
            "storage",
            "export",
            "-c",
            config.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let entries = read_archive(&output);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, vec!["acme/acme-v02.api.json"]);
}

#[test]
fn storage_accepts_a_caddyfile_config() {
    let directory = tempfile::tempdir().unwrap();
    let data_home = directory.path().join("xdg");
    let storage_root = data_home.join("caddy");
    std::fs::create_dir_all(storage_root.join("pki/authorities/local")).unwrap();
    std::fs::write(storage_root.join("pki/authorities/local/root.crt"), "CA\n").unwrap();
    // A `Caddyfile` name selects the Caddyfile adapter, like Caddy's LoadConfig.
    std::fs::write(
        directory.path().join("Caddyfile"),
        ":0 {\n\trespond \"hi\"\n}\n",
    )
    .unwrap();
    let output = directory.path().join("storage.tar");

    let (code, _, stderr) = run_with_env(
        directory.path(),
        &[
            ("XDG_DATA_HOME", data_home.to_str().unwrap()),
            ("CADDY_RS_DATA_DIR", ""),
        ],
        &[
            "storage",
            "export",
            "-c",
            "Caddyfile",
            "-o",
            output.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let entries = read_archive(&output);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, vec!["pki/authorities/local/root.crt"]);
}

#[test]
fn storage_export_reports_an_unwritable_output_path() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    std::fs::create_dir_all(&root).unwrap();
    let config = storage_config(directory.path(), "config.json", &root);
    let output = directory.path().join("no-such-dir").join("storage.tar");
    let (code, _, stderr) = run(&[
        "storage",
        "export",
        "-c",
        config.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("opening output file"), "{stderr}");
}

#[test]
fn storage_import_cleans_a_dot_prefixed_archive_key_into_the_root() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    std::fs::create_dir_all(&root).unwrap();
    let config = storage_config(directory.path(), "config.json", &root);
    // `./key` names the same file as `key` (Go's `filepath.Join` cleans it away), so it is imported
    // rather than refused with the unsafe names.
    let archive = crafted_tar("./acme/account.json", b"ACCOUNT\n");
    let (code, stdout, stderr) = run_with_stdin_capture(
        &[
            "storage",
            "import",
            "-c",
            config.to_str().unwrap(),
            "-i",
            "-",
        ],
        &archive,
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "Successfully imported storage\n"
    );
    assert_eq!(
        std::fs::read(root.join("acme/account.json")).unwrap(),
        b"ACCOUNT\n"
    );
}

// ---- `start` (background run with pingback) ---------------------------------------------------

/// Write a valid JSON config with a random admin port, used by the `start`/`--pingback` tests.
fn start_config(directory: &Path) -> std::path::PathBuf {
    let path = directory.join("config.json");
    std::fs::write(
        &path,
        r#"{"admin":{"listen":"127.0.0.1:0"},"apps":{"http":{"servers":{}}}}"#,
    )
    .expect("write start config");
    path
}

/// Write a valid `Caddyfile` with random listener/admin ports, used by the no-flag `start` test.
fn start_caddyfile(directory: &Path) -> std::path::PathBuf {
    let path = directory.join("Caddyfile");
    std::fs::write(
        &path,
        "{\n\tadmin 127.0.0.1:0\n}\n\n:0 {\n\trespond \"ok\"\n}\n",
    )
    .expect("write start Caddyfile");
    path
}

/// The pid printed by `start` on success.
fn start_pid(stdout: &str) -> i32 {
    let rest = stdout
        .split("pid=")
        .nth(1)
        .unwrap_or_else(|| panic!("no pid in start output: {stdout}"));
    rest.split(')')
        .next()
        .expect("pid closing parenthesis")
        .trim()
        .parse()
        .expect("numeric pid")
}

/// Liveness via `kill(pid, 0)`, ignoring a zombie that a non-reaping PID 1 has not collected.
fn process_alive(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let state = stat
                .rfind(')')
                .and_then(|end| stat[end + 1..].trim_start().chars().next());
            state != Some('Z')
        }
        Err(_) => false,
    }
}

fn wait_for_process_exit(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    !process_alive(pid)
}

#[test]
fn start_reports_success_and_runs_in_the_background() {
    let directory = tempfile::tempdir().unwrap();
    let config = start_config(directory.path());
    let stdout_path = directory.path().join("start.stdout");
    let stderr_path = directory.path().join("start.stderr");
    // Redirect to files rather than pipes: the background child inherits both streams, so a pipe
    // would stay open (and `output()` would block) until the child exits.
    let status = Command::new(binary())
        .current_dir(directory.path())
        .args(["start", "--config", config.to_str().unwrap()])
        .env("XDG_CONFIG_HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path())
        .stdout(Stdio::from(
            std::fs::File::create(&stdout_path).expect("create stdout"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr_path).expect("create stderr"),
        ))
        .status()
        .expect("run caddy-rs start");
    let stdout = std::fs::read_to_string(&stdout_path).expect("read start stdout");
    let stderr = std::fs::read_to_string(&stderr_path).expect("read start stderr");
    assert!(status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("Successfully started Caddy (pid="),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("Caddy is running in the background"),
        "stdout: {stdout}"
    );
    let pid = start_pid(&stdout);
    assert!(process_alive(pid), "child {pid} is not running: {stderr}");
    // The child reports its admin address on the inherited stderr; after SIGTERM that endpoint
    // must be gone too, not just the process.
    let admin = stderr
        .lines()
        .find_map(|line| line.strip_prefix("caddy-rs: admin API listening on "))
        .map(str::to_string);
    assert!(admin.is_some(), "child reported no admin API: {stderr}");
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGTERM) },
        0,
        "SIGTERM {pid}"
    );
    assert!(
        wait_for_process_exit(pid, Duration::from_secs(5)),
        "child {pid} survived SIGTERM"
    );
    if let Some(admin) = admin {
        assert!(
            TcpStream::connect(&admin).is_err(),
            "admin endpoint {admin} outlived the process"
        );
    }
}

#[test]
fn start_without_config_loads_caddyfile_in_the_working_directory() {
    let directory = tempfile::tempdir().unwrap();
    start_caddyfile(directory.path());
    let stdout_path = directory.path().join("start.stdout");
    let stderr_path = directory.path().join("start.stderr");
    let status = Command::new(binary())
        .current_dir(directory.path())
        .args(["start"])
        .env("XDG_CONFIG_HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path())
        .stdout(Stdio::from(
            std::fs::File::create(&stdout_path).expect("create stdout"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr_path).expect("create stderr"),
        ))
        .status()
        .expect("run caddy-rs start");
    let stdout = std::fs::read_to_string(&stdout_path).expect("read start stdout");
    let stderr = std::fs::read_to_string(&stderr_path).expect("read start stderr");
    assert!(status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("Successfully started Caddy (pid="),
        "stdout: {stdout}"
    );
    let pid = start_pid(&stdout);
    assert!(process_alive(pid), "child {pid} is not running: {stderr}");
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGTERM) },
        0,
        "SIGTERM {pid}"
    );
    assert!(
        wait_for_process_exit(pid, Duration::from_secs(5)),
        "child {pid} survived SIGTERM"
    );
}

#[test]
fn start_without_config_or_caddyfile_reports_child_failure() {
    let directory = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_in(directory.path(), &["start"]);
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("no configuration to load"),
        "child error not surfaced: {stderr}"
    );
    assert!(
        stderr.contains("caddy process exited with error"),
        "start did not report the child exit: {stderr}"
    );
    assert!(
        !stdout.contains("Successfully started Caddy") && !stdout.contains("pid="),
        "start reported an orphan as running: {stdout}"
    );
}

#[test]
fn start_reports_child_failure_without_leaving_an_orphan() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.json");
    let (code, stdout, stderr) = run_in(
        directory.path(),
        &["start", "--config", missing.to_str().unwrap()],
    );
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains("caddy process exited with error") || stderr.contains("cannot"),
        "stderr: {stderr}"
    );
    assert!(
        !stdout.contains("Successfully started Caddy") && !stdout.contains("pid="),
        "start reported an orphan as running: {stdout}"
    );
}

#[test]
fn start_rejects_watch_and_pidfile_before_spawning() {
    let directory = tempfile::tempdir().unwrap();
    for (args, flag) in [
        (vec!["start", "--watch"], "--watch"),
        (vec!["start", "--pidfile", "caddy.pid"], "--pidfile"),
    ] {
        let (code, stdout, stderr) = run_in(directory.path(), &args);
        assert_eq!(code, 1, "{flag}: stdout: {stdout}\nstderr: {stderr}");
        assert!(stderr.contains(flag), "{flag}: stderr: {stderr}");
        assert!(
            stderr.contains("not supported") || stderr.contains("not implemented"),
            "{flag}: stderr: {stderr}"
        );
        assert!(!stdout.contains("pid="), "{flag} spawned a child: {stdout}");
    }
}

#[test]
fn run_pingback_handshake_echoes_the_parent_token() {
    let directory = tempfile::tempdir().unwrap();
    let config = start_config(directory.path());
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind pingback listener");
    let address = listener.local_addr().expect("pingback address");
    let mut child = Command::new(binary())
        .current_dir(directory.path())
        .args([
            "run",
            "--config",
            config.to_str().unwrap(),
            "--pingback",
            &address.to_string(),
        ])
        .env("XDG_CONFIG_HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn caddy-rs run --pingback");
    let token: Vec<u8> = (0u8..32).collect();
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(&token)
        .expect("write pingback token");
    drop(child.stdin.take());
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut connection = None;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                connection = Some(stream);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("accept pingback connection: {error}"),
        }
    }
    let mut connection = connection.expect("run --pingback did not connect back");
    connection
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let mut confirmation = [0u8; 32];
    connection
        .read_exact(&mut confirmation)
        .expect("read pingback confirmation");
    assert_eq!(confirmation.as_slice(), token.as_slice());
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::c_int, libc::SIGTERM) },
        0,
        "SIGTERM pingback child"
    );
    assert!(
        wait_for_child_exit(&mut child, Duration::from_secs(10)).is_some(),
        "run --pingback child did not exit after SIGTERM"
    );
}

// ---- `file-server` command -------------------------------------------------------------------
//
// Each test spawns the compiled binary, waits for the listener to accept connections, issues a
// real HTTP/1.1 request, and asserts the status/body. The helpers kill the child on drop, so a
// failing assertion cannot leave a listener behind.

/// A spawned `caddy-rs file-server` process; killed on drop.
struct FileServerProcess {
    child: Child,
    log: std::path::PathBuf,
}

impl FileServerProcess {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for FileServerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn `caddy-rs file-server` with `args`.
fn spawn_file_server(directory: &Path, args: &[&str]) -> FileServerProcess {
    let log = directory.join("file-server.stderr");
    let file = std::fs::File::create(&log).expect("create file-server stderr log");
    let child = Command::new(binary())
        .arg("file-server")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .expect("spawn caddy-rs file-server");
    FileServerProcess { child, log }
}

/// Start `file-server` for `root` on a free loopback port, retrying if the port was taken before
/// the child could bind it. Returns the running process and the port.
fn start_file_server(directory: &Path, root: &Path, extra: &[&str]) -> (FileServerProcess, u16) {
    for attempt in 0..START_ATTEMPTS {
        let port = free_port();
        let listen = format!("127.0.0.1:{port}");
        let mut args: Vec<String> = vec![
            "--root".to_string(),
            root.display().to_string(),
            "--listen".to_string(),
            listen,
        ];
        args.extend(extra.iter().map(|argument| argument.to_string()));
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut process = spawn_file_server(directory, &arg_refs);
        let ready = wait_until(Duration::from_secs(15), || {
            TcpStream::connect(("127.0.0.1", port)).is_ok()
        });
        if ready {
            return (process, port);
        }
        let stderr = process.stderr();
        let lost_port = is_address_in_use(&stderr);
        process.stop();
        if lost_port && attempt + 1 < START_ATTEMPTS {
            continue;
        }
        panic!("file-server did not start on 127.0.0.1:{port}\nstderr:\n{stderr}");
    }
    unreachable!("file-server start attempts exhausted")
}

/// GET `path` from the `file-server` child, returning the parsed response.
///
/// A just-started listener can accept and then reset a connection while its runtime is still
/// finishing `apply` (the readiness probe only proves the socket is bound), so a transient I/O
/// error is retried before the test fails.
fn file_server_get(process: &FileServerProcess, port: u16, path: &str) -> HttpResponse {
    let target = SocketAddr::from(([127, 0, 0, 1], port));
    let mut response = Vec::new();
    let mut last_error = None;
    for _ in 0..100 {
        let attempt = (|| -> std::io::Result<Vec<u8>> {
            let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(5))?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            write!(
                stream,
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response)?;
            Ok(response)
        })();
        match attempt {
            Ok(bytes) => {
                response = bytes;
                last_error = None;
                break;
            }
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    if let Some(error) = last_error {
        panic!(
            "file-server request for {path} failed: {error}\nstderr:\n{}",
            process.stderr()
        );
    }
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response header terminator")
        + 4;
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status code");
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    HttpResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&response[split..]).into_owned(),
    }
}

#[test]
fn file_server_serves_an_existing_file() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("site");
    std::fs::create_dir_all(&root).expect("create site root");
    std::fs::write(root.join("hello.txt"), "hello from file-server\n").expect("write file");

    let (_server, port) = start_file_server(directory.path(), &root, &[]);
    let response = file_server_get(&_server, port, "/hello.txt");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hello from file-server\n");
    assert!(
        response
            .header("content-type")
            .unwrap_or_default()
            .starts_with("text/plain"),
        "content type: {:?}",
        response.header("content-type")
    );
}

#[test]
fn file_server_returns_404_for_a_missing_file() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("site");
    std::fs::create_dir_all(&root).expect("create site root");

    let (_server, port) = start_file_server(directory.path(), &root, &[]);
    let response = file_server_get(&_server, port, "/missing.txt");
    assert_eq!(response.status, 404);
}

#[test]
fn file_server_browse_lists_a_directory() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("site");
    let sub = root.join("sub");
    std::fs::create_dir_all(&sub).expect("create sub directory");
    std::fs::write(sub.join("inner.txt"), "inner\n").expect("write inner file");

    let (_server, port) = start_file_server(directory.path(), &root, &["--browse"]);
    // A directory request without the trailing slash is redirected first, like stock Caddy.
    let response = file_server_get(&_server, port, "/sub/");
    assert_eq!(response.status, 200);
    assert!(
        response.body.contains("inner.txt"),
        "listing body: {}",
        response.body
    );
}

#[test]
fn file_server_rejects_domain_with_a_located_error_before_starting_a_listener() {
    let directory = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let output = Command::new(binary())
        .args([
            "file-server",
            "--domain",
            "example.com",
            "--listen",
            &listen,
        ])
        .current_dir(directory.path())
        .output()
        .expect("run caddy-rs file-server --domain");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr:\n{stderr}");
    assert!(stderr.contains("--domain"), "stderr:\n{stderr}");
    assert!(stderr.contains("automatic HTTPS"), "stderr:\n{stderr}");
    assert!(
        !stderr.contains("Caddy serving static files"),
        "the command must not start a server; stderr:\n{stderr}"
    );
    assert!(
        TcpListener::bind(("127.0.0.1", port)).is_ok(),
        "the listener address must not have been bound"
    );
}

#[test]
fn file_server_rejects_flags_whose_capability_is_missing() {
    for (flag, expected) in [
        ("--reveal-symlinks", "--reveal-symlinks"),
        ("--debug", "--debug"),
    ] {
        let (code, _stdout, stderr) = run(&["file-server", flag]);
        assert_eq!(code, 1, "{flag} should fail; stderr:\n{stderr}");
        assert!(stderr.contains(expected), "{flag} stderr:\n{stderr}");
    }
    let (code, _stdout, stderr) = run(&["file-server", "--file-limit", "5"]);
    assert_eq!(code, 1, "--file-limit should fail; stderr:\n{stderr}");
    assert!(stderr.contains("--file-limit"), "stderr:\n{stderr}");
    let (code, _stdout, stderr) = run(&["file-server", "--precompressed", "brotli"]);
    assert_eq!(code, 1, "--precompressed should fail; stderr:\n{stderr}");
    assert!(stderr.contains("--precompressed"), "stderr:\n{stderr}");
    assert!(
        stderr.contains("http.precompressed.brotli"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn file_server_help_lists_the_command_and_its_flags() {
    let (code, stdout, stderr) = run(&["--help"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert!(stdout.contains("file-server"), "help:\n{stdout}");

    let (code, stdout, stderr) = run(&["file-server", "--help"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    for flag in [
        "--domain",
        "--root",
        "--listen",
        "--browse",
        "--reveal-symlinks",
        "--templates",
        "--access-log",
        "--debug",
        "--file-limit",
        "--no-compress",
        "--precompressed",
    ] {
        assert!(stdout.contains(flag), "help is missing {flag}:\n{stdout}");
    }
    assert!(
        stdout.contains("file-server [--domain"),
        "usage should follow stock's synopsis:\n{stdout}"
    );
}
