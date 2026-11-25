//! Acceptance harness for the zero-downtime restart claim (T-CORE-104, ADR-0044 §2).
//!
//! # Why this exists
//!
//! ADR-0044 §2 states a gap-free upgrade as a *design constraint*, not a demonstrated result, and
//! `graceful_restart_inherit.rs` says so explicitly: "The gap-free-across-exec measurement is
//! `T-CORE-104`". This file is that measurement. It runs the real binary, opens connections, drives
//! a live `SIGUSR2` restart, and records counts -- resets and refusals -- rather than a pass flag.
//!
//! # The two numbers, and why they are both needed
//!
//! A restart is only gap-free if BOTH hold across the transition:
//!
//! 1. **no reset** -- a connection established before the restart still completes afterwards, i.e.
//!    the old generation drained instead of having its sockets torn down;
//! 2. **no refusal** -- a connection *attempt* during the transition is never `ECONNREFUSED`, i.e.
//!    the listener was inherited rather than closed-and-rebound.
//!
//! Either alone is insufficient: a server that keeps existing connections but stops accepting shows
//! zero resets and many refusals; one that rebinds shows refusals with no resets if it is quick.
//!
//! # Why the negative control matters more than the positive result
//!
//! `zero_downtime` asserts `0`. A harness that can only ever print `0` would produce that same
//! number if it were broken -- if it never opened a socket, never sent the signal, or measured the
//! wrong port. So [`killing_the_process_is_measured_as_refusals_and_resets`] runs the *identical*
//! measurement against `SIGKILL`, where the answer must be bad, and asserts the counters are
//! non-zero. The instrument is proven to register failure before the zero is believed.
//!
//! # What this does not prove
//!
//! In-flight *requests* are not timed: the assertion is that connections survive, not that a request
//! issued during the drain completes within a bound. Per-connection accounting is what the task asks
//! for and what these counters record.

#![cfg(feature = "graceful-restart")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_caddy-rs")
}

/// A free port, taken by binding to port 0 and immediately releasing it.
///
/// A port that is free now can be taken by something else before the child binds it, so this is a
/// best-effort choice rather than a reservation; the harness fails loudly if the child never serves.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// A running server serving `respond "ok" 200` on `port`, killed on drop so a failing assertion
/// cannot leave a process behind holding the port.
struct Server {
    child: Child,
    log_path: std::path::PathBuf,
}

impl Server {
    fn start(dir: &std::path::Path, port: u16) -> Server {
        let config = dir.join("Caddyfile");
        // `admin off`: the measurement is about the serving listener, and tests run concurrently
        // in one process, so a fixed admin port would make them collide and the child exit 1.
        std::fs::write(
            &config,
            format!("{{\n\tadmin off\n}}\n:{port} {{\n\trespond \"ok\" 200\n}}\n"),
        )
        .expect("write the Caddyfile");
        let child = Command::new(binary())
            .args([
                "run",
                "--config",
                config.to_str().expect("utf-8 path"),
                "--adapter",
                "caddyfile",
            ])
            .stdout(Stdio::null())
            // The child's stderr is kept in a file rather than discarded: when it fails to start,
            // the reason is the whole point, and a null stderr turns a clear failure into "did not
            // begin serving".
            .stderr(Stdio::from(
                std::fs::File::create(dir.join("caddy-rs.stderr")).expect("create the log file"),
            ))
            .spawn()
            .expect("spawn caddy-rs");
        let mut server = Server {
            child,
            log_path: dir.join("caddy-rs.stderr"),
        };
        server.wait_until_serving(port);
        server
    }

    /// Poll until the port answers, so the harness never measures its own start-up as downtime.
    fn wait_until_serving(&mut self, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "caddy-rs exited with {status} before it began serving on port {port}:\n{}",
                    self.stderr_log()
                );
            }
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("caddy-rs did not begin serving on port {port} within 30s");
    }

    /// The child's captured stderr, for failure messages.
    fn stderr_log(&self) -> String {
        std::fs::read_to_string(self.log_path.clone()).unwrap_or_default()
    }

    fn signal(&self, signal: i32) {
        // `kill` is invoked rather than pulling in a signal crate for one call; the child's pid is
        // the argument, so there is no pattern matching to get wrong.
        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.child.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -{signal} failed");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The counters the task asks for: opened, reset, refused. A `u64` per counter, shared by threads.
#[derive(Default)]
struct Counters {
    opened: AtomicU64,
    reset: AtomicU64,
    refused: AtomicU64,
}

/// Hold one connection open across the restart, then use it and report whether it survived.
fn hold_connection(
    port: u16,
    counters: Arc<Counters>,
    release: Arc<AtomicU64>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut stream = match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                counters.opened.fetch_add(1, Ordering::Relaxed);
                stream
            }
            Err(_) => {
                counters.refused.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        // Wait for the harness to release us, which it does *after* the restart has been signalled.
        let deadline = Instant::now() + Duration::from_secs(60);
        while release.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        // The connection was established before the restart. If the old generation tore it down
        // instead of draining, this write or read fails -- that is the reset being counted.
        let request = b"GET / HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n";
        let survived = stream
            .write_all(request)
            .and_then(|()| {
                let mut buffer = Vec::new();
                stream.read_to_end(&mut buffer)?;
                Ok(buffer)
            })
            .map(|buffer| buffer.starts_with(b"HTTP/1.1 200"))
            .unwrap_or(false);
        if !survived {
            counters.reset.fetch_add(1, Ordering::Relaxed);
        }
    })
}

/// Attempt new connections continuously; each refusal during the transition is the gap being closed.
fn hammer(port: u16, counters: Arc<Counters>, stop: Arc<AtomicU64>) {
    while stop.load(Ordering::SeqCst) == 0 {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                drop(stream);
                counters.opened.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                counters.refused.fetch_add(1, Ordering::Relaxed);
            }
            // Any other error (a reset mid-handshake, a timeout) is not a refusal but is still a
            // failure to be served, so it is counted as one rather than silently ignored.
            Err(_) => {
                counters.refused.fetch_add(1, Ordering::Relaxed);
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Run the measurement: `holders` connections held across the transition, a hammer running through
/// it, and the given signal sent in the middle. Returns the counters.
fn measure(signal: i32, holders: usize) -> (u64, u64, u64) {
    // Unique per measurement, not per process: cargo runs the tests in this file concurrently, so
    // a process-wide directory would have the two measurements overwrite each other's Caddyfile and
    // each poll the other's port -- which shows up as "did not begin serving", not as a wrong count.
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "caddy-rs-zero-downtime-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    let port = free_port();
    let server = Server::start(&dir, port);

    let counters = Arc::new(Counters::default());
    let release = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicU64::new(0));

    let held: Vec<_> = (0..holders)
        .map(|_| hold_connection(port, Arc::clone(&counters), Arc::clone(&release)))
        .collect();

    let stop_hammer = Arc::clone(&stop);
    let hammer_counters = Arc::clone(&counters);
    let hammerer = thread::spawn(move || hammer(port, hammer_counters, stop_hammer));

    // Let both loops reach steady state before the transition, so the window measured is the
    // restart rather than start-up.
    thread::sleep(Duration::from_millis(500));
    let opened_before = counters.opened.load(Ordering::Relaxed);

    server.signal(signal);

    // Keep hammering through the transition, then stop and let the holders finish.
    thread::sleep(Duration::from_secs(2));
    stop.store(1, Ordering::SeqCst);
    let _ = hammerer.join();
    release.store(1, Ordering::SeqCst);
    for handle in held {
        let _ = handle.join();
    }

    let opened = counters.opened.load(Ordering::Relaxed);
    let reset = counters.reset.load(Ordering::Relaxed);
    let refused = counters.refused.load(Ordering::Relaxed);
    // The harness must have observed *something* after the transition, or it measured nothing and
    // its zero cannot be believed. Note what counts as activity: under SIGUSR2 the hammer keeps
    // opening connections, so `opened` grows; under SIGKILL every attempt is refused, so `opened`
    // correctly stops growing and only `refused` moves. Requiring `opened` to grow would therefore
    // fail the negative control precisely when the kill worked -- which it did, 1 run in 5.
    assert!(
        opened > opened_before || refused > 0,
        "the harness observed no connection activity after the transition began ({opened} opened, \
         {opened_before} before, {refused} refused); it measured nothing and cannot be believed"
    );
    let _ = std::fs::remove_dir_all(&dir);
    (opened, reset, refused)
}

/// The claim: a graceful restart neither resets an established connection nor refuses a new one.
#[test]
fn zero_downtime() {
    let (opened, reset, refused) = measure(libc::SIGUSR2, 5);
    assert_eq!(
        reset, 0,
        "{reset} connection(s) established before the restart were reset; {opened} were opened in \
         total, so the old generation did not drain them"
    );
    assert_eq!(
        refused, 0,
        "{refused} connection attempt(s) were refused during the restart ({opened} opened in \
         total); the listener was rebound rather than inherited"
    );
}

/// The negative control: the same measurement, on a process that is killed outright.
///
/// This is what makes [`zero_downtime`]'s zero meaningful. `SIGKILL` cannot drain and cannot hand
/// over a listener, so refusals are guaranteed; if this test ever reports zero, the instrument is
/// broken and `zero_downtime` proves nothing.
#[test]
fn killing_the_process_is_measured_as_refusals_and_resets() {
    let (_opened, reset, refused) = measure(libc::SIGKILL, 3);
    assert!(
        refused > 0,
        "SIGKILL produced no refusals, so this harness cannot detect an outage and \
         `zero_downtime`'s zero is not evidence"
    );
    assert!(
        reset > 0,
        "SIGKILL left every established connection usable, so this harness cannot detect a torn-down \
         connection and `zero_downtime`'s zero is not evidence"
    );
}

/// The failed-child case (T-CORE-103, ADR-0044 §2.4): a restart whose child cannot initialise must
/// leave the *parent* serving.
///
/// `graceful_restart.rs` already has a test named for this property, but it asserts that the error
/// string contains "still serving" -- it never starts a parent, fails a child, and shows the parent
/// answering. This is that proof: the parent is running and serving, the configuration on disk is
/// replaced with one that cannot be adapted, `SIGUSR2` asks for a restart, and the parent must still
/// answer on the same port afterwards.
///
/// This is the case that decides whether the §2 ordering is real. If the parent stopped accepting
/// while it waited for the child, a bad configuration would be an outage -- which is the whole reason
/// the readiness handshake exists.
#[test]
fn a_failed_child_leaves_the_parent_serving() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "caddy-rs-failed-child-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    let port = free_port();
    let server = Server::start(&dir, port);
    assert_eq!(
        serve_status(port),
        200,
        "the parent must be serving before the restart"
    );

    // Replace the configuration with one that cannot adapt. The child re-reads the same path, so it
    // exits before becoming ready; the parent must survive that.
    std::fs::write(
        dir.join("Caddyfile"),
        format!(":{port} {{\n\tnonexistent_directive_xyz\n}}\n"),
    )
    .expect("write the bad Caddyfile");

    server.signal(libc::SIGUSR2);
    // Give the child time to start, fail, and be reported. This is not a race against a timeout: the
    // parent blocks on the readiness pipe, so once the child has exited the outcome is decided.
    thread::sleep(Duration::from_secs(3));

    assert_eq!(
        serve_status(port),
        200,
        "a restart whose child failed to initialise took the parent down; ADR-0044 §2.4 requires the \
         old generation to keep serving"
    );
}

/// One request to `port`, returning the status code, or 0 if nothing answered.
fn serve_status(port: u16) -> u16 {
    use std::io::Write as _;
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return 0;
    };
    let _ = stream.write_all(b"GET / HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    text.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// One request to the Unix admin socket, returning the status code, or 0 if nothing answered.
fn admin_status(socket: &std::path::Path) -> u16 {
    use std::io::Write as _;
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket) else {
        return 0;
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    let _ =
        stream.write_all(b"GET /config/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// The Unix admin socket is not inherited through the binder: the child binds it itself while the
/// parent still serves it until the child is ready. The child must replace the parent's *live*
/// socket (the admin liveness probe that refuses to steal a running process's socket must not
/// apply to an upgrade child), and the old process must then exit cleanly without unlinking the
/// path that now belongs to the new one. This test ran with `admin off` before, so the probe
/// breaking upgrades went unnoticed.
#[test]
fn an_upgrade_hands_the_unix_admin_socket_to_the_new_process() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "caddy-rs-admin-upgrade-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    let port = free_port();
    let socket = dir.join("admin.sock");
    let config = dir.join("config.json");
    std::fs::write(&config, serde_json_config(port, &socket)).expect("write the config");
    let log_path = dir.join("caddy-rs.stderr");
    let mut parent = Command::new(binary())
        .args([
            "run",
            "--config",
            config.to_str().expect("utf-8 path"),
            "--adapter",
            "json",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(&log_path).expect("create the log file"),
        ))
        .spawn()
        .expect("spawn caddy-rs");
    let log = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(30);
    while serve_status(port) != 200 || admin_status(&socket) != 200 {
        assert!(
            Instant::now() < deadline,
            "the parent never served on the port and the admin socket:\n{}",
            log()
        );
        thread::sleep(Duration::from_millis(50));
    }
    let cleanup = |dir: &std::path::Path| {
        // The new process is a child of the old one (fork/exec), not of the test.
        let _ = Command::new("pkill")
            .arg("-f")
            .arg(dir.to_str().expect("utf-8 path"))
            .status();
    };

    let status = Command::new("kill")
        .arg(format!("-{}", libc::SIGUSR2))
        .arg(parent.id().to_string())
        .status()
        .expect("run kill");
    assert!(status.success());

    // The parent reports the hand-over once the child is ready. If the child cannot bind the
    // admin socket (the liveness probe refusing a socket the parent still serves) it never becomes
    // ready and the parent logs "FAILED, still serving" instead.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !log().contains("the new process is ready") {
        if Instant::now() >= deadline || log().contains("graceful restart FAILED") {
            let _ = parent.kill();
            let _ = parent.wait();
            cleanup(&dir);
            panic!(
                "the new process never became ready (does the admin liveness probe block an \
                 upgrade child?)\n{}",
                log()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Stop the old process; its shutdown must leave the replaced admin path alone.
    let status = Command::new("kill")
        .arg(format!("-{}", libc::SIGTERM))
        .arg(parent.id().to_string())
        .status()
        .expect("run kill");
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(30);
    let exit = loop {
        if let Some(exit) = parent.try_wait().expect("poll the parent") {
            break exit;
        }
        if Instant::now() >= deadline {
            let _ = parent.kill();
            let _ = parent.wait();
            cleanup(&dir);
            panic!("the old process did not exit on SIGTERM:\n{}", log());
        }
        thread::sleep(Duration::from_millis(100));
    };
    assert!(
        exit.success(),
        "the old process exited with {exit}:\n{}",
        log()
    );

    // The new process owns the admin socket: it answers, and the old process's exit did not
    // unlink the replaced path.
    let deadline = Instant::now() + Duration::from_secs(10);
    while admin_status(&socket) != 200 {
        if Instant::now() >= deadline {
            cleanup(&dir);
            panic!(
                "no process answers on the admin socket after the upgrade (the old one removed it?)\n{}",
                log()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(serve_status(port), 200, "the new process serves the site");
    cleanup(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// JSON config: one static site on `port` and the admin API on a Unix socket.
fn serde_json_config(port: u16, socket: &std::path::Path) -> String {
    format!(
        r#"{{"admin":{{"listen":"unix/{}"}},"apps":{{"http":{{"servers":{{"s":{{"listen":[":{port}"],"routes":[{{"handle":[{{"handler":"static_response","body":"ok"}}]}}]}}}}}}}}}}"#,
        socket.display()
    )
}

/// A long-lived streaming connection survives the restart (the second case the row names).
///
/// A plain held-open TCP connection proves the socket was not torn down, but not that a stream
/// *mid-conversation* keeps flowing: a server that drains by finishing the current response would
/// pass the socket test and still truncate a stream. So this test streams: a backend writes a
/// chunked body slowly, caddy-rs reverse-proxies it, and the client must receive **every** chunk --
/// including the ones written after the restart -- and the terminating zero-length chunk.
///
/// The backend is a real HTTP server on a thread, not a mock, because the property under test is
/// that the proxy does not buffer the body before the restart.
#[test]
fn a_long_lived_streaming_response_survives_the_restart() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "caddy-rs-streaming-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("create the scratch directory");

    // A chunked backend: 40 ticks at 100ms, so the restart lands mid-stream.
    const TICKS: usize = 40;
    let backend = TcpListener::bind("127.0.0.1:0").expect("bind the backend");
    let backend_port = backend.local_addr().expect("backend addr").port();
    let backend_thread = thread::spawn(move || {
        // Serve connections in a loop rather than accepting exactly one. The readiness probe below
        // opens a connection and drops it, and the proxy forwards that to the backend; a
        // single-accept backend would serve the dead probe connection and leave the real request
        // waiting forever. That is a race, and it hung this test until it was found.
        let mut served = 0usize;
        while served < 4 {
            let Ok((mut socket, _)) = backend.accept() else {
                return;
            };
            // Bounded, because a probe connection that the proxy keeps open would otherwise block
            // here instead of being skipped.
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set the backend read timeout");
            let mut request = [0u8; 4096];
            if socket.read(&mut request).unwrap_or(0) == 0 {
                // A connection that closed (or stayed silent) before sending a request is the
                // readiness probe, not the stream under test.
                continue;
            }
            served += 1;
            serve_stream(&mut socket);
        }
    });

    let port = free_port();
    let config = dir.join("Caddyfile");
    std::fs::write(
        &config,
        format!("{{\n\tadmin off\n}}\n:{port} {{\n\treverse_proxy 127.0.0.1:{backend_port}\n}}\n"),
    )
    .expect("write the Caddyfile");
    let mut child = Command::new(binary())
        .args([
            "run",
            "--config",
            config.to_str().expect("utf-8 path"),
            "--adapter",
            "caddyfile",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(dir.join("caddy-rs.stderr")).expect("create the log file"),
        ))
        .spawn()
        .expect("spawn caddy-rs");

    // Wait for the proxy to accept, then read the stream on this thread while the restart happens.
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "the proxy never began listening on {port}"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the proxy");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: probe\r\n\r\n")
        .expect("send the request");

    // Let the stream get going, then restart while it is mid-body.
    thread::sleep(Duration::from_millis(500));
    let status = Command::new("kill")
        .arg("-USR2")
        .arg(child.id().to_string())
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -USR2 failed");

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set the read timeout");
    let mut body = Vec::new();
    let _ = stream.read_to_end(&mut body);
    let _ = child.kill();
    let _ = child.wait();
    // Not joined: the backend may still be parked in `accept()` waiting for a connection that will
    // never come, and a join would hang the test instead of failing it. The listener and its thread
    // die with the process.
    drop(backend_thread);

    let text = String::from_utf8_lossy(&body);
    let ticks: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("tick"))
        .collect();
    assert_eq!(
        ticks.len(),
        TICKS,
        "the stream was truncated across the restart: received {} of {TICKS} chunks (last: {:?})",
        ticks.len(),
        ticks.last()
    );
    assert_eq!(
        ticks.last().copied(),
        Some("tick39"),
        "the stream did not continue to its final chunk across the restart"
    );
    assert!(
        text.contains("0\r\n\r\n"),
        "the terminating chunk was lost, so the stream was cut rather than completed"
    );
}

/// Write the chunked body: 40 ticks at 100ms, then the terminating chunk.
fn serve_stream(socket: &mut TcpStream) {
    const TICKS: usize = 40;
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n";
    if socket.write_all(head.as_bytes()).is_err() {
        return;
    }
    for tick in 0..TICKS {
        let body = format!("tick{tick}\n");
        let frame = format!("{:x}\r\n{body}\r\n", body.len());
        if socket.write_all(frame.as_bytes()).is_err() {
            return;
        }
        let _ = socket.flush();
        thread::sleep(Duration::from_millis(100));
    }
    let _ = socket.write_all(b"0\r\n\r\n");
}
