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
    assert!(
        opened > opened_before,
        "the harness opened no connection after the transition began ({opened} total, \
         {opened_before} before); it measured nothing and cannot be believed"
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
