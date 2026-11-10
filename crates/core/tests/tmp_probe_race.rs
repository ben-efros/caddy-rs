//! Temporary reproduction harness (untracked): concurrent preflights of one fresh data directory.
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn concurrent_preflight_of_a_fresh_root() {
    let rounds: usize = std::env::var("ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let threads: usize = std::env::var("THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    let mut failures = 0usize;
    for round in 0..rounds {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = std::env::temp_dir().join(format!(
            "caddy-rs-probe-race-{}-{nonce}-{round}",
            std::process::id()
        ));
        std::fs::create_dir_all(&parent).unwrap();
        let root = parent.join("data");
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::new();
        for _ in 0..threads {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                caddy_rs_core::data_dir::preflight(&root)
                    .map(|_| ())
                    .map_err(|e| {
                        format!(
                            "{:?} {:?} {:?}",
                            e.operation,
                            e.kind,
                            e.source.map(|s| s.kind())
                        )
                    })
            }));
        }
        for handle in handles {
            if let Err(error) = handle.join().unwrap() {
                failures += 1;
                if failures <= 5 {
                    eprintln!("round {round}: {error}");
                }
            }
        }
        let _ = std::fs::remove_dir_all(&parent);
    }
    eprintln!("failures={failures} rounds={rounds} threads={threads}");
    assert_eq!(failures, 0, "concurrent preflight must never fail");
}
