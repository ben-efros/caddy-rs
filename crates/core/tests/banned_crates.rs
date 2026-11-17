//! Dependency ban guard (T-OPS-018, implemented by T-OPS-106c).
//!
//! Two crates must never again appear anywhere in the workspace's dependency graph:
//!
//!   * `bincode` -- RUSTSEC-2025-0141 has `patched = []` in the advisory database and matches
//!     EVERY published version (including 2.0.1). No upgrade can ever satisfy the audit gate,
//!     so the only correct posture is delete, never ignore: `.cargo/audit.toml` must not carry
//!     the advisory id either. The ecdysis upgrade pipe now uses `serde-wincode` + `wincode`,
//!     which reproduces bincode 1.3.3's bytes exactly (vendor/ecdysis/tests/golden_wire.rs).
//!   * `pin-utils` 0.1.x -- RUSTSEC-2026-0441 (unmaintained); it arrived only through nix's
//!     default `aio` feature, which the vendored ecdysis manifest turns off.
//!
//! The check is offline, deterministic and reads the committed lockfile: it needs no network,
//! no cargo-audit (absent on this host) and no advisory DB. It fails the build the moment either
//! name comes back, whatever introduced it.

use std::fs;
use std::path::{Path, PathBuf};

const BANNED: [&str; 2] = ["bincode", "pin-utils"];

/// Directories containing a `Cargo.lock` that is committed and gates a build or an audit.
fn lockfile_dirs() -> Vec<PathBuf> {
    // `CARGO_MANIFEST_DIR` is `<repo>/crates/core`, so the workspace root is two levels up.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/core")
        .to_path_buf();
    // The workspace lockfile is what `cargo audit --file` and every offline build use. `pm/`
    // and `crates/plug/template/` ship their own committed lockfiles to users of those crates.
    vec![
        root.clone(),
        root.join("pm"),
        root.join("crates/plug/template"),
    ]
}

/// Package names declared by `[[package]]` stanzas of a Cargo.lock (TOC-independent: the
/// filename is always a bare `Cargo.lock` line).
fn locked_package_names(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .collect()
}

#[test]
fn workspace_lockfiles_contain_no_banned_crates() {
    let mut checked = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for dir in lockfile_dirs() {
        let path = dir.join("Cargo.lock");
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            // A directory without a lockfile (e.g. `pm/` before its first build) is not a
            // failure: there is nothing to ban. Report which ones were skipped.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!(
                    "banned-crates guard: skipping {} (no lockfile)",
                    path.display()
                );
                continue;
            }
            Err(e) => panic!("cannot read {}: {e}", path.display()),
        };
        checked += 1;
        let names = locked_package_names(&contents);
        for banned in BANNED {
            if let Some(hit) = names.iter().find(|n| n.as_str() == banned) {
                failures.push(format!(
                    "{} locks `{hit}` (banned; RUSTSEC-2025-0141 for bincode has patched = [], \
                     RUSTSEC-2026-0441 for pin-utils). Remove the dependency -- do not add an \
                     ignore to .cargo/audit.toml.",
                    path.display()
                ));
            }
        }
    }

    assert!(
        checked > 0,
        "banned-crates guard checked no lockfiles -- the paths in lockfile_dirs() are wrong"
    );
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn audit_policy_does_not_ignore_the_banned_advisories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/core")
        .to_path_buf();
    let audit_toml = root.join(".cargo/audit.toml");
    let Ok(contents) = fs::read_to_string(&audit_toml) else {
        eprintln!("banned-crates guard: no {}", audit_toml.display());
        return;
    };
    // The ban is delete-don't-ignore: an ignore entry would re-admit the crate silently.
    for id in ["RUSTSEC-2025-0141", "RUSTSEC-2026-0441"] {
        assert!(
            !contents.contains(id),
            "{} must not ignore {id}; bincode and pin-utils are banned outright",
            audit_toml.display()
        );
    }
}

#[test]
fn lockfile_parser_detects_a_banned_name() {
    // Self-test of the detector: a mutant lockfile body must be reported, so a bug in the
    // parser cannot turn the guard above into a no-op.
    let mutant = "version = 3\n\n[[package]]\nname = \"bincode\"\nversion = \"2.0.1\"\n";
    let names = locked_package_names(mutant);
    assert!(names.iter().any(|n| n == "bincode"), "{names:?}");
}
