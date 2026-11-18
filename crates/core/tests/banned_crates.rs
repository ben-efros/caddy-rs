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

/// Directories whose lockfile is required to be free of every [`BANNED`] crate.
///
/// `pm/` is a SEPARATE workspace with its own lockfile and is out of this scope: it reaches
/// `chrono` only through `axum-test` -> `expect-json` (a dev-dependency, and every published
/// `expect-json` depends on chrono), and CI's advisory gate runs `cargo audit --file Cargo.lock`
/// from the `caddy-rs` submodule root, so `pm/Cargo.lock` is never audited. The audited surface is
/// the root lockfile (plus the plug template, which ships to plugin authors).
/// A crate that must not appear in an audited lockfile.
struct Banned {
    /// Package name as it appears in a `[[package]]` stanza.
    name: &'static str,
    /// The advisory that forces removal rather than upgrade.
    advisory: &'static str,
    /// Why no version can ever satisfy the gate.
    why: &'static str,
    /// Whether the ban also covers the auxiliary `pm/` workspace.
    ///
    /// `pm/` is a separate workspace whose lockfile CI never audits (the gate runs
    /// `cargo audit --file Cargo.lock` from the `caddy-rs` submodule root). It reaches `chrono`
    /// only via the dev-dependency `axum-test` -> `expect-json`, and every published
    /// `expect-json` depends on chrono, so there is no version to move to. Keeping chrono out of
    /// `pm/` would mean dropping `axum-test`, which is a test-harness rewrite, not a dependency
    /// edge. `bincode`/`pin-utils` are absent from `pm/` and stay banned everywhere.
    audited_in_pm: bool,
}

const BANNED: [Banned; 3] = [
    Banned {
        name: "bincode",
        advisory: "RUSTSEC-2025-0141",
        why: "patched = [] matches every published version",
        audited_in_pm: true,
    },
    Banned {
        name: "pin-utils",
        advisory: "RUSTSEC-2026-0441",
        why: "unmaintained; reached only via nix's default `aio` feature",
        audited_in_pm: true,
    },
    Banned {
        name: "chrono",
        advisory: "RUSTSEC-2026-0543",
        why: "unmaintained, patched = []; replaced by caddy_rs_core::Timestamp",
        audited_in_pm: false,
    },
];

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
    //
    // NOTE for anyone adding a crate here: the program-level SBOM
    // (`docs/operations/SBOM.json`) is generated from these same lockfiles, so a ban that
    // changes them also changes the SBOM. That regeneration is owned by `scripts/merge-task.sh`
    // in the program repository, which runs it *after* staging the submodule gitlink bump; it is
    // deliberately not done on the branch, because until the gitlink moves the program-root
    // SBOM and the branch lockfiles are by definition inconsistent.
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
        let is_pm = dir.file_name().map(|n| n == "pm").unwrap_or(false);
        for banned in &BANNED {
            if is_pm && !banned.audited_in_pm {
                continue;
            }
            if let Some(hit) = names.iter().find(|n| n.as_str() == banned.name) {
                failures.push(format!(
                    "{} locks `{hit}` (banned; {}: {}). Remove the dependency -- do not add an \
                     ignore to .cargo/audit.toml.",
                    path.display(),
                    banned.advisory,
                    banned.why,
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
    for id in [
        "RUSTSEC-2025-0141",
        "RUSTSEC-2026-0441",
        "RUSTSEC-2026-0543",
    ] {
        assert!(
            !contents.contains(id),
            "{} must not ignore {id}; the banned crates are banned outright",
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
