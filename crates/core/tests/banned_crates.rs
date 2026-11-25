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

/// A crate that must not appear in an audited lockfile.
struct Banned {
    /// Package name as it appears in a `[[package]]` stanza.
    name: &'static str,
    /// The advisory that forces removal rather than upgrade.
    advisory: &'static str,
    /// Why no version can ever satisfy the gate.
    why: &'static str,
    /// Whether this crate is allowed in the lockfile at all.
    ///
    /// A `false` here is a **recorded allowance**, not an oversight: the crate is present, the
    /// reason is stated, and the removal task is named. It exists so that a tolerated dependency
    /// is visible in one place instead of being silently absent from the ban table.
    allowed: bool,
}

const BANNED: [Banned; 3] = [
    Banned {
        name: "bincode",
        advisory: "RUSTSEC-2025-0141",
        why: "patched = [] matches every published version",
        allowed: false,
    },
    Banned {
        name: "pin-utils",
        advisory: "RUSTSEC-2026-0441",
        why: "unmaintained; reached only via nix's default `aio` feature",
        allowed: false,
    },
    // Now banned outright, not allowed. T-SEC-141 replaced `axum-test` with an in-process
    // harness (`pm/crates/pm-api/src/test_harness.rs`), which removed the only path to chrono,
    // so there is no longer an edge that has no alternative.
    Banned {
        name: "chrono",
        advisory: "RUSTSEC-2026-0543",
        why: "unmaintained, patched = []; replaced by caddy_rs_core::Timestamp",
        allowed: false,
    },
];

/// Why `chrono` was once tolerated, and how it left.
///
/// Kept as a record because the reasoning explains the shape of the ban. `pm/crates/pm-api` used
/// to test its axum router with `axum-test`, which depends on `expect-json`, which depends on
/// `chrono`. `axum-test` does not feature-gate that edge, and every published `expect-json`
/// depends on `chrono`, so no version bump could remove it.
///
/// T-SEC-141 took the route this comment used to name as the only remaining one: replacing
/// `axum-test` in `pm-api`'s tests with a harness rewrite. `pm/crates/pm-api/src/test_harness.rs`
/// drives the router through `tower::ServiceExt::oneshot` and covers the API surface the suite
/// actually calls. With `axum-test` gone, `expect-json` and `chrono` left the lockfile, and
/// `chrono` moved from `allowed: true` to `allowed: false` above.
///
/// The narrow claims that justified the old allowance are still checked, and now hold for a
/// stronger reason: there is no `chrono` in the graph at all, so it is trivially absent from
/// `cargo tree --workspace -e normal` and nothing can name it in a manifest.

/// Directories containing a `Cargo.lock` that is committed and gates a build or an audit.
fn lockfile_dirs() -> Vec<PathBuf> {
    // `CARGO_MANIFEST_DIR` is `<repo>/crates/core`, so the workspace root is two levels up.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/core")
        .to_path_buf();
    // The workspace lockfile is what `cargo audit --file` and every offline build use.
    // `crates/plug/template/` ships its own committed lockfile to plugin authors.
    //
    // `pm/` is deliberately NOT listed. It is a member of this workspace (T-REL-020), not a
    // workspace root of its own, so it has no lockfile to check: `pm/Cargo.lock` was deleted when
    // the two lockfiles were reconciled into the one below. Listing it again would silently skip
    // (the NotFound arm above) and imply a second lockfile exists.
    //
    // NOTE for anyone adding a crate here: the program-level SBOM
    // (`docs/operations/SBOM.json`) is generated from these same lockfiles, so a ban that
    // changes them also changes the SBOM. That regeneration is owned by `scripts/merge-task.sh`
    // in the program repository, which runs it *after* staging the submodule gitlink bump; it is
    // deliberately not done on the branch, because until the gitlink moves the program-root
    // SBOM and the branch lockfiles are by definition inconsistent.
    vec![root.clone(), root.join("crates/plug/template")]
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
        for banned in &BANNED {
            if banned.allowed {
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

/// `chrono` is out of the graph, and this test fails if it comes back.
///
/// The old `CHRONO_ALLOWANCE` was guarded by a test that fired once `expect-json` disappeared,
/// telling the next agent to drop the allowance. T-SEC-141 removed `axum-test` (the only route to
/// `expect-json`), so that is now done: `chrono` is banned outright in `BANNED` above.
///
/// This test is the reverse ratchet. It asserts the graph really is free of `chrono`, so a
/// dependency change that drags it back in fails here rather than silently re-opening
/// RUSTSEC-2026-0543. The lockfile is read directly, keeping the guard offline and deterministic.
#[test]
fn chrono_is_absent_from_the_lockfile() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/core")
        .to_path_buf();
    let lockfile = fs::read_to_string(root.join("Cargo.lock")).expect("workspace lockfile");
    let names = locked_package_names(&lockfile);

    assert!(
        !names.iter().any(|n| n == "chrono"),
        "`chrono` is back in Cargo.lock and RUSTSEC-2026-0543 is live again. The ban in `BANNED` \
         is `allowed: false`, so this must be removed rather than re-allowlisted. The previous \
         route was pm-api's dev-dependency on `axum-test`; it now uses the in-process harness in \
         pm/crates/pm-api/src/test_harness.rs, which needs no chrono."
    );

    // Name the edges that used to carry it, so a reintroduction points at the cause.
    for crate_name in ["axum-test", "expect-json"] {
        assert!(
            !names.iter().any(|n| n == crate_name),
            "`{crate_name}` is back in Cargo.lock; it is the edge that used to pull `chrono` in. \
             If a test needs an HTTP harness, extend pm/crates/pm-api/src/test_harness.rs."
        );
    }
}

/// Nothing in this repository may name `chrono` at all.
///
/// `caddy_rs_core::Timestamp` is the replacement. This walks the manifests and sources under the
/// workspace root, so a direct `chrono` dependency or a `chrono::` path fails the build. It used
/// to permit the transitive `axum-test` edge; that edge is gone, so there is no exemption left.
#[test]
fn chrono_is_not_a_direct_dependency() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/core")
        .to_path_buf();

    let mut offences: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    // This file contains the literal `chrono::` it searches for, so it must not scan itself.
    // Skipping by canonical path keeps the exemption exact rather than skipping by filename
    // pattern, which would let a second file with the same name escape the guard.
    let this_file = fs::canonicalize(file!())
        .or_else(|_| fs::canonicalize(root.join(file!())))
        .ok();

    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip build output, VCS data and the vendored oracle: none is ours to police here.
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let is_manifest = name == "Cargo.toml";
            let is_source = name.ends_with(".rs");
            if !is_manifest && !is_source {
                continue;
            }
            if let Some(this) = &this_file {
                if fs::canonicalize(&path).ok().as_ref() == Some(this) {
                    continue;
                }
            }
            let Ok(contents) = fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            for (idx, line) in contents.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                    continue;
                }
                let hit = if is_manifest {
                    // A manifest line that assigns `chrono` as a dependency key.
                    trimmed.starts_with("chrono ") || trimmed.starts_with("chrono=")
                } else {
                    line.contains("chrono::")
                };
                if hit {
                    offences.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        scanned > 0,
        "chrono guard scanned no files -- the walk is broken"
    );
    assert!(
        offences.is_empty(),
        "`chrono` may not be named; use `caddy_rs_core::Timestamp` instead. There is no allowance: \
         T-SEC-141 removed the axum-test edge that justified one.\n{}",
        offences.join("\n")
    );
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
    // Every entry is delete-don't-ignore, and T-SEC-141 is what made that uniform: replacing
    // `axum-test` removed the only route to `chrono`, so `chrono` moved to `allowed: false` and
    // the `CHRONO_ALLOWANCE` special case went with it. For a crate banned OUTRIGHT an ignore
    // entry would re-admit it silently, so its advisory may never appear in the policy at all.
    //
    // The table still carries an `allowed` flag, and if it ever gains a `true` entry again the
    // rule for it is the one this loop used to implement: an allowed crate stays in the lockfile
    // because no version can satisfy the audit gate, so an explicit, reasoned ignore is the only
    // way to pass, and forbidding it would not remove the dependency -- it would make the gate
    // unpassable and move the pressure to weakening the gate itself. That branch is gone rather
    // than left dead, because it cannot be exercised while every entry is banned outright.
    for banned in &BANNED {
        let id = banned.advisory;
        assert!(
            !contents.contains(id),
            "{} must not mention {id} ({}); every banned crate is banned outright, so an ignore \
             entry would silently re-admit one whose advisory can never be satisfied",
            audit_toml.display(),
            banned.name
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
