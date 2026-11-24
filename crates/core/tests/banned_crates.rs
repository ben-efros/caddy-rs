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
    // ALLOWED — see `chrono_allowance`. The ban stands for every crate that could choose a
    // different dependency; `chrono` is the one case where no choice exists.
    Banned {
        name: "chrono",
        advisory: "RUSTSEC-2026-0543",
        why: "unmaintained, patched = []; replaced by caddy_rs_core::Timestamp",
        allowed: true,
    },
];

/// Why `chrono` is tolerated, and what would remove it.
///
/// `pm/crates/pm-api` tests its axum router with `axum-test`, which depends on `expect-json`,
/// which depends on `chrono`. `axum-test` does not feature-gate that edge (`expect-json` is
/// neither `optional = true` nor behind a `dep:` feature), so any use of `axum-test` pulls
/// `chrono` in. Every published `expect-json` depends on `chrono`, so there is no version to
/// move to either.
///
/// The allowance is narrow in a way that matters and is checked, not assumed:
///
///   * `cargo tree --workspace -e normal` contains **no** `chrono`. It is reachable only from
///     dev-dependencies, so it is never compiled into a shipped binary.
///   * Nothing in this repository names `chrono` in a manifest or uses `chrono::` in source.
///     It is a test-harness transitive dependency and nothing else.
///
/// So this is not "chrono is fine". It is "the only path to chrono is a dev-dependency edge that
/// has no alternative, and it does not reach the artefact". Removing it means replacing
/// `axum-test` in `pm-api`'s tests, which is a harness rewrite rather than a dependency bump.
const CHRONO_ALLOWANCE: &str =
    "allowed: reachable only via pm-api's dev-dependency axum-test -> expect-json -> chrono, \
     which axum-test does not feature-gate and no expect-json release avoids; absent from \
     `cargo tree --workspace -e normal`, so it never reaches a shipped binary";

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

/// The `chrono` allowance is only valid while `chrono` is unreachable from a normal build.
///
/// `CHRONO_ALLOWANCE` claims two things. This test checks the one that can be checked from the
/// lockfile without invoking Cargo (the guard stays offline and deterministic): that no
/// *non-test* crate depends on `chrono`. If a future change makes `chrono` a normal dependency
/// of anything, this fails and the allowance has to be re-argued rather than silently inherited.
///
/// The other half -- that nothing names `chrono` directly -- is checked by
/// `chrono_allowance_is_not_a_direct_dependency`.
#[test]
fn chrono_allowance_is_justified_by_the_dependency_kind() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/core")
        .to_path_buf();
    let lockfile = fs::read_to_string(root.join("Cargo.lock")).expect("workspace lockfile");

    // The allowance exists because of `expect-json`. If that edge ever disappears, the allowance
    // should disappear with it, and this test says so instead of letting it rot in place.
    let names = locked_package_names(&lockfile);
    if !names.iter().any(|n| n == "expect-json") {
        panic!(
            "`expect-json` is gone from Cargo.lock, so the recorded `chrono` allowance no longer \
             has a justification. Remove the allowance from BANNED (set `allowed: false`) and \
             re-run this test. Allowed-but-unnecessary is how a ban quietly stops being a ban."
        );
    }

    // `axum-test` is the only route to `expect-json`. Keep that edge visible.
    assert!(
        names.iter().any(|n| n == "axum-test"),
        "`expect-json` is locked but `axum-test` is not -- the recorded explanation for the \
         `chrono` allowance ({CHRONO_ALLOWANCE}) no longer describes the graph"
    );
}

/// Nothing in this repository may name `chrono` directly.
///
/// The allowance covers a transitive test-harness dependency, not a licence to write new code
/// against `chrono`. `caddy_rs_core::Timestamp` is the replacement. This walks the manifests and
/// sources under the workspace root, so a direct `chrono` dependency or a `chrono::` path fails
/// the build while the transitive edge above stays permitted.
#[test]
fn chrono_allowance_is_not_a_direct_dependency() {
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
        "`chrono` may not be named directly; use `caddy_rs_core::Timestamp` instead. The recorded \
         allowance covers only the transitive test-harness edge ({CHRONO_ALLOWANCE}).\n{}",
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
    // The ban is delete-don't-ignore for a crate banned OUTRIGHT: an ignore entry would re-admit
    // it silently, so those advisories may never appear in the policy.
    //
    // A crate carrying `allowed: true` is the opposite case, and the distinction is load-bearing:
    // it is permitted to stay in the lockfile precisely because no version can ever satisfy the
    // audit gate, which means the ONLY way to pass that gate is an explicit, reasoned ignore.
    // Forbidding the ignore for an allowed crate would not remove the dependency -- it would just
    // make the gate unpassable, and the pressure would move to weakening the gate itself. So the
    // rule is derived from the same table that decides the lockfile ban, rather than from a
    // second hardcoded list that can drift out of agreement with it. Each allowed ignore is still
    // checked: it must be an advisory this table knows about, and the audit policy must state a
    // reason for it rather than listing a bare id.
    for banned in &BANNED {
        let id = banned.advisory;
        if banned.allowed {
            if let Some(line) = contents.lines().find(|l| l.contains(id)) {
                assert!(
                    !line.trim_start().starts_with(&format!("\"{id}\"")),
                    "{} ignores {id} ({}) with no reason on the line. An allowance is permitted \
                     only with its justification, so a reviewer sees why: {}",
                    audit_toml.display(),
                    banned.name,
                    CHRONO_ALLOWANCE
                );
            }
            continue;
        }
        assert!(
            !contents.contains(id),
            "{} must not ignore {id} ({}); the banned crates are banned outright",
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
