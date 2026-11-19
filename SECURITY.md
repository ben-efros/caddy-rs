# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability
reporting on this repository (Security → Advisories → "Report a vulnerability"), which notifies the
maintainers without disclosing details publicly.

Include, as far as you can:

- the version or commit you tested,
- the configuration required to reproduce it (redact credentials and keys),
- the impact you believe it has, and
- any proof-of-concept steps.

You will get an acknowledgement, an assessment, and a coordinated disclosure timeline.

## Supported versions

Security fixes land on the current release line. Preview releases are supported until the next
preview supersedes them, so run a current build if you are exposing the server to untrusted traffic.

## Scope

Useful reports include configuration that bypasses validation and produces unsafe behaviour, request
handling flaws (path traversal, header injection, request smuggling), TLS or certificate-handling
mistakes, and sandbox escapes in the module runtime.

The following are not vulnerabilities in this project by themselves: behaviour inherited from the
Caddy configuration model that is documented as intentional, and configurations that this build
refuses with a located error (refusing a configuration is the intended failure mode).

## Dependency advisory gate

`cargo audit` runs in CI (`.github/workflows/security.yml`, cargo-audit 0.22.2) against the
**vendored** RustSec database in `.cargo/advisory-db/`, with `--no-fetch`, so the verdict depends
only on committed files and needs no network. The policy — which advisories are accepted, and why —
is `.cargo/audit.toml`; `--deny warnings` makes informational advisories (unmaintained, unsound,
yanked) gate too, so accepting one is a reviewed entry rather than log noise.

Run the same gate locally, offline:

```sh
cd caddy-rs
cargo audit --file Cargo.lock --deny warnings --db .cargo/advisory-db --no-fetch
```

The database is pinned at a commit recorded in `.cargo/advisory-db/SNAPSHOT`. It does not update
itself: refreshing it is a reviewed commit (the procedure is in that file), so a new upstream
advisory becomes a visible diff and a deliberate decision instead of an overnight CI failure.
See also `docs/operations/RELEASE-READINESS.md` in the program repository for the release gate.
