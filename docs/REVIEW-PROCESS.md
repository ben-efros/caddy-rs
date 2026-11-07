# Review process

Every change to this repository lands through three independent gates. Only one of them can
approve, and it is a human.

## 1. CI (blocking)

`main` is protected: a pull request is required, and the following checks must pass before merge.

| Check | What it proves |
|---|---|
| `test` (workflow `ci`) | the workspace formats, builds and tests green with `--locked` |
| `clippy` | no `clippy::correctness` findings (the deny-by-default lint group) |
| `audit` | no known advisory in the dependency graph (RustSec) |
| `release` | on tags only: reproducible build + SBOM |

A failing or missing check cannot be merged. Force-pushes and branch deletion on `main` are
disabled, history is linear, and review conversations must be resolved.

## 2. Advisory LLM review (non-blocking)

`.github/workflows/ai-review.yml` posts a review comment on pull requests. Configuration:

- `LLM_API_KEY` (secret, required to enable) — an API key for an OpenAI-compatible endpoint;
- `LLM_ENDPOINT` and `LLM_MODEL` (repository variables, optional).

The review is **advisory by design**:

- it is not a required status check, and the job cannot fail the build (`continue-on-error`);
- it never approves, never requests changes, and has no write access to code;
- without `LLM_API_KEY` it prints a skip notice and exits successfully, so forks and mirrors are
  unaffected;
- the diff is size-limited and secret-redacted before it leaves the runner.

Its purpose is to catch the defects a human skims past — unbounded reads, panics on network input,
missing tests — not to replace judgement.

## 3. Human review (blocking)

A maintainer (see `.github/CODEOWNERS`) must approve. Security-sensitive paths additionally require
a code-owner review:

`crates/tls/`, `crates/admin/src/trust.rs`, `crates/admin/src/origin.rs`, `crates/plug/`,
`.github/workflows/`, `SECURITY.md`.

## What a reviewer checks, in order

1. **Security first.** Untrusted network input is bounded and typed; TLS and authentication decisions
   fail closed; nothing logs secrets; no new `unsafe`.
2. **Compatibility honesty.** If accepted configuration, emitted JSON or runtime behaviour changes,
   the compatibility docs move with it, anything differing from Caddy is registered as a divergence,
   and unsupported constructs fail with a located error rather than being approximated.
3. **Tests that can fail.** A behaviour change without a test, or a test whose assertion cannot fail,
   is a defect.
4. **Operational cost.** New dependencies are justified and pinned; build time and binary size are
   considered; the change does not silently widen the attack surface of a `minimal` build.

## Security reports

Vulnerabilities are not reviewed in public. Follow [`SECURITY.md`](../SECURITY.md).
