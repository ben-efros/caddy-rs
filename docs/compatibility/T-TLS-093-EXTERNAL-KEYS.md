# T-TLS-093 — pointer to the program-repo decision record

This implementation branch intentionally contains **no ADR and no Rust code**. ADRs and the
compatibility register are program-repository records:

- ADR: `docs/adr/0009-external-key-providers.md` on the program-repo branch `agent/T-TLS-093`
  (worktree `/root/caddy-rs/.scratch/worktrees/T-TLS-093-program`).
- Divergence: `DIV-0117` in `docs/compatibility/BEHAVIOR-DIVERGENCES.md` on that branch, plus the
  `apps.tls.certificates.pkcs11` row in `docs/compatibility/CONFIGURATION.md`.
- Follow-ups: T-TLS-096 (loader/signer), T-TLS-097 (measurement), T-TLS-098 (runbook),
  T-TLS-099 (token-held ACME CSRs) in `plan/`.

The implementation repository has no `docs/adr/` directory; the ADR is reviewed and merged in the
program repository. This file exists only so this docs-only branch is not empty.
