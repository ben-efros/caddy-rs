# SEC-MEDIUM status — verification evidence, known failures and open items

Snapshot of the integrated branch `claude/jovial-matsumoto-71b0b3` (base `58cf4be`, five merged
fix branches plus follow-ups) when work was paused. Read together with
[SEC-MEDIUM-SUMMARY.md](SEC-MEDIUM-SUMMARY.md). Nothing here has been pushed.

## Verification evidence

Platform: Linux (openSUSE Tumbleweed under WSL2), Rust 1.98.1, run from an ext4 copy of the tree
(the `/mnt/d` DrvFS mount reports 0777 modes, which trips the server's "world-writable data
directory" check and fails about 30 server tests for environmental reasons).

| Run | Result |
|---|---|
| `cargo test --workspace --no-fail-fast` on the final tree | 180 test binaries, **4181 passed, 3 failed** (the three below) |
| **Combined tree** (medium fixes + the High fixes + `master`, merge commit `51cffd0`, now `master`): `cargo test --workspace --no-fail-fast` | 181 test binaries, **4218 passed, 4 failed**: the three known failures below plus `caddy-rs-proxy` `client::tests::explicit_port_local_address_sets_reuseaddr_and_not_no_port`, which binds the hard-coded port 45678 and collided during the parallel run (passes 3/3 in isolation; pre-existing flake, not caused by the merge) |
| Combined tree, `zero_downtime_restart` with `graceful-restart` | 1 run of 3 failed (3 of 5 tests) while another session was running a workspace test on the same machine; 6 of 6 further runs passed (5 tests each) |
| `cargo test -p caddy-rs --features graceful-restart --test zero_downtime_restart`, 5 consecutive runs on an idle host (tree before the High fixes were merged in) | 5/5 runs, 5 tests each, all passing, including `an_upgrade_hands_the_unix_admin_socket_to_the_new_process` |
| CLI test binary (`--test cli`) 6 times under 8 busy-loop CPU hogs | base: 6/6 pass; integrated tree: 6/6 pass (133 tests each) |
| Mutation check of the proxy dial classifier (allow `system.`/`time.`/`$` as operator-controlled) | `vars_handler_cannot_smuggle_request_data_into_system_placeholders` and `template_classification_is_conservative` both fail; original restored |
| Native Windows `cargo test -p caddy-rs-pm-core -p caddy-rs-pm-compiler` | 40 and 17 passed |
| Native Windows `cargo test -p caddy-rs-tls` | 537 passed, 2 failed (pre-existing, below) |

Native Windows cannot build the rest of the workspace for pre-existing reasons (`libc` is a
non-optional dependency of `config`, `proxy`, `server`, `cli`; `sd-notify` is Unix-only;
`caddy-rs-authn` needs NASM through `aws-lc-sys`). Those crates were tested on WSL only.

## Known test failures

None of these is caused by the SEC-MEDIUM changes.

1. **`caddy-rs --test cli`: `respond_rejects_interim_1xx_statuses_with_a_located_error` and
   `respond_rejects_invalid_headers_arguments_and_templates`** fail with "caddy-rs did not exit
   within 10s" (`respond --status 100 --listen 127.0.0.1:0`, `respond --header X-Bad ...`). They
   fail identically on the **untouched base commit `58cf4be`** (2 of 2 runs each on base and on the
   integrated tree, in isolation, `cargo test -p caddy-rs --test cli respond_rejects`), so this is
   pre-existing. They passed in earlier whole-binary runs on the same machine (the CLI binary
   passed 133/133, 6 times, under load), so the cause is something about the machine or its state
   at the time (for example a process already holding `127.0.0.1:2019` or another per-user
   resource from a concurrent session). It was **not diagnosed**. Next step: run the two tests
   with nothing else running, and capture `ss -ltnp` and the child's stderr when it hangs.
2. **`caddy-rs-plug --test template`: `template_compiles_and_serves_a_request`** fails with
   "cannot update the lock file ... because --locked was passed". The test builds
   `crates/plug/template` as a separate crate with `--locked`, which needs registry access that
   the sandbox does not have. `crates/plug` is untouched by this work.
3. **`caddy-rs --test cli`: `stop_orders_the_process_exit_after_the_shutdown`** is a known
   timing-sensitive test (see the `T-CLI-STOP-EXIT-FLAKY` history). It failed once in a
   whole-workspace run under heavy parallel load and passed 5/5 in isolation and 6/6 under CPU
   stress. Treated as load flakiness.
4. **`caddy-rs-tls`, native Windows only:** `provisioner_honors_configured_trusted_roots_over_real_tls`
   and `renewal_uses_configured_trusted_roots_over_real_tls` fail with Windows error 123 (invalid
   filename). `caddy_issuer_key("http://localhost:14000/dir")` returns `localhost:14000-dir`
   (`crates/tls/src/storage.rs`, asserted by an existing test), and `:` is not a legal Windows file
   name character. Pre-existing; certmagic maps `:` to `-`, so this is also a compatibility bug.
   Not fixed because changing storage keys would orphan existing on-disk certificates.

Caution when re-running: cargo (1.98) hashes workspace members by workspace-relative path, so two
checkouts built into the **same** `CARGO_TARGET_DIR` collide and reuse each other's stale
artifacts, producing bogus compile errors or bogus test results. Use one target directory per
checkout.

## Verification gaps (stated by the implementing agents or found in review)

* Several new tests were written together with their fix, or exercise a new API, so they have no
  fail-before run against the old code. Where a fix was validated by neutering it (a mutation)
  rather than by running the old code, the per-area notes say so.
* The remote mTLS admin listener's 5 s handshake has a unit test only; there is no end-to-end
  timing test.
* The admin probe's other-user (`EACCES`) and timeout branches are covered only by the
  classification function's unit test; `/stop` plus immediate restart and `caddy-rs reload` were
  not run end to end against the new socket logic.
* No real dual-stack listener test exists for the IPv4-mapped peer handling in `proxy_protocol`;
  it is covered by unit tests and a `wrap` test with a mapped peer.
* OCSP verification is exercised end to end with fixtures generated by OpenSSL (RSA-2048, P-256,
  P-384, Ed25519) and self-generated ones; it has not been run against a live third-party
  responder.
* Stock-Caddy and Go constants quoted in the notes (admin 10 s/5 s/60 s timeouts, go-proxyproto
  10 s, Go's three-way handshake timeout minimum, certmagic OCSP refresh point) come from the
  authors' recollection, not from the pinned `external/caddy` tree. Confirm them there before the
  register text is merged.
* Clippy with `-D warnings` cannot be used as a gate: `caddy-rs-core` has 19 pre-existing
  failures. No new warnings were attributed to the added code.

## Open items and decisions for later

* **The four HIGH fixes** (`file_server` Windows path traversal, default buffered-body cap, proxy
  manager first-admin setup token, ACME key file permissions) were developed on a separate branch
  (`claude/rust-caddy-security-review-923b6e`) and are now merged together with this work. The
  merge conflicted in three files, resolved by keeping both sides: `crates/server/src/limits.rs`
  (admin limits and handshake timeout plus the buffered-body limit), `crates/server/src/http.rs`
  (`is_head` for the streaming response plus the body-failure replacement) and
  `crates/http/src/file_server.rs` (the `HideMatcher` refactor plus the Windows `\`/case
  normalisation, now `normalise_hide_path`). No new tests were written for the merge itself; it is
  covered by the existing suites above. The Windows-only `file_server` guards cannot be exercised
  here (the workspace does not build on Windows).
* Group notes list residual risks that were accepted and documented rather than fixed (RFC 1918
  reachability from request-derived dials, intermediate-directory symlink swaps in `file_server`,
  no automatic re-issue of revoked managed certificates, no internal-CA name constraints, no
  Unicode normalisation of passwords).
* Items that need a maintainer decision: whether the secure defaults listed under "Defaults that
  can break an existing deployment" in the summary are acceptable for a release, and how the
  proposed register entries are numbered.
* The `docs/compatibility` notes cite Go sources from memory; the program repository's
  `BEHAVIOR-DIVERGENCES.md` is read-only here, so each note ends with the exact text to merge.

## Housekeeping for the machine that ran this

* `D:\tmp_wsl.sh` (an empty stray file) and `D:\target-group-c-win` (a cargo target directory)
  were created by an implementing agent; deleting them was blocked by a safety check. They can be
  removed by hand.
* Build output left under the WSL home directory: `~/target-final3`, `~/target-base2`,
  `~/wt-final`, `~/wt-base` (this session) and several large target directories from earlier
  sessions (`~/target`, `~/target-wt`, `~/target-wt2`, `~/target-rvS`; tens of GB each). `C:` was
  at 100% once during this work because the WSL disk image lives there; the image does not shrink
  by itself after files are deleted.
* Native Windows build output: `D:\target-jovial-win`. Git worktrees created for this work remain
  under `D:\projects\caddy-rs\.claude\worktrees\` (`agent-*`, `base-jovial`,
  `baseline-923b6e`).
