# SEC-MEDIUM-HTTP compatibility note — HTTP handler hardening

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
note records the medium/low-severity security findings fixed in `crates/http` and states, per
finding, whether the fix changes behaviour relative to stock Caddy v2.11.9. Every finding below is
either behaviour-preserving (applied unconditionally, no `stock_compat` flag) or documented as a
deliberate non-change. No finding in this group introduces a divergence, so there is no proposed
register entry; the "Register" line of each section says so explicitly.

## B1. `basic_auth`: password hashing offloaded from the async workers

### Upstream source of truth (Caddy v2.11.9)

- `modules/caddyhttp/caddyauth/basicauth.go` `HTTPBasicAuth.Authenticate` verifies the password
  inline in the request goroutine; Go goroutines are cheap, so a slow bcrypt/Argon2 comparison
  stalls only that request. It also offers an optional `hash_cache` (`HashCache`) memoising
  comparisons. For unknown users Caddy verifies against the fixed fake hash
  (`BcryptHash.FakeHash` / `Argon2idHash.FakeHash`) so account existence is not a timing oracle.
- This port does **not** implement `hash_cache` (the field is not accepted by `from_json`'s
  provider schema), so nothing was removed. It is unrelated to this fix.

### Vulnerability and fix

The previous implementation called `bcrypt::verify` / `Argon2::hash_password_into` directly inside
the async `handle`. The unknown-user fake hash is bcrypt cost 14 (about a second of CPU). A tokio
worker that runs it cannot service any other task, so a handful of concurrent requests carrying bad
Basic credentials occupied every worker thread and the whole server (all vhosts, all handlers)
stopped answering until they finished.

`verify_password_offloaded` now runs bcrypt and Argon2id on the blocking pool via
`tokio::task::spawn_blocking`, behind a process-wide `tokio::sync::Semaphore` sized to
`max(2, available_parallelism)`. Requests beyond the limit wait asynchronously for a permit (they
hold no worker thread); they are **never rejected**, so the 401 challenge / continue behaviour and
status codes are exactly Caddy's. The limiter also bounds peak Argon2 memory (`m=47104` KiB per
concurrent verification). The unknown-user path goes through the identical offload with the same
fake hash for the configured algorithm, so the timing-equalisation property is unchanged. The
`plaintext` extension is a constant-time compare of a short value and stays inline.

### stock_compat

Behaviour-preserving, so unconditional: identical in both `stock_compat` settings. No 429/503 is
introduced (waiting was chosen over rejecting precisely to avoid a divergence).

### Tests

`crates/http/src/auth.rs`: `bad_credentials_do_not_starve_the_async_workers` (one-worker runtime,
eight in-flight unknown-user requests, an unrelated task must complete within 1.5 s; took ~22 s
before the fix), `hash_verification_limiter_caps_concurrency_without_rejecting`,
`hash_verification_limit_is_a_small_multiple_of_parallelism`,
`offloaded_verification_still_accepts_and_rejects_each_algorithm`, plus the pre-existing bcrypt /
Argon2id vector and timing-equalisation tests, which run unchanged through the new path.

Register: no divergence; no entry proposed.
