# Authentication (`caddy-rs-authn`)

The `caddy-rs-authn` crate is the authentication service used by the proxy manager: it hashes and
verifies passwords, issues HS256 JWT access tokens and rotating opaque refresh tokens, and verifies
TOTP codes. TOTP details live in [TOTP.md](TOTP.md); the static FIDO2/WebAuthn passkey registry and
the `caddy-rs setup` first-boot command are documented in [WEBAUTHN.md](WEBAUTHN.md).

## Status at a glance

| Capability | Status |
| --- | --- |
| Password hashing (Argon2id) and verification (Argon2id + legacy bcrypt) | Implemented |
| JWT access-token issue/verify, refresh rotation and revocation | Implemented |
| TOTP verification, replay detection, `totp_setup`/`totp_verify`/`totp_disable` | Implemented (see [TOTP.md](TOTP.md)) |
| `UserStore` trait + `MemoryUserStore` reference backend | Implemented |
| Roles / capabilities / per-row visibility | Implemented |
| HTTP login endpoint using this service | Implemented in `pm-api` (login takes an optional `totp_code`) |
| TOTP/WebAuthn enrolment HTTP endpoints | Not wired — enrolment is a service API only (see below) |
| First-boot enrolment (`caddy-rs setup`) | Command/activation-layer shell only; placeholder 503 (see [WEBAUTHN.md](WEBAUTHN.md)) |

## Configuration and defaults

`AuthnConfig` is a plain Rust struct (`#[derive(Clone)]`): it is **not** `serde`-serialisable, so it
must be built programmatically. `TotpWindow` and `JwtSecretSource` do implement `serde`, but the
containing `AuthnConfig` does not. `Debug` redacts the signing-key source.

| Field | Default | Notes |
| --- | --- | --- |
| `jwt_secret_source` | `JwtSecretSource::Ephemeral` | A random key per start; sessions do not survive a restart. Set `Master` or `File` in production. |
| `access_ttl` | 15 minutes (`Duration::from_secs(15 * 60)`) | JWT `exp` is computed from the configured TTL. |
| `refresh_ttl` | 7 days (`Duration::from_secs(7 * 24 * 60 * 60)`) | Stored as an expiry timestamp on the refresh-token record. |
| `argon2_params` | memory 19 456 KiB, time cost 2, parallelism 1 | OWASP-recommended Argon2id defaults (2024). |
| `issuer` / `audience` | `None` | Optional JWT issuer/audience claims. |
| `totp_window` | `TotpWindow::Current` | See [TOTP.md](TOTP.md). |
| `login_throttle` | 5 failures, 30 s doubling to 15 min, 10 000 tracked keys | See [Login throttling](#login-throttling). Invalid values (zero failures, zero or inverted lockouts, zero tracked keys) make `AuthnService::new` fail with `AuthError::InvalidConfig`. |

## JWT signing secret

A deployment whose sessions must survive a restart has to choose `Master` or `File` explicitly: the
default is `Ephemeral`, and the service never silently substitutes an ephemeral key for a configured
source.

| `JwtSecretSource` | Behaviour |
| --- | --- |
| `Master(String)` | The 32-byte key is `SHA-256` of the UTF-8 secret. The same secret always yields the same key. An empty secret is rejected. Use when a secret manager injects the value. |
| `File(path)` | A random 32-byte key persisted at `path`, so sessions survive restarts. Created owner-only (`0600`) on first start. |
| `Ephemeral` | A fresh random key per start (legacy, local development only): every restart invalidates all sessions. This is the default. |

`File` fails closed rather than starting with a different key, because a silent fallback would
invalidate every session without telling anyone. The rules for `path`:

- **It must be a regular file.** A symlink at the final path component is refused; the error names
  the configured path only. The file is opened and the descriptor's metadata is compared with the
  path metadata afterwards, so a swap between check and open is detected instead of trusted.
- **An existing file must contain exactly 32 bytes.** A non-empty file of any other length is a
  configuration error: it is never repaired, truncated or overwritten. The error names the path and
  the observed length; the operator must either delete the file (a new secret is generated on the
  next start, invalidating existing sessions) or configure a master secret instead.
- **A zero-byte file is repaired.** It is the unusable leftover of a crash between create and write,
  so it is replaced with a fresh random secret. Repair is reserved for that case.
- **First-start races converge.** The install writes an owner-only sibling temp file, links it into
  place without clobbering a secret another process installed first, then re-reads the on-disk key
  (up to 3 attempts, 5 ms apart) so two processes racing on first start agree on one key. The path
  must be on a filesystem that supports atomic rename and hard links.

## Passwords

`hash_password` produces an Argon2id hash using the configured `argon2_params`; if Argon2 cannot
run it falls back to bcrypt (`DEFAULT_COST`). `verify_password` detects the stored format from the
prefix: `$argon2…` hashes are verified with Argon2, `$2…` (legacy bcrypt) with bcrypt; any other
format is a `PasswordHash` error, not a silent failure.

`login` spends the same password-verification work (a dummy hash) when the username does not exist,
so response time does not reveal whether an account exists.

## Login and token lifecycle

`AuthnService::login(username, password, totp_code)` returns a `TokenPair` (access + refresh):

- Unknown username and wrong password both return `AuthError::InvalidCredentials`.
- If the account has TOTP enabled, a missing or non-matching code returns
  `AuthError::InvalidTotpCode`. A code that is cryptographically valid but already consumed (or
  older than the last accepted step) is also reported as `InvalidTotpCode` at login: the replay
  is logged by the service rather than returned, so it is not an oracle for recently valid codes.
  `totp_verify` called directly still returns `AuthError::TotpReplay`. See [TOTP.md](TOTP.md).
- While an account is locked out (see below) the call returns `AuthError::TooManyAttempts` without
  checking any credential.
- The refresh token is opaque, single-use and rotated: `refresh` atomically consumes the presented
  token and issues a new pair. A reused, revoked, expired or unknown token is rejected with a
  distinct `AuthError` (`RefreshTokenRevoked`, `RefreshTokenNotFound`, `TokenExpired`, …);
  `revoke_all_for_user` revokes every live refresh token for an account.

## Login throttling

`login` and `totp_verify` throttle failed attempts inside the service, so every embedder (the PM
API, the CLI enrolment flow, any future caller) inherits it. `AuthnConfig::login_throttle`
(`LoginThrottleConfig`) defaults to `max_failures = 5`, `base_lockout = 30 s`,
`max_lockout = 15 min`, `max_tracked = 10 000`.

- An attempt is **reserved before** the credential is checked, under one lock, so parallel guesses
  cannot all pass an "under the limit" check. A success resets the counter; a failure leaves it
  counted.
- After `max_failures` consecutive failures the key is locked for `base_lockout`; once served, each
  further failure re-locks for twice as long (capped at `max_lockout`): one guess per lockout
  period. A key idle for `2 * max_lockout` is forgiven.
- Password failures and TOTP failures during `login` share one per-username budget. Direct
  `totp_verify` calls use a separate per-account budget (`totp:<user id>`).
- Keys are the *submitted* username (ASCII-case-folded), counted whether or not the account exists,
  so lockout state does not reveal which usernames are real. Keys over 128 bytes are replaced by a
  SHA-256 digest, and at `max_tracked` entries the least recently active unlocked entry is evicted
  (locked entries last), so the tracker's memory is bounded however many usernames are submitted.
- Counters are in-process and shared by clones of the service; they reset on restart.
- Availability trade-off: anyone who knows a username can keep that account locked out (at most
  `max_lockout` at a time). That is the price of bounding online guessing.

## Enrolment API surface (not an HTTP endpoint)

TOTP enrolment is exposed as service methods, not as PM API routes:

| Method | Behaviour |
| --- | --- |
| `totp_setup(user_id)` | Generates a 20-byte random secret, stores it on the user, clears the replay state, and returns `(secret, otpauth_uri)`. **The secret becomes active immediately** — there is no pending-enrolment state. |
| `totp_verify(user_id, code)` | Verifies a code and atomically consumes its step. |
| `totp_disable(user_id)` | Removes the secret and clears the replay state. |

Because `totp_setup` activates the secret before the user proves possession, an interrupted
enrolment can leave the account requiring codes from a secret the user never saved. Recovery is to
call `totp_setup` again (or have an administrator reset the account); callers should therefore show
the secret/URI to the user before treating enrolment as complete. The `pm-api` crate does not
currently expose TOTP enrolment endpoints — its tests call `totp_setup` directly.

## Related documentation

- [TOTP.md](TOTP.md) — window, replay rules, lookback, code handling.
- [WEBAUTHN.md](WEBAUTHN.md) — static passkey registry, `apps.auth.passkeys` / `authorized_passkeys`
  formats, and the current `caddy-rs setup --auth-method webauthn` limitation.
- [CLI.md](CLI.md) — command reference (`caddy-rs run` is the command that serves a config; see
  [CLI.md#run](CLI.md#run)). The `setup` command is a caddy-rs extension documented in
  [WEBAUTHN.md](WEBAUTHN.md).
