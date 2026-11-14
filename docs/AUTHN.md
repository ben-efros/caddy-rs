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
  older than the last accepted step) returns `AuthError::TotpReplay` — the replay signal is
  preserved through login. See [TOTP.md](TOTP.md) for how to treat it.
- The refresh token is opaque, single-use and rotated: `refresh` atomically consumes the presented
  token and issues a new pair. A reused, revoked, expired or unknown token is rejected with a
  distinct `AuthError` (`RefreshTokenRevoked`, `RefreshTokenNotFound`, `TokenExpired`, …);
  `revoke_all_for_user` revokes every live refresh token for an account.

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
