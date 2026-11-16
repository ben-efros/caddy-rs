# TOTP two-factor authentication

`caddy-rs-authn` implements time-based one-time passwords (RFC 6238) as a second factor on top of
password authentication. This page documents the parameters, the acceptance window, the replay
protection that backs it, and what is and is not wired up. Authentication tokens and the JWT secret
are documented in [AUTHN.md](AUTHN.md); passkeys and the `caddy-rs setup` command in
[WEBAUTHN.md](WEBAUTHN.md).

## Status at a glance

| Capability | Status |
| --- | --- |
| TOTP code verification (`totp_verify`) | Implemented |
| Replay / downgrade detection with bounded lookback | Implemented |
| Enrolment methods `totp_setup` / `totp_disable` | Implemented as service methods |
| PM API login with a TOTP second factor | Implemented (`totp_code` field, JSON alias `totpCode`) |
| `pm-cli` bootstrap admin with `PM_BOOTSTRAP_ADMIN_TOTP` | **Broken**: `bootstrap_admin` calls `totp_verify` before any secret is enrolled, so it can only fail with `TotpNotConfigured` (tracked as T-AUTH-002) |
| TOTP enrolment HTTP endpoints | Not implemented — no PM API route calls `totp_setup` |
| `caddy-rs setup --auth-method totp` | **Implemented** for first boot (T-SETUP-003): `step=begin` mints the secret and returns the `otpauth://` URI, `step=verify` proves possession and enrols the admin credential, closing the activation window. The credential is in process memory only (DIV-0152); persistence is T-SETUP-005. See [CLI.md](CLI.md#first-boot-enrollment) |

## Parameters and defaults

| Parameter | Value |
| --- | --- |
| Time step | 30 seconds (`TOTP_STEP_SECONDS`) |
| Code digits | 6 (`TOTP_DIGITS`) |
| Hash | SHA-1 (RFC 6238 default; what `totp_lite` is configured with) |
| Secret | 20 random bytes from `OsRng`, base32 (RFC 4648, no padding) |
| otpauth URI | `otpauth://totp/<issuer>:<username>?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30`; issuer is `AuthnConfig::issuer` or `caddy-rs` |
| Default window | `TotpWindow::Current` |

`TotpWindow` implements `serde`, but the containing `AuthnConfig` is **not** `serde`-serialisable
(it holds the JWT signing-key source and durations). Set `totp_window` programmatically where the
config is built.

## Acceptance window

`AuthnConfig::totp_window` controls which steps are tried:

| Variant | Accepted time steps | Span | Use when |
| --- | --- | --- | --- |
| `TotpWindow::Current` (default) | `current` | 30 s | Strictest policy; you control the clock on both ends. |
| `TotpWindow::PlusMinusOne` | `current - 1`, `current`, `current + 1` | 90 s | Users type codes by hand and small clock skew is unavoidable. |
| `TotpWindow::CurrentAndNext` | `current`, `current + 1` | 60 s | Compatibility with clients that pre-compute the next code. It is **not** the legacy `±1` window; use `PlusMinusOne` for that. |

A wider window is slightly weaker: an attacker who observes a code has more time in which it is
still cryptographically valid.

## Replay protection

TOTP codes are bearer credentials: anyone who observes one can present it. The service records, per
user, the **highest time step that has been accepted** (`User::totp_last_step`) and applies two
rules:

1. A code whose step is **equal to** the recorded step is a **replay**.
2. A code whose step is **lower than** the recorded step is a **downgrade attempt**: a newer code
   has already been accepted, so an older one can only be a captured value.

Both return `AuthError::TotpReplay`, never a plain `InvalidTotpCode` — that distinction is the
server-side signal that separates a typo from an attack.

Replay classification is bounded by `TOTP_REPLAY_LOOKBACK_STEPS = 10` steps (five minutes) behind
the accepted window. A code older than that horizon is indistinguishable from a wrong guess and is
reported as `Ok(false)`; without the bound a caller could force an unbounded number of HMAC
computations per attempt.

Because the rule is monotonic, accepting a `current + 1` code in `PlusMinusOne`/`CurrentAndNext`
mode consumes the *current* step as well. A user who submits the next step by mistake must wait for
the following step before a new code is accepted. This is the price of not being downgradable, and
it is why `TotpWindow::Current` is the default.

`UserStore::accept_totp_step` is required to be atomic: it returns `false` when the step is already
consumed or older than the last accepted step. `MemoryUserStore` implements this under a single
write lock, so two concurrent requests presenting the same code cannot both succeed. The method also
returns `false` if the user has no TOTP secret.

Disabling TOTP, or re-enrolling a user, clears `totp_last_step` so the new secret starts clean.

## Handling a rejected code

`totp_verify` returns:

| Result | Meaning | Recommended handling |
| --- | --- | --- |
| `Ok(true)` | Code accepted and its step consumed. | Continue with login. |
| `Ok(false)` | Code does not match any step in the configured window, and is not a known replay. | Ask the user to retry; apply the usual login rate limit. |
| `Err(AuthError::TotpReplay)` | Code is correct for a step at or below the last accepted step, or for a stale step within the replay lookback horizon. | **Do not retry.** Treat as an impersonation/replay attempt: log user id, source address and timestamp at `warn`, count it against the account's brute-force budget, and consider locking the account after repeated occurrences. |
| `Err(AuthError::TotpNotConfigured)` | The user has no TOTP secret. | Configuration error; do not prompt for a code. |
| `Err(AuthError::UserNotFound)` | Unknown user id. | Do not reveal which condition failed. |

`AuthnService::login` preserves the distinction: a missing or wrong code is
`AuthError::InvalidTotpCode`, while a replayed/downgraded code propagates
`AuthError::TotpReplay`. The PM API maps them to `401 invalid TOTP code` and
`401 TOTP code already used` respectively; a public response may deliberately collapse the replay
case to a generic error, but logs and metrics should keep the distinction.

## Enrolment

1. `AuthnService::totp_setup(user_id)` generates the secret, stores it on the user as **pending**
   (`totp_pending = true`), clears `totp_last_step`, and returns `(secret, otpauth_uri)`. Show the
   URI as a QR code and the secret as text.
2. **Pending is not active.** While `totp_pending` is set the factor does not gate login, because
   the operator has not yet proved they can produce a code. This is deliberate: if they abandon
   enrolment — wrong QR scan, lost phone, closed tab — a pending secret that gated login would lock
   them out of the very account they were trying to protect. The secret is never returned again,
   so a lost response means calling `totp_setup` again (it replaces the secret and resets the
   replay state) rather than recovering the old one.
3. `AuthnService::totp_confirm(user_id, code)` verifies the code against the pending secret and, on
   success, clears `totp_pending` — this is the step that actually enables the factor. It consumes
   the submitted step, increments `auth_epoch` and revokes refresh tokens, so a session token minted
   before the factor existed cannot outlive the change. Confirming an account whose factor is
   already active returns `TotpAlreadyEnabled`.
4. `totp_verify` proves possession and consumes the submitted step (used at login).
5. `totp_disable(user_id)` removes the secret and clears the replay state. It also increments
   `auth_epoch` and revokes refresh tokens, because removing a factor weakens the account.

The service methods do not authenticate the caller — the embedding layer must ensure that only the
user themselves (or an administrator) can call `totp_setup`/`totp_confirm`/`totp_disable`.
`caddy-rs-pm-api` is that layer for the proxy manager; see the routes below.

### PM API routes

The proxy manager exposes enrolment to a logged-in operator, each `Cache-Control: no-store`:

| Route | Body | Effect |
|---|---|---|
| `POST /api/v1/auth/totp/setup` | none | Begins enrolment, returns `{secret, otpauth_uri}` once. The only response that ever carries the secret. |
| `POST /api/v1/auth/totp/confirm` | `{totpCode}` | Verifies the code and activates the factor. Returns `{totp_enabled, auth_epoch}`. |
| `POST /api/v1/auth/totp/disable` | `{totpCode}` | Requires a current code, then removes the factor. Returns `{totp_enabled, auth_epoch}`. |

All three require a bearer token (`401` without one). A wrong, unusable or replayed code is refused
with `401` and the same message, so a caller cannot tell which it was. Because confirm and disable
retire previously minted tokens, a successful call is followed by a fresh login — which, once the
factor is active, requires the current code.

**Recovery path.** If the authenticator is lost, there is no bypass through the API by design:
`disable` needs a live code, so a stolen session token cannot strip the factor. The proxy manager's
user store is in-memory (`MemoryUserStore`, PM-109 persistence is a separate slice), so restarting
the daemon clears it and returns to the setup wizard, where a new administrator is created and can
enrol a fresh authenticator. That works because the restart wipes the whole store, not because any
per-account reset exists — there is no way to clear one account's TOTP state without loss of the
others, and no recovery-code route ships in this build. An abandoned (pending, unconfirmed)
enrolment needs no recovery at all: it never gated login, so the operator simply logs in by password
and calls `totp_setup` again.

## Related documentation

- [AUTHN.md](AUTHN.md) — configuration defaults, JWT secret rules, login/token lifecycle.
- [WEBAUTHN.md](WEBAUTHN.md) — passkey registry and the `caddy-rs setup --auth-method webauthn|totp`
  command status.
- [CLI.md](CLI.md) — command reference; `caddy-rs run` serves a configuration
  ([CLI.md#run](CLI.md#run)).
