# TOTP two-factor authentication

`caddy-rs-authn` implements time-based one-time passwords (RFC 6238) as a second
factor on top of password authentication. This page documents the acceptance
window, the replay protection that backs it, and what operators must do when a
code is rejected as a replay.

## Configuration

TOTP verification is controlled by `AuthnConfig::totp_window`:

```rust
use caddy_rs_authn::{AuthnConfig, TotpWindow};

let config = AuthnConfig {
    // Default. Accept only the current 30-second step.
    totp_window: TotpWindow::Current,
    ..AuthnConfig::default()
};
```

| Variant | Accepted time steps | Use when |
| --- | --- | --- |
| `TotpWindow::Current` (default) | `current` | You want the strictest policy and control the clock on both ends. |
| `TotpWindow::PlusMinusOne` | `current - 1`, `current`, `current + 1` | Users type codes by hand and small clock skew is unavoidable. |
| `TotpWindow::CurrentAndNext` | `current`, `current + 1` | Compatibility with clients that pre-compute the next code. |

Each step is 30 seconds, so a window covers `30s * (2 * N + 1)` of wall clock
time. A wider window is *slightly* weaker: an attacker who observes a code has
more time in which it is still cryptographically valid.

`TotpWindow` serialises as a plain enum value, so it can be carried in JSON
configuration:

```json
{ "totp_window": "PlusMinusOne" }
```

## Replay protection

TOTP codes are bearer credentials: anyone who observes one can present it. The
service therefore records, per user, the **highest time step that has been
accepted** (`User::totp_last_step`) and applies two rules:

1. A code whose step is **equal to** the recorded step is a **replay**. The same
   code is being presented a second time inside its validity window.
2. A code whose step is **lower than** the recorded step is a **downgrade
   attempt**. A newer code has already been accepted, so an older code can only
   come from an attacker replaying a captured value.

Both cases return `AuthError::TotpReplay` and are never treated as a plain
`InvalidTotpCode`. That distinction is deliberate: it is the signal an operator
needs to tell a typo apart from an attack.

Because the rule is monotonic, accepting a `current + 1` code in
`PlusMinusOne`/`CurrentAndNext` mode consumes the *current* step as well. A
user who submits the next step by mistake must wait for the following step
before a new code is accepted. This is the price of not being downgradable, and
it is why `TotpWindow::Current` is the default.

The recorded step is updated atomically inside `UserStore::accept_totp_step`, so
two concurrent requests that present the same code cannot both succeed.

Disabling TOTP, or re-enrolling a user, clears `totp_last_step` so the new
secret starts from a clean slate.

## Handling a rejected code

`totp_verify` returns:

| Result | Meaning | Recommended handling |
| --- | --- | --- |
| `Ok(true)` | Code accepted and step consumed. | Continue with login. |
| `Ok(false)` | Code does not match any step in the configured window. | Ask the user to retry; apply the usual login rate limit. |
| `Err(AuthError::TotpReplay)` | Code is correct for a step at or below the last accepted step. | **Do not retry.** Treat as an impersonation/replay attempt: log the user id, source address and timestamp at `warn`, count it against the account's brute-force budget, and consider locking the account after repeated occurrences. |
| `Err(AuthError::TotpNotConfigured)` | The user has no TOTP secret. | Configuration error; do not prompt for a code. |
| `Err(AuthError::UserNotFound)` | Unknown user id. | Do not reveal which of the two conditions failed. |

`AuthnService::login` propagates the same distinction: a replaying login attempt
fails with `Err(AuthError::TotpReplay)` rather than the generic
`Err(AuthError::InvalidTotpCode)`.

### Example

```rust
match service.login(username, password, Some(code.as_str())).await {
    Ok(tokens) => issue_session(tokens),
    Err(AuthError::TotpReplay) => {
        warn!(%username, "TOTP replay or impersonation attempt");
        authn_store.note_replay(username).await?; // your rate-limit / lockout hook
        Err(AuthError::InvalidTotpCode.into())
    }
    Err(AuthError::InvalidTotpCode) => Err(AuthError::InvalidTotpCode.into()),
    Err(other) => return Err(other.into()),
}
```

The last arm deliberately maps `TotpReplay` back to a generic error for the
*client*: the response should not tell an attacker that their code was
recognised. The distinction matters server-side, in logs and metrics, not in the
HTTP body.

## Enrolment

1. `AuthnService::totp_setup(user_id)` returns `(secret, otpauth_uri)`. Show the
   URI as a QR code and the secret as text.
2. The user proves possession by submitting a code to `totp_verify`. Only after
   that should the account be considered enrolled.
3. `AuthnService::totp_disable(user_id)` removes the secret and clears the
   replay state.
