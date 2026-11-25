# SEC-MEDIUM-AUTHN-PM compatibility note — authentication service and proxy-manager hardening

The normative divergence register lives in the program repository
(`docs/compatibility/BEHAVIOR-DIVERGENCES.md`), which is read-only for implementation tasks. This
note covers the medium/low security fixes in `caddy-rs-authn` and the proxy manager (`pm/`). The
text for the Lead to merge is at the bottom.

## Upstream source of truth (pinned `external/caddy`, tag v2.11.9)

None of these components exist in stock Caddy v2.11.9. `caddy-rs-authn`, `caddy-rs-pm-*` and the
proxy-manager API are caddy-rs extensions: stock Caddy has no user store, login endpoint, TOTP
factor or refresh-token service, and its admin API has no authentication of this kind. The
`stock_compat` flag therefore does **not** apply: every behaviour below is always on. The one place
the pm work touches stock behaviour, placeholder expansion in header values, is E3 below: stock
Caddy's `headers` handler expands `{env.*}` in operator-supplied values (`caddy.Replacer`,
`replacer.go`), and caddy-rs keeps that for hand-written Caddy JSON; the proxy manager simply
refuses to emit such placeholders from its own form fields.

## E1 — login and TOTP throttling (`crates/authn`, `pm/crates/pm-api`)

### Vulnerability

`AuthnService::login` and `totp_verify` had no failure accounting. A caller who knew the password
could try the ~10^6 six-digit codes online, and `login` propagated `AuthError::TotpReplay` as a
distinct error, telling a password-holder that a code had been valid recently. The proxy manager
had a per-username sliding window in `pm-api`'s `login_handler` only; the TOTP confirm/disable
endpoints (`verify_totp`) were not covered, and every other embedder of the crate got nothing.

### Behaviour

- `AuthnConfig::login_throttle: LoginThrottleConfig` (defaults: 5 consecutive failures, lockout
  30 s doubling to 15 min, 10 000 tracked keys). Invalid values fail `AuthnService::new` with
  `AuthError::InvalidConfig`.
- `login` reserves an attempt per submitted username (ASCII-case-folded; counted for unknown names
  exactly like known ones) before checking anything; password and TOTP failures share the budget;
  success resets it. `totp_verify` has its own per-account budget, which covers
  `totp_confirm` and the PM `confirm`/`disable` endpoints.
- A locked key returns the new `AuthError::TooManyAttempts { retry_after }` before any credential
  is evaluated. The PM API maps it to `429` + `Retry-After` (login, confirm, disable). The older
  `pm-api` sliding-window limiter on login is kept as an outer limiter.
- `login` reports a replayed or stale TOTP code as `AuthError::InvalidTotpCode` (the service logs
  the replay at `warn`). `totp_verify` called directly still returns `TotpReplay`.
- Memory is bounded: long usernames are keyed by SHA-256, and at the cap the least recently active
  unlocked entry is evicted before any locked one.
- Trade-off, stated plainly: knowing a username is enough to keep that account locked out for up to
  15 minutes at a time.

### Tests

`crates/authn/src/tests_security.rs`: `login_locks_out_after_the_failure_budget_even_for_the_correct_password`,
`four_failures_do_not_lock_and_a_success_resets_the_budget`,
`lockout_backs_off_exponentially_up_to_the_cap`,
`a_served_lockout_allows_a_correct_login_which_resets_the_backoff`,
`unknown_usernames_are_throttled_exactly_like_known_ones`,
`the_failure_budget_is_per_username_and_ignores_ascii_case`,
`totp_guessing_through_login_shares_the_password_failure_budget`,
`password_and_totp_failures_draw_from_one_budget`,
`a_replayed_totp_code_is_reported_as_a_plain_invalid_code_at_login`,
`direct_totp_verification_is_throttled_and_a_success_resets_it`,
`confirm_and_disable_paths_inherit_the_totp_throttle`,
`parallel_failures_never_exceed_the_budget`,
`the_tracker_is_bounded_and_evicts_unlocked_entries_first`,
`an_idle_key_is_forgiven_and_long_usernames_are_keyed_by_digest`,
`the_throttle_configuration_rejects_unusable_values`. `pm/crates/pm-api`:
`totp_confirm_guessing_is_throttled_with_429_and_retry_after`, `totp_disable_guessing_is_throttled`,
`service_lockouts_map_to_429_with_retry_after_and_replays_stay_masked`.

## Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`, new entry (`caddy-rs extension`, no stock Caddy
equivalent; `stock_compat` does not apply):

> **Proxy-manager authentication hardening (SEC-MEDIUM-AUTHN-PM).** The caddy-rs-only authentication
> service and proxy-manager API have no stock Caddy counterpart and are always hardened. Failed
> logins and TOTP verifications are throttled per account (5 consecutive failures, then a lockout
> of 30 s doubling to 15 min, shared by password and TOTP failures, answered as `429` with
> `Retry-After` by the API); a replayed TOTP code is reported at login exactly like a wrong one.
