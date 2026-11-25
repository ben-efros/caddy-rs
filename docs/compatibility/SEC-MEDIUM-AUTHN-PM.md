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

## E2 — `totp_setup` must not strip an active second factor (`crates/authn`, `pm-api`)

### Vulnerability

`totp_setup` unconditionally overwrote `totp_secret` and set `totp_pending = true`. Because
`has_totp()` is `secret.is_some() && !pending` and login only checks a code when `has_totp()`, one
call to `POST /auth/totp/setup` with a briefly held access token turned an account with an active
factor into a password-only account, after which the attacker could enrol their own authenticator.
That contradicted the guarantee documented on `totp_disable` ("a stolen access token alone cannot
strip the factor"). Separately, `/auth/totp/*` fell through to the default-deny `settings:admin`
gate, so non-administrators could not enrol at all.

### Behaviour

- `totp_setup` returns `AuthError::TotpAlreadyEnabled` while a confirmed factor exists (pm-api:
  `409`).
- New `totp_reenroll(user_id, current_code)` (pm-api: `POST /auth/totp/setup` with
  `{"totpCode": ...}`): verifies the current code (throttled, replay-consuming), then stores the
  replacement in the new `User::totp_pending_secret`, beside the active secret. The old factor keeps
  gating login; `totp_confirm` with a code from the *new* secret swaps them (epoch bump, refresh
  tokens revoked). `totp_disable` clears any pending replacement.
- `/auth/totp/setup|confirm|disable` are exempt from the capability gate (exact paths): every role
  manages its own factor; the handlers still require a valid bearer token.

### Tests

`crates/authn/src/tests_security.rs`: `setup_is_refused_while_a_factor_is_active_and_changes_nothing`,
`reenrolment_demands_a_valid_current_code`, `reenrolment_keeps_the_old_factor_active_until_confirmed`,
`confirming_a_reenrolment_swaps_the_secret_and_bumps_the_epoch`,
`a_second_reenrolment_replaces_the_pending_secret_and_disable_clears_it`,
`reenroll_without_an_active_factor_is_a_plain_setup`, `the_pending_secret_never_reaches_debug_output`.
`pm-api`: `an_active_factor_cannot_be_replaced_without_the_current_code`,
`a_non_admin_can_enrol_and_confirm_their_own_totp_factor`,
`a_user_manages_their_own_totp_factor_without_a_section_capability` (authz).

## E3 — placeholder text in pm-supplied fields (`pm/crates/pm-core`, `pm-compiler`, `pm-config`)

### Vulnerability

The proxy manager copied CSP, `Permissions-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
`Referrer-Policy` and the upstream host into the generated Caddy JSON without validation. Stock
Caddy's replacer (`caddy.Replacer`, `replacer.go`) and caddy-rs (`crates/http/src/placeholders.rs`,
`handlers.rs`) expand `{env.NAME}`, `{file.PATH}` and request placeholders in header values and
dial addresses at request time. An `editor`-role user (hosts update, no `settings:admin`) could set a
CSP of `{env.CF_API_TOKEN}`; after the next apply every response of the site carried the caddy-rs
process environment. An upstream host of `{http.request.header.X-Target}` let a client choose the
upstream (SSRF) and `{env.X}` leaked the variable through DNS or the `Host` header
(`preserve_host: false`).

### Behaviour

- `SecurityHeadersConfig::validate` rejects any `{` or `}` and any control character (including the
  `\r\n` of header injection) in the five string fields, with the JSON path in the error
  (`security_headers.content_security_policy must not contain ...`). Braces are rejected outright
  rather than whitelisting "safe" placeholders: none of the legitimate grammars (CSP, Permissions
  Policy, the X-Frame-Options/Referrer-Policy tokens) contains a brace.
- `Upstream::validate` applies the same rule to the host.
- `Host::validate_structure` now also validates the host's `security_headers`, so host create/update
  (`pm-hosts`), `PUT /hosts/{id}/security-headers`, route compilation and global assembly
  (`pm-config`, `PUT /security-headers`) all reject it. `pm-compiler` re-validates inside
  `security_headers_handler` as defence in depth. Values stored before this fix fail the next apply
  with a located error instead of reaching the data plane.
- Reviewed and already safe: domains and redirect targets (DNS label characters only),
  certificate paths (derived from ids, not expanded), issuer names (fixed mapping), HSTS (numeric).
  The proxy manager has no basic-auth realm or `static_response` body fields. Hand-written Caddy JSON
  keeps stock placeholder semantics; only the proxy manager's own forms refuse braces.

### Tests

`pm-core` `tests_placeholders.rs`: `every_header_field_rejects_placeholder_syntax_with_a_located_error`,
`header_fields_reject_control_characters`, `legitimate_header_values_are_still_accepted`,
`upstream_hosts_reject_placeholder_syntax`, `legitimate_upstream_hosts_are_still_accepted`,
`a_host_with_dangerous_security_headers_fails_structure_validation`. `pm-compiler`:
`placeholder_text_is_rejected_before_it_reaches_the_compiled_json`,
`a_fully_populated_legitimate_host_leaks_nothing_through_the_round_trip`. `pm-config`:
`placeholder_text_in_global_security_headers_rejects_assembly`. `pm-api`:
`an_editor_cannot_store_placeholder_text_in_host_security_headers`,
`host_creation_rejects_a_placeholder_upstream`.

## E4 — password hashing parameters and length limits (`crates/authn`, `pm-api`)

### Vulnerability (low)

`AuthnConfig::argon2_params` accepted any values, so a deployment could run with trivially weak
hashing without noticing; `hash_password` silently fell back to bcrypt when Argon2 failed (a hash of
different strength, truncating at 72 bytes); there was no cap on password length before hashing (an
unauthenticated login could make the server hash an arbitrarily large body); and
`create_first_admin` accepted an empty password (the UI said "at least 8 characters" but nothing
enforced it server-side).

### Behaviour

- `AuthnService::new` validates `argon2_params` against the OWASP minimum (`m >= 19456 KiB`,
  `t >= 2`, `p >= 1`) and returns `AuthError::InvalidConfig` naming the field. The new
  `AuthnConfig::allow_weak_argon2_params` (default `false`) is the explicit, logged opt-in; the
  in-tree tests that use cheap parameters set it.
- `hash_password` no longer falls back to bcrypt: it returns the Argon2 error. bcrypt hashes
  created earlier still verify.
- Passwords over `MAX_PASSWORD_BYTES` = 1024 are `AuthError::PasswordTooLong` in `hash_password`
  and a plain non-match in `verify_password`/`login` (no hashing work, no account oracle).
- `create_first_admin` requires `MIN_PASSWORD_CHARS` = 8 characters (`AuthError::PasswordTooShort`);
  `POST /auth/setup` maps both errors to `400` with `location: "password"`.

### Tests

`crates/authn/src/tests_security.rs`:
`argon2_parameters_below_the_owasp_minimum_are_rejected_one_by_one`,
`stronger_than_minimum_parameters_are_accepted_and_weak_ones_need_an_explicit_opt_in`,
`passwords_over_the_cap_are_refused_before_hashing_and_the_boundary_is_exact`,
`login_with_an_oversized_password_is_a_plain_credential_failure`,
`the_first_administrator_needs_a_password_of_at_least_eight_characters`. `pm-api`:
`setup_enforces_the_password_policy_server_side`. Not covered: the removed bcrypt fallback has no
test because Argon2 cannot be made to fail on demand with valid parameters.

## E5 — refresh-token reuse is treated as theft (`crates/authn`)

### Vulnerability (low)

Replaying a consumed refresh token returned `RefreshTokenRevoked` but left the token family alive:
a thief who rotated first kept a working descendant token (and its access tokens) indefinitely even
after the legitimate client noticed the failure and replayed its stale copy.

### Behaviour

`AuthnService::refresh` now, on `RefreshTokenRevoked`, looks up the token's owner, revokes every
refresh token of that user and bumps `auth_epoch` (retiring outstanding access tokens). The caller
still receives `RefreshTokenRevoked` (pm-api: `401 invalid refresh token`, unchanged) and must log in
again. Unknown and expired tokens revoke nothing; `revoke_refresh_token` (logout) is unchanged and
idempotent. A store failure while containing the reuse is returned, not swallowed.

**Follow-up (review).** The first version treated *any* revoked token as reuse, which cascaded: a
second device's routine refresh after a reset, a refresh racing a logout, or anyone who ever held an
old token could keep signing the user out. Records now carry a `RevokeReason` (`Rotated`,
`LoggedOut`, `Revoked`) and the `auth_epoch` they were issued under; only a `Rotated`, unexpired
token whose epoch still equals the user's triggers the family revocation (the epoch compare and bump
are one atomic `modify_user`). Everything else is a plain `RefreshTokenRevoked`, and expiry is
checked before revocation. The earlier "stale client ends other sessions" trade-off no longer
exists.

### Tests

`crates/authn/src/tests_security.rs`: `replaying_a_consumed_refresh_token_revokes_the_whole_family`,
`reuse_by_one_user_never_touches_another_user`, `unknown_and_expired_tokens_revoke_nothing`,
`an_idempotent_logout_replay_does_not_sign_out_other_sessions`, and for the follow-up
`refresh_after_logout_is_a_plain_rejection_with_no_side_effects`,
`refresh_after_a_password_change_does_not_end_the_new_session`,
`a_multi_device_reset_does_not_cascade`,
`a_rotated_token_replayed_after_the_epoch_moved_is_not_theft`,
`an_expired_rotated_token_is_just_expired`. Three pre-existing tests were
adjusted because they encoded the old behaviour (`login_and_refresh_rotation`,
`revoke_all_for_user_invalidates_access_and_refresh`,
`revoke_refresh_token_ends_one_session_and_is_replay_safe`).

## Follow-up review round (authn)

- **Password-guessing oracle.** `update_password` verified the current password with no throttle.
  It now reserves/clears an attempt under the same per-username key as `login`
  (`update_password_shares_the_login_failure_budget`).
- **One password policy.** `check_password_policy` (8 characters minimum, 1024 bytes maximum) is
  applied by `create_user`, `create_first_admin`, `set_password` and `update_password`; the pm-cli
  bootstrap fails startup naming `PM_BOOTSTRAP_ADMIN_PASSWORD`
  (`every_password_setting_path_applies_the_same_policy`,
  `a_too_short_bootstrap_password_fails_startup_naming_the_setting`). Existing accounts and stored
  hashes are untouched.
- **Throttle weaknesses.** The idle reset forgot the backoff level (about ten guesses per 45
  minutes instead of one per 15); it now decays one level per idle period and a penalised key
  re-locks on its first further failure. Eviction preferred the oldest unlocked entry, so ~10k
  invented usernames reset a victim whose lockout had expired; it now evicts by (locked, level,
  failures, age). Tests: `an_idle_period_decays_the_backoff_level_gradually_instead_of_forgetting_it`,
  `an_entry_whose_lockout_expired_is_not_the_one_evicted_by_username_flooding`.
- **Panic.** `now + lockout` overflowed `Instant` for a huge `max_lockout`; it is now `checked_add`
  with a far-future fallback, and `validate()` rejects `max_lockout` above one day
  (`an_enormous_max_lockout_neither_panics_nor_validates`).
- **Key vs store.** The store is case-sensitive, so the throttle key is the exact username (a folded
  key let anyone lock out `Bob` by failing as `bob`): `the_failure_budget_is_per_exact_username`.
- **Atomic updates.** `UserStore::modify_user` is new; the reuse response, `confirm_reenrolment`,
  `totp_disable`, `totp_setup`, `totp_reenroll`, `totp_confirm`, passwords, roles and
  `revoke_all_for_user` use it instead of rewriting a whole record read earlier, which could revert
  a concurrently consumed `totp_last_step` and revive a used code
  (`service_updates_do_not_revert_a_concurrently_consumed_totp_step`, with a store that serves a
  stale read).
- **Breaking changes.** `AuthError` is `#[non_exhaustive]`; `UserStore` gained `modify_user` and
  `consume_refresh_token` takes a `RevokeReason`; new fields on `User`, `AuthnConfig`,
  `RefreshTokenRecord` (see `docs/AUTHN.md`). In-tree consumers (pm-api, pm-cli, the `caddy-rs` CLI)
  needed no change beyond the pm-cli bootstrap message.

## E6 — secrets in logs and arguments in `pm-cli`

### Vulnerability (low)

`serve` logged the bootstrap TOTP enrolment URI (which embeds the secret) as a structured `warn!`
field, and a rejected bootstrap code put the same URI in the fatal error that `main` logged with
`error!`; log lines are retained and shipped far beyond the operator who must scan the code.
`--bootstrap-admin-password` / `--bootstrap-admin-totp` are ordinary clap arguments and therefore
visible in process listings and shell history (they already accept the `PM_BOOTSTRAP_ADMIN_*`
environment variables through clap's `env`).

### Behaviour

- **Superseded by the second review round (see below):** the bootstrap no longer generates a TOTP
  secret, so there is no enrolment URI to show and `bootstrap-totp-uri.txt` no longer exists.
- The credential flags keep working (removing them would break existing invocations); `main` logs a
  warning naming the flag (never the value) when either is present on the command line, steering
  operators to the environment variables / the 0600 environment file. Not changed: the bootstrap
  admin is created with `create_user`, so the 8-character minimum of E4 does not apply to
  `PM_BOOTSTRAP_ADMIN_PASSWORD`.

### Tests

`pm-cli`: `the_bootstrap_totp_uri_goes_to_stderr_and_never_to_the_structured_log` (captures the
tracing output; with the old `warn!(totp_uri = ...)` it fails with the secret in the log),
`totp_secrets_are_redacted_from_text_that_may_be_logged`,
`credential_flags_on_the_command_line_are_detected_by_name_only`,
`without_a_terminal_the_uri_goes_to_an_owner_only_file_and_nowhere_else`,
`a_failure_to_place_the_uri_is_reported_not_swallowed`,
`the_fatal_error_shown_without_a_terminal_carries_no_secret`. The wiring in `main`
(`error!`/`eprintln!` and the flag warning) is not unit-tested.

## Second review round

- **Epoch binding (high).** `refresh` never compared the consumed record's epoch with the user's,
  and `update_role` bumped the epoch without revoking refresh tokens: a thief who rotated first kept
  a live descendant across a role change and, because the real client's replay of the old token was
  then epoch-stale, no reuse response ever fired. `refresh` now refuses a record from an older epoch,
  `update_role` revokes refresh tokens, and `UserStore::store_refresh_token` must refuse an insert
  whose epoch no longer matches the user's, atomically with the insert. That closes the two races
  (a token minted between the reuse response's bump and its revoke; a `login` straddling an
  `update_password`). Tests: `a_thiefs_descendant_token_dies_when_the_role_changes`,
  `a_refresh_token_from_an_older_epoch_is_refused_even_if_never_revoked`,
  `a_token_minted_while_the_reuse_response_runs_does_not_survive_it` and
  `a_login_racing_a_password_change_does_not_outlive_it` (the last two inject the interleaving
  through a store wrapper).
- **Eviction (medium).** An adaptive attacker could push invented names to a penalty, then evict the
  victim. Entries are now kept for 24 hours after their last activity and a full table fails closed:
  unknown names are turned away, known accounts displace only unknown entries
  (`an_adaptive_flood_cannot_evict_a_penalised_victim`). Trade-offs are in `docs/AUTHN.md`.
- **Daily budget (low).** Idling to reset the count allowed about 240 guesses a day, and the TOTP
  key was an independent second allowance. Each key now totals failures over a rolling 24 hours (over
  20, every failure earns the full `max_lockout`: about 116 a day), and TOTP failures spend the login
  budget as well (`guesses_per_key_per_day_stay_bounded_whatever_the_waiting_strategy`,
  `totp_failures_spend_the_login_budget_too`).
- **Bootstrap TOTP (medium).** `PM_BOOTSTRAP_ADMIN_TOTP` asked for a code for a secret generated at
  start, which can never succeed. It now needs `PM_BOOTSTRAP_ADMIN_TOTP_SECRET` (validated base32,
  never logged) alongside it, new `AuthnService::totp_setup_with_secret`, and the normal path is
  `POST /auth/totp/setup`. The URI file and its helpers are removed (less secret at rest), which
  also makes the symlink/O_EXCL concern moot. Tests: `a_secret_and_a_matching_code_enrol_the_bootstrap_factor`,
  `a_code_without_a_secret_or_the_reverse_is_refused_before_creating_anything`,
  `a_wrong_code_or_a_malformed_secret_rolls_the_admin_back_without_echoing_the_secret`,
  `an_operator_chosen_totp_secret_is_validated_and_enrols_like_setup`.
- **Smaller items.** `modify_user` documents that implementations must hold a row lock (the closure
  is `FnOnce`) and restores `id` as well as `username`. The reuse-detection grace period is not
  implemented and the retry trade-off is documented. pm-api's own limiter now keys on the exact
  username like authn (the `ALICE` test flipped). Whitespace-only passwords are refused; Unicode
  NFC normalisation is documented as not applied because the crate is not a dependency.

## Third review round

- **Restart loop (high).** The previous change stored a TOTP *code* (valid 30 s) in the environment
  file and had `serve` re-prove it on every start; the user store is in memory, so every start
  re-ran the bootstrap with a stale code, rolled the admin back and exited 1 (a systemd restart
  loop). `serve` now enrols `PM_BOOTSTRAP_ADMIN_TOTP_SECRET` as an *active* factor with no code
  (`AuthnService::totp_activate_with_secret`); the code is checked once, by `install`, and never
  stored. Test: `the_bootstrap_factor_is_active_and_survives_every_restart` (three boots on fresh
  stores, login with a code derived from the secret), plus `install_checks_the_code_once_and_never_needs_it_again`.
- **Username oracle (medium).** The fail-closed full table of the previous round made unknown names
  answer 429 (no hash) for up to a day after a flood while real accounts answered 401. The tracker is
  now two maps: known accounts (never evicted, never refused) and a capped oldest-first map of
  invented names. Tests: `an_adaptive_flood_of_invented_names_cannot_touch_a_penalised_account`
  (100 000 invented names) and `unknown_and_known_names_stay_indistinguishable_through_a_flood`.
  The earlier "for the duration of the flood" caveat no longer applies.
- **Daily total survives success (low).** A success removed the whole entry, refunding the 24 h
  count. It now resets only the streak and level, and the window is two half-day buckets (sliding in
  12 h steps). Tests: `a_success_ends_the_streak_but_not_the_daily_total`,
  `the_daily_window_slides_in_half_day_steps`.
- **Secret strength (low).** Operator TOTP secrets must be at least 128 bits (RFC 4226), typed error
  `AuthError::InvalidTotpSecret`; tests use 160-bit secrets and
  `totp_secrets_below_128_bits_are_refused` keeps an 80-bit one as the negative case.
- **Argv and `--help` (low).** `hide_env_values` on the password and code arguments; the secret has
  no flag, only the environment variable.
- **Environment file (low).** Written through a `create_new` 0600 temporary file renamed over the
  target (a looser existing file is never truncated in place), unrelated variables preserved, stale
  code lines dropped, line breaks refused (`the_environment_file_is_replaced_atomically_and_keeps_unrelated_lines`,
  `credentials_with_line_breaks_are_refused_not_written`). It now holds password and TOTP secret
  together, so it is not a second factor against a reader of the file.
- **Deleted user (nit).** `store_refresh_token` refuses an insert for a user that no longer exists
  (`a_login_racing_a_user_deletion_gets_no_token`).

## Exact program-repository text to merge

`docs/compatibility/BEHAVIOR-DIVERGENCES.md`, new entry (`caddy-rs extension`, no stock Caddy
equivalent; `stock_compat` does not apply):

> **Proxy-manager authentication hardening (SEC-MEDIUM-AUTHN-PM).** The caddy-rs-only authentication
> service and proxy-manager API have no stock Caddy counterpart and are always hardened. Failed
> logins and TOTP verifications are throttled per account (5 consecutive failures, then a lockout
> of 30 s doubling to 15 min, shared by password and TOTP failures, answered as `429` with
> `Retry-After` by the API); a replayed TOTP code is reported at login exactly like a wrong one.
> TOTP enrolment cannot replace an active factor without a current code (the replacement is held
> pending beside the old factor until confirmed), and any role may manage its own factor. The proxy
> manager rejects `{`/`}` and control characters in the operator-supplied security-header strings and
> upstream hosts it would otherwise emit into placeholder-expanding Caddy JSON fields (stock Caddy
> expands `{env.*}` there; hand-written JSON keeps that behaviour, only the proxy-manager forms refuse).
> The authentication service refuses Argon2 parameters below the OWASP minimum (unless explicitly
> allowed), never falls back to bcrypt, caps passwords at 1024 bytes and requires 8 characters for
> the first administrator. Replaying a consumed refresh token revokes all of that user's refresh
> tokens and bumps the authentication epoch. The proxy-manager daemon prints the bootstrap TOTP
> enrolment URI to stderr instead of the structured log and warns when a bootstrap credential is
> passed as a command-line argument.
> (Follow-up review: reuse detection reacts only to a rotated, unexpired token of the current
> epoch, `update_password` shares the login failure budget, one password policy covers every
> setter, and user-record updates are atomic.)
