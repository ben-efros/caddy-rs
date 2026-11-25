//! Tests for the medium-severity hardening of the authentication service (SEC-MEDIUM-AUTHN-PM):
//! login/TOTP throttling (E1), re-enrolment of an active second factor (E2), password hashing
//! limits (E4) and refresh-token reuse detection (E5).

use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

/// Fixed TOTP step, see `tests::TEST_STEP`.
const STEP: u64 = 60_000_000;

fn fast_config() -> AuthnConfig {
    AuthnConfig {
        jwt_secret_source: JwtSecretSource::Master("test-secret".to_string()),
        argon2_params: Argon2Config {
            memory_cost: 4096,
            time_cost: 1,
            parallelism: 1,
        },
        allow_weak_argon2_params: true,
        ..AuthnConfig::default()
    }
}

fn decode(secret: &str) -> Vec<u8> {
    base32::decode(Alphabet::Rfc4648 { padding: false }, secret).unwrap()
}

/// A service whose throttle clock only moves when the test advances `clock`.
fn clocked_service(config: AuthnConfig) -> (AuthnService<MemoryUserStore>, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(0));
    let service = AuthnService::new(MemoryUserStore::new(), config)
        .expect("build service")
        .with_test_clock(clock.clone());
    (service, clock)
}

fn advance(clock: &AtomicU64, seconds: u64) {
    clock.fetch_add(seconds, Ordering::SeqCst);
}

async fn wrong_login(service: &AuthnService<MemoryUserStore>, username: &str) -> AuthError {
    service
        .login(username, "wrong-password", None)
        .await
        .expect_err("a wrong password must fail")
}

fn retry_after(error: AuthError) -> u64 {
    match error {
        AuthError::TooManyAttempts { retry_after } => retry_after.as_secs(),
        other => panic!("expected TooManyAttempts, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// E1: login / TOTP throttling
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn login_locks_out_after_the_failure_budget_even_for_the_correct_password() {
    let (service, _clock) = clocked_service(fast_config());
    service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();

    for _ in 0..5 {
        assert!(matches!(
            wrong_login(&service, "alice").await,
            AuthError::InvalidCredentials
        ));
    }
    // The budget is spent: even the right password is refused without being checked.
    let locked = service
        .login("alice", "correct horse", None)
        .await
        .expect_err("locked out");
    assert_eq!(retry_after(locked), 30);
}

#[tokio::test]
async fn four_failures_do_not_lock_and_a_success_resets_the_budget() {
    let (service, _clock) = clocked_service(fast_config());
    service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();

    for _ in 0..4 {
        wrong_login(&service, "alice").await;
    }
    service
        .login("alice", "correct horse", None)
        .await
        .expect("the fifth attempt is still allowed and succeeds");
    // The success reset the streak: four more failures are again tolerated.
    for _ in 0..4 {
        assert!(matches!(
            wrong_login(&service, "alice").await,
            AuthError::InvalidCredentials
        ));
    }
    service
        .login("alice", "correct horse", None)
        .await
        .expect("still not locked");
}

#[tokio::test]
async fn lockout_backs_off_exponentially_up_to_the_cap() {
    let (service, clock) = clocked_service(fast_config());
    service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();
    for _ in 0..5 {
        wrong_login(&service, "alice").await;
    }

    // Each lockout, once served, allows exactly one more guess, and that guess re-locks for
    // twice as long: 30 -> 60 -> 120 -> ... -> 900 (15 minutes), then it stays at the cap.
    let mut expected_wait = 30;
    for _ in 0..8 {
        let error = wrong_login(&service, "alice").await;
        assert_eq!(
            retry_after(error),
            expected_wait,
            "locked for the current period"
        );
        advance(&clock, expected_wait - 1);
        assert_eq!(
            retry_after(wrong_login(&service, "alice").await),
            1,
            "one second before expiry the account is still locked"
        );
        advance(&clock, 1);
        // The lockout has been served: this guess is evaluated (and fails) ...
        assert!(matches!(
            wrong_login(&service, "alice").await,
            AuthError::InvalidCredentials
        ));
        // ... and the next lockout is twice as long, capped at 15 minutes.
        expected_wait = (expected_wait * 2).min(900);
    }
    assert_eq!(expected_wait, 900);
}

#[tokio::test]
async fn a_served_lockout_allows_a_correct_login_which_resets_the_backoff() {
    let (service, clock) = clocked_service(fast_config());
    service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();
    for _ in 0..5 {
        wrong_login(&service, "alice").await;
    }
    advance(&clock, 30);
    service
        .login("alice", "correct horse", None)
        .await
        .expect("the legitimate user gets back in after the lockout");
    // Backoff is forgotten: a fresh budget of five again.
    for _ in 0..4 {
        assert!(matches!(
            wrong_login(&service, "alice").await,
            AuthError::InvalidCredentials
        ));
    }
}

#[tokio::test]
async fn unknown_usernames_are_throttled_exactly_like_known_ones() {
    let (service, clock) = clocked_service(fast_config());
    service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();

    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for _ in 0..6 {
        known.push(format!("{:?}", wrong_login(&service, "alice").await));
        unknown.push(format!("{:?}", wrong_login(&service, "ghost").await));
    }
    assert_eq!(
        known, unknown,
        "lockout state must not distinguish an existing account from a missing one"
    );
    assert!(known[5].contains("TooManyAttempts"));

    advance(&clock, 30);
    assert!(matches!(
        wrong_login(&service, "ghost").await,
        AuthError::InvalidCredentials
    ));
}

#[tokio::test]
async fn the_failure_budget_is_per_exact_username() {
    let (service, _clock) = clocked_service(fast_config());
    for name in ["alice", "bob", "Bob"] {
        service
            .create_user(name, "correct horse", Role::viewer())
            .await
            .unwrap();
    }
    for _ in 0..5 {
        wrong_login(&service, "alice").await;
    }
    assert!(matches!(
        service.login("alice", "correct horse", None).await,
        Err(AuthError::TooManyAttempts { .. })
    ));
    service
        .login("bob", "correct horse", None)
        .await
        .expect("another account is unaffected");

    // The store is case-sensitive, so `Bob` and `bob` are two accounts: locking one out must not
    // lock the other (a folded key would let anyone lock out `Bob` by failing as `bob`).
    for _ in 0..5 {
        wrong_login(&service, "bob").await;
    }
    assert!(matches!(
        service.login("bob", "correct horse", None).await,
        Err(AuthError::TooManyAttempts { .. })
    ));
    service
        .login("Bob", "correct horse", None)
        .await
        .expect("a differently-cased account has its own budget");
}

/// An enrolled account whose factor is active, plus a service pinned to the step after the one the
/// confirmation consumed (so a login code is not a replay of the confirmation code).
async fn totp_account(
    config: AuthnConfig,
) -> (
    AuthnService<MemoryUserStore>,
    Arc<AtomicU64>,
    UserId,
    Vec<u8>,
) {
    let clock = Arc::new(AtomicU64::new(0));
    let store = MemoryUserStore::new();
    let enroller = AuthnService::new(store.clone(), config.clone())
        .expect("build service")
        .with_test_step(STEP);
    let user = enroller
        .create_user("ivan", "correct horse", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = enroller.totp_setup(user.id).await.unwrap();
    let bytes = decode(&secret);
    enroller
        .totp_confirm(user.id, &totp_code(&bytes, STEP))
        .await
        .unwrap();
    let service = AuthnService::new(store, config)
        .expect("build service")
        .with_test_step(STEP + 1)
        .with_test_clock(clock.clone());
    (service, clock, user.id, bytes)
}

#[tokio::test]
async fn totp_guessing_through_login_shares_the_password_failure_budget() {
    let (service, _clock, _id, bytes) = totp_account(fast_config()).await;

    // An attacker who knows the password guesses codes. Missing code counts too.
    for _ in 0..5 {
        assert!(matches!(
            service.login("ivan", "correct horse", Some("abcdef")).await,
            Err(AuthError::InvalidTotpCode)
        ));
    }
    // The sixth guess is refused before the code is evaluated, so even the right code fails.
    let right = totp_code(&bytes, STEP + 1);
    assert!(matches!(
        service.login("ivan", "correct horse", Some(&right)).await,
        Err(AuthError::TooManyAttempts { .. })
    ));
}

#[tokio::test]
async fn password_and_totp_failures_draw_from_one_budget() {
    let (service, _clock, _id, _bytes) = totp_account(fast_config()).await;
    for _ in 0..3 {
        wrong_login(&service, "ivan").await;
    }
    for _ in 0..2 {
        assert!(matches!(
            service.login("ivan", "correct horse", Some("abcdef")).await,
            Err(AuthError::InvalidTotpCode)
        ));
    }
    assert!(matches!(
        service.login("ivan", "correct horse", None).await,
        Err(AuthError::TooManyAttempts { .. })
    ));
}

#[tokio::test]
async fn a_replayed_totp_code_is_reported_as_a_plain_invalid_code_at_login() {
    let (service, _clock, _id, bytes) = totp_account(fast_config()).await;
    let code = totp_code(&bytes, STEP + 1);
    service
        .login("ivan", "correct horse", Some(&code))
        .await
        .expect("first use of the code");
    let replay = service
        .login("ivan", "correct horse", Some(&code))
        .await
        .expect_err("replay");
    assert!(
        matches!(replay, AuthError::InvalidTotpCode),
        "replay must not be distinguishable from a wrong code, got {replay:?}"
    );
}

#[tokio::test]
async fn direct_totp_verification_is_throttled_and_a_success_resets_it() {
    let (service, _clock, id, bytes) = totp_account(fast_config()).await;
    for _ in 0..4 {
        assert!(!service.totp_verify(id, "abcdef").await.unwrap());
    }
    // A success inside the budget resets it.
    assert!(service
        .totp_verify(id, &totp_code(&bytes, STEP + 1))
        .await
        .unwrap());
    for _ in 0..5 {
        assert!(!service.totp_verify(id, "abcdef").await.unwrap());
    }
    assert!(matches!(
        service.totp_verify(id, &totp_code(&bytes, STEP + 2)).await,
        Err(AuthError::TooManyAttempts { .. })
    ));
}

#[tokio::test]
async fn confirm_and_disable_paths_inherit_the_totp_throttle() {
    let store = MemoryUserStore::new();
    let service = AuthnService::new(store, fast_config())
        .expect("build service")
        .with_test_step(STEP);
    let user = service
        .create_user("judy", "correct horse", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(user.id).await.unwrap();
    for _ in 0..5 {
        assert!(matches!(
            service.totp_confirm(user.id, "abcdef").await,
            Err(AuthError::InvalidTotpCode)
        ));
    }
    let right = totp_code(&decode(&secret), STEP);
    assert!(matches!(
        service.totp_confirm(user.id, &right).await,
        Err(AuthError::TooManyAttempts { .. })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_failures_never_exceed_the_budget() {
    let (service, _clock) = clocked_service(fast_config());
    service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let service = service.clone();
        tasks.push(tokio::spawn(async move {
            service.login("alice", "wrong-password", None).await
        }));
    }
    let mut verified = 0;
    let mut refused = 0;
    for task in tasks {
        match task.await.unwrap() {
            Err(AuthError::InvalidCredentials) => verified += 1,
            Err(AuthError::TooManyAttempts { .. }) => refused += 1,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(
        verified, 5,
        "exactly the budget is spent on real verifications"
    );
    assert_eq!(refused, 35);
}

#[test]
fn the_tracker_is_bounded_and_evicts_unlocked_entries_first() {
    let config = LoginThrottleConfig {
        max_tracked: 3,
        ..LoginThrottleConfig::default()
    };
    let origin = Instant::now();
    let mut tracker = AttemptTracker::default();
    // Lock one key.
    for _ in 0..config.max_failures {
        tracker.reserve("victim", origin, &config).unwrap();
    }
    // Flood with invented names, each a little later.
    for index in 0..50u64 {
        let _ = tracker.reserve(
            &format!("noise-{index}"),
            origin + Duration::from_millis(index + 1),
            &config,
        );
        assert!(tracker.entries.len() <= 3, "bounded at {index}");
    }
    assert!(
        tracker
            .reserve("victim", origin + Duration::from_secs(1), &config)
            .is_err(),
        "the locked entry survives churn from unlocked names"
    );
}

#[test]
fn an_idle_key_is_forgiven_and_long_usernames_are_keyed_by_digest() {
    let config = LoginThrottleConfig::default();
    let origin = Instant::now();
    let mut tracker = AttemptTracker::default();
    for _ in 0..4 {
        tracker.reserve("k", origin, &config).unwrap();
    }
    // 4 failures + idle for 2 * max_lockout => back to a clean slate: needs 5 more to lock.
    let later = origin + config.max_lockout * 2;
    for _ in 0..4 {
        tracker.reserve("k", later, &config).unwrap();
    }
    assert!(tracker.entries["k"].locked_until.is_none());

    let long = "A".repeat(100_000);
    let key = username_throttle_key(&long);
    assert!(
        key.len() < 200,
        "a huge username must not become a huge key"
    );
    assert_ne!(
        username_throttle_key(&long),
        username_throttle_key(&format!("{long}x"))
    );
    assert_ne!(
        username_throttle_key("Alice"),
        username_throttle_key("alice"),
        "keyed exactly like the case-sensitive store"
    );
}

#[test]
fn the_throttle_configuration_rejects_unusable_values() {
    let bad = [
        LoginThrottleConfig {
            max_failures: 0,
            ..LoginThrottleConfig::default()
        },
        LoginThrottleConfig {
            base_lockout: Duration::ZERO,
            ..LoginThrottleConfig::default()
        },
        LoginThrottleConfig {
            base_lockout: Duration::from_secs(60),
            max_lockout: Duration::from_secs(30),
            ..LoginThrottleConfig::default()
        },
        LoginThrottleConfig {
            max_tracked: 0,
            ..LoginThrottleConfig::default()
        },
    ];
    for config in bad {
        assert!(matches!(
            config.validate(),
            Err(AuthError::InvalidConfig(_))
        ));
        let service = AuthnService::new(
            MemoryUserStore::new(),
            AuthnConfig {
                login_throttle: config,
                ..fast_config()
            },
        );
        assert!(matches!(service, Err(AuthError::InvalidConfig(_))));
    }
    assert!(LoginThrottleConfig::default().validate().is_ok());
}

// ---------------------------------------------------------------------------------------------
// E2: totp_setup must not strip an active second factor
// ---------------------------------------------------------------------------------------------

/// A service over `store` pinned to TOTP step `step`.
fn at_step(store: &MemoryUserStore, step: u64) -> AuthnService<MemoryUserStore> {
    AuthnService::new(store.clone(), fast_config())
        .expect("build service")
        .with_test_step(step)
}

/// An account with an *active* factor whose confirmation consumed `STEP`.
async fn active_factor_account() -> (MemoryUserStore, UserId, Vec<u8>) {
    let store = MemoryUserStore::new();
    let service = at_step(&store, STEP);
    let user = service
        .create_user("mallory-target", "correct horse", Role::admin())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(user.id).await.unwrap();
    let bytes = decode(&secret);
    service
        .totp_confirm(user.id, &totp_code(&bytes, STEP))
        .await
        .unwrap();
    (store, user.id, bytes)
}

#[tokio::test]
async fn setup_is_refused_while_a_factor_is_active_and_changes_nothing() {
    let (store, id, old) = active_factor_account().await;
    let before = store.get_user(id).await.unwrap().unwrap();

    // The attack: a briefly held access token calls setup to turn the account password-only.
    let attacker = at_step(&store, STEP + 1);
    assert!(matches!(
        attacker.totp_setup(id).await,
        Err(AuthError::TotpAlreadyEnabled)
    ));

    let after = store.get_user(id).await.unwrap().unwrap();
    assert_eq!(
        after.totp_secret, before.totp_secret,
        "the secret is untouched"
    );
    assert!(after.has_totp(), "the factor is still active");
    assert_eq!(after.totp_last_step, before.totp_last_step);
    assert!(after.totp_pending_secret.is_none());
    assert_eq!(after.auth_epoch, before.auth_epoch);

    // Login still demands a code from the original secret.
    assert!(matches!(
        attacker
            .login("mallory-target", "correct horse", None)
            .await,
        Err(AuthError::InvalidTotpCode)
    ));
    attacker
        .login(
            "mallory-target",
            "correct horse",
            Some(&totp_code(&old, STEP + 1)),
        )
        .await
        .expect("the legitimate factor still works");
}

#[tokio::test]
async fn reenrolment_demands_a_valid_current_code() {
    let (store, id, old) = active_factor_account().await;
    let service = at_step(&store, STEP + 1);

    assert!(matches!(
        service.totp_reenroll(id, "abcdef").await,
        Err(AuthError::InvalidTotpCode)
    ));
    // The code that confirmed the factor is spent: presenting it again is a replay, not a proof.
    assert!(matches!(
        service.totp_reenroll(id, &totp_code(&old, STEP)).await,
        Err(AuthError::TotpReplay)
    ));
    let user = store.get_user(id).await.unwrap().unwrap();
    assert!(
        user.totp_pending_secret.is_none(),
        "no replacement secret is stored without proof"
    );
    assert!(user.has_totp());
}

#[tokio::test]
async fn reenrolment_keeps_the_old_factor_active_until_confirmed() {
    let (store, id, old) = active_factor_account().await;
    let proof_step = at_step(&store, STEP + 1);
    let (new_secret, uri) = proof_step
        .totp_reenroll(id, &totp_code(&old, STEP + 1))
        .await
        .expect("a current code authorises re-enrolment");
    assert!(uri.contains(&new_secret));
    let new = decode(&new_secret);

    let user = store.get_user(id).await.unwrap().unwrap();
    assert!(
        user.has_totp(),
        "has_totp never goes false during re-enrolment"
    );
    assert_ne!(user.totp_secret.as_deref(), Some(new_secret.as_str()));
    assert_eq!(
        user.totp_pending_secret.as_deref(),
        Some(new_secret.as_str())
    );
    assert!(user.public().totp_enabled);

    // An abandoned re-enrolment weakens nothing: login needs a code, and only the OLD secret's
    // code is accepted; the unconfirmed new secret's code is not.
    let later = at_step(&store, STEP + 2);
    assert!(matches!(
        later.login("mallory-target", "correct horse", None).await,
        Err(AuthError::InvalidTotpCode)
    ));
    assert!(matches!(
        later
            .login(
                "mallory-target",
                "correct horse",
                Some(&totp_code(&new, STEP + 2))
            )
            .await,
        Err(AuthError::InvalidTotpCode)
    ));
    later
        .login(
            "mallory-target",
            "correct horse",
            Some(&totp_code(&old, STEP + 2)),
        )
        .await
        .expect("the old factor still logs in");
}

#[tokio::test]
async fn confirming_a_reenrolment_swaps_the_secret_and_bumps_the_epoch() {
    let (store, id, old) = active_factor_account().await;
    let (new_secret, _) = at_step(&store, STEP + 1)
        .totp_reenroll(id, &totp_code(&old, STEP + 1))
        .await
        .unwrap();
    let new = decode(&new_secret);
    let epoch_before = store.get_user(id).await.unwrap().unwrap().auth_epoch;

    // A code from the OLD secret cannot confirm the replacement.
    let confirming = at_step(&store, STEP + 2);
    assert!(matches!(
        confirming
            .totp_confirm(id, &totp_code(&old, STEP + 2))
            .await,
        Err(AuthError::InvalidTotpCode)
    ));
    assert!(store
        .get_user(id)
        .await
        .unwrap()
        .unwrap()
        .totp_pending_secret
        .is_some());

    let confirmed = confirming
        .totp_confirm(id, &totp_code(&new, STEP + 2))
        .await
        .expect("a code from the new secret confirms it");
    assert!(confirmed.has_totp());
    assert_eq!(confirmed.totp_secret.as_deref(), Some(new_secret.as_str()));
    assert!(confirmed.totp_pending_secret.is_none());
    assert_eq!(confirmed.auth_epoch, epoch_before + 1);

    // From now on only the NEW secret logs in.
    let after = at_step(&store, STEP + 3);
    assert!(matches!(
        after
            .login(
                "mallory-target",
                "correct horse",
                Some(&totp_code(&old, STEP + 3))
            )
            .await,
        Err(AuthError::InvalidTotpCode)
    ));
    after
        .login(
            "mallory-target",
            "correct horse",
            Some(&totp_code(&new, STEP + 3)),
        )
        .await
        .expect("the new factor logs in");
}

#[tokio::test]
async fn a_second_reenrolment_replaces_the_pending_secret_and_disable_clears_it() {
    let (store, id, old) = active_factor_account().await;
    let (first, _) = at_step(&store, STEP + 1)
        .totp_reenroll(id, &totp_code(&old, STEP + 1))
        .await
        .unwrap();
    let (second, _) = at_step(&store, STEP + 2)
        .totp_reenroll(id, &totp_code(&old, STEP + 2))
        .await
        .unwrap();
    assert_ne!(first, second);
    let user = store.get_user(id).await.unwrap().unwrap();
    assert_eq!(user.totp_pending_secret.as_deref(), Some(second.as_str()));

    at_step(&store, STEP + 3).totp_disable(id).await.unwrap();
    let user = store.get_user(id).await.unwrap().unwrap();
    assert!(user.totp_secret.is_none() && user.totp_pending_secret.is_none());
    assert!(!user.has_totp());
}

#[tokio::test]
async fn reenroll_without_an_active_factor_is_a_plain_setup() {
    let store = MemoryUserStore::new();
    let service = at_step(&store, STEP);
    let user = service
        .create_user("fresh", "correct horse", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service
        .totp_reenroll(user.id, "ignored")
        .await
        .expect("nothing to prove when no factor is active");
    let stored = store.get_user(user.id).await.unwrap().unwrap();
    assert_eq!(stored.totp_secret.as_deref(), Some(secret.as_str()));
    assert!(stored.totp_pending && !stored.has_totp());
    assert!(stored.totp_pending_secret.is_none());
    // A still-pending first enrolment may be restarted.
    assert!(service.totp_setup(user.id).await.is_ok());
}

#[tokio::test]
async fn the_pending_secret_never_reaches_debug_output() {
    let (store, id, old) = active_factor_account().await;
    let (pending, _) = at_step(&store, STEP + 1)
        .totp_reenroll(id, &totp_code(&old, STEP + 1))
        .await
        .unwrap();
    let user = store.get_user(id).await.unwrap().unwrap();
    assert!(!format!("{user:?}").contains(&pending));
}

// ---------------------------------------------------------------------------------------------
// E5: refresh-token reuse is treated as theft
// ---------------------------------------------------------------------------------------------

async fn two_users() -> (AuthnService<MemoryUserStore>, MemoryUserStore) {
    let store = MemoryUserStore::new();
    let service = AuthnService::new(store.clone(), fast_config()).expect("build service");
    service
        .create_user("alice", "correct horse", Role::editor())
        .await
        .unwrap();
    service
        .create_user("bob", "battery staple", Role::viewer())
        .await
        .unwrap();
    (service, store)
}

#[tokio::test]
async fn replaying_a_consumed_refresh_token_revokes_the_whole_family() {
    let (service, store) = two_users().await;
    let alice = store.get_user_by_username("alice").await.unwrap().unwrap();
    let stolen = service.login("alice", "correct horse", None).await.unwrap();
    let other_device = service.login("alice", "correct horse", None).await.unwrap();

    // The thief rotates first and keeps the descendant; the owner then replays the old token.
    let descendant = service.refresh(&stolen.refresh_token).await.unwrap();
    assert!(service
        .verify_access_token(&descendant.access_token)
        .await
        .is_ok());
    assert!(matches!(
        service.refresh(&stolen.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    let after = store.get_user(alice.id).await.unwrap().unwrap();
    assert_eq!(after.auth_epoch, alice.auth_epoch + 1, "epoch bumped once");

    // The descendant, the user's other session and every outstanding access token are dead.
    assert!(matches!(
        service.refresh(&descendant.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    assert!(matches!(
        service.refresh(&other_device.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    assert!(service
        .verify_access_token(&descendant.access_token)
        .await
        .is_err());
    assert!(service
        .verify_access_token(&other_device.access_token)
        .await
        .is_err());

    // Logging in again works: the user is not locked out, only their old sessions are.
    service
        .login("alice", "correct horse", None)
        .await
        .expect("a fresh login after the revocation");
}

#[tokio::test]
async fn reuse_by_one_user_never_touches_another_user() {
    let (service, store) = two_users().await;
    let bob = service.login("bob", "battery staple", None).await.unwrap();
    let alice = service.login("alice", "correct horse", None).await.unwrap();
    service.refresh(&alice.refresh_token).await.unwrap();
    assert!(service.refresh(&alice.refresh_token).await.is_err());

    let bob_user = store.get_user_by_username("bob").await.unwrap().unwrap();
    assert_eq!(bob_user.auth_epoch, 0);
    assert!(service.verify_access_token(&bob.access_token).await.is_ok());
    assert!(service.refresh(&bob.refresh_token).await.is_ok());
}

#[tokio::test]
async fn unknown_and_expired_tokens_revoke_nothing() {
    let (service, store) = two_users().await;
    let alice = service.login("alice", "correct horse", None).await.unwrap();
    assert!(matches!(
        service.refresh("never-issued").await,
        Err(AuthError::RefreshTokenNotFound)
    ));
    let user = store.get_user_by_username("alice").await.unwrap().unwrap();
    assert_eq!(
        user.auth_epoch, 0,
        "an unknown token is not evidence of theft"
    );
    assert!(service.refresh(&alice.refresh_token).await.is_ok());

    // An expired token is a plain expiry, not reuse.
    let expiring = AuthnService::new(
        store.clone(),
        AuthnConfig {
            refresh_ttl: Duration::from_secs(1),
            ..fast_config()
        },
    )
    .unwrap();
    let short = expiring.login("bob", "battery staple", None).await.unwrap();
    std::thread::sleep(Duration::from_millis(2100));
    assert!(matches!(
        expiring.refresh(&short.refresh_token).await,
        Err(AuthError::TokenExpired)
    ));
    let bob = store.get_user_by_username("bob").await.unwrap().unwrap();
    assert_eq!(bob.auth_epoch, 0);
}

#[tokio::test]
async fn an_idempotent_logout_replay_does_not_sign_out_other_sessions() {
    let (service, _store) = two_users().await;
    let first = service.login("alice", "correct horse", None).await.unwrap();
    let second = service.login("alice", "correct horse", None).await.unwrap();
    service
        .revoke_refresh_token(&first.refresh_token)
        .await
        .unwrap();
    assert!(matches!(
        service.revoke_refresh_token(&first.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    assert!(
        service.refresh(&second.refresh_token).await.is_ok(),
        "logging out one device twice must not end the user's other session"
    );
}

// ---------------------------------------------------------------------------------------------
// E4: password hashing parameters, length limits
// ---------------------------------------------------------------------------------------------

fn owasp_minimum() -> Argon2Config {
    Argon2Config {
        memory_cost: 19456,
        time_cost: 2,
        parallelism: 1,
    }
}

fn strong_config(argon2_params: Argon2Config) -> AuthnConfig {
    AuthnConfig {
        jwt_secret_source: JwtSecretSource::Master("test-secret".to_string()),
        argon2_params,
        ..AuthnConfig::default()
    }
}

#[test]
fn argon2_parameters_below_the_owasp_minimum_are_rejected_one_by_one() {
    assert!(
        owasp_minimum().validate().is_ok(),
        "the minimum itself is accepted"
    );
    assert!(Argon2Config::default().validate().is_ok());

    let weak = [
        Argon2Config {
            memory_cost: 19455,
            ..owasp_minimum()
        },
        Argon2Config {
            time_cost: 1,
            ..owasp_minimum()
        },
        Argon2Config {
            time_cost: 0,
            ..owasp_minimum()
        },
        Argon2Config {
            parallelism: 0,
            ..owasp_minimum()
        },
        Argon2Config {
            memory_cost: 8,
            time_cost: 1,
            parallelism: 1,
        },
    ];
    for params in weak {
        let service = AuthnService::new(MemoryUserStore::new(), strong_config(params.clone()));
        match service {
            Err(AuthError::InvalidConfig(message)) => {
                assert!(message.contains("argon2_params"), "{message}");
            }
            Err(other) => panic!("{params:?}: wrong error {other:?}"),
            Ok(_) => panic!("{params:?} must be rejected"),
        }
    }
}

#[test]
fn stronger_than_minimum_parameters_are_accepted_and_weak_ones_need_an_explicit_opt_in() {
    AuthnService::new(
        MemoryUserStore::new(),
        strong_config(Argon2Config {
            memory_cost: 32 * 1024,
            time_cost: 3,
            parallelism: 2,
        }),
    )
    .expect("stronger parameters are fine");

    let weak = Argon2Config {
        memory_cost: 4096,
        time_cost: 1,
        parallelism: 1,
    };
    assert!(AuthnService::new(MemoryUserStore::new(), strong_config(weak.clone())).is_err());
    AuthnService::new(
        MemoryUserStore::new(),
        AuthnConfig {
            allow_weak_argon2_params: true,
            ..strong_config(weak)
        },
    )
    .expect("an explicit opt-in allows weak parameters");
}

#[test]
fn passwords_over_the_cap_are_refused_before_hashing_and_the_boundary_is_exact() {
    let params = Argon2Config {
        memory_cost: 4096,
        time_cost: 1,
        parallelism: 1,
    };
    let at_cap = "a".repeat(MAX_PASSWORD_BYTES);
    let over = "a".repeat(MAX_PASSWORD_BYTES + 1);

    let hash = hash_password(&at_cap, &params).expect("exactly the cap is hashed");
    assert!(
        hash.starts_with("$argon2id$"),
        "never a bcrypt fallback: {hash}"
    );
    assert!(verify_password(&at_cap, &hash).unwrap());

    assert!(matches!(
        hash_password(&over, &params),
        Err(AuthError::PasswordTooLong {
            max: MAX_PASSWORD_BYTES
        })
    ));
    // A multi-byte password is measured in bytes, not characters.
    let wide = "é".repeat(MAX_PASSWORD_BYTES / 2 + 1);
    assert!(matches!(
        hash_password(&wide, &params),
        Err(AuthError::PasswordTooLong { .. })
    ));
    // Verification never hashes an over-long password: it simply cannot match.
    assert!(!verify_password(&over, &hash).unwrap());
    let legacy = bcrypt::hash("short", bcrypt::DEFAULT_COST).unwrap();
    assert!(!verify_password(&over, &legacy).unwrap());
    assert!(
        verify_password("short", &legacy).unwrap(),
        "legacy bcrypt still verifies"
    );
}

#[tokio::test]
async fn login_with_an_oversized_password_is_a_plain_credential_failure() {
    let (service, _clock) = clocked_service(fast_config());
    service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();
    let huge = "x".repeat(10 * 1024 * 1024);
    for username in ["alice", "ghost"] {
        assert!(matches!(
            service.login(username, &huge, None).await,
            Err(AuthError::InvalidCredentials)
        ));
    }
}

#[tokio::test]
async fn the_first_administrator_needs_a_password_of_at_least_eight_characters() {
    let service = AuthnService::new(MemoryUserStore::new(), fast_config()).expect("build service");
    for short in ["", "a", "1234567", "ééééééé"] {
        assert!(
            matches!(
                service.create_first_admin("root", short).await,
                Err(AuthError::PasswordTooShort { min: 8 })
            ),
            "{short:?} must be rejected"
        );
    }
    assert!(matches!(
        service
            .create_first_admin("root", &"a".repeat(MAX_PASSWORD_BYTES + 1))
            .await,
        Err(AuthError::PasswordTooLong { .. })
    ));
    // Rejections created nothing: the setup window is still open, and 8 characters (counted as
    // characters, not bytes) is the accepted boundary.
    let (user, tokens) = service
        .create_first_admin("root", "pässwörd")
        .await
        .expect("8 multi-byte characters are accepted");
    assert_eq!(user.username, "root");
    assert!(!tokens.access_token.is_empty());
    assert!(matches!(
        service.create_first_admin("second", "long enough pw").await,
        Err(AuthError::UsernameExists)
    ));
}

// ---------------------------------------------------------------------------------------------
// Review round: reuse detection must not cascade, throttle hardening, policy, atomic updates
// ---------------------------------------------------------------------------------------------

async fn epoch_of(store: &MemoryUserStore, name: &str) -> u64 {
    store
        .get_user_by_username(name)
        .await
        .unwrap()
        .unwrap()
        .auth_epoch
}

#[tokio::test]
async fn refresh_after_logout_is_a_plain_rejection_with_no_side_effects() {
    let (service, store) = two_users().await;
    let a = service.login("alice", "correct horse", None).await.unwrap();
    let b = service.login("alice", "correct horse", None).await.unwrap();
    service
        .revoke_refresh_token(&a.refresh_token)
        .await
        .unwrap();

    // A refresh timer that fires after the logout presents the logged-out token.
    assert!(matches!(
        service.refresh(&a.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    assert_eq!(epoch_of(&store, "alice").await, 0);
    assert!(service.verify_access_token(&b.access_token).await.is_ok());
    service
        .refresh(&b.refresh_token)
        .await
        .expect("other device");
}

#[tokio::test]
async fn refresh_after_a_password_change_does_not_end_the_new_session() {
    let (service, store) = two_users().await;
    let alice = store.get_user_by_username("alice").await.unwrap().unwrap();
    let device_a = service.login("alice", "correct horse", None).await.unwrap();
    let device_b = service.login("alice", "correct horse", None).await.unwrap();
    service
        .update_password(alice.id, "correct horse", "new battery staple")
        .await
        .unwrap();
    let new_session = service
        .login("alice", "new battery staple", None)
        .await
        .unwrap();

    // Both old devices' routine refreshes fail, and neither signs the new session out.
    for stale in [&device_a, &device_b] {
        assert!(matches!(
            service.refresh(&stale.refresh_token).await,
            Err(AuthError::RefreshTokenRevoked)
        ));
    }
    assert_eq!(
        epoch_of(&store, "alice").await,
        1,
        "only the password change bumped it"
    );
    assert!(service
        .verify_access_token(&new_session.access_token)
        .await
        .is_ok());
    service
        .refresh(&new_session.refresh_token)
        .await
        .expect("the new session survives");
}

#[tokio::test]
async fn a_multi_device_reset_does_not_cascade() {
    let (service, store) = two_users().await;
    let a = service.login("alice", "correct horse", None).await.unwrap();
    let b = service.login("alice", "correct horse", None).await.unwrap();
    let c = service.login("alice", "correct horse", None).await.unwrap();

    // Device A rotates, then replays its stale token: a genuine reuse, the family is revoked once.
    service.refresh(&a.refresh_token).await.unwrap();
    assert!(service.refresh(&a.refresh_token).await.is_err());
    assert_eq!(epoch_of(&store, "alice").await, 1);

    // The user logs in again on A. Devices B and C then wake up with their (mass-revoked) tokens.
    let a_again = service.login("alice", "correct horse", None).await.unwrap();
    for woken in [&b, &c] {
        assert!(matches!(
            service.refresh(&woken.refresh_token).await,
            Err(AuthError::RefreshTokenRevoked)
        ));
    }
    assert_eq!(epoch_of(&store, "alice").await, 1, "no second reset");
    assert!(service
        .verify_access_token(&a_again.access_token)
        .await
        .is_ok());
    service
        .refresh(&a_again.refresh_token)
        .await
        .expect("A's new session survives the other devices waking up");

    // Replaying the long-dead rotated token again is not a new theft signal either: the family it
    // belonged to was already retired by the epoch bump.
    assert!(service.refresh(&a.refresh_token).await.is_err());
    assert_eq!(epoch_of(&store, "alice").await, 1);
}

#[tokio::test]
async fn a_rotated_token_replayed_after_the_epoch_moved_is_not_theft() {
    let (service, store) = two_users().await;
    let alice = store.get_user_by_username("alice").await.unwrap().unwrap();
    let old = service.login("alice", "correct horse", None).await.unwrap();
    service.refresh(&old.refresh_token).await.unwrap();
    service.revoke_all_for_user(alice.id).await.unwrap();
    let fresh = service.login("alice", "correct horse", None).await.unwrap();

    assert!(service.refresh(&old.refresh_token).await.is_err());
    assert_eq!(epoch_of(&store, "alice").await, 1, "not bumped again");
    service
        .refresh(&fresh.refresh_token)
        .await
        .expect("fresh session lives");
}

#[tokio::test]
async fn an_expired_rotated_token_is_just_expired() {
    let (_service, store) = two_users().await;
    let service = AuthnService::new(
        store.clone(),
        AuthnConfig {
            refresh_ttl: Duration::from_secs(1),
            ..fast_config()
        },
    )
    .unwrap();
    let tokens = service.login("alice", "correct horse", None).await.unwrap();
    service.refresh(&tokens.refresh_token).await.unwrap();
    std::thread::sleep(Duration::from_millis(2100));
    assert!(matches!(
        service.refresh(&tokens.refresh_token).await,
        Err(AuthError::TokenExpired)
    ));
    assert_eq!(epoch_of(&store, "alice").await, 0, "expiry is not reuse");
}

#[tokio::test]
async fn update_password_shares_the_login_failure_budget() {
    let (service, clock) = clocked_service(fast_config());
    let alice = service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();
    // A stolen access token cannot guess the current password at line speed.
    for _ in 0..5 {
        assert!(matches!(
            service
                .update_password(alice.id, "wrong guess", "another password")
                .await,
            Err(AuthError::InvalidCredentials)
        ));
    }
    assert!(matches!(
        service
            .update_password(alice.id, "correct horse", "another password")
            .await,
        Err(AuthError::TooManyAttempts { .. })
    ));
    // The same per-user key: login is locked out too, and recovers once the lockout ends.
    assert!(matches!(
        service.login("alice", "correct horse", None).await,
        Err(AuthError::TooManyAttempts { .. })
    ));
    advance(&clock, 31);
    service
        .update_password(alice.id, "correct horse", "another password")
        .await
        .expect("allowed again after the lockout; success clears the budget");
}

#[tokio::test]
async fn every_password_setting_path_applies_the_same_policy() {
    let (service, _clock) = clocked_service(fast_config());
    assert!(matches!(
        service.create_user("eve", "short", Role::viewer()).await,
        Err(AuthError::PasswordTooShort { min: 8 })
    ));
    assert!(matches!(
        service
            .create_user("eve", &"x".repeat(MAX_PASSWORD_BYTES + 1), Role::viewer())
            .await,
        Err(AuthError::PasswordTooLong { .. })
    ));
    let eve = service
        .create_user("eve", "12345678", Role::viewer())
        .await
        .expect("exactly the minimum");
    assert!(matches!(
        service.set_password(eve.id, "1234567").await,
        Err(AuthError::PasswordTooShort { .. })
    ));
    assert!(matches!(
        service.update_password(eve.id, "12345678", "tiny").await,
        Err(AuthError::PasswordTooShort { .. })
    ));
    // Rejections changed nothing.
    service
        .login("eve", "12345678", None)
        .await
        .expect("old password intact");
    assert!(matches!(
        check_password_policy("ééééééé"),
        Err(AuthError::PasswordTooShort { .. })
    ));
    check_password_policy("éééééééé").expect("8 characters, 16 bytes");
}

#[test]
fn an_idle_period_decays_the_backoff_level_gradually_instead_of_forgetting_it() {
    let config = LoginThrottleConfig::default();
    let mut now = Instant::now();
    let mut tracker = AttemptTracker::default();
    // Climb to level 4: every lockout is served, then one more failure re-locks immediately.
    for _ in 0..5 {
        let _ = tracker.reserve("k", now, &config);
    }
    for _ in 0..3 {
        now += config.max_lockout; // past the current lockout
        let _ = tracker.reserve("k", now, &config);
    }
    assert_eq!(tracker.entries["k"].level, 4);

    now += config.max_lockout * 2; // one idle period
    assert!(
        tracker.reserve("k", now, &config).is_ok(),
        "one guess is allowed"
    );
    assert!(
        tracker.reserve("k", now, &config).is_err(),
        "but not a fresh budget of max_failures guesses"
    );
    assert!(
        tracker.entries["k"].level >= 3,
        "level only decayed by one period"
    );
}

#[test]
fn an_entry_whose_lockout_expired_is_not_the_one_evicted_by_username_flooding() {
    let config = LoginThrottleConfig {
        max_tracked: 3,
        ..LoginThrottleConfig::default()
    };
    let origin = Instant::now();
    let mut tracker = AttemptTracker::default();
    for _ in 0..5 {
        let _ = tracker.reserve("victim", origin, &config);
    }
    let after_lock = origin + config.base_lockout + Duration::from_secs(1);
    for index in 0..50u64 {
        let _ = tracker.reserve(
            &format!("noise-{index}"),
            after_lock + Duration::from_millis(index),
            &config,
        );
    }
    let victim = tracker
        .entries
        .get("victim")
        .expect("the penalised entry survives the flood");
    assert_eq!(victim.level, 1);
    let later = after_lock + Duration::from_secs(1);
    assert!(
        tracker.reserve("victim", later, &config).is_ok(),
        "one guess"
    );
    assert!(
        tracker.reserve("victim", later, &config).is_err(),
        "its first failure re-locked, the count did not restart"
    );
}

#[test]
fn an_enormous_max_lockout_neither_panics_nor_validates() {
    let huge = LoginThrottleConfig {
        base_lockout: Duration::MAX,
        max_lockout: Duration::MAX,
        ..LoginThrottleConfig::default()
    };
    assert!(huge.validate().is_err(), "capped by validation");
    assert!(LoginThrottleConfig {
        max_lockout: Duration::from_secs(48 * 60 * 60),
        ..LoginThrottleConfig::default()
    }
    .validate()
    .is_err());
    // Even if it somehow got through, the arithmetic saturates instead of overflowing `Instant`.
    let mut tracker = AttemptTracker::default();
    let now = Instant::now();
    for _ in 0..5 {
        let _ = tracker.reserve("k", now, &huge);
    }
    assert!(tracker.reserve("k", now, &huge).is_err());
}

/// A store whose `get_user` serves a frozen snapshot, standing in for a read that raced a
/// concurrent write. Every other method, `modify_user` included, hits the real store.
#[derive(Clone)]
struct StaleReadStore {
    inner: MemoryUserStore,
    frozen: Arc<Mutex<Option<User>>>,
}

#[async_trait::async_trait]
impl UserStore for StaleReadStore {
    async fn get_user(&self, user_id: UserId) -> AuthResult<Option<User>> {
        if let Some(user) = self.frozen.lock().unwrap().clone() {
            return Ok(Some(user));
        }
        self.inner.get_user(user_id).await
    }
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
        self.inner.get_user_by_username(username).await
    }
    async fn create_user(&self, user: User) -> AuthResult<User> {
        self.inner.create_user(user).await
    }
    async fn update_user(&self, user: User) -> AuthResult<User> {
        self.inner.update_user(user).await
    }
    async fn modify_user(&self, user_id: UserId, change: UserChange) -> AuthResult<User> {
        self.inner.modify_user(user_id, change).await
    }
    async fn delete_user(&self, user_id: UserId) -> AuthResult<()> {
        self.inner.delete_user(user_id).await
    }
    async fn list_users(&self) -> AuthResult<Vec<User>> {
        self.inner.list_users().await
    }
    async fn get_refresh_token(&self, hash: &str) -> AuthResult<Option<RefreshTokenRecord>> {
        self.inner.get_refresh_token(hash).await
    }
    async fn store_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()> {
        self.inner.store_refresh_token(record).await
    }
    async fn consume_refresh_token(
        &self,
        hash: &str,
        now: i64,
        reason: RevokeReason,
    ) -> AuthResult<RefreshTokenRecord> {
        self.inner.consume_refresh_token(hash, now, reason).await
    }
    async fn revoke_all_refresh_tokens_for_user(
        &self,
        user_id: UserId,
        now: i64,
    ) -> AuthResult<()> {
        self.inner
            .revoke_all_refresh_tokens_for_user(user_id, now)
            .await
    }
    async fn accept_totp_step(&self, user_id: UserId, step: u64) -> AuthResult<bool> {
        self.inner.accept_totp_step(user_id, step).await
    }
}

#[tokio::test]
async fn service_updates_do_not_revert_a_concurrently_consumed_totp_step() {
    let inner = MemoryUserStore::new();
    let store = StaleReadStore {
        inner: inner.clone(),
        frozen: Arc::new(Mutex::new(None)),
    };
    let service = AuthnService::new(store.clone(), fast_config()).unwrap();
    let alice = service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();
    // A pending (not yet gating) secret: password login still works, but a step can be accepted.
    inner
        .modify_user(
            alice.id,
            Box::new(|user| {
                user.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
                user.totp_pending = true;
                Ok(())
            }),
        )
        .await
        .unwrap();

    for (index, scenario) in ["reuse", "revoke_all"].into_iter().enumerate() {
        let rotated = service.login("alice", "correct horse", None).await.unwrap();
        service.refresh(&rotated.refresh_token).await.unwrap();

        // A read taken *before* the step was consumed...
        *store.frozen.lock().unwrap() = inner.get_user(alice.id).await.unwrap();
        // ...and then a TOTP code is consumed concurrently.
        let step = 77 + index as u64;
        assert!(inner.accept_totp_step(alice.id, step).await.unwrap());

        match scenario {
            "reuse" => assert!(service.refresh(&rotated.refresh_token).await.is_err()),
            _ => service.revoke_all_for_user(alice.id).await.unwrap(),
        }
        let after = inner.get_user(alice.id).await.unwrap().unwrap();
        assert_eq!(
            after.totp_last_step,
            Some(step),
            "{scenario}: the consumed step must stay consumed"
        );
        *store.frozen.lock().unwrap() = None;
    }
}

// ---------------------------------------------------------------------------------------------
// Second review round
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_thiefs_descendant_token_dies_when_the_role_changes() {
    let (service, store) = two_users().await;
    let alice = store.get_user_by_username("alice").await.unwrap().unwrap();
    let t1 = service.login("alice", "correct horse", None).await.unwrap();
    // The thief rotates the stolen token first and holds the descendant.
    let t2_thief = service.refresh(&t1.refresh_token).await.unwrap();
    // An administrator changes the role: the epoch moves.
    service.update_role(alice.id, Role::viewer()).await.unwrap();
    // The real client replays T1 (rotated, but epoch-stale): no reuse response is possible any more,
    // so the descendant must already be dead.
    let _ = service.refresh(&t1.refresh_token).await;
    assert!(
        matches!(
            service.refresh(&t2_thief.refresh_token).await,
            Err(AuthError::RefreshTokenRevoked)
        ),
        "a token from before the epoch change must not mint tokens at the new epoch"
    );
}

#[tokio::test]
async fn a_refresh_token_from_an_older_epoch_is_refused_even_if_never_revoked() {
    let (service, store) = two_users().await;
    let alice = store.get_user_by_username("alice").await.unwrap().unwrap();
    let tokens = service.login("alice", "correct horse", None).await.unwrap();
    // Move the epoch without touching the token store, as a backend that missed the revoke would.
    store
        .modify_user(
            alice.id,
            Box::new(|user| {
                user.auth_epoch += 1;
                Ok(())
            }),
        )
        .await
        .unwrap();
    assert!(matches!(
        service.refresh(&tokens.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
}

/// What an interleaving hook does when its trigger point is reached.
enum Interleave {
    /// On the next `get_user`: snapshot the user, run a refresh with this token to completion, then
    /// return the (now stale) snapshot.
    ReplayOnGetUser(String),
    /// On the next `get_user_by_username`: snapshot, change the password, return the snapshot.
    ChangePasswordOnLookup {
        user: UserId,
        old: String,
        new: String,
    },
}

/// A store that injects another operation between two steps of the operation under test.
#[derive(Clone)]
struct InterleaveStore {
    inner: MemoryUserStore,
    service: Arc<Mutex<Option<AuthnService<InterleaveStore>>>>,
    hook: Arc<Mutex<Option<Interleave>>>,
    thief_result: Arc<Mutex<Option<bool>>>,
}

impl InterleaveStore {
    fn service(&self) -> AuthnService<InterleaveStore> {
        self.service.lock().unwrap().clone().expect("service set")
    }
}

#[async_trait::async_trait]
impl UserStore for InterleaveStore {
    async fn get_user(&self, user_id: UserId) -> AuthResult<Option<User>> {
        let snapshot = self.inner.get_user(user_id).await?;
        let armed = {
            let mut hook = self.hook.lock().unwrap();
            if matches!(*hook, Some(Interleave::ReplayOnGetUser(_))) {
                hook.take()
            } else {
                None
            }
        };
        if let Some(Interleave::ReplayOnGetUser(token)) = armed {
            let _ = self.service().refresh(&token).await;
        }
        Ok(snapshot)
    }
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
        let snapshot = self.inner.get_user_by_username(username).await?;
        let armed = {
            let mut hook = self.hook.lock().unwrap();
            if matches!(*hook, Some(Interleave::ChangePasswordOnLookup { .. })) {
                hook.take()
            } else {
                None
            }
        };
        if let Some(Interleave::ChangePasswordOnLookup { user, old, new }) = armed {
            self.service()
                .update_password(user, &old, &new)
                .await
                .expect("the concurrent password change succeeds");
        }
        Ok(snapshot)
    }
    async fn create_user(&self, user: User) -> AuthResult<User> {
        self.inner.create_user(user).await
    }
    async fn update_user(&self, user: User) -> AuthResult<User> {
        self.inner.update_user(user).await
    }
    async fn modify_user(&self, user_id: UserId, change: UserChange) -> AuthResult<User> {
        self.inner.modify_user(user_id, change).await
    }
    async fn delete_user(&self, user_id: UserId) -> AuthResult<()> {
        self.inner.delete_user(user_id).await
    }
    async fn list_users(&self) -> AuthResult<Vec<User>> {
        self.inner.list_users().await
    }
    async fn get_refresh_token(&self, hash: &str) -> AuthResult<Option<RefreshTokenRecord>> {
        self.inner.get_refresh_token(hash).await
    }
    async fn store_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()> {
        self.inner.store_refresh_token(record).await
    }
    async fn consume_refresh_token(
        &self,
        hash: &str,
        now: i64,
        reason: RevokeReason,
    ) -> AuthResult<RefreshTokenRecord> {
        self.inner.consume_refresh_token(hash, now, reason).await
    }
    async fn revoke_all_refresh_tokens_for_user(
        &self,
        user_id: UserId,
        now: i64,
    ) -> AuthResult<()> {
        self.inner
            .revoke_all_refresh_tokens_for_user(user_id, now)
            .await
    }
    async fn accept_totp_step(&self, user_id: UserId, step: u64) -> AuthResult<bool> {
        self.inner.accept_totp_step(user_id, step).await
    }
}

fn interleave_service() -> (AuthnService<InterleaveStore>, InterleaveStore) {
    let store = InterleaveStore {
        inner: MemoryUserStore::new(),
        service: Arc::new(Mutex::new(None)),
        hook: Arc::new(Mutex::new(None)),
        thief_result: Arc::new(Mutex::new(None)),
    };
    let service = AuthnService::new(store.clone(), fast_config()).unwrap();
    *store.service.lock().unwrap() = Some(service.clone());
    (service, store)
}

#[tokio::test]
async fn a_token_minted_while_the_reuse_response_runs_does_not_survive_it() {
    let (service, store) = interleave_service();
    service
        .create_user("alice", "correct horse", Role::editor())
        .await
        .unwrap();
    let t1 = service.login("alice", "correct horse", None).await.unwrap();
    let t2_thief = service.refresh(&t1.refresh_token).await.unwrap();

    // The thief's refresh has consumed T2' and is about to read the user; at that moment the real
    // client replays T1 and the whole reuse response (bump + revoke) completes.
    *store.hook.lock().unwrap() = Some(Interleave::ReplayOnGetUser(t1.refresh_token.clone()));
    let result = service.refresh(&t2_thief.refresh_token).await;
    assert!(
        result.is_err(),
        "the thief must not walk away with a token minted across the reset"
    );
    let _ = store.thief_result.lock().unwrap().take();
    let user = store
        .inner
        .get_user_by_username("alice")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.auth_epoch, 1, "the reuse response ran exactly once");
}

#[tokio::test]
async fn a_login_racing_a_password_change_does_not_outlive_it() {
    let (service, store) = interleave_service();
    let alice = service
        .create_user("alice", "correct horse", Role::editor())
        .await
        .unwrap();
    // The login reads the account (and verifies the old password), then the password changes, and
    // only then is the login's refresh token stored.
    *store.hook.lock().unwrap() = Some(Interleave::ChangePasswordOnLookup {
        user: alice.id,
        old: "correct horse".to_string(),
        new: "new battery staple".to_string(),
    });
    let result = service.login("alice", "correct horse", None).await;
    assert!(
        result.is_err(),
        "a login straddling a password change must not yield a session"
    );
}

#[test]
fn modify_user_cannot_change_the_id_or_username() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (service, store) = two_users().await;
        let alice = store.get_user_by_username("alice").await.unwrap().unwrap();
        let other_id = UserId::new();
        let stored = store
            .modify_user(
                alice.id,
                Box::new(move |user| {
                    user.id = other_id;
                    user.username = "mallory".to_string();
                    Ok(())
                }),
            )
            .await
            .unwrap();
        assert_eq!(stored.id, alice.id);
        assert_eq!(stored.username, "alice");
        assert!(store.get_user(alice.id).await.unwrap().is_some());
        drop(service);
    });
}

#[test]
fn an_adaptive_flood_cannot_evict_a_penalised_victim() {
    let config = LoginThrottleConfig {
        max_tracked: 100,
        ..LoginThrottleConfig::default()
    };
    let origin = Instant::now();
    let mut tracker = AttemptTracker::default();
    // The victim burns its budget: unlocked again later, but at backoff level 1.
    for _ in 0..5 {
        let _ = tracker.reserve_as("victim", true, origin, &config);
    }
    // The attacker pushes invented names to a penalty to fill the table.
    for index in 0..99 {
        for _ in 0..5 {
            let _ = tracker.reserve_as(&format!("fake-{index}"), false, origin, &config);
        }
    }
    assert_eq!(tracker.entries.len(), 100);

    // Lockouts expire; the flood keeps coming with new invented names.
    let later = origin + config.base_lockout + Duration::from_secs(1);
    for index in 0..5_000u64 {
        let admitted = tracker.reserve_as(
            &format!("new-fake-{index}"),
            false,
            later + Duration::from_millis(index),
            &config,
        );
        assert!(admitted.is_err(), "a full table turns invented names away");
        assert!(tracker.entries.len() <= 100);
    }
    let victim = tracker
        .entries
        .get("victim")
        .expect("the victim's entry is never evicted by the flood");
    assert_eq!(victim.level, 1);
    assert!(tracker.reserve_as("victim", true, later, &config).is_ok());
    assert!(
        tracker.reserve_as("victim", true, later, &config).is_err(),
        "its count did not restart: one guess, then locked again"
    );

    // A real account that has no entry yet is still admitted (displacing an invented one).
    assert!(tracker.reserve_as("newcomer", true, later, &config).is_ok());
    assert!(tracker.entries.contains_key("newcomer"));
    assert!(tracker.entries.len() <= 100);

    // Entries age out after their retention (a day of inactivity) and the table recovers.
    let much_later = later + THROTTLE_DAY + Duration::from_secs(5);
    assert!(tracker
        .reserve_as("fresh-after-a-day", false, much_later, &config)
        .is_ok());
}

fn guesses_in_a_day(wait_out_the_idle_period: bool) -> u32 {
    let config = LoginThrottleConfig::default();
    let origin = Instant::now();
    let mut now = origin;
    let mut tracker = AttemptTracker::default();
    let mut guesses = 0;
    while now.duration_since(origin) < THROTTLE_DAY {
        match tracker.reserve("target", now, &config) {
            Ok(()) => guesses += 1,
            Err(wait) => {
                now += if wait_out_the_idle_period {
                    // Sit idle long enough for the level to decay and the count to restart.
                    config.max_lockout * 2 + Duration::from_secs(1)
                } else {
                    wait + Duration::from_secs(1)
                };
            }
        }
    }
    guesses
}

#[test]
fn guesses_per_key_per_day_stay_bounded_whatever_the_waiting_strategy() {
    // 20 failures per day, then one per full lockout (15 min): about 116 at most with the defaults.
    for strategy in [false, true] {
        let guesses = guesses_in_a_day(strategy);
        assert!(
            guesses <= 120,
            "idle-waiting={strategy}: {guesses} guesses in a day"
        );
        assert!(guesses >= 20, "the budget itself is still usable");
    }
}

#[tokio::test]
async fn totp_failures_spend_the_login_budget_too() {
    let (service, _clock, id, _bytes) = totp_account(fast_config()).await;
    for _ in 0..5 {
        let _ = service.totp_verify(id, "abcdef").await;
    }
    // The account's password-login budget was drawn on as well.
    assert!(matches!(
        service.login("ivan", "correct horse", None).await,
        Err(AuthError::TooManyAttempts { .. })
    ));
}

#[tokio::test]
async fn a_whitespace_only_password_is_refused() {
    let (service, _clock) = clocked_service(fast_config());
    assert!(matches!(
        service.create_user("eve", "        ", Role::viewer()).await,
        Err(AuthError::PasswordBlank)
    ));
    assert!(matches!(check_password_policy("\t \u{a0} \n  x"), Ok(())));
    assert!(matches!(
        check_password_policy(" \t\u{3000}\n\r      "),
        Err(AuthError::PasswordBlank)
    ));
}

#[tokio::test]
async fn an_operator_chosen_totp_secret_is_validated_and_enrols_like_setup() {
    let store = MemoryUserStore::new();
    let service = AuthnService::new(store.clone(), fast_config())
        .unwrap()
        .with_test_step(STEP);
    let user = service
        .create_user("root", "correct horse", Role::admin())
        .await
        .unwrap();

    for bad in ["", "short", "not base32 !!!!!!!!", "AAAA", &"A".repeat(200)] {
        let error = service
            .totp_setup_with_secret(user.id, bad)
            .await
            .expect_err("an unusable secret is refused");
        assert!(
            bad.is_empty() || !error.to_string().contains(bad),
            "{error}"
        );
    }
    assert!(store
        .get_user(user.id)
        .await
        .unwrap()
        .unwrap()
        .totp_secret
        .is_none());

    // Spaces, padding and lowercase are tolerated; the stored form is canonical.
    service
        .totp_setup_with_secret(user.id, "jbsw y3dp ehpk 3pxp====")
        .await
        .expect("a valid secret");
    let pending = store.get_user(user.id).await.unwrap().unwrap();
    assert_eq!(pending.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert!(
        pending.totp_pending && !pending.has_totp(),
        "pending until confirmed"
    );

    let code = totp_code(&decode("JBSWY3DPEHPK3PXP"), STEP);
    service
        .totp_confirm(user.id, &code)
        .await
        .expect("proof activates it");
    assert!(store.get_user(user.id).await.unwrap().unwrap().has_totp());
    assert!(matches!(
        service
            .totp_setup_with_secret(user.id, "JBSWY3DPEHPK3PXP")
            .await,
        Err(AuthError::TotpAlreadyEnabled)
    ));
}
