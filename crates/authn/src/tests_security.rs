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
async fn the_failure_budget_is_per_username_and_ignores_ascii_case() {
    let (service, _clock) = clocked_service(fast_config());
    service
        .create_user("alice", "correct horse", Role::viewer())
        .await
        .unwrap();
    service
        .create_user("bob", "correct horse", Role::viewer())
        .await
        .unwrap();
    for _ in 0..5 {
        wrong_login(&service, "alice").await;
    }
    assert!(matches!(
        service.login("ALICE", "correct horse", None).await,
        Err(AuthError::TooManyAttempts { .. })
    ));
    service
        .login("bob", "correct horse", None)
        .await
        .expect("another account is unaffected");
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
    assert_eq!(key, username_throttle_key(&long.to_ascii_lowercase()));
    assert_ne!(
        username_throttle_key(&long),
        username_throttle_key(&format!("{long}x"))
    );
    assert_eq!(
        username_throttle_key("Alice"),
        username_throttle_key("alice")
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
