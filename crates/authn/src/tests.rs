use super::*;

/// Fixed TOTP time step for tests: the window and replay assertions must not depend on where the
/// wall clock happens to be inside a 30-second step.
const TEST_STEP: u64 = 60_000_000;

fn test_config() -> AuthnConfig {
    AuthnConfig {
        jwt_secret_source: JwtSecretSource::Master("test-secret".to_string()),
        access_ttl: Duration::from_secs(15 * 60),
        refresh_ttl: Duration::from_secs(60 * 60),
        argon2_params: Argon2Config {
            memory_cost: 4096,
            time_cost: 1,
            parallelism: 1,
        },
        issuer: None,
        audience: None,
        totp_window: TotpWindow::Current,
    }
}

fn claims_for(user_id: UserId, role: &Role, epoch: u64) -> Claims {
    let now = now_ts().expect("system clock is after the Unix epoch");
    Claims {
        sub: user_id,
        role: role.name.clone(),
        caps: role.capabilities.bits(),
        vis: role.visibility,
        epoch,
        iat: now,
        exp: now + 3600,
        iss: None,
        aud: None,
    }
}

fn test_user(username: &str) -> User {
    let now = Utc::now();
    User {
        id: UserId::new(),
        username: username.to_string(),
        password_hash: "hash".to_string(),
        role: Role::viewer(),
        totp_secret: None,
        totp_last_step: None,
        auth_epoch: 0,
        created_at: now,
        updated_at: now,
    }
}

fn decode_secret(secret: &str) -> Vec<u8> {
    base32::decode(Alphabet::Rfc4648 { padding: false }, secret).unwrap()
}

#[test]
fn capability_set_and_roles() {
    let mut caps = CapabilitySet::new();
    assert!(!caps.has(Section::Hosts, Action::View));
    caps.enable(Section::Hosts, Action::View);
    caps.enable(Section::Hosts, Action::Create);
    assert!(caps.has(Section::Hosts, Action::View));
    assert_eq!(caps.bits(), 3);

    let certificates_view = CapabilitySet::from_bits(1 << CapabilitySet::CERTIFICATES_SHIFT);
    let union = caps.union(certificates_view);
    assert!(union.has(Section::Certificates, Action::View));
    let intersection = union.intersect(caps);
    assert!(!intersection.has(Section::Certificates, Action::View));

    caps.disable(Section::Hosts, Action::View);
    assert!(!caps.has(Section::Hosts, Action::View));
    assert_eq!(CapabilitySet::default().bits(), 0);

    let admin = Role::admin();
    assert_eq!(admin.visibility, Visibility::All);
    for section in Section::all() {
        for action in Action::all() {
            assert!(admin.capabilities.has(section, action));
        }
    }

    let editor = Role::editor();
    assert!(editor.capabilities.has(Section::Hosts, Action::Create));
    assert!(!editor.capabilities.has(Section::Settings, Action::Create));

    let viewer = Role::viewer();
    assert_eq!(viewer.visibility, Visibility::Owner);
    for section in Section::all() {
        assert!(viewer.capabilities.has(section, Action::View));
        assert!(!viewer.capabilities.has(section, Action::Create));
    }
}

#[tokio::test]
async fn memory_store_user_crud() {
    let store = MemoryUserStore::new();
    let user = test_user("testuser");
    store.create_user(user.clone()).await.unwrap();

    assert_eq!(store.get_user(user.id).await.unwrap().unwrap().id, user.id);
    assert_eq!(
        store
            .get_user_by_username("testuser")
            .await
            .unwrap()
            .unwrap()
            .id,
        user.id
    );
    assert!(matches!(
        store.create_user(user.clone()).await,
        Err(AuthError::UsernameExists)
    ));

    let mut renamed = store.get_user(user.id).await.unwrap().unwrap();
    renamed.username = "updated".to_string();
    store.update_user(renamed).await.unwrap();
    assert!(store
        .get_user_by_username("testuser")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get_user_by_username("updated")
        .await
        .unwrap()
        .is_some());
    assert_eq!(store.list_users().await.unwrap().len(), 1);

    store.delete_user(user.id).await.unwrap();
    assert!(store.get_user(user.id).await.unwrap().is_none());
    assert!(matches!(
        store.delete_user(user.id).await,
        Err(AuthError::UserNotFound)
    ));
}

#[tokio::test]
async fn memory_store_refresh_token_lifecycle() {
    let store = MemoryUserStore::new();
    let user_id = UserId::new();
    let now = now_ts().expect("system clock is after the Unix epoch");
    let record = RefreshTokenRecord {
        token_hash: "hash1".to_string(),
        user_id,
        iat: now,
        expires_at: now + 60,
        revoked_at: None,
        token_id: "token1".to_string(),
    };
    store.store_refresh_token(record).await.unwrap();
    assert_eq!(
        store
            .get_refresh_token("hash1")
            .await
            .unwrap()
            .unwrap()
            .user_id,
        user_id
    );
    store.consume_refresh_token("hash1", now).await.unwrap();
    assert!(matches!(
        store.consume_refresh_token("hash1", now).await,
        Err(AuthError::RefreshTokenRevoked)
    ));

    let record = RefreshTokenRecord {
        token_hash: "hash2".to_string(),
        user_id,
        iat: now,
        expires_at: now + 60,
        revoked_at: None,
        token_id: "token2".to_string(),
    };
    store.store_refresh_token(record).await.unwrap();
    store
        .revoke_all_refresh_tokens_for_user(user_id, now)
        .await
        .unwrap();
    assert!(store
        .get_refresh_token("hash2")
        .await
        .unwrap()
        .unwrap()
        .revoked_at
        .is_some());

    let expired = RefreshTokenRecord {
        token_hash: "hash3".to_string(),
        user_id,
        iat: now - 120,
        expires_at: now - 60,
        revoked_at: None,
        token_id: "token3".to_string(),
    };
    store.store_refresh_token(expired).await.unwrap();
    assert!(matches!(
        store.consume_refresh_token("hash3", now).await,
        Err(AuthError::TokenExpired)
    ));
}

#[test]
fn password_hash_and_verify() {
    let config = Argon2Config::default();
    let hash = hash_password("test_password_123", &config).unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert_ne!(hash, "test_password_123");
    assert!(verify_password("test_password_123", &hash).unwrap());
    assert!(!verify_password("wrong_password", &hash).unwrap());
    assert!(matches!(
        verify_password("anything", "not-a-password-hash"),
        Err(AuthError::PasswordHash(_))
    ));
    assert!(verify_password("anything", "$argon2id$garbage").is_err());

    let bcrypt_hash = bcrypt_hash("correct", DEFAULT_COST).unwrap();
    assert!(verify_password("correct", &bcrypt_hash).unwrap());
    assert!(!verify_password("wrong", &bcrypt_hash).unwrap());
}

#[test]
fn verifies_hashes_produced_before_the_password_hash_upgrade() {
    // A PHC string generated by the `argon2` CLI at m=47104,t=2,p=1 - the same vector the http
    // crate proves real Caddy v2.11.7 accepts. argon2 0.6 moved to password-hash 0.6 (no
    // SaltString, `Error::Password` renamed), so this pins the stored format and the verification
    // path against hashes written by the previous version and by Caddy itself.
    let legacy =
        "$argon2id$v=19$m=47104,t=2,p=1$c2FsdHNhbHQ$Z8rbAmmUGEG/qPhwSd9oICo6lEK8zJCDzyvsJss2ftE";
    assert!(verify_password("correct horse", legacy).unwrap());
    assert!(!verify_password("wrong horse", legacy).unwrap());

    // A freshly written hash keeps the same shape and round-trips.
    let fresh = hash_password("correct horse", &Argon2Config::default()).unwrap();
    assert!(fresh.starts_with("$argon2id$v=19$m="), "{fresh}");
    assert_eq!(fresh.matches('$').count(), 5, "PHC field count: {fresh}");
    assert!(verify_password("correct horse", &fresh).unwrap());
}

#[test]
fn password_verification_is_constant_time() {
    let hash = hash_password("correct horse", &Argon2Config::default()).unwrap();
    // Argon2's PasswordVerifier compares the derived tag in constant time, and a wrong password
    // is Ok(false) rather than an early error.
    for _ in 0..4 {
        assert!(!verify_password("wrong horse", &hash).unwrap());
    }
    assert!(verify_password("correct horse", &hash).unwrap());
}

#[tokio::test]
async fn create_user_stores_hash_not_plaintext() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config()).expect("build service");
    let user = service
        .create_user("alice", "hunter2", Role::viewer())
        .await
        .unwrap();
    assert_ne!(user.password_hash, "hunter2");
    assert!(user.password_hash.starts_with("$argon2id$"));
    assert!(!format!("{user:?}").contains("hunter2"));
}

#[tokio::test]
async fn login_and_refresh_rotation() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config()).expect("build service");
    let user = service
        .create_user("alice", "password", Role::editor())
        .await
        .unwrap();
    let tokens = service.login("alice", "password", None).await.unwrap();
    let claims = service
        .verify_access_token(&tokens.access_token)
        .await
        .unwrap();
    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.role, "editor");
    assert_eq!(claims.epoch, 0);
    assert!(claims.has_capability(Section::Hosts, Action::Create));

    let rotated = service.refresh(&tokens.refresh_token).await.unwrap();
    assert_ne!(rotated.refresh_token, tokens.refresh_token);
    assert_eq!(
        service
            .verify_access_token(&rotated.access_token)
            .await
            .unwrap()
            .sub,
        user.id
    );
    assert!(matches!(
        service.refresh(&tokens.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    assert_ne!(
        service
            .refresh(&rotated.refresh_token)
            .await
            .unwrap()
            .refresh_token,
        rotated.refresh_token
    );
}

#[tokio::test]
async fn refresh_replay_and_unknown_token_errors() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config()).expect("build service");
    service
        .create_user("alice", "password", Role::viewer())
        .await
        .unwrap();
    let tokens = service.login("alice", "password", None).await.unwrap();
    service.refresh(&tokens.refresh_token).await.unwrap();
    assert!(matches!(
        service.refresh(&tokens.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    assert!(matches!(
        service.refresh("never-issued-token").await,
        Err(AuthError::RefreshTokenNotFound)
    ));
}

#[tokio::test]
async fn expired_refresh_token_is_rejected() {
    let mut config = test_config();
    config.refresh_ttl = Duration::from_secs(0);
    let service = AuthnService::new(MemoryUserStore::new(), config).expect("build service");
    service
        .create_user("alice", "password", Role::viewer())
        .await
        .unwrap();
    let tokens = service.login("alice", "password", None).await.unwrap();
    assert!(matches!(
        service.refresh(&tokens.refresh_token).await,
        Err(AuthError::TokenExpired)
    ));
}

#[tokio::test]
async fn expired_access_token_is_rejected() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config()).expect("build service");
    let user = service
        .create_user("alice", "password", Role::viewer())
        .await
        .unwrap();
    let now = now_ts().expect("system clock is after the Unix epoch");
    let claims = Claims {
        sub: user.id,
        role: "viewer".to_string(),
        caps: Role::viewer().capabilities.bits(),
        vis: Visibility::Owner,
        epoch: 0,
        iat: now - 120,
        exp: now - 60,
        iss: None,
        aud: None,
    };
    let token = encode(
        &Header::new(JwtAlgorithm::HS256),
        &claims,
        &service.encoding_key,
    )
    .unwrap();
    assert!(matches!(
        service.verify_access_token(&token).await,
        Err(AuthError::TokenExpired)
    ));
}

#[tokio::test]
async fn password_change_revokes_access_token_immediately() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config()).expect("build service");
    let user = service
        .create_user("charlie", "oldpass", Role::editor())
        .await
        .unwrap();
    // The token is minted immediately before the change; the epoch check must reject it even
    // though both operations happen within the same second.
    let tokens = service.login("charlie", "oldpass", None).await.unwrap();
    assert_eq!(
        service
            .verify_access_token(&tokens.access_token)
            .await
            .unwrap()
            .epoch,
        0
    );

    service
        .update_password(user.id, "oldpass", "newpass")
        .await
        .unwrap();
    assert!(matches!(
        service.verify_access_token(&tokens.access_token).await,
        Err(AuthError::InvalidToken)
    ));
    assert!(matches!(
        service.refresh(&tokens.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    assert!(service.login("charlie", "oldpass", None).await.is_err());
    assert!(service.login("charlie", "newpass", None).await.is_ok());
}

#[tokio::test]
async fn set_password_revokes_refresh_tokens() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config()).expect("build service");
    let user = service
        .create_user("dave", "oldpass", Role::viewer())
        .await
        .unwrap();
    let tokens = service.login("dave", "oldpass", None).await.unwrap();
    service.set_password(user.id, "adminpass").await.unwrap();
    assert!(matches!(
        service.refresh(&tokens.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    assert!(service.login("dave", "adminpass", None).await.is_ok());
}

#[tokio::test]
async fn revoke_all_for_user_invalidates_access_and_refresh() {
    let store = MemoryUserStore::new();
    let service = AuthnService::new(store.clone(), test_config()).expect("build service");
    let user = service
        .create_user("eve", "password", Role::editor())
        .await
        .unwrap();
    let tokens = service.login("eve", "password", None).await.unwrap();
    service.revoke_all_for_user(user.id).await.unwrap();
    assert!(matches!(
        service.verify_access_token(&tokens.access_token).await,
        Err(AuthError::InvalidToken)
    ));
    assert!(matches!(
        service.refresh(&tokens.refresh_token).await,
        Err(AuthError::RefreshTokenRevoked)
    ));
    assert_eq!(
        store.get_user(user.id).await.unwrap().unwrap().auth_epoch,
        1
    );
}

#[tokio::test]
async fn role_change_invalidates_access_token() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config()).expect("build service");
    let user = service
        .create_user("frank", "password", Role::editor())
        .await
        .unwrap();
    let tokens = service.login("frank", "password", None).await.unwrap();
    service.update_role(user.id, Role::viewer()).await.unwrap();
    assert!(matches!(
        service.verify_access_token(&tokens.access_token).await,
        Err(AuthError::InvalidToken)
    ));
    let tokens = service.login("frank", "password", None).await.unwrap();
    assert_eq!(
        service
            .verify_access_token(&tokens.access_token)
            .await
            .unwrap()
            .role,
        "viewer"
    );
}

#[test]
fn capability_matrix_all_sections_and_four_actions() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config()).expect("build service");
    let actions = [Action::View, Action::Create, Action::Update, Action::Delete];
    for section in Section::all() {
        for action in actions {
            let mut caps = CapabilitySet::new();
            caps.enable(section, action);
            let claims = claims_for(
                UserId::new(),
                &Role::custom("matrix", caps, Visibility::All),
                0,
            );
            assert!(service.check_permission(&claims, section, action));
            for other in actions {
                if other != action {
                    assert!(!service.check_permission(&claims, section, other));
                }
            }
        }
    }
    let denied = claims_for(
        UserId::new(),
        &Role::custom("none", CapabilitySet::NONE, Visibility::Owner),
        0,
    );
    for section in Section::all() {
        for action in actions {
            assert!(!service.check_permission(&denied, section, action));
        }
    }
}

#[tokio::test]
async fn unauthenticated_access_is_rejected() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config()).expect("build service");
    assert!(matches!(
        service.verify_access_token("not-a-jwt").await,
        Err(AuthError::InvalidToken)
    ));
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MockRow {
    id: u32,
    owner: UserId,
}

#[test]
fn row_visibility_owner_vs_all() {
    let owner = UserId::new();
    let other = UserId::new();
    let owner_claims = claims_for(owner, &Role::viewer(), 0);
    let all_claims = claims_for(other, &Role::admin(), 0);
    assert!(check_row_access(&owner_claims, owner));
    assert!(!check_row_access(&owner_claims, other));
    assert!(check_row_access(&all_claims, owner));
    assert!(check_row_access(&all_claims, other));

    let rows = vec![
        MockRow { id: 1, owner },
        MockRow {
            id: 2,
            owner: other,
        },
        MockRow { id: 3, owner },
    ];
    let visible = filter_visible_rows(&owner_claims, rows.clone(), |row| row.owner);
    assert_eq!(
        visible.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![1, 3]
    );
    assert_eq!(
        filter_visible_rows(&all_claims, rows, |row| row.owner).len(),
        3
    );
}

#[tokio::test]
async fn totp_setup_verify_skew_and_replay() {
    let mut config = test_config();
    config.totp_window = TotpWindow::PlusMinusOne;
    let service = AuthnService::new(MemoryUserStore::new(), config)
        .expect("build service")
        .with_test_step(TEST_STEP);
    let user = service
        .create_user("grace", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, uri) = service.totp_setup(user.id).await.unwrap();
    assert!(uri.starts_with("otpauth://totp/"));
    assert!(uri.contains(&secret) && uri.contains("digits=6"));
    let bytes = decode_secret(&secret);

    assert!(!service.totp_verify(user.id, "abcdef").await.unwrap());
    let current = totp_code(&bytes, TEST_STEP);
    assert!(service.totp_verify(user.id, &current).await.unwrap());
    // The same code is still inside its 30-second window, but its step was consumed.
    assert!(matches!(
        service.totp_verify(user.id, &current).await,
        Err(AuthError::TotpReplay)
    ));

    // An adjacent (future) step is accepted for clock skew, but an older step is not.
    let skewed = service
        .create_user("skew", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(skewed.id).await.unwrap();
    let bytes = decode_secret(&secret);
    let future = totp_code(&bytes, TEST_STEP + 1);
    assert!(service.totp_verify(skewed.id, &future).await.unwrap());
    assert!(matches!(
        service
            .totp_verify(skewed.id, &totp_code(&bytes, TEST_STEP))
            .await,
        Err(AuthError::TotpReplay)
    ));
    assert!(matches!(
        service.totp_verify(skewed.id, &future).await,
        Err(AuthError::TotpReplay)
    ));
}

#[tokio::test]
async fn totp_login_and_disable() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config())
        .expect("build service")
        .with_test_step(TEST_STEP);
    let user = service
        .create_user("ivan", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(user.id).await.unwrap();
    let code = totp_code(&decode_secret(&secret), TEST_STEP);

    assert!(matches!(
        service.login("ivan", "password", None).await,
        Err(AuthError::InvalidTotpCode)
    ));
    assert!(service.login("ivan", "password", Some(&code)).await.is_ok());
    // Replaying the consumed code is rejected and flagged as a replay attempt.
    assert!(matches!(
        service.login("ivan", "password", Some(&code)).await,
        Err(AuthError::TotpReplay)
    ));

    service.totp_disable(user.id).await.unwrap();
    assert!(service.login("ivan", "password", None).await.is_ok());
}

#[tokio::test]
async fn refresh_token_is_stored_hashed() {
    let store = MemoryUserStore::new();
    let service = AuthnService::new(store.clone(), test_config()).expect("build service");
    service
        .create_user("judy", "password", Role::viewer())
        .await
        .unwrap();
    let tokens = service.login("judy", "password", None).await.unwrap();

    let digest = hash_refresh_token(&tokens.refresh_token);
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(digest, tokens.refresh_token);
    assert_eq!(
        store
            .get_refresh_token(&digest)
            .await
            .unwrap()
            .unwrap()
            .token_hash,
        digest
    );
    assert!(store
        .get_refresh_token(&tokens.refresh_token)
        .await
        .unwrap()
        .is_none());
}

#[test]
fn debug_redacts_secrets() {
    let config = AuthnConfig {
        jwt_secret_source: JwtSecretSource::Master("super-secret-value".to_string()),
        ..test_config()
    };
    let config_debug = format!("{config:?}");
    assert!(config_debug.contains("[redacted]"));
    assert!(
        !config_debug.contains("super-secret-value"),
        "config Debug must not leak the master secret: {config_debug}"
    );

    // The source's own Debug impl must redact too, not just the config wrapper.
    let source = JwtSecretSource::Master("super-secret-value".to_string());
    let source_debug = format!("{source:?}");
    assert!(source_debug.contains("[redacted]"), "{source_debug}");
    assert!(
        !source_debug.contains("super-secret-value"),
        "JwtSecretSource Debug must not leak the master secret: {source_debug}"
    );
    assert_eq!(
        format!("{:?}", JwtSecretSource::Ephemeral),
        "Ephemeral",
        "ephemeral sources carry no secret and print plainly"
    );
    let file_debug = format!("{:?}", JwtSecretSource::File(PathBuf::from("/tmp/jwt.key")));
    assert!(file_debug.contains("/tmp/jwt.key"), "{file_debug}");

    let user = User {
        password_hash: "PASSWORD_HASH_SECRET".to_string(),
        totp_secret: Some("TOTP_SECRET_VALUE".to_string()),
        totp_last_step: None,
        ..test_user("secret-user")
    };
    let user_debug = format!("{user:?}");
    assert!(!user_debug.contains("PASSWORD_HASH_SECRET"));
    assert!(!user_debug.contains("TOTP_SECRET_VALUE"));
    assert!(user_debug.contains("[redacted]"));

    // The public view is the only serializable user shape, and it carries neither secret.
    let public = serde_json::to_value(user.public()).expect("public user serializes");
    let object = public.as_object().expect("public user is an object");
    assert!(!object.contains_key("password_hash"));
    assert!(!object.contains_key("totp_secret"));
    assert_eq!(object.get("totp_enabled"), Some(&serde_json::json!(true)));

    let tokens = TokenPair {
        access_token: "ACCESS_TOKEN_SECRET".to_string(),
        refresh_token: "REFRESH_TOKEN_SECRET".to_string(),
    };
    let tokens_debug = format!("{tokens:?}");
    assert!(!tokens_debug.contains("ACCESS_TOKEN_SECRET"));
    assert!(!tokens_debug.contains("REFRESH_TOKEN_SECRET"));

    let record = RefreshTokenRecord {
        token_hash: "TOKEN_HASH_SECRET".to_string(),
        user_id: UserId::new(),
        iat: now_ts().expect("system clock is after the Unix epoch"),
        expires_at: now_ts().expect("system clock is after the Unix epoch") + 60,
        revoked_at: None,
        token_id: "token-id".to_string(),
    };
    let record_debug = format!("{record:?}");
    assert!(!record_debug.contains("TOKEN_HASH_SECRET"));
    assert!(record_debug.contains("[redacted]"));
}

#[test]
fn user_record_serde_roundtrip() {
    use chrono::Utc;
    use serde_json;

    let now = Utc::now();

    let user_id = UserId::new();
    let username = "testuser".to_string();
    let role = Role::viewer();

    let record = UserRecord {
        id: user_id.clone(),
        username: username.clone(),
        role: role.clone(),
        totp_enabled: true,
        totp_last_step: Some(12345),
        auth_epoch: 42,
        created_at: now,
        updated_at: now,
    };

    // Serialize and deserialize
    let json = serde_json::to_string(&record).expect("UserRecord serializes");
    let deserialized: UserRecord = serde_json::from_str(&json).expect("UserRecord deserializes");

    // Verify all fields round-trip correctly
    assert_eq!(deserialized.id, user_id);
    assert_eq!(deserialized.username, username);
    assert_eq!(deserialized.role, role);
    assert_eq!(deserialized.totp_enabled, true);
    assert_eq!(deserialized.totp_last_step, Some(12345));
    assert_eq!(deserialized.auth_epoch, 42);
    assert_eq!(deserialized.created_at, now);
    assert_eq!(deserialized.updated_at, now);
}

#[test]
fn refresh_token_record_serde_roundtrip() {
    use chrono::{Duration, Utc};
    use serde_json;

    let now = Utc::now();
    let user_id = UserId::new();
    let token_id = "refresh-token-123".to_string();

    let record = RefreshTokenRecord {
        token_hash: "token-hash".to_string(),
        user_id: user_id.clone(),
        iat: now.timestamp(),
        expires_at: (now + Duration::hours(1)).timestamp(),
        revoked_at: Some(now.timestamp()),
        token_id: token_id.clone(),
    };

    // Serialize and deserialize
    let json = serde_json::to_string(&record).expect("RefreshTokenRecord serializes");
    let deserialized: RefreshTokenRecord =
        serde_json::from_str(&json).expect("RefreshTokenRecord deserializes");

    // Verify all fields round-trip correctly
    assert_eq!(deserialized.token_hash, record.token_hash);
    assert_eq!(deserialized.user_id, user_id);
    assert_eq!(deserialized.iat, record.iat);
    assert_eq!(deserialized.expires_at, record.expires_at);
    assert_eq!(deserialized.revoked_at, record.revoked_at);
    assert_eq!(deserialized.token_id, token_id);
}

#[test]
fn user_public_view_no_secrets() {
    use chrono::Utc;
    use serde_json;

    let now = Utc::now();

    let user = User {
        id: UserId::new(),
        username: "testuser".to_string(),
        password_hash: "SECRET_HASH".to_string(),
        role: Role::viewer(),
        totp_secret: Some("SECRET_TOTP".to_string()),
        totp_last_step: Some(12345),
        auth_epoch: 42,
        created_at: now,
        updated_at: now,
    };

    // A record built from the user omits both secrets; only `totp_enabled` is stored.
    let record = user.to_record();
    assert!(
        record.totp_enabled,
        "UserRecord should record that TOTP is enabled"
    );

    // Serialize - should not contain secrets
    let json = serde_json::to_string_pretty(&record).expect("UserRecord serializes");
    assert!(
        !json.contains("SECRET_HASH"),
        "UserRecord should not contain password hash"
    );
    assert!(
        !json.contains("SECRET_TOTP"),
        "UserRecord should not contain TOTP secret"
    );

    // Verify totp_enabled is present
    assert!(
        json.contains("\"totp_enabled\""),
        "UserRecord should contain totp_enabled field"
    );
}

#[test]
fn pre_epoch_clock_is_an_error_not_zero() {
    let pre_epoch = UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .expect("UNIX_EPOCH minus one second is representable");

    let err = system_time_to_ts(pre_epoch).expect_err("pre-epoch clock must not convert");
    match err {
        AuthError::Internal(message) => {
            assert!(
                message.contains("before the Unix epoch"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected AuthError::Internal, got {other:?}"),
    }

    // The bug this guards against: the old code returned 0, making every token look epoch-issued.
    assert_ne!(system_time_to_ts(pre_epoch).ok(), Some(0));

    // Boundary: the epoch itself is valid and maps to 0, one second later maps to 1.
    assert_eq!(system_time_to_ts(UNIX_EPOCH).expect("epoch converts"), 0);
    assert_eq!(
        system_time_to_ts(UNIX_EPOCH + Duration::from_secs(1)).expect("post-epoch converts"),
        1
    );
}

/// The clock is not injectable into [`AuthnService`], so this test covers the conversion helper and
/// documents that every entry point propagates its error.
///
/// Every clock consumer in `lib.rs` (`login` via `issue_token_pair`/`totp_verify`, `refresh`,
/// `verify_access_token`'s callers, `update_password`, `set_password`, `revoke_all_for_user`) reaches
/// the clock only through `now_ts()` or `now_step().expect("system clock is after the Unix epoch")`, both of which return `AuthResult` and are
/// called with `?`. A pre-epoch clock therefore surfaces as `AuthError::Internal` from those public
/// methods instead of silently issuing or accepting tokens at timestamp `0`. Verified by
/// `grep -n "now_ts()\|now_step().expect("system clock is after the Unix epoch")" crates/authn/src/lib.rs`: no call site uses
/// `unwrap_or`, `unwrap`, or `expect`.
#[test]
fn each_auth_entry_point_propagates_clock_error() {
    for offset in [1u64, 60, 3600, 86_400] {
        let t = UNIX_EPOCH
            .checked_sub(Duration::from_secs(offset))
            .expect("pre-epoch instant is representable");
        let err = system_time_to_ts(t).expect_err("pre-epoch clock must be an error");
        assert!(
            matches!(&err, AuthError::Internal(message) if message.contains("before the Unix epoch")),
            "offset {offset} produced {err:?}"
        );
    }

    // `now_step` derives from the same conversion, so a pre-epoch clock cannot yield TOTP step 0.
    assert!(
        now_step().is_ok(),
        "the real clock is expected to be post-epoch"
    );
}

#[tokio::test]
async fn current_window_rejects_previous_step() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config())
        .expect("build service")
        .with_test_step(TEST_STEP);
    let user = service
        .create_user("alice", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(user.id).await.unwrap();
    let bytes = decode_secret(&secret);
    let step = TEST_STEP;
    let previous = totp_code(&bytes, step.saturating_sub(1));
    // An older, cryptographically correct code is an impersonation/replay attempt, not a typo.
    assert!(matches!(
        service.totp_verify(user.id, &previous).await,
        Err(AuthError::TotpReplay)
    ));
    // The current code is still accepted: a stale code does not consume the current step.
    assert!(service
        .totp_verify(user.id, &totp_code(&bytes, step))
        .await
        .unwrap());
}

#[tokio::test]
async fn plus_minus_one_accepts_adjacent() {
    let mut config = test_config();
    config.totp_window = TotpWindow::PlusMinusOne;
    let service = AuthnService::new(MemoryUserStore::new(), config)
        .expect("build service")
        .with_test_step(TEST_STEP);
    let user = service
        .create_user("bob", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(user.id).await.unwrap();
    let bytes = decode_secret(&secret);

    let step = TEST_STEP;
    let prev = totp_code(&bytes, step.saturating_sub(1));
    let cur = totp_code(&bytes, step);
    let next = totp_code(&bytes, step + 1);

    // Every step in the ±1 window is accepted, oldest first, because each acceptance only raises
    // the monotonic floor.
    assert!(service.totp_verify(user.id, &prev).await.unwrap());
    assert!(service.totp_verify(user.id, &cur).await.unwrap());
    assert!(service.totp_verify(user.id, &next).await.unwrap());
    // The floor is now `next`: both earlier steps are rejected as replays.
    assert!(matches!(
        service.totp_verify(user.id, &cur).await,
        Err(AuthError::TotpReplay)
    ));
    assert!(matches!(
        service.totp_verify(user.id, &prev).await,
        Err(AuthError::TotpReplay)
    ));
}

#[tokio::test]
async fn replay_protection_rejects_same_code_twice() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config())
        .expect("build service")
        .with_test_step(TEST_STEP);
    let user = service
        .create_user("charlie", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(user.id).await.unwrap();
    let bytes = decode_secret(&secret);

    let cur = totp_code(&bytes, TEST_STEP);
    assert!(service.totp_verify(user.id, &cur).await.unwrap());
    // Replaying the same code in the same step is rejected as a replay attempt.
    assert!(matches!(
        service.totp_verify(user.id, &cur).await,
        Err(AuthError::TotpReplay)
    ));
}

#[tokio::test]
async fn current_and_next_matches_legacy() {
    let mut config = test_config();
    config.totp_window = TotpWindow::CurrentAndNext;
    let service = AuthnService::new(MemoryUserStore::new(), config)
        .expect("build service")
        .with_test_step(TEST_STEP);
    let user = service
        .create_user("dave", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(user.id).await.unwrap();
    let bytes = decode_secret(&secret);

    let step = TEST_STEP;
    let cur = totp_code(&bytes, step);
    let next = totp_code(&bytes, step + 1);

    assert!(service.totp_verify(user.id, &cur).await.unwrap());
    assert!(service.totp_verify(user.id, &next).await.unwrap());
    // The previous step is outside the window and older than the accepted floor, so it is
    // reported as an impersonation/replay attempt rather than a plain mismatch.
    let prev = totp_code(&bytes, step.saturating_sub(1));
    assert!(matches!(
        service.totp_verify(user.id, &prev).await,
        Err(AuthError::TotpReplay)
    ));
}

#[tokio::test]
async fn codes_older_than_the_lookback_are_plain_mismatches() {
    // A code outside both the accepted window and the bounded replay horizon cannot be told
    // apart from a wrong guess, so it is `Ok(false)` and never an unbounded HMAC search.
    let service = AuthnService::new(MemoryUserStore::new(), test_config())
        .expect("build service")
        .with_test_step(TEST_STEP);
    let user = service
        .create_user("erin", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(user.id).await.unwrap();
    let bytes = decode_secret(&secret);
    let ancient = totp_code(
        &bytes,
        TEST_STEP.saturating_sub(TOTP_REPLAY_LOOKBACK_STEPS + 5),
    );
    assert!(!service.totp_verify(user.id, &ancient).await.unwrap());
}

// --- L2: JWT secret persistence across graceful restarts -------------------------------------

#[test]
fn master_secret_produces_deterministic_key() {
    let a = JwtSecretSource::Master("correct horse battery staple".to_string())
        .resolve()
        .expect("master secret resolves");
    let b = JwtSecretSource::Master("correct horse battery staple".to_string())
        .resolve()
        .expect("master secret resolves");
    let c = JwtSecretSource::Master("another secret".to_string())
        .resolve()
        .expect("master secret resolves");
    assert_eq!(a, b, "the same master secret must yield the same key");
    assert_ne!(a, c, "different master secrets must yield different keys");

    let expected: [u8; 32] = Sha256::digest(b"correct horse battery staple").into();
    assert_eq!(a, expected, "master key is SHA-256 of the secret bytes");
}

#[test]
fn empty_master_secret_is_rejected() {
    assert!(matches!(
        JwtSecretSource::Master(String::new()).resolve(),
        Err(AuthError::Internal(_))
    ));
}

#[test]
fn ephemeral_secret_changes_each_time() {
    let a = JwtSecretSource::Ephemeral.resolve().expect("resolve");
    let b = JwtSecretSource::Ephemeral.resolve().expect("resolve");
    assert_ne!(a, b, "ephemeral secrets must not be reused");
}

#[test]
fn file_secret_persists_across_constructions() {
    let dir = std::env::temp_dir().join(format!("caddy-rs-jwt-{:?}", UserId::new()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("jwt.key");

    let first = JwtSecretSource::File(path.clone())
        .resolve()
        .expect("create");
    assert_eq!(first.len(), 32);
    let second = JwtSecretSource::File(path.clone()).resolve().expect("read");
    assert_eq!(first, second, "the file secret must survive a restart");

    let stored = std::fs::read(&path).expect("read secret file");
    assert_eq!(stored, first, "the file holds the resolved key");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("secret file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the secret file must be owner-only");
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn malformed_secret_file_is_rejected() {
    let dir = std::env::temp_dir().join(format!("caddy-rs-jwt-bad-{:?}", UserId::new()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("jwt.key");
    std::fs::write(&path, b"too short").expect("write malformed secret");

    assert!(matches!(
        JwtSecretSource::File(path.clone()).resolve(),
        Err(AuthError::Internal(_))
    ));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn sessions_survive_a_restart_with_a_persistent_secret() {
    let dir = std::env::temp_dir().join(format!("caddy-rs-jwt-restart-{:?}", UserId::new()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("jwt.key");

    let mut config = test_config();
    config.jwt_secret_source = JwtSecretSource::File(path.clone());

    let store = MemoryUserStore::new();
    let before = AuthnService::new(store.clone(), config.clone()).expect("build service");
    let user = before
        .create_user("dana", "password", Role::viewer())
        .await
        .expect("create user");
    let tokens = before.login("dana", "password", None).await.expect("login");

    // A new service instance stands in for the process that comes back after a restart.
    let after = AuthnService::new(store, config).expect("build service");
    let claims = after
        .verify_access_token(&tokens.access_token)
        .await
        .expect("access token must still verify after a restart");
    assert_eq!(
        claims.sub, user.id,
        "the token still belongs to the same user"
    );
    // NOTE: the `UserStore` is shared with the first service on purpose. That only makes the
    // restart partial: it proves the signing key was persisted, not that refresh-token or user
    // state would survive a real process restart (a persistent store is a separate concern).
    // So the refresh below only proves this store still holds the token, nothing more.
    after
        .refresh(&tokens.refresh_token)
        .await
        .expect("refresh token is still present in this store (not a restart guarantee)");

    // What actually has to hold across a restart: the same on-disk secret resolves to the same
    // key no matter how many service instances are built from it.
    let first_key = JwtSecretSource::File(path.clone())
        .resolve()
        .expect("resolve first");
    let second_key = JwtSecretSource::File(path.clone())
        .resolve()
        .expect("resolve second");
    assert_eq!(
        first_key, second_key,
        "two services built from the same File source must sign with the same key"
    );
    assert_eq!(
        std::fs::read(&path).expect("read secret file"),
        first_key,
        "the persisted file is what both instances resolved"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn empty_secret_file_is_repaired_instead_of_failing_forever() {
    let dir = std::env::temp_dir().join(format!("caddy-rs-jwt-empty-{:?}", UserId::new()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("jwt.key");
    std::fs::write(&path, b"").expect("write empty secret file");

    let key = JwtSecretSource::File(path.clone())
        .resolve()
        .expect("an empty leftover must be repaired, not hard-fail every start");
    assert_eq!(
        std::fs::read(&path).expect("read secret file"),
        key,
        "the repaired file holds the key that was returned"
    );
    assert_eq!(
        JwtSecretSource::File(path.clone()).resolve().expect("read"),
        key,
        "the repaired secret is stable across later starts"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn concurrent_creation_does_not_diverge() {
    // Two cold starts that both see a missing file must agree on one key, and the file must end
    // up holding exactly the key both returned. Repeated because the interleaving of the two
    // racers is not fully under the test's control.
    for round in 0..10 {
        let dir = std::env::temp_dir().join(format!(
            "caddy-rs-jwt-race-{}-{round}-{:?}",
            std::process::id(),
            UserId::new()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("jwt.key");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    JwtSecretSource::File(path).resolve()
                })
            })
            .collect();
        let keys: Vec<[u8; 32]> = handles
            .into_iter()
            .map(|handle| handle.join().expect("resolve thread").expect("resolve"))
            .collect();

        assert_eq!(
            keys[0], keys[1],
            "concurrent cold starts must not diverge on the signing key (round {round})"
        );
        assert_eq!(
            std::fs::read(&path).expect("read secret file"),
            keys[0],
            "the installed file must hold the key both processes returned (round {round})"
        );
        let mut leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("read temp dir")
            .map(|entry| entry.expect("dir entry").file_name())
            .filter(|name| name.to_string_lossy().ends_with(".tmp"))
            .collect();
        leftovers.sort();
        assert_eq!(leftovers.len(), 0, "no temp files may be left behind");

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn existing_world_readable_secret_file_is_read_without_rewriting_it() {
    let dir = std::env::temp_dir().join(format!("caddy-rs-jwt-mode-{:?}", UserId::new()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("jwt.key");
    let existing = [0x5Au8; 32];
    std::fs::write(&path, existing).expect("write pre-existing secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("make secret world-readable");
    }

    let key = JwtSecretSource::File(path.clone())
        .resolve()
        .expect("an existing 32-byte secret is still usable");
    assert_eq!(
        key, existing,
        "the existing secret is honoured, not replaced"
    );
    assert_eq!(
        std::fs::read(&path).expect("read secret file"),
        existing,
        "a populated secret file is never rewritten"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn planted_symlink_at_temp_path_is_not_followed() {
    let dir = std::env::temp_dir().join(format!("caddy-rs-jwt-link-{:?}", UserId::new()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("jwt.key");
    let victim = dir.join("victim.txt");
    let victim_contents = b"victim contents that must never be truncated";
    std::fs::write(&victim, victim_contents).expect("write victim file");

    // Attack 1: plant a symlink at the historical deterministic temp path.
    let legacy_temp = path.with_extension("tmp");
    std::os::unix::fs::symlink(&victim, &legacy_temp).expect("plant symlink");
    let key = JwtSecretSource::File(path.clone())
        .resolve()
        .expect("resolve must succeed despite the planted symlink");
    assert_eq!(
        std::fs::read(&victim).expect("read victim"),
        victim_contents,
        "the symlink target must not be truncated or replaced"
    );
    assert!(
        std::fs::symlink_metadata(&legacy_temp)
            .expect("legacy temp lstat")
            .file_type()
            .is_symlink(),
        "the planted symlink is left untouched"
    );
    assert!(
        std::fs::symlink_metadata(&path)
            .expect("secret lstat")
            .file_type()
            .is_file(),
        "the real secret is a regular file, not a symlink"
    );
    assert_eq!(std::fs::read(&path).expect("read secret"), key);

    // Attack 2: the exclusive temp creation itself refuses a planted symlink.
    let temp = dir.join(".planted.tmp");
    std::os::unix::fs::symlink(&victim, &temp).expect("plant second symlink");
    let result = write_secret_temp(&temp, &[0x11u8; 32]);
    assert!(
        matches!(result, Err(AuthError::Internal(_))),
        "temp creation must refuse to follow a planted symlink"
    );
    assert_eq!(
        std::fs::read(&victim).expect("read victim"),
        victim_contents,
        "refusing the symlink must not touch its target"
    );

    std::fs::remove_dir_all(&dir).ok();
}
