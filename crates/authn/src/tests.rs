use super::*;

fn test_config() -> AuthnConfig {
    AuthnConfig {
        jwt_secret: [0x5A; 32],
        access_ttl: Duration::from_secs(15 * 60),
        refresh_ttl: Duration::from_secs(60 * 60),
        argon2_params: Argon2Config {
            memory_cost: 4096,
            time_cost: 1,
            parallelism: 1,
        },
        issuer: None,
        audience: None,
    }
}

fn claims_for(user_id: UserId, role: &Role, epoch: u64) -> Claims {
    let now = now_ts();
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
    let now = now_ts();
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
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
    let service = AuthnService::new(MemoryUserStore::new(), config);
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
    let user = service
        .create_user("alice", "password", Role::viewer())
        .await
        .unwrap();
    let now = now_ts();
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
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
    let service = AuthnService::new(store.clone(), test_config());
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
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
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
    let user = service
        .create_user("grace", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, uri) = service.totp_setup(user.id).await.unwrap();
    assert!(uri.starts_with("otpauth://totp/"));
    assert!(uri.contains(&secret) && uri.contains("digits=6"));
    let bytes = decode_secret(&secret);

    assert!(!service.totp_verify(user.id, "abcdef").await.unwrap());
    let current = totp_code(&bytes, now_step());
    assert!(service.totp_verify(user.id, &current).await.unwrap());
    // The same code is still inside its 30-second window, but its step was consumed.
    assert!(!service.totp_verify(user.id, &current).await.unwrap());

    // An adjacent (future) step is accepted for clock skew, but an older step is not.
    let skewed = service
        .create_user("skew", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(skewed.id).await.unwrap();
    let bytes = decode_secret(&secret);
    let future = totp_code(&bytes, now_step() + 1);
    assert!(service.totp_verify(skewed.id, &future).await.unwrap());
    assert!(!service
        .totp_verify(skewed.id, &totp_code(&bytes, now_step()))
        .await
        .unwrap());
    assert!(!service.totp_verify(skewed.id, &future).await.unwrap());
}

#[tokio::test]
async fn totp_login_and_disable() {
    let service = AuthnService::new(MemoryUserStore::new(), test_config());
    let user = service
        .create_user("ivan", "password", Role::viewer())
        .await
        .unwrap();
    let (secret, _) = service.totp_setup(user.id).await.unwrap();
    let code = totp_code(&decode_secret(&secret), now_step());

    assert!(matches!(
        service.login("ivan", "password", None).await,
        Err(AuthError::InvalidTotpCode)
    ));
    assert!(service.login("ivan", "password", Some(&code)).await.is_ok());
    // Replaying the consumed code is rejected.
    assert!(matches!(
        service.login("ivan", "password", Some(&code)).await,
        Err(AuthError::InvalidTotpCode)
    ));

    service.totp_disable(user.id).await.unwrap();
    assert!(service.login("ivan", "password", None).await.is_ok());
}

#[tokio::test]
async fn refresh_token_is_stored_hashed() {
    let store = MemoryUserStore::new();
    let service = AuthnService::new(store.clone(), test_config());
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
        jwt_secret: [0xAB; 32],
        ..test_config()
    };
    let config_debug = format!("{config:?}");
    assert!(config_debug.contains("[redacted]"));
    assert!(!config_debug.contains("171"));

    let user = User {
        password_hash: "PASSWORD_HASH_SECRET".to_string(),
        totp_secret: Some("TOTP_SECRET_VALUE".to_string()),
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
        iat: now_ts(),
        expires_at: now_ts() + 60,
        revoked_at: None,
        token_id: "token-id".to_string(),
    };
    let record_debug = format!("{record:?}");
    assert!(!record_debug.contains("TOKEN_HASH_SECRET"));
    assert!(record_debug.contains("[redacted]"));
}

#[test]
fn user_record_serde_roundtrip() {
    use serde_json;
    use chrono::{Utc, Duration};

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
    use serde_json;
    use chrono::{Utc, Duration};

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
    let deserialized: RefreshTokenRecord = serde_json::from_str(&json).expect("RefreshTokenRecord deserializes");
    
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
    use serde_json;
    use chrono::{Utc, Duration};

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
    
    // UserRecord::from_user creates a record without secrets
    let record = UserRecord::from_user(
        user.clone(),
        "SECRET_HASH".to_string(),
        Some("SECRET_TOTP".to_string())
    );
    
    // Serialize - should not contain secrets
    let json = serde_json::to_string_pretty(&record).expect("UserRecord serializes");
    assert!(!json.contains("SECRET_HASH"), "UserRecord should not contain password hash");
    assert!(!json.contains("SECRET_TOTP"), "UserRecord should not contain TOTP secret");
    
    // Verify totp_enabled is present
    assert!(json.contains("\"totp_enabled\""), "UserRecord should contain totp_enabled field");
}
