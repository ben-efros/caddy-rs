//! Authentication and authorization service for caddy-rs.
//!
//! This crate provides a reusable authentication and authorization system with:
//! - User management with roles, capabilities, and visibility
//! - Password hashing (argon2id preferred, bcrypt fallback) with constant-time verification
//! - JWT access tokens and opaque refresh tokens with rotation
//! - TOTP two-factor authentication
//! - Permission checking based on roles, capabilities, and visibility
//! - Multiple storage backends (in-memory and persistent via pm-state adapter)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params as Argon2Params, Version,
};
use async_trait::async_trait;
use base32::Alphabet;
use bcrypt::{hash as bcrypt_hash, verify as bcrypt_verify, DEFAULT_COST};
use chrono::{DateTime, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm as JwtAlgorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use totp_lite::{totp, Sha1};
use uuid::Uuid;

/// Unique identifier for a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

impl UserId {
    /// Generate a new random user ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for UserId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// User role with capabilities and visibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// Role name (e.g., "admin", "editor", "viewer").
    pub name: String,
    /// Set of capabilities this role grants.
    pub capabilities: CapabilitySet,
    /// Visibility scope: All resources or only owner's resources.
    pub visibility: Visibility,
}

/// Visibility scope for a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Can access all resources in permitted sections.
    All,
    /// Can only access resources owned by the user.
    Owner,
}

impl Default for Visibility {
    fn default() -> Self {
        Self::Owner
    }
}

/// Bitflags for capabilities across different sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    /// No capabilities.
    pub const NONE: Self = Self(0);
    /// All capabilities.
    pub const ALL: Self = Self(u64::MAX);

    // Section bits (6 bits per section: View, Create, Update, Delete, Manage, Admin)
    const HOSTS_SHIFT: u64 = 0;
    const CERTIFICATES_SHIFT: u64 = 6;
    const ACCESS_LISTS_SHIFT: u64 = 12;
    const USERS_SHIFT: u64 = 18;
    const LOGS_SHIFT: u64 = 24;
    const SETTINGS_SHIFT: u64 = 30;

    /// Action bits within a section.
    const VIEW_BIT: u64 = 1 << 0;
    const CREATE_BIT: u64 = 1 << 1;
    const UPDATE_BIT: u64 = 1 << 2;
    const DELETE_BIT: u64 = 1 << 3;
    const MANAGE_BIT: u64 = 1 << 4;
    const ADMIN_BIT: u64 = 1 << 5;

    /// Create a new empty capability set.
    pub const fn new() -> Self {
        Self(0)
    }

    /// Create from raw bits.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Get raw bits.
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Check if a specific capability is set.
    pub fn has(&self, section: Section, action: Action) -> bool {
        let shift = section.shift();
        let bit = action.bit();
        (self.0 >> shift) & bit != 0
    }

    /// Set a specific capability.
    pub fn set(&mut self, section: Section, action: Action, value: bool) {
        let shift = section.shift();
        let bit = action.bit();
        if value {
            self.0 |= bit << shift;
        } else {
            self.0 &= !(bit << shift);
        }
    }

    /// Enable a capability.
    pub fn enable(&mut self, section: Section, action: Action) {
        self.set(section, action, true);
    }

    /// Disable a capability.
    pub fn disable(&mut self, section: Section, action: Action) {
        self.set(section, action, false);
    }

    /// Union with another capability set.
    pub fn union(&self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersection with another capability set.
    pub fn intersect(&self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::NONE
    }
}

impl std::ops::BitOr for CapabilitySet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for CapabilitySet {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitOrAssign for CapabilitySet {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAndAssign for CapabilitySet {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

/// Configuration sections for capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    Hosts,
    Certificates,
    AccessLists,
    Users,
    Logs,
    Settings,
}

impl Section {
    const fn shift(self) -> u64 {
        match self {
            Section::Hosts => CapabilitySet::HOSTS_SHIFT,
            Section::Certificates => CapabilitySet::CERTIFICATES_SHIFT,
            Section::AccessLists => CapabilitySet::ACCESS_LISTS_SHIFT,
            Section::Users => CapabilitySet::USERS_SHIFT,
            Section::Logs => CapabilitySet::LOGS_SHIFT,
            Section::Settings => CapabilitySet::SETTINGS_SHIFT,
        }
    }

    /// All sections.
    pub const fn all() -> [Section; 6] {
        [
            Section::Hosts,
            Section::Certificates,
            Section::AccessLists,
            Section::Users,
            Section::Logs,
            Section::Settings,
        ]
    }
}

/// Actions within a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    View,
    Create,
    Update,
    Delete,
    Manage,
    Admin,
}

impl Action {
    const fn bit(self) -> u64 {
        match self {
            Action::View => CapabilitySet::VIEW_BIT,
            Action::Create => CapabilitySet::CREATE_BIT,
            Action::Update => CapabilitySet::UPDATE_BIT,
            Action::Delete => CapabilitySet::DELETE_BIT,
            Action::Manage => CapabilitySet::MANAGE_BIT,
            Action::Admin => CapabilitySet::ADMIN_BIT,
        }
    }

    /// All actions.
    pub const fn all() -> [Action; 6] {
        [
            Action::View,
            Action::Create,
            Action::Update,
            Action::Delete,
            Action::Manage,
            Action::Admin,
        ]
    }
}

/// Predefined role templates.
impl Role {
    /// Administrator role with full access to everything.
    pub fn admin() -> Self {
        let mut caps = CapabilitySet::ALL;
        Self {
            name: "admin".to_string(),
            capabilities: caps,
            visibility: Visibility::All,
        }
    }

    /// Editor role with create/update/delete on most sections, view on settings.
    pub fn editor() -> Self {
        let mut caps = CapabilitySet::new();
        for section in [
            Section::Hosts,
            Section::Certificates,
            Section::AccessLists,
            Section::Logs,
        ] {
            for action in [
                Action::View,
                Action::Create,
                Action::Update,
                Action::Delete,
                Action::Manage,
            ] {
                caps.enable(section, action);
            }
        }
        caps.enable(Section::Users, Action::View);
        caps.enable(Section::Settings, Action::View);
        Self {
            name: "editor".to_string(),
            capabilities: caps,
            visibility: Visibility::All,
        }
    }

    /// Viewer role with read-only access to most sections.
    pub fn viewer() -> Self {
        let mut caps = CapabilitySet::new();
        for section in Section::all() {
            caps.enable(section, Action::View);
        }
        Self {
            name: "viewer".to_string(),
            capabilities: caps,
            visibility: Visibility::Owner,
        }
    }

    /// Custom role with specified capabilities and visibility.
    pub fn custom(
        name: impl Into<String>,
        capabilities: CapabilitySet,
        visibility: Visibility,
    ) -> Self {
        Self {
            name: name.into(),
            capabilities,
            visibility,
        }
    }
}

/// User account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Unique user identifier.
    pub id: UserId,
    /// Username (unique).
    pub username: String,
    /// Argon2id or bcrypt password hash.
    pub password_hash: String,
    /// User's role.
    pub role: Role,
    /// TOTP secret (base32 encoded), if 2FA is enabled.
    pub totp_secret: Option<String>,
    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Check if user has TOTP enabled.
    pub fn has_totp(&self) -> bool {
        self.totp_secret.is_some()
    }
}

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("user not found")]
    UserNotFound,
    #[error("username already exists")]
    UsernameExists,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("invalid token signature")]
    InvalidSignature,
    #[error("refresh token revoked")]
    RefreshTokenRevoked,
    #[error("refresh token not found")]
    RefreshTokenNotFound,
    #[error("invalid TOTP code")]
    InvalidTotpCode,
    #[error("TOTP not configured for user")]
    TotpNotConfigured,
    #[error("password hash error: {0}")]
    PasswordHash(String),
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("argon2 error: {0}")]
    Argon2(#[from] argon2::password_hash::Error),
    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("store error: {0}")]
    Store(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<anyhow::Error> for AuthError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

/// Result type for auth operations.
pub type AuthResult<T> = Result<T, AuthError>;

/// JWT claims for access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID).
    pub sub: UserId,
    /// Role name.
    pub role: String,
    /// Capabilities as bitmask.
    pub caps: u64,
    /// Visibility.
    pub vis: Visibility,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
}

impl Claims {
    /// Check if token has a specific capability.
    pub fn has_capability(&self, section: Section, action: Action) -> bool {
        let caps = CapabilitySet::from_bits(self.caps);
        caps.has(section, action)
    }
}

/// Token pair returned on login/refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// Short-lived JWT access token (e.g., 15 minutes).
    pub access_token: String,
    /// Long-lived opaque refresh token (e.g., 7 days).
    pub refresh_token: String,
}

/// Refresh token record stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshTokenRecord {
    /// Hash of the refresh token (argon2id).
    token_hash: String,
    /// Associated user ID.
    user_id: UserId,
    /// Issued at timestamp.
    iat: i64,
    /// Revoked at timestamp (if revoked).
    revoked_at: Option<i64>,
    /// Token ID for revocation tracking.
    token_id: String,
}

/// Argon2 parameters for password hashing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
    /// Memory cost (KiB).
    pub memory_cost: u32,
    /// Time cost (iterations).
    pub time_cost: u32,
    /// Parallelism.
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        // OWASP recommended defaults for Argon2id (2024)
        Self {
            memory_cost: 19456, // 19 MiB
            time_cost: 2,
            parallelism: 1,
        }
    }
}

impl Argon2Config {
    /// Create Argon2 instance from config.
    fn to_argon2(&self) -> Result<Argon2<'static>, AuthError> {
        let params = Argon2Params::new(self.memory_cost, self.time_cost, self.parallelism)
            .map_err(|e| AuthError::PasswordHash(e.to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Authentication service configuration.
#[derive(Debug, Clone)]
pub struct AuthnConfig {
    /// JWT signing secret (32 bytes for HS256).
    pub jwt_secret: [u8; 32],
    /// Access token TTL.
    pub access_ttl: Duration,
    /// Refresh token TTL.
    pub refresh_ttl: Duration,
    /// Argon2 parameters for password hashing.
    pub argon2_params: Argon2Config,
    /// Issuer for JWT tokens.
    pub issuer: Option<String>,
    /// Audience for JWT tokens.
    pub audience: Option<String>,
}

impl Default for AuthnConfig {
    fn default() -> Self {
        // Generate a random secret if not provided (for development only)
        let mut jwt_secret = [0u8; 32];
        OsRng.fill_bytes(&mut jwt_secret);

        Self {
            jwt_secret,
            access_ttl: Duration::from_secs(15 * 60), // 15 minutes
            refresh_ttl: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            argon2_params: Argon2Config::default(),
            issuer: None,
            audience: None,
        }
    }
}

/// Trait for user storage backends.
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Get user by ID.
    async fn get_user(&self, user_id: UserId) -> AuthResult<Option<User>>;

    /// Get user by username.
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>>;

    /// Create a new user.
    async fn create_user(&self, user: User) -> AuthResult<User>;

    /// Update an existing user.
    async fn update_user(&self, user: User) -> AuthResult<User>;

    /// Delete a user.
    async fn delete_user(&self, user_id: UserId) -> AuthResult<()>;

    /// List all users (for admin purposes).
    async fn list_users(&self) -> AuthResult<Vec<User>>;

    /// Get refresh token record by token ID.
    async fn get_refresh_token(&self, token_id: &str) -> AuthResult<Option<RefreshTokenRecord>>;

    /// Store a new refresh token record.
    async fn store_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()>;

    /// Update a refresh token record (e.g., mark revoked).
    async fn update_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()>;

    /// Delete all refresh tokens for a user.
    async fn delete_refresh_tokens_for_user(&self, user_id: UserId) -> AuthResult<()>;
}

/// In-memory user store implementation.
#[derive(Debug, Clone, Default)]
pub struct MemoryUserStore {
    users: Arc<RwLock<HashMap<UserId, User>>>,
    users_by_username: Arc<RwLock<HashMap<String, UserId>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshTokenRecord>>>,
}

impl MemoryUserStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserStore for MemoryUserStore {
    async fn get_user(&self, user_id: UserId) -> AuthResult<Option<User>> {
        let users = self.users.read().await;
        Ok(users.get(&user_id).cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
        let users_by_username = self.users_by_username.read().await;
        let users = self.users.read().await;
        if let Some(user_id) = users_by_username.get(username) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn create_user(&self, user: User) -> AuthResult<User> {
        let mut users = self.users.write().await;
        let mut users_by_username = self.users_by_username.write().await;

        if users_by_username.contains_key(&user.username) {
            return Err(AuthError::UsernameExists);
        }

        users_by_username.insert(user.username.clone(), user.id);
        users.insert(user.id, user.clone());
        Ok(user)
    }

    async fn update_user(&self, user: User) -> AuthResult<User> {
        let mut users = self.users.write().await;
        let users_by_username = self.users_by_username.read().await;

        // Check if username changed and new username is taken
        if let Some(existing) = users.get(&user.id) {
            if existing.username != user.username && users_by_username.contains_key(&user.username)
            {
                return Err(AuthError::UsernameExists);
            }
        } else {
            return Err(AuthError::UserNotFound);
        }

        users.insert(user.id, user.clone());
        Ok(user)
    }

    async fn delete_user(&self, user_id: UserId) -> AuthResult<()> {
        let mut users = self.users.write().await;
        let mut users_by_username = self.users_by_username.write().await;

        if let Some(user) = users.remove(&user_id) {
            users_by_username.remove(&user.username);
            // Also clean up refresh tokens
            let mut refresh_tokens = self.refresh_tokens.write().await;
            refresh_tokens.retain(|_, record| record.user_id != user_id);
            Ok(())
        } else {
            Err(AuthError::UserNotFound)
        }
    }

    async fn list_users(&self) -> AuthResult<Vec<User>> {
        let users = self.users.read().await;
        Ok(users.values().cloned().collect())
    }

    async fn get_refresh_token(&self, token_id: &str) -> AuthResult<Option<RefreshTokenRecord>> {
        let refresh_tokens = self.refresh_tokens.read().await;
        Ok(refresh_tokens.get(token_id).cloned())
    }

    async fn store_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()> {
        let mut refresh_tokens = self.refresh_tokens.write().await;
        refresh_tokens.insert(record.token_id.clone(), record);
        Ok(())
    }

    async fn update_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()> {
        let mut refresh_tokens = self.refresh_tokens.write().await;
        if refresh_tokens.contains_key(&record.token_id) {
            refresh_tokens.insert(record.token_id.clone(), record);
            Ok(())
        } else {
            Err(AuthError::RefreshTokenNotFound)
        }
    }

    async fn delete_refresh_tokens_for_user(&self, user_id: UserId) -> AuthResult<()> {
        let mut refresh_tokens = self.refresh_tokens.write().await;
        refresh_tokens.retain(|_, record| record.user_id != user_id);
        Ok(())
    }
}

/// Adapter for pm-state StateStore to implement UserStore.
#[cfg(feature = "pm-state")]
pub mod pm_state_adapter {
    use super::*;
    use caddy_rs_pm_state::{Document, Key, StateError, StateStore, Transaction, Value};

    /// Namespace for auth data in pm-state.
    const NAMESPACE_USERS: &str = "authn_users";
    const NAMESPACE_REFRESH_TOKENS: &str = "authn_refresh_tokens";

    /// UserStore implementation backed by pm-state StateStore.
    #[derive(Clone)]
    pub struct PmStateUserStore {
        store: Arc<dyn StateStore>,
    }

    impl PmStateUserStore {
        /// Create a new adapter wrapping a StateStore.
        pub fn new(store: Arc<dyn StateStore>) -> Self {
            Self { store }
        }

        fn user_key(username: &str) -> Key {
            Key::new(NAMESPACE_USERS, username)
        }

        fn user_id_key(user_id: UserId) -> Key {
            Key::new(NAMESPACE_USERS, format!("id:{}", user_id.0))
        }

        fn refresh_token_key(token_id: &str) -> Key {
            Key::new(NAMESPACE_REFRESH_TOKENS, token_id)
        }

        fn user_to_value(user: &User) -> Result<Value, AuthError> {
            serde_json::to_value(user).map_err(|e| AuthError::Store(e.to_string()))
        }

        fn value_to_user(value: Value) -> Result<User, AuthError> {
            serde_json::from_value(value).map_err(|e| AuthError::Store(e.to_string()))
        }

        fn refresh_to_value(record: &RefreshTokenRecord) -> Result<Value, AuthError> {
            serde_json::to_value(record).map_err(|e| AuthError::Store(e.to_string()))
        }

        fn value_to_refresh(value: Value) -> Result<RefreshTokenRecord, AuthError> {
            serde_json::from_value(value).map_err(|e| AuthError::Store(e.to_string()))
        }
    }

    #[async_trait]
    impl UserStore for PmStateUserStore {
        async fn get_user(&self, user_id: UserId) -> AuthResult<Option<User>> {
            let doc = self
                .store
                .get(NAMESPACE_USERS, &format!("id:{}", user_id.0))
                .map_err(|e| AuthError::Store(e.to_string()))?;
            Ok(doc.map(|d| Self::value_to_user(d.value)).transpose()?)
        }

        async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
            let doc = self
                .store
                .get(NAMESPACE_USERS, username)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            Ok(doc.map(|d| Self::value_to_user(d.value)).transpose()?)
        }

        async fn create_user(&self, user: User) -> AuthResult<User> {
            // Check if username exists
            let existing = self
                .store
                .get(NAMESPACE_USERS, &user.username)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            if existing.is_some() {
                return Err(AuthError::UsernameExists);
            }

            // Check if user ID exists
            let existing_id = self
                .store
                .get(NAMESPACE_USERS, &format!("id:{}", user.id.0))
                .map_err(|e| AuthError::Store(e.to_string()))?;
            if existing_id.is_some() {
                return Err(AuthError::Internal("User ID collision".to_string()));
            }

            let user_value = Self::user_to_value(&user)?;
            let txn = Transaction::new()
                .check_missing(NAMESPACE_USERS, &user.username)
                .check_missing(NAMESPACE_USERS, &format!("id:{}", user.id.0))
                .put(NAMESPACE_USERS, &user.username, user_value.clone())
                .put(NAMESPACE_USERS, &format!("id:{}", user.id.0), user_value);

            self.store
                .transact(txn)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            Ok(user)
        }

        async fn update_user(&self, user: User) -> AuthResult<User> {
            let existing = self
                .store
                .get(NAMESPACE_USERS, &format!("id:{}", user.id.0))
                .map_err(|e| AuthError::Store(e.to_string()))?;
            let existing_doc = existing.ok_or(AuthError::UserNotFound)?;

            // Check if username changed
            let existing_user = Self::value_to_user(existing_doc.value)?;
            if existing_user.username != user.username {
                let username_exists = self
                    .store
                    .get(NAMESPACE_USERS, &user.username)
                    .map_err(|e| AuthError::Store(e.to_string()))?;
                if username_exists.is_some() {
                    return Err(AuthError::UsernameExists);
                }
            }

            let user_value = Self::user_to_value(&user)?;
            let txn = Transaction::new()
                .check_revision(
                    NAMESPACE_USERS,
                    &format!("id:{}", user.id.0),
                    existing_doc.revision,
                )
                .put(
                    NAMESPACE_USERS,
                    &format!("id:{}", user.id.0),
                    user_value.clone(),
                );

            if existing_user.username != user.username {
                txn.delete(NAMESPACE_USERS, &existing_user.username).put(
                    NAMESPACE_USERS,
                    &user.username,
                    user_value,
                );
            } else {
                txn.put(NAMESPACE_USERS, &user.username, user_value);
            }

            self.store
                .transact(txn)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            Ok(user)
        }

        async fn delete_user(&self, user_id: UserId) -> AuthResult<()> {
            let existing = self
                .store
                .get(NAMESPACE_USERS, &format!("id:{}", user_id.0))
                .map_err(|e| AuthError::Store(e.to_string()))?;
            let existing_doc = existing.ok_or(AuthError::UserNotFound)?;
            let existing_user = Self::value_to_user(existing_doc.value)?;

            let txn = Transaction::new()
                .check_revision(
                    NAMESPACE_USERS,
                    &format!("id:{}", user_id.0),
                    existing_doc.revision,
                )
                .delete(NAMESPACE_USERS, &format!("id:{}", user_id.0))
                .delete(NAMESPACE_USERS, &existing_user.username);

            self.store
                .transact(txn)
                .map_err(|e| AuthError::Store(e.to_string()))?;

            // Delete refresh tokens for user
            self.delete_refresh_tokens_for_user(user_id).await?;
            Ok(())
        }

        async fn list_users(&self) -> AuthResult<Vec<User>> {
            let docs = self
                .store
                .scan(NAMESPACE_USERS, "id:")
                .map_err(|e| AuthError::Store(e.to_string()))?;
            let mut users = Vec::new();
            for doc in docs {
                users.push(Self::value_to_user(doc.value)?);
            }
            Ok(users)
        }

        async fn get_refresh_token(
            &self,
            token_id: &str,
        ) -> AuthResult<Option<RefreshTokenRecord>> {
            let doc = self
                .store
                .get(NAMESPACE_REFRESH_TOKENS, token_id)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            Ok(doc.map(|d| Self::value_to_refresh(d.value)).transpose()?)
        }

        async fn store_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()> {
            let value = Self::refresh_to_value(&record)?;
            let txn = Transaction::new()
                .check_missing(NAMESPACE_REFRESH_TOKENS, &record.token_id)
                .put(NAMESPACE_REFRESH_TOKENS, &record.token_id, value);
            self.store
                .transact(txn)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            Ok(())
        }

        async fn update_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()> {
            let existing = self
                .store
                .get(NAMESPACE_REFRESH_TOKENS, &record.token_id)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            let existing_doc = existing.ok_or(AuthError::RefreshTokenNotFound)?;

            let value = Self::refresh_to_value(&record)?;
            let txn = Transaction::new()
                .check_revision(
                    NAMESPACE_REFRESH_TOKENS,
                    &record.token_id,
                    existing_doc.revision,
                )
                .put(NAMESPACE_REFRESH_TOKENS, &record.token_id, value);
            self.store
                .transact(txn)
                .map_err(|e| AuthError::Store(e.to_string()))?;
            Ok(())
        }

        async fn delete_refresh_tokens_for_user(&self, user_id: UserId) -> AuthResult<()> {
            let docs = self
                .store
                .scan(NAMESPACE_REFRESH_TOKENS, "")
                .map_err(|e| AuthError::Store(e.to_string()))?;

            let mut txn = Transaction::new();
            let mut has_deletes = false;
            for doc in docs {
                if let Ok(record) = Self::value_to_refresh(doc.value.clone()) {
                    if record.user_id == user_id {
                        txn = txn.delete(NAMESPACE_REFRESH_TOKENS, &doc.key.key);
                        has_deletes = true;
                    }
                }
            }

            if has_deletes {
                self.store
                    .transact(txn)
                    .map_err(|e| AuthError::Store(e.to_string()))?;
            }
            Ok(())
        }
    }
}

/// Hash a password using Argon2id (preferred) with bcrypt fallback.
pub fn hash_password(password: &str, argon2_config: &Argon2Config) -> AuthResult<String> {
    let argon2 = argon2_config.to_argon2()?;
    let salt = SaltString::generate(&mut OsRng);

    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => Ok(hash.to_string()),
        Err(_) => {
            // Fallback to bcrypt
            let hash = bcrypt_hash(password, DEFAULT_COST)
                .map_err(|e| AuthError::PasswordHash(e.to_string()))?;
            Ok(hash)
        }
    }
}

/// Verify a password against a hash (constant-time).
/// Supports both Argon2id and bcrypt hashes.
pub fn verify_password(password: &str, hash: &str) -> AuthResult<bool> {
    // Try Argon2id first
    if let Ok(parsed_hash) = PasswordHash::new(hash) {
        let argon2 = Argon2::default();
        if argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            return Ok(true);
        }
    }

    // Fallback to bcrypt
    match bcrypt_verify(password, hash) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(AuthError::PasswordHash(e.to_string())),
    }
}

/// Generate a random refresh token.
fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base32::encode(Alphabet::Rfc4648 { padding: false }, &bytes)
}

/// Generate a random token ID.
fn generate_token_id() -> String {
    Uuid::new_v4().to_string()
}

/// Current timestamp as Unix seconds.
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Main authentication service.
pub struct AuthnService<S: UserStore> {
    store: S,
    config: AuthnConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl<S: UserStore> AuthnService<S> {
    /// Create a new AuthnService with the given store and config.
    pub fn new(store: S, config: AuthnConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(&config.jwt_secret);
        let decoding_key = DecodingKey::from_secret(&config.jwt_secret);
        Self {
            store,
            config,
            encoding_key,
            decoding_key,
        }
    }

    /// Get a reference to the config.
    pub fn config(&self) -> &AuthnConfig {
        &self.config
    }

    /// Create a new user.
    pub async fn create_user(
        &self,
        username: impl Into<String>,
        password: &str,
        role: Role,
    ) -> AuthResult<User> {
        let username = username.into();

        // Check if user already exists
        if self.store.get_user_by_username(&username).await?.is_some() {
            return Err(AuthError::UsernameExists);
        }

        let password_hash = hash_password(password, &self.config.argon2_params)?;
        let now = Utc::now();

        let user = User {
            id: UserId::new(),
            username,
            password_hash,
            role,
            totp_secret: None,
            created_at: now,
            updated_at: now,
        };

        self.store.create_user(user).await
    }

    /// Update a user's password (requires old password for verification).
    pub async fn update_password(
        &self,
        user_id: UserId,
        old_password: &str,
        new_password: &str,
    ) -> AuthResult<()> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Verify old password
        if !verify_password(old_password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        // Hash new password
        user.password_hash = hash_password(new_password, &self.config.argon2_params)?;
        user.updated_at = Utc::now();

        // Update user
        self.store.update_user(user).await?;

        // Revoke all refresh tokens for this user (password change invalidates sessions)
        self.store.delete_refresh_tokens_for_user(user_id).await?;

        Ok(())
    }

    /// Set a user's password (admin operation, no old password required).
    pub async fn set_password(&self, user_id: UserId, new_password: &str) -> AuthResult<()> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        user.password_hash = hash_password(new_password, &self.config.argon2_params)?;
        user.updated_at = Utc::now();

        self.store.update_user(user).await?;

        // Revoke all refresh tokens for this user
        self.store.delete_refresh_tokens_for_user(user_id).await?;

        Ok(())
    }

    /// Update a user's role.
    pub async fn update_role(&self, user_id: UserId, role: Role) -> AuthResult<User> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        user.role = role;
        user.updated_at = Utc::now();

        self.store.update_user(user.clone()).await?;
        Ok(user)
    }

    /// Enable TOTP for a user. Returns (secret, otpauth URI).
    pub async fn totp_setup(&self, user_id: UserId) -> AuthResult<(String, String)> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Generate a new TOTP secret
        let mut secret_bytes = [0u8; 20];
        OsRng.fill_bytes(&mut secret_bytes);
        let secret = base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes);

        // Build otpauth URI
        let issuer = self.config.issuer.as_deref().unwrap_or("caddy-rs");
        let uri = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
            urlencoding::encode(issuer),
            urlencoding::encode(&user.username),
            secret,
            urlencoding::encode(issuer)
        );

        user.totp_secret = Some(secret.clone());
        user.updated_at = Utc::now();

        self.store.update_user(user).await?;

        Ok((secret, uri))
    }

    /// Verify a TOTP code for a user.
    pub async fn totp_verify(&self, user_id: UserId, code: &str) -> AuthResult<bool> {
        let user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let secret = user.totp_secret.ok_or(AuthError::TotpNotConfigured)?;

        let totp = Totp::new(&secret)
            .map_err(|e| AuthError::Internal(format!("TOTP init failed: {}", e)))?;

        Ok(totp.verify_current(code).unwrap_or(false))
    }

    /// Disable TOTP for a user.
    pub async fn totp_disable(&self, user_id: UserId) -> AuthResult<()> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        user.totp_secret = None;
        user.updated_at = Utc::now();

        self.store.update_user(user).await?;
        Ok(())
    }

    /// Login with username, password, and optional TOTP code.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> AuthResult<TokenPair> {
        let user = self
            .store
            .get_user_by_username(username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        // Verify password
        if !verify_password(password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        // Verify TOTP if configured
        if user.has_totp() {
            let code = totp_code.ok_or(AuthError::InvalidTotpCode)?;
            if !self.totp_verify(user.id, code).await? {
                return Err(AuthError::InvalidTotpCode);
            }
        }

        self.issue_token_pair(&user).await
    }

    /// Issue a new access+refresh token pair for a user.
    async fn issue_token_pair(&self, user: &User) -> AuthResult<TokenPair> {
        let now = now_ts();
        let access_exp = now + self.config.access_ttl.as_secs() as i64;
        let refresh_exp = now + self.config.refresh_ttl.as_secs() as i64;

        // Create access token (JWT)
        let claims = Claims {
            sub: user.id,
            role: user.role.name.clone(),
            caps: user.role.capabilities.bits(),
            vis: user.role.visibility,
            iat: now,
            exp: access_exp,
        };

        let mut header = Header::new(JwtAlgorithm::HS256);
        if let Some(issuer) = &self.config.issuer {
            header.iss = Some(issuer.clone());
        }
        if let Some(audience) = &self.config.audience {
            header.aud = Some(jsonwebtoken::RegisteredClaim::Single(audience.clone()));
        }

        let access_token = encode(&header, &claims, &self.encoding_key)?;

        // Create refresh token (opaque)
        let refresh_token = generate_refresh_token();
        let token_id = generate_token_id();
        let refresh_hash = hash_password(&refresh_token, &self.config.argon2_params)?;

        let record = RefreshTokenRecord {
            token_hash: refresh_hash,
            user_id: user.id,
            iat: now,
            revoked_at: None,
            token_id: token_id.clone(),
        };

        self.store.store_refresh_token(record).await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
    }

    /// Refresh an access token using a refresh token (rotates refresh token).
    pub async fn refresh(&self, refresh_token: &str) -> AuthResult<TokenPair> {
        // We need to find the refresh token by trying all records (since we only store hash)
        // For efficiency, we store token_id separately, but here we need to look up by hash.
        // In practice, we'd include token_id in the refresh token itself.
        // For now, we'll scan all refresh tokens (acceptable for moderate scale).

        let all_tokens = self.get_all_refresh_tokens().await?;
        let mut found_record: Option<RefreshTokenRecord> = None;

        for record in all_tokens {
            if verify_password(refresh_token, &record.token_hash)? {
                found_record = Some(record);
                break;
            }
        }

        let mut record = found_record.ok_or(AuthError::RefreshTokenNotFound)?;

        // Check if revoked
        if record.revoked_at.is_some() {
            return Err(AuthError::RefreshTokenRevoked);
        }

        // Check expiration
        let now = now_ts();
        if now > record.iat + self.config.refresh_ttl.as_secs() as i64 {
            return Err(AuthError::TokenExpired);
        }

        // Get user
        let user = self
            .store
            .get_user(record.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Revoke old refresh token
        record.revoked_at = Some(now);
        self.store.update_refresh_token(record).await?;

        // Issue new token pair
        self.issue_token_pair(&user).await
    }

    /// Get all refresh tokens (for lookup by hash).
    async fn get_all_refresh_tokens(&self) -> AuthResult<Vec<RefreshTokenRecord>> {
        // This is a helper that would need to be implemented per store
        // For MemoryUserStore, we can access directly
        // For other stores, we'd need to add a method to UserStore
        // For now, we'll use a workaround via the store trait
        // In a real implementation, we'd add this to the trait

        // We'll implement this via a downcast or by adding to trait
        // For simplicity, let's add a method to the trait
        // But since we can't change the trait easily, we'll use a different approach:
        // Store the token_id in the refresh token itself (prefix)
        // Actually, let's just add a method to UserStore

        // This is a limitation - we need to scan. Let's add a method.
        // But we can't modify the trait from here without breaking.
        // Alternative: encode token_id in the refresh token.
        // Let's do that: refresh_token = token_id + "." + random_bytes

        // Actually, let's rethink. The refresh token returned to the client should be the full opaque token.
        // We can encode token_id as a prefix: token_id + "." + random
        // Then we can look up directly by token_id.

        // Let me change the approach: refresh token = token_id + "." + random_part
        // Then we can extract token_id and look up directly.

        // But the current implementation already stores the hash of the full token.
        // We need to change this. Let me update the approach.

        Err(AuthError::Internal(
            "get_all_refresh_tokens not implemented; use token_id prefix in refresh token"
                .to_string(),
        ))
    }

    /// Revoke a specific refresh token.
    pub async fn revoke_refresh_token(&self, refresh_token: &str) -> AuthResult<()> {
        // Extract token_id from refresh token (format: token_id.random)
        let token_id = refresh_token
            .split('.')
            .next()
            .ok_or(AuthError::InvalidToken)?;

        let mut record = self
            .store
            .get_refresh_token(token_id)
            .await?
            .ok_or(AuthError::RefreshTokenNotFound)?;

        // Verify the token matches (constant-time)
        if !verify_password(refresh_token, &record.token_hash)? {
            return Err(AuthError::InvalidToken);
        }

        record.revoked_at = Some(now_ts());
        self.store.update_refresh_token(record).await?;
        Ok(())
    }

    /// Revoke all refresh tokens for a user.
    pub async fn revoke_all_for_user(&self, user_id: UserId) -> AuthResult<()> {
        self.store.delete_refresh_tokens_for_user(user_id).await
    }

    /// Verify an access token and return claims.
    pub fn verify_access_token(&self, token: &str) -> AuthResult<Claims> {
        let mut validation = Validation::new(JwtAlgorithm::HS256);
        if let Some(issuer) = &self.config.issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(audience) = &self.config.audience {
            validation.set_audience(&[audience]);
        }
        validation.validate_exp = true;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::InvalidSignature,
                _ => AuthError::InvalidToken,
            }
        })?;

        Ok(token_data.claims)
    }

    /// Check if claims have permission for a section/action.
    pub fn check_permission(&self, claims: &Claims, section: Section, action: Action) -> bool {
        claims.has_capability(section, action)
    }
}

/// Extension trait to add refresh token lookup by token_id prefix.
#[async_trait]
pub trait UserStoreExt: UserStore {
    /// Get refresh token by token_id (prefix of the refresh token).
    async fn get_refresh_token_by_id(
        &self,
        token_id: &str,
    ) -> AuthResult<Option<RefreshTokenRecord>> {
        self.get_refresh_token(token_id).await
    }
}

impl<S: UserStore> UserStoreExt for S {}

// Re-implement AuthnService methods that need the extension
impl<S: UserStore> AuthnService<S> {
    /// Refresh an access token using a refresh token (rotates refresh token).
    /// Refresh token format: token_id.random_part
    pub async fn refresh(&self, refresh_token: &str) -> AuthResult<TokenPair> {
        // Extract token_id from refresh token (format: token_id.random_part)
        let token_id = refresh_token
            .split('.')
            .next()
            .ok_or(AuthError::InvalidToken)?;

        let mut record = self
            .store
            .get_refresh_token_by_id(token_id)
            .await?
            .ok_or(AuthError::RefreshTokenNotFound)?;

        // Verify the full token matches (constant-time)
        if !verify_password(refresh_token, &record.token_hash)? {
            return Err(AuthError::InvalidToken);
        }

        // Check if revoked
        if record.revoked_at.is_some() {
            return Err(AuthError::RefreshTokenRevoked);
        }

        // Check expiration
        let now = now_ts();
        if now > record.iat + self.config.refresh_ttl.as_secs() as i64 {
            return Err(AuthError::TokenExpired);
        }

        // Get user
        let user = self
            .store
            .get_user(record.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Revoke old refresh token
        record.revoked_at = Some(now);
        self.store.update_refresh_token(record).await?;

        // Issue new token pair
        self.issue_token_pair(&user).await
    }

    /// Internal: issue a new token pair with token_id embedded in refresh token.
    async fn issue_token_pair(&self, user: &User) -> AuthResult<TokenPair> {
        let now = now_ts();
        let access_exp = now + self.config.access_ttl.as_secs() as i64;

        // Create access token (JWT)
        let claims = Claims {
            sub: user.id,
            role: user.role.name.clone(),
            caps: user.role.capabilities.bits(),
            vis: user.role.visibility,
            iat: now,
            exp: access_exp,
        };

        let mut header = Header::new(JwtAlgorithm::HS256);
        if let Some(issuer) = &self.config.issuer {
            header.iss = Some(issuer.clone());
        }
        if let Some(audience) = &self.config.audience {
            header.aud = Some(jsonwebtoken::RegisteredClaim::Single(audience.clone()));
        }

        let access_token = encode(&header, &claims, &self.encoding_key)?;

        // Create refresh token with embedded token_id
        let token_id = generate_token_id();
        let random_part = generate_refresh_token();
        let refresh_token = format!("{}.{}", token_id, random_part);
        let refresh_hash = hash_password(&refresh_token, &self.config.argon2_params)?;

        let record = RefreshTokenRecord {
            token_hash: refresh_hash,
            user_id: user.id,
            iat: now,
            revoked_at: None,
            token_id: token_id.clone(),
        };

        self.store.store_refresh_token(record).await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_password_hash_argon2id() {
        let config = Argon2Config::default();
        let password = "test_password_123";
        let hash = hash_password(password, &config).unwrap();

        // Should be Argon2id format
        assert!(hash.starts_with("$argon2id$"));

        // Verify works
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[tokio::test]
    async fn test_password_hash_bcrypt_fallback() {
        // Test that bcrypt hashes can still be verified
        let bcrypt_hash = bcrypt_hash("test_password", DEFAULT_COST).unwrap();
        assert!(verify_password("test_password", &bcrypt_hash).unwrap());
        assert!(!verify_password("wrong", &bcrypt_hash).unwrap());
    }

    #[tokio::test]
    async fn test_constant_time_verification() {
        let config = Argon2Config::default();
        let hash = hash_password("password", &config).unwrap();

        // Multiple verifications should take similar time (we can't easily test timing here,
        // but we can verify the function doesn't early-return on wrong password)
        for _ in 0..10 {
            assert!(!verify_password("wrong", &hash).unwrap());
        }
        assert!(verify_password("password", &hash).unwrap());
    }

    #[tokio::test]
    async fn test_capability_set() {
        let mut caps = CapabilitySet::new();
        assert!(!caps.has(Section::Hosts, Action::View));

        caps.enable(Section::Hosts, Action::View);
        assert!(caps.has(Section::Hosts, Action::View));
        assert!(!caps.has(Section::Hosts, Action::Create));

        caps.enable(Section::Hosts, Action::Create);
        assert!(caps.has(Section::Hosts, Action::Create));

        caps.disable(Section::Hosts, Action::View);
        assert!(!caps.has(Section::Hosts, Action::View));
        assert!(caps.has(Section::Hosts, Action::Create));
    }

    #[tokio::test]
    async fn test_role_templates() {
        let admin = Role::admin();
        assert_eq!(admin.name, "admin");
        assert_eq!(admin.visibility, Visibility::All);
        for section in Section::all() {
            for action in Action::all() {
                assert!(
                    admin.capabilities.has(section, action),
                    "admin missing {section:?}/{action:?}"
                );
            }
        }

        let editor = Role::editor();
        assert_eq!(editor.name, "editor");
        assert!(editor.capabilities.has(Section::Hosts, Action::Create));
        assert!(editor.capabilities.has(Section::Settings, Action::View));
        assert!(!editor.capabilities.has(Section::Settings, Action::Create));

        let viewer = Role::viewer();
        assert_eq!(viewer.name, "viewer");
        assert_eq!(viewer.visibility, Visibility::Owner);
        for section in Section::all() {
            assert!(viewer.capabilities.has(section, Action::View));
            assert!(!viewer.capabilities.has(section, Action::Create));
        }
    }

    #[tokio::test]
    async fn test_memory_store_crud() {
        let store = MemoryUserStore::new();
        let user = User {
            id: UserId::new(),
            username: "testuser".to_string(),
            password_hash: "hash".to_string(),
            role: Role::viewer(),
            totp_secret: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Create
        let created = store.create_user(user.clone()).await.unwrap();
        assert_eq!(created.username, "testuser");

        // Get by ID
        let got = store.get_user(user.id).await.unwrap().unwrap();
        assert_eq!(got.username, "testuser");

        // Get by username
        let got = store
            .get_user_by_username("testuser")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.id, user.id);

        // Duplicate username fails
        let dup = store.create_user(user).await;
        assert!(matches!(dup, Err(AuthError::UsernameExists)));

        // Update
        let mut updated = got.clone();
        updated.username = "updated".to_string();
        let updated = store.update_user(updated).await.unwrap();
        assert_eq!(updated.username, "updated");

        // List
        let users = store.list_users().await.unwrap();
        assert_eq!(users.len(), 1);

        // Delete
        store.delete_user(user.id).await.unwrap();
        let got = store.get_user(user.id).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_storage() {
        let store = MemoryUserStore::new();
        let user_id = UserId::new();

        let record = RefreshTokenRecord {
            token_hash: "hash".to_string(),
            user_id,
            iat: now_ts(),
            revoked_at: None,
            token_id: "token123".to_string(),
        };

        store.store_refresh_token(record.clone()).await.unwrap();
        let got = store.get_refresh_token("token123").await.unwrap().unwrap();
        assert_eq!(got.user_id, user_id);

        let mut revoked = record.clone();
        revoked.revoked_at = Some(now_ts());
        store.update_refresh_token(revoked).await.unwrap();

        let got = store.get_refresh_token("token123").await.unwrap().unwrap();
        assert!(got.revoked_at.is_some());

        store.delete_refresh_tokens_for_user(user_id).await.unwrap();
        let got = store.get_refresh_token("token123").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn test_full_login_flow() {
        let store = MemoryUserStore::new();
        let config = AuthnConfig::default();
        let service = AuthnService::new(store, config);

        // Create user
        let user = service
            .create_user("alice", "password123", Role::editor())
            .await
            .unwrap();

        // Login without TOTP
        let tokens = service.login("alice", "password123", None).await.unwrap();
        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert!(tokens.refresh_token.contains('.'));

        // Verify access token
        let claims = service.verify_access_token(&tokens.access_token).unwrap();
        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.role, "editor");
        assert!(claims.has_capability(Section::Hosts, Action::Create));

        // Refresh token
        let new_tokens = service.refresh(&tokens.refresh_token).await.unwrap();
        assert_ne!(new_tokens.access_token, tokens.access_token);
        assert_ne!(new_tokens.refresh_token, tokens.refresh_token);

        // Old refresh token should be revoked
        let result = service.refresh(&tokens.refresh_token).await;
        assert!(matches!(result, Err(AuthError::RefreshTokenRevoked)));

        // New refresh token works
        let tokens2 = service.refresh(&new_tokens.refresh_token).await.unwrap();
        assert_ne!(tokens2.access_token, new_tokens.access_token);
    }

    #[tokio::test]
    async fn test_totp_setup_and_verify() {
        let store = MemoryUserStore::new();
        let config = AuthnConfig::default();
        let service = AuthnService::new(store, config);

        let user = service
            .create_user("bob", "password123", Role::viewer())
            .await
            .unwrap();

        // Setup TOTP
        let (secret, uri) = service.totp_setup(user.id).await.unwrap();
        assert!(!secret.is_empty());
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains(&secret));

        // Verify valid code (we can't easily generate a valid code in test without time sync)
        // But we can test invalid code fails
        let result = service.totp_verify(user.id, "000000").await;
        // This might pass or fail depending on time, but shouldn't error
        assert!(result.is_ok());

        // Login now requires TOTP
        let result = service.login("bob", "password123", None).await;
        assert!(matches!(result, Err(AuthError::InvalidTotpCode)));

        // Disable TOTP
        service.totp_disable(user.id).await.unwrap();

        // Login works without TOTP again
        let tokens = service.login("bob", "password123", None).await.unwrap();
        assert!(!tokens.access_token.is_empty());
    }

    #[tokio::test]
    async fn test_password_change_revokes_tokens() {
        let store = MemoryUserStore::new();
        let config = AuthnConfig::default();
        let service = AuthnService::new(store, config);

        let user = service
            .create_user("charlie", "oldpass", Role::editor())
            .await
            .unwrap();
        let tokens = service.login("charlie", "oldpass", None).await.unwrap();

        // Change password
        service
            .update_password(user.id, "oldpass", "newpass")
            .await
            .unwrap();

        // Old refresh token should be revoked
        let result = service.refresh(&tokens.refresh_token).await;
        assert!(matches!(result, Err(AuthError::RefreshTokenRevoked)));

        // Login with new password works
        let new_tokens = service.login("charlie", "newpass", None).await.unwrap();
        assert!(!new_tokens.access_token.is_empty());
    }

    #[tokio::test]
    async fn test_admin_set_password_revokes_tokens() {
        let store = MemoryUserStore::new();
        let config = AuthnConfig::default();
        let service = AuthnService::new(store, config);

        let user = service
            .create_user("dave", "oldpass", Role::viewer())
            .await
            .unwrap();
        let tokens = service.login("dave", "oldpass", None).await.unwrap();

        // Admin sets password (no old password required)
        service.set_password(user.id, "adminpass").await.unwrap();

        // Old refresh token should be revoked
        let result = service.refresh(&tokens.refresh_token).await;
        assert!(matches!(result, Err(AuthError::RefreshTokenRevoked)));

        // Login with new password works
        let new_tokens = service.login("dave", "adminpass", None).await.unwrap();
        assert!(!new_tokens.access_token.is_empty());
    }

    #[tokio::test]
    async fn test_permission_checks() {
        let store = MemoryUserStore::new();
        let config = AuthnConfig::default();
        let service = AuthnService::new(store, config);

        let user = service
            .create_user("eve", "password", Role::editor())
            .await
            .unwrap();
        let tokens = service.login("eve", "password", None).await.unwrap();
        let claims = service.verify_access_token(&tokens.access_token).unwrap();

        // Editor has create/update/delete on hosts
        assert!(service.check_permission(&claims, Section::Hosts, Action::View));
        assert!(service.check_permission(&claims, Section::Hosts, Action::Create));
        assert!(service.check_permission(&claims, Section::Hosts, Action::Update));
        assert!(service.check_permission(&claims, Section::Hosts, Action::Delete));
        assert!(service.check_permission(&claims, Section::Hosts, Action::Manage));

        // Editor has view on settings
        assert!(service.check_permission(&claims, Section::Settings, Action::View));
        assert!(!service.check_permission(&claims, Section::Settings, Action::Create));

        // Editor has view on users
        assert!(service.check_permission(&claims, Section::Users, Action::View));
        assert!(!service.check_permission(&claims, Section::Users, Action::Create));
    }

    #[tokio::test]
    async fn test_visibility_owner_vs_all() {
        let store = MemoryUserStore::new();
        let config = AuthnConfig::default();
        let service = AuthnService::new(store, config);

        // Viewer has Owner visibility
        let viewer_user = service
            .create_user("viewer1", "password", Role::viewer())
            .await
            .unwrap();
        let viewer_tokens = service.login("viewer1", "password", None).await.unwrap();
        let viewer_claims = service
            .verify_access_token(&viewer_tokens.access_token)
            .unwrap();
        assert_eq!(viewer_claims.vis, Visibility::Owner);

        // Admin has All visibility
        let admin_user = service
            .create_user("admin1", "password", Role::admin())
            .await
            .unwrap();
        let admin_tokens = service.login("admin1", "password", None).await.unwrap();
        let admin_claims = service
            .verify_access_token(&admin_tokens.access_token)
            .unwrap();
        assert_eq!(admin_claims.vis, Visibility::All);
    }

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let store = MemoryUserStore::new();
        let config = AuthnConfig::default();
        let service = AuthnService::new(store, config);

        let user = service
            .create_user("frank", "password", Role::editor())
            .await
            .unwrap();

        // Create multiple sessions
        let tokens1 = service.login("frank", "password", None).await.unwrap();
        let tokens2 = service.login("frank", "password", None).await.unwrap();
        let tokens3 = service.login("frank", "password", None).await.unwrap();

        // All should work
        service.verify_access_token(&tokens1.access_token).unwrap();
        service.verify_access_token(&tokens2.access_token).unwrap();
        service.verify_access_token(&tokens3.access_token).unwrap();

        // Revoke all
        service.revoke_all_for_user(user.id).await.unwrap();

        // All refresh tokens should be revoked
        assert!(matches!(
            service.refresh(&tokens1.refresh_token).await,
            Err(AuthError::RefreshTokenRevoked)
        ));
        assert!(matches!(
            service.refresh(&tokens2.refresh_token).await,
            Err(AuthError::RefreshTokenRevoked)
        ));
        assert!(matches!(
            service.refresh(&tokens3.refresh_token).await,
            Err(AuthError::RefreshTokenRevoked)
        ));
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let store = MemoryUserStore::new();
        let config = AuthnConfig {
            access_ttl: Duration::from_secs(1), // 1 second
            refresh_ttl: Duration::from_secs(1),
            ..AuthnConfig::default()
        };
        let service = AuthnService::new(store, config);

        let user = service
            .create_user("grace", "password", Role::viewer())
            .await
            .unwrap();
        let tokens = service.login("grace", "password", None).await.unwrap();

        // Token should be valid immediately
        service.verify_access_token(&tokens.access_token).unwrap();

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Access token should be expired
        assert!(matches!(
            service.verify_access_token(&tokens.access_token),
            Err(AuthError::TokenExpired)
        ));

        // Refresh token should also be expired
        assert!(matches!(
            service.refresh(&tokens.refresh_token).await,
            Err(AuthError::TokenExpired)
        ));
    }

    #[tokio::test]
    async fn test_custom_role() {
        let mut caps = CapabilitySet::new();
        caps.enable(Section::Hosts, Action::View);
        caps.enable(Section::Hosts, Action::Create);
        caps.enable(Section::Certificates, Action::View);

        let role = Role::custom("custom_role", caps, Visibility::Owner);
        assert_eq!(role.name, "custom_role");
        assert_eq!(role.visibility, Visibility::Owner);
        assert!(role.capabilities.has(Section::Hosts, Action::View));
        assert!(role.capabilities.has(Section::Hosts, Action::Create));
        assert!(role.capabilities.has(Section::Certificates, Action::View));
        assert!(!role.capabilities.has(Section::Certificates, Action::Create));
        assert!(!role.capabilities.has(Section::Users, Action::View));
    }
}
