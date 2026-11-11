//! Authentication and authorization service for caddy-rs.
//!
//! This crate provides a reusable authentication and authorization system with:
//! - User management with roles, capabilities, and row-level visibility
//! - Password hashing (argon2id preferred, bcrypt fallback) with constant-time verification
//! - JWT access tokens and rotating opaque refresh tokens
//! - TOTP two-factor authentication with replay protection
//! - Permission checking based on roles, capabilities, and visibility
//! - An in-memory [`UserStore`] implementation; persistent backends belong outside this crate
//!
//! The crate deliberately has no dependency on the process-manager (`pm-*`) crates. A persistent
//! store can implement [`UserStore`] without pulling process-manager state into the authentication
//! boundary.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
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
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::RwLock;
use totp_lite::{totp_custom, Sha1};
use uuid::Uuid;

/// Length of a TOTP time step in seconds.
const TOTP_STEP_SECONDS: u64 = 30;

/// Number of digits in a TOTP code.
const TOTP_DIGITS: u32 = 6;

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

/// Visibility scope for a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Can access all resources in permitted sections.
    All,
    /// Can only access resources owned by the user.
    #[default]
    Owner,
}

/// User role with capabilities and visibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// Role name (e.g., "admin", "editor", "viewer").
    pub name: String,
    /// Set of capabilities this role grants.
    pub capabilities: CapabilitySet,
    /// Visibility scope: all resources or only the owner's resources.
    pub visibility: Visibility,
}

/// Bitflags for capabilities across the six configuration sections.
///
/// Each section owns six action bits: view, create, update, delete, manage and admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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

    /// Create a capability set from raw bits.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Get the raw bits of this capability set.
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Check whether a specific capability is set.
    pub fn has(&self, section: Section, action: Action) -> bool {
        let shift = section.shift();
        let bit = action.bit();
        (self.0 >> shift) & bit != 0
    }

    /// Set or clear a specific capability.
    pub fn set(&mut self, section: Section, action: Action, value: bool) {
        let shift = section.shift();
        let bit = action.bit();
        if value {
            self.0 |= bit << shift;
        } else {
            self.0 &= !(bit << shift);
        }
    }

    /// Enable a specific capability.
    pub fn enable(&mut self, section: Section, action: Action) {
        self.set(section, action, true);
    }

    /// Disable a specific capability.
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

/// Configuration sections for capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    /// Host configuration.
    Hosts,
    /// TLS certificate configuration.
    Certificates,
    /// Access-list configuration.
    AccessLists,
    /// User management.
    Users,
    /// Log access.
    Logs,
    /// Global settings.
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
    /// Read a resource.
    View,
    /// Create a resource.
    Create,
    /// Update a resource.
    Update,
    /// Delete a resource.
    Delete,
    /// Manage a resource's lifecycle.
    Manage,
    /// Administrative operations.
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

impl Role {
    /// Administrator role with full access to everything.
    pub fn admin() -> Self {
        Self {
            name: "admin".to_string(),
            capabilities: CapabilitySet::ALL,
            visibility: Visibility::All,
        }
    }

    /// Editor role with create/update/delete on most sections and view on settings.
    pub fn editor() -> Self {
        let mut capabilities = CapabilitySet::new();
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
                capabilities.enable(section, action);
            }
        }
        capabilities.enable(Section::Users, Action::View);
        capabilities.enable(Section::Settings, Action::View);
        Self {
            name: "editor".to_string(),
            capabilities,
            visibility: Visibility::All,
        }
    }

    /// Viewer role with read-only access to every section and owner-only visibility.
    pub fn viewer() -> Self {
        let mut capabilities = CapabilitySet::new();
        for section in Section::all() {
            capabilities.enable(section, Action::View);
        }
        Self {
            name: "viewer".to_string(),
            capabilities,
            visibility: Visibility::Owner,
        }
    }

    /// Custom role with the specified capabilities and visibility.
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
#[derive(Clone, PartialEq, Eq)]
pub struct User {
    /// Unique user identifier.
    pub id: UserId,
    /// Username (unique).
    pub username: String,
    /// Argon2id or bcrypt password hash. Never a plaintext password.
    pub password_hash: String,
    /// User's role.
    pub role: Role,
    /// TOTP secret (base32 encoded), if 2FA is enabled.
    pub totp_secret: Option<String>,
    /// Last TOTP time step accepted for this user, used for replay protection.
    pub totp_last_step: Option<u64>,
    /// Monotonically increasing authentication epoch.
    ///
    /// Access tokens carry the epoch they were issued under. Password changes, role changes and
    /// explicit revocation increment it, which invalidates every previously issued access token.
    pub auth_epoch: u64,
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

    /// A serializable view with no credential material.
    ///
    /// [`User`] deliberately does not implement `Serialize`: it holds the password hash and the
    /// TOTP seed, and any accidental `serde_json::to_value(user)` in an API response would leak
    /// both. Use this view for responses. A persistent store must define its own record type rather
    /// than serializing the domain object.
    pub fn public(&self) -> PublicUser {
        PublicUser {
            id: self.id,
            username: self.username.clone(),
            role: self.role.clone(),
            totp_enabled: self.has_totp(),
            auth_epoch: self.auth_epoch,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// A record of a user that is safe to serialize and deserialize.
///
/// This type omits the password hash and TOTP secret, which are never serialized.
/// It is designed for storage and transmission where the full `User` type would expose
/// sensitive data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    /// Unique user identifier.
    pub id: UserId,
    /// Username (unique).
    pub username: String,
    /// User's role with capabilities and visibility.
    pub role: Role,
    /// Whether TOTP is enabled; the secret itself is never stored or serialized.
    pub totp_enabled: bool,
    /// Last TOTP time step accepted for this user, used for replay protection.
    pub totp_last_step: Option<u64>,
    /// Monotonically increasing authentication epoch.
    pub auth_epoch: u64,
    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Convert this user to a serializable record suitable for storage.
    ///
    /// The password hash and TOTP secret are excluded; use this method in a store implementation
    /// to create the record from a loaded `User`.
    pub fn to_record(&self) -> UserRecord {
        UserRecord {
            id: self.id,
            username: self.username.clone(),
            role: self.role.clone(),
            totp_enabled: self.has_totp(),
            totp_last_step: self.totp_last_step,
            auth_epoch: self.auth_epoch,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl UserRecord {
    /// Create a `User` from a record, populating the password hash and TOTP secret.
    pub fn from_user(
        record: UserRecord,
        password_hash: String,
        totp_secret: Option<String>,
    ) -> User {
        User {
            id: record.id,
            username: record.username,
            role: record.role,
            password_hash,
            totp_secret,
            totp_last_step: record.totp_last_step,
            auth_epoch: record.auth_epoch,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }

    /// Convert this record back to a `User`.
    pub fn to_user(self, password_hash: String, totp_secret: Option<String>) -> User {
        Self::from_user(self, password_hash, totp_secret)
    }
}

/// Safe-to-serialize user view without a password hash or TOTP secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicUser {
    /// Unique user identifier.
    pub id: UserId,
    /// Username (unique).
    pub username: String,
    /// User's role and capabilities.
    pub role: Role,
    /// Whether TOTP is configured; the secret itself is never serialized.
    pub totp_enabled: bool,
    /// Authentication epoch the user is currently on.
    pub auth_epoch: u64,
    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Increment a user's authentication epoch, failing closed on exhaustion.
///
/// Wrapping would make an ancient token valid again after 2^64 changes; that is unreachable in
/// practice but must not silently become a downgrade.
fn bump_epoch(user: &mut User) -> AuthResult<()> {
    user.auth_epoch = user
        .auth_epoch
        .checked_add(1)
        .ok_or_else(|| AuthError::Internal("authentication epoch exhausted".to_string()))?;
    Ok(())
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"[redacted]")
            .field("role", &self.role)
            .field(
                "totp_secret",
                &self.totp_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("totp_last_step", &self.totp_last_step)
            .field("auth_epoch", &self.auth_epoch)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The requested user does not exist.
    #[error("user not found")]
    UserNotFound,
    /// A user with the requested username already exists.
    #[error("username already exists")]
    UsernameExists,
    /// The supplied credentials are invalid.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// A token is invalid, malformed, or no longer valid for its user.
    #[error("invalid or expired token")]
    InvalidToken,
    /// A token has expired.
    #[error("token expired")]
    TokenExpired,
    /// A token signature did not verify.
    #[error("invalid token signature")]
    InvalidSignature,
    /// A refresh token has already been revoked.
    #[error("refresh token revoked")]
    RefreshTokenRevoked,
    /// A refresh token was never issued or has been deleted.
    #[error("refresh token not found")]
    RefreshTokenNotFound,
    /// The supplied TOTP code is invalid or has already been used.
    #[error("invalid TOTP code")]
    InvalidTotpCode,
    /// TOTP is not configured for the user.
    #[error("TOTP not configured for user")]
    TotpNotConfigured,
    /// A password hash is malformed or uses an unsupported format.
    #[error("password hash error: {0}")]
    PasswordHash(String),
    /// A JWT operation failed.
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    /// An argon2 operation failed.
    #[error("argon2 error: {0}")]
    Argon2(#[from] argon2::password_hash::Error),
    /// A bcrypt operation failed.
    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    /// A storage backend failed.
    #[error("store error: {0}")]
    Store(String),
    /// An internal invariant was violated.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for authentication operations.
pub type AuthResult<T> = Result<T, AuthError>;

/// JWT claims for access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID).
    pub sub: UserId,
    /// Role name.
    pub role: String,
    /// Capabilities as a bitmask.
    pub caps: u64,
    /// Visibility scope.
    pub vis: Visibility,
    /// Authentication epoch at issue time.
    pub epoch: u64,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

impl Claims {
    /// Check if the token has a specific capability.
    pub fn has_capability(&self, section: Section, action: Action) -> bool {
        CapabilitySet::from_bits(self.caps).has(section, action)
    }
}

/// Token pair returned on login or refresh.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// Short-lived JWT access token.
    pub access_token: String,
    /// Long-lived opaque refresh token. Only its SHA-256 digest is stored.
    pub refresh_token: String,
}

impl std::fmt::Debug for TokenPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPair")
            .field("access_token", &"[redacted]")
            .field("refresh_token", &"[redacted]")
            .finish()
    }
}

/// Refresh token record stored in the database.
#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    /// SHA-256 hex digest of the opaque refresh token. The token itself is never stored.
    token_hash: String,
    /// Associated user ID.
    user_id: UserId,
    /// Issued at timestamp.
    iat: i64,
    /// Expiration timestamp.
    expires_at: i64,
    /// Revoked at timestamp (if revoked).
    revoked_at: Option<i64>,
    /// Token ID for revocation tracking.
    token_id: String,
}

impl std::fmt::Debug for RefreshTokenRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenRecord")
            .field("token_hash", &"[redacted]")
            .field("user_id", &self.user_id)
            .field("iat", &self.iat)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .field("token_id", &self.token_id)
            .finish()
    }
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
        // OWASP recommended defaults for Argon2id (2024).
        Self {
            memory_cost: 19456,
            time_cost: 2,
            parallelism: 1,
        }
    }
}

/// Authentication service configuration.
#[derive(Clone)]
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
        let mut jwt_secret = [0u8; 32];
        OsRng.fill_bytes(&mut jwt_secret);

        Self {
            jwt_secret,
            access_ttl: Duration::from_secs(15 * 60),
            refresh_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            argon2_params: Argon2Config::default(),
            issuer: None,
            audience: None,
        }
    }
}

impl std::fmt::Debug for AuthnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthnConfig")
            .field("jwt_secret", &"[redacted]")
            .field("access_ttl", &self.access_ttl)
            .field("refresh_ttl", &self.refresh_ttl)
            .field("argon2_params", &self.argon2_params)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

/// Trait for user storage backends.
///
/// Implementations must be safe for concurrent use. Refresh tokens are keyed by their SHA-256
/// digest; the plaintext token must never be persisted.
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Get a user by ID.
    async fn get_user(&self, user_id: UserId) -> AuthResult<Option<User>>;

    /// Get a user by username.
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>>;

    /// Create a new user.
    async fn create_user(&self, user: User) -> AuthResult<User>;

    /// Update an existing user.
    async fn update_user(&self, user: User) -> AuthResult<User>;

    /// Delete a user.
    async fn delete_user(&self, user_id: UserId) -> AuthResult<()>;

    /// List all users (for administrative purposes).
    async fn list_users(&self) -> AuthResult<Vec<User>>;

    /// Get a refresh token record by the SHA-256 digest of the token.
    async fn get_refresh_token(&self, token_hash: &str) -> AuthResult<Option<RefreshTokenRecord>>;

    /// Store a new refresh token record.
    async fn store_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()>;

    /// Atomically consume a refresh token, marking it revoked.
    ///
    /// Returns [`AuthError::RefreshTokenNotFound`] for an unknown digest,
    /// [`AuthError::RefreshTokenRevoked`] for a token that was already consumed or revoked, and
    /// [`AuthError::TokenExpired`] for an expired token.
    async fn consume_refresh_token(
        &self,
        token_hash: &str,
        now: i64,
    ) -> AuthResult<RefreshTokenRecord>;

    /// Mark every refresh token belonging to a user as revoked.
    async fn revoke_all_refresh_tokens_for_user(&self, user_id: UserId, now: i64)
        -> AuthResult<()>;

    /// Atomically accept a TOTP time step for a user.
    ///
    /// Returns `false` when the step was already accepted (or is older than the last accepted
    /// step), which is how replay of a still-valid TOTP code is rejected.
    async fn accept_totp_step(&self, user_id: UserId, step: u64) -> AuthResult<bool>;
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
        Ok(self.users.read().await.get(&user_id).cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
        let user_id = self.users_by_username.read().await.get(username).copied();
        match user_id {
            Some(user_id) => Ok(self.users.read().await.get(&user_id).cloned()),
            None => Ok(None),
        }
    }

    async fn create_user(&self, user: User) -> AuthResult<User> {
        let mut users = self.users.write().await;
        let mut users_by_username = self.users_by_username.write().await;

        if users_by_username.contains_key(&user.username) {
            return Err(AuthError::UsernameExists);
        }
        if users.contains_key(&user.id) {
            return Err(AuthError::Store("user id already exists".to_string()));
        }

        users_by_username.insert(user.username.clone(), user.id);
        users.insert(user.id, user.clone());
        Ok(user)
    }

    async fn update_user(&self, user: User) -> AuthResult<User> {
        let mut users = self.users.write().await;
        let mut users_by_username = self.users_by_username.write().await;

        let old_username = match users.get(&user.id) {
            Some(existing) => existing.username.clone(),
            None => return Err(AuthError::UserNotFound),
        };

        if old_username != user.username {
            if users_by_username.contains_key(&user.username) {
                return Err(AuthError::UsernameExists);
            }
            users_by_username.remove(&old_username);
            users_by_username.insert(user.username.clone(), user.id);
        }

        users.insert(user.id, user.clone());
        Ok(user)
    }

    async fn delete_user(&self, user_id: UserId) -> AuthResult<()> {
        let mut users = self.users.write().await;
        let mut users_by_username = self.users_by_username.write().await;

        let Some(user) = users.remove(&user_id) else {
            return Err(AuthError::UserNotFound);
        };
        users_by_username.remove(&user.username);

        let mut refresh_tokens = self.refresh_tokens.write().await;
        refresh_tokens.retain(|_, record| record.user_id != user_id);
        Ok(())
    }

    async fn list_users(&self) -> AuthResult<Vec<User>> {
        Ok(self.users.read().await.values().cloned().collect())
    }

    async fn get_refresh_token(&self, token_hash: &str) -> AuthResult<Option<RefreshTokenRecord>> {
        Ok(self.refresh_tokens.read().await.get(token_hash).cloned())
    }

    async fn store_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()> {
        let token_hash = record.token_hash.clone();
        self.refresh_tokens.write().await.insert(token_hash, record);
        Ok(())
    }

    async fn consume_refresh_token(
        &self,
        token_hash: &str,
        now: i64,
    ) -> AuthResult<RefreshTokenRecord> {
        let mut refresh_tokens = self.refresh_tokens.write().await;
        let record = refresh_tokens
            .get_mut(token_hash)
            .ok_or(AuthError::RefreshTokenNotFound)?;

        if record.revoked_at.is_some() {
            return Err(AuthError::RefreshTokenRevoked);
        }
        if now >= record.expires_at {
            return Err(AuthError::TokenExpired);
        }

        record.revoked_at = Some(now);
        Ok(record.clone())
    }

    async fn revoke_all_refresh_tokens_for_user(
        &self,
        user_id: UserId,
        now: i64,
    ) -> AuthResult<()> {
        let mut refresh_tokens = self.refresh_tokens.write().await;
        for record in refresh_tokens.values_mut() {
            if record.user_id == user_id && record.revoked_at.is_none() {
                record.revoked_at = Some(now);
            }
        }
        Ok(())
    }

    async fn accept_totp_step(&self, user_id: UserId, step: u64) -> AuthResult<bool> {
        let mut users = self.users.write().await;
        let user = users.get_mut(&user_id).ok_or(AuthError::UserNotFound)?;

        if user.totp_secret.is_none() {
            return Ok(false);
        }
        if user.totp_last_step.is_some_and(|last| step <= last) {
            return Ok(false);
        }

        user.totp_last_step = Some(step);
        user.updated_at = Utc::now();
        Ok(true)
    }
}

/// Hash a password using Argon2id, falling back to bcrypt if Argon2 cannot run.
pub fn hash_password(password: &str, argon2_config: &Argon2Config) -> AuthResult<String> {
    let params = Argon2Params::new(
        argon2_config.memory_cost,
        argon2_config.time_cost,
        argon2_config.parallelism,
        None,
    )
    .map_err(|err| AuthError::PasswordHash(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // password-hash 0.6 dropped `SaltString`; the salt is plain bytes and the PHC encoder
    // base64s them exactly as before, so stored hashes keep the same shape.
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    if let Ok(hash) = argon2.hash_password_with_salt(password.as_bytes(), &salt) {
        return Ok(hash.to_string());
    }

    let hash = bcrypt_hash(password, DEFAULT_COST)?;
    Ok(hash)
}

/// Verify a password against a stored Argon2id or bcrypt hash.
///
/// A wrong password returns `Ok(false)`; only a malformed or unsupported hash is an error.
/// Argon2's `PasswordVerifier` performs the comparison in constant time.
pub fn verify_password(password: &str, hash: &str) -> AuthResult<bool> {
    if hash.starts_with("$argon2") {
        let parsed =
            PasswordHash::new(hash).map_err(|err| AuthError::PasswordHash(err.to_string()))?;
        if parsed.version.is_none() || parsed.salt.is_none() || parsed.hash.is_none() {
            return Err(AuthError::PasswordHash(
                "incomplete argon2 password hash".to_string(),
            ));
        }
        return match Argon2::default().verify_password(password.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
            Err(err) => Err(AuthError::Argon2(err)),
        };
    }

    if hash.starts_with("$2") {
        return Ok(bcrypt_verify(password, hash)?);
    }

    Err(AuthError::PasswordHash(
        "unsupported password hash format".to_string(),
    ))
}

/// Generate an opaque refresh token.
fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base32::encode(Alphabet::Rfc4648 { padding: false }, &bytes)
}

/// Generate a random token ID used for bookkeeping.
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

/// Current TOTP time step.
fn now_step() -> u64 {
    u64::try_from(now_ts()).unwrap_or_default() / TOTP_STEP_SECONDS
}

/// SHA-256 hex digest of an opaque refresh token.
fn hash_refresh_token(token: &str) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(token.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").unwrap_or_default();
    }
    encoded
}

/// Generate a TOTP code for a time step.
fn totp_code(secret: &[u8], step: u64) -> String {
    totp_custom::<Sha1>(
        TOTP_STEP_SECONDS,
        TOTP_DIGITS,
        secret,
        step * TOTP_STEP_SECONDS,
    )
}

/// Constant-time comparison for fixed-length TOTP codes.
fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

/// Check whether a claim set may access a row owned by `owner_id`.
///
/// `Visibility::All` grants access to every row. `Visibility::Owner` grants access only when the
/// token subject is the row owner.
pub fn check_row_access(claims: &Claims, owner_id: UserId) -> bool {
    match claims.vis {
        Visibility::All => true,
        Visibility::Owner => claims.sub == owner_id,
    }
}

/// Filter rows to those visible under the claims' visibility scope.
///
/// This is the row-level enforcement point: callers must pass every candidate row through this
/// function (or [`check_row_access`]) rather than trusting the claims alone.
pub fn filter_visible_rows<T>(
    claims: &Claims,
    rows: Vec<T>,
    owner_id: impl Fn(&T) -> UserId,
) -> Vec<T> {
    match claims.vis {
        Visibility::All => rows,
        Visibility::Owner => rows
            .into_iter()
            .filter(|row| claims.sub == owner_id(row))
            .collect(),
    }
}

/// Main authentication service.
pub struct AuthnService<S: UserStore> {
    store: S,
    config: AuthnConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl<S: UserStore> AuthnService<S> {
    /// Create a new service with the given store and configuration.
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

    /// Get a reference to the service configuration.
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
            totp_last_step: None,
            auth_epoch: 0,
            created_at: now,
            updated_at: now,
        };

        self.store.create_user(user).await
    }

    /// Update a user's password after verifying the old password.
    ///
    /// The authentication epoch is incremented and every refresh token is revoked, so access and
    /// refresh tokens issued before the change stop working immediately.
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

        if !verify_password(old_password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        user.password_hash = hash_password(new_password, &self.config.argon2_params)?;
        bump_epoch(&mut user)?;
        user.updated_at = Utc::now();
        self.store.update_user(user).await?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts())
            .await?;
        Ok(())
    }

    /// Set a user's password (administrative operation; no old password required).
    ///
    /// Like [`AuthnService::update_password`], this increments the authentication epoch and
    /// revokes every refresh token.
    pub async fn set_password(&self, user_id: UserId, new_password: &str) -> AuthResult<()> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        user.password_hash = hash_password(new_password, &self.config.argon2_params)?;
        bump_epoch(&mut user)?;
        user.updated_at = Utc::now();
        self.store.update_user(user).await?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts())
            .await?;
        Ok(())
    }

    /// Update a user's role.
    ///
    /// The authentication epoch is incremented so tokens carrying the old role and capabilities
    /// are rejected.
    pub async fn update_role(&self, user_id: UserId, role: Role) -> AuthResult<User> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        user.role = role;
        bump_epoch(&mut user)?;
        user.updated_at = Utc::now();
        self.store.update_user(user.clone()).await?;
        Ok(user)
    }

    /// Enable TOTP for a user. Returns `(secret, otpauth URI)`.
    pub async fn totp_setup(&self, user_id: UserId) -> AuthResult<(String, String)> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let mut secret_bytes = [0u8; 20];
        OsRng.fill_bytes(&mut secret_bytes);
        let secret = base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes);

        let issuer = self.config.issuer.as_deref().unwrap_or("caddy-rs");
        let uri = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
            urlencoding::encode(issuer),
            urlencoding::encode(&user.username),
            secret,
            urlencoding::encode(issuer),
            TOTP_DIGITS,
            TOTP_STEP_SECONDS,
        );

        user.totp_secret = Some(secret.clone());
        user.totp_last_step = None;
        user.updated_at = Utc::now();
        self.store.update_user(user).await?;

        Ok((secret, uri))
    }

    /// Verify a TOTP code for a user.
    ///
    /// The current step and one adjacent step in either direction are accepted for clock skew.
    /// The accepted step is recorded atomically, so the same code cannot be used twice.
    pub async fn totp_verify(&self, user_id: UserId, code: &str) -> AuthResult<bool> {
        let user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let secret = user
            .totp_secret
            .as_deref()
            .ok_or(AuthError::TotpNotConfigured)?;
        let secret_bytes = base32::decode(Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| AuthError::Internal("invalid base32 TOTP secret".to_string()))?;

        let current = now_step();
        let mut steps = vec![current];
        if current > 0 {
            steps.push(current - 1);
        }
        steps.push(current + 1);

        let matched = steps
            .into_iter()
            .find(|&step| constant_time_eq(code, &totp_code(&secret_bytes, step)));
        let Some(step) = matched else {
            return Ok(false);
        };

        self.store.accept_totp_step(user_id, step).await
    }

    /// Disable TOTP for a user.
    pub async fn totp_disable(&self, user_id: UserId) -> AuthResult<()> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        user.totp_secret = None;
        user.totp_last_step = None;
        user.updated_at = Utc::now();
        self.store.update_user(user).await?;
        Ok(())
    }

    /// Log in with a username, password and optional TOTP code.
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

        if !verify_password(password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        if user.has_totp() {
            let code = totp_code.ok_or(AuthError::InvalidTotpCode)?;
            if !self.totp_verify(user.id, code).await? {
                return Err(AuthError::InvalidTotpCode);
            }
        }

        self.issue_token_pair(&user).await
    }

    /// Refresh an access token using a refresh token.
    ///
    /// The presented refresh token is atomically consumed and a fresh pair is issued. A reused,
    /// revoked or expired token is rejected.
    pub async fn refresh(&self, refresh_token: &str) -> AuthResult<TokenPair> {
        let token_hash = hash_refresh_token(refresh_token);
        let record = self
            .store
            .consume_refresh_token(&token_hash, now_ts())
            .await?;
        let user = self
            .store
            .get_user(record.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        self.issue_token_pair(&user).await
    }

    /// Revoke every refresh token for a user and invalidate existing access tokens.
    pub async fn revoke_all_for_user(&self, user_id: UserId) -> AuthResult<()> {
        let mut user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        bump_epoch(&mut user)?;
        user.updated_at = Utc::now();
        self.store.update_user(user).await?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts())
            .await
    }

    /// Verify an access token and return its claims.
    ///
    /// Verification is asynchronous because the token's authentication epoch is compared with the
    /// current epoch in the store. A token issued before a password change, role change or
    /// revocation is rejected even if it has not expired.
    pub async fn verify_access_token(&self, token: &str) -> AuthResult<Claims> {
        let mut validation = Validation::new(JwtAlgorithm::HS256);
        if let Some(issuer) = &self.config.issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(audience) = &self.config.audience {
            validation.set_audience(&[audience]);
        }
        validation.validate_exp = true;
        // Access tokens are short-lived; do not accept them past their `exp` claim.
        validation.leeway = 0;

        let token_data =
            decode::<Claims>(token, &self.decoding_key, &validation).map_err(|err| {
                match err.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        AuthError::InvalidSignature
                    }
                    _ => AuthError::InvalidToken,
                }
            })?;

        let claims = token_data.claims;
        let user = self
            .store
            .get_user(claims.sub)
            .await?
            .ok_or(AuthError::InvalidToken)?;
        if user.auth_epoch != claims.epoch {
            return Err(AuthError::InvalidToken);
        }

        Ok(claims)
    }

    /// Check whether claims grant permission for a section/action pair.
    pub fn check_permission(&self, claims: &Claims, section: Section, action: Action) -> bool {
        claims.has_capability(section, action)
    }

    /// Issue a new access/refresh token pair for a user.
    async fn issue_token_pair(&self, user: &User) -> AuthResult<TokenPair> {
        let now = now_ts();
        let claims = Claims {
            sub: user.id,
            role: user.role.name.clone(),
            caps: user.role.capabilities.bits(),
            vis: user.role.visibility,
            epoch: user.auth_epoch,
            iat: now,
            exp: now + self.config.access_ttl.as_secs() as i64,
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
        };
        let access_token = encode(
            &Header::new(JwtAlgorithm::HS256),
            &claims,
            &self.encoding_key,
        )?;

        let refresh_token = generate_refresh_token();
        let token_hash = hash_refresh_token(&refresh_token);
        let record = RefreshTokenRecord {
            token_hash,
            user_id: user.id,
            iat: now,
            expires_at: now + self.config.refresh_ttl.as_secs() as i64,
            revoked_at: None,
            token_id: generate_token_id(),
        };
        self.store.store_refresh_token(record).await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
    }
}

#[cfg(test)]
mod tests;
