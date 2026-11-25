//! Authentication and authorization service for caddy-rs.
//!
//! This crate provides a reusable authentication and authorization system with:
//! - User management with roles, capabilities, and row-level visibility
//! - Password hashing (argon2id; legacy bcrypt hashes still verify) with constant-time verification
//! - JWT access tokens and rotating opaque refresh tokens
//! - TOTP two-factor authentication with a configurable window and monotonic replay protection;
//!   see `docs/TOTP.md` for the configuration and the required handling of replay rejections
//! - Permission checking based on roles, capabilities, and visibility
//! - An in-memory [`UserStore`] implementation; persistent backends belong outside this crate
//!
//! The crate deliberately has no dependency on the process-manager (`pm-*`) crates. A persistent
//! store can implement [`UserStore`] without pulling process-manager state into the authentication
//! boundary.
//!
//! # JWT signing secret file
//!
//! [`JwtSecretSource::File`] keeps the signing key in a file so existing sessions survive a
//! restart. The file is created owner-only (`0600`) on first start, must be a regular file (a
//! symlink at the final path is refused), and must contain exactly 32 bytes.
//!
//! Only a **zero-byte** file is repaired: it is an unusable leftover from a crash between create
//! and write, so it is replaced by a fresh random secret. A non-empty file of any other length is
//! never repaired, truncated or overwritten — the service fails closed with an error that names
//! the path and the observed length. The operator must then either delete the file (a new secret
//! is generated on the next start, which invalidates existing sessions) or configure a master
//! secret.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Algorithm, Argon2, Params as Argon2Params, Version,
};
use async_trait::async_trait;
use base32::Alphabet;
use bcrypt::verify as bcrypt_verify;
use caddy_rs_core::Timestamp;
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

impl std::str::FromStr for UserId {
    type Err = uuid::Error;

    /// Parse a user id from its canonical UUID string, as used in API paths.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
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
    /// True while an enrollment secret has been issued but no code has confirmed it yet.
    ///
    /// A pending secret must not gate login: the operator has not proved possession, and gating on
    /// it would lock them out of the account they were trying to protect if they abandoned
    /// enrollment. Confirmation clears this flag, which is what actually activates the factor.
    pub totp_pending: bool,
    /// Replacement secret issued by [`AuthnService::totp_reenroll`] while an active factor exists.
    ///
    /// It is stored *beside* the active [`totp_secret`](Self::totp_secret), never over it: the old
    /// factor keeps gating login (and `has_totp` stays true) until a code from this secret
    /// confirms it, so an abandoned or hostile re-enrolment cannot weaken the account.
    pub totp_pending_secret: Option<String>,
    /// Highest TOTP time step accepted for this user, used for replay protection.
    ///
    /// Any code whose time step is at or below this value is rejected: a consumed code is a
    /// replay, and an older code after a newer one has been accepted is treated as an
    /// impersonation attempt.
    pub totp_last_step: Option<u64>,
    /// Monotonically increasing authentication epoch.
    ///
    /// Access tokens carry the epoch they were issued under. Password changes, role changes and
    /// explicit revocation increment it, which invalidates every previously issued access token.
    pub auth_epoch: u64,
    /// Account creation timestamp.
    pub created_at: Timestamp,
    /// Last update timestamp.
    pub updated_at: Timestamp,
}

impl User {
    /// Check if user has TOTP enabled.
    ///
    /// A secret issued by [`AuthnService::totp_setup`] but not yet confirmed through
    /// [`AuthnService::totp_confirm`] does not count: the factor is active only once the operator
    /// has proved they can produce a code from it.
    pub fn has_totp(&self) -> bool {
        self.totp_secret.is_some() && !self.totp_pending
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
    /// Highest TOTP time step accepted for this user, used for replay protection.
    ///
    /// Any code whose time step is at or below this value is rejected: a consumed code is a
    /// replay, and an older code after a newer one has been accepted is treated as an
    /// impersonation attempt.
    pub totp_last_step: Option<u64>,
    /// Monotonically increasing authentication epoch.
    pub auth_epoch: u64,
    /// Account creation timestamp.
    pub created_at: Timestamp,
    /// Last update timestamp.
    pub updated_at: Timestamp,
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
            totp_pending: false,
            totp_pending_secret: None,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub created_at: Timestamp,
    /// Last update timestamp.
    pub updated_at: Timestamp,
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
            .field(
                "totp_pending_secret",
                &self.totp_pending_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("totp_last_step", &self.totp_last_step)
            .field("auth_epoch", &self.auth_epoch)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Authentication errors.
///
/// `#[non_exhaustive]`: variants are added as the service grows (the throttle and password-policy
/// errors were), so downstream `match`es need a wildcard arm. Adding fields to `User` and
/// `AuthnConfig` is likewise a source-breaking change for struct literals; build them from
/// `AuthnConfig::default()` with `..` and read users through the service.
#[non_exhaustive]
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
    /// The supplied TOTP code is invalid.
    #[error("invalid TOTP code")]
    InvalidTotpCode,
    /// The supplied TOTP code was already used, or predates the newest accepted code.
    ///
    /// This is a replay / impersonation attempt and is reported distinctly from a merely
    /// incorrect code so callers can alert, rate-limit, or lock the account.
    #[error("TOTP code replay or impersonation attempt")]
    TotpReplay,
    /// TOTP is not configured for the user.
    #[error("TOTP not configured for user")]
    TotpNotConfigured,
    /// TOTP is already active, so there is no pending enrollment to confirm.
    #[error("TOTP is already enabled for this account")]
    TotpAlreadyEnabled,
    /// Too many failed attempts for this account: the caller must wait before trying again.
    ///
    /// Returned *before* any credential is checked, so a locked account cannot be used to keep
    /// guessing. The same error is returned for a username that does not exist once enough
    /// attempts were made against it, so the lockout state is not an account-existence oracle.
    #[error("too many failed attempts; retry in {} seconds", .retry_after.as_secs())]
    TooManyAttempts {
        /// How long until the next attempt is accepted.
        retry_after: Duration,
    },
    /// The service configuration is unusable (weak or inconsistent parameters).
    #[error("invalid authentication configuration: {0}")]
    InvalidConfig(String),
    /// An operator-supplied TOTP secret is not base32 of 16 to 64 bytes (128 bits minimum).
    #[error("TOTP secret must be base32 (A-Z, 2-7) encoding at least 16 bytes (128 bits)")]
    InvalidTotpSecret,
    /// A new password consists only of whitespace.
    #[error("password must not be blank")]
    PasswordBlank,
    /// A new password is shorter than [`MIN_PASSWORD_CHARS`].
    #[error("password must be at least {min} characters")]
    PasswordTooShort {
        /// The minimum length, in characters.
        min: usize,
    },
    /// A password is longer than [`MAX_PASSWORD_BYTES`].
    #[error("password must be at most {max} bytes")]
    PasswordTooLong {
        /// The maximum length, in bytes.
        max: usize,
    },
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
    /// Why the token was revoked; `None` while it is live. Only a [`RevokeReason::Rotated`] token
    /// can signal theft when presented again.
    #[serde(default)]
    revoke_reason: Option<RevokeReason>,
    /// The owner's `auth_epoch` when the token was issued. Reuse of a rotated token only counts as
    /// theft while the epoch has not moved since (a password change or session reset retires the
    /// whole family anyway).
    #[serde(default)]
    epoch: u64,
    /// Token ID for revocation tracking.
    token_id: String,
}

/// Why a refresh token stopped being usable.
///
/// Recorded so that presenting a revoked token can be judged correctly: only a token that was
/// *rotated* by a normal refresh is evidence of a stolen copy. Every other revocation is an
/// ordinary event (the user logged out, changed their password, or a family revocation already
/// happened), and a client that still holds such a token must simply be told it is revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RevokeReason {
    /// Consumed by a successful `refresh`; a replay of this token indicates a copied token.
    Rotated,
    /// Consumed by a single-device logout.
    LoggedOut,
    /// Revoked in bulk (password change, factor change, reuse response, administrator action).
    Revoked,
}

impl std::fmt::Debug for RefreshTokenRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenRecord")
            .field("token_hash", &"[redacted]")
            .field("user_id", &self.user_id)
            .field("iat", &self.iat)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .field("revoke_reason", &self.revoke_reason)
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
            memory_cost: MIN_ARGON2_MEMORY_KIB,
            time_cost: MIN_ARGON2_TIME_COST,
            parallelism: MIN_ARGON2_PARALLELISM,
        }
    }
}

/// Smallest Argon2id memory cost (KiB) accepted by [`AuthnService::new`]: the OWASP minimum
/// configuration `m=19456 (19 MiB), t=2, p=1`.
pub const MIN_ARGON2_MEMORY_KIB: u32 = 19456;
/// Smallest Argon2id time cost (iterations) accepted by [`AuthnService::new`].
pub const MIN_ARGON2_TIME_COST: u32 = 2;
/// Smallest Argon2id parallelism accepted by [`AuthnService::new`].
pub const MIN_ARGON2_PARALLELISM: u32 = 1;

/// Longest password (in bytes) that is hashed or verified.
///
/// Anything longer is refused before any hashing work: an unbounded password is a CPU and memory
/// lever for an unauthenticated caller (login accepts a password from anyone), and bcrypt, which
/// legacy hashes may use, silently truncates at 72 bytes. 1024 bytes is far above any passphrase.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Shortest password (in characters) accepted when creating the first administrator.
pub const MIN_PASSWORD_CHARS: usize = 8;

/// The password policy every path that *sets* a password applies: at least
/// [`MIN_PASSWORD_CHARS`] characters (counted as characters, not bytes) and at most
/// [`MAX_PASSWORD_BYTES`] bytes. One helper so the account-creation, first-run, password-change and
/// administrative-reset paths cannot drift apart.
pub fn check_password_policy(password: &str) -> AuthResult<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AuthError::PasswordTooShort {
            min: MIN_PASSWORD_CHARS,
        });
    }
    if password.trim().is_empty() {
        return Err(AuthError::PasswordBlank);
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AuthError::PasswordTooLong {
            max: MAX_PASSWORD_BYTES,
        });
    }
    Ok(())
}

impl Argon2Config {
    /// Reject parameters weaker than the OWASP minimum, or unusable by Argon2 at all.
    ///
    /// Weak parameters are not an error in `hash_password` itself (it hashes with whatever it is
    /// given); [`AuthnService::new`] calls this so a service cannot be built with them by accident.
    pub fn validate(&self) -> AuthResult<()> {
        if self.memory_cost < MIN_ARGON2_MEMORY_KIB {
            return Err(AuthError::InvalidConfig(format!(
                "argon2_params.memory_cost {} KiB is below the minimum of {MIN_ARGON2_MEMORY_KIB} KiB",
                self.memory_cost
            )));
        }
        if self.time_cost < MIN_ARGON2_TIME_COST {
            return Err(AuthError::InvalidConfig(format!(
                "argon2_params.time_cost {} is below the minimum of {MIN_ARGON2_TIME_COST}",
                self.time_cost
            )));
        }
        if self.parallelism < MIN_ARGON2_PARALLELISM {
            return Err(AuthError::InvalidConfig(format!(
                "argon2_params.parallelism {} is below the minimum of {MIN_ARGON2_PARALLELISM}",
                self.parallelism
            )));
        }
        Argon2Params::new(self.memory_cost, self.time_cost, self.parallelism, None)
            .map_err(|error| AuthError::InvalidConfig(format!("argon2_params: {error}")))?;
        Ok(())
    }
}

/// TOTP time-step acceptance window.
///
/// The window controls how many adjacent time steps are considered valid when verifying a TOTP
/// code. A larger window is more forgiving of clock skew and user delay, but slightly increases
/// the attack surface because multiple consecutive codes are acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpWindow {
    /// Only accept the current time step. Most secure, default.
    Current,
    /// Accept current ± 1 time step. Tolerates small clock skew and user delay.
    PlusMinusOne,
    /// Accept the current time step and the next one (current + 1). An older step
    /// (`current - 1`) is never accepted.
    ///
    /// This is *not* the pre-window legacy behaviour: legacy verification accepted
    /// `current - 1` as well, which is [`TotpWindow::PlusMinusOne`]. Use that variant to
    /// reproduce the legacy window; `CurrentAndNext` exists for clients that pre-compute the
    /// next code.
    CurrentAndNext,
}

impl Default for TotpWindow {
    fn default() -> Self {
        TotpWindow::Current
    }
}

/// How many steps behind the accepted window are still inspected to classify an older code as a
/// replay rather than a plain mismatch.
///
/// A code older than this horizon is indistinguishable from a wrong guess, so it is reported as
/// `Ok(false)`. Ten steps is five minutes, which comfortably covers a captured code being replayed
/// shortly after it was observed, without letting a caller force an unbounded number of HMACs.
pub const TOTP_REPLAY_LOOKBACK_STEPS: u64 = 10;

/// Source for the JWT signing secret.
///
/// # Security Warning
/// Production deployments should **always** use [`JwtSecretSource::Master`] or
/// [`JwtSecretSource::File`] so that existing sessions remain valid across config
/// reloads and process restarts. [`JwtSecretSource::Ephemeral`] is provided only
/// for backwards compatibility and local development.
#[derive(Clone, Serialize, Deserialize)]
pub enum JwtSecretSource {
    /// Derive from a user-provided master secret string.
    ///
    /// The 32-byte signing key is produced by hashing the UTF-8 bytes of the
    /// secret with SHA-256. The same master secret always yields the same key.
    Master(String),
    /// Read from / write to a persistent file.
    ///
    /// On first start the file does not exist: a random 32-byte secret is
    /// generated, written atomically (write-temp-then-rename), and reused on
    /// every subsequent start.
    ///
    /// The final path component must be a regular file: a symlink there is refused, so the signing
    /// key cannot be redirected to a file an attacker controls.
    ///
    /// An existing file must contain exactly 32 bytes. Only a zero-byte file is repaired (it is a
    /// crash leftover, replaced by a fresh secret); any other non-empty length fails closed with an
    /// error naming the path and the observed length, and the operator must delete the file or
    /// configure a master secret.
    File(PathBuf),
    /// Generate fresh on each start (legacy behavior, **NOT recommended**).
    Ephemeral,
}

impl Default for JwtSecretSource {
    fn default() -> Self {
        Self::Ephemeral
    }
}

// Hand-written so that `Master(String)` plaintext can never reach a log line through `{:?}`.
impl std::fmt::Debug for JwtSecretSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtSecretSource::Master(_) => f.write_str("Master(\"[redacted]\")"),
            JwtSecretSource::File(path) => f.debug_tuple("File").field(path).finish(),
            JwtSecretSource::Ephemeral => f.write_str("Ephemeral"),
        }
    }
}

impl JwtSecretSource {
    /// Resolve this source to a 32-byte signing key.
    ///
    /// Fails only when a [`JwtSecretSource::File`] secret cannot be read or created; the caller
    /// must not silently fall back to an ephemeral key, because that would invalidate every
    /// existing session without telling anyone.
    fn resolve(&self) -> AuthResult<[u8; 32]> {
        match self {
            JwtSecretSource::Master(secret) => {
                if secret.is_empty() {
                    return Err(AuthError::Internal(
                        "JWT master secret must not be empty".to_string(),
                    ));
                }
                Ok(Sha256::digest(secret.as_bytes()).into())
            }
            JwtSecretSource::File(path) => {
                if let Some(key) = read_secret_file(path)? {
                    return Ok(key);
                }

                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);

                // Write to a freshly created, owner-only sibling temp file and install it. The
                // install never clobbers a secret another process created first: in that case this
                // process keeps the winner's on-disk key instead of its own.
                install_secret(path, &key)?;

                // Only ever return a key observed on disk: this both proves the write landed and
                // makes a concurrent first start converge on whichever key won the install race.
                read_secret_file_with_retries(path)
            }
            JwtSecretSource::Ephemeral => {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                Ok(key)
            }
        }
    }
}

/// How often a freshly installed secret file is re-read before giving up.
const SECRET_READ_ATTEMPTS: usize = 3;

/// Read a `[u8; 32]` secret file, returning `Ok(None)` when it does not exist yet.
fn read_secret_file(path: &std::path::Path) -> AuthResult<Option<[u8; 32]>> {
    use std::io::Read as _;

    let Some(mut file) = open_secret_file(path)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        AuthError::Internal(format!(
            "could not read JWT secret file {}: {error}",
            path.display()
        ))
    })?;
    match bytes.len() {
        32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(Some(key))
        }
        // An empty file is an unusable leftover (e.g. a crash between create and write), never a
        // valid secret: treat it as absent so the next start repairs it instead of hard-failing.
        0 => Ok(None),
        found => Err(AuthError::Internal(format!(
            "JWT secret file {} must contain exactly 32 bytes, found {found}; delete the file to \
             have a new secret generated, or configure a master secret",
            path.display()
        ))),
    }
}

/// Open the secret file, refusing to follow a symlink at the final path component.
///
/// A symlink planted at the configured secret path would redirect the signing key to a file an
/// attacker controls (or let the process read a file it should not), so the final component must
/// be a regular file. The check cannot be a bare `symlink_metadata` before `File::open`: the path
/// could be swapped for a symlink in between. The descriptor's own metadata is therefore compared
/// with the path metadata *after* the open, and any disagreement means the path changed while it
/// was being opened, so the read is refused rather than trusted.
///
/// The same descriptor metadata carries the file mode: a secret readable by group or other lets
/// any local user mint tokens, so it is refused too (owner-only `0600` is required). Reading the
/// mode from the opened descriptor rather than from the path avoids a `chmod` race between a
/// separate `stat` and the open.
#[cfg(unix)]
fn open_secret_file(path: &std::path::Path) -> AuthResult<Option<std::fs::File>> {
    let link_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(AuthError::Internal(format!(
                "could not inspect JWT secret file {}: {error}",
                path.display()
            )))
        }
    };
    if link_metadata.file_type().is_symlink() {
        return Err(AuthError::Internal(format!(
            "refusing to read JWT secret file {}: the final path component is a symlink; replace \
             it with a regular file or configure a master secret",
            path.display()
        )));
    }

    let file = std::fs::File::open(path).map_err(|error| {
        AuthError::Internal(format!(
            "could not read JWT secret file {}: {error}",
            path.display()
        ))
    })?;
    let opened_metadata = file.metadata().map_err(|error| {
        AuthError::Internal(format!(
            "could not inspect opened JWT secret file {}: {error}",
            path.display()
        ))
    })?;
    if !same_file(&opened_metadata, &link_metadata) {
        return Err(AuthError::Internal(format!(
            "refusing to read JWT secret file {}: it was replaced while being opened",
            path.display()
        )));
    }
    // A signing key readable by group or other lets any local user mint tokens, so refuse it. The
    // mode is read from the opened descriptor (fstat), not from the path before the open: a
    // `stat`-then-`open` check could be raced by a `chmod` between the two. The wording mirrors
    // `pm-cli`'s `refuse_group_or_world_readable` so an operator sees the same remediation.
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = opened_metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(AuthError::Internal(format!(
                "JWT secret file {} has mode 0o{mode:03o}, which is readable by group or other; \
                 restrict it to 0600 with `chmod 600 {}` or configure a master secret",
                path.display(),
                path.display()
            )));
        }
    }
    Ok(Some(file))
}

/// Non-Unix fallback: no `dev`/`ino` to compare and no POSIX mode bits, so only the pre-open
/// symlink check is available.
#[cfg(not(unix))]
fn open_secret_file(path: &std::path::Path) -> AuthResult<Option<std::fs::File>> {
    match std::fs::File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(AuthError::Internal(format!(
            "could not read JWT secret file {}: {error}",
            path.display()
        ))),
    }
}

/// Whether two metadata snapshots describe the same file (same device and inode).
#[cfg(unix)]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

/// Re-read the installed secret, retrying briefly so a short or partially written file observed
/// during a concurrent start is not mistaken for a permanently broken configuration.
fn read_secret_file_with_retries(path: &std::path::Path) -> AuthResult<[u8; 32]> {
    let mut last_error = None;
    for attempt in 0..SECRET_READ_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        match read_secret_file(path) {
            Ok(Some(key)) => return Ok(key),
            Ok(None) => {
                last_error = Some(AuthError::Internal(format!(
                    "JWT secret file {} disappeared before it could be verified",
                    path.display()
                )))
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        AuthError::Internal(format!(
            "could not verify JWT secret file {}",
            path.display()
        ))
    }))
}

/// A unique, unpredictable temp path next to `path` (same directory, so install stays atomic).
fn unique_secret_temp_path(path: &std::path::Path) -> PathBuf {
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "jwt-secret".to_string());
    path.with_file_name(format!(
        ".{name}.{}.{:016x}.tmp",
        std::process::id(),
        u64::from_le_bytes(suffix)
    ))
}

/// Create `temp` exclusively (never following a planted symlink or hardlink) with owner-only
/// permissions, write the key, and flush it to disk.
fn write_secret_temp(temp: &std::path::Path, key: &[u8; 32]) -> AuthResult<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(temp).map_err(|error| {
        AuthError::Internal(format!(
            "could not create temporary JWT secret file {}: {error}",
            temp.display()
        ))
    })?;
    // `create_new` already refuses to follow a symlink; verify anyway so the guarantee is local.
    let metadata = std::fs::symlink_metadata(temp).map_err(|error| {
        AuthError::Internal(format!(
            "could not inspect temporary JWT secret file {}: {error}",
            temp.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(AuthError::Internal(format!(
            "refusing to follow symlink at {}",
            temp.display()
        )));
    }
    use std::io::Write;
    file.write_all(key).map_err(|error| {
        AuthError::Internal(format!(
            "could not write JWT secret file {}: {error}",
            temp.display()
        ))
    })?;
    // A swallowed fsync could leave an empty or partial secret after a crash.
    file.sync_all().map_err(|error| {
        AuthError::Internal(format!(
            "could not flush JWT secret file {}: {error}",
            temp.display()
        ))
    })?;
    Ok(())
}

/// Best-effort parent directory fsync so the rename/link itself is durable.
fn sync_parent_directory(path: &std::path::Path) {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    };
    // Directory fsync is unsupported on some platforms/filesystems (ENOTSUP, EINVAL on Windows);
    // the file contents were already flushed above, so a failure here is not fatal.
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

/// Install `key` at `path` without overwriting a secret another process already installed.
fn install_secret(path: &std::path::Path, key: &[u8; 32]) -> AuthResult<()> {
    let temp = unique_secret_temp_path(path);
    let result = install_secret_inner(&temp, path, key);
    if result.is_err() {
        // Never leave a stray temp file (it holds secret material) behind on failure.
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn install_secret_inner(
    temp: &std::path::Path,
    path: &std::path::Path,
    key: &[u8; 32],
) -> AuthResult<()> {
    write_secret_temp(temp, key)?;

    // `hard_link` fails with `AlreadyExists` instead of replacing the destination, so exactly one
    // racing process wins the install; the losers then adopt the winner's key on the re-read.
    match std::fs::hard_link(temp, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process won the race, unless what sits there is an empty leftover: that is
            // not a usable secret, so replace it atomically instead of adopting it.
            if matches!(std::fs::metadata(path).map(|meta| meta.len()), Ok(0)) {
                std::fs::rename(temp, path).map_err(|error| {
                    AuthError::Internal(format!(
                        "could not repair JWT secret file {}: {error}",
                        path.display()
                    ))
                })?;
            }
        }
        Err(_) => {
            // Filesystems without hard links: fall back to rename, which is atomic but may
            // replace a concurrently installed secret. The verified re-read in `resolve` still
            // guarantees this process returns a key that is actually on disk.
            std::fs::rename(temp, path).map_err(|error| {
                AuthError::Internal(format!(
                    "could not install JWT secret file {}: {error}",
                    path.display()
                ))
            })?;
        }
    }

    // The installed file is the temp inode; drop the temp name (no-op error if rename moved it).
    let _ = std::fs::remove_file(temp);
    sync_parent_directory(path);
    Ok(())
}

/// Authentication service configuration.
#[derive(Clone)]
pub struct AuthnConfig {
    /// Source for the JWT signing secret.
    pub jwt_secret_source: JwtSecretSource,
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
    /// TOTP verification window.
    pub totp_window: TotpWindow,
    /// Failed-attempt throttling for [`AuthnService::login`] and [`AuthnService::totp_verify`].
    pub login_throttle: LoginThrottleConfig,
    /// Accept [`argon2_params`](Self::argon2_params) below the OWASP minimum (`m >= 19456 KiB`,
    /// `t >= 2`, `p >= 1`). Default `false`: [`AuthnService::new`] fails with
    /// [`AuthError::InvalidConfig`] instead of silently running with weak hashing. Opt in only for
    /// tests or very constrained hardware; a warning is logged when the weak values are used.
    pub allow_weak_argon2_params: bool,
}

impl Default for AuthnConfig {
    fn default() -> Self {
        Self {
            jwt_secret_source: JwtSecretSource::Ephemeral,
            access_ttl: Duration::from_secs(15 * 60),
            refresh_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            argon2_params: Argon2Config::default(),
            issuer: None,
            audience: None,
            totp_window: TotpWindow::Current,
            login_throttle: LoginThrottleConfig::default(),
            allow_weak_argon2_params: false,
        }
    }
}

/// Failed-attempt throttling: consecutive failures lock the account out with exponential backoff.
///
/// One budget covers password failures *and* TOTP failures for the same submitted username, so
/// guessing the six-digit code online is bounded by the same lockout schedule as guessing the
/// password. Counting is keyed by the submitted username string whether or not an account of that
/// name exists, which keeps the lockout state from revealing which usernames are real.
///
/// The lockout is a deliberate availability trade-off: someone who knows a username can keep that
/// account locked out (at most [`max_lockout`](Self::max_lockout) at a time). That is the cost of
/// bounding online guessing; the alternative is an unbounded guessing budget.
#[derive(Debug, Clone)]
pub struct LoginThrottleConfig {
    /// Consecutive failures tolerated before the first lockout. Must be at least 1.
    pub max_failures: u32,
    /// Length of the first lockout; it doubles for every further lockout without an intervening
    /// success. Must be non-zero.
    pub base_lockout: Duration,
    /// Upper bound for the doubling lockout. Must be at least [`base_lockout`](Self::base_lockout).
    pub max_lockout: Duration,
    /// Maximum number of **unknown** usernames (names with no account) tracked at once. Beyond it
    /// the oldest unknown entry is dropped, so submitting made-up usernames cannot grow memory
    /// without bound. Entries of existing accounts are held in a separate map that is bounded by
    /// the number of accounts and is never evicted, so no flood of invented names can displace or
    /// reset a real account's penalty, and nothing is ever refused merely because the table is full.
    pub max_tracked: usize,
}

impl Default for LoginThrottleConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            base_lockout: Duration::from_secs(30),
            max_lockout: Duration::from_secs(15 * 60),
            max_tracked: 10_000,
        }
    }
}

impl LoginThrottleConfig {
    /// Reject a configuration that would disable or break the throttle.
    pub fn validate(&self) -> AuthResult<()> {
        if self.max_failures == 0 {
            return Err(AuthError::InvalidConfig(
                "login_throttle.max_failures must be at least 1".to_string(),
            ));
        }
        if self.base_lockout.is_zero() {
            return Err(AuthError::InvalidConfig(
                "login_throttle.base_lockout must be greater than zero".to_string(),
            ));
        }
        if self.max_lockout < self.base_lockout {
            return Err(AuthError::InvalidConfig(
                "login_throttle.max_lockout must not be shorter than base_lockout".to_string(),
            ));
        }
        if self.max_lockout > MAX_LOCKOUT_CEILING {
            return Err(AuthError::InvalidConfig(format!(
                "login_throttle.max_lockout must not exceed {} seconds",
                MAX_LOCKOUT_CEILING.as_secs()
            )));
        }
        if self.max_tracked == 0 {
            return Err(AuthError::InvalidConfig(
                "login_throttle.max_tracked must be at least 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Longest lockout the configuration may ask for (one day). Beyond this the arithmetic on
/// `Instant` stops being meaningful and a lockout that long is an outage, not a throttle.
const MAX_LOCKOUT_CEILING: Duration = Duration::from_secs(24 * 60 * 60);

/// Length of the rolling window over which failures are totalled. It is tracked as two half-day
/// buckets, so the failures counted are those of the last 12 to 24 hours.
const THROTTLE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Failures tolerated per rolling [`THROTTLE_DAY`]; past this every further failure earns the full
/// `max_lockout`, however long the key was idle in between and whether or not a success intervened.
/// Bounds the guesses per key to roughly `THROTTLE_DAY_FAILURE_CAP + 24 h / max_lockout` a day (116
/// with the defaults; up to twice the cap right at a bucket boundary).
const THROTTLE_DAY_FAILURE_CAP: u32 = 20;

/// Failure state for one throttle key.
#[derive(Debug)]
struct AttemptEntry {
    /// Attempts reserved since the last success (or idle decay). Once the threshold is reached
    /// every attempt after an expired lockout re-locks immediately with a longer duration, so
    /// while the backoff level is non-zero the key gets one guess per lockout.
    failures: u32,
    /// How many lockouts this entry has served; the next one lasts `base << level`.
    level: u32,
    locked_until: Option<Instant>,
    last_activity: Instant,
    /// Start of the current half-day bucket.
    bucket_start: Instant,
    /// Failures reserved in the current half-day bucket.
    current_bucket: u32,
    /// Failures reserved in the half-day bucket before it.
    previous_bucket: u32,
}

impl AttemptEntry {
    fn new(now: Instant) -> Self {
        Self {
            failures: 0,
            level: 0,
            locked_until: None,
            last_activity: now,
            bucket_start: now,
            current_bucket: 0,
            previous_bucket: 0,
        }
    }
}

/// Failure counters shared by every clone of an [`AuthnService`].
///
/// Two maps, so that invented names can never touch real accounts: `known` holds keys of accounts
/// that exist (bounded by the number of accounts, never evicted, never refused), `unknown` holds
/// keys of names with no account and is capped at `max_tracked` with oldest-first eviction. Unknown
/// names are still counted and locked exactly like known ones, which is what keeps the two
/// externally indistinguishable.
#[derive(Debug, Default)]
struct AttemptTracker {
    known: HashMap<String, AttemptEntry>,
    unknown: HashMap<String, AttemptEntry>,
    /// Insertion order of `unknown`, for oldest-first eviction (may hold stale keys).
    unknown_order: VecDeque<String>,
}

impl AttemptTracker {
    /// [`reserve_as`](Self::reserve_as) for a key that belongs to an existing account.
    #[cfg(test)]
    fn reserve(
        &mut self,
        key: &str,
        now: Instant,
        config: &LoginThrottleConfig,
    ) -> Result<(), Duration> {
        self.reserve_as(key, true, now, config)
    }

    /// The entry for `key`, whichever map holds it.
    #[cfg(test)]
    fn entry(&self, key: &str) -> Option<&AttemptEntry> {
        self.known.get(key).or_else(|| self.unknown.get(key))
    }

    /// Number of tracked keys.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.known.len() + self.unknown.len()
    }

    /// Reserve one attempt for `key`, or report how long it stays locked.
    ///
    /// The attempt is counted *before* the credential is checked and stays counted unless the
    /// caller reports a success via [`clear`](Self::clear). Counting up front, under one lock, is
    /// what makes the budget hold under concurrency: parallel guesses cannot all observe "still
    /// under the limit" and then each get a free verification. `known` says the key belongs to an
    /// account that exists; this never fails because of table pressure.
    fn reserve_as(
        &mut self,
        key: &str,
        known: bool,
        now: Instant,
        config: &LoginThrottleConfig,
    ) -> Result<(), Duration> {
        // A key that has been quiet for twice the longest lockout is forgiven *gradually*: the
        // failure count restarts, but the backoff level only decays by one per idle period, and an
        // entry that still has a level re-locks on its next failure.
        let idle_reset = config.max_lockout.saturating_mul(2);
        let map = if known {
            &mut self.known
        } else {
            &mut self.unknown
        };
        let mut inserted = false;
        match map.get_mut(key) {
            Some(entry) => {
                match entry.locked_until {
                    Some(until) if until > now => return Err(until - now),
                    Some(_) => entry.locked_until = None,
                    None => {}
                }
                let idle = now.saturating_duration_since(entry.last_activity);
                if !idle_reset.is_zero() && idle >= idle_reset {
                    let periods = u32::try_from(idle.as_nanos() / idle_reset.as_nanos().max(1))
                        .unwrap_or(u32::MAX);
                    entry.level = entry.level.saturating_sub(periods);
                    entry.failures = if entry.level > 0 {
                        config.max_failures.saturating_sub(1)
                    } else {
                        0
                    };
                }
            }
            None => {
                map.insert(key.to_string(), AttemptEntry::new(now));
                inserted = true;
            }
        }
        if inserted && !known {
            self.unknown_order.push_back(key.to_string());
            self.trim_unknown(config.max_tracked);
        }
        let map = if known {
            &mut self.known
        } else {
            &mut self.unknown
        };
        let Some(entry) = map.get_mut(key) else {
            return Ok(());
        };
        entry.last_activity = now;
        // Two half-day buckets make the 24 h total slide instead of resetting all at once.
        let half = THROTTLE_DAY / 2;
        let elapsed = now.saturating_duration_since(entry.bucket_start);
        if elapsed >= THROTTLE_DAY {
            entry.previous_bucket = 0;
            entry.current_bucket = 0;
            entry.bucket_start = now;
        } else if elapsed >= half {
            entry.previous_bucket = entry.current_bucket;
            entry.current_bucket = 0;
            entry.bucket_start = entry.bucket_start.checked_add(half).unwrap_or(now);
        }
        entry.current_bucket = entry.current_bucket.saturating_add(1);
        entry.failures = entry.failures.saturating_add(1);
        let over_daily_cap =
            entry.previous_bucket.saturating_add(entry.current_bucket) > THROTTLE_DAY_FAILURE_CAP;
        if entry.failures >= config.max_failures || over_daily_cap {
            let lockout = if over_daily_cap {
                config.max_lockout
            } else {
                let factor = 1u32.checked_shl(entry.level).unwrap_or(u32::MAX);
                config
                    .base_lockout
                    .saturating_mul(factor)
                    .min(config.max_lockout)
            };
            // `max_lockout` is validated, but the arithmetic must not panic whatever it holds.
            entry.locked_until = Some(
                now.checked_add(lockout)
                    .or_else(|| now.checked_add(Duration::from_secs(100 * 365 * 24 * 60 * 60)))
                    .unwrap_or(now),
            );
            entry.level = entry.level.saturating_add(1);
        }
        Ok(())
    }

    /// Drop the oldest unknown entries beyond `cap`.
    fn trim_unknown(&mut self, cap: usize) {
        while self.unknown.len() > cap {
            match self.unknown_order.pop_front() {
                Some(oldest) => {
                    self.unknown.remove(&oldest);
                }
                None => break,
            }
        }
        if self.unknown_order.len() > cap.saturating_mul(2).saturating_add(16) {
            let live = &self.unknown;
            self.unknown_order.retain(|key| live.contains_key(key));
        }
    }

    /// A successful authentication ends the *streak*: the failure count, the backoff level and any
    /// lockout restart. The rolling 24 h total is deliberately kept, otherwise every legitimate
    /// login would refund a paced guesser's budget.
    fn clear(&mut self, key: &str) {
        if let Some(entry) = self.known.get_mut(key) {
            entry.failures = 0;
            entry.level = 0;
            entry.locked_until = None;
        }
        self.unknown.remove(key);
    }
}

/// Longest submitted username kept verbatim as a throttle key; longer ones are keyed by digest so
/// the tracker's memory is bounded by `max_tracked` regardless of request size.
const MAX_THROTTLE_KEY_BYTES: usize = 128;

/// Throttle key for a submitted username.
///
/// The key is the exact submitted name, because that is how the store matches: it is
/// case-sensitive, so `Bob` and `bob` are different accounts and must not share (or lock out) each
/// other's budget. A store that folds case would need the same folding here, so the two must agree;
/// the key and the lookup are deliberately defined in one place's terms (exact match).
fn username_throttle_key(username: &str) -> String {
    if username.len() > MAX_THROTTLE_KEY_BYTES {
        format!("user-sha256:{}", hash_refresh_token(username))
    } else {
        format!("user:{username}")
    }
}

/// Which of a user's two TOTP secrets a verification targets.
#[derive(Debug, Clone, Copy)]
enum TotpSlot {
    /// The secret in [`User::totp_secret`] (pending first enrolment or the active factor).
    Active,
    /// The replacement in [`User::totp_pending_secret`], awaiting confirmation.
    Pending,
}

/// Throttle key for TOTP verification of one account outside the login flow.
fn totp_throttle_key(user_id: UserId) -> String {
    format!("totp:{}", user_id.0)
}

impl std::fmt::Debug for AuthnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthnConfig")
            .field("jwt_secret_source", &"[redacted]")
            .field("access_ttl", &self.access_ttl)
            .field("refresh_ttl", &self.refresh_ttl)
            .field("argon2_params", &self.argon2_params)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("totp_window", &self.totp_window)
            .field("login_throttle", &self.login_throttle)
            .field("allow_weak_argon2_params", &self.allow_weak_argon2_params)
            .finish()
    }
}

/// A closure that edits a user record in place; see [`UserStore::modify_user`].
pub type UserChange = Box<dyn for<'a> FnOnce(&'a mut User) -> AuthResult<()> + Send>;

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

    /// Atomically read-modify-write one user: apply `change` to the stored record while holding
    /// whatever exclusion the backend needs, and persist the result.
    ///
    /// This is what service code uses to change a few fields. A `get_user` + `update_user` pair
    /// writes back the *whole* record it read, so a concurrent change to another field (notably
    /// `totp_last_step`, which makes a consumed TOTP code unusable) would be silently reverted.
    /// A backend must make the closure and the write one atomic step. The closure is `FnOnce` and
    /// is called exactly once, so **an implementation must hold a row lock (or equivalent) for the
    /// duration**: it cannot retry optimistically by re-running the closure. The closure must not
    /// change `id` or `username`; those are restored. Returns the stored result, or
    /// [`AuthError::UserNotFound`]; an error from `change` aborts without writing.
    async fn modify_user(&self, user_id: UserId, change: UserChange) -> AuthResult<User>;

    /// Delete a user.
    async fn delete_user(&self, user_id: UserId) -> AuthResult<()>;

    /// List all users (for administrative purposes).
    async fn list_users(&self) -> AuthResult<Vec<User>>;

    /// Atomically create the first admin user only if no users exist yet.
    ///
    /// The default implementation is not atomic: it lists users and then creates one, which
    /// allows a race between concurrent callers. Store backends that can provide atomic
    /// compare-and-set should override this method.
    async fn create_first_admin(&self, user: User) -> AuthResult<User> {
        if !self.list_users().await?.is_empty() {
            return Err(AuthError::UsernameExists);
        }
        self.create_user(user).await
    }

    /// Get a refresh token record by the SHA-256 digest of the token.
    async fn get_refresh_token(&self, token_hash: &str) -> AuthResult<Option<RefreshTokenRecord>>;

    /// Store a new refresh token record.
    ///
    /// **The insert must be refused with [`AuthError::RefreshTokenRevoked`] when the owner's
    /// current `auth_epoch` differs from the record's epoch**, checked atomically with the insert
    /// (under the same exclusion that `modify_user` takes). Every operation that retires a user's
    /// sessions bumps the epoch *first* and revokes the stored tokens second; a login or refresh
    /// that read the user before the bump and stores its token after the revoke would otherwise
    /// leave a live token that outlives the password change or reuse response.
    async fn store_refresh_token(&self, record: RefreshTokenRecord) -> AuthResult<()>;

    /// Atomically consume a refresh token, marking it revoked for `reason`.
    ///
    /// Returns [`AuthError::RefreshTokenNotFound`] for an unknown digest,
    /// [`AuthError::TokenExpired`] for an expired token (checked first, so an expired token never
    /// looks like reuse), and [`AuthError::RefreshTokenRevoked`] for a token that was already
    /// consumed or revoked.
    async fn consume_refresh_token(
        &self,
        token_hash: &str,
        now: i64,
        reason: RevokeReason,
    ) -> AuthResult<RefreshTokenRecord>;

    /// Mark every live refresh token belonging to a user as revoked ([`RevokeReason::Revoked`]).
    /// Tokens that were already consumed keep their original reason.
    async fn revoke_all_refresh_tokens_for_user(&self, user_id: UserId, now: i64)
        -> AuthResult<()>;

    /// Atomically accept a TOTP time step for a user.
    ///
    /// Returns `false` when the step was already accepted (or is older than the last accepted
    /// step), which is how replay of a still-valid TOTP code is rejected.
    async fn accept_totp_step(&self, user_id: UserId, step: u64) -> AuthResult<bool>;
}

/// In-memory user store implementation.
///
/// # Lock order
///
/// Every method that holds more than one write lock acquires them in this order:
/// `users` → `users_by_username` → `refresh_tokens`. No method acquires them in reverse, and
/// readers that need two maps (`get_user_by_username`) release the first guard before taking the
/// second. Keeping one order is what makes [`MemoryUserStore::create_first_admin`] deadlock-free
/// while it holds both user maps for the compare-and-set.
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

    /// Atomically create the first admin user only if no users exist yet.
    ///
    /// The check for existing users and the insertion happen under a single write lock, so
    /// concurrent callers cannot both observe an empty store and both create a user. The first
    /// caller wins; subsequent callers receive [`AuthError::UsernameExists`].
    async fn create_first_admin(&self, user: User) -> AuthResult<User> {
        let mut users = self.users.write().await;
        let mut users_by_username = self.users_by_username.write().await;

        if !users.is_empty() {
            return Err(AuthError::UsernameExists);
        }
        if users_by_username.contains_key(&user.username) {
            return Err(AuthError::UsernameExists);
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

    async fn modify_user(&self, user_id: UserId, change: UserChange) -> AuthResult<User> {
        let mut users = self.users.write().await;
        let user = users.get_mut(&user_id).ok_or(AuthError::UserNotFound)?;
        // Applied to a copy so a failing closure cannot leave a half-edited record behind. The
        // username is the index key and is never changed through here.
        let mut edited = user.clone();
        change(&mut edited)?;
        edited.username.clone_from(&user.username);
        edited.id = user.id;
        *user = edited.clone();
        Ok(edited)
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
        // Lock order users -> refresh_tokens. Holding the users guard across the insert makes the
        // epoch comparison and the insert one step with respect to `modify_user`.
        let users = self.users.read().await;
        // A user that no longer exists (deleted while a login or refresh was in flight) gets no
        // token either.
        match users.get(&record.user_id) {
            Some(user) if user.auth_epoch == record.epoch => {}
            _ => return Err(AuthError::RefreshTokenRevoked),
        }
        let token_hash = record.token_hash.clone();
        self.refresh_tokens.write().await.insert(token_hash, record);
        Ok(())
    }

    async fn consume_refresh_token(
        &self,
        token_hash: &str,
        now: i64,
        reason: RevokeReason,
    ) -> AuthResult<RefreshTokenRecord> {
        let mut refresh_tokens = self.refresh_tokens.write().await;
        let record = refresh_tokens
            .get_mut(token_hash)
            .ok_or(AuthError::RefreshTokenNotFound)?;

        // Expiry first: a token past its lifetime is expired whether or not it was also revoked,
        // so an old record can never be used to provoke the reuse response.
        if now >= record.expires_at {
            return Err(AuthError::TokenExpired);
        }
        if record.revoked_at.is_some() {
            return Err(AuthError::RefreshTokenRevoked);
        }

        record.revoked_at = Some(now);
        record.revoke_reason = Some(reason);
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
                record.revoke_reason = Some(RevokeReason::Revoked);
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
        // Reject any step at or below the highest accepted step. This rejects both an immediate
        // replay of a consumed code and a downgrade to an older code after a newer one has been
        // accepted (a replay / impersonation attempt), regardless of the configured window.
        if user.totp_last_step.is_some_and(|last| step <= last) {
            return Ok(false);
        }

        user.totp_last_step = Some(step);
        user.updated_at = Timestamp::now();
        Ok(true)
    }
}

/// Hash a password using Argon2id.
///
/// There is deliberately no fallback to a weaker algorithm: if Argon2 cannot run, the error is
/// returned (a silent switch to bcrypt would store a hash of a different strength, and bcrypt
/// truncates at 72 bytes). Passwords longer than [`MAX_PASSWORD_BYTES`] are refused with
/// [`AuthError::PasswordTooLong`] before any hashing work. The parameters are used as given;
/// [`AuthnService::new`] is what enforces the OWASP minimum on the configured ones.
pub fn hash_password(password: &str, argon2_config: &Argon2Config) -> AuthResult<String> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AuthError::PasswordTooLong {
            max: MAX_PASSWORD_BYTES,
        });
    }
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

    let hash = argon2.hash_password_with_salt(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a stored Argon2id or bcrypt hash.
///
/// A wrong password returns `Ok(false)`; only a malformed or unsupported hash is an error.
/// Argon2's `PasswordVerifier` performs the comparison in constant time. A password longer than
/// [`MAX_PASSWORD_BYTES`] can never match (it could not have been hashed) and returns `Ok(false)`
/// without doing any hashing work.
pub fn verify_password(password: &str, hash: &str) -> AuthResult<bool> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Ok(false);
    }
    let hash_bytes = hash.as_bytes();
    let is_argon2 = hash_bytes
        .get(..7)
        .map(|prefix| prefix.ct_eq(b"$argon2").into())
        .unwrap_or(false);
    let is_bcrypt = hash_bytes
        .get(..2)
        .map(|prefix| prefix.ct_eq(b"$2").into())
        .unwrap_or(false);

    if is_argon2 {
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

    if is_bcrypt {
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
///
/// A clock before the Unix epoch is a hard error rather than a silent `0`: treating it as epoch
/// would make every issued token look epoch-issued, which grants permanent validity.
fn now_ts() -> AuthResult<i64> {
    system_time_to_ts(SystemTime::now())
}

/// Convert a [`SystemTime`] to Unix seconds.
///
/// Returns [`AuthError::Internal`] when the clock is before the Unix epoch. Never falls back to a
/// default value: a wrapped timestamp of `0` would silently defeat expiry checks.
fn system_time_to_ts(t: SystemTime) -> AuthResult<i64> {
    let elapsed = t
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Internal("system clock is before the Unix epoch".to_string()))?;
    i64::try_from(elapsed.as_secs())
        .map_err(|_| AuthError::Internal("system clock is out of range".to_string()))
}

/// Compute an expiry timestamp from an issue time and a configured token TTL.
///
/// The TTL is configuration input, so a value that does not fit in an `i64` second count, or that
/// pushes the expiry past the representable range, must fail closed with an actionable error
/// instead of panicking in a debug build or silently wrapping into the past in a release build.
fn expiry_after(now: i64, ttl: Duration) -> AuthResult<i64> {
    let ttl_seconds = i64::try_from(ttl.as_secs()).map_err(|_| {
        AuthError::Internal(format!(
            "token TTL of {} seconds is too large",
            ttl.as_secs()
        ))
    })?;
    now.checked_add(ttl_seconds)
        .ok_or_else(|| AuthError::Internal("token TTL overflows the expiry timestamp".to_string()))
}

/// Current TOTP time step.
fn now_step() -> AuthResult<u64> {
    let now = u64::try_from(now_ts()?)
        .map_err(|_| AuthError::Internal("system clock is before the Unix epoch".to_string()))?;
    Ok(now / TOTP_STEP_SECONDS)
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
    // INFEASIBLE: every caller derives `step` from `now_step()`, which is at most
    // `i64::MAX / TOTP_STEP_SECONDS`, so `step * TOTP_STEP_SECONDS` cannot overflow.
    totp_custom::<Sha1>(
        TOTP_STEP_SECONDS,
        TOTP_DIGITS,
        secret,
        step * TOTP_STEP_SECONDS,
    )
}

/// The TOTP time-step length in seconds.
pub const fn totp_step_seconds() -> u64 {
    TOTP_STEP_SECONDS
}

/// The number of digits in a TOTP code.
pub const fn totp_digits() -> u32 {
    TOTP_DIGITS
}

/// Decode a base32 TOTP secret as produced by [`AuthnService::totp_setup`].
///
/// Returns `None` when `secret` is not unpadded RFC 4648 base32.
pub fn decode_totp_secret(secret: &str) -> Option<Vec<u8>> {
    base32::decode(Alphabet::Rfc4648 { padding: false }, secret)
}

/// Generate the TOTP code for `secret` at the given time step.
///
/// This is the same code the server compares against, exposed so a caller that holds the secret can
/// complete a possession proof without reimplementing the algorithm. It is *not* a verification
/// path: verification is [`AuthnService::totp_verify`], which applies the accepted window and the
/// replay rule.
pub fn totp_code_for_step(secret: &str, step: u64) -> Option<String> {
    decode_totp_secret(secret).map(|bytes| totp_code(&bytes, step))
}

/// Canonical form of an operator-supplied base32 TOTP secret.
///
/// Whitespace and `=` padding are ignored and case is folded. The secret must decode to at least 16
/// bytes (128 bits, the RFC 4226 minimum; 160 bits is recommended) and at most 64. The error never
/// contains the secret.
pub fn normalize_totp_secret(secret: &str) -> AuthResult<String> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    match base32::decode(Alphabet::Rfc4648 { padding: false }, &normalized) {
        Some(bytes) if (16..=64).contains(&bytes.len()) => Ok(normalized),
        _ => Err(AuthError::InvalidTotpSecret),
    }
}

/// The current TOTP time step for a Unix timestamp in seconds.
pub const fn totp_step_at(unix_seconds: u64) -> u64 {
    unix_seconds / TOTP_STEP_SECONDS
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
#[derive(Clone)]
pub struct AuthnService<S: UserStore> {
    store: S,
    config: AuthnConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// Hash of a fixed, unusable password. A login for an unknown username verifies against it so
    /// the miss path costs the same Argon2 work as the hit path and cannot be timed to enumerate
    /// accounts.
    dummy_password_hash: String,
    /// Fixed TOTP time step for tests, so window and replay assertions cannot flake across a
    /// 30-second boundary.
    #[cfg(test)]
    test_step: Option<u64>,
    /// Failure counters for [`LoginThrottleConfig`]; shared by every clone of the service.
    attempts: Arc<Mutex<AttemptTracker>>,
    /// Origin of the throttle clock in tests, where "now" is origin + the shared offset.
    #[cfg(test)]
    test_clock: Option<(Instant, Arc<std::sync::atomic::AtomicU64>)>,
}

impl<S: UserStore> AuthnService<S> {
    /// Create a new service with the given store and configuration.
    ///
    /// Fails when the configured [`JwtSecretSource`] cannot produce a signing key, rather than
    /// silently starting with a different (ephemeral) key that would invalidate every session.
    pub fn new(store: S, config: AuthnConfig) -> AuthResult<Self> {
        config.login_throttle.validate()?;
        if let Err(error) = config.argon2_params.validate() {
            if !config.allow_weak_argon2_params {
                return Err(error);
            }
            tracing::warn!(%error, "running with Argon2 parameters below the OWASP minimum");
        }
        let secret = config.jwt_secret_source.resolve()?;
        let encoding_key = EncodingKey::from_secret(&secret);
        let decoding_key = DecodingKey::from_secret(&secret);
        // Fixed dummy secret: no account can authenticate against it, it exists only to spend the
        // same verification work on the unknown-username branch.
        let dummy_password_hash =
            hash_password("caddy-rs-login-timing-equalizer", &config.argon2_params)?;
        Ok(Self {
            store,
            config,
            encoding_key,
            decoding_key,
            dummy_password_hash,
            #[cfg(test)]
            test_step: None,
            attempts: Arc::new(Mutex::new(AttemptTracker::default())),
            #[cfg(test)]
            test_clock: None,
        })
    }

    /// Drive the throttle clock from a shared counter of elapsed seconds. Test-only.
    #[cfg(test)]
    pub(crate) fn with_test_clock(
        mut self,
        elapsed_seconds: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        self.test_clock = Some((Instant::now(), elapsed_seconds));
        self
    }

    /// "Now" for the throttle: the monotonic clock, or the test clock when one is installed.
    fn throttle_now(&self) -> Instant {
        #[cfg(test)]
        if let Some((origin, elapsed)) = &self.test_clock {
            return *origin
                + Duration::from_secs(elapsed.load(std::sync::atomic::Ordering::SeqCst));
        }
        Instant::now()
    }

    /// Reserve one attempt for `key`, failing with [`AuthError::TooManyAttempts`] while it is
    /// locked out.
    fn reserve_attempt(&self, key: &str, known: bool) -> AuthResult<()> {
        let now = self.throttle_now();
        let mut tracker = self
            .attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tracker
            .reserve_as(key, known, now, &self.config.login_throttle)
            .map_err(|wait| AuthError::TooManyAttempts {
                // Round up: telling the client "0 seconds" invites an immediate, refused retry.
                retry_after: Duration::from_secs(
                    wait.as_secs() + u64::from(wait.subsec_nanos() > 0),
                ),
            })
    }

    /// A success ends the failure streak for `key`.
    fn clear_attempts(&self, key: &str) {
        self.attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear(key);
    }

    /// Pin the TOTP time step. Test-only: production always uses the system clock.
    #[cfg(test)]
    pub(crate) fn with_test_step(mut self, step: u64) -> Self {
        self.test_step = Some(step);
        self
    }

    /// The TOTP time step to verify against.
    fn current_step(&self) -> AuthResult<u64> {
        #[cfg(test)]
        if let Some(step) = self.test_step {
            return Ok(step);
        }
        now_step()
    }

    /// Get a reference to the service configuration.
    pub fn config(&self) -> &AuthnConfig {
        &self.config
    }

    /// List all users (delegates to the store).
    pub async fn list_users(&self) -> AuthResult<Vec<User>> {
        self.store.list_users().await
    }

    /// Create a new user.
    pub async fn create_user(
        &self,
        username: impl Into<String>,
        password: &str,
        role: Role,
    ) -> AuthResult<User> {
        let username = username.into();
        check_password_policy(password)?;
        if self.store.get_user_by_username(&username).await?.is_some() {
            return Err(AuthError::UsernameExists);
        }

        let password_hash = hash_password(password, &self.config.argon2_params)?;
        let now = Timestamp::now();
        let user = User {
            id: UserId::new(),
            username,
            password_hash,
            role,
            totp_secret: None,
            totp_pending: false,
            totp_pending_secret: None,
            totp_last_step: None,
            auth_epoch: 0,
            created_at: now,
            updated_at: now,
        };

        self.store.create_user(user).await
    }

    /// Create the first administrator atomically.
    ///
    /// Only succeeds when no users exist yet. Concurrent callers race on the store-level
    /// compare-and-set in [`MemoryUserStore::create_first_admin`]; exactly one caller wins and
    /// receives a fresh token pair, all others get [`AuthError::UsernameExists`].
    pub async fn create_first_admin(
        &self,
        username: impl Into<String>,
        password: &str,
    ) -> AuthResult<(User, TokenPair)> {
        let username = username.into();
        // Enforced here, not only in the UI: the first administrator is created by an
        // unauthenticated call, and an empty or one-character password would make the whole
        // deployment trivially guessable. Rejected before any hashing work.
        check_password_policy(password)?;
        let password_hash = hash_password(password, &self.config.argon2_params)?;
        let now = Timestamp::now();
        let user = User {
            id: UserId::new(),
            username,
            password_hash,
            role: Role::admin(),
            totp_secret: None,
            totp_pending: false,
            totp_pending_secret: None,
            totp_last_step: None,
            auth_epoch: 0,
            created_at: now,
            updated_at: now,
        };

        let user = self.store.create_first_admin(user).await?;
        let token_pair = self.issue_token_pair(&user).await?;
        Ok((user, token_pair))
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
        let user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        check_password_policy(new_password)?;
        // Verifying the current password is a password-guessing oracle for anyone holding a
        // session token, so it spends the same per-user budget as `login`.
        let key = username_throttle_key(&user.username);
        self.reserve_attempt(&key, true)?;
        if !verify_password(old_password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }
        self.clear_attempts(&key);

        let password_hash = hash_password(new_password, &self.config.argon2_params)?;
        self.store
            .modify_user(
                user_id,
                Box::new(move |user| {
                    user.password_hash = password_hash;
                    bump_epoch(user)?;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts()?)
            .await?;
        Ok(())
    }

    /// Set a user's password (administrative operation; no old password required).
    ///
    /// Like [`AuthnService::update_password`], this increments the authentication epoch and
    /// revokes every refresh token.
    pub async fn set_password(&self, user_id: UserId, new_password: &str) -> AuthResult<()> {
        check_password_policy(new_password)?;
        let password_hash = hash_password(new_password, &self.config.argon2_params)?;
        self.store
            .modify_user(
                user_id,
                Box::new(move |user| {
                    user.password_hash = password_hash;
                    bump_epoch(user)?;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts()?)
            .await?;
        Ok(())
    }

    /// Update a user's role.
    ///
    /// The authentication epoch is incremented so tokens carrying the old role and capabilities
    /// are rejected.
    pub async fn update_role(&self, user_id: UserId, role: Role) -> AuthResult<User> {
        let user = self
            .store
            .modify_user(
                user_id,
                Box::new(move |user| {
                    user.role = role;
                    bump_epoch(user)?;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        // Tokens minted under the old role must not keep refreshing into the new epoch.
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts()?)
            .await?;
        Ok(user)
    }

    /// Generate a fresh TOTP secret and its `otpauth://` URI for `username`.
    fn new_totp_secret(&self, username: &str) -> (String, String) {
        let mut secret_bytes = [0u8; 20];
        OsRng.fill_bytes(&mut secret_bytes);
        let secret = base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes);
        let uri = self.totp_uri(username, &secret);
        (secret, uri)
    }

    /// The `otpauth://` URI for `secret` (already base32).
    fn totp_uri(&self, username: &str, secret: &str) -> String {
        let issuer = self.config.issuer.as_deref().unwrap_or("caddy-rs");
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
            urlencoding::encode(issuer),
            urlencoding::encode(username),
            secret,
            urlencoding::encode(issuer),
            TOTP_DIGITS,
            TOTP_STEP_SECONDS,
        )
    }

    /// Enrol an operator-chosen secret as an *active* factor, with no code check.
    ///
    /// For unattended provisioning of a brand-new account only: the operator generated the secret
    /// and added it to their authenticator, and supplying it is the proof of possession (it is
    /// exactly as secret as the factor itself). Unlike [`totp_setup_with_secret`] it does not
    /// leave the factor pending, so it can be applied on every start of a daemon whose user store
    /// is rebuilt from the environment. Refused over an active factor.
    ///
    /// [`totp_setup_with_secret`]: Self::totp_setup_with_secret
    pub async fn totp_activate_with_secret(&self, user_id: UserId, secret: &str) -> AuthResult<()> {
        let normalized = normalize_totp_secret(secret)?;
        self.store
            .modify_user(
                user_id,
                Box::new(move |user| {
                    if user.has_totp() {
                        return Err(AuthError::TotpAlreadyEnabled);
                    }
                    user.totp_secret = Some(normalized);
                    user.totp_pending = false;
                    user.totp_pending_secret = None;
                    user.totp_last_step = None;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        Ok(())
    }

    /// Begin first-time TOTP enrolment with an operator-chosen secret (base32, RFC 4648).
    ///
    /// For unattended provisioning only: the operator added the secret to their authenticator
    /// beforehand and proves it with [`totp_confirm`](Self::totp_confirm). Behaves like
    /// [`totp_setup`](Self::totp_setup) (pending until confirmed, refused over an active factor)
    /// except for where the secret comes from. The secret is validated (spaces and `=` padding are
    /// ignored, case is folded, at least 128 bits and at most 512) and is never included in an
    /// error or a log line.
    pub async fn totp_setup_with_secret(&self, user_id: UserId, secret: &str) -> AuthResult<()> {
        let normalized = normalize_totp_secret(secret)?;
        self.store
            .modify_user(
                user_id,
                Box::new(move |user| {
                    if user.has_totp() {
                        return Err(AuthError::TotpAlreadyEnabled);
                    }
                    user.totp_secret = Some(normalized);
                    user.totp_pending = true;
                    user.totp_pending_secret = None;
                    user.totp_last_step = None;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        Ok(())
    }

    /// Begin first-time TOTP enrolment. Returns `(secret, otpauth URI)`.
    ///
    /// The secret is *pending* until [`totp_confirm`](Self::totp_confirm) succeeds. Calling this
    /// again while the enrolment is still pending replaces the pending secret.
    ///
    /// Refuses with [`AuthError::TotpAlreadyEnabled`] when a confirmed factor exists. Overwriting an
    /// active secret would silently strip the second factor (login only checks codes for an active
    /// factor), so a stolen access token could downgrade the account to password-only and enrol
    /// the attacker's own authenticator. Replacing an active factor is
    /// [`totp_reenroll`](Self::totp_reenroll), which demands a current code.
    pub async fn totp_setup(&self, user_id: UserId) -> AuthResult<(String, String)> {
        let user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        if user.has_totp() {
            return Err(AuthError::TotpAlreadyEnabled);
        }

        let (secret, uri) = self.new_totp_secret(&user.username);
        let stored = secret.clone();
        self.store
            .modify_user(
                user_id,
                Box::new(move |user| {
                    // Re-checked under the store's exclusion: a factor confirmed since the read
                    // above must not be overwritten.
                    if user.has_totp() {
                        return Err(AuthError::TotpAlreadyEnabled);
                    }
                    user.totp_secret = Some(stored);
                    user.totp_pending = true;
                    user.totp_pending_secret = None;
                    user.totp_last_step = None;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;

        Ok((secret, uri))
    }

    /// Begin replacing the secret of an *active* factor. Returns `(secret, otpauth URI)`.
    ///
    /// The caller must prove possession of the current factor with `current_code`, which is
    /// verified (and its step consumed) exactly like a login code, including the failure throttle.
    /// The new secret is stored as [`User::totp_pending_secret`] *beside* the active one: the old
    /// factor keeps gating login until [`totp_confirm`](Self::totp_confirm) is called with a code
    /// from the new secret, so an abandoned re-enrolment weakens nothing.
    ///
    /// When no factor is active there is nothing to prove, and this behaves like
    /// [`totp_setup`](Self::totp_setup) (`current_code` is ignored).
    pub async fn totp_reenroll(
        &self,
        user_id: UserId,
        current_code: &str,
    ) -> AuthResult<(String, String)> {
        let user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        if !user.has_totp() {
            return self.totp_setup(user_id).await;
        }
        if !self.totp_verify(user_id, current_code).await? {
            return Err(AuthError::InvalidTotpCode);
        }

        // Only the pending-secret field is written, atomically: verification advanced
        // `totp_last_step`, and writing a stale whole record back would un-consume the code that
        // just proved possession.
        let (secret, uri) = self.new_totp_secret(&user.username);
        let stored = secret.clone();
        self.store
            .modify_user(
                user_id,
                Box::new(move |user| {
                    if !user.has_totp() {
                        // Disabled between the proof and the write; do not resurrect a half-state.
                        return Err(AuthError::TotpNotConfigured);
                    }
                    user.totp_pending_secret = Some(stored);
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        Ok((secret, uri))
    }

    /// Confirm a pending TOTP enrollment with a code from the authenticator.
    ///
    /// This is the step that activates the factor. Until it succeeds the secret does not gate
    /// login (see [`User::has_totp`]), so an abandoned enrollment cannot lock the operator out.
    /// The confirmation consumes the code's time step through the same replay record a login uses,
    /// so the code cannot be presented again.
    ///
    /// Enabling a factor changes the account's security posture, so the authentication epoch is
    /// incremented and refresh tokens are revoked: a session token minted before the factor existed
    /// must not outlive the change.
    ///
    /// Returns the authenticated user with the factor active.
    pub async fn totp_confirm(&self, user_id: UserId, code: &str) -> AuthResult<User> {
        let pending = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        if let Some(replacement) = pending.totp_pending_secret.clone() {
            return self.confirm_reenrolment(user_id, code, replacement).await;
        }
        if pending.totp_secret.is_none() {
            return Err(AuthError::TotpNotConfigured);
        }
        if !pending.totp_pending {
            // Confirming an already-active factor is not an escalation, but it is a no-op the caller
            // should be able to see rather than a silent success.
            return Err(AuthError::TotpAlreadyEnabled);
        }
        // Verify against the pending secret before activating it. `totp_verify` does not consult
        // `has_totp`, so it works while the factor is still pending; it records the step, which is
        // what makes the confirmation code non-replayable.
        if !self.totp_verify(user_id, code).await? {
            return Err(AuthError::InvalidTotpCode);
        }

        let user = self
            .store
            .modify_user(
                user_id,
                Box::new(|user| {
                    user.totp_pending = false;
                    bump_epoch(user)?;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts()?)
            .await?;
        Ok(user)
    }

    /// Swap the active secret for the pending replacement once a code from it is presented.
    ///
    /// The code is checked against the *replacement* (through the same throttle and replay record
    /// as every other verification); the old secret is only discarded after that succeeds. The
    /// step consumed by the possession proof in [`totp_reenroll`](Self::totp_reenroll) is already
    /// recorded, so the confirming code must come from a later step.
    async fn confirm_reenrolment(
        &self,
        user_id: UserId,
        code: &str,
        replacement: String,
    ) -> AuthResult<User> {
        if !self
            .totp_verify_throttled(user_id, code, TotpSlot::Pending)
            .await?
        {
            return Err(AuthError::InvalidTotpCode);
        }

        let user = self
            .store
            .modify_user(
                user_id,
                Box::new(move |user| {
                    if user.totp_pending_secret.as_deref() != Some(replacement.as_str()) {
                        // A concurrent re-enrolment replaced or cleared the secret this code was
                        // checked against; do not install a secret the caller did not just prove.
                        return Err(AuthError::InvalidTotpCode);
                    }
                    user.totp_secret = Some(replacement);
                    user.totp_pending = false;
                    user.totp_pending_secret = None;
                    // The confirming step stays recorded (`totp_last_step` was advanced by the
                    // verification), so the code that activated the new secret cannot be replayed.
                    bump_epoch(user)?;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts()?)
            .await?;
        Ok(user)
    }

    /// Verify a TOTP code for a user.
    ///
    /// The set of *accepted* steps is determined by [`AuthnConfig::totp_window`]:
    ///
    /// - [`TotpWindow::Current`] only accepts the current time step.
    /// - [`TotpWindow::PlusMinusOne`] accepts current ± 1 step.
    /// - [`TotpWindow::CurrentAndNext`] accepts current and current + 1.
    ///
    /// When a code matches an accepted step, the step is atomically recorded in
    /// [`User::totp_last_step`]. The record is monotonic: every code for a step at or below it is
    /// rejected from then on, which prevents both an immediate replay and a downgrade to an older
    /// code after a newer one was used.
    ///
    /// A cryptographically correct code that is *not* accepted is reported as
    /// [`AuthError::TotpReplay`] rather than `Ok(false)`, so callers can treat it as an
    /// impersonation attempt. Detection of older codes is bounded by
    /// [`TOTP_REPLAY_LOOKBACK_STEPS`]: a code older than that is indistinguishable from a wrong
    /// guess and is reported as `Ok(false)`.
    ///
    /// Every call is a throttled attempt: after [`LoginThrottleConfig::max_failures`] consecutive
    /// failures for this account the call fails with [`AuthError::TooManyAttempts`] before the code
    /// is looked at, with exponentially growing lockouts. A successful verification resets the
    /// budget. This bounds online guessing of the six-digit code for every caller (enrollment
    /// confirmation, factor removal) and not just for [`login`](Self::login), which has its own
    /// per-username budget.
    pub async fn totp_verify(&self, user_id: UserId, code: &str) -> AuthResult<bool> {
        self.totp_verify_throttled(user_id, code, TotpSlot::Active)
            .await
    }

    /// [`totp_verify`](Self::totp_verify) against the chosen secret, sharing the per-account
    /// throttle so the pending secret of a re-enrolment cannot be guessed outside the budget.
    async fn totp_verify_throttled(
        &self,
        user_id: UserId,
        code: &str,
        slot: TotpSlot,
    ) -> AuthResult<bool> {
        let user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        // Two budgets: the per-account TOTP one, and the account's login one. A session holder
        // guessing codes therefore also spends the budget an online password guesser would use,
        // instead of getting an independent allowance on top of it.
        let key = totp_throttle_key(user_id);
        self.reserve_attempt(&key, true)?;
        let login_key = username_throttle_key(&user.username);
        self.reserve_attempt(&login_key, true)?;
        let verified = self.totp_verify_unthrottled(user_id, code, slot).await?;
        if verified {
            // A correct code proves the factor; the failures before it are forgiven on both keys.
            self.clear_attempts(&key);
            self.clear_attempts(&login_key);
        }
        Ok(verified)
    }

    /// The verification itself, with no failure accounting: the caller owns the throttle.
    async fn totp_verify_unthrottled(
        &self,
        user_id: UserId,
        code: &str,
        slot: TotpSlot,
    ) -> AuthResult<bool> {
        let user = self
            .store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let secret = match slot {
            TotpSlot::Active => user.totp_secret.as_deref(),
            TotpSlot::Pending => user.totp_pending_secret.as_deref(),
        }
        .ok_or(AuthError::TotpNotConfigured)?;
        let secret_bytes = base32::decode(Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| AuthError::Internal("invalid base32 TOTP secret".to_string()))?;

        let current = self.current_step()?;
        // INFEASIBLE: `current` comes from `now_step()`, which is at most
        // `i64::MAX / TOTP_STEP_SECONDS`, so the `current + 1` steps below cannot overflow, and
        // `current - 1` is guarded by `current > 0`.
        let mut steps = vec![current];
        match self.config.totp_window {
            TotpWindow::Current => {}
            TotpWindow::PlusMinusOne => {
                if current > 0 {
                    steps.push(current - 1);
                }
                steps.push(current + 1);
            }
            TotpWindow::CurrentAndNext => {
                steps.push(current + 1);
            }
        }

        let window_low = *steps.iter().min().unwrap_or(&current);
        let matched = steps
            .into_iter()
            .find(|&step| constant_time_eq(code, &totp_code(&secret_bytes, step)));

        if let Some(step) = matched {
            return if self.store.accept_totp_step(user_id, step).await? {
                Ok(true)
            } else {
                // Correct for the step, but that step was already consumed or a newer one was.
                Err(AuthError::TotpReplay)
            };
        }

        // No code matched the accepted window. A code that is correct for a *stale* step is not a
        // typo: it is a captured code being replayed, or an attempt to downgrade to an older code.
        // Report it as an impersonation attempt instead of a plain mismatch. The search is bounded
        // so an attacker cannot make verification arbitrarily expensive.
        let lookback_low = window_low.saturating_sub(TOTP_REPLAY_LOOKBACK_STEPS);
        let stale = (lookback_low..window_low)
            .rev()
            .find(|&step| constant_time_eq(code, &totp_code(&secret_bytes, step)));
        if stale.is_some() {
            return Err(AuthError::TotpReplay);
        }

        Ok(false)
    }

    /// Disable TOTP for a user.
    pub async fn totp_disable(&self, user_id: UserId) -> AuthResult<()> {
        self.store
            .modify_user(
                user_id,
                Box::new(|user| {
                    user.totp_secret = None;
                    user.totp_pending = false;
                    user.totp_pending_secret = None;
                    // The factor is gone, so there is no replay record left to protect.
                    user.totp_last_step = None;
                    // Removing a factor weakens the account, so tokens minted while it was enabled
                    // are retired rather than allowed to outlive the downgrade.
                    bump_epoch(user)?;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts()?)
            .await?;
        Ok(())
    }

    /// Log in with a username, password and optional TOTP code.
    ///
    /// # Throttling
    ///
    /// Each call reserves one attempt in the per-username budget of [`LoginThrottleConfig`] before
    /// any credential is checked; a success resets the budget. Password failures and TOTP failures
    /// draw from the same budget, and an unknown username is counted exactly like a known one, so
    /// a locked-out response never reveals whether the account exists. While locked out the call
    /// fails with [`AuthError::TooManyAttempts`].
    ///
    /// # Error reporting
    ///
    /// A TOTP code that is correct but stale or already used (a replay) is reported as
    /// [`AuthError::InvalidTotpCode`], the same as a wrong code: the distinction would tell a
    /// password-holder which codes were recently valid. The replay is logged instead.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> AuthResult<TokenPair> {
        let key = username_throttle_key(username);
        let found = self.store.get_user_by_username(username).await?;
        self.reserve_attempt(&key, found.is_some())?;

        let Some(user) = found else {
            // Spend the same password-verification work as the hit path before failing, so the
            // response time does not reveal whether the username exists.
            let _verified = verify_password(password, &self.dummy_password_hash)?;
            return Err(AuthError::InvalidCredentials);
        };

        if !verify_password(password, &user.password_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        if user.has_totp() {
            let code = totp_code.ok_or(AuthError::InvalidTotpCode)?;
            match self
                .totp_verify_unthrottled(user.id, code, TotpSlot::Active)
                .await
            {
                Ok(true) => {}
                Ok(false) => return Err(AuthError::InvalidTotpCode),
                Err(AuthError::TotpReplay) => {
                    tracing::warn!(user = %user.id.0, "TOTP replay refused at login");
                    return Err(AuthError::InvalidTotpCode);
                }
                Err(other) => return Err(other),
            }
        }

        let tokens = self
            .issue_token_pair(&user)
            .await
            .map_err(|error| match error {
                // The account's sessions were reset while this login was in flight.
                AuthError::RefreshTokenRevoked => AuthError::InvalidCredentials,
                other => other,
            })?;
        self.clear_attempts(&key);
        Ok(tokens)
    }

    /// Refresh an access token using a refresh token.
    ///
    /// The presented refresh token is atomically consumed and a fresh pair is issued. A reused,
    /// revoked or expired token is rejected.
    ///
    /// # Reuse detection
    ///
    /// Presenting a token that a normal refresh already *rotated* is treated as theft: either the
    /// legitimate client or an attacker is holding a stale copy, and the service cannot tell which.
    /// Every refresh token of that user is revoked and the authentication epoch is bumped, so the
    /// whole token family, including the descendant the thief may already have minted, and every
    /// outstanding access token stop working; the user must log in again. The caller still
    /// receives [`AuthError::RefreshTokenRevoked`].
    ///
    /// Only that one case reacts. A token revoked for any other reason (logout, a password or
    /// factor change, an earlier reuse response) is answered with `RefreshTokenRevoked` and no side
    /// effect, as are unknown and expired tokens; and a rotated token is only evidence of theft
    /// while the user's `auth_epoch` is still the one it was issued under. Otherwise a second
    /// device's routine refresh after a reset, or anyone holding an old token, could keep signing
    /// the user out.
    pub async fn refresh(&self, refresh_token: &str) -> AuthResult<TokenPair> {
        let token_hash = hash_refresh_token(refresh_token);
        let record = match self
            .store
            .consume_refresh_token(&token_hash, now_ts()?, RevokeReason::Rotated)
            .await
        {
            Ok(record) => record,
            Err(AuthError::RefreshTokenRevoked) => {
                self.revoke_family_after_reuse(&token_hash).await?;
                return Err(AuthError::RefreshTokenRevoked);
            }
            Err(other) => return Err(other),
        };
        let user = self
            .store
            .get_user(record.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        // A token issued under an earlier epoch belongs to a session that a password, factor or
        // role change (or a reuse response) already retired. Refusing it here is what stops a
        // descendant minted by a thief from carrying on after the epoch moved; tokens stored before
        // epochs were recorded (epoch 0) of an account that has since moved on must log in again.
        if record.epoch != user.auth_epoch {
            return Err(AuthError::RefreshTokenRevoked);
        }
        self.issue_token_pair(&user).await
    }

    /// Respond to the reuse of a consumed refresh token: revoke the user's whole token family.
    ///
    /// A store failure is returned rather than swallowed, so a reuse that could not be contained
    /// is reported as an error instead of looking like an ordinary rejected token.
    async fn revoke_family_after_reuse(&self, token_hash: &str) -> AuthResult<()> {
        let Some(record) = self.store.get_refresh_token(token_hash).await? else {
            return Ok(());
        };
        if record.revoke_reason != Some(RevokeReason::Rotated) || now_ts()? >= record.expires_at {
            return Ok(());
        }
        let user_id = record.user_id;
        let issued_epoch = record.epoch;
        // One atomic step: the epoch is compared and bumped under the store's exclusion, and no
        // other field of the record is rewritten (a stale whole-record write would revive a
        // consumed TOTP code).
        let bumped = self
            .store
            .modify_user(
                user_id,
                Box::new(move |user| {
                    if user.auth_epoch != issued_epoch {
                        return Err(AuthError::RefreshTokenRevoked);
                    }
                    bump_epoch(user)?;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await;
        match bumped {
            // The token predates a reset that already retired its family, or the user is gone.
            Err(AuthError::RefreshTokenRevoked | AuthError::UserNotFound) => return Ok(()),
            Err(other) => return Err(other),
            Ok(_) => {}
        }
        tracing::warn!(
            user = %user_id.0,
            "refresh token reuse detected; revoking all of the user's sessions"
        );
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts()?)
            .await
    }

    /// Revoke one refresh token, as a single-device logout does.
    ///
    /// The token is consumed exactly like [`refresh`](Self::refresh) consumes it, so a replay is
    /// rejected with [`AuthError::RefreshTokenRevoked`]. A caller that must stay idempotent (a
    /// logout that has already been processed) maps that error, and
    /// [`AuthError::RefreshTokenNotFound`], to success itself; this method keeps the distinction so
    /// it cannot hide a real store failure.
    pub async fn revoke_refresh_token(&self, refresh_token: &str) -> AuthResult<()> {
        let token_hash = hash_refresh_token(refresh_token);
        self.store
            .consume_refresh_token(&token_hash, now_ts()?, RevokeReason::LoggedOut)
            .await
            .map(|_record| ())
    }

    /// Fetch the credential-free public view of a user.
    ///
    /// Used by session endpoints that must describe the caller without exposing the password hash
    /// or TOTP seed; [`AuthError::UserNotFound`] covers a user deleted after the token was issued.
    pub async fn get_user(&self, user_id: UserId) -> AuthResult<PublicUser> {
        self.store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)
            .map(|user| user.public())
    }

    /// Revoke every refresh token for a user and invalidate existing access tokens.
    pub async fn revoke_all_for_user(&self, user_id: UserId) -> AuthResult<()> {
        self.store
            .modify_user(
                user_id,
                Box::new(|user| {
                    bump_epoch(user)?;
                    user.updated_at = Timestamp::now();
                    Ok(())
                }),
            )
            .await?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts()?)
            .await
    }

    /// Delete a user and revoke every refresh token issued to them.
    ///
    /// The refresh tokens are revoked before the record disappears so a token cannot be replayed
    /// against a store that has not yet applied the delete. A missing user is
    /// [`AuthError::UserNotFound`].
    pub async fn delete_user(&self, user_id: UserId) -> AuthResult<()> {
        self.store
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        self.store
            .revoke_all_refresh_tokens_for_user(user_id, now_ts()?)
            .await?;
        self.store.delete_user(user_id).await
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
        let now = now_ts()?;
        // Configured TTLs are external input: compute both expiries before issuing anything so a
        // nonsensical TTL fails closed instead of panicking or wrapping.
        let access_exp = expiry_after(now, self.config.access_ttl)?;
        let refresh_expires_at = expiry_after(now, self.config.refresh_ttl)?;
        let claims = Claims {
            sub: user.id,
            role: user.role.name.clone(),
            caps: user.role.capabilities.bits(),
            vis: user.role.visibility,
            epoch: user.auth_epoch,
            iat: now,
            exp: access_exp,
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
            expires_at: refresh_expires_at,
            revoked_at: None,
            revoke_reason: None,
            epoch: user.auth_epoch,
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
#[cfg(test)]
mod tests_security;
