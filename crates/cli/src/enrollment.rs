//! `caddy-rs setup`: first-boot TOTP enrollment behind the activation endpoint (T-SETUP-003).
//!
//! T-SETUP-002 made the activation link redeemable: a valid single-use token is consumed and the
//! endpoint reports `{"status":"activated","enrollment":"pending"}`. This module is the enrollment
//! step that `pending` was standing in for. Once a token is redeemed, the operator proves possession
//! of a second factor, and a successful proof enrolls exactly one admin credential and closes the
//! activation window.
//!
//! # Scope
//!
//! This build enrolls **TOTP** (`--auth-method totp`). WebAuthn enrollment is
//! `T-SETUP-010`, split out of T-SETUP-003 because nothing it needs exists yet: there is no
//! WebAuthn registration ceremony, no attestation or `authenticatorData` parsing anywhere in the
//! workspace, no HTML body is served by this crate, and `caddy_rs_auth::key_registry` is a *static*
//! registry of operator-declared passkeys whose `key_id` is a label rather than a credential ID, so
//! it has no writable path for an enrolled credential. A request for `webauthn` therefore reports
//! [`EnrollmentError::MethodUnsupported`] instead of pretending to enrol. See DIV-0152.
//!
//! # The flow
//!
//! Two steps, keyed by the same single-use activation token:
//!
//! | request | outcome |
//! |---|---|
//! | `POST /_caddy-pm/activate?token=…&step=begin` | `200`, returns the `otpauth://` URI to scan |
//! | `POST /_caddy-pm/activate?token=…&step=verify&code=…` | `200` on a correct code; `4xx` otherwise |
//!
//! `begin` mints a secret and returns it once. `verify` checks the code against that secret. A
//! correct code enrolls the admin credential and marks the enrollment complete, which is what
//! disables the endpoint: every later request is refused with
//! [`EnrollmentError::AlreadyEnrolled`] regardless of the token, because closing the window is the
//! point of enrolling.
//!
//! The secret is returned once and never logged. `begin` is idempotent for a live activation: asking
//! twice in the same activation returns the same secret rather than minting a second one, so a
//! browser refresh cannot silently invalidate a secret the operator has already scanned.
//!
//! # Not durable
//!
//! The enrolled credential lives in process memory for the activation window, exactly as activation
//! tokens do. It does not survive a restart. Persistence is `T-SETUP-005`; this module deliberately
//! does not pre-empt that design. DIV-0152 records the gap.

use std::sync::{Arc, Mutex};

use caddy_rs_authn::{
    AuthError, AuthnConfig, AuthnService, MemoryUserStore, Role, TotpWindow, UserId,
};

/// Query parameter carrying the activation token (shared with the activation endpoint).
const TOKEN_PARAM: &str = "token";
/// Query parameter selecting the enrollment step.
const STEP_PARAM: &str = "step";
/// Query parameter carrying the TOTP code on the `verify` step.
const CODE_PARAM: &str = "code";

/// The admin account an enrollment creates when the store is empty.
const ADMIN_USERNAME: &str = "admin";

/// Why an enrollment request was refused.
///
/// Every variant is a deliberate refusal with a located reason; none of them is a catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentError {
    /// The activation window is already closed: a credential has been enrolled.
    AlreadyEnrolled,
    /// The selected `--auth-method` cannot be enrolled by this build.
    MethodUnsupported {
        /// The method the operator asked for.
        method: &'static str,
    },
    /// The `step` parameter is absent, repeated or not `begin`/`verify`.
    InvalidStep,
    /// The `code` parameter is absent or not [`TOTP_CODE_DIGITS`] decimal digits.
    InvalidCode,
    /// The code was well-formed but did not match the enrolled secret.
    CodeRejected,
    /// The code matched but its time step was already used (a replay or a downgrade).
    CodeReplayed,
    /// The activation backend itself failed; carries the underlying message.
    Internal(String),
}

impl EnrollmentError {
    /// HTTP status for the refusal.
    pub fn status(&self) -> u16 {
        match self {
            Self::AlreadyEnrolled => 409,
            Self::MethodUnsupported { .. } => 501,
            Self::InvalidStep | Self::InvalidCode => 400,
            Self::CodeRejected | Self::CodeReplayed => 401,
            Self::Internal(_) => 500,
        }
    }

    /// Stable machine-readable error code.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::AlreadyEnrolled => "already_enrolled",
            Self::MethodUnsupported { .. } => "method_unsupported",
            Self::InvalidStep => "invalid_step",
            Self::InvalidCode => "invalid_code",
            Self::CodeRejected => "code_rejected",
            Self::CodeReplayed => "code_replayed",
            Self::Internal(_) => "internal",
        }
    }

    /// JSON body for the refusal. Never contains a secret or the presented code.
    pub fn body(&self) -> String {
        match self {
            Self::MethodUnsupported { method } => format!(
                "{{\"error\":\"{}\",\"method\":\"{}\",\"tracking\":\"T-SETUP-010\"}}",
                self.error_code(),
                method
            ),
            _ => format!("{{\"error\":\"{}\"}}", self.error_code()),
        }
    }

    /// The `Copy` outcome the HTTP layer renders, carrying this refusal's status and code.
    pub fn outcome(&self) -> crate::activation::ActivationOutcome {
        crate::activation::ActivationOutcome::EnrollmentRefused {
            status: self.status(),
            code: self.error_code(),
        }
    }
}

/// Number of digits in a TOTP code, matching `caddy_rs_authn`'s `TOTP_DIGITS`.
pub const TOTP_CODE_DIGITS: usize = 6;

/// A completed enrollment: what was enrolled and under which identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledCredential {
    /// The account the credential belongs to.
    pub username: String,
    /// The method that was enrolled.
    pub method: &'static str,
}

/// The enrollment step a request selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentStep {
    /// Mint (or re-return) the secret for this activation.
    Begin,
    /// Prove possession of the secret with a code.
    Verify,
}

impl EnrollmentStep {
    /// Parse the `step` parameter.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "begin" => Some(Self::Begin),
            "verify" => Some(Self::Verify),
            _ => None,
        }
    }
}

/// The outcome of one successful enrollment request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentOutcome {
    /// The secret was minted. The URI is returned exactly once per activation.
    SecretIssued {
        /// `otpauth://` URI for an authenticator app.
        otpauth_uri: String,
    },
    /// The code was correct and the credential is enrolled; the window is now closed.
    Enrolled(EnrolledCredential),
}

/// Mutable enrollment state, behind a mutex because requests are served concurrently.
#[derive(Debug, Default)]
struct State {
    /// The user id enrolled for, once `begin` has run.
    user: Option<UserId>,
    /// The secret URIs already issued in this activation (so `begin` is idempotent).
    issued_uri: Option<String>,
    /// Set once a credential has been enrolled.
    enrolled: Option<EnrolledCredential>,
    /// The activation token that opened this enrollment session.
    ///
    /// Enrollment is two steps behind one link, and the link is single-use, so the token admits the
    /// session: the first step consumes it and this field remembers which token did. Only requests
    /// carrying that same token may continue the session.
    session_token: Option<String>,
}

/// The first-boot enrollment service for one activation window.
///
/// Built once per setup boot and shared through an [`Arc`]; all methods take `&self`.
pub struct EnrollmentService {
    /// The authn service owning the TOTP secret material.
    authn: AuthnService<MemoryUserStore>,
    /// The method selected with `--auth-method`.
    method: &'static str,
    /// Whether this build can enrol the selected method.
    supported: bool,
    /// Enrollment state.
    state: Mutex<State>,
}

impl std::fmt::Debug for EnrollmentService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The authn service holds secret material; never print it.
        f.debug_struct("EnrollmentService")
            .field("method", &self.method)
            .field("supported", &self.supported)
            .finish_non_exhaustive()
    }
}

impl EnrollmentService {
    /// A service that enrolls `method` for a setup boot.
    ///
    /// `auth_method` is the `--auth-method` value as the operator wrote it (`webauthn` or `totp`).
    pub fn new(auth_method: &str) -> Self {
        let config = AuthnConfig {
            // The default `plus_minus_one` window tolerates one step of clock skew, which is what a
            // phone and a server realistically have; replay is still refused because the consumed
            // step is recorded monotonically.
            totp_window: TotpWindow::PlusMinusOne,
            ..AuthnConfig::default()
        };
        let authn = AuthnService::new(MemoryUserStore::new(), config)
            .expect("default AuthnConfig is valid");
        Self {
            authn,
            method: match auth_method {
                "totp" => "totp",
                "webauthn" => "webauthn",
                _ => "totp",
            },
            supported: auth_method == "totp",
            state: Mutex::new(State::default()),
        }
    }

    /// The method this service was built for.
    pub fn method(&self) -> &'static str {
        self.method
    }

    /// Whether a credential has been enrolled (the activation window is closed).
    pub fn is_enrolled(&self) -> bool {
        self.lock().enrolled.is_some()
    }

    /// Record that `token` opened the enrollment session.
    pub fn open_session(&self, token: &str) {
        self.lock().session_token = Some(token.to_string());
    }

    /// Whether an enrollment session is currently open.
    pub fn has_session(&self) -> bool {
        self.lock().session_token.is_some()
    }

    /// Whether `token` is the one that opened the current enrollment session.
    pub fn is_session(&self, token: &str) -> bool {
        self.lock()
            .session_token
            .as_deref()
            .is_some_and(|opened| opened == token)
    }

    /// The `otpauth://` URI issued in this activation, if any.
    ///
    /// The HTTP body is rendered from a `Copy` outcome, so the URI is read back here rather than
    /// carried in the outcome. It is returned only to the caller holding the live activation.
    pub fn issued_uri(&self) -> Option<String> {
        self.lock().issued_uri.clone()
    }

    /// Lock the state, recovering from a poisoned mutex.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Handle one enrollment request. `query` is the request target's query string.
    ///
    /// The caller has already validated and consumed the activation token, so this function only
    /// decides what the enrollment step does.
    pub async fn handle(&self, query: &str) -> Result<EnrollmentOutcome, EnrollmentError> {
        if !self.supported {
            return Err(EnrollmentError::MethodUnsupported {
                method: self.method,
            });
        }
        if self.is_enrolled() {
            return Err(EnrollmentError::AlreadyEnrolled);
        }

        let step_value = single_param(query, STEP_PARAM).ok_or(EnrollmentError::InvalidStep)?;
        let step = EnrollmentStep::parse(step_value).ok_or(EnrollmentError::InvalidStep)?;

        match step {
            EnrollmentStep::Begin => self.begin().await,
            EnrollmentStep::Verify => {
                let code = single_param(query, CODE_PARAM).ok_or(EnrollmentError::InvalidCode)?;
                if !is_well_formed_code(code) {
                    return Err(EnrollmentError::InvalidCode);
                }
                self.verify(code).await
            }
        }
    }

    /// Mint the secret for this activation, or return the one already issued.
    async fn begin(&self) -> Result<EnrollmentOutcome, EnrollmentError> {
        if let Some(uri) = self.lock().issued_uri.clone() {
            return Ok(EnrollmentOutcome::SecretIssued { otpauth_uri: uri });
        }

        let user = self
            .authn
            .create_user(ADMIN_USERNAME, &random_password(), Role::admin())
            .await
            .map_err(internal)?;
        let (_secret, uri) = self.authn.totp_setup(user.id).await.map_err(internal)?;
        let user_id = user.id;

        let mut state = self.lock();
        state.user = Some(user_id);
        state.issued_uri = Some(uri.clone());
        Ok(EnrollmentOutcome::SecretIssued { otpauth_uri: uri })
    }

    /// Verify a code against the minted secret and enroll on success.
    async fn verify(&self, code: &str) -> Result<EnrollmentOutcome, EnrollmentError> {
        let user_id = self.lock().user.ok_or(EnrollmentError::InvalidStep)?;

        match self.authn.totp_verify(user_id, code).await {
            Ok(true) => {}
            // A well-formed but wrong code: the operator mistyped, or is not the holder.
            Ok(false) => return Err(EnrollmentError::CodeRejected),
            Err(AuthError::TotpReplay) => return Err(EnrollmentError::CodeReplayed),
            Err(other) => return Err(internal(other)),
        }

        let credential = EnrolledCredential {
            username: ADMIN_USERNAME.to_string(),
            method: "totp",
        };
        let mut state = self.lock();
        state.enrolled = Some(credential.clone());
        Ok(EnrollmentOutcome::Enrolled(credential))
    }
}

/// A random password for the admin account.
///
/// The TOTP secret is the credential being enrolled; the password exists only because
/// `AuthnService::create_user` requires one, and it is never shown or persisted. It is still drawn
/// from the OS generator rather than being a constant, so a future persistence task cannot
/// accidentally ship a predictable password.
fn random_password() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Map an authn error to a refusal, keeping the message but never a secret.
fn internal(error: AuthError) -> EnrollmentError {
    EnrollmentError::Internal(error.to_string())
}

/// Whether `code` is exactly [`TOTP_CODE_DIGITS`] ASCII decimal digits.
pub fn is_well_formed_code(code: &str) -> bool {
    code.len() == TOTP_CODE_DIGITS && code.bytes().all(|b| b.is_ascii_digit())
}

/// The single value of `key` in a query string, or `None` when absent or repeated.
///
/// A repeated parameter is treated as absent rather than first-wins: for a credential check,
/// ambiguity is a reason to refuse, not a tie to break.
fn single_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    let mut found: Option<&str> = None;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name == key {
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

/// Build an [`Arc`]-shared enrollment service for the activation handler.
pub fn shared(auth_method: &str) -> Arc<EnrollmentService> {
    Arc::new(EnrollmentService::new(auth_method))
}

/// Extract the activation token from a query string (used by the endpoint wiring).
pub fn token_from_query(query: &str) -> Option<&str> {
    single_param(query, TOKEN_PARAM)
}

/// Extract the raw `token=` value even when repeated, for the endpoint's malformed-token check.
pub fn first_token_from_query(query: &str) -> Option<&str> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        (name == TOKEN_PARAM).then_some(value)
    })
}
