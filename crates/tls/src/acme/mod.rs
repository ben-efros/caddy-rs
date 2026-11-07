//! ACME (RFC 8555) directory and account foundation.
//!
//! This module covers the parts of ACME account management that do not need a live TLS stack:
//!
//! * the directory document model (`newNonce`, `newAccount`, `newOrder`, `revokeCert`, `meta`);
//! * ECDSA P-256 account keys: generation, PKCS#8 PEM load/save, public JWK and RFC 7638
//!   thumbprint;
//! * flattened JWS (ES256) signing, including external account binding (HS256);
//! * account registration request/response types, status and problem-document handling;
//! * a small client whose HTTP transport is the [`AcmeTransport`] trait, so tests drive it with a
//!   scripted mock and production code plugs in a real HTTP implementation.
//!
//! The wire client for orders, authorizations, challenges and certificate download is the next
//! task (T-TLS-041); it builds on [`AcmeClient`] and [`AccountKey`]. Account key material and the
//! registered account record are persisted through [`AcmeStorage`], with `FileStorage` and
//! `MemoryAcmeStorage` implementations available out of the box.
//!
//! Deliberate limitations (reported as divergences from Caddy v2.11.7):
//!
//! * only ECDSA P-256 / ES256 account keys are supported (Caddy/certmagic also accepts RSA and
//!   other curves when `account_key` PEM is configured);
//! * only PKCS#8 (`PRIVATE KEY`) PEM account keys are loaded; SEC1 `EC PRIVATE KEY` and PKCS#1
//!   `RSA PRIVATE KEY` blocks are rejected with a located error;
//! * ZeroSSL's automatic EAB credential provisioning is not implemented.

pub mod adaptive_challenge;
pub mod ari;
pub mod csr;
pub mod order;
pub mod transport;

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rustls::pki_types::CertificateDer;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::sync::Mutex;

use crate::acme::ari::RenewalInfo;
use crate::storage::FileStorage;
use crate::{Error, Result};

use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
};

/// IANA-registered ACME error namespace prefix.
pub const ACME_ERROR_PREFIX: &str = "urn:ietf:params:acme:error:";

/// Error type reported for an ACME `userActionRequired` problem document.
pub const USER_ACTION_REQUIRED: &str = "urn:ietf:params:acme:error:userActionRequired";

/// Errors raised while discovering a directory, managing an account key, or registering an
/// account.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// The directory document could not be decoded.
    #[error("invalid ACME directory `{url}`: {reason}")]
    InvalidDirectory {
        /// Directory URL that was fetched.
        url: String,
        /// Decoding failure.
        reason: String,
    },

    /// The directory document is missing an endpoint required by RFC 8555.
    #[error("ACME directory `{url}` is missing required endpoint `{field}`")]
    MissingDirectoryField {
        /// Directory URL that was fetched.
        url: String,
        /// Missing JSON field.
        field: &'static str,
    },

    /// The HTTP transport failed below the ACME layer.
    #[error("ACME transport request to `{url}` failed: {reason}")]
    Transport {
        /// Request URL.
        url: String,
        /// Transport failure description.
        reason: String,
    },

    /// The server returned an error without an ACME problem document.
    #[error("ACME server returned HTTP {status} for `{url}`: {detail}")]
    UnexpectedStatus {
        /// Request URL.
        url: String,
        /// HTTP status.
        status: u16,
        /// Short body excerpt.
        detail: String,
    },

    /// The server returned an RFC 7807 / RFC 8555 problem document.
    #[error("ACME problem for `{url}` (HTTP {status}) {problem_type}: {detail}")]
    Problem {
        /// Request URL.
        url: String,
        /// HTTP status.
        status: u16,
        /// Problem type URI.
        problem_type: String,
        /// Human-readable detail (`"no detail"` when absent).
        detail: String,
        /// Full problem document.
        problem: Problem,
    },

    /// The CA requires the terms of service to be accepted before an account is created.
    #[error("ACME account registration requires accepting the terms of service at `{url}`")]
    TermsOfServiceRequired {
        /// Terms-of-service URL advertised by the directory `meta` section.
        url: String,
    },

    /// Account key generation, parsing, or signing failed.
    #[error("ACME account key error: {0}")]
    AccountKey(String),

    /// A response required by the protocol is missing a header.
    #[error("ACME response for `{url}` is missing required header `{header}`")]
    MissingHeader {
        /// Request URL.
        url: String,
        /// Missing header name.
        header: &'static str,
    },

    /// A response body could not be decoded or encoded.
    #[error("ACME data for `{url}` is invalid: {reason}")]
    Decode {
        /// URL the data belongs to.
        url: String,
        /// Decoding failure.
        reason: String,
    },

    /// JWS signing failed.
    #[error("ACME JWS signing failed: {0}")]
    Signing(String),

    /// ACME Renewal Information (ARI) fetching or parsing failed.
    #[error("ACME renewal information: {reason}")]
    Ari {
        /// Failure description.
        reason: String,
    },

    /// External account binding credentials are malformed.
    #[error("ACME external account binding error: {0}")]
    ExternalAccount(String),

    /// An ACME order reached the `invalid` state.
    #[error("ACME order `{url}` is invalid: {detail}")]
    InvalidOrder {
        /// Order URL.
        url: String,
        /// Human-readable detail (from the order error object).
        detail: String,
        /// Order error problem document, when the CA provided one.
        problem: Option<Problem>,
    },

    /// An ACME authorization reached the `invalid` state.
    #[error("ACME authorization `{url}` is invalid: {detail}")]
    InvalidAuthorization {
        /// Authorization URL.
        url: String,
        /// Human-readable detail (from the failed challenge).
        detail: String,
        /// Authorization/challenge problem document, when the CA provided one.
        problem: Option<Problem>,
    },

    /// An ACME challenge failed.
    #[error("ACME challenge `{url}` ({challenge_type}) failed: {detail}")]
    InvalidChallenge {
        /// Challenge URL.
        url: String,
        /// Challenge type (`http-01`, `tls-alpn-01`, `dns-01`).
        challenge_type: String,
        /// Human-readable detail.
        detail: String,
        /// Challenge problem document, when the CA provided one.
        problem: Option<Problem>,
    },

    /// An ACME order was in a state the flow did not expect.
    #[error("ACME order `{url}` is `{status}`, expected {expected}")]
    UnexpectedOrderStatus {
        /// Order URL.
        url: String,
        /// Observed status.
        status: String,
        /// Expected status or statuses.
        expected: String,
    },

    /// An ACME authorization was in a state the flow did not expect.
    #[error("ACME authorization `{url}` is `{status}`, expected valid")]
    UnexpectedAuthorizationStatus {
        /// Authorization URL.
        url: String,
        /// Observed status.
        status: String,
    },

    /// Polling an ACME resource exceeded the policy's attempt budget.
    #[error("gave up polling `{url}` after {attempts} attempts")]
    PollingTimeout {
        /// Polled URL.
        url: String,
        /// Attempts made.
        attempts: u32,
    },

    /// No challenge offered by the authorization is enabled in the policy.
    #[error("authorization for `{identifier}` offers no enabled challenge (offered: {offered:?})")]
    NoSupportedChallenge {
        /// Identifier the authorization is for.
        identifier: String,
        /// Challenge types offered by the CA.
        offered: Vec<String>,
    },

    /// Certificate signing request generation failed.
    #[error("ACME certificate request error: {0}")]
    CertificateRequest(String),

    /// An order is not in a state that has a certificate URL.
    #[error("ACME order `{url}` has no certificate URL (status `{status}`)")]
    MissingCertificateUrl {
        /// Order URL.
        url: String,
        /// Observed order status.
        status: String,
    },

    /// The account record and the client belong to different directory URLs.
    #[error(
        "ACME account `{account_directory_url}` does not belong to directory `{directory_url}`"
    )]
    MismatchedAccountDirectory {
        /// Directory URL recorded in the account.
        account_directory_url: String,
        /// Directory URL of the client.
        directory_url: String,
    },
    /// Invalid challenge order format (e.g., "dns-01", "http-01", "tls-alpn-01").
    #[error("Invalid challenge order: {order}")]
    InvalidChallengeOrder {
        /// The invalid order string.
        order: String,
    },

    /// Challenge selection failed in the adaptive order machinery (e.g. a randomness failure).
    #[error("ACME challenge selection failed: {reason}")]
    ChallengeSelection {
        /// Failure description.
        reason: String,
    },
}

impl AcmeError {
    /// The ACME problem document carried by this error, if any.
    pub fn problem(&self) -> Option<&Problem> {
        match self {
            Self::Problem { problem, .. } => Some(problem),
            _ => None,
        }
    }

    /// The problem type URI, if this error carries a problem document.
    pub fn problem_type(&self) -> Option<&str> {
        self.problem().map(|problem| problem.problem_type.as_str())
    }

    /// Whether the CA asked for operator action (for example a changed terms-of-service
    /// agreement or account deactivation).
    pub fn is_user_action_required(&self) -> bool {
        self.problem_type() == Some(USER_ACTION_REQUIRED)
    }

    fn from_problem(url: &str, status: u16, problem: Problem) -> Self {
        Self::Problem {
            url: url.to_string(),
            status,
            problem_type: problem.problem_type.clone(),
            detail: problem
                .detail
                .clone()
                .unwrap_or_else(|| "no detail".to_string()),
            problem,
        }
    }
}

/// HTTP method used by a transport request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `DELETE`
    Delete,
    /// `PUT` (S3-compatible storage; T-TLS-022)
    Put,
}

impl HttpMethod {
    /// Uppercase wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Delete => "DELETE",
            Self::Put => "PUT",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A transport-neutral HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: HttpMethod,
    /// Absolute URL.
    pub url: String,
    /// Header name/value pairs (names keep their configured casing).
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// A bare `GET` request.
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A bare `HEAD` request.
    pub fn head(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Head,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A bare `DELETE` request.
    pub fn delete(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Delete,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A `POST` request with a flattened JWS body (`application/jose+json`).
    pub fn post_jose(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: vec![("Content-Type".to_string(), JOSE_CONTENT_TYPE.to_string())],
            body: body.into(),
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Look up a header by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Content type mandated by RFC 8555 for JWS request bodies.
pub const JOSE_CONTENT_TYPE: &str = "application/jose+json";

/// Content type of an ACME problem document.
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// A transport-neutral HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Header name/value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// An empty response with `status`.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the body.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// A JSON response body with `Content-Type: application/json`.
    pub fn with_json(status: u16, value: &serde_json::Value) -> Result<Self> {
        let body = serde_json::to_vec(value).map_err(|error| AcmeError::Decode {
            url: "response".to_string(),
            reason: error.to_string(),
        })?;
        Ok(Self::new(status)
            .with_header("Content-Type", "application/json")
            .with_body(body))
    }

    /// A problem-document response body (`application/problem+json`).
    pub fn with_problem(status: u16, value: &serde_json::Value) -> Result<Self> {
        let body = serde_json::to_vec(value).map_err(|error| AcmeError::Decode {
            url: "response".to_string(),
            reason: error.to_string(),
        })?;
        Ok(Self::new(status)
            .with_header("Content-Type", PROBLEM_CONTENT_TYPE)
            .with_body(body))
    }

    /// Whether the status is in the 2xx range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Look up a header by case-insensitive name (the last configured value wins).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The `Replay-Nonce` header, when present.
    pub fn replay_nonce(&self) -> Option<&str> {
        self.header("Replay-Nonce")
    }

    /// The `Location` header, when present.
    pub fn location(&self) -> Option<&str> {
        self.header("Location")
    }

    /// The response body decoded as UTF-8 (lossily) for diagnostics.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Decode the body as JSON, citing `url` on failure.
    pub fn json<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|error| {
            AcmeError::Decode {
                url: url.to_string(),
                reason: error.to_string(),
            }
            .into()
        })
    }

    /// Parse the body as an ACME problem document when it is one.
    pub fn problem(&self) -> Option<Problem> {
        let is_problem = self
            .header("Content-Type")
            .map(|content_type| content_type.starts_with(PROBLEM_CONTENT_TYPE))
            .unwrap_or(false);
        if !is_problem && self.status < 400 {
            return None;
        }
        let problem: Problem = serde_json::from_slice(&self.body).ok()?;
        if problem.problem_type.starts_with(ACME_ERROR_PREFIX) {
            Some(problem)
        } else {
            None
        }
    }
}

/// Convert an error response into a located [`AcmeError`].
fn response_error(url: &str, response: &HttpResponse) -> Error {
    match response.problem() {
        Some(problem) => AcmeError::from_problem(url, response.status, problem).into(),
        None => {
            let mut detail = response.body_text();
            detail.truncate(500);
            AcmeError::UnexpectedStatus {
                url: url.to_string(),
                status: response.status,
                detail,
            }
            .into()
        }
    }
}

/// The ACME directory document (RFC 8555 §7.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    /// `newNonce` endpoint.
    #[serde(default)]
    pub new_nonce: String,
    /// `newAccount` endpoint.
    #[serde(default)]
    pub new_account: String,
    /// `newOrder` endpoint.
    #[serde(default)]
    pub new_order: String,
    /// `revokeCert` endpoint.
    #[serde(default)]
    pub revoke_cert: String,
    /// Optional `keyChange` endpoint.
    #[serde(default)]
    pub key_change: Option<String>,
    /// Optional `renewalInfo` (ARI) endpoint.
    #[serde(default)]
    pub renewal_info: Option<String>,
    /// Optional directory metadata.
    #[serde(default)]
    pub meta: Option<DirectoryMeta>,
}

/// Optional directory metadata (RFC 8555 §7.1.1 and the ARI/profile extensions).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    /// Terms-of-service URL.
    #[serde(default)]
    pub terms_of_service: Option<String>,
    /// CA website URL.
    #[serde(default)]
    pub website: Option<String>,
    /// CAA identities the CA recognises.
    #[serde(default)]
    pub caa_identities: Option<Vec<String>>,
    /// Whether external account binding is mandatory.
    #[serde(default)]
    pub external_account_required: Option<bool>,
    /// Optional ACME profile descriptions keyed by profile name.
    #[serde(default)]
    pub profiles: Option<BTreeMap<String, String>>,
}

impl Directory {
    /// Parse and validate a directory document fetched from `url`.
    pub fn parse(url: &str, body: &[u8]) -> Result<Self> {
        let directory: Self =
            serde_json::from_slice(body).map_err(|error| AcmeError::InvalidDirectory {
                url: url.to_string(),
                reason: error.to_string(),
            })?;
        directory.validate(url)?;
        Ok(directory)
    }

    /// Validate that the endpoints RFC 8555 requires are present.
    pub fn validate(&self, url: &str) -> Result<()> {
        let required: [(&'static str, &str); 4] = [
            ("newNonce", &self.new_nonce),
            ("newAccount", &self.new_account),
            ("newOrder", &self.new_order),
            ("revokeCert", &self.revoke_cert),
        ];
        for (field, value) in required {
            if value.trim().is_empty() {
                return Err(AcmeError::MissingDirectoryField {
                    url: url.to_string(),
                    field,
                }
                .into());
            }
        }
        Ok(())
    }

    /// Terms-of-service URL, if the CA advertises one.
    pub fn terms_of_service(&self) -> Option<&str> {
        self.meta
            .as_ref()
            .and_then(|meta| meta.terms_of_service.as_deref())
    }

    /// Whether the CA requires external account binding.
    pub fn external_account_required(&self) -> bool {
        self.meta
            .as_ref()
            .and_then(|meta| meta.external_account_required)
            .unwrap_or(false)
    }
}

/// An RFC 7807 problem document as returned by an ACME server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// Problem type URI (for example `urn:ietf:params:acme:error:accountDoesNotExist`).
    #[serde(rename = "type")]
    pub problem_type: String,
    /// Human-readable detail.
    #[serde(default)]
    pub detail: Option<String>,
    /// HTTP status suggested by the CA.
    #[serde(default)]
    pub status: Option<u16>,
    /// Sub-problems (order authorization failures and similar).
    #[serde(default)]
    pub subproblems: Vec<Subproblem>,
    /// Identifier the problem refers to, when provided.
    #[serde(default)]
    pub identifier: Option<serde_json::Value>,
}

/// One entry of a problem document's `subproblems`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subproblem {
    /// Problem type URI.
    #[serde(rename = "type")]
    pub problem_type: String,
    /// Human-readable detail.
    #[serde(default)]
    pub detail: Option<String>,
    /// Identifier the sub-problem refers to.
    #[serde(default)]
    pub identifier: Option<serde_json::Value>,
}

impl Problem {
    /// The RFC 8555 error code (the part after `urn:ietf:params:acme:error:`), when the CA uses
    /// the standard namespace.
    pub fn error_code(&self) -> Option<&str> {
        self.problem_type.strip_prefix(ACME_ERROR_PREFIX)
    }

    /// Whether this problem has the given RFC 8555 error code.
    pub fn is(&self, code: &str) -> bool {
        self.error_code() == Some(code)
    }

    /// A human-readable diagnostic combining the CA detail, error code and sub-problems.
    ///
    /// Caddy/acmez surface the CA's `detail` (and sub-problem details for order failures); this
    /// helper produces a useful message even when the top-level problem has no detail.
    pub fn diagnostic(&self) -> String {
        let mut message = self
            .detail
            .clone()
            .or_else(|| self.error_code().map(str::to_string))
            .unwrap_or_else(|| self.problem_type.clone());
        for subproblem in &self.subproblems {
            let detail = subproblem
                .detail
                .clone()
                .or_else(|| subproblem.error_code().map(str::to_string));
            let identifier = subproblem
                .identifier
                .as_ref()
                .and_then(|identifier| identifier.get("value"))
                .and_then(serde_json::Value::as_str);
            match (detail, identifier) {
                (Some(detail), Some(identifier)) => {
                    message.push_str(&format!(" ({identifier}: {detail})"));
                }
                (Some(detail), None) => message.push_str(&format!(" ({detail})")),
                (None, Some(identifier)) => message.push_str(&format!(" ({identifier})")),
                (None, None) => {}
            }
        }
        message
    }
}

impl Subproblem {
    /// The RFC 8555 error code, when the CA uses the standard namespace.
    pub fn error_code(&self) -> Option<&str> {
        self.problem_type.strip_prefix(ACME_ERROR_PREFIX)
    }
}

/// A JSON Web Key for an ACME account (public key only).
///
/// EC keys use `crv`/`x`/`y`; RSA keys use `n`/`e`. The RFC 7638 canonical member order is
/// `crv,kty,x,y` for EC and `e,kty,n` for RSA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type: `EC` or `RSA`.
    pub kty: String,
    /// EC curve (`P-256` or `P-384`), absent for RSA keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// Base64url-encoded EC X coordinate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Base64url-encoded EC Y coordinate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// Base64url-encoded RSA modulus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// Base64url-encoded RSA public exponent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl Jwk {
    /// Build the JWK for an uncompressed P-256 public key (`0x04 || X || Y`).
    pub fn for_p256(public_key: &[u8]) -> Result<Self> {
        Self::for_ec("P-256", public_key, 32)
    }

    /// Build the JWK for an uncompressed P-384 public key (`0x04 || X || Y`).
    pub fn for_p384(public_key: &[u8]) -> Result<Self> {
        Self::for_ec("P-384", public_key, 48)
    }

    fn for_ec(curve: &str, public_key: &[u8], coordinate_len: usize) -> Result<Self> {
        let expected = 1 + coordinate_len * 2;
        if public_key.len() != expected || public_key[0] != 0x04 {
            return Err(AcmeError::AccountKey(format!(
                "{curve} public key must be {expected} bytes in uncompressed form, got {} bytes",
                public_key.len()
            ))
            .into());
        }
        Ok(Self {
            kty: "EC".to_string(),
            crv: Some(curve.to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&public_key[1..1 + coordinate_len])),
            y: Some(URL_SAFE_NO_PAD.encode(&public_key[1 + coordinate_len..])),
            n: None,
            e: None,
        })
    }

    /// Build the JWK for an RSA public key.
    pub fn for_rsa(public_key: &rsa::RsaPublicKey) -> Result<Self> {
        use rsa::traits::PublicKeyParts;
        Ok(Self {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some(URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be())),
            e: Some(URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())),
        })
    }

    /// The RFC 7638 SHA-256 thumbprint, base64url encoded.
    ///
    /// The canonical form is the required members in lexicographic order with no whitespace:
    /// `{"crv":...,"kty":"EC","x":...,"y":...}` or `{"e":...,"kty":"RSA","n":...}`.
    pub fn thumbprint(&self) -> Result<String> {
        let canonical = match self.kty.as_str() {
            "EC" => format!(
                "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
                self.crv.as_deref().unwrap_or_default(),
                self.kty,
                self.x.as_deref().unwrap_or_default(),
                self.y.as_deref().unwrap_or_default()
            ),
            "RSA" => format!(
                "{{\"e\":\"{}\",\"kty\":\"{}\",\"n\":\"{}\"}}",
                self.e.as_deref().unwrap_or_default(),
                self.kty,
                self.n.as_deref().unwrap_or_default()
            ),
            other => {
                return Err(
                    AcmeError::AccountKey(format!("unsupported JWK key type `{other}`")).into(),
                )
            }
        };
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(digest.as_ref()))
    }

    /// Canonical JSON encoding used for signatures and external account binding payloads.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| {
            AcmeError::Decode {
                url: "jwk".to_string(),
                reason: error.to_string(),
            }
            .into()
        })
    }
}

/// Account private-key algorithm/type supported by Caddy's certmagic.
///
/// Certmagic generates ECDSA P-256 keys by default but loads any ECDSA or RSA private key
/// supplied through `account_key`, selecting the JWS algorithm from the key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKeyType {
    /// ECDSA P-256 / ES256 (certmagic's generated default).
    P256,
    /// ECDSA P-384 / ES384.
    P384,
    /// RSA 2048-bit / RS256.
    Rsa2048,
    /// RSA 4096-bit / RS256.
    Rsa4096,
}

impl AccountKeyType {
    /// Parse a certmagic-style key type name (`p256`, `p384`, `rsa2048`, `rsa4096`).
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "p256" => Ok(Self::P256),
            "p384" => Ok(Self::P384),
            "rsa2048" => Ok(Self::Rsa2048),
            "rsa4096" => Ok(Self::Rsa4096),
            other => Err(AcmeError::AccountKey(format!(
                "unsupported account key type `{other}`; expected p256, p384, rsa2048 or rsa4096"
            ))
            .into()),
        }
    }

    /// Certmagic spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::P256 => "p256",
            Self::P384 => "p384",
            Self::Rsa2048 => "rsa2048",
            Self::Rsa4096 => "rsa4096",
        }
    }

    /// JWS signing algorithm used for this key type.
    pub fn jws_algorithm(self) -> &'static str {
        match self {
            Self::P256 => "ES256",
            Self::P384 => "ES384",
            Self::Rsa2048 | Self::Rsa4096 => "RS256",
        }
    }

    fn rsa_bits(self) -> Option<usize> {
        match self {
            Self::Rsa2048 => Some(2048),
            Self::Rsa4096 => Some(4096),
            Self::P256 | Self::P384 => None,
        }
    }
}

const PEM_LABEL: &str = "PRIVATE KEY";
const PEM_LABEL_EC: &str = "EC PRIVATE KEY";
const PEM_LABEL_RSA: &str = "RSA PRIVATE KEY";

/// Encode DER bytes as a PEM block.
fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::with_capacity(encoded.len() + encoded.len() / 64 + 64);
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    pem
}

/// Decode the first PEM block from `pem`, returning its label and DER bytes.
fn pem_decode(pem: &str) -> Result<(String, Vec<u8>)> {
    let mut label: Option<String> = None;
    let mut body = String::new();
    let mut done = false;
    for line in pem.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let Some(begin_label) = rest.strip_suffix("-----") else {
                continue;
            };
            label = Some(begin_label.to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("-----END ") {
            let Some(end_label) = rest.strip_suffix("-----") else {
                continue;
            };
            match label.as_deref() {
                Some(begin_label) if begin_label == end_label => {
                    done = true;
                    break;
                }
                Some(begin_label) => {
                    return Err(AcmeError::AccountKey(format!(
                        "PEM block has mismatched labels `{begin_label}` and `{end_label}`"
                    ))
                    .into())
                }
                None => continue,
            }
        }
        if label.is_some() {
            body.extend(line.chars().filter(|character| !character.is_whitespace()));
        }
    }
    let Some(label) = label else {
        return Err(AcmeError::AccountKey("no PEM block found in account key".to_string()).into());
    };
    if !done {
        return Err(
            AcmeError::AccountKey(format!("PEM block `{label}` has no matching END line")).into(),
        );
    }
    let der = STANDARD.decode(body.as_bytes()).map_err(|error| {
        AcmeError::AccountKey(format!("PEM block `{label}` is not valid base64: {error}"))
    })?;
    Ok((label, der))
}

// ---- minimal DER helpers for EC SEC1 <-> PKCS#8 conversion ---------------------------------

const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_SECP384R1: &[u64] = &[1, 3, 132, 0, 34];
const OID_ED25519: &[u64] = &[1, 3, 101, 112];

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut bytes = length.to_be_bytes().to_vec();
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    let mut encoded = Vec::with_capacity(bytes.len() + 1);
    encoded.push(0x80 | bytes.len() as u8);
    encoded.extend(bytes);
    encoded
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(content.len() + 4);
    encoded.push(tag);
    encoded.extend(der_length(content.len()));
    encoded.extend_from_slice(content);
    encoded
}

fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    der_tlv(0x30, &items.concat())
}

fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    if arcs.len() >= 2 {
        content.push((arcs[0] * 40 + arcs[1]) as u8);
        for arc in &arcs[2..] {
            let mut value = *arc;
            let mut stack = vec![(value & 0x7f) as u8];
            value >>= 7;
            while value > 0 {
                stack.push(((value & 0x7f) as u8) | 0x80);
                value >>= 7;
            }
            stack.reverse();
            content.extend(stack);
        }
    }
    der_tlv(0x06, &content)
}

fn der_integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = bytes[first..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    der_tlv(0x02, &content)
}

fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tlv(0x04, content)
}

fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(content.len() + 1);
    inner.push(0); // no unused bits
    inner.extend_from_slice(content);
    der_tlv(0x03, &inner)
}

/// One DER TLV: `(tag, content, total_encoded_len)`.
fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], usize)> {
    let tag = *input
        .first()
        .ok_or_else(|| AcmeError::AccountKey("truncated DER key".to_string()))?;
    let first = *input
        .get(1)
        .ok_or_else(|| AcmeError::AccountKey("truncated DER key length".to_string()))?;
    let (length, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || input.len() < 2 + count {
            return Err(AcmeError::AccountKey("invalid DER key length".to_string()).into());
        }
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    if input.len() < header + length {
        return Err(AcmeError::AccountKey("truncated DER key content".to_string()).into());
    }
    Ok((tag, &input[header..header + length], header + length))
}

fn ec_curve_oid_from_der(der: &[u8]) -> Result<Option<&'static [u64]>> {
    let (tag, body, _) = read_tlv(der)?;
    if tag != 0x30 {
        return Ok(None);
    }
    let mut offset = 0;
    while offset < body.len() {
        let (tag, content, consumed) = read_tlv(&body[offset..])?;
        offset += consumed;
        if tag == 0x30 {
            // AlgorithmIdentifier SEQUENCE { OID, params }.
            let (oid_tag, oid, _) = read_tlv(content)?;
            if oid_tag == 0x06 && oid == &der_oid(OID_EC_PUBLIC_KEY)[2..] {
                let (param_tag, params, _) = read_tlv(&content[oid.len() + 2..])?;
                if param_tag == 0x06 {
                    let prime256v1 = der_oid(OID_PRIME256V1);
                    let secp384r1 = der_oid(OID_SECP384R1);
                    if params == &prime256v1[2..] {
                        return Ok(Some(OID_PRIME256V1));
                    } else if params == &secp384r1[2..] {
                        return Ok(Some(OID_SECP384R1));
                    }
                }
            }
        }
    }
    Ok(None)
}

/// Convert a SEC1 `ECPrivateKey` DER into PKCS#8 `PrivateKeyInfo` DER.
fn ec_sec1_to_pkcs8(sec1: &[u8], curve_oid: &[u64]) -> Vec<u8> {
    der_sequence(&[
        der_integer(0),
        der_sequence(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(curve_oid)]),
        der_octet_string(sec1),
    ])
}

/// Encode a certmagic/Go-compatible SEC1 `ECPrivateKey` DER from a PKCS#8 key.
///
/// Go's `x509.MarshalECPrivateKey` writes the named-curve parameters and the public key in
/// addition to the scalar; `certmagic.PEMEncodePrivateKey` stores that SEC1 encoding. The inner
/// SEC1 embedded by ring may omit the parameters, so rebuild the structure explicitly.
fn ec_pkcs8_to_sec1(pkcs8: &[u8], curve_oid: &[u64], public_key: &[u8]) -> Result<Vec<u8>> {
    let (tag, body, _) = read_tlv(pkcs8)?;
    if tag != 0x30 {
        return Err(AcmeError::AccountKey("EC PKCS#8 key is not a SEQUENCE".to_string()).into());
    }
    let mut offset = 0;
    // version
    let (_, _, consumed) = read_tlv(body)?;
    offset += consumed;
    // algorithm identifier
    let (_, _, consumed) = read_tlv(&body[offset..])?;
    offset += consumed;
    // privateKey OCTET STRING containing the SEC1 ECPrivateKey
    let (tag, inner, _) = read_tlv(&body[offset..])?;
    if tag != 0x04 {
        return Err(AcmeError::AccountKey(
            "EC PKCS#8 private key is not an OCTET STRING".to_string(),
        )
        .into());
    }
    let (inner_tag, inner_body, _) = read_tlv(inner)?;
    if inner_tag != 0x30 {
        return Err(AcmeError::AccountKey("ECPrivateKey is not a SEQUENCE".to_string()).into());
    }
    let mut inner_offset = 0;
    let (_, _, consumed) = read_tlv(inner_body)?; // INTEGER 1
    inner_offset += consumed;
    let (scalar_tag, scalar, _) = read_tlv(&inner_body[inner_offset..])?;
    if scalar_tag != 0x04 {
        return Err(AcmeError::AccountKey(
            "ECPrivateKey has no private key OCTET STRING".to_string(),
        )
        .into());
    }
    Ok(der_sequence(&[
        der_integer(1),
        der_octet_string(scalar),
        der_tlv(0xA0, &der_oid(curve_oid)),
        der_tlv(0xA1, &der_bit_string(public_key)),
    ]))
}

fn ec_curve_oid_from_sec1(sec1: &[u8]) -> Result<&'static [u64]> {
    let (tag, body, _) = read_tlv(sec1)?;
    if tag != 0x30 {
        return Err(AcmeError::AccountKey("EC PRIVATE KEY is not a SEQUENCE".to_string()).into());
    }
    let mut offset = 0;
    let (_, _, consumed) = read_tlv(body)?; // version
    offset += consumed;
    let (tag, private_key, _) = read_tlv(&body[offset..])?;
    if tag != 0x04 {
        return Err(AcmeError::AccountKey(
            "EC PRIVATE KEY has no private key OCTET STRING".to_string(),
        )
        .into());
    }
    // Fall back to the scalar length when parameters are absent.
    match private_key.len() {
        32 => Ok(OID_PRIME256V1),
        48 => Ok(OID_SECP384R1),
        other => Err(AcmeError::AccountKey(format!(
            "unsupported EC private key length {other}; expected P-256 or P-384"
        ))
        .into()),
    }
}

/// An ACME account key.
///
/// Certmagic generates an ECDSA P-256 key by default, but its `account_key` configuration can
/// load ECDSA P-256/P-384 and RSA 2048/4096 keys; the JWS `alg` follows the key type (ES256,
/// ES384 or RS256). Private keys are persisted using certmagic's PEM encodings: SEC1
/// `EC PRIVATE KEY` for ECDSA and PKCS#1 `RSA PRIVATE KEY` for RSA.
pub struct AccountKey {
    key_type: AccountKeyType,
    pem: String,
    public_key: Vec<u8>,
    material: AccountKeyMaterial,
}

enum AccountKeyMaterial {
    EcdsaP256(EcdsaKeyPair),
    EcdsaP384(EcdsaKeyPair),
    Rsa(rsa::RsaPrivateKey),
}

impl fmt::Debug for AccountKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountKey")
            .field("algorithm", &self.jws_algorithm())
            .field("key_type", &self.key_type.as_str())
            .field("public_key", &URL_SAFE_NO_PAD.encode(&self.public_key))
            .finish_non_exhaustive()
    }
}

impl AccountKey {
    /// Generate a fresh ECDSA P-256 account key (certmagic's default).
    pub fn generate() -> Result<Self> {
        Self::generate_with_key_type(AccountKeyType::P256)
    }

    /// Generate a fresh account key of the given type.
    pub fn generate_with_key_type(key_type: AccountKeyType) -> Result<Self> {
        let rng = SystemRandom::new();
        match key_type {
            AccountKeyType::P256 => {
                let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map_err(|error| {
                        AcmeError::AccountKey(format!("generating P-256 key: {error}"))
                    })?;
                Self::from_ec_pkcs8(&document.as_ref().to_vec(), AccountKeyType::P256)
            }
            AccountKeyType::P384 => {
                let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
                    .map_err(|error| {
                        AcmeError::AccountKey(format!("generating P-384 key: {error}"))
                    })?;
                Self::from_ec_pkcs8(&document.as_ref().to_vec(), AccountKeyType::P384)
            }
            AccountKeyType::Rsa2048 | AccountKeyType::Rsa4096 => {
                let bits = key_type.rsa_bits().unwrap_or(2048);
                let private_key =
                    rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, bits).map_err(|error| {
                        AcmeError::AccountKey(format!("generating RSA-{bits} key: {error}"))
                    })?;
                Self::from_rsa(private_key)
            }
        }
    }

    fn from_ec_pkcs8(der: &[u8], key_type: AccountKeyType) -> Result<Self> {
        let rng = SystemRandom::new();
        let key_pair = match key_type {
            AccountKeyType::P256 => {
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng).map_err(
                    |error| {
                        AcmeError::AccountKey(format!("invalid ECDSA P-256 account key: {error}"))
                    },
                )?
            }
            AccountKeyType::P384 => {
                EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, der, &rng).map_err(
                    |error| {
                        AcmeError::AccountKey(format!("invalid ECDSA P-384 account key: {error}"))
                    },
                )?
            }
            AccountKeyType::Rsa2048 | AccountKeyType::Rsa4096 => {
                return Err(AcmeError::AccountKey(
                    "internal error: non-EC key passed to EC loader".to_string(),
                )
                .into())
            }
        };
        let public_key = key_pair.public_key().as_ref().to_vec();
        let curve_oid = match key_type {
            AccountKeyType::P256 => OID_PRIME256V1,
            AccountKeyType::P384 => OID_SECP384R1,
            _ => unreachable!(),
        };
        let sec1 = ec_pkcs8_to_sec1(der, curve_oid, &public_key)?;
        let pem = pem_encode(PEM_LABEL_EC, &sec1);
        Ok(Self {
            key_type,
            pem,
            public_key,
            material: match key_type {
                AccountKeyType::P256 => AccountKeyMaterial::EcdsaP256(key_pair),
                AccountKeyType::P384 => AccountKeyMaterial::EcdsaP384(key_pair),
                _ => unreachable!(),
            },
        })
    }

    fn from_rsa(private_key: rsa::RsaPrivateKey) -> Result<Self> {
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
        use rsa::traits::PublicKeyParts;
        let bits = private_key.n().bits();
        let key_type = match bits {
            2048 => AccountKeyType::Rsa2048,
            4096 => AccountKeyType::Rsa4096,
            other => {
                return Err(AcmeError::AccountKey(format!(
                    "unsupported RSA account key size {other} bits; expected 2048 or 4096"
                ))
                .into())
            }
        };
        let public_key = private_key
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|error| AcmeError::AccountKey(format!("encoding RSA public key: {error}")))?;
        let pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map_err(|error| AcmeError::AccountKey(format!("encoding RSA key PEM: {error}")))?;
        Ok(Self {
            key_type,
            pem: pem.to_string(),
            public_key: public_key.as_bytes().to_vec(),
            material: AccountKeyMaterial::Rsa(private_key),
        })
    }

    /// Load an account key from a certmagic-compatible PEM: SEC1 `EC PRIVATE KEY`, PKCS#1
    /// `RSA PRIVATE KEY`, or PKCS#8 `PRIVATE KEY` containing either key type.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let (label, der) = pem_decode(pem)?;
        match label.as_str() {
            PEM_LABEL_EC => {
                let curve = ec_curve_oid_from_sec1(&der)?;
                let key_type = if curve == OID_PRIME256V1 {
                    AccountKeyType::P256
                } else {
                    AccountKeyType::P384
                };
                let pkcs8 = ec_sec1_to_pkcs8(&der, curve);
                Self::from_ec_pkcs8(&pkcs8, key_type)
            }
            PEM_LABEL_RSA => {
                use rsa::pkcs1::DecodeRsaPrivateKey;
                let private_key = rsa::RsaPrivateKey::from_pkcs1_der(&der).map_err(|error| {
                    AcmeError::AccountKey(format!("invalid PKCS#1 RSA account key: {error}"))
                })?;
                Self::from_rsa(private_key)
            }
            PEM_LABEL => {
                // PKCS#8 may contain EC or RSA; detect the algorithm OID.
                if let Some(curve) = ec_curve_oid_from_der(&der)? {
                    let key_type = if curve == OID_PRIME256V1 {
                        AccountKeyType::P256
                    } else {
                        AccountKeyType::P384
                    };
                    Self::from_ec_pkcs8(&der, key_type)
                } else if {
                    let ed25519_oid = der_oid(OID_ED25519);
                    der.windows(ed25519_oid.len())
                        .any(|window| window == ed25519_oid)
                } {
                    return Err(AcmeError::AccountKey(
                        "Ed25519 account keys are not supported; expected ECDSA P-256/P-384 or RSA 2048/4096"
                            .to_string(),
                    )
                    .into());
                } else {
                    use rsa::pkcs8::DecodePrivateKey;
                    let private_key =
                        rsa::RsaPrivateKey::from_pkcs8_der(&der).map_err(|error| {
                            AcmeError::AccountKey(format!(
                                "invalid PKCS#8 account key (neither EC nor RSA): {error}"
                            ))
                        })?;
                    Self::from_rsa(private_key)
                }
            }
            other => Err(AcmeError::AccountKey(format!(
                "unsupported account key PEM label `{other}`; expected EC PRIVATE KEY, \
                 RSA PRIVATE KEY or PRIVATE KEY"
            ))
            .into()),
        }
    }

    /// Backwards-compatible alias for [`Self::from_pem`].
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        Self::from_pem(pem)
    }

    /// The account key in certmagic's PEM form (SEC1 for EC, PKCS#1 for RSA).
    pub fn to_pem(&self) -> &str {
        &self.pem
    }

    /// Backwards-compatible alias for [`Self::to_pem`]; the returned PEM matches what
    /// certmagic writes (SEC1/PKCS#1), not necessarily PKCS#8.
    pub fn to_pkcs8_pem(&self) -> &str {
        &self.pem
    }

    /// The key type.
    pub fn key_type(&self) -> AccountKeyType {
        self.key_type
    }

    /// The JWS algorithm (`ES256`, `ES384`, `RS256`).
    pub fn jws_algorithm(&self) -> &'static str {
        self.key_type.jws_algorithm()
    }

    /// Raw public key bytes: uncompressed EC point for EC keys, PKCS#1 RSA public key for RSA.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// The public JWK for this account key.
    pub fn public_jwk(&self) -> Result<Jwk> {
        match &self.material {
            AccountKeyMaterial::EcdsaP256(_) => Jwk::for_p256(&self.public_key),
            AccountKeyMaterial::EcdsaP384(_) => Jwk::for_p384(&self.public_key),
            AccountKeyMaterial::Rsa(private_key) => Jwk::for_rsa(&private_key.to_public_key()),
        }
    }

    /// The RFC 7638 SHA-256 thumbprint, base64url encoded.
    pub fn thumbprint(&self) -> Result<String> {
        self.public_jwk()?.thumbprint()
    }

    /// Sign `message` with the key's JWS algorithm, returning the raw JWS signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match &self.material {
            AccountKeyMaterial::EcdsaP256(key_pair) => {
                let rng = SystemRandom::new();
                let signature = key_pair.sign(&rng, message).map_err(|error| {
                    AcmeError::Signing(format!("ES256 signing failed: {error}"))
                })?;
                let bytes = signature.as_ref();
                if bytes.len() != 64 {
                    return Err(AcmeError::Signing(format!(
                        "ES256 signature must be 64 bytes, got {}",
                        bytes.len()
                    ))
                    .into());
                }
                Ok(bytes.to_vec())
            }
            AccountKeyMaterial::EcdsaP384(key_pair) => {
                let rng = SystemRandom::new();
                let signature = key_pair.sign(&rng, message).map_err(|error| {
                    AcmeError::Signing(format!("ES384 signing failed: {error}"))
                })?;
                let bytes = signature.as_ref();
                if bytes.len() != 96 {
                    return Err(AcmeError::Signing(format!(
                        "ES384 signature must be 96 bytes, got {}",
                        bytes.len()
                    ))
                    .into());
                }
                Ok(bytes.to_vec())
            }
            AccountKeyMaterial::Rsa(private_key) => {
                use rsa::pkcs1v15::SigningKey;
                use rsa::signature::{SignatureEncoding, Signer};
                let signing_key = SigningKey::<sha2::Sha256>::new(private_key.clone());
                Ok(signing_key.sign(message).to_vec())
            }
        }
    }

    /// Sign `message` with ES256, returning the 64-byte `r || s` signature.
    ///
    /// Only valid for P-256 keys; other key types use [`Self::sign`].
    pub fn sign_es256(&self, message: &[u8]) -> Result<[u8; 64]> {
        let signature = self.sign(message)?;
        if signature.len() != 64 {
            return Err(AcmeError::Signing(format!(
                "ES256 signature must be 64 bytes, got {}",
                signature.len()
            ))
            .into());
        }
        let mut fixed = [0_u8; 64];
        fixed.copy_from_slice(&signature);
        Ok(fixed)
    }

    /// Verify an ES256 signature with this key's public half (used by tests and diagnostics).
    pub fn verify_es256(&self, message: &[u8], signature: &[u8]) -> bool {
        if self.key_type != AccountKeyType::P256 {
            return false;
        }
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.public_key)
            .verify(message, signature)
            .is_ok()
    }

    /// Verify a signature produced by [`Self::sign`] (used by tests and diagnostics).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match &self.material {
            AccountKeyMaterial::EcdsaP256(_) => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.public_key)
                    .verify(message, signature)
                    .is_ok()
            }
            AccountKeyMaterial::EcdsaP384(_) => {
                UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &self.public_key)
                    .verify(message, signature)
                    .is_ok()
            }
            AccountKeyMaterial::Rsa(private_key) => {
                use rsa::pkcs1v15::VerifyingKey;
                use rsa::signature::Verifier;
                let public_key = private_key.to_public_key();
                let verifying_key = VerifyingKey::<sha2::Sha256>::new(public_key);
                match rsa::pkcs1v15::Signature::try_from(signature) {
                    Ok(signature) => verifying_key.verify(message, &signature).is_ok(),
                    Err(_) => false,
                }
            }
        }
    }
}

#[derive(Serialize)]
struct JwsHeader<'a> {
    alg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    url: &'a str,
}

/// Sign an ACME request payload as a flattened JWS (RFC 7515 §7.2.2).
///
/// Exactly one of `kid` (existing account) or the account key's `jwk` (new account) is placed in
/// the protected header. The `alg` header follows the loaded account key type (ES256, ES384 or
/// RS256). Returns the JSON body to POST as `application/jose+json`.
pub fn sign_jws(
    key: &AccountKey,
    kid: Option<&str>,
    nonce: Option<&str>,
    url: &str,
    payload: &[u8],
) -> Result<String> {
    let header = JwsHeader {
        alg: key.jws_algorithm(),
        kid,
        jwk: if kid.is_none() {
            Some(key.public_jwk()?)
        } else {
            None
        },
        nonce,
        url,
    };
    let protected =
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header).map_err(|error| AcmeError::Decode {
                url: url.to_string(),
                reason: error.to_string(),
            })?,
        );
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected}.{encoded_payload}");
    let signature = key.sign(signing_input.as_bytes())?;
    let body = serde_json::json!({
        "protected": protected,
        "payload": encoded_payload,
        "signature": URL_SAFE_NO_PAD.encode(signature),
    });
    serde_json::to_string(&body).map_err(|error| {
        AcmeError::Decode {
            url: url.to_string(),
            reason: error.to_string(),
        }
        .into()
    })
}

/// Fetch ARI for `certificate_der` from the CA's advertised `renewalInfo` endpoint.
///
/// Returns `Ok(None)` when the directory does not advertise ARI or the CA answers 404/410; other
/// transport/HTTP/parse errors are returned so the scheduler can fall back to its local renewal
/// heuristic (certmagic logs and reuses the previous window).
pub async fn fetch_renewal_info<T: AcmeTransport + ?Sized>(
    transport: &T,
    directory_url: &str,
    certificate_der: &[u8],
) -> Result<Option<RenewalInfo>> {
    let response = transport.request(HttpRequest::get(directory_url)).await?;
    if !response.is_success() {
        return Err(response_error(directory_url, &response));
    }
    let directory = Directory::parse(directory_url, &response.body)?;
    let Some(renewal_info_url) = directory.renewal_info.clone() else {
        return Ok(None);
    };
    let cert_id = ari::unique_identifier(certificate_der)?;
    let url = format!("{}/{}", renewal_info_url.trim_end_matches('/'), cert_id);
    let response = transport.request(HttpRequest::get(&url)).await?;
    if response.status == 404 || response.status == 410 {
        return Ok(None);
    }
    if !response.is_success() {
        return Err(response_error(&url, &response));
    }
    let now = SystemTime::now();
    let retry_after = order::retry_after(&response);
    let info = RenewalInfo::parse(&cert_id, &response.body)?.with_retry_after(now, retry_after);
    Ok(Some(info))
}

/// External account binding credentials configured as `external_account` in Caddy's
/// `tls.issuance.acme` JSON (`{"key_id": "...", "mac_key": "..."}`).
///
/// Both certmagic's `key_id`/`mac_key` member names and the `kid`/`hmac_key` spelling used by some
/// ACME tooling are accepted when reading configuration; the certmagic spelling is emitted when
/// serialising.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAccount {
    /// CA-assigned key identifier (`key_id` in Caddy JSON, `kid` in the EAB JWS header).
    #[serde(rename = "key_id", alias = "kid")]
    pub kid: String,
    /// Base64url-encoded HMAC key (`mac_key` in Caddy JSON).
    #[serde(rename = "mac_key", alias = "hmac_key")]
    pub hmac_key: String,
}

impl ExternalAccount {
    /// Build the `externalAccountBinding` JWS (HS256) for a new-account request.
    pub fn binding(
        &self,
        account_key: &AccountKey,
        new_account_url: &str,
    ) -> Result<serde_json::Value> {
        #[derive(Serialize)]
        struct EabHeader<'a> {
            alg: &'a str,
            kid: &'a str,
            url: &'a str,
        }
        let protected = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&EabHeader {
                alg: "HS256",
                kid: &self.kid,
                url: new_account_url,
            })
            .map_err(|error| AcmeError::Decode {
                url: new_account_url.to_string(),
                reason: error.to_string(),
            })?,
        );
        let payload = URL_SAFE_NO_PAD.encode(account_key.public_jwk()?.to_canonical_json()?);
        let signing_input = format!("{protected}.{payload}");
        let mac_key = URL_SAFE_NO_PAD
            .decode(self.hmac_key.as_bytes())
            .map_err(|error| {
                AcmeError::ExternalAccount(format!("EAB hmac_key is not valid base64url: {error}"))
            })?;
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &mac_key);
        let tag = ring::hmac::sign(&hmac_key, signing_input.as_bytes());
        Ok(serde_json::json!({
            "protected": protected,
            "payload": payload,
            "signature": URL_SAFE_NO_PAD.encode(tag.as_ref()),
        }))
    }
}

/// Status of an ACME account (RFC 8555 §7.1.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Account is valid and can issue certificates.
    #[default]
    Valid,
    /// Account was deactivated by its owner.
    Deactivated,
    /// Account was revoked by the CA.
    Revoked,
    /// A status added by a future ACME extension; surfaced instead of failing the parse.
    #[serde(other)]
    Unknown,
}

/// An account object returned by the CA (RFC 8555 §7.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// Account status.
    #[serde(default)]
    pub status: AccountStatus,
    /// Contact URIs, normally `mailto:` addresses.
    #[serde(default)]
    pub contact: Vec<String>,
    /// Orders URL for this account.
    #[serde(default)]
    pub orders: Option<String>,
    /// Whether the terms of service were agreed to.
    #[serde(default)]
    pub terms_of_service_agreed: Option<bool>,
    /// External account binding echo, when the CA returns one.
    #[serde(default)]
    pub external_account_binding: Option<serde_json::Value>,
}

/// The new-account request payload (RFC 8555 §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequest {
    /// Contact URIs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<String>,
    /// Whether the caller agrees to the CA's terms of service.
    #[serde(default, skip_serializing_if = "is_false")]
    pub terms_of_service_agreed: bool,
    /// Look up an existing account instead of creating one.
    #[serde(default, skip_serializing_if = "is_false")]
    pub only_return_existing: bool,
    /// Signed external account binding JWS, when the CA requires EAB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<serde_json::Value>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Description of the account to register, before it is signed and sent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccountRegistration {
    /// Contact URIs.
    pub contact: Vec<String>,
    /// Whether the caller agrees to the CA's terms of service.
    pub terms_of_service_agreed: bool,
    /// Look up an existing account instead of creating one.
    pub only_return_existing: bool,
    /// Optional external account binding credentials.
    pub external_account: Option<ExternalAccount>,
}

impl AccountRegistration {
    /// A registration for `email` that agrees to the terms of service.
    pub fn for_email(email: impl AsRef<str>) -> Self {
        Self {
            contact: vec![format!("mailto:{}", email.as_ref())],
            terms_of_service_agreed: true,
            only_return_existing: false,
            external_account: None,
        }
    }

    /// Build the wire payload, signing the external account binding when configured.
    pub fn to_wire_request(
        &self,
        account_key: &AccountKey,
        new_account_url: &str,
    ) -> Result<NewAccountRequest> {
        let external_account_binding = match &self.external_account {
            Some(external_account) => Some(external_account.binding(account_key, new_account_url)?),
            None => None,
        };
        Ok(NewAccountRequest {
            contact: self.contact.clone(),
            terms_of_service_agreed: self.terms_of_service_agreed,
            only_return_existing: self.only_return_existing,
            external_account_binding,
        })
    }
}

/// The registered account record persisted through [`AcmeStorage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAccount {
    /// Directory URL the account belongs to.
    pub directory_url: String,
    /// Account URL from the `Location` header (used as `kid` for signed requests).
    pub account_url: String,
    /// Contact URIs.
    pub contact: Vec<String>,
    /// Account status at registration time.
    pub status: AccountStatus,
    /// Whether the terms of service were agreed to.
    pub terms_of_service_agreed: bool,
    /// RFC 7638 thumbprint of the account key.
    pub key_thumbprint: String,
}

/// Transport-neutral HTTP client used by [`AcmeClient`] and other HTTP-speaking clients in this
/// crate (for example the Cloudflare DNS provider).
///
/// Production code plugs in a real HTTP client (the workspace has hyper); tests use a scripted
/// mock. Keeping this at the HTTP-message level means protocol logic (JWS, nonces, problem
/// documents, DNS provider request/response mapping) is exercised without network access.
#[async_trait]
pub trait AcmeTransport: Send + Sync {
    /// Perform one HTTP request.
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse>;

    /// Return an equivalent transport that trusts exactly `roots` for HTTPS connections.
    ///
    /// This backs Caddy's `trusted_roots_pem_files` / `acme_ca_root` options. Configured roots
    /// **replace** the platform trust store, matching certmagic (which starts from an empty
    /// `x509.CertPool` and appends the configured files). Implementations that cannot
    /// reconfigure trust (for example scripted test transports) must return a located error
    /// instead of silently falling back to platform roots.
    fn with_trusted_roots(
        &self,
        _roots: Vec<CertificateDer<'static>>,
    ) -> Result<Arc<dyn AcmeTransport>> {
        Err(AcmeError::Transport {
            url: "https://".to_string(),
            reason: "this ACME transport does not support explicit trusted roots; use HyperTransport for a CA configured with trusted_roots_pem_files".to_string(),
        }
        .into())
    }
}

#[async_trait]
impl<T: AcmeTransport + ?Sized> AcmeTransport for &T {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
        (**self).request(request).await
    }

    fn with_trusted_roots(
        &self,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<Arc<dyn AcmeTransport>> {
        (**self).with_trusted_roots(roots)
    }
}

#[async_trait]
impl<T: AcmeTransport + ?Sized> AcmeTransport for Arc<T> {
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
        (**self).request(request).await
    }

    fn with_trusted_roots(
        &self,
        roots: Vec<CertificateDer<'static>>,
    ) -> Result<Arc<dyn AcmeTransport>> {
        (**self).with_trusted_roots(roots)
    }
}

/// An ACME client bound to one directory, one account key, and one transport.
pub struct AcmeClient<T: AcmeTransport> {
    transport: T,
    directory_url: String,
    directory: Directory,
    account_key: AccountKey,
    nonce: Mutex<Option<String>>,
}

impl<T: AcmeTransport> AcmeClient<T> {
    /// Fetch `directory_url` and create a client for `account_key`.
    pub async fn connect(
        transport: T,
        directory_url: impl Into<String>,
        account_key: AccountKey,
    ) -> Result<Self> {
        let directory_url = directory_url.into();
        let response = transport.request(HttpRequest::get(&directory_url)).await?;
        if !response.is_success() {
            return Err(response_error(&directory_url, &response));
        }
        let directory = Directory::parse(&directory_url, &response.body)?;
        let nonce = response.replay_nonce().map(str::to_string);
        Ok(Self {
            transport,
            directory_url,
            directory,
            account_key,
            nonce: Mutex::new(nonce),
        })
    }

    /// The discovered directory.
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// The directory URL this client was created for.
    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    /// The account key used for signing.
    pub fn account_key(&self) -> &AccountKey {
        &self.account_key
    }

    /// Remember the `Replay-Nonce` from a response for the next request.
    async fn record_nonce(&self, response: &HttpResponse) {
        if let Some(nonce) = response.replay_nonce() {
            *self.nonce.lock().await = Some(nonce.to_string());
        }
    }

    /// Take a cached nonce or fetch a fresh one from the `newNonce` endpoint.
    pub async fn next_nonce(&self) -> Result<String> {
        if let Some(nonce) = self.nonce.lock().await.take() {
            return Ok(nonce);
        }
        let url = self.directory.new_nonce.clone();
        let request = HttpRequest::head(&url);
        let response = self.transport.request(request).await?;
        self.record_nonce(&response).await;
        if !response.is_success() {
            return Err(response_error(&url, &response));
        }
        response.replay_nonce().map(str::to_string).ok_or_else(|| {
            AcmeError::MissingHeader {
                url: url.clone(),
                header: "Replay-Nonce",
            }
            .into()
        })
    }

    /// Sign and POST `payload` to `url` as a flattened JWS.
    ///
    /// `kid` is the account URL for existing accounts, or `None` for `newAccount`, where the
    /// public JWK is embedded in the protected header instead.
    pub async fn post_signed(
        &self,
        url: &str,
        kid: Option<&str>,
        payload: &[u8],
    ) -> Result<HttpResponse> {
        self.post_signed_headers(url, kid, payload, &[]).await
    }

    /// Like [`Self::post_signed`], with additional request headers.
    ///
    /// The certificate-download endpoint needs `Accept: application/pem-certificate-chain`; the
    /// `Content-Type` header is always `application/jose+json` for signed ACME requests.
    pub async fn post_signed_headers(
        &self,
        url: &str,
        kid: Option<&str>,
        payload: &[u8],
        headers: &[(String, String)],
    ) -> Result<HttpResponse> {
        let nonce = self.next_nonce().await?;
        let body = sign_jws(&self.account_key, kid, Some(&nonce), url, payload)?;
        let mut request = HttpRequest::post_jose(url, body.into_bytes());
        for (name, value) in headers {
            request = request.with_header(name.clone(), value.clone());
        }
        let response = self.transport.request(request).await?;
        self.record_nonce(&response).await;
        Ok(response)
    }

    /// Register (or look up) an account and return the persisted record.
    ///
    /// When the directory advertises a terms-of-service URL and the registration does not agree
    /// to it, this fails with [`AcmeError::TermsOfServiceRequired`] before any request is sent.
    pub async fn register_account(
        &self,
        registration: &AccountRegistration,
    ) -> Result<StoredAccount> {
        let url = self.directory.new_account.clone();
        if let Some(terms_url) = self.directory.terms_of_service() {
            if !registration.terms_of_service_agreed && !registration.only_return_existing {
                return Err(AcmeError::TermsOfServiceRequired {
                    url: terms_url.to_string(),
                }
                .into());
            }
        }
        if self.directory.external_account_required()
            && registration.external_account.is_none()
            && !registration.only_return_existing
        {
            return Err(AcmeError::ExternalAccount(format!(
                "CA `{}` requires external account binding, but no `external_account` credentials are configured",
                self.directory_url
            ))
            .into());
        }

        let request = registration.to_wire_request(&self.account_key, &url)?;
        let payload = serde_json::to_vec(&request).map_err(|error| AcmeError::Decode {
            url: url.clone(),
            reason: error.to_string(),
        })?;
        let response = self.post_signed(&url, None, &payload).await?;
        if !response.is_success() {
            return Err(response_error(&url, &response));
        }
        let account: Account = response.json(&url)?;
        let account_url = response
            .location()
            .ok_or_else(|| AcmeError::MissingHeader {
                url: url.clone(),
                header: "Location",
            })?
            .to_string();
        let contact = if account.contact.is_empty() {
            request.contact.clone()
        } else {
            account.contact.clone()
        };
        Ok(StoredAccount {
            directory_url: self.directory_url.clone(),
            account_url,
            contact,
            status: account.status,
            terms_of_service_agreed: account
                .terms_of_service_agreed
                .unwrap_or(request.terms_of_service_agreed),
            key_thumbprint: self.account_key.thumbprint()?,
        })
    }
}

/// Blob storage used for ACME account keys and account records.
///
/// This is intentionally separate from [`crate::storage::CertificateStorage`]: account material
/// is raw PEM/JSON rather than a typed certificate record. [`FileStorage`] implements this trait,
/// and [`MemoryAcmeStorage`] provides an in-memory backend for tests.
#[async_trait]
pub trait AcmeStorage: Send + Sync {
    /// Backend name (for diagnostics and `list-modules`).
    fn name(&self) -> &'static str;

    /// Load a value by key.
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Store a value under a key, replacing any previous value.
    async fn store(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Delete a value; deleting a missing key succeeds.
    async fn delete(&self, key: &str) -> Result<()>;
}

#[async_trait]
impl<T: AcmeStorage + ?Sized> AcmeStorage for Arc<T> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        (**self).load(key).await
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        (**self).store(key, value).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        (**self).delete(key).await
    }
}

/// In-memory [`AcmeStorage`], used by tests and ephemeral deployments.
#[derive(Debug, Default)]
pub struct MemoryAcmeStorage {
    values: RwLock<BTreeMap<String, Vec<u8>>>,
}

impl MemoryAcmeStorage {
    /// Create empty storage.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AcmeStorage for MemoryAcmeStorage {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .values
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .cloned())
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.values
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.values
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(key);
        Ok(())
    }
}

fn storage_path(root: &Path, key: &str) -> Result<PathBuf> {
    if key.is_empty() || key.contains("..") || key.starts_with('/') || key.contains('\0') {
        return Err(Error::InvalidKey(key.to_string()));
    }
    Ok(root.join(key))
}

/// [`AcmeStorage`] over the filesystem certificate storage root.
///
/// Values live under `acme/...` inside the same root Caddy's `file_system` storage uses, so
/// account material survives restarts without a second configured backend.
#[async_trait]
impl AcmeStorage for FileStorage {
    fn name(&self) -> &'static str {
        "file_system"
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = storage_path(self.root(), key)?;
        match fs::read(&path).await {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Error::Io(error)),
        }
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = storage_path(self.root(), key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, value).await?;
        fs::rename(&temporary, &path).await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = storage_path(self.root(), key)?;
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Io(error)),
        }
    }
}

/// Storage keys for one account under one CA directory.
///
/// The layout mirrors certmagic's account tree (`acme/<ca-directory>/users/<account>/account.key`
/// and `account.json`), where the CA directory name is the directory URL without its scheme and
/// with path separators replaced by `-`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPaths {
    /// Storage key of the PKCS#8 account key PEM.
    pub account_key: String,
    /// Storage key of the [`StoredAccount`] JSON record.
    pub account: String,
}

/// Compute the storage keys for `directory_url` and `email`.
pub fn account_paths(directory_url: &str, email: Option<&str>) -> Result<AccountPaths> {
    let directory = sanitize_directory_url(directory_url)?;
    let user = match email {
        Some(email) if !email.trim().is_empty() => sanitize_segment(email),
        _ => "default".to_string(),
    };
    Ok(AccountPaths {
        account_key: format!("acme/{directory}/users/{user}/account.key"),
        account: format!("acme/{directory}/users/{user}/account.json"),
    })
}

fn sanitize_directory_url(directory_url: &str) -> Result<String> {
    let trimmed = directory_url.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    if without_scheme.is_empty() {
        return Err(
            AcmeError::AccountKey(format!("invalid ACME directory URL `{directory_url}`")).into(),
        );
    }
    let mut sanitized = String::with_capacity(without_scheme.len());
    for (index, character) in without_scheme.chars().enumerate() {
        if character == '/' {
            // Trim a single trailing slash, as `.../directory/` and `.../directory` are the same.
            if index + 1 == without_scheme.len() {
                continue;
            }
            sanitized.push('-');
        } else if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
            sanitized.push(character);
        } else {
            sanitized.push('-');
        }
    }
    Ok(sanitized)
}

fn sanitize_segment(segment: &str) -> String {
    let mut sanitized = String::with_capacity(segment.len());
    for character in segment.trim().chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '@' | '+') {
            sanitized.push(character);
        } else {
            sanitized.push('-');
        }
    }
    if sanitized.is_empty() {
        "default".to_string()
    } else {
        sanitized
    }
}

/// Loads and persists ACME account keys and account records through an [`AcmeStorage`] backend.
#[derive(Debug, Clone)]
pub struct AccountStore<S: AcmeStorage> {
    storage: S,
    email: Option<String>,
}

impl<S: AcmeStorage> AccountStore<S> {
    /// Create a store for `email` (or the `default` account when `None`).
    pub fn new(storage: S, email: Option<String>) -> Self {
        Self { storage, email }
    }

    /// The backing storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// The configured account email.
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Compute the storage keys for `directory_url`.
    pub fn paths(&self, directory_url: &str) -> Result<AccountPaths> {
        account_paths(directory_url, self.email.as_deref())
    }

    /// Resolve the account key for `directory_url`.
    ///
    /// A non-empty `configured_pem` (Caddy's `tls.issuance.acme.account_key`) takes precedence
    /// over storage, mirroring certmagic's behaviour: the configured key is loaded first and only
    /// used to look up an existing account; it is never written back to storage. Without a
    /// configured key, this loads the persisted key or generates and stores a new one.
    pub async fn account_key(
        &self,
        directory_url: &str,
        configured_pem: Option<&str>,
    ) -> Result<(AccountKey, bool)> {
        match configured_pem {
            Some(pem) if !pem.trim().is_empty() => Ok((AccountKey::from_pkcs8_pem(pem)?, false)),
            _ => self.load_or_create_account_key(directory_url).await,
        }
    }

    /// Load the account key for `directory_url`, generating and storing one on first use.
    ///
    /// Returns the key and whether it was newly created.
    pub async fn load_or_create_account_key(
        &self,
        directory_url: &str,
    ) -> Result<(AccountKey, bool)> {
        let paths = self.paths(directory_url)?;
        match self.storage.load(&paths.account_key).await? {
            Some(value) => {
                let pem = String::from_utf8(value).map_err(|error| {
                    AcmeError::AccountKey(format!(
                        "stored account key `{}` is not UTF-8 PEM: {error}",
                        paths.account_key
                    ))
                })?;
                Ok((AccountKey::from_pkcs8_pem(&pem)?, false))
            }
            None => {
                let key = AccountKey::generate()?;
                self.storage
                    .store(&paths.account_key, key.to_pkcs8_pem().as_bytes())
                    .await?;
                Ok((key, true))
            }
        }
    }

    /// Persist a registered account record.
    pub async fn save_account(&self, account: &StoredAccount) -> Result<()> {
        let paths = self.paths(&account.directory_url)?;
        let value = serde_json::to_vec_pretty(account).map_err(|error| AcmeError::Decode {
            url: paths.account.clone(),
            reason: error.to_string(),
        })?;
        self.storage.store(&paths.account, &value).await
    }

    /// Load a previously persisted account record for `directory_url`.
    pub async fn load_account(&self, directory_url: &str) -> Result<Option<StoredAccount>> {
        let paths = self.paths(directory_url)?;
        let Some(value) = self.storage.load(&paths.account).await? else {
            return Ok(None);
        };
        let account = serde_json::from_slice(&value).map_err(|error| AcmeError::Decode {
            url: paths.account.clone(),
            reason: error.to_string(),
        })?;
        Ok(Some(account))
    }

    /// Delete the persisted account key and record for `directory_url`.
    pub async fn delete_account(&self, directory_url: &str) -> Result<()> {
        let paths = self.paths(directory_url)?;
        self.storage.delete(&paths.account_key).await?;
        self.storage.delete(&paths.account).await
    }
}

impl<S: AcmeStorage> AccountStore<S> {
    /// Register an account with `client` and persist the resulting record.
    pub async fn register_account<T: AcmeTransport>(
        &self,
        client: &AcmeClient<T>,
        registration: &AccountRegistration,
    ) -> Result<StoredAccount> {
        let account = client.register_account(registration).await?;
        self.save_account(&account).await?;
        Ok(account)
    }
}

pub use csr::CertificateRequest;
pub use order::{
    parse_pem_certificate_chain, parse_retry_after, retry_after, AcmeAccountClient, AcmeClock,
    Authorization, AuthorizationFetch, AuthorizationStatus, Challenge, ChallengeFetch,
    ChallengePolicy, ChallengeStatus, ChallengeType, Identifier, IssuedCertificate,
    NewOrderRequest, Order, OrderFetch, OrderHandle, OrderStatus, PollPolicy, TokioClock,
};
pub use transport::{read_root_certificates_pem_files, HyperTransport, NoAcmeTransport};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ---- mock transport -------------------------------------------------------------------

    #[derive(Debug, Default)]
    struct MockTransport {
        script: std::sync::Mutex<std::collections::VecDeque<(HttpMethod, String, HttpResponse)>>,
        requests: std::sync::Mutex<Vec<HttpRequest>>,
    }

    impl MockTransport {
        fn new(script: Vec<(HttpMethod, &str, HttpResponse)>) -> Self {
            Self {
                script: std::sync::Mutex::new(
                    script
                        .into_iter()
                        .map(|(method, url, response)| (method, url.to_string(), response))
                        .collect(),
                ),
                requests: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn records(&self) -> Vec<HttpRequest> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn remaining(&self) -> usize {
            self.script
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
        }
    }

    #[async_trait]
    impl AcmeTransport for Arc<MockTransport> {
        async fn request(&self, request: HttpRequest) -> Result<HttpResponse> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request.clone());
            let next = self
                .script
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or_else(|| {
                    panic!(
                        "mock transport has no response for {} {}",
                        request.method, request.url
                    )
                });
            assert_eq!(
                next.0, request.method,
                "unexpected method for {}",
                request.url
            );
            assert_eq!(next.1, request.url, "unexpected request URL");
            Ok(next.2)
        }
    }

    // ---- fixtures -------------------------------------------------------------------------

    const DIRECTORY_URL: &str = "https://acme.test/directory";
    const NEW_ACCOUNT_URL: &str = "https://acme.test/acme/new-account";

    fn directory_json() -> serde_json::Value {
        serde_json::json!({
            "newNonce": "https://acme.test/acme/new-nonce",
            "newAccount": NEW_ACCOUNT_URL,
            "newOrder": "https://acme.test/acme/new-order",
            "revokeCert": "https://acme.test/acme/revoke-cert",
            "keyChange": "https://acme.test/acme/key-change",
            "renewalInfo": "https://acme.test/acme/renewal-info",
            "meta": {
                "termsOfService": "https://acme.test/terms",
                "website": "https://acme.test/",
                "caaIdentities": ["acme.test"],
                "externalAccountRequired": false,
                "profiles": {"shortlived": "Short-lived certificates"}
            }
        })
    }

    fn directory_response() -> HttpResponse {
        HttpResponse::with_json(200, &directory_json()).unwrap()
    }

    fn account_json() -> serde_json::Value {
        serde_json::json!({
            "status": "valid",
            "contact": ["mailto:ops@example.com"],
            "orders": "https://acme.test/acme/orders/1",
            "termsOfServiceAgreed": true
        })
    }

    fn account_created_response() -> HttpResponse {
        HttpResponse::with_json(201, &account_json())
            .unwrap()
            .with_header("Location", "https://acme.test/acme/account/42")
            .with_header("Replay-Nonce", "nonce-created")
    }

    fn decoded_jws(body: &[u8]) -> (serde_json::Value, Vec<u8>, Vec<u8>) {
        let jws: serde_json::Value = serde_json::from_slice(body).unwrap();
        let protected = jws["protected"].as_str().unwrap();
        let payload = jws["payload"].as_str().unwrap();
        let signature = jws["signature"].as_str().unwrap();
        let header =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected.as_bytes()).unwrap()).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload.as_bytes()).unwrap();
        let signature_bytes = URL_SAFE_NO_PAD.decode(signature.as_bytes()).unwrap();
        (header, payload_bytes, signature_bytes)
    }

    // ---- directory ------------------------------------------------------------------------

    #[test]
    fn parses_directory_with_meta() {
        let directory = Directory::parse(
            DIRECTORY_URL,
            &serde_json::to_vec(&directory_json()).unwrap(),
        )
        .unwrap();
        assert_eq!(directory.new_nonce, "https://acme.test/acme/new-nonce");
        assert_eq!(directory.new_account, NEW_ACCOUNT_URL);
        assert_eq!(directory.new_order, "https://acme.test/acme/new-order");
        assert_eq!(directory.revoke_cert, "https://acme.test/acme/revoke-cert");
        assert_eq!(
            directory.key_change.as_deref(),
            Some("https://acme.test/acme/key-change")
        );
        assert_eq!(
            directory.renewal_info.as_deref(),
            Some("https://acme.test/acme/renewal-info")
        );
        assert_eq!(
            directory.terms_of_service(),
            Some("https://acme.test/terms")
        );
        assert!(!directory.external_account_required());
        let meta = directory.meta.as_ref().unwrap();
        assert_eq!(meta.website.as_deref(), Some("https://acme.test/"));
        assert_eq!(
            meta.caa_identities.as_deref(),
            Some(&["acme.test".to_string()][..])
        );
        assert_eq!(
            meta.profiles
                .as_ref()
                .and_then(|profiles| profiles.get("shortlived"))
                .map(String::as_str),
            Some("Short-lived certificates")
        );
    }

    #[test]
    fn rejects_directory_missing_required_endpoint() {
        let mut value = directory_json();
        value.as_object_mut().unwrap().remove("newOrder");
        let error =
            Directory::parse(DIRECTORY_URL, &serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert!(error.to_string().contains("newOrder"), "{error}");
        assert!(error.to_string().contains(DIRECTORY_URL), "{error}");
    }

    #[test]
    fn rejects_directory_that_is_not_json() {
        let error = Directory::parse(DIRECTORY_URL, b"not json").unwrap_err();
        assert!(
            error.to_string().contains("invalid ACME directory"),
            "{error}"
        );
    }

    // ---- account keys ---------------------------------------------------------------------

    #[test]
    fn account_key_generates_and_round_trips_certmagic_pem() {
        let key = AccountKey::generate().unwrap();
        let pem = key.to_pem();
        // Certmagic's PEMEncodePrivateKey writes SEC1 `EC PRIVATE KEY` for ECDSA keys.
        assert!(pem.starts_with("-----BEGIN EC PRIVATE KEY-----\n"), "{pem}");
        assert!(pem.contains("-----END EC PRIVATE KEY-----\n"), "{pem}");

        let reloaded = AccountKey::from_pem(pem).unwrap();
        assert_eq!(reloaded.public_key_bytes(), key.public_key_bytes());
        assert_eq!(reloaded.thumbprint().unwrap(), key.thumbprint().unwrap());
        assert_eq!(reloaded.public_jwk().unwrap(), key.public_jwk().unwrap());

        let message = b"acme-jws-signing-input";
        let signature = key.sign_es256(message).unwrap();
        assert!(key.verify_es256(message, &signature));
        assert!(reloaded.verify_es256(message, &signature));
        assert!(!key.verify_es256(b"tampered", &signature));
    }

    #[test]
    fn account_key_rejects_unsupported_pem_labels() {
        let error = AccountKey::from_pem(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAA==\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported account key PEM label"),
            "{error}"
        );
        assert!(error.to_string().contains("OPENSSH PRIVATE KEY"), "{error}");
    }

    #[test]
    fn account_key_rejects_ed25519_pkcs8_with_a_located_error() {
        use ring::signature::Ed25519KeyPair;
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pem = pem_encode("PRIVATE KEY", pkcs8.as_ref());
        let error = AccountKey::from_pem(&pem).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Ed25519 account keys are not supported"),
            "{error}"
        );
    }

    #[test]
    fn account_key_rejects_rsa_sizes_outside_the_allowlist() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let private_key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
        let pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .unwrap();
        let error = AccountKey::from_pem(&pem).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported RSA account key size 1024"),
            "{error}"
        );
    }

    #[test]
    fn account_key_type_parse_rejects_unknown_types() {
        for good in ["p256", "P384", "rsa2048", "rsa4096"] {
            assert!(AccountKeyType::parse(good).is_ok(), "{good}");
        }
        let error = AccountKeyType::parse("ed25519").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported account key type `ed25519`"),
            "{error}"
        );
    }

    #[test]
    fn jwk_thumbprint_is_rfc7638_canonical() {
        let key = AccountKey::generate().unwrap();
        let jwk = key.public_jwk().unwrap();
        let thumbprint = jwk.thumbprint().unwrap();
        // Recompute over the canonical member order required by RFC 7638.
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            jwk.x.as_deref().unwrap_or_default(),
            jwk.y.as_deref().unwrap_or_default()
        );
        let expected = URL_SAFE_NO_PAD.encode(ring::digest::digest(
            &ring::digest::SHA256,
            canonical.as_bytes(),
        ));
        assert_eq!(thumbprint, expected);
        assert!(!thumbprint.contains('='));
        assert!(!thumbprint.contains('+'));
        assert!(!thumbprint.contains('/'));
    }

    // ---- account storage ------------------------------------------------------------------

    #[tokio::test]
    async fn account_paths_follow_certmagic_shape() {
        let paths = account_paths(DIRECTORY_URL, Some("ops@example.com")).unwrap();
        assert_eq!(
            paths.account_key,
            "acme/acme.test-directory/users/ops@example.com/account.key"
        );
        assert_eq!(
            paths.account,
            "acme/acme.test-directory/users/ops@example.com/account.json"
        );
        let default_paths =
            account_paths("https://acme-v02.api.letsencrypt.org/directory", None).unwrap();
        assert_eq!(
            default_paths.account_key,
            "acme/acme-v02.api.letsencrypt.org-directory/users/default/account.key"
        );
    }

    #[test]
    fn account_keys_support_certmagic_key_types_and_pem_encodings() {
        for (key_type, label, algorithm, kty, crv) in [
            (
                AccountKeyType::P256,
                "EC PRIVATE KEY",
                "ES256",
                "EC",
                Some("P-256"),
            ),
            (
                AccountKeyType::P384,
                "EC PRIVATE KEY",
                "ES384",
                "EC",
                Some("P-384"),
            ),
            (
                AccountKeyType::Rsa2048,
                "RSA PRIVATE KEY",
                "RS256",
                "RSA",
                None,
            ),
        ] {
            let key = AccountKey::generate_with_key_type(key_type).unwrap();
            assert_eq!(key.key_type(), key_type);
            assert_eq!(key.jws_algorithm(), algorithm);
            let pem = key.to_pem();
            assert!(
                pem.starts_with(&format!("-----BEGIN {label}-----\n")),
                "{key_type:?}: {pem}"
            );
            // Certmagic/Go SEC1 EC keys include the named-curve parameters and public key.
            if algorithm != "RS256" {
                let (label, der) = pem_decode(pem).unwrap();
                assert_eq!(label, "EC PRIVATE KEY");
                let curve_oid = match key_type {
                    AccountKeyType::P256 => der_oid(OID_PRIME256V1),
                    AccountKeyType::P384 => der_oid(OID_SECP384R1),
                    _ => unreachable!(),
                };
                assert!(
                    der.windows(curve_oid.len())
                        .any(|window| window == curve_oid),
                    "{key_type:?}: SEC1 parameters missing"
                );
                let (_, body, _) = read_tlv(&der).unwrap();
                let mut offset = 0;
                let mut tags = Vec::new();
                while offset < body.len() {
                    let (tag, _, consumed) = read_tlv(&body[offset..]).unwrap();
                    tags.push(tag);
                    offset += consumed;
                }
                assert_eq!(tags, vec![0x02, 0x04, 0xA0, 0xA1], "{key_type:?}");
            }
            let reloaded = AccountKey::from_pem(pem).unwrap();
            assert_eq!(reloaded.key_type(), key_type);
            assert_eq!(reloaded.thumbprint().unwrap(), key.thumbprint().unwrap());

            let jwk = key.public_jwk().unwrap();
            assert_eq!(jwk.kty, kty);
            assert_eq!(jwk.crv.as_deref(), crv);
            let message = b"acme-jws-signing-input";
            let signature = key.sign(message).unwrap();
            assert!(key.verify(message, &signature), "{key_type:?}");
            assert!(reloaded.verify(message, &signature), "{key_type:?}");
        }
    }

    #[tokio::test]
    async fn mock_transport_accepts_es384_and_rs256_account_keys() {
        for (key_type, algorithm, kty) in [
            (AccountKeyType::P384, "ES384", "EC"),
            (AccountKeyType::Rsa2048, "RS256", "RSA"),
        ] {
            let mock = Arc::new(MockTransport::new(vec![
                (HttpMethod::Get, DIRECTORY_URL, directory_response()),
                (
                    HttpMethod::Head,
                    "https://acme.test/acme/new-nonce",
                    HttpResponse::new(200).with_header("Replay-Nonce", "nonce-1"),
                ),
                (
                    HttpMethod::Post,
                    NEW_ACCOUNT_URL,
                    account_created_response(),
                ),
            ]));
            let key = AccountKey::generate_with_key_type(key_type).unwrap();
            let client = AcmeClient::connect(mock.clone(), DIRECTORY_URL, key)
                .await
                .unwrap();
            let store = AccountStore::new(
                MemoryAcmeStorage::new(),
                Some("ops@example.com".to_string()),
            );
            let account = store
                .register_account(&client, &AccountRegistration::for_email("ops@example.com"))
                .await
                .unwrap();
            assert_eq!(account.account_url, "https://acme.test/acme/account/42");
            assert_eq!(
                account.key_thumbprint,
                client.account_key().thumbprint().unwrap()
            );

            let requests = mock.records();
            let post = requests.last().expect("newAccount request");
            let (header, _payload, signature) = decoded_jws(&post.body);
            assert_eq!(header["alg"], algorithm);
            assert_eq!(header["jwk"]["kty"], kty);
            assert_eq!(
                header["jwk"],
                serde_json::to_value(client.account_key().public_jwk().unwrap()).unwrap()
            );
            let signing_input = {
                let jws: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
                format!(
                    "{}.{}",
                    jws["protected"].as_str().unwrap(),
                    jws["payload"].as_str().unwrap()
                )
            };
            assert!(client
                .account_key()
                .verify(signing_input.as_bytes(), &signature));
        }
    }

    #[tokio::test]
    async fn configured_p384_and_rsa_account_keys_take_precedence() {
        for key_type in [AccountKeyType::P384, AccountKeyType::Rsa2048] {
            let configured = AccountKey::generate_with_key_type(key_type).unwrap();
            let store = AccountStore::new(MemoryAcmeStorage::new(), None);
            let (resolved, created) = store
                .account_key(DIRECTORY_URL, Some(configured.to_pem()))
                .await
                .unwrap();
            assert!(!created);
            assert_eq!(resolved.jws_algorithm(), configured.jws_algorithm());
            assert_eq!(
                resolved.thumbprint().unwrap(),
                configured.thumbprint().unwrap()
            );
            assert!(store
                .storage()
                .load(&store.paths(DIRECTORY_URL).unwrap().account_key)
                .await
                .unwrap()
                .is_none());
        }
    }

    // RSA-4096 generation costs minutes on loaded hosts; load a pre-generated certmagic-style
    // PKCS#1/PKCS#8 key to exercise the RSA-4096 load/sign path without slowing the suite.
    const RSA_4096_ACCOUNT_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCh1JZxoHuUBRPg
5rMkjxdmsDDXe0jFyZBndf59IJ/VRC8ydPS9ATNUNxDnDkdwVv1F7cOma6Wq9TdG
7iJSaBTn1HdvcgwH9ztrJToaU03Z/LmaranUUEsKHr2HPEGocer620vzmcZwKWtM
EOgICwzA+TxrYyzdXlhsCYxvQzbrODvdhQ3KfNklyETcOSrTUublOO2SCFi3Z+u5
DwdOrZqS9ZvbWab5VBpnFEKNYva0LDp6Bb5EyiQKh86DcBztBon83lot5qpJ7GAH
TKRcfRGMAPXdx1TZMTeZshlaC74MhDJYJuvLblc4lUoTJPh78NC+mRc8/nm9LS9f
msL9X9Grr7LBDOvjH0cUCKKQqeJekvrlCJLZ/+qtqXy7sH9rwnycsDqgDIFj5fu9
4r2YaYvcJX1y+PqQ9LrvBXlscT8vsyLzZJ+cssE+dlELdABK58ejaRursLj7iIf+
84f1VcDmBBZaUg8Soce+S02V+3iblOknBAU2WXJVWL+NGlpePUTwuJM9KSFM5OLL
wKrZOmM9e8jg4oRcpGdPCumdqAPg2aMZSkwKEqMv1atCa6RCzeud9gZ1NZgHcK0Z
HRKl6GTuqrGw+BrIQUwVoLZcYS7DiAN0wsWgkswDZa+rZCZkJfLyZGp34WO5egvu
5JP7pF7HaV2sOQjMz75rPbxOiSAO/wIDAQABAoICAEnYecwg6LNLO95xN4bzusBz
nt39VmBW0Yu8lqPfir/lLMpP/0vt68++jvp4lBXJxCowTIq47XCdFBvMV6IV95Aw
bk3PE3lhEl6arrBLmidiQQm5vFjzSMK181NuJiHo1cqh3j8rSRdudxVPU6oz7J50
PONd7p+XSS8HjmtJFxrv3rV/XSMspGQuxmldttKWrmEkAJiWMXGDvNeF6ZY39uSf
qf7GosB8Zc3qu1HMOnpOAmMjEsdOHHMntI9azgBE7xuSFUGD0+oGsG00Rn4j3ilu
WMNajbfMUyxRzmq+F/ubKWP7YrbCQ4/A4/vnb3ITGhYXQrjlAIVYRJlSRC8dlc2R
brvN3aQtFbGimVC/lmCFRVGT9swv/NvVgAzrl3K/9qZB949vsS43slqdgufPkJM6
UUwxJHnDsXK9pGFQ332aI+9caE2gWeq6VnWpWNpFx+pL/Tp8LiVi51W7Rh2x90kq
ft28h0jZnBD/6mz81Dbv5A31TEqenU6X0z4fh9NVm3dl6tQnOMecgLcLGY8L/pMx
AdJlrTctDbDUUgEGieZ1YJdjtRsCrhlZJ58x8jS7SgJh9Izf2MX4esEsy0+hKINB
bX4jZxGPs41vtXhjX0Y13+9z043cWnefBrUTuMUf31v+q1qGADrfUpWI7fdm/naw
mvNCnFKti1u+cjQ6b+PZAoIBAQDc2jJHlEELX1jlbR+hku/a2T7ToBWO1tp+M830
Hco23Yts31dUlMsSLAdRE9sEWpoYIybGIWMvWCA0F4qoTavcgcqR6KW2PGtJ5ppp
9cy++NG92d4oVAdevRjYYEz8+5JIyqvrWfT5i/wdQDc+ZTS/7JSWtm0MZU32Vn8b
lqNU0TrDVy8nrUeYuWrJHhO6iRvNcEl75zeGaNZ3W9drYi4U+40HFNbDotMzVqDB
Cyu3nmbl2Xtf3BMTRSD0gXLwuBKY9uNdVt68g2buv0QwU5B3AEu/4I1asGjQkTGp
tcDyUAQNpwt8vL7hzanbiKNGu4Sjy4GF5WVLDJ836Ap+9bHZAoIBAQC7lcOR52lZ
21aNMKCvJ1kU87719nOF5mSC5W/w6asajbNzJnjdGthCn7M26kcGE1zqULFi2mL3
soJUs1iuWAzq6JdCx8tGtNAxPOex9sXsbAPwrTNZidbqpDAidUl0hOjiRB/zPvnp
BuxlKOe0mFdBb+XJ1pILiQgToIe2Mwla7AjGil406OQ/gJ/8NuFmuOc2p+YsNutO
ooEi90XWFqUVCQao0EYYlBC17OUS6iaBFtsQ4wMaMIwg08bE994garB0ffS69Frv
oNiLUyfHzqHbWdJlXj+vugRDgsrx2QtkZErLTxDfOrJMWi+fIuRHp/IuJHJCUS/I
iwrCMu/ZFGiXAoIBABuv3w3KMD1UvrhEbeq7mQY+pfmx4AIAPXQE2pT4BxnJvGjx
tukLnkmw61nmu1ZYZWkRPxMnrF+LFL5zFRb0Zc9HFjYkjGHEQU8KceFGx1xJpUG/
xnIX1rSx0COQLxaoEza88cCXjnaabgjcvBA+b9Z/ukEKrbEYIiX3wgebYu6HLG7A
x1CaEJe85v4/nwmLlsiygwPdgMCA9CISiXcU3+IRhySUIDh2eTO+cHjDBcAHQ68d
DLJ/zIRl7jO45sf2y54RlX9mHJZVgtn7cHj+gOXqS5TKee4cn4dGLIuyFXZLQbbU
ckQ5BVUZi2nSP2XmrEI8iQhYMdKuymcf1/ECrEECggEAfg3+BiYD3aZPW0G6OPmw
GyxQvuiGaQyRroSP3MypdoaSeGb6AVrwyJSY0eZNJAAPCEaBbXRj3R/QBSsgBMiW
paT3QKESMMmAvhW3fRffmShc3XcGcrz192euEPnQCsTl2mb9MXC4b6d/Y9tBGVLm
D8sqF6BhM+85xjax+/X/62GB5ClHdTarayD8YXhfr6/BcDETs9KT/ZumO+D+xQci
mCggmYCcGhglwpsWtMc0aLr7KzXh98932vd1Mxd95TrMqPubYaajFTR5T+bpbJOm
oMiTYhsboPLXuqZBypOX3DapLEZNiDTha/2O0tmXna92RxumzHnSKmmFKUshcjcM
sQKCAQEAycVOMc9jrJ7AipBorFWaDWP6f03Czmjw5/WZ+7r5jCI8QBYH0hHH24rz
+Dk60mQ5ysm1J34yM5CO1QB212JWvUQ4Ciqb4g07Dp/JPk6MoX9z32imvCxBQs4J
xB97ZB5hCf9F/MiHFaSfXITJhgZV/GPWfwuDg8eU3hUL2I7wpOiq+aotSjq09KIr
5rGBQBzY1dtlfoQaInAzuN+GEdMxoNwSL8Qno8Jh8bq/cPTUYlM7l3pLeH2IVIOs
nXvoe9e8blkTcWkAQIg/8meFBH+AssmCwahD+YR4wcuR7Qlc8EWhadYiIHejmCSV
EVdZ8IcAQzAPk1jBxj0YDC0rR5d09Q==
-----END PRIVATE KEY-----
"#;

    #[test]
    fn account_key_rsa4096_fixture_loads_and_signs() {
        let key = AccountKey::from_pem(RSA_4096_ACCOUNT_KEY_PEM).unwrap();
        assert_eq!(key.key_type(), AccountKeyType::Rsa4096);
        assert_eq!(key.jws_algorithm(), "RS256");
        let reloaded = AccountKey::from_pem(key.to_pem()).unwrap();
        assert_eq!(reloaded.public_jwk().unwrap(), key.public_jwk().unwrap());
        let message = b"rsa-4096-jws-signing-input";
        let signature = key.sign(message).unwrap();
        assert!(key.verify(message, &signature));
        assert!(reloaded.verify(message, &signature));
    }

    #[tokio::test]
    async fn account_key_persists_through_memory_storage() {
        let storage = MemoryAcmeStorage::new();
        let store = AccountStore::new(storage, Some("ops@example.com".to_string()));
        let (first, created) = store
            .load_or_create_account_key(DIRECTORY_URL)
            .await
            .unwrap();
        assert!(created);

        let (second, created_again) = store
            .load_or_create_account_key(DIRECTORY_URL)
            .await
            .unwrap();
        assert!(!created_again);
        assert_eq!(first.thumbprint().unwrap(), second.thumbprint().unwrap());
        assert_eq!(first.to_pkcs8_pem(), second.to_pkcs8_pem());
        assert_eq!(
            store.storage().name(),
            "memory",
            "storage backend must be reachable through the store"
        );
    }

    #[tokio::test]
    async fn account_record_persists_through_file_storage() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let store = AccountStore::new(storage, Some("ops@example.com".to_string()));
        let (key, created) = store
            .load_or_create_account_key(DIRECTORY_URL)
            .await
            .unwrap();
        assert!(created);
        assert_eq!(store.storage().name(), "file_system");

        let account = StoredAccount {
            directory_url: DIRECTORY_URL.to_string(),
            account_url: "https://acme.test/acme/account/42".to_string(),
            contact: vec!["mailto:ops@example.com".to_string()],
            status: AccountStatus::Valid,
            terms_of_service_agreed: true,
            key_thumbprint: key.thumbprint().unwrap(),
        };
        store.save_account(&account).await.unwrap();
        let loaded = store.load_account(DIRECTORY_URL).await.unwrap().unwrap();
        assert_eq!(loaded, account);

        // And the key is still there after a fresh store over the same backend.
        let (reloaded_key, created) = AccountStore::new(
            FileStorage::new(directory.path()),
            Some("ops@example.com".to_string()),
        )
        .load_or_create_account_key(DIRECTORY_URL)
        .await
        .unwrap();
        assert!(!created);
        assert_eq!(
            reloaded_key.thumbprint().unwrap(),
            key.thumbprint().unwrap()
        );

        store.delete_account(DIRECTORY_URL).await.unwrap();
        assert!(store.load_account(DIRECTORY_URL).await.unwrap().is_none());
        let (_, created) = store
            .load_or_create_account_key(DIRECTORY_URL)
            .await
            .unwrap();
        assert!(created, "deleted account key must be regenerated");
    }

    #[tokio::test]
    async fn account_storage_refuses_traversal_keys() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(directory.path());
        let error = storage.store("../escape", b"x").await.unwrap_err();
        assert!(error.to_string().contains("../escape"), "{error}");
    }

    // ---- client: successful registration --------------------------------------------------

    #[tokio::test]
    async fn fetches_mock_ari_window_and_falls_back_when_unavailable() {
        let leaf_pem = include_str!("../../testdata/https/example.com.pem");
        let leaf_der = crate::storage::certificate_chain_der(&[leaf_pem.to_string()])
            .unwrap()
            .remove(0);
        let cert_id = ari::unique_identifier(&leaf_der).unwrap();
        let ari_url = format!("https://acme.test/acme/renewal-info/{cert_id}");
        let body = serde_json::json!({
            "suggestedWindow": {
                "start": "2026-04-01T00:00:00Z",
                "end": "2026-04-03T00:00:00Z"
            },
            "explanationURL": "https://acme.test/why"
        });
        let mock = Arc::new(MockTransport::new(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Get,
                &ari_url,
                HttpResponse::with_json(200, &body)
                    .unwrap()
                    .with_header("Retry-After", "3600"),
            ),
        ]));
        let info = crate::acme::fetch_renewal_info(&mock, DIRECTORY_URL, &leaf_der)
            .await
            .unwrap()
            .expect("ARI window");
        assert_eq!(info.unique_identifier, cert_id);
        assert!(info.suggested_window.end > info.suggested_window.start);
        let selected = info.selected_time.expect("selected time");
        assert!(selected >= info.suggested_window.start);
        assert!(selected < info.suggested_window.end);
        assert!(info.retry_after.is_some());
        assert_eq!(
            info.explanation_url.as_deref(),
            Some("https://acme.test/why")
        );

        // A 404 (or a directory without renewalInfo) means "no ARI": the caller falls back to its
        // local renewal heuristic rather than failing the renewal.
        let missing = Arc::new(MockTransport::new(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Get,
                &ari_url,
                HttpResponse::new(404).with_body(Vec::new()),
            ),
        ]));
        assert!(
            crate::acme::fetch_renewal_info(&missing, DIRECTORY_URL, &leaf_der)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn mock_transport_registers_account_and_persists_it() {
        let mock = Arc::new(MockTransport::new(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Head,
                "https://acme.test/acme/new-nonce",
                HttpResponse::new(200).with_header("Replay-Nonce", "nonce-1"),
            ),
            (
                HttpMethod::Post,
                NEW_ACCOUNT_URL,
                account_created_response(),
            ),
        ]));
        let key = AccountKey::generate().unwrap();
        let client = AcmeClient::connect(mock.clone(), DIRECTORY_URL, key)
            .await
            .unwrap();
        assert_eq!(client.directory().new_account, NEW_ACCOUNT_URL);
        assert_eq!(client.directory_url(), DIRECTORY_URL);

        let store = AccountStore::new(
            MemoryAcmeStorage::new(),
            Some("ops@example.com".to_string()),
        );
        let registration = AccountRegistration::for_email("ops@example.com");
        let account = store
            .register_account(&client, &registration)
            .await
            .unwrap();

        assert_eq!(account.account_url, "https://acme.test/acme/account/42");
        assert_eq!(account.status, AccountStatus::Valid);
        assert_eq!(account.contact, vec!["mailto:ops@example.com".to_string()]);
        assert!(account.terms_of_service_agreed);
        assert_eq!(account.directory_url, DIRECTORY_URL);
        assert_eq!(
            account.key_thumbprint,
            client.account_key().thumbprint().unwrap()
        );
        assert_eq!(
            store.load_account(DIRECTORY_URL).await.unwrap(),
            Some(account.clone())
        );

        let requests = mock.records();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, HttpMethod::Get);
        assert_eq!(requests[1].method, HttpMethod::Head);
        assert_eq!(requests[1].url, "https://acme.test/acme/new-nonce");

        let post = &requests[2];
        assert_eq!(post.method, HttpMethod::Post);
        assert_eq!(post.url, NEW_ACCOUNT_URL);
        assert_eq!(post.header("Content-Type"), Some(JOSE_CONTENT_TYPE));

        let (header, payload, signature) = decoded_jws(&post.body);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["nonce"], "nonce-1");
        assert_eq!(header["url"], NEW_ACCOUNT_URL);
        assert_eq!(
            header["jwk"],
            serde_json::to_value(key_jwk(&client)).unwrap()
        );
        assert!(
            header.get("kid").is_none(),
            "newAccount must use jwk, not kid"
        );

        let signing_input = {
            let jws: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
            format!(
                "{}.{}",
                jws["protected"].as_str().unwrap(),
                jws["payload"].as_str().unwrap()
            )
        };
        assert!(client
            .account_key()
            .verify_es256(signing_input.as_bytes(), &signature));

        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            payload["contact"],
            serde_json::json!(["mailto:ops@example.com"])
        );
        assert_eq!(payload["termsOfServiceAgreed"], true);
        assert!(
            payload.get("onlyReturnExisting").is_none(),
            "false flags must not be serialized"
        );
        assert_eq!(mock.remaining(), 0);
    }

    fn key_jwk(client: &AcmeClient<Arc<MockTransport>>) -> Jwk {
        client.account_key().public_jwk().unwrap()
    }

    // ---- client: error handling ----------------------------------------------------------

    #[tokio::test]
    async fn mock_transport_surfaces_problem_document() {
        let mock = Arc::new(MockTransport::new(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Head,
                "https://acme.test/acme/new-nonce",
                HttpResponse::new(200).with_header("Replay-Nonce", "nonce-1"),
            ),
            (
                HttpMethod::Post,
                NEW_ACCOUNT_URL,
                HttpResponse::with_problem(
                    400,
                    &serde_json::json!({
                        "type": "urn:ietf:params:acme:error:accountDoesNotExist",
                        "detail": "No account exists with the provided key",
                        "status": 400
                    }),
                )
                .unwrap(),
            ),
        ]));
        let client = AcmeClient::connect(mock, DIRECTORY_URL, AccountKey::generate().unwrap())
            .await
            .unwrap();
        let mut registration = AccountRegistration::for_email("ops@example.com");
        registration.only_return_existing = true;
        registration.terms_of_service_agreed = false;
        let error = client.register_account(&registration).await.unwrap_err();
        let Error::Acme(acme_error) = error else {
            panic!("expected AcmeError, got {error:?}");
        };
        assert_eq!(
            acme_error.problem_type(),
            Some("urn:ietf:params:acme:error:accountDoesNotExist")
        );
        let AcmeError::Problem {
            status,
            problem,
            url,
            ..
        } = acme_error.as_ref()
        else {
            panic!("expected problem document, got {acme_error:?}");
        };
        assert_eq!(*status, 400);
        assert_eq!(*url, NEW_ACCOUNT_URL);
        assert_eq!(
            problem.detail.as_deref(),
            Some("No account exists with the provided key")
        );
        assert!(!acme_error.is_user_action_required());
    }

    #[tokio::test]
    async fn user_action_required_problem_is_flagged() {
        let mock = Arc::new(MockTransport::new(vec![
            (HttpMethod::Get, DIRECTORY_URL, directory_response()),
            (
                HttpMethod::Head,
                "https://acme.test/acme/new-nonce",
                HttpResponse::new(200).with_header("Replay-Nonce", "nonce-1"),
            ),
            (
                HttpMethod::Post,
                NEW_ACCOUNT_URL,
                HttpResponse::with_problem(
                    403,
                    &serde_json::json!({
                        "type": USER_ACTION_REQUIRED,
                        "detail": "The terms of service have changed; visit the CA website",
                        "status": 403,
                        "instance": "https://acme.test/terms"
                    }),
                )
                .unwrap(),
            ),
        ]));
        let client = AcmeClient::connect(mock, DIRECTORY_URL, AccountKey::generate().unwrap())
            .await
            .unwrap();
        let error = client
            .register_account(&AccountRegistration::for_email("ops@example.com"))
            .await
            .unwrap_err();
        let Error::Acme(acme_error) = error else {
            panic!("expected AcmeError, got {error:?}");
        };
        assert!(acme_error.is_user_action_required());
        assert!(acme_error.to_string().contains("userActionRequired"));
    }

    #[tokio::test]
    async fn terms_of_service_must_be_accepted_before_any_request() {
        let mock = Arc::new(MockTransport::new(vec![(
            HttpMethod::Get,
            DIRECTORY_URL,
            directory_response(),
        )]));
        let client =
            AcmeClient::connect(mock.clone(), DIRECTORY_URL, AccountKey::generate().unwrap())
                .await
                .unwrap();
        let mut registration = AccountRegistration::for_email("ops@example.com");
        registration.terms_of_service_agreed = false;
        let error = client.register_account(&registration).await.unwrap_err();
        let Error::Acme(acme_error) = error else {
            panic!("expected AcmeError, got {error:?}");
        };
        let AcmeError::TermsOfServiceRequired { url } = acme_error.as_ref() else {
            panic!("expected TermsOfServiceRequired, got {acme_error:?}");
        };
        assert_eq!(url, "https://acme.test/terms");
        assert_eq!(
            mock.records().len(),
            1,
            "no POST may be sent when the terms are not accepted"
        );
    }

    #[test]
    fn problem_codes_and_diagnostics_include_subproblems() {
        let problem = Problem {
            problem_type: "urn:ietf:params:acme:error:rateLimited".to_string(),
            detail: Some("too many certificates".to_string()),
            status: Some(429),
            subproblems: Vec::new(),
            identifier: None,
        };
        assert_eq!(problem.error_code(), Some("rateLimited"));
        assert!(problem.is("rateLimited"));
        assert!(!problem.is("badNonce"));
        assert_eq!(problem.diagnostic(), "too many certificates");

        let no_detail = Problem {
            problem_type: "urn:ietf:params:acme:error:badNonce".to_string(),
            detail: None,
            status: None,
            subproblems: Vec::new(),
            identifier: None,
        };
        assert_eq!(no_detail.diagnostic(), "badNonce");

        let with_subproblems = Problem {
            problem_type: "urn:ietf:params:acme:error:malformed".to_string(),
            detail: None,
            status: None,
            subproblems: vec![Subproblem {
                problem_type: "urn:ietf:params:acme:error:dns".to_string(),
                detail: Some("no TXT record".to_string()),
                identifier: Some(serde_json::json!({"type": "dns", "value": "example.com"})),
            }],
            identifier: None,
        };
        let diagnostic = with_subproblems.diagnostic();
        assert_eq!(diagnostic, "malformed (example.com: no TXT record)");
        assert_eq!(with_subproblems.subproblems[0].error_code(), Some("dns"));
    }

    #[tokio::test]
    async fn external_account_binding_is_signed_with_hs256() {
        let key = AccountKey::generate().unwrap();
        let mac_key = b"a-shared-eab-secret";
        let external_account = ExternalAccount {
            kid: "eab-kid-1".to_string(),
            hmac_key: URL_SAFE_NO_PAD.encode(mac_key),
        };
        let registration = AccountRegistration {
            contact: vec!["mailto:ops@example.com".to_string()],
            terms_of_service_agreed: true,
            only_return_existing: false,
            external_account: Some(external_account),
        };
        let request = registration.to_wire_request(&key, NEW_ACCOUNT_URL).unwrap();
        let binding = request.external_account_binding.as_ref().unwrap();
        let protected = binding["protected"].as_str().unwrap();
        let payload = binding["payload"].as_str().unwrap();
        let signature = binding["signature"].as_str().unwrap();

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
        assert_eq!(header["alg"], "HS256");
        assert_eq!(header["kid"], "eab-kid-1");
        assert_eq!(header["url"], NEW_ACCOUNT_URL);

        let payload_bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let payload_jwk: Jwk = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload_jwk, key.public_jwk().unwrap());

        let key_ring = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, mac_key);
        let verified = ring::hmac::verify(
            &key_ring,
            format!("{protected}.{payload}").as_bytes(),
            &URL_SAFE_NO_PAD.decode(signature).unwrap(),
        );
        assert!(
            verified.is_ok(),
            "EAB signature must verify with the MAC key"
        );
    }

    #[test]
    fn parses_account_statuses_and_rejects_unknown_fields_silently() {
        for (value, expected) in [
            ("valid", AccountStatus::Valid),
            ("deactivated", AccountStatus::Deactivated),
            ("revoked", AccountStatus::Revoked),
            ("future-status", AccountStatus::Unknown),
        ] {
            let account: Account =
                serde_json::from_value(serde_json::json!({"status": value})).unwrap();
            assert_eq!(account.status, expected, "status `{value}`");
        }
        // The default is the ACME initial status.
        assert_eq!(AccountStatus::default(), AccountStatus::Valid);
    }

    #[tokio::test]
    async fn configured_account_key_takes_precedence_over_storage() {
        let configured = AccountKey::generate().unwrap();
        let store = AccountStore::new(
            MemoryAcmeStorage::new(),
            Some("ops@example.com".to_string()),
        );
        let (resolved, created) = store
            .account_key(DIRECTORY_URL, Some(configured.to_pkcs8_pem()))
            .await
            .unwrap();
        assert!(!created);
        assert_eq!(
            resolved.thumbprint().unwrap(),
            configured.thumbprint().unwrap()
        );
        // A configured key is not persisted: no storage write should have happened.
        assert!(store
            .storage()
            .load(&store.paths(DIRECTORY_URL).unwrap().account_key)
            .await
            .unwrap()
            .is_none());

        // Without a configured key the store generates and persists one.
        let (generated, created) = store.account_key(DIRECTORY_URL, None).await.unwrap();
        assert!(created);
        assert!(store
            .storage()
            .load(&store.paths(DIRECTORY_URL).unwrap().account_key)
            .await
            .unwrap()
            .is_some());
        assert_ne!(
            generated.thumbprint().unwrap(),
            configured.thumbprint().unwrap()
        );
    }

    #[tokio::test]
    async fn only_return_existing_wire_request_omits_terms() {
        let key = AccountKey::generate().unwrap();
        let registration = AccountRegistration {
            contact: Vec::new(),
            terms_of_service_agreed: false,
            only_return_existing: true,
            external_account: None,
        };
        let request = registration.to_wire_request(&key, NEW_ACCOUNT_URL).unwrap();
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value, serde_json::json!({"onlyReturnExisting": true}));
    }
}
