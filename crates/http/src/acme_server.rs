//! `http.handlers.acme_server`: an RFC 8555 ACME certificate authority.
//!
//! The handler turns an ordinary HTTP route into an ACME server backed by Caddy's internal
//! (local) CA. It mirrors the HTTP contract of Caddy v2.11.9's `acme_server` module
//! (`external/caddy/modules/caddypki/acmeserver`), which delegates to smallstep's ACME API:
//!
//! ```text
//! <prefix><ca>/directory              GET/HEAD
//! <prefix><ca>/new-nonce              GET (204) / HEAD (200)
//! <prefix><ca>/new-account            POST
//! <prefix><ca>/new-order              POST
//! <prefix><ca>/account/<id>           POST
//! <prefix><ca>/account/<id>/orders    POST
//! <prefix><ca>/order/<id>             POST
//! <prefix><ca>/order/<id>/finalize    POST
//! <prefix><ca>/authz/<id>             POST
//! <prefix><ca>/challenge/<az>/<id>    POST
//! <prefix><ca>/certificate/<id>       POST
//! <prefix><ca>/revoke-cert            POST
//! <prefix><ca>/key-change             POST
//! ```
//!
//! `prefix` is the configured `path_prefix` (`/acme/` by default) and `<ca>` is the configured CA
//! ID (`local` by default), so the default directory URL is
//! `https://<host>/acme/local/directory` exactly like Caddy.
//!
//! `X-Forwarded-Proto` and `X-Forwarded-Host` are honoured as a caddy-rs extension for a
//! TLS-terminating reverse proxy: when the server's trusted-proxy policy marks the peer trusted
//! (`trusted_proxy` request variable), the client-facing scheme and host replace the listener's
//! connection scheme and request `Host`. They affect URL construction only (the JWS `url` binding
//! uses the same origin); routing, certificate identifiers and the `http-01` fetch target never
//! read them. Valid values from an untrusted peer are ignored (malformed ones are rejected), so a
//! direct client cannot spoof the external origin.
//!
//! Security-relevant properties:
//!
//! * flattened JWS only (RS256/ES256), with the unprotected header forbidden, the `nonce`
//!   consumed exactly once, and the protected `url` compared against the request URL;
//! * nonces, accounts, orders and authorizations live in bounded, capacity-evicting stores, so a
//!   hostile client cannot grow server memory without bound;
//! * `http-01` validation performs a real HTTP GET of
//!   `http://<identifier>/.well-known/acme-challenge/<token>` and compares the body with the RFC
//!   8555 key authorization in constant time; a challenge is never marked valid without it;
//! * certificate issuance goes through the internal CA's
//!   [`InternalIssuer::sign_external_spki_with`], after the CSR self-signature and the order
//!   identifiers have been checked here.
//!
//! Deliberate limitations (recorded in DIV-0102):
//!
//! * only the `http-01` challenge is offered. A configuration that explicitly enables `dns-01` or
//!   `tls-alpn-01` fails at load time with a located error, and wildcard identifiers (which need
//!   `dns-01`) are rejected at order time;
//! * ACME state is in memory for one configuration generation (no bbolt-style persistence), and
//!   `key-change` returns 501 like Caddy's smallstep `NotImplemented` route;
//! * revocation is recorded in memory only (no OCSP/CRL responder), and revocation requests must be
//!   signed by the owning account key.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use ring::rand::SecureRandom;
use serde_json::{json, Map, Value};

use caddy_rs_tls::acme::csr::{parse_csr, MAX_CSR_DER_BYTES};
use caddy_rs_tls::acme::Jwk;
use caddy_rs_tls::{ca_storage_keys, key_authorization, InternalIssuer};

use crate::body::{BodyError, StreamingResponse};
use crate::types::{Error, Handler, Outcome, Request, Response, Result, StreamingOutcome};

/// Default path prefix under which the ACME endpoints are served (Caddy's `defaultPathPrefix`).
pub const DEFAULT_PATH_PREFIX: &str = "/acme/";
/// Default lifetime of issued certificates (Caddy's `12 * time.Hour`).
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
/// Minimum certificate lifetime smallstep's ACME provisioner accepts (`MinTLSDur`).
const MIN_LIFETIME: Duration = Duration::from_secs(5 * 60);
/// Maximum certificate lifetime smallstep's ACME provisioner accepts (`MaxTLSDur`).
const MAX_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Maximum number of live nonces (FIFO eviction beyond this bound).
const MAX_NONCES: usize = 4096;
/// Maximum number of accounts (FIFO eviction beyond this bound).
const MAX_ACCOUNTS: usize = 1024;
/// Maximum number of orders (FIFO eviction beyond this bound).
const MAX_ORDERS: usize = 1024;
/// Maximum number of authorizations (FIFO eviction beyond this bound).
const MAX_AUTHORIZATIONS: usize = 4096;
/// Maximum number of identifiers in one order.
const MAX_IDENTIFIERS: usize = 100;

/// Maximum JWS request body accepted by the POST endpoints.
const MAX_JWS_BODY: usize = 64 * 1024;
/// Maximum body size accepted from an http-01 challenge response.
const MAX_CHALLENGE_BODY: usize = 8 * 1024;
/// Timeout for one http-01 validation GET.
const HTTP01_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum accepted length of an external host authority (`host` or `host:port`).
const MAX_EXTERNAL_HOST_LEN: usize = 512;
/// Header carrying the scheme through which the client reached the reverse proxy.
const FORWARDED_PROTO_HEADER: &str = "x-forwarded-proto";
/// Header carrying the host through which the client reached the reverse proxy.
const FORWARDED_HOST_HEADER: &str = "x-forwarded-host";
/// Request variable the server runtime sets from `apps.http.servers.<name>.trusted_proxies`.
const TRUSTED_PROXY_VAR: &str = "trusted_proxy";

/// ACME order lifetime (smallstep's `defaultOrderExpiry`).
const ORDER_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
/// Order backdate (smallstep's `defaultOrderBackdate`).
const ORDER_BACKDATE: Duration = Duration::from_secs(60);

const PROBLEM_MALFORMED: &str = "urn:ietf:params:acme:error:malformed";
const PROBLEM_BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";
const PROBLEM_BAD_SIGNATURE_ALGORITHM: &str = "urn:ietf:params:acme:error:badSignatureAlgorithm";
const PROBLEM_UNAUTHORIZED: &str = "urn:ietf:params:acme:error:unauthorized";
const PROBLEM_ACCOUNT_DOES_NOT_EXIST: &str = "urn:ietf:params:acme:error:accountDoesNotExist";
const PROBLEM_ORDER_NOT_READY: &str = "urn:ietf:params:acme:error:orderNotReady";
const PROBLEM_REJECTED_IDENTIFIER: &str = "urn:ietf:params:acme:error:rejectedIdentifier";
const PROBLEM_BAD_CSR: &str = "urn:ietf:params:acme:error:badCSR";
const PROBLEM_ALREADY_REVOKED: &str = "urn:ietf:params:acme:error:alreadyRevoked";
const PROBLEM_BAD_REVOCATION_REASON: &str = "urn:ietf:params:acme:error:badRevocationReason";
const PROBLEM_CONNECTION: &str = "urn:ietf:params:acme:error:connection";
const PROBLEM_SERVER_INTERNAL: &str = "urn:ietf:params:acme:error:serverInternal";

fn replay_nonce_header() -> HeaderName {
    HeaderName::from_static("replay-nonce")
}

/// One ACME problem document (`application/problem+json`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Problem {
    problem_type: &'static str,
    status: StatusCode,
    detail: String,
}

impl Problem {
    fn new(problem_type: &'static str, status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            problem_type,
            status,
            detail: detail.into(),
        }
    }

    fn malformed(detail: impl Into<String>) -> Self {
        Self::new(PROBLEM_MALFORMED, StatusCode::BAD_REQUEST, detail)
    }

    fn bad_nonce(detail: impl Into<String>) -> Self {
        Self::new(PROBLEM_BAD_NONCE, StatusCode::BAD_REQUEST, detail)
    }

    fn bad_signature_algorithm(detail: impl Into<String>) -> Self {
        Self::new(
            PROBLEM_BAD_SIGNATURE_ALGORITHM,
            StatusCode::BAD_REQUEST,
            detail,
        )
    }

    fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(PROBLEM_UNAUTHORIZED, StatusCode::UNAUTHORIZED, detail)
    }

    fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(PROBLEM_UNAUTHORIZED, StatusCode::FORBIDDEN, detail)
    }

    fn account_does_not_exist(detail: impl Into<String>) -> Self {
        Self::new(
            PROBLEM_ACCOUNT_DOES_NOT_EXIST,
            StatusCode::BAD_REQUEST,
            detail,
        )
    }

    fn order_not_ready(detail: impl Into<String>) -> Self {
        // Caddy/smallstep report `orderNotReady` with 400 (RFC 8555 shows 403).
        Self::new(PROBLEM_ORDER_NOT_READY, StatusCode::BAD_REQUEST, detail)
    }

    fn rejected_identifier(detail: impl Into<String>) -> Self {
        Self::new(PROBLEM_REJECTED_IDENTIFIER, StatusCode::BAD_REQUEST, detail)
    }

    fn bad_csr(detail: impl Into<String>) -> Self {
        Self::new(PROBLEM_BAD_CSR, StatusCode::BAD_REQUEST, detail)
    }

    fn already_revoked(detail: impl Into<String>) -> Self {
        Self::new(PROBLEM_ALREADY_REVOKED, StatusCode::BAD_REQUEST, detail)
    }

    fn bad_revocation_reason(detail: impl Into<String>) -> Self {
        Self::new(
            PROBLEM_BAD_REVOCATION_REASON,
            StatusCode::BAD_REQUEST,
            detail,
        )
    }

    fn connection(detail: impl Into<String>) -> Self {
        Self::new(PROBLEM_CONNECTION, StatusCode::BAD_REQUEST, detail)
    }

    fn server_internal(detail: impl Into<String>) -> Self {
        Self::new(
            PROBLEM_SERVER_INTERNAL,
            StatusCode::INTERNAL_SERVER_ERROR,
            detail,
        )
    }

    fn not_found(detail: impl Into<String>) -> Self {
        Self::new(PROBLEM_MALFORMED, StatusCode::NOT_FOUND, detail)
    }

    fn not_implemented(detail: impl Into<String>) -> Self {
        // Caddy advertises key-change but routes it to smallstep's `NotImplemented` (501).
        Self::new(PROBLEM_MALFORMED, StatusCode::NOT_IMPLEMENTED, detail)
    }

    fn json(&self) -> Value {
        json!({"type": self.problem_type, "detail": self.detail})
    }
}

// ---- configuration ---------------------------------------------------------------------------

/// One DNS domain constraint of an `allow`/`deny` rule set.
///
/// Caddy normalises `*.example.com` to a one-label wildcard (smallstep stores the leading-dot
/// form and matches exactly one extra label); a bare domain matches exactly. Every other form is
/// rejected at load so a rule can never be silently ineffective.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DomainConstraint {
    /// `example.com`: exactly this name.
    Exact(String),
    /// `*.example.com`: exactly one label before `example.com`.
    OneLabelWildcard(String),
}

impl DomainConstraint {
    /// Parse a rule exactly like smallstep's `normalizeAndValidateDNSDomainConstraint`.
    fn parse(value: &str) -> std::result::Result<Self, String> {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Err("domain constraint cannot be empty or whitespace".to_string());
        }
        if normalized.contains("..") {
            return Err(format!(
                "domain constraint `{value}` cannot have empty labels"
            ));
        }
        if normalized.starts_with('.') {
            return Err(format!(
                "domain constraint `{value}` with wildcard should start with *"
            ));
        }
        if normalized.rfind('*').is_some_and(|index| index > 0) {
            return Err(format!(
                "domain constraint `{value}` can only have wildcard as starting character"
            ));
        }
        if normalized == "*" {
            return Err(format!(
                "domain constraint `{value}` is not a wildcard rule; use `*.<domain>` to match one \
                 label, or an exact domain"
            ));
        }
        if normalized.starts_with('*') && !normalized.starts_with("*.") {
            return Err(format!(
                "wildcard character in domain constraint `{value}` can only be used to match \
                 (full) labels"
            ));
        }
        let (wildcard, base) = match normalized.strip_prefix("*.") {
            Some(base) => (true, base.to_string()),
            None => (false, normalized),
        };
        validate_rule_hostname(&base, value)?;
        Ok(if wildcard {
            Self::OneLabelWildcard(base)
        } else {
            Self::Exact(base)
        })
    }

    fn matches(&self, name: &str) -> bool {
        let Some(name_labels) = reverse_labels(name) else {
            return false;
        };
        let constraint = match self {
            Self::Exact(constraint) => constraint,
            Self::OneLabelWildcard(constraint) => constraint,
        };
        let Some(constraint_labels) = reverse_labels(constraint) else {
            return false;
        };
        let expected =
            constraint_labels.len() + usize::from(matches!(self, Self::OneLabelWildcard(_)));
        expected == name_labels.len()
            && constraint_labels
                .iter()
                .zip(name_labels.iter())
                .all(|(constraint, name)| constraint.eq_ignore_ascii_case(name))
    }
}

/// Hostname syntax accepted for policy rules and ACME `dns` identifiers.
///
/// Deliberately stricter than smallstep's `idna.Lookup.ToASCII` in two places (documented in
/// DIV-0102): non-ASCII labels are rejected because this build has no IDNA implementation, and
/// empty labels (`a..example.com`) are rejected even though `idna.Lookup` tolerates them. Both are
/// fail-closed choices; they cannot turn a deny rule into a fail-open one.
fn validate_rule_hostname(base: &str, original: &str) -> std::result::Result<(), String> {
    if !base.is_ascii() {
        return Err(format!(
            "domain `{original}` is not ASCII; IDNA names are not implemented by this build"
        ));
    }
    if base.len() > 253 {
        return Err(format!("domain `{original}` exceeds 253 bytes"));
    }
    if base.starts_with('-') || base.ends_with('-') {
        return Err(format!(
            "domain `{original}` has a label starting or ending with `-`"
        ));
    }
    for label in base.split('.') {
        if label.is_empty() {
            return Err(format!("domain `{original}` has an empty label"));
        }
        if label.len() > 63 {
            return Err(format!(
                "domain `{original}` has a label longer than 63 bytes"
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!(
                "domain `{original}` contains a character that is not allowed in a hostname"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "domain `{original}` has a label starting or ending with `-`"
            ));
        }
    }
    Ok(())
}

/// One parsed `allow`/`deny` rule set of the ACME server policy.
#[derive(Debug, Clone, Default)]
struct RuleSet {
    /// Exact and one-label DNS wildcard constraints (`example.com`, `*.example.com`).
    domains: Vec<DomainConstraint>,
    /// CIDR networks and single IP addresses.
    ip_ranges: Vec<IpRange>,
}

impl RuleSet {
    fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ip_ranges.is_empty()
    }

    fn allows_dns(&self, name: &str) -> bool {
        self.domains
            .iter()
            .any(|constraint| constraint.matches(name))
    }

    fn allows_ip(&self, address: IpAddr) -> bool {
        self.ip_ranges.iter().any(|range| range.contains(address))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpRange {
    network: IpAddr,
    prefix: u8,
}

impl IpRange {
    fn parse(value: &str) -> std::result::Result<Self, String> {
        if let Some((address, prefix)) = value.split_once('/') {
            let address: IpAddr = address
                .parse()
                .map_err(|_| format!("`{value}` is not a valid IP or CIDR range"))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| format!("`{value}` has an invalid prefix length"))?;
            let max = if address.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(format!("`{value}` has a prefix length larger than {max}"));
            }
            Ok(Self {
                network: address,
                prefix,
            })
        } else {
            let address: IpAddr = value
                .parse()
                .map_err(|_| format!("`{value}` is not a valid IP or CIDR range"))?;
            Ok(Self {
                network: address,
                prefix: if address.is_ipv4() { 32 } else { 128 },
            })
        }
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(network) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(network) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

/// The `policy` object of `http.handlers.acme_server`.
#[derive(Debug, Clone, Default)]
struct AcmePolicy {
    allow: Option<RuleSet>,
    deny: Option<RuleSet>,
    allow_wildcard_names: bool,
}

/// Parsed `http.handlers.acme_server` JSON.
#[derive(Debug, Clone)]
struct AcmeServerConfig {
    ca: String,
    lifetime: Duration,
    host: Option<String>,
    path_prefix: String,
    policy: AcmePolicy,
    sign_with_root: bool,
}

impl AcmeServerConfig {
    fn from_json(value: &Value, path: &str) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(path, "acme_server must be an object"))?;
        for field in object.keys() {
            match field.as_str() {
                "handler" | "ca" | "lifetime" | "host" | "path_prefix" | "resolvers"
                | "challenges" | "policy" | "sign_with_root" => {}
                other => {
                    return Err(invalid(
                        path,
                        format!(
                            "unknown acme_server field `{other}` (supported: ca, lifetime, host, \
                             path_prefix, resolvers, challenges, policy, sign_with_root)"
                        ),
                    ))
                }
            }
        }

        let ca = match object.get("ca") {
            None | Some(Value::Null) => "local".to_string(),
            Some(Value::String(ca)) if ca.is_empty() => "local".to_string(),
            Some(Value::String(ca)) => ca.clone(),
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.ca"),
                    "`ca` must be a string CA ID",
                ))
            }
        };
        ca_storage_keys(&ca).map_err(|error| {
            invalid(
                &format!("{path}.ca"),
                format!("invalid certificate authority ID `{ca}`: {error}"),
            )
        })?;

        let lifetime = match object.get("lifetime") {
            None | Some(Value::Null) => DEFAULT_LIFETIME,
            Some(Value::Number(number)) => {
                let nanoseconds = number.as_u64().ok_or_else(|| {
                    invalid(
                        &format!("{path}.lifetime"),
                        "`lifetime` must be a non-negative duration in nanoseconds",
                    )
                })?;
                if nanoseconds == 0 {
                    DEFAULT_LIFETIME
                } else {
                    Duration::from_nanos(nanoseconds)
                }
            }
            Some(Value::String(text)) => parse_duration(text).ok_or_else(|| {
                invalid(
                    &format!("{path}.lifetime"),
                    format!("invalid `lifetime` duration `{text}`"),
                )
            })?,
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.lifetime"),
                    "`lifetime` must be a duration in nanoseconds or a duration string",
                ))
            }
        };
        if lifetime.is_zero() {
            return Err(invalid(
                &format!("{path}.lifetime"),
                "`lifetime` must be greater than zero",
            ));
        }

        let host = match object.get("host") {
            None | Some(Value::Null) => None,
            Some(Value::String(host)) if host.is_empty() => None,
            Some(Value::String(host)) => Some(host.clone()),
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.host"),
                    "`host` must be a string hostname",
                ))
            }
        };

        let path_prefix = match object.get("path_prefix") {
            None | Some(Value::Null) => DEFAULT_PATH_PREFIX.to_string(),
            Some(Value::String(prefix)) if prefix.is_empty() => DEFAULT_PATH_PREFIX.to_string(),
            Some(Value::String(prefix)) => prefix.clone(),
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.path_prefix"),
                    "`path_prefix` must be a string",
                ))
            }
        };
        if !path_prefix.starts_with('/') || !path_prefix.ends_with('/') {
            return Err(invalid(
                &format!("{path}.path_prefix"),
                format!(
                    "`path_prefix` `{path_prefix}` must begin and end with `/` (Caddy's default \
                     is `/acme/`)"
                ),
            ));
        }

        match object.get("resolvers") {
            None | Some(Value::Null) => {}
            Some(Value::Array(resolvers)) if resolvers.is_empty() => {}
            Some(Value::Array(_)) => {
                return Err(invalid(
                    &format!("{path}.resolvers"),
                    "`resolvers` are only used for dns-01 validation, which this build does not \
                     implement (http-01 only); remove the option rather than relying on a no-op",
                ))
            }
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.resolvers"),
                    "`resolvers` must be an array of resolver addresses",
                ))
            }
        }

        match object.get("challenges") {
            None | Some(Value::Null) => {}
            Some(Value::Array(values)) => {
                for (index, value) in values.iter().enumerate() {
                    let value = value.as_str().ok_or_else(|| {
                        invalid(
                            &format!("{path}.challenges[{index}]"),
                            "challenge names must be strings",
                        )
                    })?;
                    let value = value.trim().to_ascii_lowercase();
                    if value != "http-01" {
                        return Err(invalid(
                            &format!("{path}.challenges[{index}]"),
                            format!(
                                "ACME challenge `{value}` is not supported by this build; \
                                 only http-01 is implemented"
                            ),
                        ));
                    }
                }
            }
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.challenges"),
                    "`challenges` must be an array of challenge names",
                ))
            }
        }

        let policy = match object.get("policy") {
            None | Some(Value::Null) => AcmePolicy::default(),
            Some(Value::Object(policy)) => parse_policy(policy, &format!("{path}.policy"))?,
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.policy"),
                    "`policy` must be an object",
                ))
            }
        };

        let sign_with_root = match object.get("sign_with_root") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => {
                return Err(invalid(
                    &format!("{path}.sign_with_root"),
                    "`sign_with_root` must be a boolean",
                ))
            }
        };

        Ok(Self {
            ca,
            lifetime,
            host,
            path_prefix,
            policy,
            sign_with_root,
        })
    }

    fn effective_lifetime(&self) -> Duration {
        self.lifetime.clamp(MIN_LIFETIME, MAX_LIFETIME)
    }
}

fn parse_policy(object: &Map<String, Value>, path: &str) -> Result<AcmePolicy> {
    for field in object.keys() {
        match field.as_str() {
            "allow" | "deny" | "allow_wildcard_names" => {}
            other => {
                return Err(invalid(
                    path,
                    format!(
                        "unknown acme_server policy field `{other}` (supported: allow, deny, \
                         allow_wildcard_names)"
                    ),
                ))
            }
        }
    }
    let allow = match object.get("allow") {
        None | Some(Value::Null) => None,
        Some(Value::Object(rules)) => Some(parse_rule_set(rules, &format!("{path}.allow"))?),
        Some(_) => {
            return Err(invalid(
                &format!("{path}.allow"),
                "`allow` must be an object",
            ))
        }
    };
    let deny = match object.get("deny") {
        None | Some(Value::Null) => None,
        Some(Value::Object(rules)) => Some(parse_rule_set(rules, &format!("{path}.deny"))?),
        Some(_) => return Err(invalid(&format!("{path}.deny"), "`deny` must be an object")),
    };
    let allow_wildcard_names = match object.get("allow_wildcard_names") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => {
            return Err(invalid(
                &format!("{path}.allow_wildcard_names"),
                "`allow_wildcard_names` must be a boolean",
            ))
        }
    };
    Ok(AcmePolicy {
        allow,
        deny,
        allow_wildcard_names,
    })
}

fn parse_rule_set(object: &Map<String, Value>, path: &str) -> Result<RuleSet> {
    let mut rules = RuleSet::default();
    for (field, value) in object {
        match field.as_str() {
            "domains" => {
                let domains = value.as_array().ok_or_else(|| {
                    invalid(&format!("{path}.domains"), "`domains` must be an array")
                })?;
                for (index, domain) in domains.iter().enumerate() {
                    let domain = domain.as_str().ok_or_else(|| {
                        invalid(
                            &format!("{path}.domains[{index}]"),
                            "domain rules must be strings",
                        )
                    })?;
                    let constraint = DomainConstraint::parse(domain)
                        .map_err(|reason| invalid(&format!("{path}.domains[{index}]"), reason))?;
                    rules.domains.push(constraint);
                }
            }
            "ip_ranges" => {
                let ranges = value.as_array().ok_or_else(|| {
                    invalid(&format!("{path}.ip_ranges"), "`ip_ranges` must be an array")
                })?;
                for (index, range) in ranges.iter().enumerate() {
                    let range = range.as_str().ok_or_else(|| {
                        invalid(
                            &format!("{path}.ip_ranges[{index}]"),
                            "IP range rules must be strings",
                        )
                    })?;
                    rules
                        .ip_ranges
                        .push(IpRange::parse(range).map_err(|reason| {
                            invalid(&format!("{path}.ip_ranges[{index}]"), reason)
                        })?);
                }
            }
            other => {
                return Err(invalid(
                    path,
                    format!("unknown policy rule field `{other}` (supported: domains, ip_ranges)"),
                ))
            }
        }
    }
    Ok(rules)
}

/// Parse a Caddy/Go duration string (`12h`, `7d`, `1h30m`, ...).
fn parse_duration(text: &str) -> Option<Duration> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut rest = text;
    let mut total = Duration::ZERO;
    let mut parsed_any = false;
    while !rest.is_empty() {
        let digits = rest
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(rest.len());
        if digits == 0 {
            return None;
        }
        let value: f64 = rest[..digits].parse().ok()?;
        if !value.is_finite() || value < 0.0 {
            return None;
        }
        rest = &rest[digits..];
        let unit_end = rest
            .find(|character: char| character.is_ascii_digit() || character == '.')
            .unwrap_or(rest.len());
        let unit = &rest[..unit_end];
        rest = &rest[unit_end..];
        let multiplier = match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 60.0 * 60.0,
            "d" => 24.0 * 60.0 * 60.0,
            _ => return None,
        };
        let seconds = value * multiplier;
        if seconds > u64::MAX as f64 {
            return None;
        }
        total = total.checked_add(Duration::from_secs_f64(seconds))?;
        parsed_any = true;
    }
    parsed_any.then_some(total)
}

fn invalid(path: &str, message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        path: path.to_string(),
        message: message.into(),
    }
}

// ---- domain constraint matching --------------------------------------------------------------

fn reverse_labels(domain: &str) -> Option<Vec<&str>> {
    if domain.is_empty() || domain.contains("..") {
        return None;
    }
    Some(domain.rsplit('.').collect())
}

// ---- identifiers and wire objects ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Identifier {
    kind: String,
    value: String,
}

impl Identifier {
    fn is_wildcard(&self) -> bool {
        self.kind == "dns" && self.value.starts_with("*.")
    }

    fn json(&self) -> Value {
        json!({"type": self.kind, "value": self.value})
    }
}

#[derive(Debug, Clone)]
struct Account {
    id: String,
    key: Jwk,
    thumbprint: String,
    contact: Vec<String>,
    status: String,
}

impl Account {
    fn url(&self, base: &str) -> String {
        format!("{base}/account/{}", self.id)
    }

    fn is_valid(&self) -> bool {
        self.status == "valid"
    }
}

#[derive(Debug, Clone)]
struct Challenge {
    id: String,
    challenge_type: String,
    token: String,
    status: String,
    validated: Option<SystemTime>,
    error: Option<Problem>,
}

#[derive(Debug, Clone)]
struct Authorization {
    id: String,
    account_id: String,
    identifier: Identifier,
    wildcard: bool,
    status: String,
    expires: SystemTime,
    challenges: Vec<Challenge>,
}

#[derive(Debug, Clone)]
struct Order {
    id: String,
    account_id: String,
    identifiers: Vec<Identifier>,
    status: String,
    expires: SystemTime,
    not_before: SystemTime,
    not_after: SystemTime,
    authorization_ids: Vec<String>,
    error: Option<Problem>,
    certificate_pem: Option<Vec<u8>>,
    leaf_der: Option<Vec<u8>>,
    revoked: bool,
}

// ---- bounded stores --------------------------------------------------------------------------

/// A map with a hard capacity; inserting a new key beyond the bound evicts the oldest entry.
///
/// ACME state is client-driven, so every collection in this module is bounded: a hostile client
/// cannot grow the server's memory without bound. Eviction is FIFO; an evicted account/order
/// behaves like an unknown resource (`accountDoesNotExist`/404).
struct BoundedMap<K: Eq + Hash + Clone, V> {
    capacity: usize,
    entries: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Eq + Hash + Clone, V> BoundedMap<K, V> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        if !self.entries.contains_key(&key) {
            while self.entries.len() >= self.capacity {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.entries.remove(&oldest);
            }
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, value)
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.values()
    }
}

/// Single-use ACME nonces with a FIFO bound.
struct NonceStore {
    nonces: VecDeque<String>,
}

impl NonceStore {
    fn new() -> Self {
        Self {
            nonces: VecDeque::new(),
        }
    }

    fn issue(&mut self) -> std::result::Result<String, Problem> {
        if self.nonces.len() >= MAX_NONCES {
            self.nonces.pop_front();
        }
        let nonce = random_token(16, "nonce")?;
        self.nonces.push_back(nonce.clone());
        Ok(nonce)
    }

    /// Consume `nonce` if it is live. Comparison is constant time and a match removes the entry,
    /// so a nonce can never be replayed.
    fn consume(&mut self, nonce: &str) -> bool {
        let position = self
            .nonces
            .iter()
            .position(|candidate| constant_time_equals(candidate.as_bytes(), nonce.as_bytes()));
        match position {
            Some(index) => {
                self.nonces.remove(index);
                true
            }
            None => false,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.nonces.len()
    }
}

struct Inner {
    nonces: NonceStore,
    accounts: BoundedMap<String, Account>,
    orders: BoundedMap<String, Order>,
    authorizations: BoundedMap<String, Authorization>,
}

struct State {
    inner: Mutex<Inner>,
}

impl State {
    fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                nonces: NonceStore::new(),
                accounts: BoundedMap::new(MAX_ACCOUNTS),
                orders: BoundedMap::new(MAX_ORDERS),
                authorizations: BoundedMap::new(MAX_AUTHORIZATIONS),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn issue_nonce(&self) -> std::result::Result<String, Problem> {
        self.lock().nonces.issue()
    }

    fn consume_nonce(&self, nonce: &str) -> bool {
        self.lock().nonces.consume(nonce)
    }

    fn account_by_thumbprint(&self, thumbprint: &str) -> Option<Account> {
        self.lock().accounts.get(&thumbprint.to_string()).cloned()
    }

    fn account_by_id(&self, id: &str) -> Option<Account> {
        self.lock()
            .accounts
            .values()
            .find(|account| account.id == id)
            .cloned()
    }

    fn insert_account(&self, account: Account) {
        self.lock()
            .accounts
            .insert(account.thumbprint.clone(), account);
    }

    fn update_account(&self, account: Account) {
        self.lock()
            .accounts
            .insert(account.thumbprint.clone(), account);
    }

    fn authorization(&self, id: &str) -> Option<Authorization> {
        self.lock().authorizations.get(&id.to_string()).cloned()
    }

    fn insert_order(&self, order: Order, authorizations: Vec<Authorization>) {
        let mut inner = self.lock();
        for authorization in authorizations {
            inner
                .authorizations
                .insert(authorization.id.clone(), authorization);
        }
        inner.orders.insert(order.id.clone(), order);
    }

    fn orders_for_account(&self, account_id: &str) -> Vec<String> {
        self.lock()
            .orders
            .values()
            .filter(|order| order.account_id == account_id)
            .map(|order| order.id.clone())
            .collect()
    }

    /// Recompute and persist an authorization's status (`pending` -> `valid`/`invalid`).
    fn refresh_authorization(&self, id: &str) -> Option<Authorization> {
        let mut inner = self.lock();
        let authorization = inner.authorizations.get(&id.to_string()).cloned()?;
        let updated = refresh_authorization_status(authorization, SystemTime::now());
        inner
            .authorizations
            .insert(updated.id.clone(), updated.clone());
        Some(updated)
    }

    /// Recompute and persist an order's status from its authorizations.
    fn refresh_order(&self, id: &str) -> Option<Order> {
        let mut inner = self.lock();
        let order = inner.orders.get(&id.to_string()).cloned()?;
        let now = SystemTime::now();
        if order.status == "valid" || order.status == "invalid" {
            return Some(order);
        }
        let status;
        if now > order.expires {
            status = "invalid";
        } else {
            let mut any_pending = false;
            let mut any_invalid = false;
            for authorization_id in &order.authorization_ids {
                let Some(authorization) = inner.authorizations.get(authorization_id).cloned()
                else {
                    any_invalid = true;
                    continue;
                };
                let refreshed = refresh_authorization_status(authorization, now);
                if refreshed.status != "pending" {
                    inner
                        .authorizations
                        .insert(refreshed.id.clone(), refreshed.clone());
                }
                match refreshed.status.as_str() {
                    "valid" => {}
                    "pending" => any_pending = true,
                    _ => any_invalid = true,
                }
            }
            status = if any_invalid {
                "invalid"
            } else if any_pending {
                "pending"
            } else {
                "ready"
            };
        }
        let mut updated = order;
        updated.status = status.to_string();
        if status == "invalid" && updated.error.is_none() {
            updated.error = Some(Problem::malformed("order has expired"));
        }
        inner.orders.insert(updated.id.clone(), updated.clone());
        Some(updated)
    }

    /// Store the result of one challenge validation and refresh the owning authorization.
    fn record_challenge_result(
        &self,
        authorization_id: &str,
        challenge_id: &str,
        result: ChallengeResult,
    ) -> Option<Authorization> {
        let mut inner = self.lock();
        let mut authorization = inner
            .authorizations
            .get(&authorization_id.to_string())?
            .clone();
        let challenge = authorization
            .challenges
            .iter_mut()
            .find(|challenge| challenge.id == challenge_id)?;
        // A concurrent request may have completed this challenge already; keep the first result.
        if challenge.status == "pending" {
            match result {
                ChallengeResult::Failed(error) => {
                    challenge.error = Some(error);
                }
                ChallengeResult::Validated => {
                    challenge.status = "valid".to_string();
                    challenge.validated = Some(SystemTime::now());
                    challenge.error = None;
                }
                ChallengeResult::Invalid(error) => {
                    challenge.status = "invalid".to_string();
                    challenge.error = Some(error);
                }
            }
        }
        let refreshed = refresh_authorization_status(authorization, SystemTime::now());
        inner
            .authorizations
            .insert(refreshed.id.clone(), refreshed.clone());
        Some(refreshed)
    }

    fn complete_order(
        &self,
        id: &str,
        certificate_pem: Vec<u8>,
        leaf_der: Vec<u8>,
    ) -> Option<Order> {
        let mut inner = self.lock();
        let mut order = inner.orders.get(&id.to_string())?.clone();
        order.status = "valid".to_string();
        order.certificate_pem = Some(certificate_pem);
        order.leaf_der = Some(leaf_der);
        order.error = None;
        inner.orders.insert(order.id.clone(), order.clone());
        Some(order)
    }

    fn revoke_order(&self, id: &str) -> Option<Order> {
        let mut inner = self.lock();
        let mut order = inner.orders.get(&id.to_string())?.clone();
        order.revoked = true;
        inner.orders.insert(order.id.clone(), order.clone());
        Some(order)
    }

    /// Find the order whose issued leaf is exactly `leaf_der`.
    fn order_for_leaf(&self, leaf_der: &[u8]) -> Option<Order> {
        self.lock()
            .orders
            .values()
            .find(|order| order.leaf_der.as_deref() == Some(leaf_der))
            .cloned()
    }

    #[cfg(test)]
    fn nonce_count(&self) -> usize {
        self.lock().nonces.len()
    }
}

fn refresh_authorization_status(
    mut authorization: Authorization,
    now: SystemTime,
) -> Authorization {
    match authorization.status.as_str() {
        "valid" | "invalid" => authorization,
        _ => {
            if now > authorization.expires {
                authorization.status = "invalid".to_string();
            } else if authorization
                .challenges
                .iter()
                .any(|challenge| challenge.status == "valid")
            {
                authorization.status = "valid".to_string();
            }
            authorization
        }
    }
}

enum ChallengeResult {
    /// The validation target could not be reached or returned an error status. The challenge
    /// stays `pending` so the client may retry (smallstep's `storeError(markInvalid=false)`).
    Failed(Problem),
    /// The expected key authorization was served; the challenge becomes `valid`.
    Validated,
    /// The target answered but with the wrong key authorization; the challenge becomes `invalid`.
    Invalid(Problem),
}

// ---- http-01 transport -----------------------------------------------------------------------

/// One response to an http-01 validation GET.
#[derive(Debug, Clone)]
pub struct Http01Fetch {
    /// HTTP status code.
    pub status: u16,
    /// Response body (bounded by the transport).
    pub body: Vec<u8>,
}

/// Transport used to validate http-01 challenges.
///
/// Production uses [`HyperHttp01Transport`]; tests inject a scripted implementation so validation
/// logic can be exercised deterministically without binding port 80.
#[async_trait]
pub trait Http01Transport: Send + Sync {
    /// Fetch `url`, returning the status and a bounded body.
    async fn fetch(&self, url: &str) -> std::result::Result<Http01Fetch, String>;
}

/// Real http-01 validation transport: a hyper HTTP/1 client with a timeout and a body cap.
pub struct HyperHttp01Transport {
    client: Client<HttpConnector, Full<Bytes>>,
}

impl Default for HyperHttp01Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperHttp01Transport {
    /// Build the transport.
    pub fn new() -> Self {
        let connector = HttpConnector::new();
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
        }
    }
}

#[async_trait]
impl Http01Transport for HyperHttp01Transport {
    async fn fetch(&self, url: &str) -> std::result::Result<Http01Fetch, String> {
        let uri: http::Uri = url
            .parse()
            .map_err(|error| format!("invalid challenge URL `{url}`: {error}"))?;
        let request = http::Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::USER_AGENT, "caddy-rs-acme-server")
            .body(Full::new(Bytes::new()))
            .map_err(|error| format!("cannot build challenge request: {error}"))?;
        let future = async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|error| format!("http GET failed: {error}"))?;
            let status = response.status().as_u16();
            let mut body = response.into_body();
            let mut data = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|error| format!("reading body failed: {error}"))?;
                if let Some(chunk) = frame.data_ref() {
                    if data.len() + chunk.len() > MAX_CHALLENGE_BODY {
                        return Err(format!(
                            "challenge response body exceeds {MAX_CHALLENGE_BODY} bytes"
                        ));
                    }
                    data.extend_from_slice(chunk);
                }
            }
            Ok(Http01Fetch { status, body: data })
        };
        match tokio::time::timeout(HTTP01_TIMEOUT, future).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "challenge request timed out after {}s",
                HTTP01_TIMEOUT.as_secs()
            )),
        }
    }
}

// ---- handler ---------------------------------------------------------------------------------

/// The `http.handlers.acme_server` handler.
pub struct AcmeServerHandler {
    config: Arc<AcmeServerConfig>,
    issuer: Arc<InternalIssuer>,
    transport: Arc<dyn Http01Transport>,
    state: Arc<State>,
}

impl std::fmt::Debug for AcmeServerHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcmeServerHandler")
            .field("ca", &self.config.ca)
            .field("lifetime", &self.config.lifetime)
            .field("path_prefix", &self.config.path_prefix)
            .field("sign_with_root", &self.config.sign_with_root)
            .field(
                "allow_wildcard_names",
                &self.config.policy.allow_wildcard_names,
            )
            .finish_non_exhaustive()
    }
}

/// External origin (`scheme://host`) advertised in the URLs for one request.
struct ExternalOrigin {
    scheme: &'static str,
    host: String,
}

/// Read one forwarded header, rejecting duplicate field lines.
///
/// A duplicated `X-Forwarded-*` header has no safe "first value" interpretation (a proxy may
/// append while a client prepends), so it is a malformed request rather than a guess.
fn forwarded_header(
    request: &Request,
    name: &'static str,
) -> std::result::Result<Option<String>, Problem> {
    let header_name = HeaderName::from_static(name);
    let mut values = request.headers.get_all(&header_name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Problem::malformed(format!(
            "multiple `{name}` headers are not allowed; refusing to guess the external URL"
        )));
    }
    let value = value.to_str().map_err(|_| {
        Problem::malformed(format!(
            "`{name}` is not valid visible ASCII; refusing to construct an external URL from it"
        ))
    })?;
    Ok(Some(value.to_string()))
}

/// Parse `X-Forwarded-Proto`: exactly `http` or `https`, case-insensitively and with surrounding
/// ASCII whitespace ignored. Lists (`https,http`) and every other scheme are malformed.
fn parse_forwarded_scheme(raw: &str) -> std::result::Result<&'static str, Problem> {
    let scheme = raw.trim_matches(|character: char| character.is_ascii_whitespace());
    if scheme.eq_ignore_ascii_case("https") {
        Ok("https")
    } else if scheme.eq_ignore_ascii_case("http") {
        Ok("http")
    } else {
        Err(Problem::malformed(
            "`X-Forwarded-Proto` must be exactly `http` or `https`",
        ))
    }
}

/// Validate a `host` or `host:port` authority and return it unchanged.
///
/// This deliberately accepts a narrow grammar: ASCII letters, digits, `.`, `-`, `_`, and a single
/// trailing numeric port; IPv6 literals only in brackets. Scheme separators, paths, queries,
/// fragments, userinfo, whitespace, control bytes, commas/lists and percent-encoding are all
/// rejected, so the value cannot smuggle a second authority or a URL component into the origin.
fn parse_external_host(raw: &str, source: &str) -> std::result::Result<String, Problem> {
    let invalid = |reason: &str| {
        Problem::malformed(format!(
            "`{source}` is not a valid host or host:port ({reason}); refusing to construct an \
             external URL from it"
        ))
    };
    if raw.is_empty() {
        return Err(invalid("empty value"));
    }
    if raw.len() > MAX_EXTERNAL_HOST_LEN {
        return Err(invalid("value is longer than the allowed maximum"));
    }
    if !raw.is_ascii() {
        return Err(invalid("value is not ASCII"));
    }
    if raw
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(invalid("value contains whitespace or a control character"));
    }

    if let Some(rest) = raw.strip_prefix('[') {
        let Some((address, after)) = rest.split_once(']') else {
            return Err(invalid("unterminated IPv6 literal"));
        };
        if address.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid("invalid IPv6 literal"));
        }
        if after.is_empty() {
            return Ok(raw.to_string());
        }
        let Some(port) = after.strip_prefix(':') else {
            return Err(invalid("unexpected characters after the IPv6 literal"));
        };
        if !valid_port(port) {
            return Err(invalid("port is not a decimal number in 0..=65535"));
        }
        return Ok(raw.to_string());
    }
    if raw.contains('[') || raw.contains(']') {
        return Err(invalid("brackets are only allowed around an IPv6 literal"));
    }

    let mut parts = raw.split(':');
    let host = parts.next().unwrap_or_default();
    let port = parts.next();
    if parts.next().is_some() {
        return Err(invalid("IPv6 literals must be bracketed"));
    }
    if let Some(port) = port {
        if !valid_port(port) {
            return Err(invalid("port is not a decimal number in 0..=65535"));
        }
    }
    if host.is_empty() {
        return Err(invalid("empty host"));
    }
    if host.len() > 253 {
        return Err(invalid("host is longer than 253 bytes"));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(invalid("empty host label"));
        }
        if label.len() > 63 {
            return Err(invalid("host label is longer than 63 bytes"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid("host label begins or ends with `-`"));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(invalid("host contains a character that is not allowed"));
        }
    }
    Ok(raw.to_string())
}

/// Whether `port` is a non-empty decimal `u16`.
fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

/// Scheme of the connection that reached this handler (not the client-facing scheme).
fn connection_scheme(request: &Request) -> &'static str {
    if request.tls {
        "https"
    } else {
        "http"
    }
}

/// The request's own authority (`Host`, else the URI authority), validated like a forwarded host.
fn request_authority(request: &Request) -> std::result::Result<String, Problem> {
    let host = request.host().ok_or_else(|| {
        Problem::malformed(
            "request has no Host header or URI authority; cannot construct the external ACME URL",
        )
    })?;
    parse_external_host(host, "Host")
}

impl AcmeServerHandler {
    /// Build the handler from its Caddy JSON, persisting CA material under `data_root`
    /// (`<data_root>/pki/authorities/<ca>/...`).
    pub fn from_json(value: &Value, path: &str, data_root: &Path) -> Result<Self> {
        let config = AcmeServerConfig::from_json(value, path)?;
        let issuer = InternalIssuer::from_data_directory(data_root).with_name(config.ca.clone());
        Ok(Self::new(
            Arc::new(config),
            Arc::new(issuer),
            Arc::new(HyperHttp01Transport::new()),
        ))
    }

    /// Build the handler with an injected issuer and http-01 transport (tests and embedders).
    ///
    /// This is the same construction path [`Self::from_json`] uses after creating the internal
    /// issuer; no validation is skipped.
    pub fn from_json_with(
        value: &Value,
        path: &str,
        issuer: Arc<InternalIssuer>,
        transport: Arc<dyn Http01Transport>,
    ) -> Result<Self> {
        let config = AcmeServerConfig::from_json(value, path)?;
        Ok(Self::new(Arc::new(config), issuer, transport))
    }

    fn new(
        config: Arc<AcmeServerConfig>,
        issuer: Arc<InternalIssuer>,
        transport: Arc<dyn Http01Transport>,
    ) -> Self {
        Self {
            config,
            issuer,
            transport,
            state: Arc::new(State::new()),
        }
    }

    /// Directory URL for this handler and request base.
    fn directory_url(&self, base: &str) -> String {
        format!("{base}/directory")
    }

    /// Resolve the external origin (`scheme` and `host`) for one request.
    ///
    /// Direct requests keep the historical behaviour: `https` plus the request `Host` (or the
    /// configured `host`), byte-identical to the URLs this handler produced before forwarded
    /// headers were honoured. `X-Forwarded-Proto` / `X-Forwarded-Host` are used only when the
    /// server's trusted-proxy policy sets `trusted_proxy=true` for the peer (the same signal
    /// `reverse_proxy` and `forward_auth` consume). Without that signal the headers are parsed and
    /// validated (a malformed value is still a loud `malformed` problem) but valid values never
    /// influence the origin, so an arbitrary client cannot choose the external URL.
    ///
    /// Security note: a forwarded origin changes only the strings this handler advertises and
    /// compares in the JWS protected `url` header. It does not affect routing, account or order
    /// ownership, certificate identifiers, or the `http-01` fetch target (which is built from the
    /// identifier alone). Because [`Self::request_url`] resolves the origin with this same
    /// function, a trusted proxy that forwards a *client-supplied* `X-Forwarded-Host` makes the
    /// binding self-consistent for that client: the client can sign the host it supplied, so the
    /// binding still proves possession of the account key and knowledge of the endpoint path, but
    /// it no longer proves the request was addressed to the proxy's canonical hostname. The trust
    /// gate, not the JWS binding, is the security boundary for that property.
    fn external_origin(&self, request: &Request) -> std::result::Result<ExternalOrigin, Problem> {
        let forwarded_proto = forwarded_header(request, FORWARDED_PROTO_HEADER)?;
        let forwarded_host = forwarded_header(request, FORWARDED_HOST_HEADER)?;
        let forwarded_scheme = forwarded_proto
            .as_deref()
            .map(parse_forwarded_scheme)
            .transpose()?;
        let forwarded_host = forwarded_host
            .as_deref()
            .map(|host| parse_external_host(host, "X-Forwarded-Host"))
            .transpose()?;

        let trusted = request
            .vars
            .get(TRUSTED_PROXY_VAR)
            .is_some_and(|value| value == "true");
        let use_forwarded = trusted && (forwarded_scheme.is_some() || forwarded_host.is_some());
        let scheme = if use_forwarded {
            forwarded_scheme.unwrap_or_else(|| connection_scheme(request))
        } else {
            // The pre-T-TLS-086 direct path always advertised `https`, including on plain HTTP
            // listeners; T-TLS-086 must not change those URLs.
            "https"
        };
        let host = match (&self.config.host, use_forwarded, forwarded_host) {
            // An operator-configured `host` is authoritative, as it was before this change.
            (Some(configured), _, _) => configured.clone(),
            (None, true, Some(forwarded_host)) => forwarded_host,
            // HTTP/2 carries the authority on the URI, not always as a `Host` header; `host()`
            // checks both, like Caddy's `r.Host`.
            _ => request_authority(request)?,
        };
        Ok(ExternalOrigin { scheme, host })
    }

    /// `<scheme>://<host>/<prefix>/<ca>`, using the external origin for this request.
    fn base_url(&self, request: &Request) -> std::result::Result<String, Problem> {
        let origin = self.external_origin(request)?;
        let prefix = self.config.path_prefix.trim_matches('/');
        let base = if prefix.is_empty() {
            format!("{}://{}/{}", origin.scheme, origin.host, self.config.ca)
        } else {
            format!(
                "{}://{}/{prefix}/{}",
                origin.scheme, origin.host, self.config.ca
            )
        };
        Ok(base)
    }

    /// URL the JWS protected `url` header must equal.
    ///
    /// Built from the same external origin as [`Self::base_url`] (ignoring the query string), so
    /// forwarding `X-Forwarded-Proto` / `X-Forwarded-Host` changes what the client must sign
    /// rather than letting it bypass the binding check.
    fn request_url(&self, request: &Request) -> std::result::Result<String, Problem> {
        let origin = self.external_origin(request)?;
        Ok(format!(
            "{}://{}{}",
            origin.scheme,
            origin.host,
            request.uri.path()
        ))
    }

    async fn serve(&self, request: &Request) -> Response {
        let method = request.method.clone();
        let route = self.route(request);
        // Every endpoint except the directory and new-nonce is POST-only (smallstep's chi routes).
        // Gate before resolving the request host or parsing a body/JWS so a wrong method gets
        // Caddy's 405 + Allow, not a malformed-request or missing-Host error.
        if !matches!(route, Route::Unknown | Route::Directory | Route::NewNonce)
            && method != Method::POST
        {
            return method_not_allowed(&[Method::POST]);
        }
        let base = match self.base_url(request) {
            Ok(base) => base,
            Err(problem) => return self.problem_response(problem, None),
        };
        match route {
            Route::Unknown => self.problem_response(
                Problem::not_found(format!("no ACME resource at `{}`", request.uri.path())),
                Some(&base),
            ),
            Route::Directory => {
                if method != Method::GET && method != Method::HEAD {
                    return method_not_allowed(&[Method::GET, Method::HEAD]);
                }
                let mut response = Response::bytes(
                    StatusCode::OK,
                    "application/json",
                    serde_json::to_vec(&self.directory_document(&base)).unwrap_or_default(),
                );
                if method == Method::HEAD {
                    response.body = Bytes::new();
                }
                response
            }
            Route::NewNonce => {
                if method != Method::GET && method != Method::HEAD {
                    return method_not_allowed(&[Method::GET, Method::HEAD]);
                }
                let status = if method == Method::HEAD {
                    StatusCode::OK
                } else {
                    StatusCode::NO_CONTENT
                };
                let response = Response {
                    status,
                    headers: HeaderMap::new(),
                    body: Bytes::new(),
                };
                self.decorate(response, &self.directory_url(&base))
            }
            Route::NewAccount => self.new_account(request, &base).await,
            Route::NewOrder => self.new_order(request, &base).await,
            Route::KeyChange => self.key_change(request, &base).await,
            Route::RevokeCert => self.revoke_cert(request, &base).await,
            Route::Account(id) => self.account(request, &base, &id).await,
            Route::OrdersByAccount(id) => self.orders_by_account(request, &base, &id).await,
            Route::Order(id) => self.order(request, &base, &id).await,
            Route::Finalize(id) => self.finalize(request, &base, &id).await,
            Route::Authorization(id) => self.authorization(request, &base, &id).await,
            Route::Challenge(authz, challenge) => {
                self.challenge(request, &base, &authz, &challenge).await
            }
            Route::Certificate(id) => self.certificate(request, &base, &id).await,
        }
    }

    fn route(&self, request: &Request) -> Route {
        let path = request.uri.path();
        let Some(suffix) = path.strip_prefix(&self.config.path_prefix) else {
            return Route::Unknown;
        };
        let mut segments = suffix.split('/');
        let Some(ca) = segments.next() else {
            return Route::Unknown;
        };
        if ca != self.config.ca {
            return Route::Unknown;
        }
        let Some(endpoint) = segments.next() else {
            return Route::Unknown;
        };
        let id = segments.next();
        let extra = segments.next();
        // Anything beyond the known path shape is not an ACME resource.
        if segments.any(|segment| !segment.is_empty()) {
            return Route::Unknown;
        }
        let has_extra = extra.is_some_and(|segment| !segment.is_empty());
        match (endpoint, id, has_extra) {
            ("directory", None, _) => Route::Directory,
            ("new-nonce", None, _) => Route::NewNonce,
            ("new-account", None, _) => Route::NewAccount,
            ("new-order", None, _) => Route::NewOrder,
            ("key-change", None, _) => Route::KeyChange,
            ("revoke-cert", None, _) => Route::RevokeCert,
            ("account", Some(id), false) => Route::Account(id.to_string()),
            ("account", Some(id), true) if extra == Some("orders") => {
                Route::OrdersByAccount(id.to_string())
            }
            ("order", Some(id), false) => Route::Order(id.to_string()),
            ("order", Some(id), true) if extra == Some("finalize") => {
                Route::Finalize(id.to_string())
            }
            ("authz", Some(id), false) => Route::Authorization(id.to_string()),
            ("challenge", Some(authz), true) => match extra {
                Some(challenge) if !challenge.is_empty() => {
                    Route::Challenge(authz.to_string(), challenge.to_string())
                }
                _ => Route::Unknown,
            },
            ("certificate", Some(id), false) => Route::Certificate(id.to_string()),
            _ => Route::Unknown,
        }
    }

    fn directory_document(&self, base: &str) -> Value {
        // Caddy/smallstep omit `meta` entirely when the ACME provisioner configures none of the
        // meta properties (ToS, website, CAA identities, EAB).
        json!({
            "newNonce": format!("{base}/new-nonce"),
            "newAccount": format!("{base}/new-account"),
            "newOrder": format!("{base}/new-order"),
            "revokeCert": format!("{base}/revoke-cert"),
            "keyChange": format!("{base}/key-change"),
        })
    }

    fn decorate(&self, mut response: Response, directory: &str) -> Response {
        if let Ok(nonce) = self.state.issue_nonce() {
            if let Ok(value) = HeaderValue::from_str(&nonce) {
                response.headers.insert(replay_nonce_header(), value);
            }
        }
        response
            .headers
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Ok(value) = HeaderValue::from_str(&format!("<{directory}>;rel=\"index\"")) {
            response.headers.append(header::LINK, value);
        }
        response
    }

    fn problem_response(&self, problem: Problem, directory: Option<&str>) -> Response {
        let body = serde_json::to_vec(&problem.json()).unwrap_or_default();
        let mut response = Response::bytes(problem.status, "application/problem+json", body);
        if let Some(directory) = directory {
            response = self.decorate(response, directory);
        }
        response
    }

    fn json_response(
        &self,
        status: StatusCode,
        value: &Value,
        directory: Option<&str>,
        headers: &[(HeaderName, String)],
    ) -> Response {
        let body = serde_json::to_vec(value).unwrap_or_default();
        let mut response = Response::bytes(status, "application/json", body);
        for (name, value) in headers {
            if let Ok(value) = HeaderValue::from_str(value) {
                response.headers.append(name.clone(), value);
            }
        }
        if let Some(directory) = directory {
            response = self.decorate(response, directory);
        }
        response
    }

    // ---- JWS ---------------------------------------------------------------------------------

    fn parse_jws(&self, request: &Request) -> std::result::Result<ParsedJws, Problem> {
        let content_type = request
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if content_type.trim() != "application/jose+json" {
            return Err(Problem::malformed(format!(
                "expected content-type to be application/jose+json, but got `{content_type}`"
            )));
        }
        if request.body.len() > MAX_JWS_BODY {
            return Err(Problem::malformed(format!(
                "JWS request body exceeds the {MAX_JWS_BODY}-byte limit"
            )));
        }
        let body: Value = serde_json::from_slice(&request.body)
            .map_err(|error| Problem::malformed(format!("failed to parse JWS: {error}")))?;
        let object = body
            .as_object()
            .ok_or_else(|| Problem::malformed("request body must be a flattened JWS object"))?;
        if object.contains_key("header") || object.contains_key("signatures") {
            return Err(Problem::malformed(
                "JWS must not use an unprotected header or the general JSON serialization",
            ));
        }
        let protected_b64 = object
            .get("protected")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed("JWS is missing the `protected` field"))?;
        let payload_b64 = object
            .get("payload")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed("JWS is missing the `payload` field"))?;
        let signature_b64 = object
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed("JWS is missing the `signature` field"))?;
        let protected_bytes = decode_base64url(protected_b64)
            .ok_or_else(|| Problem::malformed("JWS `protected` is not valid base64url"))?;
        let expected_url = self.request_url(request)?;
        if protected_bytes.len() > MAX_JWS_BODY {
            return Err(Problem::malformed("JWS protected header is too large"));
        }
        let protected: Value = serde_json::from_slice(&protected_bytes)
            .map_err(|error| Problem::malformed(format!("failed to parse JWS header: {error}")))?;
        let protected = protected
            .as_object()
            .ok_or_else(|| Problem::malformed("JWS protected header must be an object"))?;

        let algorithm = protected
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed("JWS protected header is missing `alg`"))?;
        match algorithm {
            "RS256" | "ES256" => {}
            other => {
                return Err(Problem::bad_signature_algorithm(format!(
                    "unsuitable algorithm: {other} (supported: RS256, ES256)"
                )))
            }
        }

        let nonce = protected
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::bad_nonce("JWS protected header is missing `nonce`"))?;
        if !self.state.consume_nonce(nonce) {
            return Err(Problem::bad_nonce(format!(
                "nonce `{nonce}` not found (unknown, already used, or evicted)"
            )));
        }

        let url = protected
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed("jws missing url protected header"))?;
        if url != expected_url {
            return Err(Problem::malformed(format!(
                "url header in JWS ({url}) does not match request url ({expected_url})"
            )));
        }

        let kid = protected.get("kid").and_then(Value::as_str);
        let jwk = match protected.get("jwk") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                serde_json::from_value::<Jwk>(value.clone())
                    .map_err(|error| Problem::malformed(format!("invalid jwk: {error}")))?,
            ),
        };
        if kid.is_some() && jwk.is_some() {
            return Err(Problem::malformed(
                "jwk and kid are mutually exclusive in the JWS protected header",
            ));
        }
        if kid.is_none() && jwk.is_none() {
            return Err(Problem::malformed(
                "either jwk or kid must be defined in the JWS protected header",
            ));
        }
        if let Some(jwk) = &jwk {
            check_key_matches_algorithm(algorithm, jwk)?;
        }

        let payload = decode_base64url(payload_b64)
            .ok_or_else(|| Problem::malformed("JWS `payload` is not valid base64url"))?;
        let signature = decode_base64url(signature_b64)
            .ok_or_else(|| Problem::malformed("JWS `signature` is not valid base64url"))?;

        Ok(ParsedJws {
            algorithm: algorithm.to_string(),
            kid: kid.map(str::to_string),
            jwk,
            signing_input: format!("{protected_b64}.{payload_b64}").into_bytes(),
            signature,
            payload,
        })
    }

    fn verify(&self, request: &Request, base: &str) -> std::result::Result<VerifiedJws, Problem> {
        let parsed = self.parse_jws(request)?;
        let (key, account) = match (&parsed.jwk, &parsed.kid) {
            (Some(jwk), None) => (jwk.clone(), None),
            (None, Some(kid)) => {
                let account_id = kid.rsplit('/').next().unwrap_or_default();
                let account = self.state.account_by_id(account_id).ok_or_else(|| {
                    Problem::account_does_not_exist(format!(
                        "account with ID `{account_id}` not found"
                    ))
                })?;
                if !account.is_valid() {
                    return Err(Problem::unauthorized("account is not active"));
                }
                let expected = account.url(base);
                if kid != &expected {
                    return Err(Problem::unauthorized(format!(
                        "kid does not match stored account location; expected {expected}, but got \
                         {kid}"
                    )));
                }
                (account.key.clone(), Some(account))
            }
            _ => {
                return Err(Problem::malformed(
                    "exactly one of jwk or kid must be present in the JWS protected header",
                ))
            }
        };
        check_key_matches_algorithm(&parsed.algorithm, &key)?;
        verify_jws_signature(
            &parsed.algorithm,
            &key,
            &parsed.signing_input,
            &parsed.signature,
        )?;
        Ok(VerifiedJws {
            payload: parsed.payload,
            key,
            account,
            kid: parsed.kid,
        })
    }

    fn verify_account(
        &self,
        request: &Request,
        base: &str,
    ) -> std::result::Result<(VerifiedJws, Account), Problem> {
        let verified = self.verify(request, base)?;
        let account = verified
            .account
            .clone()
            .ok_or_else(|| Problem::malformed("signature missing 'kid'"))?;
        Ok((verified, account))
    }

    // ---- account endpoints -------------------------------------------------------------------

    async fn new_account(&self, request: &Request, base: &str) -> Response {
        let directory = self.directory_url(base);
        let verified = match self.verify(request, base) {
            Ok(verified) => verified,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        if verified.kid.is_some() {
            return self.problem_response(
                Problem::malformed("jwk expected in protected header for new-account"),
                Some(&directory),
            );
        }
        let payload = match payload_object(&verified.payload, "new-account", true) {
            Ok(payload) => payload,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let contact = match parse_contact(&payload) {
            Ok(contact) => contact,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let only_return_existing = payload
            .get("onlyReturnExisting")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if only_return_existing && !contact.is_empty() {
            return self.problem_response(
                Problem::malformed("incompatible input; onlyReturnExisting must be alone"),
                Some(&directory),
            );
        }
        let thumbprint = match verified.key.thumbprint() {
            Ok(thumbprint) => thumbprint,
            Err(error) => {
                return self.problem_response(
                    Problem::malformed(format!("invalid jwk in protected header: {error}")),
                    Some(&directory),
                )
            }
        };
        if let Some(account) = self.state.account_by_thumbprint(&thumbprint) {
            let location = account.url(base);
            return self.json_response(
                StatusCode::OK,
                &account_json(&account, base),
                Some(&directory),
                &[(header::LOCATION, location)],
            );
        }
        if only_return_existing {
            return self.problem_response(
                Problem::account_does_not_exist("account does not exist"),
                Some(&directory),
            );
        }
        let id = match random_token(16, "account id") {
            Ok(id) => id,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let account = Account {
            id,
            key: verified.key.clone(),
            thumbprint,
            contact,
            status: "valid".to_string(),
        };
        self.state.insert_account(account.clone());
        let location = account.url(base);
        self.json_response(
            StatusCode::CREATED,
            &account_json(&account, base),
            Some(&directory),
            &[(header::LOCATION, location)],
        )
    }

    async fn account(&self, request: &Request, base: &str, id: &str) -> Response {
        let directory = self.directory_url(base);
        let (verified, account) = match self.verify_account(request, base) {
            Ok(result) => result,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        if account.id != id {
            return self.problem_response(
                Problem::unauthorized(format!(
                    "account `{}` does not match the requested account `{id}`",
                    account.id
                )),
                Some(&directory),
            );
        }
        let mut account = account;
        if !verified.payload.is_empty() {
            let payload = match payload_object(&verified.payload, "account update", false) {
                Ok(payload) => payload,
                Err(problem) => return self.problem_response(problem, Some(&directory)),
            };
            let contact = match parse_contact(&payload) {
                Ok(contact) => contact,
                Err(problem) => return self.problem_response(problem, Some(&directory)),
            };
            let status = payload.get("status").and_then(Value::as_str);
            if status.is_some() && !contact.is_empty() {
                return self.problem_response(
                    Problem::malformed(
                        "incompatible input; contact and status updates are mutually exclusive",
                    ),
                    Some(&directory),
                );
            }
            if let Some(status) = status {
                if status != "deactivated" {
                    return self.problem_response(
                        Problem::malformed(format!(
                            "cannot update account status to `{status}`, only `deactivated`"
                        )),
                        Some(&directory),
                    );
                }
                account.status = "deactivated".to_string();
            }
            if !contact.is_empty() {
                account.contact = contact;
            }
            self.state.update_account(account.clone());
        }
        let location = account.url(base);
        self.json_response(
            StatusCode::OK,
            &account_json(&account, base),
            Some(&directory),
            &[(header::LOCATION, location)],
        )
    }

    async fn orders_by_account(&self, request: &Request, base: &str, id: &str) -> Response {
        let directory = self.directory_url(base);
        let (verified, account) = match self.verify_account(request, base) {
            Ok(result) => result,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        if account.id != id {
            return self.problem_response(
                Problem::unauthorized(format!(
                    "account `{}` does not match the requested account `{id}`",
                    account.id
                )),
                Some(&directory),
            );
        }
        if let Err(problem) = expect_post_as_get(&verified.payload, "orders list") {
            return self.problem_response(problem, Some(&directory));
        }
        let urls: Vec<String> = self
            .state
            .orders_for_account(&account.id)
            .into_iter()
            .map(|id| format!("{base}/order/{id}"))
            .collect();
        self.json_response(StatusCode::OK, &json!(urls), Some(&directory), &[])
    }

    // ---- order endpoints ---------------------------------------------------------------------

    async fn new_order(&self, request: &Request, base: &str) -> Response {
        let directory = self.directory_url(base);
        let (verified, account) = match self.verify_account(request, base) {
            Ok(result) => result,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let payload = match payload_object(&verified.payload, "new-order", true) {
            Ok(payload) => payload,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let has_timing = ["notBefore", "notAfter"]
            .iter()
            .any(|field| payload.get(*field).is_some_and(|value| !value.is_null()));
        if has_timing {
            return self.problem_response(
                Problem::malformed(
                    "new-order notBefore/notAfter are not supported by this build; remove the \
                     fields instead of relying on a no-op",
                ),
                Some(&directory),
            );
        }
        let identifiers = match payload.get("identifiers").and_then(Value::as_array) {
            Some(identifiers) if !identifiers.is_empty() => identifiers,
            _ => {
                return self.problem_response(
                    Problem::malformed("identifiers list cannot be empty"),
                    Some(&directory),
                )
            }
        };
        if identifiers.len() > MAX_IDENTIFIERS {
            return self.problem_response(
                Problem::malformed(format!(
                    "too many identifiers: {} (limit {MAX_IDENTIFIERS})",
                    identifiers.len()
                )),
                Some(&directory),
            );
        }
        let mut normalized = Vec::with_capacity(identifiers.len());
        for (index, identifier) in identifiers.iter().enumerate() {
            let identifier = match self.normalize_identifier(identifier, index) {
                Ok(identifier) => identifier,
                Err(problem) => return self.problem_response(problem, Some(&directory)),
            };
            normalized.push(identifier);
        }

        let now = SystemTime::now();
        let expires = now + ORDER_LIFETIME;
        let not_before = now.checked_sub(ORDER_BACKDATE).unwrap_or(now);
        let not_after = now + self.config.effective_lifetime();
        let order_id = match random_token(16, "order id") {
            Ok(id) => id,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let mut authorizations = Vec::with_capacity(normalized.len());
        let mut authorization_ids = Vec::with_capacity(normalized.len());
        for identifier in &normalized {
            let authorization_id = match random_token(16, "authorization id") {
                Ok(id) => id,
                Err(problem) => return self.problem_response(problem, Some(&directory)),
            };
            let challenge_id = match random_token(16, "challenge id") {
                Ok(id) => id,
                Err(problem) => return self.problem_response(problem, Some(&directory)),
            };
            let token = match random_token(32, "challenge token") {
                Ok(token) => token,
                Err(problem) => return self.problem_response(problem, Some(&directory)),
            };
            let wildcard = identifier.is_wildcard();
            let authorization_identifier = if wildcard {
                Identifier {
                    kind: identifier.kind.clone(),
                    value: identifier
                        .value
                        .strip_prefix("*.")
                        .unwrap_or(&identifier.value)
                        .to_string(),
                }
            } else {
                identifier.clone()
            };
            authorizations.push(Authorization {
                id: authorization_id.clone(),
                account_id: account.id.clone(),
                identifier: authorization_identifier,
                wildcard,
                status: "pending".to_string(),
                expires,
                challenges: vec![Challenge {
                    id: challenge_id,
                    challenge_type: "http-01".to_string(),
                    token,
                    status: "pending".to_string(),
                    validated: None,
                    error: None,
                }],
            });
            authorization_ids.push(authorization_id);
        }
        let order = Order {
            id: order_id,
            account_id: account.id.clone(),
            identifiers: normalized,
            status: "pending".to_string(),
            expires,
            not_before,
            not_after,
            authorization_ids,
            error: None,
            certificate_pem: None,
            leaf_der: None,
            revoked: false,
        };
        self.state.insert_order(order.clone(), authorizations);
        let location = format!("{base}/order/{}", order.id);
        self.json_response(
            StatusCode::CREATED,
            &order_json(&order, base),
            Some(&directory),
            &[(header::LOCATION, location)],
        )
    }

    fn normalize_identifier(
        &self,
        value: &Value,
        index: usize,
    ) -> std::result::Result<Identifier, Problem> {
        let object = value
            .as_object()
            .ok_or_else(|| Problem::malformed(format!("identifier {index} must be an object")))?;
        let kind = object
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed(format!("identifier {index} is missing `type`")))?;
        let value = object
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed(format!("identifier {index} is missing `value`")))?;
        let identifier = match kind {
            "dns" => {
                let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
                validate_dns_name(&value)?;
                Identifier {
                    kind: "dns".to_string(),
                    value,
                }
            }
            "ip" => {
                let address: IpAddr = value
                    .trim()
                    .parse()
                    .map_err(|_| Problem::malformed(format!("invalid IP address: {value}")))?;
                Identifier {
                    kind: "ip".to_string(),
                    value: address.to_string(),
                }
            }
            other => {
                return Err(Problem::malformed(format!(
                    "identifier type unsupported: {other} (supported: dns, ip)"
                )))
            }
        };
        self.check_policy(&identifier)?;
        Ok(identifier)
    }

    fn check_policy(&self, identifier: &Identifier) -> std::result::Result<(), Problem> {
        let policy = &self.config.policy;
        if identifier.is_wildcard() {
            if !policy.allow_wildcard_names {
                return Err(Problem::rejected_identifier(format!(
                    "not authorized: wildcard name `{}` is not allowed by the ACME server policy \
                     (allow_wildcard_names is false)",
                    identifier.value
                )));
            }
            return Err(Problem::rejected_identifier(format!(
                "not authorized: wildcard identifier `{}` requires the dns-01 challenge, which \
                 this build does not implement",
                identifier.value
            )));
        }
        if let Some(deny) = &policy.deny {
            let denied = match identifier.kind.as_str() {
                "dns" => deny.allows_dns(&identifier.value),
                "ip" => identifier
                    .value
                    .parse::<IpAddr>()
                    .map(|address| deny.allows_ip(address))
                    .unwrap_or(false),
                _ => false,
            };
            if denied {
                return Err(Problem::rejected_identifier(format!(
                    "not authorized: identifier `{}` is denied by the ACME server policy",
                    identifier.value
                )));
            }
        }
        if let Some(allow) = &policy.allow {
            if !allow.is_empty() {
                match identifier.kind.as_str() {
                    "dns" if allow.domains.is_empty() => {
                        return Err(Problem::rejected_identifier(format!(
                            "not authorized: dns name `{}` is not explicitly permitted by the ACME \
                             server policy",
                            identifier.value
                        )))
                    }
                    "ip" if allow.ip_ranges.is_empty() => {
                        return Err(Problem::rejected_identifier(format!(
                            "not authorized: ip identifier `{}` is not explicitly permitted by \
                             the ACME server policy",
                            identifier.value
                        )))
                    }
                    "dns" if !allow.allows_dns(&identifier.value) => {
                        return Err(Problem::rejected_identifier(format!(
                            "not authorized: dns name `{}` is not permitted by the ACME server \
                             policy",
                            identifier.value
                        )))
                    }
                    "ip" => {
                        let permitted = identifier
                            .value
                            .parse::<IpAddr>()
                            .map(|address| allow.allows_ip(address))
                            .unwrap_or(false);
                        if !permitted {
                            return Err(Problem::rejected_identifier(format!(
                                "not authorized: ip identifier `{}` is not permitted by the ACME \
                                 server policy",
                                identifier.value
                            )));
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    async fn order(&self, request: &Request, base: &str, id: &str) -> Response {
        let directory = self.directory_url(base);
        let (verified, account) = match self.verify_account(request, base) {
            Ok(result) => result,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        if let Err(problem) = expect_post_as_get(&verified.payload, "order") {
            return self.problem_response(problem, Some(&directory));
        }
        let Some(order) = self.state.refresh_order(id) else {
            return self.problem_response(
                Problem::not_found(format!("order `{id}` not found")),
                Some(&directory),
            );
        };
        if order.account_id != account.id {
            return self.problem_response(
                Problem::unauthorized(format!(
                    "account `{}` does not own order `{id}`",
                    account.id
                )),
                Some(&directory),
            );
        }
        let location = format!("{base}/order/{id}");
        self.json_response(
            StatusCode::OK,
            &order_json(&order, base),
            Some(&directory),
            &[(header::LOCATION, location)],
        )
    }

    async fn finalize(&self, request: &Request, base: &str, id: &str) -> Response {
        let directory = self.directory_url(base);
        let (verified, account) = match self.verify_account(request, base) {
            Ok(result) => result,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let payload = match payload_object(&verified.payload, "finalize", true) {
            Ok(payload) => payload,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let csr = payload
            .get("csr")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed("finalize request is missing `csr`"));
        let csr = match csr {
            Ok(csr) => csr,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let csr_der = match decode_base64url(csr) {
            Some(csr) => csr,
            None => {
                return self.problem_response(
                    Problem::malformed("error base64url decoding csr"),
                    Some(&directory),
                )
            }
        };
        if csr_der.len() > MAX_CSR_DER_BYTES {
            return self.problem_response(
                Problem::bad_csr(format!(
                    "CSR is {} bytes, exceeding the {MAX_CSR_DER_BYTES}-byte limit",
                    csr_der.len()
                )),
                Some(&directory),
            );
        }
        let Some(order) = self.state.refresh_order(id) else {
            return self.problem_response(
                Problem::not_found(format!("order `{id}` not found")),
                Some(&directory),
            );
        };
        if order.account_id != account.id {
            return self.problem_response(
                Problem::unauthorized(format!(
                    "account `{}` does not own order `{id}`",
                    account.id
                )),
                Some(&directory),
            );
        }
        match order.status.as_str() {
            "valid" => {
                let location = format!("{base}/order/{id}");
                return self.json_response(
                    StatusCode::OK,
                    &order_json(&order, base),
                    Some(&directory),
                    &[(header::LOCATION, location)],
                );
            }
            "invalid" => {
                return self.problem_response(
                    Problem::order_not_ready(format!("order {id} has been abandoned")),
                    Some(&directory),
                )
            }
            "pending" => {
                return self.problem_response(
                    Problem::order_not_ready(format!("order {id} is not ready")),
                    Some(&directory),
                )
            }
            "ready" => {}
            other => {
                return self.problem_response(
                    Problem::server_internal(format!("unexpected order status `{other}`")),
                    Some(&directory),
                )
            }
        }

        let parsed = match parse_csr(&csr_der) {
            Ok(parsed) => parsed,
            Err(error) => {
                return self.problem_response(
                    Problem::malformed(format!("unable to parse or verify csr: {error}")),
                    Some(&directory),
                )
            }
        };
        if parsed.unsupported_names {
            return self.problem_response(
                Problem::bad_csr("Only DNS names and IP addresses are allowed"),
                Some(&directory),
            );
        }
        let mut order_names: Vec<String> = order
            .identifiers
            .iter()
            .map(|identifier| identifier.value.clone())
            .collect();
        order_names.sort();
        order_names.dedup();
        let mut csr_names = parsed.names.clone();
        csr_names.sort();
        csr_names.dedup();
        if csr_names != order_names {
            return self.problem_response(
                Problem::bad_csr(format!(
                    "CSR names do not match identifiers exactly: CSR names = {csr_names:?}, Order \
                     names = {order_names:?}"
                )),
                Some(&directory),
            );
        }

        let certificate_names: Vec<String> = order
            .identifiers
            .iter()
            .map(|identifier| identifier.value.clone())
            .collect();
        let signed = match self
            .issuer
            .sign_external_spki_with(
                &parsed.spki_der,
                &certificate_names,
                self.config.effective_lifetime(),
                self.config.sign_with_root,
            )
            .await
        {
            Ok(signed) => signed,
            Err(_) => {
                return self.problem_response(
                    Problem::server_internal(
                        "the internal CA could not issue a certificate for this order",
                    ),
                    Some(&directory),
                )
            }
        };
        let pem = pem_chain(&signed.leaf_der, &signed.chain_der);
        let Some(order) =
            self.state
                .complete_order(&order.id, pem.into_bytes(), signed.leaf_der.clone())
        else {
            return self.problem_response(
                Problem::server_internal("the order disappeared while it was being finalized"),
                Some(&directory),
            );
        };
        let location = format!("{base}/order/{id}");
        self.json_response(
            StatusCode::OK,
            &order_json(&order, base),
            Some(&directory),
            &[(header::LOCATION, location)],
        )
    }

    async fn certificate(&self, request: &Request, base: &str, id: &str) -> Response {
        let directory = self.directory_url(base);
        let (verified, account) = match self.verify_account(request, base) {
            Ok(result) => result,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        if let Err(problem) = expect_post_as_get(&verified.payload, "certificate") {
            return self.problem_response(problem, Some(&directory));
        }
        let Some(order) = self.state.refresh_order(id) else {
            return self.problem_response(
                Problem::not_found(format!("certificate `{id}` not found")),
                Some(&directory),
            );
        };
        if order.account_id != account.id {
            return self.problem_response(
                Problem::unauthorized(format!(
                    "account `{}` does not own certificate `{id}`",
                    account.id
                )),
                Some(&directory),
            );
        }
        let Some(pem) = order.certificate_pem else {
            return self.problem_response(
                Problem::order_not_ready(format!("order {id} has no certificate yet")),
                Some(&directory),
            );
        };
        let response = Response::bytes(StatusCode::OK, "application/pem-certificate-chain", pem);
        self.decorate(response, &directory)
    }

    // ---- authorization and challenge ---------------------------------------------------------

    async fn authorization(&self, request: &Request, base: &str, id: &str) -> Response {
        let directory = self.directory_url(base);
        let (verified, account) = match self.verify_account(request, base) {
            Ok(result) => result,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        if let Err(problem) = expect_post_as_get(&verified.payload, "authorization") {
            return self.problem_response(problem, Some(&directory));
        }
        let Some(authorization) = self.state.refresh_authorization(id) else {
            return self.problem_response(
                Problem::not_found(format!("authorization `{id}` not found")),
                Some(&directory),
            );
        };
        if authorization.account_id != account.id {
            return self.problem_response(
                Problem::unauthorized(format!(
                    "account `{}` does not own authorization `{id}`",
                    account.id
                )),
                Some(&directory),
            );
        }
        let location = format!("{base}/authz/{id}");
        self.json_response(
            StatusCode::OK,
            &authorization_json(&authorization, base),
            Some(&directory),
            &[(header::LOCATION, location)],
        )
    }

    async fn challenge(
        &self,
        request: &Request,
        base: &str,
        authorization_id: &str,
        challenge_id: &str,
    ) -> Response {
        let directory = self.directory_url(base);
        let (_verified, account) = match self.verify_account(request, base) {
            Ok(result) => result,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let Some(authorization) = self.state.authorization(authorization_id) else {
            return self.problem_response(
                Problem::not_found(format!("authorization `{authorization_id}` not found")),
                Some(&directory),
            );
        };
        if authorization.account_id != account.id {
            return self.problem_response(
                Problem::unauthorized(format!(
                    "account `{}` does not own challenge `{challenge_id}`",
                    account.id
                )),
                Some(&directory),
            );
        }
        let Some(challenge) = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.id == challenge_id)
        else {
            return self.problem_response(
                Problem::not_found(format!("challenge `{challenge_id}` not found")),
                Some(&directory),
            );
        };
        let authorization = if challenge.status == "pending" {
            match self
                .validate_http01(authorization_id, challenge_id, &account)
                .await
            {
                Some(authorization) => authorization,
                None => {
                    return self.problem_response(
                        Problem::not_found(format!("challenge `{challenge_id}` not found")),
                        Some(&directory),
                    )
                }
            }
        } else {
            authorization
        };
        let Some(challenge) = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.id == challenge_id)
        else {
            return self.problem_response(
                Problem::not_found(format!("challenge `{challenge_id}` not found")),
                Some(&directory),
            );
        };
        let location = format!("{base}/challenge/{authorization_id}/{challenge_id}");
        let up = format!("<{base}/authz/{authorization_id}>;rel=\"up\"");
        self.json_response(
            StatusCode::OK,
            &challenge_json(&authorization, challenge, base),
            Some(&directory),
            &[(header::LOCATION, location), (header::LINK, up)],
        )
    }

    /// Perform the real http-01 check and record its result.
    async fn validate_http01(
        &self,
        authorization_id: &str,
        challenge_id: &str,
        account: &Account,
    ) -> Option<Authorization> {
        let authorization = self.state.authorization(authorization_id)?;
        let challenge = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.id == challenge_id)?;
        let expected = key_authorization(&challenge.token, &account.thumbprint);
        let host = challenge_host(&authorization.identifier.value);
        let url = format!(
            "http://{host}/.well-known/acme-challenge/{}",
            challenge.token
        );
        let result = match self.transport.fetch(&url).await {
            Err(reason) => ChallengeResult::Failed(Problem::connection(format!(
                "error doing http GET for url {url}: {reason}"
            ))),
            Ok(fetch) if !(200..300).contains(&fetch.status) => {
                ChallengeResult::Failed(Problem::connection(format!(
                    "error doing http GET for url {url} with status code {}",
                    fetch.status
                )))
            }
            Ok(fetch) => {
                let body = String::from_utf8_lossy(&fetch.body);
                if constant_time_equals(body.trim().as_bytes(), expected.as_bytes()) {
                    ChallengeResult::Validated
                } else {
                    ChallengeResult::Invalid(Problem::rejected_identifier(
                        "keyAuthorization does not match",
                    ))
                }
            }
        };
        self.state
            .record_challenge_result(authorization_id, challenge_id, result)
    }

    // ---- revocation and key rollover ---------------------------------------------------------

    async fn revoke_cert(&self, request: &Request, base: &str) -> Response {
        let directory = self.directory_url(base);
        let verified = match self.verify(request, base) {
            Ok(verified) => verified,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let payload = match payload_object(&verified.payload, "revoke-cert", true) {
            Ok(payload) => payload,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let certificate = payload
            .get("certificate")
            .and_then(Value::as_str)
            .ok_or_else(|| Problem::malformed("revoke-cert request is missing `certificate`"));
        let certificate = match certificate {
            Ok(certificate) => certificate,
            Err(problem) => return self.problem_response(problem, Some(&directory)),
        };
        let leaf_der = match decode_base64url(certificate) {
            Some(leaf_der) => leaf_der,
            None => {
                return self.problem_response(
                    Problem::malformed("error base64url decoding payload certificate property"),
                    Some(&directory),
                )
            }
        };
        let Some(order) = self.state.order_for_leaf(&leaf_der) else {
            return self.problem_response(
                Problem::not_found("certificate was not issued by this ACME server"),
                Some(&directory),
            );
        };
        match &verified.account {
            Some(account) => {
                if order.account_id != account.id {
                    return self.problem_response(
                        Problem::forbidden(format!(
                            "account `{}` is not authorized to revoke this certificate",
                            account.id
                        )),
                        Some(&directory),
                    );
                }
            }
            None => {
                return self.problem_response(
                    Problem::forbidden(
                        "revocation signed with the certificate key is not supported by this \
                         build; sign the request with the issuing account key",
                    ),
                    Some(&directory),
                )
            }
        }
        if order.revoked {
            return self.problem_response(
                Problem::already_revoked("certificate was already revoked"),
                Some(&directory),
            );
        }
        if let Some(reason) = payload.get("reason") {
            let reason = reason.as_i64().unwrap_or(-1);
            if !(0..=10).contains(&reason) || reason == 7 {
                return self.problem_response(
                    Problem::bad_revocation_reason("reasonCode out of bounds"),
                    Some(&directory),
                );
            }
        }
        if self.state.revoke_order(&order.id).is_none() {
            return self.problem_response(
                Problem::not_found("certificate was not issued by this ACME server"),
                Some(&directory),
            );
        }
        self.decorate(
            Response {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: Bytes::new(),
            },
            &directory,
        )
    }

    async fn key_change(&self, request: &Request, base: &str) -> Response {
        let directory = self.directory_url(base);
        // Caddy routes key-change through the same `kid` lookup and then returns 501
        // (smallstep's `NotImplemented`), so the account/URL contract is still enforced.
        if let Err(problem) = self.verify_account(request, base) {
            return self.problem_response(problem, Some(&directory));
        }
        self.problem_response(
            Problem::not_implemented("this API is not implemented"),
            Some(&directory),
        )
    }
}

fn method_not_allowed(allowed: &[Method]) -> Response {
    let mut response = Response {
        status: StatusCode::METHOD_NOT_ALLOWED,
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    for method in allowed {
        if let Ok(value) = HeaderValue::from_str(method.as_str()) {
            response.headers.append(header::ALLOW, value);
        }
    }
    response
}

fn account_json(account: &Account, base: &str) -> Value {
    let mut object = Map::new();
    object.insert("status".to_string(), json!(account.status));
    if !account.contact.is_empty() {
        object.insert("contact".to_string(), json!(account.contact));
    }
    object.insert(
        "orders".to_string(),
        json!(format!("{base}/account/{}/orders", account.id)),
    );
    Value::Object(object)
}

fn order_json(order: &Order, base: &str) -> Value {
    let mut object = Map::new();
    object.insert("id".to_string(), json!(order.id));
    object.insert("status".to_string(), json!(order.status));
    object.insert("expires".to_string(), json!(rfc3339(order.expires)));
    object.insert(
        "identifiers".to_string(),
        Value::Array(order.identifiers.iter().map(Identifier::json).collect()),
    );
    object.insert("notBefore".to_string(), json!(rfc3339(order.not_before)));
    object.insert("notAfter".to_string(), json!(rfc3339(order.not_after)));
    if let Some(error) = &order.error {
        object.insert("error".to_string(), error.json());
    }
    object.insert(
        "authorizations".to_string(),
        json!(order
            .authorization_ids
            .iter()
            .map(|id| format!("{base}/authz/{id}"))
            .collect::<Vec<_>>()),
    );
    object.insert(
        "finalize".to_string(),
        json!(format!("{base}/order/{}/finalize", order.id)),
    );
    if order.status == "valid" {
        object.insert(
            "certificate".to_string(),
            json!(format!("{base}/certificate/{}", order.id)),
        );
    }
    Value::Object(object)
}

fn authorization_json(authorization: &Authorization, base: &str) -> Value {
    let mut object = Map::new();
    object.insert("identifier".to_string(), authorization.identifier.json());
    object.insert("status".to_string(), json!(authorization.status));
    object.insert(
        "challenges".to_string(),
        Value::Array(
            authorization
                .challenges
                .iter()
                .map(|challenge| challenge_json(authorization, challenge, base))
                .collect(),
        ),
    );
    object.insert("wildcard".to_string(), json!(authorization.wildcard));
    object.insert("expires".to_string(), json!(rfc3339(authorization.expires)));
    Value::Object(object)
}

fn challenge_json(authorization: &Authorization, challenge: &Challenge, base: &str) -> Value {
    let mut object = Map::new();
    object.insert("type".to_string(), json!(challenge.challenge_type));
    object.insert("status".to_string(), json!(challenge.status));
    object.insert("token".to_string(), json!(challenge.token));
    if let Some(validated) = challenge.validated {
        object.insert("validated".to_string(), json!(rfc3339(validated)));
    }
    object.insert(
        "url".to_string(),
        json!(format!(
            "{base}/challenge/{}/{}",
            authorization.id, challenge.id
        )),
    );
    if let Some(error) = &challenge.error {
        object.insert("error".to_string(), error.json());
    }
    Value::Object(object)
}

fn payload_object(
    payload: &[u8],
    endpoint: &str,
    required: bool,
) -> std::result::Result<Map<String, Value>, Problem> {
    if payload.is_empty() {
        if required {
            return Err(Problem::malformed(format!(
                "{endpoint} requires a JSON payload (POST-as-GET is not allowed here)"
            )));
        }
        return Ok(Map::new());
    }
    let value: Value = serde_json::from_slice(payload).map_err(|error| {
        Problem::malformed(format!("failed to unmarshal {endpoint} payload: {error}"))
    })?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| Problem::malformed(format!("{endpoint} payload must be a JSON object")))
}

fn expect_post_as_get(payload: &[u8], endpoint: &str) -> std::result::Result<(), Problem> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(Problem::malformed(format!(
            "expected POST-as-GET for {endpoint}"
        )))
    }
}

fn parse_contact(payload: &Map<String, Value>) -> std::result::Result<Vec<String>, Problem> {
    let Some(contact) = payload.get("contact").filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let contact = contact
        .as_array()
        .ok_or_else(|| Problem::malformed("`contact` must be an array of strings"))?;
    let mut values = Vec::with_capacity(contact.len());
    for value in contact {
        let value = value
            .as_str()
            .ok_or_else(|| Problem::malformed("`contact` entries must be strings"))?;
        if value.is_empty() {
            return Err(Problem::malformed("contact cannot be empty string"));
        }
        values.push(value.to_string());
    }
    Ok(values)
}

fn validate_dns_name(value: &str) -> std::result::Result<(), Problem> {
    // A wildcard identifier is only legal as the whole first label. The wildcard flag itself is
    // enforced by the policy, which rejects wildcard identifiers because they need dns-01.
    let (wildcard, base) = match value.strip_prefix("*.") {
        Some(base) => (true, base),
        None => (false, value),
    };
    if !wildcard && value.contains('*') {
        return Err(Problem::malformed(format!(
            "invalid DNS name: {value} (wildcard must be the whole first label)"
        )));
    }
    validate_rule_hostname(base, value).map_err(Problem::malformed)
}

fn challenge_host(value: &str) -> String {
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V6(address)) => format!("[{address}]"),
        _ => value.to_string(),
    }
}

fn pem_chain(leaf_der: &[u8], chain_der: &[Vec<u8>]) -> String {
    let mut pem = String::new();
    pem.push_str(&pem_encode("CERTIFICATE", leaf_der));
    for der in chain_der {
        pem.push_str(&pem_encode("CERTIFICATE", der));
    }
    pem
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
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

/// A parsed and structurally validated flattened JWS (not yet signature-verified).
struct ParsedJws {
    algorithm: String,
    kid: Option<String>,
    jwk: Option<Jwk>,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
    payload: Vec<u8>,
}

/// A JWS whose signature verified against an account key or an embedded JWK.
struct VerifiedJws {
    payload: Vec<u8>,
    key: Jwk,
    account: Option<Account>,
    kid: Option<String>,
}

enum Route {
    Unknown,
    Directory,
    NewNonce,
    NewAccount,
    NewOrder,
    KeyChange,
    RevokeCert,
    Account(String),
    OrdersByAccount(String),
    Order(String),
    Finalize(String),
    Authorization(String),
    Challenge(String, String),
    Certificate(String),
}

#[async_trait]
impl Handler for AcmeServerHandler {
    fn name(&self) -> &'static str {
        "acme_server"
    }

    fn requires_buffered_request_body(&self) -> bool {
        // The JWS body is collected by `handle_streaming` with `MAX_JWS_BODY` as its bound, so the
        // router (and therefore every other route in the same server) does not have to buffer
        // request bodies on this handler's behalf.
        false
    }

    fn consumes_request_body(&self) -> bool {
        true
    }

    async fn handle(&self, request: Request) -> Result<Outcome> {
        if !request.uri.path().starts_with(&self.config.path_prefix) {
            return Ok(Outcome::Continue(request));
        }
        Ok(Outcome::Respond(self.serve(&request).await))
    }

    async fn handle_streaming(&self, mut request: Request) -> Result<StreamingOutcome> {
        if !request.uri.path().starts_with(&self.config.path_prefix) {
            return Ok(StreamingOutcome::Continue(request));
        }
        let route = self.route(&request);
        let needs_body = !matches!(route, Route::Unknown | Route::Directory | Route::NewNonce);
        if needs_body {
            // Wrong-method responses must not depend on (or consume) a large request body.
            if request.method != Method::POST {
                return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                    method_not_allowed(&[Method::POST]),
                )));
            }
            let body = request.take_body();
            match body.collect(Some(MAX_JWS_BODY as u64)).await {
                Ok(bytes) => request.body = bytes,
                Err(BodyError::TooLarge { .. }) => {
                    let problem = Problem::malformed(format!(
                        "JWS request body exceeds the {MAX_JWS_BODY}-byte limit"
                    ));
                    let directory = self
                        .base_url(&request)
                        .ok()
                        .map(|base| self.directory_url(&base));
                    return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                        self.problem_response(problem, directory.as_deref()),
                    )));
                }
                Err(error) => {
                    let problem = Problem::malformed(format!(
                        "cannot read the request body for this ACME endpoint: {error}"
                    ));
                    let directory = self
                        .base_url(&request)
                        .ok()
                        .map(|base| self.directory_url(&base));
                    return Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
                        self.problem_response(problem, directory.as_deref()),
                    )));
                }
            }
        }
        Ok(StreamingOutcome::Respond(StreamingResponse::from_buffered(
            self.serve(&request).await,
        )))
    }
}

// ---- crypto helpers --------------------------------------------------------------------------

fn check_key_matches_algorithm(algorithm: &str, key: &Jwk) -> std::result::Result<(), Problem> {
    match algorithm {
        "ES256" => {
            if key.kty != "EC" || key.crv.as_deref() != Some("P-256") {
                return Err(Problem::malformed(
                    "jws key type and algorithm do not match (ES256 requires a P-256 key)",
                ));
            }
        }
        "RS256" => {
            if key.kty != "RSA" {
                return Err(Problem::malformed(
                    "jws key type and algorithm do not match (RS256 requires an RSA key)",
                ));
            }
            let modulus = key
                .n
                .as_deref()
                .and_then(decode_base64url)
                .ok_or_else(|| Problem::malformed("RSA jwk is missing `n`"))?;
            let modulus = strip_leading_zeros(&modulus);
            if modulus.len() < 256 {
                return Err(Problem::malformed(
                    "rsa keys must be at least 2048 bits (256 bytes) in size",
                ));
            }
        }
        _ => {
            return Err(Problem::bad_signature_algorithm(format!(
                "unsuitable algorithm: {algorithm}"
            )))
        }
    }
    Ok(())
}

fn verify_jws_signature(
    algorithm: &str,
    key: &Jwk,
    message: &[u8],
    signature: &[u8],
) -> std::result::Result<(), Problem> {
    let verified = match algorithm {
        "ES256" => {
            let x = key
                .x
                .as_deref()
                .and_then(decode_base64url)
                .ok_or_else(|| Problem::malformed("ES256 jwk is missing `x`"))?;
            let y = key
                .y
                .as_deref()
                .and_then(decode_base64url)
                .ok_or_else(|| Problem::malformed("ES256 jwk is missing `y`"))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(Problem::malformed("ES256 jwk coordinates must be 32 bytes"));
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                point,
            )
            .verify(message, signature)
            .is_ok()
        }
        "RS256" => {
            let modulus = key
                .n
                .as_deref()
                .and_then(decode_base64url)
                .ok_or_else(|| Problem::malformed("RSA jwk is missing `n`"))?;
            let exponent = key
                .e
                .as_deref()
                .and_then(decode_base64url)
                .ok_or_else(|| Problem::malformed("RSA jwk is missing `e`"))?;
            let modulus = strip_leading_zeros(&modulus);
            let exponent = strip_leading_zeros(&exponent);
            if modulus.len() < 256 {
                return Err(Problem::malformed(
                    "rsa keys must be at least 2048 bits (256 bytes) in size",
                ));
            }
            let public_key = rsa_public_key_der(&modulus, &exponent);
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                public_key,
            )
            .verify(message, signature)
            .is_ok()
        }
        other => {
            return Err(Problem::bad_signature_algorithm(format!(
                "unsuitable algorithm: {other}"
            )))
        }
    };
    if !verified {
        return Err(Problem::malformed("error verifying jws"));
    }
    Ok(())
}

fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    bytes[first..].to_vec()
}

/// DER-encode an RSA public key (`RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }`), which is
/// the key format ring's RSA verification expects.
fn rsa_public_key_der(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut content = der_integer(modulus);
    content.extend(der_integer(exponent));
    der_tlv(0x30, &content)
}

fn der_integer(content: &[u8]) -> Vec<u8> {
    let content = strip_leading_zeros(content);
    let mut value = content;
    if value.first().is_some_and(|first| first & 0x80 != 0) {
        let mut padded = Vec::with_capacity(value.len() + 1);
        padded.push(0);
        padded.extend_from_slice(&value);
        value = padded;
    }
    der_tlv(0x02, &value)
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(content.len() + 4);
    encoded.push(tag);
    if content.len() < 0x80 {
        encoded.push(content.len() as u8);
    } else {
        let mut bytes = content.len().to_be_bytes().to_vec();
        while bytes.first() == Some(&0) {
            bytes.remove(0);
        }
        encoded.push(0x80 | bytes.len() as u8);
        encoded.extend(bytes);
    }
    encoded.extend_from_slice(content);
    encoded
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    let value = value.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(value).ok()
}

fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    // Length is not secret (nonces and key authorizations have public lengths); the contents are
    // compared without an early exit so the comparison does not leak a matching prefix.
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn random_bytes(length: usize) -> std::result::Result<Vec<u8>, Problem> {
    let mut bytes = vec![0u8; length];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Problem::server_internal("random number generation failed"))?;
    Ok(bytes)
}

fn random_token(length: usize, purpose: &str) -> std::result::Result<String, Problem> {
    random_bytes(length)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| Problem::server_internal(format!("could not generate a random {purpose}")))
}

// ---- time formatting -------------------------------------------------------------------------

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// RFC 3339 UTC timestamp with second precision (what ACME clients expect).
fn rfc3339(time: SystemTime) -> String {
    let seconds = unix_seconds(time);
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = remainder / 3600;
    let minute = (remainder % 3600) / 60;
    let second = remainder % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats_epoch_and_known_instants() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            "2023-11-14T22:13:20Z"
        );
        // Leap-year day.
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_709_164_800)),
            "2024-02-29T00:00:00Z"
        );
    }

    #[test]
    fn duration_parser_accepts_caddy_durations() {
        assert_eq!(parse_duration("12h"), Some(Duration::from_secs(43_200)));
        assert_eq!(parse_duration("7d"), Some(Duration::from_secs(604_800)));
        assert_eq!(parse_duration("1h30m"), Some(Duration::from_secs(5_400)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("banana"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn domain_constraints_match_exact_names_and_one_label_wildcards() {
        let exact = DomainConstraint::parse("example.com").expect("exact rule");
        assert!(exact.matches("example.com"));
        assert!(exact.matches("EXAMPLE.COM"));
        assert!(!exact.matches("www.example.com"));
        assert!(!exact.matches("other.com"));

        let wildcard = DomainConstraint::parse("*.example.com").expect("wildcard rule");
        assert!(wildcard.matches("a.example.com"));
        assert!(wildcard.matches("A.EXAMPLE.COM"));
        assert!(!wildcard.matches("a.b.example.com"));
        assert!(!wildcard.matches("example.com"));
        assert!(!wildcard.matches("other.com"));

        // Every unsupported spelling is a located error instead of a silently ineffective rule.
        for (rule, needle) in [
            (".example.com", "should start with *"),
            ("*example.com", "can only be used to match"),
            ("a*.example.com", "only have wildcard as starting character"),
            ("*", "is not a wildcard rule"),
            ("*.", "empty label"),
            ("*..example.com", "empty labels"),
            ("a..example.com", "empty labels"),
            ("_acme.example.com", "not allowed in a hostname"),
            ("-bad.example.com", "starting or ending with"),
            ("bad-.example.com", "starting or ending with"),
            ("münchen.example", "not ASCII"),
        ] {
            let error = DomainConstraint::parse(rule)
                .expect_err(&format!("`{rule}` must be rejected at load"));
            assert!(
                error.contains(needle),
                "`{rule}` error `{error}` must mention `{needle}`"
            );
        }
    }

    #[test]
    fn ip_ranges_support_cidr_and_single_addresses() {
        let network = IpRange::parse("10.0.0.0/8").unwrap();
        assert!(network.contains("10.1.2.3".parse().unwrap()));
        assert!(!network.contains("11.1.2.3".parse().unwrap()));
        let single = IpRange::parse("127.0.0.1").unwrap();
        assert!(single.contains("127.0.0.1".parse().unwrap()));
        assert!(!single.contains("127.0.0.2".parse().unwrap()));
        let v6 = IpRange::parse("::1/128").unwrap();
        assert!(v6.contains("::1".parse().unwrap()));
        assert!(IpRange::parse("10.0.0.0/33").is_err());
        assert!(IpRange::parse("not-an-ip").is_err());
    }

    // ---- test harness --------------------------------------------------------------------

    use caddy_rs_tls::acme::csr::CertificateRequest;
    use caddy_rs_tls::acme::sign_jws;
    use caddy_rs_tls::acme::AccountKeyType;
    use caddy_rs_tls::{AccountKey, MemoryAcmeStorage, MemoryStorage};

    const BASE: &str = "https://acme.test/acme/local";

    struct ScriptedTransport {
        body: Mutex<Option<String>>,
        status: u16,
        fail: bool,
        requests: Mutex<Vec<String>>,
    }

    impl ScriptedTransport {
        fn success() -> Arc<Self> {
            Arc::new(Self {
                body: Mutex::new(None),
                status: 200,
                fail: false,
                requests: Mutex::new(Vec::new()),
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                body: Mutex::new(None),
                status: 200,
                fail: true,
                requests: Mutex::new(Vec::new()),
            })
        }

        fn set_body(&self, body: impl Into<String>) {
            *self.body.lock().unwrap() = Some(body.into());
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Http01Transport for ScriptedTransport {
        async fn fetch(&self, url: &str) -> std::result::Result<Http01Fetch, String> {
            self.requests.lock().unwrap().push(url.to_string());
            if self.fail {
                return Err("connection refused".to_string());
            }
            Ok(Http01Fetch {
                status: self.status,
                body: self
                    .body
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_default()
                    .into_bytes(),
            })
        }
    }

    fn memory_issuer() -> Arc<InternalIssuer> {
        Arc::new(InternalIssuer::new(
            Arc::new(MemoryAcmeStorage::new()),
            Box::new(MemoryStorage::new()),
        ))
    }

    fn test_handler_with_issuer(
        transport: Arc<dyn Http01Transport>,
        config: Value,
    ) -> (AcmeServerHandler, Arc<InternalIssuer>) {
        let issuer = memory_issuer();
        let handler =
            AcmeServerHandler::from_json_with(&config, "test", Arc::clone(&issuer), transport)
                .expect("valid acme_server configuration");
        (handler, issuer)
    }

    fn test_handler(transport: Arc<dyn Http01Transport>, config: Value) -> AcmeServerHandler {
        test_handler_with_issuer(transport, config).0
    }

    fn request(method: Method, path: &str) -> Request {
        let uri = path.parse().expect("request URI");
        let mut request = Request::new(method, uri);
        request
            .headers
            .insert(header::HOST, HeaderValue::from_static("acme.test"));
        request
    }

    async fn send(handler: &AcmeServerHandler, request: Request) -> Response {
        match handler.handle(request).await.expect("handler serves") {
            Outcome::Respond(response) => response,
            Outcome::Continue(_) => panic!("ACME handler unexpectedly passed the request through"),
        }
    }

    async fn get(handler: &AcmeServerHandler, path: &str) -> Response {
        send(handler, request(Method::GET, path)).await
    }

    /// Build a request with an explicit `Host` and optional forwarded headers.
    fn forwarded_request(
        method: Method,
        path: &str,
        host: &str,
        forwarded_proto: Option<&str>,
        forwarded_host: Option<&str>,
        trusted: bool,
    ) -> Request {
        let mut request = request(method, path);
        request.headers.insert(
            header::HOST,
            host.parse::<HeaderValue>().expect("Host header value"),
        );
        if let Some(value) = forwarded_proto {
            request.headers.insert(
                HeaderName::from_static(FORWARDED_PROTO_HEADER),
                value
                    .parse::<HeaderValue>()
                    .expect("X-Forwarded-Proto value"),
            );
        }
        if let Some(value) = forwarded_host {
            request.headers.insert(
                HeaderName::from_static(FORWARDED_HOST_HEADER),
                value
                    .parse::<HeaderValue>()
                    .expect("X-Forwarded-Host value"),
            );
        }
        if trusted {
            request
                .vars
                .insert(TRUSTED_PROXY_VAR.to_string(), "true".to_string());
        }
        request
    }

    fn header_value(response: &Response, name: HeaderName) -> Option<String> {
        response
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }

    fn body_json(response: &Response) -> Value {
        serde_json::from_slice(&response.body).unwrap_or_else(|error| {
            panic!(
                "response body is not JSON ({error}): {}",
                String::from_utf8_lossy(&response.body)
            )
        })
    }

    fn body_text(response: &Response) -> String {
        String::from_utf8_lossy(&response.body).into_owned()
    }

    fn path_of(url: &str) -> String {
        let Some((_scheme, rest)) = url.split_once("://") else {
            panic!("unexpected URL {url}");
        };
        let Some(index) = rest.find('/') else {
            panic!("unexpected URL {url}");
        };
        let path = &rest[index..];
        assert!(path.starts_with("/acme/local"), "unexpected ACME URL {url}");
        path.to_string()
    }

    struct TestClient<'a> {
        handler: &'a AcmeServerHandler,
        key: AccountKey,
        kid: Option<String>,
        nonce: Option<String>,
        /// Origin the client was advertised and signs for.
        base: String,
        /// Host the client actually connects to (the listener behind a proxy).
        request_host: String,
        forwarded_proto: Option<String>,
        forwarded_host: Option<String>,
        trusted: bool,
    }

    impl<'a> TestClient<'a> {
        async fn new(handler: &'a AcmeServerHandler) -> Self {
            let mut client = Self {
                handler,
                key: AccountKey::generate().expect("account key"),
                kid: None,
                nonce: None,
                base: "https://acme.test".to_string(),
                request_host: "acme.test".to_string(),
                forwarded_proto: None,
                forwarded_host: None,
                trusted: false,
            };
            client.refresh_nonce().await;
            client
        }

        async fn with_key(handler: &'a AcmeServerHandler, key: AccountKey) -> Self {
            let mut client = Self {
                handler,
                key,
                kid: None,
                nonce: None,
                base: "https://acme.test".to_string(),
                request_host: "acme.test".to_string(),
                forwarded_proto: None,
                forwarded_host: None,
                trusted: false,
            };
            client.refresh_nonce().await;
            client
        }

        /// Make the client sign the given external origin while connecting to `request_host`.
        fn with_forwarded_origin(
            mut self,
            base: &str,
            request_host: &str,
            forwarded_proto: &str,
            forwarded_host: &str,
        ) -> Self {
            self.base = base.to_string();
            self.request_host = request_host.to_string();
            self.forwarded_proto = Some(forwarded_proto.to_string());
            self.forwarded_host = Some(forwarded_host.to_string());
            self.trusted = true;
            self
        }

        fn apply_origin(&self, request: &mut Request) {
            request.headers.insert(
                header::HOST,
                self.request_host.parse().expect("request Host"),
            );
            if let Some(value) = &self.forwarded_proto {
                request.headers.insert(
                    HeaderName::from_static(FORWARDED_PROTO_HEADER),
                    value.parse().expect("X-Forwarded-Proto"),
                );
            }
            if let Some(value) = &self.forwarded_host {
                request.headers.insert(
                    HeaderName::from_static(FORWARDED_HOST_HEADER),
                    value.parse().expect("X-Forwarded-Host"),
                );
            }
            if self.trusted {
                request
                    .vars
                    .insert(TRUSTED_PROXY_VAR.to_string(), "true".to_string());
            }
        }

        async fn refresh_nonce(&mut self) {
            let mut request = request(Method::GET, "/acme/local/new-nonce");
            self.apply_origin(&mut request);
            let response = send(self.handler, request).await;
            self.nonce = header_value(&response, replay_nonce_header());
            assert!(self.nonce.is_some(), "new-nonce must return Replay-Nonce");
        }

        fn thumbprint(&self) -> String {
            self.key.thumbprint().expect("jwk thumbprint")
        }

        fn jws_body(&mut self, path: &str, payload: &[u8]) -> String {
            let nonce = self.nonce.take().expect("a fresh nonce");
            sign_jws(
                &self.key,
                self.kid.as_deref(),
                Some(&nonce),
                &format!("{}{path}", self.base),
                payload,
            )
            .expect("sign JWS")
        }

        async fn post_raw(&mut self, path: &str, body: String) -> Response {
            let mut request = request(Method::POST, path);
            self.apply_origin(&mut request);
            request.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/jose+json"),
            );
            request.body = Bytes::from(body);
            let response = send(self.handler, request).await;
            self.nonce = header_value(&response, replay_nonce_header());
            response
        }

        async fn post(&mut self, path: &str, payload: &[u8]) -> Response {
            let body = self.jws_body(path, payload);
            self.post_raw(path, body).await
        }

        async fn post_json(&mut self, path: &str, value: &Value) -> Response {
            let payload = serde_json::to_vec(value).expect("payload JSON");
            self.post(path, &payload).await
        }

        async fn post_as_get(&mut self, path: &str) -> Response {
            self.post(path, &[]).await
        }

        async fn register(&mut self) -> Response {
            let response = self
                .post_json(
                    "/acme/local/new-account",
                    &json!({"termsOfServiceAgreed": true}),
                )
                .await;
            if let Some(location) = header_value(&response, header::LOCATION) {
                self.kid = Some(location);
            }
            response
        }

        async fn create_order(&mut self, identifiers: Value) -> (String, Value, Response) {
            let response = self
                .post_json(
                    "/acme/local/new-order",
                    &json!({"identifiers": identifiers}),
                )
                .await;
            let location = header_value(&response, header::LOCATION);
            let json = body_json(&response);
            (
                location.map(|url| path_of(&url)).unwrap_or_default(),
                json,
                response,
            )
        }

        async fn authorization(&mut self, order: &Value) -> (String, Value) {
            let url = order["authorizations"][0]
                .as_str()
                .expect("authorization URL");
            let path = path_of(url);
            let response = self.post_as_get(&path).await;
            assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
            let json = body_json(&response);
            (path, json)
        }

        async fn validate_challenge(&mut self, authorization: &Value) -> Response {
            let url = authorization["challenges"][0]["url"]
                .as_str()
                .expect("challenge URL");
            let path = path_of(url);
            self.post_json(&path, &json!({})).await
        }

        async fn finalize(&mut self, order_path: &str, csr: &CertificateRequest) -> Response {
            let csr = URL_SAFE_NO_PAD.encode(csr.der());
            self.post_json(&format!("{order_path}/finalize"), &json!({"csr": csr}))
                .await
        }
    }

    struct ReadyOrder {
        order_path: String,
        authorization_path: String,
        challenge_path: String,
    }

    /// Drive one order to `ready`: create it, serve the expected key authorization, validate the
    /// challenge and confirm the order transition.
    async fn ready_order(
        client: &mut TestClient<'_>,
        transport: &ScriptedTransport,
        domain: &str,
    ) -> ReadyOrder {
        let (order_path, order, response) = client
            .create_order(json!([{"type": "dns", "value": domain}]))
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{}",
            body_text(&response)
        );
        let (authorization_path, authorization) = client.authorization(&order).await;
        let challenge_url = authorization["challenges"][0]["url"]
            .as_str()
            .expect("challenge URL");
        let challenge_path = path_of(challenge_url);
        let token = authorization["challenges"][0]["token"]
            .as_str()
            .expect("challenge token");
        transport.set_body(format!("{token}.{}", client.thumbprint()));
        let response = client.validate_challenge(&authorization).await;
        assert_eq!(
            body_json(&response)["status"],
            "valid",
            "{}",
            body_text(&response)
        );
        let response = client.post_as_get(&order_path).await;
        assert_eq!(
            body_json(&response)["status"],
            "ready",
            "{}",
            body_text(&response)
        );
        ReadyOrder {
            order_path,
            authorization_path,
            challenge_path,
        }
    }

    struct IssuedFlow {
        order_path: String,
        authorization_path: String,
        challenge_path: String,
        certificate_path: String,
        certificate: Response,
        csr: CertificateRequest,
    }

    /// Complete an issuance and download the certificate.
    async fn issue_flow(
        client: &mut TestClient<'_>,
        transport: &ScriptedTransport,
        domain: &str,
    ) -> IssuedFlow {
        let ready = ready_order(client, transport, domain).await;
        let csr = CertificateRequest::generate(&[domain.to_string()]).unwrap();
        let response = client.finalize(&ready.order_path, &csr).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "finalize failed: {}",
            body_text(&response)
        );
        let order = body_json(&response);
        assert_eq!(order["status"], "valid");
        let certificate_url = order["certificate"]
            .as_str()
            .expect("certificate URL")
            .to_string();
        let certificate_path = path_of(&certificate_url);
        let certificate = client.post_as_get(&certificate_path).await;
        assert_eq!(
            certificate.status,
            StatusCode::OK,
            "{}",
            body_text(&certificate)
        );
        IssuedFlow {
            order_path: ready.order_path,
            authorization_path: ready.authorization_path,
            challenge_path: ready.challenge_path,
            certificate_path,
            certificate,
            csr,
        }
    }

    fn pem_blocks(pem: &[u8]) -> Vec<Vec<u8>> {
        let text = std::str::from_utf8(pem).expect("PEM is UTF-8");
        text.split("-----BEGIN CERTIFICATE-----")
            .skip(1)
            .map(|block| {
                let end = block
                    .find("-----END CERTIFICATE-----")
                    .expect("PEM end marker");
                let encoded: String = block[..end]
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect();
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .expect("PEM base64")
            })
            .collect()
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[tokio::test]
    async fn hyper_transport_fetches_a_real_http_response_and_caps_the_body() {
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;

        async fn serve(body: &'static [u8]) -> u16 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test listener");
            let port = listener.local_addr().expect("local address").port();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |_request| async move {
                            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                                Bytes::from_static(body),
                            )))
                        }),
                    )
                    .await;
            });
            port
        }

        let port = serve(b"token.thumbprint").await;
        let transport = HyperHttp01Transport::new();
        let fetch = transport
            .fetch(&format!(
                "http://127.0.0.1:{port}/.well-known/acme-challenge/token"
            ))
            .await
            .expect("real HTTP fetch");
        assert_eq!(fetch.status, 200);
        assert_eq!(fetch.body, b"token.thumbprint");

        // A body over the cap is rejected instead of being buffered without bound.
        let oversized = vec![b'x'; MAX_CHALLENGE_BODY + 1];
        let oversized: &'static [u8] = Box::leak(oversized.into_boxed_slice());
        let port = serve(oversized).await;
        let error = transport
            .fetch(&format!(
                "http://127.0.0.1:{port}/.well-known/acme-challenge/token"
            ))
            .await
            .expect_err("oversized body is rejected");
        assert!(error.contains("exceeds"), "{error}");
    }

    // ---- directory and nonces --------------------------------------------------------------

    #[tokio::test]
    async fn directory_matches_caddy_shape_and_new_nonce_headers() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        let response = get(&handler, "/acme/local/directory").await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            header_value(&response, header::CONTENT_TYPE).as_deref(),
            Some("application/json")
        );
        let directory = body_json(&response);
        assert_eq!(
            directory,
            json!({
                "newNonce": "https://acme.test/acme/local/new-nonce",
                "newAccount": "https://acme.test/acme/local/new-account",
                "newOrder": "https://acme.test/acme/local/new-order",
                "revokeCert": "https://acme.test/acme/local/revoke-cert",
                "keyChange": "https://acme.test/acme/local/key-change",
            }),
            "the directory must be byte-for-byte Caddy's object (no invented meta)"
        );

        let response = get(&handler, "/acme/local/new-nonce").await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
        assert!(body_text(&response).is_empty());
        assert!(header_value(&response, replay_nonce_header()).is_some());
        assert_eq!(
            header_value(&response, header::CACHE_CONTROL).as_deref(),
            Some("no-store")
        );
        assert_eq!(
            header_value(&response, header::LINK).as_deref(),
            Some("<https://acme.test/acme/local/directory>;rel=\"index\"")
        );

        let response = send(&handler, request(Method::HEAD, "/acme/local/new-nonce")).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());

        // HTTP/2 style: no Host header, the authority is on the request URI.
        let mut stripped = Request::new(
            Method::GET,
            "https://acme.test/acme/local/directory".parse().unwrap(),
        );
        stripped.headers.remove(header::HOST);
        let response = send(&handler, stripped).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(
            body_json(&response)["newNonce"],
            "https://acme.test/acme/local/new-nonce"
        );

        // A path outside the prefix passes through to the next handler, like Caddy.
        let outcome = handler
            .handle(request(Method::GET, "/other"))
            .await
            .expect("passes through");
        assert!(matches!(outcome, Outcome::Continue(_)));
    }

    // ---- forwarded external origin (T-TLS-086) ---------------------------------------------

    #[tokio::test]
    async fn forwarded_proto_selects_the_external_scheme() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );

        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/directory",
                "acme.test",
                Some("http"),
                None,
                true,
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        let directory = body_json(&response);
        assert_eq!(
            directory["newNonce"],
            "http://acme.test/acme/local/new-nonce"
        );
        assert_eq!(
            directory["newOrder"],
            "http://acme.test/acme/local/new-order"
        );

        // Case-insensitive and surrounding optional whitespace is trimmed.
        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/directory",
                "acme.test",
                Some(" \tHTTPS\t "),
                None,
                true,
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(
            body_json(&response)["newNonce"],
            "https://acme.test/acme/local/new-nonce"
        );
    }

    #[tokio::test]
    async fn forwarded_host_without_proto_uses_the_connection_scheme() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );

        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/directory",
                "internal:8080",
                None,
                Some("public.example"),
                true,
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(
            body_json(&response)["newNonce"],
            "http://public.example/acme/local/new-nonce",
            "a plain connection behind the proxy falls back to http"
        );

        let mut request = forwarded_request(
            Method::GET,
            "/acme/local/directory",
            "internal:8080",
            None,
            Some("public.example"),
            true,
        );
        request.tls = true;
        let response = send(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(
            body_json(&response)["newNonce"],
            "https://public.example/acme/local/new-nonce",
            "a TLS connection behind the proxy falls back to https"
        );
    }

    #[tokio::test]
    async fn forwarded_proto_and_host_replace_the_listener_origin() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );

        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/directory",
                "internal:8080",
                Some("https"),
                Some("public.example"),
                true,
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(
            body_json(&response),
            json!({
                "newNonce": "https://public.example/acme/local/new-nonce",
                "newAccount": "https://public.example/acme/local/new-account",
                "newOrder": "https://public.example/acme/local/new-order",
                "revokeCert": "https://public.example/acme/local/revoke-cert",
                "keyChange": "https://public.example/acme/local/key-change",
            }),
            "the forwarded origin must replace the listener origin in every URL"
        );
        let body = body_text(&response);
        assert!(!body.contains("internal"), "{body}");
        assert!(
            !body.contains(":8080"),
            "the internal listener port leaked: {body}"
        );

        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/new-nonce",
                "internal:8080",
                Some("https"),
                Some("public.example"),
                true,
            ),
        )
        .await;
        assert_eq!(
            header_value(&response, header::LINK).as_deref(),
            Some("<https://public.example/acme/local/directory>;rel=\"index\"")
        );
    }

    #[tokio::test]
    async fn forwarded_host_preserves_an_explicit_port() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );

        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/directory",
                "internal:8080",
                Some("https"),
                Some("public.example:8443"),
                true,
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        let directory = body_json(&response);
        assert_eq!(
            directory["newNonce"],
            "https://public.example:8443/acme/local/new-nonce"
        );
        assert_eq!(
            directory["keyChange"],
            "https://public.example:8443/acme/local/key-change"
        );
    }

    #[tokio::test]
    async fn configured_host_remains_authoritative_over_forwarded_host() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server", "host": "configured.example"}),
        );

        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/directory",
                "internal:8080",
                Some("https"),
                Some("public.example"),
                true,
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        let directory = body_json(&response);
        assert_eq!(
            directory["newNonce"], "https://configured.example/acme/local/new-nonce",
            "an operator-configured `host` overrides the request and forwarded hosts"
        );
        assert_eq!(
            directory["newOrder"],
            "https://configured.example/acme/local/new-order"
        );
    }

    #[tokio::test]
    async fn forwarded_origin_requires_the_trusted_proxy_signal() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );

        // No `trusted_proxy` variable (for example a direct router call or an embedder): the
        // headers must not influence the origin.
        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/directory",
                "acme.test",
                Some("https"),
                Some("public.example"),
                false,
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(
            body_json(&response)["newNonce"],
            "https://acme.test/acme/local/new-nonce",
            "forwarded headers from an untrusted peer must be ignored"
        );

        // An explicit `trusted_proxy=false` is equally untrusted.
        let mut request = forwarded_request(
            Method::GET,
            "/acme/local/directory",
            "acme.test",
            Some("http"),
            Some("public.example"),
            false,
        );
        request
            .vars
            .insert(TRUSTED_PROXY_VAR.to_string(), "false".to_string());
        let response = send(&handler, request).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(
            body_json(&response)["newNonce"],
            "https://acme.test/acme/local/new-nonce",
            "a spoofed forwarded scheme must not change a direct connection's URLs"
        );

        // The same request from a trusted peer is honoured.
        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/directory",
                "acme.test",
                Some("https"),
                Some("public.example"),
                true,
            ),
        )
        .await;
        assert_eq!(
            body_json(&response)["newNonce"],
            "https://public.example/acme/local/new-nonce"
        );
    }

    #[tokio::test]
    async fn malformed_forwarded_proto_is_rejected() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );

        for proto in ["ftp", "", "https,http", "ws", "https://"] {
            let response = send(
                &handler,
                forwarded_request(
                    Method::GET,
                    "/acme/local/directory",
                    "acme.test",
                    Some(proto),
                    Some("public.example"),
                    true,
                ),
            )
            .await;
            assert_eq!(
                response.status,
                StatusCode::BAD_REQUEST,
                "`X-Forwarded-Proto: {proto}` must be rejected"
            );
            let problem = body_json(&response);
            assert_eq!(problem["type"], PROBLEM_MALFORMED, "{proto}");
            assert!(
                problem["detail"]
                    .as_str()
                    .expect("detail")
                    .contains("X-Forwarded-Proto"),
                "{problem}"
            );
        }

        // A malformed value is loud even when the peer is untrusted: it is never silently used.
        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/directory",
                "acme.test",
                Some("ftp"),
                None,
                false,
            ),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&response)["type"], PROBLEM_MALFORMED);
    }

    #[tokio::test]
    async fn malformed_forwarded_host_is_rejected() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );

        for host in [
            "https://evil.example",
            "evil.example/path",
            "evil example",
            "user@evil.example",
            "evil.example?x=1",
            "evil.example#frag",
            "evil.example:bad",
            "evil.example:",
            ":8080",
            "[::1",
            "a..b",
            "evil\\example",
            "evil.example,other.example",
            "evil.example:80:90",
            "*.example",
        ] {
            let response = send(
                &handler,
                forwarded_request(
                    Method::GET,
                    "/acme/local/directory",
                    "acme.test",
                    Some("https"),
                    Some(host),
                    true,
                ),
            )
            .await;
            assert_eq!(
                response.status,
                StatusCode::BAD_REQUEST,
                "`X-Forwarded-Host: {host}` must be rejected"
            );
            let problem = body_json(&response);
            assert_eq!(problem["type"], PROBLEM_MALFORMED, "{host}");
            assert!(
                problem["detail"]
                    .as_str()
                    .expect("detail")
                    .contains("X-Forwarded-Host"),
                "{problem}"
            );
        }
    }

    #[test]
    fn forwarded_host_parser_rejects_control_characters_and_unbounded_values() {
        for host in [
            "evil\u{0}.example",
            "evil\r.example",
            "evil\n.example",
            "evil\t.example",
            "evil\u{7f}.example",
            "evil.example\u{1}",
        ] {
            let error = parse_external_host(host, "X-Forwarded-Host")
                .expect_err("control characters are not valid in an authority");
            assert_eq!(error.problem_type, PROBLEM_MALFORMED, "{host:?}");
            assert!(error.detail.contains("X-Forwarded-Host"), "{error:?}");
        }

        let long = format!("{}.example", "a".repeat(MAX_EXTERNAL_HOST_LEN));
        assert!(
            parse_external_host(&long, "X-Forwarded-Host").is_err(),
            "an unbounded authority must be rejected"
        );
        assert!(
            parse_external_host("exämple.com", "X-Forwarded-Host").is_err(),
            "non-ASCII authorities must be rejected"
        );

        for valid in [
            "acme.test",
            "acme.test:8080",
            "127.0.0.1:443",
            "[::1]",
            "[::1]:8443",
        ] {
            assert_eq!(
                parse_external_host(valid, "X-Forwarded-Host").expect("valid authority"),
                valid
            );
        }
    }

    #[tokio::test]
    async fn duplicate_forwarded_headers_are_rejected() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );

        let mut request = forwarded_request(
            Method::GET,
            "/acme/local/directory",
            "acme.test",
            Some("https"),
            Some("public.example"),
            true,
        );
        request.headers.append(
            HeaderName::from_static(FORWARDED_PROTO_HEADER),
            HeaderValue::from_static("https"),
        );
        let response = send(&handler, request).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        let problem = body_json(&response);
        assert_eq!(problem["type"], PROBLEM_MALFORMED);
        assert!(
            problem["detail"]
                .as_str()
                .expect("detail")
                .contains("multiple `x-forwarded-proto`"),
            "{problem}"
        );

        let mut request = forwarded_request(
            Method::GET,
            "/acme/local/directory",
            "acme.test",
            Some("https"),
            Some("public.example"),
            true,
        );
        request.headers.append(
            HeaderName::from_static(FORWARDED_HOST_HEADER),
            HeaderValue::from_static("other.example"),
        );
        let response = send(&handler, request).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        let problem = body_json(&response);
        assert_eq!(problem["type"], PROBLEM_MALFORMED);
        assert!(
            problem["detail"]
                .as_str()
                .expect("detail")
                .contains("multiple `x-forwarded-host`"),
            "{problem}"
        );
    }

    #[tokio::test]
    async fn direct_connection_urls_are_byte_identical() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        let expected = json!({
            "newNonce": "https://acme.test/acme/local/new-nonce",
            "newAccount": "https://acme.test/acme/local/new-account",
            "newOrder": "https://acme.test/acme/local/new-order",
            "revokeCert": "https://acme.test/acme/local/revoke-cert",
            "keyChange": "https://acme.test/acme/local/key-change",
        });

        // The historical direct path advertises https on both plain and TLS connections.
        for tls in [false, true] {
            let mut directory_request = request(Method::GET, "/acme/local/directory");
            directory_request.tls = tls;
            let response = send(&handler, directory_request).await;
            assert_eq!(response.status, StatusCode::OK, "tls={tls}");
            assert_eq!(body_json(&response), expected, "tls={tls}");

            let mut nonce_request = request(Method::GET, "/acme/local/new-nonce");
            nonce_request.tls = tls;
            let response = send(&handler, nonce_request).await;
            assert_eq!(
                header_value(&response, header::LINK).as_deref(),
                Some("<https://acme.test/acme/local/directory>;rel=\"index\""),
                "tls={tls}"
            );
        }
    }

    #[tokio::test]
    async fn forwarded_origin_binds_the_jws_url_to_the_constructed_url() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        let key = AccountKey::generate().expect("account key");
        let payload = serde_json::to_vec(&json!({"termsOfServiceAgreed": true})).expect("payload");

        let response = send(
            &handler,
            forwarded_request(
                Method::GET,
                "/acme/local/new-nonce",
                "internal:8080",
                Some("https"),
                Some("public.example"),
                true,
            ),
        )
        .await;
        let nonce = header_value(&response, replay_nonce_header()).expect("nonce");

        // The client signs the URL it was advertised (the forwarded origin), not the listener.
        let mut request = forwarded_request(
            Method::POST,
            "/acme/local/new-account",
            "internal:8080",
            Some("https"),
            Some("public.example"),
            true,
        );
        request.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/jose+json"),
        );
        request.body = Bytes::from(
            sign_jws(
                &key,
                None,
                Some(&nonce),
                "https://public.example/acme/local/new-account",
                &payload,
            )
            .expect("sign JWS"),
        );
        let response = send(&handler, request).await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{}",
            body_text(&response)
        );
        let location = header_value(&response, header::LOCATION).expect("account location");
        assert!(
            location.starts_with("https://public.example/acme/local/account/"),
            "{location}"
        );
        let nonce = header_value(&response, replay_nonce_header()).expect("replay nonce");

        // Signing the internal listener URL does not satisfy the binding for the forwarded
        // request: the binding compares against the same constructed URL the client was given.
        let mut request = forwarded_request(
            Method::POST,
            "/acme/local/new-account",
            "internal:8080",
            Some("https"),
            Some("public.example"),
            true,
        );
        request.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/jose+json"),
        );
        request.body = Bytes::from(
            sign_jws(
                &key,
                None,
                Some(&nonce),
                "https://internal:8080/acme/local/new-account",
                &payload,
            )
            .expect("sign JWS"),
        );
        let response = send(&handler, request).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        let problem = body_json(&response);
        assert_eq!(problem["type"], PROBLEM_MALFORMED);
        assert!(
            problem["detail"]
                .as_str()
                .expect("detail")
                .contains("does not match request url"),
            "{problem}"
        );
    }

    #[tokio::test]
    async fn forwarded_origin_does_not_change_the_http01_fetch_target() {
        let transport = ScriptedTransport::success();
        let handler = test_handler(
            Arc::clone(&transport) as Arc<dyn Http01Transport>,
            json!({"handler": "acme_server"}),
        );
        let mut client = TestClient::new(&handler).await.with_forwarded_origin(
            "https://public.example",
            "internal:8080",
            "https",
            "public.example",
        );
        let response = client.register().await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{}",
            body_text(&response)
        );
        assert!(header_value(&response, header::LOCATION)
            .expect("account location")
            .starts_with("https://public.example/acme/local/account/"));

        // The whole order flow succeeds while signing the forwarded origin, and the http-01
        // validation still targets the order identifier, never the forwarded host.
        let ready = ready_order(&mut client, &transport, "challenge.example").await;
        assert!(ready.order_path.starts_with("/acme/local/order/"));
        let requests = transport.requests();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert!(
            requests[0].starts_with("http://challenge.example/.well-known/acme-challenge/"),
            "the http-01 target must come from the identifier: {requests:?}"
        );
        assert!(
            !requests[0].contains("public.example") && !requests[0].contains("internal"),
            "forwarded headers must not reach the http-01 target: {requests:?}"
        );
    }

    #[test]
    fn nonces_are_single_use_and_bounded() {
        let state = State::new();
        let first = state.issue_nonce().unwrap();
        assert!(state.consume_nonce(&first));
        assert!(
            !state.consume_nonce(&first),
            "a nonce must not be replayable"
        );

        for _ in 0..(MAX_NONCES + 32) {
            state.issue_nonce().unwrap();
        }
        assert_eq!(state.nonce_count(), MAX_NONCES, "nonce store is bounded");
    }

    // ---- JWS verification -----------------------------------------------------------------

    #[tokio::test]
    async fn jws_accepts_es256_and_rs256_accounts() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );

        let mut es256 = TestClient::new(&handler).await;
        let response = es256.register().await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{}",
            body_text(&response)
        );
        assert!(header_value(&response, header::LOCATION).is_some());

        let mut rs256 = TestClient::with_key(
            &handler,
            AccountKey::generate_with_key_type(AccountKeyType::Rsa2048).expect("RSA account key"),
        )
        .await;
        let response = rs256.register().await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{}",
            body_text(&response)
        );

        // The RS256 account can use kid-signed requests.
        let response = rs256
            .post_json(
                "/acme/local/new-order",
                &json!({"identifiers": [{"type": "dns", "value": "rsa.example"}]}),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{}",
            body_text(&response)
        );
    }

    #[tokio::test]
    async fn jws_rejects_bad_nonce_url_signature_algorithm_and_content_type() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        let mut client = TestClient::new(&handler).await;

        let nonce = client.nonce.take().expect("nonce");
        let url = format!("{BASE}/new-account");
        let payload = serde_json::to_vec(&json!({})).unwrap();
        let body = sign_jws(&client.key, None, Some(&nonce), &url, &payload).unwrap();
        let response = client
            .post_raw("/acme/local/new-account", body.clone())
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{}",
            body_text(&response)
        );
        let replay = client.post_raw("/acme/local/new-account", body).await;
        assert_eq!(replay.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&replay)["type"], PROBLEM_BAD_NONCE);

        // Missing/unknown nonce.
        let body = sign_jws(&client.key, None, Some("not-a-nonce"), &url, &payload).unwrap();
        let response = client.post_raw("/acme/local/new-account", body).await;
        assert_eq!(body_json(&response)["type"], PROBLEM_BAD_NONCE);

        // Wrong protected url.
        client.refresh_nonce().await;
        let body = sign_jws(
            &client.key,
            None,
            Some(&client.nonce.take().unwrap()),
            "https://acme.test/acme/local/new-order",
            &payload,
        )
        .unwrap();
        let response = client.post_raw("/acme/local/new-account", body).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&response)["type"], PROBLEM_MALFORMED);
        assert!(body_json(&response)["detail"]
            .as_str()
            .unwrap()
            .contains("does not match request url"));

        // Unsupported algorithm: construct the JWS by hand.
        client.refresh_nonce().await;
        let protected = json!({
            "alg": "HS256",
            "nonce": client.nonce.take().unwrap(),
            "url": url,
            "jwk": client.key.public_jwk().unwrap(),
        });
        let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let signature = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let body = json!({"protected": protected, "payload": payload, "signature": signature});
        let response = client
            .post_raw("/acme/local/new-account", body.to_string())
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(&response)["type"],
            PROBLEM_BAD_SIGNATURE_ALGORITHM
        );

        // Bad signature with a supported algorithm.
        client.refresh_nonce().await;
        let mut tampered = sign_jws(
            &client.key,
            None,
            Some(&client.nonce.take().unwrap()),
            &url,
            &serde_json::to_vec(&json!({})).unwrap(),
        )
        .unwrap();
        let mut value: Value = serde_json::from_str(&tampered).unwrap();
        value["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
        tampered = value.to_string();
        let response = client.post_raw("/acme/local/new-account", tampered).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&response)["type"], PROBLEM_MALFORMED);

        // Content type is enforced before parsing.
        let mut request = request(Method::POST, "/acme/local/new-account");
        request
            .headers
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        request.body = Bytes::from_static(b"{}");
        let response = send(&handler, request).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&response)["type"], PROBLEM_MALFORMED);
    }

    // ---- orders, policy, http-01 ----------------------------------------------------------

    #[tokio::test]
    async fn new_order_rejects_denied_allowed_and_wildcard_identifiers() {
        let deny = test_handler(
            ScriptedTransport::success(),
            json!({
                "handler": "acme_server",
                "policy": {"deny": {"domains": ["blocked.example"]}}
            }),
        );
        let mut client = TestClient::new(&deny).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (_, _, response) = client
            .create_order(json!([{"type": "dns", "value": "blocked.example"}]))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&response)["type"], PROBLEM_REJECTED_IDENTIFIER);
        assert!(body_json(&response)["detail"]
            .as_str()
            .unwrap()
            .contains("denied"));

        // A name outside the allow list is rejected; one inside it passes.
        let allow = test_handler(
            ScriptedTransport::success(),
            json!({
                "handler": "acme_server",
                "policy": {"allow": {"domains": ["allowed.example"]}}
            }),
        );
        let mut client = TestClient::new(&allow).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (_, _, response) = client
            .create_order(json!([{"type": "dns", "value": "other.example"}]))
            .await;
        assert_eq!(body_json(&response)["type"], PROBLEM_REJECTED_IDENTIFIER);
        // An IP identifier is not explicitly permitted when only DNS names are allowed.
        let (_, _, response) = client
            .create_order(json!([{"type": "ip", "value": "127.0.0.1"}]))
            .await;
        assert_eq!(body_json(&response)["type"], PROBLEM_REJECTED_IDENTIFIER);
        let (_, json, response) = client
            .create_order(json!([{"type": "dns", "value": "allowed.example"}]))
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{}",
            body_text(&response)
        );
        assert_eq!(json["status"], "pending");

        // Wildcards are rejected whether or not the flag is set: dns-01 is required to prove them.
        let no_wildcard = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        let mut client = TestClient::new(&no_wildcard).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (_, _, response) = client
            .create_order(json!([{"type": "dns", "value": "*.example.com"}]))
            .await;
        assert_eq!(body_json(&response)["type"], PROBLEM_REJECTED_IDENTIFIER);
        assert!(body_json(&response)["detail"]
            .as_str()
            .unwrap()
            .contains("allow_wildcard_names"));

        let wildcard = test_handler(
            ScriptedTransport::success(),
            json!({
                "handler": "acme_server",
                "policy": {"allow_wildcard_names": true}
            }),
        );
        let mut client = TestClient::new(&wildcard).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (_, _, response) = client
            .create_order(json!([{"type": "dns", "value": "*.example.com"}]))
            .await;
        assert_eq!(body_json(&response)["type"], PROBLEM_REJECTED_IDENTIFIER);
        assert!(body_json(&response)["detail"]
            .as_str()
            .unwrap()
            .contains("dns-01"));
    }

    #[tokio::test]
    async fn http01_validation_proves_control_and_rejects_wrong_key_authorization() {
        let transport = ScriptedTransport::success();
        let handler = test_handler(transport.clone(), json!({"handler": "acme_server"}));
        let mut client = TestClient::new(&handler).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (_, order, _) = client
            .create_order(json!([{"type": "dns", "value": "acme.example"}]))
            .await;
        let (_, authorization) = client.authorization(&order).await;
        let token = authorization["challenges"][0]["token"]
            .as_str()
            .unwrap()
            .to_string();

        // Wrong key authorization: the challenge becomes invalid and the order stays pending.
        transport.set_body("not-the-key-authorization");
        let response = client.validate_challenge(&authorization).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        let challenge = body_json(&response);
        assert_eq!(challenge["status"], "invalid");
        assert_eq!(challenge["error"]["type"], PROBLEM_REJECTED_IDENTIFIER);
        assert!(transport
            .requests()
            .iter()
            .any(|url| url == &format!("http://acme.example/.well-known/acme-challenge/{token}")));

        // A connection failure leaves the challenge pending with an error (retryable), like Caddy.
        let failing = ScriptedTransport::failing();
        let handler = test_handler(failing, json!({"handler": "acme_server"}));
        let mut client = TestClient::new(&handler).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (_, order, _) = client
            .create_order(json!([{"type": "dns", "value": "acme.example"}]))
            .await;
        let (_, authorization) = client.authorization(&order).await;
        let response = client.validate_challenge(&authorization).await;
        let challenge = body_json(&response);
        assert_eq!(challenge["status"], "pending");
        assert_eq!(challenge["error"]["type"], PROBLEM_CONNECTION);
    }

    // ---- finalize and certificate ----------------------------------------------------------

    #[tokio::test]
    async fn finalize_before_ready_is_order_not_ready() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        let mut client = TestClient::new(&handler).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (order_path, _, _) = client
            .create_order(json!([{"type": "dns", "value": "early.example"}]))
            .await;
        let csr = CertificateRequest::generate(&["early.example".to_string()]).unwrap();
        let response = client.finalize(&order_path, &csr).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&response)["type"], PROBLEM_ORDER_NOT_READY);
        assert!(body_json(&response)["detail"]
            .as_str()
            .unwrap()
            .contains("not ready"));
    }

    #[tokio::test]
    async fn complete_flow_issues_and_serves_a_two_certificate_chain_for_the_csr_key() {
        let transport = ScriptedTransport::success();
        let (handler, issuer) =
            test_handler_with_issuer(transport.clone(), json!({"handler": "acme_server"}));
        let mut client = TestClient::new(&handler).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let flow = issue_flow(&mut client, &transport, "acme.example").await;

        assert_eq!(
            header_value(&flow.certificate, header::CONTENT_TYPE).as_deref(),
            Some("application/pem-certificate-chain")
        );
        let blocks = pem_blocks(&flow.certificate.body);
        assert_eq!(
            blocks.len(),
            2,
            "Caddy returns leaf + intermediate; the root is the client trust anchor"
        );
        let ca = issuer.ca_certificates().await.expect("CA certificates");
        assert_eq!(
            blocks[1], ca.intermediate_der,
            "the second PEM block must be the signing intermediate"
        );
        let parsed = parse_csr(flow.csr.der()).unwrap();
        assert!(
            contains_subslice(&blocks[0], &parsed.spki_der),
            "the leaf certificate must carry the CSR public key"
        );

        // The account can list its orders.
        let account_url = client.kid.clone().unwrap();
        let account_path = path_of(&account_url);
        let response = client.post_as_get(&format!("{account_path}/orders")).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        let orders = body_json(&response);
        assert_eq!(orders.as_array().unwrap().len(), 1);
        assert_eq!(path_of(orders[0].as_str().unwrap()), flow.order_path);

        // Revocation by the owning account succeeds once and is then `alreadyRevoked`.
        let payload = json!({"certificate": URL_SAFE_NO_PAD.encode(&blocks[0])});
        let response = client.post_json("/acme/local/revoke-cert", &payload).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        let response = client.post_json("/acme/local/revoke-cert", &payload).await;
        assert_eq!(body_json(&response)["type"], PROBLEM_ALREADY_REVOKED);

        // key-change is advertised but not implemented, exactly like Caddy/smallstep.
        let response = client.post_json("/acme/local/key-change", &json!({})).await;
        assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn sign_with_root_returns_leaf_and_root() {
        let transport = ScriptedTransport::success();
        let (handler, issuer) = test_handler_with_issuer(
            transport.clone(),
            json!({"handler": "acme_server", "sign_with_root": true}),
        );
        let mut client = TestClient::new(&handler).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let flow = issue_flow(&mut client, &transport, "root.example").await;
        let blocks = pem_blocks(&flow.certificate.body);
        assert_eq!(blocks.len(), 2, "sign_with_root returns leaf + root");
        let ca = issuer.ca_certificates().await.expect("CA certificates");
        assert_eq!(
            blocks[1], ca.root_der,
            "the second PEM block must be the root when sign_with_root is set"
        );
    }

    #[tokio::test]
    async fn certificate_download_before_finalize_is_order_not_ready() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        let mut client = TestClient::new(&handler).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (order_path, _order, _) = client
            .create_order(json!([{"type": "dns", "value": "later.example"}]))
            .await;
        let certificate_path = format!(
            "/acme/local/certificate/{}",
            order_path.rsplit('/').next().unwrap()
        );
        let response = client.post_as_get(&certificate_path).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&response)["type"], PROBLEM_ORDER_NOT_READY);
    }

    #[tokio::test]
    async fn wildcard_policy_rules_match_exactly_one_label() {
        let deny = test_handler(
            ScriptedTransport::success(),
            json!({
                "handler": "acme_server",
                "policy": {"deny": {"domains": ["*.example.com"]}}
            }),
        );
        let mut client = TestClient::new(&deny).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (_, _, response) = client
            .create_order(json!([{"type": "dns", "value": "a.example.com"}]))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&response)["type"], PROBLEM_REJECTED_IDENTIFIER);
        for allowed in ["a.b.example.com", "example.com"] {
            let (_, _, response) = client
                .create_order(json!([{"type": "dns", "value": allowed}]))
                .await;
            assert_eq!(
                response.status,
                StatusCode::CREATED,
                "deny *.example.com must not match {allowed}: {}",
                body_text(&response)
            );
        }

        let allow = test_handler(
            ScriptedTransport::success(),
            json!({
                "handler": "acme_server",
                "policy": {"allow": {"domains": ["*.example.com"]}}
            }),
        );
        let mut client = TestClient::new(&allow).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let (_, _, response) = client
            .create_order(json!([{"type": "dns", "value": "a.example.com"}]))
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "{}",
            body_text(&response)
        );
        for denied in ["a.b.example.com", "example.com"] {
            let (_, _, response) = client
                .create_order(json!([{"type": "dns", "value": denied}]))
                .await;
            assert_eq!(
                body_json(&response)["type"],
                PROBLEM_REJECTED_IDENTIFIER,
                "allow *.example.com must not permit {denied}"
            );
        }

        // Unsupported rule spellings are located load errors, never silently ineffective rules.
        for (rule, needle) in [
            (".example.com", "should start with *"),
            ("*example.com", "can only be used to match"),
            ("a*.example.com", "only have wildcard as starting character"),
            ("*", "is not a wildcard rule"),
            ("a..example.com", "empty labels"),
        ] {
            let error = AcmeServerHandler::from_json_with(
                &json!({"handler": "acme_server", "policy": {"deny": {"domains": [rule]}}}),
                "test",
                memory_issuer(),
                ScriptedTransport::success(),
            )
            .err()
            .unwrap_or_else(|| panic!("`{rule}` must fail at load"));
            assert!(
                error.to_string().contains(needle),
                "`{rule}` error `{error}` must mention `{needle}`"
            );
        }
    }

    #[tokio::test]
    async fn malformed_dns_identifiers_are_rejected_before_any_fetch() {
        let transport = ScriptedTransport::success();
        let handler = test_handler(transport.clone(), json!({"handler": "acme_server"}));
        let mut client = TestClient::new(&handler).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);

        for bad in [
            "a.example.com:80",
            "::1",
            "[::1]",
            "_x.example.com",
            "a_b.example.com",
            "-bad.example.com",
            "a-.example.com",
            "a..example.com",
            "foo.*.example.com",
            "a/b.example.com",
            "bad name.example",
        ] {
            let (_, _, response) = client
                .create_order(json!([{"type": "dns", "value": bad}]))
                .await;
            assert_eq!(
                response.status,
                StatusCode::BAD_REQUEST,
                "`{bad}` must be rejected: {}",
                body_text(&response)
            );
            assert_eq!(
                body_json(&response)["type"],
                PROBLEM_MALFORMED,
                "`{bad}` must produce a malformed problem"
            );
        }
        assert!(
            transport.requests().is_empty(),
            "rejected identifiers must never trigger an http-01 fetch"
        );

        // Accepted forms that are valid hostnames (the oracle also accepts these).
        for good in ["localhost", "127.0.0.1", "a.example.com"] {
            let (_, _, response) = client
                .create_order(json!([{"type": "dns", "value": good}]))
                .await;
            assert_eq!(
                response.status,
                StatusCode::CREATED,
                "`{good}` should be accepted: {}",
                body_text(&response)
            );
        }
    }

    #[tokio::test]
    async fn wrong_methods_get_405_with_allow() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        for (method, path, expected) in [
            (Method::GET, "/acme/local/new-account", vec!["POST"]),
            (Method::HEAD, "/acme/local/new-order", vec!["POST"]),
            (Method::GET, "/acme/local/order/deadbeef", vec!["POST"]),
            (
                Method::GET,
                "/acme/local/certificate/deadbeef",
                vec!["POST"],
            ),
            (Method::PUT, "/acme/local/directory", vec!["GET", "HEAD"]),
            (Method::POST, "/acme/local/directory", vec!["GET", "HEAD"]),
            (Method::POST, "/acme/local/new-nonce", vec!["GET", "HEAD"]),
        ] {
            let response = send(&handler, request(method.clone(), path)).await;
            assert_eq!(
                response.status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path}"
            );
            assert!(response.body.is_empty(), "{method} {path} body");
            let allow: Vec<String> = response
                .headers
                .get_all(header::ALLOW)
                .iter()
                .map(|value| value.to_str().unwrap().to_string())
                .collect();
            assert_eq!(allow, expected, "{method} {path} Allow");
            assert!(
                header_value(&response, replay_nonce_header()).is_none(),
                "405 responses carry no Replay-Nonce"
            );
        }

        // Unknown paths remain 404 regardless of method.
        let response = send(&handler, request(Method::GET, "/acme/local/bogus")).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cross_account_access_is_rejected() {
        let transport = ScriptedTransport::success();
        let handler = test_handler(transport.clone(), json!({"handler": "acme_server"}));
        let mut owner = TestClient::new(&handler).await;
        assert_eq!(owner.register().await.status, StatusCode::CREATED);
        let owner_kid = owner.kid.clone().expect("owner kid");
        let flow = issue_flow(&mut owner, &transport, "owned.example").await;

        let mut intruder = TestClient::new(&handler).await;
        assert_eq!(intruder.register().await.status, StatusCode::CREATED);

        for path in [flow.order_path.as_str(), flow.authorization_path.as_str()] {
            let response = intruder.post_as_get(path).await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(body_json(&response)["type"], PROBLEM_UNAUTHORIZED, "{path}");
        }
        let response = intruder.post_json(&flow.challenge_path, &json!({})).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(&response)["type"], PROBLEM_UNAUTHORIZED);

        // A CSR is not needed for the ownership check; the order must be refused first.
        let csr = CertificateRequest::generate(&["owned.example".to_string()]).unwrap();
        let response = intruder.finalize(&flow.order_path, &csr).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        let response = intruder.post_as_get(&flow.certificate_path).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        let response = intruder
            .post_as_get(&format!("{}/orders", path_of(&owner_kid)))
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        let leaf = pem_blocks(&flow.certificate.body)[0].clone();
        let response = intruder
            .post_json(
                "/acme/local/revoke-cert",
                &json!({"certificate": URL_SAFE_NO_PAD.encode(&leaf)}),
            )
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(body_json(&response)["type"], PROBLEM_UNAUTHORIZED);

        // The owner still has full access.
        let response = owner.post_as_get(&flow.order_path).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
    }

    #[tokio::test]
    async fn finalize_rejects_csr_names_that_do_not_match_the_order() {
        let transport = ScriptedTransport::success();
        let handler = test_handler(transport.clone(), json!({"handler": "acme_server"}));
        let mut client = TestClient::new(&handler).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let ready = ready_order(&mut client, &transport, "ordered.example").await;

        for domains in [
            vec!["other.example".to_string()],
            vec!["ordered.example".to_string(), "extra.example".to_string()],
        ] {
            let csr = CertificateRequest::generate(&domains).unwrap();
            let response = client.finalize(&ready.order_path, &csr).await;
            assert_eq!(
                response.status,
                StatusCode::BAD_REQUEST,
                "{domains:?}: {}",
                body_text(&response)
            );
            assert_eq!(body_json(&response)["type"], PROBLEM_BAD_CSR);
            assert!(body_json(&response)["detail"]
                .as_str()
                .unwrap()
                .contains("do not match"));
        }

        // A rejected CSR leaves the order ready, so the correct CSR can still finalize.
        let response = client.post_as_get(&ready.order_path).await;
        assert_eq!(body_json(&response)["status"], "ready");
        let csr = CertificateRequest::generate(&["ordered.example".to_string()]).unwrap();
        let response = client.finalize(&ready.order_path, &csr).await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(body_json(&response)["status"], "valid");
    }

    #[tokio::test]
    async fn account_only_return_existing_and_deactivation() {
        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        let mut client = TestClient::new(&handler).await;
        assert_eq!(client.register().await.status, StatusCode::CREATED);
        let kid = client.kid.clone().expect("kid");
        let account_path = path_of(&kid);

        // Same key, onlyReturnExisting: returns the existing account with 200.
        client.kid = None;
        let response = client
            .post_json(
                "/acme/local/new-account",
                &json!({"onlyReturnExisting": true}),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(
            header_value(&response, header::LOCATION).as_deref(),
            Some(kid.as_str())
        );
        client.kid = Some(kid.clone());

        // A different key asking for an existing account gets accountDoesNotExist.
        let mut other = TestClient::new(&handler).await;
        let response = other
            .post_json(
                "/acme/local/new-account",
                &json!({"onlyReturnExisting": true}),
            )
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(body_json(&response)["type"], PROBLEM_ACCOUNT_DOES_NOT_EXIST);

        // Deactivation makes the account unusable for further ACME operations.
        let response = client
            .post_json(&account_path, &json!({"status": "deactivated"}))
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", body_text(&response));
        assert_eq!(body_json(&response)["status"], "deactivated");
        let response = client
            .post_json(
                "/acme/local/new-order",
                &json!({"identifiers": [{"type": "dns", "value": "after.example"}]}),
            )
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(&response)["type"], PROBLEM_UNAUTHORIZED);
    }

    #[tokio::test]
    async fn streaming_body_is_bounded_before_parsing() {
        use crate::body::RequestBody;

        let handler = test_handler(
            ScriptedTransport::success(),
            json!({"handler": "acme_server"}),
        );
        let mut request = request(Method::POST, "/acme/local/new-account");
        request = request.with_streaming_body(RequestBody::buffered(vec![b'x'; MAX_JWS_BODY + 1]));
        match handler
            .handle_streaming(request)
            .await
            .expect("handler serves")
        {
            StreamingOutcome::Respond(response) => {
                let response = response.into_buffered().await.expect("buffered response");
                assert_eq!(response.status, StatusCode::BAD_REQUEST);
                assert_eq!(body_json(&response)["type"], PROBLEM_MALFORMED);
                assert!(body_json(&response)["detail"]
                    .as_str()
                    .unwrap()
                    .contains("exceeds"));
            }
            StreamingOutcome::Continue(_) => panic!("ACME path must not pass through"),
            StreamingOutcome::Upgrade(_) => panic!("ACME never upgrades"),
        }
        assert!(!handler.requires_buffered_request_body());
        assert!(handler.consumes_request_body());
    }

    #[test]
    fn config_rejects_unhonourable_options_loudly() {
        let error = AcmeServerConfig::from_json(
            &json!({"handler": "acme_server", "challenges": ["dns-01"]}),
            "test",
        )
        .expect_err("dns-01 is not implemented");
        assert!(error.to_string().contains("only http-01"), "{error}");

        let error = AcmeServerConfig::from_json(
            &json!({"handler": "acme_server", "resolvers": ["1.1.1.1"]}),
            "test",
        )
        .expect_err("resolvers are a dns-01 no-op");
        assert!(error.to_string().contains("dns-01"), "{error}");

        let error = AcmeServerConfig::from_json(
            &json!({"handler": "acme_server", "unknown": true}),
            "test",
        )
        .expect_err("unknown fields are rejected");
        assert!(
            error.to_string().contains("unknown acme_server field"),
            "{error}"
        );

        let error = AcmeServerConfig::from_json(
            &json!({"handler": "acme_server", "ca": "../escape"}),
            "test",
        )
        .expect_err("unsafe CA ids are rejected");
        assert!(
            error
                .to_string()
                .contains("invalid certificate authority ID"),
            "{error}"
        );

        let config = AcmeServerConfig::from_json(
            &json!({
                "handler": "acme_server",
                "ca": "local",
                "lifetime": 604800000000000u64,
                "challenges": ["http-01"],
                "policy": {"allow": {"domains": ["example.com"]}, "deny": {"ip_ranges": ["10.0.0.0/8"]}, "allow_wildcard_names": true}
            }),
            "test",
        )
        .expect("valid configuration");
        assert_eq!(config.effective_lifetime(), Duration::from_secs(604_800));
        assert!(config.policy.allow_wildcard_names);
    }
}
