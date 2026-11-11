//! DNS-01 challenge provider interface.
//!
//! ACME's DNS-01 challenge asks the solver to publish a TXT record under
//! `_acme-challenge.<domain>` and then wait until the record is visible to the ACME server's
//! resolvers. Caddy exposes providers as `dns.providers.*` modules; this crate models the same
//! boundary as an async trait so the ACME issuer (T-TLS-040/T-TLS-061) can be tested without
//! network access.
//!
//! A provider implementation is responsible for talking to a DNS API. This module provides:
//!
//! * [`DnsProvider`] — create/delete/list TXT records, zone discovery and a propagation wait hook.
//! * [`TxtRecord`] / [`RecordId`] — the records a provider manages.
//! * [`DnsError`] — typed provider errors.
//! * [`DnsChallengeConfig`] — the `challenges.dns` shape from Caddy's ACME issuer JSON.
//! * [`InMemoryDnsProvider`] — an in-process provider used by tests (and useful for local
//!   development); it performs no network I/O.
//!
//! The Cloudflare implementation lives in [`crate::cloudflare`]. Other provider modules and the
//! `dns.providers` module registry are tracked separately; this module only defines the interface
//! they must implement.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;

/// Caddy/CertMagic default maximum time to wait for a DNS record to propagate (2 minutes).
pub const DEFAULT_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(120);

/// Default interval between propagation checks.
pub const DEFAULT_PROPAGATION_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Result alias for DNS provider operations.
pub type DnsResult<T> = std::result::Result<T, DnsError>;

/// Identifies a TXT record created by a provider.
///
/// Providers may use whatever opaque value their API returns (record ID, transaction ID, ...);
/// [`DnsProvider::delete_txt`] receives the whole [`TxtRecord`] so providers that only support
/// delete-by-name/value can ignore the ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordId(pub String);

impl RecordId {
    /// Convenience constructor.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for RecordId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A TXT record managed by a DNS provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    /// Provider-assigned identifier.
    pub id: RecordId,
    /// Fully-qualified record name without the trailing dot,
    /// e.g. `_acme-challenge.example.com`.
    pub fqdn: String,
    /// Authoritative zone that contains the record, e.g. `example.com`.
    pub zone: String,
    /// TXT record value (the ACME key authorization digest).
    pub value: String,
}

/// Typed DNS provider errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The provider does not manage any zone that contains the requested name.
    #[error("DNS provider `{provider}` does not manage a zone for `{fqdn}`")]
    ZoneNotFound {
        /// Provider that was asked.
        provider: String,
        /// Name whose zone could not be found.
        fqdn: String,
    },

    /// The DNS name is not a valid TXT record name.
    #[error("invalid DNS record name `{name}`: {reason}")]
    InvalidName {
        /// Offending name.
        name: String,
        /// Why it is invalid.
        reason: String,
    },

    /// The provider API rejected the request.
    #[error("DNS provider `{provider}` API error: {message}")]
    Provider {
        /// Provider that failed.
        provider: String,
        /// Provider/driver message.
        message: String,
    },

    /// A record could not be found for deletion.
    #[error("DNS TXT record `{fqdn}` was not found")]
    RecordNotFound {
        /// Record name.
        fqdn: String,
    },

    /// A record with the same name and value already exists.
    #[error("DNS TXT record `{fqdn}` with value `{value}` already exists")]
    RecordExists {
        /// Record name.
        fqdn: String,
        /// Record value.
        value: String,
    },

    /// Propagation polling timed out.
    #[error("timed out after {timeout:?} waiting for TXT record `{fqdn}` to propagate")]
    PropagationTimeout {
        /// Record name.
        fqdn: String,
        /// Timeout that was exceeded.
        timeout: Duration,
    },

    /// The challenge/provider configuration is invalid.
    #[error("invalid DNS challenge configuration: {message}")]
    Config {
        /// What is wrong.
        message: String,
    },

    /// A configured DNS provider module is not implemented by this build.
    #[error(
        "DNS challenge provider `{provider}` is not implemented by this build (tracking T-TLS-063)"
    )]
    UnsupportedProvider {
        /// Provider module name from `challenges.dns.provider.name`.
        provider: String,
    },

    /// A configured DNS provider option is not implemented by this build.
    #[error(
        "DNS challenge provider `{provider}` option `{option}` is not supported by this build \
         (tracking T-TLS-063)"
    )]
    UnsupportedOption {
        /// Provider module name.
        provider: String,
        /// Unsupported provider setting key.
        option: String,
    },

    /// The provider does not support an operation or challenge type.
    #[error("DNS provider `{provider}` does not support {operation}")]
    Unsupported {
        /// Provider name.
        provider: String,
        /// Unsupported operation.
        operation: String,
    },
}

/// DNS-01 challenge provider.
///
/// Implementations must be safe to share across tasks (`Send + Sync`) because a single provider
/// instance may solve concurrent challenges.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Provider module name, e.g. `cloudflare` (matches Caddy's `dns.providers` module name).
    fn name(&self) -> &str;

    /// Find the authoritative zone in this provider that contains `fqdn`.
    ///
    /// Implementations typically use [`zone_candidates`] to try the name and its parents against
    /// the zones known to the provider.
    async fn find_zone(&self, fqdn: &str) -> DnsResult<String>;

    /// Create a TXT record for `fqdn` with `value` and return the created record.
    ///
    /// Implementations should validate the name with [`validate_record_name`], discover the zone
    /// with [`DnsProvider::find_zone`] and then call the provider API.
    async fn create_txt(&self, fqdn: &str, value: &str) -> DnsResult<TxtRecord>;

    /// Delete a previously created TXT record.
    async fn delete_txt(&self, record: &TxtRecord) -> DnsResult<()>;

    /// List all TXT records with the given name (any value).
    ///
    /// This is used by the default [`DnsProvider::wait_for_propagation`].
    async fn list_txt(&self, fqdn: &str) -> DnsResult<Vec<TxtRecord>>;

    /// Interval between propagation checks; providers may override to poll more or less often.
    fn propagation_poll_interval(&self) -> Duration {
        DEFAULT_PROPAGATION_POLL_INTERVAL
    }

    /// Wait until `record` is visible through [`DnsProvider::list_txt`].
    ///
    /// This is the propagation wait hook: the default implementation polls the provider, while a
    /// provider can override it to query authoritative nameservers or use its own preflight API.
    /// Returns [`DnsError::PropagationTimeout`] when `timeout` elapses; a timeout of zero performs
    /// a single check.
    async fn wait_for_propagation(&self, record: &TxtRecord, timeout: Duration) -> DnsResult<()> {
        let started = tokio::time::Instant::now();
        let deadline = started + timeout;
        loop {
            let records = self.list_txt(&record.fqdn).await?;
            if records
                .iter()
                .any(|existing| existing.value == record.value)
            {
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(DnsError::PropagationTimeout {
                    fqdn: record.fqdn.clone(),
                    timeout,
                });
            }
            let remaining = deadline - now;
            tokio::time::sleep(self.propagation_poll_interval().min(remaining)).await;
        }
    }
}

/// Candidate zones for a name, most specific first.
///
/// Trailing dots are stripped and the name is lowercased. Single-label (TLD-only) candidates are
/// never returned, because a provider cannot own a TLD.
///
/// ```
/// # use caddy_rs_tls::dns::zone_candidates;
/// assert_eq!(
///     zone_candidates("_acme-challenge.api.example.com"),
///     vec![
///         "_acme-challenge.api.example.com",
///         "api.example.com",
///         "example.com",
///     ]
/// );
/// ```
pub fn zone_candidates(fqdn: &str) -> Vec<String> {
    let fqdn = fqdn.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = fqdn.split('.').filter(|label| !label.is_empty()).collect();
    if labels.is_empty() {
        return Vec::new();
    }
    if labels.len() == 1 {
        return vec![labels[0].to_string()];
    }
    (0..=labels.len() - 2)
        .map(|start| labels[start..].join("."))
        .collect()
}

/// Find the most specific zone in `zones` that contains `fqdn`.
pub fn longest_known_zone(fqdn: &str, zones: &[String]) -> Option<String> {
    zone_candidates(fqdn)
        .into_iter()
        .find(|candidate| zones.iter().any(|zone| zone == candidate))
}

/// Validate a TXT record name.
///
/// Names may contain underscores (`_acme-challenge` is a standard ACME name), letters, digits and
/// hyphens, with at least two labels and no empty, oversized or hyphen-edged labels. Names must be
/// ASCII (internationalised names are stored in punycode form by DNS software).
pub fn validate_record_name(fqdn: &str) -> DnsResult<()> {
    let name = fqdn.strip_suffix('.').unwrap_or(fqdn);
    let invalid = |reason: &str| DnsError::InvalidName {
        name: fqdn.to_string(),
        reason: reason.to_string(),
    };
    if name.is_empty() {
        return Err(invalid("name is empty"));
    }
    if name.len() > 253 {
        return Err(invalid("name is longer than 253 characters"));
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err(invalid("name must contain at least two labels"));
    }
    for label in labels {
        if label.is_empty() {
            return Err(invalid("name contains an empty label"));
        }
        if label.len() > 63 {
            return Err(invalid("a label is longer than 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid("labels must not start or end with a hyphen"));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid(
                "labels may only contain ASCII letters, digits, `-` and `_`",
            ));
        }
    }
    Ok(())
}

/// How long to wait for a TXT record to become visible, as configured under `challenges.dns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PropagationTimeout {
    /// Use the Caddy/CertMagic default ([`DEFAULT_PROPAGATION_TIMEOUT`]).
    #[default]
    Default,
    /// Propagation checks are disabled (`propagation_timeout: -1` in Caddy JSON).
    Disabled,
    /// Wait for the given duration.
    After(Duration),
}

impl PropagationTimeout {
    /// The timeout to use for [`DnsProvider::wait_for_propagation`], or `None` when checks are
    /// disabled.
    pub fn duration(self) -> Option<Duration> {
        match self {
            Self::Default => Some(DEFAULT_PROPAGATION_TIMEOUT),
            Self::Disabled => None,
            Self::After(timeout) => Some(timeout),
        }
    }
}

/// The `challenges.dns` configuration from Caddy's `tls.issuance.acme` JSON.
///
/// Caddy stores the provider as an inline module object:
///
/// ```json
/// {
///   "provider": { "name": "cloudflare", "api_token": "..." },
///   "propagation_delay": 0,
///   "propagation_timeout": 120000000000,
///   "resolvers": ["1.1.1.1:53"]
/// }
/// ```
///
/// Durations are nanoseconds, matching `caddy.Duration` JSON encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsChallengeConfig {
    /// DNS provider module name (`dns.providers.<name>`).
    pub provider: String,
    /// TTL for the challenge TXT record.
    pub ttl: Option<Duration>,
    /// Delay before the first propagation check.
    pub propagation_delay: Option<Duration>,
    /// Maximum propagation wait.
    pub propagation_timeout: PropagationTimeout,
    /// Custom resolvers used for propagation checks.
    pub resolvers: Vec<String>,
    /// Domain to write the challenge record under instead of the certificate domain
    /// (Caddy's `override_domain`).
    pub override_domain: Option<String>,
    /// Provider-specific settings (API tokens, ...), preserved verbatim from the module object.
    pub settings: serde_json::Map<String, Value>,
}

impl Default for DnsChallengeConfig {
    fn default() -> Self {
        Self {
            provider: String::new(),
            ttl: None,
            propagation_delay: None,
            propagation_timeout: PropagationTimeout::default(),
            resolvers: Vec::new(),
            override_domain: None,
            settings: serde_json::Map::new(),
        }
    }
}

impl DnsChallengeConfig {
    /// Parse the `challenges.dns` object from Caddy JSON.
    pub fn from_caddy_json(value: &Value) -> DnsResult<Self> {
        let object = value.as_object().ok_or_else(|| DnsError::Config {
            message: "`challenges.dns` must be an object".to_string(),
        })?;
        let provider_value = object.get("provider").ok_or_else(|| DnsError::Config {
            message: "`challenges.dns.provider` is required".to_string(),
        })?;
        let (provider, settings) = match provider_value {
            Value::Object(module) => {
                let name = module
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| DnsError::Config {
                        message: "`challenges.dns.provider.name` is required".to_string(),
                    })?;
                let mut settings = module.clone();
                settings.remove("name");
                (name.to_string(), settings)
            }
            Value::String(name) if !name.is_empty() => (name.clone(), serde_json::Map::new()),
            _ => {
                return Err(DnsError::Config {
                    message: "`challenges.dns.provider` must be a provider module object"
                        .to_string(),
                })
            }
        };

        let propagation_timeout = match object.get("propagation_timeout") {
            None | Some(Value::Null) => PropagationTimeout::Default,
            Some(Value::Number(number)) => {
                let nanoseconds = number.as_i64().ok_or_else(|| DnsError::Config {
                    message: "`challenges.dns.propagation_timeout` must be an integer number of \
                              nanoseconds"
                        .to_string(),
                })?;
                if nanoseconds < 0 {
                    PropagationTimeout::Disabled
                } else {
                    PropagationTimeout::After(Duration::from_nanos(nanoseconds as u64))
                }
            }
            Some(_) => {
                return Err(DnsError::Config {
                    message: "`challenges.dns.propagation_timeout` must be an integer number of \
                              nanoseconds (`-1` disables propagation checks)"
                        .to_string(),
                })
            }
        };

        let mut config = Self {
            provider,
            ttl: optional_duration(object, "ttl")?,
            propagation_delay: optional_duration(object, "propagation_delay")?,
            propagation_timeout,
            resolvers: string_array(object, "resolvers")?,
            override_domain: object
                .get("override_domain")
                .and_then(Value::as_str)
                .filter(|domain| !domain.is_empty())
                .map(str::to_string),
            settings,
        };
        // The provider module object and the top-level `provider` key are both part of Caddy's
        // shape; keep provider settings separate from challenge-level settings.
        config.settings.remove("provider");
        Ok(config)
    }

    /// The TXT record name to publish for `domain`, honouring `override_domain`.
    pub fn record_fqdn(&self, domain: &str) -> String {
        format!(
            "_acme-challenge.{}",
            self.override_domain.as_deref().unwrap_or(domain)
        )
    }

    /// Timeout for propagation checks, or `None` if checks are disabled.
    pub fn propagation_timeout_duration(&self) -> Option<Duration> {
        self.propagation_timeout.duration()
    }
}

fn optional_duration(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> DnsResult<Option<Duration>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => {
            let nanoseconds = number.as_i64().ok_or_else(|| DnsError::Config {
                message: format!(
                    "`challenges.dns.{field}` must be an integer number of nanoseconds"
                ),
            })?;
            if nanoseconds < 0 {
                return Err(DnsError::Config {
                    message: format!("`challenges.dns.{field}` must not be negative"),
                });
            }
            Ok(Some(Duration::from_nanos(nanoseconds as u64)))
        }
        Some(_) => Err(DnsError::Config {
            message: format!("`challenges.dns.{field}` must be an integer number of nanoseconds"),
        }),
    }
}

fn string_array(object: &serde_json::Map<String, Value>, field: &str) -> DnsResult<Vec<String>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| DnsError::Config {
                        message: format!("`challenges.dns.{field}` must be an array of strings"),
                    })
            })
            .collect(),
        Some(_) => Err(DnsError::Config {
            message: format!("`challenges.dns.{field}` must be an array of strings"),
        }),
    }
}

/// In-process [`DnsProvider`] used by tests (and local development); performs no network I/O.
///
/// Zones and records are held in memory. Tests can hide records to exercise propagation waits
/// ([`InMemoryDnsProvider::set_visible`]) and inject provider errors
/// ([`InMemoryDnsProvider::set_failure`]).
#[derive(Debug)]
pub struct InMemoryDnsProvider {
    name: String,
    zones: RwLock<Vec<String>>,
    records: RwLock<Vec<TxtRecord>>,
    next_id: AtomicU64,
    visible: AtomicBool,
    failure: RwLock<Option<DnsError>>,
}

impl Default for InMemoryDnsProvider {
    fn default() -> Self {
        Self::new()
    }
}

// INFEASIBLE: every lock unwrap in this impl guards plain Vec/Option state whose critical
// sections cannot panic, so poisoning is impossible.
impl InMemoryDnsProvider {
    /// An empty provider named `in_memory`.
    pub fn new() -> Self {
        Self {
            name: "in_memory".to_string(),
            zones: RwLock::new(Vec::new()),
            records: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(1),
            visible: AtomicBool::new(true),
            failure: RwLock::new(None),
        }
    }

    /// A provider that owns the given zones.
    pub fn with_zones(zones: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let provider = Self::new();
        provider.zones.write().unwrap().extend(
            zones
                .into_iter()
                .map(Into::into)
                .map(|zone: String| zone.trim_end_matches('.').to_ascii_lowercase()),
        );
        provider
    }

    /// Name the fake provider reports; defaults to `in_memory`.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Add a managed zone.
    pub fn add_zone(&self, zone: impl Into<String>) {
        self.zones
            .write()
            .unwrap()
            .push(zone.into().trim_end_matches('.').to_ascii_lowercase());
    }

    /// All records currently held by the provider (including ones hidden from propagation checks).
    pub fn records(&self) -> Vec<TxtRecord> {
        self.records.read().unwrap().clone()
    }

    /// Make [`DnsProvider::list_txt`] return no records when `false`, simulating slow propagation.
    pub fn set_visible(&self, visible: bool) {
        self.visible.store(visible, Ordering::SeqCst);
    }

    /// Make every provider operation fail with `error` until cleared with `set_failure(None)`.
    pub fn set_failure(&self, error: Option<DnsError>) {
        *self.failure.write().unwrap() = error;
    }

    fn injected_failure(&self) -> DnsResult<()> {
        match self.failure.read().unwrap().clone() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[async_trait]
// INFEASIBLE: same lock invariant as above; these are test-support providers.
impl DnsProvider for InMemoryDnsProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn find_zone(&self, fqdn: &str) -> DnsResult<String> {
        self.injected_failure()?;
        validate_record_name(fqdn)?;
        let zones = self.zones.read().unwrap().clone();
        longest_known_zone(fqdn, &zones).ok_or_else(|| DnsError::ZoneNotFound {
            provider: self.name.clone(),
            fqdn: fqdn.to_string(),
        })
    }

    async fn create_txt(&self, fqdn: &str, value: &str) -> DnsResult<TxtRecord> {
        self.injected_failure()?;
        let fqdn = fqdn.trim_end_matches('.').to_ascii_lowercase();
        let zone = self.find_zone(&fqdn).await?;
        let mut records = self.records.write().unwrap();
        if records
            .iter()
            .any(|record| record.fqdn == fqdn && record.value == value)
        {
            return Err(DnsError::RecordExists {
                fqdn,
                value: value.to_string(),
            });
        }
        let id = RecordId::new(format!(
            "record-{}",
            self.next_id.fetch_add(1, Ordering::SeqCst)
        ));
        let record = TxtRecord {
            id,
            fqdn,
            zone,
            value: value.to_string(),
        };
        records.push(record.clone());
        Ok(record)
    }

    async fn delete_txt(&self, record: &TxtRecord) -> DnsResult<()> {
        self.injected_failure()?;
        let mut records = self.records.write().unwrap();
        let before = records.len();
        records.retain(|existing| existing.id != record.id);
        if records.len() == before {
            return Err(DnsError::RecordNotFound {
                fqdn: record.fqdn.clone(),
            });
        }
        Ok(())
    }

    async fn list_txt(&self, fqdn: &str) -> DnsResult<Vec<TxtRecord>> {
        self.injected_failure()?;
        validate_record_name(fqdn)?;
        if !self.visible.load(Ordering::SeqCst) {
            return Ok(Vec::new());
        }
        let fqdn = fqdn.trim_end_matches('.').to_ascii_lowercase();
        Ok(self
            .records
            .read()
            .unwrap()
            .iter()
            .filter(|record| record.fqdn == fqdn)
            .cloned()
            .collect())
    }

    fn propagation_poll_interval(&self) -> Duration {
        Duration::from_millis(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> InMemoryDnsProvider {
        InMemoryDnsProvider::with_zones(["example.com", "example.net", "api.example.org"])
    }

    #[test]
    fn zone_candidates_go_from_specific_to_general() {
        assert_eq!(
            zone_candidates("_acme-challenge.api.example.com"),
            vec![
                "_acme-challenge.api.example.com",
                "api.example.com",
                "example.com",
            ]
        );
        assert_eq!(zone_candidates("example.com"), vec!["example.com"]);
        assert_eq!(zone_candidates("example.com."), vec!["example.com"]);
        assert_eq!(
            longest_known_zone("_acme-challenge.example.com", &provider_zones()),
            Some("example.com".to_string())
        );
        assert_eq!(longest_known_zone("example.org", &provider_zones()), None);
    }

    fn provider_zones() -> Vec<String> {
        ["example.com", "api.example.com"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn record_names_are_validated() {
        for valid in [
            "_acme-challenge.example.com",
            "_acme-challenge.api.example.com.",
            "example.com",
        ] {
            validate_record_name(valid)
                .unwrap_or_else(|error| panic!("`{valid}` should be valid, got {error:?}"));
        }
        for invalid in [
            "",
            "example",
            "_acme-challenge..example.com",
            "-bad.example.com",
        ] {
            assert!(
                matches!(
                    validate_record_name(invalid),
                    Err(DnsError::InvalidName { .. })
                ),
                "`{invalid}` should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn in_memory_provider_creates_lists_and_deletes() {
        let provider = provider();
        let record = provider
            .create_txt("_acme-challenge.example.com", "token-value")
            .await
            .unwrap();
        assert_eq!(record.zone, "example.com");
        assert_eq!(record.fqdn, "_acme-challenge.example.com");
        assert_eq!(
            provider
                .list_txt("_acme-challenge.example.com")
                .await
                .unwrap(),
            vec![record.clone()]
        );
        provider.delete_txt(&record).await.unwrap();
        assert!(provider
            .list_txt("_acme-challenge.example.com")
            .await
            .unwrap()
            .is_empty());
        assert!(matches!(
            provider.delete_txt(&record).await,
            Err(DnsError::RecordNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn in_memory_provider_rejects_unmanaged_zones() {
        let provider = provider();
        let error = provider
            .create_txt("_acme-challenge.unknown.invalid", "value")
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                DnsError::ZoneNotFound { provider, fqdn }
                    if provider == "in_memory" && fqdn == "_acme-challenge.unknown.invalid"
            ),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn injected_provider_failure_is_typed() {
        let provider = provider();
        provider.set_failure(Some(DnsError::Provider {
            provider: "in_memory".to_string(),
            message: "rate limited".to_string(),
        }));
        let error = provider
            .create_txt("_acme-challenge.example.com", "value")
            .await
            .unwrap_err();
        assert_eq!(
            error,
            DnsError::Provider {
                provider: "in_memory".to_string(),
                message: "rate limited".to_string(),
            }
        );
        provider.set_failure(None);
        provider
            .create_txt("_acme-challenge.example.com", "value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn propagation_wait_succeeds_once_the_record_is_visible() {
        let provider = provider();
        let record = TxtRecord {
            id: RecordId::new("unused"),
            fqdn: "_acme-challenge.example.com".to_string(),
            zone: "example.com".to_string(),
            value: "token".to_string(),
        };
        let created = provider
            .create_txt(&record.fqdn, &record.value)
            .await
            .unwrap();
        provider
            .wait_for_propagation(&created, Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn propagation_wait_times_out_with_typed_error() {
        let provider = provider();
        let record = provider
            .create_txt("_acme-challenge.example.com", "token")
            .await
            .unwrap();
        provider.set_visible(false);
        let error = provider
            .wait_for_propagation(&record, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                DnsError::PropagationTimeout { fqdn, timeout }
                    if fqdn == "_acme-challenge.example.com" && *timeout == Duration::from_millis(50)
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn challenge_config_parses_caddy_json() {
        let config = DnsChallengeConfig::from_caddy_json(&serde_json::json!({
            "provider": {
                "name": "cloudflare",
                "api_token": "secret"
            },
            "ttl": 300_000_000_000_i64,
            "propagation_delay": 10_000_000_000_i64,
            "propagation_timeout": 240_000_000_000_i64,
            "resolvers": ["1.1.1.1:53"],
            "override_domain": "challenges.example.net"
        }))
        .unwrap();
        assert_eq!(config.provider, "cloudflare");
        assert_eq!(config.ttl, Some(Duration::from_secs(300)));
        assert_eq!(config.propagation_delay, Some(Duration::from_secs(10)));
        assert_eq!(
            config.propagation_timeout_duration(),
            Some(Duration::from_secs(240))
        );
        assert_eq!(config.resolvers, vec!["1.1.1.1:53"]);
        assert_eq!(config.settings["api_token"], serde_json::json!("secret"));
        assert_eq!(
            config.record_fqdn("example.com"),
            "_acme-challenge.challenges.example.net"
        );
    }

    #[test]
    fn challenge_config_defaults_and_disabled_timeout() {
        let config =
            DnsChallengeConfig::from_caddy_json(&serde_json::json!({"provider": "route53"}))
                .unwrap();
        assert_eq!(config.provider, "route53");
        assert_eq!(
            config.propagation_timeout_duration(),
            Some(DEFAULT_PROPAGATION_TIMEOUT)
        );
        assert_eq!(
            config.record_fqdn("example.com"),
            "_acme-challenge.example.com"
        );

        let disabled = DnsChallengeConfig::from_caddy_json(&serde_json::json!({
            "provider": {"name": "cloudflare"},
            "propagation_timeout": -1
        }))
        .unwrap();
        assert_eq!(disabled.propagation_timeout_duration(), None);

        assert!(matches!(
            DnsChallengeConfig::from_caddy_json(&serde_json::json!({})),
            Err(DnsError::Config { .. })
        ));
        assert!(matches!(
            DnsChallengeConfig::from_caddy_json(&serde_json::json!({
                "provider": {"api_token": "missing-name"}
            })),
            Err(DnsError::Config { .. })
        ));
    }

    #[test]
    fn dns_errors_convert_to_tls_error() {
        let error: crate::Error = DnsError::RecordNotFound {
            fqdn: "_acme-challenge.example.com".to_string(),
        }
        .into();
        assert!(error.to_string().contains("_acme-challenge.example.com"));
    }
}
