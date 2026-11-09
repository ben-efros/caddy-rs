//! Application service for the caddy-rs proxy manager.
//!
//! [`HostService`] is the thin command layer between a future API/UI and the durable host
//! repository. It owns the three decisions the repository cannot make on its own:
//!
//! * id allocation for [`HostService::create`] — a [`HostDraft`] has no stable id, so the service
//!   reserves the next one before the repository validates and writes the host;
//! * route compilation for [`HostService::compile`] — the service reads one host snapshot and
//!   hands it to `pm-compiler`;
//! * policy-aware TLS validation before a create or update is written, when the service is
//!   configured with a [`PolicyRepository`].
//!
//! Update and delete accept the caller's expected revision unchanged, so the repository's
//! compare-and-swap remains the only concurrency control. The service validates the TLS reference
//! before the write; the repository still validates the host's structure.
//!
//! # Policy-aware TLS validation
//!
//! [`HostService::new`] keeps the pre-policy behavior and configures **no** policy repository. It
//! therefore rejects every `TlsMode::Auto` host with
//! [`ServiceError::PolicyValidationUnavailable`] rather than silently skipping the coverage check.
//! [`HostService::with_policies`] wires a [`PolicyRepository`] into the service. Before `create`
//! and `update` write a host, the service builds it and validates its TLS binding:
//!
//! * `Disabled` loads nothing and proceeds; the repository still runs structural validation;
//! * `Auto` loads `tls.auto_policy_id`. A missing policy is a located
//!   [`ServiceError::PolicyNotFound`]; a disabled policy or a domain-coverage failure is a located
//!   [`ServiceError::Tls`] carrying the [`CoreError`] from
//!   [`Host::validate`], which also re-checks mode/reference consistency;
//! * `Manual`, `AcmeConfigured` and `InternalCa` fail with
//!   [`ServiceError::UnsupportedExplicitCertificate`]. This crate has no certificate repository,
//!   so coverage cannot be checked; returning success would silently skip it.
//!
//! Failed validation persists nothing. [`HostService::create`] still reserves the id first, so a
//! rejected create consumes that id and leaves the store otherwise unchanged.
//! [`HostService::update`] builds and validates the candidate host before calling
//! `repository.update`, so the repository's compare-and-swap remains the only concurrency control
//! and no read-modify-write is introduced.
//!
//! # Scope
//!
//! This crate has no REST API, UI, authentication or authorization. It does not load
//! certificates: explicit-certificate TLS modes are rejected as unsupported until a certificate
//! repository exists. Auto policies are loaded only when a policy repository is configured.
//!
//! # Id allocation
//!
//! [`HostService::create`] reserves the id before validating or writing the host. A failed create
//! therefore consumes the id: a domain conflict leaves the store otherwise unchanged, but the next
//! successful create receives a higher id. Gaps in the id sequence are expected and safe; ids are
//! never reused, including after a delete.

#![forbid(unsafe_code)]

use std::sync::Arc;

use caddy_rs_pm_compiler::{compile_routes, CompileError, CompiledRoutes};
use caddy_rs_pm_core::{CoreError, Host, HostId, HostSpec, HostTls, TlsMode};
use caddy_rs_pm_hosts::{HostError, HostRepository, StoredHost};
use caddy_rs_pm_policies::{PolicyError, PolicyRepository};
use caddy_rs_pm_state::{Revision, StateStore};
use thiserror::Error;

/// The caller-supplied fields of a host, without a stable id.
///
/// The service assigns the id in [`HostService::create`]. Drafts always produce enabled hosts;
/// enabling or disabling an existing host is not part of this slice, and [`HostService::update`]
/// replaces the whole host with the draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDraft {
    pub domains: Vec<String>,
    pub tls: HostTls,
    pub spec: HostSpec,
}

impl HostDraft {
    pub fn new(domains: Vec<String>, tls: HostTls, spec: HostSpec) -> Self {
        Self { domains, tls, spec }
    }
}

/// A failed host command.
#[derive(Debug, Error)]
pub enum ServiceError {
    /// The repository rejected the command (validation, CAS conflict, missing host, ...).
    #[error(transparent)]
    Host(#[from] HostError),
    /// The stored hosts could not be compiled into Caddy routes.
    #[error(transparent)]
    Compile(#[from] CompileError),
    /// The auto-certificate policy repository could not be read.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// Auto TLS was requested but the service has no policy repository to validate against.
    #[error(
        "auto TLS validation is unavailable: HostService was constructed without a policy \
         repository"
    )]
    PolicyValidationUnavailable,
    /// An auto TLS host references a policy that is not stored.
    #[error("host {host_id} references auto-certificate policy {policy_id}, which was not found")]
    PolicyNotFound { host_id: u64, policy_id: u64 },
    /// Explicit-certificate TLS cannot be validated without a certificate repository.
    #[error(
        "host {host_id} uses TLS mode {mode:?}, which requires a certificate repository that \
         HostService does not have"
    )]
    UnsupportedExplicitCertificate { host_id: u64, mode: TlsMode },
    /// The built host failed TLS validation against its auto-certificate policy.
    #[error("host {host_id} failed TLS validation: {source}")]
    Tls {
        host_id: u64,
        policy_id: Option<u64>,
        #[source]
        source: CoreError,
    },
}

/// Host commands and route compilation over one [`StateStore`].
///
/// The service is cheap to clone; all clones share the repository and therefore the store.
#[derive(Clone)]
pub struct HostService {
    repository: HostRepository,
    policies: Option<PolicyRepository>,
}

impl HostService {
    /// Build a service without a policy repository.
    ///
    /// `Auto` TLS cannot be validated in this mode and is rejected with
    /// [`ServiceError::PolicyValidationUnavailable`]; use [`HostService::with_policies`] for hosts
    /// that reference an auto-certificate policy.
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self {
            repository: HostRepository::new(store),
            policies: None,
        }
    }

    /// Build a service whose `Auto` TLS hosts are validated against `policies`.
    ///
    /// `store` and `policies` must share the same underlying store; the service cannot check this,
    /// so the caller wires both from one [`StateStore`].
    pub fn with_policies(store: Arc<dyn StateStore>, policies: PolicyRepository) -> Self {
        Self {
            repository: HostRepository::new(store),
            policies: Some(policies),
        }
    }

    /// Create a host with the next persisted id.
    ///
    /// The id is allocated before validation and before the repository write, so a rejected draft,
    /// a failed TLS validation or a domain conflict consumes it and the store is otherwise
    /// unchanged. See the crate-level documentation on id allocation.
    pub fn create(&self, draft: HostDraft) -> Result<StoredHost, ServiceError> {
        let id = self.repository.next_id()?;
        let host = Host::new(HostId(id), draft.domains, draft.tls, draft.spec);
        self.validate_tls(&host)?;
        Ok(self.repository.create(host)?)
    }

    /// Replace a host under a compare-and-swap revision.
    ///
    /// The service does not read the current host first: it builds and validates the candidate host
    /// with the supplied id and lets the repository verify the revision atomically. A failed
    /// validation leaves the stored host and its revision untouched.
    pub fn update(
        &self,
        id: HostId,
        expected_revision: Revision,
        draft: HostDraft,
    ) -> Result<StoredHost, ServiceError> {
        let host = Host::new(id, draft.domains, draft.tls, draft.spec);
        self.validate_tls(&host)?;
        Ok(self.repository.update(host, expected_revision)?)
    }

    /// Validate the TLS binding before the host is written.
    ///
    /// `Disabled` needs no lookup. `Auto` requires a configured policy repository, loads the
    /// referenced policy and delegates the enabled-state, reference-consistency and coverage
    /// checks to [`Host::validate`]. Explicit-certificate modes are rejected until this crate has
    /// a certificate repository.
    fn validate_tls(&self, host: &Host) -> Result<(), ServiceError> {
        match host.tls.mode {
            TlsMode::Disabled => Ok(()),
            TlsMode::Auto => {
                let Some(policies) = &self.policies else {
                    return Err(ServiceError::PolicyValidationUnavailable);
                };
                let Some(policy_id) = host.tls.auto_policy_id else {
                    return Err(tls_error(host, CoreError::Missing("auto_policy_id")));
                };
                let Some(stored) = policies.get(policy_id)? else {
                    return Err(ServiceError::PolicyNotFound {
                        host_id: host.id.0,
                        policy_id: policy_id.0,
                    });
                };
                host.validate(None, Some(&stored.policy))
                    .map_err(|source| tls_error(host, source))
            }
            TlsMode::Manual | TlsMode::AcmeConfigured | TlsMode::InternalCa => {
                Err(ServiceError::UnsupportedExplicitCertificate {
                    host_id: host.id.0,
                    mode: host.tls.mode,
                })
            }
        }
    }

    /// Delete a host under a compare-and-swap revision.
    ///
    /// The repository also removes the host's domain index entries and records a tombstone so the id
    /// cannot be reused.
    pub fn delete(&self, id: HostId, expected_revision: Revision) -> Result<(), ServiceError> {
        Ok(self.repository.delete(id, expected_revision)?)
    }

    /// Every stored host, ordered by id.
    pub fn list(&self) -> Result<Vec<StoredHost>, ServiceError> {
        Ok(self.repository.list()?)
    }

    /// Compile all stored hosts into deterministic HTTP/HTTPS route lists.
    ///
    /// The service reads one repository snapshot; compilation itself performs no I/O.
    pub fn compile(&self) -> Result<CompiledRoutes, ServiceError> {
        let hosts = self.repository.snapshot_hosts()?;
        Ok(compile_routes(&hosts)?)
    }
}

fn tls_error(host: &Host, source: CoreError) -> ServiceError {
    ServiceError::Tls {
        host_id: host.id.0,
        policy_id: host.tls.auto_policy_id.map(|policy_id| policy_id.0),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_pm_core::{
        AutoCertificatePolicy, AutoMode, CertificateId, CertificateOrigin, CoreError, HostSpec,
        HostTls, PolicyId, ProxySpec, TlsMode, Upstream, UpstreamScheme,
    };
    use caddy_rs_pm_state::{MemoryStore, SnapshotStore, StateError};
    use serde_json::json;

    fn service() -> HostService {
        HostService::new(Arc::new(MemoryStore::default()))
    }

    fn service_with_policies() -> (HostService, PolicyRepository) {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStore::default());
        let policies = PolicyRepository::new(Arc::clone(&store));
        (
            HostService::with_policies(store, policies.clone()),
            policies,
        )
    }

    fn names(domains: &[&str]) -> Vec<String> {
        domains.iter().map(|value| (*value).to_string()).collect()
    }

    fn proxy_spec() -> HostSpec {
        HostSpec::Proxy(ProxySpec::new(Upstream::new(
            UpstreamScheme::Http,
            "10.0.0.5",
            8080,
        )))
    }

    fn proxy_draft(domains: &[&str]) -> HostDraft {
        HostDraft {
            domains: names(domains),
            tls: HostTls::disabled(),
            spec: proxy_spec(),
        }
    }

    fn auto_draft(domains: &[&str], policy_id: u64) -> HostDraft {
        HostDraft {
            domains: names(domains),
            tls: HostTls::for_auto(PolicyId(policy_id)),
            spec: proxy_spec(),
        }
    }

    fn manual_draft(domains: &[&str]) -> HostDraft {
        HostDraft {
            domains: names(domains),
            tls: HostTls::for_explicit(CertificateId(1), CertificateOrigin::Manual),
            spec: proxy_spec(),
        }
    }

    fn auto_policy(id: u64, subjects: &[&str], enabled: bool) -> AutoCertificatePolicy {
        AutoCertificatePolicy {
            id: PolicyId(id),
            name: format!("policy-{id}"),
            subjects: names(subjects),
            mode: AutoMode::OnDemand,
            issuer: None,
            key_type: None,
            renewal_window_ratio: None,
            enabled,
        }
    }

    #[test]
    fn create_allocates_sequential_ids() {
        let service = service();
        assert_eq!(
            service
                .create(proxy_draft(&["one.example.com"]))
                .expect("first")
                .host
                .id,
            HostId(1)
        );
        assert_eq!(
            service
                .create(proxy_draft(&["two.example.com"]))
                .expect("second")
                .host
                .id,
            HostId(2)
        );
    }

    #[test]
    fn create_and_list_return_hosts_in_id_order() {
        let service = service();
        let first = service
            .create(proxy_draft(&["b.example.com"]))
            .expect("create first");
        let second = service
            .create(proxy_draft(&["a.example.com"]))
            .expect("create second");
        assert_eq!(service.list().expect("list"), vec![first, second]);
    }

    #[test]
    fn compile_reflects_create_update_and_delete() {
        let service = service();
        let created = service
            .create(proxy_draft(&["site.example.com"]))
            .expect("create");

        let compiled = service.compile().expect("compile after create");
        assert!(compiled.https.is_empty());
        assert_eq!(
            compiled.http,
            vec![json!({
                "@id": "pm-host-1-http",
                "match": [{ "host": ["site.example.com"] }],
                "handle": [{
                    "handler": "reverse_proxy",
                    "upstreams": [{ "dial": "10.0.0.5:8080" }]
                }]
            })]
        );

        let updated = service
            .update(
                HostId(1),
                created.revision,
                proxy_draft(&["renamed.example.com"]),
            )
            .expect("update");
        let compiled = service.compile().expect("compile after update");
        assert_eq!(compiled.http[0]["@id"], "pm-host-1-http");
        assert_eq!(
            compiled.http[0]["match"][0]["host"],
            json!(["renamed.example.com"])
        );

        service.delete(HostId(1), updated.revision).expect("delete");
        assert!(service.list().expect("list").is_empty());
        assert!(service.compile().expect("compile after delete").is_empty());
    }

    #[test]
    fn update_rejects_a_stale_revision() {
        let service = service();
        let created = service
            .create(proxy_draft(&["first.example.com"]))
            .expect("create");
        let updated = service
            .update(
                HostId(1),
                created.revision,
                proxy_draft(&["second.example.com"]),
            )
            .expect("update");
        assert_eq!(updated.revision, created.revision + 1);

        let stale = service.update(
            HostId(1),
            created.revision,
            proxy_draft(&["third.example.com"]),
        );
        assert!(matches!(
            stale,
            Err(ServiceError::Host(HostError::State(
                StateError::Conflict { .. }
            )))
        ));
        assert_eq!(service.list().expect("list"), vec![updated]);
    }

    #[test]
    fn invalid_draft_is_rejected_without_persisting() {
        let service = service();
        let rejected = service.create(proxy_draft(&[]));
        assert!(matches!(
            rejected,
            Err(ServiceError::Host(HostError::Core(CoreError::Invalid(_))))
        ));
        assert!(service.list().expect("list").is_empty());
        assert!(service.compile().expect("compile").is_empty());
    }

    #[test]
    fn duplicate_domain_consumes_id_but_leaves_state_consistent() {
        let service = service();
        let first = service
            .create(proxy_draft(&["shared.example.com"]))
            .expect("first");
        assert_eq!(first.host.id, HostId(1));

        let duplicate = service.create(proxy_draft(&["shared.example.com"]));
        assert!(matches!(
            duplicate,
            Err(ServiceError::Host(HostError::State(
                StateError::Conflict { .. }
            )))
        ));
        assert_eq!(service.list().expect("list"), vec![first]);

        // The failed create consumed id 2, so the next host is id 3.
        let next = service
            .create(proxy_draft(&["other.example.com"]))
            .expect("next");
        assert_eq!(next.host.id, HostId(3));
        assert_eq!(service.list().expect("list").len(), 2);
        let compiled = service.compile().expect("compile");
        assert_eq!(compiled.http.len(), 2);
        assert_eq!(
            compiled
                .http
                .iter()
                .map(|route| route["match"][0]["host"].clone())
                .collect::<Vec<_>>(),
            vec![json!(["other.example.com"]), json!(["shared.example.com"]),]
        );
    }

    #[test]
    fn snapshot_backend_create_reopen_and_compile() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("pm-state.json");
        {
            let service =
                HostService::new(Arc::new(SnapshotStore::open(&path).expect("open store")));
            service
                .create(proxy_draft(&["persisted.example.com"]))
                .expect("create");
        }

        let service = HostService::new(Arc::new(SnapshotStore::open(&path).expect("reopen store")));
        let listed = service.list().expect("list after reopen");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].host.id, HostId(1));
        assert_eq!(
            listed[0].host.domains,
            vec!["persisted.example.com".to_string()]
        );

        let compiled = service.compile().expect("compile after reopen");
        assert_eq!(compiled.http.len(), 1);
        assert_eq!(compiled.http[0]["@id"], "pm-host-1-http");
        assert_eq!(
            compiled.http[0]["match"][0]["host"],
            json!(["persisted.example.com"])
        );
    }

    #[test]
    fn auto_tls_with_covering_policy_persists_host() {
        let (service, policies) = service_with_policies();
        policies
            .create(auto_policy(1, &["example.com", "*.example.com"], true))
            .expect("create policy");

        let created = service
            .create(auto_draft(&["example.com"], 1))
            .expect("create covered host");
        assert_eq!(created.host.id, HostId(1));
        assert_eq!(created.host.tls.mode, TlsMode::Auto);
        assert_eq!(created.host.tls.auto_policy_id, Some(PolicyId(1)));
        assert_eq!(service.list().expect("list"), vec![created]);
    }

    #[test]
    fn auto_tls_with_uncovered_domain_is_rejected_without_persisting() {
        let (service, policies) = service_with_policies();
        policies
            .create(auto_policy(1, &["covered.example.com"], true))
            .expect("create policy");

        let rejected = service.create(auto_draft(&["other.example.com"], 1));
        match rejected {
            Err(ServiceError::Tls {
                host_id: 1,
                policy_id: Some(1),
                source: CoreError::Coverage { origin, domains },
            }) => {
                assert_eq!(origin, CertificateOrigin::AutoGenerated);
                assert_eq!(domains, vec!["other.example.com".to_string()]);
            }
            other => panic!("expected located coverage error, got {other:?}"),
        }
        assert!(service.list().expect("list").is_empty());
        assert!(service.compile().expect("compile").is_empty());

        // The rejected create consumed id 1; the next host is id 2.
        let next = service
            .create(auto_draft(&["covered.example.com"], 1))
            .expect("create covered host");
        assert_eq!(next.host.id, HostId(2));
    }

    #[test]
    fn auto_tls_with_missing_policy_is_rejected_without_persisting() {
        let (service, _policies) = service_with_policies();
        let rejected = service.create(auto_draft(&["example.com"], 9));
        assert!(matches!(
            rejected,
            Err(ServiceError::PolicyNotFound {
                host_id: 1,
                policy_id: 9
            })
        ));
        assert!(service.list().expect("list").is_empty());
    }

    #[test]
    fn auto_tls_with_disabled_policy_is_rejected_without_persisting() {
        let (service, policies) = service_with_policies();
        policies
            .create(auto_policy(1, &["example.com"], false))
            .expect("create policy");

        match service.create(auto_draft(&["example.com"], 1)) {
            Err(ServiceError::Tls {
                host_id: 1,
                policy_id: Some(1),
                source: CoreError::Invalid(message),
            }) => assert!(
                message.contains("disabled"),
                "expected disabled-policy error, got {message}"
            ),
            other => panic!("expected located disabled-policy error, got {other:?}"),
        }
        assert!(service.list().expect("list").is_empty());
    }

    #[test]
    fn explicit_certificate_tls_is_rejected_as_unsupported() {
        let service = service();
        let rejected = service.create(manual_draft(&["example.com"]));
        assert!(matches!(
            rejected,
            Err(ServiceError::UnsupportedExplicitCertificate {
                host_id: 1,
                mode: TlsMode::Manual
            })
        ));
        assert!(service.list().expect("list").is_empty());
    }

    #[test]
    fn disabled_tls_does_not_require_a_policy_repository() {
        let service = service();
        let created = service
            .create(proxy_draft(&["plain.example.com"]))
            .expect("create without policy repository");
        assert_eq!(created.host.tls.mode, TlsMode::Disabled);
    }

    #[test]
    fn disabled_tls_works_with_a_policy_repository() {
        let (service, _policies) = service_with_policies();
        let created = service
            .create(proxy_draft(&["plain.example.com"]))
            .expect("create with policy repository");
        assert_eq!(created.host.tls.mode, TlsMode::Disabled);
    }

    #[test]
    fn auto_tls_without_policy_repository_is_unavailable() {
        let service = service();
        let rejected = service.create(auto_draft(&["example.com"], 1));
        assert!(matches!(
            rejected,
            Err(ServiceError::PolicyValidationUnavailable)
        ));
        assert!(service.list().expect("list").is_empty());
    }

    #[test]
    fn update_with_uncovered_tls_is_rejected_and_leaves_host_unchanged() {
        let (service, policies) = service_with_policies();
        policies
            .create(auto_policy(1, &["covered.example.com"], true))
            .expect("create policy");
        let created = service
            .create(auto_draft(&["covered.example.com"], 1))
            .expect("create covered host");

        let rejected = service.update(
            created.host.id,
            created.revision,
            auto_draft(&["other.example.com"], 1),
        );
        assert!(matches!(
            rejected,
            Err(ServiceError::Tls {
                source: CoreError::Coverage { .. },
                ..
            })
        ));
        assert_eq!(service.list().expect("list"), vec![created]);
    }
}
