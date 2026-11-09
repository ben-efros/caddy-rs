//! Application service for the caddy-rs proxy manager.
//!
//! [`HostService`] is the thin command layer between a future API/UI and the durable host
//! repository. It owns the two decisions the repository cannot make on its own:
//!
//! * id allocation for [`HostService::create`] — a [`HostDraft`] has no stable id, so the service
//!   reserves the next one before the repository validates and writes the host;
//! * route compilation for [`HostService::compile`] — the service reads one host snapshot and
//!   hands it to `pm-compiler`.
//!
//! Update and delete accept the caller's expected revision unchanged, so the repository's
//! compare-and-swap remains the only concurrency control. Every mutation validates the host's
//! structure in the repository; the service does not add a second validation pass.
//!
//! # Scope
//!
//! This crate has no REST API, UI, authentication or authorization. It also does **not** load
//! certificates or auto policies. When a draft uses `Manual`, `AcmeConfigured`, `InternalCa` or
//! `Auto` TLS, the caller must load the referenced object and run
//! [`Host::validate`](caddy_rs_pm_core::Host::validate) before calling `create` or `update`,
//! because [`Host::validate_structure`](caddy_rs_pm_core::Host::validate_structure) — the only
//! check the repository performs — cannot verify existence or domain coverage.
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
use caddy_rs_pm_core::{Host, HostId, HostSpec, HostTls};
use caddy_rs_pm_hosts::{HostError, HostRepository, StoredHost};
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
}

/// Host commands and route compilation over one [`StateStore`].
///
/// The service is cheap to clone; all clones share the repository and therefore the store.
#[derive(Clone)]
pub struct HostService {
    repository: HostRepository,
}

impl HostService {
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self {
            repository: HostRepository::new(store),
        }
    }

    /// Create a host with the next persisted id.
    ///
    /// The id is allocated before the repository validates the draft, so a rejected draft or a
    /// domain conflict consumes it and the store is otherwise unchanged. See the crate-level
    /// documentation on id allocation.
    pub fn create(&self, draft: HostDraft) -> Result<StoredHost, ServiceError> {
        let id = self.repository.next_id()?;
        let host = Host::new(HostId(id), draft.domains, draft.tls, draft.spec);
        Ok(self.repository.create(host)?)
    }

    /// Replace a host under a compare-and-swap revision.
    ///
    /// The service does not read the current host first: it builds the host with the supplied id and
    /// lets the repository verify the revision atomically.
    pub fn update(
        &self,
        id: HostId,
        expected_revision: Revision,
        draft: HostDraft,
    ) -> Result<StoredHost, ServiceError> {
        let host = Host::new(id, draft.domains, draft.tls, draft.spec);
        Ok(self.repository.update(host, expected_revision)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_pm_core::{CoreError, HostSpec, HostTls, ProxySpec, Upstream, UpstreamScheme};
    use caddy_rs_pm_state::{MemoryStore, SnapshotStore, StateError};
    use serde_json::json;

    fn service() -> HostService {
        HostService::new(Arc::new(MemoryStore::default()))
    }

    fn proxy_draft(domains: &[&str]) -> HostDraft {
        HostDraft {
            domains: domains.iter().map(|value| (*value).to_string()).collect(),
            tls: HostTls::disabled(),
            spec: HostSpec::Proxy(ProxySpec::new(Upstream::new(
                UpstreamScheme::Http,
                "10.0.0.5",
                8080,
            ))),
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
}
