//! Durable host repository for the caddy-rs proxy manager.
//!
//! The repository stores validated [`Host`] documents in the namespaced
//! [`StateStore`](caddy_rs_pm_state::StateStore) and maintains a domain index so hostnames remain
//! unique without scanning every host on each write. Every mutation is one compare-and-swap
//! transaction: a failed precondition or persistence error leaves the store unchanged.
//!
//! This crate is persistence only. It does not allocate TLS certificates, compile Caddy JSON or
//! expose an HTTP API.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::Arc;

use caddy_rs_pm_core::{Host, HostId};
use caddy_rs_pm_state::{Document, Revision, StateError, StateStore, Transaction};
use serde_json::{json, Value};
use thiserror::Error;

const HOSTS: &str = "pm.hosts";
const DOMAINS: &str = "pm.host-domains";
const META: &str = "pm.meta";
const NEXT_ID: &str = "next-host-id";

/// A host together with the store revision that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredHost {
    pub host: Host,
    pub revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainOwner {
    pub host_id: HostId,
    pub revision: Revision,
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error(transparent)]
    Core(#[from] caddy_rs_pm_core::CoreError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("host JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("host {0} was not found")]
    NotFound(u64),
    #[error("host domain `{0}` is already used by another host")]
    DomainInUse(String),
    #[error("host {0} already exists")]
    AlreadyExists(u64),
    #[error("invalid stored host document: {0}")]
    InvalidDocument(String),
}

/// A host repository over a [`StateStore`].
#[derive(Clone)]
pub struct HostRepository {
    store: Arc<dyn StateStore>,
}

impl HostRepository {
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self { store }
    }

    /// Read one host. A missing document is `Ok(None)`.
    pub fn get(&self, id: HostId) -> Result<Option<StoredHost>, HostError> {
        let Some(document) = self.store.get(HOSTS, &id.0.to_string())? else {
            return Ok(None);
        };
        Ok(Some(decode_host(document)?))
    }

    /// Every stored host, ordered by id.
    pub fn list(&self) -> Result<Vec<StoredHost>, HostError> {
        let mut hosts = self
            .store
            .scan(HOSTS, "")?
            .into_iter()
            .map(decode_host)
            .collect::<Result<Vec<_>, _>>()?;
        hosts.sort_by_key(|stored| stored.host.id.0);
        Ok(hosts)
    }

    /// Every stored host without revisions, for the route compiler.
    pub fn snapshot_hosts(&self) -> Result<Vec<Host>, HostError> {
        Ok(self.list()?.into_iter().map(|stored| stored.host).collect())
    }

    /// The host that owns a normalized domain, if any.
    pub fn domain_owner(&self, domain: &str) -> Result<Option<DomainOwner>, HostError> {
        let normalized = caddy_rs_pm_core::normalize_pattern(domain)?;
        let Some(document) = self.store.get(DOMAINS, &normalized)? else {
            return Ok(None);
        };
        let host_id = document
            .value
            .get("host_id")
            .and_then(Value::as_u64)
            .ok_or_else(|| HostError::InvalidDocument("domain index has no host_id".to_string()))?;
        Ok(Some(DomainOwner {
            host_id: HostId(host_id),
            revision: document.revision,
        }))
    }

    /// Insert a host with a caller-assigned id.
    ///
    /// Fails if the id exists or any normalized domain is already owned by another host. The host
    /// id and every domain index are written in one transaction.
    pub fn create(&self, host: Host) -> Result<StoredHost, HostError> {
        host.validate_structure()?;
        let domains = host.normalized_domains()?;
        let value = serde_json::to_value(&host)?;
        let mut transaction = Transaction::new().check_missing(HOSTS, host.id.0.to_string());
        for domain in &domains {
            transaction = transaction.check_missing(DOMAINS, domain.clone());
        }
        transaction = transaction.put(HOSTS, host.id.0.to_string(), value);
        for domain in &domains {
            transaction = transaction.put(DOMAINS, domain.clone(), json!({ "host_id": host.id.0 }));
        }
        let commit = self.store.transact(transaction)?;
        let revision = commit
            .written
            .iter()
            .find(|document| document.namespace == HOSTS && document.key == host.id.0.to_string())
            .map(|document| document.revision)
            .ok_or_else(|| {
                HostError::InvalidDocument("host transaction did not return the host".to_string())
            })?;
        Ok(StoredHost { host, revision })
    }

    /// Update a host under a compare-and-swap revision.
    ///
    /// Domains removed by the update release their index entries; domains added by the update are
    /// checked for conflicts. The host and index changes commit atomically.
    pub fn update(&self, host: Host, expected_revision: Revision) -> Result<StoredHost, HostError> {
        host.validate_structure()?;
        let current = self.get(host.id)?.ok_or(HostError::NotFound(host.id.0))?;
        let old_domains: BTreeSet<String> =
            current.host.normalized_domains()?.into_iter().collect();
        let new_domains: BTreeSet<String> = host.normalized_domains()?.into_iter().collect();
        let added: Vec<&String> = new_domains.difference(&old_domains).collect();
        let removed: Vec<&String> = old_domains.difference(&new_domains).collect();

        let snapshot = self.store.snapshot()?;
        let mut transaction =
            Transaction::new().check_revision(HOSTS, host.id.0.to_string(), expected_revision);
        for domain in &added {
            transaction = transaction.check_missing(DOMAINS, (*domain).clone());
        }
        for domain in &removed {
            let document = snapshot.get(DOMAINS, domain).ok_or_else(|| {
                HostError::InvalidDocument(format!("missing domain index `{domain}`"))
            })?;
            transaction = transaction.check_revision(DOMAINS, (*domain).clone(), document.revision);
        }
        transaction = transaction.put(HOSTS, host.id.0.to_string(), serde_json::to_value(&host)?);
        for domain in &added {
            transaction =
                transaction.put(DOMAINS, (*domain).clone(), json!({ "host_id": host.id.0 }));
        }
        for domain in &removed {
            transaction = transaction.delete(DOMAINS, (*domain).clone());
        }
        let commit = self.store.transact(transaction)?;
        let revision = commit
            .written
            .iter()
            .find(|document| document.namespace == HOSTS && document.key == host.id.0.to_string())
            .map(|document| document.revision)
            .ok_or_else(|| {
                HostError::InvalidDocument("host transaction did not return the host".to_string())
            })?;
        Ok(StoredHost { host, revision })
    }

    /// Delete a host and every domain index owned by it.
    pub fn delete(&self, id: HostId, expected_revision: Revision) -> Result<(), HostError> {
        let current = self.get(id)?.ok_or(HostError::NotFound(id.0))?;
        let snapshot = self.store.snapshot()?;
        let mut transaction =
            Transaction::new().check_revision(HOSTS, id.0.to_string(), expected_revision);
        for domain in current.host.normalized_domains()? {
            let document = snapshot.get(DOMAINS, &domain).ok_or_else(|| {
                HostError::InvalidDocument(format!("missing domain index `{domain}`"))
            })?;
            if document.value.get("host_id").and_then(Value::as_u64) != Some(id.0) {
                return Err(HostError::DomainInUse(domain));
            }
            transaction = transaction.check_revision(DOMAINS, domain.clone(), document.revision);
            transaction = transaction.delete(DOMAINS, domain);
        }
        transaction = transaction.delete(HOSTS, id.0.to_string());
        self.store.transact(transaction)?;
        Ok(())
    }

    /// Reserve the next numeric host id.
    ///
    /// The counter is persisted in the same store; concurrent callers race on a CAS and retry.
    pub fn next_id(&self) -> Result<u64, HostError> {
        for _ in 0..8 {
            let snapshot = self.store.snapshot()?;
            let document = snapshot.get(META, NEXT_ID);
            let next = document
                .and_then(|document| document.value.as_u64())
                .unwrap_or(1);
            let mut transaction = Transaction::new();
            transaction = match document {
                Some(document) => transaction.check_revision(META, NEXT_ID, document.revision),
                None => transaction.check_missing(META, NEXT_ID),
            };
            transaction = transaction.put(META, NEXT_ID, json!(next + 1));
            match self.store.transact(transaction) {
                Ok(_) => return Ok(next),
                Err(StateError::Conflict { .. }) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(HostError::State(StateError::Unavailable(
            "host id counter is contended".to_string(),
        )))
    }
}

fn decode_host(document: Document) -> Result<StoredHost, HostError> {
    let host: Host = serde_json::from_value(document.value)
        .map_err(|error| HostError::InvalidDocument(error.to_string()))?;
    if host.id.0.to_string() != document.key {
        return Err(HostError::InvalidDocument(format!(
            "host document key `{}` does not match host id {}",
            document.key, host.id.0
        )));
    }
    host.validate_structure()
        .map_err(|error| HostError::InvalidDocument(error.to_string()))?;
    Ok(StoredHost {
        host,
        revision: document.revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_pm_core::{
        DeadSpec, HostSpec, HostTls, ProxySpec, RedirectScheme, RedirectSpec, Upstream,
        UpstreamScheme,
    };
    use caddy_rs_pm_state::MemoryStore;

    fn repo() -> HostRepository {
        HostRepository::new(Arc::new(MemoryStore::default()))
    }

    fn proxy(id: u64, domains: &[&str]) -> Host {
        Host::new(
            HostId(id),
            domains.iter().map(|value| value.to_string()).collect(),
            HostTls::disabled(),
            HostSpec::Proxy(ProxySpec::new(Upstream::new(
                UpstreamScheme::Http,
                "10.0.0.5",
                8080,
            ))),
        )
    }

    #[test]
    fn create_get_list_and_snapshot_round_trip() {
        let repo = repo();
        let first = repo.create(proxy(2, &["b.example.com"])).expect("create");
        let second = repo.create(proxy(1, &["a.example.com"])).expect("create");
        assert_eq!(first.revision, 1);
        assert_eq!(second.revision, 1);
        assert_eq!(
            repo.get(HostId(2)).expect("get").expect("present").host,
            first.host
        );
        assert_eq!(
            repo.list()
                .expect("list")
                .into_iter()
                .map(|stored| stored.host.id.0)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(repo.snapshot_hosts().expect("snapshot").len(), 2);
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let repo = repo();
        repo.create(proxy(1, &["one.example.com"])).expect("create");
        assert!(matches!(
            repo.create(proxy(1, &["two.example.com"])),
            Err(HostError::State(StateError::Conflict { .. }))
        ));
    }

    #[test]
    fn duplicate_domain_is_rejected() {
        let repo = repo();
        repo.create(proxy(1, &["same.example.com"]))
            .expect("create");
        assert!(matches!(
            repo.create(proxy(2, &["same.example.com"])),
            Err(HostError::State(StateError::Conflict { .. }))
        ));
    }

    #[test]
    fn update_uses_cas_and_moves_domain_index() {
        let repo = repo();
        let created = repo.create(proxy(1, &["old.example.com"])).expect("create");
        let mut updated = created.host.clone();
        updated.domains = vec!["new.example.com".to_string()];
        let stored = repo.update(updated, created.revision).expect("update");
        assert_eq!(stored.revision, created.revision + 1);
        assert!(repo
            .domain_owner("new.example.com")
            .expect("owner")
            .is_some());
        assert!(repo
            .domain_owner("old.example.com")
            .expect("owner")
            .is_none());
        assert!(matches!(
            repo.update(created.host.clone(), created.revision),
            Err(HostError::State(StateError::Conflict { .. }))
        ));
    }

    #[test]
    fn delete_requires_revision_and_removes_indexes() {
        let repo = repo();
        let created = repo
            .create(proxy(1, &["gone.example.com"]))
            .expect("create");
        assert!(matches!(
            repo.delete(HostId(1), created.revision + 1),
            Err(HostError::State(StateError::Conflict { .. }))
        ));
        repo.delete(HostId(1), created.revision).expect("delete");
        assert!(repo.get(HostId(1)).expect("get").is_none());
        assert!(repo
            .domain_owner("gone.example.com")
            .expect("owner")
            .is_none());
    }

    #[test]
    fn snapshot_backend_persists_hosts_and_indexes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("pm-state.json");
        {
            let repo = HostRepository::new(Arc::new(
                caddy_rs_pm_state::SnapshotStore::open(&path).expect("open"),
            ));
            repo.create(proxy(1, &["persisted.example.com"]))
                .expect("create");
        }
        let repo = HostRepository::new(Arc::new(
            caddy_rs_pm_state::SnapshotStore::open(&path).expect("reopen"),
        ));
        assert_eq!(
            repo.get(HostId(1))
                .expect("get")
                .expect("present")
                .host
                .domains,
            vec!["persisted.example.com".to_string()]
        );
        assert_eq!(
            repo.domain_owner("persisted.example.com")
                .expect("owner")
                .expect("present")
                .host_id,
            HostId(1)
        );
    }

    #[test]
    fn next_id_is_monotonic_and_persisted_in_the_store() {
        let repo = repo();
        assert_eq!(repo.next_id().expect("first"), 1);
        assert_eq!(repo.next_id().expect("second"), 2);
        assert_eq!(repo.next_id().expect("third"), 3);
    }

    #[test]
    fn invalid_host_is_rejected_before_the_transaction() {
        let repo = repo();
        let mut host = proxy(1, &["example.com"]);
        if let HostSpec::Proxy(spec) = &mut host.spec {
            spec.upstream.port = 0;
        }
        assert!(matches!(repo.create(host), Err(HostError::Core(_))));
        assert!(repo.list().expect("list").is_empty());
    }

    #[test]
    fn redirect_host_uses_the_same_repository() {
        let repo = repo();
        let host = Host::new(
            HostId(4),
            vec!["old.example.com".to_string()],
            HostTls::disabled(),
            HostSpec::Redirect(RedirectSpec {
                scheme: RedirectScheme::Auto,
                target: "new.example.com".to_string(),
                status: 301,
                preserve_path: true,
            }),
        );
        let stored = repo.create(host).expect("create");
        assert_eq!(stored.host.kind(), caddy_rs_pm_core::HostKind::Redirect);
    }

    #[test]
    fn dead_host_uses_the_same_repository() {
        let repo = repo();
        let host = Host::new(
            HostId(5),
            vec!["dead.example.com".to_string()],
            HostTls::disabled(),
            HostSpec::Dead(DeadSpec),
        );
        repo.create(host).expect("create");
        assert_eq!(repo.list().expect("list").len(), 1);
    }
}
