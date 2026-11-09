//! Durable auto-certificate policy repository for the caddy-rs proxy manager.
//!
//! The repository stores validated [`AutoCertificatePolicy`] documents in the namespaced
//! [`StateStore`](caddy_rs_pm_state::StateStore). Every mutation is one compare-and-swap
//! transaction: a failed precondition or persistence error leaves the store unchanged. Deleted
//! ids are recorded as tombstones so a policy id is never reused, and a persisted counter hands
//! out monotonic ids.
//!
//! This crate is persistence only. It does not issue certificates, compile Caddy JSON or expose
//! an HTTP API. Coverage against hosts is a pure helper over [`Host`] values from `pm-core`; the
//! repository deliberately does not depend on `pm-hosts`.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::Arc;

use caddy_rs_pm_core::{AutoCertificatePolicy, Host, PolicyId, TlsMode};
use caddy_rs_pm_state::{Document, Revision, StateError, StateStore, Transaction};
use serde_json::json;
use thiserror::Error;

const POLICIES: &str = "pm.policies";
const TOMBSTONES: &str = "pm.policy-tombstones";
const META: &str = "pm.meta";
const NEXT_ID: &str = "next-policy-id";

/// An auto-certificate policy together with the store revision that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredPolicy {
    pub policy: AutoCertificatePolicy,
    pub revision: Revision,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error(transparent)]
    Core(#[from] caddy_rs_pm_core::CoreError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("policy JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("auto-certificate policy {0} was not found")]
    NotFound(u64),
    #[error("auto-certificate policy {0} already exists")]
    AlreadyExists(u64),
    #[error("auto-certificate policy id {0} was retired and cannot be reused")]
    IdRetired(u64),
    #[error("auto-certificate policy ids are exhausted at u64::MAX")]
    IdExhausted,
    #[error("invalid stored auto-certificate policy document: {0}")]
    InvalidDocument(String),
}

/// A policy repository over a [`StateStore`].
#[derive(Clone)]
pub struct PolicyRepository {
    store: Arc<dyn StateStore>,
}

impl PolicyRepository {
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self { store }
    }

    /// Read one policy. A missing document is `Ok(None)`.
    pub fn get(&self, id: PolicyId) -> Result<Option<StoredPolicy>, PolicyError> {
        let Some(document) = self.store.get(POLICIES, &id.0.to_string())? else {
            return Ok(None);
        };
        Ok(Some(decode_policy(document)?))
    }

    /// Every stored policy, ordered by id.
    pub fn list(&self) -> Result<Vec<StoredPolicy>, PolicyError> {
        let mut policies = self
            .store
            .scan(POLICIES, "")?
            .into_iter()
            .map(decode_policy)
            .collect::<Result<Vec<_>, _>>()?;
        policies.sort_by_key(|stored| stored.policy.id.0);
        Ok(policies)
    }

    /// Every stored policy without revisions.
    pub fn snapshot_policies(&self) -> Result<Vec<AutoCertificatePolicy>, PolicyError> {
        Ok(self
            .list()?
            .into_iter()
            .map(|stored| stored.policy)
            .collect())
    }

    /// Insert a policy with a caller-assigned id.
    ///
    /// Fails before writing if the policy is invalid, if the id already exists, or if the id was
    /// retired by a previous delete. The document is written in one transaction.
    pub fn create(&self, policy: AutoCertificatePolicy) -> Result<StoredPolicy, PolicyError> {
        policy.validate()?;
        let key = policy.id.0.to_string();
        if self.store.get(POLICIES, &key)?.is_some() {
            return Err(PolicyError::AlreadyExists(policy.id.0));
        }
        if self.store.get(TOMBSTONES, &key)?.is_some() {
            return Err(PolicyError::IdRetired(policy.id.0));
        }
        let transaction = Transaction::new()
            .check_missing(POLICIES, key.clone())
            .check_missing(TOMBSTONES, key.clone())
            .put(POLICIES, key.clone(), serde_json::to_value(&policy)?);
        let commit = self.store.transact(transaction)?;
        let revision = revision_of(&commit, &key)?;
        Ok(StoredPolicy { policy, revision })
    }

    /// Update a policy under a compare-and-swap revision.
    pub fn update(
        &self,
        policy: AutoCertificatePolicy,
        expected_revision: Revision,
    ) -> Result<StoredPolicy, PolicyError> {
        policy.validate()?;
        let key = policy.id.0.to_string();
        self.get(policy.id)?
            .ok_or(PolicyError::NotFound(policy.id.0))?;
        let transaction = Transaction::new()
            .check_revision(POLICIES, key.clone(), expected_revision)
            .put(POLICIES, key.clone(), serde_json::to_value(&policy)?);
        let commit = self.store.transact(transaction)?;
        let revision = revision_of(&commit, &key)?;
        Ok(StoredPolicy { policy, revision })
    }

    /// Delete a policy and record a tombstone so its id is never reused.
    pub fn delete(&self, id: PolicyId, expected_revision: Revision) -> Result<(), PolicyError> {
        self.get(id)?.ok_or(PolicyError::NotFound(id.0))?;
        let key = id.0.to_string();
        let transaction = Transaction::new()
            .check_revision(POLICIES, key.clone(), expected_revision)
            .check_missing(TOMBSTONES, key.clone())
            .put(TOMBSTONES, key.clone(), json!({ "policy_id": id.0 }))
            .delete(POLICIES, key);
        self.store.transact(transaction)?;
        Ok(())
    }

    /// Reserve the next numeric policy id.
    ///
    /// The counter is persisted in the same store and skips ids that already exist or were
    /// retired. Arithmetic is checked: at `u64::MAX` the counter cannot advance, so the call
    /// fails with [`PolicyError::IdExhausted`] instead of overflowing.
    pub fn next_id(&self) -> Result<u64, PolicyError> {
        for _ in 0..8 {
            let snapshot = self.store.snapshot()?;
            let document = snapshot.get(META, NEXT_ID);
            let counter = match document {
                Some(document) => document.value.as_u64().ok_or_else(|| {
                    PolicyError::InvalidDocument(
                        "policy id counter is not an unsigned integer".to_string(),
                    )
                })?,
                None => 1,
            };
            let highest = max_numeric_key(&snapshot, POLICIES)
                .max(max_numeric_key(&snapshot, TOMBSTONES))
                .unwrap_or(0);
            let above_highest = highest.checked_add(1).ok_or(PolicyError::IdExhausted)?;
            let candidate = counter.max(above_highest).max(1);
            let following = candidate.checked_add(1).ok_or(PolicyError::IdExhausted)?;
            let mut transaction = match document {
                Some(document) => {
                    Transaction::new().check_revision(META, NEXT_ID, document.revision)
                }
                None => Transaction::new().check_missing(META, NEXT_ID),
            };
            transaction = transaction
                .check_missing(POLICIES, candidate.to_string())
                .check_missing(TOMBSTONES, candidate.to_string())
                .put(META, NEXT_ID, json!(following));
            match self.store.transact(transaction) {
                Ok(_) => return Ok(candidate),
                Err(StateError::Conflict { .. }) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(PolicyError::State(StateError::Unavailable(
            "policy id counter is contended".to_string(),
        )))
    }
}

/// Check that a policy covers every domain of the hosts bound to it.
///
/// Only hosts with `tls.mode == TlsMode::Auto` and `tls.auto_policy_id == Some(policy.id)` are
/// checked. Hosts bound to another policy, to manual/ACME/CA TLS, or with TLS disabled are
/// ignored. Every domain of a selected host must be matched by [`AutoCertificatePolicy::matches`];
/// the error reports the uncovered domains together with the affected host ids.
pub fn validate_policy_coverage(
    policy: &AutoCertificatePolicy,
    hosts: &[Host],
) -> Result<(), PolicyCoverageError> {
    let mut host_ids = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for host in hosts {
        if host.tls.mode != TlsMode::Auto || host.tls.auto_policy_id != Some(policy.id) {
            continue;
        }
        let missing: Vec<String> = host
            .domains
            .iter()
            .filter(|domain| !policy.matches(domain))
            .map(|domain| {
                caddy_rs_pm_core::normalize_pattern(domain).unwrap_or_else(|_| domain.clone())
            })
            .collect();
        if !missing.is_empty() {
            host_ids.insert(host.id.0);
            domains.extend(missing);
        }
    }
    if domains.is_empty() {
        return Ok(());
    }
    Err(PolicyCoverageError {
        policy_id: policy.id.0,
        host_ids: host_ids.into_iter().collect(),
        domains: domains.into_iter().collect(),
    })
}

/// Located coverage failure: which policy, which hosts, and which domains are uncovered.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "auto-certificate policy {policy_id} does not cover domain(s) {domains:?} for host(s) \
     {host_ids:?}"
)]
pub struct PolicyCoverageError {
    pub policy_id: u64,
    pub host_ids: Vec<u64>,
    pub domains: Vec<String>,
}

fn revision_of(commit: &caddy_rs_pm_state::Commit, key: &str) -> Result<Revision, PolicyError> {
    commit
        .written
        .iter()
        .find(|document| document.namespace == POLICIES && document.key == key)
        .map(|document| document.revision)
        .ok_or_else(|| {
            PolicyError::InvalidDocument("policy transaction did not return the policy".to_string())
        })
}

fn max_numeric_key(snapshot: &caddy_rs_pm_state::Snapshot, namespace: &str) -> Option<u64> {
    snapshot
        .scan(namespace, "")
        .iter()
        .filter_map(|document| document.key.parse::<u64>().ok())
        .max()
}

fn decode_policy(document: Document) -> Result<StoredPolicy, PolicyError> {
    let policy: AutoCertificatePolicy = serde_json::from_value(document.value)
        .map_err(|error| PolicyError::InvalidDocument(error.to_string()))?;
    if policy.id.0.to_string() != document.key {
        return Err(PolicyError::InvalidDocument(format!(
            "policy document key `{}` does not match policy id {}",
            document.key, policy.id.0
        )));
    }
    policy
        .validate()
        .map_err(|error| PolicyError::InvalidDocument(error.to_string()))?;
    Ok(StoredPolicy {
        policy,
        revision: document.revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caddy_rs_pm_core::{
        AutoMode, CertificateId, CertificateOrigin, HostId, HostSpec, HostTls, ProxySpec, Upstream,
        UpstreamScheme,
    };
    use caddy_rs_pm_state::{MemoryStore, SnapshotStore};

    fn repo() -> PolicyRepository {
        PolicyRepository::new(Arc::new(MemoryStore::default()))
    }

    fn repo_with_store() -> (Arc<MemoryStore>, PolicyRepository) {
        let store = Arc::new(MemoryStore::default());
        let repo = PolicyRepository::new(Arc::clone(&store) as Arc<dyn StateStore>);
        (store, repo)
    }

    fn auto_policy(id: u64, name: &str, subjects: &[&str]) -> AutoCertificatePolicy {
        AutoCertificatePolicy {
            id: PolicyId(id),
            name: name.to_string(),
            subjects: subjects.iter().map(|value| value.to_string()).collect(),
            mode: AutoMode::OnDemand,
            issuer: None,
            key_type: None,
            renewal_window_ratio: Some(0.3),
            enabled: true,
        }
    }

    fn host(id: u64, domains: &[&str], tls: HostTls) -> Host {
        Host::new(
            HostId(id),
            domains.iter().map(|value| value.to_string()).collect(),
            tls,
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
        let second = repo
            .create(auto_policy(2, "second", &["b.example.com"]))
            .expect("create");
        let first = repo
            .create(auto_policy(1, "first", &["a.example.com"]))
            .expect("create");
        assert_eq!(first.revision, 1);
        assert_eq!(second.revision, 1);
        assert_eq!(
            repo.get(PolicyId(2)).expect("get").expect("present").policy,
            second.policy
        );
        assert_eq!(
            repo.list()
                .expect("list")
                .into_iter()
                .map(|stored| stored.policy.id.0)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(repo.snapshot_policies().expect("snapshot").len(), 2);
    }

    #[test]
    fn invalid_policy_is_rejected_before_the_transaction() {
        let repo = repo();
        assert!(matches!(
            repo.create(auto_policy(0, "zero-id", &["example.com"])),
            Err(PolicyError::Core(_))
        ));
        assert!(matches!(
            repo.create(auto_policy(1, "no-subjects", &[])),
            Err(PolicyError::Core(_))
        ));
        let mut bad_ratio = auto_policy(2, "bad-ratio", &["example.com"]);
        bad_ratio.renewal_window_ratio = Some(1.0);
        assert!(matches!(repo.create(bad_ratio), Err(PolicyError::Core(_))));
        assert!(repo.list().expect("list").is_empty());
    }

    #[test]
    fn duplicate_id_is_rejected_without_mutating_the_store() {
        let repo = repo();
        let created = repo
            .create(auto_policy(1, "first", &["one.example.com"]))
            .expect("create");
        assert!(matches!(
            repo.create(auto_policy(1, "duplicate", &["two.example.com"])),
            Err(PolicyError::AlreadyExists(1))
        ));
        assert_eq!(
            repo.get(PolicyId(1)).expect("get").expect("present").policy,
            created.policy
        );
        assert_eq!(repo.list().expect("list").len(), 1);
    }

    #[test]
    fn update_requires_the_expected_revision() {
        let repo = repo();
        let created = repo
            .create(auto_policy(1, "first", &["example.com"]))
            .expect("create");
        let mut renamed = created.policy.clone();
        renamed.name = "renamed".to_string();
        let updated = repo
            .update(renamed.clone(), created.revision)
            .expect("update");
        assert_eq!(updated.revision, created.revision + 1);
        assert_eq!(updated.policy.name, "renamed");

        assert!(matches!(
            repo.update(created.policy.clone(), created.revision),
            Err(PolicyError::State(StateError::Conflict { .. }))
        ));
        assert_eq!(
            repo.get(PolicyId(1))
                .expect("get")
                .expect("present")
                .policy
                .name,
            "renamed"
        );
    }

    #[test]
    fn update_of_a_missing_policy_is_not_found() {
        let repo = repo();
        assert!(matches!(
            repo.update(auto_policy(9, "missing", &["example.com"]), 1),
            Err(PolicyError::NotFound(9))
        ));
    }

    #[test]
    fn delete_requires_revision_and_writes_a_tombstone() {
        let (store, repo) = repo_with_store();
        let created = repo
            .create(auto_policy(1, "gone", &["gone.example.com"]))
            .expect("create");
        assert!(matches!(
            repo.delete(PolicyId(1), created.revision + 1),
            Err(PolicyError::State(StateError::Conflict { .. }))
        ));
        repo.delete(PolicyId(1), created.revision).expect("delete");
        assert!(repo.get(PolicyId(1)).expect("get").is_none());
        assert!(repo.list().expect("list").is_empty());
        let tombstone = store
            .get(TOMBSTONES, "1")
            .expect("tombstone")
            .expect("present");
        assert_eq!(tombstone.value["policy_id"], json!(1));
    }

    #[test]
    fn delete_of_a_missing_policy_is_not_found() {
        let repo = repo();
        assert!(matches!(
            repo.delete(PolicyId(7), 1),
            Err(PolicyError::NotFound(7))
        ));
    }

    #[test]
    fn next_id_is_monotonic_and_persisted_in_the_store() {
        let repo = repo();
        assert_eq!(repo.next_id().expect("first"), 1);
        assert_eq!(repo.next_id().expect("second"), 2);
        assert_eq!(repo.next_id().expect("third"), 3);
    }

    #[test]
    fn next_id_skips_existing_and_retired_ids() {
        let repo = repo();
        repo.create(auto_policy(1, "one", &["one.example.com"]))
            .expect("create");
        assert_eq!(repo.next_id().expect("next"), 2);
        let second = repo
            .create(auto_policy(2, "two", &["two.example.com"]))
            .expect("create");
        assert_eq!(repo.next_id().expect("next"), 3);
        repo.delete(PolicyId(2), second.revision).expect("delete");
        assert_eq!(repo.next_id().expect("after delete"), 4);
    }

    #[test]
    fn next_id_survives_a_snapshot_reopen() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("pm-state.json");
        {
            let repo = PolicyRepository::new(Arc::new(SnapshotStore::open(&path).expect("open")));
            assert_eq!(repo.next_id().expect("first"), 1);
            assert_eq!(repo.next_id().expect("second"), 2);
        }
        let repo = PolicyRepository::new(Arc::new(SnapshotStore::open(&path).expect("reopen")));
        assert_eq!(repo.next_id().expect("after reopen"), 3);
    }

    #[test]
    fn next_id_stops_at_u64_max_without_overflowing() {
        let (store, repo) = repo_with_store();
        store
            .transact(Transaction::new().put(META, NEXT_ID, json!(u64::MAX)))
            .expect("seed counter");
        assert!(matches!(repo.next_id(), Err(PolicyError::IdExhausted)));

        let (store, repo) = repo_with_store();
        store
            .transact(Transaction::new().put(META, NEXT_ID, json!(u64::MAX - 1)))
            .expect("seed counter");
        assert_eq!(repo.next_id().expect("reserve"), u64::MAX - 1);
        assert!(matches!(repo.next_id(), Err(PolicyError::IdExhausted)));
    }

    #[test]
    fn next_id_reports_exhaustion_when_the_highest_id_is_u64_max() {
        let repo = repo();
        repo.create(auto_policy(u64::MAX, "last", &["last.example.com"]))
            .expect("create");
        assert!(matches!(repo.next_id(), Err(PolicyError::IdExhausted)));
    }

    #[test]
    fn retired_policy_id_cannot_be_reused() {
        let repo = repo();
        let created = repo
            .create(auto_policy(1, "one", &["one.example.com"]))
            .expect("create");
        repo.delete(PolicyId(1), created.revision).expect("delete");
        assert!(matches!(
            repo.create(auto_policy(1, "reuse", &["one.example.com"])),
            Err(PolicyError::IdRetired(1))
        ));
        assert!(repo.get(PolicyId(1)).expect("get").is_none());
    }

    #[test]
    fn coverage_reports_uncovered_domains_and_host_ids() {
        let policy = auto_policy(1, "auto", &["example.com"]);
        let covered = host(10, &["example.com"], HostTls::for_auto(PolicyId(1)));
        let uncovered = host(
            7,
            &["example.com", "other.example.net"],
            HostTls::for_auto(PolicyId(1)),
        );
        let error = validate_policy_coverage(&policy, &[covered, uncovered]).expect_err("coverage");
        assert_eq!(error.policy_id, 1);
        assert_eq!(error.host_ids, vec![7]);
        assert_eq!(error.domains, vec!["other.example.net".to_string()]);
    }

    #[test]
    fn coverage_ignores_manual_foreign_policy_and_disabled_hosts() {
        let policy = auto_policy(1, "auto", &["*.example.com", "example.com"]);
        let manual = host(
            4,
            &["manual.example.net"],
            HostTls::for_explicit(CertificateId(9), CertificateOrigin::Manual),
        );
        let foreign_policy = host(5, &["foreign.example.net"], HostTls::for_auto(PolicyId(2)));
        let disabled = host(6, &["plain.example.net"], HostTls::disabled());
        let covered = host(
            7,
            &["api.example.com", "example.com"],
            HostTls::for_auto(PolicyId(1)),
        );
        assert!(
            validate_policy_coverage(&policy, &[manual, foreign_policy, disabled, covered]).is_ok()
        );
    }

    #[test]
    fn snapshot_backend_persists_policies_tombstones_and_the_counter() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("pm-policies.json");
        let policy = auto_policy(1, "persisted", &["persisted.example.com"]);
        {
            let repo = PolicyRepository::new(Arc::new(SnapshotStore::open(&path).expect("open")));
            repo.create(policy.clone()).expect("create");
            assert_eq!(repo.next_id().expect("next"), 2);
        }
        let stored = {
            let repo = PolicyRepository::new(Arc::new(SnapshotStore::open(&path).expect("reopen")));
            let stored = repo.get(PolicyId(1)).expect("get").expect("present");
            assert_eq!(stored.policy, policy);
            assert_eq!(repo.next_id().expect("after reopen"), 3);
            repo.delete(PolicyId(1), stored.revision).expect("delete");
            stored
        };
        assert_eq!(stored.policy.id, PolicyId(1));
        let repo =
            PolicyRepository::new(Arc::new(SnapshotStore::open(&path).expect("second reopen")));
        assert!(repo.get(PolicyId(1)).expect("get").is_none());
        assert_eq!(repo.next_id().expect("after delete"), 4);
        assert!(matches!(
            repo.create(policy),
            Err(PolicyError::IdRetired(1))
        ));
    }
}
