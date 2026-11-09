//! Reusable load/verify/rollback pipeline over a [`ConfigTx`].
//!
//! The PM and any other management surface use this to turn a staged generation into a live
//! caddy-rs configuration without duplicating the ordering rules. The pipeline is deliberately
//! independent of PM types: a [`ConfigTarget`] is the only integration point. Every target,
//! verification or rollback failure records a `Failed` revision, so the audit trail shows the
//! attempt even though the active generation never changes.

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{ConfigTx, Generation, RevisionStore, RevisionStoreExt, TxError};

/// A live configuration target, normally the caddy-rs admin API.
#[async_trait]
pub trait ConfigTarget: Send + Sync {
    /// Error returned by the target.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load a complete configuration document.
    async fn load(&self, config: &Value) -> Result<(), Self::Error>;

    /// Read the currently active configuration.
    async fn current(&self) -> Result<Value, Self::Error>;
}

/// A successful pipeline apply.
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub generation: Generation,
    pub changed: bool,
    /// Target config observed before the attempt. A caller that fails to durably record the
    /// verified generation can restore exactly what the target served before this call.
    pub baseline: Value,
}

/// Failure categories from the pipeline.
#[derive(Debug, Error)]
pub enum ApplyFailureKind<E: std::error::Error + Send + Sync + 'static> {
    #[error("config transaction failed: {0}")]
    Transaction(#[from] TxError),
    #[error("config target request failed: {0}")]
    Target(#[source] E),
    #[error("loaded config did not match the staged generation")]
    Verification,
    #[error("restoring the previous config failed: {0}")]
    Rollback(#[source] E),
}

/// A failed pipeline apply. `changed` is true when the attempted config differs from the active
/// generation, so a caller can record an informative failed revision.
#[derive(Debug, Error)]
#[error("{kind}")]
pub struct ApplyFailure<E: std::error::Error + Send + Sync + 'static> {
    pub changed: bool,
    #[source]
    pub kind: ApplyFailureKind<E>,
}

/// Stage, diff, load, verify and activate configurations through a [`ConfigTx`].
pub struct ConfigApplyPipeline<S: RevisionStore + RevisionStoreExt> {
    tx: ConfigTx<S>,
    lock: Mutex<()>,
}

impl<S: RevisionStore + RevisionStoreExt> ConfigApplyPipeline<S> {
    pub fn new(store: S) -> Self {
        Self {
            tx: ConfigTx::new(store),
            lock: Mutex::new(()),
        }
    }

    /// The underlying transaction, for revision history and rollback.
    pub fn tx(&self) -> &ConfigTx<S> {
        &self.tx
    }

    /// Apply `config` through `target`.
    ///
    /// A failed load or verification restores the previously active generation, or the target's
    /// pre-attempt config when the PM has no generation yet. The active generation changes only
    /// after both the load and the verification succeed.
    pub async fn apply<T: ConfigTarget + ?Sized>(
        &self,
        config: Value,
        target: &T,
    ) -> Result<ApplyOutcome, ApplyFailure<T::Error>> {
        let _guard = self.lock.lock().await;
        if let Err(error) = self.tx.stage(config.clone()) {
            let changed = self
                .tx
                .active_generation()
                .is_none_or(|active| active.config != config);
            self.record_failure(&config, &error);
            return Err(ApplyFailure {
                changed,
                kind: ApplyFailureKind::Transaction(error),
            });
        }
        let previous = self.tx.active_generation();
        let diff = self.tx.diff();
        let changed = previous
            .as_ref()
            .is_none_or(|active| active.config != config)
            || diff.as_ref().is_some_and(|diff| !diff.is_empty());
        let baseline = match target.current().await {
            Ok(baseline) => baseline,
            Err(error) => {
                self.record_failure(&config, &error);
                return Err(ApplyFailure {
                    changed,
                    kind: ApplyFailureKind::Target(error),
                });
            }
        };

        if let Err(error) = target.load(&config).await {
            let kind = match restore(target, previous.as_ref(), &baseline).await {
                Ok(()) => {
                    self.record_failure(&config, &error);
                    ApplyFailureKind::Target(error)
                }
                Err(rollback) => {
                    self.record_failure(&config, &rollback);
                    ApplyFailureKind::Rollback(rollback)
                }
            };
            return Err(ApplyFailure { changed, kind });
        }
        match target.current().await {
            Ok(current) if configs_match_ignoring_admin(&current, &config) => {}
            Ok(_) => {
                let kind = match restore(target, previous.as_ref(), &baseline).await {
                    Ok(()) => {
                        self.record_failure(&config, "verification mismatch");
                        ApplyFailureKind::Verification
                    }
                    Err(rollback) => {
                        self.record_failure(&config, &rollback);
                        ApplyFailureKind::Rollback(rollback)
                    }
                };
                return Err(ApplyFailure { changed, kind });
            }
            Err(error) => {
                let kind = match restore(target, previous.as_ref(), &baseline).await {
                    Ok(()) => {
                        self.record_failure(&config, &error);
                        ApplyFailureKind::Target(error)
                    }
                    Err(rollback) => {
                        self.record_failure(&config, &rollback);
                        ApplyFailureKind::Rollback(rollback)
                    }
                };
                return Err(ApplyFailure { changed, kind });
            }
        }

        match self.tx.apply(None) {
            Ok(generation) => Ok(ApplyOutcome {
                generation,
                changed,
                baseline,
            }),
            Err(error) => {
                let kind = match restore(target, previous.as_ref(), &baseline).await {
                    Ok(()) => ApplyFailureKind::Transaction(error),
                    Err(rollback) => ApplyFailureKind::Rollback(rollback),
                };
                Err(ApplyFailure { changed, kind })
            }
        }
    }

    fn record_failure(&self, config: &Value, error: &(impl std::fmt::Display + ?Sized)) {
        // The active generation is unchanged on every path that calls this. Recording is best
        // effort: the original target/verification error must be returned even if the audit write
        // also fails.
        let _ = self
            .tx
            .record_failed_attempt(config.clone(), error.to_string());
    }
}

async fn restore<T: ConfigTarget + ?Sized>(
    target: &T,
    previous: Option<&Generation>,
    baseline: &Value,
) -> Result<(), T::Error> {
    let restore = previous.map_or(baseline, |previous| &previous.config);
    target.load(restore).await
}

/// Caddy may add an `admin` app to the config it reports. Ignore only that key when verifying; a
/// difference anywhere else means the live config is not the staged one.
pub fn configs_match_ignoring_admin(current: &Value, expected: &Value) -> bool {
    let mut current = current.clone();
    let mut expected = expected.clone();
    if let Some(object) = current.as_object_mut() {
        object.remove("admin");
    }
    if let Some(object) = expected.as_object_mut() {
        object.remove("admin");
    }
    current == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryRevisionStore;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, thiserror::Error)]
    #[error("fake target failed")]
    struct TargetError;

    #[derive(Clone, Default)]
    struct FakeTarget {
        current: Arc<Mutex<Value>>,
        loads: Arc<Mutex<Vec<Value>>>,
        mismatch: Arc<Mutex<bool>>,
        fail: Arc<Mutex<bool>>,
    }

    impl FakeTarget {
        fn new(baseline: Value) -> Self {
            Self {
                current: Arc::new(Mutex::new(baseline)),
                loads: Arc::new(Mutex::new(Vec::new())),
                mismatch: Arc::new(Mutex::new(false)),
                fail: Arc::new(Mutex::new(false)),
            }
        }

        fn set_mismatch(&self, mismatch: bool) {
            *self.mismatch.lock().unwrap() = mismatch;
        }

        fn set_fail(&self, fail: bool) {
            *self.fail.lock().unwrap() = fail;
        }

        fn loads(&self) -> usize {
            self.loads.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl ConfigTarget for FakeTarget {
        type Error = TargetError;

        async fn load(&self, config: &Value) -> Result<(), Self::Error> {
            // Fail only the attempted new config, so the pipeline's restore load can succeed and
            // the test observes the original target error rather than a rollback error.
            if *self.fail.lock().unwrap() && config.pointer("/apps/http/servers/two").is_some() {
                return Err(TargetError);
            }
            self.loads.lock().unwrap().push(config.clone());
            *self.current.lock().unwrap() = config.clone();
            Ok(())
        }

        async fn current(&self) -> Result<Value, Self::Error> {
            // Report the baseline before the attempt, then a distinct document after a load so the
            // pipeline's verification (and baseline restore) is observable.
            if *self.mismatch.lock().unwrap() && !self.loads.lock().unwrap().is_empty() {
                return Ok(serde_json::json!({"apps": {"http": {"mismatch": true}}}));
            }
            Ok(self.current.lock().unwrap().clone())
        }
    }

    #[tokio::test]
    async fn pipeline_loads_verifies_and_activates_a_generation() {
        let target = FakeTarget::new(serde_json::json!({}));
        let pipeline = ConfigApplyPipeline::new(InMemoryRevisionStore::new());
        let config = serde_json::json!({"apps": {"http": {"servers": {}}}});
        let outcome = pipeline
            .apply(config.clone(), &target)
            .await
            .expect("apply");
        assert_eq!(outcome.generation.revision, 1);
        assert!(outcome.changed);
        assert_eq!(*target.current.lock().unwrap(), config);
        assert_eq!(target.loads(), 1);
        assert_eq!(
            pipeline.tx().active_generation().expect("active").revision,
            1
        );
    }

    #[tokio::test]
    async fn first_apply_verification_failure_restores_the_baseline() {
        let baseline = serde_json::json!({"apps": {"http": {"servers": {"old": {}}}}});
        let target = FakeTarget::new(baseline.clone());
        target.set_mismatch(true);
        let pipeline = ConfigApplyPipeline::new(InMemoryRevisionStore::new());
        let config = serde_json::json!({"apps": {"http": {"servers": {}}}});
        let failure = pipeline
            .apply(config, &target)
            .await
            .expect_err("verify fails");
        assert!(matches!(failure.kind, ApplyFailureKind::Verification));
        assert_eq!(target.loads(), 2, "attempt plus baseline restore");
        assert_eq!(
            target.loads.lock().unwrap().last().expect("restore load"),
            &baseline
        );
        assert!(pipeline.tx().active_generation().is_none());
        let history = pipeline.tx().history(10, 0);
        assert_eq!(history.len(), 1, "failed attempt is audited");
        assert_eq!(history[0].status, crate::RevisionStatus::Failed);
        assert!(history[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("verification mismatch")));
    }

    #[tokio::test]
    async fn failed_load_leaves_the_active_generation_unchanged() {
        let target = FakeTarget::new(serde_json::json!({}));
        let pipeline = ConfigApplyPipeline::new(InMemoryRevisionStore::new());
        let first = serde_json::json!({"apps": {"http": {"servers": {"one": {}}}}});
        pipeline.apply(first.clone(), &target).await.expect("first");
        target.set_fail(true);
        let second = serde_json::json!({"apps": {"http": {"servers": {"two": {}}}}});
        let failure = pipeline
            .apply(second, &target)
            .await
            .expect_err("load fails");
        assert!(matches!(
            failure.kind,
            ApplyFailureKind::Target(TargetError)
        ));
        assert_eq!(
            pipeline.tx().active_generation().expect("active").revision,
            1
        );
        assert_eq!(*target.current.lock().unwrap(), first);
        assert!(failure.changed);
    }

    #[tokio::test]
    async fn invalid_config_fails_at_stage_without_touching_the_target() {
        let target = FakeTarget::new(serde_json::json!({}));
        let pipeline = ConfigApplyPipeline::new(InMemoryRevisionStore::new());
        let failure = pipeline
            .apply(serde_json::json!({"apps": {"unknown": {}}}), &target)
            .await
            .expect_err("invalid app");
        assert!(matches!(failure.kind, ApplyFailureKind::Transaction(_)));
        assert_eq!(target.loads(), 0);
        assert_eq!(pipeline.tx().history(10, 0).len(), 1);
    }
}
