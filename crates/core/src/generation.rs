//! Immutable configuration generations and atomic reload.
//!
//! This is the architectural decision that distinguishes the port from a conventional server:
//! a configuration is provisioned as a complete, immutable generation, validated *before* it
//! replaces the active generation, and swapped in atomically. Requests acquire a generation
//! handle for their lifetime; a replaced generation is drained only after its last in-flight
//! request releases its handle.
//!
//! ```text
//! Unloaded -> Parsed -> Validated -> Provisioned -> Started -> Active
//!                                                             |
//!                                     (reload or stop) -> Stopping -> Stopped -> Cleaned
//! ```
//!
//! With [`crate::GenerationHooks`] configured (see [`crate::lifecycle`]), [`GenerationStore::load_async`] provisions and starts resources *before* the atomic swap, so a
//! failed provision keeps the previous generation active; replaced generations are stopped when
//! they are retired and cleaned up by [`drain`] after their in-flight requests finish. The
//! synchronous [`GenerationStore::load`] path is unchanged for callers without async resources.

use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex as AsyncMutex;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::lifecycle::{with_secondary, CancellationToken, GenerationHooks, GenerationResources};
use crate::module::ModuleRegistry;
use crate::validate::{validate_config, ValidationReport};

/// Lifecycle state of a configuration generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleState {
    /// No configuration is loaded.
    Unloaded = 0,
    /// The document has been decoded.
    Parsed = 1,
    /// The document passed validation.
    Validated = 2,
    /// Resources have been provisioned (listeners, upstreams, ...).
    Provisioned = 3,
    /// Provisioned resources have been started.
    Started = 4,
    /// Serving requests.
    Active = 5,
    /// Replaced; waiting for in-flight work to release it.
    Stopping = 6,
    /// All in-flight work released.
    Stopped = 7,
    /// Resources released.
    Cleaned = 8,
}

impl LifecycleState {
    /// Stable lowercase name used in status output and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            LifecycleState::Unloaded => "unloaded",
            LifecycleState::Parsed => "parsed",
            LifecycleState::Validated => "validated",
            LifecycleState::Provisioned => "provisioned",
            LifecycleState::Started => "started",
            LifecycleState::Active => "active",
            LifecycleState::Stopping => "stopping",
            LifecycleState::Stopped => "stopped",
            LifecycleState::Cleaned => "cleaned",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => LifecycleState::Unloaded,
            1 => LifecycleState::Parsed,
            2 => LifecycleState::Validated,
            3 => LifecycleState::Provisioned,
            4 => LifecycleState::Started,
            5 => LifecycleState::Active,
            6 => LifecycleState::Stopping,
            7 => LifecycleState::Stopped,
            8 => LifecycleState::Cleaned,
            _ => LifecycleState::Unloaded,
        }
    }
}

/// One immutable configuration generation.
#[derive(Debug)]
pub struct Generation {
    id: u64,
    config: Config,
    state: AtomicU8,
    created_at: SystemTime,
    validation: ValidationReport,
    /// Async resources provisioned for this generation (listeners, TLS issuers, ...).
    resources: OnceLock<Arc<GenerationResources>>,
    /// Diagnostics from the most recent failed stop/cleanup phase, for operators and tests.
    lifecycle_error: Mutex<Option<String>>,
}

impl Generation {
    fn new(id: u64, config: Config, validation: ValidationReport) -> Self {
        Self {
            id,
            config,
            state: AtomicU8::new(LifecycleState::Unloaded as u8),
            created_at: SystemTime::now(),
            validation,
            resources: OnceLock::new(),
            lifecycle_error: Mutex::new(None),
        }
    }

    /// Monotonically increasing generation id, starting at 1.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The immutable configuration document.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Validation summary recorded when the generation was loaded.
    pub fn validation(&self) -> ValidationReport {
        self.validation
    }

    /// Current lifecycle state.
    pub fn state(&self) -> LifecycleState {
        LifecycleState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// When the generation was created.
    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    fn set_state(&self, state: LifecycleState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// Attach the resources provisioned for this generation. Returns `false` when resources were
    /// already attached (framework misuse).
    pub(crate) fn attach_resources(&self, resources: Arc<GenerationResources>) -> bool {
        self.resources.set(resources).is_ok()
    }

    /// The resources provisioned for this generation, if the hooks attached any.
    pub fn resources(&self) -> Option<&Arc<GenerationResources>> {
        self.resources.get()
    }

    /// Stop this generation's resources (before or while draining). Idempotent; a failure is
    /// recorded in [`Generation::lifecycle_error`] and returned.
    pub async fn stop_resources(&self) -> Result<()> {
        let Some(resources) = self.resources.get() else {
            return Ok(());
        };
        let result = resources.stop().await;
        self.record_lifecycle_error(&result);
        result
    }

    /// Clean up this generation's resources exactly once (normally after draining). Idempotent; a
    /// failure is recorded in [`Generation::lifecycle_error`] and returned.
    pub async fn cleanup_resources(&self) -> Result<()> {
        let Some(resources) = self.resources.get() else {
            return Ok(());
        };
        let result = resources.cleanup().await;
        self.record_lifecycle_error(&result);
        result
    }

    /// Diagnostic text from the most recent failed resource stop/cleanup, if any.
    pub fn lifecycle_error(&self) -> Option<String> {
        self.lifecycle_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn record_lifecycle_error(&self, result: &Result<()>) {
        if let Err(error) = result {
            *self
                .lifecycle_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error.to_string());
        }
    }
}

/// Result of loading a new configuration generation.
#[derive(Debug)]
pub struct LoadResult {
    /// The new active generation.
    pub generation: Arc<Generation>,
    /// The generation it replaced, if any. Call [`drain`] on it once in-flight requests finish.
    pub replaced: Option<Arc<Generation>>,
    /// Validation counts for the new generation.
    pub report: ValidationReport,
}

/// Async provisioning hooks configured on a store.
///
/// A wrapper (rather than a bare `Arc<dyn GenerationHooks>`) keeps [`GenerationStore`] `Debug`
/// without printing hook internals.
#[derive(Clone)]
struct HookSet(Arc<dyn GenerationHooks>);

impl fmt::Debug for HookSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationHooks")
    }
}

/// Holds the active configuration generation.
///
/// The store is safe for concurrent use: readers clone an `Arc<Generation>` cheaply, while a
/// reloader takes the write lock only long enough to swap the pointer.
#[derive(Debug)]
pub struct GenerationStore {
    registry: Arc<ModuleRegistry>,
    active: RwLock<Option<Arc<Generation>>>,
    next_id: AtomicU64,
    /// Async lifecycle hooks. `None` means the synchronous load path is used and no resources are
    /// provisioned by the store.
    hooks: Option<HookSet>,
    /// Serialises the async load/stop transitions; the synchronous paths keep their historical
    /// (unserialised) behaviour for callers that do not use hooks.
    reload_lock: AsyncMutex<()>,
}

impl GenerationStore {
    /// Create a store with an explicit module registry.
    pub fn new(registry: Arc<ModuleRegistry>) -> Self {
        Self {
            registry,
            active: RwLock::new(None),
            next_id: AtomicU64::new(0),
            hooks: None,
            reload_lock: AsyncMutex::new(()),
        }
    }

    /// Create a store using the built-in module registry.
    pub fn with_builtin_registry() -> Self {
        Self::new(Arc::new(ModuleRegistry::builtin()))
    }

    /// The module registry used for validation and construction.
    pub fn registry(&self) -> &Arc<ModuleRegistry> {
        &self.registry
    }

    /// Configure async lifecycle hooks for this store.
    ///
    /// With hooks configured, [`GenerationStore::load_async`] provisions and starts resources
    /// before the generation becomes active; without them, the synchronous
    /// [`GenerationStore::load`] path behaves exactly as before.
    pub fn with_hooks(mut self, hooks: Arc<dyn GenerationHooks>) -> Self {
        self.hooks = Some(HookSet(hooks));
        self
    }

    /// The configured lifecycle hooks, if any.
    pub fn hooks(&self) -> Option<Arc<dyn GenerationHooks>> {
        self.hooks.as_ref().map(|hooks| Arc::clone(&hooks.0))
    }

    /// Validate a configuration without loading it.
    pub fn validate(&self, config: &Config) -> Result<ValidationReport> {
        validate_config(config, &self.registry)
    }

    /// Validate and atomically activate a new configuration generation.
    ///
    /// The current generation stays active if validation fails. On success the previous
    /// generation is marked `stopping` and returned so the caller can drain it.
    pub fn load(&self, config: Config) -> Result<LoadResult> {
        let report = self.validate(&config)?;
        let id = self.next_id.fetch_add(1, Ordering::AcqRel) + 1;
        let generation = Arc::new(Generation::new(id, config, report));
        // Provisioning is currently synchronous and infallible; TLS/storage provisioning hooks
        // arrive with the TLS workstream. The state machine is exercised now so the ordering is
        // fixed before subsystems depend on it.
        for state in [
            LifecycleState::Parsed,
            LifecycleState::Validated,
            LifecycleState::Provisioned,
            LifecycleState::Started,
        ] {
            generation.set_state(state);
        }
        generation.set_state(LifecycleState::Active);

        let replaced = {
            let mut active = self
                .active
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            active.replace(Arc::clone(&generation))
        };
        if let Some(replaced) = &replaced {
            replaced.set_state(LifecycleState::Stopping);
        }
        Ok(LoadResult {
            generation,
            replaced,
            report,
        })
    }

    /// Validate, provision, start, and atomically activate a new configuration generation using
    /// the store's [`GenerationHooks`].
    ///
    /// The ordering is the compatibility contract for resource-owning subsystems:
    ///
    /// 1. validation (the same located errors as [`GenerationStore::load`]),
    /// 2. `hooks.provision(...)` — resources are attached to the new generation,
    /// 3. `resources.start()` — resources become startable but are not yet serving the swapped
    ///    generation,
    /// 4. the atomic swap to `Active`.
    ///
    /// A failed or cancelled provision/start stops and cleans the new generation's resources
    /// exactly once and leaves the previous generation active; the returned error is located with
    /// the generation id, phase, and resource name. The replaced generation is returned for the
    /// caller to [`drain`]; draining stops and cleans its resources.
    ///
    /// Provide a [`CancellationToken`] to abort an in-flight reload; cancelling before (or during)
    /// provisioning/starting cleans up the new resources and keeps the old generation active.
    ///
    /// Without hooks configured this is equivalent to [`GenerationStore::load`].
    pub async fn load_async(
        &self,
        config: Config,
        cancellation: &CancellationToken,
    ) -> Result<LoadResult> {
        let Some(hooks) = self.hooks() else {
            return self.load(config);
        };
        let _reload = self.reload_lock.lock().await;

        let report = self.validate(&config)?;
        let id = self.next_id.fetch_add(1, Ordering::AcqRel) + 1;
        let generation = Arc::new(Generation::new(id, config, report));
        generation.set_state(LifecycleState::Parsed);
        generation.set_state(LifecycleState::Validated);

        if cancellation.is_cancelled() {
            generation.set_state(LifecycleState::Stopped);
            generation.set_state(LifecycleState::Cleaned);
            return Err(Error::LifecycleCancelled {
                generation: id,
                phase: "provision",
            });
        }

        // The framework owns the resource set from here on; anything attached by a cancelled or
        // failed provision is stopped and cleaned before we return.
        let resources = Arc::new(GenerationResources::new(id));
        if !generation.attach_resources(Arc::clone(&resources)) {
            return Err(Error::LifecycleState {
                generation: id,
                message: "generation already has resources attached".to_string(),
            });
        }

        let provision = tokio::select! {
            biased;
            _ = cancellation.cancelled() => None,
            result = hooks.provision(&generation, &resources) => Some(result),
        };
        match provision {
            Some(Ok(())) => {}
            Some(Err(error)) => {
                let cleanup_error = discard_generation(&generation, &resources).await;
                let primary = Error::Lifecycle {
                    generation: id,
                    phase: "provision",
                    resource: "provisioning".to_string(),
                    message: error.to_string(),
                };
                return Err(match cleanup_error {
                    Some(cleanup_error) => with_secondary(primary, cleanup_error),
                    None => primary,
                });
            }
            None => {
                discard_generation(&generation, &resources).await;
                return Err(Error::LifecycleCancelled {
                    generation: id,
                    phase: "provision",
                });
            }
        }
        if let Err(error) = resources.mark_provisioned() {
            discard_generation(&generation, &resources).await;
            return Err(error);
        }
        generation.set_state(LifecycleState::Provisioned);

        let started = tokio::select! {
            biased;
            _ = cancellation.cancelled() => None,
            result = resources.start() => Some(result),
        };
        match started {
            Some(Ok(())) => {}
            Some(Err(error)) => {
                // `start` already stopped/cleaned the set exactly once.
                generation.set_state(LifecycleState::Stopped);
                generation.set_state(LifecycleState::Cleaned);
                return Err(error);
            }
            None => {
                discard_generation(&generation, &resources).await;
                return Err(Error::LifecycleCancelled {
                    generation: id,
                    phase: "start",
                });
            }
        }
        generation.set_state(LifecycleState::Started);

        // A cancellation observed after start but before the swap must not leak started resources.
        if cancellation.is_cancelled() {
            discard_generation(&generation, &resources).await;
            return Err(Error::LifecycleCancelled {
                generation: id,
                phase: "activate",
            });
        }

        let replaced = {
            let mut active = self
                .active
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            active.replace(Arc::clone(&generation))
        };
        generation.set_state(LifecycleState::Active);
        if let Some(replaced) = &replaced {
            replaced.set_state(LifecycleState::Stopping);
        }
        Ok(LoadResult {
            generation,
            replaced,
            report,
        })
    }

    /// Stop the active generation, running its async `stop` hooks before returning it for
    /// [draining](drain).
    ///
    /// The generation is removed from the active slot even when a stop hook fails or the operation
    /// is cancelled; failures are returned in [`StopResult::errors`] and also recorded on the
    /// generation. The caller must [`drain`] the returned generation so its resources are cleaned
    /// up after in-flight requests finish.
    pub async fn stop_async(&self, cancellation: &CancellationToken) -> StopResult {
        let _reload = self.reload_lock.lock().await;
        let removed = self
            .active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(generation) = removed else {
            return StopResult {
                generation: None,
                errors: Vec::new(),
            };
        };
        generation.set_state(LifecycleState::Stopping);

        let mut errors = Vec::new();
        let cancelled = tokio::select! {
            biased;
            _ = cancellation.cancelled() => true,
            result = generation.stop_resources() => {
                if let Err(error) = result {
                    errors.push(error);
                }
                false
            }
        };
        if cancelled {
            errors.push(Error::LifecycleCancelled {
                generation: generation.id(),
                phase: "stop",
            });
        }
        StopResult {
            generation: Some(generation),
            errors,
        }
    }

    /// The active generation, if any.
    pub fn current(&self) -> Option<Arc<Generation>> {
        self.active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Acquire a handle for request processing. Alias of [`GenerationStore::current`], named for
    /// the call site's intent.
    pub fn acquire(&self) -> Option<Arc<Generation>> {
        self.current()
    }

    /// Deactivate the current generation without waiting for it to drain.
    ///
    /// With async hooks configured, prefer [`GenerationStore::stop_async`], which runs the stop
    /// hooks before returning. Resources of a generation removed through this synchronous method
    /// are stopped by [`drain`]'s cleanup at the latest (after in-flight requests finish).
    pub fn stop(&self) -> Option<Arc<Generation>> {
        let removed = self
            .active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(generation) = &removed {
            generation.set_state(LifecycleState::Stopping);
        }
        removed
    }

    /// Whether a generation is active.
    pub fn is_active(&self) -> bool {
        self.current().is_some()
    }
}

/// Result of [`GenerationStore::stop_async`].
#[derive(Debug)]
pub struct StopResult {
    /// The generation removed from the active slot; [`drain`] it so resources are cleaned up after
    /// in-flight requests finish. `None` when no generation was active.
    pub generation: Option<Arc<Generation>>,
    /// Lifecycle failures encountered while stopping (stop hook failures or cancellation). The
    /// generation is removed regardless.
    pub errors: Vec<Error>,
}

/// Mark an unactivated generation as stopped/cleaned after releasing its resources.
async fn discard_generation(
    generation: &Generation,
    resources: &GenerationResources,
) -> Option<Error> {
    let cleanup_error = resources.cleanup().await.err();
    if let Some(error) = &cleanup_error {
        generation.record_lifecycle_error(&Err(Error::LifecycleState {
            generation: generation.id(),
            message: error.to_string(),
        }));
    }
    generation.set_state(LifecycleState::Stopped);
    generation.set_state(LifecycleState::Cleaned);
    cleanup_error
}

/// Outcome of waiting for a replaced generation to drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// Every request handle was released.
    Drained,
    /// The timeout elapsed with request handles still outstanding.
    TimedOut {
        /// Handles still outstanding when the timeout fired.
        remaining: usize,
    },
}

/// Wait until every handle *other than the caller's* has been dropped, then mark the generation
/// stopped/cleaned and release its async resources.
///
/// Stopping the generation's resources happens here (idempotently) and their cleanup runs exactly
/// once after the last in-flight handle is released; a cleanup failure is recorded in
/// [`Generation::lifecycle_error`]. The caller must stop handing out new handles before calling.
///
/// Polling the strong count is deliberate: it needs no cooperation from request tasks and cannot
/// deadlock, at the cost of a few microseconds of latency per drain check.
pub async fn drain(generation: &Arc<Generation>, timeout: Duration) -> DrainOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = Arc::strong_count(generation);
        if remaining <= 1 {
            generation.set_state(LifecycleState::Stopped);
            // Cleanup is at-most-once even when drain races with a stop path; a cleanup failure is
            // recorded on the generation for diagnostics but does not prevent the state transition
            // (retrying would violate at-most-once cleanup).
            let _ = generation.cleanup_resources().await;
            generation.set_state(LifecycleState::Cleaned);
            return DrainOutcome::Drained;
        }
        if tokio::time::Instant::now() >= deadline {
            return DrainOutcome::TimedOut { remaining };
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::test_support::{Recorder, TestHooks, TestResource};
    use crate::lifecycle::{CancellationToken, ResourceLifecycle};

    fn config(body: &str) -> Config {
        Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [{"handle": [{"handler": "static_response", "body": body}]}]
            }}}}
        }))
        .unwrap()
    }

    #[test]
    fn load_activates_a_generation_and_records_state() {
        let store = GenerationStore::with_builtin_registry();
        assert!(store.current().is_none());
        let result = store.load(config("one")).expect("load");
        assert_eq!(result.generation.id(), 1);
        assert_eq!(result.generation.state(), LifecycleState::Active);
        assert!(result.replaced.is_none());
        assert!(store.is_active());
    }

    #[test]
    fn reload_swaps_and_returns_previous_generation() {
        let store = GenerationStore::with_builtin_registry();
        let first = store.load(config("one")).unwrap().generation;
        let second = store.load(config("two")).unwrap();
        assert_eq!(second.generation.id(), 2);
        let replaced = second.replaced.expect("replaced generation");
        assert_eq!(replaced.id(), first.id());
        assert_eq!(replaced.state(), LifecycleState::Stopping);
        assert_eq!(store.current().unwrap().id(), 2);
    }

    #[test]
    fn failed_validation_keeps_active_generation() {
        let store = GenerationStore::with_builtin_registry();
        let first = store.load(config("one")).unwrap().generation;
        let invalid = Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":8080"],
                "routes": [{"handle": [{"handler": "bogus"}]}]
            }}}}
        }))
        .unwrap();
        let error = store.load(invalid).expect_err("validation fails");
        assert!(error.to_string().contains("bogus"));
        assert_eq!(store.current().unwrap().id(), first.id());
    }

    #[tokio::test]
    async fn drain_waits_for_in_flight_request_handles() {
        let store = GenerationStore::with_builtin_registry();
        let first = store.load(config("one")).unwrap().generation;
        let replacement = store.load(config("two")).unwrap();
        let replaced = replacement.replaced.expect("replaced generation");
        assert_eq!(replaced.id(), first.id());
        // Simulate the request that still holds a handle; the reloader's own `first` handle is
        // released so only the in-flight request keeps the old generation alive.
        drop(first);

        let request_handle = Arc::clone(&replaced);
        let request = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(request_handle);
        });

        // The replacement is active immediately, while the old generation is still in flight.
        assert_eq!(store.current().unwrap().id(), 2);
        assert_eq!(replaced.state(), LifecycleState::Stopping);
        let outcome = drain(&replaced, Duration::from_secs(2)).await;
        assert_eq!(outcome, DrainOutcome::Drained);
        assert_eq!(replaced.state(), LifecycleState::Cleaned);
        request.await.unwrap();
    }

    #[tokio::test]
    async fn drain_times_out_with_remaining_handle_count() {
        let store = GenerationStore::with_builtin_registry();
        let generation = store.load(config("one")).unwrap().generation;
        let _held = Arc::clone(&generation);
        let outcome = drain(&generation, Duration::from_millis(20)).await;
        match outcome {
            DrainOutcome::TimedOut { remaining } => assert!(remaining >= 2, "{remaining}"),
            other => panic!("expected timeout, got {other:?}"),
        }
    }

    #[test]
    fn stop_clears_active_generation() {
        let store = GenerationStore::with_builtin_registry();
        store.load(config("one")).unwrap();
        let stopped = store.stop().expect("stopped generation");
        assert_eq!(stopped.state(), LifecycleState::Stopping);
        assert!(store.current().is_none());
    }

    // -- async provisioning/lifecycle integration -----------------------------------------

    /// Hooks that attach `per_call[n]` during the (1-based) n-th provision call.
    fn hooks_with_resources(
        recorder: &Recorder,
        per_call: Vec<Vec<Arc<TestResource>>>,
    ) -> Arc<TestHooks> {
        let mut hooks = TestHooks::new(recorder.clone(), Vec::new());
        for (index, resources) in per_call.into_iter().enumerate() {
            hooks = hooks.use_resources_for_call(index + 1, resources);
        }
        hooks
    }

    #[tokio::test]
    async fn load_async_provisions_and_starts_before_activation() {
        let recorder = Recorder::new();
        let old = TestResource::new(&recorder, "old");
        let new = TestResource::new(&recorder, "new");
        let hooks = hooks_with_resources(&recorder, vec![vec![old], vec![new.clone()]]);
        let store = GenerationStore::with_builtin_registry().with_hooks(hooks);
        let cancellation = CancellationToken::new();

        let loaded = store
            .load_async(config("one"), &cancellation)
            .await
            .expect("load");
        assert_eq!(loaded.generation.id(), 1);
        assert_eq!(loaded.generation.state(), LifecycleState::Active);
        assert!(loaded.replaced.is_none());
        let resources = loaded.generation.resources().expect("resources attached");
        assert_eq!(resources.phase(), ResourceLifecycle::Started);
        assert_eq!(
            recorder.events(),
            vec!["provision:1", "attach:old", "old.start"]
        );

        // The replacement is provisioned and started while the old generation is still active.
        let replacement = store
            .load_async(config("two"), &cancellation)
            .await
            .expect("reload");
        assert_eq!(replacement.generation.id(), 2);
        assert_eq!(replacement.generation.state(), LifecycleState::Active);
        let replaced = replacement.replaced.expect("replaced generation");
        assert_eq!(replaced.id(), 1);
        assert_eq!(replaced.state(), LifecycleState::Stopping);
        // Resources stay up until the replaced generation drains.
        assert_eq!(
            replaced.resources().expect("old resources").phase(),
            ResourceLifecycle::Started
        );
        assert_eq!(
            recorder.events(),
            vec![
                "provision:1",
                "attach:old",
                "old.start",
                "provision:2",
                "attach:new",
                "new.start",
            ]
        );

        // Draining the replaced generation stops and cleans its resources.
        drop(loaded.generation);
        assert_eq!(
            drain(&replaced, Duration::from_secs(1)).await,
            DrainOutcome::Drained
        );
        assert_eq!(replaced.state(), LifecycleState::Cleaned);
        assert_eq!(recorder.count("old.stop"), 1);
        assert_eq!(recorder.count("old.cleanup"), 1);
    }

    #[tokio::test]
    async fn failed_provision_keeps_previous_generation_active_and_cleans_partial_resources() {
        let recorder = Recorder::new();
        let old = TestResource::new(&recorder, "old");
        let partial = TestResource::new(&recorder, "partial");
        let hooks = hooks_with_resources(&recorder, vec![vec![old], vec![partial.clone()]]);
        hooks.fail_on_provision_call.store(2, Ordering::Release);
        hooks.attach_before_error.store(1, Ordering::Release);
        let store = GenerationStore::with_builtin_registry().with_hooks(hooks);
        let cancellation = CancellationToken::new();

        let first = store
            .load_async(config("one"), &cancellation)
            .await
            .expect("load");
        let first_id = first.generation.id();

        let error = store
            .load_async(config("two"), &cancellation)
            .await
            .expect_err("provisioning fails");
        let message = error.to_string();
        assert!(
            message.contains("generation 2 provision failed at resource `provisioning`"),
            "{message}"
        );
        assert!(
            message.contains("injected provision failure on call 2"),
            "{message}"
        );

        // Rollback: the previous generation is still active with its resources untouched.
        let current = store.current().expect("previous generation still active");
        assert_eq!(current.id(), first_id);
        assert_eq!(current.state(), LifecycleState::Active);
        assert_eq!(
            current.resources().expect("old resources").phase(),
            ResourceLifecycle::Started
        );
        // The partially provisioned resource of the failed generation was cleaned exactly once.
        assert_eq!(recorder.count("partial.start"), 0);
        assert_eq!(recorder.count("partial.cleanup"), 1);
        assert_eq!(recorder.count("old.cleanup"), 0);
        assert_eq!(recorder.count("old.stop"), 0);
    }

    #[tokio::test]
    async fn failed_start_keeps_previous_generation_active_and_cleans_resources() {
        let recorder = Recorder::new();
        let old = TestResource::new(&recorder, "old");
        let bad = TestResource::new(&recorder, "bad");
        bad.fail_start.store(true, Ordering::Release);
        let hooks = hooks_with_resources(&recorder, vec![vec![old], vec![bad.clone()]]);
        let store = GenerationStore::with_builtin_registry().with_hooks(hooks);
        let cancellation = CancellationToken::new();

        let first = store
            .load_async(config("one"), &cancellation)
            .await
            .expect("load");
        let first_id = first.generation.id();

        let error = store
            .load_async(config("two"), &cancellation)
            .await
            .expect_err("start fails");
        let message = error.to_string();
        assert!(
            message.contains("generation 2 start failed at resource `bad`"),
            "{message}"
        );
        assert!(
            message.contains("injected start failure for `bad`"),
            "{message}"
        );

        assert_eq!(store.current().expect("previous active").id(), first_id);
        assert_eq!(recorder.count("bad.start"), 1);
        assert_eq!(recorder.count("bad.stop"), 1);
        assert_eq!(recorder.count("bad.cleanup"), 1);
        assert_eq!(recorder.count("old.cleanup"), 0);
    }

    #[tokio::test]
    async fn cancelled_provision_cleans_up_and_keeps_previous_generation_active() {
        let recorder = Recorder::new();
        let old = TestResource::new(&recorder, "old");
        let new = TestResource::new(&recorder, "new");
        let hooks = hooks_with_resources(&recorder, vec![vec![old], vec![new.clone()]]);
        hooks.hang_on_provision_call.store(2, Ordering::Release);
        let store = Arc::new(GenerationStore::with_builtin_registry().with_hooks(hooks));
        let cancellation = CancellationToken::new();

        let first = store
            .load_async(config("one"), &cancellation)
            .await
            .expect("load");
        let first_id = first.generation.id();

        let load_store = Arc::clone(&store);
        let load_token = cancellation.clone();
        let loading =
            tokio::spawn(async move { load_store.load_async(config("two"), &load_token).await });
        recorder.wait_for("provision:2").await;
        cancellation.cancel();
        let error = loading.await.expect("load task").expect_err("cancelled");
        assert!(
            error
                .to_string()
                .contains("generation 2 provision was cancelled"),
            "{error}"
        );

        assert_eq!(store.current().expect("previous active").id(), first_id);
        // Resources attached before cancellation were cleaned exactly once; the old ones were not.
        assert_eq!(recorder.count("new.cleanup"), 1);
        assert_eq!(recorder.count("old.cleanup"), 0);
    }

    #[tokio::test]
    async fn cancelled_start_cleans_up_and_keeps_previous_generation_active() {
        let recorder = Recorder::new();
        let old = TestResource::new(&recorder, "old");
        let new = TestResource::new(&recorder, "new");
        new.hang_start.store(true, Ordering::Release);
        let hooks = hooks_with_resources(&recorder, vec![vec![old], vec![new.clone()]]);
        let store = Arc::new(GenerationStore::with_builtin_registry().with_hooks(hooks));
        let cancellation = CancellationToken::new();

        let first = store
            .load_async(config("one"), &cancellation)
            .await
            .expect("load");
        let first_id = first.generation.id();

        let load_store = Arc::clone(&store);
        let load_token = cancellation.clone();
        let loading =
            tokio::spawn(async move { load_store.load_async(config("two"), &load_token).await });
        recorder.wait_for("new.start").await;
        cancellation.cancel();
        let error = loading.await.expect("load task").expect_err("cancelled");
        assert!(
            error
                .to_string()
                .contains("generation 2 start was cancelled"),
            "{error}"
        );

        assert_eq!(store.current().expect("previous active").id(), first_id);
        assert_eq!(recorder.count("new.stop"), 1);
        assert_eq!(recorder.count("new.cleanup"), 1);
        assert_eq!(recorder.count("old.cleanup"), 0);
    }

    #[tokio::test]
    async fn drain_cleans_up_replaced_generation_resources_after_in_flight_handles() {
        let recorder = Recorder::new();
        let old = TestResource::new(&recorder, "old");
        let new = TestResource::new(&recorder, "new");
        let hooks = hooks_with_resources(&recorder, vec![vec![old], vec![new]]);
        let store = GenerationStore::with_builtin_registry().with_hooks(hooks);
        let cancellation = CancellationToken::new();

        store
            .load_async(config("one"), &cancellation)
            .await
            .expect("first");
        let second = store
            .load_async(config("two"), &cancellation)
            .await
            .expect("second");
        let replaced = second.replaced.expect("replaced generation");
        assert_eq!(replaced.id(), 1);

        let in_flight = Arc::clone(&replaced);
        let drain_task = tokio::spawn(async move {
            let outcome = drain(&replaced, Duration::from_secs(2)).await;
            (outcome, replaced)
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            recorder.count("old.cleanup"),
            0,
            "resources must not be cleaned while a request handle is in flight"
        );

        drop(in_flight);
        let (outcome, replaced) = drain_task.await.expect("drain task");
        assert_eq!(outcome, DrainOutcome::Drained);
        assert_eq!(replaced.state(), LifecycleState::Cleaned);
        assert_eq!(recorder.count("old.stop"), 1);
        assert_eq!(recorder.count("old.cleanup"), 1);

        // Draining again is a no-op: cleanup is at-most-once.
        assert_eq!(
            drain(&replaced, Duration::from_secs(1)).await,
            DrainOutcome::Drained
        );
        assert_eq!(recorder.count("old.cleanup"), 1);
    }

    #[tokio::test]
    async fn drain_timeout_does_not_clean_up_resources() {
        let recorder = Recorder::new();
        let old = TestResource::new(&recorder, "old");
        let new = TestResource::new(&recorder, "new");
        let hooks = hooks_with_resources(&recorder, vec![vec![old], vec![new]]);
        let store = GenerationStore::with_builtin_registry().with_hooks(hooks);
        let cancellation = CancellationToken::new();

        store
            .load_async(config("one"), &cancellation)
            .await
            .expect("first");
        let second = store
            .load_async(config("two"), &cancellation)
            .await
            .expect("second");
        let replaced = second.replaced.expect("replaced generation");
        let in_flight = Arc::clone(&replaced);

        let outcome = drain(&replaced, Duration::from_millis(20)).await;
        assert!(
            matches!(outcome, DrainOutcome::TimedOut { .. }),
            "{outcome:?}"
        );
        assert_eq!(recorder.count("old.cleanup"), 0);

        drop(in_flight);
        assert_eq!(
            drain(&replaced, Duration::from_secs(1)).await,
            DrainOutcome::Drained
        );
        assert_eq!(recorder.count("old.cleanup"), 1);
    }

    #[tokio::test]
    async fn drain_records_cleanup_failure_on_the_generation() {
        let recorder = Recorder::new();
        let old = TestResource::new(&recorder, "old");
        old.fail_cleanup.store(true, Ordering::Release);
        let new = TestResource::new(&recorder, "new");
        let hooks = hooks_with_resources(&recorder, vec![vec![old], vec![new]]);
        let store = GenerationStore::with_builtin_registry().with_hooks(hooks);
        let cancellation = CancellationToken::new();

        store
            .load_async(config("one"), &cancellation)
            .await
            .expect("first");
        let second = store
            .load_async(config("two"), &cancellation)
            .await
            .expect("second");
        let replaced = second.replaced.expect("replaced generation");
        assert_eq!(
            drain(&replaced, Duration::from_secs(1)).await,
            DrainOutcome::Drained
        );
        let recorded = replaced
            .lifecycle_error()
            .expect("cleanup failure recorded");
        assert!(
            recorded.contains("injected cleanup failure for `old`"),
            "{recorded}"
        );
    }

    #[tokio::test]
    async fn stop_async_stops_resources_and_drain_cleans_once() {
        let recorder = Recorder::new();
        let resource = TestResource::new(&recorder, "a");
        let hooks = hooks_with_resources(&recorder, vec![vec![resource]]);
        let store = GenerationStore::with_builtin_registry().with_hooks(hooks);
        let cancellation = CancellationToken::new();

        store
            .load_async(config("one"), &cancellation)
            .await
            .expect("load");
        let result = store.stop_async(&cancellation).await;
        assert!(result.errors.is_empty(), "{:?}", result.errors);
        assert!(store.current().is_none());
        let generation = result.generation.expect("removed generation");
        assert_eq!(generation.state(), LifecycleState::Stopping);
        assert_eq!(recorder.count("a.stop"), 1);
        assert_eq!(recorder.count("a.cleanup"), 0);

        assert_eq!(
            drain(&generation, Duration::from_secs(1)).await,
            DrainOutcome::Drained
        );
        assert_eq!(generation.state(), LifecycleState::Cleaned);
        assert_eq!(recorder.count("a.stop"), 1);
        assert_eq!(recorder.count("a.cleanup"), 1);
    }

    #[tokio::test]
    async fn cancelled_stop_reports_cancellation_and_cleanup_retries_after_drain() {
        let recorder = Recorder::new();
        let resource = TestResource::new(&recorder, "a");
        resource.hang_first_stop.store(true, Ordering::Release);
        let hooks = hooks_with_resources(&recorder, vec![vec![resource]]);
        let store = Arc::new(GenerationStore::with_builtin_registry().with_hooks(hooks));
        let cancellation = CancellationToken::new();

        store
            .load_async(config("one"), &cancellation)
            .await
            .expect("load");
        let stop_store = Arc::clone(&store);
        let stop_token = cancellation.clone();
        let stopping = tokio::spawn(async move { stop_store.stop_async(&stop_token).await });
        recorder.wait_for("a.stop").await;
        cancellation.cancel();
        let result = stopping.await.expect("stop task");
        assert_eq!(result.errors.len(), 1, "{:?}", result.errors);
        assert!(
            result.errors[0]
                .to_string()
                .contains("generation 1 stop was cancelled"),
            "{}",
            result.errors[0]
        );
        let generation = result.generation.expect("removed generation");
        assert!(store.current().is_none());

        // Cleanup after cancel retries the interrupted stop, then cleans up exactly once.
        assert_eq!(
            drain(&generation, Duration::from_secs(1)).await,
            DrainOutcome::Drained
        );
        assert_eq!(recorder.count("a.stop"), 2);
        assert_eq!(recorder.count("a.cleanup"), 1);
    }

    #[tokio::test]
    async fn load_async_without_hooks_matches_sync_load() {
        let store = GenerationStore::with_builtin_registry();
        let loaded = store
            .load_async(config("one"), &CancellationToken::new())
            .await
            .expect("load");
        assert_eq!(loaded.generation.state(), LifecycleState::Active);
        assert!(loaded.generation.resources().is_none());
        assert!(store.hooks().is_none());
    }
}
