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

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use crate::config::Config;
use crate::error::Result;
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
}

impl Generation {
    fn new(id: u64, config: Config, validation: ValidationReport) -> Self {
        Self {
            id,
            config,
            state: AtomicU8::new(LifecycleState::Unloaded as u8),
            created_at: SystemTime::now(),
            validation,
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

/// Holds the active configuration generation.
///
/// The store is safe for concurrent use: readers clone an `Arc<Generation>` cheaply, while a
/// reloader takes the write lock only long enough to swap the pointer.
#[derive(Debug)]
pub struct GenerationStore {
    registry: Arc<ModuleRegistry>,
    active: RwLock<Option<Arc<Generation>>>,
    next_id: AtomicU64,
}

impl GenerationStore {
    /// Create a store with an explicit module registry.
    pub fn new(registry: Arc<ModuleRegistry>) -> Self {
        Self {
            registry,
            active: RwLock::new(None),
            next_id: AtomicU64::new(0),
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
/// stopped/cleaned. The caller must stop handing out new handles before calling.
///
/// Polling the strong count is deliberate: it needs no cooperation from request tasks and cannot
/// deadlock, at the cost of a few microseconds of latency per drain check.
pub async fn drain(generation: &Arc<Generation>, timeout: Duration) -> DrainOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = Arc::strong_count(generation);
        if remaining <= 1 {
            generation.set_state(LifecycleState::Stopped);
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
}
