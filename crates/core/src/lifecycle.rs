//! Async generation lifecycle: provisioning, starting, stopping, and cleanup.
//!
//! A [`Generation`](crate::Generation) is a complete, immutable configuration snapshot. Before it
//! can become active it may need *resources* — listeners, TLS issuers, storage handles, upstream
//! health checkers — that are acquired asynchronously and must be released when the generation is
//! replaced. This module defines that contract and the framework that drives it:
//!
//! ```text
//! validate -> provision -> start -> [atomic swap: generation becomes Active]
//!                                        |
//!                 replaced: stopping -> drain (in-flight requests finish) -> stop -> cleanup
//! ```
//!
//! # Contract
//!
//! - [`GenerationHooks::provision`] runs against a *validated but not yet active* generation. It
//!   attaches resources with [`GenerationResources::attach`]. If it returns an error or is
//!   cancelled, the framework stops and cleans everything attached so far and the load fails
//!   without swapping the active generation.
//! - [`GenerationResource::start`] runs after provisioning and before the atomic swap. A start
//!   failure aborts the load: the old generation stays active and the new generation's resources
//!   are cleaned up exactly once.
//! - When a generation is replaced (or stopped), its resources are stopped, and once the
//!   generation has drained its cleanup phase runs. [`drain`](crate::drain) performs both
//!   `Stopped` and `Cleaned` transitions; cleanup is at-most-once even if it is invoked
//!   concurrently or repeatedly.
//! - Resource methods must be **idempotent and cancellation-safe**: cooperation with
//!   [`CancellationToken`] may drop a pending `start`/`stop` future, and cleanup will retry the
//!   release of any resource whose earlier attempt did not complete. Dropping a resource is the
//!   last-resort safety net for resources acquired inside a cancelled `provision`.
//!
//! The interface is additive: [`crate::ModuleRegistry`] registration is untouched, so modules own
//! their resources by implementing [`GenerationHooks`] (once per configuration generation) and
//! [`GenerationResource`] (once per owned resource).

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use tokio::sync::{Mutex, Notify};

use crate::error::{Error, Result};
use crate::generation::Generation;

/// Cooperative cancellation token for lifecycle operations.
///
/// A driver (shutdown handler, reload timeout, test) can cancel an in-flight
/// [`GenerationStore::load_async`](crate::GenerationStore::load_async) or
/// [`GenerationStore::stop_async`](crate::GenerationStore::stop_async). Lifecycle code races its
/// awaits against [`CancellationToken::cancelled`]; on cancellation the framework releases any
/// resources it already owns before returning [`Error::LifecycleCancelled`].
///
/// Cloning shares the token, so one clone can be handed to the operation and another kept by the
/// canceller.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    inner: Arc<CancellationInner>,
}

#[derive(Debug, Default)]
struct CancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    /// Create a token that is not yet cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel the operation(s) waiting on this token.
    ///
    /// Idempotent: only the first call wakes waiters.
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Resolve as soon as cancellation is requested (immediately when already cancelled).
    pub async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            // Register before re-checking so a concurrent `cancel` cannot be missed.
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Phase of one [`GenerationResources`] set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResourceLifecycle {
    /// Provisioning in progress; hooks may still attach resources.
    Provisioning = 0,
    /// Provisioned, not started.
    Provisioned = 1,
    /// Started and safe to serve traffic.
    Started = 2,
    /// Stopped; may still be cleaned up.
    Stopped = 3,
    /// Cleaned up; no further lifecycle calls have an effect.
    Cleaned = 4,
}

impl ResourceLifecycle {
    /// Stable lowercase name used in diagnostics and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            ResourceLifecycle::Provisioning => "provisioning",
            ResourceLifecycle::Provisioned => "provisioned",
            ResourceLifecycle::Started => "started",
            ResourceLifecycle::Stopped => "stopped",
            ResourceLifecycle::Cleaned => "cleaned",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => ResourceLifecycle::Provisioning,
            1 => ResourceLifecycle::Provisioned,
            2 => ResourceLifecycle::Started,
            3 => ResourceLifecycle::Stopped,
            _ => ResourceLifecycle::Cleaned,
        }
    }
}

/// One asynchronous resource owned by a generation.
///
/// Implement this for listener sets, TLS issuers, storage handles, health checkers, or any other
/// object whose acquisition (provisioning) must precede serving and whose release must follow
/// draining.
#[async_trait]
pub trait GenerationResource: Send + Sync + 'static {
    /// Stable name used to locate failures (for example `"tcp listener :8080"`).
    fn name(&self) -> &str;

    /// Acquire or bind whatever the resource needs. Runs before the generation is swapped in.
    async fn start(&self) -> Result<()>;

    /// Stop serving/accepting, but keep enough state for [`cleanup`](Self::cleanup) to release it.
    ///
    /// Called while the generation is being retired (before draining finishes is acceptable:
    /// listeners should stop accepting immediately). Must be idempotent.
    async fn stop(&self) -> Result<()>;

    /// Release all resources. Called at most once per generation, after draining; must be
    /// idempotent because cancellation can force a retry.
    async fn cleanup(&self) -> Result<()>;
}

/// Provisioning hook for one configuration generation.
///
/// The store calls this once per [`GenerationStore::load_async`](crate::GenerationStore::load_async)
/// after validation and before the atomic activation. Implementations attach resources with
/// [`GenerationResources::attach`]; the framework guarantees that everything attached is stopped
/// and cleaned up if provisioning, starting, or activation fails or is cancelled.
#[async_trait]
pub trait GenerationHooks: Send + Sync + 'static {
    /// Provision resources for `generation`.
    ///
    /// `resources` accepts [`GenerationResources::attach`] calls while the phase is
    /// [`ResourceLifecycle::Provisioning`]. Returning an error aborts the load: attached resources
    /// are stopped/cleaned exactly once and the previously active generation is left untouched.
    async fn provision(
        &self,
        generation: &Generation,
        resources: &GenerationResources,
    ) -> Result<()>;
}

/// The resources attached to one generation, with ordered, exactly-once lifecycle transitions.
///
/// The framework creates one of these per generation that uses hooks and hands it to
/// [`GenerationHooks::provision`]; the generation keeps it alive until it is cleaned up.
pub struct GenerationResources {
    generation: u64,
    phase: AtomicU8,
    slots: StdMutex<Vec<ResourceSlot>>,
    /// Serialises start/stop/cleanup so transitions cannot interleave.
    lifecycle_lock: Mutex<()>,
}

struct ResourceSlot {
    resource: Arc<dyn GenerationResource>,
    start_attempted: bool,
    started: bool,
    stopped: bool,
    cleaned: bool,
}

impl fmt::Debug for GenerationResources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationResources")
            .field("generation", &self.generation)
            .field("phase", &self.phase())
            .field("resources", &self.names())
            .finish()
    }
}

impl GenerationResources {
    /// Create an empty set for generation `generation`.
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            phase: AtomicU8::new(ResourceLifecycle::Provisioning as u8),
            slots: StdMutex::new(Vec::new()),
            lifecycle_lock: Mutex::new(()),
        }
    }

    /// Generation this set belongs to.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Current lifecycle phase.
    pub fn phase(&self) -> ResourceLifecycle {
        ResourceLifecycle::from_u8(self.phase.load(Ordering::Acquire))
    }

    /// Names of all attached resources, in provisioning order.
    pub fn names(&self) -> Vec<String> {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|slot| slot.resource.name().to_string())
            .collect()
    }

    /// Whether no resources are attached.
    pub fn is_empty(&self) -> bool {
        self.slot_count() == 0
    }

    /// Attach a resource during provisioning.
    ///
    /// Returns [`Error::LifecycleState`] if called after provisioning (the hook contract allows
    /// attachment only from [`GenerationHooks::provision`]).
    pub fn attach(&self, resource: Arc<dyn GenerationResource>) -> Result<()> {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.phase() != ResourceLifecycle::Provisioning {
            return Err(self.state_error(format!(
                "cannot attach resource `{}` after provisioning (phase `{}`)",
                resource.name(),
                self.phase().as_str()
            )));
        }
        slots.push(ResourceSlot {
            resource,
            start_attempted: false,
            started: false,
            stopped: false,
            cleaned: false,
        });
        Ok(())
    }

    /// Mark provisioning complete so the framework can start the resources.
    pub fn mark_provisioned(&self) -> Result<()> {
        match self.phase.compare_exchange(
            ResourceLifecycle::Provisioning as u8,
            ResourceLifecycle::Provisioned as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(current) => Err(self.state_error(format!(
                "cannot finish provisioning from phase `{}`",
                ResourceLifecycle::from_u8(current).as_str()
            ))),
        }
    }

    /// Start every attached resource in provisioning order.
    ///
    /// A failure stops/cleans the set (exactly once) and returns a located [`Error::Lifecycle`].
    /// If a start future is cancelled, the next [`cleanup`](Self::cleanup) stops and cleans the
    /// partially started resources.
    pub async fn start(&self) -> Result<()> {
        let _guard = self.lifecycle_lock.lock().await;
        match self.phase() {
            ResourceLifecycle::Started => return Ok(()),
            ResourceLifecycle::Provisioned => {}
            other => {
                return Err(self.state_error(format!(
                    "cannot start resources in phase `{}`",
                    other.as_str()
                )))
            }
        }

        let count = self.slot_count();
        for index in 0..count {
            self.mark_start_attempted(index);
            let resource = self.resource_at(index);
            match resource.start().await {
                Ok(()) => self.mark_started(index),
                Err(error) => {
                    let mut failures = Failures::default();
                    failures.add(resource.name(), error);
                    let start_error = failures.into_error(self.generation, "start");
                    // Release whatever started before the failure (exactly once) before returning.
                    return match self.cleanup_locked().await {
                        Ok(()) => Err(start_error),
                        Err(cleanup_error) => Err(with_secondary(start_error, cleanup_error)),
                    };
                }
            }
        }
        self.phase
            .store(ResourceLifecycle::Started as u8, Ordering::Release);
        Ok(())
    }

    /// Stop every started resource in reverse provisioning order.
    ///
    /// Idempotent: stopping a stopped or cleaned set is a no-op. Failures are collected (all
    /// resources are still attempted) and returned as one located error; [`cleanup`](Self::cleanup)
    /// will still run afterwards.
    pub async fn stop(&self) -> Result<()> {
        let _guard = self.lifecycle_lock.lock().await;
        match self.phase() {
            ResourceLifecycle::Stopped | ResourceLifecycle::Cleaned => return Ok(()),
            ResourceLifecycle::Started | ResourceLifecycle::Provisioned => {}
            ResourceLifecycle::Provisioning => {
                return Err(self.state_error("cannot stop resources while provisioning"))
            }
        }
        let mut failures = Failures::default();
        self.stop_locked(&mut failures).await;
        self.phase
            .store(ResourceLifecycle::Stopped as u8, Ordering::Release);
        failures.into_result(self.generation, "stop")
    }

    /// Stop (if necessary) and clean up every resource exactly once.
    ///
    /// The first call performs the lifecycle work; later calls return `Ok(())` without calling any
    /// resource again (at-most-once cleanup). Failures are collected, all resources are still
    /// attempted, and the first failure is returned as a located error.
    pub async fn cleanup(&self) -> Result<()> {
        let _guard = self.lifecycle_lock.lock().await;
        if self.phase() == ResourceLifecycle::Cleaned {
            return Ok(());
        }
        self.cleanup_locked().await
    }

    /// Whether cleanup has run.
    pub fn is_cleaned(&self) -> bool {
        self.phase() == ResourceLifecycle::Cleaned
    }

    // -- internals ---------------------------------------------------------------------------

    fn slot_count(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    fn resource_at(&self, index: usize) -> Arc<dyn GenerationResource> {
        Arc::clone(
            &self
                .slots
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())[index]
                .resource,
        )
    }

    fn mark_start_attempted(&self, index: usize) {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())[index]
            .start_attempted = true;
    }

    fn mark_started(&self, index: usize) {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())[index]
            .started = true;
    }

    fn mark_stopped(&self, index: usize) {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())[index]
            .stopped = true;
    }

    fn mark_cleaned(&self, index: usize) {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())[index]
            .cleaned = true;
    }

    fn slot_state(&self, index: usize) -> SlotState {
        let slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let slot = &slots[index];
        SlotState {
            start_attempted: slot.start_attempted,
            stopped: slot.stopped,
            cleaned: slot.cleaned,
        }
    }

    /// Stop resources whose start was attempted and not yet stopped, in reverse order.
    ///
    /// The lifecycle lock must be held by the caller.
    async fn stop_locked(&self, failures: &mut Failures) {
        let count = self.slot_count();
        for index in (0..count).rev() {
            let state = self.slot_state(index);
            if !state.start_attempted || state.stopped || state.cleaned {
                continue;
            }
            let resource = self.resource_at(index);
            let result = resource.stop().await;
            // Marked regardless of the result: cleanup has one attempt per resource, and a
            // failure is reported rather than retried in an infinite loop.
            self.mark_stopped(index);
            if let Err(error) = result {
                failures.add(resource.name(), error);
            }
        }
    }

    /// Stop and clean everything; called with the lifecycle lock held. Sets the phase to
    /// `Cleaned` even when some resources fail so diagnostics are not lost.
    async fn cleanup_locked(&self) -> Result<()> {
        let mut failures = Failures::default();
        self.stop_locked(&mut failures).await;

        let count = self.slot_count();
        for index in (0..count).rev() {
            if self.slot_state(index).cleaned {
                continue;
            }
            let resource = self.resource_at(index);
            let result = resource.cleanup().await;
            self.mark_cleaned(index);
            if let Err(error) = result {
                failures.add(resource.name(), error);
            }
        }
        self.phase
            .store(ResourceLifecycle::Cleaned as u8, Ordering::Release);
        failures.into_result(self.generation, "cleanup")
    }

    fn state_error(&self, message: impl Into<String>) -> Error {
        Error::LifecycleState {
            generation: self.generation,
            message: message.into(),
        }
    }
}

struct SlotState {
    start_attempted: bool,
    stopped: bool,
    cleaned: bool,
}

/// Collected failures from one lifecycle phase: the first is reported with its resource name, all
/// others are appended to its message so a multi-resource failure is not silently truncated.
#[derive(Default)]
struct Failures {
    first: Option<(String, Error)>,
    extra: Vec<String>,
}

impl Failures {
    fn add(&mut self, resource: &str, error: Error) {
        match &self.first {
            None => self.first = Some((resource.to_string(), error)),
            Some(_) => self.extra.push(format!("`{resource}`: {error}")),
        }
    }

    fn into_result(self, generation: u64, phase: &'static str) -> Result<()> {
        match self.first {
            None => Ok(()),
            Some((resource, error)) => {
                let mut message = error.to_string();
                if !self.extra.is_empty() {
                    message.push_str("; additionally: ");
                    message.push_str(&self.extra.join("; "));
                }
                Err(Error::Lifecycle {
                    generation,
                    phase,
                    resource,
                    message,
                })
            }
        }
    }

    fn into_error(self, generation: u64, phase: &'static str) -> Error {
        match self.into_result(generation, phase) {
            Ok(()) => unreachable!("into_error called with no failures"),
            Err(error) => error,
        }
    }
}

/// Combine a primary phase failure with a secondary (usually cleanup) failure.
pub(crate) fn with_secondary(primary: Error, secondary: Error) -> Error {
    match primary {
        Error::Lifecycle {
            generation,
            phase,
            resource,
            message,
        } => Error::Lifecycle {
            generation,
            phase,
            resource,
            message: format!("{message}; {secondary}"),
        },
        other => other,
    }
}

// -------------------------------------------------------------------------------------------------
// Test support (shared with the generation-store integration tests)
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    //! Fakes shared by the lifecycle and generation-store tests.

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use async_trait::async_trait;
    use tokio::sync::Notify;

    use super::{GenerationHooks, GenerationResource, GenerationResources};
    use crate::error::{Error, Result};
    use crate::generation::Generation;

    /// Thread-safe ordered event log for asserting lifecycle order.
    #[derive(Clone, Default)]
    pub(crate) struct Recorder {
        events: Arc<StdMutex<Vec<String>>>,
    }

    impl Recorder {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn record(&self, event: impl Into<String>) {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.into());
        }

        pub(crate) fn events(&self) -> Vec<String> {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        pub(crate) fn count(&self, event: &str) -> usize {
            self.events()
                .iter()
                .filter(|recorded| *recorded == event)
                .count()
        }

        pub(crate) fn contains(&self, event: &str) -> bool {
            self.events().iter().any(|recorded| recorded == event)
        }

        /// Wait (bounded) until `event` has been recorded; panics on timeout so a hung hook fails
        /// the test with a useful message instead of hanging the suite.
        pub(crate) async fn wait_for(&self, event: &str) {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            while !self.contains(event) {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for `{event}`; recorded: {:?}",
                    self.events()
                );
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
    }

    /// A fake resource recording start/stop/cleanup and injectable failures/hangs.
    pub(crate) struct TestResource {
        name: String,
        recorder: Recorder,
        pub(crate) fail_start: AtomicBool,
        pub(crate) fail_stop: AtomicBool,
        pub(crate) fail_cleanup: AtomicBool,
        /// First `start` records the event, signals `start_hang_notified`, then never resolves.
        pub(crate) hang_start: AtomicBool,
        /// First `stop` records the event, signals `stop_hang_notified`, then never resolves.
        pub(crate) hang_first_stop: AtomicBool,
        pub(crate) start_hang_notified: Arc<Notify>,
        pub(crate) stop_hang_notified: Arc<Notify>,
    }

    impl TestResource {
        pub(crate) fn new(recorder: &Recorder, name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                recorder: recorder.clone(),
                fail_start: AtomicBool::new(false),
                fail_stop: AtomicBool::new(false),
                fail_cleanup: AtomicBool::new(false),
                hang_start: AtomicBool::new(false),
                hang_first_stop: AtomicBool::new(false),
                start_hang_notified: Arc::new(Notify::new()),
                stop_hang_notified: Arc::new(Notify::new()),
            })
        }

        fn record(&self, phase: &str) {
            self.recorder.record(format!("{}.{phase}", self.name));
        }
    }

    #[async_trait]
    impl GenerationResource for TestResource {
        fn name(&self) -> &str {
            &self.name
        }

        async fn start(&self) -> Result<()> {
            self.record("start");
            if self.hang_start.swap(false, Ordering::AcqRel) {
                self.start_hang_notified.notify_waiters();
                std::future::pending::<()>().await;
            }
            if self.fail_start.load(Ordering::Acquire) {
                return Err(Error::invalid(
                    format!("test.{}", self.name),
                    format!("injected start failure for `{}`", self.name),
                ));
            }
            Ok(())
        }

        async fn stop(&self) -> Result<()> {
            self.record("stop");
            if self.hang_first_stop.swap(false, Ordering::AcqRel) {
                self.stop_hang_notified.notify_waiters();
                std::future::pending::<()>().await;
            }
            if self.fail_stop.load(Ordering::Acquire) {
                return Err(Error::invalid(
                    format!("test.{}", self.name),
                    format!("injected stop failure for `{}`", self.name),
                ));
            }
            Ok(())
        }

        async fn cleanup(&self) -> Result<()> {
            self.record("cleanup");
            if self.fail_cleanup.load(Ordering::Acquire) {
                return Err(Error::invalid(
                    format!("test.{}", self.name),
                    format!("injected cleanup failure for `{}`", self.name),
                ));
            }
            Ok(())
        }
    }

    /// Hooks that attach a fixed resource list and can fail/hang on selected provision calls.
    pub(crate) struct TestHooks {
        pub(crate) recorder: Recorder,
        /// Resources attached on every call (used when `resources_per_call` has no entry).
        pub(crate) resources: Vec<Arc<TestResource>>,
        /// Optional distinct resources per 1-based provision call; lets tests give the old and the
        /// new generation separate resources so cleanup assertions are unambiguous.
        pub(crate) resources_per_call: Vec<Vec<Arc<TestResource>>>,
        /// Number of calls so far (1-based inside `provision`).
        pub(crate) provision_calls: AtomicUsize,
        /// 1-based provision call that fails after attaching `attach_before_error` resources;
        /// 0 means never.
        pub(crate) fail_on_provision_call: AtomicUsize,
        /// 1-based provision call that attaches everything and then never resolves.
        pub(crate) hang_on_provision_call: AtomicUsize,
        /// When true, provisioning always fails after `attach_before_error` attachments.
        pub(crate) provision_always_fails: AtomicBool,
        /// How many resources to attach before an injected provision error.
        pub(crate) attach_before_error: AtomicUsize,
    }

    impl TestHooks {
        pub(crate) fn new(recorder: Recorder, resources: Vec<Arc<TestResource>>) -> Arc<Self> {
            Arc::new(Self {
                recorder,
                resources,
                resources_per_call: Vec::new(),
                provision_calls: AtomicUsize::new(0),
                fail_on_provision_call: AtomicUsize::new(0),
                hang_on_provision_call: AtomicUsize::new(0),
                provision_always_fails: AtomicBool::new(false),
                attach_before_error: AtomicUsize::new(0),
            })
        }

        /// Use `resources` for the 1-based provision call `call` (other calls fall back to
        /// [`TestHooks::resources`]).
        pub(crate) fn use_resources_for_call(
            mut self: Arc<Self>,
            call: usize,
            resources: Vec<Arc<TestResource>>,
        ) -> Arc<Self> {
            // Tests configure this before handing the hooks to a store, so it must not be shared
            // yet (otherwise the configuration would race a provision in flight).
            let hooks = Arc::get_mut(&mut self).expect("hooks are already shared");
            if hooks.resources_per_call.len() < call {
                hooks.resources_per_call.resize_with(call, Vec::new);
            }
            hooks.resources_per_call[call - 1] = resources;
            self
        }

        fn resources_for_call(&self, call: usize) -> &[Arc<TestResource>] {
            self.resources_per_call
                .get(call.saturating_sub(1))
                .filter(|resources| !resources.is_empty())
                .map(Vec::as_slice)
                .unwrap_or(self.resources.as_slice())
        }
    }

    #[async_trait]
    impl GenerationHooks for TestHooks {
        async fn provision(
            &self,
            generation: &Generation,
            resources: &GenerationResources,
        ) -> Result<()> {
            let call = self.provision_calls.fetch_add(1, Ordering::AcqRel) + 1;
            self.recorder
                .record(format!("provision:{}", generation.id()));
            let fail_call = self.fail_on_provision_call.load(Ordering::Acquire);
            let always_fails = self.provision_always_fails.load(Ordering::Acquire);
            let resources_for_call = self.resources_for_call(call);
            let attach = if fail_call == call || always_fails {
                self.attach_before_error
                    .load(Ordering::Acquire)
                    .min(resources_for_call.len())
            } else {
                resources_for_call.len()
            };
            for resource in resources_for_call.iter().take(attach) {
                resources.attach(resource.clone())?;
                self.recorder.record(format!("attach:{}", resource.name()));
            }
            if fail_call == call || always_fails {
                return Err(Error::invalid(
                    format!("test.provision.{call}"),
                    format!("injected provision failure on call {call}"),
                ));
            }
            if self.hang_on_provision_call.load(Ordering::Acquire) == call {
                std::future::pending::<()>().await;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{Recorder, TestResource};
    use super::*;

    fn resource_set(
        names: &[&str],
    ) -> (Recorder, Arc<GenerationResources>, Vec<Arc<TestResource>>) {
        let recorder = Recorder::new();
        let resources = Arc::new(GenerationResources::new(7));
        let fakes = names
            .iter()
            .map(|name| TestResource::new(&recorder, name))
            .collect();
        (recorder, resources, fakes)
    }

    fn attach(resources: &GenerationResources, fakes: &[Arc<TestResource>]) {
        for fake in fakes {
            resources.attach(fake.clone()).expect("attach");
        }
        resources.mark_provisioned().expect("mark provisioned");
    }

    #[tokio::test]
    async fn start_stop_cleanup_order_and_cleanup_exactly_once() {
        let (recorder, resources, fakes) = resource_set(&["a", "b"]);
        attach(&resources, &fakes);
        assert_eq!(resources.phase(), ResourceLifecycle::Provisioned);

        resources.start().await.expect("start");
        assert_eq!(resources.phase(), ResourceLifecycle::Started);
        resources.stop().await.expect("stop");
        assert_eq!(resources.phase(), ResourceLifecycle::Stopped);
        resources.cleanup().await.expect("cleanup");
        assert_eq!(resources.phase(), ResourceLifecycle::Cleaned);

        // Repeated stop/cleanup calls are no-ops: cleanup is at-most-once.
        resources.stop().await.expect("stop twice");
        resources.cleanup().await.expect("cleanup twice");
        assert!(resources.is_cleaned());

        assert_eq!(
            recorder.events(),
            vec![
                "a.start",
                "b.start",
                "b.stop",
                "a.stop",
                "b.cleanup",
                "a.cleanup",
            ]
        );
    }

    #[tokio::test]
    async fn start_failure_stops_and_cleans_the_set_exactly_once() {
        let (recorder, resources, fakes) = resource_set(&["a", "b", "c"]);
        fakes[1].fail_start.store(true, Ordering::Release);
        attach(&resources, &fakes);

        let error = resources.start().await.expect_err("start fails");
        let message = error.to_string();
        assert!(
            message.contains("generation 7 start failed at resource `b`"),
            "{message}"
        );
        assert!(message.contains("injected start failure"), "{message}");
        assert_eq!(resources.phase(), ResourceLifecycle::Cleaned);

        // a started, b failed, c never started; stop runs in reverse over attempted resources.
        assert_eq!(
            recorder.events(),
            vec![
                "a.start",
                "b.start",
                "b.stop",
                "a.stop",
                "c.cleanup",
                "b.cleanup",
                "a.cleanup",
            ]
        );

        // A later cleanup must not touch the resources again.
        resources
            .cleanup()
            .await
            .expect("cleanup after failure is a no-op");
        assert_eq!(recorder.count("a.cleanup"), 1);
        assert_eq!(recorder.count("b.cleanup"), 1);
    }

    #[tokio::test]
    async fn cleanup_reports_all_failures_and_continues() {
        let (recorder, resources, fakes) = resource_set(&["a", "b"]);
        fakes[0].fail_cleanup.store(true, Ordering::Release);
        fakes[1].fail_cleanup.store(true, Ordering::Release);
        attach(&resources, &fakes);
        resources.start().await.expect("start");

        let error = resources.cleanup().await.expect_err("cleanup fails");
        let message = error.to_string();
        assert!(
            message.contains("generation 7 cleanup failed at resource `b`"),
            "{message}"
        );
        assert!(message.contains("additionally"), "{message}");
        assert!(
            message.contains("injected cleanup failure for `a`"),
            "{message}"
        );
        // Both resources were attempted despite the first failure.
        assert_eq!(recorder.count("a.cleanup"), 1);
        assert_eq!(recorder.count("b.cleanup"), 1);
        assert_eq!(resources.phase(), ResourceLifecycle::Cleaned);
    }

    #[tokio::test]
    async fn cleanup_stops_resources_whose_start_was_interrupted() {
        // Simulate cancellation in the middle of `start`: the start future is dropped while the
        // resource is starting. Cleanup must still stop and clean it exactly once.
        let (recorder, resources, fakes) = resource_set(&["slow"]);
        attach(&resources, &fakes);
        let slow = fakes[0].clone();
        slow.hang_start.store(true, Ordering::Release);

        let start = tokio::spawn({
            let resources = Arc::clone(&resources);
            async move { resources.start().await }
        });
        slow.start_hang_notified.notified().await;
        start.abort();
        let _ = start.await;

        resources
            .cleanup()
            .await
            .expect("cleanup after cancelled start");
        assert_eq!(
            recorder.events(),
            vec!["slow.start", "slow.stop", "slow.cleanup"]
        );
        resources.cleanup().await.expect("idempotent cleanup");
        assert_eq!(recorder.count("slow.cleanup"), 1);
    }

    #[tokio::test]
    async fn stop_failures_are_reported_but_cleanup_still_runs() {
        let (recorder, resources, fakes) = resource_set(&["a", "b"]);
        fakes[1].fail_stop.store(true, Ordering::Release);
        attach(&resources, &fakes);
        resources.start().await.expect("start");

        let error = resources.stop().await.expect_err("stop fails");
        assert!(error.to_string().contains("injected stop failure for `b`"));
        resources.cleanup().await.expect("cleanup succeeds");
        assert_eq!(recorder.count("a.stop"), 1);
        assert_eq!(recorder.count("b.stop"), 1);
        assert_eq!(recorder.count("b.cleanup"), 1);
    }

    #[test]
    fn attach_after_provisioning_is_rejected() {
        let (_recorder, resources, fakes) = resource_set(&["a"]);
        resources.mark_provisioned().expect("mark provisioned");
        let error = resources
            .attach(fakes[0].clone())
            .expect_err("attach rejected");
        assert!(error.to_string().contains("after provisioning"), "{error}");
        assert!(resources.is_empty());
    }

    #[tokio::test]
    async fn cancellation_token_resolves_waiters_and_is_idempotent() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        let waiter = token.clone();
        let waiting = tokio::spawn(async move { waiter.cancelled().await });
        tokio::task::yield_now().await;
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
        waiting.await.expect("waiter resolves");
        // Already cancelled: the future resolves immediately.
        token.cancelled().await;
    }

    #[test]
    fn lifecycle_phase_names_are_stable() {
        assert_eq!(ResourceLifecycle::Provisioning.as_str(), "provisioning");
        assert_eq!(ResourceLifecycle::Cleaned.as_str(), "cleaned");
    }
}
