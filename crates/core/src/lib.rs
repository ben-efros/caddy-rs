//! Core runtime model for caddy-rs.
//!
//! This crate holds the pieces every other subsystem depends on and that must be stable before
//! any handler is written:
//!
//! - [`config`]: the Caddy-compatible JSON configuration model.
//! - [`autosave`]: atomic persistence/loading of the last active config (`--resume` support).
//! - [`listen`]: Caddy listen-address parsing.
//! - [`module`]: the static module registry.
//! - [`validate`]: located validation of handlers, matchers, listeners, and issuers.
//! - [`generation`]: immutable configuration generations and atomic reload/drain.
//! - [`lifecycle`]: async provisioning/start/stop/cleanup hooks for generation-owned resources.
//! - [`adapter`]: the Caddyfile-to-JSON adapter interface.
//!
//! It has no HTTP, TLS, or filesystem dependencies beyond `tokio` time/sync for draining and the
//! async generation lifecycle.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod autosave;
pub mod config;
pub mod duration;
pub mod error;
pub mod generation;
pub mod lifecycle;
pub mod listen;
pub mod module;
pub mod validate;

pub use adapter::{AdaptedConfig, ConfigAdapter};
pub use config::{
    AdminConfig, Apps, AutoHttps, AutomationPolicy, BaseLog, CertKeyFilePair, CertKeyPemPair,
    CertificateAuthority, CertificatesConfig, Config, CustomLog, HttpApp, HttpServer,
    ListenerWrapperConfig, LogEncoder, LogSampling, LogWriter, Logging, ModuleRef, NamedModuleRef,
    OnDemandConfig, PkiApp, PkiKeyPair, ProviderModuleRef, ProxyProtocolConfig,
    ProxyProtocolPolicy, Route, ServerLogConfig, SessionTicketService, SinkLog, StorageConfig,
    StringList, TlsApp, TlsAutomation,
};
pub use duration::{parse_caddy_duration, CaddyDuration};
pub use error::{Error, Result};
pub use generation::{
    drain, DrainOutcome, Generation, GenerationStore, LifecycleState, LoadResult, StopResult,
};
pub use lifecycle::{
    CancellationToken, GenerationHooks, GenerationResource, GenerationResources, ResourceLifecycle,
};
pub use listen::{ListenAddr, Network};
pub use module::{Module, ModuleKind, ModuleRegistry, ModuleRegistryBuilder, SharedModuleRegistry};
pub use validate::{validate_config, ValidationReport};

/// Version reported by `caddy-rs version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The Caddy release whose configuration contract this build targets.
pub const CADDY_COMPAT_BASELINE: &str = "v2.11.7";
