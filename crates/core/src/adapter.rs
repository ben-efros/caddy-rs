//! Configuration-adapter interface.
//!
//! Caddy treats the Caddyfile as an adapter that emits native JSON configuration. This crate
//! models that boundary so the Caddyfile adapter (`caddy-rs-config`) is just one implementation,
//! and future adapters (YAML, TOML, Kubernetes CRDs) slot in without touching the runtime.

use serde_json::Value;

use crate::error::Result;

/// The result of adapting a user-facing configuration into native configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct AdaptedConfig {
    /// Native Caddy JSON configuration.
    pub config: Value,
    /// Non-fatal compatibility warnings, in the shape Caddy's `/adapt` endpoint returns.
    pub warnings: Vec<String>,
}

/// A user-facing configuration adapter.
pub trait ConfigAdapter: Send + Sync {
    /// Stable adapter name (`caddyfile`), matching Caddy's `--adapter` flag.
    fn name(&self) -> &'static str;

    /// Adapt UTF-8 input bytes to native JSON configuration.
    fn adapt(&self, input: &[u8]) -> Result<AdaptedConfig>;
}
