//! Module registry.
//!
//! Caddy's extension model identifies every pluggable component by a dotted module id
//! (`http.handlers.reverse_proxy`) while JSON configuration usually names it by a short key
//! (`reverse_proxy`). This registry models both, and is the single place where "is this module
//! known?" is answered during validation and runtime construction.
//!
//! Built-in modules are statically registered (the Caddy model). On top of that this module
//! supports *runtime registration* for tests, embedders and (later) plugins:
//!
//! * [`Module::owned`] builds a module descriptor from owned strings (interned for the process
//!   lifetime, matching Caddy's init-time registration model);
//! * [`ModuleRegistryBuilder`] layers custom modules over the built-in registry without mutating
//!   any global state — each builder produces its own [`ModuleRegistry`];
//! * [`ModuleRegistry::overlay`] returns a new registry with extra modules, leaving the base
//!   registry (and the default registry) untouched;
//! * [`ModuleRegistry::register_owned`] registers into an existing mutable registry.
//!
//! Registration validates definitions (non-empty id/key, no control/whitespace characters) and
//! rejects duplicate ids as well as `(kind, json key)` collisions, so resolution stays
//! deterministic. The registry is a plain immutable value after construction: it is `Send + Sync`
//! and can be shared through [`SharedModuleRegistry`]/`Arc` across threads.
//!
//! Validation and listing already take the registry as a parameter
//! ([`crate::validate_config`], [`ModuleRegistry::modules`], [`ModuleRegistry::entries`]), so a
//! custom registry from this builder can validate configurations that reference custom handler or
//! matcher ids without touching the built-in path. The module descriptors carry metadata only:
//! executing a custom module still requires the owning subsystem (HTTP engine, TLS, ...) to know
//! how to construct it. Third-party out-of-process/WASM modules remain a future mechanism
//! (WS-08); see `docs/ARCHITECTURE.md`.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{Error, Result};

/// A module definition with process-lifetime strings, produced by [`Module::owned`].
///
/// Registration is expected to happen at startup (like Caddy's `init`-time module registration),
/// so the id/key/summary strings are interned for the process lifetime. Do not register modules
/// per request or otherwise unbounded.
fn intern(value: impl Into<String>) -> &'static str {
    Box::leak(value.into().into_boxed_str())
}

/// Category of a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModuleKind {
    /// HTTP middleware handler (`http.handlers.*`).
    HttpHandler,
    /// HTTP request matcher (`http.matchers.*`).
    HttpMatcher,
    /// TLS certificate issuer (`tls.issuance.*`).
    TlsIssuer,
    /// ACME DNS challenge provider (`dns.providers.*`).
    DnsProvider,
    /// Storage backend (`caddy.storage.*`).
    Storage,
    /// TLS certificate loader (`tls.certificates.*`).
    TlsCertificateLoader,
    /// TLS session-ticket key provider (`tls.stek.*`).
    StekProvider,
    /// On-Demand TLS permission module (`tls.permission.*`).
    TlsPermission,
    /// Log encoder (`caddy.logging.encoders.*`).
    LogEncoder,
    /// Log writer (`caddy.logging.writers.*`).
    LogWriter,
    /// Log core (`caddy.logging.cores.*`).
    LogCore,
    /// Listener wrapper (`caddy.listeners.*`).
    ListenerWrapper,
    /// Application module (`apps.*`).
    App,
    /// Anything else.
    Other,
}

impl ModuleKind {
    /// Stable label used in diagnostics and listings.
    pub const fn label(self) -> &'static str {
        match self {
            ModuleKind::HttpHandler => "HTTP handler",
            ModuleKind::HttpMatcher => "HTTP matcher",
            ModuleKind::TlsIssuer => "TLS issuer",
            ModuleKind::DnsProvider => "DNS provider",
            ModuleKind::Storage => "storage",
            ModuleKind::TlsCertificateLoader => "TLS certificate loader",
            ModuleKind::StekProvider => "session ticket key provider",
            ModuleKind::TlsPermission => "TLS on-demand permission",
            ModuleKind::LogEncoder => "log encoder",
            ModuleKind::LogWriter => "log writer",
            ModuleKind::LogCore => "log core",
            ModuleKind::ListenerWrapper => "listener wrapper",
            ModuleKind::App => "app",
            ModuleKind::Other => "module",
        }
    }

    /// Dotted id prefix for this kind, or `""` when there is none.
    pub const fn id_prefix(self) -> &'static str {
        match self {
            ModuleKind::HttpHandler => "http.handlers.",
            ModuleKind::HttpMatcher => "http.matchers.",
            ModuleKind::TlsIssuer => "tls.issuance.",
            ModuleKind::DnsProvider => "dns.providers.",
            ModuleKind::Storage => "caddy.storage.",
            ModuleKind::TlsCertificateLoader => "tls.certificates.",
            ModuleKind::StekProvider => "tls.stek.",
            ModuleKind::TlsPermission => "tls.permission.",
            ModuleKind::LogEncoder => "caddy.logging.encoders.",
            ModuleKind::LogWriter => "caddy.logging.writers.",
            ModuleKind::LogCore => "caddy.logging.cores.",
            ModuleKind::ListenerWrapper => "caddy.listeners.",
            ModuleKind::App => "apps.",
            ModuleKind::Other => "",
        }
    }
}

/// A registered module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    /// Fully qualified Caddy module id.
    pub id: &'static str,
    /// Key used in JSON configuration objects (for example `reverse_proxy`).
    pub json_key: &'static str,
    /// Category.
    pub kind: ModuleKind,
    /// One-line description shown by `caddy-rs list-modules`.
    pub summary: &'static str,
}

impl Module {
    /// Construct a static module record (used by the built-in table and tests).
    pub const fn new(
        id: &'static str,
        json_key: &'static str,
        kind: ModuleKind,
        summary: &'static str,
    ) -> Self {
        Self {
            id,
            json_key,
            kind,
            summary,
        }
    }

    /// Construct a runtime module record from owned strings.
    ///
    /// The strings are interned for the process lifetime; this is intended for startup-time
    /// registration (tests, embedders, plugin loaders), matching Caddy's module registration
    /// model. Use [`ModuleRegistryBuilder::register`] for a validated registration path.
    pub fn owned(
        id: impl Into<String>,
        json_key: impl Into<String>,
        kind: ModuleKind,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            id: intern(id),
            json_key: intern(json_key),
            kind,
            summary: intern(summary),
        }
    }

    /// Construct a runtime module record, validating the id/JSON key *before* interning.
    ///
    /// Prefer this over [`Module::owned`] for caller-supplied strings: a rejected definition does
    /// not leak its strings.
    pub fn try_owned(
        id: impl Into<String>,
        json_key: impl Into<String>,
        kind: ModuleKind,
        summary: impl Into<String>,
    ) -> Result<Self> {
        let id = id.into();
        let json_key = json_key.into();
        validate_definition_parts(&id, &json_key)?;
        Ok(Self {
            id: intern(id),
            json_key: intern(json_key),
            kind,
            summary: intern(summary),
        })
    }
}

/// Registry of modules known to this build plus any runtime-registered modules.
///
/// The registry is an immutable value after construction: registration methods take `&mut self`
/// and the runtime shares an `Arc<ModuleRegistry>` (see [`SharedModuleRegistry`]). Cloning is
/// cheap enough for overlays, and overlaying never mutates the source registry, so the built-in
/// default cannot be changed by a test or a plugin.
#[derive(Debug, Clone, Default)]
pub struct ModuleRegistry {
    by_id: BTreeMap<&'static str, Module>,
    by_key: BTreeMap<(&'static str, &'static str), &'static str>,
}

/// A shared, immutable module registry (what the generation store and runtimes hold).
pub type SharedModuleRegistry = Arc<ModuleRegistry>;

impl ModuleRegistry {
    /// An empty registry.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Registry populated with the modules this build knows about.
    ///
    /// Most entries are implemented and executable. A small number are **reserved**: their
    /// names are registered so configuration using them passes validation and then fails during
    /// provisioning with a tracking id ([`Error::NotImplemented`]), rather than being rejected as
    /// an unknown module. Reserved entries are marked `(planned, ...)` in their summary; the
    /// documentation lists both sets explicitly (`docs/compatibility/MODULE-PARITY.md`).
    pub fn builtin() -> Self {
        let mut registry = Self::default();
        for module in BUILTIN_MODULES {
            registry
                .register(module.clone())
                .expect("built-in module table has no duplicate ids");
        }
        registry
    }

    /// Register a module, rejecting duplicate ids and `(kind, json key)` collisions.
    ///
    /// Runtime registrations should go through [`ModuleRegistry::register_owned`] or
    /// [`ModuleRegistryBuilder`], which build the [`Module`] for you; this method accepts static or
    /// [`Module::owned`] descriptors alike.
    pub fn register(&mut self, module: Module) -> Result<()> {
        validate_module_definition(&module)?;
        if self.by_id.contains_key(module.id) {
            return Err(Error::DuplicateModule(module.id));
        }
        let key = (module.kind.label(), module.json_key);
        if let Some(existing) = self.by_key.get(&key) {
            return Err(Error::ModuleKeyConflict {
                kind: module.kind.label(),
                key: module.json_key,
                existing,
                incoming: module.id,
            });
        }
        self.by_key.insert(key, module.id);
        self.by_id.insert(module.id, module);
        Ok(())
    }

    /// Build a module from owned strings and register it.
    ///
    /// This is the runtime-extension entry point: a test or embedder can register a custom
    /// handler/matcher/storage module and then validate or list configurations against the
    /// resulting registry. See [`ModuleRegistryBuilder`] for the layered-over-builtins form.
    pub fn register_owned(
        &mut self,
        id: impl Into<String>,
        json_key: impl Into<String>,
        kind: ModuleKind,
        summary: impl Into<String>,
    ) -> Result<&mut Self> {
        self.register(Module::try_owned(id, json_key, kind, summary)?)?;
        Ok(self)
    }

    /// Return a new registry consisting of this registry plus `modules`.
    ///
    /// The source registry (including [`ModuleRegistry::builtin`]) is never modified, so callers
    /// can layer custom modules over the default without global-state hazards.
    pub fn overlay<I>(&self, modules: I) -> Result<Self>
    where
        I: IntoIterator<Item = Module>,
    {
        let mut next = self.clone();
        for module in modules {
            next.register(module)?;
        }
        Ok(next)
    }

    /// Start a builder that layers custom modules over this registry.
    pub fn builder_with_overlay(&self) -> ModuleRegistryBuilder {
        ModuleRegistryBuilder::from_registry(self.clone())
    }

    /// A registry builder that includes every built-in module (the common case).
    pub fn builder() -> ModuleRegistryBuilder {
        ModuleRegistryBuilder::with_builtins()
    }

    /// Look a module up by fully qualified id.
    pub fn get(&self, id: &str) -> Option<&Module> {
        self.by_id.get(id)
    }

    /// Look a module up by kind and short JSON key.
    pub fn get_by_key(&self, kind: ModuleKind, json_key: &str) -> Option<&Module> {
        self.by_key
            .get(&(kind.label(), json_key))
            .and_then(|id| self.by_id.get(id))
    }

    /// Resolve an HTTP handler's `handler` key.
    pub fn resolve_handler(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::HttpHandler, json_key)
    }

    /// Resolve an HTTP matcher object key.
    pub fn resolve_matcher(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::HttpMatcher, json_key)
    }

    /// Resolve a log writer's `output` key (`caddy.logging.writers.*`).
    pub fn resolve_log_writer(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::LogWriter, json_key)
    }

    /// Resolve a log encoder's `format` key (`caddy.logging.encoders.*`).
    pub fn resolve_log_encoder(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::LogEncoder, json_key)
    }

    /// Resolve a log core's `module` key (`caddy.logging.cores.*`).
    pub fn resolve_log_core(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::LogCore, json_key)
    }

    /// Resolve a TLS certificate loader key (`tls.certificates.*`).
    pub fn resolve_certificate_loader(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::TlsCertificateLoader, json_key)
    }

    /// Resolve a session-ticket key provider key (`tls.stek.*`).
    pub fn resolve_stek_provider(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::StekProvider, json_key)
    }

    /// Resolve a listener wrapper key (`caddy.listeners.*`).
    pub fn resolve_listener_wrapper(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::ListenerWrapper, json_key)
    }

    /// Resolve an On-Demand TLS permission module key (`tls.permission.*`).
    pub fn resolve_tls_permission(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::TlsPermission, json_key)
    }

    /// Whether a module id is registered.
    pub fn contains(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    /// A located "unknown module" error that suggests the closest registered key of `kind`.
    ///
    /// Every unknown-module diagnostic goes through this so the "did you mean" suggestion can
    /// never disagree with the registry: the candidates are exactly the JSON keys registered for
    /// that kind (plus their dotted ids, so a mistyped qualified reference is still recognised).
    /// `Error::code` reports the stable machine-readable code `module.unknown` for all of them.
    pub fn unknown_module(
        &self,
        kind: ModuleKind,
        name: impl AsRef<str>,
        path: impl Into<String>,
    ) -> Error {
        let candidates: Vec<&str> = self
            .modules()
            .filter(|module| module.kind == kind)
            .flat_map(|module| [module.json_key, module.id])
            .collect();
        Error::unknown_module(kind.label(), name.as_ref(), path, candidates)
    }

    /// All registered modules, ordered by id (deterministic; includes runtime registrations).
    pub fn modules(&self) -> impl Iterator<Item = &Module> {
        self.by_id.values()
    }

    /// Alias for [`ModuleRegistry::modules`], making the listing/plugin API explicit.
    pub fn entries(&self) -> impl Iterator<Item = &Module> {
        self.modules()
    }

    /// Whether `id` is one of this build's statically listed modules (not a runtime addition).
    pub fn is_builtin_module(&self, id: &str) -> bool {
        BUILTIN_MODULES.iter().any(|module| module.id == id)
    }

    /// Validate `config` against this registry (convenience for embedders/tests holding a custom
    /// registry; equivalent to [`crate::validate_config`]).
    pub fn validate(&self, config: &crate::Config) -> Result<crate::ValidationReport> {
        crate::validate::validate_config(config, self)
    }

    /// Number of registered modules.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether no modules are registered.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

/// Builds a module registry, optionally layered over the built-in modules.
///
/// The builder owns its registry, so concurrent builders never share mutable state and building
/// the same sequence of registrations always yields the same (id-ordered) registry. Duplicate ids
/// and key collisions are rejected by [`ModuleRegistryBuilder::register`].
///
/// ```ignore
/// let registry = ModuleRegistry::builder()
///     .register("http.handlers.my_plugin", "my_plugin", ModuleKind::HttpHandler, "My plugin")
///     .and_then(|builder| builder.register("http.matchers.my_matcher", "my_matcher", ModuleKind::HttpMatcher, "My matcher"))
///     .expect("no duplicates")
///     .build();
/// let report = registry.validate(&config)?; // custom ids validate like built-ins
/// ```
#[derive(Debug, Clone, Default)]
pub struct ModuleRegistryBuilder {
    registry: ModuleRegistry,
}

impl ModuleRegistryBuilder {
    /// A builder starting from an empty registry (no built-ins).
    pub fn empty() -> Self {
        Self {
            registry: ModuleRegistry::empty(),
        }
    }

    /// A builder starting from the built-in registry (custom modules are layered on top).
    pub fn with_builtins() -> Self {
        Self {
            registry: ModuleRegistry::builtin(),
        }
    }

    /// A builder starting from a copy of `registry`.
    pub fn from_registry(registry: ModuleRegistry) -> Self {
        Self { registry }
    }

    /// The registry as built so far (useful for assertions while chaining).
    pub fn registry(&self) -> &ModuleRegistry {
        &self.registry
    }

    /// Register a module from owned strings.
    pub fn register(
        mut self,
        id: impl Into<String>,
        json_key: impl Into<String>,
        kind: ModuleKind,
        summary: impl Into<String>,
    ) -> Result<Self> {
        self.registry.register_owned(id, json_key, kind, summary)?;
        Ok(self)
    }

    /// Register an existing (static or owned) module descriptor.
    pub fn register_module(mut self, module: Module) -> Result<Self> {
        self.registry.register(module)?;
        Ok(self)
    }

    /// Register every module in `modules`, failing on the first duplicate/conflict.
    pub fn overlay<I>(mut self, modules: I) -> Result<Self>
    where
        I: IntoIterator<Item = Module>,
    {
        for module in modules {
            self.registry.register(module)?;
        }
        Ok(self)
    }

    /// Finish building the registry.
    pub fn build(self) -> ModuleRegistry {
        self.registry
    }
}

/// Reject module definitions that can never be resolved or listed deterministically.
fn validate_module_definition(module: &Module) -> Result<()> {
    validate_definition_parts(module.id, module.json_key)
}

fn validate_definition_parts(id: &str, json_key: &str) -> Result<()> {
    let invalid = |message: String| Err(Error::InvalidModuleDefinition { message });
    if id.is_empty() {
        return invalid("module id must not be empty".to_string());
    }
    if id
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return invalid(format!(
            "module id `{id}` must not contain whitespace or control characters"
        ));
    }
    if id.contains(|character| character == '{' || character == '}') {
        return invalid(format!("module id `{id}` must not contain braces"));
    }
    if json_key.is_empty() {
        return invalid(format!("module `{id}` must have a non-empty JSON key"));
    }
    if json_key
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        || json_key.contains(|character| character == '{' || character == '}' || character == '/')
    {
        return invalid(format!(
            "module `{id}` JSON key `{json_key}` contains an illegal character"
        ));
    }
    Ok(())
}

/// Modules implemented by this build.
///
/// Keep this table in sync with `list-modules` output and `docs/compatibility/MODULE-PARITY.md`.
/// The module inventory generator compares it against upstream `caddy.RegisterModule` calls.
pub const BUILTIN_MODULES: &[Module] = &[
    // Listener wrappers
    Module::new(
        "caddy.listeners.proxy_protocol",
        "proxy_protocol",
        ModuleKind::ListenerWrapper,
        "PROXY protocol v1/v2 header parsing on TCP/Unix listeners",
    ),
    Module::new(
        "caddy.listeners.tls",
        "tls",
        ModuleKind::ListenerWrapper,
        "TLS handshake listener wrapper (implicit in caddy-rs; accepted as ordering marker)",
    ),
    Module::new(
        "caddy.listeners.http_redirect",
        "http_redirect",
        ModuleKind::ListenerWrapper,
        "Automatic HTTP-to-HTTPS redirect listener (planned, handled internally by the server)",
    ),
    // Applications
    Module::new("http", "http", ModuleKind::App, "HTTP server app"),
    Module::new("tls", "tls", ModuleKind::App, "TLS app"),
    // HTTP handlers
    Module::new(
        "http.handlers.static_response",
        "static_response",
        ModuleKind::HttpHandler,
        "Write a fixed or computed response",
    ),
    Module::new(
        "http.handlers.file_server",
        "file_server",
        ModuleKind::HttpHandler,
        "Serve static files from a root directory",
    ),
    Module::new(
        "http.handlers.reverse_proxy",
        "reverse_proxy",
        ModuleKind::HttpHandler,
        "Proxy requests to upstream servers",
    ),
    Module::new(
        "http.handlers.forward_auth",
        "forward_auth",
        ModuleKind::HttpHandler,
        "Authentication gate via a subrequest to an auth service (caddy-rs handler; upstream          adapts forward_auth to reverse_proxy)",
    ),
    Module::new(
        "http.handlers.authentication",
        "authentication",
        ModuleKind::HttpHandler,
        "Authentication middleware with the HTTP Basic provider (native bcrypt and argon2id password-hash verification, constant-time comparison)",
    ),
    Module::new(
        "http.handlers.basic_auth",
        "basic_auth",
        ModuleKind::HttpHandler,
        "HTTP Basic authentication (caddy-rs shorthand for the authentication handler)",
    ),
    Module::new(
        "http.handlers.rewrite",
        "rewrite",
        ModuleKind::HttpHandler,
        "Rewrite request URI, method, or headers",
    ),
    Module::new(
        "http.handlers.headers",
        "headers",
        ModuleKind::HttpHandler,
        "Set, add, or delete request/response headers",
    ),
    Module::new(
        "http.handlers.subroute",
        "subroute",
        ModuleKind::HttpHandler,
        "Nested route group",
    ),
    Module::new(
        "http.handlers.vars",
        "vars",
        ModuleKind::HttpHandler,
        "Set request variables consumed by later handlers",
    ),
    Module::new(
        "http.handlers.encode",
        "encode",
        ModuleKind::HttpHandler,
        "Response compression middleware: gzip/zstd Accept-Encoding negotiation, prefer order, minimum length, response matcher, Content-Encoding/Vary/ETag handling, streaming compression",
    ),
    Module::new(
        "http.handlers.request_body",
        "request_body",
        ModuleKind::HttpHandler,
        "Limit or replace the request body for later handlers",
    ),
    Module::new(
        "http.handlers.map",
        "map",
        ModuleKind::HttpHandler,
        "Map a source value to destination placeholders",
    ),
    Module::new(
        "http.handlers.error",
        "error",
        ModuleKind::HttpHandler,
        "Abort with a recommended status and message handled by the server's error routes",
    ),
    // HTTP matchers
    Module::new(
        "http.matchers.host",
        "host",
        ModuleKind::HttpMatcher,
        "Match request Host",
    ),
    Module::new(
        "http.matchers.path",
        "path",
        ModuleKind::HttpMatcher,
        "Match request path with wildcards",
    ),
    Module::new(
        "http.matchers.path_regexp",
        "path_regexp",
        ModuleKind::HttpMatcher,
        "Match request path with a regular expression (config only; runtime not implemented)",
    ),
    Module::new(
        "http.matchers.method",
        "method",
        ModuleKind::HttpMatcher,
        "Match request method",
    ),
    Module::new(
        "http.matchers.header",
        "header",
        ModuleKind::HttpMatcher,
        "Match request headers",
    ),
    Module::new(
        "http.matchers.query",
        "query",
        ModuleKind::HttpMatcher,
        "Match query parameters",
    ),
    Module::new(
        "http.matchers.file",
        "file",
        ModuleKind::HttpMatcher,
        "Match requests by file existence under a root (try_files)",
    ),
    Module::new(
        "http.matchers.remote_ip",
        "remote_ip",
        ModuleKind::HttpMatcher,
        "Match the direct peer IP",
    ),
    Module::new(
        "http.matchers.client_ip",
        "client_ip",
        ModuleKind::HttpMatcher,
        "Match the resolved client IP",
    ),
    Module::new(
        "http.matchers.local_ip",
        "local_ip",
        ModuleKind::HttpMatcher,
        "Match the local listener IP (caddy-rs extension; Caddy v2.11.9 has no HTTP local_ip matcher)",
    ),
    Module::new(
        "http.matchers.protocol",
        "protocol",
        ModuleKind::HttpMatcher,
        "Match the request protocol",
    ),
    Module::new(
        "http.matchers.tls",
        "tls",
        ModuleKind::HttpMatcher,
        "Match TLS connections",
    ),
    Module::new(
        "http.matchers.expression",
        "expression",
        ModuleKind::HttpMatcher,
        "CEL expression matcher (implemented subset: integer comparisons used by handle_errors)",
    ),
    // Storage
    Module::new(
        "caddy.storage.file_system",
        "file_system",
        ModuleKind::Storage,
        "Local filesystem certificate storage",
    ),
    // TLS issuers
    Module::new(
        "tls.issuance.acme",
        "acme",
        ModuleKind::TlsIssuer,
        "ACME certificate issuer (ACME client planned, M5)",
    ),
    Module::new(
        "tls.issuance.internal",
        "internal",
        ModuleKind::TlsIssuer,
        "Local internal CA issuer (planned, M5)",
    ),
    // DNS providers
    Module::new(
        "dns.providers.cloudflare",
        "cloudflare",
        ModuleKind::DnsProvider,
        "Cloudflare DNS-01 provider (planned, M6)",
    ),
    // TLS certificate loaders (configuration only; loading is part of the TLS workstream)
    Module::new(
        "tls.certificates.load_files",
        "load_files",
        ModuleKind::TlsCertificateLoader,
        "Load certificate/key pairs from disk (config only)",
    ),
    Module::new(
        "tls.certificates.load_pem",
        "load_pem",
        ModuleKind::TlsCertificateLoader,
        "Load certificate/key pairs from PEM blocks (config only)",
    ),
    Module::new(
        "tls.certificates.load_folders",
        "load_folders",
        ModuleKind::TlsCertificateLoader,
        "Load certificates from folders (config only)",
    ),
    Module::new(
        "tls.certificates.load_storage",
        "load_storage",
        ModuleKind::TlsCertificateLoader,
        "Load certificate/key pairs from storage (config only)",
    ),
    Module::new(
        "tls.certificates.automate",
        "automate",
        ModuleKind::TlsCertificateLoader,
        "Automatically manage certificates for subjects (config only)",
    ),
    // TLS session ticket key providers
    Module::new(
        "tls.stek.standard",
        "standard",
        ModuleKind::StekProvider,
        "Standard-library session ticket key provider (config only)",
    ),
    // On-Demand TLS permission modules
    Module::new(
        "tls.permission.http",
        "http",
        ModuleKind::TlsPermission,
        "Ask an HTTP endpoint for On-Demand TLS permission (config only)",
    ),
    // Logging encoders
    Module::new(
        "caddy.logging.encoders.console",
        "console",
        ModuleKind::LogEncoder,
        "Human-readable console log encoder (config only)",
    ),
    Module::new(
        "caddy.logging.encoders.json",
        "json",
        ModuleKind::LogEncoder,
        "Structured JSON log encoder (config only)",
    ),
    Module::new(
        "caddy.logging.encoders.filter",
        "filter",
        ModuleKind::LogEncoder,
        "Filtering log encoder wrapper (config only)",
    ),
    Module::new(
        "caddy.logging.encoders.append",
        "append",
        ModuleKind::LogEncoder,
        "Encoder that appends fields (config only)",
    ),
    Module::new(
        "caddy.logging.encoders.journald",
        "journald",
        ModuleKind::LogEncoder,
        "systemd journal log encoder (config only)",
    ),
    // Logging writers
    Module::new(
        "caddy.logging.writers.stdout",
        "stdout",
        ModuleKind::LogWriter,
        "Write logs to standard output (config only)",
    ),
    Module::new(
        "caddy.logging.writers.stderr",
        "stderr",
        ModuleKind::LogWriter,
        "Write logs to standard error (config only)",
    ),
    Module::new(
        "caddy.logging.writers.discard",
        "discard",
        ModuleKind::LogWriter,
        "Discard logs (config only)",
    ),
    Module::new(
        "caddy.logging.writers.file",
        "file",
        ModuleKind::LogWriter,
        "Write logs to a file with rotation (config only)",
    ),
    Module::new(
        "caddy.logging.writers.net",
        "net",
        ModuleKind::LogWriter,
        "Write logs to a network socket (config only)",
    ),
    // Logging cores
    Module::new(
        "caddy.logging.cores.mock",
        "mock",
        ModuleKind::LogCore,
        "Test log core (config only)",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_resolves_short_keys_and_ids() {
        let registry = ModuleRegistry::builtin();
        assert_eq!(
            registry.resolve_handler("reverse_proxy").map(|m| m.id),
            Some("http.handlers.reverse_proxy")
        );
        assert_eq!(
            registry.resolve_matcher("host").map(|m| m.id),
            Some("http.matchers.host")
        );
        assert!(registry.resolve_handler("not_a_real_handler").is_none());
        assert!(registry.get("apps.http").is_none());
        assert!(registry.contains("http"));
    }

    #[test]
    fn builtin_registry_covers_settings_modules() {
        let registry = ModuleRegistry::builtin();
        for (kind, key) in [
            (ModuleKind::LogWriter, "stderr"),
            (ModuleKind::LogWriter, "file"),
            (ModuleKind::LogEncoder, "json"),
            (ModuleKind::LogEncoder, "console"),
            (ModuleKind::LogCore, "mock"),
            (ModuleKind::TlsCertificateLoader, "load_files"),
            (ModuleKind::TlsCertificateLoader, "load_pem"),
            (ModuleKind::TlsCertificateLoader, "automate"),
            (ModuleKind::StekProvider, "standard"),
            (ModuleKind::TlsPermission, "http"),
            (ModuleKind::Storage, "file_system"),
            (ModuleKind::TlsIssuer, "acme"),
            (ModuleKind::DnsProvider, "cloudflare"),
            (ModuleKind::HttpHandler, "forward_auth"),
            (ModuleKind::HttpHandler, "authentication"),
            (ModuleKind::HttpHandler, "basic_auth"),
            (ModuleKind::HttpHandler, "request_body"),
            (ModuleKind::HttpHandler, "map"),
            (ModuleKind::HttpMatcher, "file"),
            (ModuleKind::HttpMatcher, "remote_ip"),
            (ModuleKind::HttpMatcher, "client_ip"),
            (ModuleKind::HttpMatcher, "local_ip"),
            (ModuleKind::HttpMatcher, "protocol"),
            (ModuleKind::HttpMatcher, "tls"),
        ] {
            assert!(
                registry.get_by_key(kind, key).is_some(),
                "missing {kind:?} module `{key}`"
            );
        }
        assert!(registry.resolve_log_encoder("xml").is_none());
    }

    #[test]
    fn duplicate_ids_are_refused() {
        let mut registry = ModuleRegistry::empty();
        registry
            .register(Module::new(
                "http.handlers.a",
                "a",
                ModuleKind::HttpHandler,
                "a",
            ))
            .unwrap();
        let err = registry
            .register(Module::new(
                "http.handlers.a",
                "b",
                ModuleKind::HttpHandler,
                "b",
            ))
            .expect_err("duplicate id");
        assert!(matches!(err, Error::DuplicateModule("http.handlers.a")));
    }

    fn config_with_handler(handler: &str) -> crate::Config {
        crate::Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {
                "listen": [":443"],
                "routes": [{"handle": [{"handler": handler}]}]
            }}}}
        }))
        .expect("config decodes")
    }

    #[test]
    fn builder_layers_custom_modules_over_builtins() {
        let builtin_count = ModuleRegistry::builtin().len();
        let registry = ModuleRegistry::builder()
            .register(
                "http.handlers.custom_echo",
                "custom_echo",
                ModuleKind::HttpHandler,
                "Test handler",
            )
            .expect("custom handler registers")
            .register(
                "http.matchers.custom_match",
                "custom_match",
                ModuleKind::HttpMatcher,
                "Test matcher",
            )
            .expect("custom matcher registers")
            .build();

        assert_eq!(registry.len(), builtin_count + 2);
        let handler = registry
            .resolve_handler("custom_echo")
            .expect("custom handler resolves");
        assert_eq!(handler.id, "http.handlers.custom_echo");
        assert_eq!(handler.kind, ModuleKind::HttpHandler);
        assert_eq!(handler.summary, "Test handler");
        assert!(!registry.is_builtin_module("http.handlers.custom_echo"));
        assert!(registry.is_builtin_module("http.handlers.static_response"));
        // Built-ins are still resolvable through the same registry.
        assert!(registry.resolve_handler("static_response").is_some());
        assert!(registry.resolve_matcher("custom_match").is_some());
    }

    #[test]
    fn custom_module_validates_config_and_unknown_still_rejected() {
        let registry = ModuleRegistry::builder()
            .register(
                "http.handlers.custom_echo",
                "custom_echo",
                ModuleKind::HttpHandler,
                "Test handler",
            )
            .expect("registers")
            .build();
        let config = config_with_handler("custom_echo");

        // The custom registry accepts the configuration through both the free function and the
        // convenience method.
        crate::validate::validate_config(&config, &registry).expect("custom handler validates");
        registry
            .validate(&config)
            .expect("convenience method agrees");

        // The built-in registry still rejects the unknown handler with a located error.
        let error = crate::validate::validate_config(&config, &ModuleRegistry::builtin())
            .expect_err("built-in registry must reject the custom handler");
        let message = error.to_string();
        assert!(
            message.contains("unknown HTTP handler module `custom_echo`"),
            "{message}"
        );
        assert!(message.contains("handle[0]"), "{message}");
    }

    #[test]
    fn duplicate_builtin_id_and_key_conflicts_are_rejected() {
        // Re-registering a built-in id is refused even with a different key.
        let error = ModuleRegistry::builder()
            .register(
                "http.handlers.static_response",
                "another_key",
                ModuleKind::HttpHandler,
                "shadow",
            )
            .expect_err("duplicate built-in id");
        assert!(matches!(error, Error::DuplicateModule(_)), "{error}");

        // A different id claiming an existing (kind, key) pair is refused too.
        let error = ModuleRegistry::builder()
            .register(
                "http.handlers.not_static_response",
                "static_response",
                ModuleKind::HttpHandler,
                "shadow",
            )
            .expect_err("duplicate json key");
        match error {
            Error::ModuleKeyConflict {
                existing, incoming, ..
            } => {
                assert_eq!(existing, "http.handlers.static_response");
                assert_eq!(incoming, "http.handlers.not_static_response");
            }
            other => panic!("expected ModuleKeyConflict, got {other}"),
        }

        // The same key under a *different kind* is legal (resolution is per kind).
        ModuleRegistry::builder()
            .register(
                "http.matchers.static_response",
                "static_response",
                ModuleKind::HttpMatcher,
                "matcher with the same short key",
            )
            .expect("different kind may reuse the key");
    }

    #[test]
    fn overlay_does_not_mutate_base_or_default() {
        let base = ModuleRegistry::builtin();
        let base_count = base.len();
        let custom = Module::owned(
            "http.handlers.overlay_only",
            "overlay_only",
            ModuleKind::HttpHandler,
            "overlay",
        );
        let layered = base.overlay([custom]).expect("overlay registers");

        assert_eq!(base.len(), base_count, "base registry is unchanged");
        assert!(base.resolve_handler("overlay_only").is_none());
        assert!(layered.resolve_handler("overlay_only").is_some());
        assert_eq!(layered.len(), base_count + 1);

        // A fresh default registry is untouched as well: registration is per-instance only.
        let fresh_default = ModuleRegistry::builtin();
        assert!(fresh_default.resolve_handler("overlay_only").is_none());
        assert_eq!(fresh_default.len(), base_count);

        // A duplicate in an overlay fails without mutating the source.
        let error = base
            .overlay([Module::owned(
                "http.handlers.static_response",
                "hijack",
                ModuleKind::HttpHandler,
                "hijack",
            )])
            .expect_err("overlay cannot shadow a built-in id");
        assert!(matches!(error, Error::DuplicateModule(_)), "{error}");
        assert_eq!(base.len(), base_count);
    }

    #[test]
    fn invalid_module_definitions_are_rejected() {
        for (id, key) in [
            ("", "key"),
            ("http.handlers.", ""),
            ("http.handlers.bad id", "bad_id"),
            ("http.handlers.bad\tid", "bad_tab"),
            ("http.handlers.bad{id", "bad_braces"),
            ("http.handlers.ok", "bad key"),
            ("http.handlers.ok", "bad/key"),
        ] {
            let error = ModuleRegistry::empty()
                .register_owned(id, key, ModuleKind::HttpHandler, "bad")
                .expect_err("definition must be rejected");
            assert!(
                matches!(error, Error::InvalidModuleDefinition { .. }),
                "id {id:?} key {key:?} produced {error}"
            );
        }
    }

    #[test]
    fn listing_is_deterministic_regardless_of_registration_order() {
        let first = ModuleRegistry::builder()
            .register("http.handlers.zeta", "zeta", ModuleKind::HttpHandler, "z")
            .and_then(|registry| {
                registry.register("http.handlers.alpha", "alpha", ModuleKind::HttpHandler, "a")
            })
            .and_then(|registry| {
                registry.register("http.handlers.beta", "beta", ModuleKind::HttpHandler, "b")
            })
            .expect("registrations")
            .build();
        let second = ModuleRegistry::builder()
            .register("http.handlers.zeta", "zeta", ModuleKind::HttpHandler, "z")
            .and_then(|registry| {
                registry.register("http.handlers.beta", "beta", ModuleKind::HttpHandler, "b")
            })
            .and_then(|registry| {
                registry.register("http.handlers.alpha", "alpha", ModuleKind::HttpHandler, "a")
            })
            .expect("registrations")
            .build();

        let ids: Vec<&str> = first.entries().map(|module| module.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "listing is id-ordered");
        assert_eq!(
            ids,
            second.entries().map(|module| module.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn registry_is_send_sync_and_concurrent_reads_are_safe() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ModuleRegistry>();

        let registry = Arc::new(
            ModuleRegistry::builder()
                .register(
                    "http.handlers.custom_echo",
                    "custom_echo",
                    ModuleKind::HttpHandler,
                    "Test handler",
                )
                .expect("registers")
                .build(),
        );
        let expected_count = registry.len();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let registry = Arc::clone(&registry);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    assert!(registry.resolve_handler("custom_echo").is_some());
                    assert_eq!(registry.len(), expected_count);
                }
                registry
                    .entries()
                    .map(|module| module.id)
                    .collect::<Vec<_>>()
            }));
        }
        let listings: Vec<Vec<&'static str>> = handles
            .into_iter()
            .map(|handle| handle.join().expect("read thread"))
            .collect();
        assert!(listings.iter().all(|listing| listing == &listings[0]));
    }

    #[test]
    fn concurrent_builders_do_not_share_state() {
        let base = Arc::new(ModuleRegistry::builtin());
        let base_count = base.len();
        let mut handles = Vec::new();
        for index in 0..8 {
            let base = Arc::clone(&base);
            handles.push(std::thread::spawn(move || {
                let id: &'static str =
                    Box::leak(format!("http.handlers.plugin_{index}").into_boxed_str());
                let key: &'static str = Box::leak(format!("plugin_{index}").into_boxed_str());
                let registry = base
                    .overlay([Module::new(id, key, ModuleKind::HttpHandler, "plugin")])
                    .expect("overlay");
                assert_eq!(registry.len(), base_count + 1);
                assert!(registry.resolve_handler(key).is_some());
                // Each builder only sees its own addition.
                for other in 0..8 {
                    if other != index {
                        let other_key = format!("plugin_{other}");
                        assert!(registry.resolve_handler(&other_key).is_none());
                    }
                }
                key
            }));
        }
        let keys: Vec<&'static str> = handles
            .into_iter()
            .map(|handle| handle.join().expect("builder thread"))
            .collect();
        assert_eq!(keys.len(), 8);
        // The shared base never changed.
        assert_eq!(base.len(), base_count);
    }
}
