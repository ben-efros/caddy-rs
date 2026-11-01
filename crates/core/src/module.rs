//! Module registry.
//!
//! Caddy's extension model identifies every pluggable component by a dotted module id
//! (`http.handlers.reverse_proxy`) while JSON configuration usually names it by a short key
//! (`reverse_proxy`). This registry models both, and is the single place where "is this module
//! known?" is answered during validation and runtime construction.
//!
//! Built-in modules are statically registered (the Caddy model). Third-party modules are a
//! planned out-of-process/WASM extension mechanism (WS-08); see `docs/ARCHITECTURE.md`.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

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
    /// Construct a module record.
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
}

/// Registry of modules known to this build.
#[derive(Debug, Clone, Default)]
pub struct ModuleRegistry {
    by_id: BTreeMap<&'static str, Module>,
    by_key: BTreeMap<(&'static str, &'static str), &'static str>,
}

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

    /// Register a module. Duplicate ids are an error.
    pub fn register(&mut self, module: Module) -> Result<()> {
        if self.by_id.contains_key(module.id) {
            return Err(Error::DuplicateModule(module.id));
        }
        self.by_key
            .insert((module.kind.label(), module.json_key), module.id);
        self.by_id.insert(module.id, module);
        Ok(())
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

    /// Resolve an On-Demand TLS permission module key (`tls.permission.*`).
    pub fn resolve_tls_permission(&self, json_key: &str) -> Option<&Module> {
        self.get_by_key(ModuleKind::TlsPermission, json_key)
    }

    /// Whether a module id is registered.
    pub fn contains(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    /// All registered modules, ordered by id.
    pub fn modules(&self) -> impl Iterator<Item = &Module> {
        self.by_id.values()
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

/// Modules implemented by this build.
///
/// Keep this table in sync with `list-modules` output and `docs/compatibility/MODULE-PARITY.md`.
/// The module inventory generator compares it against upstream `caddy.RegisterModule` calls.
pub const BUILTIN_MODULES: &[Module] = &[
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
        "Authentication middleware with the HTTP Basic provider (bcrypt/argon2id verification          not implemented)",
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
        "Response compression (config only; runtime is a pass-through)",
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
}
