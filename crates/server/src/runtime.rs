//! The runtime supervisor.
//!
//! The supervisor watches the [`GenerationStore`]. When a new generation becomes active it builds
//! routers, updates the listener map, adds/removes listeners as addresses change, and rebinds the
//! admin API if its address changed. Listeners are never torn down for an unchanged address, so a
//! reload does not create a listening gap.
//!
//! When started by systemd with `LISTEN_FDS` (`LISTEN_PID` matching this process), inherited
//! listening sockets are adopted instead of bound; see [`crate::activation`] for the mapping and
//! mismatch policy. A reload never re-adopts descriptors: sockets are adopted on the first apply,
//! and listeners added later bind normally.

use std::collections::BTreeMap;
#[cfg(feature = "http3")]
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use caddy_rs_admin::inventory::{RuntimeIntrospectionSource, RuntimeInventorySnapshot};
use caddy_rs_admin::{
    AdminApi, CertificateMetrics, LoggingConfig, MetricsRegistry, SharedRequestRecorder,
    UpstreamStatusSource,
};
use caddy_rs_core::{Generation, GenerationStore, HttpServer, ListenAddr, Network};
use caddy_rs_http::RouterBuilder;
use caddy_rs_proxy::{handler_factory_with_status_sink, HealthCheckScheduler, UpstreamStatusSink};
use caddy_rs_tls::{
    build_server_config, build_server_config_with_cert_resolver, listener_uses_tls,
    plan_automatic_https, resolver_from_config, staple_for_certificate, AcmeTlsAlpnResolver,
    AcmeTransport, AutomaticHttpsIssuer, AutomaticHttpsPlan, AutomaticHttpsProvisioner,
    AutomaticHttpsRenewals, CertificateResolver, HyperOcspTransport, HyperTransport,
    NoAcmeTransport, OcspPolicy, OcspStapler, SharedOcspStapler, TlsAlpn01TokenStore,
    TlsServerOptions, DEFAULT_HTTPS_PORT,
};
use tokio::sync::watch;

use crate::activation::{plan_activation, ActivationError, ActivationPlan, SocketActivation};
use crate::auto_https::{PreparedAutomaticHttps, RedirectPolicy};
use crate::error::{Error, Result};
use crate::limits::ServerLimits;
use crate::listeners::{bind, bind_admin, ListenerHandle, ListenerState, SharedListeners};
use crate::observability::{record_certificate_metrics, AccessLogRuntime, ServerAccessLogPolicy};
use crate::proxy_protocol::ListenerWrappers;
use crate::upstream_status::ProxyUpstreamStatusSource;

/// Observable runtime state after an apply.
#[derive(Debug, Clone, Default)]
pub struct RuntimeStatus {
    /// Active configuration generation id.
    pub generation_id: Option<u64>,
    /// Configured listen address to actual bound address (`:0` resolves here).
    pub listeners: BTreeMap<String, String>,
    /// Admin API bound address, if enabled.
    pub admin: Option<String>,
}

impl RuntimeStatus {
    /// Find the actual bound address for a configured listen string.
    pub fn listener_address(&self, configured: &str) -> Option<&str> {
        self.listeners.get(configured).map(String::as_str)
    }
}

/// Caddy's shutdown timing configuration (`apps.http.grace_period` / `shutdown_delay`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ShutdownTiming {
    /// Time to keep serving after a shutdown is requested, before initiating the grace period.
    shutdown_delay: Option<Duration>,
    /// Maximum time to wait for active ordinary connections after shutdown is initiated.
    ///
    /// `None` (absent or zero in the configuration) is Caddy's **eternal grace period**: the
    /// server waits indefinitely for in-flight requests and idle connection shutdowns. Hijacked
    /// connections (WebSockets/extended CONNECT) are excluded, matching Go's
    /// `http.Server.Shutdown`, which neither closes nor waits for them.
    grace_period: Option<Duration>,
}

impl ShutdownTiming {
    fn from_config(config: &caddy_rs_core::Config) -> Self {
        let http = config.http();
        Self {
            shutdown_delay: http
                .and_then(|http| http.shutdown_delay)
                .map(caddy_rs_core::CaddyDuration::as_duration)
                .filter(|duration| !duration.is_zero()),
            grace_period: http
                .and_then(|http| http.grace_period)
                .map(caddy_rs_core::CaddyDuration::as_duration)
                .filter(|duration| !duration.is_zero()),
        }
    }
}

/// A TLS listener without any certificate must fail the apply rather than serve cleartext or
/// complete no handshakes.
fn missing_certificates_error(listen: &str, server_name: &str, https_port: u16) -> Error {
    Error::Config(caddy_rs_core::Error::invalid(
        "apps.tls.certificates",
        format!(
            "listener `{listen}` for server `{server_name}` terminates TLS (HTTPS port \
             {https_port} or `tls_connection_policies`) but no certificates are configured; set \
             `apps.tls.certificates.load_pem`/`load_files` or enable automatic HTTPS with \
             `apps.tls.automation`"
        ),
    ))
}

/// Whether a server's `strict_sni_host` setting asks for strict SNI enforcement.
///
/// Caddy accepts either a boolean or an object with `enabled`; both spellings are recognised so a
/// configuration that depends on strict SNI fails loudly instead of being served with the default
/// certificate.
fn strict_sni_host_enabled(value: Option<&serde_json::Value>) -> bool {
    match value {
        None => false,
        Some(serde_json::Value::Bool(enabled)) => *enabled,
        Some(serde_json::Value::Object(object)) => object
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        Some(_) => true,
    }
}

/// Automatic-HTTPS work split across two apply phases.
///
/// Listeners must already be accepting connections before the ACME CA can validate an HTTP-01 or
/// TLS-ALPN-01 challenge, but the final TLS configuration needs the certificate that provisioning
/// obtains. The runtime therefore creates the issuer (and captures its TLS-ALPN token store) first,
/// binds challenge-capable listeners, provisions, and only then installs the final resolver.
struct PendingAutomaticHttps {
    plan: AutomaticHttpsPlan,
    provisioner: AutomaticHttpsProvisioner,
    base_resolver: Option<CertificateResolver>,
    serving: Arc<crate::auto_https::AutomaticHttpsServing>,
    /// Shared challenge-certificate store handed to the TLS listeners in both phases.
    tls_alpn01_tokens: Arc<TlsAlpn01TokenStore>,
    /// Shared OCSP stapler (cache survives generations; see T-TLS-081).
    ocsp_stapler: Option<SharedOcspStapler>,
}

impl PendingAutomaticHttps {
    /// Run certificate acquisition. The CA connects back to the listeners bound in the bootstrap
    /// phase, so this must only be called after they are accepting connections.
    async fn provision(self) -> Result<PreparedAutomaticHttps> {
        let tokens = Arc::clone(&self.tls_alpn01_tokens);
        let plan = self.plan;
        let provisioned = self
            .provisioner
            .provision(&plan, self.base_resolver)
            .await?;
        let resolver = provisioned.resolver;
        let mut ocsp_refresh = None;
        if let Some(stapler) = &self.ocsp_stapler {
            apply_ocsp_staples(&resolver, &plan, stapler).await;
            let task = spawn_ocsp_refresh(Arc::clone(&resolver), plan.clone(), Arc::clone(stapler));
            ocsp_refresh = Some(task);
        }
        Ok(PreparedAutomaticHttps {
            resolver,
            plan,
            serving: self.serving,
            tls_alpn01_tokens: tokens,
            renewals: provisioned.renewals,
            ocsp_refresh,
        })
    }
}

/// TLS material for one listener-state build.
struct AutomaticHttpsContext<'a> {
    /// Resolver for normal SNI. During the bootstrap phase this is the manual (configured)
    /// resolver or an empty resolver; in the final phase it is the provisioned resolver.
    resolver: Option<Arc<CertificateResolver>>,
    /// TLS-ALPN-01 challenge certificates to overlay on `acme-tls/1` handshakes.
    tokens: &'a Arc<TlsAlpn01TokenStore>,
    /// Pre-routing state for cleartext listeners (HTTP-01, redirects).
    serving: &'a Arc<crate::auto_https::AutomaticHttpsServing>,
    /// Listener ports the plan terminates TLS on (includes implicitly-HTTPS non-standard ports).
    tls_ports: &'a [u16],
    /// Configured HTTP port. Caddy never terminates TLS on it, even when the server carries
    /// explicit TLS connection policies (`modules/caddyhttp/app.go`:
    /// `useTLS := len(TLSConnPolicies) > 0 && port != http_port`).
    http_port: u16,
    /// Derived HTTP listener address from the plan, when the configuration needs one.
    http_listener: Option<String>,
    /// Whether this is the pre-provisioning build (allows a missing certificate resolver so the
    /// listener can start and answer acme-tls/1 challenges).
    bootstrap: bool,
}

/// Owns listeners and drives configuration generations.
pub struct ServerRuntime {
    store: Arc<GenerationStore>,
    reload: Arc<tokio::sync::Notify>,
    /// Injected ACME transport for automatic HTTPS (tests and embedders); production builds a
    /// [`HyperTransport`] when certificates must be obtained.
    acme_transport: Option<Arc<dyn AcmeTransport>>,
    /// Caddy data directory override for account/certificate storage (defaults to the configured
    /// `storage` root, then `.caddy-rs`).
    data_root: Option<std::path::PathBuf>,
    /// HTTP-01 tokens shared between the ACME issuer and the HTTP listeners.
    challenge_tokens: Arc<caddy_rs_tls::Http01TokenStore>,
    /// Per-listen-address serving state (router + limits), shared with accept loops.
    states: SharedListeners,
    listeners: BTreeMap<String, ListenerHandle>,
    admin: Option<ListenerHandle>,
    admin_api: AdminApi,
    status: RuntimeStatus,
    /// Socket-activation resolution state; resolved once on the first apply.
    activation: ActivationState,
    /// Generation-scoped active health-check schedulers, one vector per generation that
    /// configured `reverse_proxy.health_checks.active`. Health checks start only after the
    /// generation is serving and are stopped when the generation is replaced or the runtime stops,
    /// so no checker task can leak across reloads.
    health_schedulers: BTreeMap<u64, Vec<HealthCheckScheduler>>,
    /// Generation-scoped certificate renewal schedulers.
    ///
    /// Each successfully applied generation that manages certificates owns one scheduler, keyed by
    /// generation id. Keeping the value alive keeps renewals running; the runtime stops and drops
    /// the previous generation's scheduler after a successful reload and stops every scheduler on
    /// shutdown (`/stop`, no active generation, or process shutdown).
    renewals: BTreeMap<u64, AutomaticHttpsRenewals>,
    /// Shared OCSP stapler across generations (cache/retry state survives reloads).
    ocsp_stapler: Option<SharedOcspStapler>,
    /// Generation-scoped OCSP refresh schedulers; aborting the task stops the scan.
    ocsp_refreshes: BTreeMap<u64, OcspRefresh>,
    /// In-memory certificate store of the active generation.
    ///
    /// Handed to the next generation's provisioner so a reload can seed its resolver from the
    /// still-running certificates instead of re-issuing them (`T-TLS-065`, DIV-0064). Kept separate
    /// from `renewals` because the store must outlive a failed apply: a failed generation must not
    /// clear it.
    certificate_store: Option<Arc<caddy_rs_tls::SharedCertificateStore>>,
    /// Shared metrics recorder handed to every listener; renders through the admin `/metrics`
    /// endpoint because it shares the admin API's registry.
    recorder: SharedRequestRecorder,
    /// Certificate expiry/renewal metrics handle (same registry).
    certificate_metrics: CertificateMetrics,
    /// Access-log sinks for the active generation (`None` when access logging is not configured).
    access_log: Option<Arc<AccessLogRuntime>>,
    /// Generation id the current access-log sinks were built for.
    access_log_generation: Option<u64>,
    /// Number of renewal-scheduler history entries already exported as metrics, per generation.
    renewal_metrics_seen: BTreeMap<u64, usize>,
    /// Shutdown timing of the last active generation (`apps.http.grace_period`/`shutdown_delay`).
    shutdown_timing: ShutdownTiming,
    /// Live reverse-proxy upstream counters for `GET /reverse_proxy/upstreams`; the active
    /// generation's sink is swapped only after a successful apply.
    upstream_status: Arc<ProxyUpstreamStatusSource>,
    /// Last completed runtime-inventory snapshot for the `GET /runtime/inventory` extension
    /// (T-ADMIN-023). Refreshed after a successful apply and cleared on shutdown; the admin API
    /// copies it and marks a mismatch with the active generation as stale.
    inventory: Arc<crate::inventory::RuntimeInventorySource>,
}

/// How inherited systemd sockets are discovered for this runtime.
enum ActivationState {
    /// Read `LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES` on the first apply (the default).
    Environment,
    /// Descriptors injected by an embedder or test; consumed on the first apply.
    Injected(Option<SocketActivation>),
    /// Resolved mapping; entries are consumed as listeners adopt them.
    Planned(ActivationPlan),
    /// No socket activation for this runtime.
    Inactive,
    /// Resolution failed; every apply repeats the same located error.
    Failed { path: String, message: String },
}

/// Build the CA-pool loading context for client authentication.
///
/// `apps.pki.certificate_authorities` ids map to `<data-dir>/pki/authorities/<id>` (the layout the
/// runtime provisions), and `storage` pool sources read from the configured file-system root.
fn client_auth_ca_pool_context(
    config: &caddy_rs_core::Config,
    data_root: Option<&std::path::Path>,
) -> caddy_rs_tls::client_auth::CaPoolContext {
    let mut context = caddy_rs_tls::client_auth::CaPoolContext::new();
    let default_root = data_root.map(std::path::Path::to_path_buf);
    if let Some(root) = config
        .storage()
        .and_then(|storage| storage.root())
        .map(std::path::PathBuf::from)
        .or_else(|| default_root.clone())
    {
        context.storage_root = Some(root.clone());
        let mut declares_authorities = false;
        if let Some(pki) = config.apps.as_ref().and_then(|apps| apps.pki.as_ref()) {
            if let Some(authorities) = pki.certificate_authorities.as_ref() {
                declares_authorities = !authorities.is_empty();
                for id in authorities.keys() {
                    context
                        .pki_authorities
                        .insert(id.clone(), root.join("pki").join("authorities").join(id));
                }
            }
        }
        // Caddy provisions a default `local` authority whenever `certificate_authorities` is empty
        // (`modules/caddypki/pki.go`: `ProvisionDefaultCA` runs only when no CA is configured), so a
        // client-auth pool may reference `local` without declaring `apps.pki` at all. Resolve the
        // same on-disk location here; the loader still fails loudly when the material is absent.
        if !declares_authorities {
            context
                .pki_authorities
                .entry("local".to_string())
                .or_insert_with(|| root.join("pki").join("authorities").join("local"));
        }
    }
    context
}

impl ServerRuntime {
    /// Create a runtime for a generation store.
    pub fn new(store: Arc<GenerationStore>) -> Self {
        let reload = Arc::new(tokio::sync::Notify::new());
        let upstream_status = ProxyUpstreamStatusSource::new();
        let inventory = crate::inventory::RuntimeInventorySource::new();
        let admin_api = AdminApi::new(Arc::clone(&store))
            .with_reload_notify(Arc::clone(&reload))
            .with_upstream_status_source(
                Arc::clone(&upstream_status) as Arc<dyn UpstreamStatusSource>
            )
            .with_runtime_introspection_source(
                Arc::clone(&inventory) as Arc<dyn RuntimeIntrospectionSource>
            );
        let recorder = admin_api.request_recorder();
        let certificate_metrics = admin_api.certificate_metrics();
        Self {
            store,
            reload,
            acme_transport: None,
            data_root: None,
            challenge_tokens: Arc::new(caddy_rs_tls::Http01TokenStore::new()),
            states: SharedListeners::new(RwLock::new(std::collections::HashMap::new())),
            listeners: BTreeMap::new(),
            admin: None,
            admin_api,
            status: RuntimeStatus::default(),
            activation: ActivationState::Environment,
            health_schedulers: BTreeMap::new(),
            renewals: BTreeMap::new(),
            ocsp_stapler: None,
            ocsp_refreshes: BTreeMap::new(),
            certificate_store: None,
            recorder,
            certificate_metrics,
            access_log: None,
            access_log_generation: None,
            renewal_metrics_seen: BTreeMap::new(),
            shutdown_timing: ShutdownTiming::default(),
            upstream_status,
            inventory,
        }
    }

    /// Adopt the given inherited listening sockets instead of reading the process environment.
    ///
    /// Takes ownership of the descriptors (closing any that remain unclaimed when the runtime is
    /// dropped) and must be called before the first [`ServerRuntime::apply`]; intended for
    /// embedders and tests that need to inject systemd-style activation. If any inherited socket is
    /// not claimed by a configured listener the first apply fails with a located error.
    pub fn with_socket_activation(mut self, activation: SocketActivation) -> Self {
        self.activation = ActivationState::Injected(Some(activation));
        self
    }

    /// Inject the ACME HTTP transport used for automatic-HTTPS certificate acquisition.
    ///
    /// Tests inject a fake local CA; production leaves this unset so a [`HyperTransport`] (platform
    /// trust store) is created only when certificates actually need to be obtained.
    pub fn with_acme_transport(mut self, transport: Arc<dyn AcmeTransport>) -> Self {
        self.acme_transport = Some(transport);
        self
    }

    /// Override the Caddy data directory used for account and certificate storage.
    pub fn with_data_root(mut self, root: impl Into<std::path::PathBuf>) -> Self {
        self.data_root = Some(root.into());
        self
    }

    /// The HTTP-01 token store shared with the ACME issuer (tests seed tokens directly).
    pub fn challenge_tokens(&self) -> Arc<caddy_rs_tls::Http01TokenStore> {
        Arc::clone(&self.challenge_tokens)
    }

    /// The generation store driving this runtime.
    pub fn store(&self) -> &Arc<GenerationStore> {
        &self.store
    }

    /// Current status.
    pub fn status(&self) -> &RuntimeStatus {
        &self.status
    }

    /// A handle to the metrics registry rendered by the admin `/metrics` endpoint.
    pub fn metrics(&self) -> MetricsRegistry {
        self.admin_api.metrics()
    }

    /// A clone of the shared request recorder used by every listener.
    pub fn request_recorder(&self) -> SharedRequestRecorder {
        Arc::clone(&self.recorder)
    }

    /// Number of access-log sinks built for the active generation (0 when access logging is off).
    pub fn access_log_sink_count(&self) -> usize {
        self.access_log
            .as_ref()
            .map_or(0, |access| access.sink_count())
    }

    /// Provision-equivalent validation of the active generation, without binding listeners.
    ///
    /// Caddy's `caddy validate` *provisions* the apps, so handler/matcher modules, listener
    /// wrappers, server limits and routers are constructed before it reports success. caddy-rs
    /// used to validate only the typed configuration model, so a configuration whose modules
    /// cannot be built (for example an unsupported `expression` matcher subset or a
    /// `proxy_protocol` allow-list entry that is not a CIDR) incorrectly validated and failed
    /// only at `run`. This walks every HTTP server and builds the same router, limits,
    /// listener-wrapper plan and TLS policy as [`Self::apply`] without resolving certificates or
    /// binding sockets, so a configuration that terminates TLS without certificates still
    /// validates (Caddy obtains certificates at start, not at provision time).
    pub fn validate_provisioning(&self) -> Result<()> {
        let Some(generation) = self.store.current() else {
            return Ok(());
        };
        // Access-log sinks are provisioned by Caddy too: an unsupported writer/encoder must fail
        // validation, not the first request.
        let _access_log = self.access_log_for(&generation)?;
        let Some(http) = generation.config().http() else {
            return Ok(());
        };
        let https_port = http.https_port.unwrap_or(DEFAULT_HTTPS_PORT);
        let status_sink = UpstreamStatusSink::new();
        for (server_name, server) in &http.servers {
            let _limits = ServerLimits::from_http_server(server_name, server)?;
            let _trusted_proxies = parse_server_trusted_proxies(server, server_name)?;
            let policies = server.tls_connection_policies.as_deref();
            let has_connection_policies = policies.is_some_and(|policies| !policies.is_empty());
            if strict_sni_host_enabled(server.strict_sni_host.as_ref()) {
                return Err(Error::NotImplemented {
                    feature: "`strict_sni_host` TLS handshake rejection",
                    tracking_id: "TLS-STRICT-SNI",
                });
            }
            let _tls_options = TlsServerOptions::from_connection_policies_with_ca_pool(
                policies,
                &client_auth_ca_pool_context(generation.config(), self.data_root.as_deref()),
            )?;
            let _router = Self::build_router(server_name, server, &status_sink)?;
            for listen in &server.listen {
                let parsed = match caddy_rs_core::ListenAddr::parse(listen) {
                    Ok(parsed) => parsed,
                    Err(reason) => {
                        return Err(Error::Config(caddy_rs_core::Error::invalid(
                            format!("apps.http.servers.{server_name}.listen"),
                            format!("invalid listen address `{listen}`: {reason}"),
                        )))
                    }
                };
                validate_udp_listener(
                    listen,
                    server_name,
                    server,
                    https_port,
                    has_connection_policies,
                )?;
                // Validate the listener's implied TLS policy without requiring certificates.
                #[cfg(feature = "http3")]
                let _terminates_tls = if parsed.network == Network::Udp {
                    udp_listener_terminates_tls(listen, https_port, has_connection_policies)
                } else {
                    listener_uses_tls(listen, https_port, has_connection_policies)?
                };
                // UDP listeners were rejected above: a build without HTTP/3 validates the
                // TCP/Unix listeners only.
                #[cfg(not(feature = "http3"))]
                let _terminates_tls = {
                    // The parse above already rejected a malformed address; UDP is rejected by
                    // `validate_udp_listener`, so only TCP/Unix semantics remain here.
                    let _ = parsed.network;
                    listener_uses_tls(listen, https_port, has_connection_policies)?
                };
            }
            let _wrappers = ListenerWrappers::from_server(server)?;
        }
        Ok(())
    }

    /// Build and install the access-log sinks for one generation (flushing the old ones).
    fn access_log_for(&self, generation: &Generation) -> Result<Option<Arc<AccessLogRuntime>>> {
        if self.access_log_generation == Some(generation.id()) {
            return Ok(self.access_log.clone());
        }
        let config = generation.config();
        if config.logging.is_none() {
            // Access logging is opt-in: the implicit Caddy default sink is not opened for a
            // configuration that does not mention logging at all.
            return Ok(None);
        }
        let logging = LoggingConfig::from_config(config)?;
        Ok(AccessLogRuntime::build(Some(&logging))?)
    }

    /// Swap in the generation's access-log sinks, flushing (and logically closing) the old ones.
    ///
    /// The old sinks are closed when their last `Arc` drops; listener states hold references, so an
    /// in-flight request that started under the old generation still emits its entry, then closes.
    fn install_access_log(&mut self, generation_id: u64, access: Option<Arc<AccessLogRuntime>>) {
        if self.access_log_generation == Some(generation_id) {
            return;
        }
        if let Some(old) = self.access_log.take() {
            old.flush();
            drop(old);
        }
        self.access_log = access;
        self.access_log_generation = Some(generation_id);
    }

    /// Export certificate expiry gauges and new renewal outcomes for the active generation.
    fn record_certificate_metrics(&mut self, generation: &Generation) {
        let Some(renewals) = self.renewals.get(&generation.id()) else {
            return;
        };
        let mut seen = self
            .renewal_metrics_seen
            .get(&generation.id())
            .copied()
            .unwrap_or(0);
        record_certificate_metrics(
            &self.certificate_metrics,
            renewals,
            std::time::SystemTime::now(),
            &mut seen,
        );
        self.renewal_metrics_seen.insert(generation.id(), seen);
    }

    /// Reconcile listeners and routers with the active generation.
    ///
    /// When automatic HTTPS is active the apply is two-phase because ACME challenges require live
    /// listeners:
    ///
    /// 1. derive the automation plan and create the issuer/provisioner (no network);
    /// 2. build and publish "bootstrap" listener states whose TLS listeners advertise `acme-tls/1`
    ///    with the challenge-certificate resolver overlay, and whose cleartext listeners answer
    ///    HTTP-01 and redirects;
    /// 3. bind/start every configured listener;
    /// 4. provision certificates (the CA connects back to the now-running listeners);
    /// 5. rebuild the states with the provisioned resolver and publish them.
    ///
    /// A failure after step 2 restores the previous generation's states and stops newly bound
    /// listeners, so a failed issuance keeps the old generation serving.
    pub async fn apply(&mut self) -> Result<RuntimeStatus> {
        let Some(generation) = self.store.current() else {
            self.stop_all().await;
            self.status = RuntimeStatus::default();
            return Ok(self.status.clone());
        };
        // Access-log sinks belong to the active generation: build them before touching listeners
        // so an invalid logging configuration fails the apply loudly and leaves the previous
        // generation serving.
        let access_log = self.access_log_for(&generation)?;
        let access = match &access_log {
            Some(access) => Arc::clone(access),
            None => AccessLogRuntime::disabled(),
        };
        let pending = self.prepare_automatic_https(&generation)?;
        // A fresh sink per generation: handlers built by the router factories register here, and
        // it becomes the admin source only after the generation is serving.
        let status_sink = UpstreamStatusSink::new();
        let mut newly_bound: Vec<String> = Vec::new();

        // Without automatic HTTPS there is nothing to provision: the original single-phase path.
        let Some(pending) = pending else {
            let states = self.build_listener_states(&generation, None, &access, &status_sink)?;
            self.resolve_activation(&states)?;
            self.publish_states(&states);
            if let Err(error) = self.start_new_listeners(&states, &mut newly_bound).await {
                self.stop_listener_keys(&newly_bound).await;
                return Err(error);
            }
            self.remove_unconfigured_listeners(&states).await;
            self.reconcile_admin(&generation).await?;
            // A generation without automatic HTTPS has no renewal schedulers; retire any left by
            // an earlier automatic-HTTPS generation before publishing the new status.
            self.retire_stale_ocsp_refreshes(generation.id());
            self.retire_stale_renewals(generation.id()).await;
            self.install_access_log(generation.id(), access_log);
            self.record_certificate_metrics(&generation);
            self.upstream_status.install(Arc::clone(&status_sink));
            let health_schedulers = status_sink.spawn_health_checks();
            self.install_health_schedulers(generation.id(), health_schedulers)
                .await;
            let status = self.finish_apply(&generation);
            self.refresh_inventory();
            return Ok(status);
        };
        // Snapshot for rollback: a failed provisioning pass must leave the previous generation's
        // listener states untouched.
        let previous_states = self
            .states
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        // Phase 1: challenge-capable states, then start the listeners before provisioning.
        let bootstrap =
            self.build_bootstrap_states(&generation, &pending, &access, &status_sink)?;
        self.resolve_activation(&bootstrap)?;
        self.publish_states(&bootstrap);
        if let Err(error) = self.start_new_listeners(&bootstrap, &mut newly_bound).await {
            self.rollback_states(&previous_states, &newly_bound).await;
            return Err(error);
        }

        // Phase 2: provision certificates; the CA can now reach the listeners for HTTP-01 /
        // TLS-ALPN-01 validation.
        let prepared = match pending.provision().await {
            Ok(prepared) => prepared,
            Err(error) => {
                self.rollback_states(&previous_states, &newly_bound).await;
                return Err(error);
            }
        };

        // Phase 3: install the final states (provisioned resolver, `acme-tls/1` retained so
        // renewals can answer challenges on the same listeners).
        let PreparedAutomaticHttps {
            resolver,
            plan,
            serving,
            tls_alpn01_tokens,
            renewals,
            ocsp_refresh,
        } = prepared;
        let context = AutomaticHttpsContext {
            resolver: Some(Arc::clone(&resolver)),
            tokens: &tls_alpn01_tokens,
            serving: &serving,
            tls_ports: &plan.tls_ports,
            http_port: plan.http_port,
            http_listener: plan.http_listener(),
            bootstrap: false,
        };
        let states =
            match self.build_listener_states(&generation, Some(&context), &access, &status_sink) {
                Ok(states) => states,
                Err(error) => {
                    self.rollback_states(&previous_states, &newly_bound).await;
                    return Err(error);
                }
            };
        self.publish_states(&states);
        if let Err(error) = self.start_new_listeners(&states, &mut newly_bound).await {
            self.rollback_states(&previous_states, &newly_bound).await;
            return Err(error);
        }
        self.remove_unconfigured_listeners(&states).await;
        self.reconcile_admin(&generation).await?;

        // Adopt the new generation's renewal scheduler only after every fallible step succeeded: a
        // failure above drops `renewals`, which aborts the just-started scheduler and leaves the
        // previous generation's scheduler untouched.
        if let Some(renewals) = renewals {
            // Retain the generation's certificate store so the next generation can seed its
            // resolver from it (DIV-0064); the scheduler keeps owning the same Arc.
            self.certificate_store = Some(Arc::clone(renewals.store()));
            self.renewals.insert(generation.id(), renewals);
        }
        if let Some(refresh) = ocsp_refresh {
            self.ocsp_refreshes.insert(generation.id(), refresh);
        }
        self.retire_stale_ocsp_refreshes(generation.id());
        self.retire_stale_renewals(generation.id()).await;
        self.install_access_log(generation.id(), access_log);
        self.record_certificate_metrics(&generation);
        self.upstream_status.install(Arc::clone(&status_sink));
        let health_schedulers = status_sink.spawn_health_checks();
        self.install_health_schedulers(generation.id(), health_schedulers)
            .await;
        let status = self.finish_apply(&generation);
        self.refresh_inventory();
        Ok(status)
    }

    /// Adopt the active health-check schedulers of a successfully applied generation and stop the
    /// previous generation's checkers.
    async fn install_health_schedulers(
        &mut self,
        generation_id: u64,
        schedulers: Vec<HealthCheckScheduler>,
    ) {
        if !schedulers.is_empty() {
            self.health_schedulers.insert(generation_id, schedulers);
        }
        self.retire_stale_health_schedulers(generation_id).await;
    }

    /// Stop and drop health-check schedulers owned by generations other than
    /// `active_generation`.
    ///
    /// Called only after a successful apply, so a failed reload keeps the previous generation's
    /// checkers running (the previous upstreams are still the ones serving traffic).
    async fn retire_stale_health_schedulers(&mut self, active_generation: u64) {
        let stale: Vec<u64> = self
            .health_schedulers
            .keys()
            .copied()
            .filter(|generation| *generation != active_generation)
            .collect();
        for generation in stale {
            if let Some(schedulers) = self.health_schedulers.remove(&generation) {
                if !schedulers.is_empty() {
                    tracing::info!(
                        generation,
                        checkers = schedulers.len(),
                        "stopping active health-check schedulers for retired generation"
                    );
                }
                for scheduler in schedulers {
                    scheduler.shutdown().await;
                }
            }
        }
    }

    /// Number of live generation-scoped active health-check schedulers.
    ///
    /// Exposed for runtime tests (the Caddy admin endpoint does not expose health state; see
    /// DIV-0026).
    pub fn health_scheduler_count(&self) -> usize {
        self.health_schedulers.values().map(Vec::len).sum()
    }

    /// Generations that own at least one active health-check scheduler (for runtime tests).
    pub fn health_scheduler_generations(&self) -> Vec<u64> {
        self.health_schedulers.keys().copied().collect()
    }

    /// Stop and drop the renewal schedulers owned by generations other than `active_generation`.
    ///
    /// Called after a successful atomic swap and when a configuration without automatic HTTPS
    /// replaces one that had it, so a retired generation never keeps a renewal task alive.
    async fn retire_stale_renewals(&mut self, active_generation: u64) {
        let stale: Vec<u64> = self
            .renewals
            .keys()
            .copied()
            .filter(|generation| *generation != active_generation)
            .collect();
        for generation in stale {
            if let Some(renewals) = self.renewals.remove(&generation) {
                self.renewal_metrics_seen.remove(&generation);
                tracing::info!(
                    generation,
                    "stopping certificate renewal scheduler for retired generation"
                );
                renewals.stop().await;
            }
        }
    }

    /// Abort refresh tasks owned by generations other than `active_generation`.
    fn retire_stale_ocsp_refreshes(&mut self, active_generation: u64) {
        let stale: Vec<u64> = self
            .ocsp_refreshes
            .keys()
            .copied()
            .filter(|generation| *generation != active_generation)
            .collect();
        for generation in stale {
            if self.ocsp_refreshes.remove(&generation).is_some() {
                tracing::info!(
                    generation,
                    "stopping OCSP refresh scheduler for retired generation"
                );
            }
        }
    }

    /// Generation ids that currently own a renewal scheduler.
    pub fn renewal_scheduler_generations(&self) -> Vec<u64> {
        self.renewals.keys().copied().collect()
    }

    /// Number of generation-scoped certificate renewal schedulers owned by the runtime.
    pub fn renewal_scheduler_count(&self) -> usize {
        self.renewals.len()
    }

    /// The renewal scheduler owned by one generation, when it manages certificates.
    ///
    /// This is the handle the generation keeps alive; it is returned for diagnostics and tests.
    pub fn renewal_scheduler(&self, generation_id: u64) -> Option<&AutomaticHttpsRenewals> {
        self.renewals.get(&generation_id)
    }

    /// Whether any owned renewal scheduler's background task is currently running.
    pub fn has_running_renewal_schedulers(&self) -> bool {
        self.renewals
            .values()
            .any(caddy_rs_tls::AutomaticHttpsRenewals::is_running)
    }

    /// Replace the shared listener-state map.
    fn publish_states(&self, states: &std::collections::HashMap<String, Arc<ListenerState>>) {
        let mut shared = self
            .states
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *shared = states.clone();
    }

    /// Bind and start every configured listener that is not running yet.
    ///
    /// Listen addresses are processed in sorted order so socket-activation claims are deterministic.
    async fn start_new_listeners(
        &mut self,
        states: &std::collections::HashMap<String, Arc<ListenerState>>,
        newly_bound: &mut Vec<String>,
    ) -> Result<()> {
        let mut listens: Vec<&String> = states.keys().collect();
        listens.sort();
        for listen in listens {
            if self.listeners.contains_key(listen) {
                continue;
            }
            let inherited = match &mut self.activation {
                ActivationState::Planned(plan) => plan.claim(listen),
                _ => None,
            };
            if inherited.is_none() {
                if let ActivationState::Planned(plan) = &self.activation {
                    if plan.inherited() > 0 {
                        tracing::info!(
                            listen,
                            "no inherited socket matched this listener; binding normally"
                        );
                    }
                }
            }
            let handle = bind(
                listen,
                Arc::clone(&self.states),
                Arc::clone(&self.store),
                inherited,
            )
            .await?;
            tracing::info!(listen, bound = %handle.bound, "listening");
            self.listeners.insert(listen.clone(), handle);
            newly_bound.push(listen.clone());
        }
        // Once every inherited socket has been adopted the remaining applies bind normally.
        if let ActivationState::Planned(plan) = &self.activation {
            if !plan.has_claims() {
                self.activation = ActivationState::Inactive;
            }
        }
        Ok(())
    }

    /// Stop listeners whose address is no longer configured.
    ///
    /// Caddy's `App.stop` treats listeners that are closing during a reload like a shutdown: it
    /// honors `shutdown_delay` (sleeping while the old listener keeps accepting, so a load
    /// balancer can drain it) and enforces the grace period with a timeout context
    /// (`modules/caddyhttp/app.go` "listener closing and shutdown delay is configured" and the
    /// grace-period context). A reload does not block on the grace period, but the closing
    /// listener's connections must still be force-closed when it expires.
    async fn remove_unconfigured_listeners(
        &mut self,
        states: &std::collections::HashMap<String, Arc<ListenerState>>,
    ) {
        let removed: Vec<String> = self
            .listeners
            .keys()
            .filter(|listen| !states.contains_key(*listen))
            .cloned()
            .collect();
        if removed.is_empty() {
            return;
        }
        let timing = self.shutdown_timing;
        if let Some(delay) = timing.shutdown_delay {
            tracing::info!(
                delay_ms = delay.as_millis() as u64,
                listeners = removed.len(),
                "listeners are closing and shutdown_delay is configured; keeping them open"
            );
            tokio::time::sleep(delay).await;
        }
        for listen in removed {
            if let Some(handle) = self.listeners.remove(&listen) {
                tracing::info!(%listen, "closing listener");
                handle.begin_graceful();
                if let Some(grace) = timing.grace_period {
                    // Bound the drain like Caddy's grace-period context: force-close the closing
                    // listener's connections when the grace period expires. The reload itself does
                    // not wait for them (Caddy only waits when the process is exiting).
                    let force = handle.force.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(grace).await;
                        let _ = force.send(true);
                    });
                }
                handle.stop().await;
            }
        }
    }

    /// Stop the listeners bound during the current (failed) apply.
    async fn stop_listener_keys(&mut self, keys: &[String]) {
        for key in keys {
            if let Some(handle) = self.listeners.remove(key) {
                handle.stop().await;
            }
        }
    }

    /// Restore the previous generation's listener states and stop listeners added by this apply.
    async fn rollback_states(
        &mut self,
        previous: &std::collections::HashMap<String, Arc<ListenerState>>,
        newly_bound: &[String],
    ) {
        self.publish_states(previous);
        self.stop_listener_keys(newly_bound).await;
    }

    /// Reconcile the admin listener with the active generation.
    async fn reconcile_admin(&mut self, generation: &Generation) -> Result<()> {
        let admin_config = generation.config().admin.clone().unwrap_or_default();
        let desired_admin = if admin_config.disabled {
            None
        } else {
            Some(admin_config.listen_addr().to_string())
        };
        let current_admin = self.admin.as_ref().map(|handle| handle.bound.clone());
        if desired_admin != current_admin {
            if let Some(handle) = self.admin.take() {
                handle.stop().await;
            }
            if let Some(listen) = &desired_admin {
                let handle = bind_admin(listen, self.admin_api.clone()).await?;
                tracing::info!(listen, bound = %handle.bound, "admin API listening");
                self.admin = Some(handle);
            }
        }
        Ok(())
    }

    /// Record the applied generation in the observable status.
    /// Rebuild and install the runtime-inventory snapshot after a successful apply.
    ///
    /// The snapshot is copied from runtime state into the shared source; the admin endpoint only
    /// reads that copy, so a later reload cannot race the JSON rendering.
    fn refresh_inventory(&mut self) {
        let (configured_admin, listeners, certificates) = match self.store.current() {
            Some(generation) => {
                let config = generation.config();
                let configured_admin = config
                    .admin
                    .as_ref()
                    .map(|admin| admin.listen_addr().to_string());
                let listeners =
                    crate::inventory::listener_inventory(config, &self.status.listeners);
                let managed: Vec<Arc<caddy_rs_tls::Certificate>> = self
                    .renewals
                    .values()
                    .flat_map(|renewals| renewals.managed_certificates())
                    .collect();
                let certificates = crate::inventory::certificate_inventory(config, &managed);
                (configured_admin, listeners, certificates)
            }
            None => (None, Vec::new(), Vec::new()),
        };
        let admin = crate::inventory::admin_inventory(
            configured_admin,
            self.admin.as_ref().map(|handle| handle.bound.clone()),
        );
        let health_checks = crate::inventory::health_check_inventory(self.health_schedulers.iter());
        self.inventory.install(RuntimeInventorySnapshot {
            generation_id: self.status.generation_id,
            admin,
            listeners,
            certificates,
            health_checks,
        });
    }

    fn finish_apply(&mut self, generation: &Generation) -> RuntimeStatus {
        self.status = RuntimeStatus {
            generation_id: Some(generation.id()),
            listeners: self
                .listeners
                .iter()
                .map(|(configured, handle)| (configured.clone(), handle.bound.clone()))
                .collect(),
            admin: self.admin.as_ref().map(|handle| handle.bound.clone()),
        };
        self.status.clone()
    }

    /// The actual bound address for a configured listen string.
    pub fn listener_address(&self, configured: &str) -> Option<SocketAddr> {
        self.listeners
            .get(configured)
            .and_then(|handle| handle.socket_addr)
    }

    /// The admin API's actual bound address.
    pub fn admin_address(&self) -> Option<SocketAddr> {
        self.admin.as_ref().and_then(|handle| handle.socket_addr)
    }

    /// Serve until `shutdown` becomes true or the configuration is stopped, reconciling
    /// configuration as it changes.
    ///
    /// Caddy's `POST /stop` unloads the configuration *and exits the process*; the same is true
    /// for any external [`GenerationStore::stop`] call. The supervisor therefore ends its loop
    /// once a configuration that was active has been removed from the store (after stopping the
    /// listeners and the admin endpoint), for every adapter and for automatic-HTTPS generations.
    /// Without this, `run` would idle forever with no listeners and the CLI process would never
    /// exit, which was the real-Caddy-oracle `admin-stop#stop` finding.
    pub async fn run(self, shutdown: watch::Receiver<bool>) -> Result<()> {
        self.run_loop(shutdown, None).await
    }

    /// Serve until `shutdown` becomes true, with a second [`force`](Self::run_with_force) signal
    /// that skips the configured grace period and closes connections immediately.
    pub async fn run_with_force(
        self,
        shutdown: watch::Receiver<bool>,
        force: watch::Receiver<bool>,
    ) -> Result<()> {
        self.run_loop(shutdown, Some(force)).await
    }

    /// Shared runtime loop: reconcile configuration until a shutdown signal or a stopped
    /// configuration, then apply the shutdown delay/grace period.
    async fn run_loop(
        mut self,
        mut shutdown: watch::Receiver<bool>,
        force: Option<watch::Receiver<bool>>,
    ) -> Result<()> {
        let mut seen_active_generation = self.store.current().is_some();
        let mut store_stopped = false;
        // Track the generation that has already been applied. Re-applying an unchanged generation
        // every heartbeat would tear down and restart its renewal schedulers, cancelling any
        // in-flight ACME renewal; apply only when the active generation actually changes (or a
        // prior apply failed, leaving no recorded id).
        let mut applied_generation: Option<u64> = None;
        loop {
            // The store is the source of truth for "the server was told to stop". Detect a stop
            // *before* applying so the listeners stay up for the grace-period drain instead of
            // being torn down by the empty-generation apply.
            if seen_active_generation && self.store.current().is_none() {
                tracing::info!(
                    "configuration stopped; ending the server runtime loop (Caddy /stop semantics)"
                );
                store_stopped = true;
                break;
            }
            seen_active_generation |= self.store.current().is_some();
            let current_id = self.store.current().as_deref().map(Generation::id);
            if current_id != applied_generation {
                if let Err(error) = self.apply().await {
                    eprintln!("caddy-rs: cannot apply configuration: {error}");
                }
            }
            applied_generation = self.store.current().as_deref().map(Generation::id);
            if let Some(generation) = self.store.current() {
                self.shutdown_timing = ShutdownTiming::from_config(generation.config());
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = self.reload.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(200)) => {}
            }
        }
        let reason = if store_stopped {
            "configuration stopped"
        } else {
            "shutdown signal"
        };
        tracing::info!(
            reason,
            shutdown_delay_ms = self
                .shutdown_timing
                .shutdown_delay
                .map(|d| d.as_millis() as u64),
            grace_period_ms = self
                .shutdown_timing
                .grace_period
                .map(|d| d.as_millis() as u64),
            "initiating shutdown"
        );
        self.graceful_stop(force).await;
        Ok(())
    }

    /// Apply the configured shutdown delay/grace period, then stop every listener.
    ///
    /// * `shutdown_delay`: keep accepting and serving requests for this long after the shutdown
    ///   request (matching Caddy, which schedules shutdown instead of dropping traffic instantly).
    /// * `grace_period`: after listeners stop accepting, wait up to this long for active
    ///   connections (including streamed responses and upgraded tunnels) to finish.
    /// * a second signal / `force` channel skips both waits and force-closes connections.
    async fn graceful_stop(&mut self, mut force: Option<watch::Receiver<bool>>) {
        let timing = self.shutdown_timing;
        let mut forced = false;

        if let Some(delay) = timing.shutdown_delay {
            tracing::info!(
                delay_ms = delay.as_millis() as u64,
                "shutdown delay configured; keeping listeners open"
            );
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = force_requested(&mut force) => forced = true,
            }
        }
        if forced {
            tracing::info!("forced shutdown requested; closing connections immediately");
            self.force_all();
            self.stop_all().await;
            return;
        }

        // Stop accepting new connections before draining in-flight work.
        if let Some(admin) = &self.admin {
            admin.begin_graceful();
        }
        for handle in self.listeners.values() {
            handle.begin_graceful();
        }

        let trackers = self.trackers();

        if let Some(grace) = timing.grace_period {
            tracing::info!(
                grace_ms = grace.as_millis() as u64,
                "servers shutting down; grace period initiated"
            );
            let deadline = Instant::now() + grace;
            let drained = wait_for_trackers(&trackers, deadline, &mut force).await;
            if !drained {
                tracing::warn!(
                    grace_ms = grace.as_millis() as u64,
                    "grace period expired; force-closing remaining connections"
                );
                self.force_all();
            }
        } else {
            // Caddy without a configured grace period uses an eternal grace period
            // (modules/caddyhttp/app.go: `case app.GracePeriod > 0 ... else "servers shutting down
            // with eternal grace period"`, then `server.server.Shutdown(context.Background())`).
            // Go's Shutdown waits for active requests/idle connections but ignores hijacked
            // connections, so ordinary connections drain here while upgraded tunnels are ended by
            // the forced close as shutdown finishes (in Caddy they die with the process).
            tracing::info!("servers shutting down with eternal grace period");
            let drained = wait_for_ordinary_trackers(&trackers, &mut force).await;
            if !drained {
                tracing::info!("forced shutdown requested; closing connections immediately");
                self.force_all();
            } else if trackers.iter().any(|tracker| tracker.active_upgraded() > 0) {
                tracing::info!(
                    "ordinary connections drained; closing hijacked/upgraded connections \
                     (Go's http.Server.Shutdown does not wait for them)"
                );
                self.force_all();
            }
        }

        self.stop_all().await;
    }

    /// Trackers for every current listener and the admin endpoint.
    fn trackers(&self) -> Vec<Arc<crate::listeners::ConnectionTracker>> {
        self.admin
            .iter()
            .map(crate::listeners::ListenerHandle::tracker)
            .chain(
                self.listeners
                    .values()
                    .map(crate::listeners::ListenerHandle::tracker),
            )
            .collect()
    }

    /// Force-close connections on every listener and the admin endpoint.
    fn force_all(&self) {
        if let Some(admin) = &self.admin {
            admin.begin_force();
        }
        for handle in self.listeners.values() {
            handle.begin_force();
        }
    }

    /// Number of currently active connections across all listeners (including the admin endpoint).
    pub fn active_connections(&self) -> usize {
        self.admin
            .iter()
            .map(crate::listeners::ListenerHandle::active_connections)
            .chain(
                self.listeners
                    .values()
                    .map(crate::listeners::ListenerHandle::active_connections),
            )
            .sum()
    }

    /// Stop every listener and consume the runtime, force-closing active connections.
    pub async fn shutdown(mut self) {
        self.force_all();
        self.stop_all().await;
    }

    async fn stop_all(&mut self) {
        // Force-close remaining connections, then give their tasks a bounded moment to observe the
        // force signal and drop their tracker guards. Go's Shutdown only returns once its
        // connections are done; without this wait, connection tasks outlive the runtime and leak.
        let trackers = self.trackers();
        self.force_all();
        let remaining = wait_for_trackers_closed(&trackers, Duration::from_secs(2)).await;
        if remaining > 0 {
            tracing::warn!(
                remaining,
                "connections still active after forced shutdown; listener tasks are detached"
            );
        }
        if let Some(admin) = self.admin.take() {
            admin.stop_forcibly().await;
        }
        let listeners = std::mem::take(&mut self.listeners);
        for (_, handle) in listeners {
            handle.stop_forcibly().await;
        }
        let health_schedulers = std::mem::take(&mut self.health_schedulers);
        for (generation, schedulers) in health_schedulers {
            if !schedulers.is_empty() {
                tracing::info!(
                    generation,
                    checkers = schedulers.len(),
                    "stopping active health-check schedulers"
                );
            }
            for scheduler in schedulers {
                scheduler.shutdown().await;
            }
        }
        let renewals = std::mem::take(&mut self.renewals);
        for (generation, renewals) in renewals {
            tracing::info!(generation, "stopping certificate renewal scheduler");
            renewals.stop().await;
        }
        self.renewal_metrics_seen.clear();
        if let Some(access) = self.access_log.take() {
            access.flush();
            access.close();
        }
        self.access_log_generation = None;
        self.inventory.clear();
    }

    /// Resolve the socket-activation state for the configured listeners, once.
    fn resolve_activation(
        &mut self,
        states: &std::collections::HashMap<String, Arc<ListenerState>>,
    ) -> Result<()> {
        let state = std::mem::replace(&mut self.activation, ActivationState::Inactive);
        match state {
            ActivationState::Environment => match SocketActivation::from_env() {
                Ok(Some(activation)) => self.plan_inherited_sockets(activation, states),
                Ok(None) => Ok(()),
                Err(error) => self.fail_activation(error),
            },
            ActivationState::Injected(Some(activation)) => {
                self.plan_inherited_sockets(activation, states)
            }
            ActivationState::Injected(None) => Ok(()),
            ActivationState::Planned(plan) => {
                self.activation = ActivationState::Planned(plan);
                Ok(())
            }
            ActivationState::Inactive => Ok(()),
            ActivationState::Failed { path, message } => {
                let error = Error::SocketActivation {
                    path: path.clone(),
                    message: message.clone(),
                };
                self.activation = ActivationState::Failed { path, message };
                Err(error)
            }
        }
    }

    fn plan_inherited_sockets(
        &mut self,
        activation: SocketActivation,
        states: &std::collections::HashMap<String, Arc<ListenerState>>,
    ) -> Result<()> {
        let listen_keys: Vec<String> = states.keys().cloned().collect();
        match plan_activation(&listen_keys, activation) {
            Ok(plan) => {
                if plan.inherited() > 0 {
                    tracing::info!(
                        inherited = plan.inherited(),
                        claimed = plan.claimed_listeners().count(),
                        "resolved systemd socket activation"
                    );
                }
                self.activation = ActivationState::Planned(plan);
                Ok(())
            }
            Err(error) => self.fail_activation(error),
        }
    }

    fn fail_activation(&mut self, error: ActivationError) -> Result<()> {
        let located = Error::SocketActivation {
            path: error.path().to_string(),
            message: error.message().to_string(),
        };
        self.activation = ActivationState::Failed {
            path: error.path().to_string(),
            message: error.message().to_string(),
        };
        Err(located)
    }

    /// Build the per-listen-address serving state for a generation.
    ///
    /// The same server object can own several listen addresses; each gets the same router and the
    /// parsed [`ServerLimits`]. A malformed timeout or limit field fails the apply with the
    /// offending JSON path, so an invalid server configuration is never served.
    /// Provision automatic-HTTPS certificates for `generation` (if automation is configured).
    /// Derive the automatic-HTTPS plan and build the provisioner without doing any network work.
    ///
    /// The returned issuer's TLS-ALPN-01 token store is captured here: the bootstrap listener
    /// states must already share it before provisioning runs, otherwise `acme-tls/1` handshakes
    /// cannot be answered while the CA validates the order.

    fn prepare_automatic_https(
        &mut self,
        generation: &Generation,
    ) -> Result<Option<PendingAutomaticHttps>> {
        let config = generation.config();
        let Some(plan) = plan_automatic_https(config)? else {
            return Ok(None);
        };
        let default_root = self
            .data_root
            .clone()
            .or_else(|| {
                config
                    .storage()
                    .and_then(|storage| storage.root())
                    .map(std::path::PathBuf::from)
            })
            .unwrap_or_else(|| std::path::PathBuf::from(".caddy-rs"));
        // Select the Caddy storage module now (T-TLS-068): unknown modules and malformed roots
        // fail the apply loudly instead of silently falling back to the data directory, and the
        // provisioner persists certificates, ACME accounts and internal-CA leaves through it.
        let selected_storage =
            caddy_rs_tls::SelectedStorage::from_config(config, Some(&default_root))?;
        let root = selected_storage
            .root()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| default_root.clone());
        // Construct the ACME transport lazily: a default-on plan whose issuers are all internal
        // (for example `localhost` sites) must not require a platform CA bundle, and an injected
        // test transport is never bypassed. Public-name plans construct the production transport
        // here and fail loudly if no CA bundle is available; issuance failures roll the apply back.
        let needs_acme = plan
            .policies
            .iter()
            .any(|policy| matches!(policy.issuer, AutomaticHttpsIssuer::Acme(_)));
        let transport: Arc<dyn AcmeTransport> = match &self.acme_transport {
            Some(transport) => Arc::clone(transport),
            None if needs_acme => Arc::new(HyperTransport::new()?),
            None => Arc::new(NoAcmeTransport),
        };
        let base_resolver = resolver_from_config(config)?;
        let provisioner =
            AutomaticHttpsProvisioner::new(transport, root, Arc::clone(&self.challenge_tokens))
                .with_storage(selected_storage);
        // Seed the new generation from the still-active certificates: a reload must not re-issue
        // what the previous generation already holds in memory (storage may be empty, transient or
        // pending a write). Resolver hot-swap keeps in-flight handshakes on the old Arc.
        let provisioner = match &self.certificate_store {
            Some(store) => provisioner.with_certificate_store(Arc::clone(store)),
            None => provisioner,
        };
        let tls_alpn01_tokens = Arc::clone(provisioner.tls_alpn01_token_store());
        let redirect = plan.redirects_enabled.then(|| RedirectPolicy {
            hosts: plan.redirect_hosts.clone(),
            redirect_all: plan.redirect_all,
            host_ports: plan.redirect_ports.clone(),
            https_port: plan.https_port,
            redirect_all_port: plan.redirect_all_port,
            http_port: plan.http_port,
        });
        let ocsp_stapler = match &self.ocsp_stapler {
            Some(stapler) => Some(Arc::clone(stapler)),
            None if plan.ocsp_check_interval > std::time::Duration::ZERO => {
                match HyperOcspTransport::new() {
                    Ok(transport) => {
                        let stapler = Arc::new(OcspStapler::new(
                            Arc::new(transport),
                            OcspPolicy {
                                enabled: true,
                                must_staple: false,
                                check_interval: plan.ocsp_check_interval,
                            },
                        ));
                        self.ocsp_stapler = Some(Arc::clone(&stapler));
                        Some(stapler)
                    }
                    Err(error) => {
                        tracing::warn!(%error, "OCSP stapling disabled: no usable HTTP transport");
                        None
                    }
                }
            }
            None => None,
        };
        Ok(Some(PendingAutomaticHttps {
            ocsp_stapler,
            plan,
            provisioner,
            base_resolver,
            serving: Arc::new(crate::auto_https::AutomaticHttpsServing {
                tokens: Arc::clone(&self.challenge_tokens),
                redirect,
            }),
            tls_alpn01_tokens,
        }))
    }

    /// Build the pre-provisioning listener states.
    ///
    /// TLS listeners use the manual (configured) certificates as their normal fallback and the
    /// issuer's TLS-ALPN token store as the `acme-tls/1` overlay, so they can answer challenge
    /// handshakes even though no certificate has been obtained yet. Cleartext listeners get the
    /// HTTP-01/redirect pre-routing from the plan.
    fn build_bootstrap_states(
        &self,
        generation: &Generation,
        pending: &PendingAutomaticHttps,
        access_log: &Arc<AccessLogRuntime>,
        status_sink: &Arc<UpstreamStatusSink>,
    ) -> Result<std::collections::HashMap<String, Arc<ListenerState>>> {
        let context = AutomaticHttpsContext {
            resolver: resolver_from_config(generation.config())?.map(Arc::new),
            tokens: &pending.tls_alpn01_tokens,
            serving: &pending.serving,
            tls_ports: &pending.plan.tls_ports,
            http_port: pending.plan.http_port,
            http_listener: pending.plan.http_listener(),
            bootstrap: true,
        };
        self.build_listener_states(generation, Some(&context), access_log, status_sink)
    }

    /// Build one HTTP server's router (error routes + normal routes).
    ///
    /// The router builder consumes the raw Caddy JSON route shape. The typed config model preserves
    /// the handler/matcher objects verbatim, so re-serializing is lossless. Used by both
    /// [`Self::build_listener_states`] and [`Self::validate_provisioning`] so `validate` and `run`
    /// construct exactly the same router.
    fn build_router(
        server_name: &str,
        server: &caddy_rs_core::HttpServer,
        status_sink: &Arc<UpstreamStatusSink>,
    ) -> Result<Arc<caddy_rs_http::Router>> {
        let routes_value = serde_json::to_value(&server.routes).map_err(|error| {
            Error::Config(caddy_rs_core::Error::invalid(
                format!("apps.http.servers.{server_name}.routes"),
                format!("cannot serialize routes for the HTTP engine: {error}"),
            ))
        })?;
        let routes = routes_value.as_array().cloned().unwrap_or_default();
        // Error routes (`handle_errors`) are server-level: serializing the typed model is
        // lossless because unknown fields are preserved.
        let errors_value = server
            .errors
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                Error::Config(caddy_rs_core::Error::invalid(
                    format!("apps.http.servers.{server_name}.errors"),
                    format!("cannot serialize error routes for the HTTP engine: {error}"),
                ))
            })?;
        let router_builder = RouterBuilder::new()
            .with_custom_handler(handler_factory_with_status_sink(Arc::clone(status_sink)));
        let router_builder = router_builder
            .with_error_routes(
                errors_value.as_ref(),
                &format!("apps.http.servers.{server_name}.errors"),
            )
            .map_err(|error| {
                eprintln!("caddy-rs: server `{server_name}`: {error}");
                Error::Http(error)
            })?;
        let router = router_builder.build(&routes).map_err(|error| {
            eprintln!("caddy-rs: server `{server_name}`: {error}");
            Error::Http(error)
        })?;
        Ok(Arc::new(router))
    }

    /// Build the per-listen-address serving state for a generation.
    ///
    /// The same server object can own several listen addresses; each gets the same router and the
    /// parsed [`ServerLimits`]. A malformed timeout or limit field fails the apply with the
    /// offending JSON path, so an invalid server configuration is never served.
    ///
    /// When `automatic` is present, TLS listeners additionally advertise `acme-tls/1` and wrap
    /// their resolver with [`AcmeTlsAlpnResolver`]; challenge certificates are only selected for
    /// handshakes that offer that ALPN, and every other handshake uses the normal resolver (and
    /// therefore normal SNI behaviour).
    fn build_listener_states(
        &self,
        generation: &Generation,
        automatic: Option<&AutomaticHttpsContext<'_>>,
        access_log: &Arc<AccessLogRuntime>,
        status_sink: &Arc<UpstreamStatusSink>,
    ) -> Result<std::collections::HashMap<String, Arc<ListenerState>>> {
        let mut states = std::collections::HashMap::new();
        let Some(http) = generation.config().http() else {
            return Ok(states);
        };
        // TLS listener policy: a listener terminates TLS when its HTTP server declares connection
        // policies or when its port is the effective HTTPS port. Certificates come from
        // `apps.tls.certificates` (manual) or automatic HTTPS; a TLS listener without certificates
        // fails this apply loudly once provisioning has had its chance.
        let https_port = http.https_port.unwrap_or(DEFAULT_HTTPS_PORT);
        let manual_resolver: Option<Arc<CertificateResolver>> = if automatic.is_none() {
            resolver_from_config(generation.config())?.map(Arc::new)
        } else {
            None
        };
        let http_port = http.http_port.unwrap_or(caddy_rs_tls::DEFAULT_HTTP_PORT);
        for (server_name, server) in &http.servers {
            let limits = Arc::new(ServerLimits::from_http_server(server_name, server)?);
            let trusted_proxies = parse_server_trusted_proxies(server, server_name)?;
            let policies = server.tls_connection_policies.as_deref();
            let has_connection_policies = policies.is_some_and(|policies| !policies.is_empty());
            if strict_sni_host_enabled(server.strict_sni_host.as_ref()) {
                return Err(Error::NotImplemented {
                    feature: "`strict_sni_host` TLS handshake rejection",
                    tracking_id: "TLS-STRICT-SNI",
                });
            }
            let tls_options = TlsServerOptions::from_connection_policies_with_ca_pool(
                policies,
                &client_auth_ca_pool_context(generation.config(), self.data_root.as_deref()),
            )?;
            let router = Self::build_router(server_name, server, status_sink)?;
            // HTTP/3 Alt-Svc advertisement (h1/h2 responses only), when this server offers h3 on a
            // concrete UDP port. During the automatic-HTTPS bootstrap phase there is no final
            // resolver yet, so h3 is neither bound nor advertised until phase 2.
            let bootstrap_phase = automatic.is_some_and(|context| context.bootstrap);
            let listens = effective_listens(server, https_port, has_connection_policies);
            let alt_svc = if bootstrap_phase {
                None
            } else {
                alt_svc_for_listens(server, &listens)
            };
            for listen in &listens {
                let parsed_listen = caddy_rs_core::ListenAddr::parse(listen).map_err(|reason| {
                    Error::Config(caddy_rs_core::Error::invalid(
                        format!("apps.http.servers.{server_name}.listen"),
                        format!("invalid listen address `{listen}`: {reason}"),
                    ))
                })?;
                let is_udp = parsed_listen.network == Network::Udp;
                validate_udp_listener(
                    listen,
                    server_name,
                    server,
                    https_port,
                    has_connection_policies,
                )?;
                if is_udp && bootstrap_phase {
                    // Bind HTTP/3 only after certificates are provisioned: a QUIC endpoint's TLS
                    // configuration is fixed at bind time, so a bootstrap endpoint could keep an
                    // empty challenge resolver after issuance completes.
                    continue;
                }
                let listen_port = parsed_listen.port();
                // Under an automatic-HTTPS plan, a listener is TLS when it has explicit policies
                // or when the plan derived TLS for its port (implicit HTTPS on a non-standard
                // port). Without a plan the historical rule applies.
                #[cfg(feature = "http3")]
                let terminates_tls = if is_udp {
                    // HTTP/3 requires TLS; `validate_udp_listener` already rejected cleartext UDP
                    // listeners loudly.
                    udp_listener_terminates_tls(listen, https_port, has_connection_policies)
                } else {
                    tcp_listener_terminates_tls(
                        listen,
                        listen_port,
                        https_port,
                        has_connection_policies,
                        automatic,
                    )?
                };
                #[cfg(not(feature = "http3"))]
                let terminates_tls = {
                    // Explicit `udp/...` listeners were rejected by `validate_udp_listener`.
                    debug_assert!(!is_udp);
                    tcp_listener_terminates_tls(
                        listen,
                        listen_port,
                        https_port,
                        has_connection_policies,
                        automatic,
                    )?
                };
                let tls = if terminates_tls {
                    match automatic {
                        Some(context) => {
                            // TLS-ALPN-01 overlay: advertise `acme-tls/1` and resolve challenge
                            // certificates only for that ALPN. During the bootstrap phase an empty
                            // fallback resolver is allowed (normal handshakes fail until the
                            // certificate exists, exactly like Caddy while issuance is in flight).
                            let fallback: Arc<CertificateResolver> = match &context.resolver {
                                Some(resolver) if !resolver.is_empty() => Arc::clone(resolver),
                                _ if context.bootstrap => Arc::new(CertificateResolver::default()),
                                _ => {
                                    return Err(missing_certificates_error(
                                        listen,
                                        server_name,
                                        https_port,
                                    ))
                                }
                            };
                            if is_udp {
                                // QUIC's TLS config is derived from this one by overriding the
                                // ALPN to `h3`; the ACME TLS-ALPN-01 overlay is TCP-only.
                                Some(build_server_config_with_cert_resolver(
                                    fallback,
                                    &tls_options,
                                )?)
                            } else {
                                let overlay = Arc::new(AcmeTlsAlpnResolver::new(
                                    fallback,
                                    Arc::clone(context.tokens),
                                ));
                                let options = tls_options.clone().with_acme_tls_alpn();
                                Some(build_server_config_with_cert_resolver(overlay, &options)?)
                            }
                        }
                        None => {
                            let resolver = manual_resolver
                                .as_ref()
                                .filter(|resolver| !resolver.is_empty())
                                .ok_or_else(|| {
                                    missing_certificates_error(listen, server_name, https_port)
                                })?;
                            Some(build_server_config(Arc::clone(resolver), &tls_options)?)
                        }
                    }
                } else {
                    None
                };
                let automatic_serving = if !terminates_tls {
                    let listener_port = caddy_rs_core::ListenAddr::parse(listen)
                        .ok()
                        .and_then(|address| address.port());
                    match automatic {
                        Some(context) if listener_port == Some(http_port) => {
                            Some(Arc::clone(context.serving))
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                states.insert(
                    listen.clone(),
                    Arc::new(ListenerState {
                        router: Arc::clone(&router),
                        limits: Arc::clone(&limits),
                        trusted_proxies: Arc::clone(&trusted_proxies),
                        tls,
                        client_auth_verified: tls_options.client_auth.verifies(),
                        automatic: automatic_serving,
                        server_name: server_name.clone(),
                        recorder: Arc::clone(&self.recorder),
                        access_log: Arc::clone(access_log),
                        access_log_policy: Arc::new(ServerAccessLogPolicy::from_config(
                            server.logs.as_ref(),
                        )),
                        wrappers: Arc::new(ListenerWrappers::from_server(server)?),
                        h2c_upgrade: h2c_upgrade_enabled(server),
                        alt_svc: alt_svc.clone(),
                    }),
                );
            }
        }
        if let Some(context) = automatic {
            if let Some(listen) = &context.http_listener {
                if !states.contains_key(listen) {
                    // Challenge/redirect-only HTTP listener derived from the HTTPS site: no
                    // configured routes; the automatic pre-routing answers before the router.
                    let router = Arc::new(
                        RouterBuilder::new()
                            .with_custom_handler(caddy_rs_proxy::handler_factory())
                            .build(&[])
                            .map_err(Error::Http)?,
                    );
                    states.insert(
                        listen.clone(),
                        Arc::new(ListenerState {
                            router,
                            limits: Arc::new(ServerLimits::default()),
                            trusted_proxies: Arc::new(
                                caddy_rs_proxy::trusted_proxies::ServerTrustedProxies::default(),
                            ),
                            tls: None,
                            client_auth_verified: false,
                            automatic: Some(Arc::clone(context.serving)),
                            server_name: String::new(),
                            recorder: Arc::clone(&self.recorder),
                            access_log: Arc::clone(access_log),
                            access_log_policy: Arc::new(ServerAccessLogPolicy::default()),
                            wrappers: Arc::new(ListenerWrappers::default()),
                            h2c_upgrade: false,
                            alt_svc: None,
                        }),
                    );
                }
            }
        }
        Ok(states)
    }
}

/// Parse one server's trusted-proxy policy (`trusted_proxies`, `trusted_proxies_strict`,
/// `trusted_proxies_unix`, `client_ip_headers`) from the preserved server JSON fields.
///
/// The parser lives in `caddy-rs-proxy` because reverse_proxy/forward_auth consume the derived
/// `trusted_proxy`/`client_ip` request variables; this keeps the server's validation and the
/// handlers' interpretation of Caddy's module shapes in one place. Unknown IP-range `source`
/// modules and malformed ranges/headers fail loudly with the located path.
fn parse_server_trusted_proxies(
    server: &caddy_rs_core::config::HttpServer,
    server_name: &str,
) -> Result<Arc<caddy_rs_proxy::trusted_proxies::ServerTrustedProxies>> {
    let mut object = serde_json::Map::new();
    for field in [
        "trusted_proxies",
        "trusted_proxies_strict",
        "trusted_proxies_unix",
        "client_ip_headers",
    ] {
        if let Some(value) = server.extra.get(field) {
            object.insert(field.to_string(), value.clone());
        }
    }
    let path = format!("apps.http.servers.{server_name}");
    caddy_rs_proxy::trusted_proxies::ServerTrustedProxies::from_server_json(
        &serde_json::Value::Object(object),
        &path,
    )
    .map(Arc::new)
    .map_err(Error::Http)
}

/// Whether a server explicitly offers cleartext h2c Upgrade (Caddy `protocols` includes `h2c`).
///
/// Caddy's defaults are HTTP/1.1 plus HTTP/2 over TLS and do **not** include h2c, so an
/// `Upgrade: h2c` offer on a default cleartext listener is served as HTTP/1.1.
fn h2c_upgrade_enabled(server: &caddy_rs_core::config::HttpServer) -> bool {
    server
        .protocols
        .as_ref()
        .is_some_and(|protocols| protocols.iter().any(|protocol| protocol == "h2c"))
}

/// Wait until the force channel fires (or forever when no force channel was provided).
async fn force_requested(force: &mut Option<watch::Receiver<bool>>) -> bool {
    match force {
        None => std::future::pending::<()>().await,
        Some(receiver) => {
            if *receiver.borrow() {
                return true;
            }
            let _ = receiver.changed().await;
        }
    }
    true
}

/// Wait for every connection tracker to drain before `deadline`; returns `false` when the grace
/// period expired or a forced shutdown was requested.
async fn wait_for_trackers(
    trackers: &[Arc<crate::listeners::ConnectionTracker>],
    deadline: Instant,
    force: &mut Option<watch::Receiver<bool>>,
) -> bool {
    if trackers.iter().all(|tracker| tracker.active() == 0) {
        return true;
    }
    let now = Instant::now();
    if now >= deadline {
        return false;
    }
    let remaining = deadline - now;
    let drained = async {
        for tracker in trackers {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            if !tracker.wait_drained(Some(deadline - now)).await {
                return false;
            }
        }
        true
    };
    tokio::select! {
        drained = drained => drained,
        _ = force_requested(force) => false,
        _ = tokio::time::sleep(remaining) => false,
    }
}

/// Wait indefinitely for every ordinary connection to finish, as Caddy's eternal grace period
/// does; hijacked/upgraded tunnels are excluded (Go's `http.Server.Shutdown` ignores them).
///
/// Returns `false` when a forced shutdown was requested while waiting.
async fn wait_for_ordinary_trackers(
    trackers: &[Arc<crate::listeners::ConnectionTracker>],
    force: &mut Option<watch::Receiver<bool>>,
) -> bool {
    if trackers
        .iter()
        .all(|tracker| tracker.active_ordinary() == 0)
    {
        return true;
    }
    let drained = async {
        for tracker in trackers {
            tracker.wait_ordinary_drained().await;
        }
        true
    };
    tokio::select! {
        drained = drained => drained,
        _ = force_requested(force) => false,
    }
}

/// Wait until every tracker reports no active connections, or `timeout` expires; returns the number
/// of connections still active. Used after a forced close so connection tasks do not outlive the
/// runtime.
async fn wait_for_trackers_closed(
    trackers: &[Arc<crate::listeners::ConnectionTracker>],
    timeout: Duration,
) -> usize {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining: usize = trackers.iter().map(|tracker| tracker.active()).sum();
        if remaining == 0 || Instant::now() >= deadline {
            return remaining;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Whether one configured listen address uses the UDP network (`udp/...`).
fn is_udp_listen(listen: &str) -> bool {
    ListenAddr::parse(listen)
        .map(|address| address.network == Network::Udp)
        .unwrap_or(false)
}

/// Whether this server offers HTTP/3: Caddy's default `protocols` are `[h1, h2, h3]`, so an
/// omitted field enables h3; an explicit list must contain `h3`.
#[cfg(feature = "http3")]
fn server_offers_h3(server: &HttpServer) -> bool {
    match server.protocols.as_ref() {
        None => true,
        Some(protocols) => protocols.iter().any(|protocol| protocol == "h3"),
    }
}

/// Effective listen addresses for a server, including the UDP (QUIC) listeners Caddy derives
/// automatically.
///
/// Caddy binds a UDP socket for every TLS TCP `listen` address when the server offers HTTP/3
/// (`modules/caddyhttp/app.go`, `makeHTTP3Server`); operators do not spell `udp/...` out.
/// caddy-rs used to require the explicit form, which meant a Caddyfile that works on Caddy served
/// no HTTP/3 here. This returns the configured addresses plus one `udp/<addr>` per TLS TCP address,
/// skipping any address an explicit `udp/...` already covers so nothing is bound twice.
#[cfg(feature = "http3")]
fn effective_listens(
    server: &HttpServer,
    https_port: u16,
    has_connection_policies: bool,
) -> Vec<String> {
    let mut listens = server.listen.clone();
    if !server_offers_h3(server) {
        return listens;
    }
    let explicit: BTreeSet<String> = listens
        .iter()
        .filter_map(|listen| ListenAddr::parse(listen).ok())
        .filter(|address| address.network == Network::Udp)
        .map(|address| address.address)
        .collect();
    let derived: Vec<String> = listens
        .iter()
        .filter_map(|listen| ListenAddr::parse(listen).ok())
        .filter(|address| address.network == Network::Tcp)
        .filter(|address| address.port() == Some(https_port) || has_connection_policies)
        .filter(|address| !explicit.contains(&address.address))
        .map(|address| format!("udp/{}", address.address))
        .collect();
    listens.extend(derived);
    listens
}

/// A build without HTTP/3 never derives a UDP listener from a TLS TCP one. Explicit `udp/...`
/// entries stay in the list and are rejected by [`validate_udp_listener`] with a located error.
#[cfg(not(feature = "http3"))]
fn effective_listens(
    server: &HttpServer,
    _https_port: u16,
    _has_connection_policies: bool,
) -> Vec<String> {
    server.listen.clone()
}

/// Caddy's `http3.Server.SetQUICHeaders` value for the first concrete UDP listener port of this
/// server, when the server offers HTTP/3. Ephemeral (`:0`) UDP ports have no known value at plan
/// time and are advertised as no Alt-Svc (Caddy reports `ErrNoAltSvcPort` in that case). Used with
/// [`effective_listens`] so automatically derived UDP listeners are advertised exactly like
/// configured ones.
#[cfg(feature = "http3")]
fn alt_svc_for_listens(server: &HttpServer, listens: &[String]) -> Option<String> {
    if !server_offers_h3(server) {
        return None;
    }
    for listen in listens {
        let Ok(address) = ListenAddr::parse(listen) else {
            continue;
        };
        if address.network != Network::Udp {
            continue;
        }
        match address.port() {
            Some(port) if port != 0 => return Some(format!("h3=\":{port}\"; ma=2592000")),
            _ => return None,
        }
    }
    None
}

/// Without HTTP/3 there is nothing to advertise, so no `Alt-Svc` header is ever emitted.
#[cfg(not(feature = "http3"))]
fn alt_svc_for_listens(_server: &HttpServer, _listens: &[String]) -> Option<String> {
    None
}

/// Whether a UDP (QUIC) listener terminates TLS: port 443 (or the configured HTTPS port) or
/// explicit `tls_connection_policies`, matching the TCP rule. HTTP/3 requires TLS, so a UDP
/// listener that does not terminate TLS is a configuration error, never a silent UDP sink.
#[cfg(feature = "http3")]
fn udp_listener_terminates_tls(
    listen: &str,
    https_port: u16,
    has_connection_policies: bool,
) -> bool {
    let Ok(address) = ListenAddr::parse(listen) else {
        return false;
    };
    address.network == Network::Udp
        && (has_connection_policies || address.port() == Some(https_port))
}

/// TCP/Unix listener TLS decision shared by both feature profiles.
fn tcp_listener_terminates_tls(
    listen: &str,
    listen_port: Option<u16>,
    https_port: u16,
    has_connection_policies: bool,
    automatic: Option<&AutomaticHttpsContext<'_>>,
) -> Result<bool> {
    match automatic {
        Some(context) => {
            let wants_tls = has_connection_policies
                || listen_port.is_some_and(|port| context.tls_ports.contains(&port));
            // Caddy excludes the configured HTTP port from TLS even when the server carries
            // explicit TLS connection policies (`app.go`: `useTLS := len(TLSConnPolicies) > 0 &&
            // port != http_port`). `:0` is an ephemeral listener, not the configured HTTP port:
            // only a concrete, configured HTTP port excludes TLS.
            let on_http_port = context.http_port != 0 && listen_port == Some(context.http_port);
            Ok(wants_tls && !on_http_port)
        }
        None => Ok(listener_uses_tls(
            listen,
            https_port,
            has_connection_policies,
        )?),
    }
}

/// Locate a UDP listener that cannot serve HTTP/3 (missing TLS, missing `protocols: ["h3"]`, or a
/// build without HTTP/3), returning a located error so the configuration fails at
/// validate/apply instead of binding a socket that silently drops QUIC traffic.
#[cfg(feature = "http3")]
fn validate_udp_listener(
    listen: &str,
    server_name: &str,
    server: &HttpServer,
    https_port: u16,
    has_connection_policies: bool,
) -> Result<()> {
    if !is_udp_listen(listen) {
        return Ok(());
    }
    if !server_offers_h3(server) {
        return Err(Error::Config(caddy_rs_core::Error::invalid(
            format!("apps.http.servers.{server_name}.listen"),
            format!(
                "UDP listener `{listen}` requires the server's `protocols` to include `h3`; \
                 otherwise the socket would silently drop QUIC traffic"
            ),
        )));
    }
    if !udp_listener_terminates_tls(listen, https_port, has_connection_policies) {
        return Err(Error::Config(caddy_rs_core::Error::invalid(
            format!("apps.http.servers.{server_name}.listen"),
            format!(
                "UDP listener `{listen}` requires TLS (HTTPS port {https_port} or \
                 `tls_connection_policies`); HTTP/3 is never served cleartext"
            ),
        )));
    }
    Ok(())
}

/// A build without the `http3` feature rejects every explicit `udp/...` listen address with a
/// located error instead of binding a socket that can never serve a request.
#[cfg(not(feature = "http3"))]
fn validate_udp_listener(
    listen: &str,
    server_name: &str,
    _server: &HttpServer,
    _https_port: u16,
    _has_connection_policies: bool,
) -> Result<()> {
    if !is_udp_listen(listen) {
        return Ok(());
    }
    Err(Error::Config(caddy_rs_core::Error::invalid(
        format!("apps.http.servers.{server_name}.listen"),
        format!(
            "UDP listener `{listen}` cannot be served: HTTP/3 support is not compiled in \
             (rebuild with the `http3` feature or remove the `udp/...` listener)"
        ),
    )))
}

/// Generation-scoped OCSP refresh task. Dropping this value aborts the task.
pub(crate) struct OcspRefresh {
    handle: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for OcspRefresh {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OcspRefresh")
            .field("finished", &self.handle.is_finished())
            .finish()
    }
}

impl Drop for OcspRefresh {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Ensure/refresh staples for every certificate currently in `resolver` and hot-swap entries.
///
/// A failed refresh logs and leaves the previously inserted staple in place (the resolver entry is
/// only replaced after a successful fetch/cached response).
async fn apply_ocsp_staples(
    resolver: &CertificateResolver,
    plan: &AutomaticHttpsPlan,
    stapler: &OcspStapler,
) {
    for certificate in resolver.certificates() {
        let Some(leaf) = certificate.chain().first() else {
            continue;
        };
        let Some(issuer) = certificate.chain().get(1) else {
            continue;
        };
        let subject = certificate
            .names()
            .first()
            .map(String::as_str)
            .unwrap_or("");
        if !plan.ocsp_policy_for(subject).enabled {
            continue;
        }
        match stapler.ensure_staple(leaf.as_ref(), issuer.as_ref()).await {
            Ok(outcome) if outcome.has_staple() => {
                match resolver.insert(staple_for_certificate(stapler, certificate.clone())) {
                    Ok(()) => {}
                    Err(error) => tracing::warn!(
                        subject,
                        %error,
                        "cannot install stapled certificate into the resolver"
                    ),
                }
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(
                subject,
                %error,
                "OCSP staple refresh failed; keeping the previous staple"
            ),
        }
    }
}

/// Spawn the periodic OCSP freshness scan for one generation.
fn spawn_ocsp_refresh(
    resolver: Arc<CertificateResolver>,
    plan: AutomaticHttpsPlan,
    stapler: SharedOcspStapler,
) -> OcspRefresh {
    let period = plan
        .ocsp_check_interval
        .max(std::time::Duration::from_secs(1));
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; initial provisioning already stapled, but a scan here
        // keeps failures recoverable after the backoff window.
        loop {
            interval.tick().await;
            apply_ocsp_staples(&resolver, &plan, &stapler).await;
        }
    });
    OcspRefresh { handle }
}
