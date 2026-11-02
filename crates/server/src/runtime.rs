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
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use caddy_rs_admin::AdminApi;
use caddy_rs_core::{Generation, GenerationStore};
use caddy_rs_http::RouterBuilder;
use caddy_rs_tls::{
    build_server_config, build_server_config_with_cert_resolver, listener_uses_tls,
    plan_automatic_https, resolver_from_config, AcmeTlsAlpnResolver, AcmeTransport,
    AutomaticHttpsPlan, AutomaticHttpsProvisioner, CertificateResolver, HyperTransport,
    TlsAlpn01TokenStore, TlsServerOptions, DEFAULT_HTTPS_PORT,
};
use tokio::sync::watch;

use crate::activation::{plan_activation, ActivationError, ActivationPlan, SocketActivation};
use crate::auto_https::{PreparedAutomaticHttps, RedirectPolicy};
use crate::error::{Error, Result};
use crate::limits::ServerLimits;
use crate::listeners::{bind, bind_admin, ListenerHandle, ListenerState, SharedListeners};

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
        Ok(PreparedAutomaticHttps {
            resolver: provisioned.resolver,
            plan,
            serving: self.serving,
            tls_alpn01_tokens: tokens,
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

impl ServerRuntime {
    /// Create a runtime for a generation store.
    pub fn new(store: Arc<GenerationStore>) -> Self {
        let reload = Arc::new(tokio::sync::Notify::new());
        let admin_api = AdminApi::new(Arc::clone(&store)).with_reload_notify(Arc::clone(&reload));
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
        let pending = self.prepare_automatic_https(&generation)?;
        let mut newly_bound: Vec<String> = Vec::new();

        // Without automatic HTTPS there is nothing to provision: the original single-phase path.
        let Some(pending) = pending else {
            let states = self.build_listener_states(&generation, None)?;
            self.resolve_activation(&states)?;
            self.publish_states(&states);
            if let Err(error) = self.start_new_listeners(&states, &mut newly_bound).await {
                self.stop_listener_keys(&newly_bound).await;
                return Err(error);
            }
            self.remove_unconfigured_listeners(&states).await;
            self.reconcile_admin(&generation).await?;
            return Ok(self.finish_apply(&generation));
        };
        // Snapshot for rollback: a failed provisioning pass must leave the previous generation's
        // listener states untouched.
        let previous_states = self
            .states
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        // Phase 1: challenge-capable states, then start the listeners before provisioning.
        let bootstrap = self.build_bootstrap_states(&generation, &pending)?;
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
        let context = AutomaticHttpsContext {
            resolver: Some(Arc::clone(&prepared.resolver)),
            tokens: &prepared.tls_alpn01_tokens,
            serving: &prepared.serving,
            http_listener: prepared.plan.http_listener(),
            bootstrap: false,
        };
        let states = match self.build_listener_states(&generation, Some(&context)) {
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
        Ok(self.finish_apply(&generation))
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
        for listen in removed {
            if let Some(handle) = self.listeners.remove(&listen) {
                tracing::info!(%listen, "closing listener");
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
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut seen_active_generation = self.store.current().is_some();
        loop {
            seen_active_generation |= self.store.current().is_some();
            if let Err(error) = self.apply().await {
                eprintln!("caddy-rs: cannot apply configuration: {error}");
            }
            // `apply` with no active generation stops every listener and the admin endpoint; the
            // store is the source of truth for "the server was told to stop".
            if seen_active_generation && self.store.current().is_none() {
                tracing::info!(
                    "configuration stopped; ending the server runtime loop (Caddy /stop semantics)"
                );
                break;
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
        self.stop_all().await;
        Ok(())
    }

    /// Stop every listener and consume the runtime.
    pub async fn shutdown(mut self) {
        self.stop_all().await;
    }

    async fn stop_all(&mut self) {
        if let Some(admin) = self.admin.take() {
            admin.stop().await;
        }
        let listeners = std::mem::take(&mut self.listeners);
        for (_, handle) in listeners {
            handle.stop().await;
        }
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
        &self,
        generation: &Generation,
    ) -> Result<Option<PendingAutomaticHttps>> {
        let config = generation.config();
        let Some(plan) = plan_automatic_https(config)? else {
            return Ok(None);
        };
        let root = self
            .data_root
            .clone()
            .or_else(|| {
                config
                    .storage()
                    .and_then(|storage| storage.root())
                    .map(std::path::PathBuf::from)
            })
            .unwrap_or_else(|| std::path::PathBuf::from(".caddy-rs"));
        let transport: Arc<dyn AcmeTransport> = match &self.acme_transport {
            Some(transport) => Arc::clone(transport),
            None => Arc::new(HyperTransport::new()?),
        };
        let base_resolver = resolver_from_config(config)?;
        let provisioner =
            AutomaticHttpsProvisioner::new(transport, root, Arc::clone(&self.challenge_tokens));
        let tls_alpn01_tokens = Arc::clone(provisioner.tls_alpn01_token_store());
        let redirect = plan.redirects_enabled.then(|| RedirectPolicy {
            hosts: plan.redirect_hosts.clone(),
            redirect_all: plan.redirect_all,
            https_port: plan.https_port,
        });
        Ok(Some(PendingAutomaticHttps {
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
    ) -> Result<std::collections::HashMap<String, Arc<ListenerState>>> {
        let context = AutomaticHttpsContext {
            resolver: resolver_from_config(generation.config())?.map(Arc::new),
            tokens: &pending.tls_alpn01_tokens,
            serving: &pending.serving,
            http_listener: pending.plan.http_listener(),
            bootstrap: true,
        };
        self.build_listener_states(generation, Some(&context))
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
            let policies = server.tls_connection_policies.as_deref();
            let has_connection_policies = policies.is_some_and(|policies| !policies.is_empty());
            if strict_sni_host_enabled(server.strict_sni_host.as_ref()) {
                return Err(Error::NotImplemented {
                    feature: "`strict_sni_host` TLS handshake rejection",
                    tracking_id: "TLS-STRICT-SNI",
                });
            }
            let tls_options = TlsServerOptions::from_connection_policies(policies)?;
            // The router builder consumes the raw Caddy JSON route shape. The typed config model
            // preserves the handler/matcher objects verbatim, so re-serializing is lossless.
            let routes_value = serde_json::to_value(&server.routes).map_err(|error| {
                Error::Config(caddy_rs_core::Error::invalid(
                    format!("apps.http.servers.{server_name}.routes"),
                    format!("cannot serialize routes for the HTTP engine: {error}"),
                ))
            })?;
            let routes = routes_value.as_array().cloned().unwrap_or_default();
            let router = RouterBuilder::new()
                .with_custom_handler(caddy_rs_proxy::handler_factory())
                .build(&routes)
                .map_err(|error| {
                    eprintln!("caddy-rs: server `{server_name}`: {error}");
                    Error::Http(error)
                })?;
            let router = Arc::new(router);
            for listen in &server.listen {
                let terminates_tls =
                    listener_uses_tls(listen, https_port, has_connection_policies)?;
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
                            let overlay = Arc::new(AcmeTlsAlpnResolver::new(
                                fallback,
                                Arc::clone(context.tokens),
                            ));
                            let options = tls_options.clone().with_acme_tls_alpn();
                            Some(build_server_config_with_cert_resolver(overlay, &options)?)
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
                        tls,
                        automatic: automatic_serving,
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
                            tls: None,
                            automatic: Some(Arc::clone(context.serving)),
                        }),
                    );
                }
            }
        }
        Ok(states)
    }
}
