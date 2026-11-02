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
    build_server_config, listener_uses_tls, plan_automatic_https, resolver_from_config,
    AcmeTransport, AutomaticHttpsProvisioner, CertificateResolver, HyperTransport,
    TlsServerOptions, DEFAULT_HTTPS_PORT,
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
    pub async fn apply(&mut self) -> Result<RuntimeStatus> {
        let Some(generation) = self.store.current() else {
            self.stop_all().await;
            self.status = RuntimeStatus::default();
            return Ok(self.status.clone());
        };
        // Automatic HTTPS (certificate acquisition) runs before listener state is replaced: a
        // failure here aborts the apply and leaves the previous generation's listeners serving.
        let prepared = self.prepare_automatic_https(&generation).await?;
        let states = self.build_listener_states(&generation, prepared.as_ref())?;
        // Resolve systemd socket activation before mutating any runtime state: a mismatch
        // (unclaimed inherited socket, malformed environment, non-listening fd) must fail the
        // apply without disturbing the previous generation.
        self.resolve_activation(&states)?;

        {
            let mut shared = self
                .states
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *shared = states.clone();
        }

        // Remove listeners whose address is no longer configured.
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

        // Add newly configured listeners.
        for listen in states.keys() {
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
            self.listeners.insert(listen.to_string(), handle);
        }

        // Once every inherited socket has been adopted the remaining applies bind normally.
        if let ActivationState::Planned(plan) = &self.activation {
            if !plan.has_claims() {
                self.activation = ActivationState::Inactive;
            }
        }

        // Reconcile the admin listener.
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

        self.status = RuntimeStatus {
            generation_id: Some(generation.id()),
            listeners: self
                .listeners
                .iter()
                .map(|(configured, handle)| (configured.clone(), handle.bound.clone()))
                .collect(),
            admin: self.admin.as_ref().map(|handle| handle.bound.clone()),
        };
        Ok(self.status.clone())
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

    /// Serve until `shutdown` becomes true, reconciling configuration as it changes.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        loop {
            if let Err(error) = self.apply().await {
                eprintln!("caddy-rs: cannot apply configuration: {error}");
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
    async fn prepare_automatic_https(
        &self,
        generation: &Generation,
    ) -> Result<Option<PreparedAutomaticHttps>> {
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
        let provisioned = provisioner.provision(&plan, base_resolver).await?;
        let redirect = plan.redirects_enabled.then(|| RedirectPolicy {
            hosts: plan.redirect_hosts.clone(),
            redirect_all: plan.redirect_all,
            https_port: plan.https_port,
        });
        Ok(Some(PreparedAutomaticHttps {
            resolver: provisioned.resolver,
            serving: Arc::new(crate::auto_https::AutomaticHttpsServing {
                tokens: Arc::clone(&self.challenge_tokens),
                redirect,
            }),
            plan,
        }))
    }

    fn build_listener_states(
        &self,
        generation: &Generation,
        prepared: Option<&PreparedAutomaticHttps>,
    ) -> Result<std::collections::HashMap<String, Arc<ListenerState>>> {
        let mut states = std::collections::HashMap::new();
        let Some(http) = generation.config().http() else {
            return Ok(states);
        };
        // TLS listener policy: a listener terminates TLS when its HTTP server declares connection
        // policies or when its port is the effective HTTPS port. Certificates come from
        // `apps.tls.certificates`; a TLS listener without certificates fails this apply loudly.
        let https_port = http.https_port.unwrap_or(DEFAULT_HTTPS_PORT);
        let resolver: Option<Arc<CertificateResolver>> = match prepared {
            Some(prepared) => Some(Arc::clone(&prepared.resolver)),
            None => resolver_from_config(generation.config())?.map(Arc::new),
        };
        let http_port = http.http_port.unwrap_or(caddy_rs_tls::DEFAULT_HTTP_PORT);
        let automatic_serving = prepared.map(|prepared| Arc::clone(&prepared.serving));
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
                    let resolver = resolver.as_ref().filter(|resolver| !resolver.is_empty());
                    let resolver = resolver.ok_or_else(|| {
                        missing_certificates_error(listen, server_name, https_port)
                    })?;
                    Some(build_server_config(Arc::clone(resolver), &tls_options)?)
                } else {
                    None
                };
                let automatic = if !terminates_tls {
                    let listener_port = caddy_rs_core::ListenAddr::parse(listen)
                        .ok()
                        .and_then(|address| address.port());
                    if listener_port == Some(http_port) {
                        automatic_serving.clone()
                    } else {
                        None
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
                        automatic,
                    }),
                );
            }
        }
        if let Some(prepared) = prepared {
            if let Some(listen) = prepared.plan.http_listener() {
                if !states.contains_key(&listen) {
                    // Challenge/redirect-only HTTP listener derived from the HTTPS site: no
                    // configured routes; the automatic pre-routing answers before the router.
                    let router = Arc::new(
                        RouterBuilder::new()
                            .with_custom_handler(caddy_rs_proxy::handler_factory())
                            .build(&[])
                            .map_err(Error::Http)?,
                    );
                    states.insert(
                        listen,
                        Arc::new(ListenerState {
                            router,
                            limits: Arc::new(ServerLimits::default()),
                            tls: None,
                            automatic: Some(Arc::clone(&prepared.serving)),
                        }),
                    );
                }
            }
        }
        Ok(states)
    }
}
