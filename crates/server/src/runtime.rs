//! The runtime supervisor.
//!
//! The supervisor watches the [`GenerationStore`]. When a new generation becomes active it builds
//! routers, updates the listener map, adds/removes listeners as addresses change, and rebinds the
//! admin API if its address changed. Listeners are never torn down for an unchanged address, so a
//! reload does not create a listening gap.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use caddy_rs_admin::AdminApi;
use caddy_rs_core::{Generation, GenerationStore};
use caddy_rs_http::{Router, RouterBuilder};
use tokio::sync::watch;

use crate::error::{Error, Result};
use crate::listeners::{bind, bind_admin, ListenerHandle, SharedRouters};

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

/// Owns listeners and drives configuration generations.
pub struct ServerRuntime {
    store: Arc<GenerationStore>,
    reload: Arc<tokio::sync::Notify>,
    routers: SharedRouters,
    listeners: BTreeMap<String, ListenerHandle>,
    admin: Option<ListenerHandle>,
    admin_api: AdminApi,
    status: RuntimeStatus,
}

impl ServerRuntime {
    /// Create a runtime for a generation store.
    pub fn new(store: Arc<GenerationStore>) -> Self {
        let reload = Arc::new(tokio::sync::Notify::new());
        let admin_api = AdminApi::new(Arc::clone(&store)).with_reload_notify(Arc::clone(&reload));
        Self {
            store,
            reload,
            routers: SharedRouters::new(RwLock::new(std::collections::HashMap::new())),
            listeners: BTreeMap::new(),
            admin: None,
            admin_api,
            status: RuntimeStatus::default(),
        }
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
        let routers = self.build_routers(&generation)?;

        {
            let mut shared = self
                .routers
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *shared = routers.clone();
        }

        // Remove listeners whose address is no longer configured.
        let removed: Vec<String> = self
            .listeners
            .keys()
            .filter(|listen| !routers.contains_key(*listen))
            .cloned()
            .collect();
        for listen in removed {
            if let Some(handle) = self.listeners.remove(&listen) {
                tracing::info!(%listen, "closing listener");
                handle.stop().await;
            }
        }

        // Add newly configured listeners.
        for listen in routers.keys() {
            if self.listeners.contains_key(listen) {
                continue;
            }
            let handle = bind(listen, Arc::clone(&self.routers), Arc::clone(&self.store)).await?;
            tracing::info!(listen, bound = %handle.bound, "listening");
            self.listeners.insert(listen.to_string(), handle);
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

    fn build_routers(
        &self,
        generation: &Generation,
    ) -> Result<std::collections::HashMap<String, Arc<Router>>> {
        let mut routers = std::collections::HashMap::new();
        let Some(http) = generation.config().http() else {
            return Ok(routers);
        };
        for (server_name, server) in &http.servers {
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
                routers.insert(listen.clone(), Arc::clone(&router));
            }
        }
        Ok(routers)
    }
}
